/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "nfqueue.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <poll.h>
#include <sys/socket.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "janusgate/network.h"
#include "janusgate/packet.h"

/** Largest netlink datagram retained by one worker. */
#define JG_NFQUEUE_MESSAGE_MAX 131072U

/** Ethernet header plus the maximum supported VLAN stack. */
#define JG_NFQUEUE_LINK_HEADER_MAX (14U + (4U * JG_PACKET_VLAN_LIMIT))

/** Internal independently updated queue counters. */
struct atomic_stats {
    atomic_uint_fast64_t packets;
    atomic_uint_fast64_t accepted;
    atomic_uint_fast64_t dropped;
    atomic_uint_fast64_t malformed;
    atomic_uint_fast64_t overflows;
    atomic_uint_fast64_t message_errors;
    atomic_uint_fast64_t verdict_errors;
};

/** Complete state owned by one queue event loop. */
struct jg_nfqueue_worker {
    struct jg_nfqueue_worker_config config;
    struct nfq_handle *handle;
    struct nfq_q_handle *queue;
    jg_nfqueue_processor processor;
    void *processor_context;
    unsigned char *messages;
    unsigned char *frame;
    unsigned char link_header[JG_NFQUEUE_LINK_HEADER_MAX];
    size_t link_header_size;
    struct atomic_stats stats;
    int socket_fd;
};

/** Link-layer attributes carried beside one queued IP packet. */
struct link_attributes {
    const struct nlattr *header;
    const struct nlattr *vlan;
};

/** Offloaded VLAN fields carried in one nested queue attribute. */
struct vlan_attributes {
    const struct nlattr *protocol;
    const struct nlattr *tci;
};

/** @brief Convert one libnetfilter_queue failure to errno style. */
static int queue_error(void)
{
    return errno == 0 ? -EIO : -errno;
}

/** @brief Increment one relaxed per-worker counter. */
static void increment(atomic_uint_fast64_t *counter)
{
    (void)atomic_fetch_add_explicit(counter, 1U, memory_order_relaxed);
}

/** @brief Initialize every lock-free worker counter. */
static void initialize_stats(struct atomic_stats *stats)
{
    atomic_init(&stats->packets, 0U);
    atomic_init(&stats->accepted, 0U);
    atomic_init(&stats->dropped, 0U);
    atomic_init(&stats->malformed, 0U);
    atomic_init(&stats->overflows, 0U);
    atomic_init(&stats->message_errors, 0U);
    atomic_init(&stats->verdict_errors, 0U);
}

/** @brief Collect relevant link-layer attributes from one queue message. */
static int collect_link_attribute(const struct nlattr *attribute, void *context)
{
    struct link_attributes *attributes = context;

    if (mnl_attr_get_type(attribute) == NFQA_L2HDR) {
        attributes->header = attribute;
    } else if (mnl_attr_get_type(attribute) == NFQA_VLAN) {
        attributes->vlan = attribute;
    }
    return MNL_CB_OK;
}

/** @brief Collect protocol and tag fields from one nested VLAN attribute. */
static int collect_vlan_attribute(const struct nlattr *attribute, void *context)
{
    struct vlan_attributes *attributes = context;

    if (mnl_attr_get_type(attribute) == NFQA_VLAN_PROTO) {
        attributes->protocol = attribute;
    } else if (mnl_attr_get_type(attribute) == NFQA_VLAN_TCI) {
        attributes->tci = attribute;
    }
    return MNL_CB_OK;
}

/** @brief Recover the Ethernet header delivered separately by NFQUEUE. */
static void prepare_link_header(struct jg_nfqueue_worker *worker,
                                const struct nlmsghdr *message)
{
    struct link_attributes attributes = {0};
    size_t header_size = 0U;

    worker->link_header_size = 0U;
    if (message->nlmsg_type == NLMSG_ERROR ||
        mnl_attr_parse(message, sizeof(struct nfgenmsg), collect_link_attribute,
                       &attributes) < 0 ||
        attributes.header == NULL) {
        return;
    }

    header_size = mnl_attr_get_payload_len(attributes.header);
    if (header_size < 14U || header_size > sizeof(worker->link_header)) {
        return;
    }
    (void)memcpy(worker->link_header, mnl_attr_get_payload(attributes.header),
                 header_size);

    if (attributes.vlan != NULL) {
        struct vlan_attributes vlan = {0};

        if (header_size + 4U > sizeof(worker->link_header) ||
            mnl_attr_parse_nested(attributes.vlan, collect_vlan_attribute,
                                  &vlan) < 0 ||
            vlan.protocol == NULL || vlan.tci == NULL ||
            mnl_attr_get_payload_len(vlan.protocol) != sizeof(uint16_t) ||
            mnl_attr_get_payload_len(vlan.tci) != sizeof(uint16_t)) {
            return;
        }
        (void)memmove(worker->link_header + 16U, worker->link_header + 12U,
                      header_size - 12U);
        (void)memcpy(worker->link_header + 12U,
                     mnl_attr_get_payload(vlan.protocol), sizeof(uint16_t));
        (void)memcpy(worker->link_header + 14U, mnl_attr_get_payload(vlan.tci),
                     sizeof(uint16_t));
        header_size += 4U;
    }
    worker->link_header_size = header_size;
}

/** @brief Send one definitive verdict and update its outcome counters. */
static int send_verdict(struct jg_nfqueue_worker *worker,
                        uint32_t packet_id,
                        enum jg_nfqueue_verdict verdict)
{
    const uint32_t kernel_verdict =
        verdict == JG_NFQUEUE_ACCEPT ? NF_ACCEPT : NF_DROP;
    int result = 0;

    if (nfq_set_verdict(worker->queue, packet_id, kernel_verdict, 0U, NULL) <
        0) {
        increment(&worker->stats.verdict_errors);
        result = queue_error();
    } else if (verdict == JG_NFQUEUE_ACCEPT) {
        increment(&worker->stats.accepted);
    } else {
        increment(&worker->stats.dropped);
    }
    return result;
}

/** @brief Validate metadata and invoke the configured packet processor. */
static enum jg_nfqueue_verdict process_packet(struct jg_nfqueue_worker *worker,
                                              struct nfq_data *queue_data,
                                              unsigned char *payload,
                                              int payload_size)
{
    const uint32_t physical_ingress = nfq_get_physindev(queue_data);
    const uint32_t logical_ingress = nfq_get_indev(queue_data);
    struct jg_nfqueue_packet packet = {
        .queue_number = worker->config.queue_number,
        .ingress_index = logical_ingress,
        .physical_ingress_index = physical_ingress,
        .socket_buffer_info = nfq_get_skbinfo(queue_data),
        .data = payload,
        .size = payload_size < 0 ? 0U : (size_t)payload_size,
    };
    enum jg_nfqueue_verdict verdict = JG_NFQUEUE_DROP;

    if (payload_size <= 0 || payload == NULL ||
        (physical_ingress != 0U &&
         physical_ingress != worker->config.ingress_index) ||
        (physical_ingress == 0U &&
         logical_ingress != worker->config.ingress_index)) {
        increment(&worker->stats.malformed);
    } else {
        verdict = worker->processor(&packet, worker->processor_context);
        if (verdict != JG_NFQUEUE_ACCEPT && verdict != JG_NFQUEUE_DROP) {
            increment(&worker->stats.malformed);
            verdict = JG_NFQUEUE_DROP;
        }
    }
    return verdict;
}

/** @brief Handle one complete queued-packet callback. */
static int queue_callback(struct nfq_q_handle *queue,
                          struct nfgenmsg *message,
                          struct nfq_data *queue_data,
                          void *context)
{
    struct jg_nfqueue_worker *worker = context;
    struct nfqnl_msg_packet_hdr *header = NULL;
    unsigned char *payload = NULL;
    enum jg_nfqueue_verdict verdict = JG_NFQUEUE_DROP;
    size_t frame_size = 0U;
    uint32_t packet_id = 0U;
    int payload_size = -1;

    (void)queue;
    (void)message;
    header = nfq_get_msg_packet_hdr(queue_data);
    if (header == NULL) {
        increment(&worker->stats.malformed);
        return -EPROTO;
    }

    packet_id = ntohl(header->packet_id);
    payload_size = nfq_get_payload(queue_data, &payload);
    increment(&worker->stats.packets);
    if (payload_size > 0 && payload != NULL && worker->link_header_size > 0U &&
        (size_t)payload_size <=
            JG_NFQUEUE_MESSAGE_MAX - worker->link_header_size) {
        frame_size = worker->link_header_size + (size_t)payload_size;
        (void)memcpy(worker->frame, worker->link_header,
                     worker->link_header_size);
        (void)memcpy(worker->frame + worker->link_header_size, payload,
                     (size_t)payload_size);
        verdict =
            process_packet(worker, queue_data, worker->frame, (int)frame_size);
    } else {
        increment(&worker->stats.malformed);
    }
    return send_verdict(worker, packet_id, verdict);
}

/** @brief Configure kernel queue behavior required by one worker. */
static int configure_queue(struct jg_nfqueue_worker *worker)
{
    uint32_t flag_mask = NFQA_CFG_F_GSO;
    uint32_t flags = NFQA_CFG_F_GSO;
    int receive_buffer = (int)worker->config.receive_buffer_size;

    if (worker->config.fail_open) {
        flag_mask |= NFQA_CFG_F_FAIL_OPEN;
        flags |= NFQA_CFG_F_FAIL_OPEN;
    }
    if (nfq_set_mode(worker->queue, NFQNL_COPY_PACKET, UINT16_MAX) < 0 ||
        nfq_set_queue_maxlen(worker->queue, worker->config.queue_length) < 0 ||
        nfq_set_queue_flags(worker->queue, flag_mask, flags) < 0 ||
        setsockopt(worker->socket_fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer,
                   (socklen_t)sizeof(receive_buffer)) != 0) {
        return queue_error();
    }
    return 0;
}

/** @brief Receive and dispatch one netlink datagram. */
static int receive_messages(struct jg_nfqueue_worker *worker, int flags)
{
    ssize_t received = recv(worker->socket_fd, worker->messages,
                            JG_NFQUEUE_MESSAGE_MAX, flags | MSG_TRUNC);

    if (received > 0) {
        size_t offset = 0U;
        size_t remaining = (size_t)received;

        if ((size_t)received > JG_NFQUEUE_MESSAGE_MAX) {
            increment(&worker->stats.message_errors);
            return -EMSGSIZE;
        }
        while (remaining > 0U) {
            struct nlmsghdr *message = NULL;
            size_t aligned_size = 0U;
            size_t message_size = 0U;
            int dispatch_result = 0;

            if (remaining < sizeof(*message)) {
                increment(&worker->stats.message_errors);
                return -EPROTO;
            }
            message = (struct nlmsghdr *)(void *)(worker->messages + offset);
            message_size = message->nlmsg_len;
            if (message_size < sizeof(*message) || message_size > remaining ||
                message_size > (size_t)INT32_MAX) {
                increment(&worker->stats.message_errors);
                return -EPROTO;
            }
            prepare_link_header(worker, message);
            dispatch_result = nfq_handle_packet(worker->handle, (char *)message,
                                                (int)message_size);
            worker->link_header_size = 0U;
            if (dispatch_result < 0) {
                increment(&worker->stats.message_errors);
                return dispatch_result == -1 ? queue_error() : dispatch_result;
            }
            aligned_size = NLMSG_ALIGN(message_size);
            if (aligned_size > remaining) {
                aligned_size = message_size;
            }
            offset += aligned_size;
            remaining -= aligned_size;
        }
        return 1;
    }
    if (received == 0) {
        return -ECONNRESET;
    }
    if (errno == EINTR) {
        return 1;
    }
    if (errno == ENOBUFS) {
        increment(&worker->stats.overflows);
        return 1;
    }
    if ((flags & MSG_DONTWAIT) != 0 && errno == EAGAIN) {
        return 0;
    }
    return -errno;
}

/** @brief Drain a bounded number of already delivered queue datagrams. */
static int drain_messages(struct jg_nfqueue_worker *worker)
{
    uint32_t count = 0U;
    int result = 1;

    while (count < worker->config.queue_length && result > 0) {
        result = receive_messages(worker, MSG_DONTWAIT);
        ++count;
    }
    return result < 0 ? result : 0;
}

/** @brief Validate one bounded queue-worker configuration. */
int jg_nfqueue_worker_config_validate(
    const struct jg_nfqueue_worker_config *config)
{
    if (config == NULL || config->ingress_index == 0U ||
        config->receive_buffer_size == 0U) {
        return -EINVAL;
    }
    if (config->queue_length == 0U ||
        config->queue_length > JG_NETWORK_QUEUE_LENGTH_MAX ||
        config->receive_buffer_size > JG_NFQUEUE_RECEIVE_BUFFER_MAX ||
        config->receive_buffer_size > (uint32_t)INT32_MAX) {
        return -ERANGE;
    }
    return 0;
}

/** @brief Open and configure one exclusive kernel queue. */
int jg_nfqueue_worker_open(const struct jg_nfqueue_worker_config *config,
                           jg_nfqueue_processor processor,
                           void *context,
                           struct jg_nfqueue_worker **worker)
{
    struct jg_nfqueue_worker *opened = NULL;
    int result = 0;

    if (worker == NULL) {
        return -EINVAL;
    }
    *worker = NULL;
    if (processor == NULL) {
        return -EINVAL;
    }
    result = jg_nfqueue_worker_config_validate(config);
    if (result != 0) {
        return result;
    }
    opened = calloc(1U, sizeof(*opened));
    if (opened == NULL) {
        return -ENOMEM;
    }
    opened->config = *config;
    opened->processor = processor;
    opened->processor_context = context;
    opened->socket_fd = -1;
    initialize_stats(&opened->stats);
    opened->messages = malloc(JG_NFQUEUE_MESSAGE_MAX);
    opened->frame = malloc(JG_NFQUEUE_MESSAGE_MAX);
    if (opened->messages == NULL || opened->frame == NULL) {
        result = -ENOMEM;
    }
    if (result == 0) {
        opened->handle = nfq_open();
        if (opened->handle == NULL) {
            result = queue_error();
        }
    }
    if (result == 0) {
        opened->queue =
            nfq_create_queue(opened->handle, opened->config.queue_number,
                             queue_callback, opened);
        if (opened->queue == NULL) {
            result = queue_error();
        }
    }
    if (result == 0) {
        opened->socket_fd = nfq_fd(opened->handle);
        if (opened->socket_fd < 0) {
            result = -EBADF;
        }
    }
    if (result == 0) {
        result = configure_queue(opened);
    }
    if (result != 0) {
        jg_nfqueue_worker_close(opened);
        return result;
    }
    *worker = opened;
    return 0;
}

/** @brief Service one queue until orderly shutdown or a fatal error. */
int jg_nfqueue_worker_run(struct jg_nfqueue_worker *worker, int stop_fd)
{
    struct pollfd descriptors[2U] = {{0}};
    int result = 0;

    if (worker == NULL || stop_fd < 0) {
        return -EINVAL;
    }
    descriptors[0].fd = worker->socket_fd;
    descriptors[0].events = POLLIN;
    descriptors[1].fd = stop_fd;
    descriptors[1].events = POLLIN;
    while (result == 0) {
        const int ready = poll(descriptors, 2U, -1);

        if (ready < 0) {
            if (errno != EINTR) {
                result = -errno;
            }
        } else if ((descriptors[1].revents & POLLIN) != 0) {
            result = drain_messages(worker);
            break;
        } else if ((descriptors[0].revents & POLLIN) != 0) {
            const int receive_result = receive_messages(worker, 0);

            if (receive_result < 0) {
                result = receive_result;
            }
        } else if ((descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) !=
                       0 ||
                   (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL)) !=
                       0) {
            result = -EIO;
        }
    }
    return result;
}

/** @brief Copy one relaxed snapshot of lock-free worker counters. */
int jg_nfqueue_worker_get_stats(const struct jg_nfqueue_worker *worker,
                                struct jg_nfqueue_stats *stats)
{
    if (worker == NULL || stats == NULL) {
        return -EINVAL;
    }
    stats->packets =
        atomic_load_explicit(&worker->stats.packets, memory_order_relaxed);
    stats->accepted =
        atomic_load_explicit(&worker->stats.accepted, memory_order_relaxed);
    stats->dropped =
        atomic_load_explicit(&worker->stats.dropped, memory_order_relaxed);
    stats->malformed =
        atomic_load_explicit(&worker->stats.malformed, memory_order_relaxed);
    stats->overflows =
        atomic_load_explicit(&worker->stats.overflows, memory_order_relaxed);
    stats->message_errors = atomic_load_explicit(&worker->stats.message_errors,
                                                 memory_order_relaxed);
    stats->verdict_errors = atomic_load_explicit(&worker->stats.verdict_errors,
                                                 memory_order_relaxed);
    return 0;
}

/** @brief Unbind and release one stopped queue worker. */
void jg_nfqueue_worker_close(struct jg_nfqueue_worker *worker)
{
    if (worker == NULL) {
        return;
    }
    if (worker->queue != NULL) {
        (void)nfq_destroy_queue(worker->queue);
    }
    if (worker->handle != NULL) {
        (void)nfq_close(worker->handle);
    }
    free(worker->frame);
    free(worker->messages);
    free(worker);
}
