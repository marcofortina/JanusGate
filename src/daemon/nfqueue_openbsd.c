/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "nfqueue.h"

#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sodium.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "janusgate/network.h"
#include "janusgate/packet.h"

/** Largest raw IP packet retained while one verdict is selected. */
#define DIVERT_PACKET_SIZE_MAX 131072U

/** Ethernet header plus the parser's maximum stacked VLAN envelope. */
#define LINK_HEADER_SIZE_MAX (14U + 4U * JG_PACKET_VLAN_LIMIT)

/** Recent link envelopes retained for BPF/divert packet correlation. */
#define LINK_CACHE_SIZE 256U

/** Maximum wait for the matching BPF record after a divert delivery. */
#define LINK_CAPTURE_WAIT_MS 10

/** Ethernet protocol identifiers used to locate one network header. */
#define ETHER_TYPE_IPV4 UINT16_C(0x0800)
#define ETHER_TYPE_IPV6 UINT16_C(0x86dd)
#define ETHER_TYPE_VLAN UINT16_C(0x8100)
#define ETHER_TYPE_QINQ UINT16_C(0x88a8)

/** Independently updated queue counters. */
struct atomic_stats {
    atomic_uint_fast64_t packets;
    atomic_uint_fast64_t accepted;
    atomic_uint_fast64_t dropped;
    atomic_uint_fast64_t malformed;
    atomic_uint_fast64_t overflows;
    atomic_uint_fast64_t message_errors;
    atomic_uint_fast64_t verdict_errors;
};

/** One digest-correlated Ethernet and VLAN envelope. */
struct link_cache_entry {
    uint8_t digest[crypto_generichash_BYTES];
    uint8_t header[LINK_HEADER_SIZE_MAX];
    size_t packet_size;
    size_t header_size;
    bool valid;
};

/** Complete state owned by one divert event loop. */
struct jg_nfqueue_worker {
    struct jg_nfqueue_worker_config config;
    jg_nfqueue_processor processor;
    void *processor_context;
    struct atomic_stats stats;
    struct link_cache_entry link_cache[LINK_CACHE_SIZE];
    uint8_t *capture_buffer;
    uint8_t *packet_buffer;
    uint8_t *frame_buffer;
    size_t capture_buffer_size;
    size_t next_link_entry;
    int divert_fds[2U];
    int capture_fd;
};

/** @brief Convert one descriptor failure to a stable negative error. */
static int descriptor_error(void)
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

/** @brief Read one network-order 16-bit field without alignment assumptions. */
static uint16_t read_u16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0U] << 8U) | (uint16_t)data[1U]);
}

/** @brief Return the exact IP packet size declared by one complete header. */
static size_t network_packet_size(const uint8_t *packet, size_t available)
{
    size_t declared = 0U;

    if (available >= 20U && (packet[0U] >> 4U) == 4U) {
        declared = read_u16(packet + 2U);
        return declared >= 20U && declared <= available ? declared : 0U;
    }
    if (available >= 40U && (packet[0U] >> 4U) == 6U) {
        declared = 40U + (size_t)read_u16(packet + 4U);
        return declared == 40U && available > 40U
                   ? available
                   : (declared <= available ? declared : 0U);
    }
    return 0U;
}

/** @brief Locate the IP header after one bounded Ethernet VLAN envelope. */
static size_t network_offset(const uint8_t *frame, size_t frame_size)
{
    size_t offset = 14U;
    size_t vlan_count = 0U;
    uint16_t ether_type = 0U;

    if (frame_size < offset) {
        return 0U;
    }
    ether_type = read_u16(frame + 12U);
    while ((ether_type == ETHER_TYPE_VLAN || ether_type == ETHER_TYPE_QINQ) &&
           vlan_count < JG_PACKET_VLAN_LIMIT) {
        if (frame_size < offset + 4U) {
            return 0U;
        }
        ether_type = read_u16(frame + offset + 2U);
        offset += 4U;
        ++vlan_count;
    }
    return ether_type == ETHER_TYPE_IPV4 || ether_type == ETHER_TYPE_IPV6
               ? offset
               : 0U;
}

/** @brief Retain one captured link envelope indexed by its IP packet digest. */
static int retain_link_header(struct jg_nfqueue_worker *worker,
                              const uint8_t *frame,
                              size_t frame_size)
{
    const size_t offset = network_offset(frame, frame_size);
    const size_t packet_size =
        offset == 0U ? 0U
                     : network_packet_size(frame + offset, frame_size - offset);
    struct link_cache_entry *entry = NULL;

    if (offset == 0U || offset > LINK_HEADER_SIZE_MAX || packet_size == 0U) {
        return 0;
    }
    entry = &worker->link_cache[worker->next_link_entry];
    if (crypto_generichash(entry->digest, sizeof(entry->digest), frame + offset,
                           packet_size, NULL, 0U) != 0) {
        return -EIO;
    }
    (void)memcpy(entry->header, frame, offset);
    entry->packet_size = packet_size;
    entry->header_size = offset;
    entry->valid = true;
    worker->next_link_entry = (worker->next_link_entry + 1U) % LINK_CACHE_SIZE;
    return 0;
}

/** @brief Decode and retain every complete record in one BPF read buffer. */
static int retain_capture_records(struct jg_nfqueue_worker *worker,
                                  size_t received)
{
    size_t offset = 0U;
    int result = 0;

    while (result == 0 && offset < received) {
        struct bpf_hdr header;
        size_t record_size = 0U;

        if (received - offset < sizeof(header)) {
            return -EPROTO;
        }
        (void)memcpy(&header, worker->capture_buffer + offset, sizeof(header));
        if (header.bh_hdrlen < sizeof(header) ||
            (size_t)header.bh_hdrlen > received - offset ||
            (size_t)header.bh_caplen >
                received - offset - (size_t)header.bh_hdrlen) {
            return -EPROTO;
        }
        result = retain_link_header(
            worker, worker->capture_buffer + offset + header.bh_hdrlen,
            header.bh_caplen);
        record_size =
            BPF_WORDALIGN((size_t)header.bh_hdrlen + header.bh_caplen);
        if (record_size == 0U || record_size > received - offset) {
            return -EPROTO;
        }
        offset += record_size;
    }
    return result;
}

/** @brief Drain currently readable BPF records into the correlation cache. */
static int drain_captures(struct jg_nfqueue_worker *worker)
{
    int result = 0;

    while (result == 0) {
        const ssize_t received =
            read(worker->capture_fd, worker->capture_buffer,
                 worker->capture_buffer_size);

        if (received > 0) {
            result = retain_capture_records(worker, (size_t)received);
        } else if (received < 0 && errno == EINTR) {
            continue;
        } else if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            result = received == 0 ? -ECONNRESET : -errno;
        }
    }
    if (result != 0) {
        increment(&worker->stats.message_errors);
    }
    return result;
}

/** @brief Recover and consume the Ethernet envelope for one raw IP packet. */
static size_t recover_link_header(struct jg_nfqueue_worker *worker,
                                  const uint8_t *packet,
                                  size_t packet_size)
{
    uint8_t digest[crypto_generichash_BYTES];
    size_t index = 0U;

    if (crypto_generichash(digest, sizeof(digest), packet, packet_size, NULL,
                           0U) != 0) {
        return 0U;
    }
    for (index = 0U; index < LINK_CACHE_SIZE; ++index) {
        struct link_cache_entry *entry = &worker->link_cache[index];

        if (entry->valid && entry->packet_size == packet_size &&
            sodium_memcmp(entry->digest, digest, sizeof(digest)) == 0) {
            (void)memcpy(worker->frame_buffer, entry->header,
                         entry->header_size);
            entry->valid = false;
            return entry->header_size;
        }
    }
    return 0U;
}

/** @brief Wait briefly for a BPF record which raced its divert delivery. */
static int await_link_header(struct jg_nfqueue_worker *worker)
{
    struct pollfd capture = {
        .fd = worker->capture_fd,
        .events = POLLIN,
    };
    int ready = poll(&capture, 1U, LINK_CAPTURE_WAIT_MS);

    if (ready < 0) {
        return errno == EINTR ? 0 : -errno;
    }
    if (ready > 0 && (capture.revents & POLLIN) != 0) {
        return drain_captures(worker);
    }
    return ready > 0 && capture.revents != 0 ? -EIO : 0;
}

/** @brief Receive, classify, and resolve one diverted packet. */
static int process_divert_packet(struct jg_nfqueue_worker *worker,
                                 int descriptor,
                                 bool wait_for_capture)
{
    struct sockaddr_storage address;
    socklen_t address_size = (socklen_t)sizeof(address);
    enum jg_nfqueue_verdict verdict = JG_NFQUEUE_DROP;
    size_t link_size = 0U;
    ssize_t received = 0;
    int result = 0;

    (void)memset(&address, 0, sizeof(address));
    received =
        recvfrom(descriptor, worker->packet_buffer, DIVERT_PACKET_SIZE_MAX,
                 MSG_TRUNC, (struct sockaddr *)&address, &address_size);
    if (received < 0 &&
        (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        return 0;
    }
    if (received <= 0) {
        return received == 0 ? -ECONNRESET : -errno;
    }
    increment(&worker->stats.packets);
    if ((size_t)received > DIVERT_PACKET_SIZE_MAX ||
        network_packet_size(worker->packet_buffer, (size_t)received) !=
            (size_t)received) {
        increment(&worker->stats.malformed);
        increment(&worker->stats.dropped);
        return 1;
    }
    result = drain_captures(worker);
    if (result == 0) {
        link_size = recover_link_header(worker, worker->packet_buffer,
                                        (size_t)received);
    }
    if (result == 0 && link_size == 0U && wait_for_capture) {
        result = await_link_header(worker);
        if (result == 0) {
            link_size = recover_link_header(worker, worker->packet_buffer,
                                            (size_t)received);
        }
    }
    if (result != 0) {
        return result;
    }
    if (link_size == 0U) {
        increment(&worker->stats.malformed);
        increment(&worker->stats.dropped);
        return 1;
    }
    (void)memcpy(worker->frame_buffer + link_size, worker->packet_buffer,
                 (size_t)received);
    {
        const struct jg_nfqueue_packet packet = {
            .queue_number = worker->config.queue_number,
            .ingress_index = worker->config.ingress_index,
            .physical_ingress_index = worker->config.ingress_index,
            .data = worker->frame_buffer,
            .size = link_size + (size_t)received,
        };

        verdict = worker->processor(&packet, worker->processor_context);
    }
    if (verdict == JG_NFQUEUE_DROP) {
        increment(&worker->stats.dropped);
        return 1;
    }
    if (verdict != JG_NFQUEUE_ACCEPT) {
        increment(&worker->stats.malformed);
        increment(&worker->stats.dropped);
        return 1;
    }
    if (sendto(descriptor, worker->packet_buffer, (size_t)received,
               MSG_NOSIGNAL, (const struct sockaddr *)&address,
               address_size) != received) {
        increment(&worker->stats.verdict_errors);
        return descriptor_error();
    }
    increment(&worker->stats.accepted);
    return 1;
}

/** @brief Drain a bounded number of already delivered divert packets. */
static int drain_divert_packets(struct jg_nfqueue_worker *worker)
{
    uint32_t count = 0U;
    unsigned idle = 0U;
    int result = 0;

    while (count < worker->config.queue_length && idle < 2U) {
        result = process_divert_packet(worker, worker->divert_fds[count % 2U],
                                       false);
        if (result < 0) {
            return result;
        }
        idle = result == 0 ? idle + 1U : 0U;
        ++count;
    }
    return 0;
}

/** @brief Select the largest requested socket buffer accepted by the kernel. */
static int configure_socket_buffer(int descriptor,
                                   int option,
                                   uint32_t requested)
{
    int socket_buffer = (int)requested;

    while (setsockopt(descriptor, SOL_SOCKET, option, &socket_buffer,
                      (socklen_t)sizeof(socket_buffer)) != 0) {
        if (errno != ENOBUFS || socket_buffer <= 1) {
            return descriptor_error();
        }
        socket_buffer /= 2;
    }
    return 0;
}

/** @brief Open and bind one non-blocking divert protocol socket. */
static int open_divert_socket(int family, uint16_t port, uint32_t buffer_size)
{
    int descriptor =
        socket(family, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_DIVERT);
    int result = 0;

    if (descriptor < 0) {
        return descriptor_error();
    }
    result = configure_socket_buffer(descriptor, SO_RCVBUF, buffer_size);
    if (result == 0) {
        result = configure_socket_buffer(descriptor, SO_SNDBUF, buffer_size);
    }
    if (result == 0 && family == AF_INET) {
        const struct sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
        };

        if (bind(descriptor, (const struct sockaddr *)&address,
                 (socklen_t)sizeof(address)) != 0) {
            result = descriptor_error();
        }
    } else if (result == 0) {
        const struct sockaddr_in6 address = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(port),
        };

        if (bind(descriptor, (const struct sockaddr *)&address,
                 (socklen_t)sizeof(address)) != 0) {
            result = descriptor_error();
        }
    }
    if (result != 0) {
        (void)close(descriptor);
        return result;
    }
    return descriptor;
}

/** @brief Open and lock one inbound BPF capture descriptor. */
static int open_capture(uint32_t interface_index,
                        uint32_t requested_buffer,
                        size_t *actual_buffer)
{
    struct ifreq interface;
    unsigned buffer_size =
        requested_buffer > BPF_MAXBUFSIZE ? BPF_MAXBUFSIZE : requested_buffer;
    unsigned data_link_type = 0U;
    unsigned direction = BPF_DIRECTION_IN;
    unsigned immediate = 1U;
    int descriptor = -1;
    int result = 0;

    (void)memset(&interface, 0, sizeof(interface));
    if (if_indextoname(interface_index, interface.ifr_name) == NULL) {
        return -errno;
    }
    descriptor = open("/dev/bpf", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (descriptor < 0) {
        return descriptor_error();
    }
    if (ioctl(descriptor, BIOCSBLEN, &buffer_size) != 0 ||
        ioctl(descriptor, BIOCSETIF, &interface) != 0 ||
        ioctl(descriptor, BIOCGDLT, &data_link_type) != 0) {
        result = descriptor_error();
    } else if (data_link_type != DLT_EN10MB) {
        result = -ENOTSUP;
    } else if (ioctl(descriptor, BIOCIMMEDIATE, &immediate) != 0 ||
               ioctl(descriptor, BIOCSDIRFILT, &direction) != 0 ||
               ioctl(descriptor, BIOCGBLEN, &buffer_size) != 0 ||
               ioctl(descriptor, BIOCLOCK) != 0) {
        result = descriptor_error();
    }
    if (result != 0) {
        (void)close(descriptor);
        return result;
    }
    *actual_buffer = buffer_size;
    return descriptor;
}

/** @brief Validate one bounded divert-worker configuration. */
int jg_nfqueue_worker_config_validate(
    const struct jg_nfqueue_worker_config *config)
{
    if (config == NULL || config->queue_number == 0U ||
        config->ingress_index == 0U || config->receive_buffer_size == 0U) {
        return -EINVAL;
    }
    if (config->fail_open) {
        return -ENOTSUP;
    }
    if (config->queue_length == 0U ||
        config->queue_length > JG_NETWORK_QUEUE_LENGTH_MAX ||
        config->receive_buffer_size > JG_NFQUEUE_RECEIVE_BUFFER_MAX ||
        config->receive_buffer_size > (uint32_t)INT_MAX) {
        return -ERANGE;
    }
    return 0;
}

/** @brief Open one dual-stack divert port and its link capture. */
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
    if (sodium_init() < 0) {
        return -EIO;
    }
    opened = calloc(1U, sizeof(*opened));
    if (opened == NULL) {
        return -ENOMEM;
    }
    opened->config = *config;
    opened->processor = processor;
    opened->processor_context = context;
    opened->divert_fds[0U] = -1;
    opened->divert_fds[1U] = -1;
    opened->capture_fd = -1;
    initialize_stats(&opened->stats);
    opened->packet_buffer = malloc(DIVERT_PACKET_SIZE_MAX);
    opened->frame_buffer =
        malloc(DIVERT_PACKET_SIZE_MAX + LINK_HEADER_SIZE_MAX);
    if (opened->packet_buffer == NULL || opened->frame_buffer == NULL) {
        result = -ENOMEM;
    }
    if (result == 0) {
        opened->capture_fd =
            open_capture(config->ingress_index, config->receive_buffer_size,
                         &opened->capture_buffer_size);
        if (opened->capture_fd < 0) {
            result = opened->capture_fd;
        }
    }
    if (result == 0) {
        opened->capture_buffer = malloc(opened->capture_buffer_size);
        if (opened->capture_buffer == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        opened->divert_fds[0U] = open_divert_socket(
            AF_INET, config->queue_number, config->receive_buffer_size);
        if (opened->divert_fds[0U] < 0) {
            result = opened->divert_fds[0U];
        }
    }
    if (result == 0) {
        opened->divert_fds[1U] = open_divert_socket(
            AF_INET6, config->queue_number, config->receive_buffer_size);
        if (opened->divert_fds[1U] < 0) {
            result = opened->divert_fds[1U];
        }
    }
    if (result != 0) {
        jg_nfqueue_worker_close(opened);
        return result;
    }
    *worker = opened;
    return 0;
}

/** @brief Service diverted packets until orderly shutdown or a fatal error. */
int jg_nfqueue_worker_run(struct jg_nfqueue_worker *worker, int stop_fd)
{
    struct pollfd descriptors[4U] = {{0}};
    int result = 0;

    if (worker == NULL || stop_fd < 0) {
        return -EINVAL;
    }
    descriptors[0U].fd = worker->divert_fds[0U];
    descriptors[0U].events = POLLIN;
    descriptors[1U].fd = worker->divert_fds[1U];
    descriptors[1U].events = POLLIN;
    descriptors[2U].fd = worker->capture_fd;
    descriptors[2U].events = POLLIN;
    descriptors[3U].fd = stop_fd;
    descriptors[3U].events = POLLIN;
    while (result == 0) {
        const int ready = poll(descriptors, 4U, -1);

        if (ready < 0) {
            if (errno != EINTR) {
                result = -errno;
            }
            continue;
        }
        if ((descriptors[2U].revents & POLLIN) != 0) {
            result = drain_captures(worker);
        }
        if (result == 0 && (descriptors[3U].revents & POLLIN) != 0) {
            result = drain_divert_packets(worker);
            break;
        }
        for (size_t index = 0U; result == 0 && index < 2U; ++index) {
            if ((descriptors[index].revents & POLLIN) != 0) {
                result =
                    process_divert_packet(worker, descriptors[index].fd, true);
                if (result > 0) {
                    result = 0;
                }
            }
        }
        for (size_t index = 0U; result == 0 && index < 4U; ++index) {
            if ((descriptors[index].revents & (POLLERR | POLLHUP | POLLNVAL)) !=
                0) {
                result = -EIO;
            }
        }
    }
    return result;
}

/** @brief Copy one relaxed snapshot of lock-free worker counters. */
int jg_nfqueue_worker_get_stats(const struct jg_nfqueue_worker *worker,
                                struct jg_nfqueue_stats *stats)
{
    struct bpf_stat capture_stats = {0};

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
    if (ioctl(worker->capture_fd, BIOCGSTATS, &capture_stats) == 0) {
        stats->overflows = capture_stats.bs_drop > UINT64_MAX - stats->overflows
                               ? UINT64_MAX
                               : stats->overflows + capture_stats.bs_drop;
    }
    stats->message_errors = atomic_load_explicit(&worker->stats.message_errors,
                                                 memory_order_relaxed);
    stats->verdict_errors = atomic_load_explicit(&worker->stats.verdict_errors,
                                                 memory_order_relaxed);
    return 0;
}

/** @brief Close and release one stopped divert worker. */
void jg_nfqueue_worker_close(struct jg_nfqueue_worker *worker)
{
    if (worker == NULL) {
        return;
    }
    if (worker->divert_fds[0U] >= 0) {
        (void)close(worker->divert_fds[0U]);
    }
    if (worker->divert_fds[1U] >= 0) {
        (void)close(worker->divert_fds[1U]);
    }
    if (worker->capture_fd >= 0) {
        (void)close(worker->capture_fd);
    }
    free(worker->capture_buffer);
    free(worker->packet_buffer);
    free(worker->frame_buffer);
    free(worker);
}
