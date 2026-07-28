/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "packet_output.h"

#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <unistd.h>

/** Complete non-blocking raw Ethernet output state. */
struct jg_packet_output {
    struct jg_packet_output_config config;
    atomic_uint_fast64_t sent;
    atomic_uint_fast64_t errors;
    int socket_fd;
};

/** @brief Convert one socket failure to a stable negative error. */
static int socket_error(void)
{
    return errno == 0 ? -EIO : -errno;
}

/** @brief Increment one relaxed raw output counter. */
static void increment(atomic_uint_fast64_t *counter)
{
    (void)atomic_fetch_add_explicit(counter, 1U, memory_order_relaxed);
}

/** @brief Validate and send one complete Ethernet frame. */
static int send_frame(struct jg_packet_output *output,
                      uint32_t interface_index,
                      const uint8_t *frame,
                      size_t frame_size)
{
    struct sockaddr_ll address = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = (int)interface_index,
        .sll_halen = ETH_ALEN,
    };
    ssize_t sent = 0;

    if (frame == NULL || frame_size < ETH_HLEN ||
        frame_size > JG_PACKET_OUTPUT_FRAME_MAX) {
        increment(&output->errors);
        return -EINVAL;
    }
    (void)memcpy(address.sll_addr, frame, ETH_ALEN);
    sent = sendto(
        output->socket_fd, frame, frame_size, MSG_DONTWAIT | MSG_NOSIGNAL,
        (const struct sockaddr *)&address, (socklen_t)sizeof(address));
    if (sent < 0) {
        increment(&output->errors);
        return socket_error();
    }
    if ((size_t)sent != frame_size) {
        increment(&output->errors);
        return -EIO;
    }
    increment(&output->sent);
    return 0;
}

/** @brief Initialize conservative raw packet output defaults. */
void jg_packet_output_config_default(struct jg_packet_output_config *config)
{
    if (config == NULL) {
        return;
    }
    (void)memset(config, 0, sizeof(*config));
    config->send_buffer_size = JG_PACKET_OUTPUT_BUFFER_DEFAULT;
}

/** @brief Validate raw output interface and socket memory bounds. */
int jg_packet_output_config_validate(
    const struct jg_packet_output_config *config)
{
    if (config == NULL || config->client_interface_index == 0U ||
        config->server_interface_index == 0U ||
        config->client_interface_index == config->server_interface_index ||
        config->send_buffer_size == 0U) {
        return -EINVAL;
    }
    if (config->client_interface_index > (uint32_t)INT32_MAX ||
        config->server_interface_index > (uint32_t)INT32_MAX ||
        config->send_buffer_size > JG_PACKET_OUTPUT_BUFFER_MAX ||
        config->send_buffer_size > (uint32_t)INT32_MAX) {
        return -ERANGE;
    }
    return 0;
}

/** @brief Open and configure one non-blocking raw packet output socket. */
int jg_packet_output_open(const struct jg_packet_output_config *config,
                          struct jg_packet_output **output)
{
    struct jg_packet_output *opened = NULL;
    int send_buffer = 0;
    int result = 0;

    if (output == NULL) {
        return -EINVAL;
    }
    *output = NULL;
    result = jg_packet_output_config_validate(config);
    if (result != 0) {
        return result;
    }
    opened = calloc(1U, sizeof(*opened));
    if (opened == NULL) {
        return -ENOMEM;
    }
    opened->config = *config;
    opened->socket_fd = -1;
    atomic_init(&opened->sent, 0U);
    atomic_init(&opened->errors, 0U);
    opened->socket_fd = socket(
        AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (opened->socket_fd < 0) {
        result = socket_error();
    }
    send_buffer = (int)opened->config.send_buffer_size;
    if (result == 0 &&
        setsockopt(opened->socket_fd, SOL_SOCKET, SO_SNDBUF, &send_buffer,
                   (socklen_t)sizeof(send_buffer)) != 0) {
        result = socket_error();
    }
    if (result != 0) {
        jg_packet_output_close(opened);
        return result;
    }
    *output = opened;
    return 0;
}

/** @brief Send one TCP reset frame to each configured flow endpoint. */
int jg_packet_output_send_tcp_resets(const struct jg_tcp_reset_pair *resets,
                                     void *context)
{
    struct jg_packet_output *output = context;
    int client_result = 0;
    int server_result = 0;

    if (output == NULL || resets == NULL) {
        return -EINVAL;
    }
    client_result = send_frame(output, output->config.client_interface_index,
                               resets->to_client, resets->to_client_size);
    server_result = send_frame(output, output->config.server_interface_index,
                               resets->to_server, resets->to_server_size);
    return client_result != 0 ? client_result : server_result;
}

/** @brief Send one complete synthetic frame toward the policy client. */
int jg_packet_output_send_client_frame(const uint8_t *frame,
                                       size_t frame_size,
                                       void *context)
{
    struct jg_packet_output *output = context;

    if (output == NULL) {
        return -EINVAL;
    }
    return send_frame(output, output->config.client_interface_index, frame,
                      frame_size);
}

/** @brief Copy one relaxed snapshot of raw output counters. */
int jg_packet_output_get_stats(const struct jg_packet_output *output,
                               struct jg_packet_output_stats *stats)
{
    if (output == NULL || stats == NULL) {
        return -EINVAL;
    }
    stats->sent = atomic_load_explicit(&output->sent, memory_order_relaxed);
    stats->errors = atomic_load_explicit(&output->errors, memory_order_relaxed);
    return 0;
}

/** @brief Close and release one stopped raw packet output socket. */
void jg_packet_output_close(struct jg_packet_output *output)
{
    if (output == NULL) {
        return;
    }
    if (output->socket_fd >= 0) {
        (void)close(output->socket_fd);
    }
    free(output);
}
