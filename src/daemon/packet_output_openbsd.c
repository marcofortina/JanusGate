/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "packet_output.h"

#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/** Ethernet header bytes required by every output frame. */
#define ETHERNET_HEADER_SIZE 14U

/** Complete pair of locked BPF output descriptors. */
struct jg_packet_output {
    struct jg_packet_output_config config;
    atomic_uint_fast64_t sent;
    atomic_uint_fast64_t errors;
    int client_fd;
    int server_fd;
};

/** @brief Convert one descriptor failure to a stable negative error. */
static int descriptor_error(void)
{
    return errno == 0 ? -EIO : -errno;
}

/** @brief Increment one relaxed raw-output counter. */
static void increment(atomic_uint_fast64_t *counter)
{
    (void)atomic_fetch_add_explicit(counter, 1U, memory_order_relaxed);
}

/** @brief Open and lock one complete-header BPF output descriptor. */
static int open_output(uint32_t interface_index)
{
    struct ifreq interface;
    unsigned header_complete = 1U;
    unsigned data_link_type = 0U;
    int descriptor = -1;
    int result = 0;

    (void)memset(&interface, 0, sizeof(interface));
    if (if_indextoname(interface_index, interface.ifr_name) == NULL) {
        return -errno;
    }
    descriptor = open("/dev/bpf", O_WRONLY | O_CLOEXEC | O_NONBLOCK);
    if (descriptor < 0) {
        return descriptor_error();
    }
    if (ioctl(descriptor, BIOCSETIF, &interface) != 0 ||
        ioctl(descriptor, BIOCGDLT, &data_link_type) != 0) {
        result = descriptor_error();
    } else if (data_link_type != DLT_EN10MB) {
        result = -ENOTSUP;
    } else if (ioctl(descriptor, BIOCSHDRCMPLT, &header_complete) != 0 ||
               ioctl(descriptor, BIOCLOCK) != 0) {
        result = descriptor_error();
    }
    if (result != 0) {
        (void)close(descriptor);
        return result;
    }
    return descriptor;
}

/** @brief Validate and write one complete Ethernet frame. */
static int send_frame(struct jg_packet_output *output,
                      int descriptor,
                      const uint8_t *frame,
                      size_t frame_size)
{
    ssize_t written = 0;

    if (frame == NULL || frame_size < ETHERNET_HEADER_SIZE ||
        frame_size > JG_PACKET_OUTPUT_FRAME_MAX) {
        increment(&output->errors);
        return -EINVAL;
    }
    written = write(descriptor, frame, frame_size);
    if (written < 0) {
        increment(&output->errors);
        return descriptor_error();
    }
    if ((size_t)written != frame_size) {
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

/** @brief Validate raw output interfaces and retained compatibility bounds. */
int jg_packet_output_config_validate(
    const struct jg_packet_output_config *config)
{
    if (config == NULL || config->client_interface_index == 0U ||
        config->server_interface_index == 0U ||
        config->client_interface_index == config->server_interface_index ||
        config->send_buffer_size == 0U) {
        return -EINVAL;
    }
    if (config->client_interface_index > (uint32_t)UINT_MAX ||
        config->server_interface_index > (uint32_t)UINT_MAX ||
        config->send_buffer_size > JG_PACKET_OUTPUT_BUFFER_MAX) {
        return -ERANGE;
    }
    return 0;
}

/** @brief Open one locked BPF descriptor for each data interface. */
int jg_packet_output_open(const struct jg_packet_output_config *config,
                          struct jg_packet_output **output)
{
    struct jg_packet_output *opened = NULL;
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
    opened->client_fd = -1;
    opened->server_fd = -1;
    atomic_init(&opened->sent, 0U);
    atomic_init(&opened->errors, 0U);
    opened->client_fd = open_output(config->client_interface_index);
    if (opened->client_fd < 0) {
        result = opened->client_fd;
    }
    if (result == 0) {
        opened->server_fd = open_output(config->server_interface_index);
        if (opened->server_fd < 0) {
            result = opened->server_fd;
        }
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
    client_result = send_frame(output, output->client_fd, resets->to_client,
                               resets->to_client_size);
    server_result = send_frame(output, output->server_fd, resets->to_server,
                               resets->to_server_size);
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
    return send_frame(output, output->client_fd, frame, frame_size);
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

/** @brief Close and release one stopped raw packet output. */
void jg_packet_output_close(struct jg_packet_output *output)
{
    if (output == NULL) {
        return;
    }
    if (output->client_fd >= 0) {
        (void)close(output->client_fd);
    }
    if (output->server_fd >= 0) {
        (void)close(output->server_fd);
    }
    free(output);
}
