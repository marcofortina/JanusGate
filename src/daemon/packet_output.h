/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file packet_output.h
 * @brief Bounded raw Ethernet output for synthetic policy packets.
 */

#ifndef JANUSGATE_DAEMON_PACKET_OUTPUT_H
#define JANUSGATE_DAEMON_PACKET_OUTPUT_H

#include <stddef.h>
#include <stdint.h>

#include "tcp_reset.h"

/** Default raw packet socket send-buffer request. */
#define JG_PACKET_OUTPUT_BUFFER_DEFAULT 262144U

/** Largest accepted raw packet socket send-buffer request. */
#define JG_PACKET_OUTPUT_BUFFER_MAX 4194304U

/** Largest complete Ethernet frame accepted from packet workers. */
#define JG_PACKET_OUTPUT_FRAME_MAX 8192U

/**
 * @brief Configuration for one raw packet output socket.
 */
struct jg_packet_output_config {
    /** Interface index leading back to policy clients. */
    uint32_t client_interface_index;
    /** Interface index leading toward upstream servers. */
    uint32_t server_interface_index;
    /** Requested kernel send-buffer bytes. */
    uint32_t send_buffer_size;
};

/**
 * @brief Independently readable raw output counters.
 */
struct jg_packet_output_stats {
    /** Complete Ethernet frames sent successfully. */
    uint64_t sent;
    /** Frames rejected by validation or a socket failure. */
    uint64_t errors;
};

/** Opaque raw packet output socket. */
struct jg_packet_output;

/**
 * @brief Initialize conservative raw packet output defaults.
 *
 * Interface indices remain zero for the caller to populate.
 *
 * @param[out] config Configuration to initialize; null is ignored.
 *
 * @thread_safety This function is reentrant.
 */
void jg_packet_output_config_default(struct jg_packet_output_config *config);

/**
 * @brief Validate raw packet output interfaces and memory bounds.
 *
 * @param[in] config Configuration to validate.
 *
 * @return 0 on success.
 * @return -EINVAL for null, zero, or identical interface indices.
 * @return -ERANGE for an unsupported send-buffer size.
 *
 * @thread_safety This function is reentrant.
 */
int jg_packet_output_config_validate(
    const struct jg_packet_output_config *config);

/**
 * @brief Open one non-blocking raw Ethernet output socket.
 *
 * @param[in] config Validated output configuration.
 * @param[out] output Receives the owned output socket.
 *
 * @return 0 on success.
 * @return A negative errno-style validation, allocation, socket, or
 * configuration error otherwise.
 *
 * @thread_safety Concurrent opens are independent.
 *
 * @side_effects Opens an AF_PACKET socket requiring CAP_NET_RAW.
 */
int jg_packet_output_open(const struct jg_packet_output_config *config,
                          struct jg_packet_output **output);

/**
 * @brief Send one reset frame toward each endpoint.
 *
 * This signature can be registered directly as a data-plane reset sender.
 * Both sends are attempted even when the first one fails.
 *
 * @param[in] resets Complete reset frame pair.
 * @param[in,out] context Open `jg_packet_output` instance.
 *
 * @return 0 when both frames were sent.
 * @return A negative errno-style validation or socket error otherwise.
 *
 * @thread_safety Exactly one packet worker may use an output socket.
 *
 * @side_effects Transmits raw Ethernet frames on both configured interfaces.
 */
int jg_packet_output_send_tcp_resets(const struct jg_tcp_reset_pair *resets,
                                     void *context);

/**
 * @brief Send one synthetic frame toward the policy client.
 *
 * This signature can be registered directly as a data-plane frame sender.
 *
 * @param[in] frame Complete Ethernet frame.
 * @param[in] frame_size Number of frame bytes.
 * @param[in,out] context Open `jg_packet_output` instance.
 *
 * @return 0 when the complete frame was sent.
 * @return A negative errno-style validation or socket error otherwise.
 *
 * @thread_safety Exactly one packet worker may use an output socket.
 *
 * @side_effects Transmits one raw frame on the configured client interface.
 */
int jg_packet_output_send_client_frame(const uint8_t *frame,
                                       size_t frame_size,
                                       void *context);

/**
 * @brief Read a relaxed snapshot of raw output counters.
 *
 * @param[in] output Open packet output.
 * @param[out] stats Receives current counters.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 *
 * @thread_safety Safe while the packet worker transmits frames.
 */
int jg_packet_output_get_stats(const struct jg_packet_output *output,
                               struct jg_packet_output_stats *stats);

/**
 * @brief Close and release one stopped raw packet output.
 *
 * @param[in,out] output Output to release; null is accepted.
 *
 * @thread_safety The packet worker must no longer use the output.
 */
void jg_packet_output_close(struct jg_packet_output *output);

#endif
