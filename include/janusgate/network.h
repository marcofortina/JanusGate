/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file network.h
 * @brief Validated inline-network configuration and stable IPC encoding.
 *
 * Configuration objects contain no owned pointers and may be copied by value.
 * Encoded representations use fixed-width network-byte-order fields and
 * canonical null-padded interface names.
 *
 * @thread_safety Every function is reentrant and accesses only caller-owned
 * storage.
 *
 * @error_handling Functions return zero on success and negative errno-style
 * values for invalid configurations, malformed representations, or
 * insufficient output storage.
 */

#ifndef JANUSGATE_NETWORK_H
#define JANUSGATE_NETWORK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Maximum supported interface-name bytes excluding the null terminator. */
#define JG_INTERFACE_NAME_MAX 15U

/** Exact version-one network-configuration body size. */
#define JG_NETWORK_CONFIG_WIRE_SIZE 84U

/** Exact version-one network-state body size. */
#define JG_NETWORK_STATE_WIRE_SIZE 176U

/** Largest accepted userspace queue length. */
#define JG_NETWORK_QUEUE_LENGTH_MAX 1048576U

/** Largest accepted number of balanced queues. */
#define JG_NETWORK_QUEUE_COUNT_MAX 64U

/**
 * @brief Behavior when the userspace policy queue is unavailable.
 */
enum jg_network_failure_mode {
    /** Permit selected traffic and report degraded enforcement. */
    JG_NETWORK_FAIL_OPEN = 1,
    /** Drop selected traffic until enforcement is restored. */
    JG_NETWORK_FAIL_CLOSED = 2
};

/**
 * @brief Complete bounded inline-network configuration.
 */
struct jg_network_config {
    /** JanusGate-owned addressless data bridge. */
    char bridge[JG_INTERFACE_NAME_MAX + 1U];
    /** First data interface attached to the bridge. */
    char ingress[JG_INTERFACE_NAME_MAX + 1U];
    /** Second data interface attached to the bridge. */
    char egress[JG_INTERFACE_NAME_MAX + 1U];
    /** Deployment-addressed interface kept separate from the data bridge. */
    char management[JG_INTERFACE_NAME_MAX + 1U];
    /** Bridge MTU in `[1280, 65535]`, or zero to use the port minimum. */
    uint32_t bridge_mtu;
    /** First native packet-queue number in a contiguous balanced range. */
    uint16_t queue_first;
    /** Queue count in `[1, JG_NETWORK_QUEUE_COUNT_MAX]`. */
    uint16_t queue_count;
    /** Maximum packets retained by each queue. */
    uint32_t queue_length;
    /** Queue-unavailable behavior. */
    enum jg_network_failure_mode failure_mode;
    /** Whether spanning-tree protocol is enabled on the data bridge. */
    bool stp;
    /** Whether multicast snooping is enabled on the data bridge. */
    bool multicast_snooping;
    /** Whether the native packet filter distributes flows by current CPU. */
    bool queue_cpu_fanout;
};

/**
 * @brief Confirmed and optional pending helper network state.
 */
struct jg_network_state {
    /** Last configuration explicitly confirmed by the daemon. */
    struct jg_network_config confirmed;
    /** Configuration waiting for connectivity confirmation. */
    struct jg_network_config pending_config;
    /** Whole seconds remaining before automatic rollback. */
    uint32_t confirmation_seconds_remaining;
    /** Whether @ref confirmed contains a known configuration. */
    bool has_confirmed;
    /** Whether @ref pending_config contains an unconfirmed transaction. */
    bool pending;
};

/**
 * @brief Validate a complete proposed inline-network configuration.
 *
 * Interface names must be distinct, null-terminated, start with an
 * alphanumeric byte, and contain only ASCII alphanumeric bytes plus `_`, `-`,
 * and `.`. The queue range must fit within the native 16-bit namespace.
 *
 * @param[in] config Configuration to validate.
 *
 * @return 0 when every invariant is satisfied.
 * @return -EINVAL for null, malformed, duplicate, or unsupported values.
 * @return -ERANGE for an unsafe MTU, queue count, queue length, or queue range.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_network_config_validate(
    const struct jg_network_config *config);

/**
 * @brief Encode a validated network configuration for IPC.
 *
 * @param[in] config Configuration to encode.
 * @param[out] output Destination buffer.
 * @param[in] output_size Available destination bytes.
 * @param[out] encoded_size Receives @ref JG_NETWORK_CONFIG_WIRE_SIZE.
 *
 * @return 0 on success.
 * @return -EINVAL or -ERANGE when @p config is invalid.
 * @return -ENOSPC when @p output is too small.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Writes the canonical fixed-size representation on success.
 */
JG_PUBLIC int jg_network_config_encode(const struct jg_network_config *config,
                                       uint8_t *output,
                                       size_t output_size,
                                       size_t *encoded_size);

/**
 * @brief Decode an exact canonical network configuration from IPC.
 *
 * @param[in] data Exact version-one configuration body.
 * @param[in] data_size Number of bytes in @p data.
 * @param[out] config Receives the validated configuration.
 *
 * @return 0 on success.
 * @return -EINVAL for null arguments or invalid relational configuration.
 * @return -EMSGSIZE unless @p data_size is exact.
 * @return -EPROTONOSUPPORT for an unsupported body version.
 * @return -EPROTO for noncanonical flags, reserved bytes, or names.
 * @return -ERANGE for an unsafe numeric configuration value.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_network_config_decode(const uint8_t *data,
                                       size_t data_size,
                                       struct jg_network_config *config);

/**
 * @brief Encode canonical confirmed and pending helper state.
 *
 * Absent configuration slots are encoded as zero bytes. A non-pending state
 * must report zero confirmation seconds.
 *
 * @param[in] state Complete helper state.
 * @param[out] output Destination buffer.
 * @param[in] output_size Available destination bytes.
 * @param[out] encoded_size Receives @ref JG_NETWORK_STATE_WIRE_SIZE.
 *
 * @return 0 on success.
 * @return -EINVAL or -ERANGE for invalid state.
 * @return -ENOSPC when @p output is too small.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_network_state_encode(const struct jg_network_state *state,
                                      uint8_t *output,
                                      size_t output_size,
                                      size_t *encoded_size);

/**
 * @brief Decode one exact canonical helper network state.
 *
 * @param[in] data Exact version-one state body.
 * @param[in] data_size Number of bytes in @p data.
 * @param[out] state Receives validated helper state.
 *
 * @return 0 on success.
 * @return -EINVAL for null arguments or invalid state relationships.
 * @return -EMSGSIZE unless @p data_size is exact.
 * @return -EPROTONOSUPPORT for an unsupported body version.
 * @return -EPROTO for noncanonical flags, reserved data, or absent slots.
 * @return -ERANGE for an unsafe embedded configuration.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_network_state_decode(const uint8_t *data,
                                      size_t data_size,
                                      struct jg_network_state *state);

#endif
