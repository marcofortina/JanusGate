/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file dns_policy.h
 * @brief Persistent blocked-query response policy.
 */

#ifndef JANUSGATE_DNS_POLICY_H
#define JANUSGATE_DNS_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Exact version-one response-policy body size. */
#define JG_DNS_RESPONSE_CONFIG_WIRE_SIZE 32U

/**
 * @brief Action applied to a blocked UDP DNS query.
 */
enum jg_dns_block_action {
    /** Silently discard the original query. */
    JG_DNS_BLOCK_DROP = 1,
    /** Return an explicit policy refusal. */
    JG_DNS_BLOCK_REFUSED = 2,
    /** Return a synthetic nonexistent-domain result. */
    JG_DNS_BLOCK_NXDOMAIN = 3,
    /** Return a configured address for compatible questions. */
    JG_DNS_BLOCK_SINKHOLE = 4
};

/**
 * @brief Configuration for synthetic blocked-query responses.
 */
struct jg_dns_response_config {
    /** Selected blocked-query action. */
    enum jg_dns_block_action action;
    /** Whether an IPv4 sinkhole address is configured. */
    bool has_ipv4_sinkhole;
    /** Whether an IPv6 sinkhole address is configured. */
    bool has_ipv6_sinkhole;
    /** Whether synthetic IPv4 packets include a UDP checksum. */
    bool checksum_ipv4_udp;
    /** IPv4 sinkhole address in network byte order. */
    uint8_t ipv4_sinkhole[4U];
    /** IPv6 sinkhole address in network byte order. */
    uint8_t ipv6_sinkhole[16U];
    /** Sinkhole answer TTL in seconds. */
    uint32_t sinkhole_ttl;
};

/**
 * @brief Initialize conservative blocked-query response defaults.
 *
 * The default action is REFUSED. No sinkhole address is enabled.
 *
 * @param[out] config Configuration to initialize; null is ignored.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC void jg_dns_response_config_default(
    struct jg_dns_response_config *config);

/**
 * @brief Validate blocked-query response configuration.
 *
 * @param[in] config Configuration to validate.
 *
 * @return 0 on success.
 * @return -EINVAL for an unknown action or unusable sinkhole configuration.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_dns_response_config_validate(
    const struct jg_dns_response_config *config);

/**
 * @brief Encode one validated response policy for persistent storage.
 *
 * @param[in] config Configuration to encode.
 * @param[out] output Destination buffer.
 * @param[in] output_size Available destination bytes.
 * @param[out] encoded_size Receives @ref JG_DNS_RESPONSE_CONFIG_WIRE_SIZE.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or configuration.
 * @return -ENOSPC when the destination is too small.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_dns_response_config_encode(
    const struct jg_dns_response_config *config,
    uint8_t *output,
    size_t output_size,
    size_t *encoded_size);

/**
 * @brief Decode one canonical persistent response policy.
 *
 * @param[in] data Exact version-one policy body.
 * @param[in] data_size Number of bytes in @p data.
 * @param[out] config Receives the validated configuration.
 *
 * @return 0 on success.
 * @return -EINVAL for null arguments or invalid decoded configuration.
 * @return -EMSGSIZE unless @p data_size is exact.
 * @return -EPROTONOSUPPORT for an unsupported body version.
 * @return -EPROTO for noncanonical flags or reserved bytes.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_dns_response_config_decode(
    const uint8_t *data,
    size_t data_size,
    struct jg_dns_response_config *config);

#endif
