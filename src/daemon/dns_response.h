/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file dns_response.h
 * @brief Bounded synthetic UDP DNS policy responses.
 */

#ifndef JANUSGATE_DAEMON_DNS_RESPONSE_H
#define JANUSGATE_DAEMON_DNS_RESPONSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/packet.h"

/** Maximum complete synthetic DNS response frame size. */
#define JG_DNS_RESPONSE_FRAME_MAX 8192U

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
void jg_dns_response_config_default(struct jg_dns_response_config *config);

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
int jg_dns_response_config_validate(
    const struct jg_dns_response_config *config);

/**
 * @brief Build one client-facing response for a blocked UDP DNS query.
 *
 * The link envelope is preserved, endpoint addresses and ports are reversed,
 * and only the validated question section is copied. DROP produces no frame.
 * Sinkhole mode adds one A or AAAA answer when the selected question and
 * configured address family are compatible.
 *
 * @param[in] packet Parsed complete UDP DNS packet.
 * @param[in] query Complete DNS message from the UDP payload.
 * @param[in] query_size Number of DNS message bytes.
 * @param[in] question_index Question which triggered the block.
 * @param[in] config Validated response configuration.
 * @param[out] output Destination frame buffer.
 * @param[in] output_size Available output bytes.
 * @param[out] response_size Receives the frame size, or zero for DROP.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid packet, query, configuration, or arguments.
 * @return -ENOSPC when the output buffer is too small.
 * @return -EMSGSIZE when the synthetic IP or UDP packet is too large.
 *
 * @thread_safety This function is reentrant.
 */
int jg_dns_response_build(const struct jg_packet_view *packet,
                          const uint8_t *query,
                          size_t query_size,
                          size_t question_index,
                          const struct jg_dns_response_config *config,
                          uint8_t *output,
                          size_t output_size,
                          size_t *response_size);

#endif
