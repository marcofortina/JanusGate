/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dataplane.h"
#include "dns_response.h"
#include "janusgate/dns_policy.h"
#include "janusgate/packet.h"
#include "janusgate/policy.h"

/** Complete Ethernet, IPv4, UDP, and `blocked.test` A query. */
static const uint8_t blocked_query[] = {
    0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xaaU,
    0xbbU, 0x08U, 0x00U, 0x45U, 0x00U, 0x00U, 0x3aU, 0x12U, 0x34U, 0x00U, 0x00U,
    0x40U, 0x11U, 0x00U, 0x00U, 0xc0U, 0x00U, 0x02U, 0x0aU, 0x08U, 0x08U, 0x08U,
    0x08U, 0x30U, 0x39U, 0x00U, 0x35U, 0x00U, 0x26U, 0x00U, 0x00U, 0xbeU, 0xefU,
    0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x07U,
    'b',   'l',   'o',   'c',   'k',   'e',   'd',   0x04U, 't',   'e',   's',
    't',   0x00U, 0x00U, 0x01U, 0x00U, 0x01U,
};

/** Build one immutable policy containing the selected ordered rules. */
static int build_policy(const struct jg_policy_rule_input *rules,
                        size_t rule_count,
                        struct jg_policy_snapshot **snapshot)
{
    return jg_policy_snapshot_build(rules, rule_count, 1U, snapshot);
}

/** Verify packet parsing, DNS decoding, and block-policy composition. */
static bool verify_block_pipeline(void)
{
    const struct jg_policy_rule_input rule = {
        .id = 1U,
        .domain = "blocked.test",
        .include_subdomains = true,
        .effect = JG_POLICY_BLOCK,
        .source = JG_POLICY_SOURCE_EXPLICIT,
        .scope = {.type = JG_POLICY_SCOPE_GLOBAL},
        .attribution = "integration",
    };
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_dataplane_result result;
    bool passed = false;

    if (build_policy(&rule, 1U, &snapshot) == 0 &&
        jg_dataplane_evaluate(blocked_query, sizeof(blocked_query), NULL,
                              snapshot, &result) == 0 &&
        result.packet_result == JG_PACKET_OK &&
        result.dns_result == JG_DNS_OK &&
        result.reason == JG_DATAPLANE_POLICY_BLOCK &&
        result.verdict == JG_NFQUEUE_DROP && result.policy.rule_id == 1U) {
        passed = true;
    }
    jg_policy_snapshot_destroy(snapshot);
    return passed;
}

/** Verify explicit allow precedence over an imported blocklist rule. */
static bool verify_allow_precedence(void)
{
    const struct jg_policy_rule_input rules[] = {
        {
            .id = 1U,
            .domain = "blocked.test",
            .include_subdomains = true,
            .effect = JG_POLICY_BLOCK,
            .source = JG_POLICY_SOURCE_BLOCKLIST,
            .scope = {.type = JG_POLICY_SCOPE_GLOBAL},
            .attribution = "integration",
        },
        {
            .id = 2U,
            .domain = "blocked.test",
            .include_subdomains = false,
            .effect = JG_POLICY_ALLOW,
            .source = JG_POLICY_SOURCE_EXPLICIT,
            .scope = {.type = JG_POLICY_SCOPE_GLOBAL},
            .attribution = "integration",
        },
    };
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_dataplane_result result;
    bool passed = false;

    if (build_policy(rules, sizeof(rules) / sizeof(rules[0U]), &snapshot) ==
            0 &&
        jg_dataplane_evaluate(blocked_query, sizeof(blocked_query), NULL,
                              snapshot, &result) == 0 &&
        result.reason == JG_DATAPLANE_POLICY_ALLOW &&
        result.verdict == JG_NFQUEUE_ACCEPT && result.policy.rule_id == 2U) {
        passed = true;
    }
    jg_policy_snapshot_destroy(snapshot);
    return passed;
}

/** Build and classify one selected synthetic blocked-query response. */
static bool verify_response_action(enum jg_dns_block_action action,
                                   uint8_t expected_code,
                                   uint16_t expected_answers)
{
    struct jg_dns_response_config config;
    struct jg_packet_view query_packet;
    struct jg_packet_view response_packet;
    uint8_t response[JG_DNS_RESPONSE_FRAME_MAX];
    size_t response_size = 0U;
    const uint8_t *query = NULL;

    if (jg_packet_parse(blocked_query, sizeof(blocked_query), NULL,
                        &query_packet) != JG_PACKET_OK) {
        return false;
    }
    query = blocked_query + query_packet.payload_offset;
    jg_dns_response_config_default(&config);
    config.action = action;
    if (action == JG_DNS_BLOCK_SINKHOLE) {
        config.has_ipv4_sinkhole = true;
        config.ipv4_sinkhole[0U] = 192U;
        config.ipv4_sinkhole[1U] = 0U;
        config.ipv4_sinkhole[2U] = 2U;
        config.ipv4_sinkhole[3U] = 1U;
    }
    if (jg_dns_response_build(&query_packet, query, query_packet.payload_size,
                              0U, &config, response, sizeof(response),
                              &response_size) != 0) {
        return false;
    }
    if (action == JG_DNS_BLOCK_DROP) {
        return response_size == 0U;
    }
    if (jg_packet_parse(response, response_size, NULL, &response_packet) !=
            JG_PACKET_OK ||
        response_packet.payload_size < 8U) {
        return false;
    }
    return (response[response_packet.payload_offset + 3U] & UINT8_C(0x0f)) ==
               expected_code &&
           response[response_packet.payload_offset + 6U] ==
               (uint8_t)(expected_answers >> 8U) &&
           response[response_packet.payload_offset + 7U] ==
               (uint8_t)expected_answers;
}

/** Verify every configured UDP block action through a complete packet path. */
static bool verify_response_actions(void)
{
    return verify_response_action(JG_DNS_BLOCK_DROP, 0U, 0U) &&
           verify_response_action(JG_DNS_BLOCK_REFUSED, 5U, 0U) &&
           verify_response_action(JG_DNS_BLOCK_NXDOMAIN, 3U, 0U) &&
           verify_response_action(JG_DNS_BLOCK_SINKHOLE, 0U, 1U);
}

/** @brief Run deterministic packet-policy integration scenarios. */
int main(void)
{
    if (!verify_block_pipeline()) {
        (void)fprintf(stderr, "integration: block pipeline failed\n");
        return 1;
    }
    if (!verify_allow_precedence()) {
        (void)fprintf(stderr, "integration: allow precedence failed\n");
        return 1;
    }
    if (!verify_response_actions()) {
        (void)fprintf(stderr, "integration: response actions failed\n");
        return 1;
    }
    return 0;
}
