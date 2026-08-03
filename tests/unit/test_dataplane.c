/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>

#include <cmocka.h>

#include "dataplane.h"
#include "janusgate/policy.h"

int jg_test_dataplane(void);

/** Complete Ethernet, IPv4, UDP, and `blocked.test` DNS query. */
static const uint8_t blocked_query[] = {
    0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xaaU,
    0xbbU, 0x08U, 0x00U, 0x45U, 0x00U, 0x00U, 0x3aU, 0x12U, 0x34U, 0x00U, 0x00U,
    0x40U, 0x11U, 0x00U, 0x00U, 0xc0U, 0x00U, 0x02U, 0x0aU, 0x08U, 0x08U, 0x08U,
    0x08U, 0x30U, 0x39U, 0x00U, 0x35U, 0x00U, 0x26U, 0x00U, 0x00U, 0xbeU, 0xefU,
    0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x07U,
    'b',   'l',   'o',   'c',   'k',   'e',   'd',   0x04U, 't',   'e',   's',
    't',   0x00U, 0x00U, 0x01U, 0x00U, 0x01U,
};

/** @brief Build one immutable snapshot blocking `blocked.test`. */
static int build_policy(struct jg_policy_snapshot **snapshot)
{
    const struct jg_policy_rule_input rule = {
        .id = 17U,
        .domain = "blocked.test",
        .include_subdomains = false,
        .effect = JG_POLICY_BLOCK,
        .source = JG_POLICY_SOURCE_EXPLICIT,
        .scope = {.type = JG_POLICY_SCOPE_GLOBAL},
        .attribution = "unit test",
    };

    return jg_policy_snapshot_build(&rule, 1U, 1U, snapshot);
}

/** @brief Build one immutable snapshot blocking visible TLS SNI only. */
static int build_sni_policy(struct jg_policy_snapshot **snapshot)
{
    const struct jg_policy_rule_input rule = {
        .id = 23U,
        .domain = "resolver.example",
        .include_subdomains = true,
        .effect = JG_POLICY_BLOCK,
        .source = JG_POLICY_SOURCE_EXPLICIT,
        .target = JG_POLICY_DOMAIN_TLS_SNI,
        .scope = {.type = JG_POLICY_SCOPE_GLOBAL},
        .attribution = "unit test",
    };

    return jg_policy_snapshot_build(&rule, 1U, 1U, snapshot);
}

/** @brief Build one immutable snapshot blocking UDP destination port 853. */
static int build_destination_policy(struct jg_policy_snapshot **snapshot)
{
    const struct jg_policy_destination_rule_input rule = {
        .id = 31U,
        .effect = JG_POLICY_BLOCK,
        .source = JG_POLICY_SOURCE_EXPLICIT,
        .transport = JG_POLICY_TRANSPORT_UDP,
        .has_port = true,
        .port = 853U,
        .scope = {.type = JG_POLICY_SCOPE_GLOBAL},
        .attribution = "unit test",
    };

    return jg_policy_snapshot_build_complete(NULL, 0U, &rule, 1U, 1U, snapshot);
}

/** @brief Verify block, default allow, and malformed DNS decisions. */
static void test_udp_dns_policy(void **state)
{
    uint8_t frame[sizeof(blocked_query)];
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_dataplane_result result;

    (void)state;
    assert_int_equal(build_policy(&snapshot), 0);
    assert_int_equal(jg_dataplane_evaluate(blocked_query, sizeof(blocked_query),
                                           NULL, snapshot, &result),
                     0);
    assert_int_equal(result.verdict, JG_NFQUEUE_DROP);
    assert_int_equal(result.reason, JG_DATAPLANE_POLICY_BLOCK);
    assert_int_equal(result.question_index, 0U);
    assert_int_equal(result.policy.rule_id, 17U);
    assert_int_equal(result.policy_path, JG_POLICY_STATS_DNS);
    assert_string_equal(result.inspected_domain, "blocked.test");
    assert_int_equal(result.query_type, 1U);
    assert_true(result.client.has_mac);
    assert_memory_equal(result.client.mac, blocked_query + 6U, 6U);
    assert_int_equal(result.client.address_family, JG_POLICY_ADDRESS_IPV4);
    assert_memory_equal(result.client.address, blocked_query + 26U, 4U);

    (void)memcpy(frame, blocked_query, sizeof(frame));
    (void)memcpy(frame + 55U, "allowed", 7U);
    assert_int_equal(
        jg_dataplane_evaluate(frame, sizeof(frame), NULL, snapshot, &result),
        0);
    assert_int_equal(result.verdict, JG_NFQUEUE_ACCEPT);
    assert_int_equal(result.reason, JG_DATAPLANE_POLICY_ALLOW);
    assert_int_equal(result.policy.effect, JG_POLICY_ALLOW);
    assert_false(result.policy.matched);
    assert_string_equal(result.inspected_domain, "allowed.test");

    assert_int_equal(jg_dataplane_evaluate(frame, sizeof(frame) - 1U, NULL,
                                           snapshot, &result),
                     0);
    assert_int_equal(result.verdict, JG_NFQUEUE_DROP);
    assert_int_equal(result.reason, JG_DATAPLANE_MALFORMED);
    jg_policy_snapshot_destroy(snapshot);
}

/** @brief Verify that any blocked question rejects a multi-question query. */
static void test_multiple_questions(void **state)
{
    uint8_t frame[sizeof(blocked_query) + 18U] = {0U};
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_dataplane_result result;

    (void)state;
    assert_int_equal(build_policy(&snapshot), 0);
    (void)memcpy(frame, blocked_query, sizeof(blocked_query));
    (void)memcpy(frame + 55U, "allowed", 7U);
    (void)memcpy(frame + sizeof(blocked_query), blocked_query + 54U, 18U);
    frame[17U] = 0x4cU;
    frame[39U] = 0x38U;
    frame[47U] = 0x02U;

    assert_int_equal(
        jg_dataplane_evaluate(frame, sizeof(frame), NULL, snapshot, &result),
        0);
    assert_int_equal(result.verdict, JG_NFQUEUE_DROP);
    assert_int_equal(result.reason, JG_DATAPLANE_POLICY_BLOCK);
    assert_int_equal(result.question_index, 1U);
    assert_int_equal(result.policy.rule_id, 17U);
    assert_string_equal(result.inspected_domain, "blocked.test");
    jg_policy_snapshot_destroy(snapshot);
}

/** @brief Verify explicit handling of non-IP and fragmented traffic. */
static void test_deferred_and_pass(void **state)
{
    uint8_t frame[sizeof(blocked_query)];
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_dataplane_result result;

    (void)state;
    assert_int_equal(build_policy(&snapshot), 0);
    (void)memcpy(frame, blocked_query, sizeof(frame));
    frame[12U] = 0x08U;
    frame[13U] = 0x06U;
    assert_int_equal(
        jg_dataplane_evaluate(frame, sizeof(frame), NULL, snapshot, &result),
        0);
    assert_int_equal(result.verdict, JG_NFQUEUE_ACCEPT);
    assert_int_equal(result.reason, JG_DATAPLANE_PASS);
    assert_int_equal(result.policy_path, 0);

    (void)memcpy(frame, blocked_query, sizeof(frame));
    frame[20U] = 0x20U;
    assert_int_equal(
        jg_dataplane_evaluate(frame, sizeof(frame), NULL, snapshot, &result),
        0);
    assert_int_equal(result.verdict, JG_NFQUEUE_ACCEPT);
    assert_int_equal(result.reason, JG_DATAPLANE_FRAGMENT_PENDING);
    assert_int_equal(result.policy_path, JG_POLICY_STATS_NETWORK_DESTINATION);
    jg_policy_snapshot_destroy(snapshot);
}

/** @brief Verify visible SNI policy decisions and selected port validation. */
static void test_visible_sni_policy(void **state)
{
    struct jg_packet_view packet = {
        .frame = blocked_query,
        .frame_size = sizeof(blocked_query),
        .ip_version = JG_IP_V4,
        .transport = JG_TRANSPORT_TCP,
        .ip_protocol = (uint8_t)JG_TRANSPORT_TCP,
        .destination_port = 443U,
        .address_size = 4U,
        .source_address = {192U, 0U, 2U, 10U},
    };
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_dataplane_result result;

    (void)state;
    assert_int_equal(build_sni_policy(&snapshot), 0);
    assert_int_equal(jg_dataplane_evaluate_visible_sni(
                         &packet, "api.resolver.example", snapshot, &result),
                     0);
    assert_int_equal(result.verdict, JG_NFQUEUE_DROP);
    assert_int_equal(result.reason, JG_DATAPLANE_POLICY_BLOCK);
    assert_int_equal(result.policy.rule_id, 23U);
    assert_int_equal(result.policy_path, JG_POLICY_STATS_TLS_SNI);
    assert_string_equal(result.inspected_domain, "api.resolver.example");
    assert_int_equal(result.query_type, 0U);

    assert_int_equal(jg_dataplane_evaluate_visible_sni(
                         &packet, "allowed.example", snapshot, &result),
                     0);
    assert_int_equal(result.verdict, JG_NFQUEUE_ACCEPT);
    assert_int_equal(result.reason, JG_DATAPLANE_POLICY_ALLOW);
    assert_string_equal(result.inspected_domain, "allowed.example");

    packet.destination_port = 53U;
    assert_int_equal(jg_dataplane_evaluate_visible_sni(
                         &packet, "resolver.example", snapshot, &result),
                     -EINVAL);
    jg_policy_snapshot_destroy(snapshot);
}

/** @brief Verify destination policy is enforced before payload inspection. */
static void test_destination_policy(void **state)
{
    uint8_t frame[sizeof(blocked_query)];
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_dataplane_result result;

    (void)state;
    assert_int_equal(build_destination_policy(&snapshot), 0);
    (void)memcpy(frame, blocked_query, sizeof(frame));
    frame[36U] = 0x03U;
    frame[37U] = 0x55U;

    assert_int_equal(
        jg_dataplane_evaluate(frame, sizeof(frame), NULL, snapshot, &result),
        0);
    assert_int_equal(result.verdict, JG_NFQUEUE_DROP);
    assert_int_equal(result.reason, JG_DATAPLANE_POLICY_BLOCK);
    assert_true(result.destination_policy.matched);
    assert_int_equal(result.destination_policy.rule_id, 31U);
    assert_false(result.policy.matched);
    assert_int_equal(result.policy_path, JG_POLICY_STATS_NETWORK_DESTINATION);
    assert_string_equal(result.inspected_domain, "");
    jg_policy_snapshot_destroy(snapshot);
}

/** @brief Verify argument rejection leaves a conservative result. */
static void test_arguments(void **state)
{
    struct jg_dataplane_result result;

    (void)state;
    assert_int_equal(jg_dataplane_evaluate(NULL, 0U, NULL, NULL, &result),
                     -EINVAL);
    assert_int_equal(result.verdict, JG_NFQUEUE_DROP);
    assert_int_equal(jg_dataplane_evaluate(NULL, 0U, NULL, NULL, NULL),
                     -EINVAL);
    assert_int_equal(
        jg_dataplane_evaluate_reassembled_udp(NULL, NULL, 0U, NULL, &result),
        -EINVAL);
    assert_int_equal(result.verdict, JG_NFQUEUE_DROP);
    assert_int_equal(
        jg_dataplane_evaluate_reassembled_udp(NULL, NULL, 0U, NULL, NULL),
        -EINVAL);
    assert_int_equal(
        jg_dataplane_evaluate_tcp_dns(NULL, NULL, 0U, NULL, &result), -EINVAL);
    assert_int_equal(result.verdict, JG_NFQUEUE_DROP);
    assert_int_equal(jg_dataplane_evaluate_tcp_dns(NULL, NULL, 0U, NULL, NULL),
                     -EINVAL);
    assert_int_equal(
        jg_dataplane_evaluate_visible_sni(NULL, NULL, NULL, &result), -EINVAL);
    assert_int_equal(jg_dataplane_evaluate_visible_sni(NULL, NULL, NULL, NULL),
                     -EINVAL);
}

/** @brief Run the stateless data-plane test group. */
int jg_test_dataplane(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_udp_dns_policy),
        cmocka_unit_test(test_multiple_questions),
        cmocka_unit_test(test_deferred_and_pass),
        cmocka_unit_test(test_visible_sni_policy),
        cmocka_unit_test(test_destination_policy),
        cmocka_unit_test(test_arguments),
    };

    return cmocka_run_group_tests_name("dataplane", tests, NULL, NULL);
}
