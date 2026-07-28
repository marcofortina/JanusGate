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

    (void)memcpy(frame, blocked_query, sizeof(frame));
    (void)memcpy(frame + 55U, "allowed", 7U);
    assert_int_equal(
        jg_dataplane_evaluate(frame, sizeof(frame), NULL, snapshot, &result),
        0);
    assert_int_equal(result.verdict, JG_NFQUEUE_ACCEPT);
    assert_int_equal(result.reason, JG_DATAPLANE_POLICY_ALLOW);
    assert_int_equal(result.policy.effect, JG_POLICY_ALLOW);
    assert_false(result.policy.matched);

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

    (void)memcpy(frame, blocked_query, sizeof(frame));
    frame[20U] = 0x20U;
    assert_int_equal(
        jg_dataplane_evaluate(frame, sizeof(frame), NULL, snapshot, &result),
        0);
    assert_int_equal(result.verdict, JG_NFQUEUE_ACCEPT);
    assert_int_equal(result.reason, JG_DATAPLANE_FRAGMENT_PENDING);
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
}

/** @brief Run the stateless data-plane test group. */
int jg_test_dataplane(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_udp_dns_policy),
        cmocka_unit_test(test_multiple_questions),
        cmocka_unit_test(test_deferred_and_pass),
        cmocka_unit_test(test_arguments),
    };

    return cmocka_run_group_tests_name("dataplane", tests, NULL, NULL);
}
