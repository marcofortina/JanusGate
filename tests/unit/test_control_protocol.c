/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <string.h>

#include <cmocka.h>

#include "control_protocol.h"

int jg_test_control_protocol(void);

/** Exact bytes in the legacy version-one status representation. */
#define STATUS_VERSION_ONE_WIRE_SIZE (8U + 33U * sizeof(uint64_t))

/** @brief Construct distinctive values across every status counter group. */
static struct jg_daemon_runtime_stats make_status(void)
{
    struct jg_daemon_runtime_stats stats = {
        .policy_generation = 1U,
        .queues =
            {
                .packets = 2U,
                .accepted = 3U,
                .dropped = 4U,
                .malformed = 5U,
                .overflows = 6U,
                .message_errors = 7U,
                .verdict_errors = 8U,
            },
        .dataplane =
            {
                .packets = 9U,
                .accepted = 10U,
                .blocked = 11U,
                .malformed = 12U,
                .fragments = 13U,
                .streams = 14U,
                .tcp_resets = 15U,
                .internal_errors = 16U,
                .sni_inspected = 34U,
                .sni_encrypted_or_unavailable = 35U,
            },
        .fragments =
            {
                .stored = 17U,
                .duplicates = 18U,
                .completed = 19U,
                .malformed = 20U,
                .overlaps = 21U,
                .exhausted = 22U,
                .timeouts = 23U,
            },
        .tcp_streams =
            {
                .buffered = 24U,
                .duplicates = 25U,
                .messages = 26U,
                .closed = 27U,
                .malformed = 28U,
                .conflicts = 29U,
                .exhausted = 30U,
                .timeouts = 31U,
            },
        .output =
            {
                .sent = 32U,
                .errors = 33U,
            },
    };

    return stats;
}

/** @brief Verify canonical daemon status encoding and decoding. */
static void test_round_trip(void **state)
{
    uint8_t wire[JG_DAEMON_STATUS_WIRE_SIZE];
    uint8_t repeated[JG_DAEMON_STATUS_WIRE_SIZE];
    struct jg_daemon_runtime_stats expected = make_status();
    struct jg_daemon_runtime_stats decoded;
    size_t wire_size = 0U;
    size_t repeated_size = 0U;

    (void)state;
    assert_int_equal(
        jg_daemon_status_encode(&expected, wire, sizeof(wire), &wire_size), 0);
    assert_int_equal(wire_size, sizeof(wire));
    assert_int_equal(jg_daemon_status_decode(wire, wire_size, &decoded), 0);
    assert_int_equal(decoded.policy_generation, 1U);
    assert_int_equal(decoded.queues.verdict_errors, 8U);
    assert_int_equal(decoded.dataplane.tcp_resets, 15U);
    assert_int_equal(decoded.dataplane.sni_inspected, 34U);
    assert_int_equal(decoded.dataplane.sni_encrypted_or_unavailable, 35U);
    assert_int_equal(decoded.fragments.timeouts, 23U);
    assert_int_equal(decoded.tcp_streams.timeouts, 31U);
    assert_int_equal(decoded.output.errors, 33U);
    assert_int_equal(jg_daemon_status_encode(&decoded, repeated,
                                             sizeof(repeated), &repeated_size),
                     0);
    assert_int_equal(repeated_size, wire_size);
    assert_memory_equal(repeated, wire, wire_size);
}

/** @brief Verify backward decoding of a version-one status body. */
static void test_version_one_decode(void **state)
{
    uint8_t current[JG_DAEMON_STATUS_WIRE_SIZE];
    uint8_t legacy[STATUS_VERSION_ONE_WIRE_SIZE];
    struct jg_daemon_runtime_stats stats = make_status();
    struct jg_daemon_runtime_stats decoded;
    size_t current_size = 0U;

    (void)state;
    assert_int_equal(jg_daemon_status_encode(&stats, current, sizeof(current),
                                             &current_size),
                     0);
    (void)memcpy(legacy, current, sizeof(legacy));
    legacy[1U] = 1U;
    legacy[7U] = 33U;
    assert_int_equal(jg_daemon_status_decode(legacy, sizeof(legacy), &decoded),
                     0);
    assert_int_equal(decoded.output.errors, 33U);
    assert_int_equal(decoded.dataplane.sni_inspected, 0U);
    assert_int_equal(decoded.dataplane.sni_encrypted_or_unavailable, 0U);
}

/** @brief Verify rejection of malformed status bodies and arguments. */
static void test_errors(void **state)
{
    uint8_t wire[JG_DAEMON_STATUS_WIRE_SIZE];
    struct jg_daemon_runtime_stats stats = make_status();
    size_t wire_size = 0U;

    (void)state;
    assert_int_equal(
        jg_daemon_status_encode(&stats, wire, sizeof(wire), &wire_size), 0);
    assert_int_equal(
        jg_daemon_status_encode(NULL, wire, sizeof(wire), &wire_size), -EINVAL);
    assert_int_equal(
        jg_daemon_status_encode(&stats, wire, sizeof(wire) - 1U, &wire_size),
        -ENOSPC);
    assert_int_equal(jg_daemon_status_decode(wire, sizeof(wire) - 1U, &stats),
                     -EMSGSIZE);
    wire[1U] = 3U;
    assert_int_equal(jg_daemon_status_decode(wire, sizeof(wire), &stats),
                     -EPROTONOSUPPORT);
    wire[1U] = 2U;
    wire[3U] = 1U;
    assert_int_equal(jg_daemon_status_decode(wire, sizeof(wire), &stats),
                     -EPROTO);
    assert_int_equal(jg_daemon_status_decode(NULL, sizeof(wire), &stats),
                     -EINVAL);
}

/** @brief Run the daemon control-protocol test group. */
int jg_test_control_protocol(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_round_trip),
        cmocka_unit_test(test_version_one_decode),
        cmocka_unit_test(test_errors),
    };

    return cmocka_run_group_tests_name("control protocol", tests, NULL, NULL);
}
