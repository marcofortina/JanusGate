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

#include "janusgate/network.h"

int jg_test_network(void);

/** @brief Build one valid inline-network configuration. */
static struct jg_network_config test_config(void)
{
    const struct jg_network_config config = {
        .bridge = "br-data",
        .ingress = "eth0",
        .egress = "eth1",
        .management = "eth2",
        .bridge_mtu = 1500U,
        .queue_first = 100U,
        .queue_count = 4U,
        .queue_length = 4096U,
        .failure_mode = JG_NETWORK_FAIL_OPEN,
        .stp = false,
        .multicast_snooping = true,
        .queue_cpu_fanout = true,
    };

    return config;
}

/** @brief Verify interface separation and bounded numeric invariants. */
static void test_validation(void **state)
{
    struct jg_network_config config = test_config();

    (void)state;
    assert_int_equal(jg_network_config_validate(&config), 0);

    (void)memcpy(config.management, config.ingress, sizeof(config.management));
    assert_int_equal(jg_network_config_validate(&config), -EINVAL);

    config = test_config();
    config.bridge[2] = '/';
    assert_int_equal(jg_network_config_validate(&config), -EINVAL);

    config = test_config();
    config.bridge_mtu = 1279U;
    assert_int_equal(jg_network_config_validate(&config), -ERANGE);

    config = test_config();
    config.queue_first = UINT16_MAX;
    config.queue_count = 2U;
    assert_int_equal(jg_network_config_validate(&config), -ERANGE);

    config = test_config();
    config.queue_count = JG_NETWORK_QUEUE_COUNT_MAX + 1U;
    assert_int_equal(jg_network_config_validate(&config), -ERANGE);

    config = test_config();
    config.queue_length = JG_NETWORK_QUEUE_LENGTH_MAX + 1U;
    assert_int_equal(jg_network_config_validate(&config), -ERANGE);
}

/** @brief Verify canonical architecture-independent configuration encoding. */
static void test_round_trip(void **state)
{
    const struct jg_network_config config = test_config();
    uint8_t encoded[JG_NETWORK_CONFIG_WIRE_SIZE] = {0U};
    struct jg_network_config decoded;
    size_t encoded_size = 0U;

    (void)state;
    assert_int_equal(jg_network_config_encode(&config, encoded, sizeof(encoded),
                                              &encoded_size),
                     0);
    assert_int_equal(encoded_size, JG_NETWORK_CONFIG_WIRE_SIZE);
    assert_int_equal(encoded[1], 1U);
    assert_int_equal(encoded[3], 6U);
    assert_int_equal(encoded[13], 0U);
    assert_int_equal(encoded[14], 5U);
    assert_int_equal(encoded[15], 220U);
    assert_memory_equal(encoded + 20U, "br-data", 7U);

    assert_int_equal(
        jg_network_config_decode(encoded, sizeof(encoded), &decoded), 0);
    assert_string_equal(decoded.bridge, config.bridge);
    assert_string_equal(decoded.ingress, config.ingress);
    assert_string_equal(decoded.egress, config.egress);
    assert_string_equal(decoded.management, config.management);
    assert_int_equal(decoded.bridge_mtu, config.bridge_mtu);
    assert_int_equal(decoded.queue_first, config.queue_first);
    assert_int_equal(decoded.queue_count, config.queue_count);
    assert_int_equal(decoded.queue_length, config.queue_length);
    assert_int_equal(decoded.failure_mode, config.failure_mode);
    assert_int_equal(decoded.stp, config.stp);
    assert_int_equal(decoded.multicast_snooping, config.multicast_snooping);
    assert_int_equal(decoded.queue_cpu_fanout, config.queue_cpu_fanout);
}

/** @brief Verify rejection of malformed or noncanonical encoded bodies. */
static void test_decode_errors(void **state)
{
    const struct jg_network_config config = test_config();
    uint8_t encoded[JG_NETWORK_CONFIG_WIRE_SIZE] = {0U};
    struct jg_network_config decoded;
    size_t encoded_size = 0U;

    (void)state;
    assert_int_equal(jg_network_config_encode(&config, encoded, sizeof(encoded),
                                              &encoded_size),
                     0);

    encoded[1] = 2U;
    assert_int_equal(jg_network_config_decode(encoded, encoded_size, &decoded),
                     -EPROTONOSUPPORT);
    encoded[1] = 1U;

    encoded[3] |= 0x80U;
    assert_int_equal(jg_network_config_decode(encoded, encoded_size, &decoded),
                     -EPROTO);
    encoded[3] &= 0x7fU;

    encoded[11] = 1U;
    assert_int_equal(jg_network_config_decode(encoded, encoded_size, &decoded),
                     -EPROTO);
    encoded[11] = 0U;

    (void)memset(encoded + 20U, 'x', JG_INTERFACE_NAME_MAX + 1U);
    assert_int_equal(jg_network_config_decode(encoded, encoded_size, &decoded),
                     -EPROTO);

    assert_int_equal(
        jg_network_config_decode(encoded, encoded_size - 1U, &decoded),
        -EMSGSIZE);
}

/** @brief Verify encoder argument and destination validation. */
static void test_encode_errors(void **state)
{
    const struct jg_network_config config = test_config();
    uint8_t encoded[JG_NETWORK_CONFIG_WIRE_SIZE] = {0U};
    size_t encoded_size = 0U;

    (void)state;
    assert_int_equal(jg_network_config_encode(
                         &config, encoded, sizeof(encoded) - 1U, &encoded_size),
                     -ENOSPC);
    assert_int_equal(
        jg_network_config_encode(&config, NULL, sizeof(encoded), &encoded_size),
        -EINVAL);
}

/** @brief Verify canonical helper-state encoding and absent slots. */
static void test_state_round_trip(void **state)
{
    const struct jg_network_config config = test_config();
    struct jg_network_state expected = {
        .confirmed = config,
        .pending_config = config,
        .confirmation_seconds_remaining = 73U,
        .has_confirmed = true,
        .pending = true,
    };
    struct jg_network_state decoded;
    uint8_t encoded[JG_NETWORK_STATE_WIRE_SIZE];
    uint8_t zero_slots[JG_NETWORK_STATE_WIRE_SIZE - 8U] = {0U};
    size_t encoded_size = 0U;

    (void)state;
    expected.pending_config.queue_length = 8192U;
    assert_int_equal(jg_network_state_encode(&expected, encoded,
                                             sizeof(encoded), &encoded_size),
                     0);
    assert_int_equal(encoded_size, sizeof(encoded));
    assert_int_equal(jg_network_state_decode(encoded, encoded_size, &decoded),
                     0);
    assert_true(decoded.has_confirmed);
    assert_true(decoded.pending);
    assert_int_equal(decoded.confirmation_seconds_remaining, 73U);
    assert_string_equal(decoded.confirmed.bridge, config.bridge);
    assert_int_equal(decoded.pending_config.queue_length, 8192U);

    (void)memset(&expected, 0, sizeof(expected));
    assert_int_equal(jg_network_state_encode(&expected, encoded,
                                             sizeof(encoded), &encoded_size),
                     0);
    assert_memory_equal(encoded + 8U, zero_slots, sizeof(zero_slots));
    assert_int_equal(jg_network_state_decode(encoded, encoded_size, &decoded),
                     0);
    assert_false(decoded.has_confirmed);
    assert_false(decoded.pending);
}

/** @brief Verify malformed or noncanonical helper-state rejection. */
static void test_state_errors(void **state)
{
    const struct jg_network_state empty = {0};
    struct jg_network_state decoded;
    uint8_t encoded[JG_NETWORK_STATE_WIRE_SIZE];
    size_t encoded_size = 0U;

    (void)state;
    assert_int_equal(jg_network_state_encode(&empty, encoded, sizeof(encoded),
                                             &encoded_size),
                     0);
    encoded[3U] = 0x80U;
    assert_int_equal(jg_network_state_decode(encoded, encoded_size, &decoded),
                     -EPROTO);
    encoded[3U] = 0U;
    encoded[8U] = 1U;
    assert_int_equal(jg_network_state_decode(encoded, encoded_size, &decoded),
                     -EPROTO);
    assert_int_equal(
        jg_network_state_decode(encoded, encoded_size - 1U, &decoded),
        -EMSGSIZE);
    assert_int_equal(jg_network_state_encode(
                         &empty, encoded, sizeof(encoded) - 1U, &encoded_size),
                     -ENOSPC);
}

/** @brief Run the inline-network configuration test group. */
int jg_test_network(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_validation),
        cmocka_unit_test(test_round_trip),
        cmocka_unit_test(test_decode_errors),
        cmocka_unit_test(test_encode_errors),
        cmocka_unit_test(test_state_round_trip),
        cmocka_unit_test(test_state_errors),
    };

    return cmocka_run_group_tests_name("network", tests, NULL, NULL);
}
