/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>

#include <cmocka.h>

#include "packet_output.h"

int jg_test_packet_output(void);

/** @brief Verify raw output defaults and bounded validation. */
static void test_configuration(void **state)
{
    struct jg_packet_output_config config;
    struct jg_packet_output *output = NULL;

    (void)state;
    jg_packet_output_config_default(&config);
    assert_int_equal(config.client_interface_index, 0U);
    assert_int_equal(config.server_interface_index, 0U);
    assert_int_equal(config.send_buffer_size, JG_PACKET_OUTPUT_BUFFER_DEFAULT);
    assert_int_equal(jg_packet_output_config_validate(&config), -EINVAL);

    config.client_interface_index = 2U;
    config.server_interface_index = 3U;
    assert_int_equal(jg_packet_output_config_validate(&config), 0);
    config.server_interface_index = 2U;
    assert_int_equal(jg_packet_output_config_validate(&config), -EINVAL);
    config.server_interface_index = 3U;
    config.send_buffer_size = JG_PACKET_OUTPUT_BUFFER_MAX + 1U;
    assert_int_equal(jg_packet_output_config_validate(&config), -ERANGE);
    assert_int_equal(jg_packet_output_open(NULL, &output), -EINVAL);
    assert_null(output);
    assert_int_equal(jg_packet_output_open(&config, NULL), -EINVAL);
    jg_packet_output_config_default(NULL);
}

/** @brief Verify null-safe output operations without privileged sockets. */
static void test_operations(void **state)
{
    struct jg_tcp_reset_pair resets = {0};

    (void)state;
    assert_int_equal(jg_packet_output_send_tcp_resets(&resets, NULL), -EINVAL);
    assert_int_equal(jg_packet_output_send_tcp_resets(NULL, NULL), -EINVAL);
    assert_int_equal(jg_packet_output_send_client_frame(NULL, 0U, NULL),
                     -EINVAL);
    assert_int_equal(jg_packet_output_get_stats(NULL, NULL), -EINVAL);
    jg_packet_output_close(NULL);
}

/** @brief Run the bounded raw packet output test group. */
int jg_test_packet_output(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_configuration),
        cmocka_unit_test(test_operations),
    };

    return cmocka_run_group_tests_name("packet output", tests, NULL, NULL);
}
