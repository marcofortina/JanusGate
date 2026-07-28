/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>

#include <cmocka.h>

#include "daemon_runtime.h"
#include "nfqueue.h"
#include "packet_output.h"

int jg_test_daemon_runtime(void);

/** @brief Verify conservative packet-runtime defaults and bounds. */
static void test_configuration(void **state)
{
    struct jg_daemon_runtime_config config;

    (void)state;
    jg_daemon_runtime_config_default(&config);
    assert_string_equal(config.database_path, JG_DAEMON_DATABASE_PATH);
    assert_int_equal(config.database_busy_timeout_ms, 5000U);
    assert_int_equal(config.queue_receive_buffer_size,
                     JG_NFQUEUE_RECEIVE_BUFFER_DEFAULT);
    assert_int_equal(config.packet_send_buffer_size,
                     JG_PACKET_OUTPUT_BUFFER_DEFAULT);
    assert_false(config.pin_workers);
    assert_int_equal(jg_daemon_runtime_config_validate(&config), 0);

    config.database_path = "relative.db";
    assert_int_equal(jg_daemon_runtime_config_validate(&config), -EINVAL);
    config.database_path = JG_DAEMON_DATABASE_PATH;
    config.queue_receive_buffer_size = JG_NFQUEUE_RECEIVE_BUFFER_MAX + 1U;
    assert_int_equal(jg_daemon_runtime_config_validate(&config), -ERANGE);
    config.queue_receive_buffer_size = JG_NFQUEUE_RECEIVE_BUFFER_DEFAULT;
    config.packet_send_buffer_size = JG_PACKET_OUTPUT_BUFFER_MAX + 1U;
    assert_int_equal(jg_daemon_runtime_config_validate(&config), -ERANGE);
    jg_daemon_runtime_config_default(NULL);
}

/** @brief Verify null-safe runtime control without privileged resources. */
static void test_operations(void **state)
{
    struct jg_daemon_runtime_config config;
    struct jg_daemon_runtime *runtime = NULL;
    uint64_t generation = 0U;

    (void)state;
    jg_daemon_runtime_config_default(&config);
    assert_int_equal(jg_daemon_runtime_start(&config, NULL), -EINVAL);
    assert_int_equal(jg_daemon_runtime_start(NULL, &runtime), -EINVAL);
    assert_null(runtime);
    assert_int_equal(jg_daemon_runtime_request_stop(NULL), -EINVAL);
    assert_int_equal(jg_daemon_runtime_wait(NULL), -EINVAL);
    assert_int_equal(jg_daemon_runtime_join(NULL), -EINVAL);
    assert_int_equal(jg_daemon_runtime_reload_policy(NULL), -EINVAL);
    assert_int_equal(jg_daemon_runtime_get_policy_generation(NULL, &generation),
                     -EINVAL);
    assert_int_equal(jg_daemon_runtime_get_policy_generation(runtime, NULL),
                     -EINVAL);
    jg_daemon_runtime_destroy(NULL);
}

/** @brief Run the production packet-runtime test group. */
int jg_test_daemon_runtime(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_configuration),
        cmocka_unit_test(test_operations),
    };

    return cmocka_run_group_tests_name("daemon runtime", tests, NULL, NULL);
}
