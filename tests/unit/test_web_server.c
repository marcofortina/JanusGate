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

#include "web_server.h"

int jg_test_web_server(void);

/** @brief Verify secure scalar HTTPS configuration bounds. */
static void test_web_config_validation(void **state)
{
    struct jg_web_config config;

    (void)state;
    jg_web_config_default(&config);
    assert_int_equal(jg_web_config_validate(&config), 0);
    config.listen_address = "0.0.0.0";
    assert_int_equal(jg_web_config_validate(&config), -EINVAL);
    config.listen_address = "::";
    assert_int_equal(jg_web_config_validate(&config), -EINVAL);
    config.listen_address = "192.168.77.1";
    config.web_root = "relative";
    assert_int_equal(jg_web_config_validate(&config), -EINVAL);
    config.web_root = JG_WEB_DEFAULT_ROOT;
    config.control_socket_path = "relative";
    assert_int_equal(jg_web_config_validate(&config), -EINVAL);
    config.control_socket_path = JG_CONTROL_SOCKET_PATH;
    config.worker_count = 1U;
    assert_int_equal(jg_web_config_validate(&config), -ERANGE);
}

/** @brief Verify exact IPv4 and IPv6 TLS listener expressions. */
static void test_web_listener(void **state)
{
    struct jg_web_config config;
    char listener[128U];

    (void)state;
    jg_web_config_default(&config);
    assert_int_equal(jg_web_build_listener(&config, listener, sizeof(listener)),
                     0);
    assert_string_equal(listener, "192.168.77.1:443s");
    config.listen_address = "2001:db8::1";
    config.port = 8443U;
    assert_int_equal(jg_web_build_listener(&config, listener, sizeof(listener)),
                     0);
    assert_string_equal(listener, "[2001:db8::1]:8443s");
    assert_int_equal(jg_web_build_listener(&config, listener, 4U), -ENOSPC);
    assert_string_equal(listener, "[20");
}

/** @brief Run the HTTPS server configuration unit-test group. */
int jg_test_web_server(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_web_config_validation),
        cmocka_unit_test(test_web_listener),
    };

    return cmocka_run_group_tests_name("web_server", tests, NULL, NULL);
}
