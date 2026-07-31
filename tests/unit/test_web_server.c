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

#include "web_gateway.h"
#include "web_server.h"

int jg_test_web_server(void);

/** @brief Verify secure scalar HTTPS configuration bounds. */
static void test_web_config_validation(void **state)
{
    struct jg_web_config config;

    (void)state;
    jg_web_config_default(&config);
    assert_int_equal(jg_web_config_validate(&config), 0);
    assert_int_equal(config.api_port, JG_WEB_DEFAULT_API_PORT);
    assert_string_equal(config.client_ca_path,
                        JG_CERTIFICATE_CLIENT_CA_DEFAULT_PATH);
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
    config.api_port = config.port;
    assert_int_equal(jg_web_config_validate(&config), -EINVAL);
    config.api_port = JG_WEB_DEFAULT_API_PORT;
    config.client_ca_path = "relative";
    assert_int_equal(jg_web_config_validate(&config), -EINVAL);
    config.client_ca_path = JG_CERTIFICATE_CLIENT_CA_DEFAULT_PATH;
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
    assert_int_equal(
        jg_web_build_listener(&config, config.port, listener, sizeof(listener)),
        0);
#if defined(__OpenBSD__)
    assert_string_equal(listener, "192.168.77.1:8443s");
#else
    assert_string_equal(listener, "192.168.77.1:443s");
#endif
    config.listen_address = "2001:db8::1";
    config.port = 8443U;
    assert_int_equal(
        jg_web_build_listener(&config, config.port, listener, sizeof(listener)),
        0);
    assert_string_equal(listener, "[2001:db8::1]:8443s");
    assert_int_equal(jg_web_build_listener(&config, config.api_port, listener,
                                           sizeof(listener)),
                     0);
    assert_string_equal(listener, "[2001:db8::1]:9443s");
    assert_int_equal(jg_web_build_listener(&config, config.port, listener, 4U),
                     -ENOSPC);
    assert_string_equal(listener, "[20");
}

/** @brief Verify strict JSON and Prometheus daemon response decoding. */
static void test_gateway_response_formats(void **state)
{
    static const uint8_t json_response[] =
        "{\"status\":200,\"body\":{\"ready\":true}}";
    static const uint8_t metrics_response[] =
        "{\"status\":200,"
        "\"content_type\":\"text/plain; version=0.0.4; charset=utf-8\","
        "\"text\":\"# TYPE janusgate_ready gauge\\n"
        "janusgate_ready 1\\n\"}";
    static const uint8_t invalid_response[] =
        "{\"status\":200,\"content_type\":\"text/html\","
        "\"text\":\"invalid\"}";
    struct jg_web_gateway_response response = {0};

    (void)state;
    assert_int_equal(jg_web_gateway_decode_response(
                         json_response, sizeof(json_response) - 1U, &response),
                     0);
    assert_int_equal(response.status, 200);
    assert_string_equal(response.content_type,
                        "application/json; charset=utf-8");
    assert_string_equal(response.body, "{\"ready\":true}");
    jg_web_gateway_response_clear(&response);

    assert_int_equal(
        jg_web_gateway_decode_response(
            metrics_response, sizeof(metrics_response) - 1U, &response),
        0);
    assert_int_equal(response.status, 200);
    assert_string_equal(response.content_type,
                        "text/plain; version=0.0.4; charset=utf-8");
    assert_string_equal(response.body, "# TYPE janusgate_ready gauge\n"
                                       "janusgate_ready 1\n");
    jg_web_gateway_response_clear(&response);

    assert_int_equal(
        jg_web_gateway_decode_response(
            invalid_response, sizeof(invalid_response) - 1U, &response),
        -EPROTO);
    jg_web_gateway_response_clear(&response);
}

/** @brief Run the HTTPS server configuration unit-test group. */
int jg_test_web_server(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_web_config_validation),
        cmocka_unit_test(test_web_listener),
        cmocka_unit_test(test_gateway_response_formats),
    };

    return cmocka_run_group_tests_name("web_server", tests, NULL, NULL);
}
