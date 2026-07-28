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

#include "client.h"

int jg_test_cli_client(void);

/** @brief Verify strict JSON and text management response decoding. */
static void test_response_decoding(void **state)
{
    static const char json_response[] =
        "{\"status\":200,\"body\":{\"ready\":true,\"count\":2}}";
    static const char text_response[] =
        "{\"status\":200,"
        "\"content_type\":\"text/plain; version=0.0.4; charset=utf-8\","
        "\"text\":\"janusgate_ready 1\\n\"}";
    static const char cookie_response[] =
        "{\"status\":200,\"body\":{},\"set_session\":\"invalid\"}";
    struct jg_cli_response response = {0};

    (void)state;
    assert_int_equal(jg_cli_response_decode(
                         json_response, sizeof(json_response) - 1U, &response),
                     0);
    assert_int_equal(response.status, 200);
    assert_string_equal(response.content_type,
                        "application/json; charset=utf-8");
    assert_string_equal(response.body, "{\"count\":2,\"ready\":true}");
    jg_cli_response_clear(&response);

    assert_int_equal(jg_cli_response_decode(
                         text_response, sizeof(text_response) - 1U, &response),
                     0);
    assert_string_equal(response.body, "janusgate_ready 1\n");
    jg_cli_response_clear(&response);

    assert_int_equal(jg_cli_response_decode(cookie_response,
                                            sizeof(cookie_response) - 1U,
                                            &response),
                     -EPROTO);
    assert_null(response.body);
}

/** @brief Verify local request arguments fail before transport access. */
static void test_request_validation(void **state)
{
    static const char token[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    struct jg_cli_response response = {0};
    json_t *body = json_object();

    (void)state;
    assert_non_null(body);
    assert_int_equal(jg_cli_local_request("relative.sock", token, "GET",
                                          "/api/v1/status", NULL, body,
                                          &response),
                     -EINVAL);
    assert_int_equal(jg_cli_local_request("/tmp/control.sock", "short", "GET",
                                          "/api/v1/status", NULL, body,
                                          &response),
                     -EINVAL);
    assert_int_equal(jg_cli_local_request("/tmp/control.sock", token, "TRACE",
                                          "/api/v1/status", NULL, body,
                                          &response),
                     -EINVAL);
    assert_int_equal(jg_cli_local_request("/tmp/control.sock", token, "GET",
                                          "/api/v1/status?q", NULL, body,
                                          &response),
                     -EINVAL);
    json_decref(body);
}

/** @brief Run the CLI management-client unit-test group. */
int jg_test_cli_client(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_response_decoding),
        cmocka_unit_test(test_request_validation),
    };

    return cmocka_run_group_tests_name("cli_client", tests, NULL, NULL);
}
