/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <jansson.h>

#include "janusgate/account.h"
#include "janusgate/ipc.h"
#include "management.h"

int jg_test_management(void);

/** Complete private filesystem and database fixture for management tests. */
struct management_fixture {
    char directory[64U];
    char database_path[128U];
    char key_path[128U];
    struct jg_database *database;
    struct jg_management *management;
};

/** @brief Write one exact buffer to a newly created private file. */
static void write_private_file(const char *path,
                               const uint8_t *data,
                               size_t data_size)
{
    size_t offset = 0U;
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    assert_true(descriptor >= 0);
    while (offset < data_size) {
        const ssize_t count =
            write(descriptor, data + offset, data_size - offset);

        assert_true(count > 0);
        offset += (size_t)count;
    }
    assert_int_equal(close(descriptor), 0);
}

/** @brief Create private storage and management state around a fresh schema. */
static int setup_management(void **state)
{
    static const char template[] = "/tmp/janusgate-management-XXXXXX";
    uint8_t key[JG_AUTH_TOTP_KEY_SIZE];
    struct management_fixture *fixture = calloc(1U, sizeof(*fixture));
    int written = 0;

    assert_non_null(fixture);
    (void)snprintf(fixture->directory, sizeof(fixture->directory), "%s",
                   template);
    assert_non_null(mkdtemp(fixture->directory));
    written = snprintf(fixture->database_path, sizeof(fixture->database_path),
                       "%s/janusgate.db", fixture->directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(fixture->database_path));
    written = snprintf(fixture->key_path, sizeof(fixture->key_path),
                       "%s/totp.key", fixture->directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(fixture->key_path));
    for (size_t index = 0U; index < sizeof(key); ++index) {
        key[index] = (uint8_t)(index + 1U);
    }
    write_private_file(fixture->key_path, key, sizeof(key));
    assert_int_equal(
        jg_database_open(fixture->database_path, 1000U, &fixture->database), 0);
    assert_int_equal(jg_management_create(fixture->database, fixture->key_path,
                                          &fixture->management),
                     0);
    *state = fixture;
    return 0;
}

/** @brief Remove SQLite side files and every private fixture resource. */
static int teardown_management(void **state)
{
    struct management_fixture *fixture = *state;
    char auxiliary[160U];
    int written = 0;

    jg_management_destroy(fixture->management);
    jg_database_close(fixture->database);
    written = snprintf(auxiliary, sizeof(auxiliary), "%s-wal",
                       fixture->database_path);
    if (written > 0 && (size_t)written < sizeof(auxiliary)) {
        (void)unlink(auxiliary);
    }
    written = snprintf(auxiliary, sizeof(auxiliary), "%s-shm",
                       fixture->database_path);
    if (written > 0 && (size_t)written < sizeof(auxiliary)) {
        (void)unlink(auxiliary);
    }
    (void)unlink(fixture->database_path);
    (void)unlink(fixture->key_path);
    (void)rmdir(fixture->directory);
    free(fixture);
    return 0;
}

/** @brief Process one textual envelope and parse its exact JSON response. */
static json_t *process_request(struct management_fixture *fixture,
                               const char *request)
{
    uint8_t response[JG_IPC_MAX_BODY_SIZE];
    json_error_t error;
    json_t *parsed = NULL;
    size_t response_size = 0U;

    assert_int_equal(jg_management_process(fixture->management,
                                           (const uint8_t *)request,
                                           strlen(request), response,
                                           sizeof(response), &response_size),
                     0);
    parsed = json_loadb((const char *)response, response_size,
                        JSON_REJECT_DUPLICATES, &error);
    assert_non_null(parsed);
    assert_true(json_is_object(parsed));
    return parsed;
}

/** @brief Verify bootstrap, login session validation, CSRF, and logout. */
static void test_browser_authentication(void **state)
{
    static const char password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    char token[JG_AUTH_SECRET_TEXT_SIZE];
    char request[2048U];
    char session[JG_AUTH_SECRET_TEXT_SIZE];
    char csrf[JG_AUTH_SECRET_TEXT_SIZE];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    const time_t now = time(NULL);
    int written = 0;

    assert_true(now > 0);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, token),
                     0);
    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"bootstrap-1\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/bootstrap\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"body\":{"
        "\"token\":\"%s\",\"username\":\"administrator\","
        "\"password\":\"%s\"}}",
        token, password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    assert_int_equal(json_string_length(value), JG_AUTH_SECRET_TEXT_SIZE - 1U);
    (void)snprintf(session, sizeof(session), "%s", json_string_value(value));
    body = json_object_get(response, "body");
    value = json_object_get(body, "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(csrf, sizeof(csrf), "%s", json_string_value(value));
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"session-1\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/auth/session\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    value = json_object_get(json_object_get(body, "user"), "username");
    assert_string_equal(json_string_value(value), "administrator");
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"logout-1\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/logout\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    assert_true(json_is_true(json_object_get(response, "clear_session")));
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"session-2\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/auth/session\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     401);
    json_decref(response);
}

/** @brief Verify malformed and cross-origin requests fail closed. */
static void test_request_rejection(void **state)
{
    struct management_fixture *fixture = *state;
    json_t *response = process_request(fixture, "{}");
    const char invalid_origin[] =
        "{\"request_id\":\"login-1\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/login\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.0.2.1\","
        "\"remote_address\":\"192.0.2.10\","
        "\"body\":{\"username\":\"nobody\",\"password\":\"invalid\"}}";

    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);
    response = process_request(fixture, invalid_origin);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     403);
    json_decref(response);
}

/** @brief Run the serialized management authentication test group. */
int jg_test_management(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_browser_authentication,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_request_rejection,
                                        setup_management, teardown_management),
    };

    return cmocka_run_group_tests_name("management", tests, NULL, NULL);
}
