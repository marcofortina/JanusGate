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
#include "janusgate/audit.h"
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
                                          NULL, &fixture->management),
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
    struct jg_account_token_config token_config = {
        .name = "status test",
        .permissions = JG_ACCESS_STATUS_READ,
        .requests_per_minute = 1U,
    };
    struct jg_account_api_token api_token;
    struct jg_policy_rule_input domain_rules[2U];
    struct jg_policy_destination_rule_input destination_rules[2U];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
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
    user_id = (uint64_t)json_integer_value(
        json_object_get(json_object_get(body, "user"), "id"));
    value = json_object_get(body, "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(csrf, sizeof(csrf), "%s", json_string_value(value));
    json_decref(response);

    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &api_token),
                     0);
    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"status-token-1\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/status\",\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                       "\"body\":{}}",
                       api_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     429);
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

    (void)memset(domain_rules, 0, sizeof(domain_rules));
    domain_rules[0U].id = 2U;
    domain_rules[0U].domain = "Blocked.Example.";
    domain_rules[0U].include_subdomains = true;
    domain_rules[0U].effect = JG_POLICY_BLOCK;
    domain_rules[0U].source = JG_POLICY_SOURCE_EXPLICIT;
    domain_rules[0U].scope.type = JG_POLICY_SCOPE_GLOBAL;
    domain_rules[0U].attribution = "management test";
    domain_rules[1U].id = 1U;
    domain_rules[1U].domain = "safe.example";
    domain_rules[1U].effect = JG_POLICY_ALLOW;
    domain_rules[1U].source = JG_POLICY_SOURCE_EXPLICIT;
    domain_rules[1U].scope.type = JG_POLICY_SCOPE_VLAN;
    domain_rules[1U].scope.value.vlan_id = 20U;
    domain_rules[1U].attribution = "local exception";
    assert_int_equal(jg_database_replace_domain_rules(
                         fixture->database, domain_rules,
                         sizeof(domain_rules) / sizeof(domain_rules[0U])),
                     0);
    (void)memset(destination_rules, 0, sizeof(destination_rules));
    destination_rules[0U].id = 5U;
    destination_rules[0U].effect = JG_POLICY_BLOCK;
    destination_rules[0U].source = JG_POLICY_SOURCE_EXPLICIT;
    destination_rules[0U].transport = JG_POLICY_TRANSPORT_ANY;
    destination_rules[0U].has_port = true;
    destination_rules[0U].port = 853U;
    destination_rules[0U].scope.type = JG_POLICY_SCOPE_GLOBAL;
    destination_rules[0U].attribution = "encrypted DNS";
    destination_rules[1U].id = 3U;
    destination_rules[1U].effect = JG_POLICY_ALLOW;
    destination_rules[1U].source = JG_POLICY_SOURCE_EXPLICIT;
    destination_rules[1U].transport = JG_POLICY_TRANSPORT_TCP;
    destination_rules[1U].has_address = true;
    destination_rules[1U].address_family = JG_POLICY_ADDRESS_IPV4;
    destination_rules[1U].address[0U] = 203U;
    destination_rules[1U].address[1U] = 0U;
    destination_rules[1U].address[2U] = 113U;
    destination_rules[1U].address[3U] = 99U;
    destination_rules[1U].prefix_length = 24U;
    destination_rules[1U].scope.type = JG_POLICY_SCOPE_VLAN;
    destination_rules[1U].scope.value.vlan_id = 20U;
    destination_rules[1U].attribution = "resolver exception";
    assert_int_equal(
        jg_database_replace_destination_rules(
            fixture->database, destination_rules,
            sizeof(destination_rules) / sizeof(destination_rules[0U])),
        0);
    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"domains-1\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/domains\",\"query\":\"limit=1\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "count")), 1);
    assert_true(json_is_true(json_object_get(body, "has_more")));
    assert_int_equal(json_integer_value(json_object_get(body, "next_after_id")),
                     1);
    value = json_array_get(json_object_get(body, "domains"), 0U);
    assert_string_equal(json_string_value(json_object_get(value, "domain")),
                        "safe.example");
    assert_string_equal(json_string_value(json_object_get(
                            json_object_get(value, "scope"), "type")),
                        "vlan");
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"domains-2\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/domains\","
                 "\"query\":\"after_id=1&limit=1\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(body, "has_more")));
    assert_true(json_is_null(json_object_get(body, "next_after_id")));
    value = json_array_get(json_object_get(body, "domains"), 0U);
    assert_string_equal(json_string_value(json_object_get(value, "domain")),
                        "blocked.example");
    assert_true(json_is_true(json_object_get(value, "include_subdomains")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destinations-1\",\"method\":\"GET\","
        "\"path\":\"/api/v1/policies/destinations\","
        "\"query\":\"limit=1\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\",\"body\":{}}",
        session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(body, "has_more")));
    value = json_array_get(json_object_get(body, "destination_rules"), 0U);
    assert_int_equal(json_integer_value(json_object_get(value, "id")), 3);
    assert_string_equal(json_string_value(json_object_get(value, "address")),
                        "203.0.113.0");
    assert_int_equal(
        json_integer_value(json_object_get(value, "prefix_length")), 24);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destinations-2\",\"method\":\"GET\","
        "\"path\":\"/api/v1/policies/destinations\","
        "\"query\":\"after_id=3&limit=1\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\",\"body\":{}}",
        session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(body, "has_more")));
    value = json_array_get(json_object_get(body, "destination_rules"), 0U);
    assert_int_equal(json_integer_value(json_object_get(value, "id")), 5);
    assert_int_equal(json_integer_value(json_object_get(value, "port")), 853);
    assert_true(json_is_null(json_object_get(value, "address")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destination-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/policies/destinations\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"action\":\"block\","
        "\"transport\":\"any\",\"address\":null,\"prefix_length\":null,"
        "\"port\":853,\"scope\":{\"type\":\"global\"},"
        "\"attribution\":\"encrypted DNS\",\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destination-invalid\",\"method\":\"POST\","
        "\"path\":\"/api/v1/policies/destinations\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"action\":\"block\","
        "\"transport\":\"tcp\",\"address\":null,\"prefix_length\":null,"
        "\"port\":null,\"scope\":{\"type\":\"global\"},"
        "\"attribution\":\"invalid\",\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destination-update\",\"method\":\"PATCH\","
        "\"path\":\"/api/v1/policies/destinations/3\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"revision\":1,\"action\":\"allow\","
        "\"transport\":\"tcp\",\"address\":\"203.0.113.0\","
        "\"prefix_length\":24,\"port\":null,"
        "\"scope\":{\"type\":\"vlan\",\"vlan\":20},"
        "\"attribution\":\"resolver exception\",\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destination-delete\",\"method\":\"DELETE\","
        "\"path\":\"/api/v1/policies/destinations/3\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"revision\":1}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"domain-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/domains\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"domain\":\"new.example\","
        "\"include_subdomains\":true,\"action\":\"block\","
        "\"target\":\"dns\",\"scope\":{\"type\":\"global\"},"
        "\"attribution\":\"local policy\",\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"domain-invalid\",\"method\":\"POST\","
        "\"path\":\"/api/v1/domains\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"domain\":\"new.example\","
        "\"include_subdomains\":true,\"action\":\"block\","
        "\"target\":\"dns\",\"scope\":{\"type\":\"mac\","
        "\"address\":\"invalid\"},\"attribution\":\"local policy\","
        "\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"domain-update\",\"method\":\"PATCH\","
        "\"path\":\"/api/v1/domains/1\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"revision\":1,"
        "\"domain\":\"safe.example\",\"include_subdomains\":false,"
        "\"action\":\"allow\",\"target\":\"dns\","
        "\"scope\":{\"type\":\"vlan\",\"vlan\":20},"
        "\"attribution\":\"local exception\",\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"domain-delete\",\"method\":\"DELETE\","
        "\"path\":\"/api/v1/domains/1\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"revision\":1}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"policy-simulate\",\"method\":\"POST\","
        "\"path\":\"/api/v1/policies/simulate\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"body\":{\"domain\":\"Example.ORG.\",\"source_ip\":\"192.0.2.50\","
        "\"source_mac\":\"02:00:00:00:00:01\",\"vlan\":20,"
        "\"destination_ip\":\"203.0.113.53\","
        "\"destination_port\":53,\"transport\":\"udp\"}}",
        session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"policy-simulate-invalid\",\"method\":\"POST\","
        "\"path\":\"/api/v1/policies/simulate\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"body\":{\"domain\":\"example.org\","
        "\"source_mac\":\"not-a-mac\"}}",
        session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"metrics-1\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/metrics\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
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

/** @brief Verify forced password change and authenticated session rotation. */
static void test_password_change(void **state)
{
    static const char administrator_password[] = "correct horse battery staple";
    static const char initial_password[] = "initial operator password is long";
    static const char replacement_password[] =
        "replacement operator password is long";
    struct management_fixture *fixture = *state;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[4096U];
    char administrator_session[JG_AUTH_SECRET_TEXT_SIZE];
    char administrator_csrf[JG_AUTH_SECRET_TEXT_SIZE];
    char operator_session[JG_AUTH_SECRET_TEXT_SIZE];
    char operator_csrf[JG_AUTH_SECRET_TEXT_SIZE];
    char renewed_session[JG_AUTH_SECRET_TEXT_SIZE];
    char renewed_csrf[JG_AUTH_SECRET_TEXT_SIZE];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    const time_t now = time(NULL);
    int written = 0;

    assert_true(now > 0);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"password-bootstrap\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/bootstrap\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"body\":{"
        "\"token\":\"%s\",\"username\":\"administrator\","
        "\"password\":\"%s\"}}",
        bootstrap, administrator_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    (void)snprintf(administrator_session, sizeof(administrator_session), "%s",
                   json_string_value(value));
    value = json_object_get(json_object_get(response, "body"), "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(administrator_csrf, sizeof(administrator_csrf), "%s",
                   json_string_value(value));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"password-user-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/users\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"username\":\"operator\",\"password\":\"%s\","
        "\"role\":\"operator\",\"force_password_change\":true}}",
        administrator_session, administrator_csrf, initial_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"password-login\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/login\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.20\",\"body\":{"
        "\"username\":\"operator\",\"password\":\"%s\"}}",
        initial_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    (void)snprintf(operator_session, sizeof(operator_session), "%s",
                   json_string_value(value));
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(json_object_get(body, "user"),
                                             "force_password_change")));
    value = json_object_get(body, "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(operator_csrf, sizeof(operator_csrf), "%s",
                   json_string_value(value));
    json_decref(response);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"password-status\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/status\",\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.20\",\"session\":\"%s\","
                       "\"body\":{}}",
                       operator_session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     403);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"password-change\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/password\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.20\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"current_password\":\"%s\",\"new_password\":\"%s\"}}",
        operator_session, operator_csrf, initial_password,
        replacement_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    (void)snprintf(renewed_session, sizeof(renewed_session), "%s",
                   json_string_value(value));
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(json_object_get(body, "user"),
                                              "force_password_change")));
    value = json_object_get(body, "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(renewed_csrf, sizeof(renewed_csrf), "%s",
                   json_string_value(value));
    assert_string_not_equal(renewed_session, operator_session);
    assert_string_not_equal(renewed_csrf, operator_csrf);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"password-old-session\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/auth/session\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.20\","
                 "\"session\":\"%s\",\"body\":{}}",
                 operator_session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     401);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"password-new-session\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/auth/session\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.20\","
                 "\"session\":\"%s\",\"body\":{}}",
                 renewed_session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(json_object_get(body, "user"),
                                              "force_password_change")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"password-audit\",\"method\":\"GET\","
        "\"path\":\"/api/v1/audit\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\",\"body\":{}}",
        administrator_session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "total")), 2);
    value = json_array_get(json_object_get(body, "events"), 0U);
    assert_string_equal(json_string_value(json_object_get(value, "action")),
                        "user.password_change");
    json_decref(response);
}

/** @brief Verify authorized user CRUD, pagination, and audit chaining. */
static void test_user_api(void **state)
{
    static const char administrator_password[] = "correct horse battery staple";
    static const char operator_password[] =
        "operator password is suitably long";
    static const char replacement_password[] =
        "replacement password is suitably long";
    struct management_fixture *fixture = *state;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[4096U];
    char session[JG_AUTH_SECRET_TEXT_SIZE];
    char csrf[JG_AUTH_SECRET_TEXT_SIZE];
    struct jg_audit_verification verification;
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    json_t *user = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    uint64_t revision = 0U;
    int written = 0;

    assert_true(now > 0);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"users-bootstrap\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/bootstrap\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"body\":{"
        "\"token\":\"%s\",\"username\":\"administrator\","
        "\"password\":\"%s\"}}",
        bootstrap, administrator_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    (void)snprintf(session, sizeof(session), "%s", json_string_value(value));
    body = json_object_get(response, "body");
    value = json_object_get(body, "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(csrf, sizeof(csrf), "%s", json_string_value(value));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"user-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/users\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"username\":\"operator\",\"password\":\"%s\","
        "\"role\":\"operator\",\"force_password_change\":false}}",
        session, csrf, operator_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    user = json_object_get(json_object_get(response, "body"), "user");
    user_id = (uint64_t)json_integer_value(json_object_get(user, "id"));
    revision = (uint64_t)json_integer_value(json_object_get(user, "revision"));
    assert_true(user_id > 0U);
    assert_int_equal(revision, 1U);
    assert_string_equal(json_string_value(json_object_get(user, "role")),
                        "operator");
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"users-list\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/users\",\"query\":\"offset=1&limit=1\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "total")), 2);
    assert_int_equal(json_array_size(json_object_get(body, "users")), 1U);
    user = json_array_get(json_object_get(body, "users"), 0U);
    assert_string_equal(json_string_value(json_object_get(user, "username")),
                        "operator");
    assert_true(json_is_null(json_object_get(body, "next_offset")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"user-update\",\"method\":\"PATCH\","
        "\"path\":\"/api/v1/users/%llu\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"revision\":%llu,\"role\":\"auditor\",\"enabled\":true,"
        "\"force_password_change\":true}}",
        (unsigned long long)user_id, session, csrf,
        (unsigned long long)revision);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    user = json_object_get(json_object_get(response, "body"), "user");
    revision = (uint64_t)json_integer_value(json_object_get(user, "revision"));
    assert_int_equal(revision, 2U);
    assert_true(json_is_true(json_object_get(user, "force_password_change")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"user-password\",\"method\":\"POST\","
        "\"path\":\"/api/v1/users/%llu/password\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"revision\":%llu,\"password\":\"%s\","
        "\"force_password_change\":false}}",
        (unsigned long long)user_id, session, csrf,
        (unsigned long long)revision, replacement_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    user = json_object_get(json_object_get(response, "body"), "user");
    assert_int_equal(json_integer_value(json_object_get(user, "revision")), 3);
    assert_false(json_is_true(json_object_get(user, "force_password_change")));
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"users-query-invalid\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/users\",\"query\":\"limit=0\","
                 "\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
                 "\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"audit-list\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/audit\",\"query\":\"limit=2\","
                       "\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
                       "\"body\":{}}",
                       session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "total")), 3);
    assert_int_equal(json_array_size(json_object_get(body, "events")), 2U);
    value = json_array_get(json_object_get(body, "events"), 0U);
    assert_string_equal(json_string_value(json_object_get(value, "action")),
                        "user.password_reset");
    assert_int_equal(json_string_length(json_object_get(value, "event_hash")),
                     JG_AUDIT_HASH_SIZE * 2U);
    json_decref(response);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"audit-verify\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/audit/verify\","
                       "\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
                       "\"body\":{}}",
                       session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(body, "valid")));
    assert_int_equal(
        json_integer_value(json_object_get(body, "records_inspected")), 3);
    assert_true(json_is_null(json_object_get(body, "first_invalid_id")));
    json_decref(response);

    assert_int_equal(jg_database_audit_verify(fixture->database, &verification),
                     0);
    assert_true(verification.valid);
    assert_int_equal(verification.records_inspected, 3U);
}

/** @brief Verify one-time token issue, inventory, use, and revocation. */
static void test_token_api(void **state)
{
    static const char administrator_password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[4096U];
    char session[JG_AUTH_SECRET_TEXT_SIZE];
    char csrf[JG_AUTH_SECRET_TEXT_SIZE];
    char secret[JG_AUTH_SECRET_TEXT_SIZE];
    struct jg_audit_verification verification;
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    json_t *token = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    uint64_t token_id = 0U;
    int written = 0;

    assert_true(now > 0);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"tokens-bootstrap\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/bootstrap\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"body\":{"
        "\"token\":\"%s\",\"username\":\"administrator\","
        "\"password\":\"%s\"}}",
        bootstrap, administrator_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    (void)snprintf(session, sizeof(session), "%s", json_string_value(value));
    body = json_object_get(response, "body");
    user_id = (uint64_t)json_integer_value(
        json_object_get(json_object_get(body, "user"), "id"));
    value = json_object_get(body, "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(csrf, sizeof(csrf), "%s", json_string_value(value));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"token-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/tokens\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"user_id\":%llu,\"name\":\"management automation\","
        "\"scopes\":\"status:read,access:write\",\"expires_at\":null,"
        "\"source_network\":\"192.0.2.0/24\","
        "\"requests_per_minute\":60}}",
        session, csrf, (unsigned long long)user_id);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    token = json_object_get(json_object_get(response, "body"), "token");
    token_id = (uint64_t)json_integer_value(json_object_get(token, "id"));
    value = json_object_get(token, "secret");
    assert_true(token_id > 0U);
    assert_true(json_is_string(value));
    assert_int_equal(json_string_length(value), JG_AUTH_SECRET_TEXT_SIZE - 1U);
    (void)snprintf(secret, sizeof(secret), "%s", json_string_value(value));
    assert_string_equal(
        json_string_value(json_object_get(token, "source_network")),
        "192.0.2.0/24");
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"tokens-bearer-list\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/tokens\",\"query\":\"limit=10\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"bearer\":\"%s\",\"body\":{}}",
                 secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "total")), 1);
    token = json_array_get(json_object_get(body, "tokens"), 0U);
    assert_null(json_object_get(token, "secret"));
    assert_false(json_is_true(json_object_get(token, "revoked")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"token-revoke\",\"method\":\"DELETE\","
        "\"path\":\"/api/v1/tokens/%llu\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{}}",
        (unsigned long long)token_id, session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    token = json_object_get(json_object_get(response, "body"), "token");
    assert_true(json_is_true(json_object_get(token, "revoked")));
    assert_int_equal(json_integer_value(json_object_get(token, "revision")), 2);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"tokens-revoked-list\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/tokens\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"bearer\":\"%s\",\"body\":{}}",
                 secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     401);
    json_decref(response);

    assert_int_equal(jg_database_audit_verify(fixture->database, &verification),
                     0);
    assert_true(verification.valid);
    assert_int_equal(verification.records_inspected, 2U);
}

/** @brief Verify authenticated blocklist-source paging and state JSON. */
static void test_source_api(void **state)
{
    static const char password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    struct jg_auth_password_policy password_policy;
    struct jg_account_token_config token_config = {
        .name = "source test",
        .permissions = JG_ACCESS_POLICY_READ | JG_ACCESS_POLICY_WRITE,
        .requests_per_minute = 100U,
    };
    struct jg_database_blocklist_source_config source_config = {
        .name = "Threat domains",
        .url = "https://lists.example/domains",
        .format = JG_BLOCKLIST_FORMAT_HOSTS,
        .mode = JG_BLOCKLIST_TOLERANT,
        .enabled = true,
        .update_interval_seconds = 3600U,
        .max_download_bytes = 1048576U,
        .max_decompressed_bytes = 4194304U,
        .connect_timeout_ms = 5000U,
        .transfer_timeout_ms = 30000U,
        .redirect_limit = 3U,
        .retry_base_seconds = 60U,
        .retry_max_seconds = 3600U,
    };
    struct jg_database_blocklist_source source;
    struct jg_account_api_token api_token;
    struct jg_audit_verification verification;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[2048U];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    uint64_t source_id = 0U;
    uint64_t source_revision = 0U;
    int written = 0;

    assert_true(now > 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator",
                         (const uint8_t *)password, strlen(password),
                         &password_policy, (uint64_t)now, &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &api_token),
                     0);
    assert_int_equal(jg_database_create_blocklist_source(
                         fixture->database, &source_config, &source),
                     0);
    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"sources-list\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/sources\",\"query\":\"limit=1\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"bearer\":\"%s\",\"body\":{}}",
                 api_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "count")), 1);
    assert_false(json_is_true(json_object_get(body, "has_more")));
    assert_true(json_is_null(json_object_get(body, "next_after_id")));
    value = json_array_get(json_object_get(body, "sources"), 0U);
    assert_int_equal(json_integer_value(json_object_get(value, "id")),
                     (json_int_t)source.id);
    assert_string_equal(json_string_value(json_object_get(value, "name")),
                        source_config.name);
    assert_string_equal(json_string_value(json_object_get(value, "format")),
                        "hosts");
    assert_string_equal(json_string_value(json_object_get(value, "mode")),
                        "tolerant");
    assert_string_equal(json_string_value(json_object_get(value, "health")),
                        "unknown");
    assert_true(json_is_null(json_object_get(value, "active_checksum")));
    assert_true(json_is_null(json_object_get(value, "last_attempt_at")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"source-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/sources\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{"
        "\"name\":\"API source\","
        "\"url\":\"https://127.0.0.1:1/blocklist\","
        "\"signature_url\":null,\"format\":\"domain\",\"mode\":\"strict\","
        "\"enabled\":true,\"update_interval_seconds\":7200,"
        "\"max_download_bytes\":2048,\"max_decompressed_bytes\":8192,"
        "\"connect_timeout_ms\":100,\"transfer_timeout_ms\":100,"
        "\"redirect_limit\":2,\"retry_base_seconds\":60,"
        "\"retry_max_seconds\":600,\"sha256_pin\":null,"
        "\"ed25519_public_key\":null}}",
        api_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     202);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(body, "published")));
    value = json_object_get(body, "source");
    source_id = (uint64_t)json_integer_value(json_object_get(value, "id"));
    source_revision =
        (uint64_t)json_integer_value(json_object_get(value, "revision"));
    assert_true(source_id > source.id);
    assert_int_equal(source_revision, 1U);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"source-update\",\"method\":\"PATCH\","
        "\"path\":\"/api/v1/sources/%llu\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{"
        "\"revision\":%llu,\"name\":\"API source updated\","
        "\"url\":\"https://127.0.0.1:1/blocklist\","
        "\"signature_url\":null,"
        "\"format\":\"hosts\",\"mode\":\"tolerant\",\"enabled\":false,"
        "\"update_interval_seconds\":7200,\"max_download_bytes\":2048,"
        "\"max_decompressed_bytes\":8192,\"connect_timeout_ms\":100,"
        "\"transfer_timeout_ms\":100,\"redirect_limit\":2,"
        "\"retry_base_seconds\":60,\"retry_max_seconds\":600,"
        "\"sha256_pin\":null,\"ed25519_public_key\":null}}",
        (unsigned long long)source_id, api_token.secret,
        (unsigned long long)source_revision);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     202);
    value = json_object_get(json_object_get(response, "body"), "source");
    source_revision =
        (uint64_t)json_integer_value(json_object_get(value, "revision"));
    assert_int_equal(source_revision, 2U);
    assert_false(json_is_true(json_object_get(value, "enabled")));
    assert_string_equal(json_string_value(json_object_get(value, "format")),
                        "hosts");
    json_decref(response);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"source-refresh\",\"method\":\"POST\","
                       "\"path\":\"/api/v1/sources/%llu/refresh\","
                       "\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                       "\"body\":{\"revision\":%llu}}",
                       (unsigned long long)source_id, api_token.secret,
                       (unsigned long long)source_revision);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     502);
    body = json_object_get(response, "body");
    assert_string_equal(json_string_value(json_object_get(
                            json_object_get(body, "error"), "code")),
                        "blocklist_update_failed");
    value = json_object_get(body, "source");
    assert_string_equal(json_string_value(json_object_get(value, "health")),
                        "failed");
    assert_int_equal(
        json_integer_value(json_object_get(value, "consecutive_failures")), 1);
    value = json_object_get(body, "attempt");
    assert_false(json_is_true(json_object_get(value, "success")));
    assert_string_equal(json_string_value(json_object_get(value, "outcome")),
                        "failed");
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"source-delete\",\"method\":\"DELETE\","
                 "\"path\":\"/api/v1/sources/%llu\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{\"revision\":%llu}}",
                 (unsigned long long)source_id, api_token.secret,
                 (unsigned long long)source_revision);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     202);
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(body, "deleted")));
    assert_int_equal(json_integer_value(json_object_get(body, "id")),
                     (json_int_t)source_id);
    json_decref(response);
    assert_int_equal(jg_database_audit_verify(fixture->database, &verification),
                     0);
    assert_true(verification.valid);
    assert_int_equal(verification.records_inspected, 4U);
}

/** @brief Verify due remote sources retain health and system audit state. */
static void test_scheduled_source_update(void **state)
{
    struct management_fixture *fixture = *state;
    const struct jg_database_blocklist_source_config config = {
        .name = "Scheduled source",
        .url = "https://127.0.0.1:1/blocklist",
        .format = JG_BLOCKLIST_FORMAT_DOMAIN,
        .mode = JG_BLOCKLIST_STRICT,
        .enabled = true,
        .update_interval_seconds = 3600U,
        .max_download_bytes = 4096U,
        .max_decompressed_bytes = 8192U,
        .connect_timeout_ms = 100U,
        .transfer_timeout_ms = 100U,
        .redirect_limit = 2U,
        .retry_base_seconds = 10U,
        .retry_max_seconds = 80U,
    };
    struct jg_database_blocklist_source source;
    struct jg_database_blocklist_source updated;
    struct jg_audit_record audit;
    uint64_t total = 0U;
    size_t attempts = 0U;
    size_t count = 0U;
    bool has_more = false;

    assert_int_equal(jg_database_create_blocklist_source(fixture->database,
                                                         &config, &source),
                     0);
    assert_int_equal(jg_management_update_due_blocklists(fixture->management,
                                                         100U, &attempts),
                     0);
    assert_int_equal(attempts, 1U);
    assert_int_equal(jg_database_list_blocklist_sources(fixture->database, 0U,
                                                        1U, &updated, &count,
                                                        &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_false(has_more);
    assert_int_equal(updated.health, JG_DATABASE_BLOCKLIST_FAILED);
    assert_int_equal(updated.last_attempt_at, 100U);
    assert_int_equal(updated.consecutive_failures, 1U);
    assert_int_equal(jg_database_audit_list(fixture->database, 0U, &audit, 1U,
                                            &count, &total),
                     0);
    assert_int_equal(count, 1U);
    assert_int_equal(total, 1U);
    assert_int_equal(audit.actor_type, JG_AUDIT_ACTOR_SYSTEM);
    assert_false(audit.has_actor_id);
    assert_false(audit.success);
    assert_string_equal(audit.source, "scheduler");
    assert_string_equal(audit.action, "blocklist.source.refresh");

    attempts = 1U;
    assert_int_equal(jg_management_update_due_blocklists(fixture->management,
                                                         101U, &attempts),
                     0);
    assert_int_equal(attempts, 0U);
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
        cmocka_unit_test_setup_teardown(test_password_change, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_user_api, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_token_api, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_source_api, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_scheduled_source_update,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_request_rejection,
                                        setup_management, teardown_management),
    };

    return cmocka_run_group_tests_name("management", tests, NULL, NULL);
}
