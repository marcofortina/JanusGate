/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <sodium.h>

#include "janusgate/alert.h"
#include "janusgate/database.h"

int jg_test_alert(void);

/* Private database fixture for alert-storage tests. */
struct alert_fixture {
    char directory[64U];
    char database_path[128U];
    struct jg_database *database;
};

/** @brief Open one fresh private alert database. */
static int setup_alert(void **state)
{
    static const char template[] = "/tmp/janusgate-alert-XXXXXX";
    struct alert_fixture *fixture = calloc(1U, sizeof(*fixture));
    int written = 0;

    assert_non_null(fixture);
    (void)snprintf(fixture->directory, sizeof(fixture->directory), "%s",
                   template);
    assert_non_null(mkdtemp(fixture->directory));
    written = snprintf(fixture->database_path, sizeof(fixture->database_path),
                       "%s/janusgate.db", fixture->directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(fixture->database_path));
    assert_int_equal(
        jg_database_open(fixture->database_path, 1000U, &fixture->database), 0);
    *state = fixture;
    return 0;
}

/** @brief Close and remove one private alert database. */
static int teardown_alert(void **state)
{
    struct alert_fixture *fixture = *state;
    char auxiliary[160U];
    int written = 0;

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
    (void)rmdir(fixture->directory);
    free(fixture);
    return 0;
}

/** @brief Decode one lowercase hexadecimal secret returned exactly once. */
static void decode_secret(const char text[JG_ALERT_WEBHOOK_SECRET_TEXT_SIZE],
                          uint8_t secret[JG_ALERT_WEBHOOK_SECRET_SIZE])
{
    for (size_t index = 0U; index < JG_ALERT_WEBHOOK_SECRET_SIZE; ++index) {
        unsigned int value = 0U;

        assert_int_equal(sscanf(text + index * 2U, "%2x", &value), 1);
        secret[index] = (uint8_t)value;
    }
}

/** @brief Verify defaults and strict alert-configuration validation. */
static void test_alert_configuration(void **state)
{
    struct alert_fixture *fixture = *state;
    struct jg_alert_configuration configuration = {0};
    struct jg_alert_configuration updated = {0};
    struct jg_alert_configuration_update replacement;

    assert_int_equal(
        jg_database_alert_configuration_load(fixture->database, &configuration),
        0);
    assert_true(configuration.values.enabled);
    assert_int_equal(configuration.values.evaluation_interval_seconds, 60U);
    assert_int_equal(configuration.values.certificate_warning_days, 30U);
    assert_false(configuration.values.webhook_enabled);
    assert_false(configuration.webhook_secret_configured);
    assert_int_equal(configuration.revision, 1U);
    replacement = configuration.values;
    replacement.webhook_url = "https://alerts.home.arpa/janusgate";
    replacement.evaluation_interval_seconds = 120U;
    assert_int_equal(jg_database_alert_configuration_replace(
                         fixture->database, &replacement,
                         configuration.revision, 100U, &updated),
                     0);
    assert_int_equal(updated.revision, 2U);
    assert_int_equal(updated.values.evaluation_interval_seconds, 120U);
    assert_string_equal(updated.values.webhook_url,
                        "https://alerts.home.arpa/janusgate");
    jg_alert_configuration_clear(&updated);
    assert_int_equal(jg_database_alert_configuration_replace(
                         fixture->database, &replacement,
                         configuration.revision, 101U, &updated),
                     -EAGAIN);
    replacement.webhook_enabled = true;
    assert_int_equal(jg_database_alert_configuration_replace(
                         fixture->database, &replacement, 2U, 101U, &updated),
                     -ENOENT);
    replacement.webhook_enabled = false;
    replacement.webhook_url = "http://alerts.home.arpa/janusgate";
    assert_int_equal(jg_alert_configuration_validate(&replacement), -EINVAL);
    replacement.webhook_url = "https://user@alerts.home.arpa/janusgate";
    assert_int_equal(jg_alert_configuration_validate(&replacement), -EINVAL);
    replacement.webhook_url = "https://alerts.home.arpa/janusgate#fragment";
    assert_int_equal(jg_alert_configuration_validate(&replacement), -EINVAL);
    replacement.webhook_url = "https://alerts.home.arpa/janusgate";
    replacement.webhook_ca_pem = "not a certificate";
    assert_int_equal(jg_alert_configuration_validate(&replacement), -EINVAL);
    jg_alert_configuration_clear(&configuration);
}

/** @brief Verify one-time secret rotation and authenticated persistence. */
static void test_alert_secret(void **state)
{
    struct alert_fixture *fixture = *state;
    struct jg_alert_configuration configuration = {0};
    struct jg_alert_configuration updated = {0};
    struct jg_alert_configuration_update replacement;
    uint8_t expected[JG_ALERT_WEBHOOK_SECRET_SIZE];
    uint8_t loaded[JG_ALERT_WEBHOOK_SECRET_SIZE];
    uint8_t key[JG_ALERT_WEBHOOK_SECRET_SIZE];
    uint8_t wrong_key[JG_ALERT_WEBHOOK_SECRET_SIZE];
    char secret_text[JG_ALERT_WEBHOOK_SECRET_TEXT_SIZE];

    randombytes_buf(key, sizeof(key));
    randombytes_buf(wrong_key, sizeof(wrong_key));
    assert_int_equal(
        jg_database_alert_webhook_secret_load(fixture->database, key, loaded),
        -ENOENT);
    assert_int_equal(
        jg_database_alert_webhook_secret_rotate(
            fixture->database, key, 1U, 200U, secret_text, &configuration),
        0);
    assert_true(configuration.webhook_secret_configured);
    assert_int_equal(configuration.revision, 2U);
    assert_int_equal(strlen(secret_text),
                     JG_ALERT_WEBHOOK_SECRET_TEXT_SIZE - 1U);
    decode_secret(secret_text, expected);
    assert_int_equal(
        jg_database_alert_webhook_secret_load(fixture->database, key, loaded),
        0);
    assert_memory_equal(loaded, expected, sizeof(expected));
    assert_int_equal(jg_database_alert_webhook_secret_load(fixture->database,
                                                           wrong_key, loaded),
                     -EBADMSG);
    replacement = configuration.values;
    replacement.webhook_url = "https://alerts.home.arpa/janusgate";
    replacement.webhook_enabled = true;
    assert_int_equal(jg_database_alert_configuration_replace(
                         fixture->database, &replacement,
                         configuration.revision, 201U, &updated),
                     0);
    assert_true(updated.values.webhook_enabled);
    assert_true(updated.webhook_secret_configured);
    sodium_memzero(secret_text, sizeof(secret_text));
    sodium_memzero(expected, sizeof(expected));
    sodium_memzero(loaded, sizeof(loaded));
    sodium_memzero(wrong_key, sizeof(wrong_key));
    sodium_memzero(key, sizeof(key));
    jg_alert_configuration_clear(&updated);
    jg_alert_configuration_clear(&configuration);
}

/** @brief Run alert storage tests. */
int jg_test_alert(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_alert_configuration, setup_alert,
                                        teardown_alert),
        cmocka_unit_test_setup_teardown(test_alert_secret, setup_alert,
                                        teardown_alert),
    };

    return cmocka_run_group_tests_name("alert", tests, NULL, NULL);
}
