/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <jansson.h>

#include "janusgate/logging.h"

int jg_test_logging(void);

/** @brief Configure trace logging with safe test-only destinations. */
static struct jg_logging_config trace_config(void)
{
    struct jg_logging_config config;

    jg_logging_config_default(&config);
    config.global_level = JG_LOG_TRACE;
    config.destinations = JG_LOG_DESTINATION_STDERR;
    config.diagnostic_until = (uint64_t)time(NULL) + 60U;
    return config;
}

/** @brief Verify exact configuration validation and JSON round trips. */
static void test_configuration(void **state)
{
    struct jg_logging_config config;
    struct jg_logging_config decoded;
    char encoded[2048U];
    size_t encoded_size = 0U;

    (void)state;
    jg_logging_config_default(&config);
    assert_int_equal(jg_logging_config_validate(&config), 0);
    assert_int_equal(jg_logging_config_encode(&config, encoded, sizeof(encoded),
                                              &encoded_size),
                     0);
    assert_int_equal(jg_logging_config_decode(encoded, encoded_size, &decoded),
                     0);
    assert_int_equal(decoded.global_level, JG_LOG_INFO);
    assert_int_equal(decoded.destinations, config.destinations);
    assert_int_equal(decoded.rate_limit_per_second,
                     config.rate_limit_per_second);
    assert_int_equal(decoded.trace_capacity, config.trace_capacity);
    assert_false(decoded.include_identifiers);

    config.global_level = JG_LOG_DEBUG;
    assert_int_equal(jg_logging_config_validate(&config), -EINVAL);
    config.diagnostic_until = 1U;
    config.override_count = 2U;
    (void)memcpy(config.overrides[0U].component, "dns", sizeof("dns"));
    config.overrides[0U].level = JG_LOG_DEBUG;
    config.overrides[1U] = config.overrides[0U];
    assert_int_equal(jg_logging_config_validate(&config), -EINVAL);
    jg_logging_config_default(&config);
    config.diagnostic_until = 1U;
    assert_int_equal(jg_logging_config_validate(&config), -EINVAL);
    jg_logging_config_default(&config);
    config.include_identifiers = true;
    assert_int_equal(jg_logging_config_validate(&config), -EINVAL);
    assert_int_equal(jg_logging_config_decode("{\"unknown\":true}",
                                              sizeof("{\"unknown\":true}") - 1U,
                                              &decoded),
                     -EINVAL);
}

/** @brief Capture one structured record and verify recursive redaction. */
static void test_emission_and_redaction(void **state)
{
    struct jg_logging_config config = trace_config();
    struct jg_log_trace_record records[2U];
    struct jg_logging_stats stats;
    char output[JG_LOG_RECORD_MAX + 2U];
    int descriptors[2U];
    int saved_stderr = -1;
    ssize_t output_size = 0;
    size_t record_count = 0U;
    json_error_t error;
    json_t *record = NULL;
    json_t *details = NULL;

    (void)state;
    config.trace_capacity = 2U;
    assert_int_equal(pipe(descriptors), 0);
    saved_stderr = dup(STDERR_FILENO);
    assert_true(saved_stderr >= 0);
    assert_int_equal(dup2(descriptors[1U], STDERR_FILENO), STDERR_FILENO);
    assert_int_equal(close(descriptors[1U]), 0);

    assert_int_equal(jg_logging_initialize("test-logger", &config), 0);
    assert_int_equal(
        jg_log_emit(JG_LOG_TRACE, "dns", "dns.policy.decision", "request-1",
                    "DNS policy decision completed",
                    "{\"domain\":\"example.org\",\"nested\":"
                    "{\"password\":\"unsafe\",\"result\":\"blocked\"}}"),
        0);

    assert_int_equal(dup2(saved_stderr, STDERR_FILENO), STDERR_FILENO);
    assert_int_equal(close(saved_stderr), 0);
    output_size = read(descriptors[0U], output, sizeof(output) - 1U);
    assert_true(output_size > 0);
    assert_int_equal(close(descriptors[0U]), 0);
    output[(size_t)output_size] = '\0';

    record = json_loadb(output, (size_t)output_size, 0U, &error);
    assert_true(json_is_object(record));
    assert_string_equal(json_string_value(json_object_get(record, "severity")),
                        "trace");
    assert_string_equal(
        json_string_value(json_object_get(record, "correlation_id")),
        "request-1");
    details = json_object_get(record, "details");
    assert_string_equal(json_string_value(json_object_get(details, "domain")),
                        "[redacted]");
    assert_string_equal(json_string_value(json_object_get(
                            json_object_get(details, "nested"), "password")),
                        "[redacted]");
    assert_string_equal(json_string_value(json_object_get(
                            json_object_get(details, "nested"), "result")),
                        "blocked");
    json_decref(record);

    assert_int_equal(
        jg_logging_trace_snapshot(records, 2U, &record_count, &stats), 0);
    assert_int_equal(record_count, 1U);
    assert_int_equal(stats.emitted, 1U);
    assert_int_equal(stats.suppressed, 0U);
    assert_true(stats.diagnostic_active);
    assert_non_null(strstr(records[0U].json, "\"request-1\""));
    assert_null(strstr(records[0U].json, "unsafe"));
    jg_logging_shutdown();
}

/** @brief Verify diagnostic expiration and bounded rate suppression. */
static void test_runtime_limits(void **state)
{
    struct jg_logging_config config = trace_config();
    struct jg_log_trace_record records[4U];
    struct jg_logging_stats stats;
    size_t record_count = 0U;
    int descriptors[2U];
    int saved_stderr = -1;

    (void)state;
    config.diagnostic_until = 1U;
    assert_int_equal(jg_logging_initialize("test-logger", &config), 0);
    assert_false(jg_log_enabled("dns", JG_LOG_TRACE));
    assert_true(jg_log_enabled("dns", JG_LOG_INFO));

    config = trace_config();
    config.rate_limit_per_second = 1U;
    config.trace_capacity = 4U;
    assert_int_equal(pipe(descriptors), 0);
    saved_stderr = dup(STDERR_FILENO);
    assert_true(saved_stderr >= 0);
    assert_int_equal(dup2(descriptors[1U], STDERR_FILENO), STDERR_FILENO);
    assert_int_equal(close(descriptors[1U]), 0);
    assert_int_equal(jg_logging_initialize("test-logger", &config), 0);
    for (size_t index = 0U; index < 3U; ++index) {
        assert_int_equal(jg_log_emit(JG_LOG_INFO, "runtime", "runtime.test",
                                     NULL, "Runtime limit test", NULL),
                         0);
    }
    assert_int_equal(dup2(saved_stderr, STDERR_FILENO), STDERR_FILENO);
    assert_int_equal(close(saved_stderr), 0);
    assert_int_equal(close(descriptors[0U]), 0);
    assert_int_equal(
        jg_logging_trace_snapshot(records, 4U, &record_count, &stats), 0);
    assert_true(record_count >= 1U);
    assert_true(stats.suppressed >= 1U);
    jg_logging_shutdown();
}

/** @brief Run the structured logging test group. */
int jg_test_logging(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_configuration),
        cmocka_unit_test(test_emission_and_redaction),
        cmocka_unit_test(test_runtime_limits),
    };

    return cmocka_run_group_tests_name("logging", tests, NULL, NULL);
}
