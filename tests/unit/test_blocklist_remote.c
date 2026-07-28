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

#include "janusgate/blocklist_remote.h"

int jg_test_blocklist_remote(void);

/** @brief Build a valid remote-source configuration for isolated tests. */
static struct jg_blocklist_remote_config test_config(void)
{
    struct jg_blocklist_remote_config config;

    (void)memset(&config, 0, sizeof(config));
    config.url = "https://127.0.0.1:1/blocklist";
    config.format = JG_BLOCKLIST_FORMAT_DOMAIN;
    config.mode = JG_BLOCKLIST_STRICT;
    config.attribution = "remote test source";
    jg_blocklist_limits_default(&config.import_limits);
    config.max_download_bytes = config.import_limits.max_file_bytes;
    config.connect_timeout_ms = 100U;
    config.transfer_timeout_ms = 100U;
    config.redirect_limit = 2U;
    config.update_interval_seconds = 3600U;
    config.retry_base_seconds = 10U;
    config.retry_max_seconds = 80U;
    return config;
}

/** @brief Verify zero-state initialization and due-time boundaries. */
static void test_schedule_state(void **state)
{
    struct jg_blocklist_remote_state remote_state;

    (void)state;
    (void)memset(&remote_state, 0xa5, sizeof(remote_state));
    jg_blocklist_remote_state_init(&remote_state);

    assert_true(jg_blocklist_remote_due(&remote_state, 0U));
    assert_int_equal(remote_state.consecutive_failures, 0U);
    assert_string_equal(remote_state.etag, "");
    assert_string_equal(remote_state.last_modified, "");

    remote_state.next_attempt_at = 50U;
    assert_false(jg_blocklist_remote_due(&remote_state, 49U));
    assert_true(jg_blocklist_remote_due(&remote_state, 50U));
    assert_false(jg_blocklist_remote_due(NULL, 50U));
}

/** @brief Verify rejection of insecure and inconsistent configurations. */
static void test_invalid_configuration(void **state)
{
    struct jg_blocklist_remote_config config = test_config();
    struct jg_blocklist_remote_state remote_state;
    enum jg_blocklist_remote_status status;
    struct jg_blocklist *blocklist = NULL;

    (void)state;
    jg_blocklist_remote_state_init(&remote_state);
    config.url = "http://example.test/blocklist";
    assert_int_equal(jg_blocklist_remote_update(&config, &remote_state, 42U,
                                                &status, &blocklist, NULL),
                     -EINVAL);
    assert_int_equal(remote_state.last_attempt_at, 0U);
    assert_null(blocklist);

    config = test_config();
    (void)memset(remote_state.etag, 'x', sizeof(remote_state.etag));
    assert_int_equal(jg_blocklist_remote_update(&config, &remote_state, 42U,
                                                &status, &blocklist, NULL),
                     -EINVAL);
    assert_int_equal(remote_state.last_attempt_at, 0U);

    jg_blocklist_remote_state_init(&remote_state);
    config.signature_url = "https://example.test/signature";
    assert_int_equal(jg_blocklist_remote_update(&config, &remote_state, 42U,
                                                &status, &blocklist, NULL),
                     -EINVAL);
}

/** @brief Verify a transport failure preserves output and schedules retry. */
static void test_failed_attempt(void **state)
{
    const struct jg_blocklist_remote_config config = test_config();
    struct jg_blocklist_remote_state remote_state;
    struct jg_blocklist_remote_report report;
    enum jg_blocklist_remote_status status;
    struct jg_blocklist *blocklist = NULL;
    int result = 0;

    (void)state;
    jg_blocklist_remote_state_init(&remote_state);
    result = jg_blocklist_remote_update(&config, &remote_state, 100U, &status,
                                        &blocklist, &report);

    assert_true(result < 0);
    assert_null(blocklist);
    assert_int_equal(report.http_status, 0L);
    assert_int_equal(remote_state.last_attempt_at, 100U);
    assert_int_equal(remote_state.last_success_at, 0U);
    assert_int_equal(remote_state.consecutive_failures, 1U);
    assert_true(remote_state.next_attempt_at >= 110U);
    assert_true(remote_state.next_attempt_at <= 112U);
}

/** @brief Run the secure remote-blocklist update test group. */
int jg_test_blocklist_remote(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_schedule_state),
        cmocka_unit_test(test_invalid_configuration),
        cmocka_unit_test(test_failed_attempt),
    };

    return cmocka_run_group_tests_name("blocklist remote", tests, NULL, NULL);
}
