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

#include "blocklist_update.h"

int jg_test_blocklist_update(void);

/** Complete private database fixture for blocklist-update tests. */
struct blocklist_update_fixture {
    char directory[64U];
    char database_path[128U];
    struct jg_database *database;
};

/** @brief Create one valid source configuration with bounded test timeouts. */
static struct jg_database_blocklist_source_config source_config(const char *url)
{
    const struct jg_database_blocklist_source_config config = {
        .name = "Updater test",
        .url = url,
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

    return config;
}

/** @brief Open a fresh private database for one update test. */
static int setup_blocklist_update(void **state)
{
    static const char template[] = "/tmp/janusgate-update-XXXXXX";
    struct blocklist_update_fixture *fixture = calloc(1U, sizeof(*fixture));
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

/** @brief Close and remove one private blocklist-update database. */
static int teardown_blocklist_update(void **state)
{
    struct blocklist_update_fixture *fixture = *state;
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

/** @brief Verify transport failures persist retry state and source health. */
static void test_failed_remote_update(void **state)
{
    struct blocklist_update_fixture *fixture = *state;
    const struct jg_database_blocklist_source_config config =
        source_config("https://127.0.0.1:1/blocklist");
    struct jg_database_blocklist_source source;
    struct jg_blocklist_update_result update;

    assert_int_equal(jg_database_create_blocklist_source(fixture->database,
                                                         &config, &source),
                     0);
    assert_int_equal(jg_blocklist_update(fixture->database, source.id,
                                         source.revision, 100U, &update),
                     0);
    assert_true(update.attempted);
    assert_true(update.attempt_result < 0);
    assert_false(update.activated);
    assert_int_equal(update.source.last_attempt_at, 100U);
    assert_int_equal(update.source.consecutive_failures, 1U);
    assert_true(update.source.next_attempt_at >= 110U);
    assert_true(update.source.next_attempt_at <= 112U);
    assert_int_equal(update.source.health, JG_DATABASE_BLOCKLIST_FAILED);
    assert_string_equal(update.source.last_error,
                        jg_blocklist_update_error(update.attempt_result));
}

/** @brief Verify local sources and stale revisions never start a transfer. */
static void test_precondition_failures(void **state)
{
    struct blocklist_update_fixture *fixture = *state;
    const struct jg_database_blocklist_source_config config =
        source_config(NULL);
    struct jg_database_blocklist_source source;
    struct jg_blocklist_update_result update;

    assert_int_equal(jg_database_create_blocklist_source(fixture->database,
                                                         &config, &source),
                     0);
    assert_int_equal(jg_blocklist_update(fixture->database, source.id,
                                         source.revision + 1U, 100U, &update),
                     -EAGAIN);
    assert_false(update.attempted);
    assert_int_equal(jg_blocklist_update(fixture->database, source.id,
                                         source.revision, 100U, &update),
                     -EINVAL);
    assert_false(update.attempted);
    assert_int_equal(jg_blocklist_update(fixture->database, source.id + 1U, 1U,
                                         100U, &update),
                     -ENOENT);
}

/** @brief Verify local imports activate atomically and retain a good list. */
static void test_local_import(void **state)
{
    static const uint8_t valid[] = "alpha.example\nbeta.example\n";
    static const uint8_t invalid[] = "not a domain\n";
    struct blocklist_update_fixture *fixture = *state;
    const struct jg_database_blocklist_source_config config =
        source_config(NULL);
    struct jg_database_blocklist_source source;
    struct jg_database_domain_rule rules[2U];
    struct jg_blocklist_update_result update;
    size_t count = 0U;
    bool has_more = false;

    assert_int_equal(jg_database_create_blocklist_source(fixture->database,
                                                         &config, &source),
                     0);
    assert_int_equal(
        jg_blocklist_import_local(fixture->database, source.id, source.revision,
                                  valid, sizeof(valid) - 1U, 100U, &update),
        0);
    assert_true(update.attempted);
    assert_int_equal(update.attempt_result, 0);
    assert_true(update.activated);
    assert_int_equal(update.source.health, JG_DATABASE_BLOCKLIST_HEALTHY);
    assert_int_equal(update.source.active_entries, 2U);
    assert_int_equal(update.source.last_success_at, 100U);
    assert_int_equal(jg_database_list_domain_rules(fixture->database, 0U, 2U,
                                                   rules, &count, &has_more),
                     0);
    assert_int_equal(count, 2U);
    assert_false(has_more);
    assert_string_equal(rules[0U].domain, "alpha.example");
    assert_string_equal(rules[1U].domain, "beta.example");

    assert_int_equal(
        jg_blocklist_import_local(fixture->database, source.id, source.revision,
                                  invalid, sizeof(invalid) - 1U, 101U, &update),
        0);
    assert_true(update.attempted);
    assert_true(update.attempt_result < 0);
    assert_false(update.activated);
    assert_int_equal(update.source.health, JG_DATABASE_BLOCKLIST_DEGRADED);
    assert_int_equal(update.source.active_entries, 2U);
    assert_int_equal(update.source.last_success_at, 100U);
    assert_int_equal(update.source.last_attempt_at, 101U);
    assert_string_equal(update.source.last_error,
                        jg_blocklist_import_error(update.attempt_result));
}

/** @brief Run the persistent remote-blocklist update test group. */
int jg_test_blocklist_update(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_failed_remote_update,
                                        setup_blocklist_update,
                                        teardown_blocklist_update),
        cmocka_unit_test_setup_teardown(test_precondition_failures,
                                        setup_blocklist_update,
                                        teardown_blocklist_update),
        cmocka_unit_test_setup_teardown(test_local_import,
                                        setup_blocklist_update,
                                        teardown_blocklist_update),
    };

    return cmocka_run_group_tests_name("blocklist update", tests, NULL, NULL);
}
