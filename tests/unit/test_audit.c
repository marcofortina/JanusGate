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
#include <sys/stat.h>
#include <unistd.h>

#include <cmocka.h>
#include <sqlite3.h>

#include "janusgate/audit.h"
#include "janusgate/database.h"

int jg_test_audit(void);

/** @brief Create one private database for an audit test. */
static struct jg_database *open_test_database(char *directory,
                                              size_t directory_size,
                                              char *path,
                                              size_t path_size)
{
    const char template[] = "/tmp/janusgate-audit-XXXXXX";
    struct jg_database *database = NULL;
    int written = 0;

    assert_true(directory_size >= sizeof(template));
    (void)snprintf(directory, directory_size, "%s", template);
    assert_non_null(mkdtemp(directory));
    written = snprintf(path, path_size, "%s/janusgate.db", directory);
    assert_true(written > 0);
    assert_true((size_t)written < path_size);
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    return database;
}

/** @brief Remove one audit test database and its auxiliary files. */
static void remove_test_database(const char *directory, const char *path)
{
    static const char *const suffixes[] = {"-wal", "-shm", ".lkg"};
    char auxiliary[512U];
    size_t index = 0U;

    for (index = 0U; index < sizeof(suffixes) / sizeof(suffixes[0]); ++index) {
        const int written = snprintf(auxiliary, sizeof(auxiliary), "%s%s", path,
                                     suffixes[index]);

        if (written > 0 && (size_t)written < sizeof(auxiliary)) {
            (void)unlink(auxiliary);
        }
    }
    (void)unlink(path);
    (void)rmdir(directory);
}

/** @brief Construct one valid system audit event. */
static struct jg_audit_event make_event(const char *action, const char *details)
{
    const struct jg_audit_event event = {
        .occurred_at = 1000U,
        .actor_type = JG_AUDIT_ACTOR_SYSTEM,
        .source = "local",
        .action = action,
        .object_type = "policy",
        .object_id = "default",
        .details = details,
        .success = true,
        .request_id = "request-1",
    };

    return event;
}

/** @brief Verify chained appends, provenance, and invalid-input rejection. */
static void test_append_and_verify(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_database *database =
        open_test_database(directory, sizeof(directory), path, sizeof(path));
    struct jg_audit_event first = make_event("policy.create", "{}");
    struct jg_audit_event second = make_event("policy.update", "{\"id\":1}");
    struct jg_audit_event invalid = make_event("", "{}");
    struct jg_audit_append_result first_result;
    struct jg_audit_append_result second_result;
    struct jg_audit_record records[1U];
    struct jg_audit_verification verification;
    uint8_t zero[JG_AUDIT_HASH_SIZE] = {0};
    size_t count = 0U;
    uint64_t total = 0U;

    (void)state;
    assert_int_equal(jg_database_audit_append(database, &first, &first_result),
                     0);
    assert_int_equal(first_result.event_id, 1U);
    assert_memory_equal(first_result.previous_hash, zero, sizeof(zero));

    second.occurred_at = 1001U;
    second.actor_type = JG_AUDIT_ACTOR_USER;
    second.has_actor_id = true;
    second.actor_id = 7U;
    second.has_previous_revision = true;
    second.previous_revision = 1U;
    second.has_new_revision = true;
    second.new_revision = 2U;
    second.request_id = "request-2";
    assert_int_equal(
        jg_database_audit_append(database, &second, &second_result), 0);
    assert_int_equal(second_result.event_id, 2U);
    assert_memory_equal(second_result.previous_hash, first_result.event_hash,
                        JG_AUDIT_HASH_SIZE);
    assert_true(memcmp(first_result.event_hash, second_result.event_hash,
                       JG_AUDIT_HASH_SIZE) != 0);

    assert_int_equal(jg_database_audit_append(database, &invalid, NULL),
                     -EINVAL);
    assert_int_equal(jg_database_audit_verify(database, &verification), 0);
    assert_true(verification.valid);
    assert_int_equal(verification.records_inspected, 2U);
    assert_int_equal(verification.first_invalid_id, 0U);

    assert_int_equal(
        jg_database_audit_list(database, 0U, records, 1U, &count, &total), 0);
    assert_int_equal(count, 1U);
    assert_int_equal(total, 2U);
    assert_int_equal(records[0U].event_id, second_result.event_id);
    assert_int_equal(records[0U].actor_type, JG_AUDIT_ACTOR_USER);
    assert_true(records[0U].has_actor_id);
    assert_int_equal(records[0U].actor_id, 7U);
    assert_string_equal(records[0U].details, "{\"id\":1}");
    assert_memory_equal(records[0U].previous_hash, first_result.event_hash,
                        JG_AUDIT_HASH_SIZE);
    assert_memory_equal(records[0U].event_hash, second_result.event_hash,
                        JG_AUDIT_HASH_SIZE);
    assert_false(records[0U].first);

    assert_int_equal(
        jg_database_audit_list(database, 1U, records, 1U, &count, &total), 0);
    assert_int_equal(records[0U].event_id, first_result.event_id);
    assert_true(records[0U].first);
    assert_memory_equal(records[0U].previous_hash, zero, sizeof(zero));

    jg_database_close(database);
    remove_test_database(directory, path);
}

/** @brief Verify that semantic tampering identifies the first broken record. */
static void test_tampering_detected(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_database *database =
        open_test_database(directory, sizeof(directory), path, sizeof(path));
    struct jg_audit_event first = make_event("policy.create", "{}");
    struct jg_audit_event second = make_event("policy.update", "{\"id\":1}");
    struct jg_audit_verification verification;
    sqlite3 *handle = NULL;

    (void)state;
    assert_int_equal(jg_database_audit_append(database, &first, NULL), 0);
    second.occurred_at = 1001U;
    assert_int_equal(jg_database_audit_append(database, &second, NULL), 0);
    jg_database_close(database);

    assert_int_equal(
        sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE, NULL), SQLITE_OK);
    assert_int_equal(
        sqlite3_exec(handle,
                     "UPDATE audit_events SET details='tampered' WHERE id=2;",
                     NULL, NULL, NULL),
        SQLITE_OK);
    assert_int_equal(sqlite3_close(handle), SQLITE_OK);

    database = NULL;
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_audit_verify(database, &verification), 0);
    assert_false(verification.valid);
    assert_int_equal(verification.records_inspected, 2U);
    assert_int_equal(verification.first_invalid_id, 2U);

    jg_database_close(database);
    remove_test_database(directory, path);
}

/** @brief Run the persistent audit-chain test group. */
int jg_test_audit(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_append_and_verify),
        cmocka_unit_test(test_tampering_detected),
    };

    return cmocka_run_group_tests_name("audit", tests, NULL, NULL);
}
