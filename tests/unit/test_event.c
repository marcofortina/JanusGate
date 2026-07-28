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
#include <unistd.h>

#include <cmocka.h>

#include "janusgate/database.h"
#include "janusgate/event.h"

int jg_test_event(void);

/** Complete private database fixture for operational-event tests. */
struct event_fixture {
    char directory[64U];
    char database_path[128U];
    struct jg_database *database;
};

/** @brief Open one fresh private event database. */
static int setup_event(void **state)
{
    static const char template[] = "/tmp/janusgate-event-XXXXXX";
    struct event_fixture *fixture = calloc(1U, sizeof(*fixture));
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

/** @brief Close and remove one private event database. */
static int teardown_event(void **state)
{
    struct event_fixture *fixture = *state;
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

/** @brief Verify canonical append, stable paging, and exact filters. */
static void test_event_lifecycle(void **state)
{
    struct event_fixture *fixture = *state;
    const struct jg_event first = {
        .occurred_at = 100U,
        .severity = JG_EVENT_SEVERITY_INFO,
        .component = "daemon",
        .code = "startup.complete",
        .message = "Packet enforcement started.",
        .details = "{\"queues\":4,\"bridge\":\"jgbr0\"}",
    };
    const struct jg_event second = {
        .occurred_at = 101U,
        .severity = JG_EVENT_SEVERITY_WARNING,
        .component = "blocklist",
        .code = "source.degraded",
        .message = "A remote source retained its last-known-good list.",
        .details = "{\"source_id\":7}",
    };
    const struct jg_event third = {
        .occurred_at = 102U,
        .severity = JG_EVENT_SEVERITY_WARNING,
        .component = "daemon",
        .code = "queue.pressure",
        .message = "Queue pressure crossed its warning threshold.",
        .details = "{}",
    };
    struct jg_event_record records[2U];
    struct jg_event_filter filter = {
        .severity = JG_EVENT_SEVERITY_ANY,
    };
    uint64_t identifier = 0U;
    size_t count = 0U;
    bool has_more = false;

    assert_int_equal(
        jg_database_event_append(fixture->database, &first, &identifier), 0);
    assert_int_equal(identifier, 1U);
    assert_int_equal(jg_database_event_append(fixture->database, &second, NULL),
                     0);
    assert_int_equal(jg_database_event_append(fixture->database, &third, NULL),
                     0);

    assert_int_equal(jg_database_event_list(fixture->database, &filter, records,
                                            2U, &count, &has_more),
                     0);
    assert_int_equal(count, 2U);
    assert_true(has_more);
    assert_int_equal(records[0U].id, 1U);
    assert_string_equal(records[0U].component, "daemon");
    assert_string_equal(records[0U].details,
                        "{\"bridge\":\"jgbr0\",\"queues\":4}");
    assert_int_equal(records[1U].id, 2U);

    filter.after_id = records[1U].id;
    assert_int_equal(jg_database_event_list(fixture->database, &filter, records,
                                            2U, &count, &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_false(has_more);
    assert_int_equal(records[0U].id, 3U);

    filter.after_id = 0U;
    filter.severity = JG_EVENT_SEVERITY_WARNING;
    filter.component = "daemon";
    assert_int_equal(jg_database_event_list(fixture->database, &filter, records,
                                            2U, &count, &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_int_equal(records[0U].id, 3U);
    assert_string_equal(records[0U].code, "queue.pressure");
}

/** @brief Verify invalid administrative content is rejected before storage. */
static void test_event_validation(void **state)
{
    struct event_fixture *fixture = *state;
    struct jg_event event = {
        .occurred_at = 100U,
        .severity = JG_EVENT_SEVERITY_INFO,
        .component = "daemon",
        .code = "valid.code",
        .message = "Valid message.",
        .details = "{}",
    };
    struct jg_event_record record;
    struct jg_event_filter filter = {
        .severity = JG_EVENT_SEVERITY_ANY,
    };
    size_t count = 0U;
    bool has_more = false;

    event.component = "Invalid Component";
    assert_int_equal(jg_database_event_append(fixture->database, &event, NULL),
                     -EINVAL);
    event.component = "daemon";
    event.message = "line\nbreak";
    assert_int_equal(jg_database_event_append(fixture->database, &event, NULL),
                     -EILSEQ);
    event.message = "Valid message.";
    event.details = "[]";
    assert_int_equal(jg_database_event_append(fixture->database, &event, NULL),
                     -EINVAL);
    assert_int_equal(jg_database_event_list(fixture->database, &filter, &record,
                                            1U, &count, &has_more),
                     0);
    assert_int_equal(count, 0U);
    assert_false(has_more);
}

/** @brief Verify newest-first diagnostic selection of severe events. */
static void test_recent_errors(void **state)
{
    struct event_fixture *fixture = *state;
    struct jg_event event = {
        .occurred_at = 100U,
        .severity = JG_EVENT_SEVERITY_INFO,
        .component = "daemon",
        .code = "test.event",
        .message = "Test event.",
        .details = "{}",
    };
    struct jg_event_record records[2U];
    size_t count = 0U;

    assert_int_equal(jg_database_event_append(fixture->database, &event, NULL),
                     0);
    event.occurred_at = 101U;
    event.severity = JG_EVENT_SEVERITY_ERROR;
    event.code = "test.error";
    assert_int_equal(jg_database_event_append(fixture->database, &event, NULL),
                     0);
    event.occurred_at = 102U;
    event.severity = JG_EVENT_SEVERITY_WARNING;
    event.code = "test.warning";
    assert_int_equal(jg_database_event_append(fixture->database, &event, NULL),
                     0);
    event.occurred_at = 103U;
    event.severity = JG_EVENT_SEVERITY_CRITICAL;
    event.code = "test.critical";
    assert_int_equal(jg_database_event_append(fixture->database, &event, NULL),
                     0);
    assert_int_equal(jg_database_event_list_recent_errors(fixture->database,
                                                          records, 2U, &count),
                     0);
    assert_int_equal(count, 2U);
    assert_int_equal(records[0U].id, 4U);
    assert_int_equal(records[0U].severity, JG_EVENT_SEVERITY_CRITICAL);
    assert_int_equal(records[1U].id, 2U);
    assert_int_equal(records[1U].severity, JG_EVENT_SEVERITY_ERROR);
}

/** @brief Run the bounded operational-event test group. */
int jg_test_event(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_event_lifecycle, setup_event,
                                        teardown_event),
        cmocka_unit_test_setup_teardown(test_event_validation, setup_event,
                                        teardown_event),
        cmocka_unit_test_setup_teardown(test_recent_errors, setup_event,
                                        teardown_event),
    };

    return cmocka_run_group_tests_name("event", tests, NULL, NULL);
}
