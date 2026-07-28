/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>
#include <unistd.h>

#include <cmocka.h>

#include "janusgate/database.h"
#include "janusgate/policy.h"
#include "policy_store.h"

int jg_test_policy_store(void);

/** State exchanged with one policy-replacement test thread. */
struct replacement_task {
    struct jg_policy_store *store;
    struct jg_policy_snapshot *replacement;
    atomic_bool completed;
    int result;
};

/** @brief Build one empty snapshot with the requested generation. */
static struct jg_policy_snapshot *build_snapshot(uint64_t generation)
{
    struct jg_policy_snapshot *snapshot = NULL;

    assert_int_equal(jg_policy_snapshot_build(NULL, 0U, generation, &snapshot),
                     0);
    return snapshot;
}

/** @brief Create one private temporary database path. */
static void make_database_path(char *directory,
                               size_t directory_size,
                               char *path,
                               size_t path_size)
{
    const char template[] = "/tmp/janusgate-policy-store-XXXXXX";
    int written = 0;

    assert_true(directory_size >= sizeof(template));
    (void)snprintf(directory, directory_size, "%s", template);
    assert_non_null(mkdtemp(directory));
    written = snprintf(path, path_size, "%s/janusgate.db", directory);
    assert_true(written > 0);
    assert_true((size_t)written < path_size);
}

/** @brief Remove one policy-store test database and directory. */
static void remove_database(const char *directory, const char *path)
{
    char auxiliary[512U];
    int written = snprintf(auxiliary, sizeof(auxiliary), "%s-wal", path);

    if (written > 0 && (size_t)written < sizeof(auxiliary)) {
        (void)unlink(auxiliary);
    }
    written = snprintf(auxiliary, sizeof(auxiliary), "%s-shm", path);
    if (written > 0 && (size_t)written < sizeof(auxiliary)) {
        (void)unlink(auxiliary);
    }
    written = snprintf(auxiliary, sizeof(auxiliary), "%s.lkg", path);
    if (written > 0 && (size_t)written < sizeof(auxiliary)) {
        (void)unlink(auxiliary);
    }
    (void)unlink(path);
    (void)rmdir(directory);
}

/** @brief Read one snapshot generation through a protected slot. */
static uint64_t read_generation(struct jg_policy_store *store,
                                size_t reader_index)
{
    const struct jg_policy_snapshot *snapshot =
        jg_policy_store_acquire(store, reader_index);
    struct jg_policy_snapshot_info info;

    assert_non_null(snapshot);
    assert_int_equal(jg_policy_snapshot_get_info(snapshot, &info), 0);
    jg_policy_store_release(store, reader_index);
    return info.generation;
}

/** @brief Replace a policy snapshot and report reclamation completion. */
static void *replace_snapshot(void *context)
{
    struct replacement_task *task = context;

    task->result = jg_policy_store_replace(task->store, task->replacement);
    atomic_store_explicit(&task->completed, true, memory_order_release);
    return NULL;
}

/** @brief Verify atomic replacement and independent reader slots. */
static void test_replacement(void **state)
{
    struct jg_policy_snapshot *initial = build_snapshot(1U);
    struct jg_policy_snapshot *replacement = build_snapshot(2U);
    struct jg_policy_store *store = NULL;

    (void)state;
    assert_int_equal(jg_policy_store_create(initial, 2U, &store), 0);
    assert_int_equal(read_generation(store, 0U), 1U);
    assert_int_equal(read_generation(store, 1U), 1U);
    assert_int_equal(jg_policy_store_replace(store, replacement), 0);
    assert_int_equal(read_generation(store, 0U), 2U);
    assert_int_equal(read_generation(store, 1U), 2U);
    jg_policy_store_destroy(store);
}

/** @brief Verify that replacement waits for an existing protected reader. */
static void test_reader_quiescence(void **state)
{
    struct jg_policy_snapshot *initial = build_snapshot(1U);
    struct replacement_task task = {
        .replacement = build_snapshot(2U),
    };
    const struct jg_policy_snapshot *held = NULL;
    struct jg_policy_snapshot_info info;
    pthread_t thread;
    size_t attempt = 0U;

    (void)state;
    atomic_init(&task.completed, false);
    assert_int_equal(jg_policy_store_create(initial, 2U, &task.store), 0);
    held = jg_policy_store_acquire(task.store, 0U);
    assert_non_null(held);
    assert_int_equal(pthread_create(&thread, NULL, replace_snapshot, &task), 0);

    for (attempt = 0U; attempt < 100000U; ++attempt) {
        if (read_generation(task.store, 1U) == 2U) {
            break;
        }
        (void)sched_yield();
    }
    assert_true(attempt < 100000U);
    assert_false(atomic_load_explicit(&task.completed, memory_order_acquire));
    assert_int_equal(jg_policy_snapshot_get_info(held, &info), 0);
    assert_int_equal(info.generation, 1U);

    jg_policy_store_release(task.store, 0U);
    assert_int_equal(pthread_join(thread, NULL), 0);
    assert_true(atomic_load_explicit(&task.completed, memory_order_acquire));
    assert_int_equal(task.result, 0);
    jg_policy_store_destroy(task.store);
}

/** @brief Verify validated database reload and failure preservation. */
static void test_database_reload(void **state)
{
    const struct jg_policy_rule_input rule = {
        .id = 7U,
        .domain = "blocked.test",
        .effect = JG_POLICY_BLOCK,
        .source = JG_POLICY_SOURCE_EXPLICIT,
        .scope = {.type = JG_POLICY_SCOPE_GLOBAL},
        .attribution = "policy store test",
    };
    char directory[64U];
    char path[512U];
    struct jg_policy_snapshot *initial = build_snapshot(1U);
    struct jg_policy_store *store = NULL;
    struct jg_database *database = NULL;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_replace_domain_rules(database, &rule, 1U), 0);
    assert_int_equal(jg_policy_store_create(initial, 1U, &store), 0);
    assert_int_equal(jg_policy_store_reload_from_database(store, database, 2U),
                     0);
    assert_int_equal(read_generation(store, 0U), 2U);
    assert_int_equal(jg_policy_store_reload_from_database(store, database, 0U),
                     -EINVAL);
    assert_int_equal(read_generation(store, 0U), 2U);
    assert_int_equal(jg_policy_store_reload_from_database(NULL, database, 3U),
                     -EINVAL);
    assert_int_equal(jg_policy_store_reload_from_database(store, NULL, 3U),
                     -EINVAL);
    jg_policy_store_destroy(store);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify invalid slots and ownership-preserving failures. */
static void test_arguments(void **state)
{
    struct jg_policy_snapshot *snapshot = build_snapshot(1U);
    struct jg_policy_store *store = NULL;

    (void)state;
    assert_int_equal(jg_policy_store_create(snapshot, 0U, &store), -EINVAL);
    assert_null(store);
    assert_int_equal(jg_policy_store_create(
                         snapshot, JG_POLICY_STORE_READER_MAX + 1U, &store),
                     -EINVAL);
    assert_int_equal(jg_policy_store_create(snapshot, 1U, &store), 0);
    assert_int_equal(jg_policy_store_replace(store, snapshot), -EALREADY);
    assert_null(jg_policy_store_acquire(store, 1U));
    jg_policy_store_release(store, 1U);
    assert_int_equal(jg_policy_store_replace(store, NULL), -EINVAL);
    jg_policy_store_destroy(store);
    jg_policy_store_destroy(NULL);
}

/** @brief Run the atomic policy-store test group. */
int jg_test_policy_store(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_replacement),
        cmocka_unit_test(test_reader_quiescence),
        cmocka_unit_test(test_database_reload),
        cmocka_unit_test(test_arguments),
    };

    return cmocka_run_group_tests_name("policy store", tests, NULL, NULL);
}
