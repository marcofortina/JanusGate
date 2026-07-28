/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <sched.h>
#include <stdatomic.h>

#include <pthread.h>

#include <cmocka.h>

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
        cmocka_unit_test(test_arguments),
    };

    return cmocka_run_group_tests_name("policy store", tests, NULL, NULL);
}
