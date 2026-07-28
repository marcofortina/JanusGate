/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "policy_store.h"

#include <errno.h>
#include <sched.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

/** Conservative cache-line separation for independently written slots. */
#define POLICY_READER_ALIGNMENT 64U

/** One cache-line-separated reader hazard pointer. */
struct reader_slot {
    alignas(
        POLICY_READER_ALIGNMENT) _Atomic(struct jg_policy_snapshot *) snapshot;
};

/** Complete fixed-size hazard-pointer policy store. */
struct jg_policy_store {
    _Atomic(struct jg_policy_snapshot *) current;
    struct reader_slot readers[JG_POLICY_STORE_READER_MAX];
    size_t reader_count;
};

/** @brief Determine whether any reader still protects one snapshot. */
static bool snapshot_in_use(const struct jg_policy_store *store,
                            const struct jg_policy_snapshot *snapshot)
{
    size_t index = 0U;

    for (index = 0U; index < store->reader_count; ++index) {
        if (atomic_load_explicit(&store->readers[index].snapshot,
                                 memory_order_seq_cst) == snapshot) {
            return true;
        }
    }
    return false;
}

/** @brief Wait for every pre-publication reader to leave one snapshot. */
static void wait_for_readers(const struct jg_policy_store *store,
                             const struct jg_policy_snapshot *snapshot)
{
    while (snapshot_in_use(store, snapshot)) {
        (void)sched_yield();
    }
}

/** @brief Create one fixed-reader policy store. */
int jg_policy_store_create(struct jg_policy_snapshot *initial,
                           size_t reader_count,
                           struct jg_policy_store **store)
{
    struct jg_policy_store *created = NULL;
    size_t index = 0U;

    if (store == NULL) {
        return -EINVAL;
    }
    *store = NULL;
    if (initial == NULL || reader_count == 0U ||
        reader_count > JG_POLICY_STORE_READER_MAX) {
        return -EINVAL;
    }
    created = malloc(sizeof(*created));
    if (created == NULL) {
        return -ENOMEM;
    }
    atomic_init(&created->current, initial);
    for (index = 0U; index < JG_POLICY_STORE_READER_MAX; ++index) {
        atomic_init(&created->readers[index].snapshot, NULL);
    }
    created->reader_count = reader_count;
    *store = created;
    return 0;
}

/** @brief Acquire a stable current snapshot through one hazard slot. */
const struct jg_policy_snapshot *jg_policy_store_acquire(
    struct jg_policy_store *store,
    size_t reader_index)
{
    struct jg_policy_snapshot *snapshot = NULL;

    if (store == NULL || reader_index >= store->reader_count) {
        return NULL;
    }
    do {
        snapshot = atomic_load_explicit(&store->current, memory_order_seq_cst);
        atomic_store_explicit(&store->readers[reader_index].snapshot, snapshot,
                              memory_order_seq_cst);
    } while (snapshot !=
             atomic_load_explicit(&store->current, memory_order_seq_cst));
    return snapshot;
}

/** @brief Clear one reader's hazard slot. */
void jg_policy_store_release(struct jg_policy_store *store, size_t reader_index)
{
    if (store == NULL || reader_index >= store->reader_count) {
        return;
    }
    atomic_store_explicit(&store->readers[reader_index].snapshot, NULL,
                          memory_order_seq_cst);
}

/** @brief Publish a snapshot and reclaim its quiescent predecessor. */
int jg_policy_store_replace(struct jg_policy_store *store,
                            struct jg_policy_snapshot *replacement)
{
    struct jg_policy_snapshot *previous = NULL;

    if (store == NULL || replacement == NULL) {
        return -EINVAL;
    }
    if (atomic_load_explicit(&store->current, memory_order_seq_cst) ==
        replacement) {
        return -EALREADY;
    }
    previous = atomic_exchange_explicit(&store->current, replacement,
                                        memory_order_seq_cst);
    wait_for_readers(store, previous);
    jg_policy_snapshot_destroy(previous);
    return 0;
}

/** @brief Load, validate, and atomically publish one persistent policy view. */
int jg_policy_store_reload_from_database(struct jg_policy_store *store,
                                         struct jg_database *database,
                                         uint64_t generation)
{
    struct jg_policy_snapshot *replacement = NULL;
    int result = 0;

    if (store == NULL || database == NULL || generation == 0U) {
        return -EINVAL;
    }
    result =
        jg_database_load_policy_snapshot(database, generation, &replacement);
    if (result == 0) {
        result = jg_policy_store_replace(store, replacement);
        if (result == 0) {
            replacement = NULL;
        }
    }
    jg_policy_snapshot_destroy(replacement);
    return result;
}

/** @brief Release the current snapshot and policy store allocation. */
void jg_policy_store_destroy(struct jg_policy_store *store)
{
    struct jg_policy_snapshot *current = NULL;

    if (store == NULL) {
        return;
    }
    current = atomic_load_explicit(&store->current, memory_order_seq_cst);
    jg_policy_snapshot_destroy(current);
    free(store);
}
