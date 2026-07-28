/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file policy_store.h
 * @brief Lock-free readers for atomically replaceable policy snapshots.
 */

#ifndef JANUSGATE_DAEMON_POLICY_STORE_H
#define JANUSGATE_DAEMON_POLICY_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "janusgate/database.h"
#include "janusgate/network.h"
#include "janusgate/policy.h"

/** Packet workers plus one serialized management policy reader. */
#define JG_POLICY_STORE_READER_MAX (JG_NETWORK_QUEUE_COUNT_MAX + 1U)

/** Opaque owner of one current immutable policy snapshot. */
struct jg_policy_store;

/**
 * @brief Create a policy store with a fixed reader-slot count.
 *
 * Ownership of @p initial transfers only on success.
 *
 * @param[in,out] initial Initial immutable snapshot.
 * @param[in] reader_count Number of independent reader slots.
 * @param[out] store Receives the owned policy store.
 *
 * @return 0 on success.
 * @return -EINVAL for a null snapshot or destination, zero readers, or too
 * many readers.
 * @return -ENOMEM when allocation fails.
 *
 * @thread_safety Concurrent creation calls are independent.
 */
int jg_policy_store_create(struct jg_policy_snapshot *initial,
                           size_t reader_count,
                           struct jg_policy_store **store);

/**
 * @brief Protect and return the current snapshot for one reader.
 *
 * @param[in,out] store Policy store.
 * @param[in] reader_index Exclusive reader slot.
 *
 * @return The current immutable snapshot.
 * @return null for an invalid store or reader index.
 *
 * @thread_safety Each reader slot belongs to exactly one thread. Different
 * slots acquire without locks and may run concurrently with replacement.
 */
const struct jg_policy_snapshot *jg_policy_store_acquire(
    struct jg_policy_store *store,
    size_t reader_index);

/**
 * @brief Release one reader's protected snapshot.
 *
 * @param[in,out] store Policy store.
 * @param[in] reader_index Exclusive reader slot.
 *
 * @thread_safety Must be called by the thread which acquired the slot.
 */
void jg_policy_store_release(struct jg_policy_store *store,
                             size_t reader_index);

/**
 * @brief Atomically publish a complete replacement snapshot.
 *
 * Ownership of @p replacement transfers on success. The previous snapshot is
 * destroyed only after all readers which observed it have released it.
 *
 * @param[in,out] store Policy store.
 * @param[in,out] replacement Complete immutable replacement.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -EALREADY when @p replacement is already current.
 *
 * @thread_safety Readers remain lock-free. Replacement calls require one
 * externally serialized writer.
 *
 * @side_effects May yield while readers finish, then destroys the old snapshot.
 */
int jg_policy_store_replace(struct jg_policy_store *store,
                            struct jg_policy_snapshot *replacement);

/**
 * @brief Build and atomically publish policy from one database view.
 *
 * A load or validation failure leaves the current snapshot unchanged.
 *
 * @param[in,out] store Policy store receiving the replacement.
 * @param[in,out] database Open persistent database.
 * @param[in] generation Nonzero generation assigned to the replacement.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument or zero generation.
 * @return A negative errno-style database, allocation, validation, or
 * replacement error otherwise.
 *
 * @thread_safety Calls require one externally serialized writer. Readers
 * remain lock-free.
 *
 * @side_effects Reads persistent rules and reclaims the previous snapshot
 * after its readers become quiescent.
 */
int jg_policy_store_reload_from_database(struct jg_policy_store *store,
                                         struct jg_database *database,
                                         uint64_t generation);

/**
 * @brief Destroy a policy store and its current snapshot.
 *
 * @param[in,out] store Store to release; null is accepted.
 *
 * @thread_safety No reader or writer may remain active.
 */
void jg_policy_store_destroy(struct jg_policy_store *store);

#endif
