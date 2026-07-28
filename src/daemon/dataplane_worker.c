/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "dataplane_worker.h"

#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>

#include "dataplane.h"

/** Independently updated counters for one data-plane worker. */
struct atomic_dataplane_stats {
    atomic_uint_fast64_t packets;
    atomic_uint_fast64_t accepted;
    atomic_uint_fast64_t blocked;
    atomic_uint_fast64_t malformed;
    atomic_uint_fast64_t fragments;
    atomic_uint_fast64_t streams;
    atomic_uint_fast64_t internal_errors;
};

/** Complete per-queue data-plane context. */
struct jg_dataplane_worker {
    struct jg_policy_store *store;
    struct jg_packet_limits limits;
    struct atomic_dataplane_stats stats;
    size_t reader_index;
};

/** @brief Determine whether packet parser limits are safe. */
static bool limits_valid(const struct jg_packet_limits *limits)
{
    return limits->max_vlan_tags <= JG_PACKET_VLAN_LIMIT &&
           limits->max_ipv6_extensions != 0U &&
           limits->max_ipv6_extension_bytes != 0U;
}

/** @brief Initialize every relaxed per-worker counter. */
static void initialize_stats(struct atomic_dataplane_stats *stats)
{
    atomic_init(&stats->packets, 0U);
    atomic_init(&stats->accepted, 0U);
    atomic_init(&stats->blocked, 0U);
    atomic_init(&stats->malformed, 0U);
    atomic_init(&stats->fragments, 0U);
    atomic_init(&stats->streams, 0U);
    atomic_init(&stats->internal_errors, 0U);
}

/** @brief Increment one relaxed data-plane counter. */
static void increment(atomic_uint_fast64_t *counter)
{
    (void)atomic_fetch_add_explicit(counter, 1U, memory_order_relaxed);
}

/** @brief Account for one explicit stateless classification result. */
static void account_result(struct jg_dataplane_worker *worker,
                           const struct jg_dataplane_result *result)
{
    if (result->verdict == JG_NFQUEUE_ACCEPT) {
        increment(&worker->stats.accepted);
    } else {
        increment(&worker->stats.blocked);
    }
    if (result->reason == JG_DATAPLANE_MALFORMED) {
        increment(&worker->stats.malformed);
    } else if (result->reason == JG_DATAPLANE_FRAGMENT_PENDING) {
        increment(&worker->stats.fragments);
    } else if (result->reason == JG_DATAPLANE_STREAM_PENDING) {
        increment(&worker->stats.streams);
    }
}

/** @brief Create one exclusive policy-reading packet worker. */
int jg_dataplane_worker_create(struct jg_policy_store *store,
                               size_t reader_index,
                               const struct jg_packet_limits *limits,
                               struct jg_dataplane_worker **worker)
{
    struct jg_dataplane_worker *created = NULL;
    const struct jg_policy_snapshot *snapshot = NULL;

    if (worker == NULL) {
        return -EINVAL;
    }
    *worker = NULL;
    if (store == NULL) {
        return -EINVAL;
    }
    created = malloc(sizeof(*created));
    if (created == NULL) {
        return -ENOMEM;
    }
    created->store = store;
    created->reader_index = reader_index;
    if (limits == NULL) {
        jg_packet_limits_default(&created->limits);
    } else {
        created->limits = *limits;
    }
    if (!limits_valid(&created->limits)) {
        free(created);
        return -EINVAL;
    }
    initialize_stats(&created->stats);

    snapshot = jg_policy_store_acquire(store, reader_index);
    if (snapshot == NULL) {
        free(created);
        return -EINVAL;
    }
    jg_policy_store_release(store, reader_index);
    *worker = created;
    return 0;
}

/** @brief Classify one queued packet through a protected policy snapshot. */
enum jg_nfqueue_verdict jg_dataplane_worker_process(
    const struct jg_nfqueue_packet *packet,
    void *context)
{
    struct jg_dataplane_worker *worker = context;
    const struct jg_policy_snapshot *snapshot = NULL;
    struct jg_dataplane_result result;
    int evaluation_result = 0;

    if (packet == NULL || worker == NULL || packet->data == NULL) {
        return JG_NFQUEUE_DROP;
    }
    increment(&worker->stats.packets);
    snapshot = jg_policy_store_acquire(worker->store, worker->reader_index);
    if (snapshot == NULL) {
        increment(&worker->stats.internal_errors);
        increment(&worker->stats.blocked);
        return JG_NFQUEUE_DROP;
    }
    evaluation_result = jg_dataplane_evaluate(
        packet->data, packet->size, &worker->limits, snapshot, &result);
    jg_policy_store_release(worker->store, worker->reader_index);
    if (evaluation_result != 0) {
        increment(&worker->stats.internal_errors);
        increment(&worker->stats.blocked);
        return JG_NFQUEUE_DROP;
    }
    account_result(worker, &result);
    return result.verdict;
}

/** @brief Copy one relaxed snapshot of per-worker classification counters. */
int jg_dataplane_worker_get_stats(const struct jg_dataplane_worker *worker,
                                  struct jg_dataplane_stats *stats)
{
    if (worker == NULL || stats == NULL) {
        return -EINVAL;
    }
    stats->packets =
        atomic_load_explicit(&worker->stats.packets, memory_order_relaxed);
    stats->accepted =
        atomic_load_explicit(&worker->stats.accepted, memory_order_relaxed);
    stats->blocked =
        atomic_load_explicit(&worker->stats.blocked, memory_order_relaxed);
    stats->malformed =
        atomic_load_explicit(&worker->stats.malformed, memory_order_relaxed);
    stats->fragments =
        atomic_load_explicit(&worker->stats.fragments, memory_order_relaxed);
    stats->streams =
        atomic_load_explicit(&worker->stats.streams, memory_order_relaxed);
    stats->internal_errors = atomic_load_explicit(
        &worker->stats.internal_errors, memory_order_relaxed);
    return 0;
}

/** @brief Release one stopped per-queue packet worker. */
void jg_dataplane_worker_destroy(struct jg_dataplane_worker *worker)
{
    free(worker);
}
