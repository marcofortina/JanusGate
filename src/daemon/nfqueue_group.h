/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file nfqueue_group.h
 * @brief Independent worker group for a contiguous NFQUEUE range.
 */

#ifndef JANUSGATE_DAEMON_NFQUEUE_GROUP_H
#define JANUSGATE_DAEMON_NFQUEUE_GROUP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nfqueue.h"

/**
 * @brief Complete configuration shared by one NFQUEUE worker group.
 */
struct jg_nfqueue_group_config {
    /** First queue number in the contiguous range. */
    uint16_t queue_first;
    /** Number of queues and worker threads. */
    uint16_t queue_count;
    /** Expected physical data-ingress interface index. */
    uint32_t ingress_index;
    /** Maximum packets retained by every kernel queue. */
    uint32_t queue_length;
    /** Requested netlink receive-buffer bytes for every worker. */
    uint32_t receive_buffer_size;
    /** First CPU used when worker pinning is enabled. */
    uint32_t first_cpu;
    /** Whether queue overflow or absence permits traffic. */
    bool fail_open;
    /** Whether workers are pinned to consecutive CPU identifiers. */
    bool pin_workers;
};

/** Opaque running or stopped group of queue workers. */
struct jg_nfqueue_group;

/**
 * @brief Validate one complete worker-group configuration.
 *
 * @param[in] config Configuration to validate.
 *
 * @return 0 on success.
 * @return -EINVAL for a null configuration, zero worker count, or invalid
 * worker fields.
 * @return -ERANGE when the queue range, worker count, or requested CPU range
 * exceeds supported bounds.
 *
 * @thread_safety This function is reentrant.
 */
int jg_nfqueue_group_config_validate(
    const struct jg_nfqueue_group_config *config);

/**
 * @brief Open all queues and start one independent thread per queue.
 *
 * The optional @p contexts array must contain one processor context per queue.
 * A null array passes a null context to every worker.
 *
 * @param[in] config Validated group configuration.
 * @param[in] processor Packet decision function shared by all workers.
 * @param[in,out] contexts Per-worker processor contexts, or null.
 * @param[out] group Receives the owned running group.
 *
 * @return 0 on success.
 * @return A negative errno-style validation, queue, allocation, affinity, or
 * thread error otherwise.
 *
 * @thread_safety Start calls managing overlapping queue ranges must be
 * externally serialized.
 *
 * @side_effects Opens every queue and starts worker threads.
 */
int jg_nfqueue_group_start(const struct jg_nfqueue_group_config *config,
                           jg_nfqueue_processor processor,
                           void *const *contexts,
                           struct jg_nfqueue_group **group);

/**
 * @brief Request an orderly non-blocking stop of every worker.
 *
 * @param[in,out] group Running group.
 *
 * @return 0 when the request is present.
 * @return -EINVAL for a null group.
 * @return A negative errno-style event-notification error otherwise.
 *
 * @thread_safety Safe to call concurrently and repeatedly.
 *
 * @side_effects Makes the shared stop descriptor readable.
 */
int jg_nfqueue_group_request_stop(struct jg_nfqueue_group *group);

/**
 * @brief Request an orderly stop and join every worker.
 *
 * @param[in,out] group Running or stopped group.
 *
 * @return 0 after an orderly stop.
 * @return The first negative worker or join error otherwise.
 *
 * @thread_safety Exactly one control thread may join a group.
 *
 * @side_effects Makes the stop descriptor readable and waits for every worker.
 */
int jg_nfqueue_group_join(struct jg_nfqueue_group *group);

/**
 * @brief Aggregate current worker counters without a global packet-path lock.
 *
 * Counter sums saturate at UINT64_MAX.
 *
 * @param[in] group Worker group.
 * @param[out] stats Receives aggregate counters.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 *
 * @thread_safety Safe while workers are running.
 */
int jg_nfqueue_group_get_stats(const struct jg_nfqueue_group *group,
                               struct jg_nfqueue_stats *stats);

/**
 * @brief Stop if necessary and release a worker group.
 *
 * @param[in,out] group Group to release; null is accepted.
 *
 * @thread_safety No other control operation may use the group concurrently.
 *
 * @side_effects Stops threads, unbinds queues, and closes their sockets.
 */
void jg_nfqueue_group_destroy(struct jg_nfqueue_group *group);

#endif
