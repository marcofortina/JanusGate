/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file dataplane_worker.h
 * @brief Per-queue policy reader and packet-decision context.
 */

#ifndef JANUSGATE_DAEMON_DATAPLANE_WORKER_H
#define JANUSGATE_DAEMON_DATAPLANE_WORKER_H

#include <stddef.h>
#include <stdint.h>

#include "fragment.h"
#include "janusgate/packet.h"
#include "nfqueue.h"
#include "policy_store.h"
#include "tcp_reset.h"
#include "tcp_stream.h"

/**
 * @brief Synchronous output function for one pair of TCP reset frames.
 *
 * @param[in] resets Complete reset frame pair.
 * @param[in,out] context Sender-specific context.
 *
 * @return 0 on success.
 * @return A negative errno-style error otherwise.
 */
typedef int (*jg_dataplane_reset_sender)(const struct jg_tcp_reset_pair *resets,
                                         void *context);

/**
 * @brief Lock-free counters maintained by one data-plane worker.
 */
struct jg_dataplane_stats {
    /** Packets submitted to stateless classification. */
    uint64_t packets;
    /** Immediate accepted verdicts. */
    uint64_t accepted;
    /** Immediate blocked verdicts. */
    uint64_t blocked;
    /** Malformed packets or selected protocol messages. */
    uint64_t malformed;
    /** Fragmented packets deferred to fragment state. */
    uint64_t fragments;
    /** TCP packets deferred to stream state. */
    uint64_t streams;
    /** Blocked TCP connections reset successfully. */
    uint64_t tcp_resets;
    /** Internal classification failures closed with a drop. */
    uint64_t internal_errors;
};

/** Opaque per-queue data-plane context. */
struct jg_dataplane_worker;

/**
 * @brief Create one worker bound to an exclusive policy-reader slot.
 *
 * @param[in,out] store Shared replaceable policy store.
 * @param[in] reader_index Exclusive policy reader index.
 * @param[in] limits Packet parser limits, or null for conservative defaults.
 * @param[in] fragment_limits Fragment bounds, or null for defaults.
 * @param[in] stream_limits TCP stream bounds, or null for defaults.
 * @param[out] worker Receives the owned worker.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments, limits, or reader index.
 * @return -ERANGE when a supported state limit is exceeded.
 * @return -EOVERFLOW when a state arena size cannot be represented.
 * @return -ENOMEM when allocation fails.
 *
 * @thread_safety Each reader index may belong to only one worker.
 */
int jg_dataplane_worker_create(struct jg_policy_store *store,
                               size_t reader_index,
                               const struct jg_packet_limits *limits,
                               const struct jg_fragment_limits *fragment_limits,
                               const struct jg_tcp_stream_limits *stream_limits,
                               struct jg_dataplane_worker **worker);

/**
 * @brief Configure synchronous TCP reset output for blocked DNS streams.
 *
 * @param[in,out] worker Data-plane worker to configure.
 * @param[in] sender Reset output function.
 * @param[in,out] context Context passed unchanged to @p sender.
 *
 * @return 0 on success.
 * @return -EINVAL for a null worker or sender.
 *
 * @thread_safety Configure the worker before its queue thread starts.
 */
int jg_dataplane_worker_set_reset_sender(struct jg_dataplane_worker *worker,
                                         jg_dataplane_reset_sender sender,
                                         void *context);

/**
 * @brief Process one NFQUEUE packet against the current policy snapshot.
 *
 * This function matches @ref jg_nfqueue_processor and may be passed directly
 * to a queue worker or group.
 *
 * @param[in] packet Immutable packet and kernel metadata.
 * @param[in,out] context Data-plane worker.
 *
 * @return An explicit accept or drop verdict.
 *
 * @thread_safety Exactly one queue thread may use a worker context.
 */
enum jg_nfqueue_verdict jg_dataplane_worker_process(
    const struct jg_nfqueue_packet *packet,
    void *context);

/**
 * @brief Read a relaxed coherent snapshot of data-plane counters.
 *
 * @param[in] worker Data-plane worker.
 * @param[out] stats Receives current counters.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 *
 * @thread_safety Safe while the worker processes packets.
 */
int jg_dataplane_worker_get_stats(const struct jg_dataplane_worker *worker,
                                  struct jg_dataplane_stats *stats);

/**
 * @brief Read the worker's detailed fragment-tracker counters.
 *
 * @param[in] worker Data-plane worker.
 * @param[out] stats Receives current fragment counters.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 *
 * @thread_safety Safe while the worker processes packets.
 */
int jg_dataplane_worker_get_fragment_stats(
    const struct jg_dataplane_worker *worker,
    struct jg_fragment_stats *stats);

/**
 * @brief Read the worker's detailed TCP stream-tracker counters.
 *
 * @param[in] worker Data-plane worker.
 * @param[out] stats Receives current stream counters.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 *
 * @thread_safety Safe while the worker processes packets.
 */
int jg_dataplane_worker_get_stream_stats(
    const struct jg_dataplane_worker *worker,
    struct jg_tcp_stream_stats *stats);

/**
 * @brief Release one stopped data-plane worker.
 *
 * @param[in,out] worker Worker to release; null is accepted.
 *
 * @thread_safety The worker must no longer process packets.
 */
void jg_dataplane_worker_destroy(struct jg_dataplane_worker *worker);

#endif
