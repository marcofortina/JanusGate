/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file policy_stats_collector.h
 * @brief Non-blocking packet-path policy-statistics collection.
 */

#ifndef JANUSGATE_DAEMON_POLICY_STATS_COLLECTOR_H
#define JANUSGATE_DAEMON_POLICY_STATS_COLLECTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/database.h"
#include "janusgate/policy_stats.h"

/** Default number of queued packet-path statistic events. */
#define JG_POLICY_STATS_QUEUE_DEFAULT 4096U

/** Smallest supported collector queue. */
#define JG_POLICY_STATS_QUEUE_MIN 2U

/** Largest supported collector queue. */
#define JG_POLICY_STATS_QUEUE_MAX 65536U

/** Selected and enforcing rules retained across both policy dimensions. */
#define JG_POLICY_STATS_EVENT_RULE_MAX 4U

/** One matching rule within a self-contained packet event. */
struct jg_policy_stats_event_rule {
    /** Domain or destination rule namespace. */
    enum jg_policy_stats_dimension dimension;
    /** Positive database identifier valid for the sampled policy generation. */
    uint64_t rule_id;
    /** Immutable identity copied from the matching policy snapshot. */
    uint8_t statistics_id[JG_POLICY_RULE_IDENTITY_SIZE];
    /** Whether this rule selected its dimension's verdict. */
    bool decision;
    /** Whether this rule would block when enforced. */
    bool would_block;
    /** Whether this rule enforced a block, including behind observation. */
    bool enforced_block;
    /** Whether this rule enforced allow, including behind observation. */
    bool allow_decision;
    /** Whether a higher-precedence matching rule superseded this rule. */
    bool shadowed;
};

/** Self-contained statistic event copied from one packet worker. */
struct jg_policy_stats_event {
    /** Immutable policy generation used to produce this event. */
    uint64_t policy_generation;
    /** Observation time as Unix seconds. */
    uint64_t occurred_at;
    /** Primary inspection path for this packet decision. */
    enum jg_policy_stats_path path;
    /** Client identity available during matching. */
    struct jg_policy_client client;
    /** Queried domain or visible SNI, empty for destination-only inspection. */
    char domain[JG_DOMAIN_NAME_MAX + 1U];
    /** DNS query type, or zero outside DNS inspection. */
    uint16_t query_type;
    /** Whether at least one rule matched. */
    bool matched;
    /** Whether an observed or enforced rule would block. */
    bool would_block;
    /** Whether the effective verdict blocked the request. */
    bool enforced_block;
    /** Number of initialized entries in @ref rules. */
    size_t rule_count;
    /** Selected and enforcing domain and destination rule outcomes. */
    struct jg_policy_stats_event_rule rules[JG_POLICY_STATS_EVENT_RULE_MAX];
};

/** Relaxed operational counters for one collector. */
struct jg_policy_stats_collector_stats {
    /** Events accepted into the bounded queue. */
    uint64_t submitted;
    /** Events discarded without affecting packet verdicts. */
    uint64_t dropped;
    /** Events discarded while an applied restore held the writer barrier. */
    uint64_t restore_dropped;
    /** Events discarded after their policy generation ceased to be active. */
    uint64_t stale_generation_dropped;
    /** Request samples committed to persistent aggregates. */
    uint64_t recorded_requests;
    /** Rule samples committed to persistent aggregates. */
    uint64_t recorded_rules;
    /** Failed persistent aggregation batches. */
    uint64_t write_failures;
    /** Completed automatic cleanup batches. */
    uint64_t cleanup_batches;
    /** Failed automatic cleanup attempts. */
    uint64_t cleanup_failures;
    /** Current retained impact rows. */
    uint64_t detail_rows;
    /** Latest aggregate bytes occupied by SQLite files. */
    uint64_t estimated_bytes;
    /** New impact rows rejected by a cardinality budget. */
    uint64_t cardinality_dropped;
    /** Impact samples skipped while storage thresholds were exceeded. */
    uint64_t storage_dropped;
    /** One while byte or filesystem thresholds suspend detail collection. */
    uint64_t storage_suspended;
};

/** Opaque bounded asynchronous statistics collector. */
struct jg_policy_stats_collector;

/**
 * @brief Create a stopped collector with an independent database connection.
 *
 * @param[in] database Open primary database used to create a peer connection.
 * @param[in] capacity Number of queued events.
 * @param[in] initial_generation First accepted immutable policy generation.
 * @param[out] collector Receives the owned stopped collector.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or bounds.
 * @return -ENOMEM when allocation fails.
 * @return A negative errno-style value for another database or mutex failure.
 *
 * @thread_safety The primary database must not be closed during this call.
 */
int jg_policy_stats_collector_create(
    struct jg_database *database,
    size_t capacity,
    uint64_t initial_generation,
    struct jg_policy_stats_collector **collector);

/**
 * @brief Suspend submissions and wait until the database writer is idle.
 *
 * Queued events are explicitly discarded so no sample from the old policy
 * generation can reach a replacement database.
 */
int jg_policy_stats_collector_pause(struct jg_policy_stats_collector *collector,
                                    bool restore);

/** @brief Resume collection for one newly published policy generation. */
int jg_policy_stats_collector_resume(
    struct jg_policy_stats_collector *collector,
    uint64_t generation);

/** @brief Start the single database-writer thread. */
int jg_policy_stats_collector_start(
    struct jg_policy_stats_collector *collector);

/**
 * @brief Try to enqueue one packet-path event without waiting.
 *
 * @return 0 when the event was copied.
 * @return -EAGAIN when the queue or its mutex is immediately unavailable.
 * @return -ECANCELED before start or after a stop request.
 * @return -EINVAL for invalid event content.
 *
 * @thread_safety Safe for concurrent packet workers.
 */
int jg_policy_stats_collector_submit(
    struct jg_policy_stats_collector *collector,
    const struct jg_policy_stats_event *event);

/** @brief Request a non-blocking stop after all queued events are drained. */
int jg_policy_stats_collector_request_stop(
    struct jg_policy_stats_collector *collector);

/** @brief Join the writer thread after an explicit stop request. */
int jg_policy_stats_collector_join(struct jg_policy_stats_collector *collector);

/** @brief Read relaxed collector health counters. */
int jg_policy_stats_collector_get_stats(
    const struct jg_policy_stats_collector *collector,
    struct jg_policy_stats_collector_stats *stats);

/** @brief Stop, join, and release a collector and its peer connection. */
void jg_policy_stats_collector_destroy(
    struct jg_policy_stats_collector *collector);

#endif
