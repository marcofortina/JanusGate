/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file policy_stats.h
 * @brief Persistent policy-impact counters and detail retention.
 */

#ifndef JANUSGATE_POLICY_STATS_H
#define JANUSGATE_POLICY_STATS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/policy.h"
#include "janusgate/version.h"

/** Default detailed policy-statistics retention in calendar months. */
#define JG_POLICY_STATS_RETENTION_DEFAULT 12U

/** Smallest configurable detailed-statistics retention. */
#define JG_POLICY_STATS_RETENTION_MIN 1U

/** Largest configurable detailed-statistics retention. */
#define JG_POLICY_STATS_RETENTION_MAX 120U

/** Largest number of samples accepted by one database batch. */
#define JG_POLICY_STATS_BATCH_MAX 1024U

/** Largest number of statistic records returned by one page. */
#define JG_POLICY_STATS_PAGE_MAX 100U

/** Largest cleanup batch, bounding one write transaction. */
#define JG_POLICY_STATS_CLEANUP_BATCH_MAX 10000U

/** Largest number of related rules or impacted clients in one analysis. */
#define JG_POLICY_ANALYSIS_RELATED_MAX 16U

/** Policy rule namespace used by statistics and analysis. */
enum jg_policy_stats_dimension {
    /** Domain rule namespace. */
    JG_POLICY_STATS_DOMAIN = 1,
    /** Network-destination rule namespace. */
    JG_POLICY_STATS_DESTINATION = 2
};

/** Traffic inspection path that produced a statistic. */
enum jg_policy_stats_path {
    /** Classic DNS question inspection. */
    JG_POLICY_STATS_DNS = 1,
    /** Visible TLS ClientHello server-name inspection. */
    JG_POLICY_STATS_TLS_SNI = 2,
    /** Destination address, port, and transport inspection. */
    JG_POLICY_STATS_NETWORK_DESTINATION = 3
};

/** One request-level traffic sample. */
struct jg_policy_traffic_sample {
    /** Observation time as Unix seconds. */
    uint64_t occurred_at;
    /** Inspection path used by the request. */
    enum jg_policy_stats_path path;
    /** Whether at least one policy rule matched. */
    bool matched;
    /** Whether an observed or enforced rule would block the request. */
    bool would_block;
    /** Whether the effective verdict blocked the request. */
    bool enforced_block;
};

/** One matching-rule impact sample. */
struct jg_policy_rule_sample {
    /** Observation time as Unix seconds. */
    uint64_t occurred_at;
    /** Domain or destination rule namespace. */
    enum jg_policy_stats_dimension dimension;
    /** Stable positive rule identifier. */
    uint64_t rule_id;
    /** Inspection path used by the request. */
    enum jg_policy_stats_path path;
    /** Client identity available during policy matching. */
    struct jg_policy_client client;
    /** Queried domain, or an empty string for destination-only inspection. */
    const char *domain;
    /** DNS query type, or zero outside the DNS path. */
    uint16_t query_type;
    /** Whether this matching rule selected its dimension's verdict. */
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

/** Persistent detailed-statistics retention configuration. */
struct jg_policy_stats_config {
    /** Whether scheduled retention cleanup is enabled. */
    bool retention_enabled;
    /** Number of calendar months retained in detailed buckets. */
    uint32_t retention_months;
    /** Monotonic optimistic-concurrency revision. */
    uint64_t revision;
    /** Last configuration modification time as Unix seconds. */
    uint64_t updated_at;
    /** Last completed detail cleanup time as Unix seconds, or zero. */
    uint64_t last_cleanup_at;
};

/** Lifetime request counters preserved across detail cleanup. */
struct jg_policy_traffic_stats {
    /** Total inspected requests. */
    uint64_t request_count;
    /** Requests matching at least one rule. */
    uint64_t matched_count;
    /** Requests that an observed or enforced rule would block. */
    uint64_t would_block_count;
    /** Requests effectively blocked. */
    uint64_t enforced_block_count;
    /** First recorded request time as Unix seconds. */
    uint64_t first_request_at;
    /** Most recent recorded request time as Unix seconds. */
    uint64_t last_request_at;
};

/** Lifetime counters for one policy rule. */
struct jg_policy_rule_stats {
    /** Domain or destination rule namespace. */
    enum jg_policy_stats_dimension dimension;
    /** Stable positive rule identifier. */
    uint64_t rule_id;
    /** Every recorded match. */
    uint64_t match_count;
    /** Matches selecting their dimension's verdict. */
    uint64_t decision_count;
    /** Matching blocks in either enforcement mode. */
    uint64_t would_block_count;
    /** Matching blocks that were enforced, including shadowed rules. */
    uint64_t enforced_block_count;
    /** Matching allows that were enforced, including shadowed rules. */
    uint64_t allow_decision_count;
    /** Matches superseded by higher-precedence rules. */
    uint64_t shadowed_count;
    /** First recorded match time as Unix seconds. */
    uint64_t first_hit_at;
    /** Most recent recorded match time as Unix seconds. */
    uint64_t last_hit_at;
};

/** Detailed impact summary retained for one rule. */
struct jg_policy_rule_impact {
    /** Distinct client identities represented by retained detail. */
    uint64_t distinct_client_count;
    /** Distinct VLAN identifiers represented by retained detail. */
    uint64_t distinct_vlan_count;
    /** Distinct queried domains represented by retained detail. */
    uint64_t distinct_domain_count;
    /** Retained matches observed through classic DNS. */
    uint64_t dns_match_count;
    /** Retained matches observed through visible TLS SNI. */
    uint64_t tls_sni_match_count;
    /** Retained matches observed through destination policy. */
    uint64_t destination_match_count;
};

/** One impacted client returned by rule analysis. */
struct jg_policy_client_impact {
    /** Client address family, or none when unavailable. */
    enum jg_policy_address_family address_family;
    /** Client network address; IPv4 uses the first four bytes. */
    uint8_t address[16U];
    /** Whether a MAC address was available. */
    bool has_mac;
    /** Client MAC address when @ref has_mac is true. */
    uint8_t mac[6U];
    /** Whether a VLAN identifier was available. */
    bool has_vlan;
    /** VLAN identifier when @ref has_vlan is true. */
    uint16_t vlan_id;
    /** Retained matches attributed to this client identity. */
    uint64_t match_count;
    /** Retained would-block matches for this client identity. */
    uint64_t would_block_count;
    /** Most recent retained bucket containing this client. */
    uint64_t last_hit_at;
};

/** Conservative static relationships for one persistent policy rule. */
struct jg_policy_rule_relations {
    /** Exact functional duplicate identifiers. */
    uint64_t duplicate_ids[JG_POLICY_ANALYSIS_RELATED_MAX];
    /** Number of identifiers stored in @ref duplicate_ids. */
    size_t duplicate_count;
    /** Exact-predicate opposite-action identifiers. */
    uint64_t conflict_ids[JG_POLICY_ANALYSIS_RELATED_MAX];
    /** Number of identifiers stored in @ref conflict_ids. */
    size_t conflict_count;
    /** Higher-precedence exact-predicate rule identifiers. */
    uint64_t shadowing_ids[JG_POLICY_ANALYSIS_RELATED_MAX];
    /** Number of identifiers stored in @ref shadowing_ids. */
    size_t shadowing_count;
    /** More-specific allows or broader blocks forming allow exceptions. */
    uint64_t allow_exception_ids[JG_POLICY_ANALYSIS_RELATED_MAX];
    /** Number of identifiers stored in @ref allow_exception_ids. */
    size_t allow_exception_count;
    /** Whether any relationship list exceeded its returned bound. */
    bool truncated;
    /** Whether the rule cannot currently participate in policy. */
    bool unreachable;
    /** Whether unreachability is caused by the rule being disabled. */
    bool disabled;
};

/** Preview or result of one incremental detailed-statistics cleanup. */
struct jg_policy_stats_cleanup_report {
    /** Oldest retained time derived using calendar-month arithmetic. */
    uint64_t cutoff_at;
    /** Detail rows eligible before this cleanup batch. */
    uint64_t impact_rows;
    /** Traffic rows eligible before this cleanup batch. */
    uint64_t traffic_rows;
    /** Impact detail rows removed by this batch. */
    uint64_t deleted_impact_rows;
    /** Traffic detail rows removed by this batch. */
    uint64_t deleted_traffic_rows;
    /** Whether no eligible detail rows remain. */
    bool complete;
};

/** Opaque database connection declared by database.h. */
struct jg_database;

/**
 * @brief Load persistent detailed-statistics retention configuration.
 *
 * @param[in] database Open database.
 * @param[out] config Receives the self-contained configuration.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -EILSEQ for invalid persistent content.
 * @return A negative errno-style value for another SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_load_policy_stats_config(
    struct jg_database *database,
    struct jg_policy_stats_config *config);

/**
 * @brief Replace retention configuration at its expected revision.
 *
 * @param[in] database Open database.
 * @param[in] retention_enabled Whether scheduled cleanup is enabled.
 * @param[in] retention_months Calendar months of details to retain.
 * @param[in] expected_revision Revision observed by the caller.
 * @param[in] updated_at Modification time as Unix seconds.
 * @param[out] updated Receives the updated configuration.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or bounds.
 * @return -EAGAIN when the persistent revision has changed.
 * @return -EOVERFLOW when the revision cannot advance.
 * @return A negative errno-style value for another SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_update_policy_stats_config(
    struct jg_database *database,
    bool retention_enabled,
    uint32_t retention_months,
    uint64_t expected_revision,
    uint64_t updated_at,
    struct jg_policy_stats_config *updated);

/**
 * @brief Atomically add bounded request and matching-rule sample batches.
 *
 * Either batch may be empty, but not both. Lifetime counters saturate instead
 * of wrapping; detailed records are merged into UTC hour buckets.
 *
 * @param[in] database Open database.
 * @param[in] traffic Request samples, or null when @p traffic_count is zero.
 * @param[in] traffic_count Number of request samples.
 * @param[in] rules Rule samples, or null when @p rule_count is zero.
 * @param[in] rule_count Number of matching-rule samples.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments, relationships, or bounds.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Updates lifetime aggregates and detailed hourly buckets in one
 * transaction.
 */
JG_PUBLIC int jg_database_record_policy_stats(
    struct jg_database *database,
    const struct jg_policy_traffic_sample *traffic,
    size_t traffic_count,
    const struct jg_policy_rule_sample *rules,
    size_t rule_count);

/**
 * @brief Load lifetime request-level policy counters.
 *
 * @param[in] database Open database.
 * @param[out] stats Receives the self-contained counters.
 *
 * @return 0 on success.
 * @return -ENOENT before the first request sample is recorded.
 * @return -EINVAL for a null argument.
 * @return A negative errno-style value for another SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_load_policy_traffic_stats(
    struct jg_database *database,
    struct jg_policy_traffic_stats *stats);

/**
 * @brief Read one identifier-ordered page of lifetime rule counters.
 *
 * @param[in] database Open database.
 * @param[in] dimension Domain or destination rule namespace.
 * @param[in] after_rule_id Exclusive positive-identifier cursor, or zero.
 * @param[in] limit Requested page size.
 * @param[out] stats Array with room for at least @p limit records.
 * @param[out] count Number of records written.
 * @param[out] has_more Whether another record follows this page.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or bounds.
 * @return -EILSEQ for invalid persistent content.
 * @return A negative errno-style value for another SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_list_policy_rule_stats(
    struct jg_database *database,
    enum jg_policy_stats_dimension dimension,
    uint64_t after_rule_id,
    size_t limit,
    struct jg_policy_rule_stats *stats,
    size_t *count,
    bool *has_more);

/**
 * @brief Load lifetime and retained-detail impact for one rule.
 *
 * @param[in] database Open database.
 * @param[in] dimension Domain or destination rule namespace.
 * @param[in] rule_id Stable positive rule identifier.
 * @param[out] stats Receives lifetime counters when present.
 * @param[out] has_stats Whether @p stats contains persistent counters.
 * @param[out] impact Receives retained-detail cardinalities and path counts.
 * @param[out] clients Receives the most active retained client identities.
 * @param[in] client_limit Number of client slots, up to the analysis maximum.
 * @param[out] client_count Number of client records written.
 *
 * @return 0 on success, including a rule without traffic.
 * @return -EINVAL for invalid arguments.
 * @return -EILSEQ for invalid persistent content.
 * @return A negative errno-style value for another SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_load_policy_rule_impact(
    struct jg_database *database,
    enum jg_policy_stats_dimension dimension,
    uint64_t rule_id,
    struct jg_policy_rule_stats *stats,
    bool *has_stats,
    struct jg_policy_rule_impact *impact,
    struct jg_policy_client_impact *clients,
    size_t client_limit,
    size_t *client_count);

/**
 * @brief Analyze provable static relationships for one persistent rule.
 *
 * Findings intentionally omit ambiguous relationships rather than producing
 * false positives. Exact duplicates can make a rule unreachable; disabled
 * rules are reported separately.
 *
 * @param[in] database Open database.
 * @param[in] dimension Domain or destination rule namespace.
 * @param[in] rule_id Stable positive rule identifier.
 * @param[out] relations Receives bounded related-rule identifiers.
 *
 * @return 0 on success.
 * @return -ENOENT when the rule does not exist.
 * @return -EINVAL for invalid arguments.
 * @return A negative errno-style value for another SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_analyze_policy_rule(
    struct jg_database *database,
    enum jg_policy_stats_dimension dimension,
    uint64_t rule_id,
    struct jg_policy_rule_relations *relations);

/**
 * @brief Preview detailed rows eligible under the retention configuration.
 *
 * Preview uses the configured duration even when scheduled cleanup is
 * disabled, allowing an administrator to assess a manual cleanup.
 *
 * @param[in] database Open database.
 * @param[in] now Reference time as Unix seconds.
 * @param[out] report Receives the cutoff and eligible row counts.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or bounds.
 * @return A negative errno-style value for another SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_preview_policy_stats_cleanup(
    struct jg_database *database,
    uint64_t now,
    struct jg_policy_stats_cleanup_report *report);

/**
 * @brief Remove one bounded batch of expired detail without lifetime loss.
 *
 * Cleanup is explicit regardless of the scheduled-cleanup setting. Repeated
 * calls complete large cleanups without holding one long write transaction.
 *
 * @param[in] database Open database.
 * @param[in] now Reference time as Unix seconds.
 * @param[in] batch_size Maximum detail rows removed in this transaction.
 * @param[out] report Receives eligibility, deletion, and completion counts.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or bounds.
 * @return A negative errno-style value for another SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Deletes only expired detail buckets. Lifetime counters are
 * preserved.
 */
JG_PUBLIC int jg_database_cleanup_policy_stats(
    struct jg_database *database,
    uint64_t now,
    size_t batch_size,
    struct jg_policy_stats_cleanup_report *report);

#endif
