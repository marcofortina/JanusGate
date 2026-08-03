/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "dataplane_worker.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include <pthread.h>

#include "dataplane.h"
#include "dns_response.h"
#include "janusgate/checked.h"
#include "janusgate/logging.h"
#include "janusgate/tls_client_hello.h"
#include "policy_stats_collector.h"

/** Independently updated counters for one data-plane worker. */
struct atomic_dataplane_stats {
    atomic_uint_fast64_t packets;
    atomic_uint_fast64_t accepted;
    atomic_uint_fast64_t blocked;
    atomic_uint_fast64_t malformed;
    atomic_uint_fast64_t fragments;
    atomic_uint_fast64_t streams;
    atomic_uint_fast64_t tcp_resets;
    atomic_uint_fast64_t dns_dropped;
    atomic_uint_fast64_t dns_refused;
    atomic_uint_fast64_t dns_nxdomain;
    atomic_uint_fast64_t dns_sinkholed;
    atomic_uint_fast64_t internal_errors;
    atomic_uint_fast64_t sni_inspected;
    atomic_uint_fast64_t sni_encrypted_or_unavailable;
};

/** Complete per-queue data-plane context. */
struct jg_dataplane_worker {
    struct jg_policy_store *store;
    struct jg_policy_stats_collector *policy_stats;
    struct jg_fragment_tracker *fragments;
    struct jg_tcp_stream_tracker *streams;
    struct jg_tcp_stream_tracker *tls_streams;
    struct jg_packet_limits limits;
    struct atomic_dataplane_stats stats;
    uint8_t *fragment_payload;
    uint8_t *fragment_frame;
    uint8_t *dns_response;
    uint8_t *stream_output;
    uint8_t *tls_output;
    struct jg_tcp_stream_message *stream_messages;
    struct jg_tls_client_hello_parser *tls_parsers;
    size_t fragment_payload_size;
    size_t fragment_frame_size;
    size_t stream_output_size;
    size_t stream_message_capacity;
    size_t tls_output_size;
    size_t tls_parser_count;
    size_t reader_index;
    jg_dataplane_reset_sender reset_sender;
    void *reset_context;
    pthread_mutex_t dns_response_lock;
    struct jg_dns_response_config dns_response_config;
    jg_dataplane_frame_sender frame_sender;
    void *frame_context;
    bool dns_response_lock_initialized;
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
    atomic_init(&stats->tcp_resets, 0U);
    atomic_init(&stats->dns_dropped, 0U);
    atomic_init(&stats->dns_refused, 0U);
    atomic_init(&stats->dns_nxdomain, 0U);
    atomic_init(&stats->dns_sinkholed, 0U);
    atomic_init(&stats->internal_errors, 0U);
    atomic_init(&stats->sni_inspected, 0U);
    atomic_init(&stats->sni_encrypted_or_unavailable, 0U);
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

/** @brief Return one stable data-plane decision name. */
static const char *decision_name(enum jg_dataplane_reason reason)
{
    switch (reason) {
    case JG_DATAPLANE_PASS:
        return "pass";
    case JG_DATAPLANE_POLICY_ALLOW:
        return "policy_allow";
    case JG_DATAPLANE_POLICY_BLOCK:
        return "policy_block";
    case JG_DATAPLANE_MALFORMED:
        return "malformed";
    case JG_DATAPLANE_FRAGMENT_PENDING:
        return "fragment_pending";
    case JG_DATAPLANE_STREAM_PENDING:
        return "stream_pending";
    case JG_DATAPLANE_SNI_ENCRYPTED_OR_UNAVAILABLE:
        return "sni_unavailable";
    default:
        return "unknown";
    }
}

/** @brief Emit one bounded packet decision without packet payload bytes. */
static void trace_decision(struct jg_dataplane_worker *worker,
                           const struct jg_nfqueue_packet *packet,
                           const struct jg_dataplane_result *decision,
                           const char *domain,
                           int operation_result)
{
    const enum jg_log_level level =
        operation_result == 0 ? JG_LOG_TRACE : JG_LOG_WARNING;
    const uint64_t packet_number =
        atomic_load_explicit(&worker->stats.packets, memory_order_relaxed);
    const uint64_t rule_id = decision == NULL
                                 ? 0U
                                 : (decision->policy.rule_id != 0U
                                        ? decision->policy.rule_id
                                        : decision->destination_policy.rule_id);
    char correlation[JG_LOG_CORRELATION_MAX + 1U];
    char details[JG_LOG_DETAILS_MAX + 1U];
    int written = 0;

    if (!jg_log_enabled("dataplane", level)) {
        return;
    }
    written = snprintf(correlation, sizeof(correlation), "queue-%u-packet-%llu",
                       (unsigned)packet->queue_number,
                       (unsigned long long)packet_number);
    if (written <= 0 || (size_t)written >= sizeof(correlation)) {
        return;
    }
    if (domain == NULL) {
        written = snprintf(
            details, sizeof(details),
            "{\"operation_result\":%d,\"queue\":%u,\"reason\":\"%s\","
            "\"rule_id\":%llu,\"verdict\":\"%s\"}",
            operation_result, (unsigned)packet->queue_number,
            decision == NULL ? "unavailable" : decision_name(decision->reason),
            (unsigned long long)rule_id,
            decision != NULL && decision->verdict == JG_NFQUEUE_ACCEPT
                ? "accept"
                : "drop");
    } else {
        written = snprintf(
            details, sizeof(details),
            "{\"domain\":\"%s\",\"operation_result\":%d,\"queue\":%u,"
            "\"reason\":\"%s\",\"rule_id\":%llu,\"verdict\":\"%s\"}",
            domain, operation_result, (unsigned)packet->queue_number,
            decision_name(decision->reason), (unsigned long long)rule_id,
            decision->verdict == JG_NFQUEUE_ACCEPT ? "accept" : "drop");
    }
    if (written > 0 && (size_t)written < sizeof(details)) {
        (void)jg_log_emit(
            level, "dataplane",
            operation_result == 0 ? "dataplane.decision" : "dataplane.error",
            correlation,
            operation_result == 0 ? "Packet policy decision completed"
                                  : "Packet policy decision failed",
            details);
    }
}

/** @brief Read monotonic milliseconds for fragment expiration. */
static int monotonic_milliseconds(uint64_t *milliseconds)
{
    struct timespec time;

    if (milliseconds == NULL) {
        return -EINVAL;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) {
        return -errno;
    }
    *milliseconds = (uint64_t)time.tv_sec * UINT64_C(1000) +
                    (uint64_t)time.tv_nsec / UINT64_C(1000000);
    return 0;
}

/** @brief Append one selected or shadowed rule to a bounded event. */
static void append_stats_rule(struct jg_policy_stats_event *event,
                              enum jg_policy_stats_dimension dimension,
                              uint64_t rule_id,
                              enum jg_policy_effect effect,
                              bool decision,
                              bool enforced)
{
    struct jg_policy_stats_event_rule *rule = &event->rules[event->rule_count];

    *rule = (struct jg_policy_stats_event_rule){
        .dimension = dimension,
        .rule_id = rule_id,
        .decision = decision,
        .would_block = effect == JG_POLICY_BLOCK,
        .enforced_block = enforced && effect == JG_POLICY_BLOCK,
        .allow_decision = enforced && effect == JG_POLICY_ALLOW,
        .shadowed = !decision,
    };
    ++event->rule_count;
}

/** @brief Retain selected and distinct enforcing domain rules. */
static void append_domain_stats(struct jg_policy_stats_event *event,
                                const struct jg_policy_match *match)
{
    const bool same_rule =
        match->enforcing_matched && match->enforcing_rule_id == match->rule_id;

    if (!match->matched) {
        return;
    }
    append_stats_rule(event, JG_POLICY_STATS_DOMAIN, match->rule_id,
                      match->configured_effect, true, same_rule);
    if (match->enforcing_matched && !same_rule) {
        append_stats_rule(event, JG_POLICY_STATS_DOMAIN,
                          match->enforcing_rule_id, match->effect, false, true);
    }
}

/** @brief Retain selected and distinct enforcing destination rules. */
static void append_destination_stats(
    struct jg_policy_stats_event *event,
    const struct jg_policy_destination_match *match)
{
    const bool same_rule =
        match->enforcing_matched && match->enforcing_rule_id == match->rule_id;

    if (!match->matched) {
        return;
    }
    append_stats_rule(event, JG_POLICY_STATS_DESTINATION, match->rule_id,
                      match->configured_effect, true, same_rule);
    if (match->enforcing_matched && !same_rule) {
        append_stats_rule(event, JG_POLICY_STATS_DESTINATION,
                          match->enforcing_rule_id, match->effect, false, true);
    }
}

/** @brief Submit one complete policy decision without delaying its verdict. */
static void submit_policy_stats(struct jg_dataplane_worker *worker,
                                const struct jg_dataplane_result *result)
{
    struct jg_policy_stats_event event = {0};
    time_t occurred_at = 0;
    size_t index = 0U;

    if (worker->policy_stats == NULL || result->policy_path == 0 ||
        result->reason == JG_DATAPLANE_MALFORMED ||
        result->reason == JG_DATAPLANE_FRAGMENT_PENDING ||
        result->reason == JG_DATAPLANE_STREAM_PENDING) {
        return;
    }
    occurred_at = time(NULL);
    if (occurred_at < 0) {
        return;
    }
    event.occurred_at = (uint64_t)occurred_at;
    event.path = result->policy_path;
    event.client = result->client;
    event.query_type = result->query_type;
    (void)memcpy(event.domain, result->inspected_domain,
                 strlen(result->inspected_domain) + 1U);
    append_domain_stats(&event, &result->policy);
    append_destination_stats(&event, &result->destination_policy);
    event.matched = event.rule_count != 0U;
    for (index = 0U; index < event.rule_count; ++index) {
        event.would_block = event.would_block || event.rules[index].would_block;
        event.enforced_block =
            event.enforced_block || event.rules[index].enforced_block;
    }
    (void)jg_policy_stats_collector_submit(worker->policy_stats, &event);
}

/** @brief Send the configured response for one blocked complete UDP query. */
static int respond_blocked_udp(struct jg_dataplane_worker *worker,
                               const struct jg_dataplane_result *result,
                               const uint8_t *query,
                               size_t query_size)
{
    struct jg_dns_response_config config;
    jg_dataplane_frame_sender sender = NULL;
    void *sender_context = NULL;
    size_t response_size = 0U;
    int operation_result = pthread_mutex_lock(&worker->dns_response_lock);

    if (operation_result != 0) {
        return -operation_result;
    }
    config = worker->dns_response_config;
    sender = worker->frame_sender;
    sender_context = worker->frame_context;
    operation_result = pthread_mutex_unlock(&worker->dns_response_lock);
    if (operation_result != 0) {
        return -operation_result;
    }
    operation_result = jg_dns_response_build(
        &result->packet, query, query_size, result->question_index, &config,
        worker->dns_response, JG_DNS_RESPONSE_FRAME_MAX, &response_size);

    if (operation_result == 0 && response_size != 0U) {
        if (sender == NULL) {
            return -ENOTCONN;
        }
        operation_result =
            sender(worker->dns_response, response_size, sender_context);
    }
    if (operation_result == 0) {
        if (config.action == JG_DNS_BLOCK_DROP) {
            increment(&worker->stats.dns_dropped);
        } else if (config.action == JG_DNS_BLOCK_REFUSED) {
            increment(&worker->stats.dns_refused);
        } else if (config.action == JG_DNS_BLOCK_NXDOMAIN) {
            increment(&worker->stats.dns_nxdomain);
        } else {
            increment(&worker->stats.dns_sinkholed);
        }
    }
    return operation_result;
}

/** @brief Process one fragment through bounded reconstruction state. */
static int process_fragment(struct jg_dataplane_worker *worker,
                            const struct jg_policy_snapshot *snapshot,
                            struct jg_dataplane_result *result)
{
    enum jg_fragment_result fragment_result = JG_FRAGMENT_MALFORMED;
    size_t reassembled_size = 0U;
    size_t frame_size = 0U;
    uint64_t now_ms = 0U;
    int operation_result = monotonic_milliseconds(&now_ms);

    if (operation_result == 0) {
        operation_result = jg_fragment_tracker_add(
            worker->fragments, &result->packet, now_ms,
            worker->fragment_payload, worker->fragment_payload_size,
            &reassembled_size, &fragment_result);
    }
    if (operation_result != 0) {
        return operation_result;
    }
    if (fragment_result == JG_FRAGMENT_COMPLETE) {
        operation_result = jg_fragment_build_frame(
            &result->packet, worker->fragment_payload, reassembled_size,
            worker->fragment_frame, worker->fragment_frame_size, &frame_size);
        if (operation_result == 0) {
            operation_result =
                jg_dataplane_evaluate(worker->fragment_frame, frame_size,
                                      &worker->limits, snapshot, result);
        }
        return operation_result;
    }
    if (fragment_result == JG_FRAGMENT_MALFORMED ||
        fragment_result == JG_FRAGMENT_OVERLAP ||
        fragment_result == JG_FRAGMENT_EXHAUSTED) {
        result->verdict = JG_NFQUEUE_DROP;
        result->reason = JG_DATAPLANE_MALFORMED;
    }
    return 0;
}

/** @brief Reject and reset one stream blocked by domain policy. */
static int reset_blocked_stream(struct jg_dataplane_worker *worker,
                                struct jg_tcp_stream_tracker *tracker,
                                const struct jg_dataplane_result *result,
                                uint64_t now_ms)
{
    struct jg_tcp_reset_pair resets;
    int operation_result = 0;

    if (result->reason != JG_DATAPLANE_POLICY_BLOCK) {
        return -EINVAL;
    }
    operation_result =
        jg_tcp_stream_tracker_reject_flow(tracker, &result->packet, now_ms);
    if (operation_result != 0) {
        return operation_result;
    }
    if (worker->reset_sender == NULL) {
        return -ENOTCONN;
    }
    operation_result = jg_tcp_reset_build(&result->packet, &resets);
    if (operation_result == 0) {
        operation_result = worker->reset_sender(&resets, worker->reset_context);
    }
    if (operation_result == 0) {
        increment(&worker->stats.tcp_resets);
    }
    return operation_result;
}

/** @brief Process one TCP packet through bounded DNS stream state. */
static int process_stream(struct jg_dataplane_worker *worker,
                          const struct jg_policy_snapshot *snapshot,
                          struct jg_dataplane_result *result)
{
    enum jg_tcp_stream_result stream_result = JG_TCP_STREAM_MALFORMED;
    size_t message_count = 0U;
    uint64_t now_ms = 0U;
    int operation_result = monotonic_milliseconds(&now_ms);

    if (operation_result == 0) {
        operation_result = jg_tcp_stream_tracker_add(
            worker->streams, &result->packet, now_ms, worker->stream_output,
            worker->stream_output_size, worker->stream_messages,
            worker->stream_message_capacity, &message_count, &stream_result);
    }
    if (operation_result != 0) {
        return operation_result;
    }
    if (stream_result == JG_TCP_STREAM_MESSAGES) {
        for (size_t index = 0U; index < message_count; ++index) {
            operation_result = jg_dataplane_evaluate_tcp_dns(
                &result->packet,
                worker->stream_output + worker->stream_messages[index].offset,
                worker->stream_messages[index].size, snapshot, result);
            if (operation_result != 0) {
                return operation_result;
            }
            submit_policy_stats(worker, result);
            result->policy_path = 0;
            if (result->verdict == JG_NFQUEUE_DROP) {
                return reset_blocked_stream(worker, worker->streams, result,
                                            now_ms);
            }
        }
    } else if (stream_result == JG_TCP_STREAM_BUFFERED ||
               stream_result == JG_TCP_STREAM_DUPLICATE) {
        result->verdict = JG_NFQUEUE_ACCEPT;
        result->reason = JG_DATAPLANE_STREAM_PENDING;
    } else if (stream_result == JG_TCP_STREAM_CLOSED) {
        result->verdict = JG_NFQUEUE_ACCEPT;
        result->reason = JG_DATAPLANE_PASS;
    } else {
        result->verdict = JG_NFQUEUE_DROP;
        result->reason = JG_DATAPLANE_MALFORMED;
    }
    return 0;
}

/** @brief Mark a TLS packet as accepted while its SNI remains unavailable. */
static void accept_unavailable_sni(struct jg_dataplane_result *result)
{
    result->verdict = JG_NFQUEUE_ACCEPT;
    result->reason = JG_DATAPLANE_SNI_ENCRYPTED_OR_UNAVAILABLE;
}

/** @brief Apply one terminal ClientHello result to a selected TLS stream. */
static int apply_client_hello(struct jg_dataplane_worker *worker,
                              const struct jg_policy_snapshot *snapshot,
                              struct jg_dataplane_result *result,
                              const struct jg_tls_client_hello *hello,
                              enum jg_tls_client_hello_result hello_result,
                              uint64_t now_ms)
{
    int operation_result = 0;

    if (hello_result == JG_TLS_CLIENT_HELLO_COMPLETE &&
        hello->has_server_name) {
        increment(&worker->stats.sni_inspected);
        if (hello->encrypted_client_hello) {
            increment(&worker->stats.sni_encrypted_or_unavailable);
        }
        operation_result = jg_dataplane_evaluate_visible_sni(
            &result->packet, hello->server_name, snapshot, result);
        if (operation_result != 0 || result->verdict == JG_NFQUEUE_DROP) {
            return operation_result != 0
                       ? operation_result
                       : reset_blocked_stream(worker, worker->tls_streams,
                                              result, now_ms);
        }
        if (hello->encrypted_client_hello) {
            accept_unavailable_sni(result);
        }
    } else if (hello_result == JG_TLS_CLIENT_HELLO_COMPLETE ||
               hello_result == JG_TLS_CLIENT_HELLO_NOT_CLIENT_HELLO) {
        increment(&worker->stats.sni_encrypted_or_unavailable);
        accept_unavailable_sni(result);
    } else if (hello_result == JG_TLS_CLIENT_HELLO_MALFORMED ||
               hello_result == JG_TLS_CLIENT_HELLO_TOO_LARGE) {
        result->verdict = JG_NFQUEUE_DROP;
        result->reason = JG_DATAPLANE_MALFORMED;
        operation_result = jg_tcp_stream_tracker_reject_flow(
            worker->tls_streams, &result->packet, now_ms);
    } else {
        result->verdict = JG_NFQUEUE_ACCEPT;
        result->reason = JG_DATAPLANE_STREAM_PENDING;
    }
    return operation_result;
}

/** @brief Process one selected TCP packet through bounded TLS stream state. */
static int process_tls_stream(struct jg_dataplane_worker *worker,
                              const struct jg_policy_snapshot *snapshot,
                              struct jg_dataplane_result *result)
{
    struct jg_tcp_raw_stream_chunk chunk;
    enum jg_tcp_raw_stream_result stream_result = JG_TCP_RAW_STREAM_EXHAUSTED;
    struct jg_tls_client_hello hello;
    enum jg_tls_client_hello_result hello_result = JG_TLS_CLIENT_HELLO_MORE;
    uint64_t now_ms = 0U;
    int operation_result = monotonic_milliseconds(&now_ms);

    if (operation_result == 0) {
        operation_result = jg_tcp_stream_tracker_add_raw(
            worker->tls_streams, &result->packet, now_ms, worker->tls_output,
            worker->tls_output_size, &chunk, &stream_result);
    }
    if (operation_result != 0) {
        return operation_result;
    }
    if (chunk.flow_index != SIZE_MAX &&
        chunk.flow_index >= worker->tls_parser_count) {
        return -ERANGE;
    }
    if (chunk.flow_index != SIZE_MAX && chunk.new_flow) {
        jg_tls_client_hello_parser_init(&worker->tls_parsers[chunk.flow_index]);
    }
    if (stream_result == JG_TCP_RAW_STREAM_BYTES) {
        if (worker->tls_parsers[chunk.flow_index].terminal ==
            JG_TLS_CLIENT_HELLO_MORE) {
            hello_result = jg_tls_client_hello_parser_feed(
                &worker->tls_parsers[chunk.flow_index], worker->tls_output,
                chunk.size, &hello);
            operation_result = apply_client_hello(worker, snapshot, result,
                                                  &hello, hello_result, now_ms);
        } else {
            result->verdict = JG_NFQUEUE_ACCEPT;
            result->reason = JG_DATAPLANE_PASS;
        }
    } else if (stream_result == JG_TCP_RAW_STREAM_BUFFERED ||
               stream_result == JG_TCP_RAW_STREAM_DUPLICATE) {
        result->verdict = JG_NFQUEUE_ACCEPT;
        result->reason = JG_DATAPLANE_STREAM_PENDING;
    } else if (stream_result == JG_TCP_RAW_STREAM_CLOSED) {
        result->verdict = JG_NFQUEUE_ACCEPT;
        result->reason = JG_DATAPLANE_PASS;
    } else {
        result->verdict = JG_NFQUEUE_DROP;
        result->reason = JG_DATAPLANE_MALFORMED;
    }
    if (chunk.closed && chunk.flow_index != SIZE_MAX) {
        jg_tls_client_hello_parser_init(&worker->tls_parsers[chunk.flow_index]);
    }
    return operation_result;
}

/** @brief Create one exclusive policy-reading packet worker. */
int jg_dataplane_worker_create(struct jg_policy_store *store,
                               size_t reader_index,
                               const struct jg_packet_limits *limits,
                               const struct jg_fragment_limits *fragment_limits,
                               const struct jg_tcp_stream_limits *stream_limits,
                               struct jg_dataplane_worker **worker)
{
    struct jg_fragment_limits default_fragment_limits;
    struct jg_tcp_stream_limits default_stream_limits;
    const struct jg_fragment_limits *active_fragment_limits = fragment_limits;
    const struct jg_tcp_stream_limits *active_stream_limits = stream_limits;
    struct jg_dataplane_worker *created = NULL;
    const struct jg_policy_snapshot *snapshot = NULL;
    int result = 0;

    if (worker == NULL) {
        return -EINVAL;
    }
    *worker = NULL;
    if (store == NULL) {
        return -EINVAL;
    }
    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        return -ENOMEM;
    }
    result = pthread_mutex_init(&created->dns_response_lock, NULL);
    if (result != 0) {
        free(created);
        return -result;
    }
    created->dns_response_lock_initialized = true;
    created->store = store;
    created->reader_index = reader_index;
    if (limits == NULL) {
        jg_packet_limits_default(&created->limits);
    } else {
        created->limits = *limits;
    }
    if (!limits_valid(&created->limits)) {
        jg_dataplane_worker_destroy(created);
        return -EINVAL;
    }
    if (active_fragment_limits == NULL) {
        jg_fragment_limits_default(&default_fragment_limits);
        active_fragment_limits = &default_fragment_limits;
    }
    result = jg_fragment_limits_validate(active_fragment_limits);
    if (result != 0) {
        jg_dataplane_worker_destroy(created);
        return result;
    }
    created->fragment_payload_size =
        active_fragment_limits->max_bytes_per_datagram;
    if (!jg_size_add(created->fragment_payload_size,
                     JG_FRAGMENT_FRAME_OVERHEAD_MAX,
                     &created->fragment_frame_size)) {
        jg_dataplane_worker_destroy(created);
        return -EOVERFLOW;
    }
    created->fragment_payload = malloc(created->fragment_payload_size);
    created->fragment_frame = malloc(created->fragment_frame_size);
    created->dns_response = malloc(JG_DNS_RESPONSE_FRAME_MAX);
    result =
        jg_fragment_tracker_create(active_fragment_limits, &created->fragments);
    if (created->fragment_payload == NULL || created->fragment_frame == NULL ||
        created->dns_response == NULL || result != 0) {
        jg_dataplane_worker_destroy(created);
        return result != 0 ? result : -ENOMEM;
    }
    if (active_stream_limits == NULL) {
        jg_tcp_stream_limits_default(&default_stream_limits);
        active_stream_limits = &default_stream_limits;
    }
    result = jg_tcp_stream_limits_validate(active_stream_limits);
    if (result != 0) {
        jg_dataplane_worker_destroy(created);
        return result;
    }
    created->stream_output_size = active_stream_limits->max_buffered_bytes;
    created->stream_message_capacity =
        active_stream_limits->max_messages_per_packet;
    created->stream_output = malloc(created->stream_output_size);
    created->stream_messages = calloc(created->stream_message_capacity,
                                      sizeof(*created->stream_messages));
    result =
        jg_tcp_stream_tracker_create(active_stream_limits, &created->streams);
    if (created->stream_output == NULL || created->stream_messages == NULL ||
        result != 0) {
        jg_dataplane_worker_destroy(created);
        return result != 0 ? result : -ENOMEM;
    }
    created->tls_parser_count = active_stream_limits->max_flows;
    created->tls_output_size = active_stream_limits->max_buffered_bytes;
    created->tls_output = malloc(created->tls_output_size);
    created->tls_parsers =
        calloc(created->tls_parser_count, sizeof(*created->tls_parsers));
    result = jg_tcp_stream_tracker_create(active_stream_limits,
                                          &created->tls_streams);
    if (created->tls_output == NULL || created->tls_parsers == NULL ||
        result != 0) {
        jg_dataplane_worker_destroy(created);
        return result != 0 ? result : -ENOMEM;
    }
    initialize_stats(&created->stats);
    jg_dns_response_config_default(&created->dns_response_config);
    created->dns_response_config.action = JG_DNS_BLOCK_DROP;

    snapshot = jg_policy_store_acquire(store, reader_index);
    if (snapshot == NULL) {
        jg_dataplane_worker_destroy(created);
        return -EINVAL;
    }
    jg_policy_store_release(store, reader_index);
    *worker = created;
    return 0;
}

/** @brief Configure synchronous reset output for one stopped worker. */
int jg_dataplane_worker_set_reset_sender(struct jg_dataplane_worker *worker,
                                         jg_dataplane_reset_sender sender,
                                         void *context)
{
    if (worker == NULL || sender == NULL) {
        return -EINVAL;
    }
    worker->reset_sender = sender;
    worker->reset_context = context;
    return 0;
}

/** @brief Configure blocked UDP DNS response generation and output. */
int jg_dataplane_worker_set_dns_response(
    struct jg_dataplane_worker *worker,
    const struct jg_dns_response_config *config,
    jg_dataplane_frame_sender sender,
    void *context)
{
    int result = 0;

    if (worker == NULL || jg_dns_response_config_validate(config) != 0 ||
        (config->action != JG_DNS_BLOCK_DROP && sender == NULL)) {
        return -EINVAL;
    }
    result = pthread_mutex_lock(&worker->dns_response_lock);
    if (result == 0) {
        worker->dns_response_config = *config;
        worker->frame_sender = sender;
        worker->frame_context = context;
        result = pthread_mutex_unlock(&worker->dns_response_lock);
    }
    return result == 0 ? 0 : -result;
}

/** @brief Attach one process-wide non-blocking statistics collector. */
int jg_dataplane_worker_set_policy_stats(
    struct jg_dataplane_worker *worker,
    struct jg_policy_stats_collector *collector)
{
    if (worker == NULL || collector == NULL) {
        return -EINVAL;
    }
    worker->policy_stats = collector;
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
    char domain[JG_DOMAIN_NAME_MAX + 1U] = {0};
    int evaluation_result = 0;

    if (packet == NULL || worker == NULL || packet->data == NULL) {
        return JG_NFQUEUE_DROP;
    }
    increment(&worker->stats.packets);
    snapshot = jg_policy_store_acquire(worker->store, worker->reader_index);
    if (snapshot == NULL) {
        increment(&worker->stats.internal_errors);
        increment(&worker->stats.blocked);
        trace_decision(worker, packet, NULL, NULL, -EIO);
        return JG_NFQUEUE_DROP;
    }
    evaluation_result = jg_dataplane_evaluate(
        packet->data, packet->size, &worker->limits, snapshot, &result);
    if (evaluation_result == 0 &&
        result.reason == JG_DATAPLANE_FRAGMENT_PENDING) {
        evaluation_result = process_fragment(worker, snapshot, &result);
    }
    if (evaluation_result == 0 && result.reason == JG_DATAPLANE_POLICY_BLOCK &&
        result.packet.transport == JG_TRANSPORT_UDP &&
        result.packet.destination_port == 53U &&
        result.question_index != SIZE_MAX) {
        evaluation_result = respond_blocked_udp(
            worker, &result, result.packet.frame + result.packet.payload_offset,
            result.packet.payload_size);
    }
    if (evaluation_result == 0 &&
        result.reason == JG_DATAPLANE_STREAM_PENDING &&
        result.packet.transport == JG_TRANSPORT_TCP &&
        result.packet.destination_port == 53U) {
        evaluation_result = process_stream(worker, snapshot, &result);
    } else if (evaluation_result == 0 &&
               result.reason == JG_DATAPLANE_STREAM_PENDING &&
               result.packet.transport == JG_TRANSPORT_TCP &&
               (result.packet.destination_port == 443U ||
                result.packet.destination_port == 853U)) {
        evaluation_result = process_tls_stream(worker, snapshot, &result);
    }
    if (result.policy.domain != NULL) {
        (void)snprintf(domain, sizeof(domain), "%s", result.policy.domain);
    }
    submit_policy_stats(worker, &result);
    jg_policy_store_release(worker->store, worker->reader_index);
    if (evaluation_result != 0) {
        increment(&worker->stats.internal_errors);
        increment(&worker->stats.blocked);
        trace_decision(worker, packet, &result,
                       domain[0U] == '\0' ? NULL : domain, evaluation_result);
        return JG_NFQUEUE_DROP;
    }
    account_result(worker, &result);
    trace_decision(worker, packet, &result, domain[0U] == '\0' ? NULL : domain,
                   0);
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
    stats->tcp_resets =
        atomic_load_explicit(&worker->stats.tcp_resets, memory_order_relaxed);
    stats->dns_dropped =
        atomic_load_explicit(&worker->stats.dns_dropped, memory_order_relaxed);
    stats->dns_refused =
        atomic_load_explicit(&worker->stats.dns_refused, memory_order_relaxed);
    stats->dns_nxdomain =
        atomic_load_explicit(&worker->stats.dns_nxdomain, memory_order_relaxed);
    stats->dns_sinkholed = atomic_load_explicit(&worker->stats.dns_sinkholed,
                                                memory_order_relaxed);
    stats->internal_errors = atomic_load_explicit(
        &worker->stats.internal_errors, memory_order_relaxed);
    stats->sni_inspected = atomic_load_explicit(&worker->stats.sni_inspected,
                                                memory_order_relaxed);
    stats->sni_encrypted_or_unavailable = atomic_load_explicit(
        &worker->stats.sni_encrypted_or_unavailable, memory_order_relaxed);
    return 0;
}

/** @brief Copy the worker's detailed fragment-tracker counters. */
int jg_dataplane_worker_get_fragment_stats(
    const struct jg_dataplane_worker *worker,
    struct jg_fragment_stats *stats)
{
    return worker == NULL
               ? -EINVAL
               : jg_fragment_tracker_get_stats(worker->fragments, stats);
}

/** @brief Copy the worker's detailed TCP stream-tracker counters. */
int jg_dataplane_worker_get_stream_stats(
    const struct jg_dataplane_worker *worker,
    struct jg_tcp_stream_stats *stats)
{
    return worker == NULL
               ? -EINVAL
               : jg_tcp_stream_tracker_get_stats(worker->streams, stats);
}

/** @brief Release one stopped per-queue packet worker. */
void jg_dataplane_worker_destroy(struct jg_dataplane_worker *worker)
{
    if (worker == NULL) {
        return;
    }
    jg_tcp_stream_tracker_destroy(worker->tls_streams);
    jg_tcp_stream_tracker_destroy(worker->streams);
    jg_fragment_tracker_destroy(worker->fragments);
    free(worker->tls_parsers);
    free(worker->tls_output);
    free(worker->stream_messages);
    free(worker->stream_output);
    free(worker->dns_response);
    free(worker->fragment_frame);
    free(worker->fragment_payload);
    if (worker->dns_response_lock_initialized) {
        (void)pthread_mutex_destroy(&worker->dns_response_lock);
    }
    free(worker);
}
