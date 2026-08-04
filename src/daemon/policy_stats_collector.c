/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "policy_stats_collector.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "database_internal.h"

/** Events written in one SQLite transaction. */
#define POLICY_STATS_WRITE_BATCH 128U

/** Rows removed by one automatic retention transaction. */
#define POLICY_STATS_CLEANUP_BATCH 1000U

/** Delay after one incomplete cleanup batch. */
#define POLICY_STATS_CLEANUP_CONTINUE_SECONDS 1U

/** Delay after one failed cleanup attempt. */
#define POLICY_STATS_CLEANUP_RETRY_SECONDS 60U

/** Normal interval between completed retention checks. */
#define POLICY_STATS_CLEANUP_INTERVAL_SECONDS 86400U

/** Independently updated collector counters. */
struct atomic_collector_stats {
    atomic_uint_fast64_t submitted;
    atomic_uint_fast64_t dropped;
    atomic_uint_fast64_t restore_dropped;
    atomic_uint_fast64_t stale_generation_dropped;
    atomic_uint_fast64_t recorded_requests;
    atomic_uint_fast64_t recorded_rules;
    atomic_uint_fast64_t write_failures;
    atomic_uint_fast64_t cleanup_batches;
    atomic_uint_fast64_t cleanup_failures;
};

/** Complete bounded collector state. */
struct jg_policy_stats_collector {
    struct jg_database *database;
    struct jg_policy_stats_event *queue;
    struct jg_policy_stats_event *batch;
    struct jg_policy_traffic_sample *traffic;
    struct jg_policy_rule_sample *rules;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    pthread_t thread;
    struct atomic_collector_stats stats;
    size_t capacity;
    size_t batch_capacity;
    size_t head;
    size_t count;
    uint64_t next_cleanup_at;
    uint64_t generation;
    bool mutex_initialized;
    bool condition_initialized;
    bool started;
    bool stopping;
    bool paused;
    bool restore_pause;
    bool writer_active;
};

/** @brief Add to one relaxed counter while saturating at UINT64_MAX. */
static void atomic_saturating_add(atomic_uint_fast64_t *counter, uint64_t value)
{
    uint_fast64_t current = atomic_load_explicit(counter, memory_order_relaxed);

    while (current != UINT_FAST64_MAX) {
        const uint_fast64_t remaining = UINT_FAST64_MAX - current;
        const uint_fast64_t increment =
            value > (uint64_t)remaining ? remaining : (uint_fast64_t)value;

        if (atomic_compare_exchange_weak_explicit(
                counter, &current, current + increment, memory_order_relaxed,
                memory_order_relaxed)) {
            return;
        }
    }
}

/** @brief Initialize every relaxed collector counter. */
static void initialize_stats(struct atomic_collector_stats *stats)
{
    atomic_init(&stats->submitted, 0U);
    atomic_init(&stats->dropped, 0U);
    atomic_init(&stats->restore_dropped, 0U);
    atomic_init(&stats->stale_generation_dropped, 0U);
    atomic_init(&stats->recorded_requests, 0U);
    atomic_init(&stats->recorded_rules, 0U);
    atomic_init(&stats->write_failures, 0U);
    atomic_init(&stats->cleanup_batches, 0U);
    atomic_init(&stats->cleanup_failures, 0U);
}

/** @brief Check whether one event path and domain pair is canonical. */
static bool event_path_valid(const struct jg_policy_stats_event *event)
{
    if (memchr(event->domain, '\0', sizeof(event->domain)) == NULL) {
        return false;
    }
    if (event->path == JG_POLICY_STATS_DNS) {
        return event->query_type != 0U &&
               jg_domain_is_normalized(event->domain);
    }
    if (event->path == JG_POLICY_STATS_TLS_SNI) {
        return event->query_type == 0U &&
               jg_domain_is_normalized(event->domain);
    }
    return event->path == JG_POLICY_STATS_NETWORK_DESTINATION &&
           event->query_type == 0U && event->domain[0U] == '\0';
}

/** @brief Check whether one client identity has valid persistent bounds. */
static bool event_client_valid(const struct jg_policy_client *client)
{
    return (client->address_family == JG_POLICY_ADDRESS_NONE ||
            client->address_family == JG_POLICY_ADDRESS_IPV4 ||
            client->address_family == JG_POLICY_ADDRESS_IPV6) &&
           (!client->has_vlan || client->vlan_id <= 4094U);
}

/** @brief Check relationships within one matching-rule event entry. */
static bool event_rule_valid(const struct jg_policy_stats_event_rule *rule)
{
    static const uint8_t empty_identity[JG_POLICY_RULE_IDENTITY_SIZE] = {0};

    return (rule->dimension == JG_POLICY_STATS_DOMAIN ||
            rule->dimension == JG_POLICY_STATS_DESTINATION) &&
           rule->rule_id != 0U && rule->rule_id <= INT64_MAX &&
           memcmp(rule->statistics_id, empty_identity,
                  sizeof(empty_identity)) != 0 &&
           rule->decision != rule->shadowed &&
           (!rule->enforced_block || rule->would_block) &&
           (!rule->allow_decision ||
            (!rule->would_block && !rule->enforced_block));
}

/** @brief Validate one complete event before non-blocking submission. */
static bool event_valid(const struct jg_policy_stats_event *event)
{
    size_t index = 0U;

    if (event == NULL || event->policy_generation == 0U ||
        event->occurred_at > INT64_MAX ||
        event->rule_count > JG_POLICY_STATS_EVENT_RULE_MAX ||
        !event_path_valid(event) || !event_client_valid(&event->client) ||
        (event->would_block && !event->matched) ||
        (event->enforced_block && !event->would_block)) {
        return false;
    }
    for (index = 0U; index < event->rule_count; ++index) {
        if (!event_rule_valid(&event->rules[index])) {
            return false;
        }
    }
    return true;
}

/** @brief Copy one queue prefix into the writer's private batch. */
static size_t drain_batch(struct jg_policy_stats_collector *collector)
{
    const size_t drained = collector->count < collector->batch_capacity
                               ? collector->count
                               : collector->batch_capacity;
    size_t index = 0U;

    for (index = 0U; index < drained; ++index) {
        collector->batch[index] = collector->queue[collector->head];
        collector->head = (collector->head + 1U) % collector->capacity;
    }
    collector->count -= drained;
    return drained;
}

/** @brief Convert self-contained events to the database batch contract. */
static size_t prepare_database_batch(
    struct jg_policy_stats_collector *collector,
    size_t event_count)
{
    size_t event_index = 0U;
    size_t rule_count = 0U;

    for (event_index = 0U; event_index < event_count; ++event_index) {
        const struct jg_policy_stats_event *event =
            &collector->batch[event_index];
        size_t rule_index = 0U;

        collector->traffic[event_index] = (struct jg_policy_traffic_sample){
            .occurred_at = event->occurred_at,
            .path = event->path,
            .matched = event->matched,
            .would_block = event->would_block,
            .enforced_block = event->enforced_block,
        };
        for (rule_index = 0U; rule_index < event->rule_count; ++rule_index) {
            const struct jg_policy_stats_event_rule *rule =
                &event->rules[rule_index];
            const bool domain = rule->dimension == JG_POLICY_STATS_DOMAIN;

            collector->rules[rule_count] = (struct jg_policy_rule_sample){
                .occurred_at = event->occurred_at,
                .dimension = rule->dimension,
                .rule_id = rule->rule_id,
                .path =
                    domain ? event->path : JG_POLICY_STATS_NETWORK_DESTINATION,
                .client = event->client,
                .domain = domain ? event->domain : "",
                .query_type = domain ? event->query_type : 0U,
                .decision = rule->decision,
                .would_block = rule->would_block,
                .enforced_block = rule->enforced_block,
                .allow_decision = rule->allow_decision,
                .shadowed = rule->shadowed,
            };
            (void)memcpy(collector->rules[rule_count].statistics_id,
                         rule->statistics_id,
                         sizeof(collector->rules[rule_count].statistics_id));
            ++rule_count;
        }
    }
    return rule_count;
}

/** @brief Persist one drained batch and account for its outcome. */
static void write_batch(struct jg_policy_stats_collector *collector,
                        size_t event_count)
{
    const size_t rule_count = prepare_database_batch(collector, event_count);
    const int result = jg_database_record_policy_stats(
        collector->database, collector->traffic, event_count, collector->rules,
        rule_count);

    if (result == 0) {
        atomic_saturating_add(&collector->stats.recorded_requests, event_count);
        atomic_saturating_add(&collector->stats.recorded_rules, rule_count);
    } else {
        atomic_saturating_add(&collector->stats.write_failures, 1U);
    }
}

/** @brief Add bounded seconds to a wall-clock time. */
static uint64_t future_time(uint64_t now, uint64_t delay)
{
    return delay > UINT64_MAX - now ? UINT64_MAX : now + delay;
}

/** @brief Run at most one automatic detail-retention transaction. */
static void run_cleanup(struct jg_policy_stats_collector *collector,
                        uint64_t now)
{
    struct jg_policy_stats_cleanup_report report = {0};
    struct jg_policy_stats_config config;
    int result =
        jg_database_load_policy_stats_config(collector->database, &config);

    if (result == 0 && config.retention_enabled) {
        result = jg_database_cleanup_policy_stats(
            collector->database, now, POLICY_STATS_CLEANUP_BATCH, &report);
    }
    if (result != 0) {
        atomic_saturating_add(&collector->stats.cleanup_failures, 1U);
        collector->next_cleanup_at =
            future_time(now, POLICY_STATS_CLEANUP_RETRY_SECONDS);
    } else if (!config.retention_enabled || report.complete) {
        if (config.retention_enabled) {
            atomic_saturating_add(&collector->stats.cleanup_batches, 1U);
        }
        collector->next_cleanup_at =
            future_time(now, POLICY_STATS_CLEANUP_INTERVAL_SECONDS);
    } else {
        atomic_saturating_add(&collector->stats.cleanup_batches, 1U);
        collector->next_cleanup_at =
            future_time(now, POLICY_STATS_CLEANUP_CONTINUE_SECONDS);
    }
}

/** @brief Wait for queued work, a stop request, or the retention deadline. */
static void wait_for_work(struct jg_policy_stats_collector *collector)
{
    while ((collector->count == 0U || collector->paused) &&
           !collector->stopping) {
        const time_t current = time(NULL);
        struct timespec deadline;
        int status = 0;

        if (collector->paused) {
            status =
                pthread_cond_wait(&collector->condition, &collector->mutex);
            if (status != 0) {
                return;
            }
            continue;
        }
        if (current < 0 || (uint64_t)current >= collector->next_cleanup_at) {
            return;
        }
        deadline.tv_sec = collector->next_cleanup_at > (uint64_t)INT64_MAX
                              ? (time_t)INT64_MAX
                              : (time_t)collector->next_cleanup_at;
        deadline.tv_nsec = 0L;
        status = pthread_cond_timedwait(&collector->condition,
                                        &collector->mutex, &deadline);
        if (status != 0 && status != ETIMEDOUT) {
            return;
        }
    }
}

/** @brief Drain queued events and perform scheduled retention. */
static void *collector_main(void *context)
{
    struct jg_policy_stats_collector *collector = context;

    for (;;) {
        size_t event_count = 0U;
        bool stopping = false;
        bool cleanup_due = false;
        const int status = pthread_mutex_lock(&collector->mutex);

        if (status != 0) {
            atomic_saturating_add(&collector->stats.write_failures, 1U);
            return NULL;
        }
        wait_for_work(collector);
        if (!collector->paused) {
            const time_t current = time(NULL);

            event_count = drain_batch(collector);
            cleanup_due =
                current < 0 || (uint64_t)current >= collector->next_cleanup_at;
        }
        stopping = collector->stopping;
        collector->writer_active = event_count != 0U || cleanup_due;
        (void)pthread_mutex_unlock(&collector->mutex);

        if (event_count != 0U) {
            write_batch(collector, event_count);
        }
        if (!stopping && cleanup_due) {
            const time_t current = time(NULL);

            if (current >= 0) {
                run_cleanup(collector, (uint64_t)current);
            }
        }
        if (pthread_mutex_lock(&collector->mutex) != 0) {
            atomic_saturating_add(&collector->stats.write_failures, 1U);
            return NULL;
        }
        collector->writer_active = false;
        (void)pthread_cond_broadcast(&collector->condition);
        (void)pthread_mutex_unlock(&collector->mutex);
        if (stopping && event_count == 0U) {
            return NULL;
        }
    }
}

/** @brief Create a stopped collector with one database-writer connection. */
int jg_policy_stats_collector_create(
    struct jg_database *database,
    size_t capacity,
    uint64_t initial_generation,
    struct jg_policy_stats_collector **collector)
{
    struct jg_policy_stats_collector *created = NULL;
    int status = 0;
    int result = 0;

    if (collector == NULL) {
        return -EINVAL;
    }
    *collector = NULL;
    if (database == NULL || capacity < JG_POLICY_STATS_QUEUE_MIN ||
        initial_generation == 0U || capacity > JG_POLICY_STATS_QUEUE_MAX) {
        return -EINVAL;
    }
    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        return -ENOMEM;
    }
    created->capacity = capacity;
    created->generation = initial_generation;
    created->batch_capacity = capacity < POLICY_STATS_WRITE_BATCH
                                  ? capacity
                                  : POLICY_STATS_WRITE_BATCH;
    created->queue = calloc(capacity, sizeof(*created->queue));
    created->batch = calloc(created->batch_capacity, sizeof(*created->batch));
    created->traffic =
        calloc(created->batch_capacity, sizeof(*created->traffic));
    created->rules =
        calloc(created->batch_capacity * JG_POLICY_STATS_EVENT_RULE_MAX,
               sizeof(*created->rules));
    if (created->queue == NULL || created->batch == NULL ||
        created->traffic == NULL || created->rules == NULL) {
        jg_policy_stats_collector_destroy(created);
        return -ENOMEM;
    }
    status = pthread_mutex_init(&created->mutex, NULL);
    result = status == 0 ? 0 : -status;
    created->mutex_initialized = result == 0;
    if (result == 0) {
        status = pthread_cond_init(&created->condition, NULL);
        result = status == 0 ? 0 : -status;
        created->condition_initialized = result == 0;
    }
    if (result == 0) {
        result = jg_database_open_peer(database, &created->database);
    }
    if (result != 0) {
        jg_policy_stats_collector_destroy(created);
        return result;
    }
    initialize_stats(&created->stats);
    *collector = created;
    return 0;
}

/** @brief Start the collector's single database-writer thread. */
int jg_policy_stats_collector_start(struct jg_policy_stats_collector *collector)
{
    int status = 0;
    int result = 0;

    if (collector == NULL) {
        return -EINVAL;
    }
    status = pthread_mutex_lock(&collector->mutex);
    if (status != 0) {
        return -status;
    }
    if (collector->started) {
        result = -EALREADY;
    } else if (collector->stopping) {
        result = -ECANCELED;
    } else {
        const time_t current = time(NULL);

        collector->next_cleanup_at = current < 0 ? 0U : (uint64_t)current;
        status =
            pthread_create(&collector->thread, NULL, collector_main, collector);
        if (status == 0) {
            collector->started = true;
        } else {
            result = -status;
        }
    }
    status = pthread_mutex_unlock(&collector->mutex);
    return result == 0 && status != 0 ? -status : result;
}

/** @brief Try to enqueue one valid event without waiting on packet paths. */
int jg_policy_stats_collector_submit(
    struct jg_policy_stats_collector *collector,
    const struct jg_policy_stats_event *event)
{
    size_t tail = 0U;
    bool restore_drop = false;
    bool stale_drop = false;
    int status = 0;
    int result = 0;

    if (collector == NULL || !event_valid(event)) {
        return -EINVAL;
    }
    status = pthread_mutex_trylock(&collector->mutex);
    if (status == EBUSY) {
        atomic_saturating_add(&collector->stats.dropped, 1U);
        return -EAGAIN;
    }
    if (status != 0) {
        atomic_saturating_add(&collector->stats.dropped, 1U);
        return -status;
    }
    if (!collector->started || collector->stopping) {
        result = -ECANCELED;
    } else if (collector->paused) {
        result = -ECANCELED;
        restore_drop = collector->restore_pause;
        stale_drop = !collector->restore_pause;
    } else if (event->policy_generation != collector->generation) {
        result = -ESTALE;
        stale_drop = true;
    } else if (collector->count == collector->capacity) {
        result = -EAGAIN;
    } else {
        tail = (collector->head + collector->count) % collector->capacity;
        collector->queue[tail] = *event;
        ++collector->count;
        atomic_saturating_add(&collector->stats.submitted, 1U);
        (void)pthread_cond_signal(&collector->condition);
    }
    status = pthread_mutex_unlock(&collector->mutex);
    if (result != 0) {
        atomic_saturating_add(&collector->stats.dropped, 1U);
        if (restore_drop) {
            atomic_saturating_add(&collector->stats.restore_dropped, 1U);
        }
        if (stale_drop) {
            atomic_saturating_add(&collector->stats.stale_generation_dropped,
                                  1U);
        }
    }
    return result == 0 && status != 0 ? -status : result;
}

/** @brief Quiesce the writer and discard queued events at a policy boundary. */
int jg_policy_stats_collector_pause(struct jg_policy_stats_collector *collector,
                                    bool restore)
{
    size_t discarded = 0U;
    int status = 0;
    int result = 0;

    if (collector == NULL) {
        return -EINVAL;
    }
    status = pthread_mutex_lock(&collector->mutex);
    if (status != 0) {
        return -status;
    }
    if (!collector->started || collector->stopping) {
        result = -ECANCELED;
    } else if (collector->paused) {
        result = -EALREADY;
    } else {
        collector->paused = true;
        collector->restore_pause = restore;
        discarded = collector->count;
        collector->head = 0U;
        collector->count = 0U;
        atomic_saturating_add(&collector->stats.dropped, discarded);
        if (restore) {
            atomic_saturating_add(&collector->stats.restore_dropped, discarded);
        } else {
            atomic_saturating_add(&collector->stats.stale_generation_dropped,
                                  discarded);
        }
        (void)pthread_cond_broadcast(&collector->condition);
        while (status == 0 && collector->writer_active) {
            status =
                pthread_cond_wait(&collector->condition, &collector->mutex);
        }
        if (status != 0) {
            result = -status;
        }
    }
    status = pthread_mutex_unlock(&collector->mutex);
    return result == 0 && status != 0 ? -status : result;
}

/** @brief Resume collection for exactly one published policy generation. */
int jg_policy_stats_collector_resume(
    struct jg_policy_stats_collector *collector,
    uint64_t generation)
{
    int status = 0;
    int result = 0;

    if (collector == NULL || generation == 0U) {
        return -EINVAL;
    }
    status = pthread_mutex_lock(&collector->mutex);
    if (status != 0) {
        return -status;
    }
    if (!collector->started || collector->stopping) {
        result = -ECANCELED;
    } else if (!collector->paused) {
        result = -EALREADY;
    } else {
        collector->generation = generation;
        collector->paused = false;
        collector->restore_pause = false;
        (void)pthread_cond_broadcast(&collector->condition);
    }
    status = pthread_mutex_unlock(&collector->mutex);
    return result == 0 && status != 0 ? -status : result;
}

/** @brief Request a non-blocking stop after draining queued events. */
int jg_policy_stats_collector_request_stop(
    struct jg_policy_stats_collector *collector)
{
    int status = 0;
    int result = 0;

    if (collector == NULL) {
        return -EINVAL;
    }
    status = pthread_mutex_lock(&collector->mutex);
    if (status != 0) {
        return -status;
    }
    if (!collector->started) {
        result = -ECANCELED;
    } else {
        collector->stopping = true;
        (void)pthread_cond_broadcast(&collector->condition);
    }
    status = pthread_mutex_unlock(&collector->mutex);
    return result == 0 && status != 0 ? -status : result;
}

/** @brief Join one explicitly stopped collector thread. */
int jg_policy_stats_collector_join(struct jg_policy_stats_collector *collector)
{
    int status = 0;

    if (collector == NULL) {
        return -EINVAL;
    }
    status = pthread_mutex_lock(&collector->mutex);
    if (status != 0) {
        return -status;
    }
    if (!collector->started || !collector->stopping) {
        (void)pthread_mutex_unlock(&collector->mutex);
        return -EINVAL;
    }
    status = pthread_mutex_unlock(&collector->mutex);
    if (status != 0) {
        return -status;
    }
    status = pthread_join(collector->thread, NULL);
    if (status != 0) {
        return -status;
    }
    status = pthread_mutex_lock(&collector->mutex);
    if (status != 0) {
        return -status;
    }
    collector->started = false;
    status = pthread_mutex_unlock(&collector->mutex);
    return status == 0 ? 0 : -status;
}

/** @brief Copy relaxed collector health counters. */
int jg_policy_stats_collector_get_stats(
    const struct jg_policy_stats_collector *collector,
    struct jg_policy_stats_collector_stats *stats)
{
    if (collector == NULL || stats == NULL) {
        return -EINVAL;
    }
    stats->submitted =
        atomic_load_explicit(&collector->stats.submitted, memory_order_relaxed);
    stats->dropped =
        atomic_load_explicit(&collector->stats.dropped, memory_order_relaxed);
    stats->restore_dropped = atomic_load_explicit(
        &collector->stats.restore_dropped, memory_order_relaxed);
    stats->stale_generation_dropped = atomic_load_explicit(
        &collector->stats.stale_generation_dropped, memory_order_relaxed);
    stats->recorded_requests = atomic_load_explicit(
        &collector->stats.recorded_requests, memory_order_relaxed);
    stats->recorded_rules = atomic_load_explicit(
        &collector->stats.recorded_rules, memory_order_relaxed);
    stats->write_failures = atomic_load_explicit(
        &collector->stats.write_failures, memory_order_relaxed);
    stats->cleanup_batches = atomic_load_explicit(
        &collector->stats.cleanup_batches, memory_order_relaxed);
    stats->cleanup_failures = atomic_load_explicit(
        &collector->stats.cleanup_failures, memory_order_relaxed);
    return 0;
}

/** @brief Stop, join, and release one collector and its database peer. */
void jg_policy_stats_collector_destroy(
    struct jg_policy_stats_collector *collector)
{
    if (collector == NULL) {
        return;
    }
    if (collector->started) {
        (void)jg_policy_stats_collector_request_stop(collector);
        (void)jg_policy_stats_collector_join(collector);
    }
    jg_database_close(collector->database);
    if (collector->condition_initialized) {
        (void)pthread_cond_destroy(&collector->condition);
    }
    if (collector->mutex_initialized) {
        (void)pthread_mutex_destroy(&collector->mutex);
    }
    free(collector->rules);
    free(collector->traffic);
    free(collector->batch);
    free(collector->queue);
    free(collector);
}
