/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>

#include "janusgate/database.h"
#include "policy_stats_collector.h"

int jg_test_policy_stats_collector(void);

/** @brief Create one private temporary database path. */
static void make_database_path(char *directory,
                               size_t directory_size,
                               char *path,
                               size_t path_size)
{
    const char template[] = "/tmp/janusgate-stats-XXXXXX";
    int written = 0;

    (void)snprintf(directory, directory_size, "%s", template);
    assert_non_null(mkdtemp(directory));
    written = snprintf(path, path_size, "%s/janusgate.db", directory);
    assert_true(written > 0);
    assert_true((size_t)written < path_size);
}

/** @brief Remove one test database and its SQLite side files. */
static void remove_database(const char *directory, const char *path)
{
    static const char *const suffixes[] = {"-wal", "-shm", ".lkg", ".recovery"};
    char auxiliary[560U];
    size_t index = 0U;

    for (index = 0U; index < sizeof(suffixes) / sizeof(suffixes[0U]); ++index) {
        const int written = snprintf(auxiliary, sizeof(auxiliary), "%s%s", path,
                                     suffixes[index]);

        if (written > 0 && (size_t)written < sizeof(auxiliary)) {
            (void)unlink(auxiliary);
        }
    }
    (void)unlink(path);
    (void)rmdir(directory);
}

/** @brief Retry one deliberately non-blocking event submission. */
static void submit_event(struct jg_policy_stats_collector *collector,
                         const struct jg_policy_stats_event *event)
{
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000L};
    size_t attempt = 0U;
    int result = -EAGAIN;

    for (attempt = 0U; attempt < 2000U && result == -EAGAIN; ++attempt) {
        result = jg_policy_stats_collector_submit(collector, event);
        if (result == -EAGAIN) {
            (void)nanosleep(&pause, NULL);
        }
    }
    assert_int_equal(result, 0);
}

/** @brief Wait until the initial automatic cleanup transaction completes. */
static void wait_for_cleanup(struct jg_policy_stats_collector *collector)
{
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000L};
    struct jg_policy_stats_collector_stats stats;
    size_t attempt = 0U;

    (void)memset(&stats, 0, sizeof(stats));
    for (attempt = 0U; attempt < 2000U && stats.cleanup_batches == 0U;
         ++attempt) {
        assert_int_equal(jg_policy_stats_collector_get_stats(collector, &stats),
                         0);
        if (stats.cleanup_batches == 0U) {
            (void)nanosleep(&pause, NULL);
        }
    }
    assert_true(stats.cleanup_batches > 0U);
    assert_int_equal(stats.cleanup_failures, 0U);
}

/** @brief Verify asynchronous aggregation, draining, and retention. */
static void test_collection(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_policy_stats_event dns = {
        .policy_generation = 1U,
        .occurred_at = 7200U,
        .path = JG_POLICY_STATS_DNS,
        .client =
            {
                .has_mac = true,
                .mac = {0x02U, 0U, 0U, 0U, 0U, 1U},
                .address_family = JG_POLICY_ADDRESS_IPV4,
                .address = {192U, 0U, 2U, 10U},
                .has_vlan = true,
                .vlan_id = 30U,
            },
        .domain = "observed.example",
        .query_type = 1U,
        .matched = true,
        .would_block = true,
        .rule_count = 2U,
        .rules =
            {
                {
                    .dimension = JG_POLICY_STATS_DOMAIN,
                    .rule_id = 10U,
                    .statistics_id = {0x10U},
                    .decision = true,
                    .would_block = true,
                },
                {
                    .dimension = JG_POLICY_STATS_DESTINATION,
                    .rule_id = 20U,
                    .statistics_id = {0x20U},
                    .would_block = true,
                    .shadowed = true,
                },
            },
    };
    struct jg_policy_stats_event tls = {
        .policy_generation = 1U,
        .occurred_at = 10800U,
        .path = JG_POLICY_STATS_TLS_SNI,
        .client =
            {
                .address_family = JG_POLICY_ADDRESS_IPV6,
                .address = {0x20U, 0x01U, 0x0dU, 0xb8U},
            },
        .domain = "allowed.example",
        .matched = true,
        .rule_count = 1U,
        .rules =
            {
                {
                    .dimension = JG_POLICY_STATS_DOMAIN,
                    .rule_id = 11U,
                    .statistics_id = {0x11U},
                    .decision = true,
                    .allow_decision = true,
                },
            },
    };
    const struct jg_policy_traffic_sample old_traffic = {
        .occurred_at = 3600U,
        .path = JG_POLICY_STATS_DNS,
    };
    struct jg_policy_stats_collector_stats collector_stats;
    struct jg_policy_stats_cleanup_report cleanup;
    struct jg_policy_stats_config config;
    struct jg_policy_stats_config_update update;
    struct jg_policy_traffic_stats traffic_stats;
    struct jg_policy_rule_stats rules[2U];
    struct jg_policy_stats_collector *collector = NULL;
    struct jg_database *database = NULL;
    const time_t current = time(NULL);
    size_t count = 0U;
    bool has_more = false;

    (void)state;
    assert_true(current > 0);
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_load_policy_stats_config(database, &config),
                     0);
    update = (struct jg_policy_stats_config_update){
        .retention_enabled = false,
        .detail_enabled = config.detail_enabled,
        .retention_months = 1U,
        .detail_max_rows = config.detail_max_rows,
        .detail_max_rows_per_rule_hour = config.detail_max_rows_per_rule_hour,
        .detail_max_domains_per_rule_hour =
            config.detail_max_domains_per_rule_hour,
        .maximum_database_bytes = config.maximum_database_bytes,
        .minimum_free_bytes = config.minimum_free_bytes,
    };
    assert_int_equal(jg_database_update_policy_stats_config(
                         database, &update, config.revision, 100U, &config),
                     0);
    assert_int_equal(jg_policy_stats_collector_create(
                         database, JG_POLICY_STATS_QUEUE_MIN, 1U, &collector),
                     0);
    assert_int_equal(jg_policy_stats_collector_submit(collector, &dns),
                     -ECANCELED);
    assert_int_equal(jg_policy_stats_collector_start(collector), 0);
    assert_int_equal(jg_policy_stats_collector_start(collector), -EALREADY);
    submit_event(collector, &dns);
    submit_event(collector, &tls);
    assert_int_equal(jg_policy_stats_collector_request_stop(collector), 0);
    assert_int_equal(jg_policy_stats_collector_join(collector), 0);
    assert_int_equal(jg_policy_stats_collector_join(collector), -EINVAL);
    assert_int_equal(jg_policy_stats_collector_submit(collector, &dns),
                     -ECANCELED);
    assert_int_equal(
        jg_policy_stats_collector_get_stats(collector, &collector_stats), 0);
    assert_int_equal(collector_stats.submitted, 2U);
    assert_true(collector_stats.dropped >= 2U);
    assert_int_equal(collector_stats.recorded_requests, 2U);
    assert_int_equal(collector_stats.recorded_rules, 3U);
    assert_int_equal(collector_stats.write_failures, 0U);
    jg_policy_stats_collector_destroy(collector);
    collector = NULL;

    assert_int_equal(
        jg_database_load_policy_traffic_stats(database, &traffic_stats), 0);
    assert_int_equal(traffic_stats.request_count, 2U);
    assert_int_equal(
        jg_database_list_policy_rule_stats(database, JG_POLICY_STATS_DOMAIN, 0U,
                                           2U, rules, &count, &has_more),
        0);
    assert_int_equal(count, 2U);
    assert_false(has_more);
    assert_int_equal(rules[0U].would_block_count, 1U);
    assert_int_equal(rules[1U].allow_decision_count, 1U);
    assert_int_equal(jg_database_list_policy_rule_stats(
                         database, JG_POLICY_STATS_DESTINATION, 0U, 1U, rules,
                         &count, &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_int_equal(rules[0U].shadowed_count, 1U);

    assert_int_equal(
        jg_database_record_policy_stats(database, &old_traffic, 1U, NULL, 0U),
        0);
    update.retention_enabled = true;
    assert_int_equal(jg_database_update_policy_stats_config(
                         database, &update, config.revision, 200U, &config),
                     0);
    assert_int_equal(
        jg_policy_stats_collector_create(database, 8U, 1U, &collector), 0);
    assert_int_equal(jg_policy_stats_collector_start(collector), 0);
    wait_for_cleanup(collector);
    assert_int_equal(jg_policy_stats_collector_request_stop(collector), 0);
    assert_int_equal(jg_policy_stats_collector_join(collector), 0);
    jg_policy_stats_collector_destroy(collector);
    collector = NULL;

    assert_int_equal(jg_database_preview_policy_stats_cleanup(
                         database, (uint64_t)current, &cleanup),
                     0);
    assert_true(cleanup.complete);
    assert_int_equal(cleanup.impact_rows, 0U);
    assert_int_equal(cleanup.traffic_rows, 0U);
    assert_int_equal(
        jg_database_load_policy_traffic_stats(database, &traffic_stats), 0);
    assert_int_equal(traffic_stats.request_count, 3U);

    assert_int_equal(jg_policy_stats_collector_create(NULL, 8U, 1U, &collector),
                     -EINVAL);
    assert_int_equal(
        jg_policy_stats_collector_create(database, 1U, 1U, &collector),
        -EINVAL);
    assert_int_equal(jg_policy_stats_collector_start(NULL), -EINVAL);
    assert_int_equal(jg_policy_stats_collector_request_stop(NULL), -EINVAL);
    assert_int_equal(jg_policy_stats_collector_join(NULL), -EINVAL);
    assert_int_equal(
        jg_policy_stats_collector_get_stats(NULL, &collector_stats), -EINVAL);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify restore barriers and stale-generation rejection. */
static void test_generation_barrier(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_policy_stats_event event = {
        .policy_generation = 1U,
        .occurred_at = 7200U,
        .path = JG_POLICY_STATS_DNS,
        .client =
            {
                .address_family = JG_POLICY_ADDRESS_IPV4,
                .address = {192U, 0U, 2U, 20U},
            },
        .domain = "generation.example",
        .query_type = 1U,
    };
    struct jg_policy_stats_collector_stats stats;
    struct jg_policy_stats_collector *collector = NULL;
    struct jg_database *database = NULL;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(
        jg_policy_stats_collector_create(database, 8U, 1U, &collector), 0);
    assert_int_equal(jg_policy_stats_collector_start(collector), 0);

    assert_int_equal(jg_policy_stats_collector_pause(collector, true), 0);
    assert_int_equal(jg_policy_stats_collector_pause(collector, true),
                     -EALREADY);
    assert_int_equal(jg_policy_stats_collector_submit(collector, &event),
                     -ECANCELED);
    assert_int_equal(jg_policy_stats_collector_resume(collector, 2U), 0);
    assert_int_equal(jg_policy_stats_collector_resume(collector, 2U),
                     -EALREADY);
    assert_int_equal(jg_policy_stats_collector_submit(collector, &event),
                     -ESTALE);
    event.policy_generation = 2U;
    submit_event(collector, &event);

    assert_int_equal(jg_policy_stats_collector_request_stop(collector), 0);
    assert_int_equal(jg_policy_stats_collector_join(collector), 0);
    assert_int_equal(jg_policy_stats_collector_get_stats(collector, &stats), 0);
    assert_int_equal(stats.submitted, 1U);
    assert_int_equal(stats.dropped, 2U);
    assert_int_equal(stats.restore_dropped, 1U);
    assert_int_equal(stats.stale_generation_dropped, 1U);
    assert_int_equal(stats.recorded_requests, 1U);
    jg_policy_stats_collector_destroy(collector);

    assert_int_equal(jg_policy_stats_collector_pause(NULL, true), -EINVAL);
    assert_int_equal(jg_policy_stats_collector_resume(NULL, 1U), -EINVAL);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Run the asynchronous policy-statistics collector test group. */
int jg_test_policy_stats_collector(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_collection),
        cmocka_unit_test(test_generation_barrier),
    };

    return cmocka_run_group_tests_name("policy stats collector", tests, NULL,
                                       NULL);
}
