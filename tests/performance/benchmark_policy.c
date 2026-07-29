/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/resource.h>
#include <unistd.h>

#include "dataplane.h"
#include "janusgate/database.h"
#include "janusgate/policy.h"
#include "janusgate/version.h"

/** Bytes reserved for each deterministic benchmark domain. */
#define BENCHMARK_DOMAIN_SIZE 32U

/** Default number of direct policy lookup samples. */
#define BENCHMARK_LOOKUP_SAMPLES 200000U

/** Default number of complete DNS frame evaluations. */
#define BENCHMARK_PACKET_SAMPLES 500000U

/** Maximum accepted sample count for one bounded benchmark run. */
#define BENCHMARK_SAMPLE_LIMIT 10000000U

/** Documented steady-state one-million-rule memory budget. */
#define BENCHMARK_RESIDENT_BUDGET_MIB 512.0

/** Documented peak one-million-rule construction memory budget. */
#define BENCHMARK_PEAK_BUDGET_MIB 1024.0

/** Required complete DNS frame evaluations per second. */
#define BENCHMARK_DNS_QPS_MINIMUM 25000.0

/** Required median normalized policy lookup latency in microseconds. */
#define BENCHMARK_LOOKUP_MEDIAN_MAX_US 100.0

/** Required p99 added DNS policy latency in microseconds. */
#define BENCHMARK_ADDED_P99_MAX_US 2000.0

/** Complete benchmark configuration parsed from the command line. */
struct benchmark_config {
    size_t rule_count;
    size_t lookup_samples;
    size_t packet_samples;
    bool enforce;
};

/** Measurements emitted as stable machine-readable JSON. */
struct benchmark_metrics {
    uint64_t build_ns;
    uint64_t lookup_elapsed_ns;
    uint64_t lookup_median_ns;
    uint64_t lookup_p99_ns;
    uint64_t dataplane_elapsed_ns;
    uint64_t dataplane_median_ns;
    uint64_t dataplane_p99_ns;
    uint64_t added_p99_ns;
    uint64_t resident_bytes;
    uint64_t peak_bytes;
};

/** Complete Ethernet, IPv4, UDP, and benchmark-domain DNS query. */
static const uint8_t dns_query_template[] = {
    0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xaaU,
    0xbbU, 0x08U, 0x00U, 0x45U, 0x00U, 0x00U, 0x44U, 0x12U, 0x34U, 0x00U, 0x00U,
    0x40U, 0x11U, 0x00U, 0x00U, 0xc0U, 0x00U, 0x02U, 0x0aU, 0x08U, 0x08U, 0x08U,
    0x08U, 0x30U, 0x39U, 0x00U, 0x35U, 0x00U, 0x30U, 0x00U, 0x00U, 0xbeU, 0xefU,
    0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x07U,
    'd',   '0',   '0',   '0',   '0',   '0',   '0',   0x09U, 'b',   'e',   'n',
    'c',   'h',   'm',   'a',   'r',   'k',   0x04U, 't',   'e',   's',   't',
    0x00U, 0x00U, 0x01U, 0x00U, 0x01U,
};

/** Print the exact benchmark command syntax. */
static void print_usage(FILE *stream)
{
    (void)fprintf(
        stream,
        "usage: janusgate-policy-benchmark [options]\n"
        "  --rules COUNT     policy rules, 1..1000000 (default: 1000000)\n"
        "  --lookups COUNT   direct lookup samples (default: 200000)\n"
        "  --packets COUNT   DNS frame samples (default: 500000)\n"
        "  --enforce         fail unless all documented targets pass\n"
        "  --help            show this help\n");
}

/** Parse one positive size bounded by the selected maximum. */
static int parse_count(const char *text, size_t maximum, size_t *value)
{
    char *end = NULL;
    unsigned long long parsed = 0U;

    if (text == NULL || value == NULL || text[0U] == '\0') {
        return -EINVAL;
    }
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0U ||
        parsed > (unsigned long long)maximum) {
        return -EINVAL;
    }
    *value = (size_t)parsed;
    return 0;
}

/** Parse strict benchmark options without accepting positional arguments. */
static int parse_arguments(int argc,
                           char **argv,
                           struct benchmark_config *config)
{
    int index = 1;

    if (config == NULL) {
        return -EINVAL;
    }
    config->rule_count = JG_DATABASE_POLICY_RULE_LIMIT;
    config->lookup_samples = BENCHMARK_LOOKUP_SAMPLES;
    config->packet_samples = BENCHMARK_PACKET_SAMPLES;
    config->enforce = false;

    while (index < argc) {
        if (strcmp(argv[index], "--enforce") == 0) {
            config->enforce = true;
            ++index;
        } else if (strcmp(argv[index], "--help") == 0) {
            print_usage(stdout);
            return 1;
        } else if (index + 1 < argc && strcmp(argv[index], "--rules") == 0) {
            if (parse_count(argv[index + 1], JG_DATABASE_POLICY_RULE_LIMIT,
                            &config->rule_count) != 0) {
                return -EINVAL;
            }
            index += 2;
        } else if (index + 1 < argc && strcmp(argv[index], "--lookups") == 0) {
            if (parse_count(argv[index + 1], BENCHMARK_SAMPLE_LIMIT,
                            &config->lookup_samples) != 0) {
                return -EINVAL;
            }
            index += 2;
        } else if (index + 1 < argc && strcmp(argv[index], "--packets") == 0) {
            if (parse_count(argv[index + 1], BENCHMARK_SAMPLE_LIMIT,
                            &config->packet_samples) != 0) {
                return -EINVAL;
            }
            index += 2;
        } else {
            return -EINVAL;
        }
    }
    if (config->enforce &&
        config->rule_count != JG_DATABASE_POLICY_RULE_LIMIT) {
        return -EINVAL;
    }
    return 0;
}

/** Read a monotonic nanosecond timestamp. */
static int monotonic_time(uint64_t *nanoseconds)
{
    struct timespec value;

    if (nanoseconds == NULL) {
        return -EINVAL;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return -errno;
    }
    *nanoseconds =
        (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
    return 0;
}

/** Return one nonnegative elapsed duration. */
static uint64_t elapsed_time(uint64_t started, uint64_t finished)
{
    return finished >= started ? finished - started : 0U;
}

/** Compare two nanosecond durations for qsort. */
static int compare_duration(const void *left, const void *right)
{
    const uint64_t first = *(const uint64_t *)left;
    const uint64_t second = *(const uint64_t *)right;

    if (first < second) {
        return -1;
    }
    if (first > second) {
        return 1;
    }
    return 0;
}

/** Select a nearest-rank percentile from sorted nonempty samples. */
static uint64_t percentile(const uint64_t *samples,
                           size_t sample_count,
                           size_t percent)
{
    size_t rank = 0U;

    if (samples == NULL || sample_count == 0U || percent == 0U ||
        percent > 100U) {
        return 0U;
    }
    rank = (sample_count * percent + 99U) / 100U;
    return samples[rank - 1U];
}

/** Return the current Linux resident set in bytes. */
static uint64_t resident_bytes(void)
{
    FILE *status = fopen("/proc/self/statm", "r");
    unsigned long total_pages = 0UL;
    unsigned long resident_pages = 0UL;
    const long page_size = sysconf(_SC_PAGESIZE);
    uint64_t bytes = 0U;

    if (status != NULL &&
        fscanf(status, "%lu %lu", &total_pages, &resident_pages) == 2 &&
        page_size > 0) {
        bytes = (uint64_t)resident_pages * (uint64_t)page_size;
    }
    if (status != NULL) {
        (void)fclose(status);
    }
    return bytes;
}

/** Return the Linux peak resident set in bytes. */
static uint64_t peak_resident_bytes(void)
{
    struct rusage usage;

    if (getrusage(RUSAGE_SELF, &usage) != 0 || usage.ru_maxrss < 0) {
        return 0U;
    }
    return (uint64_t)usage.ru_maxrss * UINT64_C(1024);
}

/** Format one deterministic rule domain into caller-owned storage. */
static int format_domain(size_t index, char domain[BENCHMARK_DOMAIN_SIZE])
{
    const int written =
        snprintf(domain, BENCHMARK_DOMAIN_SIZE, "d%06zu.benchmark.test", index);

    return written > 0 && (size_t)written < BENCHMARK_DOMAIN_SIZE ? 0
                                                                  : -EOVERFLOW;
}

/** Allocate and initialize the complete representative policy input. */
static int prepare_rules(size_t rule_count,
                         struct jg_policy_rule_input **rules,
                         char **names)
{
    struct jg_policy_rule_input *created_rules = NULL;
    char *created_names = NULL;
    size_t index = 0U;

    if (rule_count == 0U || rules == NULL || names == NULL) {
        return -EINVAL;
    }
    *rules = NULL;
    *names = NULL;
    created_rules = calloc(rule_count, sizeof(*created_rules));
    created_names = calloc(rule_count, BENCHMARK_DOMAIN_SIZE);
    if (created_rules == NULL || created_names == NULL) {
        free(created_names);
        free(created_rules);
        return -ENOMEM;
    }
    for (index = 0U; index < rule_count; ++index) {
        char *domain = created_names + index * BENCHMARK_DOMAIN_SIZE;

        if (format_domain(index, domain) != 0) {
            free(created_names);
            free(created_rules);
            return -EOVERFLOW;
        }
        created_rules[index].id = (uint64_t)index + 1U;
        created_rules[index].domain = domain;
        created_rules[index].effect = JG_POLICY_BLOCK;
        created_rules[index].source = JG_POLICY_SOURCE_BLOCKLIST;
        created_rules[index].target = JG_POLICY_DOMAIN_DNS;
        created_rules[index].scope.type = JG_POLICY_SCOPE_GLOBAL;
        created_rules[index].attribution = "performance benchmark";
    }
    *rules = created_rules;
    *names = created_names;
    return 0;
}

/** Advance one deterministic pseudo-random sample selector. */
static uint64_t next_sample(uint64_t *state)
{
    uint64_t value = *state;

    value ^= value << 13U;
    value ^= value >> 7U;
    value ^= value << 17U;
    *state = value;
    return value;
}

/** Measure normalized direct policy lookup latency. */
static int measure_lookups(const struct jg_policy_snapshot *snapshot,
                           size_t rule_count,
                           size_t sample_count,
                           struct benchmark_metrics *metrics)
{
    uint64_t *durations = NULL;
    uint64_t started_all = 0U;
    uint64_t finished_all = 0U;
    uint64_t random_state = UINT64_C(0x4a616e7573476174);
    size_t index = 0U;
    int result = 0;

    if (snapshot == NULL || rule_count == 0U || sample_count == 0U ||
        metrics == NULL) {
        return -EINVAL;
    }
    durations = malloc(sample_count * sizeof(*durations));
    if (durations == NULL) {
        return -ENOMEM;
    }
    result = monotonic_time(&started_all);
    for (index = 0U; result == 0 && index < sample_count; ++index) {
        struct jg_policy_match match;
        char domain[BENCHMARK_DOMAIN_SIZE];
        uint64_t started = 0U;
        uint64_t finished = 0U;
        const size_t selected =
            (size_t)(next_sample(&random_state) % (uint64_t)rule_count);

        result = format_domain(selected, domain);
        if (result == 0) {
            result = monotonic_time(&started);
        }
        if (result == 0) {
            result = jg_policy_match_domain(snapshot, domain, NULL, &match);
        }
        if (result == 0) {
            result = monotonic_time(&finished);
        }
        if (result == 0 && (!match.matched || match.effect != JG_POLICY_BLOCK ||
                            match.rule_id != (uint64_t)selected + 1U)) {
            result = -EIO;
        }
        durations[index] = elapsed_time(started, finished);
    }
    if (result == 0) {
        result = monotonic_time(&finished_all);
    }
    if (result == 0) {
        qsort(durations, sample_count, sizeof(*durations), compare_duration);
        metrics->lookup_elapsed_ns = elapsed_time(started_all, finished_all);
        metrics->lookup_median_ns = percentile(durations, sample_count, 50U);
        metrics->lookup_p99_ns = percentile(durations, sample_count, 99U);
    }
    free(durations);
    return result;
}

/** Build one benchmark DNS query for the selected policy rule. */
static int build_dns_query(size_t rule_index,
                           uint8_t frame[sizeof(dns_query_template)])
{
    char domain[BENCHMARK_DOMAIN_SIZE];

    if (frame == NULL || format_domain(rule_index, domain) != 0) {
        return -EINVAL;
    }
    (void)memcpy(frame, dns_query_template, sizeof(dns_query_template));
    (void)memcpy(frame + 55U, domain, 7U);
    return 0;
}

/** Measure complete DNS parsing and policy classification. */
static int measure_dataplane(const struct jg_policy_snapshot *snapshot,
                             size_t rule_count,
                             size_t sample_count,
                             struct benchmark_metrics *metrics)
{
    struct jg_policy_snapshot *empty = NULL;
    uint8_t frame[sizeof(dns_query_template)];
    uint64_t *durations = NULL;
    uint64_t *added = NULL;
    uint64_t started_all = 0U;
    uint64_t finished_all = 0U;
    size_t index = 0U;
    int result = 0;

    if (snapshot == NULL || rule_count == 0U || sample_count == 0U ||
        metrics == NULL) {
        return -EINVAL;
    }
    result = build_dns_query(rule_count - 1U, frame);
    if (result == 0) {
        result = jg_policy_snapshot_build(NULL, 0U, 2U, &empty);
    }
    if (result == 0) {
        durations = malloc(sample_count * sizeof(*durations));
        added = malloc(sample_count * sizeof(*added));
        if (durations == NULL || added == NULL) {
            result = -ENOMEM;
        }
    }
    for (index = 0U; result == 0 && index < sample_count; ++index) {
        struct jg_dataplane_result baseline;
        struct jg_dataplane_result policy;
        uint64_t baseline_started = 0U;
        uint64_t baseline_finished = 0U;
        uint64_t policy_started = 0U;
        uint64_t policy_finished = 0U;
        uint64_t baseline_duration = 0U;

        result = monotonic_time(&baseline_started);
        if (result == 0) {
            result = jg_dataplane_evaluate(frame, sizeof(frame), NULL, empty,
                                           &baseline);
        }
        if (result == 0) {
            result = monotonic_time(&baseline_finished);
        }
        if (result == 0) {
            result = monotonic_time(&policy_started);
        }
        if (result == 0) {
            result = jg_dataplane_evaluate(frame, sizeof(frame), NULL, snapshot,
                                           &policy);
        }
        if (result == 0) {
            result = monotonic_time(&policy_finished);
        }
        if (result == 0 && (baseline.verdict != JG_NFQUEUE_ACCEPT ||
                            policy.verdict != JG_NFQUEUE_DROP ||
                            policy.reason != JG_DATAPLANE_POLICY_BLOCK)) {
            result = -EIO;
        }
        baseline_duration = elapsed_time(baseline_started, baseline_finished);
        durations[index] = elapsed_time(policy_started, policy_finished);
        added[index] = durations[index] > baseline_duration
                           ? durations[index] - baseline_duration
                           : 0U;
    }
    if (result == 0) {
        result = monotonic_time(&started_all);
    }
    for (index = 0U; result == 0 && index < sample_count; ++index) {
        struct jg_dataplane_result policy;

        result = jg_dataplane_evaluate(frame, sizeof(frame), NULL, snapshot,
                                       &policy);
        if (result == 0 && policy.verdict != JG_NFQUEUE_DROP) {
            result = -EIO;
        }
    }
    if (result == 0) {
        result = monotonic_time(&finished_all);
    }
    if (result == 0) {
        qsort(durations, sample_count, sizeof(*durations), compare_duration);
        qsort(added, sample_count, sizeof(*added), compare_duration);
        metrics->dataplane_elapsed_ns = elapsed_time(started_all, finished_all);
        metrics->dataplane_median_ns = percentile(durations, sample_count, 50U);
        metrics->dataplane_p99_ns = percentile(durations, sample_count, 99U);
        metrics->added_p99_ns = percentile(added, sample_count, 99U);
    }
    free(added);
    free(durations);
    jg_policy_snapshot_destroy(empty);
    return result;
}

/** Convert a nanosecond duration to fractional microseconds. */
static double microseconds(uint64_t nanoseconds)
{
    return (double)nanoseconds / 1000.0;
}

/** Convert a byte count to binary mebibytes. */
static double mebibytes(uint64_t bytes)
{
    return (double)bytes / (1024.0 * 1024.0);
}

/** Calculate operations per second from a count and elapsed duration. */
static double operations_per_second(size_t count, uint64_t nanoseconds)
{
    if (nanoseconds == 0U) {
        return 0.0;
    }
    return (double)count * 1000000000.0 / (double)nanoseconds;
}

/** Check every documented benchmark acceptance threshold. */
static bool metrics_pass(const struct benchmark_config *config,
                         const struct benchmark_metrics *metrics)
{
    return config->rule_count == JG_DATABASE_POLICY_RULE_LIMIT &&
           operations_per_second(config->packet_samples,
                                 metrics->dataplane_elapsed_ns) >=
               BENCHMARK_DNS_QPS_MINIMUM &&
           microseconds(metrics->lookup_median_ns) <
               BENCHMARK_LOOKUP_MEDIAN_MAX_US &&
           microseconds(metrics->added_p99_ns) < BENCHMARK_ADDED_P99_MAX_US &&
           mebibytes(metrics->resident_bytes) <=
               BENCHMARK_RESIDENT_BUDGET_MIB &&
           mebibytes(metrics->peak_bytes) <= BENCHMARK_PEAK_BUDGET_MIB;
}

/** Emit stable JSON containing raw measurements and thresholds. */
static void print_metrics(const struct benchmark_config *config,
                          const struct benchmark_metrics *metrics,
                          bool passed)
{
    (void)printf(
        "{\n"
        "  \"_license\": \"AGPL-3.0-or-later\",\n"
        "  \"_copyright\": \"Copyright (C) 2026 Marco Fortina "
        "<marco_fortina@hotmail.it>\",\n"
        "  \"benchmark\": \"janusgate-policy\",\n"
        "  \"version\": \"%s\",\n"
        "  \"source_commit\": \"%s\",\n"
        "  \"build_compiler\": \"%s\",\n"
        "  \"build_target\": \"%s\",\n"
        "  \"rules\": %zu,\n"
        "  \"lookup_samples\": %zu,\n"
        "  \"packet_samples\": %zu,\n"
        "  \"policy_build_seconds\": %.6f,\n"
        "  \"resident_after_build_mib\": %.3f,\n"
        "  \"peak_build_rss_mib\": %.3f,\n"
        "  \"lookup_throughput_qps\": %.3f,\n"
        "  \"lookup_median_us\": %.3f,\n"
        "  \"lookup_p99_us\": %.3f,\n"
        "  \"dataplane_dns_qps\": %.3f,\n"
        "  \"dataplane_median_us\": %.3f,\n"
        "  \"dataplane_p99_us\": %.3f,\n"
        "  \"dns_policy_added_p99_us\": %.3f,\n"
        "  \"thresholds\": {\n"
        "    \"dataplane_dns_qps_min\": %.0f,\n"
        "    \"lookup_median_us_max\": %.0f,\n"
        "    \"dns_policy_added_p99_us_max\": %.0f,\n"
        "    \"resident_after_build_mib_max\": %.0f,\n"
        "    \"peak_build_rss_mib_max\": %.0f\n"
        "  },\n"
        "  \"thresholds_enforced\": %s,\n"
        "  \"passed\": %s\n"
        "}\n",
        jg_version_string(), jg_build_commit(), jg_build_compiler(),
        jg_build_target(), config->rule_count, config->lookup_samples,
        config->packet_samples, (double)metrics->build_ns / 1000000000.0,
        mebibytes(metrics->resident_bytes), mebibytes(metrics->peak_bytes),
        operations_per_second(config->lookup_samples,
                              metrics->lookup_elapsed_ns),
        microseconds(metrics->lookup_median_ns),
        microseconds(metrics->lookup_p99_ns),
        operations_per_second(config->packet_samples,
                              metrics->dataplane_elapsed_ns),
        microseconds(metrics->dataplane_median_ns),
        microseconds(metrics->dataplane_p99_ns),
        microseconds(metrics->added_p99_ns), BENCHMARK_DNS_QPS_MINIMUM,
        BENCHMARK_LOOKUP_MEDIAN_MAX_US, BENCHMARK_ADDED_P99_MAX_US,
        BENCHMARK_RESIDENT_BUDGET_MIB, BENCHMARK_PEAK_BUDGET_MIB,
        config->enforce ? "true" : "false", passed ? "true" : "false");
}

/** Build the representative snapshot and run every performance measurement. */
static int run_benchmark(const struct benchmark_config *config)
{
    struct jg_policy_rule_input *rules = NULL;
    struct jg_policy_snapshot *snapshot = NULL;
    struct benchmark_metrics metrics;
    char *names = NULL;
    uint64_t started = 0U;
    uint64_t finished = 0U;
    bool passed = false;
    int result = 0;

    (void)memset(&metrics, 0, sizeof(metrics));
    result = prepare_rules(config->rule_count, &rules, &names);
    if (result == 0) {
        result = monotonic_time(&started);
    }
    if (result == 0) {
        result =
            jg_policy_snapshot_build(rules, config->rule_count, 1U, &snapshot);
    }
    if (result == 0) {
        result = monotonic_time(&finished);
    }
    free(names);
    free(rules);
    if (result == 0) {
        metrics.build_ns = elapsed_time(started, finished);
        metrics.resident_bytes = resident_bytes();
        result = measure_lookups(snapshot, config->rule_count,
                                 config->lookup_samples, &metrics);
    }
    if (result == 0) {
        result = measure_dataplane(snapshot, config->rule_count,
                                   config->packet_samples, &metrics);
    }
    metrics.peak_bytes = peak_resident_bytes();
    if (result == 0) {
        passed = metrics_pass(config, &metrics);
        print_metrics(config, &metrics, passed);
        if (config->enforce && !passed) {
            result = -ERANGE;
        }
    }
    jg_policy_snapshot_destroy(snapshot);
    return result;
}

/** Parse options, execute the benchmark, and report one concise failure. */
int main(int argc, char **argv)
{
    struct benchmark_config config;
    int result = parse_arguments(argc, argv, &config);

    if (result == 1) {
        return 0;
    }
    if (result != 0) {
        print_usage(stderr);
        return 2;
    }
    result = run_benchmark(&config);
    if (result != 0) {
        (void)fprintf(stderr, "janusgate-policy-benchmark: %s\n",
                      strerror(-result));
        return 1;
    }
    return 0;
}
