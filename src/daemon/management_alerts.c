/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_alerts.c
 * @brief Native condition evaluation and asynchronous alert delivery.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/stat.h>
#include <sys/statvfs.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>
#include <sodium.h>

#include "alert_webhook.h"
#include "database_internal.h"
#include "janusgate/certificate.h"
#include "janusgate/logging.h"

/** Slow audit-chain verification cadence. */
#define MANAGEMENT_ALERT_AUDIT_INTERVAL 3600U

/** Maximum deliveries attempted in one worker pass. */
#define MANAGEMENT_ALERT_DELIVERY_BATCH 4U

/** Blocklist source records evaluated per bounded storage page. */
#define MANAGEMENT_ALERT_SOURCE_PAGE 16U

/** Maximum JanusGate filesystem paths evaluated together. */
#define MANAGEMENT_ALERT_FILESYSTEM_COUNT 4U

/** Mutable sampling state owned by the alert worker thread. */
struct management_alerts {
    struct jg_database *database;
    struct jg_management *management;
    pthread_mutex_t mutex;
    pthread_cond_t wake;
    pthread_t thread;
    uint64_t last_audit_at;
    uint64_t queue_window_started_at;
    uint64_t queue_baseline;
    uint64_t authentication_window_started_at;
    uint64_t authentication_baseline;
    uint64_t audit_first_invalid_id;
    bool audit_valid;
    bool audit_known;
    bool mutex_initialized;
    bool condition_initialized;
    bool thread_started;
    bool stopping;
    bool initial_pass_complete;
};

_Static_assert(JG_AUTH_TOTP_KEY_SIZE == JG_ALERT_WEBHOOK_SECRET_SIZE,
               "management protection key size must match alert encryption");

/** @brief Retain the first error while continuing independent checks. */
static void retain_error(int candidate, int *result)
{
    if (*result == 0 && candidate != 0) {
        *result = candidate;
    }
}

/** @brief Read current Unix time for evaluation and delivery. */
static int alert_time(uint64_t *now)
{
    const time_t current = time(NULL);

    if (now == NULL || current < 0) {
        return -EIO;
    }
    *now = (uint64_t)current;
    return 0;
}

/** @brief Reconcile one fixed condition and discard its record. */
static int reconcile(struct management_alerts *alerts,
                     const struct jg_alert_configuration *configuration,
                     enum jg_alert_type type,
                     const char *resource,
                     enum jg_alert_severity severity,
                     const char *summary,
                     const char *details,
                     bool active,
                     uint64_t now)
{
    const struct jg_alert_condition condition = {
        .type = type,
        .resource = resource,
        .severity = severity,
        .summary = summary,
        .details = details,
    };
    struct jg_alert_incident incident;
    enum jg_alert_transition transition = JG_ALERT_TRANSITION_NONE;

    return jg_database_alert_reconcile(alerts->database, &condition, active,
                                       configuration->values.webhook_enabled,
                                       now, &incident, &transition);
}

/** @brief Evaluate aggregate management degradation. */
static int evaluate_degraded(struct management_alerts *alerts,
                             const struct jg_alert_configuration *configuration,
                             uint64_t now)
{
    const uint32_t reasons = management_degraded_reasons(alerts->management);
    char details[64U];
    const int written = snprintf(details, sizeof(details),
                                 "{\"reasons\":%" PRIu32 "}", reasons);

    if (written <= 0 || (size_t)written >= sizeof(details)) {
        return -EOVERFLOW;
    }
    return reconcile(alerts, configuration, JG_ALERT_TYPE_APPLIANCE_DEGRADED,
                     "appliance", JG_ALERT_SEVERITY_CRITICAL,
                     "Management consistency is degraded.", details,
                     reasons != 0U, now);
}

/** @brief Evaluate persistent and applied policy synchronization. */
static int evaluate_policy_sync(
    struct management_alerts *alerts,
    const struct jg_alert_configuration *configuration,
    uint64_t now)
{
    struct jg_database_policy_sync sync = {0};
    char details[192U];
    int result = jg_database_policy_sync_load(alerts->database, &sync);
    bool synchronized =
        result == 0 && sync.desired_revision == sync.applied_revision;
    int written = 0;

    atomic_store_explicit(&alerts->management->health->policy_synchronized,
                          synchronized, memory_order_release);
    if (result == 0) {
        written = snprintf(
            details, sizeof(details),
            "{\"applied_revision\":%" PRIu64 ",\"desired_revision\":%" PRIu64
            ",\"last_attempt_at\":%" PRIu64 "}",
            sync.applied_revision, sync.desired_revision, sync.last_attempt_at);
    } else {
        written =
            snprintf(details, sizeof(details), "{\"storage_error\":true}");
    }
    if (written <= 0 || (size_t)written >= sizeof(details)) {
        return -EOVERFLOW;
    }
    retain_error(
        reconcile(alerts, configuration, JG_ALERT_TYPE_POLICY_UNSYNCHRONIZED,
                  "policy", JG_ALERT_SEVERITY_CRITICAL,
                  result == 0 ? "Runtime policy is not synchronized."
                              : "Policy synchronization state is unavailable.",
                  details, !synchronized, now),
        &result);
    return result;
}

/** @brief Verify and evaluate the append-only audit chain. */
static int evaluate_audit(struct management_alerts *alerts,
                          const struct jg_alert_configuration *configuration,
                          uint64_t now)
{
    char details[96U];
    int result = 0;
    int written = 0;

    if (!alerts->audit_known || now < alerts->last_audit_at ||
        now - alerts->last_audit_at >= MANAGEMENT_ALERT_AUDIT_INTERVAL) {
        struct jg_audit_verification verification;

        result = jg_database_audit_verify(alerts->database, &verification);
        alerts->last_audit_at = now;
        alerts->audit_known = true;
        alerts->audit_valid = result == 0 && verification.valid;
        alerts->audit_first_invalid_id =
            result == 0 ? verification.first_invalid_id : 0U;
    }
    atomic_store_explicit(&alerts->management->health->audit_valid,
                          alerts->audit_valid, memory_order_release);
    written = snprintf(
        details, sizeof(details),
        "{\"first_invalid_id\":%" PRIu64 ",\"verification_error\":%s}",
        alerts->audit_first_invalid_id, result == 0 ? "false" : "true");
    if (written <= 0 || (size_t)written >= sizeof(details)) {
        return -EOVERFLOW;
    }
    retain_error(
        reconcile(alerts, configuration, JG_ALERT_TYPE_AUDIT_UNVERIFIABLE,
                  "audit", JG_ALERT_SEVERITY_CRITICAL,
                  result == 0 ? "The audit chain cannot be verified."
                              : "Audit verification could not be completed.",
                  details, !alerts->audit_valid, now),
        &result);
    return result;
}

/** @brief Evaluate remaining management-certificate lifetime. */
static int evaluate_certificate(
    struct management_alerts *alerts,
    const struct jg_alert_configuration *configuration,
    uint64_t now)
{
    struct jg_certificate_info certificate;
    const uint64_t warning_seconds =
        (uint64_t)configuration->values.certificate_warning_days * 86400U;
    char details[128U];
    int result = jg_certificate_inspect_file(
        alerts->management->certificate_path, &certificate);
    bool active = result != 0;
    enum jg_alert_severity severity = JG_ALERT_SEVERITY_ERROR;
    int written = 0;

    if (result == 0) {
        const uint64_t remaining =
            certificate.not_after > now ? certificate.not_after - now : 0U;

        active = remaining <= warning_seconds;
        severity = remaining == 0U ? JG_ALERT_SEVERITY_CRITICAL
                                   : JG_ALERT_SEVERITY_WARNING;
        written = snprintf(details, sizeof(details),
                           "{\"not_after\":%" PRIu64
                           ",\"remaining_seconds\":%" PRIu64 "}",
                           certificate.not_after, remaining);
        atomic_store_explicit(
            &alerts->management->health->certificate_expiry_timestamp,
            certificate.not_after, memory_order_release);
    } else {
        written = snprintf(details, sizeof(details),
                           "{\"certificate_unavailable\":true}");
        atomic_store_explicit(
            &alerts->management->health->certificate_expiry_timestamp, 0U,
            memory_order_release);
    }
    if (written <= 0 || (size_t)written >= sizeof(details)) {
        return -EOVERFLOW;
    }
    retain_error(
        reconcile(alerts, configuration, JG_ALERT_TYPE_CERTIFICATE_EXPIRING,
                  "management", severity,
                  result == 0
                      ? "The management certificate is nearing expiry."
                      : "The management certificate cannot be inspected.",
                  details, active, now),
        &result);
    return result;
}

/** @brief Evaluate one enabled remote blocklist source. */
static int evaluate_source(struct management_alerts *alerts,
                           const struct jg_alert_configuration *configuration,
                           const struct jg_database_blocklist_source *source,
                           uint64_t now,
                           uint64_t *unhealthy_count,
                           uint64_t *stale_count)
{
    const uint64_t success_age =
        source->last_success_at <= now ? now - source->last_success_at : 0U;
    const uint64_t initial_age =
        source->created_at <= now ? now - source->created_at : 0U;
    const uint64_t stale_after =
        source->update_interval_seconds >
                UINT64_MAX - configuration->values.source_stale_seconds
            ? UINT64_MAX
            : source->update_interval_seconds +
                  configuration->values.source_stale_seconds;
    const bool remote = source->url[0U] != '\0';
    const bool unhealthy =
        source->enabled && remote &&
        (source->consecutive_failures >=
             configuration->values.source_failure_threshold ||
         source->health == JG_DATABASE_BLOCKLIST_FAILED);
    const bool stale =
        source->enabled && remote &&
        (source->last_success_at == 0U ? initial_age > stale_after
                                       : success_age > stale_after);
    char resource[48U];
    char details[256U];
    const int resource_written =
        snprintf(resource, sizeof(resource), "source-%" PRIu64, source->id);
    const int details_written =
        snprintf(details, sizeof(details),
                 "{\"consecutive_failures\":%" PRIu32
                 ",\"last_success_at\":%" PRIu64 ",\"stale\":%s}",
                 source->consecutive_failures, source->last_success_at,
                 stale ? "true" : "false");

    if (resource_written <= 0 || (size_t)resource_written >= sizeof(resource) ||
        details_written <= 0 || (size_t)details_written >= sizeof(details)) {
        return -EOVERFLOW;
    }
    *unhealthy_count += unhealthy ? 1U : 0U;
    *stale_count += stale ? 1U : 0U;
    return reconcile(
        alerts, configuration, JG_ALERT_TYPE_SOURCE_UNHEALTHY, resource,
        unhealthy ? JG_ALERT_SEVERITY_ERROR : JG_ALERT_SEVERITY_WARNING,
        unhealthy ? "An enabled blocklist source is unhealthy."
                  : "An enabled blocklist source is stale.",
        details, unhealthy || stale, now);
}

/** @brief Evaluate every persistent blocklist source. */
static int evaluate_sources(struct management_alerts *alerts,
                            const struct jg_alert_configuration *configuration,
                            uint64_t now)
{
    struct jg_database_blocklist_source *sources =
        calloc(MANAGEMENT_ALERT_SOURCE_PAGE, sizeof(*sources));
    uint64_t after_id = 0U;
    uint64_t unhealthy = 0U;
    uint64_t stale = 0U;
    size_t count = 0U;
    bool has_more = false;
    int result = 0;

    if (sources == NULL) {
        return -ENOMEM;
    }
    do {
        int page_result = jg_database_list_blocklist_sources(
            alerts->database, after_id, MANAGEMENT_ALERT_SOURCE_PAGE, sources,
            &count, &has_more);

        retain_error(page_result, &result);
        if (page_result != 0) {
            break;
        }
        for (size_t index = 0U; index < count; ++index) {
            retain_error(evaluate_source(alerts, configuration, &sources[index],
                                         now, &unhealthy, &stale),
                         &result);
        }
        if (count != 0U) {
            after_id = sources[count - 1U].id;
        }
    } while (has_more);
    atomic_store_explicit(
        &alerts->management->health->blocklist_sources_unhealthy, unhealthy,
        memory_order_release);
    atomic_store_explicit(&alerts->management->health->blocklist_sources_stale,
                          stale, memory_order_release);
    free(sources);
    return result;
}

/** @brief Multiply filesystem blocks and block size with saturation. */
static uint64_t filesystem_bytes(uint64_t blocks, uint64_t block_size)
{
    return block_size != 0U && blocks > UINT64_MAX / block_size
               ? UINT64_MAX
               : blocks * block_size;
}

/** @brief Evaluate one JanusGate path and its underlying filesystem. */
static int evaluate_filesystem_path(
    struct management_alerts *alerts,
    const struct jg_alert_configuration *configuration,
    const char *path,
    const char *path_resource,
    dev_t seen[MANAGEMENT_ALERT_FILESYSTEM_COUNT],
    size_t *seen_count,
    uint64_t *minimum_bytes,
    uint64_t *minimum_basis_points,
    uint64_t now)
{
    struct stat metadata;
    struct statvfs filesystem;
    char resource[64U];
    char details[192U];
    uint64_t available = 0U;
    uint64_t basis_points = 0U;
    bool low = false;
    int result = 0;
    int written = 0;

    if (stat(path, &metadata) != 0 || statvfs(path, &filesystem) != 0) {
        const int path_result =
            reconcile(alerts, configuration, JG_ALERT_TYPE_FILESYSTEM_LOW_SPACE,
                      path_resource, JG_ALERT_SEVERITY_ERROR,
                      "A JanusGate filesystem path is unavailable.",
                      "{\"path_unavailable\":true}", true, now);

        return path_result != 0 ? path_result : -EIO;
    }
    retain_error(reconcile(alerts, configuration,
                           JG_ALERT_TYPE_FILESYSTEM_LOW_SPACE, path_resource,
                           JG_ALERT_SEVERITY_ERROR,
                           "A JanusGate filesystem path is unavailable.",
                           "{\"path_unavailable\":false}", false, now),
                 &result);
    for (size_t index = 0U; index < *seen_count; ++index) {
        if (seen[index] == metadata.st_dev) {
            return result;
        }
    }
    if (*seen_count >= MANAGEMENT_ALERT_FILESYSTEM_COUNT) {
        return result == 0 ? -EOVERFLOW : result;
    }
    seen[*seen_count] = metadata.st_dev;
    ++*seen_count;
    available = filesystem_bytes((uint64_t)filesystem.f_bavail,
                                 (uint64_t)filesystem.f_frsize);
    if (filesystem.f_blocks != 0U) {
        const long double ratio =
            (long double)filesystem.f_bavail / (long double)filesystem.f_blocks;

        basis_points = ratio >= 1.0L ? 10000U : (uint64_t)(ratio * 10000.0L);
    }
    if (available < *minimum_bytes) {
        *minimum_bytes = available;
    }
    if (basis_points < *minimum_basis_points) {
        *minimum_basis_points = basis_points;
    }
    low = available < configuration->values.filesystem_minimum_bytes ||
          basis_points <
              (uint64_t)configuration->values.filesystem_minimum_percent * 100U;
    written = snprintf(resource, sizeof(resource), "device-%" PRIuMAX,
                       (uintmax_t)metadata.st_dev);
    if (written <= 0 || (size_t)written >= sizeof(resource)) {
        return result == 0 ? -EOVERFLOW : result;
    }
    written = snprintf(details, sizeof(details),
                       "{\"available_basis_points\":%" PRIu64
                       ",\"available_bytes\":%" PRIu64 "}",
                       basis_points, available);
    if (written <= 0 || (size_t)written >= sizeof(details)) {
        return result == 0 ? -EOVERFLOW : result;
    }
    retain_error(
        reconcile(alerts, configuration, JG_ALERT_TYPE_FILESYSTEM_LOW_SPACE,
                  resource, JG_ALERT_SEVERITY_WARNING,
                  "A JanusGate filesystem has insufficient free space.",
                  details, low, now),
        &result);
    return result;
}

/** @brief Evaluate free space for every filesystem used by JanusGate. */
static int evaluate_filesystems(
    struct management_alerts *alerts,
    const struct jg_alert_configuration *configuration,
    uint64_t now)
{
    const char *const paths[MANAGEMENT_ALERT_FILESYSTEM_COUNT] = {
        alerts->database->path,
        alerts->management->certificate_path,
        alerts->management->totp_key_path,
        alerts->management->backup_directory,
    };
    static const char *const resources[MANAGEMENT_ALERT_FILESYSTEM_COUNT] = {
        "database-path",
        "certificate-path",
        "protection-key-path",
        "backup-path",
    };
    dev_t seen[MANAGEMENT_ALERT_FILESYSTEM_COUNT];
    size_t seen_count = 0U;
    uint64_t minimum_bytes = UINT64_MAX;
    uint64_t minimum_basis_points = UINT64_MAX;
    int result = 0;

    for (size_t index = 0U; index < MANAGEMENT_ALERT_FILESYSTEM_COUNT;
         ++index) {
        retain_error(evaluate_filesystem_path(alerts, configuration,
                                              paths[index], resources[index],
                                              seen, &seen_count, &minimum_bytes,
                                              &minimum_basis_points, now),
                     &result);
    }
    atomic_store_explicit(
        &alerts->management->health->filesystem_minimum_available_bytes,
        minimum_bytes == UINT64_MAX ? 0U : minimum_bytes, memory_order_release);
    atomic_store_explicit(
        &alerts->management->health->filesystem_minimum_available_basis_points,
        minimum_basis_points == UINT64_MAX ? 0U : minimum_basis_points,
        memory_order_release);
    return result;
}

/** @brief Add one monotonic counter with saturation. */
static uint64_t saturated_add(uint64_t first, uint64_t second)
{
    return first > UINT64_MAX - second ? UINT64_MAX : first + second;
}

/** @brief Return aggregate queue failures which can lose enforcement traffic.
 */
static uint64_t queue_failures(const struct jg_daemon_runtime_stats *stats)
{
    uint64_t failures =
        saturated_add(stats->queues.malformed, stats->queues.overflows);

    failures = saturated_add(failures, stats->queues.message_errors);
    return saturated_add(failures, stats->queues.verdict_errors);
}

/** @brief Evaluate packet-queue failures over one complete fixed window. */
static int evaluate_queues(struct management_alerts *alerts,
                           const struct jg_alert_configuration *configuration,
                           uint64_t now)
{
    struct jg_daemon_runtime_stats stats;
    char details[96U];
    uint64_t current = 0U;
    uint64_t failures = 0U;
    int result =
        jg_daemon_runtime_get_stats(alerts->management->runtime, &stats);
    int written = 0;

    if (result != 0) {
        return result;
    }
    current = queue_failures(&stats);
    if (alerts->queue_window_started_at == 0U ||
        now < alerts->queue_window_started_at) {
        alerts->queue_window_started_at = now;
        alerts->queue_baseline = current;
        return reconcile(alerts, configuration, JG_ALERT_TYPE_QUEUE_DROPS,
                         "packet-queues", JG_ALERT_SEVERITY_ERROR,
                         "Packet queues dropped enforcement traffic.",
                         "{\"failures\":0}", false, now);
    }
    if (now - alerts->queue_window_started_at <
        configuration->values.queue_window_seconds) {
        return 0;
    }
    failures = current >= alerts->queue_baseline
                   ? current - alerts->queue_baseline
                   : current;
    alerts->queue_window_started_at = now;
    alerts->queue_baseline = current;
    written =
        snprintf(details, sizeof(details),
                 "{\"failures\":%" PRIu64 ",\"window_seconds\":%" PRIu32 "}",
                 failures, configuration->values.queue_window_seconds);
    if (written <= 0 || (size_t)written >= sizeof(details)) {
        return -EOVERFLOW;
    }
    return reconcile(
        alerts, configuration, JG_ALERT_TYPE_QUEUE_DROPS, "packet-queues",
        JG_ALERT_SEVERITY_ERROR, "Packet queues dropped enforcement traffic.",
        details, failures >= configuration->values.queue_drop_threshold, now);
}

/** @brief Evaluate rejected credentials over one complete fixed window. */
static int evaluate_authentication(
    struct management_alerts *alerts,
    const struct jg_alert_configuration *configuration,
    uint64_t now)
{
    const uint64_t current = atomic_load_explicit(
        &alerts->management->health->authentication_failures_total,
        memory_order_acquire);
    char details[112U];
    uint64_t failures = 0U;
    int written = 0;

    if (alerts->authentication_window_started_at == 0U ||
        now < alerts->authentication_window_started_at) {
        alerts->authentication_window_started_at = now;
        alerts->authentication_baseline = current;
        return reconcile(
            alerts, configuration, JG_ALERT_TYPE_AUTHENTICATION_FAILURES,
            "management", JG_ALERT_SEVERITY_WARNING,
            "Authentication failures crossed the configured threshold.",
            "{\"failures\":0}", false, now);
    }
    if (now - alerts->authentication_window_started_at <
        configuration->values.authentication_window_seconds) {
        return 0;
    }
    failures = current >= alerts->authentication_baseline
                   ? current - alerts->authentication_baseline
                   : current;
    alerts->authentication_window_started_at = now;
    alerts->authentication_baseline = current;
    written =
        snprintf(details, sizeof(details),
                 "{\"failures\":%" PRIu64 ",\"window_seconds\":%" PRIu32 "}",
                 failures, configuration->values.authentication_window_seconds);
    if (written <= 0 || (size_t)written >= sizeof(details)) {
        return -EOVERFLOW;
    }
    return reconcile(
        alerts, configuration, JG_ALERT_TYPE_AUTHENTICATION_FAILURES,
        "management", JG_ALERT_SEVERITY_WARNING,
        "Authentication failures crossed the configured threshold.", details,
        failures >= configuration->values.authentication_failure_threshold,
        now);
}

/** @brief Resolve every currently open incident when evaluation is disabled. */
static int resolve_open_incidents(
    struct management_alerts *alerts,
    const struct jg_alert_configuration *configuration,
    uint64_t now)
{
    struct jg_alert_incident *incidents =
        calloc(JG_ALERT_PAGE_MAX, sizeof(*incidents));
    struct jg_alert_filter filter = {
        .state = JG_ALERT_STATE_OPEN,
    };
    size_t count = 0U;
    bool has_more = false;
    int result = 0;

    if (incidents == NULL) {
        return -ENOMEM;
    }
    do {
        int list_result =
            jg_database_alert_list(alerts->database, &filter, incidents,
                                   JG_ALERT_PAGE_MAX, &count, &has_more);

        retain_error(list_result, &result);
        if (list_result != 0) {
            break;
        }
        for (size_t index = 0U; index < count; ++index) {
            const struct jg_alert_condition condition = {
                .type = incidents[index].type,
                .resource = incidents[index].resource,
                .severity = incidents[index].severity,
                .summary = incidents[index].summary,
                .details = incidents[index].details,
            };
            struct jg_alert_incident resolved;
            enum jg_alert_transition transition;

            retain_error(jg_database_alert_reconcile(
                             alerts->database, &condition, false,
                             configuration->values.webhook_enabled, now,
                             &resolved, &transition),
                         &result);
        }
        if (count != 0U) {
            filter.before_id = incidents[count - 1U].id;
        }
    } while (has_more);
    free(incidents);
    return result;
}

/** @brief Publish one complete alert-storage metrics snapshot. */
static int publish_storage_metrics(struct management_alerts *alerts)
{
    struct jg_alert_storage_metrics metrics;
    int result = jg_database_alert_storage_metrics(alerts->database, &metrics);

    if (result != 0) {
        return result;
    }
    for (size_t index = 0U; index < JG_ALERT_TYPE_COUNT; ++index) {
        atomic_store_explicit(
            &alerts->management->health->alert_open_by_type[index],
            metrics.open_by_type[index], memory_order_release);
    }
    atomic_store_explicit(&alerts->management->health->alert_incidents_retained,
                          metrics.opened_total, memory_order_release);
    atomic_store_explicit(
        &alerts->management->health->alert_resolutions_retained,
        metrics.resolved_total, memory_order_release);
    atomic_store_explicit(&alerts->management->health->alert_deliveries_pending,
                          metrics.deliveries_pending, memory_order_release);
    atomic_store_explicit(
        &alerts->management->health->alert_deliveries_succeeded,
        metrics.deliveries_succeeded, memory_order_release);
    atomic_store_explicit(&alerts->management->health->alert_deliveries_failed,
                          metrics.deliveries_failed, memory_order_release);
    return 0;
}

/** @brief Evaluate every enabled native alert condition once. */
static int evaluate_conditions(
    struct management_alerts *alerts,
    const struct jg_alert_configuration *configuration,
    uint64_t now)
{
    int result = 0;

    if (!configuration->values.enabled) {
        retain_error(resolve_open_incidents(alerts, configuration, now),
                     &result);
    } else {
        retain_error(evaluate_degraded(alerts, configuration, now), &result);
        retain_error(evaluate_policy_sync(alerts, configuration, now), &result);
        retain_error(evaluate_audit(alerts, configuration, now), &result);
        retain_error(evaluate_certificate(alerts, configuration, now), &result);
        retain_error(evaluate_sources(alerts, configuration, now), &result);
        retain_error(evaluate_filesystems(alerts, configuration, now), &result);
        retain_error(evaluate_queues(alerts, configuration, now), &result);
        retain_error(evaluate_authentication(alerts, configuration, now),
                     &result);
    }
    retain_error(jg_database_alert_prune(alerts->database), &result);
    retain_error(publish_storage_metrics(alerts), &result);
    return result;
}

/** @brief Check whether shutdown was requested between delivery attempts. */
static bool delivery_stopping(struct management_alerts *alerts)
{
    bool stopping = true;

    if (pthread_mutex_lock(&alerts->mutex) == 0) {
        stopping = alerts->stopping;
        (void)pthread_mutex_unlock(&alerts->mutex);
    }
    return stopping;
}

/**
 * @brief Deliver one bounded batch while each attempt holds a restore lease.
 */
int management_alerts_deliver_pending(struct management_alerts *alerts)
{
    int result = 0;

    if (alerts == NULL) {
        return -EINVAL;
    }
    for (size_t index = 0U; result == 0 && !delivery_stopping(alerts) &&
                            index < MANAGEMENT_ALERT_DELIVERY_BATCH;
         ++index) {
        struct jg_alert_configuration configuration = {0};
        struct jg_alert_delivery delivery;
        uint8_t secret[JG_ALERT_WEBHOOK_SECRET_SIZE] = {0};
        char error[JG_ALERT_DELIVERY_ERROR_MAX + 1U];
        uint64_t attempted_at = 0U;
        uint64_t completed_at = 0U;
        int delivery_result = alert_time(&attempted_at);
        bool claimed = false;
        bool mutation_active = false;

        if (delivery_result == 0) {
            delivery_result = management_mutation_begin(alerts->management);
            mutation_active = delivery_result == 0;
        }
        if (delivery_result == 0) {
            delivery_result = jg_database_alert_delivery_claim(
                alerts->database, alerts->management->secrets->totp_key,
                attempted_at, &configuration, secret, &delivery);
        }
        claimed = delivery_result == 0;
        if (claimed) {
            const int webhook_result = alert_webhook_deliver(
                configuration.values.webhook_url,
                configuration.values.webhook_ca_pem,
                configuration.values.webhook_timeout_seconds, secret,
                delivery.event_id, attempted_at, delivery.payload, error);

            delivery_result = alert_time(&completed_at);
            if (delivery_result == 0) {
                int completion_result = jg_database_alert_delivery_complete(
                    alerts->database, &delivery, webhook_result == 0,
                    completed_at, webhook_result == 0 ? NULL : error);

                retain_error(publish_storage_metrics(alerts),
                             &completion_result);
                retain_error(completion_result, &delivery_result);
            }
            retain_error(webhook_result, &delivery_result);
        }
        if (mutation_active) {
            management_mutation_end(alerts->management);
        }
        jg_alert_configuration_clear(&configuration);
        sodium_memzero(secret, sizeof(secret));
        if (!claimed && delivery_result == -ENOENT) {
            break;
        }
        retain_error(delivery_result, &result);
    }
    return result;
}

/** @brief Enqueue the startup event when delivery was already configured. */
static int enqueue_startup_event(
    struct management_alerts *alerts,
    const struct jg_alert_configuration *configuration,
    uint64_t now)
{
    int result = 0;

    if (!alerts->initial_pass_complete &&
        configuration->values.webhook_enabled) {
        result = jg_database_alert_event_enqueue(
            alerts->database, "service.started", JG_ALERT_SEVERITY_WARNING,
            "The JanusGate service started.", "{}", now, NULL);
    }
    alerts->initial_pass_complete = true;
    return result;
}

/** @brief Convert one evaluation interval to an absolute wake time. */
static struct timespec next_wake(uint64_t now, uint32_t interval)
{
    const uint64_t maximum = (uint64_t)INT64_MAX;
    const uint64_t wake = now > maximum - interval ? maximum : now + interval;

    return (struct timespec){
        .tv_sec = (time_t)wake,
        .tv_nsec = 0L,
    };
}

/** @brief Run native evaluation and delivery until management shutdown. */
static void *run_management_alerts(void *context)
{
    struct management_alerts *alerts = context;

    for (;;) {
        struct jg_alert_configuration configuration = {0};
        uint64_t now = 0U;
        uint64_t delivery_at = 0U;
        uint32_t interval = 60U;
        int evaluation_result = alert_time(&now);
        int delivery_result = 0;
        bool stop = false;
        bool mutation_active = false;

        if (evaluation_result == 0) {
            evaluation_result = management_mutation_begin(alerts->management);
            mutation_active = evaluation_result == 0;
        }
        if (evaluation_result == 0) {
            evaluation_result = jg_database_alert_configuration_load(
                alerts->database, &configuration);
        }
        if (evaluation_result == 0) {
            interval = configuration.values.evaluation_interval_seconds;
            retain_error(enqueue_startup_event(alerts, &configuration, now),
                         &evaluation_result);
            retain_error(evaluate_conditions(alerts, &configuration, now),
                         &evaluation_result);
        }
        if (mutation_active) {
            management_mutation_end(alerts->management);
        }
        jg_alert_configuration_clear(&configuration);
        if (evaluation_result != -EBUSY) {
            atomic_store_explicit(
                &alerts->management->health->alert_last_evaluation_at, now,
                memory_order_release);
            atomic_store_explicit(
                &alerts->management->health->alert_evaluation_successful,
                evaluation_result == 0, memory_order_release);
        }
        if (evaluation_result != 0 && evaluation_result != -EBUSY) {
            (void)jg_log_emit(JG_LOG_WARNING, "alerting",
                              "alerting.evaluation_failed", "",
                              "Native alert evaluation did not complete", NULL);
        }

        delivery_result = management_alerts_deliver_pending(alerts);
        if (alert_time(&delivery_at) != 0) {
            delivery_at = now;
        }
        if (delivery_result != -EBUSY) {
            atomic_store_explicit(
                &alerts->management->health->alert_last_delivery_at,
                delivery_at, memory_order_release);
            atomic_store_explicit(
                &alerts->management->health->alert_delivery_successful,
                delivery_result == 0, memory_order_release);
        }
        if (delivery_result != 0 && delivery_result != -EBUSY) {
            (void)jg_log_emit(
                JG_LOG_WARNING, "alerting", "alerting.delivery_failed", "",
                "Webhook delivery processing did not complete", NULL);
        }

        if (pthread_mutex_lock(&alerts->mutex) != 0) {
            break;
        }
        stop = alerts->stopping;
        if (!stop) {
            const struct timespec wake = next_wake(now, interval);

            (void)pthread_cond_timedwait(&alerts->wake, &alerts->mutex, &wake);
            stop = alerts->stopping;
        }
        (void)pthread_mutex_unlock(&alerts->mutex);
        if (stop) {
            break;
        }
    }
    return NULL;
}

/** @brief Start native alert evaluation and asynchronous delivery. */
int management_alerts_create(struct jg_management *management,
                             struct management_alerts **alerts)
{
    struct management_alerts *created = NULL;
    int status = 0;
    int result = 0;

    if (management == NULL || alerts == NULL) {
        return -EINVAL;
    }
    *alerts = NULL;
    if (management->runtime == NULL) {
        return 0;
    }
    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        return -ENOMEM;
    }
    created->management = management;
    result = jg_database_open_peer(management->database, &created->database);
    if (result == 0) {
        status = pthread_mutex_init(&created->mutex, NULL);
        result = status == 0 ? 0 : -status;
        created->mutex_initialized = result == 0;
    }
    if (result == 0) {
        status = pthread_cond_init(&created->wake, NULL);
        result = status == 0 ? 0 : -status;
        created->condition_initialized = result == 0;
    }
    if (result != 0) {
        management_alerts_destroy(created);
        return result;
    }
    *alerts = created;
    return 0;
}

/** @brief Start one fully initialized native alert worker. */
int management_alerts_start(struct management_alerts *alerts)
{
    int status = 0;

    if (alerts == NULL || alerts->thread_started) {
        return -EINVAL;
    }
    status =
        pthread_create(&alerts->thread, NULL, run_management_alerts, alerts);
    if (status == 0) {
        alerts->thread_started = true;
    }
    return status == 0 ? 0 : -status;
}

/** @brief Stop and release native alert evaluation state. */
void management_alerts_destroy(struct management_alerts *alerts)
{
    if (alerts == NULL) {
        return;
    }
    if (alerts->mutex_initialized) {
        (void)pthread_mutex_lock(&alerts->mutex);
        alerts->stopping = true;
        if (alerts->condition_initialized) {
            (void)pthread_cond_broadcast(&alerts->wake);
        }
        (void)pthread_mutex_unlock(&alerts->mutex);
    }
    if (alerts->thread_started) {
        (void)pthread_join(alerts->thread, NULL);
    }
    jg_database_close(alerts->database);
    if (alerts->condition_initialized) {
        (void)pthread_cond_destroy(&alerts->wake);
    }
    if (alerts->mutex_initialized) {
        (void)pthread_mutex_destroy(&alerts->mutex);
    }
    free(alerts);
}

/** @brief Wake alert evaluation after a relevant configuration change. */
void management_alerts_wake(struct management_alerts *alerts)
{
    if (alerts != NULL && alerts->mutex_initialized &&
        pthread_mutex_lock(&alerts->mutex) == 0) {
        if (alerts->condition_initialized) {
            (void)pthread_cond_signal(&alerts->wake);
        }
        (void)pthread_mutex_unlock(&alerts->mutex);
    }
}

/** @brief Count one rejected credential or authenticated transport. */
void management_alert_authentication_failed(struct jg_management *management)
{
    _Atomic uint64_t *counter = NULL;
    uint64_t current = 0U;

    if (management == NULL || management->health == NULL) {
        return;
    }
    counter = &management->health->authentication_failures_total;
    current = atomic_load_explicit(counter, memory_order_relaxed);
    while (current != UINT64_MAX &&
           !atomic_compare_exchange_weak_explicit(
               counter, &current, current + 1U, memory_order_relaxed,
               memory_order_relaxed)) {
    }
}
