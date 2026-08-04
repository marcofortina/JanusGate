/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "metrics.h"

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "janusgate/checked.h"

/** Number of stable metrics emitted from one runtime snapshot. */
#define METRIC_COUNT 53U

/** Number of scalar management metrics emitted after runtime counters. */
#define MANAGEMENT_METRIC_COUNT 15U

/** Stable metadata for one numeric Prometheus metric. */
struct metric_descriptor {
    const char *name;
    const char *type;
    const char *help;
};

/** Ordered public metric names and descriptions. */
static const struct metric_descriptor metrics[METRIC_COUNT] = {
    {"janusgate_policy_generation", "gauge",
     "Current immutable policy generation."},
    {"janusgate_nfqueue_packets_total", "counter",
     "Packets received from the kernel policy queue."},
    {"janusgate_nfqueue_accepted_total", "counter",
     "Packets accepted through NFQUEUE."},
    {"janusgate_nfqueue_dropped_total", "counter",
     "Packets dropped through NFQUEUE."},
    {"janusgate_nfqueue_malformed_total", "counter",
     "Malformed NFQUEUE messages."},
    {"janusgate_nfqueue_overflows_total", "counter",
     "Kernel queue overflow notifications."},
    {"janusgate_nfqueue_message_errors_total", "counter",
     "NFQUEUE transport message errors."},
    {"janusgate_nfqueue_verdict_errors_total", "counter",
     "NFQUEUE verdict submission errors."},
    {"janusgate_dataplane_packets_total", "counter",
     "Packets classified by the DNS dataplane."},
    {"janusgate_dataplane_allowed_total", "counter",
     "Packets allowed by policy."},
    {"janusgate_dataplane_blocked_total", "counter",
     "Packets blocked by policy."},
    {"janusgate_dataplane_malformed_total", "counter",
     "Malformed packets rejected by the dataplane."},
    {"janusgate_dataplane_fragments_total", "counter",
     "Fragmented packets presented to reconstruction."},
    {"janusgate_dataplane_tcp_segments_total", "counter",
     "TCP DNS segments presented to stream tracking."},
    {"janusgate_dataplane_tcp_resets_total", "counter",
     "Reset pairs emitted for blocked TCP DNS flows."},
    {"janusgate_dataplane_internal_errors_total", "counter",
     "Internal dataplane processing errors."},
    {"janusgate_fragments_stored_total", "counter",
     "Fragments retained while awaiting completion."},
    {"janusgate_fragments_duplicate_total", "counter",
     "Duplicate fragments observed."},
    {"janusgate_fragments_completed_total", "counter",
     "Fragmented datagrams reconstructed successfully."},
    {"janusgate_fragments_malformed_total", "counter",
     "Malformed fragments rejected."},
    {"janusgate_fragments_overlap_total", "counter",
     "Datagrams rejected after overlapping fragments."},
    {"janusgate_fragments_exhausted_total", "counter",
     "Fragments rejected by configured resource bounds."},
    {"janusgate_fragments_timeout_total", "counter",
     "Incomplete datagrams removed after timeout."},
    {"janusgate_tcp_stream_buffered_total", "counter",
     "TCP segments retained while awaiting a DNS message."},
    {"janusgate_tcp_stream_duplicate_total", "counter",
     "Duplicate TCP DNS segments observed."},
    {"janusgate_tcp_stream_messages_total", "counter",
     "Complete DNS messages reconstructed from TCP."},
    {"janusgate_tcp_stream_closed_total", "counter",
     "Tracked TCP DNS flows closed by FIN or RST."},
    {"janusgate_tcp_stream_malformed_total", "counter",
     "Malformed TCP DNS streams rejected."},
    {"janusgate_tcp_stream_conflict_total", "counter",
     "TCP DNS flows rejected after conflicting retransmission."},
    {"janusgate_tcp_stream_exhausted_total", "counter",
     "TCP DNS segments rejected by resource bounds."},
    {"janusgate_tcp_stream_timeout_total", "counter",
     "Tracked TCP DNS flows removed after timeout."},
    {"janusgate_packet_output_sent_total", "counter",
     "Synthetic Ethernet frames sent successfully."},
    {"janusgate_packet_output_errors_total", "counter",
     "Synthetic Ethernet frame output errors."},
    {"janusgate_tls_sni_inspected_total", "counter",
     "Visible TLS server names evaluated against policy."},
    {"janusgate_tls_sni_encrypted_or_unavailable_total", "counter",
     "TLS flows whose private server name was encrypted or unavailable."},
    {"janusgate_dns_block_drop_total", "counter",
     "Blocked UDP DNS queries discarded without a response."},
    {"janusgate_dns_block_refused_total", "counter",
     "REFUSED responses sent for blocked UDP DNS queries."},
    {"janusgate_dns_block_nxdomain_total", "counter",
     "NXDOMAIN responses sent for blocked UDP DNS queries."},
    {"janusgate_dns_block_sinkhole_total", "counter",
     "Sinkhole responses sent for blocked UDP DNS queries."},
    {"janusgate_policy_stats_submitted_total", "counter",
     "Policy decisions accepted by the statistics collector."},
    {"janusgate_policy_stats_dropped_total", "counter",
     "Policy decisions discarded without delaying traffic."},
    {"janusgate_policy_stats_dropped_during_restore_total", "counter",
     "Policy decisions discarded while a database restore was quiesced."},
    {"janusgate_policy_stats_stale_generation_dropped_total", "counter",
     "Policy decisions discarded after their policy generation expired."},
    {"janusgate_policy_stats_recorded_requests_total", "counter",
     "Policy request samples committed to persistent statistics."},
    {"janusgate_policy_stats_recorded_rules_total", "counter",
     "Policy rule samples committed to persistent statistics."},
    {"janusgate_policy_stats_write_failures_total", "counter",
     "Failed policy-statistics write batches."},
    {"janusgate_policy_stats_cleanup_batches_total", "counter",
     "Completed automatic policy-statistics cleanup batches."},
    {"janusgate_policy_stats_cleanup_failures_total", "counter",
     "Failed automatic policy-statistics cleanup attempts."},
    {"janusgate_policy_stats_detail_rows", "gauge",
     "Detailed policy-impact rows currently retained."},
    {"janusgate_policy_stats_estimated_bytes", "gauge",
     "Latest aggregate byte estimate for JanusGate SQLite files."},
    {"janusgate_policy_stats_cardinality_dropped_total", "counter",
     "New policy-impact rows rejected by persistent cardinality budgets."},
    {"janusgate_policy_stats_storage_dropped_total", "counter",
     "Policy-impact samples skipped while storage thresholds were exceeded."},
    {"janusgate_policy_stats_storage_suspended", "gauge",
     "Whether storage thresholds currently suspend detailed statistics."},
};

/** Ordered management metric names and descriptions. */
static const struct metric_descriptor
    management_metrics[MANAGEMENT_METRIC_COUNT] = {
        {"janusgate_authentication_failures_total", "counter",
         "Rejected management authentication attempts."},
        {"janusgate_alert_incidents_retained", "gauge",
         "Incident openings currently retained."},
        {"janusgate_alert_incidents_resolved_retained", "gauge",
         "Resolved incidents currently retained."},
        {"janusgate_alert_deliveries_pending", "gauge",
         "Webhook notifications awaiting delivery."},
        {"janusgate_alert_deliveries_succeeded_retained", "gauge",
         "Successful webhook deliveries currently retained."},
        {"janusgate_alert_deliveries_failed_retained", "gauge",
         "Abandoned webhook deliveries currently retained."},
        {"janusgate_alert_last_evaluation_timestamp_seconds", "gauge",
         "Unix timestamp of the latest native alert evaluation."},
        {"janusgate_management_certificate_expiry_timestamp_seconds", "gauge",
         "Unix timestamp at which the management certificate expires."},
        {"janusgate_blocklist_sources_unhealthy", "gauge",
         "Enabled remote blocklist sources currently unhealthy."},
        {"janusgate_blocklist_sources_stale", "gauge",
         "Enabled remote blocklist sources currently stale."},
        {"janusgate_filesystem_minimum_available_bytes", "gauge",
         "Minimum free bytes across JanusGate filesystems."},
        {"janusgate_alert_evaluation_successful", "gauge",
         "Whether the latest native alert evaluation completed."},
        {"janusgate_audit_valid", "gauge",
         "Whether the latest audit-chain verification succeeded."},
        {"janusgate_policy_synchronized", "gauge",
         "Whether desired and applied policy revisions match."},
        {"janusgate_management_degraded", "gauge",
         "Whether management consistency is degraded."},
};

/** Fixed labelled metric describing currently open incidents. */
static const struct metric_descriptor open_alerts_metric = {
    "janusgate_alerts_open",
    "gauge",
    "Currently open native alert incidents by fixed type.",
};

/** Ratio metric for the least available JanusGate filesystem. */
static const struct metric_descriptor filesystem_ratio_metric = {
    "janusgate_filesystem_minimum_available_ratio",
    "gauge",
    "Minimum free-space ratio across JanusGate filesystems.",
};

_Static_assert(sizeof(metrics) / sizeof(metrics[0]) == METRIC_COUNT,
               "metric descriptors and values must remain aligned");

/** @brief Copy runtime counters into their stable metric order. */
static void collect_values(const struct jg_daemon_runtime_stats *stats,
                           uint64_t values[METRIC_COUNT])
{
    values[0U] = stats->policy_generation;
    values[1U] = stats->queues.packets;
    values[2U] = stats->queues.accepted;
    values[3U] = stats->queues.dropped;
    values[4U] = stats->queues.malformed;
    values[5U] = stats->queues.overflows;
    values[6U] = stats->queues.message_errors;
    values[7U] = stats->queues.verdict_errors;
    values[8U] = stats->dataplane.packets;
    values[9U] = stats->dataplane.accepted;
    values[10U] = stats->dataplane.blocked;
    values[11U] = stats->dataplane.malformed;
    values[12U] = stats->dataplane.fragments;
    values[13U] = stats->dataplane.streams;
    values[14U] = stats->dataplane.tcp_resets;
    values[15U] = stats->dataplane.internal_errors;
    values[16U] = stats->fragments.stored;
    values[17U] = stats->fragments.duplicates;
    values[18U] = stats->fragments.completed;
    values[19U] = stats->fragments.malformed;
    values[20U] = stats->fragments.overlaps;
    values[21U] = stats->fragments.exhausted;
    values[22U] = stats->fragments.timeouts;
    values[23U] = stats->tcp_streams.buffered;
    values[24U] = stats->tcp_streams.duplicates;
    values[25U] = stats->tcp_streams.messages;
    values[26U] = stats->tcp_streams.closed;
    values[27U] = stats->tcp_streams.malformed;
    values[28U] = stats->tcp_streams.conflicts;
    values[29U] = stats->tcp_streams.exhausted;
    values[30U] = stats->tcp_streams.timeouts;
    values[31U] = stats->output.sent;
    values[32U] = stats->output.errors;
    values[33U] = stats->dataplane.sni_inspected;
    values[34U] = stats->dataplane.sni_encrypted_or_unavailable;
    values[35U] = stats->dataplane.dns_dropped;
    values[36U] = stats->dataplane.dns_refused;
    values[37U] = stats->dataplane.dns_nxdomain;
    values[38U] = stats->dataplane.dns_sinkholed;
    values[39U] = stats->policy_stats.submitted;
    values[40U] = stats->policy_stats.dropped;
    values[41U] = stats->policy_stats.restore_dropped;
    values[42U] = stats->policy_stats.stale_generation_dropped;
    values[43U] = stats->policy_stats.recorded_requests;
    values[44U] = stats->policy_stats.recorded_rules;
    values[45U] = stats->policy_stats.write_failures;
    values[46U] = stats->policy_stats.cleanup_batches;
    values[47U] = stats->policy_stats.cleanup_failures;
    values[48U] = stats->policy_stats.detail_rows;
    values[49U] = stats->policy_stats.estimated_bytes;
    values[50U] = stats->policy_stats.cardinality_dropped;
    values[51U] = stats->policy_stats.storage_dropped;
    values[52U] = stats->policy_stats.storage_suspended;
}

/** @brief Copy scalar management counters into stable metric order. */
static void collect_management_values(
    const struct jg_management_metrics *management,
    uint64_t values[MANAGEMENT_METRIC_COUNT])
{
    values[0U] = management->authentication_failures_total;
    values[1U] = management->alert_incidents_retained;
    values[2U] = management->alert_resolutions_retained;
    values[3U] = management->alert_deliveries_pending;
    values[4U] = management->alert_deliveries_succeeded;
    values[5U] = management->alert_deliveries_failed;
    values[6U] = management->alert_last_evaluation_at;
    values[7U] = management->certificate_expiry_timestamp;
    values[8U] = management->blocklist_sources_unhealthy;
    values[9U] = management->blocklist_sources_stale;
    values[10U] = management->filesystem_minimum_available_bytes;
    values[11U] = management->alert_evaluation_successful;
    values[12U] = management->audit_valid;
    values[13U] = management->policy_synchronized;
    values[14U] = management->management_degraded;
}

/** @brief Measure one complete Prometheus metric record. */
static int measure_metric(const struct metric_descriptor *descriptor,
                          uint64_t value,
                          size_t *size)
{
    const int measured =
        snprintf(NULL, 0, "# HELP %s %s\n# TYPE %s %s\n%s %" PRIu64 "\n",
                 descriptor->name, descriptor->help, descriptor->name,
                 descriptor->type, descriptor->name, value);

    if (measured < 0) {
        return -EIO;
    }
    return jg_size_add(*size, (size_t)measured, size) ? 0 : -EOVERFLOW;
}

/** @brief Write one complete Prometheus metric record. */
static int write_metric(const struct metric_descriptor *descriptor,
                        uint64_t value,
                        char *output,
                        size_t output_size,
                        size_t *offset)
{
    const int written =
        snprintf(output + *offset, output_size - *offset,
                 "# HELP %s %s\n# TYPE %s %s\n%s %" PRIu64 "\n",
                 descriptor->name, descriptor->help, descriptor->name,
                 descriptor->type, descriptor->name, value);

    if (written < 0 || (size_t)written >= output_size - *offset) {
        return -EIO;
    }
    *offset += (size_t)written;
    return 0;
}

/** @brief Measure all fixed labels of the open-alert metric family. */
static int measure_open_alerts(const struct jg_management_metrics *management,
                               size_t *size)
{
    int measured = snprintf(NULL, 0, "# HELP %s %s\n# TYPE %s %s\n",
                            open_alerts_metric.name, open_alerts_metric.help,
                            open_alerts_metric.name, open_alerts_metric.type);

    if (measured < 0 || !jg_size_add(*size, (size_t)measured, size)) {
        return measured < 0 ? -EIO : -EOVERFLOW;
    }
    for (size_t index = 0U; index < JG_ALERT_TYPE_COUNT; ++index) {
        const char *type = jg_alert_type_name((enum jg_alert_type)(index + 1U));

        measured = type == NULL
                       ? -1
                       : snprintf(NULL, 0, "%s{type=\"%s\"} %" PRIu64 "\n",
                                  open_alerts_metric.name, type,
                                  management->alert_open_by_type[index]);
        if (measured < 0 || !jg_size_add(*size, (size_t)measured, size)) {
            return measured < 0 ? -EIO : -EOVERFLOW;
        }
    }
    return 0;
}

/** @brief Write all fixed labels of the open-alert metric family. */
static int write_open_alerts(const struct jg_management_metrics *management,
                             char *output,
                             size_t output_size,
                             size_t *offset)
{
    int written = snprintf(output + *offset, output_size - *offset,
                           "# HELP %s %s\n# TYPE %s %s\n",
                           open_alerts_metric.name, open_alerts_metric.help,
                           open_alerts_metric.name, open_alerts_metric.type);

    if (written < 0 || (size_t)written >= output_size - *offset) {
        return -EIO;
    }
    *offset += (size_t)written;
    for (size_t index = 0U; index < JG_ALERT_TYPE_COUNT; ++index) {
        const char *type = jg_alert_type_name((enum jg_alert_type)(index + 1U));

        written = type == NULL
                      ? -1
                      : snprintf(output + *offset, output_size - *offset,
                                 "%s{type=\"%s\"} %" PRIu64 "\n",
                                 open_alerts_metric.name, type,
                                 management->alert_open_by_type[index]);
        if (written < 0 || (size_t)written >= output_size - *offset) {
            return -EIO;
        }
        *offset += (size_t)written;
    }
    return 0;
}

/** @brief Measure the fixed-point free-space ratio metric. */
static int measure_filesystem_ratio(uint64_t basis_points, size_t *size)
{
    const int measured = snprintf(
        NULL, 0, "# HELP %s %s\n# TYPE %s %s\n%s %" PRIu64 ".%04" PRIu64 "\n",
        filesystem_ratio_metric.name, filesystem_ratio_metric.help,
        filesystem_ratio_metric.name, filesystem_ratio_metric.type,
        filesystem_ratio_metric.name, basis_points / 10000U,
        basis_points % 10000U);

    if (measured < 0) {
        return -EIO;
    }
    return jg_size_add(*size, (size_t)measured, size) ? 0 : -EOVERFLOW;
}

/** @brief Write the fixed-point free-space ratio metric. */
static int write_filesystem_ratio(uint64_t basis_points,
                                  char *output,
                                  size_t output_size,
                                  size_t *offset)
{
    const int written =
        snprintf(output + *offset, output_size - *offset,
                 "# HELP %s %s\n# TYPE %s %s\n%s %" PRIu64 ".%04" PRIu64 "\n",
                 filesystem_ratio_metric.name, filesystem_ratio_metric.help,
                 filesystem_ratio_metric.name, filesystem_ratio_metric.type,
                 filesystem_ratio_metric.name, basis_points / 10000U,
                 basis_points % 10000U);

    if (written < 0 || (size_t)written >= output_size - *offset) {
        return -EIO;
    }
    *offset += (size_t)written;
    return 0;
}

/** @brief Render a complete bounded Prometheus runtime snapshot. */
int jg_metrics_render(const struct jg_daemon_runtime_stats *stats,
                      const struct jg_management_metrics *management,
                      char *output,
                      size_t output_size,
                      size_t *written)
{
    uint64_t values[METRIC_COUNT];
    uint64_t management_values[MANAGEMENT_METRIC_COUNT];
    size_t required = 0U;
    size_t offset = 0U;
    size_t index = 0U;
    int result = 0;

    if (stats == NULL || management == NULL || output == NULL ||
        written == NULL) {
        return -EINVAL;
    }
    *written = 0U;
    if (output_size > 0U) {
        output[0] = '\0';
    }
    collect_values(stats, values);
    collect_management_values(management, management_values);
    for (index = 0U; result == 0 && index < METRIC_COUNT; ++index) {
        result = measure_metric(&metrics[index], values[index], &required);
    }
    for (index = 0U; result == 0 && index < MANAGEMENT_METRIC_COUNT; ++index) {
        result = measure_metric(&management_metrics[index],
                                management_values[index], &required);
    }
    if (result == 0) {
        result = measure_open_alerts(management, &required);
    }
    if (result == 0) {
        result = measure_filesystem_ratio(
            management->filesystem_minimum_available_basis_points, &required);
    }
    *written = required;
    if (result != 0) {
        return result;
    }
    if (output_size <= required) {
        return -ENOSPC;
    }
    for (index = 0U; result == 0 && index < METRIC_COUNT; ++index) {
        result = write_metric(&metrics[index], values[index], output,
                              output_size, &offset);
    }
    for (index = 0U; result == 0 && index < MANAGEMENT_METRIC_COUNT; ++index) {
        result =
            write_metric(&management_metrics[index], management_values[index],
                         output, output_size, &offset);
    }
    if (result == 0) {
        result = write_open_alerts(management, output, output_size, &offset);
    }
    if (result == 0) {
        result = write_filesystem_ratio(
            management->filesystem_minimum_available_basis_points, output,
            output_size, &offset);
    }
    if (result == 0) {
        *written = offset;
    } else {
        output[0] = '\0';
    }
    return result;
}
