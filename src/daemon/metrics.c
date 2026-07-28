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
#define METRIC_COUNT 39U

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
     "Packets received from Linux NFQUEUE."},
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

/** @brief Render a complete bounded Prometheus runtime snapshot. */
int jg_metrics_render(const struct jg_daemon_runtime_stats *stats,
                      char *output,
                      size_t output_size,
                      size_t *written)
{
    uint64_t values[METRIC_COUNT];
    size_t required = 0U;
    size_t offset = 0U;
    size_t index = 0U;
    int result = 0;

    if (stats == NULL || output == NULL || written == NULL) {
        return -EINVAL;
    }
    *written = 0U;
    if (output_size > 0U) {
        output[0] = '\0';
    }
    collect_values(stats, values);
    for (index = 0U; result == 0 && index < METRIC_COUNT; ++index) {
        result = measure_metric(&metrics[index], values[index], &required);
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
    if (result == 0) {
        *written = offset;
    } else {
        output[0] = '\0';
    }
    return result;
}
