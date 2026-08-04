/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file metrics.h
 * @brief Stable Prometheus exposition for daemon runtime counters.
 *
 * Output contains no labels or administrator-controlled text. It can be
 * returned directly by an authenticated management endpoint.
 */

#ifndef JANUSGATE_DAEMON_METRICS_H
#define JANUSGATE_DAEMON_METRICS_H

#include <stddef.h>
#include <stdint.h>

#include "daemon_runtime.h"
#include "janusgate/alert.h"

/** Bounded management and alerting snapshot for Prometheus exposition. */
struct jg_management_metrics {
    /** Rejected management authentication attempts. */
    uint64_t authentication_failures_total;
    /** Open incident counts indexed by fixed alert type minus one. */
    uint64_t alert_open_by_type[JG_ALERT_TYPE_COUNT];
    /** Incident-opening transitions retained in storage. */
    uint64_t alert_incidents_retained;
    /** Resolved incidents retained in storage. */
    uint64_t alert_resolutions_retained;
    /** Webhook notifications awaiting delivery. */
    uint64_t alert_deliveries_pending;
    /** Successful webhook deliveries retained in storage. */
    uint64_t alert_deliveries_succeeded;
    /** Abandoned webhook deliveries retained in storage. */
    uint64_t alert_deliveries_failed;
    /** Latest native alert evaluation Unix timestamp. */
    uint64_t alert_last_evaluation_at;
    /** Latest webhook delivery-processing Unix timestamp. */
    uint64_t alert_last_delivery_at;
    /** Management certificate expiry Unix timestamp. */
    uint64_t certificate_expiry_timestamp;
    /** Enabled remote blocklist sources currently unhealthy. */
    uint64_t blocklist_sources_unhealthy;
    /** Enabled remote blocklist sources currently stale. */
    uint64_t blocklist_sources_stale;
    /** Minimum free bytes across JanusGate filesystems. */
    uint64_t filesystem_minimum_available_bytes;
    /** Minimum free ratio in ten-thousandths. */
    uint64_t filesystem_minimum_available_basis_points;
    /** One when the latest alert evaluation completed, otherwise zero. */
    uint64_t alert_evaluation_successful;
    /** One when the latest webhook delivery pass completed, otherwise zero. */
    uint64_t alert_delivery_successful;
    /** One when the latest audit verification succeeded, otherwise zero. */
    uint64_t audit_valid;
    /** One when desired and applied policy revisions match. */
    uint64_t policy_synchronized;
    /** One when management consistency is degraded. */
    uint64_t management_degraded;
};

/**
 * @brief Render one runtime snapshot in Prometheus text format.
 *
 * The function first measures the complete representation and never returns
 * partial output. The required byte count excludes the null terminator.
 *
 * @param[in] stats Aggregate daemon runtime snapshot.
 * @param[in] management Management and alerting snapshot.
 * @param[out] output Destination buffer.
 * @param[in] output_size Available destination bytes including null.
 * @param[out] written Receives the complete required bytes excluding null.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -ENOSPC when @p output cannot hold the complete representation.
 * @return -EOVERFLOW when a representation size cannot be expressed.
 *
 * @thread_safety This function is reentrant.
 */
int jg_metrics_render(const struct jg_daemon_runtime_stats *stats,
                      const struct jg_management_metrics *management,
                      char *output,
                      size_t output_size,
                      size_t *written);

#endif
