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

#include "daemon_runtime.h"

/**
 * @brief Render one runtime snapshot in Prometheus text format.
 *
 * The function first measures the complete representation and never returns
 * partial output. The required byte count excludes the null terminator.
 *
 * @param[in] stats Aggregate daemon runtime snapshot.
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
                      char *output,
                      size_t output_size,
                      size_t *written);

#endif
