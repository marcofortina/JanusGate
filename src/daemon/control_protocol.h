/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file control_protocol.h
 * @brief Stable daemon status body for the local control protocol.
 */

#ifndef JANUSGATE_DAEMON_CONTROL_PROTOCOL_H
#define JANUSGATE_DAEMON_CONTROL_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include "daemon_runtime.h"

/** Number of ordered counters in the current daemon status body. */
#define JG_DAEMON_STATUS_COUNTER_COUNT 35U

/** Exact bytes in the current daemon status body. */
#define JG_DAEMON_STATUS_WIRE_SIZE                                             \
    (8U + JG_DAEMON_STATUS_COUNTER_COUNT * sizeof(uint64_t))

/**
 * @brief Encode aggregate daemon status into its canonical binary body.
 *
 * @param[in] stats Aggregate runtime status.
 * @param[out] output Destination buffer.
 * @param[in] output_size Available destination bytes.
 * @param[out] encoded_size Receives @ref JG_DAEMON_STATUS_WIRE_SIZE.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -ENOSPC when @p output is too small.
 *
 * @thread_safety This function is reentrant.
 */
int jg_daemon_status_encode(const struct jg_daemon_runtime_stats *stats,
                            uint8_t *output,
                            size_t output_size,
                            size_t *encoded_size);

/**
 * @brief Decode one exact canonical daemon status body.
 *
 * Version-one and current status bodies are accepted.
 *
 * @param[in] data Exact supported status body.
 * @param[in] data_size Number of bytes in @p data.
 * @param[out] stats Receives decoded aggregate counters.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -EMSGSIZE unless @p data_size is exact.
 * @return -EPROTONOSUPPORT for an unsupported body version.
 * @return -EPROTO for noncanonical metadata.
 *
 * @thread_safety This function is reentrant.
 */
int jg_daemon_status_decode(const uint8_t *data,
                            size_t data_size,
                            struct jg_daemon_runtime_stats *stats);

#endif
