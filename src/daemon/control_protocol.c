/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "control_protocol.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "janusgate/checked.h"

/** Version of the fixed daemon status body. */
#define DAEMON_STATUS_VERSION 1U

/** Fixed metadata bytes preceding ordered status counters. */
#define DAEMON_STATUS_HEADER_SIZE 8U

/** @brief Copy semantic status fields into their stable wire order. */
static void collect_counters(const struct jg_daemon_runtime_stats *stats,
                             uint64_t *values)
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
}

/** @brief Restore semantic status fields from stable wire order. */
static void restore_counters(const uint64_t *values,
                             struct jg_daemon_runtime_stats *stats)
{
    stats->policy_generation = values[0U];
    stats->queues.packets = values[1U];
    stats->queues.accepted = values[2U];
    stats->queues.dropped = values[3U];
    stats->queues.malformed = values[4U];
    stats->queues.overflows = values[5U];
    stats->queues.message_errors = values[6U];
    stats->queues.verdict_errors = values[7U];
    stats->dataplane.packets = values[8U];
    stats->dataplane.accepted = values[9U];
    stats->dataplane.blocked = values[10U];
    stats->dataplane.malformed = values[11U];
    stats->dataplane.fragments = values[12U];
    stats->dataplane.streams = values[13U];
    stats->dataplane.tcp_resets = values[14U];
    stats->dataplane.internal_errors = values[15U];
    stats->fragments.stored = values[16U];
    stats->fragments.duplicates = values[17U];
    stats->fragments.completed = values[18U];
    stats->fragments.malformed = values[19U];
    stats->fragments.overlaps = values[20U];
    stats->fragments.exhausted = values[21U];
    stats->fragments.timeouts = values[22U];
    stats->tcp_streams.buffered = values[23U];
    stats->tcp_streams.duplicates = values[24U];
    stats->tcp_streams.messages = values[25U];
    stats->tcp_streams.closed = values[26U];
    stats->tcp_streams.malformed = values[27U];
    stats->tcp_streams.conflicts = values[28U];
    stats->tcp_streams.exhausted = values[29U];
    stats->tcp_streams.timeouts = values[30U];
    stats->output.sent = values[31U];
    stats->output.errors = values[32U];
}

/** @brief Encode one fixed version-one daemon status body. */
int jg_daemon_status_encode(const struct jg_daemon_runtime_stats *stats,
                            uint8_t *output,
                            size_t output_size,
                            size_t *encoded_size)
{
    uint64_t values[JG_DAEMON_STATUS_COUNTER_COUNT];
    size_t index = 0U;

    if (stats == NULL || output == NULL || encoded_size == NULL) {
        return -EINVAL;
    }
    if (output_size < JG_DAEMON_STATUS_WIRE_SIZE) {
        return -ENOSPC;
    }
    collect_counters(stats, values);
    (void)memset(output, 0, JG_DAEMON_STATUS_WIRE_SIZE);
    (void)jg_write_u16_be(output, output_size, 0U, DAEMON_STATUS_VERSION);
    (void)jg_write_u32_be(output, output_size, 4U,
                          JG_DAEMON_STATUS_COUNTER_COUNT);
    for (index = 0U; index < JG_DAEMON_STATUS_COUNTER_COUNT; ++index) {
        (void)jg_write_u64_be(output, output_size,
                              DAEMON_STATUS_HEADER_SIZE +
                                  index * sizeof(uint64_t),
                              values[index]);
    }
    *encoded_size = JG_DAEMON_STATUS_WIRE_SIZE;
    return 0;
}

/** @brief Decode one exact version-one daemon status body. */
int jg_daemon_status_decode(const uint8_t *data,
                            size_t data_size,
                            struct jg_daemon_runtime_stats *stats)
{
    uint64_t values[JG_DAEMON_STATUS_COUNTER_COUNT];
    struct jg_daemon_runtime_stats decoded = {0};
    uint32_t counter_count = 0U;
    uint16_t version = 0U;
    uint16_t reserved = 0U;
    size_t index = 0U;

    if (data == NULL || stats == NULL) {
        return -EINVAL;
    }
    if (data_size != JG_DAEMON_STATUS_WIRE_SIZE) {
        return -EMSGSIZE;
    }
    if (!jg_read_u16_be(data, data_size, 0U, &version) ||
        !jg_read_u16_be(data, data_size, 2U, &reserved) ||
        !jg_read_u32_be(data, data_size, 4U, &counter_count)) {
        return -EPROTO;
    }
    if (version != DAEMON_STATUS_VERSION) {
        return -EPROTONOSUPPORT;
    }
    if (reserved != 0U || counter_count != JG_DAEMON_STATUS_COUNTER_COUNT) {
        return -EPROTO;
    }
    for (index = 0U; index < JG_DAEMON_STATUS_COUNTER_COUNT; ++index) {
        if (!jg_read_u64_be(data, data_size,
                            DAEMON_STATUS_HEADER_SIZE +
                                index * sizeof(uint64_t),
                            &values[index])) {
            return -EPROTO;
        }
    }
    restore_counters(values, &decoded);
    *stats = decoded;
    return 0;
}
