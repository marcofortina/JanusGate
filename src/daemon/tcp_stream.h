/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file tcp_stream.h
 * @brief Bounded client-to-server DNS-over-TCP stream reconstruction.
 */

#ifndef JANUSGATE_DAEMON_TCP_STREAM_H
#define JANUSGATE_DAEMON_TCP_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "janusgate/packet.h"

/** TCP FIN control bit. */
#define JG_TCP_FLAG_FIN UINT8_C(0x01)

/** TCP SYN control bit. */
#define JG_TCP_FLAG_SYN UINT8_C(0x02)

/** TCP RST control bit. */
#define JG_TCP_FLAG_RST UINT8_C(0x04)

/** Largest configurable number of tracked TCP flows per worker. */
#define JG_TCP_STREAM_FLOW_LIMIT 1024U

/** Largest configurable receive window retained for one flow. */
#define JG_TCP_STREAM_BYTES_LIMIT 262144U

/** Largest configurable number of disjoint buffered ranges. */
#define JG_TCP_STREAM_SEGMENT_LIMIT 128U

/** Largest DNS message representable by its TCP length prefix. */
#define JG_TCP_STREAM_DNS_LIMIT 65535U

/** Largest number of messages emitted by one packet operation. */
#define JG_TCP_STREAM_MESSAGE_LIMIT 128U

/** Largest configurable idle or connection lifetime in milliseconds. */
#define JG_TCP_STREAM_TIMEOUT_LIMIT UINT64_C(86400000)

/**
 * @brief Resource and lifetime bounds for one independent stream tracker.
 */
struct jg_tcp_stream_limits {
    /** Maximum concurrently tracked client-to-server flows. */
    size_t max_flows;
    /** Maximum concurrent flows for one source IP address. */
    size_t max_flows_per_source;
    /** Maximum buffered sequence-space bytes for one flow. */
    size_t max_buffered_bytes;
    /** Maximum disjoint buffered ranges for one flow. */
    size_t max_out_of_order_segments;
    /** Maximum accepted DNS message bytes, excluding its length prefix. */
    size_t max_dns_message_size;
    /** Maximum complete messages emitted by one packet operation. */
    size_t max_messages_per_packet;
    /** Idle flow expiration interval in monotonic milliseconds. */
    uint64_t idle_timeout_ms;
    /** Absolute connection lifetime in monotonic milliseconds. */
    uint64_t connection_timeout_ms;
};

/**
 * @brief Location of one complete DNS message in the caller output buffer.
 */
struct jg_tcp_stream_message {
    /** First message byte in the output buffer. */
    size_t offset;
    /** Message bytes, excluding the two-byte TCP length prefix. */
    size_t size;
};

/**
 * @brief Packet-level outcome from one stream-tracker operation.
 */
enum jg_tcp_stream_result {
    /** New bytes were retained while a complete DNS message is unavailable. */
    JG_TCP_STREAM_BUFFERED = 1,
    /** The packet contributed no new stream bytes. */
    JG_TCP_STREAM_DUPLICATE = 2,
    /** One or more complete DNS messages were copied to caller storage. */
    JG_TCP_STREAM_MESSAGES = 3,
    /** FIN or RST removed the flow. */
    JG_TCP_STREAM_CLOSED = 4,
    /** DNS framing or packet metadata is invalid. */
    JG_TCP_STREAM_MALFORMED = 5,
    /** Conflicting retransmission rejected the flow until timeout. */
    JG_TCP_STREAM_CONFLICT = 6,
    /** A configured flow, byte, source, segment, or batch bound was reached. */
    JG_TCP_STREAM_EXHAUSTED = 7
};

/**
 * @brief Independently readable stream-tracker counters.
 */
struct jg_tcp_stream_stats {
    /** Packets which retained new incomplete stream bytes. */
    uint64_t buffered;
    /** Duplicate or fully consumed retransmissions observed. */
    uint64_t duplicates;
    /** Complete DNS messages emitted to callers. */
    uint64_t messages;
    /** Flows removed by FIN or RST. */
    uint64_t closed;
    /** Malformed frames or DNS length prefixes rejected. */
    uint64_t malformed;
    /** Flows rejected after conflicting retransmissions. */
    uint64_t conflicts;
    /** Packets rejected by configured resource bounds. */
    uint64_t exhausted;
    /** Active flows removed after idle or connection timeout. */
    uint64_t timeouts;
};

/** Opaque per-worker DNS-over-TCP stream tracker. */
struct jg_tcp_stream_tracker;

/**
 * @brief Initialize conservative per-worker stream limits.
 *
 * Defaults retain 128 flows, 16 flows per source, 16384 bytes and 32
 * disjoint ranges per flow. DNS messages are limited to 4096 bytes and 32
 * messages per packet operation. Idle and connection timeouts are 30 seconds
 * and 5 minutes respectively.
 *
 * @param[out] limits Limits to initialize; null is ignored.
 *
 * @thread_safety This function is reentrant.
 */
void jg_tcp_stream_limits_default(struct jg_tcp_stream_limits *limits);

/**
 * @brief Validate every stream memory, batch, and lifetime bound.
 *
 * @param[in] limits Limits to validate.
 *
 * @return 0 on success.
 * @return -EINVAL for a null or zero field.
 * @return -ERANGE when a supported maximum is exceeded or related bounds are
 * inconsistent.
 *
 * @thread_safety This function is reentrant.
 */
int jg_tcp_stream_limits_validate(const struct jg_tcp_stream_limits *limits);

/**
 * @brief Create one fully preallocated per-worker stream tracker.
 *
 * @param[in] limits Validated limits, or null for conservative defaults.
 * @param[out] tracker Receives the owned tracker.
 *
 * @return 0 on success.
 * @return -EINVAL or -ERANGE for invalid limits or arguments.
 * @return -EOVERFLOW when an arena size cannot be represented.
 * @return -ENOMEM when allocation fails.
 *
 * @thread_safety Concurrent creations are independent.
 */
int jg_tcp_stream_tracker_create(const struct jg_tcp_stream_limits *limits,
                                 struct jg_tcp_stream_tracker **tracker);

/**
 * @brief Add one complete client-to-server TCP segment.
 *
 * The caller output buffer must hold at least the configured buffered-byte
 * limit and @p messages must hold at least the configured message batch
 * limit. Complete messages are copied without their two-byte length prefixes.
 *
 * @param[in,out] tracker Per-worker stream tracker.
 * @param[in] packet Parsed, non-fragmented TCP packet view.
 * @param[in] now_ms Current monotonic milliseconds.
 * @param[out] output Destination for complete DNS message bytes.
 * @param[in] output_size Available destination bytes.
 * @param[out] messages Complete message locations in @p output.
 * @param[in] message_capacity Available message locations.
 * @param[out] message_count Number of emitted messages.
 * @param[out] result Packet-level stream outcome.
 *
 * @return 0 when @p result was produced.
 * @return -EINVAL for invalid arguments or packet metadata.
 * @return -ENOSPC when caller output storage is below configured limits.
 *
 * @thread_safety Exactly one packet thread may use a tracker.
 *
 * @side_effects Updates bounded stream state and counters.
 */
int jg_tcp_stream_tracker_add(struct jg_tcp_stream_tracker *tracker,
                              const struct jg_packet_view *packet,
                              uint64_t now_ms,
                              uint8_t *output,
                              size_t output_size,
                              struct jg_tcp_stream_message *messages,
                              size_t message_capacity,
                              size_t *message_count,
                              enum jg_tcp_stream_result *result);

/**
 * @brief Reject an existing flow after one emitted message is blocked.
 *
 * The compact rejection entry prevents a retransmission of the packet which
 * completed the blocked message from being accepted as already consumed.
 *
 * @param[in,out] tracker Per-worker stream tracker.
 * @param[in] packet Parsed TCP packet identifying the flow.
 * @param[in] now_ms Current monotonic milliseconds.
 *
 * @return 0 when a rejection entry was retained.
 * @return -EINVAL for invalid arguments or packet metadata.
 * @return -ENOSPC when no bounded rejection slot is available.
 *
 * @thread_safety Exactly one packet thread may use a tracker.
 *
 * @side_effects Discards buffered bytes and retains the flow key until timeout.
 */
int jg_tcp_stream_tracker_reject_flow(struct jg_tcp_stream_tracker *tracker,
                                      const struct jg_packet_view *packet,
                                      uint64_t now_ms);

/**
 * @brief Read a relaxed snapshot of stream counters.
 *
 * @param[in] tracker Stream tracker.
 * @param[out] stats Receives current counters.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 *
 * @thread_safety Safe while the packet thread updates the tracker.
 */
int jg_tcp_stream_tracker_get_stats(const struct jg_tcp_stream_tracker *tracker,
                                    struct jg_tcp_stream_stats *stats);

/**
 * @brief Destroy a stopped stream tracker.
 *
 * @param[in,out] tracker Tracker to release; null is accepted.
 *
 * @thread_safety The tracker must no longer process packets.
 */
void jg_tcp_stream_tracker_destroy(struct jg_tcp_stream_tracker *tracker);

#endif
