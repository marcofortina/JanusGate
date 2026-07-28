/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file fragment.h
 * @brief Bounded IPv4 and IPv6 fragment payload reconstruction.
 */

#ifndef JANUSGATE_DAEMON_FRAGMENT_H
#define JANUSGATE_DAEMON_FRAGMENT_H

#include <stddef.h>
#include <stdint.h>

#include "janusgate/packet.h"

/** Largest configurable number of tracked fragmented datagrams. */
#define JG_FRAGMENT_DATAGRAM_LIMIT 1024U

/** Largest configurable fragment count retained for one datagram. */
#define JG_FRAGMENT_PER_DATAGRAM_LIMIT 64U

/** Largest configurable reconstructed IP payload. */
#define JG_FRAGMENT_BYTES_LIMIT 65535U

/** Maximum link and normalized IP header bytes added after reconstruction. */
#define JG_FRAGMENT_FRAME_OVERHEAD_MAX 128U

/** Largest configurable idle timeout in milliseconds. */
#define JG_FRAGMENT_TIMEOUT_MAX 120000U

/**
 * @brief Resource bounds for one independent fragment tracker.
 */
struct jg_fragment_limits {
    /** Maximum concurrently tracked datagrams. */
    size_t max_datagrams;
    /** Maximum retained fragments per datagram. */
    size_t max_fragments_per_datagram;
    /** Maximum reconstructed payload bytes per datagram. */
    size_t max_bytes_per_datagram;
    /** Maximum concurrent datagrams for one source IP address. */
    size_t max_datagrams_per_source;
    /** Idle expiration interval in monotonic milliseconds. */
    uint64_t timeout_ms;
};

/**
 * @brief Result of adding one valid fragmented packet.
 */
enum jg_fragment_result {
    /** Fragment was retained while gaps remain. */
    JG_FRAGMENT_STORED = 1,
    /** Byte-identical fragment was already retained. */
    JG_FRAGMENT_DUPLICATE = 2,
    /** Datagram became complete and was copied to the output. */
    JG_FRAGMENT_COMPLETE = 3,
    /** Fragment syntax or declared range is invalid. */
    JG_FRAGMENT_MALFORMED = 4,
    /** Datagram is rejected after an overlap or conflict until timeout. */
    JG_FRAGMENT_OVERLAP = 5,
    /** A configured memory, source, byte, or fragment bound was reached. */
    JG_FRAGMENT_EXHAUSTED = 6
};

/**
 * @brief Fragment-tracker health and attack counters.
 */
struct jg_fragment_stats {
    /** Fragments retained in incomplete datagrams. */
    uint64_t stored;
    /** Byte-identical duplicate fragments observed. */
    uint64_t duplicates;
    /** Datagrams reconstructed successfully. */
    uint64_t completed;
    /** Malformed fragments rejected. */
    uint64_t malformed;
    /** Datagrams invalidated by overlaps or conflicts. */
    uint64_t overlaps;
    /** Fragments rejected by configured resource bounds. */
    uint64_t exhausted;
    /** Incomplete datagrams removed after idle timeout. */
    uint64_t timeouts;
};

/** Opaque per-worker fragment tracker. */
struct jg_fragment_tracker;

/**
 * @brief Initialize conservative per-worker fragment limits.
 *
 * Defaults retain 128 datagrams, 32 fragments and 4096 bytes per datagram,
 * 16 datagrams per source, for 30 seconds of idle time.
 *
 * @param[out] limits Limits to initialize; null is ignored.
 *
 * @thread_safety This function is reentrant.
 */
void jg_fragment_limits_default(struct jg_fragment_limits *limits);

/**
 * @brief Validate fragment-tracker resource limits.
 *
 * @param[in] limits Limits to validate.
 *
 * @return 0 on success.
 * @return -EINVAL for a null or zero field.
 * @return -ERANGE when a supported maximum is exceeded or the per-source
 * bound exceeds the global datagram bound.
 *
 * @thread_safety This function is reentrant.
 */
int jg_fragment_limits_validate(const struct jg_fragment_limits *limits);

/**
 * @brief Create one fully preallocated fragment tracker.
 *
 * @param[in] limits Validated limits, or null for conservative defaults.
 * @param[out] tracker Receives the owned tracker.
 *
 * @return 0 on success.
 * @return -EINVAL or -ERANGE for invalid limits or arguments.
 * @return -EOVERFLOW when the bounded arena size cannot be represented.
 * @return -ENOMEM when allocation fails.
 *
 * @thread_safety Concurrent creations are independent.
 */
int jg_fragment_tracker_create(const struct jg_fragment_limits *limits,
                               struct jg_fragment_tracker **tracker);

/**
 * @brief Retain one fragment and reconstruct a complete IP payload.
 *
 * Fragment offsets are interpreted relative to the IPv4 payload or IPv6
 * fragmentable part exactly as populated by @ref jg_packet_parse.
 *
 * @param[in,out] tracker Per-worker tracker.
 * @param[in] packet Parsed fragmented packet view.
 * @param[in] now_ms Current monotonic milliseconds.
 * @param[out] output Destination for a completed payload.
 * @param[in] output_size Available destination bytes.
 * @param[out] reassembled_size Completed bytes, or zero while incomplete.
 * @param[out] result Packet-level fragment outcome.
 *
 * @return 0 when @p result was produced.
 * @return -EINVAL for invalid arguments or a non-fragmented packet view.
 * @return -ENOSPC if a complete payload does not fit @p output.
 *
 * @thread_safety Exactly one packet thread may use a tracker.
 *
 * @side_effects Updates bounded fragment state and counters.
 */
int jg_fragment_tracker_add(struct jg_fragment_tracker *tracker,
                            const struct jg_packet_view *packet,
                            uint64_t now_ms,
                            uint8_t *output,
                            size_t output_size,
                            size_t *reassembled_size,
                            enum jg_fragment_result *result);

/**
 * @brief Wrap one reconstructed fragmentable payload in a normalized frame.
 *
 * The original Ethernet and VLAN envelope is preserved. A minimal
 * non-fragmented IPv4 or IPv6 header is built from validated packet metadata.
 *
 * @param[in] packet Any parsed fragment from the completed datagram.
 * @param[in] payload Complete reconstructed fragmentable IP payload.
 * @param[in] payload_size Number of reconstructed payload bytes.
 * @param[out] output Destination for the normalized Ethernet frame.
 * @param[in] output_size Available destination bytes.
 * @param[out] frame_size Receives the complete normalized frame size.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid fragment metadata or arguments.
 * @return -ENOSPC when @p output is too small.
 * @return -EMSGSIZE when the payload cannot fit the selected IP version.
 *
 * @thread_safety This function is reentrant.
 */
int jg_fragment_build_frame(const struct jg_packet_view *packet,
                            const uint8_t *payload,
                            size_t payload_size,
                            uint8_t *output,
                            size_t output_size,
                            size_t *frame_size);

/**
 * @brief Read a relaxed snapshot of fragment counters.
 *
 * @param[in] tracker Fragment tracker.
 * @param[out] stats Receives current counters.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 *
 * @thread_safety Safe while the packet thread updates the tracker.
 */
int jg_fragment_tracker_get_stats(const struct jg_fragment_tracker *tracker,
                                  struct jg_fragment_stats *stats);

/**
 * @brief Destroy a stopped fragment tracker.
 *
 * @param[in,out] tracker Tracker to release; null is accepted.
 *
 * @thread_safety The tracker must no longer process fragments.
 */
void jg_fragment_tracker_destroy(struct jg_fragment_tracker *tracker);

#endif
