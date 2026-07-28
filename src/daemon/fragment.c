/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "fragment.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "janusgate/checked.h"

/** Canonical key for one fragmented IPv4 or IPv6 datagram. */
struct fragment_key {
    uint8_t source[JG_PACKET_ADDRESS_SIZE];
    uint8_t destination[JG_PACKET_ADDRESS_SIZE];
    uint16_t vlan_tci[JG_PACKET_VLAN_LIMIT];
    uint32_t fragment_id;
    size_t address_size;
    size_t vlan_count;
    enum jg_ip_version ip_version;
    uint8_t protocol;
};

/** One non-overlapping retained payload interval. */
struct fragment_interval {
    size_t offset;
    size_t size;
    bool more_fragments;
};

/** Metadata for one active fragment-reassembly slot. */
struct fragment_entry {
    struct fragment_key key;
    uint64_t expires_at;
    size_t fragment_count;
    size_t expected_size;
    bool has_last;
    bool rejected;
    bool active;
};

/** Independently readable fragment-tracker counters. */
struct atomic_fragment_stats {
    atomic_uint_fast64_t stored;
    atomic_uint_fast64_t duplicates;
    atomic_uint_fast64_t completed;
    atomic_uint_fast64_t malformed;
    atomic_uint_fast64_t overlaps;
    atomic_uint_fast64_t exhausted;
    atomic_uint_fast64_t timeouts;
};

/** Complete preallocated per-worker fragment state. */
struct jg_fragment_tracker {
    struct jg_fragment_limits limits;
    struct fragment_entry *entries;
    struct fragment_interval *intervals;
    uint8_t *payloads;
    struct atomic_fragment_stats stats;
};

/** @brief Increment one relaxed fragment counter. */
static void increment(atomic_uint_fast64_t *counter)
{
    (void)atomic_fetch_add_explicit(counter, 1U, memory_order_relaxed);
}

/** @brief Initialize every independently readable tracker counter. */
static void initialize_stats(struct atomic_fragment_stats *stats)
{
    atomic_init(&stats->stored, 0U);
    atomic_init(&stats->duplicates, 0U);
    atomic_init(&stats->completed, 0U);
    atomic_init(&stats->malformed, 0U);
    atomic_init(&stats->overlaps, 0U);
    atomic_init(&stats->exhausted, 0U);
    atomic_init(&stats->timeouts, 0U);
}

/** @brief Return the fixed interval slice for one entry index. */
static struct fragment_interval *entry_intervals(
    const struct jg_fragment_tracker *tracker,
    size_t entry_index)
{
    return tracker->intervals +
           entry_index * tracker->limits.max_fragments_per_datagram;
}

/** @brief Return the fixed payload slice for one entry index. */
static uint8_t *entry_payload(const struct jg_fragment_tracker *tracker,
                              size_t entry_index)
{
    return tracker->payloads +
           entry_index * tracker->limits.max_bytes_per_datagram;
}

/** @brief Clear one entry while preserving its preallocated arena slices. */
static void clear_entry(struct jg_fragment_tracker *tracker, size_t entry_index)
{
    struct fragment_interval *intervals = entry_intervals(tracker, entry_index);

    (void)memset(intervals, 0,
                 tracker->limits.max_fragments_per_datagram *
                     sizeof(*intervals));
    (void)memset(&tracker->entries[entry_index], 0,
                 sizeof(tracker->entries[0]));
}

/** @brief Build one canonical key from a validated fragmented packet. */
static void build_key(const struct jg_packet_view *packet,
                      struct fragment_key *key)
{
    size_t index = 0U;

    (void)memset(key, 0, sizeof(*key));
    (void)memcpy(key->source, packet->source_address, packet->address_size);
    (void)memcpy(key->destination, packet->destination_address,
                 packet->address_size);
    for (index = 0U; index < packet->vlan_count; ++index) {
        key->vlan_tci[index] = packet->vlan_tci[index] & UINT16_C(0x0fff);
    }
    key->fragment_id = packet->fragment_id;
    key->address_size = packet->address_size;
    key->vlan_count = packet->vlan_count;
    key->ip_version = packet->ip_version;
    key->protocol = packet->ip_protocol;
}

/** @brief Determine whether two canonical fragment keys are identical. */
static bool keys_equal(const struct fragment_key *left,
                       const struct fragment_key *right)
{
    return left->fragment_id == right->fragment_id &&
           left->address_size == right->address_size &&
           left->vlan_count == right->vlan_count &&
           left->ip_version == right->ip_version &&
           left->protocol == right->protocol &&
           memcmp(left->source, right->source, left->address_size) == 0 &&
           memcmp(left->destination, right->destination, left->address_size) ==
               0 &&
           memcmp(left->vlan_tci, right->vlan_tci,
                  left->vlan_count * sizeof(left->vlan_tci[0])) == 0;
}

/** @brief Determine whether two keys share the same source identity. */
static bool sources_equal(const struct fragment_key *left,
                          const struct fragment_key *right)
{
    return left->ip_version == right->ip_version &&
           left->address_size == right->address_size &&
           memcmp(left->source, right->source, left->address_size) == 0;
}

/** @brief Expire every entry whose idle deadline has elapsed. */
static void expire_entries(struct jg_fragment_tracker *tracker, uint64_t now_ms)
{
    size_t index = 0U;

    for (index = 0U; index < tracker->limits.max_datagrams; ++index) {
        if (tracker->entries[index].active &&
            tracker->entries[index].expires_at <= now_ms) {
            const bool rejected = tracker->entries[index].rejected;

            clear_entry(tracker, index);
            if (!rejected) {
                increment(&tracker->stats.timeouts);
            }
        }
    }
}

/** @brief Find an existing key and the first free tracker slot. */
static size_t find_entry(const struct jg_fragment_tracker *tracker,
                         const struct fragment_key *key,
                         size_t *free_index)
{
    size_t index = 0U;

    *free_index = SIZE_MAX;
    for (index = 0U; index < tracker->limits.max_datagrams; ++index) {
        if (!tracker->entries[index].active) {
            if (*free_index == SIZE_MAX) {
                *free_index = index;
            }
        } else if (keys_equal(&tracker->entries[index].key, key)) {
            return index;
        }
    }
    return SIZE_MAX;
}

/** @brief Count active datagrams associated with one source address. */
static size_t source_entry_count(const struct jg_fragment_tracker *tracker,
                                 const struct fragment_key *key)
{
    size_t count = 0U;
    size_t index = 0U;

    for (index = 0U; index < tracker->limits.max_datagrams; ++index) {
        if (tracker->entries[index].active &&
            sources_equal(&tracker->entries[index].key, key)) {
            ++count;
        }
    }
    return count;
}

/** @brief Return one saturated idle-expiration deadline. */
static uint64_t expiration_deadline(const struct jg_fragment_tracker *tracker,
                                    uint64_t now_ms)
{
    return now_ms > UINT64_MAX - tracker->limits.timeout_ms
               ? UINT64_MAX
               : now_ms + tracker->limits.timeout_ms;
}

/** @brief Create a new active entry in one known free slot. */
static void initialize_entry(struct jg_fragment_tracker *tracker,
                             size_t entry_index,
                             const struct fragment_key *key,
                             uint64_t now_ms)
{
    struct fragment_entry *entry = &tracker->entries[entry_index];

    entry->key = *key;
    entry->expires_at = expiration_deadline(tracker, now_ms);
    entry->active = true;
}

/** @brief Reject one datagram key until its fresh timeout expires. */
static void reject_entry(struct jg_fragment_tracker *tracker,
                         size_t entry_index,
                         uint64_t now_ms)
{
    const struct fragment_key key = tracker->entries[entry_index].key;

    clear_entry(tracker, entry_index);
    initialize_entry(tracker, entry_index, &key, now_ms);
    tracker->entries[entry_index].rejected = true;
}

/** @brief Find an overlap or byte-identical duplicate interval. */
static enum jg_fragment_result inspect_intervals(
    const struct jg_fragment_tracker *tracker,
    size_t entry_index,
    size_t fragment_offset,
    size_t fragment_size,
    bool more_fragments,
    const uint8_t *fragment)
{
    const struct fragment_entry *entry = &tracker->entries[entry_index];
    const struct fragment_interval *intervals =
        entry_intervals(tracker, entry_index);
    const uint8_t *payload = entry_payload(tracker, entry_index);
    const size_t fragment_end = fragment_offset + fragment_size;
    size_t index = 0U;

    for (index = 0U; index < entry->fragment_count; ++index) {
        const size_t interval_end =
            intervals[index].offset + intervals[index].size;

        if (fragment_offset == intervals[index].offset &&
            fragment_size == intervals[index].size &&
            more_fragments == intervals[index].more_fragments &&
            memcmp(fragment, payload + intervals[index].offset,
                   fragment_size) == 0) {
            return JG_FRAGMENT_DUPLICATE;
        }
        if (fragment_offset < interval_end &&
            intervals[index].offset < fragment_end) {
            return JG_FRAGMENT_OVERLAP;
        }
    }
    return JG_FRAGMENT_STORED;
}

/** @brief Insert one interval while preserving ascending offset order. */
static void insert_interval(struct jg_fragment_tracker *tracker,
                            size_t entry_index,
                            size_t fragment_offset,
                            size_t fragment_size,
                            bool more_fragments)
{
    struct fragment_entry *entry = &tracker->entries[entry_index];
    struct fragment_interval *intervals = entry_intervals(tracker, entry_index);
    size_t insertion = entry->fragment_count;

    while (insertion > 0U &&
           intervals[insertion - 1U].offset > fragment_offset) {
        intervals[insertion] = intervals[insertion - 1U];
        --insertion;
    }
    intervals[insertion].offset = fragment_offset;
    intervals[insertion].size = fragment_size;
    intervals[insertion].more_fragments = more_fragments;
    ++entry->fragment_count;
}

/** @brief Determine whether sorted intervals cover the expected payload. */
static bool entry_complete(const struct jg_fragment_tracker *tracker,
                           size_t entry_index)
{
    const struct fragment_entry *entry = &tracker->entries[entry_index];
    const struct fragment_interval *intervals =
        entry_intervals(tracker, entry_index);
    size_t cursor = 0U;
    size_t index = 0U;

    if (!entry->has_last) {
        return false;
    }
    for (index = 0U; index < entry->fragment_count; ++index) {
        if (intervals[index].offset != cursor) {
            return false;
        }
        cursor += intervals[index].size;
    }
    return cursor == entry->expected_size;
}

/** @brief Initialize conservative fragment-tracker limits. */
void jg_fragment_limits_default(struct jg_fragment_limits *limits)
{
    if (limits == NULL) {
        return;
    }
    limits->max_datagrams = 128U;
    limits->max_fragments_per_datagram = 32U;
    limits->max_bytes_per_datagram = 4096U;
    limits->max_datagrams_per_source = 16U;
    limits->timeout_ms = 30000U;
}

/** @brief Validate every fragment memory and lifetime bound. */
int jg_fragment_limits_validate(const struct jg_fragment_limits *limits)
{
    if (limits == NULL || limits->max_datagrams == 0U ||
        limits->max_fragments_per_datagram == 0U ||
        limits->max_bytes_per_datagram == 0U ||
        limits->max_datagrams_per_source == 0U || limits->timeout_ms == 0U) {
        return -EINVAL;
    }
    if (limits->max_datagrams > JG_FRAGMENT_DATAGRAM_LIMIT ||
        limits->max_fragments_per_datagram > JG_FRAGMENT_PER_DATAGRAM_LIMIT ||
        limits->max_bytes_per_datagram > JG_FRAGMENT_BYTES_LIMIT ||
        limits->max_datagrams_per_source > limits->max_datagrams ||
        limits->timeout_ms > JG_FRAGMENT_TIMEOUT_MAX) {
        return -ERANGE;
    }
    return 0;
}

/** @brief Create one fully preallocated per-worker fragment tracker. */
int jg_fragment_tracker_create(const struct jg_fragment_limits *limits,
                               struct jg_fragment_tracker **tracker)
{
    struct jg_fragment_limits defaults;
    const struct jg_fragment_limits *active_limits = limits;
    struct jg_fragment_tracker *created = NULL;
    size_t interval_count = 0U;
    size_t payload_bytes = 0U;
    int result = 0;

    if (tracker == NULL) {
        return -EINVAL;
    }
    *tracker = NULL;
    if (active_limits == NULL) {
        jg_fragment_limits_default(&defaults);
        active_limits = &defaults;
    }
    result = jg_fragment_limits_validate(active_limits);
    if (result != 0) {
        return result;
    }
    if (!jg_size_multiply(active_limits->max_datagrams,
                          active_limits->max_fragments_per_datagram,
                          &interval_count) ||
        !jg_size_multiply(active_limits->max_datagrams,
                          active_limits->max_bytes_per_datagram,
                          &payload_bytes)) {
        return -EOVERFLOW;
    }

    created = calloc(1U, sizeof(*created));
    if (created != NULL) {
        created->entries =
            calloc(active_limits->max_datagrams, sizeof(*created->entries));
        created->intervals =
            calloc(interval_count, sizeof(*created->intervals));
        created->payloads = malloc(payload_bytes);
    }
    if (created == NULL || created->entries == NULL ||
        created->intervals == NULL || created->payloads == NULL) {
        jg_fragment_tracker_destroy(created);
        return -ENOMEM;
    }
    created->limits = *active_limits;
    initialize_stats(&created->stats);
    *tracker = created;
    return 0;
}

/** @brief Retain one bounded fragment or return a completed payload. */
int jg_fragment_tracker_add(struct jg_fragment_tracker *tracker,
                            const struct jg_packet_view *packet,
                            uint64_t now_ms,
                            uint8_t *output,
                            size_t output_size,
                            size_t *reassembled_size,
                            enum jg_fragment_result *result)
{
    struct fragment_key key;
    struct fragment_entry *entry = NULL;
    const uint8_t *fragment = NULL;
    size_t free_index = SIZE_MAX;
    size_t entry_index = SIZE_MAX;
    size_t fragment_end = 0U;
    enum jg_fragment_result interval_result = JG_FRAGMENT_STORED;

    if (tracker == NULL || packet == NULL || output == NULL ||
        reassembled_size == NULL || result == NULL || !packet->fragmented ||
        packet->frame == NULL ||
        (packet->ip_version != JG_IP_V4 && packet->ip_version != JG_IP_V6) ||
        packet->address_size == 0U ||
        packet->address_size > JG_PACKET_ADDRESS_SIZE ||
        packet->vlan_count > JG_PACKET_VLAN_LIMIT ||
        !jg_range_valid(packet->transport_offset, packet->transport_size,
                        packet->frame_size)) {
        return -EINVAL;
    }
    *reassembled_size = 0U;
    build_key(packet, &key);
    expire_entries(tracker, now_ms);
    entry_index = find_entry(tracker, &key, &free_index);

    if (entry_index != SIZE_MAX && tracker->entries[entry_index].rejected) {
        increment(&tracker->stats.overlaps);
        *result = JG_FRAGMENT_OVERLAP;
        return 0;
    }
    if (packet->transport_size == 0U ||
        (packet->more_fragments && packet->transport_size % 8U != 0U) ||
        !jg_size_add(packet->fragment_offset, packet->transport_size,
                     &fragment_end)) {
        if (entry_index != SIZE_MAX) {
            reject_entry(tracker, entry_index, now_ms);
        }
        increment(&tracker->stats.malformed);
        *result = JG_FRAGMENT_MALFORMED;
        return 0;
    }
    if (fragment_end > tracker->limits.max_bytes_per_datagram) {
        if (entry_index != SIZE_MAX) {
            reject_entry(tracker, entry_index, now_ms);
        }
        increment(&tracker->stats.exhausted);
        *result = JG_FRAGMENT_EXHAUSTED;
        return 0;
    }
    if (entry_index == SIZE_MAX) {
        if (free_index == SIZE_MAX ||
            source_entry_count(tracker, &key) >=
                tracker->limits.max_datagrams_per_source) {
            increment(&tracker->stats.exhausted);
            *result = JG_FRAGMENT_EXHAUSTED;
            return 0;
        }
        entry_index = free_index;
        initialize_entry(tracker, entry_index, &key, now_ms);
    }
    entry = &tracker->entries[entry_index];
    fragment = packet->frame + packet->transport_offset;
    if (entry->has_last && fragment_end > entry->expected_size) {
        reject_entry(tracker, entry_index, now_ms);
        increment(&tracker->stats.overlaps);
        *result = JG_FRAGMENT_OVERLAP;
        return 0;
    }
    if (!packet->more_fragments && entry->has_last &&
        entry->expected_size != fragment_end) {
        reject_entry(tracker, entry_index, now_ms);
        increment(&tracker->stats.overlaps);
        *result = JG_FRAGMENT_OVERLAP;
        return 0;
    }
    interval_result = inspect_intervals(
        tracker, entry_index, packet->fragment_offset, packet->transport_size,
        packet->more_fragments, fragment);
    if (interval_result == JG_FRAGMENT_DUPLICATE) {
        increment(&tracker->stats.duplicates);
        *result = interval_result;
        return 0;
    }
    if (interval_result == JG_FRAGMENT_OVERLAP) {
        reject_entry(tracker, entry_index, now_ms);
        increment(&tracker->stats.overlaps);
        *result = interval_result;
        return 0;
    }
    if (entry->fragment_count >= tracker->limits.max_fragments_per_datagram) {
        reject_entry(tracker, entry_index, now_ms);
        increment(&tracker->stats.exhausted);
        *result = JG_FRAGMENT_EXHAUSTED;
        return 0;
    }

    (void)memcpy(entry_payload(tracker, entry_index) + packet->fragment_offset,
                 fragment, packet->transport_size);
    insert_interval(tracker, entry_index, packet->fragment_offset,
                    packet->transport_size, packet->more_fragments);
    if (!packet->more_fragments) {
        entry->has_last = true;
        entry->expected_size = fragment_end;
    }
    entry->expires_at = expiration_deadline(tracker, now_ms);

    if (!entry_complete(tracker, entry_index)) {
        increment(&tracker->stats.stored);
        *result = JG_FRAGMENT_STORED;
        return 0;
    }
    if (output_size < entry->expected_size) {
        reject_entry(tracker, entry_index, now_ms);
        return -ENOSPC;
    }
    *reassembled_size = entry->expected_size;
    (void)memcpy(output, entry_payload(tracker, entry_index),
                 *reassembled_size);
    clear_entry(tracker, entry_index);
    increment(&tracker->stats.completed);
    *result = JG_FRAGMENT_COMPLETE;
    return 0;
}

/** @brief Copy one relaxed snapshot of fragment-tracker counters. */
int jg_fragment_tracker_get_stats(const struct jg_fragment_tracker *tracker,
                                  struct jg_fragment_stats *stats)
{
    if (tracker == NULL || stats == NULL) {
        return -EINVAL;
    }
    stats->stored =
        atomic_load_explicit(&tracker->stats.stored, memory_order_relaxed);
    stats->duplicates =
        atomic_load_explicit(&tracker->stats.duplicates, memory_order_relaxed);
    stats->completed =
        atomic_load_explicit(&tracker->stats.completed, memory_order_relaxed);
    stats->malformed =
        atomic_load_explicit(&tracker->stats.malformed, memory_order_relaxed);
    stats->overlaps =
        atomic_load_explicit(&tracker->stats.overlaps, memory_order_relaxed);
    stats->exhausted =
        atomic_load_explicit(&tracker->stats.exhausted, memory_order_relaxed);
    stats->timeouts =
        atomic_load_explicit(&tracker->stats.timeouts, memory_order_relaxed);
    return 0;
}

/** @brief Release every fragment arena owned by one stopped tracker. */
void jg_fragment_tracker_destroy(struct jg_fragment_tracker *tracker)
{
    if (tracker == NULL) {
        return;
    }
    free(tracker->payloads);
    free(tracker->intervals);
    free(tracker->entries);
    free(tracker);
}
