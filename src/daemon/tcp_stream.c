/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "tcp_stream.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "janusgate/checked.h"

/** Smallest valid DNS message carried by a TCP length prefix. */
#define DNS_HEADER_SIZE 12U

/** Canonical client-to-server TCP flow identity. */
struct stream_key {
    uint8_t source[JG_PACKET_ADDRESS_SIZE];
    uint8_t destination[JG_PACKET_ADDRESS_SIZE];
    uint16_t vlan_tci[JG_PACKET_VLAN_LIMIT];
    uint16_t source_port;
    uint16_t destination_port;
    size_t address_size;
    size_t vlan_count;
    enum jg_ip_version ip_version;
};

/** Metadata for one active preallocated flow slot. */
struct stream_entry {
    struct stream_key key;
    uint64_t idle_deadline;
    uint64_t connection_deadline;
    uint32_t base_sequence;
    bool rejected;
    bool active;
};

/** Independently readable stream-tracker counters. */
struct atomic_stream_stats {
    atomic_uint_fast64_t buffered;
    atomic_uint_fast64_t duplicates;
    atomic_uint_fast64_t messages;
    atomic_uint_fast64_t closed;
    atomic_uint_fast64_t malformed;
    atomic_uint_fast64_t conflicts;
    atomic_uint_fast64_t exhausted;
    atomic_uint_fast64_t timeouts;
};

/** Complete preallocated per-worker stream state. */
struct jg_tcp_stream_tracker {
    struct jg_tcp_stream_limits limits;
    struct stream_entry *entries;
    uint8_t *buffers;
    uint8_t *present;
    struct atomic_stream_stats stats;
};

/** @brief Increment one relaxed stream counter. */
static void increment(atomic_uint_fast64_t *counter)
{
    (void)atomic_fetch_add_explicit(counter, 1U, memory_order_relaxed);
}

/** @brief Add one bounded value to a relaxed stream counter. */
static void add_count(atomic_uint_fast64_t *counter, size_t value)
{
    (void)atomic_fetch_add_explicit(counter, (uint_fast64_t)value,
                                    memory_order_relaxed);
}

/** @brief Initialize every independently readable tracker counter. */
static void initialize_stats(struct atomic_stream_stats *stats)
{
    atomic_init(&stats->buffered, 0U);
    atomic_init(&stats->duplicates, 0U);
    atomic_init(&stats->messages, 0U);
    atomic_init(&stats->closed, 0U);
    atomic_init(&stats->malformed, 0U);
    atomic_init(&stats->conflicts, 0U);
    atomic_init(&stats->exhausted, 0U);
    atomic_init(&stats->timeouts, 0U);
}

/** @brief Return the fixed byte slice for one flow index. */
static uint8_t *flow_buffer(const struct jg_tcp_stream_tracker *tracker,
                            size_t flow_index)
{
    return tracker->buffers + flow_index * tracker->limits.max_buffered_bytes;
}

/** @brief Return the fixed presence-map slice for one flow index. */
static uint8_t *flow_presence(const struct jg_tcp_stream_tracker *tracker,
                              size_t flow_index)
{
    return tracker->present + flow_index * tracker->limits.max_buffered_bytes;
}

/** @brief Clear one flow while retaining its preallocated arena slices. */
static void clear_flow(struct jg_tcp_stream_tracker *tracker, size_t flow_index)
{
    (void)memset(flow_presence(tracker, flow_index), 0,
                 tracker->limits.max_buffered_bytes);
    (void)memset(&tracker->entries[flow_index], 0, sizeof(tracker->entries[0]));
}

/** @brief Build one canonical key from a validated TCP packet. */
static void build_key(const struct jg_packet_view *packet,
                      struct stream_key *key)
{
    size_t index = 0U;

    (void)memset(key, 0, sizeof(*key));
    (void)memcpy(key->source, packet->source_address, packet->address_size);
    (void)memcpy(key->destination, packet->destination_address,
                 packet->address_size);
    for (index = 0U; index < packet->vlan_count; ++index) {
        key->vlan_tci[index] = packet->vlan_tci[index] & UINT16_C(0x0fff);
    }
    key->source_port = packet->source_port;
    key->destination_port = packet->destination_port;
    key->address_size = packet->address_size;
    key->vlan_count = packet->vlan_count;
    key->ip_version = packet->ip_version;
}

/** @brief Determine whether two canonical stream keys are identical. */
static bool keys_equal(const struct stream_key *left,
                       const struct stream_key *right)
{
    return left->source_port == right->source_port &&
           left->destination_port == right->destination_port &&
           left->address_size == right->address_size &&
           left->vlan_count == right->vlan_count &&
           left->ip_version == right->ip_version &&
           memcmp(left->source, right->source, left->address_size) == 0 &&
           memcmp(left->destination, right->destination, left->address_size) ==
               0 &&
           memcmp(left->vlan_tci, right->vlan_tci,
                  left->vlan_count * sizeof(left->vlan_tci[0])) == 0;
}

/** @brief Determine whether two keys share one source identity. */
static bool sources_equal(const struct stream_key *left,
                          const struct stream_key *right)
{
    return left->ip_version == right->ip_version &&
           left->address_size == right->address_size &&
           memcmp(left->source, right->source, left->address_size) == 0;
}

/** @brief Return one saturated deadline relative to monotonic time. */
static uint64_t deadline(uint64_t now_ms, uint64_t duration_ms)
{
    return now_ms > UINT64_MAX - duration_ms ? UINT64_MAX
                                             : now_ms + duration_ms;
}

/** @brief Expire idle or over-age stream entries. */
static void expire_flows(struct jg_tcp_stream_tracker *tracker, uint64_t now_ms)
{
    size_t index = 0U;

    for (index = 0U; index < tracker->limits.max_flows; ++index) {
        if (tracker->entries[index].active &&
            (tracker->entries[index].idle_deadline <= now_ms ||
             tracker->entries[index].connection_deadline <= now_ms)) {
            const bool rejected = tracker->entries[index].rejected;

            clear_flow(tracker, index);
            if (!rejected) {
                increment(&tracker->stats.timeouts);
            }
        }
    }
}

/** @brief Find an existing flow key and the first free slot. */
static size_t find_flow(const struct jg_tcp_stream_tracker *tracker,
                        const struct stream_key *key,
                        size_t *free_index)
{
    size_t index = 0U;

    *free_index = SIZE_MAX;
    for (index = 0U; index < tracker->limits.max_flows; ++index) {
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

/** @brief Count active flow slots associated with one source address. */
static size_t source_flow_count(const struct jg_tcp_stream_tracker *tracker,
                                const struct stream_key *key)
{
    size_t count = 0U;
    size_t index = 0U;

    for (index = 0U; index < tracker->limits.max_flows; ++index) {
        if (tracker->entries[index].active &&
            sources_equal(&tracker->entries[index].key, key)) {
            ++count;
        }
    }
    return count;
}

/** @brief Initialize one active flow in a known free slot. */
static void initialize_flow(struct jg_tcp_stream_tracker *tracker,
                            size_t flow_index,
                            const struct stream_key *key,
                            uint32_t base_sequence,
                            uint64_t now_ms)
{
    struct stream_entry *entry = &tracker->entries[flow_index];

    entry->key = *key;
    entry->idle_deadline = deadline(now_ms, tracker->limits.idle_timeout_ms);
    entry->connection_deadline =
        deadline(now_ms, tracker->limits.connection_timeout_ms);
    entry->base_sequence = base_sequence;
    entry->active = true;
}

/** @brief Reject one flow key until a fresh idle timeout expires. */
static void reject_flow(struct jg_tcp_stream_tracker *tracker,
                        size_t flow_index,
                        uint64_t now_ms)
{
    const struct stream_key key = tracker->entries[flow_index].key;
    const uint32_t base_sequence = tracker->entries[flow_index].base_sequence;

    clear_flow(tracker, flow_index);
    initialize_flow(tracker, flow_index, &key, base_sequence, now_ms);
    tracker->entries[flow_index].rejected = true;
}

/** @brief Count disjoint received byte ranges in one flow window. */
static size_t range_count(const struct jg_tcp_stream_tracker *tracker,
                          size_t flow_index)
{
    const uint8_t *present = flow_presence(tracker, flow_index);
    size_t count = 0U;
    size_t index = 0U;
    bool inside = false;

    for (index = 0U; index < tracker->limits.max_buffered_bytes; ++index) {
        if (present[index] != 0U && !inside) {
            ++count;
            inside = true;
        } else if (present[index] == 0U) {
            inside = false;
        }
    }
    return count;
}

/** @brief Count contiguous bytes beginning at the current stream base. */
static size_t contiguous_size(const struct jg_tcp_stream_tracker *tracker,
                              size_t flow_index)
{
    const uint8_t *present = flow_presence(tracker, flow_index);
    size_t size = 0U;

    while (size < tracker->limits.max_buffered_bytes && present[size] != 0U) {
        ++size;
    }
    return size;
}

/** @brief Determine whether any byte remains buffered for one flow. */
static bool flow_has_bytes(const struct jg_tcp_stream_tracker *tracker,
                           size_t flow_index)
{
    const uint8_t *present = flow_presence(tracker, flow_index);
    size_t index = 0U;

    for (index = 0U; index < tracker->limits.max_buffered_bytes; ++index) {
        if (present[index] != 0U) {
            return true;
        }
    }
    return false;
}

/** @brief Consume a contiguous stream prefix and compact the receive window. */
static void consume_prefix(struct jg_tcp_stream_tracker *tracker,
                           size_t flow_index,
                           size_t consumed)
{
    struct stream_entry *entry = &tracker->entries[flow_index];
    uint8_t *buffer = flow_buffer(tracker, flow_index);
    uint8_t *present = flow_presence(tracker, flow_index);
    const size_t remaining = tracker->limits.max_buffered_bytes - consumed;

    (void)memmove(buffer, buffer + consumed, remaining);
    (void)memmove(present, present + consumed, remaining);
    (void)memset(buffer + remaining, 0, consumed);
    (void)memset(present + remaining, 0, consumed);
    entry->base_sequence += (uint32_t)consumed;
}

/** @brief Insert non-conflicting payload bytes into one receive window. */
static enum jg_tcp_stream_result insert_payload(
    const struct jg_tcp_stream_tracker *tracker,
    size_t flow_index,
    size_t offset,
    const uint8_t *payload,
    size_t payload_size,
    bool *changed)
{
    uint8_t *buffer = flow_buffer(tracker, flow_index);
    uint8_t *present = flow_presence(tracker, flow_index);
    size_t index = 0U;

    *changed = false;
    for (index = 0U; index < payload_size; ++index) {
        if (present[offset + index] != 0U) {
            if (buffer[offset + index] != payload[index]) {
                return JG_TCP_STREAM_CONFLICT;
            }
        } else {
            buffer[offset + index] = payload[index];
            present[offset + index] = 1U;
            *changed = true;
        }
    }
    return *changed ? JG_TCP_STREAM_BUFFERED : JG_TCP_STREAM_DUPLICATE;
}

/** @brief Emit complete length-prefixed DNS messages from one stream prefix. */
static enum jg_tcp_stream_result emit_messages(
    const struct jg_tcp_stream_tracker *tracker,
    size_t flow_index,
    uint8_t *output,
    struct jg_tcp_stream_message *messages,
    size_t *message_count,
    size_t *consumed)
{
    const uint8_t *buffer = flow_buffer(tracker, flow_index);
    const size_t contiguous = contiguous_size(tracker, flow_index);
    size_t output_offset = 0U;
    size_t cursor = 0U;
    size_t count = 0U;

    while (contiguous - cursor >= 2U) {
        const size_t message_size =
            ((size_t)buffer[cursor] << 8U) | (size_t)buffer[cursor + 1U];
        size_t framed_size = 0U;

        if (message_size < DNS_HEADER_SIZE ||
            message_size > tracker->limits.max_dns_message_size) {
            return JG_TCP_STREAM_MALFORMED;
        }
        framed_size = message_size + 2U;
        if (framed_size > contiguous - cursor) {
            break;
        }
        if (count >= tracker->limits.max_messages_per_packet) {
            return JG_TCP_STREAM_EXHAUSTED;
        }
        messages[count].offset = output_offset;
        messages[count].size = message_size;
        (void)memcpy(output + output_offset, buffer + cursor + 2U,
                     message_size);
        output_offset += message_size;
        cursor += framed_size;
        ++count;
    }
    *message_count = count;
    *consumed = cursor;
    return count == 0U ? JG_TCP_STREAM_BUFFERED : JG_TCP_STREAM_MESSAGES;
}

/** @brief Validate metadata for one selected client-to-server TCP flow. */
static bool packet_valid_for_port(const struct jg_packet_view *packet,
                                  uint16_t destination_port)
{
    return packet != NULL && packet->frame != NULL && !packet->fragmented &&
           packet->transport == JG_TRANSPORT_TCP &&
           packet->ip_protocol == (uint8_t)JG_TRANSPORT_TCP &&
           packet->destination_port == destination_port &&
           (packet->ip_version == JG_IP_V4 || packet->ip_version == JG_IP_V6) &&
           packet->address_size != 0U &&
           packet->address_size <= JG_PACKET_ADDRESS_SIZE &&
           packet->vlan_count <= JG_PACKET_VLAN_LIMIT &&
           jg_range_valid(packet->payload_offset, packet->payload_size,
                          packet->frame_size);
}

/** @brief Initialize conservative stream-tracker limits. */
void jg_tcp_stream_limits_default(struct jg_tcp_stream_limits *limits)
{
    if (limits == NULL) {
        return;
    }
    limits->max_flows = 128U;
    limits->max_flows_per_source = 16U;
    limits->max_buffered_bytes = 16384U;
    limits->max_out_of_order_segments = 32U;
    limits->max_dns_message_size = 4096U;
    limits->max_messages_per_packet = 32U;
    limits->idle_timeout_ms = 30000U;
    limits->connection_timeout_ms = 300000U;
}

/** @brief Validate every stream memory and lifetime bound. */
int jg_tcp_stream_limits_validate(const struct jg_tcp_stream_limits *limits)
{
    if (limits == NULL || limits->max_flows == 0U ||
        limits->max_flows_per_source == 0U ||
        limits->max_buffered_bytes == 0U ||
        limits->max_out_of_order_segments == 0U ||
        limits->max_dns_message_size == 0U ||
        limits->max_messages_per_packet == 0U ||
        limits->idle_timeout_ms == 0U || limits->connection_timeout_ms == 0U) {
        return -EINVAL;
    }
    if (limits->max_flows > JG_TCP_STREAM_FLOW_LIMIT ||
        limits->max_flows_per_source > limits->max_flows ||
        limits->max_buffered_bytes > JG_TCP_STREAM_BYTES_LIMIT ||
        limits->max_out_of_order_segments > JG_TCP_STREAM_SEGMENT_LIMIT ||
        limits->max_out_of_order_segments > limits->max_buffered_bytes ||
        limits->max_dns_message_size > JG_TCP_STREAM_DNS_LIMIT ||
        limits->max_dns_message_size + 2U > limits->max_buffered_bytes ||
        limits->max_messages_per_packet > JG_TCP_STREAM_MESSAGE_LIMIT ||
        limits->idle_timeout_ms > JG_TCP_STREAM_TIMEOUT_LIMIT ||
        limits->connection_timeout_ms > JG_TCP_STREAM_TIMEOUT_LIMIT ||
        limits->idle_timeout_ms > limits->connection_timeout_ms) {
        return -ERANGE;
    }
    return 0;
}

/** @brief Create one fully preallocated per-worker stream tracker. */
int jg_tcp_stream_tracker_create(const struct jg_tcp_stream_limits *limits,
                                 struct jg_tcp_stream_tracker **tracker)
{
    struct jg_tcp_stream_limits defaults;
    const struct jg_tcp_stream_limits *active_limits = limits;
    struct jg_tcp_stream_tracker *created = NULL;
    size_t arena_size = 0U;
    int result = 0;

    if (tracker == NULL) {
        return -EINVAL;
    }
    *tracker = NULL;
    if (active_limits == NULL) {
        jg_tcp_stream_limits_default(&defaults);
        active_limits = &defaults;
    }
    result = jg_tcp_stream_limits_validate(active_limits);
    if (result != 0) {
        return result;
    }
    if (!jg_size_multiply(active_limits->max_flows,
                          active_limits->max_buffered_bytes, &arena_size)) {
        return -EOVERFLOW;
    }

    created = calloc(1U, sizeof(*created));
    if (created != NULL) {
        created->entries =
            calloc(active_limits->max_flows, sizeof(*created->entries));
        created->buffers = calloc(arena_size, 1U);
        created->present = calloc(arena_size, 1U);
    }
    if (created == NULL || created->entries == NULL ||
        created->buffers == NULL || created->present == NULL) {
        jg_tcp_stream_tracker_destroy(created);
        return -ENOMEM;
    }
    created->limits = *active_limits;
    initialize_stats(&created->stats);
    *tracker = created;
    return 0;
}

/** @brief Add one bounded TCP segment and emit complete DNS messages. */
int jg_tcp_stream_tracker_add(struct jg_tcp_stream_tracker *tracker,
                              const struct jg_packet_view *packet,
                              uint64_t now_ms,
                              uint8_t *output,
                              size_t output_size,
                              struct jg_tcp_stream_message *messages,
                              size_t message_capacity,
                              size_t *message_count,
                              enum jg_tcp_stream_result *result)
{
    struct stream_key key;
    struct stream_entry *entry = NULL;
    const uint8_t *payload = NULL;
    uint32_t payload_sequence = 0U;
    uint32_t distance = 0U;
    size_t free_index = SIZE_MAX;
    size_t flow_index = SIZE_MAX;
    size_t payload_offset = 0U;
    size_t payload_size = 0U;
    size_t consumed = 0U;
    enum jg_tcp_stream_result operation = JG_TCP_STREAM_BUFFERED;
    bool changed = false;
    bool syn = false;
    bool fin = false;
    bool rst = false;

    if (tracker == NULL || output == NULL || messages == NULL ||
        message_count == NULL || result == NULL ||
        !packet_valid_for_port(packet, 53U)) {
        return -EINVAL;
    }
    syn = (packet->tcp_flags & JG_TCP_FLAG_SYN) != 0U;
    fin = (packet->tcp_flags & JG_TCP_FLAG_FIN) != 0U;
    rst = (packet->tcp_flags & JG_TCP_FLAG_RST) != 0U;
    *message_count = 0U;
    if (output_size < tracker->limits.max_buffered_bytes ||
        message_capacity < tracker->limits.max_messages_per_packet) {
        return -ENOSPC;
    }

    build_key(packet, &key);
    expire_flows(tracker, now_ms);
    flow_index = find_flow(tracker, &key, &free_index);
    if (rst) {
        if (flow_index != SIZE_MAX) {
            clear_flow(tracker, flow_index);
        }
        increment(&tracker->stats.closed);
        *result = JG_TCP_STREAM_CLOSED;
        return 0;
    }
    payload_sequence = packet->tcp_sequence + (syn ? 1U : 0U);
    if (syn && flow_index != SIZE_MAX) {
        clear_flow(tracker, flow_index);
        free_index = flow_index;
        flow_index = SIZE_MAX;
    }
    if (flow_index != SIZE_MAX && tracker->entries[flow_index].rejected) {
        increment(&tracker->stats.conflicts);
        *result = JG_TCP_STREAM_CONFLICT;
        return 0;
    }
    if (flow_index == SIZE_MAX && (packet->payload_size != 0U || syn)) {
        if (free_index == SIZE_MAX ||
            source_flow_count(tracker, &key) >=
                tracker->limits.max_flows_per_source) {
            increment(&tracker->stats.exhausted);
            *result = JG_TCP_STREAM_EXHAUSTED;
            return 0;
        }
        flow_index = free_index;
        initialize_flow(tracker, flow_index, &key, payload_sequence, now_ms);
    }
    if (flow_index == SIZE_MAX) {
        if (fin) {
            increment(&tracker->stats.closed);
            *result = JG_TCP_STREAM_CLOSED;
        } else {
            increment(&tracker->stats.duplicates);
            *result = JG_TCP_STREAM_DUPLICATE;
        }
        return 0;
    }
    entry = &tracker->entries[flow_index];
    entry->idle_deadline = deadline(now_ms, tracker->limits.idle_timeout_ms);
    if (packet->payload_size == 0U) {
        if (fin) {
            if (flow_has_bytes(tracker, flow_index)) {
                reject_flow(tracker, flow_index, now_ms);
            } else {
                clear_flow(tracker, flow_index);
            }
            increment(&tracker->stats.closed);
            *result = JG_TCP_STREAM_CLOSED;
        } else {
            *result = JG_TCP_STREAM_BUFFERED;
        }
        return 0;
    }

    payload = packet->frame + packet->payload_offset;
    payload_size = packet->payload_size;
    distance = payload_sequence - entry->base_sequence;
    if (distance <= UINT32_C(0x7fffffff)) {
        payload_offset = (size_t)distance;
    } else {
        const uint32_t consumed_prefix =
            entry->base_sequence - payload_sequence;

        if ((size_t)consumed_prefix >= payload_size) {
            if (fin) {
                if (flow_has_bytes(tracker, flow_index)) {
                    reject_flow(tracker, flow_index, now_ms);
                } else {
                    clear_flow(tracker, flow_index);
                }
                increment(&tracker->stats.closed);
                *result = JG_TCP_STREAM_CLOSED;
            } else {
                increment(&tracker->stats.duplicates);
                *result = JG_TCP_STREAM_DUPLICATE;
            }
            return 0;
        }
        payload += consumed_prefix;
        payload_size -= consumed_prefix;
    }
    if (!jg_range_valid(payload_offset, payload_size,
                        tracker->limits.max_buffered_bytes)) {
        reject_flow(tracker, flow_index, now_ms);
        increment(&tracker->stats.exhausted);
        *result = JG_TCP_STREAM_EXHAUSTED;
        return 0;
    }

    operation = insert_payload(tracker, flow_index, payload_offset, payload,
                               payload_size, &changed);
    if (operation == JG_TCP_STREAM_CONFLICT) {
        reject_flow(tracker, flow_index, now_ms);
        increment(&tracker->stats.conflicts);
        *result = operation;
        return 0;
    }
    if (range_count(tracker, flow_index) >
        tracker->limits.max_out_of_order_segments) {
        reject_flow(tracker, flow_index, now_ms);
        increment(&tracker->stats.exhausted);
        *result = JG_TCP_STREAM_EXHAUSTED;
        return 0;
    }
    operation = emit_messages(tracker, flow_index, output, messages,
                              message_count, &consumed);
    if (operation == JG_TCP_STREAM_MALFORMED) {
        reject_flow(tracker, flow_index, now_ms);
        increment(&tracker->stats.malformed);
        *result = operation;
        return 0;
    }
    if (operation == JG_TCP_STREAM_EXHAUSTED) {
        reject_flow(tracker, flow_index, now_ms);
        increment(&tracker->stats.exhausted);
        *result = operation;
        return 0;
    }
    if (operation == JG_TCP_STREAM_MESSAGES) {
        consume_prefix(tracker, flow_index, consumed);
        add_count(&tracker->stats.messages, *message_count);
    } else if (changed) {
        increment(&tracker->stats.buffered);
    } else {
        increment(&tracker->stats.duplicates);
        operation = JG_TCP_STREAM_DUPLICATE;
    }
    if (fin) {
        if (flow_has_bytes(tracker, flow_index)) {
            reject_flow(tracker, flow_index, now_ms);
        } else {
            clear_flow(tracker, flow_index);
        }
        increment(&tracker->stats.closed);
        if (operation != JG_TCP_STREAM_MESSAGES) {
            operation = JG_TCP_STREAM_CLOSED;
        }
    }
    *result = operation;
    return 0;
}

/** @brief Reconstruct generic ordered bytes for TLS protocol parsing. */
int jg_tcp_stream_tracker_add_raw(struct jg_tcp_stream_tracker *tracker,
                                  const struct jg_packet_view *packet,
                                  uint64_t now_ms,
                                  uint8_t *output,
                                  size_t output_size,
                                  struct jg_tcp_raw_stream_chunk *chunk,
                                  enum jg_tcp_raw_stream_result *result)
{
    struct stream_key key;
    struct stream_entry *entry = NULL;
    const uint8_t *payload = NULL;
    uint32_t payload_sequence = 0U;
    uint32_t distance = 0U;
    size_t free_index = SIZE_MAX;
    size_t flow_index = SIZE_MAX;
    size_t payload_offset = 0U;
    size_t payload_size = 0U;
    size_t contiguous = 0U;
    enum jg_tcp_stream_result insertion = JG_TCP_STREAM_BUFFERED;
    bool changed = false;
    bool syn = false;
    bool fin = false;
    bool rst = false;

    if (tracker == NULL || output == NULL || chunk == NULL || result == NULL ||
        !(packet_valid_for_port(packet, 443U) ||
          packet_valid_for_port(packet, 853U))) {
        return -EINVAL;
    }
    syn = (packet->tcp_flags & JG_TCP_FLAG_SYN) != 0U;
    fin = (packet->tcp_flags & JG_TCP_FLAG_FIN) != 0U;
    rst = (packet->tcp_flags & JG_TCP_FLAG_RST) != 0U;
    *chunk = (struct jg_tcp_raw_stream_chunk){
        .flow_index = SIZE_MAX,
    };
    if (output_size < tracker->limits.max_buffered_bytes) {
        return -ENOSPC;
    }

    build_key(packet, &key);
    expire_flows(tracker, now_ms);
    flow_index = find_flow(tracker, &key, &free_index);
    if (rst) {
        if (flow_index != SIZE_MAX) {
            chunk->flow_index = flow_index;
            clear_flow(tracker, flow_index);
        }
        increment(&tracker->stats.closed);
        *result = JG_TCP_RAW_STREAM_CLOSED;
        return 0;
    }
    payload_sequence = packet->tcp_sequence + (syn ? 1U : 0U);
    if (syn && flow_index != SIZE_MAX) {
        clear_flow(tracker, flow_index);
        free_index = flow_index;
        flow_index = SIZE_MAX;
    }
    if (flow_index != SIZE_MAX && tracker->entries[flow_index].rejected) {
        increment(&tracker->stats.conflicts);
        *result = JG_TCP_RAW_STREAM_CONFLICT;
        return 0;
    }
    if (flow_index == SIZE_MAX && (packet->payload_size != 0U || syn)) {
        if (free_index == SIZE_MAX ||
            source_flow_count(tracker, &key) >=
                tracker->limits.max_flows_per_source) {
            increment(&tracker->stats.exhausted);
            *result = JG_TCP_RAW_STREAM_EXHAUSTED;
            return 0;
        }
        flow_index = free_index;
        initialize_flow(tracker, flow_index, &key, payload_sequence, now_ms);
        chunk->new_flow = true;
    }
    if (flow_index == SIZE_MAX) {
        if (fin) {
            increment(&tracker->stats.closed);
            *result = JG_TCP_RAW_STREAM_CLOSED;
        } else {
            increment(&tracker->stats.duplicates);
            *result = JG_TCP_RAW_STREAM_DUPLICATE;
        }
        return 0;
    }

    chunk->flow_index = flow_index;
    entry = &tracker->entries[flow_index];
    entry->idle_deadline = deadline(now_ms, tracker->limits.idle_timeout_ms);
    if (packet->payload_size == 0U) {
        if (fin) {
            if (flow_has_bytes(tracker, flow_index)) {
                reject_flow(tracker, flow_index, now_ms);
            } else {
                clear_flow(tracker, flow_index);
            }
            chunk->closed = true;
            increment(&tracker->stats.closed);
            *result = JG_TCP_RAW_STREAM_CLOSED;
        } else {
            *result = JG_TCP_RAW_STREAM_BUFFERED;
        }
        return 0;
    }

    payload = packet->frame + packet->payload_offset;
    payload_size = packet->payload_size;
    distance = payload_sequence - entry->base_sequence;
    if (distance <= UINT32_C(0x7fffffff)) {
        payload_offset = (size_t)distance;
    } else {
        const uint32_t consumed_prefix =
            entry->base_sequence - payload_sequence;

        if ((size_t)consumed_prefix >= payload_size) {
            if (fin) {
                if (flow_has_bytes(tracker, flow_index)) {
                    reject_flow(tracker, flow_index, now_ms);
                } else {
                    clear_flow(tracker, flow_index);
                }
                chunk->closed = true;
                increment(&tracker->stats.closed);
                *result = JG_TCP_RAW_STREAM_CLOSED;
            } else {
                increment(&tracker->stats.duplicates);
                *result = JG_TCP_RAW_STREAM_DUPLICATE;
            }
            return 0;
        }
        payload += consumed_prefix;
        payload_size -= consumed_prefix;
    }
    if (!jg_range_valid(payload_offset, payload_size,
                        tracker->limits.max_buffered_bytes)) {
        reject_flow(tracker, flow_index, now_ms);
        increment(&tracker->stats.exhausted);
        *result = JG_TCP_RAW_STREAM_EXHAUSTED;
        return 0;
    }

    insertion = insert_payload(tracker, flow_index, payload_offset, payload,
                               payload_size, &changed);
    if (insertion == JG_TCP_STREAM_CONFLICT) {
        reject_flow(tracker, flow_index, now_ms);
        increment(&tracker->stats.conflicts);
        *result = JG_TCP_RAW_STREAM_CONFLICT;
        return 0;
    }
    if (range_count(tracker, flow_index) >
        tracker->limits.max_out_of_order_segments) {
        reject_flow(tracker, flow_index, now_ms);
        increment(&tracker->stats.exhausted);
        *result = JG_TCP_RAW_STREAM_EXHAUSTED;
        return 0;
    }

    contiguous = contiguous_size(tracker, flow_index);
    if (contiguous > 0U) {
        (void)memcpy(output, flow_buffer(tracker, flow_index), contiguous);
        consume_prefix(tracker, flow_index, contiguous);
        chunk->size = contiguous;
        add_count(&tracker->stats.messages, contiguous);
        *result = JG_TCP_RAW_STREAM_BYTES;
    } else if (changed) {
        increment(&tracker->stats.buffered);
        *result = JG_TCP_RAW_STREAM_BUFFERED;
    } else {
        increment(&tracker->stats.duplicates);
        *result = JG_TCP_RAW_STREAM_DUPLICATE;
    }
    if (fin) {
        if (flow_has_bytes(tracker, flow_index)) {
            reject_flow(tracker, flow_index, now_ms);
        } else {
            clear_flow(tracker, flow_index);
        }
        chunk->closed = true;
        increment(&tracker->stats.closed);
        if (*result != JG_TCP_RAW_STREAM_BYTES) {
            *result = JG_TCP_RAW_STREAM_CLOSED;
        }
    }
    return 0;
}

/** @brief Replace one existing flow with a compact rejection entry. */
int jg_tcp_stream_tracker_reject_flow(struct jg_tcp_stream_tracker *tracker,
                                      const struct jg_packet_view *packet,
                                      uint64_t now_ms)
{
    struct stream_key key;
    size_t free_index = SIZE_MAX;
    size_t flow_index = SIZE_MAX;

    if (tracker == NULL || !(packet_valid_for_port(packet, 53U) ||
                             packet_valid_for_port(packet, 443U) ||
                             packet_valid_for_port(packet, 853U))) {
        return -EINVAL;
    }
    build_key(packet, &key);
    expire_flows(tracker, now_ms);
    flow_index = find_flow(tracker, &key, &free_index);
    if (flow_index == SIZE_MAX) {
        if (free_index == SIZE_MAX ||
            source_flow_count(tracker, &key) >=
                tracker->limits.max_flows_per_source) {
            return -ENOSPC;
        }
        flow_index = free_index;
        initialize_flow(tracker, flow_index, &key, packet->tcp_sequence,
                        now_ms);
    }
    reject_flow(tracker, flow_index, now_ms);
    return 0;
}

/** @brief Copy one relaxed snapshot of stream-tracker counters. */
int jg_tcp_stream_tracker_get_stats(const struct jg_tcp_stream_tracker *tracker,
                                    struct jg_tcp_stream_stats *stats)
{
    if (tracker == NULL || stats == NULL) {
        return -EINVAL;
    }
    stats->buffered =
        atomic_load_explicit(&tracker->stats.buffered, memory_order_relaxed);
    stats->duplicates =
        atomic_load_explicit(&tracker->stats.duplicates, memory_order_relaxed);
    stats->messages =
        atomic_load_explicit(&tracker->stats.messages, memory_order_relaxed);
    stats->closed =
        atomic_load_explicit(&tracker->stats.closed, memory_order_relaxed);
    stats->malformed =
        atomic_load_explicit(&tracker->stats.malformed, memory_order_relaxed);
    stats->conflicts =
        atomic_load_explicit(&tracker->stats.conflicts, memory_order_relaxed);
    stats->exhausted =
        atomic_load_explicit(&tracker->stats.exhausted, memory_order_relaxed);
    stats->timeouts =
        atomic_load_explicit(&tracker->stats.timeouts, memory_order_relaxed);
    return 0;
}

/** @brief Release every stream arena owned by one stopped tracker. */
void jg_tcp_stream_tracker_destroy(struct jg_tcp_stream_tracker *tracker)
{
    if (tracker == NULL) {
        return;
    }
    free(tracker->present);
    free(tracker->buffers);
    free(tracker->entries);
    free(tracker);
}
