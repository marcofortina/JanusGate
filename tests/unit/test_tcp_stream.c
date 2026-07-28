/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>

#include <cmocka.h>

#include "tcp_stream.h"

int jg_test_tcp_stream(void);

/** First minimal DNS query body used by stream framing tests. */
static const uint8_t dns_message_a[12U] = {
    0x12U, 0x34U, 0x01U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
};

/** Second minimal DNS query body used by stream framing tests. */
static const uint8_t dns_message_b[12U] = {
    0x56U, 0x78U, 0x01U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
};

/** Stable non-null storage for TCP packets without application bytes. */
static const uint8_t empty_payload = 0U;

/** @brief Append one two-byte length prefix and DNS message body. */
static size_t append_message(uint8_t *stream,
                             size_t offset,
                             const uint8_t *message,
                             size_t message_size)
{
    stream[offset] = (uint8_t)(message_size >> 8U);
    stream[offset + 1U] = (uint8_t)message_size;
    (void)memcpy(stream + offset + 2U, message, message_size);
    return offset + 2U + message_size;
}

/** @brief Build one direct parsed TCP view over caller-owned payload bytes. */
static struct jg_packet_view tcp_view(const uint8_t *payload,
                                      size_t payload_size,
                                      uint32_t sequence,
                                      uint8_t flags,
                                      uint16_t source_port)
{
    struct jg_packet_view packet = {
        .frame = payload,
        .frame_size = payload_size,
        .ip_version = JG_IP_V4,
        .source_address = {192U, 0U, 2U, 10U},
        .destination_address = {192U, 0U, 2U, 53U},
        .address_size = 4U,
        .ip_protocol = (uint8_t)JG_TRANSPORT_TCP,
        .transport = JG_TRANSPORT_TCP,
        .source_port = source_port,
        .destination_port = 53U,
        .tcp_sequence = sequence,
        .tcp_flags = flags,
        .payload_offset = 0U,
        .payload_size = payload_size,
        .transport_complete = true,
    };

    return packet;
}

/** @brief Create one small deterministic stream tracker for unit tests. */
static struct jg_tcp_stream_tracker *create_tracker(size_t out_of_order_limit)
{
    const struct jg_tcp_stream_limits limits = {
        .max_flows = 2U,
        .max_flows_per_source = 2U,
        .max_buffered_bytes = 64U,
        .max_out_of_order_segments = out_of_order_limit,
        .max_dns_message_size = 32U,
        .max_messages_per_packet = 4U,
        .idle_timeout_ms = 1000U,
        .connection_timeout_ms = 5000U,
    };
    struct jg_tcp_stream_tracker *tracker = NULL;

    assert_int_equal(jg_tcp_stream_tracker_create(&limits, &tracker), 0);
    return tracker;
}

/** @brief Add one packet using the standard unit-test output arenas. */
static enum jg_tcp_stream_result add_packet(
    struct jg_tcp_stream_tracker *tracker,
    const struct jg_packet_view *packet,
    uint64_t now_ms,
    uint8_t *output,
    struct jg_tcp_stream_message *messages,
    size_t *message_count)
{
    enum jg_tcp_stream_result result = JG_TCP_STREAM_MALFORMED;

    assert_int_equal(jg_tcp_stream_tracker_add(tracker, packet, now_ms, output,
                                               64U, messages, 4U, message_count,
                                               &result),
                     0);
    return result;
}

/** @brief Add one packet through generic ordered-byte reconstruction. */
static enum jg_tcp_raw_stream_result add_raw_packet(
    struct jg_tcp_stream_tracker *tracker,
    const struct jg_packet_view *packet,
    uint64_t now_ms,
    uint8_t *output,
    struct jg_tcp_raw_stream_chunk *chunk)
{
    enum jg_tcp_raw_stream_result result = JG_TCP_RAW_STREAM_EXHAUSTED;

    assert_int_equal(jg_tcp_stream_tracker_add_raw(tracker, packet, now_ms,
                                                   output, 64U, chunk, &result),
                     0);
    return result;
}

/** @brief Verify partial framing, message batches, and blocked retransmission.
 */
static void test_message_reassembly(void **state)
{
    uint8_t stream[28U];
    uint8_t output[64U];
    struct jg_tcp_stream_message messages[4U];
    struct jg_tcp_stream_tracker *tracker = create_tracker(4U);
    struct jg_packet_view packet =
        tcp_view(&empty_payload, 0U, 100U, JG_TCP_FLAG_SYN, 12000U);
    struct jg_tcp_stream_stats stats;
    size_t message_count = 0U;
    size_t stream_size = 0U;

    (void)state;
    stream_size = append_message(stream, stream_size, dns_message_a,
                                 sizeof(dns_message_a));
    stream_size = append_message(stream, stream_size, dns_message_b,
                                 sizeof(dns_message_b));
    assert_int_equal(stream_size, sizeof(stream));
    assert_int_equal(
        add_packet(tracker, &packet, 100U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);

    packet = tcp_view(stream, 1U, 101U, 0U, 12000U);
    assert_int_equal(
        add_packet(tracker, &packet, 101U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    packet = tcp_view(stream + 1U, sizeof(stream) - 1U, 102U, 0U, 12000U);
    assert_int_equal(
        add_packet(tracker, &packet, 102U, output, messages, &message_count),
        JG_TCP_STREAM_MESSAGES);
    assert_int_equal(message_count, 2U);
    assert_int_equal(messages[0U].offset, 0U);
    assert_int_equal(messages[0U].size, sizeof(dns_message_a));
    assert_memory_equal(output + messages[0U].offset, dns_message_a,
                        sizeof(dns_message_a));
    assert_int_equal(messages[1U].offset, sizeof(dns_message_a));
    assert_memory_equal(output + messages[1U].offset, dns_message_b,
                        sizeof(dns_message_b));

    assert_int_equal(jg_tcp_stream_tracker_reject_flow(tracker, &packet, 103U),
                     0);
    packet = tcp_view(stream, sizeof(stream), 101U, 0U, 12000U);
    assert_int_equal(
        add_packet(tracker, &packet, 104U, output, messages, &message_count),
        JG_TCP_STREAM_CONFLICT);
    assert_int_equal(jg_tcp_stream_tracker_get_stats(tracker, &stats), 0);
    assert_int_equal(stats.buffered, 1U);
    assert_int_equal(stats.messages, 2U);
    assert_int_equal(stats.conflicts, 1U);
    jg_tcp_stream_tracker_destroy(tracker);
}

/** @brief Verify out-of-order reconstruction across TCP sequence wraparound. */
static void test_out_of_order_wraparound(void **state)
{
    uint8_t stream[14U];
    uint8_t output[64U];
    struct jg_tcp_stream_message messages[4U];
    struct jg_tcp_stream_tracker *tracker = create_tracker(4U);
    const uint32_t syn_sequence = UINT32_MAX - 5U;
    const uint32_t base_sequence = syn_sequence + 1U;
    struct jg_packet_view packet =
        tcp_view(&empty_payload, 0U, syn_sequence, JG_TCP_FLAG_SYN, 12001U);
    size_t message_count = 0U;

    (void)state;
    assert_int_equal(
        append_message(stream, 0U, dns_message_a, sizeof(dns_message_a)),
        sizeof(stream));
    assert_int_equal(
        add_packet(tracker, &packet, 100U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);

    packet = tcp_view(stream + 7U, 7U, base_sequence + 7U, 0U, 12001U);
    assert_int_equal(
        add_packet(tracker, &packet, 101U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    packet = tcp_view(stream, 7U, base_sequence, 0U, 12001U);
    assert_int_equal(
        add_packet(tracker, &packet, 102U, output, messages, &message_count),
        JG_TCP_STREAM_MESSAGES);
    assert_int_equal(message_count, 1U);
    assert_memory_equal(output, dns_message_a, sizeof(dns_message_a));

    packet = tcp_view(stream, sizeof(stream), base_sequence, 0U, 12001U);
    assert_int_equal(
        add_packet(tracker, &packet, 103U, output, messages, &message_count),
        JG_TCP_STREAM_DUPLICATE);
    jg_tcp_stream_tracker_destroy(tracker);
}

/** @brief Verify conflicting retransmissions and invalid DNS framing. */
static void test_rejections(void **state)
{
    uint8_t stream[14U];
    uint8_t conflict[7U];
    uint8_t output[64U];
    static const uint8_t oversized_prefix[2U] = {0U, 33U};
    struct jg_tcp_stream_message messages[4U];
    struct jg_tcp_stream_tracker *tracker = create_tracker(4U);
    struct jg_packet_view packet =
        tcp_view(&empty_payload, 0U, 200U, JG_TCP_FLAG_SYN, 12002U);
    size_t message_count = 0U;

    (void)state;
    (void)append_message(stream, 0U, dns_message_a, sizeof(dns_message_a));
    assert_int_equal(
        add_packet(tracker, &packet, 100U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    packet = tcp_view(stream, 7U, 201U, 0U, 12002U);
    assert_int_equal(
        add_packet(tracker, &packet, 101U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    (void)memcpy(conflict, stream, sizeof(conflict));
    conflict[6U] ^= UINT8_C(0xff);
    packet = tcp_view(conflict, sizeof(conflict), 201U, 0U, 12002U);
    assert_int_equal(
        add_packet(tracker, &packet, 102U, output, messages, &message_count),
        JG_TCP_STREAM_CONFLICT);
    packet = tcp_view(stream + 7U, 7U, 208U, 0U, 12002U);
    assert_int_equal(
        add_packet(tracker, &packet, 103U, output, messages, &message_count),
        JG_TCP_STREAM_CONFLICT);

    packet =
        tcp_view(oversized_prefix, sizeof(oversized_prefix), 300U, 0U, 12003U);
    assert_int_equal(
        add_packet(tracker, &packet, 104U, output, messages, &message_count),
        JG_TCP_STREAM_MALFORMED);
    jg_tcp_stream_tracker_destroy(tracker);
}

/** @brief Verify segment bounds, timeout cleanup, FIN, and RST handling. */
static void test_limits_and_lifetime(void **state)
{
    static const uint8_t byte = 0U;
    uint8_t output[64U];
    struct jg_tcp_stream_message messages[4U];
    struct jg_tcp_stream_tracker *tracker = create_tracker(2U);
    struct jg_packet_view packet =
        tcp_view(&empty_payload, 0U, 400U, JG_TCP_FLAG_SYN, 12004U);
    struct jg_tcp_stream_stats stats;
    size_t message_count = 0U;

    (void)state;
    assert_int_equal(
        add_packet(tracker, &packet, 100U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    packet = tcp_view(&byte, 1U, 403U, 0U, 12004U);
    assert_int_equal(
        add_packet(tracker, &packet, 101U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    packet.tcp_sequence = 405U;
    assert_int_equal(
        add_packet(tracker, &packet, 102U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    packet.tcp_sequence = 407U;
    assert_int_equal(
        add_packet(tracker, &packet, 103U, output, messages, &message_count),
        JG_TCP_STREAM_EXHAUSTED);

    packet = tcp_view(&empty_payload, 0U, 500U, JG_TCP_FLAG_SYN, 12005U);
    assert_int_equal(
        add_packet(tracker, &packet, 1104U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    packet.tcp_flags = JG_TCP_FLAG_FIN;
    packet.tcp_sequence = 501U;
    assert_int_equal(
        add_packet(tracker, &packet, 1105U, output, messages, &message_count),
        JG_TCP_STREAM_CLOSED);
    packet.tcp_flags = JG_TCP_FLAG_RST;
    assert_int_equal(
        add_packet(tracker, &packet, 1106U, output, messages, &message_count),
        JG_TCP_STREAM_CLOSED);
    assert_int_equal(jg_tcp_stream_tracker_get_stats(tracker, &stats), 0);
    assert_int_equal(stats.exhausted, 1U);
    assert_int_equal(stats.timeouts, 0U);
    assert_int_equal(stats.closed, 2U);
    jg_tcp_stream_tracker_destroy(tracker);

    tracker = create_tracker(4U);
    packet = tcp_view(&empty_payload, 0U, 600U, JG_TCP_FLAG_SYN, 12006U);
    assert_int_equal(
        add_packet(tracker, &packet, 100U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    packet.source_port = 12007U;
    packet.tcp_sequence = 700U;
    assert_int_equal(
        add_packet(tracker, &packet, 1101U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    assert_int_equal(jg_tcp_stream_tracker_get_stats(tracker, &stats), 0);
    assert_int_equal(stats.timeouts, 1U);
    jg_tcp_stream_tracker_destroy(tracker);

    tracker = create_tracker(4U);
    packet = tcp_view(&empty_payload, 0U, 800U, JG_TCP_FLAG_SYN, 12008U);
    assert_int_equal(
        add_packet(tracker, &packet, 100U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    packet.tcp_flags = 0U;
    packet.tcp_sequence = 801U;
    assert_int_equal(
        add_packet(tracker, &packet, 900U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    assert_int_equal(
        add_packet(tracker, &packet, 1800U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    assert_int_equal(
        add_packet(tracker, &packet, 2700U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    assert_int_equal(
        add_packet(tracker, &packet, 3600U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    assert_int_equal(
        add_packet(tracker, &packet, 4500U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    packet.source_port = 12009U;
    packet.tcp_sequence = 900U;
    packet.tcp_flags = JG_TCP_FLAG_SYN;
    assert_int_equal(
        add_packet(tracker, &packet, 5101U, output, messages, &message_count),
        JG_TCP_STREAM_BUFFERED);
    assert_int_equal(jg_tcp_stream_tracker_get_stats(tracker, &stats), 0);
    assert_int_equal(stats.timeouts, 1U);
    jg_tcp_stream_tracker_destroy(tracker);
}

/** @brief Verify configuration and caller-storage argument validation. */
static void test_configuration(void **state)
{
    struct jg_tcp_stream_limits limits;
    struct jg_tcp_stream_tracker *tracker = NULL;
    struct jg_packet_view packet =
        tcp_view(&empty_payload, 0U, 800U, JG_TCP_FLAG_SYN, 12008U);
    struct jg_tcp_stream_message messages[4U];
    enum jg_tcp_stream_result result;
    uint8_t output[64U];
    size_t message_count = 0U;

    (void)state;
    jg_tcp_stream_limits_default(&limits);
    assert_int_equal(jg_tcp_stream_limits_validate(&limits), 0);
    limits.max_flows = 0U;
    assert_int_equal(jg_tcp_stream_limits_validate(&limits), -EINVAL);
    jg_tcp_stream_limits_default(&limits);
    limits.max_buffered_bytes = limits.max_dns_message_size;
    assert_int_equal(jg_tcp_stream_limits_validate(&limits), -ERANGE);
    assert_int_equal(jg_tcp_stream_tracker_create(NULL, &tracker), 0);
    assert_non_null(tracker);
    jg_tcp_stream_tracker_destroy(tracker);
    tracker = create_tracker(4U);

    assert_int_equal(jg_tcp_stream_tracker_add(tracker, &packet, 100U, output,
                                               sizeof(output) - 1U, messages,
                                               4U, &message_count, &result),
                     -ENOSPC);
    assert_int_equal(jg_tcp_stream_tracker_add(NULL, &packet, 100U, output,
                                               sizeof(output), messages, 4U,
                                               &message_count, &result),
                     -EINVAL);
    assert_int_equal(jg_tcp_stream_tracker_reject_flow(tracker, &packet, 100U),
                     0);
    assert_int_equal(jg_tcp_stream_tracker_get_stats(NULL, NULL), -EINVAL);
    assert_int_equal(jg_tcp_stream_tracker_create(NULL, NULL), -EINVAL);
    jg_tcp_stream_limits_default(NULL);
    jg_tcp_stream_tracker_destroy(NULL);
    jg_tcp_stream_tracker_destroy(tracker);
}

/** @brief Verify generic out-of-order byte reconstruction and isolation. */
static void test_raw_reassembly(void **state)
{
    static const uint8_t bytes[] = "0123456789abcdefghij";
    uint8_t conflict[10U];
    uint8_t output[64U];
    struct jg_tcp_stream_tracker *tracker = create_tracker(4U);
    struct jg_packet_view packet =
        tcp_view(&empty_payload, 0U, 100U, JG_TCP_FLAG_SYN, 13000U);
    struct jg_tcp_raw_stream_chunk chunk;
    enum jg_tcp_raw_stream_result raw_result;

    (void)state;
    packet.destination_port = 443U;
    assert_int_equal(add_raw_packet(tracker, &packet, 100U, output, &chunk),
                     JG_TCP_RAW_STREAM_BUFFERED);
    assert_true(chunk.new_flow);

    packet = tcp_view(bytes + 10U, 10U, 111U, 0U, 13000U);
    packet.destination_port = 443U;
    assert_int_equal(add_raw_packet(tracker, &packet, 101U, output, &chunk),
                     JG_TCP_RAW_STREAM_BUFFERED);
    assert_int_equal(chunk.size, 0U);
    packet = tcp_view(bytes, 10U, 101U, 0U, 13000U);
    packet.destination_port = 443U;
    assert_int_equal(add_raw_packet(tracker, &packet, 102U, output, &chunk),
                     JG_TCP_RAW_STREAM_BYTES);
    assert_int_equal(chunk.size, sizeof(bytes) - 1U);
    assert_memory_equal(output, bytes, sizeof(bytes) - 1U);

    assert_int_equal(add_raw_packet(tracker, &packet, 103U, output, &chunk),
                     JG_TCP_RAW_STREAM_DUPLICATE);
    packet.destination_port = 53U;
    assert_int_equal(jg_tcp_stream_tracker_add_raw(tracker, &packet, 104U,
                                                   output, sizeof(output),
                                                   &chunk, &raw_result),
                     -EINVAL);

    packet = tcp_view(&empty_payload, 0U, 200U, JG_TCP_FLAG_SYN, 13001U);
    packet.destination_port = 853U;
    assert_int_equal(add_raw_packet(tracker, &packet, 200U, output, &chunk),
                     JG_TCP_RAW_STREAM_BUFFERED);
    packet = tcp_view(bytes, 10U, 206U, 0U, 13001U);
    packet.destination_port = 853U;
    assert_int_equal(add_raw_packet(tracker, &packet, 201U, output, &chunk),
                     JG_TCP_RAW_STREAM_BUFFERED);
    (void)memcpy(conflict, bytes, sizeof(conflict));
    conflict[0U] ^= UINT8_C(0xff);
    packet = tcp_view(conflict, sizeof(conflict), 206U, 0U, 13001U);
    packet.destination_port = 853U;
    assert_int_equal(add_raw_packet(tracker, &packet, 202U, output, &chunk),
                     JG_TCP_RAW_STREAM_CONFLICT);
    jg_tcp_stream_tracker_destroy(tracker);
}

/** @brief Run the DNS-over-TCP stream-tracker test group. */
int jg_test_tcp_stream(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_message_reassembly),
        cmocka_unit_test(test_out_of_order_wraparound),
        cmocka_unit_test(test_rejections),
        cmocka_unit_test(test_limits_and_lifetime),
        cmocka_unit_test(test_configuration),
        cmocka_unit_test(test_raw_reassembly),
    };

    return cmocka_run_group_tests_name("TCP stream", tests, NULL, NULL);
}
