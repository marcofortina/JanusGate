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

#include "fragment.h"

int jg_test_fragment(void);

/** @brief Build one direct fragment view over caller-owned payload bytes. */
static struct jg_packet_view fragment_view(const uint8_t *payload,
                                           size_t payload_size,
                                           size_t fragment_offset,
                                           bool more_fragments,
                                           uint32_t fragment_id)
{
    struct jg_packet_view packet = {
        .frame = payload,
        .frame_size = payload_size,
        .ip_version = JG_IP_V4,
        .source_address = {192U, 0U, 2U, 10U},
        .destination_address = {192U, 0U, 2U, 53U},
        .address_size = 4U,
        .fragment_id = fragment_id,
        .fragment_offset = fragment_offset,
        .more_fragments = more_fragments,
        .fragmented = true,
        .ip_protocol = (uint8_t)JG_TRANSPORT_UDP,
        .transport_offset = 0U,
        .transport_size = payload_size,
    };

    return packet;
}

/** @brief Create one small deterministic tracker for unit tests. */
static struct jg_fragment_tracker *create_tracker(void)
{
    const struct jg_fragment_limits limits = {
        .max_datagrams = 2U,
        .max_fragments_per_datagram = 4U,
        .max_bytes_per_datagram = 32U,
        .max_datagrams_per_source = 2U,
        .timeout_ms = 1000U,
    };
    struct jg_fragment_tracker *tracker = NULL;

    assert_int_equal(jg_fragment_tracker_create(&limits, &tracker), 0);
    return tracker;
}

/** @brief Verify out-of-order reconstruction and duplicate handling. */
static void test_reassembly(void **state)
{
    static const uint8_t first[] = "abcdefgh";
    static const uint8_t second[] = "ijklmnop";
    static const uint8_t last[] = "qrstu";
    static const uint8_t expected[] = "abcdefghijklmnopqrstu";
    struct jg_fragment_tracker *tracker = create_tracker();
    struct jg_packet_view packet =
        fragment_view(second, sizeof(second) - 1U, 8U, true, 7U);
    struct jg_fragment_stats stats;
    enum jg_fragment_result result;
    uint8_t output[32U];
    size_t output_size = 0U;

    (void)state;
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 100U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    assert_int_equal(result, JG_FRAGMENT_STORED);
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 101U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    assert_int_equal(result, JG_FRAGMENT_DUPLICATE);

    packet = fragment_view(first, sizeof(first) - 1U, 0U, true, 7U);
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 102U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    assert_int_equal(result, JG_FRAGMENT_STORED);
    packet = fragment_view(last, sizeof(last) - 1U, 16U, false, 7U);
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 103U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    assert_int_equal(result, JG_FRAGMENT_COMPLETE);
    assert_int_equal(output_size, sizeof(expected) - 1U);
    assert_memory_equal(output, expected, output_size);
    assert_int_equal(jg_fragment_tracker_get_stats(tracker, &stats), 0);
    assert_int_equal(stats.stored, 2U);
    assert_int_equal(stats.duplicates, 1U);
    assert_int_equal(stats.completed, 1U);
    jg_fragment_tracker_destroy(tracker);
}

/** @brief Verify conflicting overlap and malformed-length rejection. */
static void test_rejections(void **state)
{
    static const uint8_t first[] = "abcdefgh";
    static const uint8_t conflict[] = "abcdEfgh";
    static const uint8_t short_fragment[] = "abcdefg";
    struct jg_fragment_tracker *tracker = create_tracker();
    struct jg_packet_view packet =
        fragment_view(first, sizeof(first) - 1U, 0U, true, 8U);
    enum jg_fragment_result result;
    uint8_t output[32U];
    size_t output_size = 0U;

    (void)state;
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 100U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    packet = fragment_view(conflict, sizeof(conflict) - 1U, 0U, true, 8U);
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 101U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    assert_int_equal(result, JG_FRAGMENT_OVERLAP);

    packet = fragment_view(first, sizeof(first) - 1U, 0U, true, 8U);
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 102U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    assert_int_equal(result, JG_FRAGMENT_OVERLAP);

    packet = fragment_view(first, sizeof(first) - 1U, 0U, true, 9U);
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 103U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    packet.more_fragments = false;
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 104U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    assert_int_equal(result, JG_FRAGMENT_OVERLAP);

    packet = fragment_view(short_fragment, sizeof(short_fragment) - 1U, 0U,
                           true, 10U);
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 105U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    assert_int_equal(result, JG_FRAGMENT_MALFORMED);
    jg_fragment_tracker_destroy(tracker);
}

/** @brief Verify byte limits, idle expiration, and argument handling. */
static void test_limits_and_timeout(void **state)
{
    static const uint8_t fragment[] = "abcdefgh";
    struct jg_fragment_tracker *tracker = create_tracker();
    struct jg_packet_view packet =
        fragment_view(fragment, sizeof(fragment) - 1U, 0U, true, 10U);
    struct jg_fragment_stats stats;
    enum jg_fragment_result result;
    uint8_t output[32U];
    size_t output_size = 0U;

    (void)state;
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 100U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    packet.fragment_id = 11U;
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 1101U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    assert_int_equal(jg_fragment_tracker_get_stats(tracker, &stats), 0);
    assert_int_equal(stats.timeouts, 1U);

    packet.fragment_id = 12U;
    packet.fragment_offset = 32U;
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 1102U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    assert_int_equal(result, JG_FRAGMENT_EXHAUSTED);
    packet.fragmented = false;
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 1103U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     -EINVAL);
    jg_fragment_tracker_destroy(tracker);
}

/** @brief Verify default and rejected fragment resource limits. */
static void test_configuration(void **state)
{
    static const uint8_t payload[] = "abcdefgh";
    uint8_t frame[12U] = {0U};
    struct jg_fragment_tracker *tracker = create_tracker();
    struct jg_packet_view packet =
        fragment_view(frame, sizeof(frame), 0U, true, 20U);
    struct jg_fragment_limits limits;
    enum jg_fragment_result result;
    uint8_t output[32U];
    size_t output_size = 0U;

    (void)state;
    (void)memcpy(frame + 4U, payload, sizeof(payload) - 1U);
    packet.transport_offset = 4U;
    packet.transport_size = sizeof(payload) - 1U;
    assert_int_equal(jg_fragment_tracker_add(tracker, &packet, 100U, output,
                                             sizeof(output), &output_size,
                                             &result),
                     0);
    assert_int_equal(result, JG_FRAGMENT_STORED);
    jg_fragment_tracker_destroy(tracker);

    jg_fragment_limits_default(&limits);
    assert_int_equal(jg_fragment_limits_validate(&limits), 0);
    limits.max_datagrams_per_source = limits.max_datagrams + 1U;
    assert_int_equal(jg_fragment_limits_validate(&limits), -ERANGE);
    limits.max_datagrams_per_source = 1U;
    limits.timeout_ms = 0U;
    assert_int_equal(jg_fragment_limits_validate(&limits), -EINVAL);
    assert_int_equal(jg_fragment_limits_validate(NULL), -EINVAL);
    assert_int_equal(jg_fragment_tracker_create(NULL, NULL), -EINVAL);
    jg_fragment_tracker_destroy(NULL);
}

/** @brief Verify normalized frames produced from reconstructed payloads. */
static void test_normalized_frame(void **state)
{
    uint8_t envelope[14U] = {
        0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U,
        0x77U, 0x88U, 0x99U, 0xaaU, 0xbbU, 0x08U, 0x00U,
    };
    uint8_t tcp[20U] = {0U};
    uint8_t frame[128U];
    struct jg_packet_view fragment = {
        .frame = envelope,
        .frame_size = sizeof(envelope),
        .network_offset = 14U,
        .ip_version = JG_IP_V4,
        .source_address = {192U, 0U, 2U, 10U},
        .destination_address = {192U, 0U, 2U, 53U},
        .address_size = 4U,
        .fragment_id = 19U,
        .fragmented = true,
        .ip_protocol = (uint8_t)JG_TRANSPORT_TCP,
    };
    struct jg_packet_view parsed;
    size_t frame_size = 0U;

    (void)state;
    tcp[0U] = 0x30U;
    tcp[1U] = 0x39U;
    tcp[2U] = 0x00U;
    tcp[3U] = 0x35U;
    tcp[12U] = 0x50U;
    assert_int_equal(jg_fragment_build_frame(&fragment, tcp, sizeof(tcp), frame,
                                             sizeof(frame), &frame_size),
                     0);
    assert_int_equal(frame_size, 54U);
    assert_memory_equal(frame, envelope, sizeof(envelope));
    assert_int_equal(jg_packet_parse(frame, frame_size, NULL, &parsed),
                     JG_PACKET_OK);
    assert_false(parsed.fragmented);
    assert_int_equal(parsed.transport, JG_TRANSPORT_TCP);
    assert_int_equal(parsed.source_port, 12345U);
    assert_int_equal(parsed.destination_port, 53U);

    assert_int_equal(jg_fragment_build_frame(&fragment, tcp, sizeof(tcp), frame,
                                             53U, &frame_size),
                     -ENOSPC);
    assert_int_equal(frame_size, 0U);
    fragment.fragmented = false;
    assert_int_equal(jg_fragment_build_frame(&fragment, tcp, sizeof(tcp), frame,
                                             sizeof(frame), &frame_size),
                     -EINVAL);
}

/** @brief Run the bounded fragment-tracker test group. */
int jg_test_fragment(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_reassembly),
        cmocka_unit_test(test_rejections),
        cmocka_unit_test(test_limits_and_timeout),
        cmocka_unit_test(test_configuration),
        cmocka_unit_test(test_normalized_frame),
    };

    return cmocka_run_group_tests_name("fragment", tests, NULL, NULL);
}
