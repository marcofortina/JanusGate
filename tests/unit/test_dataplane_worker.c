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

#include "dataplane_worker.h"
#include "janusgate/policy.h"
#include "policy_store.h"

int jg_test_dataplane_worker(void);

/** Minimal valid non-IP Ethernet frame. */
static const uint8_t arp_frame[] = {
    0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U,
    0x77U, 0x88U, 0x99U, 0xaaU, 0xbbU, 0x08U, 0x06U,
};

/** UDP header and `blocked.test` DNS query used for fragmentation. */
static const uint8_t fragmented_query[] = {
    0x30U, 0x39U, 0x00U, 0x35U, 0x00U, 0x26U, 0x00U, 0x00U, 0xbeU, 0xefU,
    0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x07U, 'b',   'l',   'o',   'c',   'k',   'e',   'd',   0x04U, 't',
    'e',   's',   't',   0x00U, 0x00U, 0x01U, 0x00U, 0x01U,
};

/** Length-prefixed `blocked.test` DNS query used for TCP reconstruction. */
static const uint8_t tcp_query[] = {
    0x00U, 0x1eU, 0xbeU, 0xefU, 0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x07U, 'b',   'l',   'o',   'c',   'k',   'e',   'd',
    0x04U, 't',   'e',   's',   't',   0x00U, 0x00U, 0x01U, 0x00U, 0x01U,
};

/** @brief Build one empty immutable policy store. */
static struct jg_policy_store *build_store(void)
{
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_policy_store *store = NULL;

    assert_int_equal(jg_policy_snapshot_build(NULL, 0U, 1U, &snapshot), 0);
    assert_int_equal(jg_policy_store_create(snapshot, 1U, &store), 0);
    return store;
}

/** @brief Build one policy store blocking the fragmented test query. */
static struct jg_policy_store *build_blocking_store(void)
{
    const struct jg_policy_rule_input rule = {
        .id = 17U,
        .domain = "blocked.test",
        .effect = JG_POLICY_BLOCK,
        .source = JG_POLICY_SOURCE_EXPLICIT,
        .scope = {.type = JG_POLICY_SCOPE_GLOBAL},
        .attribution = "unit test",
    };
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_policy_store *store = NULL;

    assert_int_equal(jg_policy_snapshot_build(&rule, 1U, 1U, &snapshot), 0);
    assert_int_equal(jg_policy_store_create(snapshot, 1U, &store), 0);
    return store;
}

/** @brief Build one Ethernet and IPv4 fragment of the test UDP query. */
static size_t build_fragment(uint8_t *frame,
                             size_t frame_size,
                             size_t fragment_offset,
                             size_t fragment_size,
                             bool more_fragments)
{
    const size_t complete_size = 34U + fragment_size;
    const uint16_t ip_size = (uint16_t)(20U + fragment_size);
    const uint16_t fragment_field = (uint16_t)(fragment_offset / 8U) |
                                    (more_fragments ? UINT16_C(0x2000) : 0U);

    assert_true(complete_size <= frame_size);
    assert_true(fragment_offset + fragment_size <= sizeof(fragmented_query));
    (void)memset(frame, 0, complete_size);
    (void)memcpy(frame, arp_frame, 12U);
    frame[12U] = 0x08U;
    frame[13U] = 0x00U;
    frame[14U] = 0x45U;
    frame[16U] = (uint8_t)(ip_size >> 8U);
    frame[17U] = (uint8_t)ip_size;
    frame[18U] = 0x12U;
    frame[19U] = 0x34U;
    frame[20U] = (uint8_t)(fragment_field >> 8U);
    frame[21U] = (uint8_t)fragment_field;
    frame[22U] = 64U;
    frame[23U] = (uint8_t)JG_TRANSPORT_UDP;
    frame[26U] = 192U;
    frame[28U] = 2U;
    frame[29U] = 10U;
    frame[30U] = 192U;
    frame[32U] = 2U;
    frame[33U] = 53U;
    (void)memcpy(frame + 34U, fragmented_query + fragment_offset,
                 fragment_size);
    return complete_size;
}

/** @brief Build one Ethernet, IPv4, and TCP segment of the test query. */
static size_t build_tcp_segment(uint8_t *frame,
                                size_t frame_size,
                                size_t query_offset,
                                size_t query_size,
                                uint32_t sequence)
{
    const size_t complete_size = 54U + query_size;
    const uint16_t ip_size = (uint16_t)(40U + query_size);

    assert_true(complete_size <= frame_size);
    assert_true(query_offset + query_size <= sizeof(tcp_query));
    (void)memset(frame, 0, complete_size);
    (void)memcpy(frame, arp_frame, 12U);
    frame[12U] = 0x08U;
    frame[13U] = 0x00U;
    frame[14U] = 0x45U;
    frame[16U] = (uint8_t)(ip_size >> 8U);
    frame[17U] = (uint8_t)ip_size;
    frame[18U] = 0x56U;
    frame[19U] = 0x78U;
    frame[22U] = 64U;
    frame[23U] = (uint8_t)JG_TRANSPORT_TCP;
    frame[26U] = 192U;
    frame[28U] = 2U;
    frame[29U] = 10U;
    frame[30U] = 192U;
    frame[32U] = 2U;
    frame[33U] = 53U;
    frame[34U] = 0x30U;
    frame[35U] = 0x39U;
    frame[37U] = 0x35U;
    frame[38U] = (uint8_t)(sequence >> 24U);
    frame[39U] = (uint8_t)(sequence >> 16U);
    frame[40U] = (uint8_t)(sequence >> 8U);
    frame[41U] = (uint8_t)sequence;
    frame[46U] = 0x50U;
    frame[47U] = 0x18U;
    (void)memcpy(frame + 54U, tcp_query + query_offset, query_size);
    return complete_size;
}

/** @brief Verify direct queue adaptation and relaxed worker counters. */
static void test_processing(void **state)
{
    const struct jg_nfqueue_packet packet = {
        .queue_number = 100U,
        .ingress_index = 2U,
        .data = arp_frame,
        .size = sizeof(arp_frame),
    };
    struct jg_policy_store *store = build_store();
    struct jg_dataplane_worker *worker = NULL;
    struct jg_dataplane_stats stats;

    (void)state;
    assert_int_equal(
        jg_dataplane_worker_create(store, 0U, NULL, NULL, NULL, &worker), 0);
    assert_int_equal(jg_dataplane_worker_process(&packet, worker),
                     JG_NFQUEUE_ACCEPT);
    assert_int_equal(jg_dataplane_worker_get_stats(worker, &stats), 0);
    assert_int_equal(stats.packets, 1U);
    assert_int_equal(stats.accepted, 1U);
    assert_int_equal(stats.blocked, 0U);
    assert_int_equal(stats.internal_errors, 0U);
    jg_dataplane_worker_destroy(worker);
    jg_policy_store_destroy(store);
}

/** @brief Verify that the completing blocked fragment is not forwarded. */
static void test_fragmented_dns(void **state)
{
    uint8_t first_frame[58U];
    uint8_t last_frame[48U];
    struct jg_nfqueue_packet packet = {
        .queue_number = 100U,
        .ingress_index = 2U,
    };
    struct jg_policy_store *store = build_blocking_store();
    struct jg_dataplane_worker *worker = NULL;
    struct jg_dataplane_stats stats;
    struct jg_fragment_stats fragment_stats;

    (void)state;
    assert_int_equal(
        jg_dataplane_worker_create(store, 0U, NULL, NULL, NULL, &worker), 0);
    packet.data = first_frame;
    packet.size =
        build_fragment(first_frame, sizeof(first_frame), 0U, 24U, true);
    assert_int_equal(jg_dataplane_worker_process(&packet, worker),
                     JG_NFQUEUE_ACCEPT);

    packet.data = last_frame;
    packet.size =
        build_fragment(last_frame, sizeof(last_frame), 24U, 14U, false);
    assert_int_equal(jg_dataplane_worker_process(&packet, worker),
                     JG_NFQUEUE_DROP);
    assert_int_equal(jg_dataplane_worker_get_stats(worker, &stats), 0);
    assert_int_equal(stats.packets, 2U);
    assert_int_equal(stats.accepted, 1U);
    assert_int_equal(stats.blocked, 1U);
    assert_int_equal(stats.fragments, 1U);
    assert_int_equal(stats.internal_errors, 0U);
    assert_int_equal(
        jg_dataplane_worker_get_fragment_stats(worker, &fragment_stats), 0);
    assert_int_equal(fragment_stats.stored, 1U);
    assert_int_equal(fragment_stats.completed, 1U);
    jg_dataplane_worker_destroy(worker);
    jg_policy_store_destroy(store);
}

/** @brief Verify blocked DNS-over-TCP completion and retransmission handling.
 */
static void test_tcp_dns(void **state)
{
    uint8_t first_frame[70U];
    uint8_t last_frame[70U];
    struct jg_nfqueue_packet packet = {
        .queue_number = 100U,
        .ingress_index = 2U,
    };
    struct jg_policy_store *store = build_blocking_store();
    struct jg_dataplane_worker *worker = NULL;
    struct jg_dataplane_stats stats;
    struct jg_tcp_stream_stats stream_stats;

    (void)state;
    assert_int_equal(
        jg_dataplane_worker_create(store, 0U, NULL, NULL, NULL, &worker), 0);
    packet.data = first_frame;
    packet.size =
        build_tcp_segment(first_frame, sizeof(first_frame), 0U, 16U, 1000U);
    assert_int_equal(jg_dataplane_worker_process(&packet, worker),
                     JG_NFQUEUE_ACCEPT);

    packet.data = last_frame;
    packet.size =
        build_tcp_segment(last_frame, sizeof(last_frame), 16U, 16U, 1016U);
    assert_int_equal(jg_dataplane_worker_process(&packet, worker),
                     JG_NFQUEUE_DROP);
    assert_int_equal(jg_dataplane_worker_process(&packet, worker),
                     JG_NFQUEUE_DROP);
    assert_int_equal(jg_dataplane_worker_get_stats(worker, &stats), 0);
    assert_int_equal(stats.packets, 3U);
    assert_int_equal(stats.accepted, 1U);
    assert_int_equal(stats.blocked, 2U);
    assert_int_equal(stats.streams, 1U);
    assert_int_equal(stats.internal_errors, 0U);
    assert_int_equal(
        jg_dataplane_worker_get_stream_stats(worker, &stream_stats), 0);
    assert_int_equal(stream_stats.messages, 1U);
    assert_int_equal(stream_stats.conflicts, 1U);
    jg_dataplane_worker_destroy(worker);
    jg_policy_store_destroy(store);
}

/** @brief Verify invalid limits, reader slots, and packet arguments. */
static void test_arguments(void **state)
{
    struct jg_fragment_limits fragment_limits;
    struct jg_tcp_stream_limits stream_limits;
    struct jg_packet_limits limits = {
        .max_vlan_tags = JG_PACKET_VLAN_LIMIT + 1U,
        .max_ipv6_extensions = 1U,
        .max_ipv6_extension_bytes = 8U,
    };
    struct jg_policy_store *store = build_store();
    struct jg_dataplane_worker *worker = NULL;

    (void)state;
    assert_int_equal(
        jg_dataplane_worker_create(store, 1U, NULL, NULL, NULL, &worker),
        -EINVAL);
    assert_int_equal(
        jg_dataplane_worker_create(store, 0U, &limits, NULL, NULL, &worker),
        -EINVAL);
    jg_fragment_limits_default(&fragment_limits);
    fragment_limits.max_datagrams = 0U;
    assert_int_equal(jg_dataplane_worker_create(
                         store, 0U, NULL, &fragment_limits, NULL, &worker),
                     -EINVAL);
    jg_fragment_limits_default(&fragment_limits);
    fragment_limits.max_datagrams = JG_FRAGMENT_DATAGRAM_LIMIT + 1U;
    assert_int_equal(jg_dataplane_worker_create(
                         store, 0U, NULL, &fragment_limits, NULL, &worker),
                     -ERANGE);
    jg_tcp_stream_limits_default(&stream_limits);
    stream_limits.max_flows = 0U;
    assert_int_equal(jg_dataplane_worker_create(store, 0U, NULL, NULL,
                                                &stream_limits, &worker),
                     -EINVAL);
    jg_tcp_stream_limits_default(&stream_limits);
    stream_limits.max_flows = JG_TCP_STREAM_FLOW_LIMIT + 1U;
    assert_int_equal(jg_dataplane_worker_create(store, 0U, NULL, NULL,
                                                &stream_limits, &worker),
                     -ERANGE);
    assert_int_equal(
        jg_dataplane_worker_create(store, 0U, NULL, NULL, NULL, NULL), -EINVAL);
    assert_int_equal(jg_dataplane_worker_process(NULL, NULL), JG_NFQUEUE_DROP);
    assert_int_equal(jg_dataplane_worker_get_stats(NULL, NULL), -EINVAL);
    assert_int_equal(jg_dataplane_worker_get_fragment_stats(NULL, NULL),
                     -EINVAL);
    assert_int_equal(jg_dataplane_worker_get_stream_stats(NULL, NULL), -EINVAL);
    jg_dataplane_worker_destroy(NULL);
    jg_policy_store_destroy(store);
}

/** @brief Run the per-queue data-plane worker test group. */
int jg_test_dataplane_worker(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_processing),
        cmocka_unit_test(test_fragmented_dns),
        cmocka_unit_test(test_tcp_dns),
        cmocka_unit_test(test_arguments),
    };

    return cmocka_run_group_tests_name("dataplane worker", tests, NULL, NULL);
}
