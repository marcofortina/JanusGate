/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "janusgate/packet.h"

int jg_test_packet(void);

/** @brief Initialize an Ethernet header with the requested EtherType. */
static void make_ethernet(uint8_t *frame, uint16_t ether_type)
{
    size_t index = 0U;

    for (index = 0U; index < 12U; ++index) {
        frame[index] = (uint8_t)index;
    }
    frame[12] = (uint8_t)(ether_type >> 8U);
    frame[13] = (uint8_t)(ether_type & UINT16_C(0xff));
}

/** @brief Verify parsing of a complete Ethernet, IPv4, and UDP frame. */
static void test_ipv4_udp(void **state)
{
    uint8_t frame[14U + 20U + 8U + 4U] = {0U};
    struct jg_packet_view view;

    (void)state;
    make_ethernet(frame, UINT16_C(0x0800));
    frame[14] = 0x45U;
    frame[16] = 0U;
    frame[17] = 32U;
    frame[23] = 17U;
    frame[26] = 192U;
    frame[27] = 0U;
    frame[28] = 2U;
    frame[29] = 1U;
    frame[30] = 198U;
    frame[31] = 51U;
    frame[32] = 100U;
    frame[33] = 53U;
    frame[34] = 0x30U;
    frame[35] = 0x39U;
    frame[36] = 0U;
    frame[37] = 53U;
    frame[38] = 0U;
    frame[39] = 12U;
    frame[42] = 1U;
    frame[43] = 2U;
    frame[44] = 3U;
    frame[45] = 4U;

    assert_int_equal(jg_packet_parse(frame, sizeof(frame), NULL, &view),
                     JG_PACKET_OK);
    assert_int_equal(view.ip_version, JG_IP_V4);
    assert_int_equal(view.transport, JG_TRANSPORT_UDP);
    assert_int_equal(view.source_port, 12345U);
    assert_int_equal(view.destination_port, 53U);
    assert_int_equal(view.payload_size, 4U);
    assert_true(view.transport_complete);
}

/** @brief Verify VLAN, IPv4 options, and TCP header parsing. */
static void test_vlan_ipv4_options_tcp(void **state)
{
    uint8_t frame[18U + 24U + 20U] = {0U};
    struct jg_packet_view view;

    (void)state;
    make_ethernet(frame, UINT16_C(0x8100));
    frame[14] = 0x00U;
    frame[15] = 0x64U;
    frame[16] = 0x08U;
    frame[17] = 0x00U;
    frame[18] = 0x46U;
    frame[20] = 0U;
    frame[21] = 44U;
    frame[27] = 6U;
    frame[42] = 0x01U;
    frame[43] = 0xbbU;
    frame[44] = 0U;
    frame[45] = 53U;
    frame[46] = 0x12U;
    frame[47] = 0x34U;
    frame[48] = 0x56U;
    frame[49] = 0x78U;
    frame[54] = 0x50U;
    frame[55] = 0x18U;

    assert_int_equal(jg_packet_parse(frame, sizeof(frame), NULL, &view),
                     JG_PACKET_OK);
    assert_int_equal(view.vlan_count, 1U);
    assert_int_equal(view.vlan_tci[0], 100U);
    assert_int_equal(view.transport, JG_TRANSPORT_TCP);
    assert_int_equal(view.source_port, 443U);
    assert_int_equal(view.destination_port, 53U);
    assert_int_equal(view.tcp_sequence, UINT32_C(0x12345678));
    assert_int_equal(view.payload_size, 0U);
}

/** @brief Verify traversal of a bounded IPv6 extension header. */
static void test_ipv6_extension_udp(void **state)
{
    uint8_t frame[14U + 40U + 8U + 8U] = {0U};
    struct jg_packet_view view;
    size_t ip = 14U;
    size_t extension = ip + 40U;
    size_t udp = extension + 8U;

    (void)state;
    make_ethernet(frame, UINT16_C(0x86dd));
    frame[ip] = 0x60U;
    frame[ip + 4U] = 0U;
    frame[ip + 5U] = 16U;
    frame[ip + 6U] = 0U;
    frame[extension] = 17U;
    frame[extension + 1U] = 0U;
    frame[udp] = 0x14U;
    frame[udp + 1U] = 0xe9U;
    frame[udp + 2U] = 0U;
    frame[udp + 3U] = 53U;
    frame[udp + 4U] = 0U;
    frame[udp + 5U] = 8U;

    assert_int_equal(jg_packet_parse(frame, sizeof(frame), NULL, &view),
                     JG_PACKET_OK);
    assert_int_equal(view.ip_version, JG_IP_V6);
    assert_int_equal(view.transport, JG_TRANSPORT_UDP);
    assert_int_equal(view.source_port, 5353U);
    assert_int_equal(view.destination_port, 53U);
}

/** @brief Verify safe handling of a noninitial IP fragment. */
static void test_noninitial_fragment(void **state)
{
    uint8_t frame[14U + 20U + 8U] = {0U};
    struct jg_packet_view view;

    (void)state;
    make_ethernet(frame, UINT16_C(0x0800));
    frame[14] = 0x45U;
    frame[16] = 0U;
    frame[17] = 28U;
    frame[20] = 0x20U;
    frame[21] = 0x01U;
    frame[23] = 17U;

    assert_int_equal(jg_packet_parse(frame, sizeof(frame), NULL, &view),
                     JG_PACKET_OK);
    assert_true(view.fragmented);
    assert_int_equal(view.fragment_offset, 8U);
    assert_true(view.more_fragments);
    assert_int_equal(view.transport, JG_TRANSPORT_NONE);
}

/** @brief Verify rejection of inconsistent lengths and exhausted limits. */
static void test_invalid_lengths_and_limits(void **state)
{
    uint8_t frame[22U] = {0U};
    struct jg_packet_view view;
    struct jg_packet_limits limits;

    (void)state;
    make_ethernet(frame, UINT16_C(0x8100));
    frame[14] = 0U;
    frame[15] = 1U;
    frame[16] = 0x81U;
    frame[17] = 0U;
    frame[18] = 0U;
    frame[19] = 2U;
    frame[20] = 0x08U;
    frame[21] = 0U;
    jg_packet_limits_default(&limits);
    limits.max_vlan_tags = 1U;

    assert_int_equal(jg_packet_parse(frame, sizeof(frame), &limits, &view),
                     JG_PACKET_LIMIT_EXCEEDED);
    assert_null(view.frame);

    make_ethernet(frame, UINT16_C(0x0800));
    assert_int_equal(jg_packet_parse(frame, sizeof(frame), NULL, &view),
                     JG_PACKET_TRUNCATED);

    assert_int_equal(jg_packet_parse(NULL, 0U, NULL, &view),
                     JG_PACKET_MALFORMED);
    assert_int_equal(jg_packet_parse(frame, sizeof(frame), NULL, NULL),
                     JG_PACKET_MALFORMED);
}

/** @brief Run the Ethernet, IP, and transport parser test group. */
int jg_test_packet(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ipv4_udp),
        cmocka_unit_test(test_vlan_ipv4_options_tcp),
        cmocka_unit_test(test_ipv6_extension_udp),
        cmocka_unit_test(test_noninitial_fragment),
        cmocka_unit_test(test_invalid_lengths_and_limits),
    };

    return cmocka_run_group_tests_name("packet", tests, NULL, NULL);
}
