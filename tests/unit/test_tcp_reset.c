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

#include "janusgate/checked.h"
#include "janusgate/packet.h"
#include "tcp_reset.h"
#include "tcp_stream.h"

int jg_test_tcp_reset(void);

/** @brief Add network-order bytes to a checksum verification sum. */
static uint32_t checksum_add(const uint8_t *data,
                             size_t data_size,
                             uint32_t sum)
{
    size_t index = 0U;

    for (index = 0U; index + 1U < data_size; index += 2U) {
        sum += ((uint32_t)data[index] << 8U) | (uint32_t)data[index + 1U];
    }
    if (index < data_size) {
        sum += (uint32_t)data[index] << 8U;
    }
    return sum;
}

/** @brief Fold one checksum verification sum without complementing it. */
static uint16_t checksum_fold(uint32_t sum)
{
    while ((sum >> 16U) != 0U) {
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16U);
    }
    return (uint16_t)sum;
}

/** @brief Verify a complete TCP checksum for IPv4 or IPv6. */
static void assert_tcp_checksum(const uint8_t *frame,
                                size_t network_offset,
                                enum jg_ip_version ip_version)
{
    const size_t network_size = ip_version == JG_IP_V4 ? 20U : 40U;
    const size_t tcp_offset = network_offset + network_size;
    uint32_t sum = 0U;

    if (ip_version == JG_IP_V4) {
        sum = checksum_add(frame + network_offset + 12U, 8U, sum);
    } else {
        sum = checksum_add(frame + network_offset + 8U, 32U, sum);
    }
    sum += (uint32_t)JG_TRANSPORT_TCP;
    sum += 20U;
    sum = checksum_add(frame + tcp_offset, 20U, sum);
    assert_int_equal(checksum_fold(sum), UINT16_C(0xffff));
}

/** @brief Build one parsed IPv4 TCP packet with four payload bytes. */
static struct jg_packet_view ipv4_packet(uint8_t *frame, uint8_t flags)
{
    struct jg_packet_view packet;

    (void)memset(frame, 0, 58U);
    for (size_t index = 0U; index < 12U; ++index) {
        frame[index] = (uint8_t)(index + 1U);
    }
    frame[12U] = 0x08U;
    frame[13U] = 0x00U;
    frame[14U] = 0x45U;
    frame[16U] = 0x00U;
    frame[17U] = 0x2cU;
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
    frame[38U] = 0x01U;
    frame[39U] = 0x02U;
    frame[40U] = 0x03U;
    frame[41U] = 0x04U;
    frame[42U] = 0xa0U;
    frame[43U] = 0xb0U;
    frame[44U] = 0xc0U;
    frame[45U] = 0xd0U;
    frame[46U] = 0x50U;
    frame[47U] = flags;
    frame[54U] = 1U;
    frame[55U] = 2U;
    frame[56U] = 3U;
    frame[57U] = 4U;
    assert_int_equal(jg_packet_parse(frame, 58U, NULL, &packet), JG_PACKET_OK);
    return packet;
}

/** @brief Build one parsed VLAN-tagged IPv6 TCP packet. */
static struct jg_packet_view ipv6_packet(uint8_t *frame)
{
    struct jg_packet_view packet;

    (void)memset(frame, 0, 82U);
    for (size_t index = 0U; index < 12U; ++index) {
        frame[index] = (uint8_t)(index + 16U);
    }
    frame[12U] = 0x81U;
    frame[13U] = 0x00U;
    frame[14U] = 0x00U;
    frame[15U] = 0x64U;
    frame[16U] = 0x86U;
    frame[17U] = 0xddU;
    frame[18U] = 0x60U;
    frame[22U] = 0x00U;
    frame[23U] = 0x18U;
    frame[24U] = (uint8_t)JG_TRANSPORT_TCP;
    frame[25U] = 64U;
    frame[33U] = 1U;
    frame[49U] = 2U;
    frame[58U] = 0x30U;
    frame[59U] = 0x39U;
    frame[61U] = 0x35U;
    frame[62U] = 0x11U;
    frame[63U] = 0x22U;
    frame[64U] = 0x33U;
    frame[65U] = 0x44U;
    frame[66U] = 0x55U;
    frame[67U] = 0x66U;
    frame[68U] = 0x77U;
    frame[69U] = 0x88U;
    frame[70U] = 0x50U;
    frame[71U] = 0x10U;
    frame[78U] = 5U;
    frame[79U] = 6U;
    frame[80U] = 7U;
    frame[81U] = 8U;
    assert_int_equal(jg_packet_parse(frame, 82U, NULL, &packet), JG_PACKET_OK);
    return packet;
}

/** @brief Verify IPv4 reset directions, sequence rules, and checksums. */
static void test_ipv4_resets(void **state)
{
    uint8_t frame[58U];
    struct jg_packet_view packet = ipv4_packet(frame, UINT8_C(0x18));
    struct jg_tcp_reset_pair resets;
    uint32_t value = 0U;

    (void)state;
    assert_int_equal(jg_tcp_reset_build(&packet, &resets), 0);
    assert_int_equal(resets.to_client_size, 54U);
    assert_int_equal(resets.to_server_size, 54U);
    assert_memory_equal(resets.to_client, frame + 6U, 6U);
    assert_memory_equal(resets.to_client + 6U, frame, 6U);
    assert_memory_equal(resets.to_server, frame, 12U);
    assert_memory_equal(resets.to_client + 26U, frame + 30U, 4U);
    assert_memory_equal(resets.to_client + 30U, frame + 26U, 4U);
    assert_true(
        jg_read_u32_be(resets.to_client, resets.to_client_size, 38U, &value));
    assert_int_equal(value, UINT32_C(0xa0b0c0d0));
    assert_int_equal(resets.to_client[47U], JG_TCP_FLAG_RST);
    assert_true(
        jg_read_u32_be(resets.to_server, resets.to_server_size, 38U, &value));
    assert_int_equal(value, UINT32_C(0x01020304));
    assert_int_equal(resets.to_server[47U], JG_TCP_FLAG_RST);
    assert_int_equal(
        checksum_fold(checksum_add(resets.to_client + 14U, 20U, 0U)),
        UINT16_C(0xffff));
    assert_int_equal(
        checksum_fold(checksum_add(resets.to_server + 14U, 20U, 0U)),
        UINT16_C(0xffff));
    assert_tcp_checksum(resets.to_client, 14U, JG_IP_V4);
    assert_tcp_checksum(resets.to_server, 14U, JG_IP_V4);

    packet = ipv4_packet(frame, 0U);
    assert_int_equal(jg_tcp_reset_build(&packet, &resets), 0);
    assert_int_equal(resets.to_client[47U], JG_TCP_FLAG_RST | UINT8_C(0x10));
    assert_true(
        jg_read_u32_be(resets.to_client, resets.to_client_size, 42U, &value));
    assert_int_equal(value, UINT32_C(0x01020308));
}

/** @brief Verify VLAN preservation and the mandatory IPv6 TCP checksum. */
static void test_ipv6_vlan_resets(void **state)
{
    uint8_t frame[82U];
    struct jg_packet_view packet = ipv6_packet(frame);
    struct jg_tcp_reset_pair resets;

    (void)state;
    assert_int_equal(jg_tcp_reset_build(&packet, &resets), 0);
    assert_int_equal(resets.to_client_size, 78U);
    assert_int_equal(resets.to_server_size, 78U);
    assert_memory_equal(resets.to_client + 12U, frame + 12U, 6U);
    assert_memory_equal(resets.to_server + 12U, frame + 12U, 6U);
    assert_memory_equal(resets.to_client + 26U, frame + 42U, 16U);
    assert_memory_equal(resets.to_client + 42U, frame + 26U, 16U);
    assert_tcp_checksum(resets.to_client, 18U, JG_IP_V6);
    assert_tcp_checksum(resets.to_server, 18U, JG_IP_V6);
}

/** @brief Verify conservative outputs for invalid reset arguments. */
static void test_arguments(void **state)
{
    uint8_t frame[58U];
    struct jg_packet_view packet = ipv4_packet(frame, UINT8_C(0x10));
    struct jg_tcp_reset_pair resets;

    (void)state;
    assert_int_equal(jg_tcp_reset_build(NULL, &resets), -EINVAL);
    assert_int_equal(resets.to_client_size, 0U);
    assert_int_equal(jg_tcp_reset_build(&packet, NULL), -EINVAL);
    packet.fragmented = true;
    assert_int_equal(jg_tcp_reset_build(&packet, &resets), -EINVAL);
}

/** @brief Run the TCP reset frame-construction test group. */
int jg_test_tcp_reset(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ipv4_resets),
        cmocka_unit_test(test_ipv6_vlan_resets),
        cmocka_unit_test(test_arguments),
    };

    return cmocka_run_group_tests_name("TCP reset", tests, NULL, NULL);
}
