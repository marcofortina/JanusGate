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

#include "dns_response.h"
#include "janusgate/checked.h"
#include "janusgate/packet.h"

int jg_test_dns_response(void);

/** Complete Ethernet, IPv4, UDP, and A query for `blocked.test`. */
static const uint8_t ipv4_query[] = {
    0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xaaU,
    0xbbU, 0x08U, 0x00U, 0x45U, 0x00U, 0x00U, 0x3aU, 0x12U, 0x34U, 0x00U, 0x00U,
    0x40U, 0x11U, 0x00U, 0x00U, 0xc0U, 0x00U, 0x02U, 0x0aU, 0x08U, 0x08U, 0x08U,
    0x08U, 0x30U, 0x39U, 0x00U, 0x35U, 0x00U, 0x26U, 0x00U, 0x00U, 0xbeU, 0xefU,
    0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x07U,
    'b',   'l',   'o',   'c',   'k',   'e',   'd',   0x04U, 't',   'e',   's',
    't',   0x00U, 0x00U, 0x01U, 0x00U, 0x01U,
};

/** @brief Add bytes to one test-side Internet-checksum accumulator. */
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

/** @brief Fold a test-side Internet-checksum accumulator without complement. */
static uint16_t checksum_fold(uint32_t sum)
{
    while ((sum >> 16U) != 0U) {
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16U);
    }
    return (uint16_t)sum;
}

/** @brief Verify one parsed UDP frame's pseudo-header checksum. */
static bool udp_checksum_valid(const uint8_t *frame,
                               const struct jg_packet_view *packet)
{
    uint32_t sum = 0U;

    if (packet->ip_version == JG_IP_V4) {
        sum = checksum_add(frame + packet->network_offset + 12U, 8U, sum);
    } else {
        sum = checksum_add(frame + packet->network_offset + 8U, 32U, sum);
        sum += (uint32_t)(packet->transport_size >> 16U);
    }
    sum += (uint32_t)packet->transport_size;
    sum += (uint32_t)JG_TRANSPORT_UDP;
    sum = checksum_add(frame + packet->transport_offset, packet->transport_size,
                       sum);
    return checksum_fold(sum) == UINT16_MAX;
}

/** @brief Parse the immutable IPv4 query fixture. */
static struct jg_packet_view parse_ipv4_query(void)
{
    struct jg_packet_view packet;

    assert_int_equal(
        jg_packet_parse(ipv4_query, sizeof(ipv4_query), NULL, &packet),
        JG_PACKET_OK);
    return packet;
}

/** @brief Verify REFUSED, NXDOMAIN, and DROP response semantics. */
static void test_basic_actions(void **state)
{
    struct jg_packet_view packet = parse_ipv4_query();
    struct jg_dns_response_config config;
    struct jg_packet_view response_packet;
    uint8_t response[512U];
    size_t response_size = 0U;
    uint16_t flags = 0U;

    (void)state;
    jg_dns_response_config_default(&config);
    assert_int_equal(
        jg_dns_response_build(&packet, ipv4_query + packet.payload_offset,
                              packet.payload_size, 0U, &config, response,
                              sizeof(response), &response_size),
        0);
    assert_int_equal(response_size, sizeof(ipv4_query));
    assert_memory_equal(response, ipv4_query + 6U, 6U);
    assert_memory_equal(response + 6U, ipv4_query, 6U);
    assert_memory_equal(response + 26U, ipv4_query + 30U, 4U);
    assert_memory_equal(response + 30U, ipv4_query + 26U, 4U);
    assert_int_equal(checksum_fold(checksum_add(response + 14U, 20U, 0U)),
                     UINT16_MAX);
    assert_int_equal(
        jg_packet_parse(response, response_size, NULL, &response_packet),
        JG_PACKET_OK);
    assert_true(udp_checksum_valid(response, &response_packet));
    assert_true(jg_read_u16_be(response, response_size, 44U, &flags));
    assert_int_equal(flags, UINT16_C(0x8185));
    assert_memory_equal(response + 42U, ipv4_query + 42U, 2U);
    assert_memory_equal(response + 54U, ipv4_query + 54U,
                        sizeof(ipv4_query) - 54U);

    config.action = JG_DNS_BLOCK_NXDOMAIN;
    assert_int_equal(
        jg_dns_response_build(&packet, ipv4_query + packet.payload_offset,
                              packet.payload_size, 0U, &config, response,
                              sizeof(response), &response_size),
        0);
    assert_true(jg_read_u16_be(response, response_size, 44U, &flags));
    assert_int_equal(flags, UINT16_C(0x8183));

    config.action = JG_DNS_BLOCK_DROP;
    assert_int_equal(
        jg_dns_response_build(&packet, ipv4_query + packet.payload_offset,
                              packet.payload_size, 0U, &config, response,
                              sizeof(response), &response_size),
        0);
    assert_int_equal(response_size, 0U);
}

/** @brief Verify A sinkhole answers and incompatible question handling. */
static void test_sinkhole(void **state)
{
    struct jg_packet_view packet = parse_ipv4_query();
    struct jg_dns_response_config config;
    uint8_t query[sizeof(ipv4_query)];
    uint8_t response[512U];
    size_t response_size = 0U;
    uint16_t answer_count = 0U;

    (void)state;
    jg_dns_response_config_default(&config);
    config.action = JG_DNS_BLOCK_SINKHOLE;
    config.has_ipv4_sinkhole = true;
    config.ipv4_sinkhole[0U] = 192U;
    config.ipv4_sinkhole[1U] = 0U;
    config.ipv4_sinkhole[2U] = 2U;
    config.ipv4_sinkhole[3U] = 80U;
    config.sinkhole_ttl = 300U;

    assert_int_equal(
        jg_dns_response_build(&packet, ipv4_query + packet.payload_offset,
                              packet.payload_size, 0U, &config, response,
                              sizeof(response), &response_size),
        0);
    assert_true(jg_read_u16_be(response, response_size, 48U, &answer_count));
    assert_int_equal(answer_count, 1U);
    assert_memory_equal(response + response_size - 4U, config.ipv4_sinkhole,
                        4U);

    (void)memcpy(query, ipv4_query, sizeof(query));
    query[sizeof(query) - 4U] = 0U;
    query[sizeof(query) - 3U] = 28U;
    assert_int_equal(jg_packet_parse(query, sizeof(query), NULL, &packet),
                     JG_PACKET_OK);
    assert_int_equal(
        jg_dns_response_build(&packet, query + packet.payload_offset,
                              packet.payload_size, 0U, &config, response,
                              sizeof(response), &response_size),
        0);
    assert_true(jg_read_u16_be(response, response_size, 48U, &answer_count));
    assert_int_equal(answer_count, 0U);
}

/** @brief Verify the mandatory checksum on one synthetic IPv6 response. */
static void test_ipv6_checksum(void **state)
{
    const size_t dns_size = sizeof(ipv4_query) - 42U;
    const size_t query_size = 14U + 40U + 8U + dns_size;
    struct jg_dns_response_config config;
    struct jg_packet_view packet;
    struct jg_packet_view response_packet;
    uint8_t query[128U] = {0U};
    uint8_t response[512U];
    size_t response_size = 0U;

    (void)state;
    assert_true(query_size <= sizeof(query));
    (void)memcpy(query, ipv4_query, 12U);
    query[12U] = 0x86U;
    query[13U] = 0xddU;
    query[14U] = 0x60U;
    (void)jg_write_u16_be(query, sizeof(query), 18U, (uint16_t)(8U + dns_size));
    query[20U] = (uint8_t)JG_TRANSPORT_UDP;
    query[21U] = 64U;
    query[22U] = 0x20U;
    query[23U] = 0x01U;
    query[24U] = 0x0dU;
    query[25U] = 0xb8U;
    query[37U] = 0x10U;
    query[38U] = 0x20U;
    query[39U] = 0x01U;
    query[40U] = 0x48U;
    query[41U] = 0x60U;
    query[42U] = 0x48U;
    query[43U] = 0x60U;
    query[52U] = 0x88U;
    query[53U] = 0x88U;
    query[54U] = 0x30U;
    query[55U] = 0x39U;
    query[56U] = 0x00U;
    query[57U] = 0x35U;
    (void)jg_write_u16_be(query, sizeof(query), 58U, (uint16_t)(8U + dns_size));
    (void)memcpy(query + 62U, ipv4_query + 42U, dns_size);

    assert_int_equal(jg_packet_parse(query, query_size, NULL, &packet),
                     JG_PACKET_OK);
    jg_dns_response_config_default(&config);
    assert_int_equal(
        jg_dns_response_build(&packet, query + packet.payload_offset,
                              packet.payload_size, 0U, &config, response,
                              sizeof(response), &response_size),
        0);
    assert_int_equal(
        jg_packet_parse(response, response_size, NULL, &response_packet),
        JG_PACKET_OK);
    assert_true(udp_checksum_valid(response, &response_packet));
}

/** @brief Verify that a synthetic response preserves the complete VLAN tag. */
static void test_vlan_envelope(void **state)
{
    struct jg_dns_response_config config;
    struct jg_packet_view packet;
    uint8_t query[sizeof(ipv4_query) + 4U];
    uint8_t response[512U];
    size_t response_size = 0U;

    (void)state;
    (void)memcpy(query, ipv4_query, 12U);
    query[12U] = 0x81U;
    query[13U] = 0x00U;
    query[14U] = 0x01U;
    query[15U] = 0x23U;
    query[16U] = 0x08U;
    query[17U] = 0x00U;
    (void)memcpy(query + 18U, ipv4_query + 14U, sizeof(ipv4_query) - 14U);
    assert_int_equal(jg_packet_parse(query, sizeof(query), NULL, &packet),
                     JG_PACKET_OK);

    jg_dns_response_config_default(&config);
    assert_int_equal(
        jg_dns_response_build(&packet, query + packet.payload_offset,
                              packet.payload_size, 0U, &config, response,
                              sizeof(response), &response_size),
        0);
    assert_int_equal(response_size, sizeof(query));
    assert_memory_equal(response + 12U, query + 12U, 6U);
}

/** @brief Verify strict configuration and argument validation. */
static void test_validation(void **state)
{
    struct jg_packet_view packet = parse_ipv4_query();
    struct jg_dns_response_config config;
    struct jg_dns_response_config decoded;
    uint8_t wire[JG_DNS_RESPONSE_CONFIG_WIRE_SIZE];
    uint8_t response[512U];
    size_t encoded_size = 0U;
    size_t response_size = 1U;

    (void)state;
    jg_dns_response_config_default(&config);
    assert_int_equal(jg_dns_response_config_validate(&config), 0);
    assert_int_equal(jg_dns_response_config_encode(&config, wire, sizeof(wire),
                                                   &encoded_size),
                     0);
    assert_int_equal(encoded_size, sizeof(wire));
    assert_int_equal(
        jg_dns_response_config_decode(wire, sizeof(wire), &decoded), 0);
    assert_int_equal(decoded.action, JG_DNS_BLOCK_REFUSED);
    assert_true(decoded.checksum_ipv4_udp);
    assert_int_equal(decoded.sinkhole_ttl, 60U);
    config.action = JG_DNS_BLOCK_SINKHOLE;
    assert_int_equal(jg_dns_response_config_validate(&config), -EINVAL);
    config.action = (enum jg_dns_block_action)0;
    assert_int_equal(jg_dns_response_config_validate(&config), -EINVAL);
    assert_int_equal(
        jg_dns_response_build(&packet, ipv4_query + packet.payload_offset,
                              packet.payload_size, 0U, &config, response,
                              sizeof(response), &response_size),
        -EINVAL);
    assert_int_equal(response_size, 0U);
    assert_int_equal(jg_dns_response_build(&packet,
                                           ipv4_query + packet.payload_offset,
                                           packet.payload_size, 0U, &config,
                                           response, sizeof(response), NULL),
                     -EINVAL);
    jg_dns_response_config_default(NULL);
}

/** @brief Run the synthetic UDP DNS response test group. */
int jg_test_dns_response(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_basic_actions),
        cmocka_unit_test(test_sinkhole),
        cmocka_unit_test(test_ipv6_checksum),
        cmocka_unit_test(test_vlan_envelope),
        cmocka_unit_test(test_validation),
    };

    return cmocka_run_group_tests_name("DNS response", tests, NULL, NULL);
}
