/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "tcp_reset.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "janusgate/checked.h"
#include "tcp_stream.h"

/** Ethernet destination-address offset and size. */
#define ETHERNET_DESTINATION_OFFSET 0U
#define ETHERNET_SOURCE_OFFSET 6U
#define ETHERNET_ADDRESS_SIZE 6U

/** Fixed reset IP and TCP header sizes. */
#define IPV4_HEADER_SIZE 20U
#define IPV6_HEADER_SIZE 40U
#define TCP_HEADER_SIZE 20U

/** TCP acknowledgement control bit. */
#define TCP_FLAG_ACK UINT8_C(0x10)

/** @brief Add bounded network-order bytes to a one's-complement sum. */
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

/** @brief Fold and complement one Internet checksum accumulator. */
static uint16_t checksum_finish(uint32_t sum)
{
    while ((sum >> 16U) != 0U) {
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16U);
    }
    return (uint16_t)~sum;
}

/** @brief Write the IPv4 header checksum into one complete reset frame. */
static void write_ipv4_checksum(uint8_t *frame, size_t network_offset)
{
    const uint16_t checksum = checksum_finish(
        checksum_add(frame + network_offset, IPV4_HEADER_SIZE, 0U));

    (void)jg_write_u16_be(frame, JG_TCP_RESET_FRAME_MAX, network_offset + 10U,
                          checksum);
}

/** @brief Calculate one TCP checksum including its IP pseudo-header. */
static uint16_t tcp_checksum(const uint8_t *frame,
                             size_t network_offset,
                             enum jg_ip_version ip_version)
{
    const size_t tcp_offset =
        network_offset +
        (ip_version == JG_IP_V4 ? IPV4_HEADER_SIZE : IPV6_HEADER_SIZE);
    uint32_t sum = 0U;

    if (ip_version == JG_IP_V4) {
        sum = checksum_add(frame + network_offset + 12U, 8U, sum);
    } else {
        sum = checksum_add(frame + network_offset + 8U, 32U, sum);
    }
    sum += (uint32_t)JG_TRANSPORT_TCP;
    sum += TCP_HEADER_SIZE;
    sum = checksum_add(frame + tcp_offset, TCP_HEADER_SIZE, sum);
    return checksum_finish(sum);
}

/** @brief Copy and optionally reverse one Ethernet and VLAN envelope. */
static void build_link_header(const struct jg_packet_view *packet,
                              bool reverse,
                              uint8_t *frame)
{
    (void)memcpy(frame, packet->frame, packet->network_offset);
    if (reverse) {
        uint8_t destination[ETHERNET_ADDRESS_SIZE];

        (void)memcpy(destination, frame + ETHERNET_DESTINATION_OFFSET,
                     sizeof(destination));
        (void)memcpy(frame + ETHERNET_DESTINATION_OFFSET,
                     frame + ETHERNET_SOURCE_OFFSET, ETHERNET_ADDRESS_SIZE);
        (void)memcpy(frame + ETHERNET_SOURCE_OFFSET, destination,
                     sizeof(destination));
    }
}

/** @brief Build one minimal IPv4 or IPv6 reset network header. */
static void build_network_header(const struct jg_packet_view *packet,
                                 bool reverse,
                                 uint8_t *frame)
{
    uint8_t *network = frame + packet->network_offset;
    const uint8_t *source =
        reverse ? packet->destination_address : packet->source_address;
    const uint8_t *destination =
        reverse ? packet->source_address : packet->destination_address;

    if (packet->ip_version == JG_IP_V4) {
        (void)memset(network, 0, IPV4_HEADER_SIZE);
        network[0U] = UINT8_C(0x45);
        (void)jg_write_u16_be(network, IPV4_HEADER_SIZE, 2U,
                              IPV4_HEADER_SIZE + TCP_HEADER_SIZE);
        network[8U] = 64U;
        network[9U] = (uint8_t)JG_TRANSPORT_TCP;
        (void)memcpy(network + 12U, source, 4U);
        (void)memcpy(network + 16U, destination, 4U);
        write_ipv4_checksum(frame, packet->network_offset);
    } else {
        (void)memset(network, 0, IPV6_HEADER_SIZE);
        network[0U] = UINT8_C(0x60);
        (void)jg_write_u16_be(network, IPV6_HEADER_SIZE, 4U, TCP_HEADER_SIZE);
        network[6U] = (uint8_t)JG_TRANSPORT_TCP;
        network[7U] = 64U;
        (void)memcpy(network + 8U, source, JG_PACKET_ADDRESS_SIZE);
        (void)memcpy(network + 24U, destination, JG_PACKET_ADDRESS_SIZE);
    }
}

/** @brief Build one TCP reset header and its pseudo-header checksum. */
static void build_tcp_header(const struct jg_packet_view *packet,
                             bool reverse,
                             uint32_t sequence,
                             uint32_t acknowledgement,
                             uint8_t flags,
                             uint8_t *frame)
{
    const size_t network_size =
        packet->ip_version == JG_IP_V4 ? IPV4_HEADER_SIZE : IPV6_HEADER_SIZE;
    const size_t tcp_offset = packet->network_offset + network_size;
    uint8_t *tcp = frame + tcp_offset;
    const uint16_t source_port =
        reverse ? packet->destination_port : packet->source_port;
    const uint16_t destination_port =
        reverse ? packet->source_port : packet->destination_port;
    uint16_t checksum = 0U;

    (void)memset(tcp, 0, TCP_HEADER_SIZE);
    (void)jg_write_u16_be(tcp, TCP_HEADER_SIZE, 0U, source_port);
    (void)jg_write_u16_be(tcp, TCP_HEADER_SIZE, 2U, destination_port);
    (void)jg_write_u32_be(tcp, TCP_HEADER_SIZE, 4U, sequence);
    (void)jg_write_u32_be(tcp, TCP_HEADER_SIZE, 8U, acknowledgement);
    tcp[12U] = UINT8_C(0x50);
    tcp[13U] = flags;
    checksum = tcp_checksum(frame, packet->network_offset, packet->ip_version);
    (void)jg_write_u16_be(tcp, TCP_HEADER_SIZE, 16U, checksum);
}

/** @brief Build one complete reset frame in the requested direction. */
static int build_reset(const struct jg_packet_view *packet,
                       bool reverse,
                       uint32_t sequence,
                       uint32_t acknowledgement,
                       uint8_t flags,
                       uint8_t *frame,
                       size_t *frame_size)
{
    const size_t network_size =
        packet->ip_version == JG_IP_V4 ? IPV4_HEADER_SIZE : IPV6_HEADER_SIZE;
    size_t complete_size = 0U;

    if (!jg_size_add(packet->network_offset, network_size + TCP_HEADER_SIZE,
                     &complete_size) ||
        complete_size > JG_TCP_RESET_FRAME_MAX) {
        return -ENOSPC;
    }
    (void)memset(frame, 0, JG_TCP_RESET_FRAME_MAX);
    build_link_header(packet, reverse, frame);
    build_network_header(packet, reverse, frame);
    build_tcp_header(packet, reverse, sequence, acknowledgement, flags, frame);
    *frame_size = complete_size;
    return 0;
}

/** @brief Validate metadata required to construct both reset frames. */
static bool packet_valid(const struct jg_packet_view *packet)
{
    return packet != NULL && packet->frame != NULL &&
           packet->network_offset >= 14U &&
           packet->network_offset <= JG_TCP_RESET_FRAME_MAX &&
           packet->transport == JG_TRANSPORT_TCP &&
           packet->ip_protocol == (uint8_t)JG_TRANSPORT_TCP &&
           !packet->fragmented &&
           ((packet->ip_version == JG_IP_V4 && packet->address_size == 4U) ||
            (packet->ip_version == JG_IP_V6 &&
             packet->address_size == JG_PACKET_ADDRESS_SIZE)) &&
           jg_range_valid(0U, packet->network_offset, packet->frame_size) &&
           jg_range_valid(packet->payload_offset, packet->payload_size,
                          packet->frame_size) &&
           packet->payload_size <= UINT32_MAX - 2U;
}

/** @brief Build reset frames directed to both TCP endpoints. */
int jg_tcp_reset_build(const struct jg_packet_view *packet,
                       struct jg_tcp_reset_pair *resets)
{
    uint32_t client_acknowledgement = 0U;
    uint32_t client_sequence = 0U;
    uint8_t client_flags = JG_TCP_FLAG_RST;
    uint32_t segment_size = 0U;
    int result = 0;

    if (resets == NULL) {
        return -EINVAL;
    }
    (void)memset(resets, 0, sizeof(*resets));
    if (!packet_valid(packet)) {
        return -EINVAL;
    }
    segment_size = (uint32_t)packet->payload_size;
    if ((packet->tcp_flags & JG_TCP_FLAG_SYN) != 0U) {
        ++segment_size;
    }
    if ((packet->tcp_flags & JG_TCP_FLAG_FIN) != 0U) {
        ++segment_size;
    }
    if ((packet->tcp_flags & TCP_FLAG_ACK) != 0U) {
        client_sequence = packet->tcp_acknowledgement;
    } else {
        client_acknowledgement = packet->tcp_sequence + segment_size;
        client_flags |= TCP_FLAG_ACK;
    }

    result =
        build_reset(packet, true, client_sequence, client_acknowledgement,
                    client_flags, resets->to_client, &resets->to_client_size);
    if (result == 0) {
        result = build_reset(packet, false, packet->tcp_sequence, 0U,
                             JG_TCP_FLAG_RST, resets->to_server,
                             &resets->to_server_size);
    }
    if (result != 0) {
        (void)memset(resets, 0, sizeof(*resets));
    }
    return result;
}
