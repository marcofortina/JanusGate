/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/packet.h"

#include <string.h>

#include "janusgate/checked.h"

#define JG_ETHERNET_HEADER_SIZE 14U
#define JG_VLAN_HEADER_SIZE 4U
#define JG_IPV4_MIN_HEADER_SIZE 20U
#define JG_IPV6_HEADER_SIZE 40U
#define JG_UDP_HEADER_SIZE 8U
#define JG_TCP_MIN_HEADER_SIZE 20U

#define JG_ETHERTYPE_IPV4 UINT16_C(0x0800)
#define JG_ETHERTYPE_IPV6 UINT16_C(0x86dd)
#define JG_ETHERTYPE_VLAN UINT16_C(0x8100)
#define JG_ETHERTYPE_PROVIDER_VLAN UINT16_C(0x88a8)
#define JG_ETHERTYPE_QINQ UINT16_C(0x9100)

#define JG_IPPROTO_HOPOPTS 0U
#define JG_IPPROTO_ROUTING 43U
#define JG_IPPROTO_FRAGMENT 44U
#define JG_IPPROTO_ESP 50U
#define JG_IPPROTO_AH 51U
#define JG_IPPROTO_DSTOPTS 60U
#define JG_IPPROTO_MOBILITY 135U

/**
 * @brief Determine whether an EtherType introduces another VLAN header.
 *
 * @param[in] ether_type Host-order EtherType.
 *
 * @return `true` for supported customer and provider VLAN tags.
 */
static bool is_vlan_ether_type(uint16_t ether_type)
{
    return ether_type == JG_ETHERTYPE_VLAN ||
           ether_type == JG_ETHERTYPE_PROVIDER_VLAN ||
           ether_type == JG_ETHERTYPE_QINQ;
}

/**
 * @brief Parse and validate a UDP header.
 *
 * @param[in,out] view Packet view with a validated transport range.
 *
 * @return A packet parser result.
 */
static enum jg_packet_result parse_udp(struct jg_packet_view *view)
{
    uint16_t udp_length = 0U;

    if (view->transport_size < JG_UDP_HEADER_SIZE) {
        return JG_PACKET_TRUNCATED;
    }
    if (!jg_read_u16_be(view->frame, view->frame_size, view->transport_offset,
                        &view->source_port) ||
        !jg_read_u16_be(view->frame, view->frame_size,
                        view->transport_offset + 2U, &view->destination_port) ||
        !jg_read_u16_be(view->frame, view->frame_size,
                        view->transport_offset + 4U, &udp_length)) {
        return JG_PACKET_TRUNCATED;
    }
    if (udp_length < JG_UDP_HEADER_SIZE) {
        return JG_PACKET_MALFORMED;
    }

    view->payload_offset = view->transport_offset + JG_UDP_HEADER_SIZE;
    if ((size_t)udp_length <= view->transport_size) {
        view->payload_size = (size_t)udp_length - JG_UDP_HEADER_SIZE;
        view->transport_complete = true;
    } else if (view->fragmented && view->more_fragments) {
        view->payload_size = view->transport_size - JG_UDP_HEADER_SIZE;
        view->transport_complete = false;
    } else {
        return JG_PACKET_TRUNCATED;
    }
    view->transport = JG_TRANSPORT_UDP;
    return JG_PACKET_OK;
}

/**
 * @brief Parse and validate a TCP header.
 *
 * @param[in,out] view Packet view with a validated transport range.
 *
 * @return A packet parser result.
 */
static enum jg_packet_result parse_tcp(struct jg_packet_view *view)
{
    uint8_t data_offset_words = 0U;
    size_t header_size = 0U;

    if (view->transport_size < JG_TCP_MIN_HEADER_SIZE) {
        return JG_PACKET_TRUNCATED;
    }
    if (!jg_read_u16_be(view->frame, view->frame_size, view->transport_offset,
                        &view->source_port) ||
        !jg_read_u16_be(view->frame, view->frame_size,
                        view->transport_offset + 2U, &view->destination_port) ||
        !jg_read_u32_be(view->frame, view->frame_size,
                        view->transport_offset + 4U, &view->tcp_sequence) ||
        !jg_read_u32_be(view->frame, view->frame_size,
                        view->transport_offset + 8U,
                        &view->tcp_acknowledgement)) {
        return JG_PACKET_TRUNCATED;
    }

    data_offset_words =
        (uint8_t)(view->frame[view->transport_offset + 12U] >> 4U);
    if (data_offset_words < 5U) {
        return JG_PACKET_MALFORMED;
    }
    header_size = (size_t)data_offset_words * 4U;
    if (header_size > view->transport_size) {
        return JG_PACKET_TRUNCATED;
    }

    view->tcp_flags = view->frame[view->transport_offset + 13U];
    view->payload_offset = view->transport_offset + header_size;
    view->payload_size = view->transport_size - header_size;
    view->transport_complete = !view->fragmented || !view->more_fragments;
    view->transport = JG_TRANSPORT_TCP;
    return JG_PACKET_OK;
}

/**
 * @brief Parse a transport header when it begins in the current fragment.
 *
 * @param[in,out] view Packet view holding protocol and range metadata.
 *
 * @return A packet parser result.
 */
static enum jg_packet_result parse_transport(struct jg_packet_view *view)
{
    if (view->fragmented && view->fragment_offset != 0U) {
        view->transport = JG_TRANSPORT_NONE;
        view->payload_offset = view->transport_offset;
        view->payload_size = view->transport_size;
        return JG_PACKET_OK;
    }
    if (view->ip_protocol == (uint8_t)JG_TRANSPORT_UDP) {
        return parse_udp(view);
    }
    if (view->ip_protocol == (uint8_t)JG_TRANSPORT_TCP) {
        return parse_tcp(view);
    }
    view->transport = JG_TRANSPORT_OTHER;
    view->payload_offset = view->transport_offset;
    view->payload_size = view->transport_size;
    view->transport_complete = !view->fragmented || !view->more_fragments;
    return JG_PACKET_OK;
}

/**
 * @brief Parse a validated Ethernet payload as IPv4.
 *
 * @param[in,out] view Packet view containing source frame metadata.
 *
 * @return A packet parser result.
 */
static enum jg_packet_result parse_ipv4(struct jg_packet_view *view)
{
    size_t available = view->frame_size - view->network_offset;
    uint8_t first = 0U;
    size_t header_size = 0U;
    uint16_t total_length = 0U;
    uint16_t fragment_field = 0U;
    uint16_t identification = 0U;

    if (available < JG_IPV4_MIN_HEADER_SIZE) {
        return JG_PACKET_TRUNCATED;
    }
    first = view->frame[view->network_offset];
    if ((first >> 4U) != 4U) {
        return JG_PACKET_MALFORMED;
    }
    header_size = (size_t)(first & UINT8_C(0x0f)) * 4U;
    if (header_size < JG_IPV4_MIN_HEADER_SIZE) {
        return JG_PACKET_MALFORMED;
    }
    if (header_size > available) {
        return JG_PACKET_TRUNCATED;
    }
    if (!jg_read_u16_be(view->frame, view->frame_size,
                        view->network_offset + 2U, &total_length) ||
        !jg_read_u16_be(view->frame, view->frame_size,
                        view->network_offset + 4U, &identification) ||
        !jg_read_u16_be(view->frame, view->frame_size,
                        view->network_offset + 6U, &fragment_field)) {
        return JG_PACKET_TRUNCATED;
    }
    if ((size_t)total_length < header_size) {
        return JG_PACKET_MALFORMED;
    }
    if ((size_t)total_length > available) {
        return JG_PACKET_TRUNCATED;
    }

    view->ip_version = JG_IP_V4;
    view->address_size = 4U;
    (void)memcpy(view->source_address, view->frame + view->network_offset + 12U,
                 view->address_size);
    (void)memcpy(view->destination_address,
                 view->frame + view->network_offset + 16U, view->address_size);
    view->fragment_id = (uint32_t)identification;
    view->fragment_offset = (size_t)(fragment_field & UINT16_C(0x1fff)) * 8U;
    view->more_fragments = (fragment_field & UINT16_C(0x2000)) != 0U;
    view->fragmented = view->fragment_offset != 0U || view->more_fragments;
    view->ip_protocol = view->frame[view->network_offset + 9U];
    view->transport_offset = view->network_offset + header_size;
    view->transport_size = (size_t)total_length - header_size;
    return parse_transport(view);
}

/**
 * @brief Identify IPv6 extension headers with an eight-octet length unit.
 *
 * @param[in] next_header IPv6 next-header value.
 *
 * @return `true` when the common extension length encoding applies.
 */
static bool is_ipv6_common_extension(uint8_t next_header)
{
    return next_header == JG_IPPROTO_HOPOPTS ||
           next_header == JG_IPPROTO_ROUTING ||
           next_header == JG_IPPROTO_DSTOPTS ||
           next_header == JG_IPPROTO_MOBILITY;
}

/**
 * @brief Parse IPv6 extensions and establish the transport range.
 *
 * @param[in,out] view Packet view with validated IPv6 payload bounds.
 * @param[in] limits Active parser resource limits.
 * @param[in] first_next_header Initial IPv6 next-header value.
 *
 * @return A packet parser result.
 */
static enum jg_packet_result parse_ipv6_extensions(
    struct jg_packet_view *view,
    const struct jg_packet_limits *limits,
    uint8_t first_next_header)
{
    uint8_t next_header = first_next_header;
    size_t cursor = view->network_offset + JG_IPV6_HEADER_SIZE;
    size_t remaining = view->transport_size;
    size_t extension_count = 0U;
    size_t extension_bytes = 0U;

    while (is_ipv6_common_extension(next_header) ||
           next_header == JG_IPPROTO_FRAGMENT || next_header == JG_IPPROTO_AH) {
        size_t extension_size = 0U;

        if (extension_count >= limits->max_ipv6_extensions) {
            return JG_PACKET_LIMIT_EXCEEDED;
        }
        if (remaining < 2U) {
            return JG_PACKET_TRUNCATED;
        }
        if (next_header == JG_IPPROTO_FRAGMENT) {
            uint16_t fragment_field = 0U;

            extension_size = 8U;
            if (remaining < extension_size ||
                !jg_read_u16_be(view->frame, view->frame_size, cursor + 2U,
                                &fragment_field) ||
                !jg_read_u32_be(view->frame, view->frame_size, cursor + 4U,
                                &view->fragment_id)) {
                return JG_PACKET_TRUNCATED;
            }
            if ((fragment_field & UINT16_C(0x0006)) != 0U) {
                return JG_PACKET_MALFORMED;
            }
            view->fragmented = true;
            view->fragment_offset =
                (size_t)((fragment_field & UINT16_C(0xfff8)) >> 3U) * 8U;
            view->more_fragments = (fragment_field & UINT16_C(0x0001)) != 0U;
        } else if (next_header == JG_IPPROTO_AH) {
            extension_size = ((size_t)view->frame[cursor + 1U] + 2U) * 4U;
        } else {
            extension_size = ((size_t)view->frame[cursor + 1U] + 1U) * 8U;
        }
        if (extension_size > remaining) {
            return JG_PACKET_TRUNCATED;
        }
        if (!jg_size_add(extension_bytes, extension_size, &extension_bytes) ||
            extension_bytes > limits->max_ipv6_extension_bytes) {
            return JG_PACKET_LIMIT_EXCEEDED;
        }

        next_header = view->frame[cursor];
        cursor += extension_size;
        remaining -= extension_size;
        ++extension_count;

        if (view->fragmented && view->fragment_offset != 0U) {
            break;
        }
    }

    view->ip_protocol = next_header;
    view->transport_offset = cursor;
    view->transport_size = remaining;
    if (next_header == JG_IPPROTO_ESP) {
        view->transport = JG_TRANSPORT_OTHER;
        view->payload_offset = cursor;
        view->payload_size = remaining;
        view->transport_complete = !view->fragmented || !view->more_fragments;
        return JG_PACKET_OK;
    }
    return parse_transport(view);
}

/**
 * @brief Parse a validated Ethernet payload as IPv6.
 *
 * @param[in,out] view Packet view containing source frame metadata.
 * @param[in] limits Active parser resource limits.
 *
 * @return A packet parser result.
 */
static enum jg_packet_result parse_ipv6(struct jg_packet_view *view,
                                        const struct jg_packet_limits *limits)
{
    size_t available = view->frame_size - view->network_offset;
    uint16_t payload_length = 0U;
    uint8_t next_header = 0U;

    if (available < JG_IPV6_HEADER_SIZE) {
        return JG_PACKET_TRUNCATED;
    }
    if ((view->frame[view->network_offset] >> 4U) != 6U) {
        return JG_PACKET_MALFORMED;
    }
    if (!jg_read_u16_be(view->frame, view->frame_size,
                        view->network_offset + 4U, &payload_length)) {
        return JG_PACKET_TRUNCATED;
    }
    if ((size_t)payload_length > available - JG_IPV6_HEADER_SIZE) {
        return JG_PACKET_TRUNCATED;
    }

    view->ip_version = JG_IP_V6;
    view->address_size = JG_PACKET_ADDRESS_SIZE;
    (void)memcpy(view->source_address, view->frame + view->network_offset + 8U,
                 view->address_size);
    (void)memcpy(view->destination_address,
                 view->frame + view->network_offset + 24U, view->address_size);
    next_header = view->frame[view->network_offset + 6U];
    view->transport_offset = view->network_offset + JG_IPV6_HEADER_SIZE;
    view->transport_size = (size_t)payload_length;
    return parse_ipv6_extensions(view, limits, next_header);
}

/** @brief Initialize conservative parser resource limits. */
void jg_packet_limits_default(struct jg_packet_limits *limits)
{
    if (limits == NULL) {
        return;
    }
    limits->max_vlan_tags = 4U;
    limits->max_ipv6_extensions = 8U;
    limits->max_ipv6_extension_bytes = 2048U;
}

/** @brief Parse a bounded Ethernet frame into a non-owning packet view. */
enum jg_packet_result jg_packet_parse(const uint8_t *frame,
                                      size_t frame_size,
                                      const struct jg_packet_limits *limits,
                                      struct jg_packet_view *view)
{
    struct jg_packet_limits default_limits;
    const struct jg_packet_limits *active_limits = limits;
    size_t cursor = 12U;
    uint16_t ether_type = 0U;
    enum jg_packet_result result = JG_PACKET_MALFORMED;

    if (view == NULL) {
        return JG_PACKET_MALFORMED;
    }
    (void)memset(view, 0, sizeof(*view));
    if (frame == NULL) {
        return JG_PACKET_MALFORMED;
    }
    if (active_limits == NULL) {
        jg_packet_limits_default(&default_limits);
        active_limits = &default_limits;
    }
    if (active_limits->max_vlan_tags > JG_PACKET_VLAN_LIMIT ||
        active_limits->max_ipv6_extensions == 0U ||
        active_limits->max_ipv6_extension_bytes == 0U) {
        return JG_PACKET_MALFORMED;
    }
    if (frame_size < JG_ETHERNET_HEADER_SIZE ||
        !jg_read_u16_be(frame, frame_size, cursor, &ether_type)) {
        return JG_PACKET_TRUNCATED;
    }

    view->frame = frame;
    view->frame_size = frame_size;
    view->ether_type_offset = cursor;
    cursor += 2U;
    while (is_vlan_ether_type(ether_type)) {
        uint16_t tag = 0U;

        if (view->vlan_count >= active_limits->max_vlan_tags) {
            (void)memset(view, 0, sizeof(*view));
            return JG_PACKET_LIMIT_EXCEEDED;
        }
        if (!jg_read_u16_be(frame, frame_size, cursor, &tag) ||
            !jg_read_u16_be(frame, frame_size, cursor + 2U, &ether_type)) {
            (void)memset(view, 0, sizeof(*view));
            return JG_PACKET_TRUNCATED;
        }
        view->vlan_tci[view->vlan_count] = tag;
        ++view->vlan_count;
        view->ether_type_offset = cursor + 2U;
        cursor += JG_VLAN_HEADER_SIZE;
    }
    view->ether_type = ether_type;
    view->network_offset = cursor;

    if (ether_type == JG_ETHERTYPE_IPV4) {
        result = parse_ipv4(view);
    } else if (ether_type == JG_ETHERTYPE_IPV6) {
        result = parse_ipv6(view, active_limits);
    } else {
        return JG_PACKET_NON_IP;
    }
    if (result == JG_PACKET_OK) {
        return result;
    }

    (void)memset(view, 0, sizeof(*view));
    return result;
}
