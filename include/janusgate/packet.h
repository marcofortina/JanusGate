/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file packet.h
 * @brief Bounded Ethernet, IP, UDP, and TCP packet parsing.
 *
 * A packet view owns no memory and remains valid only while the caller keeps
 * the source frame unchanged. Parsing never writes to the source frame and
 * does not allocate.
 *
 * @thread_safety Parsing is reentrant. A view may be read concurrently while
 * its source frame remains immutable.
 *
 * @error_handling The parser distinguishes truncation, malformed protocol
 * fields, resource limits, and non-IP Ethernet payloads.
 */

#ifndef JANUSGATE_PACKET_H
#define JANUSGATE_PACKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Maximum VLAN tags retained in a parsed packet view. */
#define JG_PACKET_VLAN_LIMIT 8U

/** Maximum bytes in an IPv6 address. */
#define JG_PACKET_ADDRESS_SIZE 16U

/**
 * @brief Packet parser result.
 */
enum jg_packet_result {
    /** Parsing completed and all selected headers are valid. */
    JG_PACKET_OK = 0,
    /** The Ethernet payload is valid but not IPv4 or IPv6. */
    JG_PACKET_NON_IP,
    /** The supplied frame ends before a declared field or header. */
    JG_PACKET_TRUNCATED,
    /** A header contains an invalid version, size, or reserved value. */
    JG_PACKET_MALFORMED,
    /** A configured parser bound was exceeded. */
    JG_PACKET_LIMIT_EXCEEDED
};

/**
 * @brief Parsed network-layer protocol.
 */
enum jg_ip_version {
    /** No IP header was parsed. */
    JG_IP_NONE = 0,
    /** Internet Protocol version 4. */
    JG_IP_V4 = 4,
    /** Internet Protocol version 6. */
    JG_IP_V6 = 6
};

/**
 * @brief Parsed transport protocol.
 */
enum jg_transport_protocol {
    /** Transport parsing was not applicable or not possible. */
    JG_TRANSPORT_NONE = 0,
    /** User Datagram Protocol. */
    JG_TRANSPORT_UDP = 17,
    /** Transmission Control Protocol. */
    JG_TRANSPORT_TCP = 6,
    /** A protocol other than UDP or TCP. */
    JG_TRANSPORT_OTHER = 255
};

/**
 * @brief Configurable parser resource bounds.
 */
struct jg_packet_limits {
    /** Maximum accepted stacked VLAN tags, from 0 through JG_PACKET_VLAN_LIMIT.
     */
    size_t max_vlan_tags;
    /** Maximum IPv6 extension headers examined. */
    size_t max_ipv6_extensions;
    /** Maximum aggregate bytes occupied by IPv6 extension headers. */
    size_t max_ipv6_extension_bytes;
};

/**
 * @brief Non-owning view of a validated frame.
 */
struct jg_packet_view {
    /** Original immutable Ethernet frame. */
    const uint8_t *frame;
    /** Number of bytes available in @ref frame. */
    size_t frame_size;
    /** Offset of the final network-layer EtherType field. */
    size_t ether_type_offset;
    /** Final host-order EtherType after stacked VLAN headers. */
    uint16_t ether_type;
    /** Number of parsed VLAN tags. */
    size_t vlan_count;
    /** Host-order tag control information, outermost first. */
    uint16_t vlan_tci[JG_PACKET_VLAN_LIMIT];
    /** Offset of the first IP header byte. */
    size_t network_offset;
    /** Parsed IP version. */
    enum jg_ip_version ip_version;
    /** Source address in network byte order; IPv4 occupies the first four
     * bytes. */
    uint8_t source_address[JG_PACKET_ADDRESS_SIZE];
    /** Destination address in network byte order; IPv4 occupies the first four
     * bytes. */
    uint8_t destination_address[JG_PACKET_ADDRESS_SIZE];
    /** Number of significant bytes in each address. */
    size_t address_size;
    /** Host-order IPv4 identification or IPv6 fragment identification. */
    uint32_t fragment_id;
    /** Fragment payload offset in bytes. */
    size_t fragment_offset;
    /** Whether the datagram indicates additional fragments. */
    bool more_fragments;
    /** Whether an IPv4 or IPv6 fragment header was observed. */
    bool fragmented;
    /** Network-layer next-header or protocol value after extension traversal.
     */
    uint8_t ip_protocol;
    /** Offset of the transport header or opaque fragment payload. */
    size_t transport_offset;
    /** Bytes available from @ref transport_offset within the IP packet. */
    size_t transport_size;
    /** Parsed transport type. */
    enum jg_transport_protocol transport;
    /** Source UDP or TCP port in host order. */
    uint16_t source_port;
    /** Destination UDP or TCP port in host order. */
    uint16_t destination_port;
    /** Host-order TCP sequence number. */
    uint32_t tcp_sequence;
    /** Host-order TCP acknowledgement number. */
    uint32_t tcp_acknowledgement;
    /** TCP control flags byte. */
    uint8_t tcp_flags;
    /** Offset of UDP or TCP application payload. */
    size_t payload_offset;
    /** Application payload bytes present in this frame. */
    size_t payload_size;
    /** Whether the declared transport payload is complete in this frame. */
    bool transport_complete;
};

/**
 * @brief Initialize conservative packet parser limits.
 *
 * Defaults accept four stacked VLAN tags, eight IPv6 extension headers, and
 * 2048 aggregate IPv6 extension bytes.
 *
 * @param[out] limits Limits structure to initialize. A null pointer is ignored.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC void jg_packet_limits_default(struct jg_packet_limits *limits);

/**
 * @brief Parse a complete captured Ethernet frame.
 *
 * @param[in] frame Immutable frame bytes.
 * @param[in] frame_size Number of available bytes in @p frame.
 * @param[in] limits Resource bounds. Null selects conservative defaults.
 * @param[out] view Packet view populated on success or non-IP return.
 *
 * @return JG_PACKET_OK for a valid IP packet.
 * @return JG_PACKET_NON_IP for a valid non-IP Ethernet frame.
 * @return JG_PACKET_TRUNCATED when bytes required by a header are absent.
 * @return JG_PACKET_MALFORMED for an invalid protocol field.
 * @return JG_PACKET_LIMIT_EXCEEDED when a configured bound is crossed.
 *
 * @thread_safety This function is reentrant and has no global state.
 *
 * @side_effects On any error, @p view is cleared before returning.
 */
JG_PUBLIC enum jg_packet_result jg_packet_parse(
    const uint8_t *frame,
    size_t frame_size,
    const struct jg_packet_limits *limits,
    struct jg_packet_view *view);

#endif
