/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fragment.h"
#include "janusgate/backup.h"
#include "janusgate/blocklist.h"
#include "janusgate/dns.h"
#include "janusgate/ipc.h"
#include "janusgate/packet.h"
#include "janusgate/tls_client_hello.h"
#include "management.h"
#include "tcp_stream.h"

#ifndef JG_FUZZ_TARGET
#define JG_FUZZ_TARGET 0
#endif

/** Largest input retained by stateful fuzz harnesses. */
#define FUZZ_STATEFUL_INPUT_MAX 4096U

/** LibFuzzer entry point selected independently for each executable. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/** Exercise the complete Ethernet and IP parser. */
static void fuzz_packet(const uint8_t *data, size_t size)
{
    struct jg_packet_view packet;

    (void)jg_packet_parse(data, size, NULL, &packet);
}

/** Place arbitrary extension bytes behind a valid IPv6 Ethernet envelope. */
static void fuzz_ipv6_extensions(const uint8_t *data, size_t size)
{
    const size_t header_size = 14U + 40U;
    uint8_t *frame = NULL;
    struct jg_packet_view packet;

    if (size > UINT16_MAX) {
        return;
    }
    frame = calloc(header_size + size, 1U);
    if (frame == NULL) {
        return;
    }
    frame[12U] = 0x86U;
    frame[13U] = 0xddU;
    frame[14U] = 0x60U;
    frame[18U] = (uint8_t)(size >> 8U);
    frame[19U] = (uint8_t)size;
    frame[20U] = size == 0U ? 59U : data[0U];
    frame[21U] = 64U;
    if (size != 0U) {
        (void)memcpy(frame + header_size, data, size);
    }
    (void)jg_packet_parse(frame, header_size + size, NULL, &packet);
    free(frame);
}

/** Exercise complete DNS query validation. */
static void fuzz_dns(const uint8_t *data, size_t size)
{
    struct jg_dns_message message;

    (void)jg_dns_parse_query(data, size, &message);
}

/** Exercise bounded DNS name decompression at input-selected offsets. */
static void fuzz_dns_name(const uint8_t *data, size_t size)
{
    char name[JG_DOMAIN_NAME_MAX + 1U];
    size_t next_offset = 0U;
    const size_t offset = size == 0U ? 0U : (size_t)data[0U] % size;

    (void)jg_dns_decode_name(data, size, offset, name, sizeof(name),
                             &next_offset);
}

/** Populate a valid TCP packet view borrowing one fuzz buffer. */
static void initialize_tcp_packet(const uint8_t *data,
                                  size_t size,
                                  uint16_t destination_port,
                                  struct jg_packet_view *packet)
{
    size_t index = 0U;

    (void)memset(packet, 0, sizeof(*packet));
    packet->frame = data;
    packet->frame_size = size;
    packet->ip_version = JG_IP_V4;
    packet->ip_protocol = (uint8_t)JG_TRANSPORT_TCP;
    packet->transport = JG_TRANSPORT_TCP;
    packet->address_size = 4U;
    packet->source_port = 49152U;
    packet->destination_port = destination_port;
    packet->tcp_sequence =
        size >= 4U ? ((uint32_t)data[0U] << 24U) | ((uint32_t)data[1U] << 16U) |
                         ((uint32_t)data[2U] << 8U) | (uint32_t)data[3U]
                   : 1U;
    packet->payload_size = size;
    packet->transport_complete = true;
    for (index = 0U; index < packet->address_size; ++index) {
        packet->source_address[index] =
            size == 0U ? (uint8_t)index : data[index % size];
        packet->destination_address[index] =
            size == 0U ? (uint8_t)(index + 4U)
                       : data[(size - 1U - index) % size];
    }
}

/** Exercise DNS-over-TCP length framing with bounded tracker storage. */
static void fuzz_tcp_dns(const uint8_t *data, size_t size)
{
    struct jg_tcp_stream_limits limits;
    struct jg_tcp_stream_tracker *tracker = NULL;
    struct jg_packet_view packet;
    uint8_t output[FUZZ_STATEFUL_INPUT_MAX];
    struct jg_tcp_stream_message messages[8U];
    size_t message_count = 0U;
    enum jg_tcp_stream_result stream_result = JG_TCP_STREAM_MALFORMED;

    if (size > FUZZ_STATEFUL_INPUT_MAX) {
        return;
    }
    jg_tcp_stream_limits_default(&limits);
    limits.max_flows = 4U;
    limits.max_flows_per_source = 4U;
    limits.max_buffered_bytes = sizeof(output);
    limits.max_out_of_order_segments = 8U;
    limits.max_dns_message_size = sizeof(output) - 2U;
    limits.max_messages_per_packet = sizeof(messages) / sizeof(messages[0U]);
    if (jg_tcp_stream_tracker_create(&limits, &tracker) != 0) {
        return;
    }
    initialize_tcp_packet(data, size, 53U, &packet);
    (void)jg_tcp_stream_tracker_add(tracker, &packet, 1U, output,
                                    sizeof(output), messages,
                                    sizeof(messages) / sizeof(messages[0U]),
                                    &message_count, &stream_result);
    jg_tcp_stream_tracker_destroy(tracker);
}

/** Exercise ordered and out-of-order generic TCP segment reconstruction. */
static void fuzz_tcp_reassembly(const uint8_t *data, size_t size)
{
    struct jg_tcp_stream_limits limits;
    struct jg_tcp_stream_tracker *tracker = NULL;
    struct jg_packet_view packet;
    uint8_t output[FUZZ_STATEFUL_INPUT_MAX];
    struct jg_tcp_raw_stream_chunk chunk;
    enum jg_tcp_raw_stream_result stream_result = JG_TCP_RAW_STREAM_BUFFERED;
    size_t split = size / 2U;

    if (size > FUZZ_STATEFUL_INPUT_MAX) {
        return;
    }
    jg_tcp_stream_limits_default(&limits);
    limits.max_flows = 4U;
    limits.max_flows_per_source = 4U;
    limits.max_buffered_bytes = sizeof(output);
    limits.max_out_of_order_segments = 8U;
    if (jg_tcp_stream_tracker_create(&limits, &tracker) != 0) {
        return;
    }
    initialize_tcp_packet(data, size, 853U, &packet);
    packet.payload_offset = split;
    packet.payload_size = size - split;
    packet.tcp_sequence += (uint32_t)split;
    (void)jg_tcp_stream_tracker_add_raw(tracker, &packet, 1U, output,
                                        sizeof(output), &chunk, &stream_result);
    packet.payload_offset = 0U;
    packet.payload_size = split;
    packet.tcp_sequence -= (uint32_t)split;
    (void)jg_tcp_stream_tracker_add_raw(tracker, &packet, 2U, output,
                                        sizeof(output), &chunk, &stream_result);
    jg_tcp_stream_tracker_destroy(tracker);
}

/** Exercise fragment interval accounting and bounded reconstruction. */
static void fuzz_fragments(const uint8_t *data, size_t size)
{
    struct jg_fragment_limits limits;
    struct jg_fragment_tracker *tracker = NULL;
    struct jg_packet_view packet;
    uint8_t output[FUZZ_STATEFUL_INPUT_MAX];
    size_t reassembled_size = 0U;
    enum jg_fragment_result fragment_result = JG_FRAGMENT_MALFORMED;

    if (size == 0U || size > FUZZ_STATEFUL_INPUT_MAX) {
        return;
    }
    jg_fragment_limits_default(&limits);
    limits.max_datagrams = 4U;
    limits.max_datagrams_per_source = 4U;
    limits.max_fragments_per_datagram = 8U;
    limits.max_bytes_per_datagram = sizeof(output);
    if (jg_fragment_tracker_create(&limits, &tracker) != 0) {
        return;
    }
    (void)memset(&packet, 0, sizeof(packet));
    packet.frame = data;
    packet.frame_size = size;
    packet.ip_version = JG_IP_V4;
    packet.address_size = 4U;
    packet.ip_protocol = (uint8_t)JG_TRANSPORT_UDP;
    packet.fragmented = true;
    packet.more_fragments = (data[0U] & 1U) != 0U;
    packet.fragment_id = size > 1U ? data[1U] : 1U;
    packet.fragment_offset =
        size > 2U ? (size_t)(data[2U] & UINT8_C(0x0f)) * 8U : 0U;
    packet.transport_size = size;
    (void)jg_fragment_tracker_add(tracker, &packet, 1U, output, sizeof(output),
                                  &reassembled_size, &fragment_result);
    jg_fragment_tracker_destroy(tracker);
}

/** Exercise incremental ClientHello parsing at changing segment boundaries. */
static void fuzz_tls_client_hello(const uint8_t *data, size_t size)
{
    struct jg_tls_client_hello_parser parser;
    struct jg_tls_client_hello hello;
    size_t offset = 0U;

    jg_tls_client_hello_parser_init(&parser);
    while (offset < size) {
        const size_t remaining = size - offset;
        const size_t chunk =
            remaining < 1U + (size_t)(data[offset] & UINT8_C(0x1f))
                ? remaining
                : 1U + (size_t)(data[offset] & UINT8_C(0x1f));

        (void)jg_tls_client_hello_parser_feed(&parser, data + offset, chunk,
                                              &hello);
        offset += chunk;
    }
    if (size == 0U) {
        (void)jg_tls_client_hello_parser_feed(&parser, NULL, 0U, &hello);
    }
}

/** Exercise one bounded blocklist syntax and release successful imports. */
static void fuzz_blocklist(const uint8_t *data,
                           size_t size,
                           enum jg_blocklist_format format)
{
    struct jg_blocklist_limits limits;
    struct jg_blocklist *blocklist = NULL;

    jg_blocklist_limits_default(&limits);
    limits.max_file_bytes = 65536U;
    limits.max_line_bytes = 4096U;
    limits.max_entries = 1024U;
    (void)jg_blocklist_import(data, size, format, JG_BLOCKLIST_TOLERANT,
                              "fuzz corpus", &limits, &blocklist, NULL);
    jg_blocklist_destroy(blocklist);
}

/** Exercise exact local-control frame decoding. */
static void fuzz_control_protocol(const uint8_t *data, size_t size)
{
    struct jg_ipc_message message;

    (void)jg_ipc_decode(data, size, &message);
}

/** Exercise strict internal REST request-envelope decoding. */
static void fuzz_rest_json(const uint8_t *data, size_t size)
{
    (void)jg_management_request_validate(data, size);
}

/** Exercise backup header, version, bounds, and checksum validation. */
static void fuzz_backup_manifest(const uint8_t *data, size_t size)
{
    struct jg_backup_info info;

    (void)jg_backup_inspect(data, size, &info);
}

/** Select the parser owned by one independently named fuzz executable. */
static void fuzz_selected_target(const uint8_t *data, size_t size)
{
    switch (JG_FUZZ_TARGET) {
    case 1:
        fuzz_packet(data, size);
        break;
    case 2:
        fuzz_ipv6_extensions(data, size);
        break;
    case 3:
        fuzz_dns(data, size);
        break;
    case 4:
        fuzz_dns_name(data, size);
        break;
    case 5:
        fuzz_tcp_dns(data, size);
        break;
    case 6:
        fuzz_tcp_reassembly(data, size);
        break;
    case 7:
        fuzz_fragments(data, size);
        break;
    case 8:
        fuzz_tls_client_hello(data, size);
        break;
    case 9:
        fuzz_blocklist(data, size, JG_BLOCKLIST_FORMAT_DOMAIN);
        break;
    case 10:
        fuzz_blocklist(data, size, JG_BLOCKLIST_FORMAT_HOSTS);
        break;
    case 11:
        fuzz_blocklist(data, size, JG_BLOCKLIST_FORMAT_RPZ);
        break;
    case 12:
        fuzz_control_protocol(data, size);
        break;
    case 13:
        fuzz_rest_json(data, size);
        break;
    case 14:
        fuzz_backup_manifest(data, size);
        break;
    default:
        break;
    }
}

/** @brief Run one bounded production parser under libFuzzer. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_selected_target(data, size);
    return 0;
}
