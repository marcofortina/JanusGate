/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "dns_response.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "janusgate/checked.h"
#include "janusgate/dns.h"

/** Fixed protocol header sizes. */
#define DNS_HEADER_SIZE 12U
#define IPV4_HEADER_SIZE 20U
#define IPV6_HEADER_SIZE 40U
#define UDP_HEADER_SIZE 8U

/** DNS flag and result-code fields used in synthetic responses. */
#define DNS_FLAG_RESPONSE UINT16_C(0x8000)
#define DNS_FLAG_RECURSION_DESIRED UINT16_C(0x0100)
#define DNS_FLAG_RECURSION_AVAILABLE UINT16_C(0x0080)
#define DNS_FLAG_CHECKING_DISABLED UINT16_C(0x0010)
#define DNS_RCODE_NXDOMAIN UINT16_C(3)
#define DNS_RCODE_REFUSED UINT16_C(5)

/** Supported sinkhole resource-record types and class. */
#define DNS_TYPE_A UINT16_C(1)
#define DNS_TYPE_AAAA UINT16_C(28)
#define DNS_CLASS_IN UINT16_C(1)

/** @brief Add bounded bytes to one Internet-checksum accumulator. */
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

/** @brief Fold and complement one Internet-checksum accumulator. */
static uint16_t checksum_finish(uint32_t sum)
{
    while ((sum >> 16U) != 0U) {
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16U);
    }
    return (uint16_t)~sum;
}

/** @brief Encode one normalized policy name in uncompressed DNS form. */
static int encode_name(const char *name,
                       uint8_t *output,
                       size_t output_size,
                       size_t *encoded_size)
{
    const char *label = name;
    size_t cursor = 0U;

    while (*label != '\0') {
        const char *dot = strchr(label, '.');
        const size_t length =
            dot == NULL ? strlen(label) : (size_t)(dot - label);

        if (length == 0U || length > JG_DOMAIN_LABEL_MAX ||
            cursor + 1U + length >= output_size) {
            return -ENOSPC;
        }
        output[cursor] = (uint8_t)length;
        ++cursor;
        (void)memcpy(output + cursor, label, length);
        cursor += length;
        if (dot == NULL) {
            break;
        }
        label = dot + 1;
    }
    if (cursor >= output_size) {
        return -ENOSPC;
    }
    output[cursor] = 0U;
    *encoded_size = cursor + 1U;
    return 0;
}

/** @brief Select the sinkhole address compatible with one DNS question. */
static const uint8_t *sinkhole_address(
    const struct jg_dns_question *question,
    const struct jg_dns_response_config *config,
    size_t *address_size)
{
    if (question->class_code == DNS_CLASS_IN && question->type == DNS_TYPE_A &&
        config->has_ipv4_sinkhole) {
        *address_size = 4U;
        return config->ipv4_sinkhole;
    }
    if (question->class_code == DNS_CLASS_IN &&
        question->type == DNS_TYPE_AAAA && config->has_ipv6_sinkhole) {
        *address_size = 16U;
        return config->ipv6_sinkhole;
    }
    *address_size = 0U;
    return NULL;
}

/** @brief Build the DNS message body and optional sinkhole answer. */
static int build_dns_message(const uint8_t *query,
                             const struct jg_dns_message *parsed,
                             size_t question_index,
                             const struct jg_dns_response_config *config,
                             uint8_t *output,
                             size_t output_size,
                             size_t *message_size)
{
    const struct jg_dns_question *question = &parsed->questions[question_index];
    const uint8_t *address = NULL;
    size_t address_size = 0U;
    size_t answer_name_size = 0U;
    size_t cursor = DNS_HEADER_SIZE + parsed->question_wire_size;
    uint16_t flags = DNS_FLAG_RESPONSE | DNS_FLAG_RECURSION_AVAILABLE |
                     (parsed->flags & (DNS_FLAG_RECURSION_DESIRED |
                                       DNS_FLAG_CHECKING_DISABLED));
    uint16_t answer_count = 0U;

    if (config->action == JG_DNS_BLOCK_REFUSED) {
        flags |= DNS_RCODE_REFUSED;
    } else if (config->action == JG_DNS_BLOCK_NXDOMAIN) {
        flags |= DNS_RCODE_NXDOMAIN;
    } else {
        address = sinkhole_address(question, config, &address_size);
        answer_count = (uint16_t)(address == NULL ? 0U : 1U);
    }
    if (!jg_range_valid(0U, cursor, output_size)) {
        return -ENOSPC;
    }
    (void)memset(output, 0, cursor);
    (void)jg_write_u16_be(output, output_size, 0U, parsed->id);
    (void)jg_write_u16_be(output, output_size, 2U, flags);
    (void)jg_write_u16_be(output, output_size, 4U, parsed->wire_question_count);
    (void)jg_write_u16_be(output, output_size, 6U, answer_count);
    (void)memcpy(output + DNS_HEADER_SIZE, query + DNS_HEADER_SIZE,
                 parsed->question_wire_size);

    if (answer_count != 0U) {
        int result = encode_name(question->name, output + cursor,
                                 output_size - cursor, &answer_name_size);

        if (result != 0) {
            return result;
        }
        cursor += answer_name_size;
        if (!jg_range_valid(cursor, 10U + address_size, output_size)) {
            return -ENOSPC;
        }
        (void)jg_write_u16_be(output, output_size, cursor, question->type);
        (void)jg_write_u16_be(output, output_size, cursor + 2U,
                              question->class_code);
        (void)jg_write_u32_be(output, output_size, cursor + 4U,
                              config->sinkhole_ttl);
        (void)jg_write_u16_be(output, output_size, cursor + 8U,
                              (uint16_t)address_size);
        (void)memcpy(output + cursor + 10U, address, address_size);
        cursor += 10U + address_size;
    }
    *message_size = cursor;
    return 0;
}

/** @brief Copy and reverse the original Ethernet and VLAN envelope. */
static void build_link_header(const struct jg_packet_view *packet,
                              uint8_t *output)
{
    uint8_t client[6U];

    (void)memcpy(output, packet->frame, packet->network_offset);
    (void)memcpy(client, output + 6U, sizeof(client));
    (void)memcpy(output + 6U, output, sizeof(client));
    (void)memcpy(output, client, sizeof(client));
}

/** @brief Build a minimal reversed IPv4 or IPv6 UDP network header. */
static void build_network_header(const struct jg_packet_view *packet,
                                 size_t udp_size,
                                 uint8_t *network)
{
    if (packet->ip_version == JG_IP_V4) {
        (void)memset(network, 0, IPV4_HEADER_SIZE);
        network[0U] = UINT8_C(0x45);
        (void)jg_write_u16_be(network, IPV4_HEADER_SIZE, 2U,
                              (uint16_t)(IPV4_HEADER_SIZE + udp_size));
        network[8U] = 64U;
        network[9U] = (uint8_t)JG_TRANSPORT_UDP;
        (void)memcpy(network + 12U, packet->destination_address, 4U);
        (void)memcpy(network + 16U, packet->source_address, 4U);
        (void)jg_write_u16_be(
            network, IPV4_HEADER_SIZE, 10U,
            checksum_finish(checksum_add(network, IPV4_HEADER_SIZE, 0U)));
    } else {
        (void)memset(network, 0, IPV6_HEADER_SIZE);
        network[0U] = UINT8_C(0x60);
        (void)jg_write_u16_be(network, IPV6_HEADER_SIZE, 4U,
                              (uint16_t)udp_size);
        network[6U] = (uint8_t)JG_TRANSPORT_UDP;
        network[7U] = 64U;
        (void)memcpy(network + 8U, packet->destination_address, 16U);
        (void)memcpy(network + 24U, packet->source_address, 16U);
    }
}

/** @brief Calculate a UDP checksum including its IP pseudo-header. */
static uint16_t udp_checksum(const uint8_t *network,
                             enum jg_ip_version ip_version,
                             size_t udp_size)
{
    const size_t network_size =
        ip_version == JG_IP_V4 ? IPV4_HEADER_SIZE : IPV6_HEADER_SIZE;
    uint32_t sum = 0U;
    uint16_t checksum = 0U;

    if (ip_version == JG_IP_V4) {
        sum = checksum_add(network + 12U, 8U, sum);
    } else {
        sum = checksum_add(network + 8U, 32U, sum);
        sum += (uint32_t)(udp_size >> 16U);
    }
    sum += (uint32_t)udp_size;
    sum += (uint32_t)JG_TRANSPORT_UDP;
    sum = checksum_add(network + network_size, udp_size, sum);
    checksum = checksum_finish(sum);
    return checksum == 0U ? UINT16_MAX : checksum;
}

/** @brief Validate packet metadata required for response construction. */
static bool packet_valid(const struct jg_packet_view *packet)
{
    return packet != NULL && packet->frame != NULL &&
           packet->network_offset >= 14U &&
           packet->transport == JG_TRANSPORT_UDP &&
           packet->ip_protocol == (uint8_t)JG_TRANSPORT_UDP &&
           packet->destination_port == 53U && packet->source_port != 0U &&
           !packet->fragmented && packet->transport_complete &&
           ((packet->ip_version == JG_IP_V4 && packet->address_size == 4U) ||
            (packet->ip_version == JG_IP_V6 &&
             packet->address_size == JG_PACKET_ADDRESS_SIZE)) &&
           jg_range_valid(0U, packet->network_offset, packet->frame_size);
}

/** @brief Initialize explicit-refusal response defaults. */
void jg_dns_response_config_default(struct jg_dns_response_config *config)
{
    if (config == NULL) {
        return;
    }
    (void)memset(config, 0, sizeof(*config));
    config->action = JG_DNS_BLOCK_REFUSED;
    config->checksum_ipv4_udp = true;
    config->sinkhole_ttl = 60U;
}

/** @brief Validate action-specific response configuration. */
int jg_dns_response_config_validate(const struct jg_dns_response_config *config)
{
    if (config == NULL ||
        (config->action != JG_DNS_BLOCK_DROP &&
         config->action != JG_DNS_BLOCK_REFUSED &&
         config->action != JG_DNS_BLOCK_NXDOMAIN &&
         config->action != JG_DNS_BLOCK_SINKHOLE) ||
        (config->action == JG_DNS_BLOCK_SINKHOLE &&
         ((!config->has_ipv4_sinkhole && !config->has_ipv6_sinkhole) ||
          config->sinkhole_ttl == 0U))) {
        return -EINVAL;
    }
    return 0;
}

/** @brief Build one bounded client-facing blocked-query response frame. */
int jg_dns_response_build(const struct jg_packet_view *packet,
                          const uint8_t *query,
                          size_t query_size,
                          size_t question_index,
                          const struct jg_dns_response_config *config,
                          uint8_t *output,
                          size_t output_size,
                          size_t *response_size)
{
    struct jg_dns_message parsed;
    size_t network_size = 0U;
    size_t dns_size = 0U;
    size_t udp_size = 0U;
    size_t complete_size = 0U;
    uint8_t *network = NULL;
    uint8_t *udp = NULL;
    uint8_t *dns = NULL;
    uint16_t checksum = 0U;
    int result = 0;

    if (response_size == NULL) {
        return -EINVAL;
    }
    *response_size = 0U;
    if (query == NULL || output == NULL || !packet_valid(packet) ||
        jg_dns_response_config_validate(config) != 0 ||
        jg_dns_parse_query(query, query_size, &parsed) != JG_DNS_OK ||
        question_index >= parsed.question_count) {
        return -EINVAL;
    }
    if (config->action == JG_DNS_BLOCK_DROP) {
        return 0;
    }

    network_size =
        packet->ip_version == JG_IP_V4 ? IPV4_HEADER_SIZE : IPV6_HEADER_SIZE;
    if (!jg_size_add(packet->network_offset, network_size + UDP_HEADER_SIZE,
                     &complete_size) ||
        complete_size > output_size) {
        return -ENOSPC;
    }
    dns = output + complete_size;
    result = build_dns_message(query, &parsed, question_index, config, dns,
                               output_size - complete_size, &dns_size);
    if (result != 0) {
        return result;
    }
    if (!jg_size_add(UDP_HEADER_SIZE, dns_size, &udp_size) ||
        udp_size > UINT16_MAX ||
        (packet->ip_version == JG_IP_V4 &&
         IPV4_HEADER_SIZE + udp_size > UINT16_MAX) ||
        !jg_size_add(complete_size, dns_size, &complete_size) ||
        complete_size > output_size) {
        return -EMSGSIZE;
    }

    build_link_header(packet, output);
    network = output + packet->network_offset;
    build_network_header(packet, udp_size, network);
    udp = network + network_size;
    (void)memset(udp, 0, UDP_HEADER_SIZE);
    (void)jg_write_u16_be(udp, UDP_HEADER_SIZE, 0U, packet->destination_port);
    (void)jg_write_u16_be(udp, UDP_HEADER_SIZE, 2U, packet->source_port);
    (void)jg_write_u16_be(udp, UDP_HEADER_SIZE, 4U, (uint16_t)udp_size);
    if (packet->ip_version == JG_IP_V6 || config->checksum_ipv4_udp) {
        checksum = udp_checksum(network, packet->ip_version, udp_size);
        (void)jg_write_u16_be(udp, UDP_HEADER_SIZE, 6U, checksum);
    }
    *response_size = complete_size;
    return 0;
}
