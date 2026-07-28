/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "dataplane.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "janusgate/checked.h"

/** Ethernet source-address offset and size. */
#define ETHERNET_SOURCE_OFFSET 6U
#define ETHERNET_ADDRESS_SIZE 6U

/** Fixed UDP header bytes. */
#define UDP_HEADER_SIZE 8U

/** Maximum valid IEEE 802.1Q VLAN identifier. */
#define VLAN_ID_MAX 4094U

/** @brief Initialize one conservative result before parsing begins. */
static void initialize_result(struct jg_dataplane_result *result)
{
    (void)memset(result, 0, sizeof(*result));
    result->verdict = JG_NFQUEUE_DROP;
    result->reason = JG_DATAPLANE_MALFORMED;
    result->packet_result = JG_PACKET_MALFORMED;
    result->dns_result = JG_DNS_MALFORMED;
    result->question_index = SIZE_MAX;
}

/** @brief Derive client policy attributes from a validated packet view. */
static int build_client(const struct jg_packet_view *packet,
                        struct jg_policy_client *client)
{
    if (packet == NULL || client == NULL || packet->frame == NULL ||
        packet->frame_size < ETHERNET_SOURCE_OFFSET + ETHERNET_ADDRESS_SIZE ||
        packet->address_size == 0U ||
        packet->address_size > JG_PACKET_ADDRESS_SIZE ||
        packet->vlan_count > JG_PACKET_VLAN_LIMIT) {
        return -EINVAL;
    }
    (void)memset(client, 0, sizeof(*client));
    client->has_mac = true;
    (void)memcpy(client->mac, packet->frame + ETHERNET_SOURCE_OFFSET,
                 ETHERNET_ADDRESS_SIZE);
    if (packet->ip_version == JG_IP_V4) {
        client->address_family = JG_POLICY_ADDRESS_IPV4;
    } else if (packet->ip_version == JG_IP_V6) {
        client->address_family = JG_POLICY_ADDRESS_IPV6;
    }
    (void)memcpy(client->address, packet->source_address, packet->address_size);

    if (packet->vlan_count != 0U) {
        const uint16_t vlan_id =
            packet->vlan_tci[packet->vlan_count - 1U] & UINT16_C(0x0fff);

        if (vlan_id > VLAN_ID_MAX) {
            return -EINVAL;
        }
        client->has_vlan = true;
        client->vlan_id = vlan_id;
    }
    return 0;
}

/** @brief Evaluate packet destination properties before protocol inspection. */
static int evaluate_destination(const struct jg_packet_view *packet,
                                const struct jg_policy_client *client,
                                const struct jg_policy_snapshot *snapshot,
                                struct jg_dataplane_result *result)
{
    struct jg_policy_destination destination = {
        .address_family = packet->ip_version == JG_IP_V4
                              ? JG_POLICY_ADDRESS_IPV4
                              : JG_POLICY_ADDRESS_IPV6,
        .port = packet->destination_port,
    };

    if (packet->transport == JG_TRANSPORT_TCP) {
        destination.transport = JG_POLICY_TRANSPORT_TCP;
    } else if (packet->transport == JG_TRANSPORT_UDP) {
        destination.transport = JG_POLICY_TRANSPORT_UDP;
    }
    (void)memcpy(destination.address, packet->destination_address,
                 packet->address_size);
    if (jg_policy_match_destination(snapshot, &destination, client,
                                    &result->destination_policy) != 0) {
        return -EINVAL;
    }
    if (result->destination_policy.effect == JG_POLICY_BLOCK) {
        result->verdict = JG_NFQUEUE_DROP;
        result->reason = JG_DATAPLANE_POLICY_BLOCK;
    }
    return 0;
}

/** @brief Evaluate every normalized question in one parsed DNS query. */
static int evaluate_dns(const struct jg_dns_message *dns,
                        const struct jg_policy_client *client,
                        const struct jg_policy_snapshot *snapshot,
                        struct jg_dataplane_result *result)
{
    size_t index = 0U;

    for (index = 0U; index < dns->question_count; ++index) {
        struct jg_policy_match match;
        int match_result = jg_policy_match_domain(
            snapshot, dns->questions[index].name, client, &match);

        if (match_result != 0) {
            return match_result;
        }
        if (index == 0U ||
            (match.matched && (!result->policy.matched ||
                               match.source > result->policy.source))) {
            result->question_index = index;
            result->policy = match;
        }
        if (match.effect == JG_POLICY_BLOCK) {
            result->verdict = JG_NFQUEUE_DROP;
            result->reason = JG_DATAPLANE_POLICY_BLOCK;
            result->question_index = index;
            result->policy = match;
            return 0;
        }
    }
    result->verdict = JG_NFQUEUE_ACCEPT;
    result->reason = JG_DATAPLANE_POLICY_ALLOW;
    return 0;
}

/** @brief Parse and evaluate one complete DNS message for a packet client. */
static int evaluate_dns_message(const struct jg_packet_view *packet,
                                const uint8_t *message,
                                size_t message_size,
                                const struct jg_policy_snapshot *snapshot,
                                struct jg_dataplane_result *result)
{
    struct jg_policy_client client;
    struct jg_dns_message dns;
    int evaluation_result = 0;

    if (message == NULL || snapshot == NULL ||
        build_client(packet, &client) != 0) {
        return -EINVAL;
    }
    result->dns_result = jg_dns_parse_query(message, message_size, &dns);
    if (result->dns_result != JG_DNS_OK) {
        return 0;
    }
    evaluation_result = evaluate_dns(&dns, &client, snapshot, result);
    return evaluation_result == 0 ? 0 : -EINVAL;
}

/** @brief Evaluate one complete Ethernet frame without mutable shared state. */
int jg_dataplane_evaluate(const uint8_t *frame,
                          size_t frame_size,
                          const struct jg_packet_limits *limits,
                          const struct jg_policy_snapshot *snapshot,
                          struct jg_dataplane_result *result)
{
    struct jg_policy_client client;
    struct jg_dns_message dns;
    int evaluation_result = 0;

    if (result == NULL) {
        return -EINVAL;
    }
    initialize_result(result);
    if (frame == NULL || snapshot == NULL) {
        return -EINVAL;
    }

    result->packet_result =
        jg_packet_parse(frame, frame_size, limits, &result->packet);
    if (result->packet_result == JG_PACKET_NON_IP) {
        result->verdict = JG_NFQUEUE_ACCEPT;
        result->reason = JG_DATAPLANE_PASS;
        return 0;
    }
    if (result->packet_result != JG_PACKET_OK ||
        build_client(&result->packet, &client) != 0) {
        return 0;
    }
    if (evaluate_destination(&result->packet, &client, snapshot, result) != 0) {
        return -EINVAL;
    }
    if (result->reason == JG_DATAPLANE_POLICY_BLOCK) {
        return 0;
    }
    if (result->packet.fragmented) {
        result->verdict = JG_NFQUEUE_ACCEPT;
        result->reason = JG_DATAPLANE_FRAGMENT_PENDING;
        return 0;
    }
    if (result->packet.transport == JG_TRANSPORT_TCP &&
        (result->packet.destination_port == 53U ||
         result->packet.destination_port == 443U ||
         result->packet.destination_port == 853U)) {
        result->verdict = JG_NFQUEUE_ACCEPT;
        result->reason = JG_DATAPLANE_STREAM_PENDING;
        return 0;
    }
    if (result->packet.transport != JG_TRANSPORT_UDP ||
        result->packet.destination_port != 53U) {
        result->verdict = JG_NFQUEUE_ACCEPT;
        result->reason = JG_DATAPLANE_PASS;
        return 0;
    }
    if (!result->packet.transport_complete) {
        return 0;
    }

    result->dns_result =
        jg_dns_parse_query(frame + result->packet.payload_offset,
                           result->packet.payload_size, &dns);
    if (result->dns_result != JG_DNS_OK) {
        return 0;
    }
    evaluation_result = evaluate_dns(&dns, &client, snapshot, result);
    return evaluation_result == 0 ? 0 : -EINVAL;
}

/** @brief Evaluate a complete UDP payload reconstructed from IP fragments. */
int jg_dataplane_evaluate_reassembled_udp(
    const struct jg_packet_view *packet,
    const uint8_t *payload,
    size_t payload_size,
    const struct jg_policy_snapshot *snapshot,
    struct jg_dataplane_result *result)
{
    struct jg_packet_view packet_copy = {0};
    uint16_t destination_port = 0U;
    uint16_t udp_size = 0U;

    if (result == NULL) {
        return -EINVAL;
    }
    if (packet != NULL) {
        packet_copy = *packet;
    }
    initialize_result(result);
    if (packet == NULL || payload == NULL || snapshot == NULL ||
        !packet_copy.fragmented ||
        packet_copy.ip_protocol != (uint8_t)JG_TRANSPORT_UDP) {
        return -EINVAL;
    }
    result->packet = packet_copy;
    result->packet_result = JG_PACKET_OK;
    if (payload_size < UDP_HEADER_SIZE ||
        !jg_read_u16_be(payload, payload_size, 2U, &destination_port) ||
        !jg_read_u16_be(payload, payload_size, 4U, &udp_size) ||
        (size_t)udp_size != payload_size) {
        return 0;
    }
    if (destination_port != 53U) {
        result->verdict = JG_NFQUEUE_ACCEPT;
        result->reason = JG_DATAPLANE_PASS;
        return 0;
    }
    return evaluate_dns_message(&packet_copy, payload + UDP_HEADER_SIZE,
                                payload_size - UDP_HEADER_SIZE, snapshot,
                                result);
}

/** @brief Evaluate one complete DNS message reconstructed from TCP. */
int jg_dataplane_evaluate_tcp_dns(const struct jg_packet_view *packet,
                                  const uint8_t *message,
                                  size_t message_size,
                                  const struct jg_policy_snapshot *snapshot,
                                  struct jg_dataplane_result *result)
{
    struct jg_packet_view packet_copy = {0};

    if (result == NULL) {
        return -EINVAL;
    }
    if (packet != NULL) {
        packet_copy = *packet;
    }
    initialize_result(result);
    if (packet == NULL || message == NULL || snapshot == NULL ||
        packet_copy.fragmented || packet_copy.transport != JG_TRANSPORT_TCP ||
        packet_copy.ip_protocol != (uint8_t)JG_TRANSPORT_TCP ||
        packet_copy.destination_port != 53U) {
        return -EINVAL;
    }
    result->packet = packet_copy;
    result->packet_result = JG_PACKET_OK;
    return evaluate_dns_message(&packet_copy, message, message_size, snapshot,
                                result);
}

/** @brief Evaluate one visible SNI reconstructed from a selected TCP flow. */
int jg_dataplane_evaluate_visible_sni(const struct jg_packet_view *packet,
                                      const char *server_name,
                                      const struct jg_policy_snapshot *snapshot,
                                      struct jg_dataplane_result *result)
{
    struct jg_packet_view packet_copy = {0};
    struct jg_policy_client client;
    int match_result = 0;

    if (result == NULL) {
        return -EINVAL;
    }
    if (packet != NULL) {
        packet_copy = *packet;
    }
    initialize_result(result);
    if (packet == NULL || server_name == NULL || snapshot == NULL ||
        packet_copy.fragmented || packet_copy.transport != JG_TRANSPORT_TCP ||
        packet_copy.ip_protocol != (uint8_t)JG_TRANSPORT_TCP ||
        (packet_copy.destination_port != 443U &&
         packet_copy.destination_port != 853U) ||
        build_client(&packet_copy, &client) != 0) {
        return -EINVAL;
    }
    result->packet = packet_copy;
    result->packet_result = JG_PACKET_OK;
    match_result = jg_policy_match_visible_sni(snapshot, server_name, &client,
                                               &result->policy);
    if (match_result != 0) {
        return -EINVAL;
    }
    result->verdict = result->policy.effect == JG_POLICY_BLOCK
                          ? JG_NFQUEUE_DROP
                          : JG_NFQUEUE_ACCEPT;
    result->reason = result->policy.effect == JG_POLICY_BLOCK
                         ? JG_DATAPLANE_POLICY_BLOCK
                         : JG_DATAPLANE_POLICY_ALLOW;
    return 0;
}
