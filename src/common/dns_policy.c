/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/dns_policy.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "janusgate/checked.h"

/** Version of the fixed response-policy body. */
#define RESPONSE_CONFIG_VERSION 1U

/** Canonical response-policy boolean flags. */
enum response_config_flag {
    RESPONSE_CONFIG_IPV4 = 1U << 0U,
    RESPONSE_CONFIG_IPV6 = 1U << 1U,
    RESPONSE_CONFIG_IPV4_CHECKSUM = 1U << 2U,
    RESPONSE_CONFIG_FLAG_ALL = RESPONSE_CONFIG_IPV4 | RESPONSE_CONFIG_IPV6 |
                               RESPONSE_CONFIG_IPV4_CHECKSUM
};

/** Field offsets in the version-one response-policy body. */
enum response_config_offset {
    RESPONSE_VERSION_OFFSET = 0,
    RESPONSE_ACTION_OFFSET = 2,
    RESPONSE_FLAGS_OFFSET = 4,
    RESPONSE_RESERVED_OFFSET = 6,
    RESPONSE_TTL_OFFSET = 8,
    RESPONSE_IPV4_OFFSET = 12,
    RESPONSE_IPV6_OFFSET = 16
};

/** @brief Test whether one disabled address field is canonically empty. */
static bool bytes_empty(const uint8_t *bytes, size_t size)
{
    size_t index = 0U;

    for (index = 0U; index < size; ++index) {
        if (bytes[index] != 0U) {
            return false;
        }
    }
    return true;
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
        (!config->has_ipv4_sinkhole &&
         !bytes_empty(config->ipv4_sinkhole, sizeof(config->ipv4_sinkhole))) ||
        (!config->has_ipv6_sinkhole &&
         !bytes_empty(config->ipv6_sinkhole, sizeof(config->ipv6_sinkhole))) ||
        (config->action == JG_DNS_BLOCK_SINKHOLE &&
         ((!config->has_ipv4_sinkhole && !config->has_ipv6_sinkhole) ||
          config->sinkhole_ttl == 0U))) {
        return -EINVAL;
    }
    return 0;
}

/** @brief Encode one validated fixed response-policy body. */
int jg_dns_response_config_encode(const struct jg_dns_response_config *config,
                                  uint8_t *output,
                                  size_t output_size,
                                  size_t *encoded_size)
{
    uint16_t flags = 0U;

    if (output == NULL || encoded_size == NULL ||
        jg_dns_response_config_validate(config) != 0) {
        return -EINVAL;
    }
    if (output_size < JG_DNS_RESPONSE_CONFIG_WIRE_SIZE) {
        return -ENOSPC;
    }
    if (config->has_ipv4_sinkhole) {
        flags |= RESPONSE_CONFIG_IPV4;
    }
    if (config->has_ipv6_sinkhole) {
        flags |= RESPONSE_CONFIG_IPV6;
    }
    if (config->checksum_ipv4_udp) {
        flags |= RESPONSE_CONFIG_IPV4_CHECKSUM;
    }

    (void)memset(output, 0, JG_DNS_RESPONSE_CONFIG_WIRE_SIZE);
    (void)jg_write_u16_be(output, output_size, RESPONSE_VERSION_OFFSET,
                          RESPONSE_CONFIG_VERSION);
    (void)jg_write_u16_be(output, output_size, RESPONSE_ACTION_OFFSET,
                          (uint16_t)config->action);
    (void)jg_write_u16_be(output, output_size, RESPONSE_FLAGS_OFFSET, flags);
    (void)jg_write_u32_be(output, output_size, RESPONSE_TTL_OFFSET,
                          config->sinkhole_ttl);
    (void)memcpy(output + RESPONSE_IPV4_OFFSET, config->ipv4_sinkhole,
                 sizeof(config->ipv4_sinkhole));
    (void)memcpy(output + RESPONSE_IPV6_OFFSET, config->ipv6_sinkhole,
                 sizeof(config->ipv6_sinkhole));
    *encoded_size = JG_DNS_RESPONSE_CONFIG_WIRE_SIZE;
    return 0;
}

/** @brief Decode one canonical fixed response-policy body. */
int jg_dns_response_config_decode(const uint8_t *data,
                                  size_t data_size,
                                  struct jg_dns_response_config *config)
{
    struct jg_dns_response_config decoded;
    uint32_t ttl = 0U;
    uint16_t version = 0U;
    uint16_t action = 0U;
    uint16_t flags = 0U;
    uint16_t reserved = 0U;

    if (data == NULL || config == NULL) {
        return -EINVAL;
    }
    if (data_size != JG_DNS_RESPONSE_CONFIG_WIRE_SIZE) {
        return -EMSGSIZE;
    }
    if (!jg_read_u16_be(data, data_size, RESPONSE_VERSION_OFFSET, &version) ||
        !jg_read_u16_be(data, data_size, RESPONSE_ACTION_OFFSET, &action) ||
        !jg_read_u16_be(data, data_size, RESPONSE_FLAGS_OFFSET, &flags) ||
        !jg_read_u16_be(data, data_size, RESPONSE_RESERVED_OFFSET, &reserved) ||
        !jg_read_u32_be(data, data_size, RESPONSE_TTL_OFFSET, &ttl)) {
        return -EPROTO;
    }
    if (version != RESPONSE_CONFIG_VERSION) {
        return -EPROTONOSUPPORT;
    }
    if ((flags & (uint16_t)~RESPONSE_CONFIG_FLAG_ALL) != 0U || reserved != 0U) {
        return -EPROTO;
    }

    (void)memset(&decoded, 0, sizeof(decoded));
    decoded.action = (enum jg_dns_block_action)action;
    decoded.has_ipv4_sinkhole = (flags & RESPONSE_CONFIG_IPV4) != 0U;
    decoded.has_ipv6_sinkhole = (flags & RESPONSE_CONFIG_IPV6) != 0U;
    decoded.checksum_ipv4_udp = (flags & RESPONSE_CONFIG_IPV4_CHECKSUM) != 0U;
    decoded.sinkhole_ttl = ttl;
    (void)memcpy(decoded.ipv4_sinkhole, data + RESPONSE_IPV4_OFFSET,
                 sizeof(decoded.ipv4_sinkhole));
    (void)memcpy(decoded.ipv6_sinkhole, data + RESPONSE_IPV6_OFFSET,
                 sizeof(decoded.ipv6_sinkhole));
    if (jg_dns_response_config_validate(&decoded) != 0) {
        return -EINVAL;
    }
    *config = decoded;
    return 0;
}
