/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/network.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "janusgate/checked.h"

/** Version of the fixed network-configuration body. */
#define NETWORK_CONFIG_VERSION 1U

/** Version of the fixed helper-state body. */
#define NETWORK_STATE_VERSION 1U

/** Boolean configuration flags in the fixed body. */
enum network_flag {
    NETWORK_FLAG_STP = 1U << 0U,
    NETWORK_FLAG_MULTICAST_SNOOPING = 1U << 1U,
    NETWORK_FLAG_CPU_FANOUT = 1U << 2U,
    NETWORK_FLAG_ALL = NETWORK_FLAG_STP | NETWORK_FLAG_MULTICAST_SNOOPING |
                       NETWORK_FLAG_CPU_FANOUT
};

/** Field offsets in the version-one configuration body. */
enum network_offset {
    VERSION_OFFSET = 0,
    FLAGS_OFFSET = 2,
    FAILURE_MODE_OFFSET = 4,
    QUEUE_FIRST_OFFSET = 6,
    QUEUE_COUNT_OFFSET = 8,
    RESERVED_OFFSET = 10,
    BRIDGE_MTU_OFFSET = 12,
    QUEUE_LENGTH_OFFSET = 16,
    BRIDGE_NAME_OFFSET = 20,
    INGRESS_NAME_OFFSET = 36,
    EGRESS_NAME_OFFSET = 52,
    MANAGEMENT_NAME_OFFSET = 68
};

/** Presence flags in the fixed helper-state body. */
enum network_state_flag {
    NETWORK_STATE_HAS_CONFIRMED = 1U << 0U,
    NETWORK_STATE_HAS_PENDING = 1U << 1U,
    NETWORK_STATE_FLAG_ALL =
        NETWORK_STATE_HAS_CONFIRMED | NETWORK_STATE_HAS_PENDING
};

/** Field offsets in the version-one helper-state body. */
enum network_state_offset {
    STATE_VERSION_OFFSET = 0,
    STATE_FLAGS_OFFSET = 2,
    STATE_REMAINING_OFFSET = 4,
    STATE_CONFIRMED_OFFSET = 8,
    STATE_PENDING_OFFSET = STATE_CONFIRMED_OFFSET + JG_NETWORK_CONFIG_WIRE_SIZE
};

/** @brief Determine whether one byte is allowed in an interface name. */
static bool interface_character_valid(char character)
{
    return (character >= 'a' && character <= 'z') ||
           (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9') || character == '_' ||
           character == '-' || character == '.';
}

/** @brief Validate one bounded, null-terminated interface name. */
static bool interface_name_valid(const char *name)
{
    size_t length = 0U;

    if (name == NULL || !((name[0] >= 'a' && name[0] <= 'z') ||
                          (name[0] >= 'A' && name[0] <= 'Z') ||
                          (name[0] >= '0' && name[0] <= '9'))) {
        return false;
    }
    while (length <= JG_INTERFACE_NAME_MAX && name[length] != '\0') {
        if (!interface_character_valid(name[length])) {
            return false;
        }
        ++length;
    }
    return length > 0U && length <= JG_INTERFACE_NAME_MAX;
}

/** @brief Validate a complete inline-network configuration. */
int jg_network_config_validate(const struct jg_network_config *config)
{
    uint32_t queue_end = 0U;

    if (config == NULL || !interface_name_valid(config->bridge) ||
        !interface_name_valid(config->ingress) ||
        !interface_name_valid(config->egress) ||
        !interface_name_valid(config->management) ||
        strcmp(config->bridge, config->ingress) == 0 ||
        strcmp(config->bridge, config->egress) == 0 ||
        strcmp(config->bridge, config->management) == 0 ||
        strcmp(config->ingress, config->egress) == 0 ||
        strcmp(config->ingress, config->management) == 0 ||
        strcmp(config->egress, config->management) == 0 ||
        (config->failure_mode != JG_NETWORK_FAIL_OPEN &&
         config->failure_mode != JG_NETWORK_FAIL_CLOSED)) {
        return -EINVAL;
    }
    queue_end = (uint32_t)config->queue_first + (uint32_t)config->queue_count;
    if ((config->bridge_mtu != 0U &&
         (config->bridge_mtu < 1280U || config->bridge_mtu > 65535U)) ||
        config->queue_count == 0U ||
        config->queue_count > JG_NETWORK_QUEUE_COUNT_MAX ||
        queue_end > 65536U || config->queue_length == 0U ||
        config->queue_length > JG_NETWORK_QUEUE_LENGTH_MAX) {
        return -ERANGE;
    }
    return 0;
}

/** @brief Copy one validated name into a canonical fixed-width slot. */
static void encode_name(uint8_t *output, size_t offset, const char *name)
{
    (void)memcpy(output + offset, name, strlen(name));
}

/** @brief Encode a validated configuration into its stable binary body. */
int jg_network_config_encode(const struct jg_network_config *config,
                             uint8_t *output,
                             size_t output_size,
                             size_t *encoded_size)
{
    uint16_t flags = 0U;
    int result = 0;

    if (output == NULL || encoded_size == NULL) {
        return -EINVAL;
    }
    result = jg_network_config_validate(config);
    if (result != 0) {
        return result;
    }
    if (output_size < JG_NETWORK_CONFIG_WIRE_SIZE) {
        return -ENOSPC;
    }
    if (config->stp) {
        flags |= NETWORK_FLAG_STP;
    }
    if (config->multicast_snooping) {
        flags |= NETWORK_FLAG_MULTICAST_SNOOPING;
    }
    if (config->queue_cpu_fanout) {
        flags |= NETWORK_FLAG_CPU_FANOUT;
    }

    (void)memset(output, 0, JG_NETWORK_CONFIG_WIRE_SIZE);
    (void)jg_write_u16_be(output, output_size, VERSION_OFFSET,
                          NETWORK_CONFIG_VERSION);
    (void)jg_write_u16_be(output, output_size, FLAGS_OFFSET, flags);
    (void)jg_write_u16_be(output, output_size, FAILURE_MODE_OFFSET,
                          (uint16_t)config->failure_mode);
    (void)jg_write_u16_be(output, output_size, QUEUE_FIRST_OFFSET,
                          config->queue_first);
    (void)jg_write_u16_be(output, output_size, QUEUE_COUNT_OFFSET,
                          config->queue_count);
    (void)jg_write_u32_be(output, output_size, BRIDGE_MTU_OFFSET,
                          config->bridge_mtu);
    (void)jg_write_u32_be(output, output_size, QUEUE_LENGTH_OFFSET,
                          config->queue_length);
    encode_name(output, BRIDGE_NAME_OFFSET, config->bridge);
    encode_name(output, INGRESS_NAME_OFFSET, config->ingress);
    encode_name(output, EGRESS_NAME_OFFSET, config->egress);
    encode_name(output, MANAGEMENT_NAME_OFFSET, config->management);
    *encoded_size = JG_NETWORK_CONFIG_WIRE_SIZE;
    return 0;
}

/** @brief Decode one canonical fixed-width interface-name slot. */
static bool decode_name(const uint8_t *data, size_t offset, char *name)
{
    size_t length = 0U;

    while (length <= JG_INTERFACE_NAME_MAX && data[offset + length] != '\0') {
        ++length;
    }
    if (length == 0U || length > JG_INTERFACE_NAME_MAX) {
        return false;
    }
    for (size_t index = length + 1U; index <= JG_INTERFACE_NAME_MAX; ++index) {
        if (data[offset + index] != 0U) {
            return false;
        }
    }
    (void)memcpy(name, data + offset, JG_INTERFACE_NAME_MAX + 1U);
    return interface_name_valid(name);
}

/** @brief Decode and validate one stable binary network configuration. */
int jg_network_config_decode(const uint8_t *data,
                             size_t data_size,
                             struct jg_network_config *config)
{
    struct jg_network_config decoded;
    uint32_t bridge_mtu = 0U;
    uint32_t queue_length = 0U;
    uint16_t version = 0U;
    uint16_t flags = 0U;
    uint16_t failure_mode = 0U;
    uint16_t queue_first = 0U;
    uint16_t queue_count = 0U;
    uint16_t reserved = 0U;
    int result = 0;

    if (data == NULL || config == NULL) {
        return -EINVAL;
    }
    if (data_size != JG_NETWORK_CONFIG_WIRE_SIZE) {
        return -EMSGSIZE;
    }
    if (!jg_read_u16_be(data, data_size, VERSION_OFFSET, &version) ||
        !jg_read_u16_be(data, data_size, FLAGS_OFFSET, &flags) ||
        !jg_read_u16_be(data, data_size, FAILURE_MODE_OFFSET, &failure_mode) ||
        !jg_read_u16_be(data, data_size, QUEUE_FIRST_OFFSET, &queue_first) ||
        !jg_read_u16_be(data, data_size, QUEUE_COUNT_OFFSET, &queue_count) ||
        !jg_read_u16_be(data, data_size, RESERVED_OFFSET, &reserved) ||
        !jg_read_u32_be(data, data_size, BRIDGE_MTU_OFFSET, &bridge_mtu) ||
        !jg_read_u32_be(data, data_size, QUEUE_LENGTH_OFFSET, &queue_length)) {
        return -EPROTO;
    }
    if (version != NETWORK_CONFIG_VERSION) {
        return -EPROTONOSUPPORT;
    }
    if ((flags & (uint16_t)~NETWORK_FLAG_ALL) != 0U || reserved != 0U) {
        return -EPROTO;
    }

    (void)memset(&decoded, 0, sizeof(decoded));
    if (!decode_name(data, BRIDGE_NAME_OFFSET, decoded.bridge) ||
        !decode_name(data, INGRESS_NAME_OFFSET, decoded.ingress) ||
        !decode_name(data, EGRESS_NAME_OFFSET, decoded.egress) ||
        !decode_name(data, MANAGEMENT_NAME_OFFSET, decoded.management)) {
        return -EPROTO;
    }
    decoded.bridge_mtu = bridge_mtu;
    decoded.queue_first = queue_first;
    decoded.queue_count = queue_count;
    decoded.queue_length = queue_length;
    decoded.failure_mode = (enum jg_network_failure_mode)failure_mode;
    decoded.stp = (flags & NETWORK_FLAG_STP) != 0U;
    decoded.multicast_snooping =
        (flags & NETWORK_FLAG_MULTICAST_SNOOPING) != 0U;
    decoded.queue_cpu_fanout = (flags & NETWORK_FLAG_CPU_FANOUT) != 0U;
    result = jg_network_config_validate(&decoded);
    if (result != 0) {
        return result;
    }
    *config = decoded;
    return 0;
}

/** @brief Determine whether one exact byte range is canonically zero. */
static bool bytes_are_zero(const uint8_t *data, size_t size)
{
    for (size_t index = 0U; index < size; ++index) {
        if (data[index] != 0U) {
            return false;
        }
    }
    return true;
}

/** @brief Encode one canonical confirmed and pending helper state. */
int jg_network_state_encode(const struct jg_network_state *state,
                            uint8_t *output,
                            size_t output_size,
                            size_t *encoded_size)
{
    size_t config_size = 0U;
    uint16_t flags = 0U;
    int result = 0;

    if (state == NULL || output == NULL || encoded_size == NULL ||
        (!state->pending && state->confirmation_seconds_remaining != 0U)) {
        return -EINVAL;
    }
    if (output_size < JG_NETWORK_STATE_WIRE_SIZE) {
        return -ENOSPC;
    }
    if (state->has_confirmed) {
        result = jg_network_config_validate(&state->confirmed);
        flags |= NETWORK_STATE_HAS_CONFIRMED;
    }
    if (result == 0 && state->pending) {
        result = jg_network_config_validate(&state->pending_config);
        flags |= NETWORK_STATE_HAS_PENDING;
    }
    if (result != 0) {
        return result;
    }
    (void)memset(output, 0, JG_NETWORK_STATE_WIRE_SIZE);
    (void)jg_write_u16_be(output, output_size, STATE_VERSION_OFFSET,
                          NETWORK_STATE_VERSION);
    (void)jg_write_u16_be(output, output_size, STATE_FLAGS_OFFSET, flags);
    (void)jg_write_u32_be(output, output_size, STATE_REMAINING_OFFSET,
                          state->confirmation_seconds_remaining);
    if (state->has_confirmed) {
        result = jg_network_config_encode(
            &state->confirmed, output + STATE_CONFIRMED_OFFSET,
            JG_NETWORK_CONFIG_WIRE_SIZE, &config_size);
    }
    if (result == 0 && state->pending) {
        result = jg_network_config_encode(
            &state->pending_config, output + STATE_PENDING_OFFSET,
            JG_NETWORK_CONFIG_WIRE_SIZE, &config_size);
    }
    if (result == 0 && config_size != JG_NETWORK_CONFIG_WIRE_SIZE &&
        (state->has_confirmed || state->pending)) {
        result = -EIO;
    }
    if (result == 0) {
        *encoded_size = JG_NETWORK_STATE_WIRE_SIZE;
    }
    return result;
}

/** @brief Decode one canonical confirmed and pending helper state. */
int jg_network_state_decode(const uint8_t *data,
                            size_t data_size,
                            struct jg_network_state *state)
{
    struct jg_network_state decoded;
    uint32_t remaining = 0U;
    uint16_t version = 0U;
    uint16_t flags = 0U;
    int result = 0;

    if (data == NULL || state == NULL) {
        return -EINVAL;
    }
    if (data_size != JG_NETWORK_STATE_WIRE_SIZE) {
        return -EMSGSIZE;
    }
    if (!jg_read_u16_be(data, data_size, STATE_VERSION_OFFSET, &version) ||
        !jg_read_u16_be(data, data_size, STATE_FLAGS_OFFSET, &flags) ||
        !jg_read_u32_be(data, data_size, STATE_REMAINING_OFFSET, &remaining)) {
        return -EPROTO;
    }
    if (version != NETWORK_STATE_VERSION) {
        return -EPROTONOSUPPORT;
    }
    if ((flags & (uint16_t)~NETWORK_STATE_FLAG_ALL) != 0U ||
        ((flags & NETWORK_STATE_HAS_PENDING) == 0U && remaining != 0U)) {
        return -EPROTO;
    }
    (void)memset(&decoded, 0, sizeof(decoded));
    decoded.has_confirmed = (flags & NETWORK_STATE_HAS_CONFIRMED) != 0U;
    decoded.pending = (flags & NETWORK_STATE_HAS_PENDING) != 0U;
    decoded.confirmation_seconds_remaining = remaining;
    if (decoded.has_confirmed) {
        result = jg_network_config_decode(data + STATE_CONFIRMED_OFFSET,
                                          JG_NETWORK_CONFIG_WIRE_SIZE,
                                          &decoded.confirmed);
    } else if (!bytes_are_zero(data + STATE_CONFIRMED_OFFSET,
                               JG_NETWORK_CONFIG_WIRE_SIZE)) {
        result = -EPROTO;
    }
    if (result == 0 && decoded.pending) {
        result = jg_network_config_decode(data + STATE_PENDING_OFFSET,
                                          JG_NETWORK_CONFIG_WIRE_SIZE,
                                          &decoded.pending_config);
    } else if (result == 0 && !bytes_are_zero(data + STATE_PENDING_OFFSET,
                                              JG_NETWORK_CONFIG_WIRE_SIZE)) {
        result = -EPROTO;
    }
    if (result == 0) {
        *state = decoded;
    }
    return result;
}
