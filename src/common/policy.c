/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/policy.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#include "janusgate/checked.h"
#include "janusgate/domain.h"

/** Rule representation used only while constructing a snapshot. */
struct build_rule {
    uint64_t id;
    char *domain;
    char *attribution;
    bool include_subdomains;
    enum jg_policy_effect effect;
    enum jg_policy_source source;
    enum jg_policy_domain_target target;
    struct jg_policy_scope scope;
};

/** Destination-rule representation used while constructing a snapshot. */
struct build_destination_rule {
    uint64_t id;
    char *attribution;
    enum jg_policy_effect effect;
    enum jg_policy_source source;
    enum jg_policy_transport transport;
    bool has_address;
    enum jg_policy_address_family address_family;
    uint8_t address[16U];
    uint8_t prefix_length;
    bool has_port;
    uint16_t port;
    struct jg_policy_scope scope;
};

/** Compact rule representation retained by an immutable snapshot. */
struct stored_rule {
    uint64_t id;
    uint32_t domain_offset;
    uint32_t attribution_offset;
    uint8_t priority;
    bool include_subdomains;
    enum jg_policy_effect effect;
    enum jg_policy_source source;
    enum jg_policy_domain_target target;
    struct jg_policy_scope scope;
};

/** Compact destination rule retained by an immutable snapshot. */
struct stored_destination_rule {
    uint64_t id;
    uint32_t attribution_offset;
    uint8_t priority;
    enum jg_policy_effect effect;
    enum jg_policy_source source;
    enum jg_policy_transport transport;
    bool has_address;
    enum jg_policy_address_family address_family;
    uint8_t address[16U];
    uint8_t prefix_length;
    bool has_port;
    uint16_t port;
    struct jg_policy_scope scope;
};

/** One occupied or empty open-addressing table slot. */
struct policy_slot {
    uint64_t hash;
    uint32_t first_rule;
    uint32_t rule_count;
    bool occupied;
};

/** Private immutable snapshot layout. */
struct jg_policy_snapshot {
    struct jg_policy_snapshot_info info;
    struct stored_rule *rules;
    char *strings;
    struct stored_destination_rule *destination_rules;
    char *destination_strings;
    struct policy_slot *table;
    size_t table_capacity;
    uint8_t hash_key[crypto_shorthash_KEYBYTES];
};

/**
 * @brief Measure a string while enforcing a small public-input bound.
 *
 * @return Zero on success or -EINVAL for a null, empty, overlong, or
 * control-character-containing string.
 */
static int attribution_length(const char *value, size_t *length)
{
    size_t index = 0U;

    if (value == NULL || length == NULL) {
        return -EINVAL;
    }
    for (index = 0U; index <= JG_POLICY_ATTRIBUTION_MAX; ++index) {
        const uint8_t byte = (uint8_t)value[index];

        if (byte == 0U) {
            if (index == 0U) {
                return -EINVAL;
            }
            *length = index;
            return 0;
        }
        if (byte < UINT8_C(0x20) || byte == UINT8_C(0x7f)) {
            return -EINVAL;
        }
    }
    return -EINVAL;
}

/** @brief Validate one rule action against its declared source. */
static bool effect_source_valid(enum jg_policy_effect effect,
                                enum jg_policy_source source)
{
    if (effect != JG_POLICY_ALLOW && effect != JG_POLICY_BLOCK) {
        return false;
    }
    switch (source) {
    case JG_POLICY_SOURCE_BLOCKLIST:
        return effect == JG_POLICY_BLOCK;
    case JG_POLICY_SOURCE_EXPLICIT:
        return true;
    case JG_POLICY_SOURCE_EMERGENCY:
        return effect == JG_POLICY_ALLOW;
    case JG_POLICY_SOURCE_DEFAULT:
    default:
        return false;
    }
}

/** @brief Validate a domain rule class and matching target. */
static bool rule_class_valid(const struct jg_policy_rule_input *rule)
{
    if (!effect_source_valid(rule->effect, rule->source)) {
        return false;
    }
    if (rule->target != JG_POLICY_DOMAIN_DNS &&
        rule->target != JG_POLICY_DOMAIN_TLS_SNI) {
        return false;
    }
    if (rule->target == JG_POLICY_DOMAIN_TLS_SNI &&
        rule->source != JG_POLICY_SOURCE_EXPLICIT) {
        return false;
    }
    return true;
}

/**
 * @brief Copy and mask a scope into its canonical representation.
 */
static int scope_normalize(const struct jg_policy_scope *input,
                           struct jg_policy_scope *output)
{
    size_t address_size = 0U;
    size_t complete_bytes = 0U;
    size_t first_clear_byte = 0U;
    uint8_t remaining_bits = 0U;

    if (input == NULL || output == NULL) {
        return -EINVAL;
    }
    (void)memset(output, 0, sizeof(*output));
    output->type = input->type;

    switch (input->type) {
    case JG_POLICY_SCOPE_GLOBAL:
        return 0;
    case JG_POLICY_SCOPE_MAC:
        (void)memcpy(output->value.mac, input->value.mac,
                     sizeof(output->value.mac));
        return 0;
    case JG_POLICY_SCOPE_IPV4:
        address_size = 4U;
        if (input->value.network.prefix_length > 32U) {
            return -EINVAL;
        }
        break;
    case JG_POLICY_SCOPE_IPV6:
        address_size = 16U;
        if (input->value.network.prefix_length > 128U) {
            return -EINVAL;
        }
        break;
    case JG_POLICY_SCOPE_VLAN:
        if (input->value.vlan_id > 4094U) {
            return -EINVAL;
        }
        output->value.vlan_id = input->value.vlan_id;
        return 0;
    default:
        return -EINVAL;
    }

    output->value.network.prefix_length = input->value.network.prefix_length;
    (void)memcpy(output->value.network.address, input->value.network.address,
                 address_size);
    complete_bytes = (size_t)input->value.network.prefix_length / 8U;
    remaining_bits = (uint8_t)(input->value.network.prefix_length % 8U);
    first_clear_byte = complete_bytes;
    if (remaining_bits != 0U) {
        const uint8_t mask = (uint8_t)(UINT8_C(0xff) << (8U - remaining_bits));

        output->value.network.address[complete_bytes] &= mask;
        first_clear_byte = complete_bytes + 1U;
    }
    if (first_clear_byte < address_size) {
        (void)memset(output->value.network.address + first_clear_byte, 0,
                     address_size - first_clear_byte);
    }
    return 0;
}

/** @brief Copy one network prefix while clearing every host bit. */
static int destination_address_normalize(
    const struct jg_policy_destination_rule_input *input,
    struct build_destination_rule *output)
{
    size_t address_size = 0U;
    size_t complete_bytes = 0U;
    size_t first_clear_byte = 0U;
    uint8_t remaining_bits = 0U;

    if (!input->has_address) {
        if (input->address_family != JG_POLICY_ADDRESS_NONE ||
            input->prefix_length != 0U) {
            return -EINVAL;
        }
        return 0;
    }
    if (input->address_family == JG_POLICY_ADDRESS_IPV4) {
        address_size = 4U;
        if (input->prefix_length > 32U) {
            return -EINVAL;
        }
    } else if (input->address_family == JG_POLICY_ADDRESS_IPV6) {
        address_size = 16U;
        if (input->prefix_length > 128U) {
            return -EINVAL;
        }
    } else {
        return -EINVAL;
    }

    output->has_address = true;
    output->address_family = input->address_family;
    output->prefix_length = input->prefix_length;
    (void)memcpy(output->address, input->address, address_size);
    complete_bytes = (size_t)input->prefix_length / 8U;
    remaining_bits = (uint8_t)(input->prefix_length % 8U);
    first_clear_byte = complete_bytes;
    if (remaining_bits != 0U) {
        const uint8_t mask = (uint8_t)(UINT8_C(0xff) << (8U - remaining_bits));

        output->address[complete_bytes] &= mask;
        first_clear_byte = complete_bytes + 1U;
    }
    if (first_clear_byte < address_size) {
        (void)memset(output->address + first_clear_byte, 0,
                     address_size - first_clear_byte);
    }
    return 0;
}

/** Compare two canonical scopes without inspecting union padding. */
static int scope_compare(const struct jg_policy_scope *left,
                         const struct jg_policy_scope *right)
{
    size_t address_size = 0U;
    int result = 0;

    if (left->type != right->type) {
        return left->type < right->type ? -1 : 1;
    }
    switch (left->type) {
    case JG_POLICY_SCOPE_GLOBAL:
        return 0;
    case JG_POLICY_SCOPE_MAC:
        return memcmp(left->value.mac, right->value.mac,
                      sizeof(left->value.mac));
    case JG_POLICY_SCOPE_IPV4:
    case JG_POLICY_SCOPE_IPV6:
        if (left->value.network.prefix_length !=
            right->value.network.prefix_length) {
            return left->value.network.prefix_length <
                           right->value.network.prefix_length
                       ? -1
                       : 1;
        }
        address_size = left->type == JG_POLICY_SCOPE_IPV4 ? 4U : 16U;
        return memcmp(left->value.network.address, right->value.network.address,
                      address_size);
    case JG_POLICY_SCOPE_VLAN:
        if (left->value.vlan_id < right->value.vlan_id) {
            result = -1;
        } else if (left->value.vlan_id > right->value.vlan_id) {
            result = 1;
        }
        return result;
    default:
        return 0;
    }
}

/** Compare canonical build rules, placing the identifier last for
 * deduplication. */
static int build_rule_compare(const void *left_value, const void *right_value)
{
    const struct build_rule *left = left_value;
    const struct build_rule *right = right_value;
    int result = strcmp(left->domain, right->domain);

    if (result != 0) {
        return result;
    }
    if (left->include_subdomains != right->include_subdomains) {
        return left->include_subdomains ? 1 : -1;
    }
    if (left->target != right->target) {
        return left->target < right->target ? -1 : 1;
    }
    if (left->source != right->source) {
        return left->source < right->source ? -1 : 1;
    }
    if (left->effect != right->effect) {
        return left->effect < right->effect ? -1 : 1;
    }
    result = scope_compare(&left->scope, &right->scope);
    if (result != 0) {
        return result;
    }
    result = strcmp(left->attribution, right->attribution);
    if (result != 0) {
        return result;
    }
    if (left->id < right->id) {
        return -1;
    }
    if (left->id > right->id) {
        return 1;
    }
    return 0;
}

/** Determine whether two adjacent sorted rules differ only by identifier. */
static bool build_rule_same_content(const struct build_rule *left,
                                    const struct build_rule *right)
{
    return strcmp(left->domain, right->domain) == 0 &&
           left->include_subdomains == right->include_subdomains &&
           left->target == right->target && left->source == right->source &&
           left->effect == right->effect &&
           scope_compare(&left->scope, &right->scope) == 0 &&
           strcmp(left->attribution, right->attribution) == 0;
}

/**
 * @brief Normalize all external rules into one temporary packed string area.
 *
 * A validation pass first computes the exact allocation size. A second pass
 * fills it, avoiding a heap allocation for every input string.
 */
static int prepare_rules(const struct jg_policy_rule_input *input,
                         size_t input_count,
                         struct build_rule **prepared,
                         char **strings)
{
    struct build_rule *build = NULL;
    char *packed = NULL;
    char normalized[JG_DOMAIN_NAME_MAX + 1U];
    size_t allocation_size = 0U;
    size_t packed_size = 0U;
    size_t cursor = 0U;
    size_t index = 0U;

    if (prepared == NULL || strings == NULL ||
        (input_count != 0U && input == NULL)) {
        return -EINVAL;
    }
    *prepared = NULL;
    *strings = NULL;
    if (input_count == 0U) {
        return 0;
    }
    if (input_count > (size_t)UINT32_MAX ||
        !jg_size_multiply(input_count, sizeof(*build), &allocation_size)) {
        return -EOVERFLOW;
    }

    for (index = 0U; index < input_count; ++index) {
        struct jg_policy_scope normalized_scope;
        size_t domain_size = 0U;
        size_t source_length = 0U;
        size_t source_size = 0U;

        if (input[index].id == 0U || !rule_class_valid(&input[index]) ||
            scope_normalize(&input[index].scope, &normalized_scope) != 0 ||
            jg_domain_normalize(input[index].domain, normalized,
                                sizeof(normalized)) != 0 ||
            attribution_length(input[index].attribution, &source_length) != 0) {
            return -EINVAL;
        }
        domain_size = strlen(normalized) + 1U;
        source_size = source_length + 1U;
        if (!jg_size_add(packed_size, domain_size, &packed_size) ||
            !jg_size_add(packed_size, source_size, &packed_size) ||
            packed_size > (size_t)UINT32_MAX) {
            return -EOVERFLOW;
        }
    }

    build = malloc(allocation_size);
    packed = malloc(packed_size);
    if (build == NULL || packed == NULL) {
        free(build);
        free(packed);
        return -ENOMEM;
    }
    (void)memset(build, 0, allocation_size);

    for (index = 0U; index < input_count; ++index) {
        size_t domain_size = 0U;
        size_t source_length = 0U;
        size_t source_size = 0U;

        (void)jg_domain_normalize(input[index].domain, normalized,
                                  sizeof(normalized));
        (void)attribution_length(input[index].attribution, &source_length);
        domain_size = strlen(normalized) + 1U;
        source_size = source_length + 1U;

        build[index].id = input[index].id;
        build[index].domain = packed + cursor;
        (void)memcpy(build[index].domain, normalized, domain_size);
        cursor += domain_size;
        build[index].attribution = packed + cursor;
        (void)memcpy(build[index].attribution, input[index].attribution,
                     source_size);
        cursor += source_size;
        build[index].include_subdomains = input[index].include_subdomains;
        build[index].effect = input[index].effect;
        build[index].source = input[index].source;
        build[index].target = input[index].target;
        (void)scope_normalize(&input[index].scope, &build[index].scope);
    }

    *prepared = build;
    *strings = packed;
    return 0;
}

/** @brief Compare canonical destination rules for deterministic packing. */
static int destination_rule_compare(const void *left_value,
                                    const void *right_value)
{
    const struct build_destination_rule *left = left_value;
    const struct build_destination_rule *right = right_value;
    int result = 0;

    if (left->has_address != right->has_address) {
        return left->has_address ? 1 : -1;
    }
    if (left->address_family != right->address_family) {
        return left->address_family < right->address_family ? -1 : 1;
    }
    if (left->prefix_length != right->prefix_length) {
        return left->prefix_length < right->prefix_length ? -1 : 1;
    }
    result = memcmp(left->address, right->address, sizeof(left->address));
    if (result != 0) {
        return result;
    }
    if (left->has_port != right->has_port) {
        return left->has_port ? 1 : -1;
    }
    if (left->port != right->port) {
        return left->port < right->port ? -1 : 1;
    }
    if (left->transport != right->transport) {
        return left->transport < right->transport ? -1 : 1;
    }
    if (left->source != right->source) {
        return left->source < right->source ? -1 : 1;
    }
    if (left->effect != right->effect) {
        return left->effect < right->effect ? -1 : 1;
    }
    result = scope_compare(&left->scope, &right->scope);
    if (result != 0) {
        return result;
    }
    result = strcmp(left->attribution, right->attribution);
    if (result != 0) {
        return result;
    }
    if (left->id < right->id) {
        return -1;
    }
    return left->id > right->id ? 1 : 0;
}

/** @brief Test whether sorted destination rules differ only by identifier. */
static bool destination_rule_same_content(
    const struct build_destination_rule *left,
    const struct build_destination_rule *right)
{
    return left->has_address == right->has_address &&
           left->address_family == right->address_family &&
           left->prefix_length == right->prefix_length &&
           memcmp(left->address, right->address, sizeof(left->address)) == 0 &&
           left->has_port == right->has_port && left->port == right->port &&
           left->transport == right->transport &&
           left->source == right->source && left->effect == right->effect &&
           scope_compare(&left->scope, &right->scope) == 0 &&
           strcmp(left->attribution, right->attribution) == 0;
}

/** @brief Validate and pack temporary destination-rule construction data. */
static int prepare_destination_rules(
    const struct jg_policy_destination_rule_input *input,
    size_t input_count,
    struct build_destination_rule **prepared,
    char **strings)
{
    struct build_destination_rule *build = NULL;
    char *packed = NULL;
    size_t allocation_size = 0U;
    size_t packed_size = 0U;
    size_t cursor = 0U;
    size_t index = 0U;

    if (prepared == NULL || strings == NULL ||
        (input_count != 0U && input == NULL)) {
        return -EINVAL;
    }
    *prepared = NULL;
    *strings = NULL;
    if (input_count == 0U) {
        return 0;
    }
    if (input_count > (size_t)UINT32_MAX ||
        !jg_size_multiply(input_count, sizeof(*build), &allocation_size)) {
        return -EOVERFLOW;
    }

    for (index = 0U; index < input_count; ++index) {
        struct build_destination_rule normalized = {0};
        size_t attribution_size = 0U;

        if (input[index].id == 0U ||
            !effect_source_valid(input[index].effect, input[index].source) ||
            (input[index].transport != JG_POLICY_TRANSPORT_ANY &&
             input[index].transport != JG_POLICY_TRANSPORT_TCP &&
             input[index].transport != JG_POLICY_TRANSPORT_UDP) ||
            (!input[index].has_address && !input[index].has_port) ||
            (input[index].has_port && input[index].port == 0U) ||
            (!input[index].has_port && input[index].port != 0U) ||
            destination_address_normalize(&input[index], &normalized) != 0 ||
            scope_normalize(&input[index].scope, &normalized.scope) != 0 ||
            attribution_length(input[index].attribution, &attribution_size) !=
                0) {
            return -EINVAL;
        }
        if (!jg_size_add(packed_size, attribution_size + 1U, &packed_size) ||
            packed_size > (size_t)UINT32_MAX) {
            return -EOVERFLOW;
        }
    }

    build = malloc(allocation_size);
    packed = malloc(packed_size);
    if (build == NULL || packed == NULL) {
        free(build);
        free(packed);
        return -ENOMEM;
    }
    (void)memset(build, 0, allocation_size);
    for (index = 0U; index < input_count; ++index) {
        const size_t attribution_size = strlen(input[index].attribution) + 1U;

        build[index].id = input[index].id;
        build[index].effect = input[index].effect;
        build[index].source = input[index].source;
        build[index].transport = input[index].transport;
        build[index].has_port = input[index].has_port;
        build[index].port = input[index].port;
        build[index].attribution = packed + cursor;
        (void)memcpy(build[index].attribution, input[index].attribution,
                     attribution_size);
        cursor += attribution_size;
        (void)destination_address_normalize(&input[index], &build[index]);
        (void)scope_normalize(&input[index].scope, &build[index].scope);
    }
    *prepared = build;
    *strings = packed;
    return 0;
}

/** Return the precedence rank mandated by the policy model. */
static uint8_t policy_priority(enum jg_policy_effect effect,
                               enum jg_policy_source source,
                               enum jg_policy_scope_type scope)
{
    if (source == JG_POLICY_SOURCE_EMERGENCY) {
        return 6U;
    }
    if (source == JG_POLICY_SOURCE_EXPLICIT && effect == JG_POLICY_ALLOW) {
        return scope == JG_POLICY_SCOPE_GLOBAL ? 4U : 5U;
    }
    if (source == JG_POLICY_SOURCE_EXPLICIT && effect == JG_POLICY_BLOCK) {
        return scope == JG_POLICY_SCOPE_GLOBAL ? 2U : 3U;
    }
    return 1U;
}

/** Convert SipHash output to an integer used for table probing. */
static uint64_t domain_hash(const struct jg_policy_snapshot *snapshot,
                            const char *domain)
{
    uint8_t bytes[crypto_shorthash_BYTES];
    uint64_t value = 0U;
    size_t index = 0U;

    (void)crypto_shorthash(bytes, (const uint8_t *)domain,
                           (unsigned long long)strlen(domain),
                           snapshot->hash_key);
    for (index = 0U; index < sizeof(bytes); ++index) {
        value = (value << 8U) | (uint64_t)bytes[index];
    }
    return value;
}

/** Locate one domain group in an immutable open-addressing table. */
static const struct policy_slot *find_slot(
    const struct jg_policy_snapshot *snapshot,
    const char *domain)
{
    uint64_t hash = 0U;
    size_t slot_index = 0U;
    size_t probe_count = 0U;

    if (snapshot->table_capacity == 0U) {
        return NULL;
    }
    hash = domain_hash(snapshot, domain);
    slot_index = (size_t)hash & (snapshot->table_capacity - 1U);
    for (probe_count = 0U; probe_count < snapshot->table_capacity;
         ++probe_count) {
        const struct policy_slot *slot = &snapshot->table[slot_index];
        const char *stored_domain = NULL;

        if (!slot->occupied) {
            return NULL;
        }
        stored_domain =
            snapshot->strings + snapshot->rules[slot->first_rule].domain_offset;
        if (slot->hash == hash && strcmp(stored_domain, domain) == 0) {
            return slot;
        }
        slot_index = (slot_index + 1U) & (snapshot->table_capacity - 1U);
    }
    return NULL;
}

/** Feed one unsigned integer to SHA-256 in a stable byte order. */
static void checksum_u64(crypto_hash_sha256_state *state, uint64_t value)
{
    uint8_t bytes[8U];
    size_t index = 0U;

    for (index = 0U; index < sizeof(bytes); ++index) {
        bytes[sizeof(bytes) - index - 1U] = (uint8_t)(value & UINT64_C(0xff));
        value >>= 8U;
    }
    (void)crypto_hash_sha256_update(state, bytes, sizeof(bytes));
}

/** Feed a length-prefixed string to the canonical snapshot checksum. */
static void checksum_string(crypto_hash_sha256_state *state, const char *value)
{
    const size_t length = strlen(value);

    checksum_u64(state, (uint64_t)length);
    (void)crypto_hash_sha256_update(state, (const uint8_t *)value,
                                    (unsigned long long)length);
}

/** Feed the meaningful fields of one canonical scope to SHA-256. */
static void checksum_scope(crypto_hash_sha256_state *state,
                           const struct jg_policy_scope *scope)
{
    const uint8_t type = (uint8_t)scope->type;

    (void)crypto_hash_sha256_update(state, &type, 1U);
    switch (scope->type) {
    case JG_POLICY_SCOPE_GLOBAL:
        break;
    case JG_POLICY_SCOPE_MAC:
        (void)crypto_hash_sha256_update(state, scope->value.mac, 6U);
        break;
    case JG_POLICY_SCOPE_IPV4:
        (void)crypto_hash_sha256_update(
            state, &scope->value.network.prefix_length, 1U);
        (void)crypto_hash_sha256_update(state, scope->value.network.address,
                                        4U);
        break;
    case JG_POLICY_SCOPE_IPV6:
        (void)crypto_hash_sha256_update(
            state, &scope->value.network.prefix_length, 1U);
        (void)crypto_hash_sha256_update(state, scope->value.network.address,
                                        16U);
        break;
    case JG_POLICY_SCOPE_VLAN:
        checksum_u64(state, scope->value.vlan_id);
        break;
    default:
        break;
    }
}

/** Compute the canonical digest independently of random table placement. */
static void snapshot_checksum(struct jg_policy_snapshot *snapshot)
{
    static const uint8_t format[] = "JanusGate policy snapshot 3";
    crypto_hash_sha256_state state;
    size_t index = 0U;

    (void)crypto_hash_sha256_init(&state);
    (void)crypto_hash_sha256_update(&state, format, sizeof(format) - 1U);
    checksum_u64(&state, (uint64_t)snapshot->info.rule_count);
    checksum_u64(&state, (uint64_t)snapshot->info.destination_rule_count);
    for (index = 0U; index < snapshot->info.rule_count; ++index) {
        const struct stored_rule *rule = &snapshot->rules[index];
        const uint8_t include_subdomains = rule->include_subdomains ? 1U : 0U;
        const uint8_t effect = (uint8_t)rule->effect;
        const uint8_t source = (uint8_t)rule->source;
        const uint8_t target = (uint8_t)rule->target;

        checksum_u64(&state, rule->id);
        checksum_string(&state, snapshot->strings + rule->domain_offset);
        (void)crypto_hash_sha256_update(&state, &include_subdomains, 1U);
        (void)crypto_hash_sha256_update(&state, &effect, 1U);
        (void)crypto_hash_sha256_update(&state, &source, 1U);
        (void)crypto_hash_sha256_update(&state, &target, 1U);
        checksum_scope(&state, &rule->scope);
        checksum_string(&state, snapshot->strings + rule->attribution_offset);
    }
    for (index = 0U; index < snapshot->info.destination_rule_count; ++index) {
        const struct stored_destination_rule *rule =
            &snapshot->destination_rules[index];
        const uint8_t effect = (uint8_t)rule->effect;
        const uint8_t source = (uint8_t)rule->source;
        const uint8_t transport = (uint8_t)rule->transport;
        const uint8_t has_address = rule->has_address ? 1U : 0U;
        const uint8_t family = (uint8_t)rule->address_family;
        const uint8_t has_port = rule->has_port ? 1U : 0U;
        const size_t address_size =
            rule->address_family == JG_POLICY_ADDRESS_IPV4 ? 4U : 16U;

        checksum_u64(&state, rule->id);
        (void)crypto_hash_sha256_update(&state, &effect, 1U);
        (void)crypto_hash_sha256_update(&state, &source, 1U);
        (void)crypto_hash_sha256_update(&state, &transport, 1U);
        (void)crypto_hash_sha256_update(&state, &has_address, 1U);
        if (rule->has_address) {
            (void)crypto_hash_sha256_update(&state, &family, 1U);
            (void)crypto_hash_sha256_update(&state, &rule->prefix_length, 1U);
            (void)crypto_hash_sha256_update(&state, rule->address,
                                            address_size);
        }
        (void)crypto_hash_sha256_update(&state, &has_port, 1U);
        if (rule->has_port) {
            checksum_u64(&state, rule->port);
        }
        checksum_scope(&state, &rule->scope);
        checksum_string(&state, snapshot->destination_strings +
                                    rule->attribution_offset);
    }
    (void)crypto_hash_sha256_final(&state, snapshot->info.checksum);
}

/**
 * @brief Allocate and fill final packed rules and their lookup table.
 */
static int snapshot_populate(struct jg_policy_snapshot *snapshot,
                             const struct build_rule *rules,
                             size_t rule_count)
{
    size_t strings_size = 0U;
    size_t rules_size = 0U;
    size_t table_size = 0U;
    size_t unique_domains = 0U;
    size_t required_slots = 0U;
    size_t cursor = 0U;
    size_t index = 0U;

    for (index = 0U; index < rule_count; ++index) {
        const size_t domain_size = strlen(rules[index].domain) + 1U;
        const size_t attribution_size = strlen(rules[index].attribution) + 1U;

        if (!jg_size_add(strings_size, domain_size, &strings_size) ||
            !jg_size_add(strings_size, attribution_size, &strings_size) ||
            strings_size > (size_t)UINT32_MAX) {
            return -EOVERFLOW;
        }
        if (index == 0U ||
            strcmp(rules[index - 1U].domain, rules[index].domain) != 0) {
            ++unique_domains;
        }
    }
    if (!jg_size_multiply(rule_count, sizeof(*snapshot->rules), &rules_size)) {
        return -EOVERFLOW;
    }
    if (rule_count != 0U) {
        snapshot->rules = malloc(rules_size);
        snapshot->strings = malloc(strings_size);
        if (snapshot->rules == NULL || snapshot->strings == NULL) {
            return -ENOMEM;
        }
        (void)memset(snapshot->rules, 0, rules_size);
    }

    for (index = 0U; index < rule_count; ++index) {
        struct stored_rule *stored = &snapshot->rules[index];
        const size_t domain_size = strlen(rules[index].domain) + 1U;
        const size_t attribution_size = strlen(rules[index].attribution) + 1U;

        stored->id = rules[index].id;
        stored->domain_offset = (uint32_t)cursor;
        (void)memcpy(snapshot->strings + cursor, rules[index].domain,
                     domain_size);
        cursor += domain_size;
        stored->attribution_offset = (uint32_t)cursor;
        (void)memcpy(snapshot->strings + cursor, rules[index].attribution,
                     attribution_size);
        cursor += attribution_size;
        stored->priority = policy_priority(
            rules[index].effect, rules[index].source, rules[index].scope.type);
        stored->include_subdomains = rules[index].include_subdomains;
        stored->effect = rules[index].effect;
        stored->source = rules[index].source;
        stored->target = rules[index].target;
        stored->scope = rules[index].scope;
    }

    if (unique_domains == 0U) {
        return 0;
    }
    if (!jg_size_multiply(unique_domains, 2U, &required_slots)) {
        return -EOVERFLOW;
    }
    snapshot->table_capacity = 1U;
    while (snapshot->table_capacity < required_slots) {
        if (snapshot->table_capacity > SIZE_MAX / 2U) {
            return -EOVERFLOW;
        }
        snapshot->table_capacity *= 2U;
    }
    if (!jg_size_multiply(snapshot->table_capacity, sizeof(*snapshot->table),
                          &table_size)) {
        return -EOVERFLOW;
    }
    snapshot->table = malloc(table_size);
    if (snapshot->table == NULL) {
        return -ENOMEM;
    }
    (void)memset(snapshot->table, 0, table_size);

    index = 0U;
    while (index < rule_count) {
        const char *domain =
            snapshot->strings + snapshot->rules[index].domain_offset;
        const size_t first_rule = index;
        uint64_t hash = 0U;
        size_t slot_index = 0U;

        do {
            ++index;
        } while (index < rule_count &&
                 strcmp(domain, snapshot->strings +
                                    snapshot->rules[index].domain_offset) == 0);

        hash = domain_hash(snapshot, domain);
        slot_index = (size_t)hash & (snapshot->table_capacity - 1U);
        while (snapshot->table[slot_index].occupied) {
            slot_index = (slot_index + 1U) & (snapshot->table_capacity - 1U);
        }
        snapshot->table[slot_index].hash = hash;
        snapshot->table[slot_index].first_rule = (uint32_t)first_rule;
        snapshot->table[slot_index].rule_count = (uint32_t)(index - first_rule);
        snapshot->table[slot_index].occupied = true;
    }
    return 0;
}

/** @brief Allocate and fill final packed destination rules. */
static int snapshot_populate_destinations(
    struct jg_policy_snapshot *snapshot,
    const struct build_destination_rule *rules,
    size_t rule_count)
{
    size_t rules_size = 0U;
    size_t strings_size = 0U;
    size_t cursor = 0U;
    size_t index = 0U;

    if (rule_count == 0U) {
        return 0;
    }
    if (!jg_size_multiply(rule_count, sizeof(*snapshot->destination_rules),
                          &rules_size)) {
        return -EOVERFLOW;
    }
    for (index = 0U; index < rule_count; ++index) {
        if (!jg_size_add(strings_size, strlen(rules[index].attribution) + 1U,
                         &strings_size) ||
            strings_size > (size_t)UINT32_MAX) {
            return -EOVERFLOW;
        }
    }
    snapshot->destination_rules = malloc(rules_size);
    snapshot->destination_strings = malloc(strings_size);
    if (snapshot->destination_rules == NULL ||
        snapshot->destination_strings == NULL) {
        return -ENOMEM;
    }
    (void)memset(snapshot->destination_rules, 0, rules_size);
    for (index = 0U; index < rule_count; ++index) {
        struct stored_destination_rule *stored =
            &snapshot->destination_rules[index];
        const size_t attribution_size = strlen(rules[index].attribution) + 1U;

        stored->id = rules[index].id;
        stored->attribution_offset = (uint32_t)cursor;
        (void)memcpy(snapshot->destination_strings + cursor,
                     rules[index].attribution, attribution_size);
        cursor += attribution_size;
        stored->priority = policy_priority(
            rules[index].effect, rules[index].source, rules[index].scope.type);
        stored->effect = rules[index].effect;
        stored->source = rules[index].source;
        stored->transport = rules[index].transport;
        stored->has_address = rules[index].has_address;
        stored->address_family = rules[index].address_family;
        (void)memcpy(stored->address, rules[index].address,
                     sizeof(stored->address));
        stored->prefix_length = rules[index].prefix_length;
        stored->has_port = rules[index].has_port;
        stored->port = rules[index].port;
        stored->scope = rules[index].scope;
    }
    snapshot->info.destination_rule_count = rule_count;
    return 0;
}

/** @brief Build a normalized, deduplicated immutable policy snapshot. */
int jg_policy_snapshot_build(const struct jg_policy_rule_input *rules,
                             size_t rule_count,
                             uint64_t generation,
                             struct jg_policy_snapshot **snapshot)
{
    return jg_policy_snapshot_build_complete(rules, rule_count, NULL, 0U,
                                             generation, snapshot);
}

/** @brief Build complete normalized immutable domain and destination policy. */
int jg_policy_snapshot_build_complete(
    const struct jg_policy_rule_input *rules,
    size_t rule_count,
    const struct jg_policy_destination_rule_input *destination_rules,
    size_t destination_rule_count,
    uint64_t generation,
    struct jg_policy_snapshot **snapshot)
{
    struct jg_policy_snapshot *created = NULL;
    struct build_rule *prepared = NULL;
    struct build_destination_rule *prepared_destinations = NULL;
    char *temporary_strings = NULL;
    char *temporary_destination_strings = NULL;
    size_t retained_count = 0U;
    size_t retained_destination_count = 0U;
    size_t index = 0U;
    time_t build_time = 0;
    int result = 0;

    if (snapshot == NULL) {
        return -EINVAL;
    }
    *snapshot = NULL;
    if (generation == 0U || (rule_count != 0U && rules == NULL) ||
        (destination_rule_count != 0U && destination_rules == NULL)) {
        return -EINVAL;
    }
    if (sodium_init() < 0) {
        return -EIO;
    }
    result = prepare_rules(rules, rule_count, &prepared, &temporary_strings);
    if (result != 0) {
        return result;
    }
    result = prepare_destination_rules(
        destination_rules, destination_rule_count, &prepared_destinations,
        &temporary_destination_strings);
    if (result != 0) {
        free(temporary_strings);
        free(prepared);
        return result;
    }

    if (rule_count > 1U) {
        qsort(prepared, rule_count, sizeof(*prepared), build_rule_compare);
    }
    for (index = 0U; index < rule_count; ++index) {
        if (retained_count == 0U ||
            !build_rule_same_content(&prepared[retained_count - 1U],
                                     &prepared[index])) {
            prepared[retained_count] = prepared[index];
            ++retained_count;
        }
    }
    if (destination_rule_count > 1U) {
        qsort(prepared_destinations, destination_rule_count,
              sizeof(*prepared_destinations), destination_rule_compare);
    }
    for (index = 0U; index < destination_rule_count; ++index) {
        if (retained_destination_count == 0U ||
            !destination_rule_same_content(
                &prepared_destinations[retained_destination_count - 1U],
                &prepared_destinations[index])) {
            prepared_destinations[retained_destination_count] =
                prepared_destinations[index];
            ++retained_destination_count;
        }
    }

    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        free(temporary_destination_strings);
        free(prepared_destinations);
        free(temporary_strings);
        free(prepared);
        return -ENOMEM;
    }
    randombytes_buf(created->hash_key, sizeof(created->hash_key));
    result = snapshot_populate(created, prepared, retained_count);
    if (result == 0) {
        result = snapshot_populate_destinations(created, prepared_destinations,
                                                retained_destination_count);
    }
    free(temporary_destination_strings);
    free(prepared_destinations);
    free(temporary_strings);
    free(prepared);
    if (result != 0) {
        jg_policy_snapshot_destroy(created);
        return result;
    }

    build_time = time(NULL);
    if (build_time == (time_t)-1) {
        jg_policy_snapshot_destroy(created);
        return -EIO;
    }
    created->info.generation = generation;
    created->info.built_at = (uint64_t)build_time;
    created->info.rule_count = retained_count;
    snapshot_checksum(created);
    *snapshot = created;
    return 0;
}

/** @brief Release all storage owned by an immutable policy snapshot. */
void jg_policy_snapshot_destroy(struct jg_policy_snapshot *snapshot)
{
    if (snapshot == NULL) {
        return;
    }
    jg_secure_clear(snapshot->hash_key, sizeof(snapshot->hash_key));
    free(snapshot->table);
    free(snapshot->destination_strings);
    free(snapshot->destination_rules);
    free(snapshot->strings);
    free(snapshot->rules);
    free(snapshot);
}

/** @brief Copy stable metadata from an immutable policy snapshot. */
int jg_policy_snapshot_get_info(const struct jg_policy_snapshot *snapshot,
                                struct jg_policy_snapshot_info *info)
{
    if (snapshot == NULL || info == NULL) {
        return -EINVAL;
    }
    *info = snapshot->info;
    return 0;
}

/** Validate caller-provided client properties before matching scopes. */
static bool client_valid(const struct jg_policy_client *client)
{
    if (client == NULL) {
        return true;
    }
    if (client->address_family != JG_POLICY_ADDRESS_NONE &&
        client->address_family != JG_POLICY_ADDRESS_IPV4 &&
        client->address_family != JG_POLICY_ADDRESS_IPV6) {
        return false;
    }
    return !client->has_vlan || client->vlan_id <= 4094U;
}

/** Compare the leading prefix bits of two network-order addresses. */
static bool address_matches(const uint8_t *client,
                            const uint8_t *network,
                            uint8_t prefix_length)
{
    const size_t complete_bytes = (size_t)prefix_length / 8U;
    const uint8_t remaining_bits = (uint8_t)(prefix_length % 8U);

    if (memcmp(client, network, complete_bytes) != 0) {
        return false;
    }
    if (remaining_bits != 0U) {
        const uint8_t mask = (uint8_t)(UINT8_C(0xff) << (8U - remaining_bits));

        return (client[complete_bytes] & mask) == network[complete_bytes];
    }
    return true;
}

/** Determine whether one canonical scope accepts the supplied client. */
static bool scope_matches(const struct jg_policy_scope *scope,
                          const struct jg_policy_client *client)
{
    switch (scope->type) {
    case JG_POLICY_SCOPE_GLOBAL:
        return true;
    case JG_POLICY_SCOPE_MAC:
        return client != NULL && client->has_mac &&
               memcmp(client->mac, scope->value.mac, sizeof(client->mac)) == 0;
    case JG_POLICY_SCOPE_IPV4:
        return client != NULL &&
               client->address_family == JG_POLICY_ADDRESS_IPV4 &&
               address_matches(client->address, scope->value.network.address,
                               scope->value.network.prefix_length);
    case JG_POLICY_SCOPE_IPV6:
        return client != NULL &&
               client->address_family == JG_POLICY_ADDRESS_IPV6 &&
               address_matches(client->address, scope->value.network.address,
                               scope->value.network.prefix_length);
    case JG_POLICY_SCOPE_VLAN:
        return client != NULL && client->has_vlan &&
               client->vlan_id == scope->value.vlan_id;
    default:
        return false;
    }
}

/**
 * @brief Select the highest-priority eligible rule in one domain group.
 *
 * Equal-precedence rules are resolved by their stable identifier.
 */
static const struct stored_rule *match_slot(
    const struct jg_policy_snapshot *snapshot,
    const struct policy_slot *slot,
    const struct jg_policy_client *client,
    bool exact_domain,
    enum jg_policy_domain_target target)
{
    const struct stored_rule *best = NULL;
    size_t index = 0U;

    if (slot == NULL) {
        return NULL;
    }
    for (index = 0U; index < (size_t)slot->rule_count; ++index) {
        const struct stored_rule *rule =
            &snapshot->rules[(size_t)slot->first_rule + index];

        if (rule->target != target ||
            (!exact_domain && !rule->include_subdomains) ||
            !scope_matches(&rule->scope, client)) {
            continue;
        }
        if (best == NULL || rule->priority > best->priority ||
            (rule->priority == best->priority && rule->id < best->id)) {
            best = rule;
        }
    }
    return best;
}

/** @brief Match one normalized domain in a selected protocol context. */
static int match_domain_target(const struct jg_policy_snapshot *snapshot,
                               const char *domain,
                               const struct jg_policy_client *client,
                               enum jg_policy_domain_target target,
                               struct jg_policy_match *match)
{
    const struct stored_rule *best = NULL;
    const char *candidate = domain;
    bool exact_domain = true;

    if (snapshot == NULL || match == NULL || !jg_domain_is_normalized(domain) ||
        !client_valid(client)) {
        return -EINVAL;
    }

    (void)memset(match, 0, sizeof(*match));
    match->effect = JG_POLICY_ALLOW;
    while (candidate != NULL) {
        const struct policy_slot *slot = find_slot(snapshot, candidate);
        const struct stored_rule *current =
            match_slot(snapshot, slot, client, exact_domain, target);
        const char *separator = NULL;

        if (current != NULL &&
            (best == NULL || current->priority > best->priority)) {
            best = current;
        }
        separator = strchr(candidate, '.');
        candidate = separator == NULL ? NULL : separator + 1;
        exact_domain = false;
    }

    if (best != NULL) {
        match->effect = best->effect;
        match->matched = true;
        match->rule_id = best->id;
        match->source = best->source;
        match->domain = snapshot->strings + best->domain_offset;
        match->attribution = snapshot->strings + best->attribution_offset;
    }
    return 0;
}

/** @brief Match a normalized DNS name using precedence and client scope. */
int jg_policy_match_domain(const struct jg_policy_snapshot *snapshot,
                           const char *domain,
                           const struct jg_policy_client *client,
                           struct jg_policy_match *match)
{
    return match_domain_target(snapshot, domain, client, JG_POLICY_DOMAIN_DNS,
                               match);
}

/** @brief Match a normalized visible TLS SNI using explicit SNI rules. */
int jg_policy_match_visible_sni(const struct jg_policy_snapshot *snapshot,
                                const char *server_name,
                                const struct jg_policy_client *client,
                                struct jg_policy_match *match)
{
    return match_domain_target(snapshot, server_name, client,
                               JG_POLICY_DOMAIN_TLS_SNI, match);
}

/** @brief Validate destination properties supplied to packet-path matching. */
static bool destination_valid(const struct jg_policy_destination *destination)
{
    return destination != NULL &&
           (destination->transport == JG_POLICY_TRANSPORT_TCP ||
            destination->transport == JG_POLICY_TRANSPORT_UDP) &&
           (destination->address_family == JG_POLICY_ADDRESS_IPV4 ||
            destination->address_family == JG_POLICY_ADDRESS_IPV6) &&
           destination->port != 0U;
}

/** @brief Test one stored destination rule against packet properties. */
static bool destination_rule_matches(
    const struct stored_destination_rule *rule,
    const struct jg_policy_destination *destination,
    const struct jg_policy_client *client)
{
    if (rule->transport != JG_POLICY_TRANSPORT_ANY &&
        rule->transport != destination->transport) {
        return false;
    }
    if (rule->has_port && rule->port != destination->port) {
        return false;
    }
    if (rule->has_address &&
        (rule->address_family != destination->address_family ||
         !address_matches(destination->address, rule->address,
                          rule->prefix_length))) {
        return false;
    }
    return scope_matches(&rule->scope, client);
}

/** @brief Rank equally privileged destination rules by specificity. */
static uint16_t destination_rule_specificity(
    const struct stored_destination_rule *rule)
{
    uint16_t specificity = 0U;

    if (rule->has_address) {
        specificity = (uint16_t)rule->prefix_length + 1U;
    }
    if (rule->has_port) {
        specificity += 256U;
    }
    if (rule->transport != JG_POLICY_TRANSPORT_ANY) {
        specificity += 512U;
    }
    return specificity;
}

/** @brief Match immutable destination rules using policy precedence. */
int jg_policy_match_destination(const struct jg_policy_snapshot *snapshot,
                                const struct jg_policy_destination *destination,
                                const struct jg_policy_client *client,
                                struct jg_policy_destination_match *match)
{
    const struct stored_destination_rule *best = NULL;
    size_t index = 0U;

    if (snapshot == NULL || !destination_valid(destination) ||
        !client_valid(client) || match == NULL) {
        return -EINVAL;
    }
    (void)memset(match, 0, sizeof(*match));
    match->effect = JG_POLICY_ALLOW;
    for (index = 0U; index < snapshot->info.destination_rule_count; ++index) {
        const struct stored_destination_rule *current =
            &snapshot->destination_rules[index];

        if (!destination_rule_matches(current, destination, client)) {
            continue;
        }
        if (best == NULL || current->priority > best->priority ||
            (current->priority == best->priority &&
             destination_rule_specificity(current) >
                 destination_rule_specificity(best)) ||
            (current->priority == best->priority &&
             destination_rule_specificity(current) ==
                 destination_rule_specificity(best) &&
             current->id < best->id)) {
            best = current;
        }
    }
    if (best != NULL) {
        match->effect = best->effect;
        match->matched = true;
        match->rule_id = best->id;
        match->source = best->source;
        match->attribution =
            snapshot->destination_strings + best->attribution_offset;
    }
    return 0;
}
