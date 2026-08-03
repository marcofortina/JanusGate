/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/database.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#include "database_internal.h"
#include "janusgate/checked.h"
#include "janusgate/domain.h"

/** @brief Return the persistent text representation of a policy effect. */
static const char *effect_text(enum jg_policy_effect effect)
{
    return effect == JG_POLICY_ALLOW ? "allow" : "block";
}

/** @brief Return the persistent text representation of a transport selector. */
static const char *transport_text(enum jg_policy_transport transport)
{
    switch (transport) {
    case JG_POLICY_TRANSPORT_ANY:
        return "any";
    case JG_POLICY_TRANSPORT_TCP:
        return "tcp";
    case JG_POLICY_TRANSPORT_UDP:
        return "udp";
    default:
        return NULL;
    }
}

/** @brief Return the persistent text representation of a domain target. */
static const char *target_text(enum jg_policy_domain_target target)
{
    switch (target) {
    case JG_POLICY_DOMAIN_DNS:
        return "dns";
    case JG_POLICY_DOMAIN_TLS_SNI:
        return "tls_sni";
    default:
        return NULL;
    }
}

/** @brief Return the persistent text representation of a policy source. */
static const char *source_text(enum jg_policy_source source)
{
    switch (source) {
    case JG_POLICY_SOURCE_BLOCKLIST:
        return "blocklist";
    case JG_POLICY_SOURCE_EXPLICIT:
        return "explicit";
    case JG_POLICY_SOURCE_EMERGENCY:
        return "emergency";
    case JG_POLICY_SOURCE_DEFAULT:
    default:
        return NULL;
    }
}

/** @brief Return the persistent text representation of a policy scope. */
static const char *scope_text(enum jg_policy_scope_type type)
{
    switch (type) {
    case JG_POLICY_SCOPE_GLOBAL:
        return "global";
    case JG_POLICY_SCOPE_MAC:
        return "mac";
    case JG_POLICY_SCOPE_IPV4:
        return "ipv4";
    case JG_POLICY_SCOPE_IPV6:
        return "ipv6";
    case JG_POLICY_SCOPE_VLAN:
        return "vlan";
    default:
        return NULL;
    }
}

/** @brief Mask host bits from one policy network before persistence. */
static void canonical_network(uint8_t *output,
                              const uint8_t *input,
                              size_t address_size,
                              uint8_t prefix_length)
{
    const size_t complete_bytes = (size_t)prefix_length / 8U;
    const uint8_t remaining_bits = (uint8_t)(prefix_length % 8U);
    size_t first_clear_byte = complete_bytes;

    (void)memset(output, 0, 16U);
    (void)memcpy(output, input, address_size);
    if (remaining_bits != 0U) {
        const uint8_t mask = (uint8_t)(UINT8_C(0xff) << (8U - remaining_bits));

        output[complete_bytes] &= mask;
        first_clear_byte = complete_bytes + 1U;
    }
    if (first_clear_byte < address_size) {
        (void)memset(output + first_clear_byte, 0,
                     address_size - first_clear_byte);
    }
}

/** @brief Validate a complete replacement rule set before opening a
 * transaction. */
static int validate_domain_rules(const struct jg_policy_rule_input *rules,
                                 size_t rule_count)
{
    struct jg_policy_snapshot *validation = NULL;
    size_t index = 0U;
    int result = 0;

    if (rule_count > JG_DATABASE_POLICY_RULE_LIMIT ||
        (rule_count != 0U && rules == NULL)) {
        return -EINVAL;
    }
    for (index = 0U; index < rule_count; ++index) {
        if (rules[index].id > (uint64_t)INT64_MAX) {
            return -EOVERFLOW;
        }
    }
    result = jg_policy_snapshot_build(rules, rule_count, 1U, &validation);
    jg_policy_snapshot_destroy(validation);
    return result;
}

/** @brief Bind a validated policy scope to one domain-rule insert. */
static int bind_scope(sqlite3_stmt *statement,
                      const struct jg_policy_scope *scope,
                      int type_parameter,
                      int value_parameter,
                      int prefix_parameter,
                      int vlan_parameter)
{
    uint8_t address[16U];
    const char *type = scope_text(scope->type);
    int status = SQLITE_OK;

    if (type == NULL) {
        return -EINVAL;
    }
    status =
        sqlite3_bind_text(statement, type_parameter, type, -1, SQLITE_STATIC);
    if (status != SQLITE_OK) {
        return jg_database_sqlite_result(status);
    }
    switch (scope->type) {
    case JG_POLICY_SCOPE_GLOBAL:
        break;
    case JG_POLICY_SCOPE_MAC:
        status = sqlite3_bind_blob(statement, value_parameter, scope->value.mac,
                                   6, SQLITE_TRANSIENT);
        break;
    case JG_POLICY_SCOPE_IPV4:
        canonical_network(address, scope->value.network.address, 4U,
                          scope->value.network.prefix_length);
        status = sqlite3_bind_blob(statement, value_parameter, address, 4,
                                   SQLITE_TRANSIENT);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, prefix_parameter,
                                      scope->value.network.prefix_length);
        }
        break;
    case JG_POLICY_SCOPE_IPV6:
        canonical_network(address, scope->value.network.address, 16U,
                          scope->value.network.prefix_length);
        status = sqlite3_bind_blob(statement, value_parameter, address, 16,
                                   SQLITE_TRANSIENT);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, prefix_parameter,
                                      scope->value.network.prefix_length);
        }
        break;
    case JG_POLICY_SCOPE_VLAN:
        status =
            sqlite3_bind_int(statement, vlan_parameter, scope->value.vlan_id);
        break;
    default:
        return -EINVAL;
    }
    return jg_database_sqlite_result(status);
}

/** @brief Bind one validated domain rule to a prepared write statement. */
static int bind_domain_rule(sqlite3_stmt *statement,
                            const struct jg_policy_rule_input *rule)
{
    char normalized[JG_DOMAIN_NAME_MAX + 1U];
    const char *persistent_source = source_text(rule->source);
    const char *persistent_target = target_text(rule->target);
    int status = sqlite3_reset(statement);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        result = jg_database_sqlite_result(sqlite3_clear_bindings(statement));
    }
    if (result == 0) {
        result =
            jg_domain_normalize(rule->domain, normalized, sizeof(normalized));
    }
    if (result == 0) {
        status = rule->id == 0U ? sqlite3_bind_null(statement, 1)
                                : sqlite3_bind_int64(statement, 1,
                                                     (sqlite3_int64)rule->id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_text(statement, 2, normalized, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(
            statement, 3, rule->include_subdomains ? "suffix" : "exact", -1,
            SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 4, effect_text(rule->effect), -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && persistent_source != NULL) {
        status = sqlite3_bind_text(statement, 5, persistent_source, -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        result = -EINVAL;
    }
    if (result == 0) {
        result = bind_scope(statement, &rule->scope, 6, 7, 8, 9);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 10, rule->attribution, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && persistent_target != NULL) {
        status = sqlite3_bind_text(statement, 11, persistent_target, -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        result = -EINVAL;
    }
    return result;
}

/** @brief Atomically replace every active persistent domain rule. */
int jg_database_replace_domain_rules(struct jg_database *database,
                                     const struct jg_policy_rule_input *rules,
                                     size_t rule_count)
{
    static const char insert[] =
        "INSERT INTO domain_rules("
        "id,domain,match_type,effect,source,scope_type,scope_value,"
        "prefix_length,vlan_id,attribution,enabled,updated_at,target"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,unixepoch(),?11);";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    int status;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = validate_domain_rules(rules, rule_count);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        result = jg_database_execute_sql(database->handle,
                                         "DELETE FROM domain_rules;");
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    for (index = 0U; result == 0 && index < rule_count; ++index) {
        result = bind_domain_rule(statement, &rules[index]);
        if (result == 0) {
            status = sqlite3_step(statement);
            result =
                status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    return result;
}

/** @brief Validate destination rules before opening a write transaction. */
static int validate_destination_rules(
    const struct jg_policy_destination_rule_input *rules,
    size_t rule_count)
{
    struct jg_policy_snapshot *validation = NULL;
    size_t index = 0U;
    int result = 0;

    if (rule_count > JG_DATABASE_POLICY_RULE_LIMIT ||
        (rule_count != 0U && rules == NULL)) {
        return -EINVAL;
    }
    for (index = 0U; index < rule_count; ++index) {
        if (rules[index].id > (uint64_t)INT64_MAX) {
            return -EOVERFLOW;
        }
    }
    result = jg_policy_snapshot_build_complete(NULL, 0U, rules, rule_count, 1U,
                                               &validation);
    jg_policy_snapshot_destroy(validation);
    return result;
}

/** @brief Bind one validated destination rule to a prepared write statement. */
static int bind_destination_rule(
    sqlite3_stmt *statement,
    const struct jg_policy_destination_rule_input *rule)
{
    uint8_t address[16U];
    const char *persistent_source = source_text(rule->source);
    const char *persistent_transport = transport_text(rule->transport);
    int status = sqlite3_reset(statement);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        result = jg_database_sqlite_result(sqlite3_clear_bindings(statement));
    }
    if (result == 0) {
        status = rule->id == 0U ? sqlite3_bind_null(statement, 1)
                                : sqlite3_bind_int64(statement, 1,
                                                     (sqlite3_int64)rule->id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 2, effect_text(rule->effect), -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && persistent_source != NULL) {
        status = sqlite3_bind_text(statement, 3, persistent_source, -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        result = -EINVAL;
    }
    if (result == 0 && persistent_transport != NULL) {
        status = sqlite3_bind_text(statement, 4, persistent_transport, -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        result = -EINVAL;
    }
    if (result == 0 && rule->has_address) {
        const size_t address_size =
            rule->address_family == JG_POLICY_ADDRESS_IPV4 ? 4U : 16U;

        canonical_network(address, rule->address, address_size,
                          rule->prefix_length);
        status = sqlite3_bind_int(statement, 5, (int)rule->address_family);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_blob(statement, 6, address, (int)address_size,
                                       SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, 7, rule->prefix_length);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && rule->has_port) {
        status = sqlite3_bind_int(statement, 8, rule->port);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_scope(statement, &rule->scope, 9, 10, 11, 12);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 13, rule->attribution, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    return result;
}

/** @brief Atomically replace every active persistent destination rule. */
int jg_database_replace_destination_rules(
    struct jg_database *database,
    const struct jg_policy_destination_rule_input *rules,
    size_t rule_count)
{
    static const char insert[] =
        "INSERT INTO destination_rules("
        "id,effect,source,protocol,family,address,prefix_length,port,"
        "scope_type,scope_value,scope_prefix_length,scope_vlan_id,"
        "attribution,enabled,updated_at"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,1,"
        "unixepoch());";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = validate_destination_rules(rules, rule_count);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        result = jg_database_execute_sql(database->handle,
                                         "DELETE FROM destination_rules;");
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    for (index = 0U; result == 0 && index < rule_count; ++index) {
        result = bind_destination_rule(statement, &rules[index]);
        if (result == 0) {
            status = sqlite3_step(statement);
            result =
                status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    return result;
}

/** @brief Decode a persistent policy effect. */
static int decode_effect(const char *text, enum jg_policy_effect *effect)
{
    if (strcmp(text, "allow") == 0) {
        *effect = JG_POLICY_ALLOW;
        return 0;
    }
    if (strcmp(text, "block") == 0) {
        *effect = JG_POLICY_BLOCK;
        return 0;
    }
    return -EILSEQ;
}

/** @brief Decode a persistent policy source. */
static int decode_source(const char *text, enum jg_policy_source *source)
{
    if (strcmp(text, "blocklist") == 0) {
        *source = JG_POLICY_SOURCE_BLOCKLIST;
        return 0;
    }
    if (strcmp(text, "explicit") == 0) {
        *source = JG_POLICY_SOURCE_EXPLICIT;
        return 0;
    }
    if (strcmp(text, "emergency") == 0) {
        *source = JG_POLICY_SOURCE_EMERGENCY;
        return 0;
    }
    return -EILSEQ;
}

/** @brief Decode one persistent transport selector. */
static int decode_transport(const char *text,
                            enum jg_policy_transport *transport)
{
    if (strcmp(text, "any") == 0) {
        *transport = JG_POLICY_TRANSPORT_ANY;
        return 0;
    }
    if (strcmp(text, "tcp") == 0) {
        *transport = JG_POLICY_TRANSPORT_TCP;
        return 0;
    }
    if (strcmp(text, "udp") == 0) {
        *transport = JG_POLICY_TRANSPORT_UDP;
        return 0;
    }
    return -EILSEQ;
}

/** @brief Decode a persistent domain-policy target. */
static int decode_target(const char *text, enum jg_policy_domain_target *target)
{
    if (strcmp(text, "dns") == 0) {
        *target = JG_POLICY_DOMAIN_DNS;
        return 0;
    }
    if (strcmp(text, "tls_sni") == 0) {
        *target = JG_POLICY_DOMAIN_TLS_SNI;
        return 0;
    }
    return -EILSEQ;
}

/** @brief Decode and validate one persistent client scope. */
static int decode_scope(sqlite3_stmt *statement,
                        const char *type,
                        int value_column,
                        int prefix_column,
                        int vlan_column,
                        struct jg_policy_scope *scope)
{
    const void *value = sqlite3_column_blob(statement, value_column);
    const int value_size = sqlite3_column_bytes(statement, value_column);

    (void)memset(scope, 0, sizeof(*scope));
    if (strcmp(type, "global") == 0) {
        scope->type = JG_POLICY_SCOPE_GLOBAL;
        return sqlite3_column_type(statement, value_column) == SQLITE_NULL &&
                       sqlite3_column_type(statement, prefix_column) ==
                           SQLITE_NULL &&
                       sqlite3_column_type(statement, vlan_column) ==
                           SQLITE_NULL
                   ? 0
                   : -EILSEQ;
    }
    if (strcmp(type, "mac") == 0 && value != NULL && value_size == 6) {
        scope->type = JG_POLICY_SCOPE_MAC;
        (void)memcpy(scope->value.mac, value, 6U);
        return 0;
    }
    if (strcmp(type, "ipv4") == 0 && value != NULL && value_size == 4 &&
        sqlite3_column_type(statement, prefix_column) == SQLITE_INTEGER) {
        const int prefix = sqlite3_column_int(statement, prefix_column);

        if (prefix >= 0 && prefix <= 32) {
            scope->type = JG_POLICY_SCOPE_IPV4;
            (void)memcpy(scope->value.network.address, value, 4U);
            scope->value.network.prefix_length = (uint8_t)prefix;
            return 0;
        }
    }
    if (strcmp(type, "ipv6") == 0 && value != NULL && value_size == 16 &&
        sqlite3_column_type(statement, prefix_column) == SQLITE_INTEGER) {
        const int prefix = sqlite3_column_int(statement, prefix_column);

        if (prefix >= 0 && prefix <= 128) {
            scope->type = JG_POLICY_SCOPE_IPV6;
            (void)memcpy(scope->value.network.address, value, 16U);
            scope->value.network.prefix_length = (uint8_t)prefix;
            return 0;
        }
    }
    if (strcmp(type, "vlan") == 0 &&
        sqlite3_column_type(statement, vlan_column) == SQLITE_INTEGER) {
        const int vlan_id = sqlite3_column_int(statement, vlan_column);

        if (vlan_id >= 0 && vlan_id <= 4094) {
            scope->type = JG_POLICY_SCOPE_VLAN;
            scope->value.vlan_id = (uint16_t)vlan_id;
            return 0;
        }
    }
    return -EILSEQ;
}

/** @brief Decode one selected database row into snapshot-builder input. */
static int decode_domain_rule(sqlite3_stmt *statement,
                              struct jg_policy_rule_input *rule,
                              char *strings,
                              size_t strings_size,
                              size_t *cursor)
{
    const char *domain = NULL;
    const char *match_type = NULL;
    const char *effect = NULL;
    const char *source = NULL;
    const char *scope = NULL;
    const char *attribution = NULL;
    const char *target = NULL;
    size_t domain_length = 0U;
    size_t text_length = 0U;
    size_t attribution_length = 0U;
    sqlite3_int64 identifier = 0;
    int result = 0;

    if (sqlite3_column_type(statement, 0) != SQLITE_INTEGER) {
        return -EILSEQ;
    }
    identifier = sqlite3_column_int64(statement, 0);
    if (identifier <= 0) {
        return -EILSEQ;
    }
    result =
        jg_database_column_required_text(statement, 1, &domain, &domain_length);
    if (result == 0 && !jg_domain_is_normalized(domain)) {
        result = -EILSEQ;
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 2, &match_type,
                                                  &text_length);
    }
    if (result == 0) {
        if (strcmp(match_type, "suffix") == 0) {
            rule->include_subdomains = true;
        } else if (strcmp(match_type, "exact") != 0) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 3, &effect,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_effect(effect, &rule->effect);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 4, &source,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_source(source, &rule->source);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 5, &scope,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_scope(statement, scope, 6, 7, 8, &rule->scope);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 9, &attribution,
                                                  &attribution_length);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 10, &target,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_target(target, &rule->target);
    }
    if (result == 0 &&
        (!jg_range_valid(*cursor, domain_length + 1U, strings_size) ||
         !jg_range_valid(*cursor + domain_length + 1U, attribution_length + 1U,
                         strings_size))) {
        result = -EOVERFLOW;
    }
    if (result == 0) {
        rule->id = (uint64_t)identifier;
        rule->domain = strings + *cursor;
        (void)memcpy(strings + *cursor, domain, domain_length);
        strings[*cursor + domain_length] = '\0';
        *cursor += domain_length + 1U;
        rule->attribution = strings + *cursor;
        (void)memcpy(strings + *cursor, attribution, attribution_length);
        strings[*cursor + attribution_length] = '\0';
        *cursor += attribution_length + 1U;
    }
    return result;
}

/** @brief Decode one persistent destination address and prefix. */
static int decode_destination_address(
    sqlite3_stmt *statement,
    struct jg_policy_destination_rule_input *rule)
{
    const int address_type = sqlite3_column_type(statement, 5);

    if (address_type == SQLITE_NULL) {
        return sqlite3_column_type(statement, 4) == SQLITE_NULL &&
                       sqlite3_column_type(statement, 6) == SQLITE_NULL
                   ? 0
                   : -EILSEQ;
    }
    if (address_type == SQLITE_BLOB &&
        sqlite3_column_type(statement, 4) == SQLITE_INTEGER &&
        sqlite3_column_type(statement, 6) == SQLITE_INTEGER) {
        const int family = sqlite3_column_int(statement, 4);
        const int prefix = sqlite3_column_int(statement, 6);
        const int address_size = sqlite3_column_bytes(statement, 5);
        const void *address = sqlite3_column_blob(statement, 5);

        if ((family == 4 && address_size == 4 && prefix >= 0 && prefix <= 32) ||
            (family == 6 && address_size == 16 && prefix >= 0 &&
             prefix <= 128)) {
            rule->has_address = true;
            rule->address_family = (enum jg_policy_address_family)family;
            rule->prefix_length = (uint8_t)prefix;
            (void)memcpy(rule->address, address, (size_t)address_size);
            return 0;
        }
    }
    return -EILSEQ;
}

/** @brief Decode one selected destination-rule database row. */
static int decode_destination_rule(
    sqlite3_stmt *statement,
    struct jg_policy_destination_rule_input *rule,
    char *strings,
    size_t strings_size,
    size_t *cursor)
{
    const char *effect = NULL;
    const char *source = NULL;
    const char *transport = NULL;
    const char *scope = NULL;
    const char *attribution = NULL;
    size_t text_length = 0U;
    size_t attribution_length = 0U;
    sqlite3_int64 identifier = 0;
    int result = 0;

    if (sqlite3_column_type(statement, 0) != SQLITE_INTEGER) {
        return -EILSEQ;
    }
    identifier = sqlite3_column_int64(statement, 0);
    if (identifier <= 0) {
        return -EILSEQ;
    }
    result =
        jg_database_column_required_text(statement, 1, &effect, &text_length);
    if (result == 0) {
        result = decode_effect(effect, &rule->effect);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 2, &source,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_source(source, &rule->source);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 3, &transport,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_transport(transport, &rule->transport);
    }
    if (result == 0) {
        result = decode_destination_address(statement, rule);
    }
    if (result == 0 && sqlite3_column_type(statement, 7) != SQLITE_NULL) {
        const int port = sqlite3_column_int(statement, 7);

        if (sqlite3_column_type(statement, 7) != SQLITE_INTEGER || port <= 0 ||
            port > 65535) {
            result = -EILSEQ;
        } else {
            rule->has_port = true;
            rule->port = (uint16_t)port;
        }
    }
    if (result == 0 && !rule->has_address && !rule->has_port) {
        result = -EILSEQ;
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 8, &scope,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_scope(statement, scope, 9, 10, 11, &rule->scope);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 12, &attribution,
                                                  &attribution_length);
    }
    if (result == 0 &&
        !jg_range_valid(*cursor, attribution_length + 1U, strings_size)) {
        result = -EOVERFLOW;
    }
    if (result == 0) {
        rule->id = (uint64_t)identifier;
        rule->attribution = strings + *cursor;
        (void)memcpy(strings + *cursor, attribution, attribution_length);
        strings[*cursor + attribution_length] = '\0';
        *cursor += attribution_length + 1U;
    }
    return result;
}

/** @brief Decode enabled, modification time, and revision columns. */
static int decode_rule_metadata(sqlite3_stmt *statement,
                                int enabled_column,
                                int updated_at_column,
                                int revision_column,
                                bool *enabled,
                                uint64_t *updated_at,
                                uint64_t *revision)
{
    sqlite3_int64 persistent_updated_at = 0;
    sqlite3_int64 persistent_revision = 0;
    int persistent_enabled = 0;

    if (sqlite3_column_type(statement, enabled_column) != SQLITE_INTEGER ||
        sqlite3_column_type(statement, updated_at_column) != SQLITE_INTEGER ||
        sqlite3_column_type(statement, revision_column) != SQLITE_INTEGER) {
        return -EILSEQ;
    }
    persistent_enabled = sqlite3_column_int(statement, enabled_column);
    persistent_updated_at = sqlite3_column_int64(statement, updated_at_column);
    persistent_revision = sqlite3_column_int64(statement, revision_column);
    if ((persistent_enabled != 0 && persistent_enabled != 1) ||
        persistent_updated_at < 0 || persistent_revision <= 0) {
        return -EILSEQ;
    }
    *enabled = persistent_enabled != 0;
    *updated_at = (uint64_t)persistent_updated_at;
    *revision = (uint64_t)persistent_revision;
    return 0;
}

/** @brief Decode one persistent domain rule into an owned record. */
static int decode_domain_record(sqlite3_stmt *statement,
                                struct jg_database_domain_rule *record)
{
    char strings[JG_DOMAIN_NAME_MAX + JG_POLICY_ATTRIBUTION_MAX + 2U];
    struct jg_policy_rule_input rule;
    size_t cursor = 0U;
    int result = 0;

    (void)memset(&rule, 0, sizeof(rule));
    (void)memset(record, 0, sizeof(*record));
    result =
        decode_domain_rule(statement, &rule, strings, sizeof(strings), &cursor);
    if (result == 0) {
        result = decode_rule_metadata(statement, 11, 12, 13, &record->enabled,
                                      &record->updated_at, &record->revision);
    }
    if (result == 0 && sqlite3_column_type(statement, 14) != SQLITE_TEXT) {
        result = -EILSEQ;
    }
    if (result == 0) {
        result = jg_database_column_optional_text(
            statement, 14, record->category, sizeof(record->category));
    }
    if (result == 0 && !jg_utf8_text_valid((const uint8_t *)record->category,
                                           strlen(record->category), true)) {
        result = -EILSEQ;
    }
    if (result == 0) {
        record->id = rule.id;
        record->include_subdomains = rule.include_subdomains;
        record->effect = rule.effect;
        record->source = rule.source;
        record->target = rule.target;
        record->scope = rule.scope;
        (void)memcpy(record->domain, rule.domain, strlen(rule.domain) + 1U);
        (void)memcpy(record->attribution, rule.attribution,
                     strlen(rule.attribution) + 1U);
    }
    return result;
}

/** @brief Decode one persistent destination rule into an owned record. */
static int decode_destination_record(
    sqlite3_stmt *statement,
    struct jg_database_destination_rule *record)
{
    char strings[JG_POLICY_ATTRIBUTION_MAX + 1U];
    struct jg_policy_destination_rule_input rule;
    size_t cursor = 0U;
    int result = 0;

    (void)memset(&rule, 0, sizeof(rule));
    (void)memset(record, 0, sizeof(*record));
    result = decode_destination_rule(statement, &rule, strings, sizeof(strings),
                                     &cursor);
    if (result == 0) {
        result = decode_rule_metadata(statement, 13, 14, 15, &record->enabled,
                                      &record->updated_at, &record->revision);
    }
    if (result == 0) {
        record->id = rule.id;
        record->effect = rule.effect;
        record->source = rule.source;
        record->transport = rule.transport;
        record->has_address = rule.has_address;
        record->address_family = rule.address_family;
        (void)memcpy(record->address, rule.address, sizeof(record->address));
        record->prefix_length = rule.prefix_length;
        record->has_port = rule.has_port;
        record->port = rule.port;
        record->scope = rule.scope;
        (void)memcpy(record->attribution, rule.attribution,
                     strlen(rule.attribution) + 1U);
    }
    return result;
}

/** @brief Read one stable identifier-ordered page of domain rules. */
int jg_database_list_domain_rules(struct jg_database *database,
                                  uint64_t after_id,
                                  size_t limit,
                                  struct jg_database_domain_rule *rules,
                                  size_t *count,
                                  bool *has_more)
{
    static const char query[] =
        "SELECT id,domain,match_type,effect,source,scope_type,scope_value,"
        "prefix_length,vlan_id,attribution,target,enabled,updated_at,revision,"
        "category FROM domain_rules WHERE id>?1 ORDER BY id LIMIT ?2;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    bool more = false;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || after_id > (uint64_t)INT64_MAX || limit == 0U ||
        limit > JG_DATABASE_POLICY_PAGE_MAX || rules == NULL || count == NULL ||
        has_more == NULL) {
        return -EINVAL;
    }
    *count = 0U;
    *has_more = false;
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)after_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 2, (int)(limit + 1U));
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (index == limit) {
            more = true;
            break;
        }
        result = decode_domain_record(statement, &rules[index]);
        ++index;
    }
    if (result == 0 && !more && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *count = index;
        *has_more = more;
    }
    return result;
}

/** @brief Validate one new or replacement domain rule. */
static int validate_domain_rule(const struct jg_policy_rule_input *rule,
                                bool creating)
{
    struct jg_policy_rule_input validation;

    if (rule == NULL) {
        return -EINVAL;
    }
    if (creating && rule->id != 0U) {
        return -EINVAL;
    }
    if (!creating && (rule->id == 0U || rule->id > (uint64_t)INT64_MAX)) {
        return -EINVAL;
    }
    validation = *rule;
    if (creating) {
        validation.id = 1U;
    }
    return validate_domain_rules(&validation, 1U);
}

/** @brief Read one domain record by its exact identifier. */
static int read_domain_record(struct jg_database *database,
                              uint64_t rule_id,
                              struct jg_database_domain_rule *record)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_domain_rules(database, rule_id - 1U, 1U,
                                               record, &count, &has_more);

    (void)has_more;
    if (result == 0 && (count != 1U || record->id != rule_id)) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Create one persistent domain rule with an assigned identifier. */
int jg_database_create_domain_rule(struct jg_database *database,
                                   const struct jg_policy_rule_input *rule,
                                   bool enabled,
                                   struct jg_database_domain_rule *created)
{
    static const char insert[] =
        "INSERT INTO domain_rules("
        "id,domain,match_type,effect,source,scope_type,scope_value,"
        "prefix_length,vlan_id,attribution,enabled,updated_at,target"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?12,unixepoch(),?11);";
    struct jg_database_domain_rule record;
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 identifier = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || created == NULL) {
        return -EINVAL;
    }
    (void)memset(created, 0, sizeof(*created));
    result = validate_domain_rule(rule, true);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_domain_rule(statement, rule);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 12, enabled ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        identifier = sqlite3_last_insert_rowid(database->handle);
        if (identifier <= 0) {
            result = -EIO;
        } else {
            result =
                read_domain_record(database, (uint64_t)identifier, &record);
        }
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        *created = record;
    }
    return result;
}

/** @brief Replace one domain rule at its expected revision. */
int jg_database_update_domain_rule(struct jg_database *database,
                                   const struct jg_policy_rule_input *rule,
                                   bool enabled,
                                   uint64_t expected_revision,
                                   struct jg_database_domain_rule *updated)
{
    static const char revision_query[] =
        "SELECT revision FROM domain_rules WHERE id=?1;";
    static const char update[] =
        "UPDATE domain_rules SET domain=?2,match_type=?3,effect=?4,source=?5,"
        "scope_type=?6,scope_value=?7,prefix_length=?8,vlan_id=?9,"
        "attribution=?10,target=?11,enabled=?12,updated_at=unixepoch(),"
        "revision=revision+1 WHERE id=?1 AND revision=?13"
        " AND revision<9223372036854775807;";
    struct jg_database_domain_rule record;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || expected_revision == 0U ||
        expected_revision > (uint64_t)INT64_MAX || updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result = validate_domain_rule(rule, false);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_domain_rule(statement, rule);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 12, enabled ? 1 : 0);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 13,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_write_conflict(database->handle, revision_query,
                                            rule->id, expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = read_domain_record(database, rule->id, &record);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        *updated = record;
    }
    return result;
}

/** @brief Delete one domain rule at its expected revision. */
int jg_database_delete_domain_rule(struct jg_database *database,
                                   uint64_t rule_id,
                                   uint64_t expected_revision)
{
    static const char revision_query[] =
        "SELECT revision FROM domain_rules WHERE id=?1;";
    static const char remove[] =
        "DELETE FROM domain_rules WHERE id=?1 AND revision=?2;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || rule_id == 0U || rule_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin(database);
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, remove, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)rule_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_write_conflict(database->handle, revision_query,
                                            rule_id, expected_revision, false);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    return result;
}

/** @brief Read one stable identifier-ordered page of destination rules. */
int jg_database_list_destination_rules(
    struct jg_database *database,
    uint64_t after_id,
    size_t limit,
    struct jg_database_destination_rule *rules,
    size_t *count,
    bool *has_more)
{
    static const char query[] =
        "SELECT id,effect,source,protocol,family,address,prefix_length,port,"
        "scope_type,scope_value,scope_prefix_length,scope_vlan_id,attribution,"
        "enabled,updated_at,revision FROM destination_rules WHERE id>?1"
        " ORDER BY id LIMIT ?2;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    bool more = false;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || after_id > (uint64_t)INT64_MAX || limit == 0U ||
        limit > JG_DATABASE_POLICY_PAGE_MAX || rules == NULL || count == NULL ||
        has_more == NULL) {
        return -EINVAL;
    }
    *count = 0U;
    *has_more = false;
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)after_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 2, (int)(limit + 1U));
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (index == limit) {
            more = true;
            break;
        }
        result = decode_destination_record(statement, &rules[index]);
        ++index;
    }
    if (result == 0 && !more && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *count = index;
        *has_more = more;
    }
    return result;
}

/** @brief Validate one new or replacement destination rule. */
static int validate_destination_rule(
    const struct jg_policy_destination_rule_input *rule,
    bool creating)
{
    struct jg_policy_destination_rule_input validation;

    if (rule == NULL) {
        return -EINVAL;
    }
    if (creating && rule->id != 0U) {
        return -EINVAL;
    }
    if (!creating && (rule->id == 0U || rule->id > (uint64_t)INT64_MAX)) {
        return -EINVAL;
    }
    validation = *rule;
    if (creating) {
        validation.id = 1U;
    }
    return validate_destination_rules(&validation, 1U);
}

/** @brief Read one destination record by its exact identifier. */
static int read_destination_record(struct jg_database *database,
                                   uint64_t rule_id,
                                   struct jg_database_destination_rule *record)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_destination_rules(database, rule_id - 1U, 1U,
                                                    record, &count, &has_more);

    (void)has_more;
    if (result == 0 && (count != 1U || record->id != rule_id)) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Create one destination rule with an assigned identifier. */
int jg_database_create_destination_rule(
    struct jg_database *database,
    const struct jg_policy_destination_rule_input *rule,
    bool enabled,
    struct jg_database_destination_rule *created)
{
    static const char insert[] =
        "INSERT INTO destination_rules("
        "id,effect,source,protocol,family,address,prefix_length,port,"
        "scope_type,scope_value,scope_prefix_length,scope_vlan_id,"
        "attribution,enabled,updated_at"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,"
        "unixepoch());";
    struct jg_database_destination_rule record;
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 identifier = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || created == NULL) {
        return -EINVAL;
    }
    (void)memset(created, 0, sizeof(*created));
    result = validate_destination_rule(rule, true);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_destination_rule(statement, rule);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 14, enabled ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        identifier = sqlite3_last_insert_rowid(database->handle);
        if (identifier <= 0) {
            result = -EIO;
        } else {
            result = read_destination_record(database, (uint64_t)identifier,
                                             &record);
        }
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        *created = record;
    }
    return result;
}

/** @brief Replace one destination rule at its expected revision. */
int jg_database_update_destination_rule(
    struct jg_database *database,
    const struct jg_policy_destination_rule_input *rule,
    bool enabled,
    uint64_t expected_revision,
    struct jg_database_destination_rule *updated)
{
    static const char revision_query[] =
        "SELECT revision FROM destination_rules WHERE id=?1;";
    static const char update[] =
        "UPDATE destination_rules SET effect=?2,source=?3,protocol=?4,"
        "family=?5,address=?6,prefix_length=?7,port=?8,scope_type=?9,"
        "scope_value=?10,scope_prefix_length=?11,scope_vlan_id=?12,"
        "attribution=?13,enabled=?14,updated_at=unixepoch(),"
        "revision=revision+1 WHERE id=?1 AND revision=?15"
        " AND revision<9223372036854775807;";
    struct jg_database_destination_rule record;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || expected_revision == 0U ||
        expected_revision > (uint64_t)INT64_MAX || updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result = validate_destination_rule(rule, false);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_destination_rule(statement, rule);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 14, enabled ? 1 : 0);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 15,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_write_conflict(database->handle, revision_query,
                                            rule->id, expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = read_destination_record(database, rule->id, &record);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        *updated = record;
    }
    return result;
}

/** @brief Delete one destination rule at its expected revision. */
int jg_database_delete_destination_rule(struct jg_database *database,
                                        uint64_t rule_id,
                                        uint64_t expected_revision)
{
    static const char revision_query[] =
        "SELECT revision FROM destination_rules WHERE id=?1;";
    static const char remove[] =
        "DELETE FROM destination_rules WHERE id=?1 AND revision=?2;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || rule_id == 0U || rule_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin(database);
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, remove, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)rule_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_write_conflict(database->handle, revision_query,
                                            rule_id, expected_revision, false);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    return result;
}

/** @brief Read active rule counts and packed-string bytes. */
static int read_policy_size(sqlite3 *handle,
                            size_t *rule_count,
                            size_t *strings_size)
{
    static const char query[] =
        "SELECT count(*),coalesce(sum("
        "length(CAST(r.domain AS BLOB))+"
        "length(CAST(r.attribution AS BLOB))+2),0)"
        " FROM domain_rules AS r LEFT JOIN blocklist_sources AS s"
        " ON s.id=r.blocklist_source_id WHERE r.enabled=1"
        " AND (r.source!='blocklist' OR r.blocklist_source_id IS NULL"
        " OR s.enabled=1);";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, query, -1, 0U, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            const sqlite3_int64 count = sqlite3_column_int64(statement, 0);
            const sqlite3_int64 bytes = sqlite3_column_int64(statement, 1);

            if (count < 0 ||
                count > (sqlite3_int64)JG_DATABASE_POLICY_RULE_LIMIT ||
                bytes < 0 || (uint64_t)bytes > (uint64_t)SIZE_MAX) {
                result = -EOVERFLOW;
            } else {
                *rule_count = (size_t)count;
                *strings_size = (size_t)bytes;
            }
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Read active destination-rule count and attribution bytes. */
static int read_destination_policy_size(sqlite3 *handle,
                                        size_t *rule_count,
                                        size_t *strings_size)
{
    static const char query[] = "SELECT count(*),coalesce(sum("
                                "length(CAST(attribution AS BLOB))+1),0)"
                                " FROM destination_rules WHERE enabled=1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, query, -1, 0U, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            const sqlite3_int64 count = sqlite3_column_int64(statement, 0);
            const sqlite3_int64 bytes = sqlite3_column_int64(statement, 1);

            if (count < 0 ||
                count > (sqlite3_int64)JG_DATABASE_POLICY_RULE_LIMIT ||
                bytes < 0 || (uint64_t)bytes > (uint64_t)SIZE_MAX) {
                result = -EOVERFLOW;
            } else {
                *rule_count = (size_t)count;
                *strings_size = (size_t)bytes;
            }
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Read enabled encrypted-DNS endpoint count and attribution bytes. */
static int read_encrypted_endpoint_size(sqlite3 *handle,
                                        size_t *rule_count,
                                        size_t *strings_size)
{
    static const char query[] =
        "SELECT count(*),coalesce(sum(length(CAST(s.name AS BLOB))+1),0)"
        " FROM encrypted_dns_endpoints e"
        " JOIN encrypted_dns_sources s ON s.id=e.source_id"
        " WHERE s.enabled=1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, query, -1, 0U, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            const sqlite3_int64 count = sqlite3_column_int64(statement, 0);
            const sqlite3_int64 bytes = sqlite3_column_int64(statement, 1);

            if (count < 0 ||
                count > (sqlite3_int64)JG_DATABASE_POLICY_RULE_LIMIT ||
                bytes < 0 || (uint64_t)bytes > (uint64_t)SIZE_MAX) {
                result = -EOVERFLOW;
            } else {
                *rule_count = (size_t)count;
                *strings_size = (size_t)bytes;
            }
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Copy one consistent active-rule view into caller-owned storage. */
static int read_domain_rules(sqlite3 *handle,
                             struct jg_policy_rule_input *rules,
                             size_t rule_count,
                             char *strings,
                             size_t strings_size)
{
    static const char query[] =
        "SELECT r.id,r.domain,r.match_type,r.effect,r.source,r.scope_type,"
        "r.scope_value,r.prefix_length,r.vlan_id,r.attribution,r.target"
        " FROM domain_rules AS r LEFT JOIN blocklist_sources AS s"
        " ON s.id=r.blocklist_source_id WHERE r.enabled=1"
        " AND (r.source!='blocklist' OR r.blocklist_source_id IS NULL"
        " OR s.enabled=1) ORDER BY r.id;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    size_t cursor = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (handle == NULL ||
        (rule_count != 0U && (rules == NULL || strings == NULL))) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(handle, query, -1, SQLITE_PREPARE_PERSISTENT,
                                &statement, NULL);
    result = jg_database_sqlite_result(status);
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (index >= rule_count) {
            result = -EILSEQ;
        } else {
            result = decode_domain_rule(statement, &rules[index], strings,
                                        strings_size, &cursor);
            ++index;
        }
    }
    if (result == 0 && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && (index != rule_count || cursor != strings_size)) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Copy one consistent active destination-rule view. */
static int read_destination_rules(
    sqlite3 *handle,
    struct jg_policy_destination_rule_input *rules,
    size_t rule_count,
    char *strings,
    size_t strings_size)
{
    static const char query[] =
        "SELECT id,effect,source,protocol,family,address,prefix_length,port,"
        "scope_type,scope_value,scope_prefix_length,scope_vlan_id,attribution "
        "FROM destination_rules WHERE enabled=1 ORDER BY id;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    size_t cursor = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (handle == NULL ||
        (rule_count != 0U && (rules == NULL || strings == NULL))) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(handle, query, -1, SQLITE_PREPARE_PERSISTENT,
                                &statement, NULL);
    result = jg_database_sqlite_result(status);
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (index >= rule_count) {
            result = -EILSEQ;
        } else {
            result = decode_destination_rule(statement, &rules[index], strings,
                                             strings_size, &cursor);
            ++index;
        }
    }
    if (result == 0 && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && (index != rule_count || cursor != strings_size)) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Copy enabled encrypted-DNS endpoints into destination-rule input. */
static int read_encrypted_endpoints(
    sqlite3 *handle,
    struct jg_policy_destination_rule_input *rules,
    size_t rule_count,
    char *strings,
    size_t strings_size)
{
    static const char query[] =
        "SELECT s.name,e.family,e.address,e.port,e.transport"
        " FROM encrypted_dns_endpoints e"
        " JOIN encrypted_dns_sources s ON s.id=e.source_id"
        " WHERE s.enabled=1"
        " ORDER BY s.id,e.family,e.address,e.port,e.transport;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    size_t cursor = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (handle == NULL ||
        (rule_count != 0U && (rules == NULL || strings == NULL))) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(handle, query, -1, SQLITE_PREPARE_PERSISTENT,
                                &statement, NULL);
    result = jg_database_sqlite_result(status);
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        const char *attribution = NULL;
        const char *transport = NULL;
        const void *address = sqlite3_column_blob(statement, 2);
        const int address_size = sqlite3_column_bytes(statement, 2);
        const int family = sqlite3_column_int(statement, 1);
        const int port = sqlite3_column_int(statement, 3);
        size_t attribution_size = 0U;
        size_t text_size = 0U;

        if (index >= rule_count ||
            sqlite3_column_type(statement, 1) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 2) != SQLITE_BLOB ||
            sqlite3_column_type(statement, 3) != SQLITE_INTEGER || port <= 0 ||
            port > 65535 ||
            !((family == 4 && address_size == 4) ||
              (family == 6 && address_size == 16))) {
            result = -EILSEQ;
        }
        if (result == 0) {
            result = jg_database_column_required_text(
                statement, 0, &attribution, &attribution_size);
        }
        if (result == 0) {
            result = jg_database_column_required_text(statement, 4, &transport,
                                                      &text_size);
        }
        if (result == 0) {
            result = decode_transport(transport, &rules[index].transport);
        }
        if (result == 0 && rules[index].transport != JG_POLICY_TRANSPORT_TCP &&
            rules[index].transport != JG_POLICY_TRANSPORT_UDP) {
            result = -EILSEQ;
        }
        if (result == 0 &&
            !jg_range_valid(cursor, attribution_size + 1U, strings_size)) {
            result = -EOVERFLOW;
        }
        if (result == 0) {
            rules[index].id = (UINT64_C(1) << 63U) | (uint64_t)(index + 1U);
            rules[index].effect = JG_POLICY_BLOCK;
            rules[index].source = JG_POLICY_SOURCE_BLOCKLIST;
            rules[index].has_address = true;
            rules[index].address_family = (enum jg_policy_address_family)family;
            (void)memcpy(rules[index].address, address, (size_t)address_size);
            rules[index].prefix_length = family == 4 ? 32U : 128U;
            rules[index].has_port = true;
            rules[index].port = (uint16_t)port;
            rules[index].scope.type = JG_POLICY_SCOPE_GLOBAL;
            rules[index].attribution = strings + cursor;
            (void)memcpy(strings + cursor, attribution, attribution_size);
            strings[cursor + attribution_size] = '\0';
            cursor += attribution_size + 1U;
            ++index;
        }
    }
    if (result == 0 && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && (index != rule_count || cursor != strings_size)) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Load active persistent rules into a new immutable snapshot. */
int jg_database_load_policy_snapshot(struct jg_database *database,
                                     uint64_t generation,
                                     struct jg_policy_snapshot **snapshot)
{
    struct jg_policy_rule_input *rules = NULL;
    struct jg_policy_destination_rule_input *destination_rules = NULL;
    char *strings = NULL;
    char *destination_strings = NULL;
    size_t rule_count = 0U;
    size_t destination_rule_count = 0U;
    size_t encrypted_endpoint_count = 0U;
    size_t complete_destination_count = 0U;
    size_t strings_size = 0U;
    size_t destination_strings_size = 0U;
    size_t encrypted_strings_size = 0U;
    size_t complete_destination_strings_size = 0U;
    size_t rules_size = 0U;
    size_t destination_rules_size = 0U;
    int result = 0;

    if (snapshot == NULL) {
        return -EINVAL;
    }
    *snapshot = NULL;
    if (database == NULL || generation == 0U) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin_read(database);
    if (result == 0) {
        result = read_policy_size(database->handle, &rule_count, &strings_size);
    }
    if (result == 0) {
        result = read_destination_policy_size(database->handle,
                                              &destination_rule_count,
                                              &destination_strings_size);
    }
    if (result == 0) {
        result = read_encrypted_endpoint_size(database->handle,
                                              &encrypted_endpoint_count,
                                              &encrypted_strings_size);
    }
    if (result == 0 &&
        (!jg_size_add(destination_rule_count, encrypted_endpoint_count,
                      &complete_destination_count) ||
         complete_destination_count > JG_DATABASE_POLICY_RULE_LIMIT ||
         !jg_size_add(destination_strings_size, encrypted_strings_size,
                      &complete_destination_strings_size))) {
        result = -EOVERFLOW;
    }
    if (result == 0 &&
        !jg_size_multiply(rule_count, sizeof(*rules), &rules_size)) {
        result = -EOVERFLOW;
    }
    if (result == 0 && !jg_size_multiply(complete_destination_count,
                                         sizeof(*destination_rules),
                                         &destination_rules_size)) {
        result = -EOVERFLOW;
    }
    if (result == 0 && rule_count != 0U) {
        rules = calloc(1U, rules_size);
        strings = malloc(strings_size);
        if (rules == NULL || strings == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (destination_rule_count != 0U || encrypted_endpoint_count != 0U)) {
        destination_rules = calloc(1U, destination_rules_size);
        destination_strings = malloc(complete_destination_strings_size);
        if (destination_rules == NULL || destination_strings == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = read_domain_rules(database->handle, rules, rule_count, strings,
                                   strings_size);
    }
    if (result == 0) {
        result = read_destination_rules(
            database->handle, destination_rules, destination_rule_count,
            destination_strings, destination_strings_size);
    }
    if (result == 0 && encrypted_endpoint_count != 0U) {
        result = read_encrypted_endpoints(
            database->handle, destination_rules + destination_rule_count,
            encrypted_endpoint_count,
            destination_strings + destination_strings_size,
            encrypted_strings_size);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        result = jg_policy_snapshot_build_complete(
            rules, rule_count, destination_rules, complete_destination_count,
            generation, snapshot);
    }
    free(destination_strings);
    free(destination_rules);
    free(strings);
    free(rules);
    return result;
}
