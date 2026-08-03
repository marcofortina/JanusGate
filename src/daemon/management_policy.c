/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_policy.c
 * @brief DNS policy and destination-rule management.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "janusgate/access.h"
#include "janusgate/audit.h"
#include "janusgate/database.h"
#include "janusgate/policy.h"

/** @brief Advance, publish, and persist one policy revision attempt. */
int management_publish_policy_change(struct jg_management *management,
                                     uint64_t now,
                                     bool *published,
                                     uint64_t *runtime_generation)
{
    struct jg_database_policy_sync sync;
    const char *error = NULL;
    int publish_result = 0;
    int result = 0;

    if (management == NULL || published == NULL || runtime_generation == NULL) {
        return -EINVAL;
    }
    *published = false;
    *runtime_generation = 0U;
    result = jg_database_policy_sync_advance(management->database, now, &sync);
    if (result == 0) {
        publish_result = management->runtime == NULL
                             ? -ENODEV
                             : jg_daemon_runtime_reload_policy_from_database(
                                   management->runtime, management->database);
    }
    if (result == 0 && publish_result == 0) {
        publish_result = jg_daemon_runtime_get_policy_generation(
            management->runtime, runtime_generation);
    }
    if (result == 0) {
        *published = publish_result == 0;
        if (!*published) {
            error = management->runtime == NULL ? "runtime_unavailable"
                                                : "runtime_reload_failed";
        }
        result = jg_database_policy_sync_record(management->database,
                                                sync.desired_revision,
                                                *published, error, now, &sync);
    }
    return result;
}

/** @brief Parse one exact colon-separated 48-bit MAC address. */
static int parse_mac_address(const char *text, uint8_t address[6U])
{
    uint8_t parsed[6U];

    if (text == NULL || strlen(text) != 17U) {
        return -EINVAL;
    }
    for (size_t index = 0U; index < sizeof(parsed); ++index) {
        uint8_t high = 0U;
        uint8_t low = 0U;
        const size_t offset = index * 3U;

        if (hexadecimal_value(text[offset], &high) != 0 ||
            hexadecimal_value(text[offset + 1U], &low) != 0 ||
            (index + 1U < sizeof(parsed) && text[offset + 2U] != ':')) {
            return -EINVAL;
        }
        parsed[index] = (uint8_t)((high << 4U) | low);
    }
    (void)memcpy(address, parsed, sizeof(parsed));
    return 0;
}

/** @brief Return the stable external name for one policy action. */
static const char *policy_effect_name(enum jg_policy_effect effect)
{
    switch (effect) {
    case JG_POLICY_ALLOW:
        return "allow";
    case JG_POLICY_BLOCK:
        return "block";
    default:
        return NULL;
    }
}

/** @brief Return the stable external name for one enforcement mode. */
static const char *policy_enforcement_name(
    enum jg_policy_enforcement enforcement)
{
    switch (enforcement) {
    case JG_POLICY_ENFORCE:
        return "enforce";
    case JG_POLICY_OBSERVE:
        return "observe";
    default:
        return NULL;
    }
}

/** @brief Return the stable external name for one policy source. */
static const char *policy_source_name(enum jg_policy_source source)
{
    switch (source) {
    case JG_POLICY_SOURCE_DEFAULT:
        return "default";
    case JG_POLICY_SOURCE_BLOCKLIST:
        return "blocklist";
    case JG_POLICY_SOURCE_EXPLICIT:
        return "explicit";
    case JG_POLICY_SOURCE_EMERGENCY:
        return "emergency";
    default:
        return NULL;
    }
}

/** @brief Return the stable external name for one domain policy target. */
static const char *policy_target_name(enum jg_policy_domain_target target)
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

/** @brief Return the stable external name for one policy scope. */
static const char *policy_scope_name(enum jg_policy_scope_type type)
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

/** @brief Convert one canonical client scope to public JSON. */
static json_t *policy_scope_json(const struct jg_policy_scope *scope)
{
    char address[INET6_ADDRSTRLEN];
    char mac[18U];
    const char *name = policy_scope_name(scope->type);
    json_t *body = json_object();
    int written = 0;
    int result = 0;

    if (name == NULL || body == NULL ||
        json_object_set_new(body, "type", json_string(name)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && scope->type == JG_POLICY_SCOPE_MAC) {
        written = snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                           scope->value.mac[0U], scope->value.mac[1U],
                           scope->value.mac[2U], scope->value.mac[3U],
                           scope->value.mac[4U], scope->value.mac[5U]);
        if (written != (int)(sizeof(mac) - 1U) ||
            json_object_set_new(body, "address", json_string(mac)) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 && (scope->type == JG_POLICY_SCOPE_IPV4 ||
                        scope->type == JG_POLICY_SCOPE_IPV6)) {
        const int family =
            scope->type == JG_POLICY_SCOPE_IPV4 ? AF_INET : AF_INET6;

        if (inet_ntop(family, scope->value.network.address, address,
                      sizeof(address)) == NULL ||
            json_object_set_new(body, "address", json_string(address)) != 0 ||
            json_object_set_new(
                body, "prefix_length",
                json_integer((json_int_t)scope->value.network.prefix_length)) !=
                0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 && scope->type == JG_POLICY_SCOPE_VLAN &&
        json_object_set_new(body, "vlan",
                            json_integer((json_int_t)scope->value.vlan_id)) !=
            0) {
        result = -ENOMEM;
    }
    if (result != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Convert one persistent domain rule to public JSON. */
static json_t *domain_rule_json(const struct jg_database_domain_rule *rule)
{
    const char *effect = policy_effect_name(rule->effect);
    const char *source = policy_source_name(rule->source);
    const char *target = policy_target_name(rule->target);
    json_t *body = json_object();
    json_t *scope = policy_scope_json(&rule->scope);

    if (effect == NULL || source == NULL || target == NULL || body == NULL ||
        scope == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)rule->id)) !=
            0 ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)rule->revision)) != 0 ||
        json_object_set_new(body, "updated_at",
                            json_integer((json_int_t)rule->updated_at)) != 0 ||
        json_object_set_new(body, "domain", json_string(rule->domain)) != 0 ||
        json_object_set_new(body, "include_subdomains",
                            json_boolean(rule->include_subdomains)) != 0 ||
        json_object_set_new(body, "action", json_string(effect)) != 0 ||
        json_object_set_new(body, "source", json_string(source)) != 0 ||
        json_object_set_new(body, "target", json_string(target)) != 0 ||
        json_object_set_new(body, "attribution",
                            json_string(rule->attribution)) != 0 ||
        json_object_set_new(body, "category", json_string(rule->category)) !=
            0 ||
        json_object_set_new(body, "enabled", json_boolean(rule->enabled)) !=
            0 ||
        json_object_set(body, "scope", scope) != 0) {
        json_decref(scope);
        json_decref(body);
        return NULL;
    }
    json_decref(scope);
    return body;
}

/** @brief Return the stable external name for one transport selector. */
static const char *policy_transport_name(enum jg_policy_transport transport)
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

/** @brief Convert one persistent destination rule to public JSON. */
static json_t *destination_rule_json(
    const struct jg_database_destination_rule *rule)
{
    char address[INET6_ADDRSTRLEN];
    const char *effect = policy_effect_name(rule->effect);
    const char *source = policy_source_name(rule->source);
    const char *transport = policy_transport_name(rule->transport);
    json_t *body = json_object();
    json_t *scope = policy_scope_json(&rule->scope);
    int result = 0;

    if (rule->has_address) {
        const int family =
            rule->address_family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6;

        if (inet_ntop(family, rule->address, address, sizeof(address)) ==
            NULL) {
            result = -EINVAL;
        }
    }
    if (result != 0 || effect == NULL || source == NULL || transport == NULL ||
        body == NULL || scope == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)rule->id)) !=
            0 ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)rule->revision)) != 0 ||
        json_object_set_new(body, "updated_at",
                            json_integer((json_int_t)rule->updated_at)) != 0 ||
        json_object_set_new(body, "action", json_string(effect)) != 0 ||
        json_object_set_new(body, "source", json_string(source)) != 0 ||
        json_object_set_new(body, "transport", json_string(transport)) != 0 ||
        json_object_set_new(body, "address",
                            rule->has_address ? json_string(address)
                                              : json_null()) != 0 ||
        json_object_set_new(body, "prefix_length",
                            rule->has_address
                                ? json_integer((json_int_t)rule->prefix_length)
                                : json_null()) != 0 ||
        json_object_set_new(body, "port",
                            rule->has_port
                                ? json_integer((json_int_t)rule->port)
                                : json_null()) != 0 ||
        json_object_set_new(body, "attribution",
                            json_string(rule->attribution)) != 0 ||
        json_object_set_new(body, "enabled", json_boolean(rule->enabled)) !=
            0 ||
        json_object_set(body, "scope", scope) != 0) {
        json_decref(scope);
        json_decref(body);
        return NULL;
    }
    json_decref(scope);
    return body;
}

/** @brief Parse one optional external domain policy target. */
static bool parse_policy_target(const char *text,
                                enum jg_policy_domain_target *target)
{
    if (text == NULL || target == NULL) {
        return false;
    }
    if (text[0U] == '\0' || strcmp(text, "dns") == 0) {
        *target = JG_POLICY_DOMAIN_DNS;
        return true;
    }
    if (strcmp(text, "tls_sni") == 0) {
        *target = JG_POLICY_DOMAIN_TLS_SNI;
        return true;
    }
    return false;
}

/** @brief Parse one external allow or block action. */
static bool parse_policy_effect(const char *text, enum jg_policy_effect *effect)
{
    if (text == NULL || effect == NULL) {
        return false;
    }
    if (strcmp(text, "allow") == 0) {
        *effect = JG_POLICY_ALLOW;
        return true;
    }
    if (strcmp(text, "block") == 0) {
        *effect = JG_POLICY_BLOCK;
        return true;
    }
    return false;
}

/** @brief Parse one strict domain-rule client scope object. */
static int parse_policy_scope(json_t *object, struct jg_policy_scope *scope)
{
    static const char *const global_fields[] = {"type"};
    static const char *const address_fields[] = {"type", "address"};
    static const char *const network_fields[] = {
        "type",
        "address",
        "prefix_length",
    };
    static const char *const vlan_fields[] = {"type", "vlan"};
    const char *type = NULL;
    const char *address = NULL;
    json_t *prefix_value = NULL;
    json_t *vlan_value = NULL;
    json_int_t number = -1;
    int family = AF_UNSPEC;

    (void)memset(scope, 0, sizeof(*scope));
    if (!json_is_object(object)) {
        return -EINVAL;
    }
    type = required_string(object, "type", 3U, 6U);
    if (type == NULL) {
        return -EINVAL;
    }
    if (strcmp(type, "global") == 0) {
        if (!fields_allowed(object, global_fields,
                            sizeof(global_fields) /
                                sizeof(global_fields[0U]))) {
            return -EINVAL;
        }
        scope->type = JG_POLICY_SCOPE_GLOBAL;
        return 0;
    }
    if (strcmp(type, "mac") == 0) {
        address = required_string(object, "address", 17U, 17U);
        if (!fields_allowed(object, address_fields,
                            sizeof(address_fields) /
                                sizeof(address_fields[0U])) ||
            parse_mac_address(address, scope->value.mac) != 0) {
            return -EINVAL;
        }
        scope->type = JG_POLICY_SCOPE_MAC;
        return 0;
    }
    if (strcmp(type, "ipv4") == 0 || strcmp(type, "ipv6") == 0) {
        address = required_string(object, "address", 2U, INET6_ADDRSTRLEN - 1U);
        prefix_value = json_object_get(object, "prefix_length");
        number = json_is_integer(prefix_value)
                     ? json_integer_value(prefix_value)
                     : -1;
        family = strcmp(type, "ipv4") == 0 ? AF_INET : AF_INET6;
        if (!fields_allowed(object, network_fields,
                            sizeof(network_fields) /
                                sizeof(network_fields[0U])) ||
            address == NULL || number < 0 ||
            number > (family == AF_INET ? 32 : 128) ||
            inet_pton(family, address, scope->value.network.address) != 1) {
            return -EINVAL;
        }
        scope->type =
            family == AF_INET ? JG_POLICY_SCOPE_IPV4 : JG_POLICY_SCOPE_IPV6;
        scope->value.network.prefix_length = (uint8_t)number;
        return 0;
    }
    if (strcmp(type, "vlan") == 0) {
        vlan_value = json_object_get(object, "vlan");
        number =
            json_is_integer(vlan_value) ? json_integer_value(vlan_value) : -1;
        if (!fields_allowed(object, vlan_fields,
                            sizeof(vlan_fields) / sizeof(vlan_fields[0U])) ||
            number < 0 || number > 4094) {
            return -EINVAL;
        }
        scope->type = JG_POLICY_SCOPE_VLAN;
        scope->value.vlan_id = (uint16_t)number;
        return 0;
    }
    return -EINVAL;
}

/** @brief Parse one complete explicit domain-rule request body. */
static int parse_domain_rule_request(json_t *body,
                                     uint64_t rule_id,
                                     bool updating,
                                     struct jg_policy_rule_input *rule,
                                     bool *enabled,
                                     uint64_t *revision)
{
    static const char *const create_fields[] = {
        "domain", "include_subdomains", "action",  "target",
        "scope",  "attribution",        "enabled",
    };
    static const char *const update_fields[] = {
        "revision", "domain", "include_subdomains", "action",
        "target",   "scope",  "attribution",        "enabled",
    };
    const char *domain = required_string(body, "domain", 1U, 1024U);
    const char *action = required_string(body, "action", 5U, 5U);
    const char *target = required_string(body, "target", 3U, 7U);
    const char *attribution =
        required_string(body, "attribution", 1U, JG_POLICY_ATTRIBUTION_MAX);
    json_t *scope = json_object_get(body, "scope");
    int result = 0;

    (void)memset(rule, 0, sizeof(*rule));
    *revision = 0U;
    if ((updating &&
         !fields_allowed(body, update_fields,
                         sizeof(update_fields) / sizeof(update_fields[0U]))) ||
        (!updating &&
         !fields_allowed(body, create_fields,
                         sizeof(create_fields) / sizeof(create_fields[0U]))) ||
        domain == NULL || action == NULL || target == NULL ||
        attribution == NULL ||
        !required_boolean(body, "include_subdomains",
                          &rule->include_subdomains) ||
        !required_boolean(body, "enabled", enabled) ||
        !parse_policy_effect(action, &rule->effect) ||
        !parse_policy_target(target, &rule->target)) {
        return -EINVAL;
    }
    if (updating && !required_identifier(body, "revision", revision)) {
        return -EINVAL;
    }
    result = parse_policy_scope(scope, &rule->scope);
    if (result == 0) {
        rule->id = rule_id;
        rule->domain = domain;
        rule->source = JG_POLICY_SOURCE_EXPLICIT;
        rule->attribution = attribution;
    }
    return result;
}

/** @brief Parse one destination-rule transport selector. */
static bool parse_policy_transport_selector(const char *text,
                                            enum jg_policy_transport *transport)
{
    if (text == NULL || transport == NULL) {
        return false;
    }
    if (strcmp(text, "any") == 0) {
        *transport = JG_POLICY_TRANSPORT_ANY;
        return true;
    }
    if (strcmp(text, "tcp") == 0) {
        *transport = JG_POLICY_TRANSPORT_TCP;
        return true;
    }
    if (strcmp(text, "udp") == 0) {
        *transport = JG_POLICY_TRANSPORT_UDP;
        return true;
    }
    return false;
}

/** @brief Parse one complete explicit destination-rule request body. */
static int parse_destination_rule_request(
    json_t *body,
    uint64_t rule_id,
    bool updating,
    struct jg_policy_destination_rule_input *rule,
    bool *enabled,
    uint64_t *revision)
{
    static const char *const create_fields[] = {
        "action", "transport", "address",     "prefix_length",
        "port",   "scope",     "attribution", "enabled",
    };
    static const char *const update_fields[] = {
        "revision", "action", "transport",   "address", "prefix_length",
        "port",     "scope",  "attribution", "enabled",
    };
    const char *action = required_string(body, "action", 5U, 5U);
    const char *transport = required_string(body, "transport", 3U, 3U);
    const char *attribution =
        required_string(body, "attribution", 1U, JG_POLICY_ATTRIBUTION_MAX);
    json_t *address_value = json_object_get(body, "address");
    json_t *prefix_value = json_object_get(body, "prefix_length");
    json_t *port_value = json_object_get(body, "port");
    json_t *scope = json_object_get(body, "scope");
    const char *address =
        json_is_string(address_value) ? json_string_value(address_value) : NULL;
    json_int_t prefix =
        json_is_integer(prefix_value) ? json_integer_value(prefix_value) : -1;
    json_int_t port =
        json_is_integer(port_value) ? json_integer_value(port_value) : -1;
    int result = 0;

    (void)memset(rule, 0, sizeof(*rule));
    *revision = 0U;
    if ((updating &&
         !fields_allowed(body, update_fields,
                         sizeof(update_fields) / sizeof(update_fields[0U]))) ||
        (!updating &&
         !fields_allowed(body, create_fields,
                         sizeof(create_fields) / sizeof(create_fields[0U]))) ||
        action == NULL || transport == NULL || attribution == NULL ||
        address_value == NULL || prefix_value == NULL || port_value == NULL ||
        !required_boolean(body, "enabled", enabled) ||
        !parse_policy_effect(action, &rule->effect) ||
        !parse_policy_transport_selector(transport, &rule->transport)) {
        return -EINVAL;
    }
    if (updating && !required_identifier(body, "revision", revision)) {
        return -EINVAL;
    }
    if (json_is_string(address_value)) {
        if (bounded_length(address, INET6_ADDRSTRLEN - 1U) >=
            INET6_ADDRSTRLEN) {
            return -EINVAL;
        }
        if (inet_pton(AF_INET, address, rule->address) == 1 && prefix >= 0 &&
            prefix <= 32) {
            rule->address_family = JG_POLICY_ADDRESS_IPV4;
        } else if (inet_pton(AF_INET6, address, rule->address) == 1 &&
                   prefix >= 0 && prefix <= 128) {
            rule->address_family = JG_POLICY_ADDRESS_IPV6;
        } else {
            return -EINVAL;
        }
        rule->has_address = true;
        rule->prefix_length = (uint8_t)prefix;
    } else if (!json_is_null(address_value) || !json_is_null(prefix_value)) {
        return -EINVAL;
    }
    if (json_is_integer(port_value)) {
        if (port <= 0 || port > 65535) {
            return -EINVAL;
        }
        rule->has_port = true;
        rule->port = (uint16_t)port;
    } else if (!json_is_null(port_value)) {
        return -EINVAL;
    }
    if (!rule->has_address && !rule->has_port) {
        return -EINVAL;
    }
    result = parse_policy_scope(scope, &rule->scope);
    if (result == 0) {
        rule->id = rule_id;
        rule->source = JG_POLICY_SOURCE_EXPLICIT;
        rule->attribution = attribution;
    }
    return result;
}

/** @brief Parse one external TCP or UDP policy transport. */
static bool parse_policy_transport(const char *text,
                                   enum jg_policy_transport *transport)
{
    if (text == NULL || transport == NULL) {
        return false;
    }
    if (strcmp(text, "tcp") == 0) {
        *transport = JG_POLICY_TRANSPORT_TCP;
        return true;
    }
    if (strcmp(text, "udp") == 0) {
        *transport = JG_POLICY_TRANSPORT_UDP;
        return true;
    }
    return false;
}

/** @brief Return the stable external name for a selected policy dimension. */
static const char *policy_dimension_name(
    enum jg_policy_match_dimension dimension)
{
    switch (dimension) {
    case JG_POLICY_MATCH_DEFAULT:
        return "default";
    case JG_POLICY_MATCH_DOMAIN:
        return "domain";
    case JG_POLICY_MATCH_DESTINATION:
        return "destination";
    default:
        return NULL;
    }
}

/** @brief Serialize the rule that supplies one effective dimension verdict. */
static json_t *policy_simulation_enforcing_json(
    const struct jg_policy_simulation_match *match,
    enum jg_policy_match_dimension dimension)
{
    const char *effect = policy_effect_name(match->effect);
    const char *source = policy_source_name(match->enforcing_source);
    const char *dimension_name = policy_dimension_name(dimension);
    json_t *body = NULL;

    if (!match->enforcing_matched) {
        return json_null();
    }
    body = json_object();
    if (effect == NULL || source == NULL || dimension_name == NULL ||
        body == NULL ||
        json_object_set_new(body, "dimension", json_string(dimension_name)) !=
            0 ||
        json_object_set_new(body, "action", json_string(effect)) != 0 ||
        json_object_set_new(
            body, "rule_id",
            json_integer((json_int_t)match->enforcing_rule_id)) != 0 ||
        json_object_set_new(body, "source", json_string(source)) != 0 ||
        json_object_set_new(body, "domain",
                            match->enforcing_domain[0U] == '\0'
                                ? json_null()
                                : json_string(match->enforcing_domain)) != 0 ||
        json_object_set_new(body, "attribution",
                            match->enforcing_attribution[0U] == '\0'
                                ? json_null()
                                : json_string(match->enforcing_attribution)) !=
            0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Convert one self-contained simulated rule match to JSON. */
static json_t *policy_simulation_match_json(
    const struct jg_policy_simulation_match *match,
    enum jg_policy_match_dimension dimension)
{
    const char *effect = policy_effect_name(match->effect);
    const char *configured_effect =
        policy_effect_name(match->configured_effect);
    const char *enforcement = policy_enforcement_name(match->enforcement);
    const char *source = policy_source_name(match->source);
    const char *dimension_name = policy_dimension_name(dimension);
    json_t *body = json_object();
    json_t *enforcing_rule = policy_simulation_enforcing_json(match, dimension);

    if (effect == NULL || configured_effect == NULL || enforcement == NULL ||
        source == NULL || dimension_name == NULL || body == NULL ||
        enforcing_rule == NULL ||
        json_object_set_new(body, "dimension", json_string(dimension_name)) !=
            0 ||
        json_object_set_new(body, "matched", json_boolean(match->matched)) !=
            0 ||
        json_object_set_new(body, "action", json_string(effect)) != 0 ||
        json_object_set_new(body, "configured_action",
                            json_string(configured_effect)) != 0 ||
        json_object_set_new(body, "enforcement", json_string(enforcement)) !=
            0 ||
        json_object_set_new(body, "would_have_blocked",
                            json_boolean(match->would_have_blocked)) != 0 ||
        json_object_set_new(body, "rule_id",
                            match->matched
                                ? json_integer((json_int_t)match->rule_id)
                                : json_null()) != 0 ||
        json_object_set_new(body, "source", json_string(source)) != 0 ||
        json_object_set_new(body, "domain",
                            match->domain[0U] == '\0'
                                ? json_null()
                                : json_string(match->domain)) != 0 ||
        json_object_set_new(body, "attribution",
                            match->attribution[0U] == '\0'
                                ? json_null()
                                : json_string(match->attribution)) != 0 ||
        json_object_set(body, "enforcing_rule", enforcing_rule) != 0) {
        json_decref(enforcing_rule);
        json_decref(body);
        return NULL;
    }
    json_decref(enforcing_rule);
    return body;
}

/** @brief Append one stable, human-readable policy explanation step. */
static int append_policy_explanation(json_t *steps, const char *text)
{
    return json_array_append_new(steps, json_string(text)) == 0 ? 0 : -ENOMEM;
}

/** @brief Describe the configured and effective winners of one simulation. */
static int build_policy_explanation(
    const struct jg_policy_simulation *simulation,
    json_t *steps)
{
    const struct jg_policy_simulation_match *selected_match = NULL;
    const struct jg_policy_simulation_match *effective_match = NULL;
    const char *selected_dimension =
        policy_dimension_name(simulation->selected);
    const char *effective_dimension =
        policy_dimension_name(simulation->effective_selected);
    const char *configured_effect =
        policy_effect_name(simulation->configured_effect);
    const char *effect = policy_effect_name(simulation->effect);
    char text[768U];
    int written = 0;

    if (selected_dimension == NULL || effective_dimension == NULL ||
        configured_effect == NULL || effect == NULL) {
        return -EINVAL;
    }
    if (simulation->selected == JG_POLICY_MATCH_DOMAIN) {
        selected_match = &simulation->domain;
    } else if (simulation->selected == JG_POLICY_MATCH_DESTINATION) {
        selected_match = &simulation->destination;
    }
    if (simulation->effective_selected == JG_POLICY_MATCH_DOMAIN) {
        effective_match = &simulation->domain;
    } else if (simulation->effective_selected == JG_POLICY_MATCH_DESTINATION) {
        effective_match = &simulation->destination;
    }
    if (selected_match == NULL) {
        if (append_policy_explanation(steps, "No configured rule matched.") !=
            0) {
            return -ENOMEM;
        }
    } else {
        written = snprintf(text, sizeof(text),
                           "Rule %llu (%s) selected %s in the %s policy.",
                           (unsigned long long)selected_match->rule_id,
                           selected_match->attribution[0U] == '\0'
                               ? policy_source_name(selected_match->source)
                               : selected_match->attribution,
                           configured_effect, selected_dimension);
        if (written <= 0 || (size_t)written >= sizeof(text) ||
            append_policy_explanation(steps, text) != 0) {
            return -ENOMEM;
        }
        if (simulation->would_have_blocked) {
            written = snprintf(
                text, sizeof(text),
                "Rule %llu is observe-only; its block is not enforced.",
                (unsigned long long)selected_match->rule_id);
            if (written <= 0 || (size_t)written >= sizeof(text) ||
                append_policy_explanation(steps, text) != 0) {
                return -ENOMEM;
            }
        }
    }
    if (effective_match != NULL && effective_match->enforcing_matched) {
        written = snprintf(
            text, sizeof(text),
            "Rule %llu (%s) supplies the effective %s action in the %s "
            "policy.",
            (unsigned long long)effective_match->enforcing_rule_id,
            effective_match->enforcing_attribution[0U] == '\0'
                ? policy_source_name(effective_match->enforcing_source)
                : effective_match->enforcing_attribution,
            effect, effective_dimension);
        if (written <= 0 || (size_t)written >= sizeof(text) ||
            append_policy_explanation(steps, text) != 0) {
            return -ENOMEM;
        }
    } else if (append_policy_explanation(
                   steps,
                   "No enforced rule blocks the request; the default action "
                   "is allow.") != 0) {
        return -ENOMEM;
    }
    written = snprintf(text, sizeof(text), "Effective action: %s.", effect);
    return written > 0 && (size_t)written < sizeof(text)
               ? append_policy_explanation(steps, text)
               : -ENOMEM;
}

/** @brief Serialize one complete policy simulation explanation. */
static json_t *policy_simulation_json(
    const struct jg_policy_simulation *simulation)
{
    const char *effect = policy_effect_name(simulation->effect);
    const char *configured_effect =
        policy_effect_name(simulation->configured_effect);
    const char *target = policy_target_name(simulation->target);
    const char *selected = policy_dimension_name(simulation->selected);
    const char *effective_selected =
        policy_dimension_name(simulation->effective_selected);
    const struct jg_policy_simulation_match *selected_match = NULL;
    const struct jg_policy_simulation_match *effective_match = NULL;
    json_t *body = json_object();
    json_t *domain = policy_simulation_match_json(&simulation->domain,
                                                  JG_POLICY_MATCH_DOMAIN);
    json_t *destination =
        simulation->destination_evaluated
            ? policy_simulation_match_json(&simulation->destination,
                                           JG_POLICY_MATCH_DESTINATION)
            : json_null();
    json_t *matching_rule = NULL;
    json_t *effective_rule = NULL;
    json_t *path = json_array();
    json_t *sources = json_array();
    json_t *explanation = json_array();
    int result = 0;

    if (simulation->selected == JG_POLICY_MATCH_DOMAIN) {
        selected_match = &simulation->domain;
    } else if (simulation->selected == JG_POLICY_MATCH_DESTINATION) {
        selected_match = &simulation->destination;
    }
    if (simulation->effective_selected == JG_POLICY_MATCH_DOMAIN) {
        effective_match = &simulation->domain;
    } else if (simulation->effective_selected == JG_POLICY_MATCH_DESTINATION) {
        effective_match = &simulation->destination;
    }
    matching_rule = selected_match == NULL
                        ? json_null()
                        : policy_simulation_match_json(selected_match,
                                                       simulation->selected);
    effective_rule = effective_match == NULL
                         ? json_null()
                         : policy_simulation_enforcing_json(
                               effective_match, simulation->effective_selected);
    if (effect == NULL || configured_effect == NULL || target == NULL ||
        selected == NULL || effective_selected == NULL || body == NULL ||
        domain == NULL || destination == NULL || matching_rule == NULL ||
        effective_rule == NULL || path == NULL || sources == NULL ||
        explanation == NULL || simulation->generation > (uint64_t)INT64_MAX) {
        result = -ENOMEM;
    }
    if (result == 0) {
        result = build_policy_explanation(simulation, explanation);
    }
    if (result == 0 && simulation->destination_evaluated &&
        json_array_append_new(path, json_string("destination")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        !(simulation->selected == JG_POLICY_MATCH_DESTINATION &&
          simulation->effect == JG_POLICY_BLOCK) &&
        json_array_append_new(path, json_string("domain")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && simulation->selected == JG_POLICY_MATCH_DEFAULT &&
        json_array_append_new(path, json_string("default")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && simulation->destination.attribution[0U] != '\0' &&
        json_array_append_new(
            sources, json_string(simulation->destination.attribution)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && simulation->domain.attribution[0U] != '\0' &&
        (simulation->destination.attribution[0U] == '\0' ||
         strcmp(simulation->domain.attribution,
                simulation->destination.attribution) != 0) &&
        json_array_append_new(
            sources, json_string(simulation->domain.attribution)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (json_object_set_new(body, "normalized_domain",
                             json_string(simulation->normalized_domain)) != 0 ||
         json_object_set_new(body, "target", json_string(target)) != 0 ||
         json_object_set_new(body, "action", json_string(effect)) != 0 ||
         json_object_set_new(body, "configured_action",
                             json_string(configured_effect)) != 0 ||
         json_object_set_new(body, "would_have_blocked",
                             json_boolean(simulation->would_have_blocked)) !=
             0 ||
         json_object_set_new(body, "selected", json_string(selected)) != 0 ||
         json_object_set_new(body, "effective_selected",
                             json_string(effective_selected)) != 0 ||
         json_object_set_new(
             body, "policy_generation",
             json_integer((json_int_t)simulation->generation)) != 0 ||
         json_object_set(body, "domain_match", domain) != 0 ||
         json_object_set(body, "destination_match", destination) != 0 ||
         json_object_set(body, "matching_rule", matching_rule) != 0 ||
         json_object_set(body, "effective_rule", effective_rule) != 0 ||
         json_object_set(body, "precedence_path", path) != 0 ||
         json_object_set(body, "sources", sources) != 0 ||
         json_object_set(body, "explanation", explanation) != 0)) {
        result = -ENOMEM;
    }
    json_decref(domain);
    json_decref(destination);
    json_decref(matching_rule);
    json_decref(effective_rule);
    json_decref(path);
    json_decref(sources);
    json_decref(explanation);
    if (result != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Append one domain-rule mutation and publication outcome. */
static int append_domain_rule_audit(struct jg_management *management,
                                    const struct management_request *request,
                                    const struct remote_address *remote,
                                    const struct authenticated_actor *actor,
                                    const char *action,
                                    bool has_previous_revision,
                                    uint64_t previous_revision,
                                    bool has_new_revision,
                                    const struct jg_database_domain_rule *rule,
                                    bool published,
                                    uint64_t generation,
                                    uint64_t now)
{
    char object_id[32U];
    char source_address[INET6_ADDRSTRLEN];
    const char *effect = policy_effect_name(rule->effect);
    const char *target = policy_target_name(rule->target);
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int written = snprintf(object_id, sizeof(object_id), "%llu",
                           (unsigned long long)rule->id);
    int result = 0;

    if (written <= 0 || (size_t)written >= sizeof(object_id) ||
        effect == NULL || target == NULL ||
        inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source_address,
                  sizeof(source_address)) == NULL ||
        details == NULL ||
        json_object_set_new(details, "domain", json_string(rule->domain)) !=
            0 ||
        json_object_set_new(details, "action", json_string(effect)) != 0 ||
        json_object_set_new(details, "target", json_string(target)) != 0 ||
        json_object_set_new(details, "include_subdomains",
                            json_boolean(rule->include_subdomains)) != 0 ||
        json_object_set_new(details, "enabled", json_boolean(rule->enabled)) !=
            0 ||
        json_object_set_new(details, "published", json_boolean(published)) !=
            0 ||
        json_object_set_new(details, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0) {
        encoded = json_dumps(details, JSON_COMPACT | JSON_SORT_KEYS);
        if (encoded == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        event = (struct jg_audit_event){
            .occurred_at = now,
            .actor_type = actor_audit_type(actor),
            .has_actor_id = actor_has_identifier(actor),
            .actor_id = actor->actor_id,
            .source = source_address,
            .action = action,
            .object_type = "domain_rule",
            .object_id = object_id,
            .details = encoded,
            .has_previous_revision = has_previous_revision,
            .previous_revision = previous_revision,
            .has_new_revision = has_new_revision,
            .new_revision = rule->revision,
            .success = published,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one destination-rule mutation and publication outcome. */
static int append_destination_rule_audit(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const char *action,
    bool has_previous_revision,
    uint64_t previous_revision,
    bool has_new_revision,
    const struct jg_database_destination_rule *rule,
    bool published,
    uint64_t generation,
    uint64_t now)
{
    char object_id[32U];
    char source_address[INET6_ADDRSTRLEN];
    json_t *details = destination_rule_json(rule);
    char *encoded = NULL;
    struct jg_audit_event event;
    int written = snprintf(object_id, sizeof(object_id), "%llu",
                           (unsigned long long)rule->id);
    int result = 0;

    if (written <= 0 || (size_t)written >= sizeof(object_id) ||
        inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source_address,
                  sizeof(source_address)) == NULL ||
        details == NULL ||
        json_object_set_new(details, "published", json_boolean(published)) !=
            0 ||
        json_object_set_new(details, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0) {
        encoded = json_dumps(details, JSON_COMPACT | JSON_SORT_KEYS);
        if (encoded == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        event = (struct jg_audit_event){
            .occurred_at = now,
            .actor_type = actor_audit_type(actor),
            .has_actor_id = actor_has_identifier(actor),
            .actor_id = actor->actor_id,
            .source = source_address,
            .action = action,
            .object_type = "destination_rule",
            .object_id = object_id,
            .details = encoded,
            .has_previous_revision = has_previous_revision,
            .previous_revision = previous_revision,
            .has_new_revision = has_new_revision,
            .new_revision = rule->revision,
            .success = published,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Simulate one authenticated decision on the active policy snapshot. */
int handle_policy_simulation(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written)
{
    static const char *const fields[] = {
        "domain", "target",         "source_ip",        "source_mac",
        "vlan",   "destination_ip", "destination_port", "transport",
    };
    struct authenticated_actor actor;
    struct jg_policy_client client;
    struct jg_policy_destination destination;
    struct jg_policy_simulation simulation;
    struct remote_address parsed_address;
    const char *domain = NULL;
    const char *target_text = NULL;
    const char *source_ip = NULL;
    const char *source_mac = NULL;
    const char *destination_ip = NULL;
    const char *transport_text = NULL;
    json_t *target_value = json_object_get(request->body, "target");
    json_t *source_ip_value = json_object_get(request->body, "source_ip");
    json_t *source_mac_value = json_object_get(request->body, "source_mac");
    json_t *vlan_value = json_object_get(request->body, "vlan");
    json_t *destination_ip_value =
        json_object_get(request->body, "destination_ip");
    json_t *destination_port_value =
        json_object_get(request->body, "destination_port");
    json_t *transport_value = json_object_get(request->body, "transport");
    enum jg_policy_domain_target target = JG_POLICY_DOMAIN_DNS;
    bool has_client = false;
    bool has_destination = false;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_POLICY_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    (void)memset(&client, 0, sizeof(client));
    (void)memset(&destination, 0, sizeof(destination));
    domain = required_string(request->body, "domain", 1U, 1024U);
    target_text = optional_string(request->body, "target", 7U);
    source_ip =
        optional_string(request->body, "source_ip", INET6_ADDRSTRLEN - 1U);
    source_mac = optional_string(request->body, "source_mac", 17U);
    destination_ip =
        optional_string(request->body, "destination_ip", INET6_ADDRSTRLEN - 1U);
    transport_text = optional_string(request->body, "transport", 3U);
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        domain == NULL || target_text == NULL || source_ip == NULL ||
        source_mac == NULL || destination_ip == NULL ||
        transport_text == NULL ||
        (target_value != NULL && target_text[0U] == '\0') ||
        (source_ip_value != NULL && source_ip[0U] == '\0') ||
        (source_mac_value != NULL && source_mac[0U] == '\0') ||
        (destination_ip_value != NULL && destination_ip[0U] == '\0') ||
        (transport_value != NULL && transport_text[0U] == '\0') ||
        !parse_policy_target(target_text, &target)) {
        return respond_error(400, "invalid_body",
                             "The policy-simulation request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (source_ip[0U] != '\0') {
        result = parse_remote_address(source_ip, &parsed_address);
        if (result == 0) {
            client.address_family = parsed_address.family;
            (void)memcpy(client.address, parsed_address.address,
                         parsed_address.family == JG_POLICY_ADDRESS_IPV4 ? 4U
                                                                         : 16U);
            has_client = true;
        }
    }
    if (result == 0 && source_mac[0U] != '\0') {
        result = parse_mac_address(source_mac, client.mac);
        if (result == 0) {
            client.has_mac = true;
            has_client = true;
        }
    }
    if (result == 0 && vlan_value != NULL) {
        const json_int_t vlan =
            json_is_integer(vlan_value) ? json_integer_value(vlan_value) : -1;

        if (vlan < 0 || vlan > 4094) {
            result = -EINVAL;
        } else {
            client.has_vlan = true;
            client.vlan_id = (uint16_t)vlan;
            has_client = true;
        }
    }
    has_destination = destination_ip[0U] != '\0';
    if (result == 0 && has_destination) {
        const json_int_t port = json_is_integer(destination_port_value)
                                    ? json_integer_value(destination_port_value)
                                    : -1;

        result = parse_remote_address(destination_ip, &parsed_address);
        if (result == 0 &&
            (!parse_policy_transport(transport_text, &destination.transport) ||
             port <= 0 || port > 65535)) {
            result = -EINVAL;
        }
        if (result == 0) {
            destination.address_family = parsed_address.family;
            (void)memcpy(destination.address, parsed_address.address,
                         parsed_address.family == JG_POLICY_ADDRESS_IPV4 ? 4U
                                                                         : 16U);
            destination.port = (uint16_t)port;
        }
    } else if (result == 0 &&
               (destination_port_value != NULL || transport_value != NULL)) {
        result = -EINVAL;
    }
    if (result != 0) {
        return respond_error(400, "invalid_body",
                             "The policy-simulation request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = jg_daemon_runtime_simulate_policy(
        management->runtime, target, domain, has_client ? &client : NULL,
        has_destination ? &destination : NULL, &simulation);
    if (result == -EINVAL || result == -ENOSPC) {
        return respond_error(
            400, "invalid_simulation",
            "The simulation input is not a valid policy query.",
            request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    body = policy_simulation_json(&simulation);
    if (body == NULL) {
        return -ENOMEM;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Refresh shared health from persistent policy publication state. */
void jg_management_refresh_policy_health(struct jg_management *management)
{
    if (management != NULL) {
        refresh_policy_sync_health(management);
    }
}

/** @brief Return one authenticated stable page of domain rules. */
int handle_domain_rules_list(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_domain_rule *rules = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    uint64_t after_id = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    bool has_more = false;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_POLICY_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_page_query(request->query, "after_id",
                         JG_DATABASE_POLICY_PAGE_MAX, &after_id, &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The domain-rule pagination is not valid.",
                             request->request_id, output, output_size, written);
    }
    rules = calloc(limit, sizeof(*rules));
    if (rules == NULL) {
        return -ENOMEM;
    }
    result = jg_database_list_domain_rules(management->database, after_id,
                                           limit, rules, &count, &has_more);
    if (result != 0) {
        free(rules);
        return respond_error(500, "domains_unavailable",
                             "The domain rules could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = domain_rule_json(&rules[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "after_id",
                             json_integer((json_int_t)after_id)) != 0 ||
         json_object_set_new(body, "limit", json_integer((json_int_t)limit)) !=
             0 ||
         json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "has_more", json_boolean(has_more)) != 0 ||
         json_object_set(body, "domains", items) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        json_t *next = has_more && count > 0U
                           ? json_integer((json_int_t)rules[count - 1U].id)
                           : json_null();

        if (json_object_set_new(body, "next_after_id", next) != 0) {
            result = -ENOMEM;
        }
    }
    free(rules);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Return one authenticated stable page of destination rules. */
int handle_destination_rules_list(struct jg_management *management,
                                  const struct management_request *request,
                                  const struct remote_address *remote,
                                  uint64_t now,
                                  uint8_t *output,
                                  size_t output_size,
                                  size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_destination_rule *rules = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    uint64_t after_id = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    bool has_more = false;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_POLICY_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_page_query(request->query, "after_id",
                         JG_DATABASE_POLICY_PAGE_MAX, &after_id, &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The destination-rule pagination is not valid.",
                             request->request_id, output, output_size, written);
    }
    rules = calloc(limit, sizeof(*rules));
    if (rules == NULL) {
        return -ENOMEM;
    }
    result = jg_database_list_destination_rules(
        management->database, after_id, limit, rules, &count, &has_more);
    if (result != 0) {
        free(rules);
        return respond_error(500, "destinations_unavailable",
                             "The destination rules could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = destination_rule_json(&rules[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "after_id",
                             json_integer((json_int_t)after_id)) != 0 ||
         json_object_set_new(body, "limit", json_integer((json_int_t)limit)) !=
             0 ||
         json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "has_more", json_boolean(has_more)) != 0 ||
         json_object_set(body, "destination_rules", items) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        json_t *next = has_more && count > 0U
                           ? json_integer((json_int_t)rules[count - 1U].id)
                           : json_null();

        if (json_object_set_new(body, "next_after_id", next) != 0) {
            result = -ENOMEM;
        }
    }
    free(rules);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Publish persistent policy and audit one domain-rule change. */
static int publish_domain_rule_change(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const char *action,
    bool has_previous_revision,
    uint64_t previous_revision,
    bool has_new_revision,
    const struct jg_database_domain_rule *rule,
    uint64_t now,
    bool *published,
    uint64_t *generation)
{
    int result = management_publish_policy_change(management, now, published,
                                                  generation);

    if (result == 0) {
        result = append_domain_rule_audit(management, request, remote, actor,
                                          action, has_previous_revision,
                                          previous_revision, has_new_revision,
                                          rule, *published, *generation, now);
    }
    return result;
}

/** @brief Encode one created or updated domain-rule result. */
static int respond_domain_rule(int status,
                               const struct jg_database_domain_rule *rule,
                               bool published,
                               uint64_t generation,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    json_t *body = json_object();
    json_t *item = domain_rule_json(rule);

    if (body == NULL || item == NULL ||
        json_object_set(body, "domain", item) != 0 ||
        json_object_set_new(body, "published", json_boolean(published)) != 0 ||
        json_object_set_new(body, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
        json_decref(item);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(item);
    return encode_response(status, body, NULL, output, output_size, written);
}

/** @brief Create one explicit domain rule and publish a new snapshot. */
int handle_domain_rule_create(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    struct authenticated_actor actor;
    struct jg_policy_rule_input rule;
    struct jg_database_domain_rule created = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool enabled = false;
    bool published = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = parse_domain_rule_request(request->body, 0U, false, &rule,
                                       &enabled, &revision);
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The domain-rule request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = audited_mutation_begin(management);
    if (result == 0) {
        result = jg_database_create_domain_rule(management->database, &rule,
                                                enabled, &created);
    }
    result = audited_mutation_check(management, result);
    if (result == -EINVAL || result == -ERANGE || result == -ENOSPC) {
        return respond_error(400, "invalid_domain_rule",
                             "The domain-rule properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "domain_create_failed",
                             "The domain rule could not be created.",
                             request->request_id, output, output_size, written);
    }
    result = publish_domain_rule_change(management, request, remote, &actor,
                                        "policy.domain.create", false, 0U, true,
                                        &created, now, &published, &generation);
    result = audited_mutation_finish(management, result, true);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The domain-rule creation and its audit were not committed.",
            request->request_id, output, output_size, written);
    }
    return respond_domain_rule(published ? 201 : 202, &created, published,
                               generation, output, output_size, written);
}

/** @brief Read one exact domain rule for guarded mutation. */
static int get_domain_rule(struct jg_database *database,
                           uint64_t rule_id,
                           struct jg_database_domain_rule *rule)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_domain_rules(database, rule_id - 1U, 1U, rule,
                                               &count, &has_more);

    (void)has_more;
    return result == 0 && (count != 1U || rule->id != rule_id) ? -ENOENT
                                                               : result;
}

/** @brief Update one explicit domain rule and publish a new snapshot. */
int handle_domain_rule_update(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t rule_id,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    struct authenticated_actor actor;
    struct jg_policy_rule_input rule;
    struct jg_database_domain_rule previous = {0};
    struct jg_database_domain_rule updated = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool enabled = false;
    bool published = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = parse_domain_rule_request(request->body, rule_id, true, &rule,
                                       &enabled, &revision);
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The domain-rule update is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = get_domain_rule(management->database, rule_id, &previous);
    if (result == 0 && previous.source != JG_POLICY_SOURCE_EXPLICIT) {
        return respond_error(
            409, "managed_domain_rule",
            "This rule is managed by its policy source and cannot be edited.",
            request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = audited_mutation_begin(management);
    }
    if (result == 0) {
        result = jg_database_update_domain_rule(management->database, &rule,
                                                enabled, revision, &updated);
    }
    result = audited_mutation_check(management, result);
    if (result == -ENOENT) {
        return respond_error(404, "domain_not_found",
                             "The domain rule was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "The domain rule has changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -ERANGE || result == -ENOSPC) {
        return respond_error(400, "invalid_domain_rule",
                             "The domain-rule properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "domain_update_failed",
                             "The domain rule could not be updated.",
                             request->request_id, output, output_size, written);
    }
    result = publish_domain_rule_change(
        management, request, remote, &actor, "policy.domain.update", true,
        revision, true, &updated, now, &published, &generation);
    result = audited_mutation_finish(management, result, true);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The domain-rule update and its audit were not committed.",
            request->request_id, output, output_size, written);
    }
    return respond_domain_rule(published ? 200 : 202, &updated, published,
                               generation, output, output_size, written);
}

/** @brief Delete one explicit domain rule and publish a new snapshot. */
int handle_domain_rule_delete(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t rule_id,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    static const char *const fields[] = {"revision"};
    struct authenticated_actor actor;
    struct jg_database_domain_rule removed = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        !required_identifier(request->body, "revision", &revision)) {
        return respond_error(400, "invalid_body",
                             "The domain-rule deletion is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = get_domain_rule(management->database, rule_id, &removed);
    if (result == 0 && removed.source != JG_POLICY_SOURCE_EXPLICIT) {
        return respond_error(
            409, "managed_domain_rule",
            "This rule is managed by its policy source and cannot be deleted.",
            request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = audited_mutation_begin(management);
    }
    if (result == 0) {
        result = jg_database_delete_domain_rule(management->database, rule_id,
                                                revision);
    }
    result = audited_mutation_check(management, result);
    if (result == -ENOENT) {
        return respond_error(404, "domain_not_found",
                             "The domain rule was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "The domain rule has changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "domain_delete_failed",
                             "The domain rule could not be deleted.",
                             request->request_id, output, output_size, written);
    }
    result = publish_domain_rule_change(
        management, request, remote, &actor, "policy.domain.delete", true,
        revision, false, &removed, now, &published, &generation);
    result = audited_mutation_finish(management, result, true);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The domain-rule deletion and its audit were not committed.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)rule_id)) !=
            0 ||
        json_object_set_new(body, "deleted", json_true()) != 0 ||
        json_object_set_new(body, "published", json_boolean(published)) != 0 ||
        json_object_set_new(body, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(published ? 200 : 202, body, NULL, output,
                           output_size, written);
}

/** @brief Publish policy and audit one destination-rule change. */
static int publish_destination_rule_change(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const char *action,
    bool has_previous_revision,
    uint64_t previous_revision,
    bool has_new_revision,
    const struct jg_database_destination_rule *rule,
    uint64_t now,
    bool *published,
    uint64_t *generation)
{
    int result = management_publish_policy_change(management, now, published,
                                                  generation);

    if (result == 0) {
        result = append_destination_rule_audit(
            management, request, remote, actor, action, has_previous_revision,
            previous_revision, has_new_revision, rule, *published, *generation,
            now);
    }
    return result;
}

/** @brief Encode one created or updated destination-rule result. */
static int respond_destination_rule(
    int status,
    const struct jg_database_destination_rule *rule,
    bool published,
    uint64_t generation,
    uint8_t *output,
    size_t output_size,
    size_t *written)
{
    json_t *body = json_object();
    json_t *item = destination_rule_json(rule);

    if (body == NULL || item == NULL ||
        json_object_set(body, "destination_rule", item) != 0 ||
        json_object_set_new(body, "published", json_boolean(published)) != 0 ||
        json_object_set_new(body, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
        json_decref(item);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(item);
    return encode_response(status, body, NULL, output, output_size, written);
}

/** @brief Read one exact destination rule for guarded mutation. */
static int get_destination_rule(struct jg_database *database,
                                uint64_t rule_id,
                                struct jg_database_destination_rule *rule)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_destination_rules(database, rule_id - 1U, 1U,
                                                    rule, &count, &has_more);

    (void)has_more;
    return result == 0 && (count != 1U || rule->id != rule_id) ? -ENOENT
                                                               : result;
}

/** @brief Create one explicit destination rule and publish a snapshot. */
int handle_destination_rule_create(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written)
{
    struct authenticated_actor actor;
    struct jg_policy_destination_rule_input rule;
    struct jg_database_destination_rule created = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool enabled = false;
    bool published = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = parse_destination_rule_request(request->body, 0U, false, &rule,
                                            &enabled, &revision);
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The destination-rule request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = audited_mutation_begin(management);
    if (result == 0) {
        result = jg_database_create_destination_rule(management->database,
                                                     &rule, enabled, &created);
    }
    result = audited_mutation_check(management, result);
    if (result == -EINVAL || result == -ERANGE || result == -ENOSPC) {
        return respond_error(400, "invalid_destination_rule",
                             "The destination-rule properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "destination_create_failed",
                             "The destination rule could not be created.",
                             request->request_id, output, output_size, written);
    }
    result = publish_destination_rule_change(
        management, request, remote, &actor, "policy.destination.create", false,
        0U, true, &created, now, &published, &generation);
    result = audited_mutation_finish(management, result, true);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The destination-rule creation and its audit were not committed.",
            request->request_id, output, output_size, written);
    }
    return respond_destination_rule(published ? 201 : 202, &created, published,
                                    generation, output, output_size, written);
}

/** @brief Update one explicit destination rule and publish a snapshot. */
int handle_destination_rule_update(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t rule_id,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written)
{
    struct authenticated_actor actor;
    struct jg_policy_destination_rule_input rule;
    struct jg_database_destination_rule previous = {0};
    struct jg_database_destination_rule updated = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool enabled = false;
    bool published = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = parse_destination_rule_request(request->body, rule_id, true, &rule,
                                            &enabled, &revision);
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The destination-rule update is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = get_destination_rule(management->database, rule_id, &previous);
    if (result == 0 && previous.source != JG_POLICY_SOURCE_EXPLICIT) {
        return respond_error(
            409, "managed_destination_rule",
            "This rule is managed by its policy source and cannot be edited.",
            request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = audited_mutation_begin(management);
    }
    if (result == 0) {
        result = jg_database_update_destination_rule(
            management->database, &rule, enabled, revision, &updated);
    }
    result = audited_mutation_check(management, result);
    if (result == -ENOENT) {
        return respond_error(404, "destination_not_found",
                             "The destination rule was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(
            409, "revision_conflict",
            "The destination rule has changed; reload and retry.",
            request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -ERANGE || result == -ENOSPC) {
        return respond_error(400, "invalid_destination_rule",
                             "The destination-rule properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "destination_update_failed",
                             "The destination rule could not be updated.",
                             request->request_id, output, output_size, written);
    }
    result = publish_destination_rule_change(
        management, request, remote, &actor, "policy.destination.update", true,
        revision, true, &updated, now, &published, &generation);
    result = audited_mutation_finish(management, result, true);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The destination-rule update and its audit were not committed.",
            request->request_id, output, output_size, written);
    }
    return respond_destination_rule(published ? 200 : 202, &updated, published,
                                    generation, output, output_size, written);
}

/** @brief Delete one explicit destination rule and publish a snapshot. */
int handle_destination_rule_delete(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t rule_id,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written)
{
    static const char *const fields[] = {"revision"};
    struct authenticated_actor actor;
    struct jg_database_destination_rule removed = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        !required_identifier(request->body, "revision", &revision)) {
        return respond_error(400, "invalid_body",
                             "The destination-rule deletion is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = get_destination_rule(management->database, rule_id, &removed);
    if (result == 0 && removed.source != JG_POLICY_SOURCE_EXPLICIT) {
        return respond_error(
            409, "managed_destination_rule",
            "This rule is managed by its policy source and cannot be deleted.",
            request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = audited_mutation_begin(management);
    }
    if (result == 0) {
        result = jg_database_delete_destination_rule(management->database,
                                                     rule_id, revision);
    }
    result = audited_mutation_check(management, result);
    if (result == -ENOENT) {
        return respond_error(404, "destination_not_found",
                             "The destination rule was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(
            409, "revision_conflict",
            "The destination rule has changed; reload and retry.",
            request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "destination_delete_failed",
                             "The destination rule could not be deleted.",
                             request->request_id, output, output_size, written);
    }
    result = publish_destination_rule_change(
        management, request, remote, &actor, "policy.destination.delete", true,
        revision, false, &removed, now, &published, &generation);
    result = audited_mutation_finish(management, result, true);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The destination-rule deletion and its audit were not committed.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)rule_id)) !=
            0 ||
        json_object_set_new(body, "deleted", json_true()) != 0 ||
        json_object_set_new(body, "published", json_boolean(published)) != 0 ||
        json_object_set_new(body, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(published ? 200 : 202, body, NULL, output,
                           output_size, written);
}
