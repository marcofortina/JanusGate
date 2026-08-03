/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_policy.c
 * @brief DNS policy, destination rule, and blocklist management.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>

#include "blocklist_update.h"
#include "janusgate/access.h"
#include "janusgate/audit.h"
#include "janusgate/blocklist.h"
#include "janusgate/blocklist_remote.h"
#include "janusgate/database.h"
#include "janusgate/event.h"
#include "janusgate/policy.h"

/** @brief Advance, publish, and persist one policy revision attempt. */
static int publish_policy_change(struct jg_management *management,
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

/** @brief Return the stable external name for one blocklist syntax. */
static const char *blocklist_format_name(enum jg_blocklist_format format)
{
    switch (format) {
    case JG_BLOCKLIST_FORMAT_DOMAIN:
        return "domain";
    case JG_BLOCKLIST_FORMAT_HOSTS:
        return "hosts";
    case JG_BLOCKLIST_FORMAT_CATEGORY:
        return "category";
    case JG_BLOCKLIST_FORMAT_RPZ:
        return "rpz";
    case JG_BLOCKLIST_FORMAT_JSON:
        return "json";
    default:
        return NULL;
    }
}

/** @brief Return the stable external name for one blocklist import mode. */
static const char *blocklist_mode_name(enum jg_blocklist_mode mode)
{
    switch (mode) {
    case JG_BLOCKLIST_STRICT:
        return "strict";
    case JG_BLOCKLIST_TOLERANT:
        return "tolerant";
    default:
        return NULL;
    }
}

/** @brief Return the stable external name for blocklist source health. */
static const char *blocklist_health_name(
    enum jg_database_blocklist_health health)
{
    switch (health) {
    case JG_DATABASE_BLOCKLIST_UNKNOWN:
        return "unknown";
    case JG_DATABASE_BLOCKLIST_HEALTHY:
        return "healthy";
    case JG_DATABASE_BLOCKLIST_DEGRADED:
        return "degraded";
    case JG_DATABASE_BLOCKLIST_FAILED:
        return "failed";
    default:
        return NULL;
    }
}

/** @brief Encode one optional fixed-size digest as lowercase hexadecimal. */
static json_t *optional_digest_json(const uint8_t *digest,
                                    size_t digest_size,
                                    bool present)
{
    char encoded[JG_BLOCKLIST_CHECKSUM_SIZE * 2U + 1U];

    if (!present) {
        return json_null();
    }
    if (digest_size > JG_BLOCKLIST_CHECKSUM_SIZE ||
        sodium_bin2hex(encoded, sizeof(encoded), digest, digest_size) == NULL) {
        return NULL;
    }
    return json_string(encoded);
}

/** @brief Convert one persistent blocklist source and state to public JSON. */
static json_t *blocklist_source_json(
    const struct jg_database_blocklist_source *source)
{
    const char *format = blocklist_format_name(source->format);
    const char *mode = blocklist_mode_name(source->mode);
    const char *health = blocklist_health_name(source->health);
    json_t *body = json_object();
    json_t *sha256_pin = optional_digest_json(
        source->sha256_pin, sizeof(source->sha256_pin), source->has_sha256_pin);
    json_t *public_key = optional_digest_json(
        source->ed25519_public_key, sizeof(source->ed25519_public_key),
        source->has_signature);
    json_t *active_checksum = optional_digest_json(
        source->active_checksum, sizeof(source->active_checksum),
        source->has_active_checksum);
    int result = 0;

    if (format == NULL || mode == NULL || health == NULL || body == NULL ||
        sha256_pin == NULL || public_key == NULL || active_checksum == NULL) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (json_object_set_new(body, "id",
                             json_integer((json_int_t)source->id)) != 0 ||
         json_object_set_new(body, "revision",
                             json_integer((json_int_t)source->revision)) != 0 ||
         json_object_set_new(body, "created_at",
                             json_integer((json_int_t)source->created_at)) !=
             0 ||
         json_object_set_new(body, "updated_at",
                             json_integer((json_int_t)source->updated_at)) !=
             0 ||
         json_object_set_new(body, "name", json_string(source->name)) != 0 ||
         json_object_set_new(body, "url",
                             source->url[0U] == '\0'
                                 ? json_null()
                                 : json_string(source->url)) != 0 ||
         json_object_set_new(body, "signature_url",
                             source->signature_url[0U] == '\0'
                                 ? json_null()
                                 : json_string(source->signature_url)) != 0 ||
         json_object_set_new(body, "format", json_string(format)) != 0 ||
         json_object_set_new(body, "mode", json_string(mode)) != 0 ||
         json_object_set_new(body, "enabled", json_boolean(source->enabled)) !=
             0 ||
         json_object_set_new(
             body, "update_interval_seconds",
             json_integer((json_int_t)source->update_interval_seconds)) != 0 ||
         json_object_set_new(
             body, "max_download_bytes",
             json_integer((json_int_t)source->max_download_bytes)) != 0 ||
         json_object_set_new(
             body, "max_decompressed_bytes",
             json_integer((json_int_t)source->max_decompressed_bytes)) != 0 ||
         json_object_set_new(
             body, "connect_timeout_ms",
             json_integer((json_int_t)source->connect_timeout_ms)) != 0 ||
         json_object_set_new(
             body, "transfer_timeout_ms",
             json_integer((json_int_t)source->transfer_timeout_ms)) != 0 ||
         json_object_set_new(
             body, "redirect_limit",
             json_integer((json_int_t)source->redirect_limit)) != 0 ||
         json_object_set_new(
             body, "retry_base_seconds",
             json_integer((json_int_t)source->retry_base_seconds)) != 0 ||
         json_object_set_new(
             body, "retry_max_seconds",
             json_integer((json_int_t)source->retry_max_seconds)) != 0 ||
         json_object_set(body, "sha256_pin", sha256_pin) != 0 ||
         json_object_set(body, "ed25519_public_key", public_key) != 0 ||
         json_object_set_new(body, "etag",
                             source->etag[0U] == '\0'
                                 ? json_null()
                                 : json_string(source->etag)) != 0 ||
         json_object_set_new(body, "last_modified",
                             source->last_modified[0U] == '\0'
                                 ? json_null()
                                 : json_string(source->last_modified)) != 0 ||
         json_object_set_new(
             body, "consecutive_failures",
             json_integer((json_int_t)source->consecutive_failures)) != 0 ||
         json_object_set(body, "active_checksum", active_checksum) != 0 ||
         json_object_set_new(
             body, "active_entries",
             json_integer((json_int_t)source->active_entries)) != 0 ||
         json_object_set_new(
             body, "rejected_entries",
             json_integer((json_int_t)source->rejected_entries)) != 0 ||
         json_object_set_new(body, "health", json_string(health)) != 0 ||
         json_object_set_new(body, "last_error",
                             source->last_error[0U] == '\0'
                                 ? json_null()
                                 : json_string(source->last_error)) != 0 ||
         set_optional_timestamp(body, "last_attempt_at",
                                source->last_attempt_at) != 0 ||
         set_optional_timestamp(body, "last_success_at",
                                source->last_success_at) != 0 ||
         set_optional_timestamp(body, "next_attempt_at",
                                source->next_attempt_at) != 0)) {
        result = -ENOMEM;
    }
    json_decref(sha256_pin);
    json_decref(public_key);
    json_decref(active_checksum);
    if (result != 0) {
        json_decref(body);
        return NULL;
    }
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

/** @brief Parse one external blocklist syntax name. */
static bool parse_blocklist_format(const char *text,
                                   enum jg_blocklist_format *format)
{
    if (text == NULL || format == NULL) {
        return false;
    }
    if (strcmp(text, "domain") == 0) {
        *format = JG_BLOCKLIST_FORMAT_DOMAIN;
    } else if (strcmp(text, "hosts") == 0) {
        *format = JG_BLOCKLIST_FORMAT_HOSTS;
    } else if (strcmp(text, "category") == 0) {
        *format = JG_BLOCKLIST_FORMAT_CATEGORY;
    } else if (strcmp(text, "rpz") == 0) {
        *format = JG_BLOCKLIST_FORMAT_RPZ;
    } else if (strcmp(text, "json") == 0) {
        *format = JG_BLOCKLIST_FORMAT_JSON;
    } else {
        return false;
    }
    return true;
}

/** @brief Parse one external blocklist import mode. */
static bool parse_blocklist_mode(const char *text, enum jg_blocklist_mode *mode)
{
    if (text == NULL || mode == NULL) {
        return false;
    }
    if (strcmp(text, "strict") == 0) {
        *mode = JG_BLOCKLIST_STRICT;
    } else if (strcmp(text, "tolerant") == 0) {
        *mode = JG_BLOCKLIST_TOLERANT;
    } else {
        return false;
    }
    return true;
}

/** @brief Parse one complete create or replacement source request. */
static int parse_blocklist_source_request(
    json_t *body,
    bool updating,
    struct jg_database_blocklist_source_config *config,
    uint64_t *revision)
{
    static const char *const fields[] = {
        "revision",
        "name",
        "url",
        "signature_url",
        "format",
        "mode",
        "enabled",
        "update_interval_seconds",
        "max_download_bytes",
        "max_decompressed_bytes",
        "connect_timeout_ms",
        "transfer_timeout_ms",
        "redirect_limit",
        "retry_base_seconds",
        "retry_max_seconds",
        "sha256_pin",
        "ed25519_public_key",
    };
    const char *format = NULL;
    const char *mode = NULL;
    uint64_t update_interval = 0U;
    uint64_t max_download = 0U;
    uint64_t max_decompressed = 0U;
    uint64_t connect_timeout = 0U;
    uint64_t transfer_timeout = 0U;
    uint64_t redirect_limit = 0U;
    uint64_t retry_base = 0U;
    uint64_t retry_max = 0U;

    (void)memset(config, 0, sizeof(*config));
    *revision = 0U;
    config->name =
        required_string(body, "name", 1U, JG_DATABASE_BLOCKLIST_NAME_MAX);
    format = required_string(body, "format", 3U, 8U);
    mode = required_string(body, "mode", 6U, 8U);
    if (!fields_allowed(body, fields, sizeof(fields) / sizeof(fields[0U])) ||
        config->name == NULL ||
        !required_nullable_string(body, "url", JG_DATABASE_BLOCKLIST_URL_MAX,
                                  &config->url) ||
        !required_nullable_string(body, "signature_url",
                                  JG_DATABASE_BLOCKLIST_URL_MAX,
                                  &config->signature_url) ||
        !parse_blocklist_format(format, &config->format) ||
        !parse_blocklist_mode(mode, &config->mode) ||
        !required_boolean(body, "enabled", &config->enabled) ||
        !required_unsigned(body, "update_interval_seconds", (uint64_t)INT64_MAX,
                           &update_interval) ||
        !required_unsigned(body, "max_download_bytes", (uint64_t)SIZE_MAX,
                           &max_download) ||
        !required_unsigned(body, "max_decompressed_bytes", (uint64_t)SIZE_MAX,
                           &max_decompressed) ||
        !required_unsigned(body, "connect_timeout_ms",
                           JG_BLOCKLIST_CONNECT_TIMEOUT_MAX,
                           &connect_timeout) ||
        !required_unsigned(body, "transfer_timeout_ms",
                           JG_BLOCKLIST_TRANSFER_TIMEOUT_MAX,
                           &transfer_timeout) ||
        !required_unsigned(body, "redirect_limit", UINT32_MAX,
                           &redirect_limit) ||
        !required_unsigned(body, "retry_base_seconds", (uint64_t)INT64_MAX,
                           &retry_base) ||
        !required_unsigned(body, "retry_max_seconds", (uint64_t)INT64_MAX,
                           &retry_max) ||
        !required_optional_digest(body, "sha256_pin", config->sha256_pin,
                                  &config->has_sha256_pin) ||
        !required_optional_digest(body, "ed25519_public_key",
                                  config->ed25519_public_key,
                                  &config->has_signature) ||
        (updating && !required_identifier(body, "revision", revision)) ||
        (!updating && json_object_get(body, "revision") != NULL)) {
        return -EINVAL;
    }
    config->update_interval_seconds = update_interval;
    config->max_download_bytes = (size_t)max_download;
    config->max_decompressed_bytes = (size_t)max_decompressed;
    config->connect_timeout_ms = (uint32_t)connect_timeout;
    config->transfer_timeout_ms = (uint32_t)transfer_timeout;
    config->redirect_limit = (uint32_t)redirect_limit;
    config->retry_base_seconds = retry_base;
    config->retry_max_seconds = retry_max;
    return 0;
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

/** @brief Convert one self-contained simulated rule match to JSON. */
static json_t *policy_simulation_match_json(
    const struct jg_policy_simulation_match *match,
    enum jg_policy_match_dimension dimension)
{
    const char *effect = policy_effect_name(match->effect);
    const char *source = policy_source_name(match->source);
    const char *dimension_name = policy_dimension_name(dimension);
    json_t *body = json_object();

    if (effect == NULL || source == NULL || dimension_name == NULL ||
        body == NULL ||
        json_object_set_new(body, "dimension", json_string(dimension_name)) !=
            0 ||
        json_object_set_new(body, "matched", json_boolean(match->matched)) !=
            0 ||
        json_object_set_new(body, "action", json_string(effect)) != 0 ||
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
                                : json_string(match->attribution)) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Serialize one complete policy simulation explanation. */
static json_t *policy_simulation_json(
    const struct jg_policy_simulation *simulation)
{
    const char *effect = policy_effect_name(simulation->effect);
    const char *target = policy_target_name(simulation->target);
    const char *selected = policy_dimension_name(simulation->selected);
    const struct jg_policy_simulation_match *selected_match = NULL;
    json_t *body = json_object();
    json_t *domain = policy_simulation_match_json(&simulation->domain,
                                                  JG_POLICY_MATCH_DOMAIN);
    json_t *destination =
        simulation->destination_evaluated
            ? policy_simulation_match_json(&simulation->destination,
                                           JG_POLICY_MATCH_DESTINATION)
            : json_null();
    json_t *matching_rule = NULL;
    json_t *path = json_array();
    json_t *sources = json_array();
    int result = 0;

    if (simulation->selected == JG_POLICY_MATCH_DOMAIN) {
        selected_match = &simulation->domain;
    } else if (simulation->selected == JG_POLICY_MATCH_DESTINATION) {
        selected_match = &simulation->destination;
    }
    matching_rule = selected_match == NULL
                        ? json_null()
                        : policy_simulation_match_json(selected_match,
                                                       simulation->selected);
    if (effect == NULL || target == NULL || selected == NULL || body == NULL ||
        domain == NULL || destination == NULL || matching_rule == NULL ||
        path == NULL || sources == NULL ||
        simulation->generation > (uint64_t)INT64_MAX) {
        result = -ENOMEM;
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
         json_object_set_new(body, "selected", json_string(selected)) != 0 ||
         json_object_set_new(
             body, "policy_generation",
             json_integer((json_int_t)simulation->generation)) != 0 ||
         json_object_set(body, "domain_match", domain) != 0 ||
         json_object_set(body, "destination_match", destination) != 0 ||
         json_object_set(body, "matching_rule", matching_rule) != 0 ||
         json_object_set(body, "precedence_path", path) != 0 ||
         json_object_set(body, "sources", sources) != 0)) {
        result = -ENOMEM;
    }
    json_decref(domain);
    json_decref(destination);
    json_decref(matching_rule);
    json_decref(path);
    json_decref(sources);
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

/** @brief Append one blocklist-source mutation and publication outcome. */
static int append_blocklist_source_audit(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const char *action,
    bool has_previous_revision,
    uint64_t previous_revision,
    bool has_new_revision,
    const struct jg_database_blocklist_source *source,
    bool published,
    uint64_t generation,
    uint64_t now)
{
    char object_id[32U];
    char source_address[INET6_ADDRSTRLEN];
    json_t *details = blocklist_source_json(source);
    char *encoded = NULL;
    struct jg_audit_event event;
    int written = snprintf(object_id, sizeof(object_id), "%llu",
                           (unsigned long long)source->id);
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
            .object_type = "blocklist_source",
            .object_id = object_id,
            .details = encoded,
            .has_previous_revision = has_previous_revision,
            .previous_revision = previous_revision,
            .has_new_revision = has_new_revision,
            .new_revision = source->revision,
            .success = true,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one authenticated blocklist update outcome. */
static int append_blocklist_update_audit(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const char *action,
    const struct jg_blocklist_update_result *update,
    int operation_result,
    bool published,
    uint64_t generation,
    uint64_t now)
{
    char object_id[32U];
    char source_address[INET6_ADDRSTRLEN];
    const bool system_actor = actor == NULL;
    const char *outcome = "rejected";
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int written = snprintf(object_id, sizeof(object_id), "%llu",
                           (unsigned long long)update->source.id);
    int result = 0;

    if (operation_result == 0 && update->attempted &&
        update->attempt_result == 0) {
        outcome = update->activated ? "updated" : "not_modified";
    } else if (update->attempted) {
        outcome = "failed";
    }
    if (system_actor) {
        (void)snprintf(source_address, sizeof(source_address), "%s",
                       "scheduler");
    } else if (request == NULL || remote == NULL ||
               inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET
                                                                  : AF_INET6,
                         remote->address, source_address,
                         sizeof(source_address)) == NULL) {
        result = -EINVAL;
    }
    if (result == 0 &&
        (written <= 0 || (size_t)written >= sizeof(object_id) ||
         details == NULL ||
         json_object_set_new(details, "attempted",
                             json_boolean(update->attempted)) != 0 ||
         json_object_set_new(details, "outcome", json_string(outcome)) != 0 ||
         json_object_set_new(details, "operation_result",
                             json_integer(operation_result)) != 0 ||
         json_object_set_new(details, "attempt_result",
                             json_integer(update->attempt_result)) != 0 ||
         json_object_set_new(details, "http_status",
                             json_integer(update->report.http_status)) != 0 ||
         json_object_set_new(
             details, "input_bytes",
             json_integer((json_int_t)update->report.body_size)) != 0 ||
         json_object_set_new(
             details, "entries_parsed",
             json_integer((json_int_t)update->report.import.entries_parsed)) !=
             0 ||
         json_object_set_new(
             details, "records_rejected",
             json_integer(
                 (json_int_t)update->report.import.records_rejected)) != 0 ||
         json_object_set_new(details, "published", json_boolean(published)) !=
             0 ||
         json_object_set_new(details, "policy_generation",
                             json_integer((json_int_t)generation)) != 0)) {
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
            .actor_type =
                system_actor ? JG_AUDIT_ACTOR_SYSTEM : actor_audit_type(actor),
            .has_actor_id = !system_actor && actor_has_identifier(actor),
            .actor_id = system_actor ? 0U : actor->actor_id,
            .source = source_address,
            .action = action,
            .object_type = "blocklist_source",
            .object_id = object_id,
            .details = encoded,
            .has_previous_revision = true,
            .previous_revision = update->source.revision,
            .has_new_revision = true,
            .new_revision = update->source.revision,
            .success = operation_result == 0 && update->attempt_result == 0 &&
                       (!update->activated || published),
            .request_id = system_actor ? "" : request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one scheduler outcome to the operational event stream. */
static int append_blocklist_update_event(
    struct jg_management *management,
    const struct jg_blocklist_update_result *update,
    int operation_result,
    uint64_t now)
{
    char details[128U];
    const char *code = "source.not_modified";
    const char *message = "The scheduled source remains current.";
    enum jg_event_severity severity = JG_EVENT_SEVERITY_DEBUG;
    struct jg_event event;
    int written = 0;

    if (operation_result != 0) {
        code = "source.state_failed";
        message = "The scheduled source state could not be committed.";
        severity = JG_EVENT_SEVERITY_ERROR;
    } else if (update->attempt_result != 0) {
        code = "source.update_failed";
        message = "The scheduled source update failed.";
        severity = JG_EVENT_SEVERITY_WARNING;
    } else if (update->activated) {
        code = "source.updated";
        message = "The scheduled source activated a new blocklist.";
        severity = JG_EVENT_SEVERITY_INFO;
    }
    written = snprintf(
        details, sizeof(details), "{\"attempt_result\":%d,\"source_id\":%llu}",
        update->attempt_result, (unsigned long long)update->source.id);
    if (written <= 0 || (size_t)written >= sizeof(details)) {
        return -EOVERFLOW;
    }
    event = (struct jg_event){
        .occurred_at = now,
        .severity = severity,
        .component = "blocklist",
        .code = code,
        .message = message,
        .details = details,
    };
    return jg_database_event_append(management->database, &event, NULL);
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

/** @brief Return one authenticated stable page of blocklist sources. */
int handle_blocklist_sources_list(struct jg_management *management,
                                  const struct management_request *request,
                                  const struct remote_address *remote,
                                  uint64_t now,
                                  uint8_t *output,
                                  size_t output_size,
                                  size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_blocklist_source *sources = NULL;
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
                             "The blocklist-source pagination is not valid.",
                             request->request_id, output, output_size, written);
    }
    sources = calloc(limit, sizeof(*sources));
    if (sources == NULL) {
        return -ENOMEM;
    }
    result = jg_database_list_blocklist_sources(
        management->database, after_id, limit, sources, &count, &has_more);
    if (result != 0) {
        free(sources);
        return respond_error(500, "sources_unavailable",
                             "The blocklist sources could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = blocklist_source_json(&sources[index]);

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
         json_object_set(body, "sources", items) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        json_t *next = has_more && count > 0U
                           ? json_integer((json_int_t)sources[count - 1U].id)
                           : json_null();

        if (json_object_set_new(body, "next_after_id", next) != 0) {
            result = -ENOMEM;
        }
    }
    free(sources);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Load one exact blocklist source for mutation and audit. */
static int load_blocklist_source(struct jg_management *management,
                                 uint64_t source_id,
                                 struct jg_database_blocklist_source *source)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_blocklist_sources(
        management->database, source_id - 1U, 1U, source, &count, &has_more);

    (void)has_more;
    if (result == 0 && (count != 1U || source->id != source_id)) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Track and publish policy after a blocklist-source mutation. */
static int publish_blocklist_source_change(struct jg_management *management,
                                           uint64_t now,
                                           bool *published,
                                           uint64_t *generation)
{
    return publish_policy_change(management, now, published, generation);
}

/** @brief Encode one created or updated blocklist-source result. */
static int respond_blocklist_source(
    int status,
    const struct jg_database_blocklist_source *source,
    bool published,
    uint64_t generation,
    uint8_t *output,
    size_t output_size,
    size_t *written)
{
    json_t *body = json_object();
    json_t *item = blocklist_source_json(source);

    if (body == NULL || item == NULL ||
        json_object_set(body, "source", item) != 0 ||
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

/** @brief Create one blocklist source through an authorized API request. */
int handle_blocklist_source_create(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_blocklist_source_config config;
    struct jg_database_blocklist_source created = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = parse_blocklist_source_request(request->body, false, &config,
                                            &revision);
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The blocklist-source request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = audited_mutation_begin(management);
    if (result == 0) {
        result = jg_database_create_blocklist_source(management->database,
                                                     &config, &created);
    }
    result = audited_mutation_check(management, result);
    if (result == -EEXIST) {
        return respond_error(409, "source_name_exists",
                             "The blocklist-source name is already in use.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -EILSEQ) {
        return respond_error(400, "invalid_source",
                             "The blocklist-source properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "source_create_failed",
                             "The blocklist source could not be created.",
                             request->request_id, output, output_size, written);
    }
    result = publish_blocklist_source_change(management, now, &published,
                                             &generation);
    if (result == 0) {
        result = append_blocklist_source_audit(
            management, request, remote, &actor, "blocklist.source.create",
            false, 0U, true, &created, published, generation, now);
    }
    result = audited_mutation_finish(management, result, true);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The source creation and its audit record were not committed.",
            request->request_id, output, output_size, written);
    }
    return respond_blocklist_source(published ? 201 : 202, &created, published,
                                    generation, output, output_size, written);
}

/** @brief Replace one blocklist source through an authorized API request. */
int handle_blocklist_source_update(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t source_id,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_blocklist_source_config config;
    struct jg_database_blocklist_source updated = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result =
        parse_blocklist_source_request(request->body, true, &config, &revision);
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The blocklist-source update is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = audited_mutation_begin(management);
    if (result == 0) {
        result = jg_database_update_blocklist_source(
            management->database, source_id, &config, revision, &updated);
    }
    result = audited_mutation_check(management, result);
    if (result == -ENOENT) {
        return respond_error(404, "source_not_found",
                             "The blocklist source was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "The source has changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EEXIST) {
        return respond_error(409, "source_name_exists",
                             "The blocklist-source name is already in use.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -EILSEQ) {
        return respond_error(400, "invalid_source",
                             "The blocklist-source properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "source_update_failed",
                             "The blocklist source could not be updated.",
                             request->request_id, output, output_size, written);
    }
    result = publish_blocklist_source_change(management, now, &published,
                                             &generation);
    if (result == 0) {
        result = append_blocklist_source_audit(
            management, request, remote, &actor, "blocklist.source.update",
            true, revision, true, &updated, published, generation, now);
    }
    result = audited_mutation_finish(management, result, true);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The source update and its audit record were not committed.",
            request->request_id, output, output_size, written);
    }
    return respond_blocklist_source(published ? 200 : 202, &updated, published,
                                    generation, output, output_size, written);
}

/** @brief Delete one blocklist source through an authorized API request. */
int handle_blocklist_source_delete(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t source_id,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written)
{
    static const char *const fields[] = {"revision"};
    struct authenticated_actor actor;
    struct jg_database_blocklist_source removed = {0};
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
                             "The blocklist-source deletion is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = load_blocklist_source(management, source_id, &removed);
    if (result == 0) {
        result = audited_mutation_begin(management);
    }
    if (result == 0) {
        result = jg_database_delete_blocklist_source(management->database,
                                                     source_id, revision);
    }
    result = audited_mutation_check(management, result);
    if (result == -ENOENT) {
        return respond_error(404, "source_not_found",
                             "The blocklist source was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "The source has changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "source_delete_failed",
                             "The blocklist source could not be deleted.",
                             request->request_id, output, output_size, written);
    }
    result = publish_blocklist_source_change(management, now, &published,
                                             &generation);
    if (result == 0) {
        result = append_blocklist_source_audit(
            management, request, remote, &actor, "blocklist.source.delete",
            true, revision, false, &removed, published, generation, now);
    }
    result = audited_mutation_finish(management, result, true);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The source deletion and its audit record were not committed.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)source_id)) !=
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

/** @brief Encode one complete manual blocklist update outcome. */
static int respond_blocklist_update(
    const struct management_request *request,
    const struct jg_blocklist_update_result *update,
    const char *failure_code,
    const char *failure_message,
    int failure_status,
    bool published,
    uint64_t generation,
    uint8_t *output,
    size_t output_size,
    size_t *written)
{
    const bool successful = update->attempt_result == 0;
    const char *outcome = successful
                              ? (update->activated ? "updated" : "not_modified")
                              : "failed";
    json_t *body = successful ? json_object()
                              : error_body(failure_code, failure_message,
                                           request->request_id);
    json_t *source = blocklist_source_json(&update->source);
    json_t *attempt = json_object();
    int result = 0;

    if (body == NULL || source == NULL || attempt == NULL ||
        json_object_set_new(attempt, "success", json_boolean(successful)) !=
            0 ||
        json_object_set_new(attempt, "outcome", json_string(outcome)) != 0 ||
        json_object_set_new(
            attempt, "http_status",
            update->report.http_status == 0L
                ? json_null()
                : json_integer((json_int_t)update->report.http_status)) != 0 ||
        json_object_set_new(
            attempt, "input_bytes",
            json_integer((json_int_t)update->report.body_size)) != 0 ||
        json_object_set_new(
            attempt, "records_seen",
            json_integer((json_int_t)update->report.import.records_seen)) !=
            0 ||
        json_object_set_new(
            attempt, "entries_parsed",
            json_integer((json_int_t)update->report.import.entries_parsed)) !=
            0 ||
        json_object_set_new(
            attempt, "records_rejected",
            json_integer((json_int_t)update->report.import.records_rejected)) !=
            0 ||
        json_object_set_new(
            attempt, "duplicates_removed",
            json_integer(
                (json_int_t)update->report.import.duplicates_removed)) != 0 ||
        json_object_set(body, "source", source) != 0 ||
        json_object_set(body, "attempt", attempt) != 0 ||
        json_object_set_new(body, "published", json_boolean(published)) != 0 ||
        json_object_set_new(body, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
        result = -ENOMEM;
    }
    json_decref(source);
    json_decref(attempt);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(successful
                               ? (update->activated && !published ? 202 : 200)
                               : failure_status,
                           body, NULL, output, output_size, written);
}

/** Completion context for one manual remote-source refresh job. */
struct source_refresh_completion {
    struct jg_management *management;
    const struct management_request *request;
    const struct remote_address *remote;
    const struct authenticated_actor *actor;
    const char *action;
    uint64_t now;
    uint64_t generation;
    int operation_result;
    bool published;
    bool append_event;
    bool called;
};

/** @brief Publish and audit one refreshed source inside its transaction. */
static int complete_source_refresh(
    void *context,
    const struct jg_blocklist_update_result *update)
{
    struct source_refresh_completion *completion = context;
    int result = 0;

    completion->called = true;
    if (update->activated) {
        result = publish_blocklist_source_change(
            completion->management, completion->now, &completion->published,
            &completion->generation);
    }
    completion->operation_result =
        completion->append_event && update->activated && !completion->published
            ? -EIO
            : 0;
    if (result == 0) {
        result = append_blocklist_update_audit(
            completion->management, completion->request, completion->remote,
            completion->actor, completion->action, update,
            completion->operation_result, completion->published,
            completion->generation, completion->now);
    }

    if (result == 0 && completion->append_event) {
        result = append_blocklist_update_event(completion->management, update,
                                               completion->operation_result,
                                               completion->now);
    }
    return result;
}

/** @brief Reconcile policy health after a blocklist update transaction. */
static void finish_blocklist_policy_transaction(
    struct jg_management *management,
    bool activated,
    int transaction_result)
{
    int reload_result = 0;

    if (!activated) {
        return;
    }
    if (transaction_result != 0 && management->runtime != NULL) {
        reload_result = jg_daemon_runtime_reload_policy(management->runtime);
    }
    if (reload_result != 0) {
        mark_management_degraded(
            management, MANAGEMENT_DEGRADED_POLICY_SYNC,
            "management.policy_rollback",
            "The runtime policy could not be synchronized after rollback");
    } else {
        refresh_policy_sync_health(management);
    }
}

/** @brief Execute one authenticated remote-source refresh job. */
int execute_source_refresh_job(struct jg_management *management,
                               const struct management_job *job,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    const struct management_request request = {
        .request_id = job->request_id,
    };
    struct source_refresh_completion completion = {
        .management = management,
        .request = &request,
        .remote = &job->remote,
        .actor = &job->actor,
        .action = "blocklist.source.refresh",
        .now = job->started_at,
    };
    struct jg_blocklist_update_result update;
    int result = jg_blocklist_update_complete(
        management->database, job->parameters.source.id,
        job->parameters.source.revision, job->started_at,
        complete_source_refresh, &completion, &update);

    finish_blocklist_policy_transaction(management, update.activated, result);
    if (result == -ENOENT) {
        return respond_error(404, "source_not_found",
                             "The blocklist source was not found.",
                             request.request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "The source has changed; reload and retry.",
                             request.request_id, output, output_size, written);
    }
    if (result == -EINVAL) {
        return respond_error(409, "local_source",
                             "Local sources cannot be refreshed remotely.",
                             request.request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(
            500, "source_update_failed",
            "The source update or its audit record could not be committed.",
            request.request_id, output, output_size, written);
    }
    return respond_blocklist_update(
        &request, &update, "blocklist_update_failed",
        jg_blocklist_update_error(update.attempt_result), 502,
        completion.published, completion.generation, output, output_size,
        written);
}

/** @brief Refresh one remote blocklist source through an authorized request. */
int handle_blocklist_source_refresh(struct jg_management *management,
                                    const struct management_request *request,
                                    const struct remote_address *remote,
                                    uint64_t source_id,
                                    uint64_t now,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *written)
{
    static const char *const fields[] = {"revision"};
    struct authenticated_actor actor;
    struct management_job_submission prepared = {
        .required_permission = JG_ACCESS_POLICY_WRITE,
        .kind = MANAGEMENT_JOB_SOURCE_REFRESH,
    };
    uint64_t revision = 0U;
    uint64_t job_id = 0U;
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
                             "The blocklist refresh request is not valid.",
                             request->request_id, output, output_size, written);
    }
    prepared.parameters.source.id = source_id;
    prepared.parameters.source.revision = revision;
    result = submit_management_job(management, request, remote, &actor,
                                   &prepared, now, &job_id);
    if (result != 0) {
        return respond_job_submission_error(
            result, request, "The source refresh could not be queued.", output,
            output_size, written);
    }
    return respond_job_accepted(job_id, output, output_size, written);
}

/** @brief Execute one authenticated local blocklist import job. */
int execute_blocklist_import_job(struct jg_management *management,
                                 const struct management_job *job,
                                 uint8_t *output,
                                 size_t output_size,
                                 size_t *written)
{
    const struct management_request request = {
        .request_id = job->request_id,
    };
    struct source_refresh_completion completion = {
        .management = management,
        .request = &request,
        .remote = &job->remote,
        .actor = &job->actor,
        .action = "blocklist.source.import",
        .now = job->started_at,
    };
    struct jg_blocklist_update_result update;
    int result = jg_blocklist_import_local_complete(
        management->database, job->parameters.blocklist_import.source_id,
        job->parameters.blocklist_import.revision,
        job->parameters.blocklist_import.content,
        job->parameters.blocklist_import.content_size, job->started_at,
        complete_source_refresh, &completion, &update);

    finish_blocklist_policy_transaction(management, update.activated, result);
    if (result == -ENOENT) {
        return respond_error(404, "source_not_found",
                             "The blocklist source was not found.",
                             request.request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "The source has changed; reload and retry.",
                             request.request_id, output, output_size, written);
    }
    if (result == -EINVAL) {
        return respond_error(409, "remote_source",
                             "Remote sources cannot receive local imports.",
                             request.request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(
            500, "source_import_failed",
            "The local blocklist state and audit could not be committed.",
            request.request_id, output, output_size, written);
    }
    return respond_blocklist_update(
        &request, &update, "blocklist_import_failed",
        jg_blocklist_import_error(update.attempt_result), 422,
        completion.published, completion.generation, output, output_size,
        written);
}

/** @brief Queue one uploaded blocklist for an authorized local source. */
int handle_blocklist_import(struct jg_management *management,
                            const struct management_request *request,
                            const struct remote_address *remote,
                            uint64_t now,
                            uint8_t *output,
                            size_t output_size,
                            size_t *written)
{
    static const char *const fields[] = {
        "source_id",
        "revision",
        "content",
    };
    struct authenticated_actor actor;
    struct management_job_submission prepared = {
        .required_permission = JG_ACCESS_POLICY_WRITE,
        .kind = MANAGEMENT_JOB_BLOCKLIST_IMPORT,
    };
    json_t *content_value = json_object_get(request->body, "content");
    const char *content =
        json_is_string(content_value) ? json_string_value(content_value) : NULL;
    const size_t content_size =
        json_is_string(content_value) ? json_string_length(content_value) : 0U;
    uint64_t job_id = 0U;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        !required_identifier(request->body, "source_id",
                             &prepared.parameters.blocklist_import.source_id) ||
        !required_identifier(request->body, "revision",
                             &prepared.parameters.blocklist_import.revision) ||
        content == NULL) {
        return respond_error(400, "invalid_body",
                             "The local blocklist import is not valid.",
                             request->request_id, output, output_size, written);
    }
    prepared.parameters.blocklist_import.content =
        malloc(content_size == 0U ? 1U : content_size);
    if (prepared.parameters.blocklist_import.content == NULL) {
        return -ENOMEM;
    }
    if (content_size > 0U) {
        (void)memcpy(prepared.parameters.blocklist_import.content, content,
                     content_size);
    }
    prepared.parameters.blocklist_import.content_size = content_size;
    result = submit_management_job(management, request, remote, &actor,
                                   &prepared, now, &job_id);
    management_job_parameters_clear(prepared.kind, &prepared.parameters);
    if (result != 0) {
        return respond_job_submission_error(
            result, request, "The local blocklist import could not be queued.",
            output, output_size, written);
    }
    return respond_job_accepted(job_id, output, output_size, written);
}

/** @brief Process and audit every enabled remote source currently due. */
int update_due_blocklists_now(struct jg_management *management,
                              uint64_t now,
                              size_t *attempts)
{
    struct jg_database_blocklist_source *sources = NULL;
    uint64_t after_id = 0U;
    size_t attempt_count = 0U;
    bool has_more = true;
    int result = 0;

    if (management == NULL || now == 0U) {
        return -EINVAL;
    }
    if (attempts != NULL) {
        *attempts = 0U;
    }
    sources = calloc(JG_DATABASE_POLICY_PAGE_MAX, sizeof(*sources));
    if (sources == NULL) {
        return -ENOMEM;
    }
    while (result == 0 && has_more) {
        size_t count = 0U;

        result = jg_database_list_blocklist_sources(
            management->database, after_id, JG_DATABASE_POLICY_PAGE_MAX,
            sources, &count, &has_more);
        for (size_t index = 0U; result == 0 && index < count; ++index) {
            struct jg_blocklist_update_result update;
            struct source_refresh_completion completion = {
                .management = management,
                .action = "blocklist.source.refresh",
                .now = now,
                .append_event = true,
            };

            after_id = sources[index].id;
            if (!sources[index].enabled || sources[index].url[0U] == '\0' ||
                sources[index].next_attempt_at > now) {
                continue;
            }
            result = jg_blocklist_update_complete(
                management->database, sources[index].id,
                sources[index].revision, now, complete_source_refresh,
                &completion, &update);
            if (update.attempted) {
                ++attempt_count;
            }
            finish_blocklist_policy_transaction(management, update.activated,
                                                result);
            if (result == 0 && completion.operation_result != 0) {
                result = completion.operation_result;
            }
            if (result != 0 && update.source.id != 0U && !completion.called) {
                const int audit_result = append_blocklist_update_audit(
                    management, NULL, NULL, NULL, "blocklist.source.refresh",
                    &update, result, false, 0U, now);
                const int event_result = append_blocklist_update_event(
                    management, &update, result, now);

                if (audit_result != 0) {
                    result = audit_result;
                } else if (event_result != 0) {
                    result = event_result;
                }
            }
        }
    }
    free(sources);
    if (attempts != NULL) {
        *attempts = attempt_count;
    }
    return result;
}

/** @brief Queue due source processing without blocking the control server. */
int jg_management_update_due_blocklists(struct jg_management *management,
                                        uint64_t now,
                                        size_t *attempts)
{
    if (management == NULL || now == 0U) {
        return -EINVAL;
    }
    if (attempts != NULL) {
        *attempts = 0U;
    }
    if (management_degraded_reasons(management) != 0U) {
        return -EROFS;
    }
    return submit_scheduled_source_job(management, now);
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
    int result = publish_policy_change(management, now, published, generation);

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
    int result = publish_policy_change(management, now, published, generation);

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
