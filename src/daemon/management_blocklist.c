/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_blocklist.c
 * @brief Blocklist source and update management.
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
#include <sodium.h>

#include "blocklist_update.h"
#include "janusgate/access.h"
#include "janusgate/audit.h"
#include "janusgate/blocklist.h"
#include "janusgate/database.h"
#include "janusgate/event.h"
#include "janusgate/policy.h"

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

/** @brief Return the stable external name for one enforcement mode. */
static const char *enforcement_name(enum jg_policy_enforcement enforcement)
{
    return enforcement == JG_POLICY_ENFORCE
               ? "enforce"
               : (enforcement == JG_POLICY_OBSERVE ? "observe" : NULL);
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
    const char *enforcement = enforcement_name(source->enforcement);
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

    if (format == NULL || mode == NULL || health == NULL ||
        enforcement == NULL || body == NULL || sha256_pin == NULL ||
        public_key == NULL || active_checksum == NULL) {
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
         json_object_set_new(body, "enforcement", json_string(enforcement)) !=
             0 ||
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

/** @brief Parse one optional source enforcement mode. */
static bool parse_source_enforcement(const char *text,
                                     enum jg_policy_enforcement *enforcement)
{
    if (text == NULL || enforcement == NULL) {
        return false;
    }
    if (text[0U] == '\0' || strcmp(text, "enforce") == 0) {
        *enforcement = JG_POLICY_ENFORCE;
        return true;
    }
    if (strcmp(text, "observe") == 0) {
        *enforcement = JG_POLICY_OBSERVE;
        return true;
    }
    return false;
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
        "enforcement",
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
    const char *enforcement = NULL;
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
    enforcement = optional_string(body, "enforcement", 7U);
    if (!fields_allowed(body, fields, sizeof(fields) / sizeof(fields[0U])) ||
        config->name == NULL ||
        !required_nullable_string(body, "url", JG_DATABASE_BLOCKLIST_URL_MAX,
                                  &config->url) ||
        !required_nullable_string(body, "signature_url",
                                  JG_DATABASE_BLOCKLIST_URL_MAX,
                                  &config->signature_url) ||
        !parse_blocklist_format(format, &config->format) ||
        !parse_blocklist_mode(mode, &config->mode) ||
        !parse_source_enforcement(enforcement, &config->enforcement) ||
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
    return management_publish_policy_change(management, now, published,
                                            generation);
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
