/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_logging.c
 * @brief Logging configuration and diagnostic trace management.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "janusgate/access.h"
#include "janusgate/audit.h"
#include "janusgate/database.h"
#include "janusgate/logging.h"

/** @brief Report whether a logging configuration enables diagnostics. */
static bool logging_diagnostics_configured(
    const struct jg_logging_config *config)
{
    if (config->global_level > JG_LOG_INFO) {
        return true;
    }
    for (size_t index = 0U; index < config->override_count; ++index) {
        if (config->overrides[index].level > JG_LOG_INFO) {
            return true;
        }
    }
    return false;
}

/** @brief Parse one exact logging destination array. */
static int parse_logging_destinations(json_t *values, uint32_t *destinations)
{
    size_t index = 0U;
    json_t *value = NULL;

    *destinations = 0U;
    if (!json_is_array(values) || json_array_size(values) == 0U ||
        json_array_size(values) > 2U) {
        return -EINVAL;
    }
    json_array_foreach(values, index, value)
    {
        const char *name = json_string_value(value);
        uint32_t destination = 0U;

        if (name != NULL && strcmp(name, "stderr") == 0) {
            destination = JG_LOG_DESTINATION_STDERR;
        } else if (name != NULL && strcmp(name, "syslog") == 0) {
            destination = JG_LOG_DESTINATION_SYSLOG;
        } else {
            return -EINVAL;
        }
        if ((*destinations & destination) != 0U) {
            return -EINVAL;
        }
        *destinations |= destination;
    }
    return 0;
}

/** @brief Parse exact per-component logging overrides. */
static int parse_logging_overrides(json_t *values,
                                   struct jg_logging_config *config)
{
    static const char *const fields[] = {
        "component",
        "level",
    };
    size_t index = 0U;
    json_t *value = NULL;

    if (!json_is_array(values) ||
        json_array_size(values) > JG_LOG_OVERRIDE_COUNT_MAX) {
        return -EINVAL;
    }
    config->override_count = json_array_size(values);
    json_array_foreach(values, index, value)
    {
        const char *component =
            required_string(value, "component", 1U, JG_LOG_COMPONENT_MAX);
        const char *level = required_string(value, "level", 4U, 7U);

        if (!fields_allowed(value, fields,
                            sizeof(fields) / sizeof(fields[0U])) ||
            json_object_size(value) != 2U || component == NULL ||
            jg_log_level_parse(level, &config->overrides[index].level) != 0) {
            return -EINVAL;
        }
        (void)memcpy(config->overrides[index].component, component,
                     strlen(component) + 1U);
    }
    return 0;
}

/** @brief Parse one exact revision-bound logging update. */
static int parse_logging_request(json_t *body,
                                 uint64_t now,
                                 uint64_t *revision,
                                 struct jg_logging_config *config)
{
    static const char *const fields[] = {
        "revision",
        "global_level",
        "destinations",
        "rate_limit_per_second",
        "trace_capacity",
        "diagnostic_duration_seconds",
        "include_identifiers",
        "overrides",
    };
    const char *global_level = required_string(body, "global_level", 4U, 7U);
    uint64_t rate_limit = 0U;
    uint64_t trace_capacity = 0U;
    uint64_t duration = 0U;
    int result = 0;

    jg_logging_config_default(config);
    if (!fields_allowed(body, fields, sizeof(fields) / sizeof(fields[0U])) ||
        json_object_size(body) != sizeof(fields) / sizeof(fields[0U]) ||
        !required_identifier(body, "revision", revision) ||
        global_level == NULL ||
        jg_log_level_parse(global_level, &config->global_level) != 0 ||
        !required_unsigned(body, "rate_limit_per_second", JG_LOG_RATE_LIMIT_MAX,
                           &rate_limit) ||
        rate_limit == 0U ||
        !required_unsigned(body, "trace_capacity", JG_LOG_TRACE_CAPACITY_MAX,
                           &trace_capacity) ||
        !required_unsigned(body, "diagnostic_duration_seconds",
                           MANAGEMENT_DIAGNOSTIC_DURATION_MAX, &duration) ||
        !required_boolean(body, "include_identifiers",
                          &config->include_identifiers)) {
        return -EINVAL;
    }
    config->rate_limit_per_second = (uint32_t)rate_limit;
    config->trace_capacity = (uint32_t)trace_capacity;
    result = parse_logging_destinations(json_object_get(body, "destinations"),
                                        &config->destinations);
    if (result == 0) {
        result =
            parse_logging_overrides(json_object_get(body, "overrides"), config);
    }
    if (result == 0 && logging_diagnostics_configured(config)) {
        if (duration < MANAGEMENT_DIAGNOSTIC_DURATION_MIN ||
            now > (uint64_t)INT64_MAX - duration) {
            result = -ERANGE;
        } else {
            config->diagnostic_until = now + duration;
        }
    } else if (result == 0 && duration != 0U) {
        result = -EINVAL;
    }
    if (result == 0) {
        result = jg_logging_config_validate(config);
    }
    return result;
}

/** @brief Serialize configured logging destinations. */
static json_t *logging_destinations_json(uint32_t destinations)
{
    json_t *values = json_array();

    if (values == NULL ||
        ((destinations & JG_LOG_DESTINATION_STDERR) != 0U &&
         json_array_append_new(values, json_string("stderr")) != 0) ||
        ((destinations & JG_LOG_DESTINATION_SYSLOG) != 0U &&
         json_array_append_new(values, json_string("syslog")) != 0)) {
        json_decref(values);
        return NULL;
    }
    return values;
}

/** @brief Serialize configured per-component logging overrides. */
static json_t *logging_overrides_json(const struct jg_logging_config *config)
{
    json_t *values = json_array();

    if (values == NULL) {
        return NULL;
    }
    for (size_t index = 0U; index < config->override_count; ++index) {
        json_t *value = json_object();

        if (value == NULL ||
            json_object_set_new(
                value, "component",
                json_string(config->overrides[index].component)) != 0 ||
            json_object_set_new(value, "level",
                                json_string(jg_log_level_name(
                                    config->overrides[index].level))) != 0 ||
            json_array_append_new(values, value) != 0) {
            json_decref(value);
            json_decref(values);
            return NULL;
        }
    }
    return values;
}

/** @brief Serialize persistent logging state and bounded runtime counters. */
static json_t *logging_response(const struct jg_database_logging_config *record,
                                uint64_t now)
{
    struct jg_logging_stats stats;
    json_t *body = json_object();
    json_t *destinations =
        logging_destinations_json(record->config.destinations);
    json_t *overrides = logging_overrides_json(&record->config);
    const uint64_t remaining = record->config.diagnostic_until > now
                                   ? record->config.diagnostic_until - now
                                   : 0U;
    int result = jg_logging_get(NULL, &stats);

    if (result == 0 &&
        (body == NULL || destinations == NULL || overrides == NULL ||
         set_counter(body, "revision", record->revision) != 0 ||
         set_counter(body, "updated_at", record->updated_at) != 0 ||
         json_object_set_new(body, "global_level",
                             json_string(jg_log_level_name(
                                 record->config.global_level))) != 0 ||
         json_object_set(body, "destinations", destinations) != 0 ||
         set_counter(body, "rate_limit_per_second",
                     record->config.rate_limit_per_second) != 0 ||
         set_counter(body, "trace_capacity", record->config.trace_capacity) !=
             0 ||
         set_counter(body, "diagnostic_until",
                     record->config.diagnostic_until) != 0 ||
         set_counter(body, "diagnostic_remaining_seconds", remaining) != 0 ||
         json_object_set_new(body, "diagnostic_active",
                             json_boolean(remaining != 0U)) != 0 ||
         json_object_set_new(
             body, "include_identifiers",
             json_boolean(record->config.include_identifiers)) != 0 ||
         json_object_set(body, "overrides", overrides) != 0 ||
         set_counter(body, "emitted", stats.emitted) != 0 ||
         set_counter(body, "suppressed", stats.suppressed) != 0 ||
         set_counter(body, "buffered", (uint64_t)stats.buffered) != 0)) {
        result = -ENOMEM;
    }
    json_decref(overrides);
    json_decref(destinations);
    if (result != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Append one authenticated logging configuration mutation. */
static int append_logging_audit(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const struct jg_database_logging_config *previous,
    const struct jg_database_logging_config *updated,
    uint64_t now)
{
    char source[INET6_ADDRSTRLEN];
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int result = 0;

    if (inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source, sizeof(source)) == NULL) {
        result = -EINVAL;
    }
    if (result == 0 &&
        (details == NULL ||
         json_object_set_new(details, "global_level",
                             json_string(jg_log_level_name(
                                 updated->config.global_level))) != 0 ||
         json_object_set_new(
             details, "include_identifiers",
             json_boolean(updated->config.include_identifiers)) != 0 ||
         set_counter(details, "diagnostic_until",
                     updated->config.diagnostic_until) != 0)) {
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
            .source = source,
            .action = "logging.update",
            .object_type = "logging_configuration",
            .object_id = "active",
            .details = encoded,
            .has_previous_revision = true,
            .previous_revision = previous->revision,
            .has_new_revision = true,
            .new_revision = updated->revision,
            .success = true,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Return persistent logging configuration and runtime counters. */
int handle_logging_get(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_logging_config record;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_STATUS_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The logging request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_database_load_logging_config(management->database, &record);
    if (result != 0) {
        return respond_error(503, "logging_unavailable",
                             "Logging configuration is unavailable.",
                             request->request_id, output, output_size, written);
    }
    body = logging_response(&record, now);
    if (body == NULL) {
        return -ENOMEM;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Persist, audit, and activate logging configuration. */
int handle_logging_update(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_logging_config previous;
    struct jg_database_logging_config updated;
    struct jg_logging_config config;
    json_t *body = NULL;
    uint64_t revision = 0U;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_SYSTEM_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = request->query[0U] == '\0'
                 ? parse_logging_request(request->body, now, &revision, &config)
                 : -EINVAL;
    if (result != 0) {
        return respond_error(
            result == -ERANGE ? 422 : 400,
            result == -ERANGE ? "logging_limits" : "invalid_body",
            result == -ERANGE
                ? "Diagnostic logging must expire between 60 and 3600 seconds."
                : "The logging configuration is not valid.",
            request->request_id, output, output_size, written);
    }
    result = jg_database_load_logging_config(management->database, &previous);
    if (result == 0) {
        result = jg_database_replace_logging_config(
            management->database, &config, revision, &updated);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "Logging configuration changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "logging_update_failed",
                             "Logging configuration could not be updated.",
                             request->request_id, output, output_size, written);
    }
    result = jg_logging_configure(&updated.config);
    if (result == 0) {
        result = append_logging_audit(management, request, remote, &actor,
                                      &previous, &updated, now);
    }
    if (result != 0) {
        return respond_error(
            500, "logging_activation_failed",
            "Logging was saved but could not be activated or audited.",
            request->request_id, output, output_size, written);
    }
    body = logging_response(&updated, now);
    if (body == NULL) {
        return -ENOMEM;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Return the bounded in-memory diagnostic trace window. */
int handle_logging_traces(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written)
{
    struct authenticated_actor actor;
    struct jg_log_trace_record *records = NULL;
    struct jg_logging_stats stats;
    json_t *body = NULL;
    json_t *values = NULL;
    size_t count = 0U;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_OPERATE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The trace request is not valid.",
                             request->request_id, output, output_size, written);
    }
    records = calloc(JG_LOG_TRACE_CAPACITY_MAX, sizeof(*records));
    body = json_object();
    values = json_array();
    if (records == NULL || body == NULL || values == NULL) {
        result = -ENOMEM;
    }
    if (result == 0) {
        result = jg_logging_trace_snapshot(records, JG_LOG_TRACE_CAPACITY_MAX,
                                           &count, &stats);
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_error_t error;
        json_t *value =
            json_loads(records[index].json, JSON_REJECT_DUPLICATES, &error);

        if (!json_is_object(value) ||
            json_array_append_new(values, value) != 0) {
            json_decref(value);
            result = -EILSEQ;
        }
    }
    free(records);
    if (result == 0 &&
        (json_object_set(body, "records", values) != 0 ||
         set_counter(body, "count", (uint64_t)count) != 0 ||
         set_counter(body, "emitted", stats.emitted) != 0 ||
         set_counter(body, "suppressed", stats.suppressed) != 0 ||
         json_object_set_new(body, "diagnostic_active",
                             json_boolean(stats.diagnostic_active)) != 0)) {
        result = -ENOMEM;
    }
    json_decref(values);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}
