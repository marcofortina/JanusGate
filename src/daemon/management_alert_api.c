/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_alert_api.c
 * @brief Native alert incident and notification administration.
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
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>

#include "janusgate/access.h"
#include "janusgate/audit.h"

/** Number of fields in one complete alert configuration replacement. */
#define ALERT_CONFIGURATION_FIELD_COUNT 16U

/** @brief Set one optional string or explicit JSON null. */
static int set_optional_string(json_t *object,
                               const char *name,
                               const char *value)
{
    return json_object_set_new(
        object, name, value == NULL ? json_null() : json_string(value));
}

/** @brief Serialize one complete alert configuration without secret material.
 */
static json_t *alert_configuration_json(
    const struct jg_alert_configuration *configuration)
{
    const struct jg_alert_configuration_update *values = &configuration->values;
    json_t *body = json_object();

    if (body == NULL ||
        set_counter(body, "revision", configuration->revision) != 0 ||
        set_optional_timestamp(body, "updated_at", configuration->updated_at) !=
            0 ||
        json_object_set_new(body, "enabled", json_boolean(values->enabled)) !=
            0 ||
        set_counter(body, "evaluation_interval_seconds",
                    values->evaluation_interval_seconds) != 0 ||
        set_counter(body, "certificate_warning_days",
                    values->certificate_warning_days) != 0 ||
        set_counter(body, "source_failure_threshold",
                    values->source_failure_threshold) != 0 ||
        set_counter(body, "source_stale_seconds",
                    values->source_stale_seconds) != 0 ||
        set_counter(body, "filesystem_minimum_percent",
                    values->filesystem_minimum_percent) != 0 ||
        set_counter(body, "filesystem_minimum_bytes",
                    values->filesystem_minimum_bytes) != 0 ||
        set_counter(body, "queue_window_seconds",
                    values->queue_window_seconds) != 0 ||
        set_counter(body, "queue_drop_threshold",
                    values->queue_drop_threshold) != 0 ||
        set_counter(body, "authentication_window_seconds",
                    values->authentication_window_seconds) != 0 ||
        set_counter(body, "authentication_failure_threshold",
                    values->authentication_failure_threshold) != 0 ||
        json_object_set_new(body, "webhook_enabled",
                            json_boolean(values->webhook_enabled)) != 0 ||
        set_optional_string(body, "webhook_url", values->webhook_url) != 0 ||
        set_optional_string(body, "webhook_ca_pem", values->webhook_ca_pem) !=
            0 ||
        set_counter(body, "webhook_timeout_seconds",
                    values->webhook_timeout_seconds) != 0 ||
        json_object_set_new(
            body, "webhook_secret_configured",
            json_boolean(configuration->webhook_secret_configured)) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Read one required string-or-null configuration field. */
static bool required_optional_string(const json_t *object,
                                     const char *name,
                                     size_t maximum,
                                     const char **value)
{
    json_t *field = json_object_get(object, name);

    *value = NULL;
    if (json_is_null(field)) {
        return true;
    }
    if (!json_is_string(field) || json_string_length(field) == 0U ||
        json_string_length(field) > maximum) {
        return false;
    }
    *value = json_string_value(field);
    return true;
}

/** @brief Parse one complete revision-bound alert configuration. */
static int parse_alert_configuration(
    json_t *body,
    uint64_t *revision,
    struct jg_alert_configuration_update *update)
{
    static const char *const fields[ALERT_CONFIGURATION_FIELD_COUNT] = {
        "revision",
        "enabled",
        "evaluation_interval_seconds",
        "certificate_warning_days",
        "source_failure_threshold",
        "source_stale_seconds",
        "filesystem_minimum_percent",
        "filesystem_minimum_bytes",
        "queue_window_seconds",
        "queue_drop_threshold",
        "authentication_window_seconds",
        "authentication_failure_threshold",
        "webhook_enabled",
        "webhook_url",
        "webhook_ca_pem",
        "webhook_timeout_seconds",
    };
    uint64_t evaluation_interval = 0U;
    uint64_t certificate_warning = 0U;
    uint64_t source_failures = 0U;
    uint64_t source_stale = 0U;
    uint64_t filesystem_percent = 0U;
    uint64_t filesystem_bytes = 0U;
    uint64_t queue_window = 0U;
    uint64_t queue_threshold = 0U;
    uint64_t authentication_window = 0U;
    uint64_t authentication_threshold = 0U;
    uint64_t webhook_timeout = 0U;

    if (!fields_allowed(body, fields, ALERT_CONFIGURATION_FIELD_COUNT) ||
        json_object_size(body) != ALERT_CONFIGURATION_FIELD_COUNT ||
        !required_identifier(body, "revision", revision) ||
        !required_boolean(body, "enabled", &update->enabled) ||
        !required_unsigned(body, "evaluation_interval_seconds", UINT32_MAX,
                           &evaluation_interval) ||
        !required_unsigned(body, "certificate_warning_days", UINT32_MAX,
                           &certificate_warning) ||
        !required_unsigned(body, "source_failure_threshold", UINT32_MAX,
                           &source_failures) ||
        !required_unsigned(body, "source_stale_seconds", UINT32_MAX,
                           &source_stale) ||
        !required_unsigned(body, "filesystem_minimum_percent", UINT32_MAX,
                           &filesystem_percent) ||
        !required_unsigned(body, "filesystem_minimum_bytes", INT64_MAX,
                           &filesystem_bytes) ||
        !required_unsigned(body, "queue_window_seconds", UINT32_MAX,
                           &queue_window) ||
        !required_unsigned(body, "queue_drop_threshold", INT64_MAX,
                           &queue_threshold) ||
        !required_unsigned(body, "authentication_window_seconds", UINT32_MAX,
                           &authentication_window) ||
        !required_unsigned(body, "authentication_failure_threshold", INT64_MAX,
                           &authentication_threshold) ||
        !required_boolean(body, "webhook_enabled", &update->webhook_enabled) ||
        !required_optional_string(body, "webhook_url", JG_ALERT_WEBHOOK_URL_MAX,
                                  &update->webhook_url) ||
        !required_optional_string(body, "webhook_ca_pem",
                                  JG_ALERT_WEBHOOK_CA_MAX,
                                  &update->webhook_ca_pem) ||
        !required_unsigned(body, "webhook_timeout_seconds", UINT32_MAX,
                           &webhook_timeout)) {
        return -EINVAL;
    }
    update->evaluation_interval_seconds = (uint32_t)evaluation_interval;
    update->certificate_warning_days = (uint32_t)certificate_warning;
    update->source_failure_threshold = (uint32_t)source_failures;
    update->source_stale_seconds = (uint32_t)source_stale;
    update->filesystem_minimum_percent = (uint32_t)filesystem_percent;
    update->filesystem_minimum_bytes = filesystem_bytes;
    update->queue_window_seconds = (uint32_t)queue_window;
    update->queue_drop_threshold = queue_threshold;
    update->authentication_window_seconds = (uint32_t)authentication_window;
    update->authentication_failure_threshold = authentication_threshold;
    update->webhook_timeout_seconds = (uint32_t)webhook_timeout;
    return jg_alert_configuration_validate(update);
}

/** @brief Convert one incident record to public JSON. */
static json_t *alert_incident_json(const struct jg_alert_incident *incident)
{
    json_error_t error;
    json_t *details =
        json_loads(incident->details, JSON_REJECT_DUPLICATES, &error);
    json_t *body = json_object();

    if (!json_is_object(details) || body == NULL ||
        set_counter(body, "id", incident->id) != 0 ||
        json_object_set_new(body, "type",
                            json_string(jg_alert_type_name(incident->type))) !=
            0 ||
        json_object_set_new(body, "resource",
                            json_string(incident->resource)) != 0 ||
        json_object_set_new(
            body, "severity",
            json_string(jg_alert_severity_name(incident->severity))) != 0 ||
        json_object_set_new(
            body, "state", json_string(jg_alert_state_name(incident->state))) !=
            0 ||
        json_object_set_new(body, "summary", json_string(incident->summary)) !=
            0 ||
        json_object_set(body, "details", details) != 0 ||
        set_counter(body, "opened_at", incident->opened_at) != 0 ||
        set_counter(body, "updated_at", incident->updated_at) != 0 ||
        set_optional_timestamp(body, "resolved_at", incident->resolved_at) !=
            0 ||
        set_counter(body, "occurrences", incident->occurrences) != 0) {
        json_decref(details);
        json_decref(body);
        return NULL;
    }
    json_decref(details);
    return body;
}

/** @brief Parse one exact decimal query value. */
static int parse_query_unsigned(const char *value,
                                size_t size,
                                uint64_t maximum,
                                uint64_t *parsed)
{
    uint64_t result = 0U;

    if (size == 0U) {
        return -EINVAL;
    }
    for (size_t index = 0U; index < size; ++index) {
        const uint8_t digit = (uint8_t)value[index] - (uint8_t)'0';

        if (digit > 9U || result > (maximum - digit) / 10U) {
            return -EINVAL;
        }
        result = result * 10U + digit;
    }
    *parsed = result;
    return 0;
}

/** @brief Parse one fixed incident state query value. */
static bool parse_alert_state(const char *value,
                              size_t size,
                              enum jg_alert_state *state)
{
    for (int candidate = JG_ALERT_STATE_OPEN;
         candidate <= JG_ALERT_STATE_RESOLVED; ++candidate) {
        const char *name = jg_alert_state_name((enum jg_alert_state)candidate);

        if (name != NULL && strlen(name) == size &&
            memcmp(name, value, size) == 0) {
            *state = (enum jg_alert_state)candidate;
            return true;
        }
    }
    return false;
}

/** @brief Parse one fixed incident type query value. */
static bool parse_alert_type(const char *value,
                             size_t size,
                             enum jg_alert_type *type)
{
    for (int candidate = JG_ALERT_TYPE_APPLIANCE_DEGRADED;
         candidate <= JG_ALERT_TYPE_AUTHENTICATION_FAILURES; ++candidate) {
        const char *name = jg_alert_type_name((enum jg_alert_type)candidate);

        if (name != NULL && strlen(name) == size &&
            memcmp(name, value, size) == 0) {
            *type = (enum jg_alert_type)candidate;
            return true;
        }
    }
    return false;
}

/** @brief Parse stable native-alert pagination and exact filters. */
static int parse_alert_query(const char *query,
                             struct jg_alert_filter *filter,
                             size_t *limit)
{
    const char *cursor = query;
    bool have_before_id = false;
    bool have_limit = false;
    bool have_state = false;
    bool have_type = false;
    int result = 0;

    *filter = (struct jg_alert_filter){0};
    *limit = JG_ALERT_PAGE_MAX < 50U ? JG_ALERT_PAGE_MAX : 50U;
    while (result == 0 && cursor != NULL && *cursor != '\0') {
        const char *end = strchr(cursor, '&');
        const char *equals = strchr(cursor, '=');
        const size_t field_size =
            end == NULL ? strlen(cursor) : (size_t)(end - cursor);
        const size_t name_size =
            equals == NULL ? field_size : (size_t)(equals - cursor);
        const char *value =
            equals == NULL || name_size >= field_size ? NULL : equals + 1;
        const size_t value_size =
            value == NULL ? 0U : field_size - name_size - 1U;
        uint64_t parsed = 0U;

        if (equals == NULL || name_size == 0U || value_size == 0U ||
            name_size >= field_size) {
            result = -EINVAL;
        } else if (name_size == sizeof("before_id") - 1U &&
                   memcmp(cursor, "before_id", name_size) == 0 &&
                   !have_before_id) {
            result = parse_query_unsigned(value, value_size, INT64_MAX,
                                          &filter->before_id);
            have_before_id = result == 0;
        } else if (name_size == sizeof("limit") - 1U &&
                   memcmp(cursor, "limit", name_size) == 0 && !have_limit) {
            result = parse_query_unsigned(value, value_size, JG_ALERT_PAGE_MAX,
                                          &parsed);
            if (result == 0 && parsed > 0U) {
                *limit = (size_t)parsed;
                have_limit = true;
            } else {
                result = -EINVAL;
            }
        } else if (name_size == sizeof("state") - 1U &&
                   memcmp(cursor, "state", name_size) == 0 && !have_state &&
                   parse_alert_state(value, value_size, &filter->state)) {
            have_state = true;
        } else if (name_size == sizeof("type") - 1U &&
                   memcmp(cursor, "type", name_size) == 0 && !have_type &&
                   parse_alert_type(value, value_size, &filter->type)) {
            have_type = true;
        } else {
            result = -EINVAL;
        }
        cursor = end == NULL ? NULL : end + 1;
        if (end != NULL && end[1] == '\0') {
            result = -EINVAL;
        }
    }
    return result;
}

/** @brief Append one authenticated alert administration event. */
static int append_alert_audit(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              const struct authenticated_actor *actor,
                              const char *action,
                              json_t *details,
                              uint64_t previous_revision,
                              uint64_t new_revision,
                              uint64_t now)
{
    char source[INET6_ADDRSTRLEN];
    char *encoded = NULL;
    struct jg_audit_event event;
    int result = 0;

    if (inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source, sizeof(source)) == NULL) {
        return -EINVAL;
    }
    encoded = json_dumps(details, JSON_COMPACT | JSON_SORT_KEYS);
    if (encoded == NULL) {
        return -ENOMEM;
    }
    event = (struct jg_audit_event){
        .occurred_at = now,
        .actor_type = actor_audit_type(actor),
        .has_actor_id = actor_has_identifier(actor),
        .actor_id = actor->actor_id,
        .source = source,
        .action = action,
        .object_type = "alerting",
        .object_id = "native",
        .details = encoded,
        .has_previous_revision = previous_revision != 0U,
        .previous_revision = previous_revision,
        .has_new_revision = new_revision != 0U,
        .new_revision = new_revision,
        .success = true,
        .request_id = request->request_id,
    };
    result = jg_database_audit_append(management->database, &event, NULL);
    free(encoded);
    return result;
}

/** @brief Return one filtered page of native alert incidents. */
int handle_alerts_list(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written)
{
    struct authenticated_actor actor;
    struct jg_alert_filter filter;
    struct jg_alert_incident *incidents = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    size_t limit = 0U;
    size_t count = 0U;
    bool has_more = false;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_STATUS_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_alert_query(request->query, &filter, &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The alert filters or pagination are not valid.",
                             request->request_id, output, output_size, written);
    }
    incidents = calloc(limit, sizeof(*incidents));
    if (incidents == NULL) {
        return -ENOMEM;
    }
    result = jg_database_alert_list(management->database, &filter, incidents,
                                    limit, &count, &has_more);
    body = json_object();
    items = json_array();
    if (result == 0 && (body == NULL || items == NULL)) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = alert_incident_json(&incidents[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (set_counter(body, "before_id", filter.before_id) != 0 ||
         set_counter(body, "limit", (uint64_t)limit) != 0 ||
         set_counter(body, "count", (uint64_t)count) != 0 ||
         json_object_set_new(body, "has_more", json_boolean(has_more)) != 0 ||
         json_object_set_new(
             body, "state",
             filter.state == JG_ALERT_STATE_ANY
                 ? json_null()
                 : json_string(jg_alert_state_name(filter.state))) != 0 ||
         json_object_set_new(
             body, "type",
             filter.type == JG_ALERT_TYPE_ANY
                 ? json_null()
                 : json_string(jg_alert_type_name(filter.type))) != 0 ||
         json_object_set(body, "alerts", items) != 0)) {
        result = -ENOMEM;
    }
    free(incidents);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "alerts_unavailable",
                             "Native alert incidents could not be read.",
                             request->request_id, output, output_size, written);
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Return or replace native alert configuration. */
int handle_alert_configuration(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    struct authenticated_actor actor;
    struct jg_alert_configuration configuration = {0};
    struct jg_alert_configuration_update update = {0};
    const bool replacing = strcmp(request->method, "PUT") == 0;
    uint64_t revision = 0U;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, replacing,
                                    replacing ? JG_ACCESS_SYSTEM_WRITE
                                              : JG_ACCESS_STATUS_READ,
                                    now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        (!replacing && json_object_size(request->body) != 0U)) {
        return respond_error(400, "invalid_request",
                             "The alert configuration request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (replacing) {
        result = parse_alert_configuration(request->body, &revision, &update);
        if (result != 0) {
            return respond_error(
                400, "invalid_body", "The alert configuration is not valid.",
                request->request_id, output, output_size, written);
        }
        result = jg_database_alert_configuration_replace(
            management->database, &update, revision, now, &configuration);
    } else {
        result = jg_database_alert_configuration_load(management->database,
                                                      &configuration);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "Alert configuration changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result == -ENOENT) {
        return respond_error(
            409, "webhook_secret_required",
            "Generate a webhook secret before enabling delivery.",
            request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "alert_configuration_failed",
                             "Alert configuration could not be processed.",
                             request->request_id, output, output_size, written);
    }
    body = alert_configuration_json(&configuration);
    if (body == NULL) {
        jg_alert_configuration_clear(&configuration);
        return -ENOMEM;
    }
    if (replacing) {
        json_t *details = json_pack("{s:b,s:b}", "enabled", update.enabled,
                                    "webhook_enabled", update.webhook_enabled);

        result =
            details == NULL
                ? -ENOMEM
                : append_alert_audit(management, request, remote, &actor,
                                     "alerting.configuration.update", details,
                                     revision, configuration.revision, now);
        json_decref(details);
        if (result == 0) {
            management_alerts_wake(management->alerts);
        }
    }
    jg_alert_configuration_clear(&configuration);
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "audit_failure",
                             "The alert configuration could not be audited.",
                             request->request_id, output, output_size, written);
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Rotate and return the webhook secret exactly once. */
int handle_alert_webhook_secret(struct jg_management *management,
                                const struct management_request *request,
                                const struct remote_address *remote,
                                uint64_t now,
                                uint8_t *output,
                                size_t output_size,
                                size_t *written)
{
    static const char *const fields[] = {"revision"};
    struct authenticated_actor actor;
    struct jg_alert_configuration configuration = {0};
    char secret[JG_ALERT_WEBHOOK_SECRET_TEXT_SIZE] = {0};
    uint64_t revision = 0U;
    json_t *body = NULL;
    json_t *details = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_SYSTEM_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields, 1U) ||
        json_object_size(request->body) != 1U ||
        !required_identifier(request->body, "revision", &revision)) {
        return respond_error(
            400, "invalid_body",
            "A current alert configuration revision is required.",
            request->request_id, output, output_size, written);
    }
    result = jg_database_alert_webhook_secret_rotate(
        management->database, management->secrets->totp_key, revision, now,
        secret, &configuration);
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "Alert configuration changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result == 0) {
        details = json_object();
        result =
            details == NULL
                ? -ENOMEM
                : append_alert_audit(management, request, remote, &actor,
                                     "alerting.webhook.secret.rotate", details,
                                     revision, configuration.revision, now);
    }
    if (result == 0) {
        body = alert_configuration_json(&configuration);
        if (body == NULL || json_object_set_new(body, "webhook_secret",
                                                json_string(secret)) != 0) {
            json_decref(body);
            body = NULL;
            result = -ENOMEM;
        }
    }
    json_decref(details);
    jg_alert_configuration_clear(&configuration);
    sodium_memzero(secret, sizeof(secret));
    if (result != 0) {
        return respond_error(500, "webhook_secret_failed",
                             "The webhook secret could not be rotated.",
                             request->request_id, output, output_size, written);
    }
    management_alerts_wake(management->alerts);
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Enqueue one authenticated webhook test notification. */
int handle_alert_webhook_test(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    struct authenticated_actor actor;
    struct jg_alert_configuration configuration = {0};
    char event_id[JG_ALERT_EVENT_ID_SIZE];
    json_t *details = NULL;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_SYSTEM_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The webhook test request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_database_alert_configuration_load(management->database,
                                                  &configuration);
    if (result == 0 && !configuration.values.webhook_enabled) {
        jg_alert_configuration_clear(&configuration);
        return respond_error(409, "webhook_disabled",
                             "Enable webhook delivery before sending a test.",
                             request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = jg_database_alert_event_enqueue(
            management->database, "webhook.test", JG_ALERT_SEVERITY_WARNING,
            "JanusGate webhook test notification.", "{}", now, event_id);
    }
    if (result == 0) {
        details = json_object();
        result = details == NULL
                     ? -ENOMEM
                     : append_alert_audit(management, request, remote, &actor,
                                          "alerting.webhook.test", details, 0U,
                                          0U, now);
    }
    if (result == 0) {
        body = json_pack("{s:s,s:s}", "event_id", event_id, "state", "pending");
        result = body == NULL ? -ENOMEM : 0;
    }
    json_decref(details);
    jg_alert_configuration_clear(&configuration);
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "webhook_test_failed",
                             "The webhook test could not be queued.",
                             request->request_id, output, output_size, written);
    }
    management_alerts_wake(management->alerts);
    return encode_response(202, body, NULL, output, output_size, written);
}
