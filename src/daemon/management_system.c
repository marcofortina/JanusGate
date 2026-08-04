/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_system.c
 * @brief System status, observability, and lifecycle management.
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
#include <time.h>

#include <jansson.h>
#include <sodium.h>

#include "daemon_runtime.h"
#include "diagnostic_bundle.h"
#include "janusgate/access.h"
#include "janusgate/audit.h"
#include "janusgate/database.h"
#include "janusgate/diagnostic.h"
#include "janusgate/event.h"
#include "janusgate/ipc.h"
#include "metrics.h"
#include "netd_client.h"

/** @brief Return the stable external name for one audit actor kind. */
static const char *audit_actor_name(enum jg_audit_actor_type actor)
{
    switch (actor) {
    case JG_AUDIT_ACTOR_SYSTEM:
        return "system";
    case JG_AUDIT_ACTOR_USER:
        return "user";
    case JG_AUDIT_ACTOR_TOKEN:
        return "token";
    case JG_AUDIT_ACTOR_LOCAL:
        return "local";
    default:
        return NULL;
    }
}

/** @brief Convert one immutable audit record to public JSON. */
static json_t *audit_json(const struct jg_audit_record *record)
{
    char previous_hash[JG_AUDIT_HASH_SIZE * 2U + 1U];
    char event_hash[JG_AUDIT_HASH_SIZE * 2U + 1U];
    const char *actor = audit_actor_name(record->actor_type);
    json_t *body = json_object();

    (void)memset(previous_hash, 0, sizeof(previous_hash));
    if (!record->first &&
        sodium_bin2hex(previous_hash, sizeof(previous_hash),
                       record->previous_hash, JG_AUDIT_HASH_SIZE) == NULL) {
        json_decref(body);
        return NULL;
    }
    if (actor == NULL ||
        sodium_bin2hex(event_hash, sizeof(event_hash), record->event_hash,
                       JG_AUDIT_HASH_SIZE) == NULL ||
        body == NULL ||
        json_object_set_new(body, "id",
                            json_integer((json_int_t)record->event_id)) != 0 ||
        json_object_set_new(body, "occurred_at",
                            json_integer((json_int_t)record->occurred_at)) !=
            0 ||
        json_object_set_new(body, "actor_type", json_string(actor)) != 0 ||
        json_object_set_new(body, "actor_id",
                            record->has_actor_id
                                ? json_integer((json_int_t)record->actor_id)
                                : json_null()) != 0 ||
        json_object_set_new(body, "source", json_string(record->source)) != 0 ||
        json_object_set_new(body, "action", json_string(record->action)) != 0 ||
        json_object_set_new(body, "object_type",
                            json_string(record->object_type)) != 0 ||
        json_object_set_new(body, "object_id",
                            record->object_id[0U] == '\0'
                                ? json_null()
                                : json_string(record->object_id)) != 0 ||
        json_object_set_new(body, "details", json_string(record->details)) !=
            0 ||
        json_object_set_new(
            body, "previous_revision",
            record->has_previous_revision
                ? json_integer((json_int_t)record->previous_revision)
                : json_null()) != 0 ||
        json_object_set_new(body, "new_revision",
                            record->has_new_revision
                                ? json_integer((json_int_t)record->new_revision)
                                : json_null()) != 0 ||
        json_object_set_new(body, "success", json_boolean(record->success)) !=
            0 ||
        json_object_set_new(body, "request_id",
                            json_string(record->request_id)) != 0 ||
        json_object_set_new(body, "previous_hash",
                            record->first ? json_null()
                                          : json_string(previous_hash)) != 0 ||
        json_object_set_new(body, "event_hash", json_string(event_hash)) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Return the stable external name for one event severity. */
static const char *event_severity_name(enum jg_event_severity severity)
{
    switch (severity) {
    case JG_EVENT_SEVERITY_DEBUG:
        return "debug";
    case JG_EVENT_SEVERITY_INFO:
        return "info";
    case JG_EVENT_SEVERITY_WARNING:
        return "warning";
    case JG_EVENT_SEVERITY_ERROR:
        return "error";
    case JG_EVENT_SEVERITY_CRITICAL:
        return "critical";
    case JG_EVENT_SEVERITY_ANY:
    default:
        return NULL;
    }
}

/** @brief Parse one optional external event severity. */
static bool parse_event_severity(const char *text,
                                 size_t text_size,
                                 enum jg_event_severity *severity)
{
    static const struct {
        const char *name;
        enum jg_event_severity severity;
    } values[] = {
        {"debug", JG_EVENT_SEVERITY_DEBUG},
        {"info", JG_EVENT_SEVERITY_INFO},
        {"warning", JG_EVENT_SEVERITY_WARNING},
        {"error", JG_EVENT_SEVERITY_ERROR},
        {"critical", JG_EVENT_SEVERITY_CRITICAL},
    };

    for (size_t index = 0U; index < sizeof(values) / sizeof(values[0U]);
         ++index) {
        if (strlen(values[index].name) == text_size &&
            memcmp(values[index].name, text, text_size) == 0) {
            *severity = values[index].severity;
            return true;
        }
    }
    return false;
}

/** @brief Validate one bounded external event identifier. */
static bool event_identifier_valid(const char *text, size_t text_size)
{
    if (text == NULL || text_size == 0U || text_size > JG_EVENT_COMPONENT_MAX) {
        return false;
    }
    for (size_t index = 0U; index < text_size; ++index) {
        const char character = text[index];

        if (!((character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') || character == '_' ||
              character == '-' || character == '.')) {
            return false;
        }
    }
    return true;
}

/** @brief Convert one immutable operational event to public JSON. */
static json_t *event_json(const struct jg_event_record *record)
{
    const char *severity = event_severity_name(record->severity);
    json_error_t error;
    json_t *body = json_object();
    json_t *details =
        json_loads(record->details, JSON_REJECT_DUPLICATES, &error);

    if (severity == NULL || body == NULL || !json_is_object(details) ||
        json_object_set_new(body, "id", json_integer((json_int_t)record->id)) !=
            0 ||
        json_object_set_new(body, "occurred_at",
                            json_integer((json_int_t)record->occurred_at)) !=
            0 ||
        json_object_set_new(body, "severity", json_string(severity)) != 0 ||
        json_object_set_new(body, "component",
                            json_string(record->component)) != 0 ||
        json_object_set_new(body, "code", json_string(record->code)) != 0 ||
        json_object_set_new(body, "message", json_string(record->message)) !=
            0 ||
        json_object_set(body, "details", details) != 0) {
        json_decref(details);
        json_decref(body);
        return NULL;
    }
    json_decref(details);
    return body;
}

/** @brief Parse stable operational-event pagination and exact filters. */
static int parse_event_query(const char *query,
                             struct jg_event_filter *filter,
                             char component[JG_EVENT_COMPONENT_MAX + 1U],
                             size_t *limit)
{
    const char *cursor = query;
    bool have_after_id = false;
    bool have_limit = false;
    bool have_severity = false;
    bool have_component = false;
    int result = 0;

    *filter = (struct jg_event_filter){
        .severity = JG_EVENT_SEVERITY_ANY,
    };
    component[0U] = '\0';
    *limit = JG_EVENT_PAGE_MAX < 50U ? JG_EVENT_PAGE_MAX : 50U;
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
        } else if (name_size == sizeof("after_id") - 1U &&
                   memcmp(cursor, "after_id", name_size) == 0 &&
                   !have_after_id) {
            result = parse_decimal(value, value_size, (uint64_t)INT64_MAX,
                                   &filter->after_id);
            have_after_id = result == 0;
        } else if (name_size == sizeof("limit") - 1U &&
                   memcmp(cursor, "limit", name_size) == 0 && !have_limit) {
            result =
                parse_decimal(value, value_size, JG_EVENT_PAGE_MAX, &parsed);
            if (result == 0 && parsed > 0U) {
                *limit = (size_t)parsed;
                have_limit = true;
            } else {
                result = -EINVAL;
            }
        } else if (name_size == sizeof("severity") - 1U &&
                   memcmp(cursor, "severity", name_size) == 0 &&
                   !have_severity &&
                   parse_event_severity(value, value_size, &filter->severity)) {
            have_severity = true;
        } else if (name_size == sizeof("component") - 1U &&
                   memcmp(cursor, "component", name_size) == 0 &&
                   !have_component &&
                   event_identifier_valid(value, value_size)) {
            (void)memcpy(component, value, value_size);
            component[value_size] = '\0';
            filter->component = component;
            have_component = true;
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

/** @brief Append one authenticated configuration reload outcome. */
static int append_configuration_audit(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    int operation_result,
    uint64_t previous_generation,
    const struct jg_daemon_configuration_status *status,
    uint64_t now)
{
    char source_address[INET6_ADDRSTRLEN];
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int result = 0;

    if (details == NULL ||
        inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source_address,
                  sizeof(source_address)) == NULL) {
        result = details == NULL ? -ENOMEM : -EINVAL;
    }
    if (result == 0 &&
        (json_object_set_new(details, "operation_result",
                             json_integer(operation_result)) != 0 ||
         json_object_set_new(details, "restart_required",
                             json_boolean(operation_result == 0 &&
                                          status->restart_required)) != 0)) {
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
            .action = "configuration.reload",
            .object_type = "runtime_configuration",
            .object_id = "active",
            .details = encoded,
            .has_previous_revision = true,
            .previous_revision = previous_generation,
            .has_new_revision = operation_result == 0,
            .new_revision =
                operation_result == 0 ? status->policy_generation : 0U,
            .success = operation_result == 0,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one successful diagnostic archive creation event. */
static int append_diagnostic_audit(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   const struct authenticated_actor *actor,
                                   const char *filename,
                                   const char *checksum,
                                   size_t archive_size,
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
         json_object_set_new(details, "checksum_sha256",
                             json_string(checksum)) != 0 ||
         json_object_set_new(details, "size_bytes",
                             json_integer((json_int_t)archive_size)) != 0)) {
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
            .action = "diagnostics.create",
            .object_type = "diagnostic_archive",
            .object_id = filename,
            .details = encoded,
            .success = true,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one accepted appliance lifecycle action. */
static int append_system_audit(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               const struct authenticated_actor *actor,
                               const char *action,
                               uint64_t now)
{
    char source[INET6_ADDRSTRLEN];
    const struct jg_audit_event event = {
        .occurred_at = now,
        .actor_type = actor_audit_type(actor),
        .has_actor_id = actor_has_identifier(actor),
        .actor_id = actor->actor_id,
        .source = source,
        .action = action,
        .object_type = "appliance",
        .object_id = NULL,
        .details = "{\"confirmed\":true}",
        .success = true,
        .request_id = request->request_id,
    };

    if (inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source, sizeof(source)) == NULL) {
        return -EINVAL;
    }
    return jg_database_audit_append(management->database, &event, NULL);
}

/** @brief Attach one borrowed child object and preserve caller ownership. */
static int set_object(json_t *parent, const char *name, json_t *child)
{
    return json_object_set(parent, name, child) == 0 ? 0 : -ENOMEM;
}

/** @brief Serialize every current packet-runtime counter for the status API. */
static json_t *status_body(const struct jg_daemon_runtime_stats *stats)
{
    json_t *body = json_object();
    json_t *queues = json_object();
    json_t *dataplane = json_object();
    json_t *fragments = json_object();
    json_t *streams = json_object();
    json_t *output = json_object();
    int result = 0;

    if (body == NULL || queues == NULL || dataplane == NULL ||
        fragments == NULL || streams == NULL || output == NULL) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (json_object_set_new(body, "ready", json_true()) != 0 ||
         set_counter(body, "policy_generation", stats->policy_generation) !=
             0 ||
         set_counter(queues, "packets", stats->queues.packets) != 0 ||
         set_counter(queues, "accepted", stats->queues.accepted) != 0 ||
         set_counter(queues, "dropped", stats->queues.dropped) != 0 ||
         set_counter(queues, "malformed", stats->queues.malformed) != 0 ||
         set_counter(queues, "overflows", stats->queues.overflows) != 0 ||
         set_counter(queues, "message_errors", stats->queues.message_errors) !=
             0 ||
         set_counter(queues, "verdict_errors", stats->queues.verdict_errors) !=
             0)) {
        result = -EOVERFLOW;
    }
    if (result == 0 &&
        (set_counter(dataplane, "packets", stats->dataplane.packets) != 0 ||
         set_counter(dataplane, "accepted", stats->dataplane.accepted) != 0 ||
         set_counter(dataplane, "blocked", stats->dataplane.blocked) != 0 ||
         set_counter(dataplane, "malformed", stats->dataplane.malformed) != 0 ||
         set_counter(dataplane, "fragments", stats->dataplane.fragments) != 0 ||
         set_counter(dataplane, "streams", stats->dataplane.streams) != 0 ||
         set_counter(dataplane, "tcp_resets", stats->dataplane.tcp_resets) !=
             0 ||
         set_counter(dataplane, "internal_errors",
                     stats->dataplane.internal_errors) != 0 ||
         set_counter(dataplane, "sni_inspected",
                     stats->dataplane.sni_inspected) != 0 ||
         set_counter(dataplane, "sni_encrypted_or_unavailable",
                     stats->dataplane.sni_encrypted_or_unavailable) != 0 ||
         set_counter(dataplane, "dns_dropped", stats->dataplane.dns_dropped) !=
             0 ||
         set_counter(dataplane, "dns_refused", stats->dataplane.dns_refused) !=
             0 ||
         set_counter(dataplane, "dns_nxdomain",
                     stats->dataplane.dns_nxdomain) != 0 ||
         set_counter(dataplane, "dns_sinkholed",
                     stats->dataplane.dns_sinkholed) != 0)) {
        result = -EOVERFLOW;
    }
    if (result == 0 &&
        (set_counter(fragments, "stored", stats->fragments.stored) != 0 ||
         set_counter(fragments, "duplicates", stats->fragments.duplicates) !=
             0 ||
         set_counter(fragments, "completed", stats->fragments.completed) != 0 ||
         set_counter(fragments, "malformed", stats->fragments.malformed) != 0 ||
         set_counter(fragments, "overlaps", stats->fragments.overlaps) != 0 ||
         set_counter(fragments, "exhausted", stats->fragments.exhausted) != 0 ||
         set_counter(fragments, "timeouts", stats->fragments.timeouts) != 0 ||
         set_counter(streams, "buffered", stats->tcp_streams.buffered) != 0 ||
         set_counter(streams, "duplicates", stats->tcp_streams.duplicates) !=
             0 ||
         set_counter(streams, "messages", stats->tcp_streams.messages) != 0 ||
         set_counter(streams, "closed", stats->tcp_streams.closed) != 0 ||
         set_counter(streams, "malformed", stats->tcp_streams.malformed) != 0 ||
         set_counter(streams, "conflicts", stats->tcp_streams.conflicts) != 0 ||
         set_counter(streams, "exhausted", stats->tcp_streams.exhausted) != 0 ||
         set_counter(streams, "timeouts", stats->tcp_streams.timeouts) != 0 ||
         set_counter(output, "sent", stats->output.sent) != 0 ||
         set_counter(output, "errors", stats->output.errors) != 0)) {
        result = -EOVERFLOW;
    }
    if (result == 0 && (set_object(body, "queues", queues) != 0 ||
                        set_object(body, "dataplane", dataplane) != 0 ||
                        set_object(body, "fragments", fragments) != 0 ||
                        set_object(body, "tcp_streams", streams) != 0 ||
                        set_object(body, "output", output) != 0)) {
        result = -ENOMEM;
    }
    json_decref(output);
    json_decref(streams);
    json_decref(fragments);
    json_decref(dataplane);
    json_decref(queues);
    if (result != 0) {
        json_decref(body);
        body = NULL;
    }
    return body;
}

/** @brief Return authenticated daemon readiness and packet counters. */
int handle_status(struct jg_management *management,
                  const struct management_request *request,
                  const struct remote_address *remote,
                  uint64_t now,
                  uint8_t *output,
                  size_t output_size,
                  size_t *written)
{
    struct authenticated_actor actor;
    struct jg_daemon_runtime_stats stats;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_STATUS_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The status request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL ||
        jg_daemon_runtime_get_stats(management->runtime, &stats) != 0) {
        return respond_error(503, "status_unavailable",
                             "Runtime status is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    body = status_body(&stats);
    if (body == NULL) {
        return -ENOMEM;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Encode the persistent policy-publication relationship. */
static json_t *policy_sync_health_json(
    const struct jg_database_policy_sync *sync,
    bool available)
{
    json_t *body = json_object();
    int result = 0;

    if (body == NULL) {
        return NULL;
    }
    if (json_object_set_new(body, "available", json_boolean(available)) != 0 ||
        json_object_set_new(
            body, "synchronized",
            json_boolean(available && sync->desired_revision ==
                                          sync->applied_revision)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && available) {
        if (set_counter(body, "desired_revision", sync->desired_revision) !=
                0 ||
            set_counter(body, "applied_revision", sync->applied_revision) !=
                0 ||
            json_object_set_new(
                body, "last_attempt_at",
                sync->last_attempt_at == 0U
                    ? json_null()
                    : json_integer((json_int_t)sync->last_attempt_at)) != 0 ||
            json_object_set_new(body, "last_error",
                                sync->last_error[0U] == '\0'
                                    ? json_null()
                                    : json_string(sync->last_error)) != 0) {
            result = -ENOMEM;
        }
    } else if (result == 0 &&
               (json_object_set_new(body, "desired_revision", json_null()) !=
                    0 ||
                json_object_set_new(body, "applied_revision", json_null()) !=
                    0 ||
                json_object_set_new(body, "last_attempt_at", json_null()) !=
                    0 ||
                json_object_set_new(body, "last_error", json_null()) != 0)) {
        result = -ENOMEM;
    }
    if (result != 0) {
        json_decref(body);
        body = NULL;
    }
    return body;
}

/** @brief Encode management consistency and mutation availability. */
static json_t *management_health_json(
    uint32_t reasons,
    const struct jg_database_policy_sync *sync,
    bool policy_available,
    bool restore_in_progress)
{
    json_t *body = json_object();
    json_t *items = json_array();
    json_t *policy = policy_sync_health_json(sync, policy_available);
    int result = 0;

    if (body == NULL || items == NULL || policy == NULL) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (reasons & MANAGEMENT_DEGRADED_DATABASE_ROLLBACK) != 0U &&
        json_array_append_new(items, json_string("database_rollback")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (reasons & MANAGEMENT_DEGRADED_EXTERNAL_RECOVERY) != 0U &&
        json_array_append_new(items, json_string("external_recovery")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && (reasons & MANAGEMENT_DEGRADED_POLICY_SYNC) != 0U &&
        json_array_append_new(items, json_string("policy_sync")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (json_object_set_new(body, "available", json_true()) != 0 ||
         json_object_set_new(body, "degraded", json_boolean(reasons != 0U)) !=
             0 ||
         json_object_set_new(
             body, "mutations_allowed",
             json_boolean(reasons == 0U && !restore_in_progress)) != 0 ||
         json_object_set_new(body, "restore_in_progress",
                             json_boolean(restore_in_progress)) != 0 ||
         json_object_set(body, "reasons", items) != 0 ||
         set_object(body, "policy", policy) != 0)) {
        result = -ENOMEM;
    }
    json_decref(policy);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        body = NULL;
    }
    return body;
}

/** @brief Return authenticated management, daemon, and helper health. */
int handle_health(struct jg_management *management,
                  const struct management_request *request,
                  const struct remote_address *remote,
                  uint64_t now,
                  uint8_t *output,
                  size_t output_size,
                  size_t *written)
{
    struct authenticated_actor actor;
    struct jg_daemon_runtime_stats stats;
    struct jg_database_policy_sync policy_sync = {0};
    struct jg_network_state network_state;
    json_t *body = NULL;
    json_t *management_state = NULL;
    json_t *daemon = NULL;
    json_t *network = NULL;
    uint32_t degraded_reasons = 0U;
    bool daemon_available = false;
    bool network_available = false;
    bool policy_available = false;
    bool restore_in_progress = false;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_STATUS_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The health request is not valid.",
                             request->request_id, output, output_size, written);
    }
    daemon_available =
        management->runtime != NULL &&
        jg_daemon_runtime_get_stats(management->runtime, &stats) == 0;
    network_available = jg_netd_client_state(&network_state) == 0;
    policy_available =
        jg_database_policy_sync_load(management->database, &policy_sync) == 0;
    if (!policy_available ||
        policy_sync.desired_revision != policy_sync.applied_revision) {
        mark_management_degraded(
            management, MANAGEMENT_DEGRADED_POLICY_SYNC,
            "management.policy_unsynchronized",
            "Persistent policy is not synchronized with the runtime");
    }
    degraded_reasons = management_degraded_reasons(management);
    restore_in_progress = management_restore_in_progress(management);
    body = json_object();
    management_state = management_health_json(
        degraded_reasons, &policy_sync, policy_available, restore_in_progress);
    daemon = json_object();
    network = json_object();
    if (body == NULL || management_state == NULL || daemon == NULL ||
        network == NULL ||
        json_object_set_new(body, "healthy",
                            json_boolean(degraded_reasons == 0U &&
                                         daemon_available &&
                                         network_available)) != 0 ||
        json_object_set_new(daemon, "available",
                            json_boolean(daemon_available)) != 0 ||
        json_object_set_new(network, "available",
                            json_boolean(network_available)) != 0 ||
        (daemon_available && set_counter(daemon, "policy_generation",
                                         stats.policy_generation) != 0) ||
        (network_available &&
         (json_object_set_new(network, "configured",
                              json_boolean(network_state.has_confirmed)) != 0 ||
          json_object_set_new(network, "pending",
                              json_boolean(network_state.pending)) != 0)) ||
        set_object(body, "management", management_state) != 0 ||
        set_object(body, "daemon", daemon) != 0 ||
        set_object(body, "network", network) != 0) {
        result = -ENOMEM;
    }
    json_decref(network);
    json_decref(daemon);
    json_decref(management_state);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Copy one consistent-enough lock-free management metrics snapshot. */
static void collect_management_metrics(const struct jg_management *management,
                                       struct jg_management_metrics *metrics)
{
    *metrics = (struct jg_management_metrics){0};
    metrics->authentication_failures_total =
        atomic_load_explicit(&management->health->authentication_failures_total,
                             memory_order_acquire);
    for (size_t index = 0U; index < JG_ALERT_TYPE_COUNT; ++index) {
        metrics->alert_open_by_type[index] =
            atomic_load_explicit(&management->health->alert_open_by_type[index],
                                 memory_order_acquire);
    }
    metrics->alert_incidents_retained = atomic_load_explicit(
        &management->health->alert_incidents_retained, memory_order_acquire);
    metrics->alert_resolutions_retained = atomic_load_explicit(
        &management->health->alert_resolutions_retained, memory_order_acquire);
    metrics->alert_deliveries_pending = atomic_load_explicit(
        &management->health->alert_deliveries_pending, memory_order_acquire);
    metrics->alert_deliveries_succeeded = atomic_load_explicit(
        &management->health->alert_deliveries_succeeded, memory_order_acquire);
    metrics->alert_deliveries_failed = atomic_load_explicit(
        &management->health->alert_deliveries_failed, memory_order_acquire);
    metrics->alert_last_evaluation_at = atomic_load_explicit(
        &management->health->alert_last_evaluation_at, memory_order_acquire);
    metrics->alert_last_delivery_at = atomic_load_explicit(
        &management->health->alert_last_delivery_at, memory_order_acquire);
    metrics->certificate_expiry_timestamp =
        atomic_load_explicit(&management->health->certificate_expiry_timestamp,
                             memory_order_acquire);
    metrics->blocklist_sources_unhealthy = atomic_load_explicit(
        &management->health->blocklist_sources_unhealthy, memory_order_acquire);
    metrics->blocklist_sources_stale = atomic_load_explicit(
        &management->health->blocklist_sources_stale, memory_order_acquire);
    metrics->filesystem_minimum_available_bytes = atomic_load_explicit(
        &management->health->filesystem_minimum_available_bytes,
        memory_order_acquire);
    metrics->filesystem_minimum_available_basis_points = atomic_load_explicit(
        &management->health->filesystem_minimum_available_basis_points,
        memory_order_acquire);
    metrics->alert_evaluation_successful =
        atomic_load_explicit(&management->health->alert_evaluation_successful,
                             memory_order_acquire)
            ? 1U
            : 0U;
    metrics->alert_delivery_successful =
        atomic_load_explicit(&management->health->alert_delivery_successful,
                             memory_order_acquire)
            ? 1U
            : 0U;
    metrics->audit_valid =
        atomic_load_explicit(&management->health->audit_valid,
                             memory_order_acquire)
            ? 1U
            : 0U;
    metrics->policy_synchronized =
        atomic_load_explicit(&management->health->policy_synchronized,
                             memory_order_acquire)
            ? 1U
            : 0U;
    metrics->management_degraded =
        management_degraded_reasons(management) != 0U ? 1U : 0U;
}

/** @brief Return authenticated Prometheus text for the current runtime. */
int handle_metrics(struct jg_management *management,
                   const struct management_request *request,
                   const struct remote_address *remote,
                   uint64_t now,
                   uint8_t *output,
                   size_t output_size,
                   size_t *written)
{
    static const char content_type[] =
        "text/plain; version=0.0.4; charset=utf-8";
    struct authenticated_actor actor;
    struct jg_daemon_runtime_stats stats;
    struct jg_management_metrics management_metrics;
    char placeholder = '\0';
    char *metrics = NULL;
    size_t metrics_size = 0U;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_METRICS_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The metrics request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL ||
        jg_daemon_runtime_get_stats(management->runtime, &stats) != 0) {
        return respond_error(503, "metrics_unavailable",
                             "Runtime metrics are temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    collect_management_metrics(management, &management_metrics);
    result = jg_metrics_render(&stats, &management_metrics, &placeholder, 0U,
                               &metrics_size);
    if (result != -ENOSPC || metrics_size == 0U ||
        metrics_size >= JG_IPC_MAX_BODY_SIZE / 2U) {
        return respond_error(500, "metrics_failure",
                             "Runtime metrics could not be rendered.",
                             request->request_id, output, output_size, written);
    }
    metrics = malloc(metrics_size + 1U);
    if (metrics == NULL) {
        return -ENOMEM;
    }
    result = jg_metrics_render(&stats, &management_metrics, metrics,
                               metrics_size + 1U, &metrics_size);
    if (result == 0) {
        result = encode_text_response(200, content_type, metrics, metrics_size,
                                      output, output_size, written);
    }
    free(metrics);
    return result;
}

/** @brief Validate or atomically reload persistent runtime configuration. */
int handle_configuration(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         bool reload,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    struct authenticated_actor actor;
    struct jg_daemon_configuration_status status;
    json_t *body = NULL;
    uint64_t previous_generation = 0U;
    int audit_result = 0;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_OPERATE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The configuration request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "runtime_unavailable",
                             "Runtime configuration is unavailable while the "
                             "service is offline.",
                             request->request_id, output, output_size, written);
    }
    if (reload) {
        result = jg_daemon_runtime_get_policy_generation(management->runtime,
                                                         &previous_generation);
        if (result == 0) {
            result = jg_daemon_runtime_reload_configuration(management->runtime,
                                                            &status);
        }
        audit_result = append_configuration_audit(
            management, request, remote, &actor, result, previous_generation,
            &status, now);
        refresh_policy_sync_health(management);
        if (audit_result != 0) {
            return respond_error(
                500, "audit_failure",
                "The configuration reload could not be audited.",
                request->request_id, output, output_size, written);
        }
    } else {
        result = jg_daemon_runtime_validate_configuration(management->runtime,
                                                          &status);
    }
    if (result != 0) {
        if (result == -EOVERFLOW || result == -EBUSY) {
            return respond_error(
                409, "configuration_conflict",
                "The persistent configuration cannot be processed now.",
                request->request_id, output, output_size, written);
        }
        if (result == -EINVAL || result == -ERANGE || result == -EILSEQ ||
            result == -EPROTONOSUPPORT) {
            return respond_error(
                422, "configuration_invalid",
                "The persistent configuration did not pass validation.",
                request->request_id, output, output_size, written);
        }
        return respond_error(
            503, "configuration_unavailable",
            "The persistent configuration could not be validated.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "validated", json_true()) != 0 ||
        json_object_set_new(body, "reloaded", json_boolean(reload)) != 0 ||
        json_object_set_new(
            body, "network_revision",
            json_integer((json_int_t)status.network_revision)) != 0 ||
        json_object_set_new(
            body, "policy_generation",
            json_integer((json_int_t)status.policy_generation)) != 0 ||
        json_object_set_new(
            body, "domain_rule_count",
            json_integer((json_int_t)status.domain_rule_count)) != 0 ||
        json_object_set_new(
            body, "destination_rule_count",
            json_integer((json_int_t)status.destination_rule_count)) != 0 ||
        json_object_set_new(body, "restart_required",
                            json_boolean(status.restart_required)) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Authorize, audit, and defer one appliance lifecycle action. */
int handle_system_action(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         enum jg_system_action action,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    static const char *const fields[] = {
        "confirm",
    };
    struct authenticated_actor actor;
    const char *action_name = NULL;
    json_t *body = NULL;
    bool confirmed = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_SYSTEM_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        json_object_size(request->body) != 1U ||
        !required_boolean(request->body, "confirm", &confirmed) || !confirmed ||
        action < JG_SYSTEM_ACTION_RESTART ||
        action > JG_SYSTEM_ACTION_POWEROFF) {
        return respond_error(
            400, "confirmation_required",
            "The lifecycle action requires an exact explicit confirmation.",
            request->request_id, output, output_size, written);
    }
    if (management->pending_system_action != JG_SYSTEM_ACTION_NONE) {
        return respond_error(409, "system_action_pending",
                             "Another lifecycle action is already pending.",
                             request->request_id, output, output_size, written);
    }
    action_name = action == JG_SYSTEM_ACTION_RESTART
                      ? "service.restart"
                      : (action == JG_SYSTEM_ACTION_REBOOT ? "system.reboot"
                                                           : "system.shutdown");
    result = append_system_audit(management, request, remote, &actor,
                                 action_name, now);
    if (result != 0) {
        return respond_error(500, "audit_failure",
                             "The lifecycle action could not be audited.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "accepted", json_true()) != 0 ||
        json_object_set_new(body, "action", json_string(action_name)) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    result = encode_response(202, body, NULL, output, output_size, written);
    if (result == 0) {
        management->pending_system_action = action;
    }
    return result;
}

/** @brief Format one UTC diagnostic archive filename. */
static int diagnostic_filename(
    uint64_t now,
    char filename[MANAGEMENT_DIAGNOSTIC_FILENAME_SIZE])
{
    time_t timestamp = 0;
    struct tm utc;

    if (now > (uint64_t)INT64_MAX) {
        return -EOVERFLOW;
    }
    timestamp = (time_t)now;
    if ((uint64_t)timestamp != now || gmtime_r(&timestamp, &utc) == NULL ||
        strftime(filename, MANAGEMENT_DIAGNOSTIC_FILENAME_SIZE,
                 "janusgate-diagnostics-%Y%m%dT%H%M%SZ.tar.gz", &utc) == 0U) {
        return -EOVERFLOW;
    }
    return 0;
}

/** @brief Create and return one authenticated diagnostic archive job. */
int execute_diagnostics_create_job(struct jg_management *management,
                                   const struct management_job *job,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written)
{
    const struct management_request request_value = {
        .request_id = job->request_id,
    };
    const struct management_request *request = &request_value;
    const struct remote_address *remote = &job->remote;
    const struct authenticated_actor *actor = &job->actor;
    uint8_t checksum[crypto_hash_sha256_BYTES];
    char checksum_text[crypto_hash_sha256_BYTES * 2U + 1U];
    char filename[MANAGEMENT_DIAGNOSTIC_FILENAME_SIZE];
    uint8_t *archive = NULL;
    char *encoded = NULL;
    json_t *body = NULL;
    size_t archive_size = 0U;
    size_t encoded_size = 0U;
    const uint64_t now = job->started_at;
    int result = 0;

    if (management->runtime == NULL) {
        return respond_error(
            503, "runtime_unavailable",
            "Diagnostics are unavailable while the service is offline.",
            request->request_id, output, output_size, written);
    }
    result =
        jg_diagnostic_bundle_create(management->database, management->runtime,
                                    now, &archive, &archive_size);
    if (result != 0) {
        return respond_error(
            result == -EMSGSIZE ? 413 : 500,
            result == -EMSGSIZE ? "diagnostic_too_large"
                                : "diagnostic_create_failed",
            result == -EMSGSIZE
                ? "The diagnostic archive exceeds its configured limit."
                : "The diagnostic archive could not be created.",
            request->request_id, output, output_size, written);
    }
    if (archive_size > MANAGEMENT_DIAGNOSTIC_ARCHIVE_SIZE_MAX) {
        jg_diagnostic_archive_destroy(archive);
        return respond_error(
            413, "diagnostic_too_large",
            "The diagnostic archive exceeds its management transfer limit.",
            request->request_id, output, output_size, written);
    }
    encoded_size =
        sodium_base64_encoded_len(archive_size, sodium_base64_VARIANT_ORIGINAL);
    if (diagnostic_filename(now, filename) != 0 || encoded_size == 0U ||
        encoded_size > JG_IPC_MAX_BODY_SIZE) {
        jg_diagnostic_archive_destroy(archive);
        return respond_error(500, "diagnostic_create_failed",
                             "The diagnostic archive could not be encoded.",
                             request->request_id, output, output_size, written);
    }
    encoded = malloc(encoded_size);
    if (encoded == NULL) {
        jg_diagnostic_archive_destroy(archive);
        return -ENOMEM;
    }
    (void)crypto_hash_sha256(checksum, archive, archive_size);
    (void)sodium_bin2hex(checksum_text, sizeof(checksum_text), checksum,
                         sizeof(checksum));
    if (sodium_bin2base64(encoded, encoded_size, archive, archive_size,
                          sodium_base64_VARIANT_ORIGINAL) == NULL) {
        sodium_memzero(checksum, sizeof(checksum));
        jg_diagnostic_archive_destroy(archive);
        free(encoded);
        return respond_error(500, "diagnostic_create_failed",
                             "The diagnostic archive could not be encoded.",
                             request->request_id, output, output_size, written);
    }
    result =
        append_diagnostic_audit(management, request, remote, actor, filename,
                                checksum_text, archive_size, now);
    if (result != 0) {
        sodium_memzero(checksum, sizeof(checksum));
        jg_diagnostic_archive_destroy(archive);
        free(encoded);
        return respond_error(500, "audit_failure",
                             "The diagnostic archive could not be audited.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "filename", json_string(filename)) != 0 ||
        json_object_set_new(body, "media_type",
                            json_string("application/gzip")) != 0 ||
        json_object_set_new(body, "size_bytes",
                            json_integer((json_int_t)archive_size)) != 0 ||
        json_object_set_new(body, "checksum_sha256",
                            json_string(checksum_text)) != 0 ||
        json_object_set_new(body, "data_base64", json_string(encoded)) != 0) {
        result = -ENOMEM;
    }
    sodium_memzero(checksum, sizeof(checksum));
    jg_diagnostic_archive_destroy(archive);
    free(encoded);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(201, body, NULL, output, output_size, written);
}

/** @brief Queue one authenticated diagnostic archive creation. */
int handle_diagnostics_create(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    struct authenticated_actor actor;
    struct management_job_submission prepared = {
        .required_permission = JG_ACCESS_OPERATE,
        .kind = MANAGEMENT_JOB_DIAGNOSTICS_CREATE,
    };
    uint64_t job_id = 0U;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_OPERATE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The diagnostic request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(
            503, "runtime_unavailable",
            "Diagnostics are unavailable while the service is offline.",
            request->request_id, output, output_size, written);
    }
    result = submit_management_job(management, request, remote, &actor,
                                   &prepared, now, &job_id);
    if (result != 0) {
        return respond_job_submission_error(
            result, request, "The diagnostic archive could not be queued.",
            output, output_size, written);
    }
    return respond_job_accepted(job_id, output, output_size, written);
}

/** @brief Return one authenticated filtered page of operational events. */
int handle_events_list(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written)
{
    struct authenticated_actor actor;
    struct jg_event_filter filter;
    struct jg_event_record *records = NULL;
    char component[JG_EVENT_COMPONENT_MAX + 1U];
    json_t *body = NULL;
    json_t *items = NULL;
    size_t limit = 0U;
    size_t count = 0U;
    bool has_more = false;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_EVENTS_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_event_query(request->query, &filter, component, &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The event filters or pagination are not valid.",
                             request->request_id, output, output_size, written);
    }
    records = calloc(limit, sizeof(*records));
    if (records == NULL) {
        return -ENOMEM;
    }
    result = jg_database_event_list(management->database, &filter, records,
                                    limit, &count, &has_more);
    if (result != 0) {
        free(records);
        return respond_error(500, "events_unavailable",
                             "The operational events could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = event_json(&records[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "after_id",
                             json_integer((json_int_t)filter.after_id)) != 0 ||
         json_object_set_new(body, "limit", json_integer((json_int_t)limit)) !=
             0 ||
         json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "has_more", json_boolean(has_more)) != 0 ||
         json_object_set_new(
             body, "severity",
             filter.severity == JG_EVENT_SEVERITY_ANY
                 ? json_null()
                 : json_string(event_severity_name(filter.severity))) != 0 ||
         json_object_set_new(body, "component",
                             filter.component == NULL
                                 ? json_null()
                                 : json_string(filter.component)) != 0 ||
         json_object_set(body, "events", items) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        json_t *next = has_more && count > 0U
                           ? json_integer((json_int_t)records[count - 1U].id)
                           : json_null();

        if (json_object_set_new(body, "next_after_id", next) != 0) {
            result = -ENOMEM;
        }
    }
    free(records);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Return one authenticated page of immutable audit records. */
int handle_audit_list(struct jg_management *management,
                      const struct management_request *request,
                      const struct remote_address *remote,
                      uint64_t now,
                      uint8_t *output,
                      size_t output_size,
                      size_t *written)
{
    struct authenticated_actor actor;
    struct jg_audit_record *records = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    uint64_t offset = 0U;
    uint64_t total = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_AUDIT_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_page_query(request->query, "offset", JG_AUDIT_PAGE_MAX, &offset,
                         &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The audit pagination parameters are not valid.",
                             request->request_id, output, output_size, written);
    }
    records = calloc(limit, sizeof(*records));
    if (records == NULL) {
        return -ENOMEM;
    }
    result = jg_database_audit_list(management->database, offset, records,
                                    limit, &count, &total);
    if (result != 0) {
        free(records);
        return respond_error(500, "audit_unavailable",
                             "The audit records could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = audit_json(&records[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "offset",
                             json_integer((json_int_t)offset)) != 0 ||
         json_object_set_new(body, "limit", json_integer((json_int_t)limit)) !=
             0 ||
         json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "total", json_integer((json_int_t)total)) !=
             0 ||
         json_object_set(body, "events", items) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        const uint64_t next = offset + (uint64_t)count;
        json_t *next_value = count > 0U && next < total
                                 ? json_integer((json_int_t)next)
                                 : json_null();

        if (json_object_set_new(body, "next_offset", next_value) != 0) {
            result = -ENOMEM;
        }
    }
    free(records);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Verify and report the complete authenticated audit chain. */
int handle_audit_verify(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written)
{
    struct authenticated_actor actor;
    struct jg_audit_verification verification;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_AUDIT_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The audit verification request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_database_audit_verify(management->database, &verification);
    if (result != 0) {
        return respond_error(500, "audit_verification_failed",
                             "The audit chain could not be verified.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "valid", json_boolean(verification.valid)) !=
            0 ||
        json_object_set_new(
            body, "records_inspected",
            json_integer((json_int_t)verification.records_inspected)) != 0 ||
        json_object_set_new(
            body, "first_invalid_id",
            verification.first_invalid_id == 0U
                ? json_null()
                : json_integer((json_int_t)verification.first_invalid_id)) !=
            0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}
