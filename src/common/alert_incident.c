/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/alert.h"

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
#include <sqlite3.h>

#include "database_internal.h"
#include "janusgate/checked.h"

/** Largest persistent signed integer. */
#define ALERT_VALUE_MAX UINT64_C(9223372036854775807)

/** Largest complete internal alert key including its terminator. */
#define ALERT_KEY_SIZE 161U

/** Maximum webhook attempts before permanent abandonment. */
#define ALERT_DELIVERY_ATTEMPTS_MAX 10U

/** Seconds after which an interrupted delivery claim may be recovered. */
#define ALERT_DELIVERY_CLAIM_TIMEOUT 120U

/** @brief Encode fixed bytes as lowercase hexadecimal text. */
static void encode_hex(const uint8_t *bytes, size_t size, char *text)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t index = 0U; index < size; ++index) {
        text[index * 2U] = digits[bytes[index] >> 4U];
        text[index * 2U + 1U] = digits[bytes[index] & UINT8_C(0x0f)];
    }
    text[size * 2U] = '\0';
}

/** @brief Return one bounded string length or one past the limit. */
static size_t bounded_length(const char *text, size_t maximum)
{
    size_t length = 0U;

    if (text == NULL) {
        return maximum + 1U;
    }
    while (length <= maximum && text[length] != '\0') {
        ++length;
    }
    return length;
}

/** @brief Validate one lowercase stable event identifier. */
static bool identifier_valid(const char *text, size_t maximum)
{
    const size_t length = bounded_length(text, maximum);

    if (length == 0U || length > maximum) {
        return false;
    }
    for (size_t index = 0U; index < length; ++index) {
        const char character = text[index];

        if (!((character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') || character == '_' ||
              character == '-' || character == '.')) {
            return false;
        }
    }
    return true;
}

/** @brief Parse one bounded JSON object and return canonical text. */
static int canonical_object(const char *details,
                            size_t maximum,
                            char **canonical,
                            json_t **object)
{
    const size_t details_size = bounded_length(details, maximum);
    json_error_t error;
    json_t *parsed = NULL;

    *canonical = NULL;
    if (object != NULL) {
        *object = NULL;
    }
    if (details_size < 2U || details_size > maximum) {
        return -EINVAL;
    }
    parsed = json_loadb(details, details_size, JSON_REJECT_DUPLICATES, &error);
    if (!json_is_object(parsed)) {
        json_decref(parsed);
        return -EINVAL;
    }
    *canonical = json_dumps(parsed, JSON_COMPACT | JSON_SORT_KEYS);
    if (*canonical == NULL) {
        json_decref(parsed);
        return -ENOMEM;
    }
    if (strlen(*canonical) > maximum) {
        free(*canonical);
        *canonical = NULL;
        json_decref(parsed);
        return -EINVAL;
    }
    if (object != NULL) {
        *object = parsed;
    } else {
        json_decref(parsed);
    }
    return 0;
}

/** @brief Parse one exact persistent alert type. */
static enum jg_alert_type parse_type(const char *text)
{
    for (unsigned int value = 1U; value <= JG_ALERT_TYPE_COUNT; ++value) {
        const enum jg_alert_type type = (enum jg_alert_type)value;
        const char *name = jg_alert_type_name(type);

        if (name != NULL && strcmp(name, text) == 0) {
            return type;
        }
    }
    return JG_ALERT_TYPE_ANY;
}

/** @brief Parse one exact persistent alert severity. */
static enum jg_alert_severity parse_severity(const char *text)
{
    for (unsigned int value = JG_ALERT_SEVERITY_WARNING;
         value <= JG_ALERT_SEVERITY_CRITICAL; ++value) {
        const enum jg_alert_severity severity = (enum jg_alert_severity)value;
        const char *name = jg_alert_severity_name(severity);

        if (name != NULL && strcmp(name, text) == 0) {
            return severity;
        }
    }
    return 0;
}

/** @brief Parse one exact persistent alert state. */
static enum jg_alert_state parse_state(const char *text)
{
    if (strcmp(text, "open") == 0) {
        return JG_ALERT_STATE_OPEN;
    }
    if (strcmp(text, "resolved") == 0) {
        return JG_ALERT_STATE_RESOLVED;
    }
    return JG_ALERT_STATE_ANY;
}

/** @brief Return the stable persistent name for one alert type. */
const char *jg_alert_type_name(enum jg_alert_type type)
{
    static const char *const names[JG_ALERT_TYPE_COUNT] = {
        "appliance_degraded", "policy_unsynchronized",
        "audit_unverifiable", "certificate_expiring",
        "source_unhealthy",   "filesystem_low_space",
        "queue_drops",        "authentication_failures",
    };

    return type >= JG_ALERT_TYPE_APPLIANCE_DEGRADED &&
                   type <= JG_ALERT_TYPE_AUTHENTICATION_FAILURES
               ? names[(size_t)type - 1U]
               : NULL;
}

/** @brief Return the stable persistent name for one alert severity. */
const char *jg_alert_severity_name(enum jg_alert_severity severity)
{
    switch (severity) {
    case JG_ALERT_SEVERITY_WARNING:
        return "warning";
    case JG_ALERT_SEVERITY_ERROR:
        return "error";
    case JG_ALERT_SEVERITY_CRITICAL:
        return "critical";
    default:
        return NULL;
    }
}

/** @brief Return the stable persistent name for one alert state. */
const char *jg_alert_state_name(enum jg_alert_state state)
{
    switch (state) {
    case JG_ALERT_STATE_OPEN:
        return "open";
    case JG_ALERT_STATE_RESOLVED:
        return "resolved";
    case JG_ALERT_STATE_ANY:
    default:
        return NULL;
    }
}

/** @brief Validate condition content and construct its stable key. */
static int validate_condition(const struct jg_alert_condition *condition,
                              char key[ALERT_KEY_SIZE],
                              char **details)
{
    const char *type =
        condition == NULL ? NULL : jg_alert_type_name(condition->type);
    const size_t resource_size =
        condition == NULL
            ? 0U
            : bounded_length(condition->resource, JG_ALERT_RESOURCE_MAX);
    const size_t summary_size =
        condition == NULL
            ? 0U
            : bounded_length(condition->summary, JG_ALERT_SUMMARY_MAX);
    int written = 0;

    if (type == NULL || jg_alert_severity_name(condition->severity) == NULL ||
        resource_size == 0U || resource_size > JG_ALERT_RESOURCE_MAX ||
        summary_size == 0U || summary_size > JG_ALERT_SUMMARY_MAX ||
        !jg_utf8_text_valid((const uint8_t *)condition->resource, resource_size,
                            false) ||
        !jg_utf8_text_valid((const uint8_t *)condition->summary, summary_size,
                            false)) {
        return -EINVAL;
    }
    written = snprintf(key, ALERT_KEY_SIZE, "%s:%s", type, condition->resource);
    if (written <= 0 || (size_t)written >= ALERT_KEY_SIZE) {
        return -EOVERFLOW;
    }
    return canonical_object(condition->details, JG_ALERT_DETAILS_MAX, details,
                            NULL);
}

/** @brief Copy and validate one required persistent text column. */
static int read_text(sqlite3_stmt *statement,
                     int column,
                     char *output,
                     size_t output_size,
                     bool json)
{
    const char *text = (const char *)sqlite3_column_text(statement, column);
    const int bytes = sqlite3_column_bytes(statement, column);
    char *canonical = NULL;
    int result = 0;

    if (sqlite3_column_type(statement, column) != SQLITE_TEXT || text == NULL ||
        bytes <= 0 || (size_t)bytes >= output_size ||
        memchr(text, '\0', (size_t)bytes) != NULL ||
        (!json &&
         !jg_utf8_text_valid((const uint8_t *)text, (size_t)bytes, false))) {
        return -EILSEQ;
    }
    (void)memcpy(output, text, (size_t)bytes);
    output[bytes] = '\0';
    if (json) {
        result = canonical_object(output, output_size - 1U, &canonical, NULL);
        if (result == 0 && strcmp(output, canonical) != 0) {
            result = -EILSEQ;
        } else if (result != 0 && result != -ENOMEM) {
            result = -EILSEQ;
        }
        free(canonical);
    }
    return result;
}

/** @brief Decode and validate one persistent incident row. */
static int decode_incident(sqlite3_stmt *statement,
                           struct jg_alert_incident *incident)
{
    const char *type = (const char *)sqlite3_column_text(statement, 1);
    const char *severity = (const char *)sqlite3_column_text(statement, 3);
    const char *state = (const char *)sqlite3_column_text(statement, 4);
    const int type_size = sqlite3_column_bytes(statement, 1);
    const int severity_size = sqlite3_column_bytes(statement, 3);
    const int state_size = sqlite3_column_bytes(statement, 4);
    uint64_t opened_at = 0U;
    uint64_t updated_at = 0U;
    uint64_t resolved_at = 0U;
    uint64_t occurrences = 0U;
    (void)memset(incident, 0, sizeof(*incident));
    int result = jg_database_column_unsigned(statement, 0, &incident->id);
    if (result == 0 &&
        (type == NULL || severity == NULL || state == NULL ||
         (incident->type = parse_type(type)) == JG_ALERT_TYPE_ANY ||
         (incident->severity = parse_severity(severity)) == 0 ||
         (incident->state = parse_state(state)) == JG_ALERT_STATE_ANY ||
         type_size != (int)strlen(jg_alert_type_name(incident->type)) ||
         severity_size !=
             (int)strlen(jg_alert_severity_name(incident->severity)) ||
         state_size != (int)strlen(jg_alert_state_name(incident->state)))) {
        result = -EILSEQ;
    }
    if (result == 0) {
        result = read_text(statement, 2, incident->resource,
                           sizeof(incident->resource), false);
    }
    if (result == 0) {
        result = read_text(statement, 5, incident->summary,
                           sizeof(incident->summary), false);
    }
    if (result == 0) {
        result = read_text(statement, 6, incident->details,
                           sizeof(incident->details), true);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 7, &opened_at);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 8, &updated_at);
    }
    if (result == 0) {
        result =
            jg_database_column_optional_unsigned(statement, 9, &resolved_at);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 10, &occurrences);
    }
    if (result == 0 &&
        (incident->id == 0U || updated_at < opened_at || occurrences == 0U ||
         (incident->state == JG_ALERT_STATE_OPEN && resolved_at != 0U) ||
         (incident->state == JG_ALERT_STATE_RESOLVED &&
          resolved_at < opened_at))) {
        result = -EILSEQ;
    }
    if (result == 0) {
        incident->opened_at = opened_at;
        incident->updated_at = updated_at;
        incident->resolved_at = resolved_at;
        incident->occurrences = occurrences;
    } else {
        (void)memset(incident, 0, sizeof(*incident));
    }
    return result;
}

/** @brief Load one open incident by stable condition key. */
static int load_open(sqlite3 *handle,
                     const char *key,
                     struct jg_alert_incident *incident)
{
    static const char query[] =
        "SELECT id,type,resource,severity,state,summary,details,opened_at,"
        "updated_at,resolved_at,occurrences FROM alert_incidents "
        "WHERE alert_key=?1 AND state='open';";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, key, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result =
            status == SQLITE_ROW
                ? decode_incident(statement, incident)
                : (status == SQLITE_DONE ? -ENOENT
                                         : jg_database_sqlite_result(status));
    }
    if (result == 0 && sqlite3_step(statement) != SQLITE_DONE) {
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

/** @brief Load one incident by exact identifier. */
static int load_incident(sqlite3 *handle,
                         uint64_t identifier,
                         struct jg_alert_incident *incident)
{
    static const char query[] =
        "SELECT id,type,resource,severity,state,summary,details,opened_at,"
        "updated_at,resolved_at,occurrences FROM alert_incidents WHERE id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)identifier);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result =
            status == SQLITE_ROW
                ? decode_incident(statement, incident)
                : (status == SQLITE_DONE ? -ENOENT
                                         : jg_database_sqlite_result(status));
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Insert one already-canonical outbox payload. */
static int enqueue_payload(sqlite3 *handle,
                           uint64_t incident_id,
                           const char *kind,
                           const char *event_code,
                           const char *transition,
                           const char *payload,
                           uint64_t now,
                           char event_id[JG_ALERT_EVENT_ID_SIZE])
{
    static const char insert[] =
        "INSERT INTO alert_outbox(event_uuid,incident_id,kind,event_code,"
        "transition,payload,status,created_at,next_attempt_at) VALUES("
        "?1,?2,?3,?4,?5,?6,'pending',?7,?7);";
    uint8_t event_uuid[JG_ALERT_DELIVERY_CLAIM_SIZE];
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = sodium_init() < 0 ? -EIO : 0;

    if (event_id != NULL) {
        event_id[0U] = '\0';
    }
    if (result == 0) {
        randombytes_buf(event_uuid, sizeof(event_uuid));
        status = sqlite3_prepare_v3(
            handle, insert, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }

    if (result == 0) {
        status = sqlite3_bind_blob(statement, 1, event_uuid,
                                   (int)sizeof(event_uuid), SQLITE_TRANSIENT);
    }
    if (result == 0 && status == SQLITE_OK) {
        status =
            incident_id == 0U
                ? sqlite3_bind_null(statement, 2)
                : sqlite3_bind_int64(statement, 2, (sqlite3_int64)incident_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_text(statement, 3, kind, -1, SQLITE_STATIC);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_text(statement, 4, event_code, -1,
                                       SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_text(statement, 5, transition, -1, SQLITE_STATIC);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_text(statement, 6, payload, -1, SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 7, (sqlite3_int64)now);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && event_id != NULL) {
        encode_hex(event_uuid, sizeof(event_uuid), event_id);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    sodium_memzero(event_uuid, sizeof(event_uuid));
    return result;
}

/** @brief Build and enqueue one incident transition payload. */
static int enqueue_incident(sqlite3 *handle,
                            const struct jg_alert_incident *incident,
                            enum jg_alert_transition transition,
                            uint64_t now)
{
    const char *transition_name =
        transition == JG_ALERT_TRANSITION_OPEN ? "open" : "resolved";
    const char *event_code = transition == JG_ALERT_TRANSITION_OPEN
                                 ? "alert.opened"
                                 : "alert.resolved";
    json_error_t error;
    json_t *details =
        json_loads(incident->details, JSON_REJECT_DUPLICATES, &error);
    json_t *alert = json_object();
    json_t *root = json_object();
    char *payload = NULL;
    int result = details == NULL || alert == NULL || root == NULL ? -ENOMEM : 0;

    if (result == 0 &&
        (json_object_set_new(alert, "id",
                             json_integer((json_int_t)incident->id)) != 0 ||
         json_object_set_new(alert, "type",
                             json_string(jg_alert_type_name(incident->type))) !=
             0 ||
         json_object_set_new(alert, "resource",
                             json_string(incident->resource)) != 0 ||
         json_object_set_new(
             alert, "severity",
             json_string(jg_alert_severity_name(incident->severity))) != 0 ||
         json_object_set_new(
             alert, "state",
             json_string(jg_alert_state_name(incident->state))) != 0 ||
         json_object_set_new(alert, "summary",
                             json_string(incident->summary)) != 0 ||
         json_object_set(alert, "details", details) != 0 ||
         json_object_set_new(alert, "opened_at",
                             json_integer((json_int_t)incident->opened_at)) !=
             0 ||
         json_object_set_new(
             alert, "resolved_at",
             incident->resolved_at == 0U
                 ? json_null()
                 : json_integer((json_int_t)incident->resolved_at)) != 0 ||
         json_object_set_new(alert, "occurrences",
                             json_integer((json_int_t)incident->occurrences)) !=
             0 ||
         json_object_set_new(root, "schema_version", json_integer(1)) != 0 ||
         json_object_set_new(root, "event", json_string(event_code)) != 0 ||
         json_object_set_new(root, "transition",
                             json_string(transition_name)) != 0 ||
         json_object_set(root, "alert", alert) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        payload = json_dumps(root, JSON_COMPACT | JSON_SORT_KEYS);
        if (payload == NULL) {
            result = -ENOMEM;
        } else if (strlen(payload) > JG_ALERT_PAYLOAD_MAX) {
            result = -EOVERFLOW;
        }
    }
    if (result == 0) {
        result = enqueue_payload(handle, incident->id, "incident", event_code,
                                 transition_name, payload, now, NULL);
    }
    free(payload);
    json_decref(root);
    json_decref(alert);
    json_decref(details);
    return result;
}

/** @brief Read the next occurrence number for one stable alert key. */
static int next_occurrence(sqlite3 *handle,
                           const char *key,
                           uint64_t *occurrence)
{
    static const char query[] =
        "SELECT coalesce(max(occurrences),0) FROM alert_incidents "
        "WHERE alert_key=?1;";
    sqlite3_stmt *statement = NULL;
    uint64_t previous = 0U;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, key, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_ROW
                     ? jg_database_column_unsigned(statement, 0, &previous)
                     : jg_database_sqlite_result(status);
    }
    if (result == 0) {
        if (previous >= ALERT_VALUE_MAX) {
            result = -EOVERFLOW;
        } else {
            *occurrence = previous + 1U;
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

/** @brief Insert a newly active alert incident. */
static int open_incident(sqlite3 *handle,
                         const char *key,
                         const struct jg_alert_condition *condition,
                         const char *details,
                         uint64_t now,
                         struct jg_alert_incident *incident)
{
    static const char insert[] =
        "INSERT INTO alert_incidents(alert_key,type,resource,severity,state,"
        "summary,details,opened_at,updated_at,occurrences) VALUES("
        "?1,?2,?3,?4,'open',?5,?6,?7,?7,?8);";
    sqlite3_stmt *statement = NULL;
    uint64_t occurrence = 0U;
    int status = SQLITE_OK;
    int result = next_occurrence(handle, key, &occurrence);

    if (result == 0) {
        status = sqlite3_prepare_v3(
            handle, insert, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, key, -1, SQLITE_TRANSIENT);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_text(statement, 2,
                                       jg_alert_type_name(condition->type), -1,
                                       SQLITE_STATIC);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_text(statement, 3, condition->resource, -1,
                                       SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_text(
                statement, 4, jg_alert_severity_name(condition->severity), -1,
                SQLITE_STATIC);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_text(statement, 5, condition->summary, -1,
                                       SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_text(statement, 6, details, -1, SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 7, (sqlite3_int64)now);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_int64(statement, 8, (sqlite3_int64)occurrence);
        }
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
        const sqlite3_int64 identifier = sqlite3_last_insert_rowid(handle);

        result = identifier <= 0
                     ? -EOVERFLOW
                     : load_incident(handle, (uint64_t)identifier, incident);
    }
    return result;
}

/** @brief Update materially changed content for one open incident. */
static int refresh_incident(sqlite3 *handle,
                            const struct jg_alert_condition *condition,
                            const char *details,
                            uint64_t now,
                            struct jg_alert_incident *incident)
{
    static const char update[] =
        "UPDATE alert_incidents SET severity=?1,summary=?2,details=?3,"
        "updated_at=?4 WHERE id=?5 AND state='open';";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_text(statement, 1,
                                   jg_alert_severity_name(condition->severity),
                                   -1, SQLITE_STATIC);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_text(statement, 2, condition->summary, -1,
                                       SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_text(statement, 3, details, -1, SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 4, (sqlite3_int64)now);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_int64(statement, 5, (sqlite3_int64)incident->id);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(handle) != 1) {
        result = -EAGAIN;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result == 0 ? load_incident(handle, incident->id, incident) : result;
}

/** @brief Resolve one currently open incident. */
static int resolve_incident(sqlite3 *handle,
                            uint64_t now,
                            struct jg_alert_incident *incident)
{
    static const char update[] =
        "UPDATE alert_incidents SET state='resolved',updated_at=?1,"
        "resolved_at=?1 WHERE id=?2 AND state='open';";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)now);
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_int64(statement, 2, (sqlite3_int64)incident->id);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(handle) != 1) {
        result = -EAGAIN;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result == 0 ? load_incident(handle, incident->id, incident) : result;
}

/** @brief Reconcile one evaluated condition with persistent incident state. */
int jg_database_alert_reconcile(struct jg_database *database,
                                const struct jg_alert_condition *condition,
                                bool active,
                                bool notify,
                                uint64_t now,
                                struct jg_alert_incident *incident,
                                enum jg_alert_transition *transition)
{
    char key[ALERT_KEY_SIZE];
    char *details = NULL;
    struct jg_alert_incident current = {0};
    enum jg_alert_transition changed = JG_ALERT_TRANSITION_NONE;
    int result = 0;

    if (database == NULL || incident == NULL || transition == NULL ||
        now == 0U || now > ALERT_VALUE_MAX) {
        return -EINVAL;
    }
    (void)memset(incident, 0, sizeof(*incident));
    *transition = JG_ALERT_TRANSITION_NONE;
    result = validate_condition(condition, key, &details);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        result = load_open(database->handle, key, &current);
        if (result == -ENOENT) {
            result = 0;
            (void)memset(&current, 0, sizeof(current));
        }
    }
    if (result == 0 && active && current.id == 0U) {
        result = open_incident(database->handle, key, condition, details, now,
                               &current);
        changed = JG_ALERT_TRANSITION_OPEN;
    } else if (result == 0 && active &&
               (current.severity != condition->severity ||
                strcmp(current.summary, condition->summary) != 0 ||
                strcmp(current.details, details) != 0)) {
        result = refresh_incident(database->handle, condition, details, now,
                                  &current);
    } else if (result == 0 && !active && current.id != 0U) {
        result = resolve_incident(database->handle, now, &current);
        changed = JG_ALERT_TRANSITION_RESOLVED;
    }
    if (result == 0 && notify && changed != JG_ALERT_TRANSITION_NONE) {
        result = enqueue_incident(database->handle, &current, changed, now);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        *incident = current;
        *transition = changed;
    }
    free(details);
    return result;
}

/** @brief List one stable newest-first page of alert incidents. */
int jg_database_alert_list(struct jg_database *database,
                           const struct jg_alert_filter *filter,
                           struct jg_alert_incident *incidents,
                           size_t capacity,
                           size_t *count,
                           bool *has_more)
{
    static const char query[] =
        "SELECT id,type,resource,severity,state,summary,details,opened_at,"
        "updated_at,resolved_at,occurrences FROM alert_incidents WHERE "
        "(?1=0 OR id<?1) AND (?2 IS NULL OR state=?2) AND "
        "(?3 IS NULL OR type=?3) ORDER BY id DESC LIMIT ?4;";
    const char *state =
        filter == NULL ? NULL : jg_alert_state_name(filter->state);
    const char *type = filter == NULL ? NULL : jg_alert_type_name(filter->type);
    sqlite3_stmt *statement = NULL;
    size_t loaded = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (count != NULL) {
        *count = 0U;
    }
    if (has_more != NULL) {
        *has_more = false;
    }
    if (database == NULL || filter == NULL || incidents == NULL ||
        count == NULL || has_more == NULL || capacity == 0U ||
        capacity > JG_ALERT_PAGE_MAX || filter->before_id > ALERT_VALUE_MAX ||
        (filter->state != JG_ALERT_STATE_ANY && state == NULL) ||
        (filter->type != JG_ALERT_TYPE_ANY && type == NULL)) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status =
            sqlite3_bind_int64(statement, 1, (sqlite3_int64)filter->before_id);
        if (status == SQLITE_OK) {
            status = state == NULL ? sqlite3_bind_null(statement, 2)
                                   : sqlite3_bind_text(statement, 2, state, -1,
                                                       SQLITE_STATIC);
        }
        if (status == SQLITE_OK) {
            status = type == NULL ? sqlite3_bind_null(statement, 3)
                                  : sqlite3_bind_text(statement, 3, type, -1,
                                                      SQLITE_STATIC);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, 4, (int)capacity + 1);
        }
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && loaded <= capacity &&
           (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (loaded < capacity) {
            result = decode_incident(statement, &incidents[loaded]);
        }
        ++loaded;
    }
    if (result == 0 && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *has_more = loaded > capacity;
        *count = loaded > capacity ? capacity : loaded;
    }
    return result;
}

/** @brief Enqueue one bounded operational notification event. */
int jg_database_alert_event_enqueue(struct jg_database *database,
                                    const char *event_code,
                                    enum jg_alert_severity severity,
                                    const char *summary,
                                    const char *details,
                                    uint64_t now,
                                    char event_id[JG_ALERT_EVENT_ID_SIZE])
{
    const size_t summary_size = bounded_length(summary, JG_ALERT_SUMMARY_MAX);
    char *canonical = NULL;
    json_t *details_object = NULL;
    json_t *root = NULL;
    char *payload = NULL;
    int result = 0;

    if (event_id != NULL) {
        event_id[0U] = '\0';
    }
    if (database == NULL ||
        !identifier_valid(event_code, JG_ALERT_EVENT_CODE_MAX) ||
        jg_alert_severity_name(severity) == NULL || summary_size == 0U ||
        summary_size > JG_ALERT_SUMMARY_MAX || now == 0U ||
        now > ALERT_VALUE_MAX ||
        !jg_utf8_text_valid((const uint8_t *)summary, summary_size, false)) {
        return -EINVAL;
    }
    result = canonical_object(details, JG_ALERT_DETAILS_MAX, &canonical,
                              &details_object);
    if (result == 0) {
        root = json_object();
        if (root == NULL ||
            json_object_set_new(root, "schema_version", json_integer(1)) != 0 ||
            json_object_set_new(root, "event", json_string(event_code)) != 0 ||
            json_object_set_new(
                root, "severity",
                json_string(jg_alert_severity_name(severity))) != 0 ||
            json_object_set_new(root, "summary", json_string(summary)) != 0 ||
            json_object_set(root, "details", details_object) != 0 ||
            json_object_set_new(root, "occurred_at",
                                json_integer((json_int_t)now)) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        payload = json_dumps(root, JSON_COMPACT | JSON_SORT_KEYS);
        if (payload == NULL) {
            result = -ENOMEM;
        } else if (strlen(payload) > JG_ALERT_PAYLOAD_MAX) {
            result = -EOVERFLOW;
        }
    }
    if (result == 0) {
        result = enqueue_payload(database->handle, 0U, "event", event_code,
                                 "event", payload, now, event_id);
    }
    free(payload);
    json_decref(root);
    json_decref(details_object);
    free(canonical);
    return result;
}

/** @brief Atomically claim the oldest due pending webhook delivery. */
int jg_database_alert_delivery_next(struct jg_database *database,
                                    uint64_t now,
                                    struct jg_alert_delivery *delivery)
{
    static const char query[] =
        "SELECT id,event_uuid,payload,attempts FROM alert_outbox WHERE "
        "status='pending' AND next_attempt_at<=?1 AND (claim_token IS NULL "
        "OR claimed_at<=?2) ORDER BY id LIMIT 1;";
    static const char claim[] =
        "UPDATE alert_outbox SET claim_token=?1,claimed_at=?2 WHERE id=?3 "
        "AND status='pending' AND next_attempt_at<=?2 AND (claim_token IS "
        "NULL OR claimed_at<=?4);";
    sqlite3_stmt *statement = NULL;
    const void *event_uuid = NULL;
    const uint64_t stale_before = now > ALERT_DELIVERY_CLAIM_TIMEOUT
                                      ? now - ALERT_DELIVERY_CLAIM_TIMEOUT
                                      : 0U;
    uint64_t attempts = 0U;
    int status = SQLITE_OK;
    int result = sodium_init() < 0 ? -EIO : 0;

    if (database == NULL || delivery == NULL || now > ALERT_VALUE_MAX) {
        return -EINVAL;
    }
    (void)memset(delivery, 0, sizeof(*delivery));
    if (result == 0) {
        randombytes_buf(delivery->claim, sizeof(delivery->claim));
    }
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, query, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)now);
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_int64(statement, 2, (sqlite3_int64)stale_before);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result =
            status == SQLITE_ROW
                ? 0
                : (status == SQLITE_DONE ? -ENOENT
                                         : jg_database_sqlite_result(status));
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 0, &delivery->id);
    }
    if (result == 0) {
        event_uuid = sqlite3_column_blob(statement, 1);
        if (event_uuid == NULL || sqlite3_column_bytes(statement, 1) !=
                                      JG_ALERT_DELIVERY_CLAIM_SIZE) {
            result = -EILSEQ;
        } else {
            encode_hex(event_uuid, JG_ALERT_DELIVERY_CLAIM_SIZE,
                       delivery->event_id);
        }
    }
    if (result == 0) {
        result = read_text(statement, 2, delivery->payload,
                           sizeof(delivery->payload), true);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 3, &attempts);
        if (result == 0 && attempts >= ALERT_DELIVERY_ATTEMPTS_MAX) {
            result = -EILSEQ;
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        statement = NULL;
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, claim, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_blob(statement, 1, delivery->claim,
                              (int)sizeof(delivery->claim), SQLITE_TRANSIENT);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)now);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_int64(statement, 3, (sqlite3_int64)delivery->id);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_int64(statement, 4, (sqlite3_int64)stale_before);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = -EAGAIN;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        delivery->attempts = (uint32_t)attempts;
        result = jg_database_transaction_commit(database);
    }
    if (result != 0) {
        (void)jg_database_transaction_rollback(database);
        (void)memset(delivery, 0, sizeof(*delivery));
    }
    return result;
}

/** @brief Atomically snapshot webhook transport and claim one due delivery. */
int jg_database_alert_delivery_claim(
    struct jg_database *database,
    const uint8_t protection_key[JG_ALERT_WEBHOOK_SECRET_SIZE],
    uint64_t now,
    struct jg_alert_configuration *configuration,
    uint8_t secret[JG_ALERT_WEBHOOK_SECRET_SIZE],
    struct jg_alert_delivery *delivery)
{
    int result = 0;

    if (database == NULL || protection_key == NULL || configuration == NULL ||
        secret == NULL || delivery == NULL) {
        return -EINVAL;
    }
    (void)memset(configuration, 0, sizeof(*configuration));
    (void)memset(secret, 0, JG_ALERT_WEBHOOK_SECRET_SIZE);
    (void)memset(delivery, 0, sizeof(*delivery));
    result = jg_database_transaction_begin(database);
    if (result == 0) {
        result = jg_database_alert_configuration_load(database, configuration);
    }
    if (result == 0 && !configuration->values.webhook_enabled) {
        result = -ENOENT;
    }
    if (result == 0) {
        result = jg_database_alert_webhook_secret_load(database, protection_key,
                                                       secret);
    }
    if (result == 0) {
        result = jg_database_alert_delivery_next(database, now, delivery);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result != 0) {
        jg_alert_configuration_clear(configuration);
        sodium_memzero(secret, JG_ALERT_WEBHOOK_SECRET_SIZE);
        (void)memset(delivery, 0, sizeof(*delivery));
    }
    return result;
}

/** @brief Complete one webhook delivery attempt. */
int jg_database_alert_delivery_complete(
    struct jg_database *database,
    const struct jg_alert_delivery *delivery,
    bool delivered,
    uint64_t now,
    const char *error)
{
    static const char query[] =
        "SELECT attempts FROM alert_outbox WHERE id=?1 AND status='pending' "
        "AND claim_token=?2;";
    static const char update[] =
        "UPDATE alert_outbox SET status=?1,next_attempt_at=?2,attempts=?3,"
        "delivered_at=?4,last_error=?5,claim_token=NULL,claimed_at=NULL WHERE "
        "id=?6 AND status='pending' AND claim_token=?7;";
    const size_t error_size =
        error == NULL ? 0U : bounded_length(error, JG_ALERT_DELIVERY_ERROR_MAX);
    sqlite3_stmt *statement = NULL;
    uint64_t attempts = 0U;
    uint64_t delay = 0U;
    uint64_t next_attempt_at = now;
    const char *status_name = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || delivery == NULL || delivery->id == 0U ||
        delivery->id > ALERT_VALUE_MAX || now > ALERT_VALUE_MAX ||
        (!delivered &&
         (error_size == 0U || error_size > JG_ALERT_DELIVERY_ERROR_MAX ||
          !jg_utf8_text_valid((const uint8_t *)error, error_size, false)))) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin(database);
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, query, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)delivery->id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_blob(statement, 2, delivery->claim,
                                       (int)sizeof(delivery->claim),
                                       SQLITE_TRANSIENT);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result =
            status == SQLITE_ROW
                ? jg_database_column_unsigned(statement, 0, &attempts)
                : (status == SQLITE_DONE ? -ENOENT
                                         : jg_database_sqlite_result(status));
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        statement = NULL;
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0 && attempts >= ALERT_DELIVERY_ATTEMPTS_MAX) {
        result = -EILSEQ;
    }
    if (result == 0) {
        ++attempts;
        if (delivered) {
            status_name = "delivered";
        } else if (attempts >= ALERT_DELIVERY_ATTEMPTS_MAX) {
            status_name = "abandoned";
        } else {
            status_name = "pending";
            delay = UINT64_C(30) << (attempts > 7U ? 7U : attempts - 1U);
            if (delay > 3600U) {
                delay = 3600U;
            }
        }
        if (delay > ALERT_VALUE_MAX - now) {
            result = -EOVERFLOW;
        } else {
            next_attempt_at += delay;
        }
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_text(statement, 1, status_name, -1, SQLITE_STATIC);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2,
                                        (sqlite3_int64)next_attempt_at);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 3, (sqlite3_int64)attempts);
        }
        if (status == SQLITE_OK) {
            status = delivered
                         ? sqlite3_bind_int64(statement, 4, (sqlite3_int64)now)
                         : sqlite3_bind_null(statement, 4);
        }
        if (status == SQLITE_OK) {
            status = delivered ? sqlite3_bind_null(statement, 5)
                               : sqlite3_bind_text(statement, 5, error, -1,
                                                   SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_int64(statement, 6, (sqlite3_int64)delivery->id);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_blob(statement, 7, delivery->claim,
                                       (int)sizeof(delivery->claim),
                                       SQLITE_TRANSIENT);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = -EAGAIN;
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

/** @brief Collect bounded incident and delivery aggregates for monitoring. */
int jg_database_alert_storage_metrics(struct jg_database *database,
                                      struct jg_alert_storage_metrics *metrics)
{
    static const char incidents[] =
        "SELECT type,count(*) FROM alert_incidents WHERE state='open' "
        "GROUP BY type;";
    static const char totals[] =
        "SELECT count(*),coalesce(sum(state='resolved'),0) FROM "
        "alert_incidents;";
    static const char deliveries[] =
        "SELECT coalesce(sum(status='pending'),0),"
        "coalesce(sum(status='delivered'),0),"
        "coalesce(sum(status='abandoned'),0) FROM alert_outbox;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || metrics == NULL) {
        return -EINVAL;
    }
    (void)memset(metrics, 0, sizeof(*metrics));
    status = sqlite3_prepare_v3(database->handle, incidents, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(statement, 0);
        const enum jg_alert_type type =
            name == NULL ? JG_ALERT_TYPE_ANY : parse_type(name);
        uint64_t count = 0U;

        result = jg_database_column_unsigned(statement, 1, &count);
        if (result == 0 && type == JG_ALERT_TYPE_ANY) {
            result = -EILSEQ;
        } else if (result == 0) {
            metrics->open_by_type[(size_t)type - 1U] = count;
        }
    }
    if (result == 0 && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        statement = NULL;
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, totals, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_step(statement) == SQLITE_ROW) {
        result =
            jg_database_column_unsigned(statement, 0, &metrics->opened_total);
        if (result == 0) {
            result = jg_database_column_unsigned(statement, 1,
                                                 &metrics->resolved_total);
        }
    } else if (result == 0) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        statement = NULL;
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, deliveries, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_step(statement) == SQLITE_ROW) {
        result = jg_database_column_unsigned(statement, 0,
                                             &metrics->deliveries_pending);
        if (result == 0) {
            result = jg_database_column_unsigned(
                statement, 1, &metrics->deliveries_succeeded);
        }
        if (result == 0) {
            result = jg_database_column_unsigned(statement, 2,
                                                 &metrics->deliveries_failed);
        }
    } else if (result == 0) {
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

/** @brief Prune terminal alert history beyond fixed retention bounds. */
int jg_database_alert_prune(struct jg_database *database)
{
    static const char prune[] =
        "DELETE FROM alert_outbox WHERE status!='pending' AND id NOT IN("
        "SELECT id FROM alert_outbox WHERE status!='pending' ORDER BY id DESC "
        "LIMIT 1000);"
        "DELETE FROM alert_incidents WHERE state='resolved' AND id NOT IN("
        "SELECT id FROM alert_incidents WHERE state='resolved' ORDER BY id "
        "DESC LIMIT 10000);";

    return database == NULL ? -EINVAL
                            : jg_database_execute_sql(database->handle, prune);
}
