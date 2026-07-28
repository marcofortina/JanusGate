/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/event.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sqlite3.h>

#include "database_internal.h"
#include "janusgate/checked.h"

/** @brief Return one bounded string length or one past the maximum. */
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

/** @brief Validate one lowercase stable identifier. */
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

/** @brief Return the persistent name for one event severity. */
static const char *severity_name(enum jg_event_severity severity)
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

/** @brief Parse one exact persistent event severity. */
static bool parse_severity(const char *text,
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

/** @brief Validate and canonicalize one bounded JSON details object. */
static int canonical_details(const char *details, char **canonical)
{
    const size_t details_size = bounded_length(details, JG_EVENT_DETAILS_MAX);
    json_error_t error;
    json_t *parsed = NULL;
    int result = 0;

    *canonical = NULL;
    if (details_size == 0U || details_size > JG_EVENT_DETAILS_MAX) {
        return -EINVAL;
    }
    if (!jg_utf8_text_valid((const uint8_t *)details, details_size, false)) {
        return -EILSEQ;
    }
    parsed = json_loadb(details, details_size, JSON_REJECT_DUPLICATES, &error);
    if (!json_is_object(parsed)) {
        json_decref(parsed);
        return -EINVAL;
    }
    *canonical = json_dumps(parsed, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(parsed);
    if (*canonical == NULL) {
        return -ENOMEM;
    }
    if (strlen(*canonical) > JG_EVENT_DETAILS_MAX) {
        free(*canonical);
        *canonical = NULL;
        result = -EINVAL;
    }
    return result;
}

/** @brief Validate one complete event before persistence. */
static int validate_event(const struct jg_event *event, char **details)
{
    size_t message_size = 0U;

    if (event == NULL || event->occurred_at == 0U ||
        event->occurred_at > (uint64_t)INT64_MAX ||
        severity_name(event->severity) == NULL ||
        !identifier_valid(event->component, JG_EVENT_COMPONENT_MAX) ||
        !identifier_valid(event->code, JG_EVENT_CODE_MAX)) {
        return -EINVAL;
    }
    message_size = bounded_length(event->message, JG_EVENT_MESSAGE_MAX);
    if (message_size == 0U || message_size > JG_EVENT_MESSAGE_MAX) {
        return -EINVAL;
    }
    if (!jg_utf8_text_valid((const uint8_t *)event->message, message_size,
                            false)) {
        return -EILSEQ;
    }
    return canonical_details(event->details, details);
}

/** @brief Append one validated operational event. */
int jg_database_event_append(struct jg_database *database,
                             const struct jg_event *event,
                             uint64_t *event_id)
{
    static const char insert[] =
        "INSERT INTO operational_events("
        "occurred_at,severity,component,code,message,details"
        ") VALUES(?1,?2,?3,?4,?5,?6);";
    char *details = NULL;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (event_id != NULL) {
        *event_id = 0U;
    }
    if (database == NULL) {
        return -EINVAL;
    }
    result = validate_event(event, &details);
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int64(statement, 1, (sqlite3_int64)event->occurred_at);
    }
    if (status == SQLITE_OK && result == 0) {
        status = sqlite3_bind_text(statement, 2, severity_name(event->severity),
                                   -1, SQLITE_STATIC);
    }
    if (status == SQLITE_OK && result == 0) {
        status = sqlite3_bind_text(statement, 3, event->component, -1,
                                   SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK && result == 0) {
        status =
            sqlite3_bind_text(statement, 4, event->code, -1, SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK && result == 0) {
        status = sqlite3_bind_text(statement, 5, event->message, -1,
                                   SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK && result == 0) {
        status = sqlite3_bind_text(statement, 6, details, -1, SQLITE_TRANSIENT);
    }
    if (result == 0) {
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && event_id != NULL) {
        const sqlite3_int64 identifier =
            sqlite3_last_insert_rowid(database->handle);

        if (identifier <= 0) {
            result = -EOVERFLOW;
        } else {
            *event_id = (uint64_t)identifier;
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    free(details);
    return result;
}

/** @brief Read one exact SQLite text cell and validate its bounds. */
static int read_text(sqlite3_stmt *statement,
                     int column,
                     char *output,
                     size_t output_size,
                     bool identifier)
{
    const char *text = (const char *)sqlite3_column_text(statement, column);
    const int bytes = sqlite3_column_bytes(statement, column);

    if (sqlite3_column_type(statement, column) != SQLITE_TEXT || text == NULL ||
        bytes < 0 || (size_t)bytes >= output_size ||
        memchr(text, '\0', (size_t)bytes) != NULL ||
        !jg_utf8_text_valid((const uint8_t *)text, (size_t)bytes, false) ||
        (identifier && !identifier_valid(text, output_size - 1U))) {
        return -EILSEQ;
    }
    (void)memcpy(output, text, (size_t)bytes);
    output[bytes] = '\0';
    return 0;
}

/** @brief Decode and validate one persistent event row. */
static int decode_record(sqlite3_stmt *statement,
                         struct jg_event_record *record)
{
    const sqlite3_int64 identifier = sqlite3_column_int64(statement, 0);
    const sqlite3_int64 occurred_at = sqlite3_column_int64(statement, 1);
    const char *severity = (const char *)sqlite3_column_text(statement, 2);
    const int severity_size = sqlite3_column_bytes(statement, 2);
    char *canonical = NULL;
    int result = 0;

    (void)memset(record, 0, sizeof(*record));
    if (sqlite3_column_type(statement, 0) != SQLITE_INTEGER ||
        identifier <= 0 ||
        sqlite3_column_type(statement, 1) != SQLITE_INTEGER ||
        occurred_at < 0 || sqlite3_column_type(statement, 2) != SQLITE_TEXT ||
        severity == NULL || severity_size <= 0 ||
        !parse_severity(severity, (size_t)severity_size, &record->severity)) {
        return -EILSEQ;
    }
    record->id = (uint64_t)identifier;
    record->occurred_at = (uint64_t)occurred_at;
    result = read_text(statement, 3, record->component,
                       sizeof(record->component), true);
    if (result == 0) {
        result =
            read_text(statement, 4, record->code, sizeof(record->code), true);
    }
    if (result == 0) {
        result = read_text(statement, 5, record->message,
                           sizeof(record->message), false);
    }
    if (result == 0) {
        result = read_text(statement, 6, record->details,
                           sizeof(record->details), false);
    }
    if (result == 0) {
        result = canonical_details(record->details, &canonical);
        if (result == 0 && strcmp(record->details, canonical) != 0) {
            result = -EILSEQ;
        } else if (result != 0 && result != -ENOMEM) {
            result = -EILSEQ;
        }
    }
    free(canonical);
    if (result != 0) {
        (void)memset(record, 0, sizeof(*record));
    }
    return result;
}

/** @brief Bind one stable event-page query. */
static int bind_list(sqlite3_stmt *statement,
                     const struct jg_event_filter *filter,
                     size_t limit)
{
    const char *severity = severity_name(filter->severity);
    int status =
        sqlite3_bind_int64(statement, 1, (sqlite3_int64)filter->after_id);

    if (status == SQLITE_OK) {
        status = severity == NULL ? sqlite3_bind_null(statement, 2)
                                  : sqlite3_bind_text(statement, 2, severity,
                                                      -1, SQLITE_STATIC);
    }
    if (status == SQLITE_OK) {
        status = filter->component == NULL
                     ? sqlite3_bind_null(statement, 3)
                     : sqlite3_bind_text(statement, 3, filter->component, -1,
                                         SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 4, (sqlite3_int64)limit);
    }
    return jg_database_sqlite_result(status);
}

/** @brief List one filtered stable page of operational events. */
int jg_database_event_list(struct jg_database *database,
                           const struct jg_event_filter *filter,
                           struct jg_event_record *records,
                           size_t capacity,
                           size_t *count,
                           bool *has_more)
{
    static const char query[] =
        "SELECT id,occurred_at,severity,component,code,message,details"
        " FROM operational_events WHERE id>?1"
        " AND (?2 IS NULL OR severity=?2)"
        " AND (?3 IS NULL OR component=?3)"
        " ORDER BY id LIMIT ?4;";
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
    if (database == NULL || filter == NULL || records == NULL ||
        count == NULL || has_more == NULL || capacity == 0U ||
        capacity > JG_EVENT_PAGE_MAX ||
        filter->after_id > (uint64_t)INT64_MAX ||
        (filter->severity != JG_EVENT_SEVERITY_ANY &&
         severity_name(filter->severity) == NULL) ||
        (filter->component != NULL &&
         !identifier_valid(filter->component, JG_EVENT_COMPONENT_MAX))) {
        return -EINVAL;
    }
    (void)memset(records, 0, capacity * sizeof(*records));
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        result = bind_list(statement, filter, capacity + 1U);
    }
    while (result == 0 && loaded <= capacity) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            break;
        }
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else if (loaded == capacity) {
            *has_more = true;
            break;
        } else {
            result = decode_record(statement, &records[loaded]);
            if (result == 0) {
                ++loaded;
            }
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *count = loaded;
    } else {
        (void)memset(records, 0, capacity * sizeof(*records));
        *has_more = false;
    }
    return result;
}
