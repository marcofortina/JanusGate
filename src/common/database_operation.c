/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "janusgate/database.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sqlite3.h>

#include "database_internal.h"
#include "janusgate/checked.h"

/** @brief Validate one stable lowercase management-operation kind. */
static bool operation_kind_valid(const char *kind)
{
    size_t length = 0U;

    if (kind == NULL) {
        return false;
    }
    while (length <= JG_DATABASE_OPERATION_KIND_MAX && kind[length] != '\0') {
        const unsigned char character = (unsigned char)kind[length];

        if (!((character >= (unsigned char)'a' &&
               character <= (unsigned char)'z') ||
              (character >= (unsigned char)'0' &&
               character <= (unsigned char)'9') ||
              character == (unsigned char)'_')) {
            return false;
        }
        ++length;
    }
    return length != 0U && length <= JG_DATABASE_OPERATION_KIND_MAX;
}

/** @brief Return the persistent name of one authenticated operation actor. */
static const char *operation_actor_name(enum jg_audit_actor_type actor)
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

/** @brief Parse one persistent authenticated operation actor name. */
static bool operation_actor_parse(const char *name,
                                  enum jg_audit_actor_type *actor)
{
    if (strcmp(name, "system") == 0) {
        *actor = JG_AUDIT_ACTOR_SYSTEM;
    } else if (strcmp(name, "user") == 0) {
        *actor = JG_AUDIT_ACTOR_USER;
    } else if (strcmp(name, "token") == 0) {
        *actor = JG_AUDIT_ACTOR_TOKEN;
    } else if (strcmp(name, "local") == 0) {
        *actor = JG_AUDIT_ACTOR_LOCAL;
    } else {
        return false;
    }
    return true;
}

/** @brief Validate one bounded UTF-8 operation provenance field. */
static bool operation_text_valid(const char *text,
                                 size_t minimum,
                                 size_t maximum)
{
    const size_t size = text == NULL ? 0U : strnlen(text, maximum + 1U);

    return text != NULL && size >= minimum && size <= maximum &&
           jg_utf8_text_valid((const uint8_t *)text, size, minimum == 0U);
}

/** @brief Validate actor and bounded text semantics for operation provenance.
 */
static bool operation_context_valid(
    const struct jg_database_operation_context *context)
{
    const bool actor_has_identifier =
        context != NULL && (context->actor_type == JG_AUDIT_ACTOR_USER ||
                            context->actor_type == JG_AUDIT_ACTOR_TOKEN);

    return context != NULL &&
           operation_actor_name(context->actor_type) != NULL &&
           context->has_actor_id == actor_has_identifier &&
           (!context->has_actor_id ||
            (context->actor_id > 0U &&
             context->actor_id <= (uint64_t)INT64_MAX)) &&
           operation_text_valid(context->source, 1U, JG_AUDIT_SOURCE_MAX) &&
           operation_text_valid(context->request_id, 0U,
                                JG_AUDIT_REQUEST_ID_MAX) &&
           operation_text_valid(context->requested_action, 1U,
                                JG_AUDIT_ACTION_MAX);
}

/** @brief Reserve the singleton durable management-operation slot. */
int jg_database_operation_prepare(
    struct jg_database *database,
    const char *kind,
    const uint8_t *payload,
    size_t payload_size,
    const struct jg_database_operation_context *context,
    uint64_t created_at)
{
    static const char insert[] =
        "INSERT INTO management_operations(id,kind,state,payload,created_at,"
        "actor_type,actor_id,source,request_id,requested_action)"
        " VALUES(1,?1,'preparing',?2,?3,?4,?5,?6,?7,?8)"
        " ON CONFLICT(id) DO NOTHING;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || !operation_kind_valid(kind) ||
        (payload == NULL && payload_size != 0U) ||
        payload_size > JG_DATABASE_OPERATION_PAYLOAD_MAX ||
        !operation_context_valid(context) || created_at > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, insert, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, kind, -1, SQLITE_TRANSIENT);
        if (status == SQLITE_OK) {
            status =
                payload_size == 0U
                    ? sqlite3_bind_zeroblob(statement, 2, 0)
                    : sqlite3_bind_blob(statement, 2, payload,
                                        (int)payload_size, SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_int64(statement, 3, (sqlite3_int64)created_at);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_text(
                statement, 4, operation_actor_name(context->actor_type), -1,
                SQLITE_STATIC);
        }
        if (status == SQLITE_OK) {
            status = context->has_actor_id
                         ? sqlite3_bind_int64(statement, 5,
                                              (sqlite3_int64)context->actor_id)
                         : sqlite3_bind_null(statement, 5);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_text(statement, 6, context->source, -1,
                                       SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_text(statement, 7, context->request_id, -1,
                                       SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_text(statement, 8, context->requested_action,
                                       -1, SQLITE_TRANSIENT);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = -EBUSY;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Mark the pending operation safe to recover before external work. */
int jg_database_operation_mark_ready(struct jg_database *database)
{
    static const char update[] =
        "UPDATE management_operations SET state='ready'"
        " WHERE id=1 AND state='preparing';";
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = jg_database_execute_sql(database->handle, update);
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Load the singleton durable management operation. */
int jg_database_operation_load(struct jg_database *database,
                               struct jg_database_operation *operation)
{
    static const char query[] =
        "SELECT kind,state,payload,created_at,actor_type,actor_id,source,"
        "request_id,requested_action FROM management_operations WHERE id=1;";
    struct jg_database_operation loaded;
    sqlite3_stmt *statement = NULL;
    const char *kind = NULL;
    const char *state = NULL;
    const char *actor_name = NULL;
    const char *source = NULL;
    const char *request_id = NULL;
    const char *requested_action = NULL;
    const void *payload = NULL;
    size_t kind_size = 0U;
    size_t state_size = 0U;
    size_t actor_name_size = 0U;
    size_t source_size = 0U;
    size_t request_id_size = 0U;
    size_t requested_action_size = 0U;
    int payload_size = 0;
    sqlite3_int64 created_at = 0;
    sqlite3_int64 actor_id = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || operation == NULL) {
        return -EINVAL;
    }
    (void)memset(&loaded, 0, sizeof(loaded));
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result =
            jg_database_column_required_text(statement, 0, &kind, &kind_size);
    }
    if (result == 0) {
        result =
            jg_database_column_required_text(statement, 1, &state, &state_size);
    }
    if (result == 0 && (kind_size > JG_DATABASE_OPERATION_KIND_MAX ||
                        !operation_kind_valid(kind) ||
                        !((state_size == sizeof("ready") - 1U &&
                           memcmp(state, "ready", state_size) == 0) ||
                          (state_size == sizeof("preparing") - 1U &&
                           memcmp(state, "preparing", state_size) == 0)))) {
        result = -EILSEQ;
    }
    if (result == 0 && sqlite3_column_type(statement, 2) != SQLITE_BLOB) {
        result = -EILSEQ;
    }
    if (result == 0) {
        payload = sqlite3_column_blob(statement, 2);
        payload_size = sqlite3_column_bytes(statement, 2);
        created_at = sqlite3_column_int64(statement, 3);
        if (payload_size < 0 ||
            (size_t)payload_size > JG_DATABASE_OPERATION_PAYLOAD_MAX ||
            (payload == NULL && payload_size != 0) ||
            sqlite3_column_type(statement, 3) != SQLITE_INTEGER ||
            created_at < 0) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 4, &actor_name,
                                                  &actor_name_size);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 6, &source,
                                                  &source_size);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 7, &request_id,
                                                  &request_id_size);
    }
    if (result == 0) {
        result = jg_database_column_required_text(
            statement, 8, &requested_action, &requested_action_size);
    }
    if (result == 0) {
        const bool has_actor_id =
            sqlite3_column_type(statement, 5) == SQLITE_INTEGER;

        actor_id = sqlite3_column_int64(statement, 5);
        loaded.has_actor_id = has_actor_id;
        if (!operation_actor_parse(actor_name, &loaded.actor_type) ||
            actor_name_size == 0U || actor_name_size > sizeof("system") - 1U ||
            (!has_actor_id &&
             sqlite3_column_type(statement, 5) != SQLITE_NULL) ||
            (has_actor_id && actor_id <= 0) ||
            ((loaded.actor_type == JG_AUDIT_ACTOR_USER ||
              loaded.actor_type == JG_AUDIT_ACTOR_TOKEN) != has_actor_id) ||
            !operation_text_valid(source, 1U, JG_AUDIT_SOURCE_MAX) ||
            source_size != strlen(source) ||
            !operation_text_valid(request_id, 0U, JG_AUDIT_REQUEST_ID_MAX) ||
            request_id_size != strlen(request_id) ||
            !operation_text_valid(requested_action, 1U, JG_AUDIT_ACTION_MAX) ||
            requested_action_size != strlen(requested_action)) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        (void)memcpy(loaded.kind, kind, kind_size);
        loaded.kind[kind_size] = '\0';
        if (payload_size != 0) {
            (void)memcpy(loaded.payload, payload, (size_t)payload_size);
        }
        loaded.payload_size = (size_t)payload_size;
        loaded.created_at = (uint64_t)created_at;
        loaded.actor_id = (uint64_t)actor_id;
        (void)memcpy(loaded.source, source, source_size);
        loaded.source[source_size] = '\0';
        (void)memcpy(loaded.request_id, request_id, request_id_size);
        loaded.request_id[request_id_size] = '\0';
        (void)memcpy(loaded.requested_action, requested_action,
                     requested_action_size);
        loaded.requested_action[requested_action_size] = '\0';
        loaded.ready = state_size == sizeof("ready") - 1U;
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
    if (result == 0) {
        *operation = loaded;
    }
    return result;
}

/** @brief Remove the singleton durable management operation. */
int jg_database_operation_clear(struct jg_database *database)
{
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = jg_database_execute_sql(
        database->handle, "DELETE FROM management_operations WHERE id=1;");
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Load persistent policy publication state. */
int jg_database_policy_sync_load(struct jg_database *database,
                                 struct jg_database_policy_sync *state)
{
    static const char query[] =
        "SELECT desired_revision,applied_revision,last_attempt_at,last_error"
        " FROM policy_sync_state WHERE id=1;";
    struct jg_database_policy_sync loaded;
    sqlite3_stmt *statement = NULL;
    const char *error = NULL;
    size_t error_size = 0U;
    sqlite3_int64 desired_revision = 0;
    sqlite3_int64 applied_revision = 0;
    sqlite3_int64 last_attempt_at = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || state == NULL) {
        return -EINVAL;
    }
    (void)memset(&loaded, 0, sizeof(loaded));
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_ROW    ? 0
                 : status == SQLITE_DONE ? -EILSEQ
                                         : jg_database_sqlite_result(status);
    }
    if (result == 0) {
        desired_revision = sqlite3_column_int64(statement, 0);
        applied_revision = sqlite3_column_int64(statement, 1);
        last_attempt_at = sqlite3_column_int64(statement, 2);
        if (sqlite3_column_type(statement, 0) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 1) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 2) != SQLITE_INTEGER ||
            desired_revision <= 0 || applied_revision <= 0 ||
            applied_revision > desired_revision || last_attempt_at < 0) {
            result = -EILSEQ;
        }
    }
    if (result == 0 && sqlite3_column_type(statement, 3) != SQLITE_NULL) {
        result =
            jg_database_column_required_text(statement, 3, &error, &error_size);
        if (result == 0 && (error_size == 0U ||
                            error_size > JG_DATABASE_POLICY_SYNC_ERROR_MAX)) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        loaded.desired_revision = (uint64_t)desired_revision;
        loaded.applied_revision = (uint64_t)applied_revision;
        loaded.last_attempt_at = (uint64_t)last_attempt_at;
        if (error != NULL) {
            (void)memcpy(loaded.last_error, error, error_size);
            loaded.last_error[error_size] = '\0';
        }
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
    if (result == 0) {
        *state = loaded;
    }
    return result;
}

/** @brief Advance the desired policy revision after a persistent mutation. */
int jg_database_policy_sync_advance(struct jg_database *database,
                                    uint64_t now,
                                    struct jg_database_policy_sync *state)
{
    static const char update[] =
        "UPDATE policy_sync_state SET desired_revision=desired_revision+1,"
        "last_error=NULL,updated_at=?1 WHERE id=1"
        " AND desired_revision<9223372036854775807;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || state == NULL || now > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, update, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = -EOVERFLOW;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = jg_database_policy_sync_load(database, state);
    }
    return result;
}

/** @brief Record the result of publishing one desired policy revision. */
int jg_database_policy_sync_record(struct jg_database *database,
                                   uint64_t desired_revision,
                                   bool applied,
                                   const char *error,
                                   uint64_t now,
                                   struct jg_database_policy_sync *state)
{
    static const char update[] =
        "UPDATE policy_sync_state SET applied_revision="
        "CASE WHEN ?2=1 THEN ?1 ELSE applied_revision END,"
        "last_attempt_at=?3,last_error=?4,updated_at=?3"
        " WHERE id=1 AND desired_revision=?1;";
    const size_t error_size =
        error == NULL ? 0U
                      : strnlen(error, JG_DATABASE_POLICY_SYNC_ERROR_MAX + 1U);
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || state == NULL || desired_revision == 0U ||
        desired_revision > (uint64_t)INT64_MAX || now > (uint64_t)INT64_MAX ||
        (applied && error != NULL) ||
        (!applied && (error == NULL || error_size == 0U ||
                      error_size > JG_DATABASE_POLICY_SYNC_ERROR_MAX))) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, update, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status =
            sqlite3_bind_int64(statement, 1, (sqlite3_int64)desired_revision);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, 2, applied ? 1 : 0);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 3, (sqlite3_int64)now);
        }
        if (status == SQLITE_OK) {
            status = applied
                         ? sqlite3_bind_null(statement, 4)
                         : sqlite3_bind_text(statement, 4, error,
                                             (int)error_size, SQLITE_TRANSIENT);
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
        result = jg_database_policy_sync_load(database, state);
    }
    return result;
}
