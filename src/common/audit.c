/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/audit.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sodium.h>
#include <sqlite3.h>

#include "database_internal.h"
#include "janusgate/checked.h"

/** Canonical hash format tag and version. */
static const uint8_t audit_hash_tag[] = {'J', 'G', 'A', 'U', 'D', 'I', 'T', 1U};

/** Bounded text bytes participating in an audit hash. */
struct audit_text {
    const uint8_t *data;
    size_t size;
    bool present;
};

/** Validated semantic fields participating in an audit hash. */
struct audit_material {
    uint64_t occurred_at;
    enum jg_audit_actor_type actor_type;
    bool has_actor_id;
    uint64_t actor_id;
    struct audit_text source;
    struct audit_text action;
    struct audit_text object_type;
    struct audit_text object_id;
    struct audit_text details;
    bool has_previous_revision;
    uint64_t previous_revision;
    bool has_new_revision;
    uint64_t new_revision;
    bool success;
    struct audit_text request_id;
};

/** @brief Return a bounded string length or one past the accepted maximum. */
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

/** @brief Initialize a required bounded text span. */
static bool required_text(const char *text,
                          size_t minimum,
                          size_t maximum,
                          struct audit_text *span)
{
    const size_t length = bounded_length(text, maximum);

    span->data = (const uint8_t *)text;
    span->size = length;
    span->present = text != NULL;
    return text != NULL && length >= minimum && length <= maximum;
}

/** @brief Initialize an optional bounded text span. */
static bool optional_text(const char *text,
                          size_t maximum,
                          struct audit_text *span)
{
    if (text == NULL) {
        span->data = NULL;
        span->size = 0U;
        span->present = false;
        return true;
    }
    return required_text(text, 1U, maximum, span);
}

/** @brief Validate an actor kind and its identifier semantics. */
static bool actor_valid(enum jg_audit_actor_type type,
                        bool has_identifier,
                        uint64_t identifier)
{
    if (type == JG_AUDIT_ACTOR_SYSTEM) {
        return !has_identifier;
    }
    return (type == JG_AUDIT_ACTOR_USER || type == JG_AUDIT_ACTOR_TOKEN) &&
           has_identifier && identifier > 0U &&
           identifier <= (uint64_t)INT64_MAX;
}

/** @brief Convert and validate one public event for hashing and storage. */
static int event_material(const struct jg_audit_event *event,
                          struct audit_material *material)
{
    if (event == NULL || material == NULL) {
        return -EINVAL;
    }
    (void)memset(material, 0, sizeof(*material));
    material->occurred_at = event->occurred_at;
    material->actor_type = event->actor_type;
    material->has_actor_id = event->has_actor_id;
    material->actor_id = event->actor_id;
    material->has_previous_revision = event->has_previous_revision;
    material->previous_revision = event->previous_revision;
    material->has_new_revision = event->has_new_revision;
    material->new_revision = event->new_revision;
    material->success = event->success;
    if (!actor_valid(event->actor_type, event->has_actor_id, event->actor_id)) {
        return -EINVAL;
    }
    if ((event->has_previous_revision && event->previous_revision == 0U) ||
        (event->has_new_revision && event->new_revision == 0U)) {
        return -EINVAL;
    }
    if (event->occurred_at > (uint64_t)INT64_MAX ||
        (event->has_previous_revision &&
         event->previous_revision > (uint64_t)INT64_MAX) ||
        (event->has_new_revision &&
         event->new_revision > (uint64_t)INT64_MAX)) {
        return -EOVERFLOW;
    }
    if (!required_text(event->source, 1U, JG_AUDIT_SOURCE_MAX,
                       &material->source) ||
        !required_text(event->action, 1U, JG_AUDIT_ACTION_MAX,
                       &material->action) ||
        !required_text(event->object_type, 1U, JG_AUDIT_OBJECT_TYPE_MAX,
                       &material->object_type) ||
        !optional_text(event->object_id, JG_AUDIT_OBJECT_ID_MAX,
                       &material->object_id) ||
        !required_text(event->details, 0U, JG_AUDIT_DETAILS_MAX,
                       &material->details) ||
        !required_text(event->request_id, 0U, JG_AUDIT_REQUEST_ID_MAX,
                       &material->request_id)) {
        return -EINVAL;
    }
    return 0;
}

/** @brief Feed one byte into an audit hash. */
static void hash_byte(crypto_generichash_state *state, uint8_t value)
{
    (void)crypto_generichash_update(state, &value, sizeof(value));
}

/** @brief Feed one big-endian integer into an audit hash. */
static void hash_u64(crypto_generichash_state *state, uint64_t value)
{
    uint8_t encoded[sizeof(uint64_t)];

    (void)jg_write_u64_be(encoded, sizeof(encoded), 0U, value);
    (void)crypto_generichash_update(state, encoded, sizeof(encoded));
}

/** @brief Feed one required length-prefixed text span into an audit hash. */
static void hash_text(crypto_generichash_state *state,
                      const struct audit_text *text)
{
    uint8_t encoded[sizeof(uint32_t)];

    (void)jg_write_u32_be(encoded, sizeof(encoded), 0U, (uint32_t)text->size);
    (void)crypto_generichash_update(state, encoded, sizeof(encoded));
    if (text->size > 0U) {
        (void)crypto_generichash_update(state, text->data, text->size);
    }
}

/** @brief Feed one optional text span into an audit hash. */
static void hash_optional_text(crypto_generichash_state *state,
                               const struct audit_text *text)
{
    hash_byte(state, text->present ? 1U : 0U);
    if (text->present) {
        hash_text(state, text);
    }
}

/** @brief Feed one optional integer into an audit hash. */
static void hash_optional_u64(crypto_generichash_state *state,
                              bool present,
                              uint64_t value)
{
    hash_byte(state, present ? 1U : 0U);
    if (present) {
        hash_u64(state, value);
    }
}

/** @brief Compute the canonical digest of one validated audit event. */
static int compute_event_hash(const uint8_t previous[JG_AUDIT_HASH_SIZE],
                              const struct audit_material *material,
                              uint8_t output[JG_AUDIT_HASH_SIZE])
{
    crypto_generichash_state state;

    if (sodium_init() < 0) {
        return -EIO;
    }
    if (crypto_generichash_init(&state, NULL, 0U, JG_AUDIT_HASH_SIZE) != 0) {
        return -EIO;
    }
    (void)crypto_generichash_update(&state, audit_hash_tag,
                                    sizeof(audit_hash_tag));
    (void)crypto_generichash_update(&state, previous, JG_AUDIT_HASH_SIZE);
    hash_u64(&state, material->occurred_at);
    hash_byte(&state, (uint8_t)material->actor_type);
    hash_optional_u64(&state, material->has_actor_id, material->actor_id);
    hash_text(&state, &material->source);
    hash_text(&state, &material->action);
    hash_text(&state, &material->object_type);
    hash_optional_text(&state, &material->object_id);
    hash_text(&state, &material->details);
    hash_optional_u64(&state, material->has_previous_revision,
                      material->previous_revision);
    hash_optional_u64(&state, material->has_new_revision,
                      material->new_revision);
    hash_byte(&state, material->success ? 1U : 0U);
    hash_text(&state, &material->request_id);
    return crypto_generichash_final(&state, output, JG_AUDIT_HASH_SIZE) == 0
               ? 0
               : -EIO;
}

/** @brief Execute one trusted SQL statement without result rows. */
static int execute_statement(sqlite3 *handle, const char *sql)
{
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, sql, -1, 0U, &statement, NULL);
    int result = jg_database_sqlite_result(status);

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
    return result;
}

/** @brief Read the latest persistent event digest under a transaction. */
static int read_latest_hash(sqlite3 *handle,
                            uint8_t previous[JG_AUDIT_HASH_SIZE],
                            bool *present)
{
    static const char query[] =
        "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, query, -1, 0U, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    *present = false;
    (void)memset(previous, 0, JG_AUDIT_HASH_SIZE);
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_ROW) {
            const void *stored = sqlite3_column_blob(statement, 0);

            if (stored == NULL ||
                sqlite3_column_bytes(statement, 0) != JG_AUDIT_HASH_SIZE) {
                result = -EILSEQ;
            } else {
                (void)memcpy(previous, stored, JG_AUDIT_HASH_SIZE);
                *present = true;
            }
        } else if (status != SQLITE_DONE) {
            result = jg_database_sqlite_result(status);
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

/** @brief Return the stable database spelling of an actor kind. */
static const char *actor_name(enum jg_audit_actor_type type)
{
    switch (type) {
    case JG_AUDIT_ACTOR_SYSTEM:
        return "system";
    case JG_AUDIT_ACTOR_USER:
        return "user";
    case JG_AUDIT_ACTOR_TOKEN:
        return "token";
    default:
        return NULL;
    }
}

/** @brief Bind one validated event and its chain digests for insertion. */
static int bind_insert(sqlite3_stmt *statement,
                       const struct jg_audit_event *event,
                       const struct audit_material *material,
                       const uint8_t previous[JG_AUDIT_HASH_SIZE],
                       bool has_previous,
                       const uint8_t digest[JG_AUDIT_HASH_SIZE])
{
    const char *actor = actor_name(event->actor_type);
    int status =
        sqlite3_bind_int64(statement, 1, (sqlite3_int64)event->occurred_at);

    if (status == SQLITE_OK) {
        status = sqlite3_bind_text(statement, 2, actor, -1, SQLITE_STATIC);
    }
    if (status == SQLITE_OK) {
        status = event->has_actor_id
                     ? sqlite3_bind_int64(statement, 3,
                                          (sqlite3_int64)event->actor_id)
                     : sqlite3_bind_null(statement, 3);
    }
    if (status == SQLITE_OK) {
        status =
            sqlite3_bind_text(statement, 4, event->action,
                              (int)material->action.size, SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_text(statement, 5, event->object_type,
                                   (int)material->object_type.size,
                                   SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = event->object_id != NULL
                     ? sqlite3_bind_text(statement, 6, event->object_id,
                                         (int)material->object_id.size,
                                         SQLITE_TRANSIENT)
                     : sqlite3_bind_null(statement, 6);
    }
    if (status == SQLITE_OK) {
        status =
            sqlite3_bind_text(statement, 7, event->details,
                              (int)material->details.size, SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = has_previous
                     ? sqlite3_bind_blob(statement, 8, previous,
                                         JG_AUDIT_HASH_SIZE, SQLITE_TRANSIENT)
                     : sqlite3_bind_null(statement, 8);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_blob(statement, 9, digest, JG_AUDIT_HASH_SIZE,
                                   SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status =
            sqlite3_bind_text(statement, 10, event->source,
                              (int)material->source.size, SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status =
            event->has_previous_revision
                ? sqlite3_bind_int64(statement, 11,
                                     (sqlite3_int64)event->previous_revision)
                : sqlite3_bind_null(statement, 11);
    }
    if (status == SQLITE_OK) {
        status = event->has_new_revision
                     ? sqlite3_bind_int64(statement, 12,
                                          (sqlite3_int64)event->new_revision)
                     : sqlite3_bind_null(statement, 12);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(statement, 13, event->success ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status =
            sqlite3_bind_text(statement, 14, event->request_id,
                              (int)material->request_id.size, SQLITE_TRANSIENT);
    }
    return jg_database_sqlite_result(status);
}

/** @brief Insert one validated audit event under an active transaction. */
static int insert_event(sqlite3 *handle,
                        const struct jg_audit_event *event,
                        const struct audit_material *material,
                        const uint8_t previous[JG_AUDIT_HASH_SIZE],
                        bool has_previous,
                        const uint8_t digest[JG_AUDIT_HASH_SIZE],
                        uint64_t *event_id)
{
    static const char insert[] =
        "INSERT INTO audit_events("
        "occurred_at,actor_type,actor_id,action,object_type,object_id,details,"
        "previous_hash,event_hash,source,previous_revision,new_revision,"
        "success,request_id) VALUES("
        "?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14);";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, insert, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        result = bind_insert(statement, event, material, previous, has_previous,
                             digest);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0) {
        const sqlite3_int64 identifier = sqlite3_last_insert_rowid(handle);

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
    return result;
}

/** @brief Append one event atomically to the persistent audit chain. */
int jg_database_audit_append(struct jg_database *database,
                             const struct jg_audit_event *event,
                             struct jg_audit_append_result *append_result)
{
    struct audit_material material;
    uint8_t previous[JG_AUDIT_HASH_SIZE];
    uint8_t digest[JG_AUDIT_HASH_SIZE];
    uint64_t event_id = 0U;
    bool has_previous = false;
    bool transaction = false;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    if (append_result != NULL) {
        (void)memset(append_result, 0, sizeof(*append_result));
    }
    result = event_material(event, &material);
    if (result == 0) {
        result = execute_statement(database->handle, "BEGIN IMMEDIATE;");
        transaction = result == 0;
    }
    if (result == 0) {
        result = read_latest_hash(database->handle, previous, &has_previous);
    }
    if (result == 0) {
        result = compute_event_hash(previous, &material, digest);
    }
    if (result == 0) {
        result = insert_event(database->handle, event, &material, previous,
                              has_previous, digest, &event_id);
    }
    if (result == 0) {
        result = execute_statement(database->handle, "COMMIT;");
        if (result == 0) {
            transaction = false;
        }
    }
    if (transaction) {
        (void)execute_statement(database->handle, "ROLLBACK;");
    }
    if (result == 0 && append_result != NULL) {
        append_result->event_id = event_id;
        (void)memcpy(append_result->previous_hash, previous, sizeof(previous));
        (void)memcpy(append_result->event_hash, digest, sizeof(digest));
    }
    sodium_memzero(digest, sizeof(digest));
    return result;
}

/** @brief Parse one stable actor name from SQLite text. */
static bool parse_actor(const struct audit_text *text,
                        enum jg_audit_actor_type *actor)
{
    if (text->size == sizeof("system") - 1U &&
        memcmp(text->data, "system", text->size) == 0) {
        *actor = JG_AUDIT_ACTOR_SYSTEM;
        return true;
    }
    if (text->size == sizeof("user") - 1U &&
        memcmp(text->data, "user", text->size) == 0) {
        *actor = JG_AUDIT_ACTOR_USER;
        return true;
    }
    if (text->size == sizeof("token") - 1U &&
        memcmp(text->data, "token", text->size) == 0) {
        *actor = JG_AUDIT_ACTOR_TOKEN;
        return true;
    }
    return false;
}

/** @brief Read one required or optional SQLite text value as raw bytes. */
static bool read_text(sqlite3_stmt *statement,
                      int column,
                      bool optional,
                      struct audit_text *text)
{
    const int type = sqlite3_column_type(statement, column);

    if (type == SQLITE_NULL && optional) {
        text->data = NULL;
        text->size = 0U;
        text->present = false;
        return true;
    }
    if (type != SQLITE_TEXT) {
        return false;
    }
    text->data = sqlite3_column_text(statement, column);
    text->size = (size_t)sqlite3_column_bytes(statement, column);
    text->present = true;
    return text->data != NULL;
}

/** @brief Read one nonnegative required SQLite integer. */
static bool read_u64(sqlite3_stmt *statement, int column, uint64_t *value)
{
    const sqlite3_int64 stored = sqlite3_column_int64(statement, column);

    if (sqlite3_column_type(statement, column) != SQLITE_INTEGER ||
        stored < 0) {
        return false;
    }
    *value = (uint64_t)stored;
    return true;
}

/** @brief Read one positive optional SQLite integer. */
static bool read_optional_u64(sqlite3_stmt *statement,
                              int column,
                              bool *present,
                              uint64_t *value)
{
    if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
        *present = false;
        *value = 0U;
        return true;
    }
    *present = true;
    return read_u64(statement, column, value) && *value > 0U;
}

/** @brief Check bounded text and actor semantics loaded from SQLite. */
static bool stored_material_valid(const struct audit_material *material)
{
    return actor_valid(material->actor_type, material->has_actor_id,
                       material->actor_id) &&
           material->source.present && material->source.size >= 1U &&
           material->source.size <= JG_AUDIT_SOURCE_MAX &&
           material->action.present && material->action.size >= 1U &&
           material->action.size <= JG_AUDIT_ACTION_MAX &&
           material->object_type.present && material->object_type.size >= 1U &&
           material->object_type.size <= JG_AUDIT_OBJECT_TYPE_MAX &&
           (!material->object_id.present ||
            (material->object_id.size >= 1U &&
             material->object_id.size <= JG_AUDIT_OBJECT_ID_MAX)) &&
           material->details.present &&
           material->details.size <= JG_AUDIT_DETAILS_MAX &&
           material->request_id.present &&
           material->request_id.size <= JG_AUDIT_REQUEST_ID_MAX;
}

/** @brief Decode one selected audit row into its canonical material. */
static bool read_material(sqlite3_stmt *statement,
                          uint64_t *event_id,
                          struct audit_material *material)
{
    struct audit_text actor;
    uint64_t success = 0U;

    (void)memset(material, 0, sizeof(*material));
    if (!read_u64(statement, 0, event_id) || *event_id == 0U ||
        !read_u64(statement, 1, &material->occurred_at) ||
        !read_text(statement, 2, false, &actor) ||
        !parse_actor(&actor, &material->actor_type) ||
        !read_optional_u64(statement, 3, &material->has_actor_id,
                           &material->actor_id) ||
        !read_text(statement, 4, false, &material->action) ||
        !read_text(statement, 5, false, &material->object_type) ||
        !read_text(statement, 6, true, &material->object_id) ||
        !read_text(statement, 7, false, &material->details) ||
        !read_text(statement, 10, false, &material->source) ||
        !read_optional_u64(statement, 11, &material->has_previous_revision,
                           &material->previous_revision) ||
        !read_optional_u64(statement, 12, &material->has_new_revision,
                           &material->new_revision) ||
        !read_u64(statement, 13, &success) || success > 1U ||
        !read_text(statement, 14, false, &material->request_id)) {
        return false;
    }
    material->success = success != 0U;
    return stored_material_valid(material);
}

/** @brief Validate one row's stored links against its computed digest. */
static int verify_row(sqlite3_stmt *statement,
                      bool first,
                      const uint8_t previous[JG_AUDIT_HASH_SIZE],
                      uint8_t next[JG_AUDIT_HASH_SIZE],
                      uint64_t *event_id,
                      bool *valid)
{
    struct audit_material material;
    uint8_t computed[JG_AUDIT_HASH_SIZE];
    const void *stored_previous = sqlite3_column_blob(statement, 8);
    const void *stored_event = sqlite3_column_blob(statement, 9);
    int result = 0;

    *event_id = 0U;
    *valid = read_material(statement, event_id, &material);
    if (*valid) {
        if (first) {
            *valid = sqlite3_column_type(statement, 8) == SQLITE_NULL;
        } else {
            *valid = stored_previous != NULL &&
                     sqlite3_column_bytes(statement, 8) == JG_AUDIT_HASH_SIZE &&
                     sodium_memcmp(stored_previous, previous,
                                   JG_AUDIT_HASH_SIZE) == 0;
        }
    }
    if (*valid) {
        *valid = stored_event != NULL &&
                 sqlite3_column_bytes(statement, 9) == JG_AUDIT_HASH_SIZE;
    }
    if (*valid) {
        result = compute_event_hash(previous, &material, computed);
        if (result == 0) {
            *valid =
                sodium_memcmp(stored_event, computed, JG_AUDIT_HASH_SIZE) == 0;
        }
    }
    if (result == 0 && *valid) {
        (void)memcpy(next, stored_event, JG_AUDIT_HASH_SIZE);
    }
    sodium_memzero(computed, sizeof(computed));
    return result;
}

/** @brief Verify every record and link in the persistent audit chain. */
int jg_database_audit_verify(struct jg_database *database,
                             struct jg_audit_verification *verification)
{
    static const char query[] =
        "SELECT id,occurred_at,actor_type,actor_id,action,object_type,"
        "object_id,details,previous_hash,event_hash,source,previous_revision,"
        "new_revision,success,request_id FROM audit_events ORDER BY id;";
    sqlite3_stmt *statement = NULL;
    uint8_t previous[JG_AUDIT_HASH_SIZE] = {0};
    uint8_t next[JG_AUDIT_HASH_SIZE];
    uint64_t event_id = 0U;
    bool first = true;
    bool valid = true;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || verification == NULL) {
        return -EINVAL;
    }
    (void)memset(verification, 0, sizeof(*verification));
    verification->valid = true;
    status =
        sqlite3_prepare_v3(database->handle, query, -1, 0U, &statement, NULL);
    result = jg_database_sqlite_result(status);
    while (result == 0 && verification->valid &&
           (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (verification->records_inspected == UINT64_MAX) {
            result = -EOVERFLOW;
            break;
        }
        ++verification->records_inspected;
        result =
            verify_row(statement, first, previous, next, &event_id, &valid);
        if (result == 0 && !valid) {
            verification->valid = false;
            verification->first_invalid_id = event_id;
        } else if (result == 0) {
            (void)memcpy(previous, next, sizeof(previous));
            first = false;
        }
    }
    if (result == 0 && verification->valid && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    sodium_memzero(previous, sizeof(previous));
    sodium_memzero(next, sizeof(next));
    return result;
}
