/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/database.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sqlite3.h>

#include "database_internal.h"
#include "janusgate/checked.h"

/** @brief Return the persistent text for one enforcement mode. */
static const char *enforcement_text(enum jg_policy_enforcement enforcement)
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

/** @brief Decode one persistent enforcement mode. */
static int decode_enforcement(const char *text,
                              enum jg_policy_enforcement *enforcement)
{
    if (strcmp(text, "enforce") == 0) {
        *enforcement = JG_POLICY_ENFORCE;
        return 0;
    }
    if (strcmp(text, "observe") == 0) {
        *enforcement = JG_POLICY_OBSERVE;
        return 0;
    }
    return -EILSEQ;
}

/** @brief Return the persistent text for a non-global client scope. */
static const char *scope_text(enum jg_policy_scope_type type)
{
    switch (type) {
    case JG_POLICY_SCOPE_MAC:
        return "mac";
    case JG_POLICY_SCOPE_IPV4:
        return "ipv4";
    case JG_POLICY_SCOPE_IPV6:
        return "ipv6";
    case JG_POLICY_SCOPE_VLAN:
        return "vlan";
    case JG_POLICY_SCOPE_GLOBAL:
    default:
        return NULL;
    }
}

/** @brief Validate a bounded human-readable policy selector name. */
static int validate_name(const char *name)
{
    size_t length = 0U;

    if (name == NULL) {
        return -EINVAL;
    }
    while (length <= JG_DATABASE_POLICY_NAME_MAX && name[length] != '\0') {
        ++length;
    }
    if (length == 0U || length > JG_DATABASE_POLICY_NAME_MAX ||
        !jg_utf8_text_valid((const uint8_t *)name, length, false)) {
        return -EINVAL;
    }
    return 0;
}

/** @brief Validate and canonicalize one policy scope-mode configuration. */
static int normalize_config(
    const struct jg_database_policy_scope_mode_config *input,
    struct jg_database_policy_scope_mode_config *output)
{
    int result = 0;

    if (input == NULL || output == NULL ||
        enforcement_text(input->enforcement) == NULL ||
        input->scope.type == JG_POLICY_SCOPE_GLOBAL) {
        return -EINVAL;
    }
    result = validate_name(input->name);
    if (result == 0) {
        *output = *input;
        result = jg_policy_scope_normalize(&input->scope, &output->scope);
    }
    return result;
}

/** @brief Bind one canonical non-global policy scope. */
static int bind_scope(sqlite3_stmt *statement,
                      const struct jg_policy_scope *scope)
{
    const char *type = scope_text(scope->type);
    int status = SQLITE_OK;

    if (type == NULL) {
        return -EINVAL;
    }
    status = sqlite3_bind_text(statement, 3, type, -1, SQLITE_STATIC);
    if (status != SQLITE_OK) {
        return jg_database_sqlite_result(status);
    }
    switch (scope->type) {
    case JG_POLICY_SCOPE_MAC:
        status = sqlite3_bind_blob(statement, 4, scope->value.mac, 6,
                                   SQLITE_TRANSIENT);
        break;
    case JG_POLICY_SCOPE_IPV4:
    case JG_POLICY_SCOPE_IPV6:
        status = sqlite3_bind_blob(statement, 4, scope->value.network.address,
                                   scope->type == JG_POLICY_SCOPE_IPV4 ? 4 : 16,
                                   SQLITE_TRANSIENT);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, 5,
                                      scope->value.network.prefix_length);
        }
        break;
    case JG_POLICY_SCOPE_VLAN:
        status = sqlite3_bind_int(statement, 6, scope->value.vlan_id);
        break;
    case JG_POLICY_SCOPE_GLOBAL:
    default:
        return -EINVAL;
    }
    return jg_database_sqlite_result(status);
}

/** @brief Bind one validated policy scope-mode configuration. */
static int bind_config(
    sqlite3_stmt *statement,
    const struct jg_database_policy_scope_mode_config *config)
{
    int status =
        sqlite3_bind_text(statement, 1, config->name, -1, SQLITE_TRANSIENT);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_text(statement, 2,
                                   enforcement_text(config->enforcement), -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_scope(statement, &config->scope);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 7, config->enabled ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    return result;
}

/** @brief Decode one strict non-global scope from a selected row. */
static int decode_scope(sqlite3_stmt *statement,
                        const char *type,
                        struct jg_policy_scope *scope)
{
    const void *value = sqlite3_column_blob(statement, 4);
    const int value_size = sqlite3_column_bytes(statement, 4);
    struct jg_policy_scope canonical;

    (void)memset(scope, 0, sizeof(*scope));
    if (strcmp(type, "mac") == 0 && value != NULL && value_size == 6 &&
        sqlite3_column_type(statement, 5) == SQLITE_NULL &&
        sqlite3_column_type(statement, 6) == SQLITE_NULL) {
        scope->type = JG_POLICY_SCOPE_MAC;
        (void)memcpy(scope->value.mac, value, 6U);
        return 0;
    }
    if ((strcmp(type, "ipv4") == 0 || strcmp(type, "ipv6") == 0) &&
        value != NULL && value_size == (strcmp(type, "ipv4") == 0 ? 4 : 16) &&
        sqlite3_column_type(statement, 5) == SQLITE_INTEGER &&
        sqlite3_column_type(statement, 6) == SQLITE_NULL) {
        const int prefix = sqlite3_column_int(statement, 5);
        const int maximum = value_size == 4 ? 32 : 128;

        if (prefix >= 0 && prefix <= maximum) {
            scope->type =
                value_size == 4 ? JG_POLICY_SCOPE_IPV4 : JG_POLICY_SCOPE_IPV6;
            (void)memcpy(scope->value.network.address, value,
                         (size_t)value_size);
            scope->value.network.prefix_length = (uint8_t)prefix;
            if (jg_policy_scope_normalize(scope, &canonical) == 0 &&
                memcmp(canonical.value.network.address,
                       scope->value.network.address, (size_t)value_size) == 0) {
                return 0;
            }
        }
    }
    if (strcmp(type, "vlan") == 0 &&
        sqlite3_column_type(statement, 4) == SQLITE_NULL &&
        sqlite3_column_type(statement, 5) == SQLITE_NULL &&
        sqlite3_column_type(statement, 6) == SQLITE_INTEGER) {
        const int vlan_id = sqlite3_column_int(statement, 6);

        if (vlan_id >= 0 && vlan_id <= 4094) {
            scope->type = JG_POLICY_SCOPE_VLAN;
            scope->value.vlan_id = (uint16_t)vlan_id;
            return 0;
        }
    }
    return -EILSEQ;
}

/** @brief Decode one complete persistent scope-mode record. */
static int decode_mode(sqlite3_stmt *statement,
                       struct jg_database_policy_scope_mode *mode)
{
    const char *name = NULL;
    const char *enforcement = NULL;
    const char *scope = NULL;
    size_t name_length = 0U;
    size_t text_length = 0U;
    uint64_t identifier = 0U;
    uint64_t revision = 0U;
    uint64_t created_at = 0U;
    uint64_t updated_at = 0U;
    int enabled = 0;
    int result = 0;

    (void)memset(mode, 0, sizeof(*mode));
    result = jg_database_column_unsigned(statement, 0, &identifier);
    if (result == 0 && identifier == 0U) {
        result = -EILSEQ;
    }
    if (result == 0) {
        result =
            jg_database_column_required_text(statement, 1, &name, &name_length);
    }
    if (result == 0 &&
        (name_length == 0U || name_length > JG_DATABASE_POLICY_NAME_MAX ||
         !jg_utf8_text_valid((const uint8_t *)name, name_length, false))) {
        result = -EILSEQ;
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 2, &enforcement,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_enforcement(enforcement, &mode->enforcement);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 3, &scope,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_scope(statement, scope, &mode->scope);
    }
    if (result == 0 && sqlite3_column_type(statement, 7) != SQLITE_INTEGER) {
        result = -EILSEQ;
    }
    if (result == 0) {
        enabled = sqlite3_column_int(statement, 7);
        if (enabled != 0 && enabled != 1) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 8, &revision);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 9, &created_at);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 10, &updated_at);
    }
    if (result == 0 && (revision == 0U || updated_at < created_at)) {
        result = -EILSEQ;
    }
    if (result == 0) {
        mode->id = identifier;
        mode->revision = revision;
        mode->created_at = created_at;
        mode->updated_at = updated_at;
        mode->enabled = enabled != 0;
        (void)memcpy(mode->name, name, name_length);
        mode->name[name_length] = '\0';
    }
    return result;
}

/** @brief Load snapshot-wide policy enforcement. */
int jg_database_load_policy_config(struct jg_database *database,
                                   struct jg_database_policy_config *config)
{
    static const char query[] =
        "SELECT enforcement,revision,updated_at FROM policy_configuration "
        "WHERE id=1;";
    struct jg_database_policy_config loaded;
    sqlite3_stmt *statement = NULL;
    const char *enforcement = NULL;
    size_t text_length = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || config == NULL) {
        return -EINVAL;
    }
    (void)memset(&loaded, 0, sizeof(loaded));
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_ROW ? 0 : jg_database_sqlite_result(status);
        if (status == SQLITE_DONE) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 0, &enforcement,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_enforcement(enforcement, &loaded.enforcement);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 1, &loaded.revision);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 2, &loaded.updated_at);
    }
    if (result == 0 && loaded.revision == 0U) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *config = loaded;
    }
    return result;
}

/** @brief Replace snapshot-wide policy enforcement optimistically. */
int jg_database_replace_policy_config(struct jg_database *database,
                                      enum jg_policy_enforcement enforcement,
                                      uint64_t expected_revision,
                                      struct jg_database_policy_config *updated)
{
    static const char update[] =
        "UPDATE policy_configuration SET enforcement=?1,"
        "revision=revision+1,updated_at=unixepoch() WHERE id=1 AND revision=?2 "
        "AND revision<9223372036854775807;";
    static const char revision_query[] =
        "SELECT revision FROM policy_configuration WHERE id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || enforcement_text(enforcement) == NULL ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX ||
        updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    status = sqlite3_prepare_v3(database->handle, update, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, enforcement_text(enforcement),
                                   -1, SQLITE_STATIC);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_write_conflict(database->handle, revision_query,
                                            1U, expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = jg_database_load_policy_config(database, updated);
    }
    return result;
}

/** @brief List one stable page of persistent policy scope modes. */
int jg_database_list_policy_scope_modes(
    struct jg_database *database,
    uint64_t after_id,
    size_t limit,
    struct jg_database_policy_scope_mode *modes,
    size_t *count,
    bool *has_more)
{
    static const char query[] =
        "SELECT id,name,enforcement,scope_type,scope_value,prefix_length,"
        "vlan_id,enabled,revision,created_at,updated_at FROM "
        "policy_scope_modes WHERE id>?1 ORDER BY id LIMIT ?2;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    bool more = false;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || after_id > (uint64_t)INT64_MAX || limit == 0U ||
        limit > JG_DATABASE_POLICY_PAGE_MAX || modes == NULL || count == NULL ||
        has_more == NULL) {
        return -EINVAL;
    }
    *count = 0U;
    *has_more = false;
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)after_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, 2, (int)(limit + 1U));
        }
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (index == limit) {
            more = true;
            break;
        }
        result = decode_mode(statement, &modes[index]);
        if (result == 0) {
            ++index;
        }
    }
    if (result == 0 && !more && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *count = index;
        *has_more = more;
    }
    return result;
}

/** @brief Read one policy scope mode by exact identifier. */
static int read_mode(struct jg_database *database,
                     uint64_t mode_id,
                     struct jg_database_policy_scope_mode *mode)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_policy_scope_modes(database, mode_id - 1U, 1U,
                                                     mode, &count, &has_more);

    (void)has_more;
    if (result == 0 && (count != 1U || mode->id != mode_id)) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Create one persistent client or VLAN policy mode. */
int jg_database_create_policy_scope_mode(
    struct jg_database *database,
    const struct jg_database_policy_scope_mode_config *config,
    struct jg_database_policy_scope_mode *created)
{
    static const char insert[] =
        "INSERT INTO policy_scope_modes(name,enforcement,scope_type,"
        "scope_value,prefix_length,vlan_id,enabled,revision,created_at,"
        "updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,1,unixepoch(),unixepoch());";
    struct jg_database_policy_scope_mode_config canonical;
    struct jg_database_policy_scope_mode record;
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 identifier = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || created == NULL) {
        return -EINVAL;
    }
    (void)memset(created, 0, sizeof(*created));
    result = normalize_config(config, &canonical);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_config(statement, &canonical);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result =
            status == SQLITE_CONSTRAINT_UNIQUE
                ? -EEXIST
                : (status == SQLITE_DONE ? 0
                                         : jg_database_sqlite_result(status));
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        identifier = sqlite3_last_insert_rowid(database->handle);
        result = identifier > 0
                     ? read_mode(database, (uint64_t)identifier, &record)
                     : -EIO;
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        *created = record;
    }
    return result;
}

/** @brief Replace one policy scope mode optimistically. */
int jg_database_update_policy_scope_mode(
    struct jg_database *database,
    uint64_t mode_id,
    const struct jg_database_policy_scope_mode_config *config,
    uint64_t expected_revision,
    struct jg_database_policy_scope_mode *updated)
{
    static const char update[] =
        "UPDATE policy_scope_modes SET name=?1,enforcement=?2,scope_type=?3,"
        "scope_value=?4,prefix_length=?5,vlan_id=?6,enabled=?7,"
        "revision=revision+1,updated_at=unixepoch() WHERE id=?8 AND "
        "revision=?9 AND revision<9223372036854775807;";
    static const char revision_query[] =
        "SELECT revision FROM policy_scope_modes WHERE id=?1;";
    struct jg_database_policy_scope_mode_config canonical;
    struct jg_database_policy_scope_mode record;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || mode_id == 0U || mode_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX ||
        updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result = normalize_config(config, &canonical);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_config(statement, &canonical);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 8, (sqlite3_int64)mode_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 9,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result =
            status == SQLITE_CONSTRAINT_UNIQUE
                ? -EEXIST
                : (status == SQLITE_DONE ? 0
                                         : jg_database_sqlite_result(status));
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_write_conflict(database->handle, revision_query,
                                            mode_id, expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = read_mode(database, mode_id, &record);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        *updated = record;
    }
    return result;
}

/** @brief Delete one policy scope mode optimistically. */
int jg_database_delete_policy_scope_mode(struct jg_database *database,
                                         uint64_t mode_id,
                                         uint64_t expected_revision)
{
    static const char remove[] =
        "DELETE FROM policy_scope_modes WHERE id=?1 AND revision=?2;";
    static const char revision_query[] =
        "SELECT revision FROM policy_scope_modes WHERE id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || mode_id == 0U || mode_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin(database);
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, remove, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)mode_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_write_conflict(database->handle, revision_query,
                                            mode_id, expected_revision, false);
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
