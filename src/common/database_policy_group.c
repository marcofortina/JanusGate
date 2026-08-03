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

/** @brief Validate one bounded UTF-8 policy-group field. */
static int validate_text(const char *text, size_t maximum, bool allow_empty)
{
    size_t length = 0U;

    if (text == NULL) {
        return -EINVAL;
    }
    while (length <= maximum && text[length] != '\0') {
        ++length;
    }
    if (length > maximum || (!allow_empty && length == 0U) ||
        !jg_utf8_text_valid((const uint8_t *)text, length, allow_empty)) {
        return -EINVAL;
    }
    return 0;
}

/** @brief Validate one complete policy-group configuration. */
static int validate_config(const struct jg_database_policy_group_config *config)
{
    int result = 0;

    if (config == NULL || enforcement_text(config->enforcement) == NULL) {
        return -EINVAL;
    }
    result = validate_text(config->name, JG_DATABASE_POLICY_NAME_MAX, false);
    if (result == 0) {
        result = validate_text(config->description,
                               JG_DATABASE_POLICY_DESCRIPTION_MAX, true);
    }
    return result;
}

/** @brief Bind one validated policy-group configuration. */
static int bind_config(sqlite3_stmt *statement,
                       const struct jg_database_policy_group_config *config)
{
    int status =
        sqlite3_bind_text(statement, 1, config->name, -1, SQLITE_TRANSIENT);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_text(statement, 2, config->description, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 3,
                                   enforcement_text(config->enforcement), -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 4, config->enabled ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    return result;
}

/** @brief Decode one complete persistent policy-group record. */
static int decode_group(sqlite3_stmt *statement,
                        struct jg_database_policy_group *group)
{
    const char *name = NULL;
    const char *description = NULL;
    const char *enforcement = NULL;
    size_t name_length = 0U;
    size_t description_length = 0U;
    size_t text_length = 0U;
    uint64_t identifier = 0U;
    int enabled = 0;
    int result = 0;

    (void)memset(group, 0, sizeof(*group));
    result = jg_database_column_unsigned(statement, 0, &identifier);
    if (result == 0) {
        result =
            jg_database_column_required_text(statement, 1, &name, &name_length);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 2, &description,
                                                  &description_length);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 3, &enforcement,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_enforcement(enforcement, &group->enforcement);
    }
    if (result == 0 && sqlite3_column_type(statement, 4) != SQLITE_INTEGER) {
        result = -EILSEQ;
    }
    if (result == 0) {
        enabled = sqlite3_column_int(statement, 4);
        if (enabled != 0 && enabled != 1) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 5, &group->revision);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 6, &group->created_at);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 7, &group->updated_at);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 8,
                                             &group->domain_rule_count);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 9,
                                             &group->destination_rule_count);
    }
    if (result == 0 &&
        (identifier == 0U || group->revision == 0U ||
         group->updated_at < group->created_at || name_length == 0U ||
         name_length > JG_DATABASE_POLICY_NAME_MAX ||
         description_length > JG_DATABASE_POLICY_DESCRIPTION_MAX ||
         !jg_utf8_text_valid((const uint8_t *)name, name_length, false) ||
         !jg_utf8_text_valid((const uint8_t *)description, description_length,
                             true))) {
        result = -EILSEQ;
    }
    if (result == 0) {
        group->id = identifier;
        group->enabled = enabled != 0;
        (void)memcpy(group->name, name, name_length);
        group->name[name_length] = '\0';
        (void)memcpy(group->description, description, description_length);
        group->description[description_length] = '\0';
    }
    return result;
}

/** @brief Read one stable page of persistent policy groups. */
int jg_database_list_policy_groups(struct jg_database *database,
                                   uint64_t after_id,
                                   size_t limit,
                                   struct jg_database_policy_group *groups,
                                   size_t *count,
                                   bool *has_more)
{
    static const char query[] =
        "SELECT g.id,g.name,g.description,g.enforcement,g.enabled,g.revision,"
        "g.created_at,g.updated_at,(SELECT count(*) FROM domain_rules AS d "
        "WHERE d.group_id=g.id),(SELECT count(*) FROM destination_rules AS r "
        "WHERE r.group_id=g.id) FROM policy_groups AS g WHERE g.id>?1 "
        "ORDER BY g.id LIMIT ?2;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    bool more = false;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || after_id > (uint64_t)INT64_MAX || limit == 0U ||
        limit > JG_DATABASE_POLICY_PAGE_MAX || groups == NULL ||
        count == NULL || has_more == NULL) {
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
        result = decode_group(statement, &groups[index]);
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

/** @brief Read one policy group by exact identifier. */
static int read_group(struct jg_database *database,
                      uint64_t group_id,
                      struct jg_database_policy_group *group)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_policy_groups(database, group_id - 1U, 1U,
                                                group, &count, &has_more);

    (void)has_more;
    if (result == 0 && (count != 1U || group->id != group_id)) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Create one persistent policy group. */
int jg_database_create_policy_group(
    struct jg_database *database,
    const struct jg_database_policy_group_config *config,
    struct jg_database_policy_group *created)
{
    static const char insert[] =
        "INSERT INTO policy_groups(name,description,enforcement,enabled,"
        "revision,created_at,updated_at) VALUES(?1,?2,?3,?4,1,unixepoch(),"
        "unixepoch());";
    struct jg_database_policy_group record;
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 identifier = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || created == NULL) {
        return -EINVAL;
    }
    (void)memset(created, 0, sizeof(*created));
    result = validate_config(config);
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
        result = bind_config(statement, config);
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
                     ? read_group(database, (uint64_t)identifier, &record)
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

/** @brief Replace one persistent policy group optimistically. */
int jg_database_update_policy_group(
    struct jg_database *database,
    uint64_t group_id,
    const struct jg_database_policy_group_config *config,
    uint64_t expected_revision,
    struct jg_database_policy_group *updated)
{
    static const char update[] =
        "UPDATE policy_groups SET name=?1,description=?2,enforcement=?3,"
        "enabled=?4,revision=revision+1,updated_at=unixepoch() WHERE id=?5 AND "
        "revision=?6 AND revision<9223372036854775807;";
    static const char revision_query[] =
        "SELECT revision FROM policy_groups WHERE id=?1;";
    struct jg_database_policy_group record;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || group_id == 0U || group_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX ||
        updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result = validate_config(config);
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
        result = bind_config(statement, config);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 5, (sqlite3_int64)group_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 6,
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
                                            group_id, expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = read_group(database, group_id, &record);
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

/** @brief Delete one persistent policy group optimistically. */
int jg_database_delete_policy_group(struct jg_database *database,
                                    uint64_t group_id,
                                    uint64_t expected_revision)
{
    static const char remove[] =
        "DELETE FROM policy_groups WHERE id=?1 AND revision=?2;";
    static const char revision_query[] =
        "SELECT revision FROM policy_groups WHERE id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || group_id == 0U || group_id > (uint64_t)INT64_MAX ||
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
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)group_id);
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
                                            group_id, expected_revision, false);
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
