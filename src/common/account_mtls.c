/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/account.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sqlite3.h>

#include "account_internal.h"
#include "database_internal.h"

/** @brief Check one bounded certificate distinguished name. */
static bool certificate_name_valid(const char *name)
{
    size_t length = 0U;

    if (name == NULL || name[0U] == '\0') {
        return false;
    }
    while (length <= JG_CERTIFICATE_NAME_MAX && name[length] != '\0') {
        ++length;
    }
    return length > 0U && length <= JG_CERTIFICATE_NAME_MAX;
}

/** @brief Validate a client-certificate mapping before persistence. */
static int mtls_mapping_config_validate(
    const struct jg_account_mtls_mapping_config *config)
{
    const bool maps_user = config != NULL && config->user_id != 0U;
    const bool maps_role =
        config != NULL && config->role != JG_ACCESS_ROLE_NONE;

    if (config == NULL || maps_user == maps_role ||
        (maps_user && config->user_id > (uint64_t)INT64_MAX) ||
        (maps_role && !jg_account_role_valid(config->role)) ||
        !certificate_name_valid(config->subject) ||
        !certificate_name_valid(config->issuer) || config->not_before == 0U ||
        config->not_after < config->not_before ||
        config->not_after > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    return 0;
}

/** @brief Return whether one persistent user identifier exists. */
static int user_identifier_exists(sqlite3 *handle,
                                  uint64_t user_id,
                                  bool *exists)
{
    static const char query[] =
        "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1);";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    *exists = false;
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW ||
            sqlite3_column_type(statement, 0) != SQLITE_INTEGER) {
            result = status == SQLITE_ROW ? -EILSEQ
                                          : jg_database_sqlite_result(status);
        } else {
            *exists = sqlite3_column_int(statement, 0) != 0;
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

/** @brief Decode one safe client-certificate mapping row. */
static int decode_mtls_mapping_row(sqlite3_stmt *statement,
                                   struct jg_account_mtls_mapping *mapping)
{
    const sqlite3_int64 mapping_id = sqlite3_column_int64(statement, 0);
    const void *fingerprint = sqlite3_column_blob(statement, 1);
    const sqlite3_int64 user_id = sqlite3_column_int64(statement, 2);
    const char *username = (const char *)sqlite3_column_text(statement, 3);
    const sqlite3_int64 role_id = sqlite3_column_int64(statement, 4);
    const sqlite3_int64 created_at = sqlite3_column_int64(statement, 5);
    const char *subject = (const char *)sqlite3_column_text(statement, 6);
    const char *issuer = (const char *)sqlite3_column_text(statement, 7);
    const sqlite3_int64 not_before = sqlite3_column_int64(statement, 8);
    const sqlite3_int64 not_after = sqlite3_column_int64(statement, 9);
    const sqlite3_int64 revoked_at = sqlite3_column_int64(statement, 10);
    const sqlite3_int64 revision = sqlite3_column_int64(statement, 11);
    const int enabled = sqlite3_column_int(statement, 12);
    const bool maps_user = sqlite3_column_type(statement, 2) == SQLITE_INTEGER;
    const bool maps_role = sqlite3_column_type(statement, 4) == SQLITE_INTEGER;
    const bool revoked = sqlite3_column_type(statement, 10) == SQLITE_INTEGER;
    const int username_size = sqlite3_column_bytes(statement, 3);
    const int subject_size = sqlite3_column_bytes(statement, 6);
    const int issuer_size = sqlite3_column_bytes(statement, 7);
    enum jg_access_role role = JG_ACCESS_ROLE_NONE;

    if (mapping == NULL || mapping_id <= 0 || fingerprint == NULL ||
        sqlite3_column_bytes(statement, 1) != 32 || maps_user == maps_role ||
        created_at < 0 || subject == NULL || subject_size < 0 ||
        subject_size > (int)JG_CERTIFICATE_NAME_MAX || issuer == NULL ||
        issuer_size < 0 || issuer_size > (int)JG_CERTIFICATE_NAME_MAX ||
        not_before < 0 || not_after < not_before || revision <= 0 ||
        sqlite3_column_type(statement, 12) != SQLITE_INTEGER ||
        (enabled != 0 && enabled != 1) || (enabled == 1 && revoked) ||
        (enabled == 0 && !revoked) || (revoked && revoked_at < created_at)) {
        return -EILSEQ;
    }
    if (maps_user && (user_id <= 0 || username == NULL || username_size <= 0 ||
                      username_size > (int)JG_ACCOUNT_USERNAME_MAX)) {
        return -EILSEQ;
    }
    if (maps_role) {
        role = jg_account_role_from_id(role_id);
        if (role == JG_ACCESS_ROLE_NONE) {
            return -EILSEQ;
        }
    }
    (void)memset(mapping, 0, sizeof(*mapping));
    mapping->mapping_id = (uint64_t)mapping_id;
    mapping->user_id = maps_user ? (uint64_t)user_id : 0U;
    mapping->role = role;
    mapping->revision = (uint64_t)revision;
    mapping->created_at = (uint64_t)created_at;
    mapping->not_before = (uint64_t)not_before;
    mapping->not_after = (uint64_t)not_after;
    mapping->revoked_at = revoked ? (uint64_t)revoked_at : 0U;
    (void)memcpy(mapping->fingerprint_sha256, fingerprint,
                 sizeof(mapping->fingerprint_sha256));
    (void)memcpy(mapping->subject, subject, (size_t)subject_size);
    mapping->subject[(size_t)subject_size] = '\0';
    (void)memcpy(mapping->issuer, issuer, (size_t)issuer_size);
    mapping->issuer[(size_t)issuer_size] = '\0';
    if (maps_user) {
        (void)memcpy(mapping->username, username, (size_t)username_size);
        mapping->username[(size_t)username_size] = '\0';
        if (!jg_account_username_valid(mapping->username)) {
            (void)memset(mapping, 0, sizeof(*mapping));
            return -EILSEQ;
        }
    }
    return 0;
}

/** @brief Read one client-certificate mapping with a prepared query. */
static int load_mtls_mapping(sqlite3 *handle,
                             uint64_t mapping_id,
                             struct jg_account_mtls_mapping *mapping)
{
    static const char query[] =
        "SELECT m.id,m.fingerprint_sha256,m.user_id,u.username,m.role_id,"
        "m.created_at,m.subject,m.issuer,m.not_before,m.not_after,"
        "m.revoked_at,m.revision,m.enabled FROM mtls_mappings m"
        " LEFT JOIN users u ON u.id=m.user_id WHERE m.id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)mapping_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_ROW) {
            result = decode_mtls_mapping_row(statement, mapping);
        } else {
            result = status == SQLITE_DONE ? -ENOENT
                                           : jg_database_sqlite_result(status);
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

/** @brief Create one current client-certificate identity mapping. */
int jg_account_mtls_mapping_create(
    struct jg_database *database,
    const struct jg_account_mtls_mapping_config *config,
    uint64_t now,
    struct jg_account_mtls_mapping *mapping)
{
    static const char insert[] =
        "INSERT INTO mtls_mappings(fingerprint_sha256,user_id,role_id,enabled,"
        "created_at,subject,issuer,not_before,not_after,revision)"
        " VALUES(?1,?2,?3,1,?4,?5,?6,?7,?8,1);";
    sqlite3_stmt *statement = NULL;
    bool user_exists = false;
    int status = SQLITE_OK;
    int result = 0;

    if (mapping != NULL) {
        (void)memset(mapping, 0, sizeof(*mapping));
    }
    if (database == NULL || mapping == NULL || now == 0U ||
        now > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = mtls_mapping_config_validate(config);
    if (result == 0 && (config->not_before > now || config->not_after < now)) {
        result = -EACCES;
    }
    if (result == 0 && config->user_id != 0U) {
        result = user_identifier_exists(database->handle, config->user_id,
                                        &user_exists);
        if (result == 0 && !user_exists) {
            result = -ENOENT;
        }
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_blob(statement, 1, config->fingerprint_sha256, 32,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && config->user_id != 0U) {
        status =
            sqlite3_bind_int64(statement, 2, (sqlite3_int64)config->user_id);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        result = jg_database_sqlite_result(sqlite3_bind_null(statement, 2));
    }
    if (result == 0 && config->role != JG_ACCESS_ROLE_NONE) {
        status = sqlite3_bind_int(statement, 3, (int)config->role);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        result = jg_database_sqlite_result(sqlite3_bind_null(statement, 3));
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 4, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 5, config->subject, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 6, config->issuer, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int64(statement, 7, (sqlite3_int64)config->not_before);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int64(statement, 8, (sqlite3_int64)config->not_after);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = 0;
        } else if ((status & 0xff) == SQLITE_CONSTRAINT) {
            result = -EEXIST;
        } else {
            result = jg_database_sqlite_result(status);
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        const sqlite3_int64 identifier =
            sqlite3_last_insert_rowid(database->handle);

        result = identifier <= 0
                     ? -EIO
                     : load_mtls_mapping(database->handle, (uint64_t)identifier,
                                         mapping);
    }
    if (result != 0) {
        (void)memset(mapping, 0, sizeof(*mapping));
    }
    return result;
}

/** @brief Read one client-certificate mapping by identifier. */
int jg_account_mtls_mapping_get(struct jg_database *database,
                                uint64_t mapping_id,
                                struct jg_account_mtls_mapping *mapping)
{
    int result = 0;

    if (mapping != NULL) {
        (void)memset(mapping, 0, sizeof(*mapping));
    }
    if (database == NULL || mapping == NULL || mapping_id == 0U ||
        mapping_id > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = load_mtls_mapping(database->handle, mapping_id, mapping);
    if (result != 0) {
        (void)memset(mapping, 0, sizeof(*mapping));
    }
    return result;
}

/** @brief List one stable bounded page of client-certificate mappings. */
int jg_account_mtls_mapping_list(struct jg_database *database,
                                 uint64_t offset,
                                 struct jg_account_mtls_mapping *mappings,
                                 size_t capacity,
                                 size_t *count,
                                 uint64_t *total)
{
    static const char count_query[] = "SELECT count(*) FROM mtls_mappings;";
    static const char list_query[] =
        "SELECT m.id,m.fingerprint_sha256,m.user_id,u.username,m.role_id,"
        "m.created_at,m.subject,m.issuer,m.not_before,m.not_after,"
        "m.revoked_at,m.revision,m.enabled FROM mtls_mappings m"
        " LEFT JOIN users u ON u.id=m.user_id"
        " ORDER BY m.id LIMIT ?1 OFFSET ?2;";
    sqlite3_stmt *statement = NULL;
    bool transaction_open = false;
    size_t loaded = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (count != NULL) {
        *count = 0U;
    }
    if (total != NULL) {
        *total = 0U;
    }
    if (database == NULL || mappings == NULL || count == NULL ||
        total == NULL || capacity == 0U ||
        capacity > JG_ACCOUNT_MTLS_PAGE_MAX || capacity > (size_t)INT64_MAX ||
        offset > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    (void)memset(mappings, 0, capacity * sizeof(*mappings));
    result = jg_database_transaction_begin_read(database);
    transaction_open = result == 0;
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, count_query, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW || sqlite3_column_int64(statement, 0) < 0) {
            result = status == SQLITE_ROW ? -EILSEQ
                                          : jg_database_sqlite_result(status);
        } else {
            *total = (uint64_t)sqlite3_column_int64(statement, 0);
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
            sqlite3_prepare_v3(database->handle, list_query, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)capacity);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)offset);
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (loaded >= capacity) {
            result = -EOVERFLOW;
        } else {
            result = decode_mtls_mapping_row(statement, &mappings[loaded]);
            if (result == 0) {
                ++loaded;
            }
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
        result = jg_database_transaction_commit(database);
        transaction_open = result != 0;
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
        (void)memset(mappings, 0, capacity * sizeof(*mappings));
        *total = 0U;
    } else {
        *count = loaded;
    }
    return result;
}

/** @brief Persist one idempotent client-certificate mapping revocation. */
int jg_account_mtls_mapping_revoke(struct jg_database *database,
                                   uint64_t mapping_id,
                                   uint64_t now)
{
    static const char update[] = "UPDATE mtls_mappings SET enabled=0,"
                                 "revoked_at=coalesce(revoked_at,?1),"
                                 "revision=CASE WHEN revoked_at IS NULL THEN "
                                 "revision+1 ELSE revision END"
                                 " WHERE id=?2;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || mapping_id == 0U ||
        mapping_id > (uint64_t)INT64_MAX || now == 0U ||
        now > (uint64_t)INT64_MAX) {
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
        status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)mapping_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = -ENOENT;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Authorize one token owner through a current mTLS mapping. */
int jg_account_mtls_mapping_authorize(struct jg_database *database,
                                      const uint8_t fingerprint_sha256[32U],
                                      uint64_t user_id,
                                      uint64_t now)
{
    static const char query[] =
        "SELECT EXISTS(SELECT 1 FROM mtls_mappings m"
        " WHERE m.fingerprint_sha256=?1 AND m.enabled=1"
        " AND m.revoked_at IS NULL AND m.not_before<=?2 AND m.not_after>=?2"
        " AND (m.user_id=?3 OR m.role_id IN"
        " (SELECT role_id FROM user_roles WHERE user_id=?3)));";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || fingerprint_sha256 == NULL || user_id == 0U ||
        user_id > (uint64_t)INT64_MAX || now == 0U ||
        now > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_blob(statement, 1, fingerprint_sha256, 32,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 3, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW ||
            sqlite3_column_type(statement, 0) != SQLITE_INTEGER) {
            result = status == SQLITE_ROW ? -EILSEQ
                                          : jg_database_sqlite_result(status);
        } else if (sqlite3_column_int(statement, 0) == 0) {
            result = -EACCES;
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
