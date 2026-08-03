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

/** @brief Return the persistent text for one backup kind. */
static const char *backup_kind_text(enum jg_backup_kind kind)
{
    switch (kind) {
    case JG_BACKUP_CONFIGURATION:
        return "configuration";
    case JG_BACKUP_FULL:
        return "full";
    }
    return NULL;
}

/** @brief Validate one bounded plain backup filename. */
static bool backup_filename_valid(const char *filename)
{
    const size_t length =
        filename == NULL ? 0U : strnlen(filename, JG_BACKUP_FILENAME_MAX + 1U);
    size_t index = 0U;

    if (length == 0U || length > JG_BACKUP_FILENAME_MAX ||
        filename[0U] == '.') {
        return false;
    }
    for (index = 0U; index < length; ++index) {
        const char character = filename[index];
        const bool valid = (character >= 'a' && character <= 'z') ||
                           (character >= 'A' && character <= 'Z') ||
                           (character >= '0' && character <= '9') ||
                           character == '-' || character == '_' ||
                           character == '.';

        if (!valid) {
            return false;
        }
    }
    return true;
}

/** @brief Decode one backup metadata row. */
static int decode_backup(sqlite3_stmt *statement,
                         struct jg_database_backup *backup)
{
    const char *kind = NULL;
    const char *filename = NULL;
    const void *checksum = NULL;
    size_t kind_size = 0U;
    size_t filename_size = 0U;
    uint64_t id = 0U;
    uint64_t created_at = 0U;
    uint64_t schema_version = 0U;
    uint64_t size_bytes = 0U;
    int result = jg_database_column_unsigned(statement, 0, &id);

    if (result == 0) {
        result = jg_database_column_unsigned(statement, 1, &created_at);
    }
    if (result == 0) {
        result =
            jg_database_column_required_text(statement, 2, &kind, &kind_size);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 3, &filename,
                                                  &filename_size);
    }
    if (result == 0 &&
        (sqlite3_column_type(statement, 4) != SQLITE_BLOB ||
         sqlite3_column_bytes(statement, 4) != (int)sizeof(backup->checksum))) {
        result = -EILSEQ;
    }
    if (result == 0) {
        checksum = sqlite3_column_blob(statement, 4);
        if (checksum == NULL) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 5, &schema_version);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 6, &size_bytes);
    }
    if (result == 0 && (id == 0U || kind_size == 0U ||
                        filename_size > JG_BACKUP_FILENAME_MAX ||
                        schema_version == 0U || schema_version > UINT32_MAX ||
                        size_bytes == 0U || size_bytes > SIZE_MAX)) {
        result = -EILSEQ;
    }
    if (result == 0) {
        if (strcmp(kind, "configuration") == 0) {
            backup->kind = JG_BACKUP_CONFIGURATION;
        } else if (strcmp(kind, "full") == 0) {
            backup->kind = JG_BACKUP_FULL;
        } else {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        (void)memcpy(backup->filename, filename, filename_size);
        backup->filename[filename_size] = '\0';
        if (!backup_filename_valid(backup->filename)) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        backup->id = id;
        backup->created_at = created_at;
        backup->schema_version = (uint32_t)schema_version;
        backup->size_bytes = (size_t)size_bytes;
        (void)memcpy(backup->checksum, checksum, sizeof(backup->checksum));
    }
    return result;
}

/** @brief Record one successfully stored backup archive. */
int jg_database_create_backup(struct jg_database *database,
                              const struct jg_database_backup *backup,
                              struct jg_database_backup *created)
{
    static const char query[] =
        "INSERT INTO backup_metadata(created_at,kind,path,checksum,"
        "schema_version,size_bytes) VALUES(?1,?2,?3,?4,?5,?6);";
    const char *kind = backup == NULL ? NULL : backup_kind_text(backup->kind);
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 identifier = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || backup == NULL || created == NULL ||
        backup->id != 0U || backup->created_at > (uint64_t)INT64_MAX ||
        kind == NULL || !backup_filename_valid(backup->filename) ||
        backup->schema_version == 0U || backup->size_bytes == 0U ||
        backup->size_bytes > (size_t)INT64_MAX) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status =
            sqlite3_bind_int64(statement, 1, (sqlite3_int64)backup->created_at);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 2, kind, -1, SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 3, backup->filename, -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_blob(statement, 4, backup->checksum,
                              (int)sizeof(backup->checksum), SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 5, backup->schema_version);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int64(statement, 6, (sqlite3_int64)backup->size_bytes);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        identifier = sqlite3_last_insert_rowid(database->handle);
        if (identifier <= 0) {
            result = -EOVERFLOW;
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *created = *backup;
        created->id = (uint64_t)identifier;
    }
    return result;
}

/** @brief Load one backup metadata record by identifier. */
int jg_database_load_backup(struct jg_database *database,
                            uint64_t backup_id,
                            struct jg_database_backup *backup)
{
    static const char query[] =
        "SELECT id,created_at,kind,path,checksum,schema_version,size_bytes "
        "FROM backup_metadata WHERE id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || backup_id == 0U ||
        backup_id > (uint64_t)INT64_MAX || backup == NULL) {
        return -EINVAL;
    }
    (void)memset(backup, 0, sizeof(*backup));
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)backup_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status == SQLITE_ROW) {
            result = decode_backup(statement, backup);
        } else {
            result = jg_database_sqlite_result(status);
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
    return result;
}

/** @brief Test whether one archive filename has persistent backup metadata. */
int jg_database_backup_filename_exists(struct jg_database *database,
                                       const char *filename,
                                       bool *exists)
{
    static const char query[] =
        "SELECT 1 FROM backup_metadata WHERE path=?1 LIMIT 1;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || !backup_filename_valid(filename) ||
        exists == NULL) {
        return -EINVAL;
    }
    *exists = false;
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status =
            sqlite3_bind_text(statement, 1, filename, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_ROW) {
            *exists = true;
        } else if (status != SQLITE_DONE) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0 && *exists && sqlite3_step(statement) != SQLITE_DONE) {
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

/** @brief Read one stable identifier-ordered backup metadata page. */
int jg_database_list_backups(struct jg_database *database,
                             uint64_t after_id,
                             size_t limit,
                             struct jg_database_backup *backups,
                             size_t *count,
                             bool *has_more)
{
    static const char query[] =
        "SELECT id,created_at,kind,path,checksum,schema_version,size_bytes "
        "FROM backup_metadata WHERE id>?1 ORDER BY id LIMIT ?2;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    bool more = false;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || after_id > (uint64_t)INT64_MAX || limit == 0U ||
        limit > JG_DATABASE_BACKUP_PAGE_MAX || backups == NULL ||
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
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 2, (int)(limit + 1U));
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (index == limit) {
            more = true;
            break;
        }
        result = decode_backup(statement, &backups[index]);
        ++index;
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
