/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/account.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sodium.h>
#include <sqlite3.h>

#include "database_internal.h"

/** Administrator role identifier inserted by the initial schema. */
#define ADMINISTRATOR_ROLE_ID 1

/** @brief Execute one fixed transaction-control statement. */
static int execute_fixed(sqlite3 *handle, const char *sql)
{
    return jg_database_sqlite_result(
        sqlite3_exec(handle, sql, NULL, NULL, NULL));
}

/** @brief Validate one conservative ASCII local username. */
static bool username_valid(const char *username)
{
    size_t length = 0U;

    if (username == NULL || !((username[0U] >= 'A' && username[0U] <= 'Z') ||
                              (username[0U] >= 'a' && username[0U] <= 'z') ||
                              (username[0U] >= '0' && username[0U] <= '9'))) {
        return false;
    }
    while (length <= JG_ACCOUNT_USERNAME_MAX && username[length] != '\0') {
        const char character = username[length];

        if (!((character >= 'A' && character <= 'Z') ||
              (character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') || character == '.' ||
              character == '_' || character == '-')) {
            return false;
        }
        ++length;
    }
    return length > 0U && length <= JG_ACCOUNT_USERNAME_MAX;
}

/** @brief Determine transactionally whether any local user exists. */
static int users_exist(sqlite3 *handle, bool *exists)
{
    static const char query[] = "SELECT EXISTS(SELECT 1 FROM users);";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
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

/** @brief Replace the singleton bootstrap digest in one open transaction. */
static int store_bootstrap(sqlite3 *handle,
                           const uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE],
                           uint64_t now,
                           uint64_t expires_at)
{
    static const char sql[] = "INSERT INTO bootstrap_credentials("
                              "id,token_hash,created_at,expires_at,consumed_at"
                              ") VALUES(1,?1,?2,?3,NULL)"
                              " ON CONFLICT(id) DO UPDATE SET"
                              " token_hash=excluded.token_hash,"
                              " created_at=excluded.created_at,"
                              " expires_at=excluded.expires_at,"
                              " consumed_at=NULL;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, sql, -1, SQLITE_PREPARE_PERSISTENT,
                                    &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_blob(
            statement, 1, digest, JG_AUTH_SECRET_DIGEST_SIZE, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 3, (sqlite3_int64)expires_at);
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
    return result;
}

/** @brief Issue one bootstrap credential while no users exist. */
int jg_account_bootstrap_issue(struct jg_database *database,
                               uint64_t now,
                               uint64_t lifetime,
                               char token[JG_AUTH_SECRET_TEXT_SIZE])
{
    uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE];
    uint64_t expires_at = 0U;
    bool exists = false;
    bool transaction_open = false;
    int result = 0;

    if (token == NULL) {
        return -EINVAL;
    }
    (void)memset(token, 0, JG_AUTH_SECRET_TEXT_SIZE);
    if (database == NULL || now == 0U || now > (uint64_t)INT64_MAX ||
        lifetime < JG_ACCOUNT_BOOTSTRAP_LIFETIME_MIN ||
        lifetime > JG_ACCOUNT_BOOTSTRAP_LIFETIME_MAX) {
        return -EINVAL;
    }
    if (lifetime > (uint64_t)INT64_MAX - now) {
        return -EOVERFLOW;
    }
    expires_at = now + lifetime;
    result = execute_fixed(database->handle, "BEGIN IMMEDIATE;");
    if (result == 0) {
        transaction_open = true;
        result = users_exist(database->handle, &exists);
    }
    if (result == 0 && exists) {
        result = -EEXIST;
    }
    if (result == 0) {
        result = jg_auth_secret_issue(token, digest);
    }
    if (result == 0) {
        result = store_bootstrap(database->handle, digest, now, expires_at);
    }
    if (result == 0) {
        result = execute_fixed(database->handle, "COMMIT;");
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)execute_fixed(database->handle, "ROLLBACK;");
    }
    sodium_memzero(digest, sizeof(digest));
    if (result != 0) {
        sodium_memzero(token, JG_AUTH_SECRET_TEXT_SIZE);
    }
    return result;
}

/** @brief Verify the singleton bootstrap credential in a write transaction. */
static int verify_bootstrap(sqlite3 *handle,
                            const uint8_t candidate[JG_AUTH_SECRET_DIGEST_SIZE],
                            uint64_t now)
{
    static const char query[] = "SELECT token_hash,expires_at,consumed_at"
                                " FROM bootstrap_credentials WHERE id=1;";
    sqlite3_stmt *statement = NULL;
    const void *persistent = NULL;
    int persistent_size = 0;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -EACCES;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        persistent = sqlite3_column_blob(statement, 0);
        persistent_size = sqlite3_column_bytes(statement, 0);
        if (sqlite3_column_type(statement, 0) != SQLITE_BLOB ||
            persistent_size != JG_AUTH_SECRET_DIGEST_SIZE ||
            sqlite3_column_type(statement, 1) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 1) <= (sqlite3_int64)now ||
            sqlite3_column_type(statement, 2) != SQLITE_NULL ||
            !jg_auth_secret_digest_equal(candidate, persistent)) {
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

/** @brief Insert the first administrator and its fixed role assignment. */
static int insert_administrator(sqlite3 *handle,
                                const char *username,
                                const char *password_hash,
                                uint64_t now,
                                uint64_t *user_id)
{
    static const char insert_user[] =
        "INSERT INTO users("
        "username,password_hash,enabled,failed_logins,created_at,"
        "password_changed_at,force_password_change,revision,session_epoch"
        ") VALUES(?1,?2,1,0,?3,?3,0,1,1);";
    static const char insert_role[] =
        "INSERT INTO user_roles(user_id,role_id) VALUES(?1,?2);";
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 identifier = 0;
    int status = sqlite3_prepare_v3(
        handle, insert_user, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status =
            sqlite3_bind_text(statement, 1, username, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 2, password_hash, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 3, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        statement = NULL;
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        identifier = sqlite3_last_insert_rowid(handle);
        if (identifier <= 0) {
            result = -EIO;
        }
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(handle, insert_role, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, identifier);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 2, ADMINISTRATOR_ROLE_ID);
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
        *user_id = (uint64_t)identifier;
    }
    return result;
}

/** @brief Mark the verified singleton bootstrap credential as consumed. */
static int consume_bootstrap(sqlite3 *handle, uint64_t now)
{
    static const char sql[] = "UPDATE bootstrap_credentials SET consumed_at=?1"
                              " WHERE id=1 AND consumed_at IS NULL;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, sql, -1, SQLITE_PREPARE_PERSISTENT,
                                    &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(handle) != 1) {
        result = -EACCES;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Atomically create the first administrator through bootstrap. */
int jg_account_create_initial_administrator(
    struct jg_database *database,
    const uint8_t *token,
    size_t token_size,
    const char *username,
    const uint8_t *password,
    size_t password_size,
    const struct jg_auth_password_policy *password_policy,
    uint64_t now,
    uint64_t *user_id)
{
    char password_hash[JG_AUTH_PASSWORD_HASH_SIZE];
    uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE];
    bool exists = false;
    bool transaction_open = false;
    int result = 0;

    if (user_id == NULL) {
        return -EINVAL;
    }
    *user_id = 0U;
    if (database == NULL || token == NULL || token_size == 0U ||
        token_size > JG_AUTH_SECRET_TEXT_SIZE - 1U ||
        !username_valid(username) || password == NULL || now == 0U ||
        now > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = jg_auth_password_hash(password_policy, password, password_size,
                                   password_hash);
    if (result == 0) {
        result = jg_auth_secret_digest(token, token_size, digest);
    }
    if (result == 0) {
        result = execute_fixed(database->handle, "BEGIN IMMEDIATE;");
        transaction_open = result == 0;
    }
    if (result == 0) {
        result = users_exist(database->handle, &exists);
    }
    if (result == 0 && exists) {
        result = -EEXIST;
    }
    if (result == 0) {
        result = verify_bootstrap(database->handle, digest, now);
    }
    if (result == 0) {
        result = insert_administrator(database->handle, username, password_hash,
                                      now, user_id);
    }
    if (result == 0) {
        result = consume_bootstrap(database->handle, now);
    }
    if (result == 0) {
        result = execute_fixed(database->handle, "COMMIT;");
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)execute_fixed(database->handle, "ROLLBACK;");
        *user_id = 0U;
    }
    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(password_hash, sizeof(password_hash));
    return result;
}
