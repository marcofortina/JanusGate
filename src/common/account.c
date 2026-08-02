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

/** Persistent fields needed while verifying one local user. */
struct authentication_record {
    uint64_t user_id;
    uint64_t revision;
    uint64_t session_epoch;
    uint64_t locked_until;
    uint32_t failed_logins;
    char password_hash[JG_AUTH_PASSWORD_HASH_SIZE];
    bool enabled;
    bool force_password_change;
};

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
    result = jg_database_transaction_begin(database);
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
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
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
        result = jg_database_transaction_begin(database);
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
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
        *user_id = 0U;
    }
    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(password_hash, sizeof(password_hash));
    return result;
}

/** @brief Convert one persistent role identifier to its public value. */
static enum jg_access_role role_from_id(sqlite3_int64 role_id)
{
    switch (role_id) {
    case JG_ACCESS_ROLE_ADMINISTRATOR:
        return JG_ACCESS_ROLE_ADMINISTRATOR;
    case JG_ACCESS_ROLE_OPERATOR:
        return JG_ACCESS_ROLE_OPERATOR;
    case JG_ACCESS_ROLE_AUDITOR:
        return JG_ACCESS_ROLE_AUDITOR;
    default:
        return JG_ACCESS_ROLE_NONE;
    }
}

/** @brief Validate one assignable fixed backend role. */
static bool role_valid(enum jg_access_role role)
{
    return role != JG_ACCESS_ROLE_NONE &&
           role_from_id((sqlite3_int64)role) == role;
}

/** @brief Decode one user row selected in the shared administrative order. */
static int decode_user_row(sqlite3_stmt *statement,
                           struct jg_account_user *user)
{
    const sqlite3_int64 user_id = sqlite3_column_int64(statement, 0);
    const char *username = (const char *)sqlite3_column_text(statement, 1);
    const int username_size = sqlite3_column_bytes(statement, 1);
    const sqlite3_int64 enabled = sqlite3_column_int64(statement, 2);
    const sqlite3_int64 failed_logins = sqlite3_column_int64(statement, 3);
    const sqlite3_int64 locked_until = sqlite3_column_int64(statement, 4);
    const sqlite3_int64 created_at = sqlite3_column_int64(statement, 5);
    const sqlite3_int64 password_changed_at =
        sqlite3_column_int64(statement, 6);
    const sqlite3_int64 last_login_at = sqlite3_column_int64(statement, 7);
    const sqlite3_int64 force_password_change =
        sqlite3_column_int64(statement, 8);
    const sqlite3_int64 revision = sqlite3_column_int64(statement, 9);
    const sqlite3_int64 totp_enabled = sqlite3_column_int64(statement, 10);
    const enum jg_access_role role =
        role_from_id(sqlite3_column_int64(statement, 11));
    const sqlite3_int64 role_count = sqlite3_column_int64(statement, 12);

    if (user == NULL || user_id <= 0 || username == NULL ||
        username_size <= 0 || (size_t)username_size > JG_ACCOUNT_USERNAME_MAX ||
        failed_logins < 0 || failed_logins > (sqlite3_int64)UINT32_MAX ||
        locked_until < 0 || created_at < 0 || password_changed_at < 0 ||
        last_login_at < 0 || revision <= 0 || (enabled != 0 && enabled != 1) ||
        (force_password_change != 0 && force_password_change != 1) ||
        (totp_enabled != 0 && totp_enabled != 1) ||
        role == JG_ACCESS_ROLE_NONE || role_count != 1) {
        return -EILSEQ;
    }
    (void)memset(user, 0, sizeof(*user));
    user->user_id = (uint64_t)user_id;
    (void)memcpy(user->username, username, (size_t)username_size);
    user->username[(size_t)username_size] = '\0';
    if (!username_valid(user->username)) {
        (void)memset(user, 0, sizeof(*user));
        return -EILSEQ;
    }
    user->role = role;
    user->revision = (uint64_t)revision;
    user->created_at = (uint64_t)created_at;
    user->password_changed_at = (uint64_t)password_changed_at;
    user->last_login_at = (uint64_t)last_login_at;
    user->locked_until = (uint64_t)locked_until;
    user->failed_logins = (uint32_t)failed_logins;
    user->enabled = enabled != 0;
    user->force_password_change = force_password_change != 0;
    user->totp_enabled = totp_enabled != 0;
    return 0;
}

/** @brief Load one complete administrative user record by identifier. */
static int load_user(sqlite3 *handle,
                     uint64_t user_id,
                     struct jg_account_user *user)
{
    static const char query[] =
        "SELECT u.id,u.username,u.enabled,u.failed_logins,"
        "coalesce(u.locked_until,0),u.created_at,u.password_changed_at,"
        "coalesce(u.last_login_at,0),u.force_password_change,u.revision,"
        "coalesce((SELECT enabled FROM totp_credentials"
        " WHERE user_id=u.id),0),"
        "(SELECT role_id FROM user_roles WHERE user_id=u.id LIMIT 1),"
        "(SELECT count(*) FROM user_roles WHERE user_id=u.id)"
        " FROM users u WHERE u.id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_ROW) {
            result = decode_user_row(statement, user);
        } else if (status == SQLITE_DONE) {
            result = -ENOENT;
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
    return result;
}

/** @brief Delete every web session owned by one local user. */
static int delete_user_sessions(sqlite3 *handle, uint64_t user_id)
{
    static const char sql[] = "DELETE FROM web_sessions WHERE user_id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, sql, -1, SQLITE_PREPARE_PERSISTENT,
                                    &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
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

/** @brief Revoke every active API token owned by one local user. */
static int revoke_user_tokens(sqlite3 *handle, uint64_t user_id, uint64_t now)
{
    static const char sql[] =
        "UPDATE api_tokens SET revoked_at=?1,revision=revision+1"
        " WHERE user_id=?2 AND revoked_at IS NULL;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, sql, -1, SQLITE_PREPARE_PERSISTENT,
                                    &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)user_id);
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

/** @brief Count enabled users retaining the administrator role. */
static int count_enabled_administrators(sqlite3 *handle, uint64_t *count)
{
    static const char query[] =
        "SELECT count(*) FROM users u JOIN user_roles ur ON ur.user_id=u.id"
        " WHERE u.enabled=1 AND ur.role_id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int(statement, 1, ADMINISTRATOR_ROLE_ID);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW || sqlite3_column_int64(statement, 0) < 0) {
            result = status == SQLITE_ROW ? -EILSEQ
                                          : jg_database_sqlite_result(status);
        } else {
            *count = (uint64_t)sqlite3_column_int64(statement, 0);
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

/** @brief List a bounded stable page of local users. */
int jg_account_user_list(struct jg_database *database,
                         uint64_t offset,
                         struct jg_account_user *users,
                         size_t capacity,
                         size_t *count,
                         uint64_t *total)
{
    static const char count_query[] = "SELECT count(*) FROM users;";
    static const char list_query[] =
        "SELECT u.id,u.username,u.enabled,u.failed_logins,"
        "coalesce(u.locked_until,0),u.created_at,u.password_changed_at,"
        "coalesce(u.last_login_at,0),u.force_password_change,u.revision,"
        "coalesce((SELECT enabled FROM totp_credentials"
        " WHERE user_id=u.id),0),"
        "(SELECT role_id FROM user_roles WHERE user_id=u.id LIMIT 1),"
        "(SELECT count(*) FROM user_roles WHERE user_id=u.id)"
        " FROM users u ORDER BY u.username COLLATE BINARY,u.id"
        " LIMIT ?1 OFFSET ?2;";
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
    if (database == NULL || users == NULL || count == NULL || total == NULL ||
        capacity == 0U || capacity > JG_ACCOUNT_USER_PAGE_MAX ||
        capacity > (size_t)INT64_MAX || offset > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    (void)memset(users, 0, capacity * sizeof(*users));
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
    while (result == 0 && loaded < capacity) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            break;
        }
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            result = decode_user_row(statement, &users[loaded]);
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
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
            *count = loaded;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
        (void)memset(users, 0, capacity * sizeof(*users));
        *count = 0U;
        *total = 0U;
    }
    return result;
}

/** @brief Insert one local user and its single role transactionally. */
int jg_account_user_create(
    struct jg_database *database,
    const char *username,
    const uint8_t *password,
    size_t password_size,
    const struct jg_auth_password_policy *password_policy,
    enum jg_access_role role,
    bool force_password_change,
    uint64_t now,
    struct jg_account_user *user)
{
    static const char insert_user[] =
        "INSERT INTO users("
        "username,password_hash,enabled,failed_logins,locked_until,created_at,"
        "password_changed_at,force_password_change,last_login_at,revision,"
        "session_epoch"
        ") VALUES(?1,?2,1,0,NULL,?3,?3,?4,NULL,1,1);";
    static const char insert_role[] =
        "INSERT INTO user_roles(user_id,role_id) VALUES(?1,?2);";
    char password_hash[JG_AUTH_PASSWORD_HASH_SIZE];
    sqlite3_stmt *statement = NULL;
    bool transaction_open = false;
    uint64_t user_id = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (user != NULL) {
        (void)memset(user, 0, sizeof(*user));
    }
    if (database == NULL || !username_valid(username) || password == NULL ||
        password_policy == NULL || !role_valid(role) || now == 0U ||
        now > (uint64_t)INT64_MAX || user == NULL) {
        return -EINVAL;
    }
    result = jg_auth_password_hash(password_policy, password, password_size,
                                   password_hash);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
        transaction_open = result == 0;
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert_user, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
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
        status = sqlite3_bind_int(statement, 4, force_password_change ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if ((status & 0xff) == SQLITE_CONSTRAINT) {
            result = -EEXIST;
        } else {
            result =
                status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        const sqlite3_int64 identifier =
            sqlite3_last_insert_rowid(database->handle);

        if (identifier <= 0) {
            result = -EOVERFLOW;
        } else {
            user_id = (uint64_t)identifier;
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
            sqlite3_prepare_v3(database->handle, insert_role, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 2, (int)role);
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
        result = load_user(database->handle, user_id, user);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    if (result != 0) {
        (void)memset(user, 0, sizeof(*user));
    }
    sodium_memzero(password_hash, sizeof(password_hash));
    return result;
}

/** @brief Replace one user's mutable role and authentication state. */
int jg_account_user_update(struct jg_database *database,
                           uint64_t user_id,
                           uint64_t expected_revision,
                           const struct jg_account_user_update *update,
                           uint64_t now,
                           struct jg_account_user *user)
{
    static const char update_user[] =
        "UPDATE users SET enabled=?1,force_password_change=?2,"
        "revision=revision+1,session_epoch=session_epoch+1"
        " WHERE id=?3 AND revision=?4;";
    static const char update_role[] =
        "UPDATE user_roles SET role_id=?1 WHERE user_id=?2;";
    struct jg_account_user current = {0};
    sqlite3_stmt *statement = NULL;
    bool transaction_open = false;
    uint64_t administrator_count = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (user != NULL) {
        (void)memset(user, 0, sizeof(*user));
    }
    if (database == NULL || user_id == 0U || user_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX ||
        update == NULL || !role_valid(update->role) || now == 0U ||
        now > (uint64_t)INT64_MAX || user == NULL) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin(database);
    transaction_open = result == 0;
    if (result == 0) {
        result = load_user(database->handle, user_id, &current);
    }
    if (result == 0 && current.revision != expected_revision) {
        result = -ESTALE;
    }
    if (result == 0 && current.enabled &&
        current.role == JG_ACCESS_ROLE_ADMINISTRATOR &&
        (!update->enabled || update->role != JG_ACCESS_ROLE_ADMINISTRATOR)) {
        result = count_enabled_administrators(database->handle,
                                              &administrator_count);
        if (result == 0 && administrator_count <= 1U) {
            result = -EPERM;
        }
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update_user, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 1, update->enabled ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 2,
                                  update->force_password_change ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 3, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int64(statement, 4, (sqlite3_int64)expected_revision);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = -ESTALE;
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
            sqlite3_prepare_v3(database->handle, update_role, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 1, (int)update->role);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = delete_user_sessions(database->handle, user_id);
    }
    if (result == 0 && !update->enabled) {
        result = revoke_user_tokens(database->handle, user_id, now);
    }
    if (result == 0) {
        result = load_user(database->handle, user_id, user);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    if (result != 0) {
        (void)memset(user, 0, sizeof(*user));
    }
    return result;
}

/** @brief Replace one user's password and revoke issued credentials. */
int jg_account_user_reset_password(
    struct jg_database *database,
    uint64_t user_id,
    uint64_t expected_revision,
    const uint8_t *password,
    size_t password_size,
    const struct jg_auth_password_policy *password_policy,
    bool force_password_change,
    uint64_t now,
    struct jg_account_user *user)
{
    static const char update_password[] =
        "UPDATE users SET password_hash=?1,password_changed_at=?2,"
        "force_password_change=?3,failed_logins=0,locked_until=NULL,"
        "revision=revision+1,session_epoch=session_epoch+1"
        " WHERE id=?4 AND revision=?5;";
    char password_hash[JG_AUTH_PASSWORD_HASH_SIZE];
    sqlite3_stmt *statement = NULL;
    bool transaction_open = false;
    int status = SQLITE_OK;
    int result = 0;

    if (user != NULL) {
        (void)memset(user, 0, sizeof(*user));
    }
    if (database == NULL || user_id == 0U || user_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX ||
        password == NULL || password_policy == NULL || now == 0U ||
        now > (uint64_t)INT64_MAX || user == NULL) {
        return -EINVAL;
    }
    result = jg_auth_password_hash(password_policy, password, password_size,
                                   password_hash);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
        transaction_open = result == 0;
    }
    if (result == 0) {
        result = load_user(database->handle, user_id, user);
    }
    if (result == 0 && user->revision != expected_revision) {
        result = -ESTALE;
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update_password, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, password_hash, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 3, force_password_change ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 4, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int64(statement, 5, (sqlite3_int64)expected_revision);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = -ESTALE;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = delete_user_sessions(database->handle, user_id);
    }
    if (result == 0) {
        result = revoke_user_tokens(database->handle, user_id, now);
    }
    if (result == 0) {
        result = load_user(database->handle, user_id, user);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    if (result != 0) {
        (void)memset(user, 0, sizeof(*user));
    }
    sodium_memzero(password_hash, sizeof(password_hash));
    return result;
}

/** @brief Read one bounded authentication record by exact username. */
static int load_authentication_record(sqlite3 *handle,
                                      const char *username,
                                      struct authentication_record *record)
{
    static const char query[] =
        "SELECT id,password_hash,enabled,failed_logins,locked_until,"
        "force_password_change,revision,session_epoch"
        " FROM users WHERE username=?1;";
    sqlite3_stmt *statement = NULL;
    const char *password_hash = NULL;
    int password_hash_size = 0;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    (void)memset(record, 0, sizeof(*record));
    if (result == 0) {
        status =
            sqlite3_bind_text(statement, 1, username, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        password_hash = (const char *)sqlite3_column_text(statement, 1);
        password_hash_size = sqlite3_column_bytes(statement, 1);
        if (sqlite3_column_type(statement, 0) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 0) <= 0 ||
            sqlite3_column_type(statement, 1) != SQLITE_TEXT ||
            password_hash_size <= 0 ||
            (size_t)password_hash_size >= JG_AUTH_PASSWORD_HASH_SIZE ||
            sqlite3_column_type(statement, 2) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 3) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 3) < 0 ||
            sqlite3_column_int64(statement, 3) > JG_ACCOUNT_FAILED_LOGIN_MAX ||
            (sqlite3_column_type(statement, 4) != SQLITE_NULL &&
             (sqlite3_column_type(statement, 4) != SQLITE_INTEGER ||
              sqlite3_column_int64(statement, 4) < 0)) ||
            sqlite3_column_type(statement, 5) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 6) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 6) <= 0 ||
            sqlite3_column_type(statement, 7) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 7) <= 0) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        record->user_id = (uint64_t)sqlite3_column_int64(statement, 0);
        (void)memcpy(record->password_hash, password_hash,
                     (size_t)password_hash_size);
        record->password_hash[(size_t)password_hash_size] = '\0';
        record->enabled = sqlite3_column_int(statement, 2) != 0;
        record->failed_logins = (uint32_t)sqlite3_column_int64(statement, 3);
        if (sqlite3_column_type(statement, 4) == SQLITE_INTEGER) {
            record->locked_until = (uint64_t)sqlite3_column_int64(statement, 4);
        }
        record->force_password_change = sqlite3_column_int(statement, 5) != 0;
        record->revision = (uint64_t)sqlite3_column_int64(statement, 6);
        record->session_epoch = (uint64_t)sqlite3_column_int64(statement, 7);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Verify that credentials did not change during password hashing. */
static bool authentication_record_matches(
    const struct authentication_record *verified,
    const struct authentication_record *current)
{
    return verified->user_id == current->user_id &&
           verified->revision == current->revision &&
           verified->session_epoch == current->session_epoch &&
           verified->enabled == current->enabled &&
           verified->force_password_change == current->force_password_change &&
           strcmp(verified->password_hash, current->password_hash) == 0;
}

/** @brief Perform equivalent Argon2id work for an unknown username. */
static int perform_unknown_user_work(
    const struct jg_auth_password_policy *password_policy)
{
    uint8_t password[JG_AUTH_PASSWORD_MAX];
    char password_hash[JG_AUTH_PASSWORD_HASH_SIZE];
    size_t password_size = 0U;
    int result = 0;

    if (password_policy == NULL ||
        password_policy->minimum_length > sizeof(password)) {
        return -EINVAL;
    }
    password_size = password_policy->minimum_length;
    (void)memset(password, UINT8_C(0xa5), password_size);
    result = jg_auth_password_hash(password_policy, password, password_size,
                                   password_hash);
    sodium_memzero(password_hash, sizeof(password_hash));
    sodium_memzero(password, sizeof(password));
    return result;
}

/** @brief Calculate the persistent exponential delay after one failure. */
static uint64_t login_lock_delay(uint32_t failed_logins)
{
    uint64_t delay = 1U;
    uint32_t exponent = failed_logins > 0U ? failed_logins - 1U : 0U;

    while (exponent > 0U && delay < JG_ACCOUNT_LOCK_DELAY_MAX) {
        delay *= 2U;
        --exponent;
    }
    return delay > JG_ACCOUNT_LOCK_DELAY_MAX ? JG_ACCOUNT_LOCK_DELAY_MAX
                                             : delay;
}

/** @brief Persist one failed login and its next allowed timestamp. */
static int record_login_failure(sqlite3 *handle,
                                const struct authentication_record *record,
                                uint64_t now)
{
    static const char sql[] =
        "UPDATE users SET failed_logins=?1,locked_until=?2"
        " WHERE id=?3;";
    sqlite3_stmt *statement = NULL;
    uint32_t failures = record->failed_logins;
    uint64_t locked_until = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (failures < JG_ACCOUNT_FAILED_LOGIN_MAX) {
        ++failures;
    }
    locked_until = now + login_lock_delay(failures);
    status = sqlite3_prepare_v3(handle, sql, -1, SQLITE_PREPARE_PERSISTENT,
                                &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)failures);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)locked_until);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int64(statement, 3, (sqlite3_int64)record->user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(handle) != 1) {
        result = -EIO;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Persist a successful login and optional password-hash upgrade. */
static int record_login_success(sqlite3 *handle,
                                uint64_t user_id,
                                uint64_t now,
                                const char *replacement_hash)
{
    static const char update[] =
        "UPDATE users SET failed_logins=0,locked_until=NULL,last_login_at=?1,"
        "password_hash=coalesce(?2,password_hash) WHERE id=?3;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && replacement_hash != NULL) {
        status = sqlite3_bind_text(statement, 2, replacement_hash, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        status = sqlite3_bind_null(statement, 2);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 3, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(handle) != 1) {
        result = -EIO;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Convert one persistent role name to backend permissions. */
static uint32_t permissions_for_role(const char *role)
{
    if (strcmp(role, "administrator") == 0) {
        return jg_access_role_permissions(JG_ACCESS_ROLE_ADMINISTRATOR);
    }
    if (strcmp(role, "operator") == 0) {
        return jg_access_role_permissions(JG_ACCESS_ROLE_OPERATOR);
    }
    if (strcmp(role, "auditor") == 0) {
        return jg_access_role_permissions(JG_ACCESS_ROLE_AUDITOR);
    }
    return 0U;
}

/** @brief Load the role union and enabled TOTP state for one user. */
static int load_identity_authorization(sqlite3 *handle,
                                       uint64_t user_id,
                                       uint32_t *permissions,
                                       bool *totp_enabled)
{
    static const char role_query[] = "SELECT r.name FROM roles r"
                                     " JOIN user_roles ur ON ur.role_id=r.id"
                                     " WHERE ur.user_id=?1 ORDER BY r.id;";
    static const char totp_query[] =
        "SELECT enabled FROM totp_credentials WHERE user_id=?1;";
    sqlite3_stmt *statement = NULL;
    uint32_t granted = 0U;
    int status = sqlite3_prepare_v3(
        handle, role_query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    *permissions = 0U;
    *totp_enabled = false;
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        const char *role = (const char *)sqlite3_column_text(statement, 0);
        const uint32_t role_permissions =
            role == NULL ? 0U : permissions_for_role(role);

        if (sqlite3_column_type(statement, 0) != SQLITE_TEXT ||
            role_permissions == 0U) {
            result = -EILSEQ;
        } else {
            granted |= role_permissions;
        }
    }
    if (result == 0 && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && granted == 0U) {
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
            sqlite3_prepare_v3(handle, totp_query, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_ROW) {
            if (sqlite3_column_type(statement, 0) != SQLITE_INTEGER) {
                result = -EILSEQ;
            } else {
                *totp_enabled = sqlite3_column_int(statement, 0) != 0;
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
    if (result == 0) {
        *permissions = granted;
    }
    return result;
}

/** @brief Authenticate one local user and update persistent login state. */
int jg_account_authenticate(
    struct jg_database *database,
    const char *username,
    const uint8_t *password,
    size_t password_size,
    const struct jg_auth_password_policy *password_policy,
    uint64_t now,
    struct jg_account_identity *identity)
{
    struct authentication_record record;
    struct authentication_record current;
    char replacement_hash[JG_AUTH_PASSWORD_HASH_SIZE];
    uint32_t permissions = 0U;
    bool password_valid = false;
    bool needs_rehash = false;
    bool totp_enabled = false;
    bool transaction_open = false;
    int authentication_result = 0;
    int result = 0;

    if (identity == NULL) {
        return -EINVAL;
    }
    (void)memset(identity, 0, sizeof(*identity));
    (void)memset(&record, 0, sizeof(record));
    (void)memset(&current, 0, sizeof(current));
    (void)memset(replacement_hash, 0, sizeof(replacement_hash));
    if (database == NULL || !username_valid(username) || password == NULL ||
        password_size > JG_AUTH_PASSWORD_MAX || now == 0U ||
        now > (uint64_t)INT64_MAX - JG_ACCOUNT_LOCK_DELAY_MAX) {
        return password_size > JG_AUTH_PASSWORD_MAX ? -ERANGE : -EINVAL;
    }
    result = load_authentication_record(database->handle, username, &record);
    if (result == -ENOENT) {
        result = perform_unknown_user_work(password_policy);
        authentication_result = result == 0 ? -EACCES : 0;
    }
    if (result == 0 && authentication_result == 0 && !record.enabled) {
        result = jg_auth_password_verify(password_policy, password,
                                         password_size, record.password_hash,
                                         &password_valid, &needs_rehash);
        authentication_result = result == 0 ? -EACCES : 0;
    }
    if (result == 0 && authentication_result == 0) {
        result = jg_auth_password_verify(password_policy, password,
                                         password_size, record.password_hash,
                                         &password_valid, &needs_rehash);
    }
    if (result == 0 && authentication_result == 0 && !password_valid &&
        record.locked_until > now) {
        authentication_result = -EAGAIN;
    }
    if (result == 0 && authentication_result == 0 && needs_rehash) {
        result = jg_auth_password_hash(password_policy, password, password_size,
                                       replacement_hash);
    }
    if (result == 0 && authentication_result == 0) {
        result = jg_database_transaction_begin(database);
        transaction_open = result == 0;
    }
    if (result == 0 && authentication_result == 0) {
        result =
            load_authentication_record(database->handle, username, &current);
        if (result == -ENOENT) {
            result = 0;
            authentication_result = -EAGAIN;
        } else if (result == 0 &&
                   !authentication_record_matches(&record, &current)) {
            authentication_result = -EAGAIN;
        }
    }
    if (result == 0 && authentication_result == 0 && !password_valid &&
        current.locked_until > now) {
        authentication_result = -EAGAIN;
    }
    if (result == 0 && authentication_result == 0 && !password_valid) {
        result = record_login_failure(database->handle, &current, now);
        authentication_result = result == 0 ? -EACCES : 0;
    }
    if (result == 0 && authentication_result == 0) {
        result = record_login_success(database->handle, current.user_id, now,
                                      needs_rehash ? replacement_hash : NULL);
    }
    if (result == 0 && authentication_result == 0) {
        result = load_identity_authorization(database->handle, current.user_id,
                                             &permissions, &totp_enabled);
    }
    if (result == 0 && transaction_open) {
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0 && authentication_result == 0) {
        identity->user_id = current.user_id;
        (void)memcpy(identity->username, username, strlen(username) + 1U);
        identity->permissions = permissions;
        identity->revision = current.revision;
        identity->session_epoch = current.session_epoch;
        identity->force_password_change = current.force_password_change;
        identity->totp_enabled = totp_enabled;
        identity->mfa_complete = !totp_enabled;
    }
    sodium_memzero(replacement_hash, sizeof(replacement_hash));
    sodium_memzero(&record, sizeof(record));
    sodium_memzero(&current, sizeof(current));
    return result == 0 ? authentication_result : result;
}

/** @brief Return the network-order byte count for a supported address. */
static size_t address_size(enum jg_policy_address_family family)
{
    if (family == JG_POLICY_ADDRESS_IPV4) {
        return 4U;
    }
    if (family == JG_POLICY_ADDRESS_IPV6) {
        return 16U;
    }
    return 0U;
}

/** @brief Validate one optional exact remote-address binding. */
static bool remote_address_valid(enum jg_policy_address_family family,
                                 const uint8_t *address)
{
    return (family == JG_POLICY_ADDRESS_NONE && address == NULL) ||
           ((family == JG_POLICY_ADDRESS_IPV4 ||
             family == JG_POLICY_ADDRESS_IPV6) &&
            address != NULL);
}

/** @brief Insert one session only for a current enabled identity epoch. */
static int insert_session(
    sqlite3 *handle,
    const struct jg_account_identity *identity,
    const uint8_t session_digest[JG_AUTH_SECRET_DIGEST_SIZE],
    const uint8_t csrf_digest[JG_AUTH_SECRET_DIGEST_SIZE],
    uint64_t now,
    uint64_t expires_at,
    enum jg_policy_address_family remote_family,
    const uint8_t *remote_address)
{
    static const char sql[] =
        "INSERT INTO web_sessions("
        "user_id,session_hash,csrf_hash,created_at,expires_at,last_seen_at,"
        "remote_address,session_epoch"
        ") SELECT id,?1,?2,?3,?4,?3,?5,session_epoch FROM users"
        " WHERE id=?6 AND enabled=1 AND session_epoch=?7;";
    sqlite3_stmt *statement = NULL;
    const size_t remote_size = address_size(remote_family);
    int status = sqlite3_prepare_v3(handle, sql, -1, SQLITE_PREPARE_PERSISTENT,
                                    &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status =
            sqlite3_bind_blob(statement, 1, session_digest,
                              JG_AUTH_SECRET_DIGEST_SIZE, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_blob(statement, 2, csrf_digest,
                              JG_AUTH_SECRET_DIGEST_SIZE, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 3, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 4, (sqlite3_int64)expires_at);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && remote_size != 0U) {
        status = sqlite3_bind_blob(statement, 5, remote_address,
                                   (int)remote_size, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        status = sqlite3_bind_null(statement, 5);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int64(statement, 6, (sqlite3_int64)identity->user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 7,
                                    (sqlite3_int64)identity->session_epoch);
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

/** @brief Issue and persist one opaque web session. */
int jg_account_session_issue(struct jg_database *database,
                             const struct jg_account_identity *identity,
                             uint64_t now,
                             uint64_t lifetime,
                             enum jg_policy_address_family remote_family,
                             const uint8_t *remote_address,
                             struct jg_account_session_tokens *tokens)
{
    uint8_t session_digest[JG_AUTH_SECRET_DIGEST_SIZE];
    uint8_t csrf_digest[JG_AUTH_SECRET_DIGEST_SIZE];
    uint64_t expires_at = 0U;
    int result = 0;

    if (tokens == NULL) {
        return -EINVAL;
    }
    (void)memset(tokens, 0, sizeof(*tokens));
    if (database == NULL || identity == NULL || identity->user_id == 0U ||
        identity->user_id > (uint64_t)INT64_MAX ||
        identity->session_epoch == 0U ||
        identity->session_epoch > (uint64_t)INT64_MAX || now == 0U ||
        now > (uint64_t)INT64_MAX ||
        !remote_address_valid(remote_family, remote_address)) {
        return -EINVAL;
    }
    if (identity->totp_enabled && !identity->mfa_complete) {
        return -EACCES;
    }
    if (lifetime < JG_ACCOUNT_SESSION_LIFETIME_MIN ||
        lifetime > JG_ACCOUNT_SESSION_LIFETIME_MAX) {
        return -ERANGE;
    }
    if (lifetime > (uint64_t)INT64_MAX - now) {
        return -EOVERFLOW;
    }
    expires_at = now + lifetime;
    result = jg_auth_secret_issue(tokens->session, session_digest);
    if (result == 0) {
        result = jg_auth_secret_issue(tokens->csrf, csrf_digest);
    }
    if (result == 0) {
        result = insert_session(database->handle, identity, session_digest,
                                csrf_digest, now, expires_at, remote_family,
                                remote_address);
    }
    if (result == 0) {
        tokens->expires_at = expires_at;
    } else {
        sodium_memzero(tokens, sizeof(*tokens));
    }
    sodium_memzero(csrf_digest, sizeof(csrf_digest));
    sodium_memzero(session_digest, sizeof(session_digest));
    return result;
}

/** Persistent session fields copied before finalizing a query. */
struct session_record {
    uint64_t user_id;
    uint64_t expires_at;
    uint64_t last_seen_at;
    uint64_t session_epoch;
    uint64_t user_session_epoch;
    uint64_t revision;
    uint8_t csrf_digest[JG_AUTH_SECRET_DIGEST_SIZE];
    uint8_t remote_address[16U];
    size_t remote_address_size;
    char username[JG_ACCOUNT_USERNAME_MAX + 1U];
    bool enabled;
    bool force_password_change;
};

/** @brief Read one session and current user state by persistent digest. */
static int load_session(sqlite3 *handle,
                        const uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE],
                        struct session_record *record)
{
    static const char query[] =
        "SELECT s.user_id,s.csrf_hash,s.expires_at,s.last_seen_at,"
        "s.remote_address,s.session_epoch,u.username,u.enabled,"
        "u.force_password_change,u.revision,u.session_epoch"
        " FROM web_sessions s JOIN users u ON u.id=s.user_id"
        " WHERE s.session_hash=?1;";
    sqlite3_stmt *statement = NULL;
    const void *csrf = NULL;
    const void *remote = NULL;
    const char *username = NULL;
    int csrf_size = 0;
    int remote_size = 0;
    int username_size = 0;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    (void)memset(record, 0, sizeof(*record));
    if (result == 0) {
        status = sqlite3_bind_blob(
            statement, 1, digest, JG_AUTH_SECRET_DIGEST_SIZE, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        csrf = sqlite3_column_blob(statement, 1);
        csrf_size = sqlite3_column_bytes(statement, 1);
        remote = sqlite3_column_blob(statement, 4);
        remote_size = sqlite3_column_bytes(statement, 4);
        username = (const char *)sqlite3_column_text(statement, 6);
        username_size = sqlite3_column_bytes(statement, 6);
        if (sqlite3_column_type(statement, 0) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 0) <= 0 ||
            sqlite3_column_type(statement, 1) != SQLITE_BLOB ||
            csrf_size != JG_AUTH_SECRET_DIGEST_SIZE ||
            sqlite3_column_type(statement, 2) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 2) < 0 ||
            sqlite3_column_type(statement, 3) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 3) < 0 ||
            !((sqlite3_column_type(statement, 4) == SQLITE_NULL &&
               remote_size == 0) ||
              (sqlite3_column_type(statement, 4) == SQLITE_BLOB &&
               (remote_size == 4 || remote_size == 16))) ||
            sqlite3_column_type(statement, 5) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 5) <= 0 ||
            sqlite3_column_type(statement, 6) != SQLITE_TEXT ||
            username_size <= 0 ||
            (size_t)username_size > JG_ACCOUNT_USERNAME_MAX ||
            sqlite3_column_type(statement, 7) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 8) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 9) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 9) <= 0 ||
            sqlite3_column_type(statement, 10) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 10) <= 0) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        record->user_id = (uint64_t)sqlite3_column_int64(statement, 0);
        (void)memcpy(record->csrf_digest, csrf, sizeof(record->csrf_digest));
        record->expires_at = (uint64_t)sqlite3_column_int64(statement, 2);
        record->last_seen_at = (uint64_t)sqlite3_column_int64(statement, 3);
        if (remote_size > 0) {
            (void)memcpy(record->remote_address, remote, (size_t)remote_size);
            record->remote_address_size = (size_t)remote_size;
        }
        record->session_epoch = (uint64_t)sqlite3_column_int64(statement, 5);
        (void)memcpy(record->username, username, (size_t)username_size);
        record->username[(size_t)username_size] = '\0';
        record->enabled = sqlite3_column_int(statement, 7) != 0;
        record->force_password_change = sqlite3_column_int(statement, 8) != 0;
        record->revision = (uint64_t)sqlite3_column_int64(statement, 9);
        record->user_session_epoch =
            (uint64_t)sqlite3_column_int64(statement, 10);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Match a persistent optional address against the current peer. */
static bool session_address_matches(const struct session_record *record,
                                    enum jg_policy_address_family remote_family,
                                    const uint8_t *remote_address)
{
    const size_t current_size = address_size(remote_family);

    if (record->remote_address_size == 0U) {
        return true;
    }
    return current_size == record->remote_address_size &&
           remote_address != NULL &&
           sodium_memcmp(record->remote_address, remote_address,
                         current_size) == 0;
}

/** @brief Advance one session activity timestamp after the write interval. */
static int touch_session(sqlite3 *handle,
                         const uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE],
                         uint64_t now)
{
    static const char update[] =
        "UPDATE web_sessions SET last_seen_at=?1 WHERE session_hash=?2;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_blob(
            statement, 2, digest, JG_AUTH_SECRET_DIGEST_SIZE, SQLITE_TRANSIENT);
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

/** @brief Validate one session, CSRF value, epoch, and idle lifetime. */
int jg_account_session_validate(struct jg_database *database,
                                const uint8_t *session,
                                size_t session_size,
                                const uint8_t *csrf,
                                size_t csrf_size,
                                bool require_csrf,
                                uint64_t now,
                                uint64_t inactivity_timeout,
                                enum jg_policy_address_family remote_family,
                                const uint8_t *remote_address,
                                struct jg_account_identity *identity)
{
    struct session_record record;
    uint8_t session_digest[JG_AUTH_SECRET_DIGEST_SIZE];
    uint8_t csrf_digest[JG_AUTH_SECRET_DIGEST_SIZE];
    uint32_t permissions = 0U;
    bool totp_enabled = false;
    bool transaction_open = false;
    int authentication_result = 0;
    int result = 0;

    if (identity == NULL) {
        return -EINVAL;
    }
    (void)memset(identity, 0, sizeof(*identity));
    (void)memset(csrf_digest, 0, sizeof(csrf_digest));
    if (database == NULL || session == NULL ||
        session_size != JG_AUTH_SECRET_TEXT_SIZE - 1U || now == 0U ||
        now > (uint64_t)INT64_MAX ||
        !remote_address_valid(remote_family, remote_address) ||
        (require_csrf &&
         (csrf == NULL || csrf_size != JG_AUTH_SECRET_TEXT_SIZE - 1U)) ||
        (!require_csrf && (csrf != NULL || csrf_size != 0U))) {
        return -EINVAL;
    }
    if (inactivity_timeout < JG_ACCOUNT_SESSION_INACTIVITY_MIN ||
        inactivity_timeout > JG_ACCOUNT_SESSION_INACTIVITY_MAX) {
        return -ERANGE;
    }
    result = jg_auth_secret_digest(session, session_size, session_digest);
    if (result == 0 && require_csrf) {
        result = jg_auth_secret_digest(csrf, csrf_size, csrf_digest);
    }
    if (result == 0) {
        result = jg_database_transaction_begin(database);
        transaction_open = result == 0;
    }
    if (result == 0) {
        result = load_session(database->handle, session_digest, &record);
        if (result == -ENOENT) {
            result = 0;
            authentication_result = -EACCES;
        }
    }
    if (result == 0 && authentication_result == 0 &&
        (!record.enabled || record.session_epoch != record.user_session_epoch ||
         record.expires_at <= now || record.last_seen_at > now ||
         now - record.last_seen_at > inactivity_timeout ||
         !session_address_matches(&record, remote_family, remote_address) ||
         (require_csrf &&
          !jg_auth_secret_digest_equal(csrf_digest, record.csrf_digest)))) {
        authentication_result = -EACCES;
    }
    if (result == 0 && authentication_result == 0) {
        result = load_identity_authorization(database->handle, record.user_id,
                                             &permissions, &totp_enabled);
    }
    if (result == 0 && authentication_result == 0 &&
        now - record.last_seen_at >= JG_ACCOUNT_SESSION_TOUCH_INTERVAL) {
        result = touch_session(database->handle, session_digest, now);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0 && authentication_result == 0) {
        identity->user_id = record.user_id;
        (void)memcpy(identity->username, record.username,
                     strlen(record.username) + 1U);
        identity->permissions = permissions;
        identity->revision = record.revision;
        identity->session_epoch = record.user_session_epoch;
        identity->force_password_change = record.force_password_change;
        identity->totp_enabled = totp_enabled;
        identity->mfa_complete = true;
    }
    sodium_memzero(csrf_digest, sizeof(csrf_digest));
    sodium_memzero(session_digest, sizeof(session_digest));
    sodium_memzero(&record, sizeof(record));
    return result == 0 ? authentication_result : result;
}

/** @brief Delete one session by opaque identifier digest. */
int jg_account_session_revoke(struct jg_database *database,
                              const uint8_t *session,
                              size_t session_size)
{
    static const char delete_session[] =
        "DELETE FROM web_sessions WHERE session_hash=?1;";
    uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE];
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || session == NULL ||
        session_size != JG_AUTH_SECRET_TEXT_SIZE - 1U) {
        return -EINVAL;
    }
    result = jg_auth_secret_digest(session, session_size, digest);
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, delete_session, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_blob(
            statement, 1, digest, JG_AUTH_SECRET_DIGEST_SIZE, SQLITE_TRANSIENT);
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
    sodium_memzero(digest, sizeof(digest));
    return result;
}

/** @brief Increment one user epoch and remove all stored sessions. */
int jg_account_sessions_revoke_all(struct jg_database *database,
                                   uint64_t user_id)
{
    static const char update_user[] =
        "UPDATE users SET session_epoch=session_epoch+1,revision=revision+1"
        " WHERE id=?1;";
    static const char delete_sessions[] =
        "DELETE FROM web_sessions WHERE user_id=?1;";
    sqlite3_stmt *statement = NULL;
    bool transaction_open = false;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || user_id == 0U || user_id > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin(database);
    transaction_open = result == 0;
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update_user, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
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
        statement = NULL;
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, delete_sessions, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
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
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    return result;
}

/** @brief Validate one bounded printable token display name. */
static bool token_name_valid(const char *name)
{
    size_t size = 0U;

    if (name == NULL) {
        return false;
    }
    while (size <= JG_ACCOUNT_TOKEN_NAME_MAX && name[size] != '\0') {
        const uint8_t character = (uint8_t)name[size];

        if (character < UINT8_C(0x20) || character == UINT8_C(0x7f)) {
            return false;
        }
        ++size;
    }
    return size > 0U && size <= JG_ACCOUNT_TOKEN_NAME_MAX;
}

/** @brief Clear host bits from one token source-network restriction. */
static void canonicalize_source_address(uint8_t output[16U],
                                        const uint8_t input[16U],
                                        size_t input_size,
                                        uint8_t prefix)
{
    const size_t complete_bytes = (size_t)prefix / 8U;
    const uint8_t remaining_bits = (uint8_t)(prefix % 8U);
    size_t first_clear = complete_bytes;

    (void)memset(output, 0, 16U);
    (void)memcpy(output, input, input_size);
    if (remaining_bits != 0U) {
        output[complete_bytes] &=
            (uint8_t)(UINT8_C(0xff) << (8U - remaining_bits));
        first_clear = complete_bytes + 1U;
    }
    if (first_clear < input_size) {
        (void)memset(output + first_clear, 0, input_size - first_clear);
    }
}

/** @brief Validate an API-token configuration and its optional network. */
static int token_config_validate(const struct jg_account_token_config *config,
                                 uint64_t now)
{
    if (config == NULL || !token_name_valid(config->name) ||
        config->permissions == 0U ||
        (config->permissions & ~JG_ACCESS_PERMISSION_ALL) != 0U ||
        config->requests_per_minute < JG_ACCOUNT_TOKEN_RATE_MIN ||
        config->requests_per_minute > JG_ACCOUNT_TOKEN_RATE_MAX ||
        (config->expires_at != 0U &&
         (config->expires_at <= now ||
          config->expires_at > (uint64_t)INT64_MAX))) {
        return -EINVAL;
    }
    if (config->source_family == JG_POLICY_ADDRESS_NONE) {
        return config->source_prefix == 0U ? 0 : -EINVAL;
    }
    if (config->source_family == JG_POLICY_ADDRESS_IPV4) {
        return config->source_prefix <= 32U ? 0 : -EINVAL;
    }
    if (config->source_family == JG_POLICY_ADDRESS_IPV6) {
        return config->source_prefix <= 128U ? 0 : -EINVAL;
    }
    return -EINVAL;
}

/** @brief Read current user authorization and enablement for token issue. */
static int load_token_owner(sqlite3 *handle,
                            uint64_t user_id,
                            bool *enabled,
                            uint32_t *permissions)
{
    static const char query[] = "SELECT enabled FROM users WHERE id=?1;";
    sqlite3_stmt *statement = NULL;
    bool ignored_totp = false;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    *enabled = false;
    *permissions = 0U;
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else if (sqlite3_column_type(statement, 0) != SQLITE_INTEGER) {
            result = -EILSEQ;
        } else {
            *enabled = sqlite3_column_int(statement, 0) != 0;
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = load_identity_authorization(handle, user_id, permissions,
                                             &ignored_totp);
    }
    return result;
}

/** @brief Insert one validated API token and return its identifier. */
static int insert_api_token(sqlite3 *handle,
                            uint64_t user_id,
                            const struct jg_account_token_config *config,
                            const uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE],
                            const char *scopes,
                            uint64_t now,
                            uint64_t *token_id)
{
    static const char insert[] =
        "INSERT INTO api_tokens("
        "user_id,name,token_hash,scopes,created_at,expires_at,source_family,"
        "source_address,source_prefix,requests_per_minute,revision"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1);";
    uint8_t canonical_address[16U];
    sqlite3_stmt *statement = NULL;
    const size_t source_size = address_size(config->source_family);
    int status = sqlite3_prepare_v3(
        handle, insert, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    (void)memset(canonical_address, 0, sizeof(canonical_address));
    if (source_size != 0U) {
        canonicalize_source_address(canonical_address, config->source_address,
                                    source_size, config->source_prefix);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_text(statement, 2, config->name, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_blob(
            statement, 3, digest, JG_AUTH_SECRET_DIGEST_SIZE, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 4, scopes, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 5, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && config->expires_at != 0U) {
        status =
            sqlite3_bind_int64(statement, 6, (sqlite3_int64)config->expires_at);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        status = sqlite3_bind_null(statement, 6);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && source_size != 0U) {
        status = sqlite3_bind_int(statement, 7, (int)config->source_family);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        status = sqlite3_bind_null(statement, 7);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && source_size != 0U) {
        status = sqlite3_bind_blob(statement, 8, canonical_address,
                                   (int)source_size, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        status = sqlite3_bind_null(statement, 8);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && source_size != 0U) {
        status = sqlite3_bind_int(statement, 9, config->source_prefix);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        status = sqlite3_bind_null(statement, 9);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 10,
                                    (sqlite3_int64)config->requests_per_minute);
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

        if (identifier <= 0) {
            result = -EIO;
        } else {
            *token_id = (uint64_t)identifier;
        }
    }
    sodium_memzero(canonical_address, sizeof(canonical_address));
    return result;
}

/** @brief Issue one API token constrained by current owner permissions. */
int jg_account_token_issue(struct jg_database *database,
                           uint64_t user_id,
                           const struct jg_account_token_config *config,
                           uint64_t now,
                           struct jg_account_api_token *token)
{
    uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE];
    char scopes[JG_ACCESS_SCOPE_TEXT_MAX + 1U];
    uint32_t owner_permissions = 0U;
    bool owner_enabled = false;
    bool transaction_open = false;
    int result = 0;

    if (token == NULL) {
        return -EINVAL;
    }
    (void)memset(token, 0, sizeof(*token));
    if (database == NULL || user_id == 0U || user_id > (uint64_t)INT64_MAX ||
        now == 0U || now > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = token_config_validate(config, now);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
        transaction_open = result == 0;
    }
    if (result == 0) {
        result = load_token_owner(database->handle, user_id, &owner_enabled,
                                  &owner_permissions);
    }
    if (result == 0 &&
        (!owner_enabled ||
         !jg_access_grants(owner_permissions, config->permissions))) {
        result = -EACCES;
    }
    if (result == 0) {
        result =
            jg_access_scope_format(config->permissions, scopes, sizeof(scopes));
    }
    if (result == 0) {
        result = jg_auth_secret_issue(token->secret, digest);
    }
    if (result == 0) {
        result = insert_api_token(database->handle, user_id, config, digest,
                                  scopes, now, &token->token_id);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    sodium_memzero(digest, sizeof(digest));
    if (result != 0) {
        sodium_memzero(token, sizeof(*token));
    }
    return result;
}

/** @brief Decode one safe administrative API-token metadata row. */
static int decode_token_row(sqlite3_stmt *statement,
                            struct jg_account_token_record *token)
{
    const sqlite3_int64 token_id = sqlite3_column_int64(statement, 0);
    const sqlite3_int64 user_id = sqlite3_column_int64(statement, 1);
    const char *username = (const char *)sqlite3_column_text(statement, 2);
    const char *name = (const char *)sqlite3_column_text(statement, 3);
    const char *scopes = (const char *)sqlite3_column_text(statement, 4);
    const int username_size = sqlite3_column_bytes(statement, 2);
    const int name_size = sqlite3_column_bytes(statement, 3);
    const sqlite3_int64 created_at = sqlite3_column_int64(statement, 5);
    const sqlite3_int64 requests_per_minute =
        sqlite3_column_int64(statement, 12);
    const sqlite3_int64 revision = sqlite3_column_int64(statement, 13);
    const int family_type = sqlite3_column_type(statement, 9);
    const int address_type = sqlite3_column_type(statement, 10);
    const int prefix_type = sqlite3_column_type(statement, 11);
    const void *source_address = sqlite3_column_blob(statement, 10);
    const int source_size = sqlite3_column_bytes(statement, 10);
    uint32_t permissions = 0U;

    if (token == NULL || token_id <= 0 || user_id <= 0 || username == NULL ||
        username_size <= 0 || (size_t)username_size > JG_ACCOUNT_USERNAME_MAX ||
        name == NULL || name_size <= 0 ||
        (size_t)name_size > JG_ACCOUNT_TOKEN_NAME_MAX || scopes == NULL ||
        created_at < 0 || requests_per_minute < JG_ACCOUNT_TOKEN_RATE_MIN ||
        requests_per_minute > JG_ACCOUNT_TOKEN_RATE_MAX || revision <= 0 ||
        (sqlite3_column_type(statement, 6) != SQLITE_NULL &&
         (sqlite3_column_type(statement, 6) != SQLITE_INTEGER ||
          sqlite3_column_int64(statement, 6) < 0)) ||
        (sqlite3_column_type(statement, 7) != SQLITE_NULL &&
         (sqlite3_column_type(statement, 7) != SQLITE_INTEGER ||
          sqlite3_column_int64(statement, 7) < 0)) ||
        (sqlite3_column_type(statement, 8) != SQLITE_NULL &&
         (sqlite3_column_type(statement, 8) != SQLITE_INTEGER ||
          sqlite3_column_int64(statement, 8) < 0)) ||
        !((family_type == SQLITE_NULL && address_type == SQLITE_NULL &&
           prefix_type == SQLITE_NULL) ||
          (family_type == SQLITE_INTEGER && address_type == SQLITE_BLOB &&
           prefix_type == SQLITE_INTEGER && source_address != NULL &&
           ((sqlite3_column_int(statement, 9) == JG_POLICY_ADDRESS_IPV4 &&
             source_size == 4 && sqlite3_column_int(statement, 11) >= 0 &&
             sqlite3_column_int(statement, 11) <= 32) ||
            (sqlite3_column_int(statement, 9) == JG_POLICY_ADDRESS_IPV6 &&
             source_size == 16 && sqlite3_column_int(statement, 11) >= 0 &&
             sqlite3_column_int(statement, 11) <= 128)))) ||
        jg_access_scope_parse(scopes, &permissions) != 0) {
        return -EILSEQ;
    }
    (void)memset(token, 0, sizeof(*token));
    token->token_id = (uint64_t)token_id;
    token->user_id = (uint64_t)user_id;
    token->revision = (uint64_t)revision;
    token->created_at = (uint64_t)created_at;
    if (sqlite3_column_type(statement, 6) == SQLITE_INTEGER) {
        token->expires_at = (uint64_t)sqlite3_column_int64(statement, 6);
    }
    if (sqlite3_column_type(statement, 7) == SQLITE_INTEGER) {
        token->last_used_at = (uint64_t)sqlite3_column_int64(statement, 7);
    }
    if (sqlite3_column_type(statement, 8) == SQLITE_INTEGER) {
        token->revoked_at = (uint64_t)sqlite3_column_int64(statement, 8);
    }
    token->permissions = permissions;
    token->requests_per_minute = (uint32_t)requests_per_minute;
    if (family_type == SQLITE_INTEGER) {
        token->source_family =
            (enum jg_policy_address_family)sqlite3_column_int(statement, 9);
        (void)memcpy(token->source_address, source_address,
                     (size_t)source_size);
        token->source_prefix = (uint8_t)sqlite3_column_int(statement, 11);
    }
    (void)memcpy(token->name, name, (size_t)name_size);
    token->name[(size_t)name_size] = '\0';
    (void)memcpy(token->username, username, (size_t)username_size);
    token->username[(size_t)username_size] = '\0';
    if (!token_name_valid(token->name) || !username_valid(token->username)) {
        (void)memset(token, 0, sizeof(*token));
        return -EILSEQ;
    }
    return 0;
}

/** @brief Read one safe administrative API-token metadata record. */
int jg_account_token_get(struct jg_database *database,
                         uint64_t token_id,
                         struct jg_account_token_record *token)
{
    static const char query[] =
        "SELECT t.id,t.user_id,u.username,t.name,t.scopes,t.created_at,"
        "t.expires_at,t.last_used_at,t.revoked_at,t.source_family,"
        "t.source_address,t.source_prefix,t.requests_per_minute,t.revision"
        " FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (token != NULL) {
        (void)memset(token, 0, sizeof(*token));
    }
    if (database == NULL || token_id == 0U || token_id > (uint64_t)INT64_MAX ||
        token == NULL) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)token_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_ROW) {
            result = decode_token_row(statement, token);
        } else if (status == SQLITE_DONE) {
            result = -ENOENT;
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
    if (result != 0) {
        (void)memset(token, 0, sizeof(*token));
    }
    return result;
}

/** @brief List one stable bounded page of safe API-token metadata. */
int jg_account_token_list(struct jg_database *database,
                          uint64_t offset,
                          struct jg_account_token_record *tokens,
                          size_t capacity,
                          size_t *count,
                          uint64_t *total)
{
    static const char count_query[] = "SELECT count(*) FROM api_tokens;";
    static const char list_query[] =
        "SELECT t.id,t.user_id,u.username,t.name,t.scopes,t.created_at,"
        "t.expires_at,t.last_used_at,t.revoked_at,t.source_family,"
        "t.source_address,t.source_prefix,t.requests_per_minute,t.revision"
        " FROM api_tokens t JOIN users u ON u.id=t.user_id"
        " ORDER BY t.id LIMIT ?1 OFFSET ?2;";
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
    if (database == NULL || tokens == NULL || count == NULL || total == NULL ||
        capacity == 0U || capacity > JG_ACCOUNT_TOKEN_PAGE_MAX ||
        capacity > (size_t)INT64_MAX || offset > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    (void)memset(tokens, 0, capacity * sizeof(*tokens));
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
    while (result == 0 && loaded < capacity) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            break;
        }
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            result = decode_token_row(statement, &tokens[loaded]);
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
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
            *count = loaded;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
        (void)memset(tokens, 0, capacity * sizeof(*tokens));
        *count = 0U;
        *total = 0U;
    }
    return result;
}

/** Fields copied from one persistent API token and its owner. */
struct api_token_record {
    uint64_t token_id;
    uint64_t user_id;
    uint64_t expires_at;
    uint64_t last_used_at;
    uint64_t revision;
    uint64_t session_epoch;
    uint32_t scoped_permissions;
    uint32_t requests_per_minute;
    uint8_t source_address[16U];
    uint8_t source_prefix;
    size_t source_address_size;
    char username[JG_ACCOUNT_USERNAME_MAX + 1U];
    bool has_expiry;
    bool has_last_use;
    bool enabled;
    bool force_password_change;
};

/** @brief Load one API token and current owning user by token digest. */
static int load_api_token(sqlite3 *handle,
                          const uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE],
                          struct api_token_record *record)
{
    static const char query[] =
        "SELECT t.id,t.user_id,t.scopes,t.expires_at,t.last_used_at,"
        "t.revoked_at,t.source_family,t.source_address,t.source_prefix,"
        "t.requests_per_minute,u.username,u.enabled,u.force_password_change,"
        "u.revision,u.session_epoch"
        " FROM api_tokens t JOIN users u ON u.id=t.user_id"
        " WHERE t.token_hash=?1;";
    sqlite3_stmt *statement = NULL;
    const char *scopes = NULL;
    const void *source_address = NULL;
    const char *username = NULL;
    int source_size = 0;
    int username_size = 0;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    (void)memset(record, 0, sizeof(*record));
    if (result == 0) {
        status = sqlite3_bind_blob(
            statement, 1, digest, JG_AUTH_SECRET_DIGEST_SIZE, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        scopes = (const char *)sqlite3_column_text(statement, 2);
        source_address = sqlite3_column_blob(statement, 7);
        source_size = sqlite3_column_bytes(statement, 7);
        username = (const char *)sqlite3_column_text(statement, 10);
        username_size = sqlite3_column_bytes(statement, 10);
        if (sqlite3_column_type(statement, 0) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 0) <= 0 ||
            sqlite3_column_type(statement, 1) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 1) <= 0 ||
            sqlite3_column_type(statement, 2) != SQLITE_TEXT ||
            (sqlite3_column_type(statement, 3) != SQLITE_NULL &&
             (sqlite3_column_type(statement, 3) != SQLITE_INTEGER ||
              sqlite3_column_int64(statement, 3) < 0)) ||
            (sqlite3_column_type(statement, 4) != SQLITE_NULL &&
             (sqlite3_column_type(statement, 4) != SQLITE_INTEGER ||
              sqlite3_column_int64(statement, 4) < 0)) ||
            (sqlite3_column_type(statement, 5) != SQLITE_NULL &&
             (sqlite3_column_type(statement, 5) != SQLITE_INTEGER ||
              sqlite3_column_int64(statement, 5) < 0)) ||
            !((sqlite3_column_type(statement, 6) == SQLITE_NULL &&
               sqlite3_column_type(statement, 7) == SQLITE_NULL &&
               sqlite3_column_type(statement, 8) == SQLITE_NULL) ||
              (sqlite3_column_type(statement, 6) == SQLITE_INTEGER &&
               sqlite3_column_type(statement, 7) == SQLITE_BLOB &&
               sqlite3_column_type(statement, 8) == SQLITE_INTEGER &&
               ((sqlite3_column_int(statement, 6) == 4 && source_size == 4 &&
                 sqlite3_column_int(statement, 8) >= 0 &&
                 sqlite3_column_int(statement, 8) <= 32) ||
                (sqlite3_column_int(statement, 6) == 6 && source_size == 16 &&
                 sqlite3_column_int(statement, 8) >= 0 &&
                 sqlite3_column_int(statement, 8) <= 128)))) ||
            sqlite3_column_type(statement, 9) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 9) < JG_ACCOUNT_TOKEN_RATE_MIN ||
            sqlite3_column_int64(statement, 9) > JG_ACCOUNT_TOKEN_RATE_MAX ||
            sqlite3_column_type(statement, 10) != SQLITE_TEXT ||
            username_size <= 0 ||
            (size_t)username_size > JG_ACCOUNT_USERNAME_MAX ||
            sqlite3_column_type(statement, 11) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 12) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 13) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 13) <= 0 ||
            sqlite3_column_type(statement, 14) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 14) <= 0) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        result = jg_access_scope_parse(scopes, &record->scoped_permissions);
        if (result != 0) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        record->token_id = (uint64_t)sqlite3_column_int64(statement, 0);
        record->user_id = (uint64_t)sqlite3_column_int64(statement, 1);
        if (sqlite3_column_type(statement, 3) == SQLITE_INTEGER) {
            record->has_expiry = true;
            record->expires_at = (uint64_t)sqlite3_column_int64(statement, 3);
        }
        if (sqlite3_column_type(statement, 4) == SQLITE_INTEGER) {
            record->has_last_use = true;
            record->last_used_at = (uint64_t)sqlite3_column_int64(statement, 4);
        }
        if (sqlite3_column_type(statement, 5) == SQLITE_INTEGER) {
            result = -EACCES;
        }
        if (source_size > 0) {
            (void)memcpy(record->source_address, source_address,
                         (size_t)source_size);
            record->source_address_size = (size_t)source_size;
            record->source_prefix = (uint8_t)sqlite3_column_int(statement, 8);
        }
        record->requests_per_minute =
            (uint32_t)sqlite3_column_int64(statement, 9);
        (void)memcpy(record->username, username, (size_t)username_size);
        record->username[(size_t)username_size] = '\0';
        record->enabled = sqlite3_column_int(statement, 11) != 0;
        record->force_password_change = sqlite3_column_int(statement, 12) != 0;
        record->revision = (uint64_t)sqlite3_column_int64(statement, 13);
        record->session_epoch = (uint64_t)sqlite3_column_int64(statement, 14);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Match one source address against a persistent network prefix. */
static bool source_network_matches(const struct api_token_record *record,
                                   enum jg_policy_address_family remote_family,
                                   const uint8_t *remote_address)
{
    const size_t remote_size = address_size(remote_family);
    const size_t complete_bytes = (size_t)record->source_prefix / 8U;
    const uint8_t remaining_bits = (uint8_t)(record->source_prefix % 8U);

    if (record->source_address_size == 0U) {
        return true;
    }
    if (remote_address == NULL || remote_size != record->source_address_size ||
        memcmp(record->source_address, remote_address, complete_bytes) != 0) {
        return false;
    }
    if (remaining_bits == 0U) {
        return true;
    }
    return (record->source_address[complete_bytes] >> (8U - remaining_bits)) ==
           (remote_address[complete_bytes] >> (8U - remaining_bits));
}

/** @brief Advance one API token's last-use timestamp. */
static int touch_api_token(sqlite3 *handle, uint64_t token_id, uint64_t now)
{
    static const char update[] =
        "UPDATE api_tokens SET last_used_at=?1 WHERE id=?2;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)token_id);
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

/** @brief Authenticate one API token with current owner and source policy. */
int jg_account_token_validate(struct jg_database *database,
                              const uint8_t *token,
                              size_t token_size,
                              uint64_t now,
                              enum jg_policy_address_family remote_family,
                              const uint8_t *remote_address,
                              struct jg_account_identity *identity,
                              uint64_t *token_id,
                              uint32_t *requests_per_minute)
{
    struct api_token_record record;
    uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE];
    uint32_t role_permissions = 0U;
    bool ignored_totp = false;
    bool transaction_open = false;
    int authentication_result = 0;
    int result = 0;

    if (identity == NULL || token_id == NULL || requests_per_minute == NULL) {
        return -EINVAL;
    }
    (void)memset(identity, 0, sizeof(*identity));
    *token_id = 0U;
    *requests_per_minute = 0U;
    if (database == NULL || token == NULL ||
        token_size != JG_AUTH_SECRET_TEXT_SIZE - 1U || now == 0U ||
        now > (uint64_t)INT64_MAX ||
        !remote_address_valid(remote_family, remote_address) ||
        remote_family == JG_POLICY_ADDRESS_NONE) {
        return -EINVAL;
    }
    result = jg_auth_secret_digest(token, token_size, digest);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
        transaction_open = result == 0;
    }
    if (result == 0) {
        result = load_api_token(database->handle, digest, &record);
        if (result == -ENOENT || result == -EACCES) {
            result = 0;
            authentication_result = -EACCES;
        }
    }
    if (result == 0 && authentication_result == 0 &&
        (!record.enabled || record.force_password_change ||
         (record.has_expiry && record.expires_at <= now) ||
         !source_network_matches(&record, remote_family, remote_address))) {
        authentication_result = -EACCES;
    }
    if (result == 0 && authentication_result == 0) {
        result = load_identity_authorization(database->handle, record.user_id,
                                             &role_permissions, &ignored_totp);
    }
    if (result == 0 && authentication_result == 0) {
        role_permissions &= record.scoped_permissions;
        if (role_permissions == 0U) {
            authentication_result = -EACCES;
        }
    }
    if (result == 0 && authentication_result == 0 &&
        (!record.has_last_use ||
         (record.last_used_at <= now &&
          now - record.last_used_at >= JG_ACCOUNT_SESSION_TOUCH_INTERVAL))) {
        result = touch_api_token(database->handle, record.token_id, now);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0 && authentication_result == 0) {
        identity->user_id = record.user_id;
        (void)memcpy(identity->username, record.username,
                     strlen(record.username) + 1U);
        identity->permissions = role_permissions;
        identity->revision = record.revision;
        identity->session_epoch = record.session_epoch;
        identity->force_password_change = false;
        identity->totp_enabled = false;
        identity->mfa_complete = true;
        *token_id = record.token_id;
        *requests_per_minute = record.requests_per_minute;
    }
    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(&record, sizeof(record));
    return result == 0 ? authentication_result : result;
}

/** @brief Persist one idempotent API-token revocation. */
int jg_account_token_revoke(struct jg_database *database,
                            uint64_t token_id,
                            uint64_t now)
{
    static const char update[] =
        "UPDATE api_tokens SET revoked_at=coalesce(revoked_at,?1),"
        "revision=CASE WHEN revoked_at IS NULL THEN revision+1 ELSE revision "
        "END"
        " WHERE id=?2;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || token_id == 0U || token_id > (uint64_t)INT64_MAX ||
        now == 0U || now > (uint64_t)INT64_MAX) {
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
        status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)token_id);
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
        (maps_role && !role_valid(config->role)) ||
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
        role = role_from_id(role_id);
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
        if (!username_valid(mapping->username)) {
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

/** Persistent encrypted TOTP credential copied from SQLite. */
struct totp_record {
    uint8_t ciphertext[JG_AUTH_TOTP_CIPHERTEXT_SIZE];
    uint8_t nonce[JG_AUTH_TOTP_NONCE_SIZE];
    bool enabled;
};

/** @brief Read an optional encrypted TOTP credential for one user. */
static int load_totp_record(sqlite3 *handle,
                            uint64_t user_id,
                            struct totp_record *record)
{
    static const char query[] = "SELECT secret_ciphertext,nonce,enabled"
                                " FROM totp_credentials WHERE user_id=?1;";
    sqlite3_stmt *statement = NULL;
    const void *ciphertext = NULL;
    const void *nonce = NULL;
    int ciphertext_size = 0;
    int nonce_size = 0;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    (void)memset(record, 0, sizeof(*record));
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        ciphertext = sqlite3_column_blob(statement, 0);
        ciphertext_size = sqlite3_column_bytes(statement, 0);
        nonce = sqlite3_column_blob(statement, 1);
        nonce_size = sqlite3_column_bytes(statement, 1);
        if (sqlite3_column_type(statement, 0) != SQLITE_BLOB ||
            ciphertext_size != JG_AUTH_TOTP_CIPHERTEXT_SIZE ||
            sqlite3_column_type(statement, 1) != SQLITE_BLOB ||
            nonce_size != JG_AUTH_TOTP_NONCE_SIZE ||
            sqlite3_column_type(statement, 2) != SQLITE_INTEGER) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        (void)memcpy(record->ciphertext, ciphertext,
                     sizeof(record->ciphertext));
        (void)memcpy(record->nonce, nonce, sizeof(record->nonce));
        record->enabled = sqlite3_column_int(statement, 2) != 0;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Insert or replace one disabled encrypted TOTP enrollment. */
static int store_pending_totp(
    sqlite3 *handle,
    uint64_t user_id,
    const uint8_t ciphertext[JG_AUTH_TOTP_CIPHERTEXT_SIZE],
    const uint8_t nonce[JG_AUTH_TOTP_NONCE_SIZE],
    uint64_t now)
{
    static const char upsert[] =
        "INSERT INTO totp_credentials("
        "user_id,secret_ciphertext,nonce,enabled,created_at"
        ") VALUES(?1,?2,?3,0,?4)"
        " ON CONFLICT(user_id) DO UPDATE SET"
        " secret_ciphertext=excluded.secret_ciphertext,"
        " nonce=excluded.nonce,enabled=0,created_at=excluded.created_at;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, upsert, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_blob(statement, 2, ciphertext,
                              JG_AUTH_TOTP_CIPHERTEXT_SIZE, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_blob(statement, 3, nonce, JG_AUTH_TOTP_NONCE_SIZE,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 4, (sqlite3_int64)now);
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

/** @brief Delete every recovery code for one user inside a transaction. */
static int delete_recovery_codes(sqlite3 *handle, uint64_t user_id)
{
    static const char delete_codes[] =
        "DELETE FROM recovery_codes WHERE user_id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, delete_codes, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
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

/** @brief Begin encrypted TOTP enrollment for one enabled user. */
int jg_account_totp_provision(struct jg_database *database,
                              uint64_t user_id,
                              const uint8_t key[JG_AUTH_TOTP_KEY_SIZE],
                              uint64_t now,
                              struct jg_account_totp_provisioning *provisioning)
{
    struct totp_record existing;
    uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE];
    uint8_t ciphertext[JG_AUTH_TOTP_CIPHERTEXT_SIZE];
    uint8_t nonce[JG_AUTH_TOTP_NONCE_SIZE];
    uint32_t ignored_permissions = 0U;
    bool user_enabled = false;
    bool transaction_open = false;
    int result = 0;

    if (provisioning == NULL) {
        return -EINVAL;
    }
    (void)memset(provisioning, 0, sizeof(*provisioning));
    if (database == NULL || user_id == 0U || user_id > (uint64_t)INT64_MAX ||
        key == NULL || now == 0U || now > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = jg_auth_totp_secret_issue(secret, provisioning->secret);
    if (result == 0) {
        result = jg_auth_totp_encrypt(key, secret, nonce, ciphertext);
    }
    if (result == 0) {
        result = jg_database_transaction_begin(database);
        transaction_open = result == 0;
    }
    if (result == 0) {
        result = load_token_owner(database->handle, user_id, &user_enabled,
                                  &ignored_permissions);
    }
    if (result == 0 && !user_enabled) {
        result = -EACCES;
    }
    if (result == 0) {
        result = load_totp_record(database->handle, user_id, &existing);
        if (result == -ENOENT) {
            result = 0;
        } else if (result == 0 && existing.enabled) {
            result = -EEXIST;
        }
    }
    if (result == 0) {
        result = store_pending_totp(database->handle, user_id, ciphertext,
                                    nonce, now);
    }
    if (result == 0) {
        result = delete_recovery_codes(database->handle, user_id);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    sodium_memzero(&existing, sizeof(existing));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(ciphertext, sizeof(ciphertext));
    sodium_memzero(secret, sizeof(secret));
    if (result != 0) {
        sodium_memzero(provisioning, sizeof(*provisioning));
    }
    return result;
}

/** @brief Generate independent recovery values and persistent digests. */
static int generate_recovery_codes(
    struct jg_account_recovery_codes *codes,
    uint8_t digests[JG_ACCOUNT_RECOVERY_CODE_COUNT][JG_AUTH_SECRET_DIGEST_SIZE])
{
    int result = 0;

    (void)memset(codes, 0, sizeof(*codes));
    (void)memset(digests, 0,
                 JG_ACCOUNT_RECOVERY_CODE_COUNT * JG_AUTH_SECRET_DIGEST_SIZE);
    for (size_t index = 0U;
         result == 0 && index < JG_ACCOUNT_RECOVERY_CODE_COUNT; ++index) {
        result = jg_auth_secret_issue(codes->codes[index], digests[index]);
    }
    return result;
}

/** @brief Replace every persistent recovery-code digest for one user. */
static int store_recovery_codes(
    sqlite3 *handle,
    uint64_t user_id,
    uint8_t digests[JG_ACCOUNT_RECOVERY_CODE_COUNT][JG_AUTH_SECRET_DIGEST_SIZE],
    uint64_t now)
{
    static const char insert[] =
        "INSERT INTO recovery_codes(user_id,code_hash,created_at,used_at)"
        " VALUES(?1,?2,?3,NULL);";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, insert, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        result = delete_recovery_codes(handle, user_id);
    }
    for (size_t index = 0U;
         result == 0 && index < JG_ACCOUNT_RECOVERY_CODE_COUNT; ++index) {
        status = sqlite3_reset(statement);
        result = jg_database_sqlite_result(status);
        if (result == 0) {
            result =
                jg_database_sqlite_result(sqlite3_clear_bindings(statement));
        }
        if (result == 0) {
            status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
            result = jg_database_sqlite_result(status);
        }
        if (result == 0) {
            status =
                sqlite3_bind_blob(statement, 2, digests[index],
                                  JG_AUTH_SECRET_DIGEST_SIZE, SQLITE_TRANSIENT);
            result = jg_database_sqlite_result(status);
        }
        if (result == 0) {
            status = sqlite3_bind_int64(statement, 3, (sqlite3_int64)now);
            result = jg_database_sqlite_result(status);
        }
        if (result == 0) {
            status = sqlite3_step(statement);
            result =
                status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
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

/** @brief Set the persistent TOTP credential enabled state. */
static int enable_totp(sqlite3 *handle, uint64_t user_id)
{
    static const char update[] = "UPDATE totp_credentials SET enabled=1"
                                 " WHERE user_id=?1 AND enabled=0;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(handle) != 1) {
        result = -EALREADY;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Advance one user epoch and delete its sessions in a transaction. */
static int advance_user_epoch(sqlite3 *handle, uint64_t user_id)
{
    static const char update_user[] =
        "UPDATE users SET session_epoch=session_epoch+1,revision=revision+1"
        " WHERE id=?1;";
    static const char delete_sessions[] =
        "DELETE FROM web_sessions WHERE user_id=?1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update_user, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(handle) != 1) {
        result = -ENOENT;
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
            sqlite3_prepare_v3(handle, delete_sessions, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
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

/** @brief Confirm pending TOTP and atomically issue recovery codes. */
int jg_account_totp_confirm(struct jg_database *database,
                            uint64_t user_id,
                            const uint8_t key[JG_AUTH_TOTP_KEY_SIZE],
                            uint32_t code,
                            uint64_t now,
                            struct jg_account_recovery_codes *recovery_codes)
{
    struct totp_record record;
    uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE];
    uint8_t digests[JG_ACCOUNT_RECOVERY_CODE_COUNT][JG_AUTH_SECRET_DIGEST_SIZE];
    bool code_valid = false;
    bool transaction_open = false;
    int result = 0;

    if (recovery_codes == NULL) {
        return -EINVAL;
    }
    (void)memset(recovery_codes, 0, sizeof(*recovery_codes));
    if (database == NULL || user_id == 0U || user_id > (uint64_t)INT64_MAX ||
        key == NULL || code >= UINT32_C(1000000) || now == 0U ||
        now > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin(database);
    transaction_open = result == 0;
    if (result == 0) {
        result = load_totp_record(database->handle, user_id, &record);
    }
    if (result == 0 && record.enabled) {
        result = -EALREADY;
    }
    if (result == 0) {
        result =
            jg_auth_totp_decrypt(key, record.nonce, record.ciphertext, secret);
    }
    if (result == 0) {
        result = jg_auth_totp_verify(secret, now, code, 1U, &code_valid);
    }
    if (result == 0 && !code_valid) {
        result = -EACCES;
    }
    if (result == 0) {
        result = generate_recovery_codes(recovery_codes, digests);
    }
    if (result == 0) {
        result = store_recovery_codes(database->handle, user_id, digests, now);
    }
    if (result == 0) {
        result = enable_totp(database->handle, user_id);
    }
    if (result == 0) {
        result = advance_user_epoch(database->handle, user_id);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    sodium_memzero(digests, sizeof(digests));
    sodium_memzero(secret, sizeof(secret));
    sodium_memzero(&record, sizeof(record));
    if (result != 0) {
        sodium_memzero(recovery_codes, sizeof(*recovery_codes));
    }
    return result;
}

/** @brief Load one current enabled identity by persistent identifier. */
static int load_current_identity(sqlite3 *handle,
                                 uint64_t user_id,
                                 struct jg_account_identity *identity)
{
    static const char query[] =
        "SELECT username,enabled,force_password_change,revision,session_epoch"
        " FROM users WHERE id=?1;";
    sqlite3_stmt *statement = NULL;
    const char *username = NULL;
    uint32_t permissions = 0U;
    bool totp_enabled = false;
    int username_size = 0;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    (void)memset(identity, 0, sizeof(*identity));
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        username = (const char *)sqlite3_column_text(statement, 0);
        username_size = sqlite3_column_bytes(statement, 0);
        if (sqlite3_column_type(statement, 0) != SQLITE_TEXT ||
            username_size <= 0 ||
            (size_t)username_size > JG_ACCOUNT_USERNAME_MAX ||
            sqlite3_column_type(statement, 1) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 2) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 3) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 3) <= 0 ||
            sqlite3_column_type(statement, 4) != SQLITE_INTEGER ||
            sqlite3_column_int64(statement, 4) <= 0) {
            result = -EILSEQ;
        } else if (sqlite3_column_int(statement, 1) == 0) {
            result = -EACCES;
        }
    }
    if (result == 0) {
        identity->user_id = user_id;
        (void)memcpy(identity->username, username, (size_t)username_size);
        identity->username[(size_t)username_size] = '\0';
        identity->force_password_change = sqlite3_column_int(statement, 2) != 0;
        identity->revision = (uint64_t)sqlite3_column_int64(statement, 3);
        identity->session_epoch = (uint64_t)sqlite3_column_int64(statement, 4);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = load_identity_authorization(handle, user_id, &permissions,
                                             &totp_enabled);
    }
    if (result == 0) {
        identity->permissions = permissions;
        identity->totp_enabled = totp_enabled;
        identity->mfa_complete = !totp_enabled;
    }
    return result;
}

/** @brief Check that a password identity still denotes the current user. */
static bool password_identity_current(
    const struct jg_account_identity *password_identity,
    const struct jg_account_identity *current)
{
    return password_identity->user_id == current->user_id &&
           password_identity->revision == current->revision &&
           password_identity->session_epoch == current->session_epoch &&
           strcmp(password_identity->username, current->username) == 0 &&
           password_identity->totp_enabled &&
           !password_identity->mfa_complete && current->totp_enabled;
}

/** @brief Complete password authentication using current TOTP. */
int jg_account_totp_authenticate(
    struct jg_database *database,
    const struct jg_account_identity *password_identity,
    const uint8_t key[JG_AUTH_TOTP_KEY_SIZE],
    uint32_t code,
    uint64_t now,
    struct jg_account_identity *identity)
{
    struct jg_account_identity current;
    struct totp_record record;
    uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE];
    bool code_valid = false;
    int result = 0;

    if (identity == NULL) {
        return -EINVAL;
    }
    (void)memset(identity, 0, sizeof(*identity));
    if (database == NULL || password_identity == NULL ||
        password_identity->user_id == 0U || key == NULL ||
        code >= UINT32_C(1000000) || now == 0U) {
        return -EINVAL;
    }
    result = load_current_identity(database->handle, password_identity->user_id,
                                   &current);
    if (result == 0 &&
        !password_identity_current(password_identity, &current)) {
        result = -EACCES;
    }
    if (result == 0) {
        result = load_totp_record(database->handle, current.user_id, &record);
    }
    if (result == 0 && !record.enabled) {
        result = -ENOENT;
    }
    if (result == 0) {
        result =
            jg_auth_totp_decrypt(key, record.nonce, record.ciphertext, secret);
    }
    if (result == 0) {
        result = jg_auth_totp_verify(secret, now, code, 1U, &code_valid);
    }
    if (result == 0 && !code_valid) {
        result = -EACCES;
    }
    if (result == 0) {
        current.mfa_complete = true;
        *identity = current;
    }
    sodium_memzero(secret, sizeof(secret));
    sodium_memzero(&record, sizeof(record));
    sodium_memzero(&current, sizeof(current));
    return result;
}

/** @brief Consume one unused recovery-code digest. */
static int consume_recovery_code(
    sqlite3 *handle,
    uint64_t user_id,
    const uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE],
    uint64_t now)
{
    static const char update[] =
        "UPDATE recovery_codes SET used_at=?1"
        " WHERE user_id=?2 AND code_hash=?3 AND used_at IS NULL;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)now);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)user_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_blob(
            statement, 3, digest, JG_AUTH_SECRET_DIGEST_SIZE, SQLITE_TRANSIENT);
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

/** @brief Complete password authentication with one recovery code. */
int jg_account_recovery_authenticate(
    struct jg_database *database,
    const struct jg_account_identity *password_identity,
    const uint8_t *recovery_code,
    size_t recovery_code_size,
    uint64_t now,
    struct jg_account_identity *identity)
{
    struct jg_account_identity current;
    uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE];
    bool transaction_open = false;
    int result = 0;

    if (identity == NULL) {
        return -EINVAL;
    }
    (void)memset(identity, 0, sizeof(*identity));
    if (database == NULL || password_identity == NULL ||
        password_identity->user_id == 0U || recovery_code == NULL ||
        recovery_code_size != JG_AUTH_SECRET_TEXT_SIZE - 1U || now == 0U ||
        now > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = jg_auth_secret_digest(recovery_code, recovery_code_size, digest);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
        transaction_open = result == 0;
    }
    if (result == 0) {
        result = load_current_identity(database->handle,
                                       password_identity->user_id, &current);
    }
    if (result == 0 &&
        !password_identity_current(password_identity, &current)) {
        result = -EACCES;
    }
    if (result == 0) {
        result = consume_recovery_code(database->handle, current.user_id,
                                       digest, now);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        current.mfa_complete = true;
        *identity = current;
    }
    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(&current, sizeof(current));
    return result;
}

/** @brief Delete TOTP state with optional revision and result handling. */
static int disable_totp(struct jg_database *database,
                        uint64_t user_id,
                        uint64_t expected_revision,
                        struct jg_account_user *user)
{
    static const char delete_totp[] =
        "DELETE FROM totp_credentials WHERE user_id=?1;";
    struct jg_account_user current = {0};
    sqlite3_stmt *statement = NULL;
    bool transaction_open = false;
    int status = SQLITE_OK;
    int result = 0;

    if (user != NULL) {
        (void)memset(user, 0, sizeof(*user));
    }
    if (database == NULL || user_id == 0U || user_id > (uint64_t)INT64_MAX ||
        expected_revision > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin(database);
    transaction_open = result == 0;
    if (result == 0) {
        result = load_user(database->handle, user_id, &current);
    }
    if (result == 0 && expected_revision != 0U &&
        current.revision != expected_revision) {
        result = -ESTALE;
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, delete_totp, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id);
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
    if (result == 0) {
        result = delete_recovery_codes(database->handle, user_id);
    }
    if (result == 0) {
        result = advance_user_epoch(database->handle, user_id);
    }
    if (result == 0 && user != NULL) {
        result = load_user(database->handle, user_id, user);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    if (result != 0 && user != NULL) {
        (void)memset(user, 0, sizeof(*user));
    }
    return result;
}

/** @brief Administratively remove one user's TOTP credentials. */
int jg_account_user_disable_totp(struct jg_database *database,
                                 uint64_t user_id,
                                 uint64_t expected_revision,
                                 struct jg_account_user *user)
{
    if (expected_revision == 0U || user == NULL) {
        return -EINVAL;
    }
    return disable_totp(database, user_id, expected_revision, user);
}

/** @brief Delete TOTP state and invalidate every user session. */
int jg_account_totp_disable(struct jg_database *database, uint64_t user_id)
{
    return disable_totp(database, user_id, 0U, NULL);
}
