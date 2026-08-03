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

#include "account_internal.h"
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
bool jg_account_username_valid(const char *username)
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
        !jg_account_username_valid(username) || password == NULL || now == 0U ||
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
enum jg_access_role jg_account_role_from_id(sqlite3_int64 role_id)
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
bool jg_account_role_valid(enum jg_access_role role)
{
    return role != JG_ACCESS_ROLE_NONE &&
           jg_account_role_from_id((sqlite3_int64)role) == role;
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
        jg_account_role_from_id(sqlite3_column_int64(statement, 11));
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
    if (!jg_account_username_valid(user->username)) {
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
int jg_account_load_user(sqlite3 *handle,
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
    if (database == NULL || !jg_account_username_valid(username) ||
        password == NULL || password_policy == NULL ||
        !jg_account_role_valid(role) || now == 0U ||
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
        result = jg_account_load_user(database->handle, user_id, user);
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
        update == NULL || !jg_account_role_valid(update->role) || now == 0U ||
        now > (uint64_t)INT64_MAX || user == NULL) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin(database);
    transaction_open = result == 0;
    if (result == 0) {
        result = jg_account_load_user(database->handle, user_id, &current);
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
        result = jg_account_load_user(database->handle, user_id, user);
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
        result = jg_account_load_user(database->handle, user_id, user);
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
        result = jg_account_load_user(database->handle, user_id, user);
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
int jg_account_load_identity_authorization(sqlite3 *handle,
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

/** @brief Read current user authorization and enablement. */
int jg_account_load_user_authorization(sqlite3 *handle,
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
        result = jg_account_load_identity_authorization(
            handle, user_id, permissions, &ignored_totp);
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
    if (database == NULL || !jg_account_username_valid(username) ||
        password == NULL || password_size > JG_AUTH_PASSWORD_MAX || now == 0U ||
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
        result = jg_account_load_identity_authorization(
            database->handle, current.user_id, &permissions, &totp_enabled);
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
size_t jg_account_address_size(enum jg_policy_address_family family)
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
bool jg_account_remote_address_valid(enum jg_policy_address_family family,
                                     const uint8_t *address)
{
    return (family == JG_POLICY_ADDRESS_NONE && address == NULL) ||
           ((family == JG_POLICY_ADDRESS_IPV4 ||
             family == JG_POLICY_ADDRESS_IPV6) &&
            address != NULL);
}
