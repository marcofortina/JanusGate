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
    (void)memset(replacement_hash, 0, sizeof(replacement_hash));
    if (database == NULL || !username_valid(username) || password == NULL ||
        password_size > JG_AUTH_PASSWORD_MAX || now == 0U ||
        now > (uint64_t)INT64_MAX - JG_ACCOUNT_LOCK_DELAY_MAX) {
        return password_size > JG_AUTH_PASSWORD_MAX ? -ERANGE : -EINVAL;
    }
    result = execute_fixed(database->handle, "BEGIN IMMEDIATE;");
    transaction_open = result == 0;
    if (result == 0) {
        result =
            load_authentication_record(database->handle, username, &record);
        if (result == -ENOENT) {
            result = perform_unknown_user_work(password_policy);
            authentication_result = result == 0 ? -EACCES : 0;
        }
    }
    if (result == 0 && authentication_result == 0 && !record.enabled) {
        result = jg_auth_password_verify(password_policy, password,
                                         password_size, record.password_hash,
                                         &password_valid, &needs_rehash);
        authentication_result = result == 0 ? -EACCES : 0;
    }
    if (result == 0 && authentication_result == 0 &&
        record.locked_until > now) {
        authentication_result = -EAGAIN;
    }
    if (result == 0 && authentication_result == 0) {
        result = jg_auth_password_verify(password_policy, password,
                                         password_size, record.password_hash,
                                         &password_valid, &needs_rehash);
    }
    if (result == 0 && authentication_result == 0 && !password_valid) {
        result = record_login_failure(database->handle, &record, now);
        authentication_result = result == 0 ? -EACCES : 0;
    }
    if (result == 0 && authentication_result == 0 && needs_rehash) {
        result = jg_auth_password_hash(password_policy, password, password_size,
                                       replacement_hash);
    }
    if (result == 0 && authentication_result == 0) {
        result = record_login_success(database->handle, record.user_id, now,
                                      needs_rehash ? replacement_hash : NULL);
    }
    if (result == 0 && authentication_result == 0) {
        result = load_identity_authorization(database->handle, record.user_id,
                                             &permissions, &totp_enabled);
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
    if (result == 0 && authentication_result == 0) {
        identity->user_id = record.user_id;
        (void)memcpy(identity->username, username, strlen(username) + 1U);
        identity->permissions = permissions;
        identity->revision = record.revision;
        identity->session_epoch = record.session_epoch;
        identity->force_password_change = record.force_password_change;
        identity->totp_enabled = totp_enabled;
    }
    sodium_memzero(replacement_hash, sizeof(replacement_hash));
    sodium_memzero(&record, sizeof(record));
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
        result = execute_fixed(database->handle, "BEGIN IMMEDIATE;");
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
        result = execute_fixed(database->handle, "COMMIT;");
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)execute_fixed(database->handle, "ROLLBACK;");
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
    result = execute_fixed(database->handle, "BEGIN IMMEDIATE;");
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
        result = execute_fixed(database->handle, "COMMIT;");
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)execute_fixed(database->handle, "ROLLBACK;");
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
        result = execute_fixed(database->handle, "BEGIN IMMEDIATE;");
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
        sodium_memzero(token, sizeof(*token));
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
        result = execute_fixed(database->handle, "BEGIN IMMEDIATE;");
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
        result = execute_fixed(database->handle, "COMMIT;");
        if (result == 0) {
            transaction_open = false;
        }
    }
    if (result != 0 && transaction_open) {
        (void)execute_fixed(database->handle, "ROLLBACK;");
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
