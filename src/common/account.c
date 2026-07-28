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
