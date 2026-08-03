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
        result = jg_account_load_user_authorization(
            database->handle, user_id, &user_enabled, &ignored_permissions);
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
        result = jg_account_load_identity_authorization(
            handle, user_id, &permissions, &totp_enabled);
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
        result = jg_account_load_user(database->handle, user_id, &current);
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
