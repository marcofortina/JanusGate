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
    const size_t remote_size = jg_account_address_size(remote_family);
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
        !jg_account_remote_address_valid(remote_family, remote_address)) {
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
    const size_t current_size = jg_account_address_size(remote_family);

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
        "UPDATE web_sessions SET last_seen_at=?1 WHERE session_hash=?2 AND "
        "last_seen_at<=?3;";
    const uint64_t cutoff = now >= JG_ACCOUNT_SESSION_TOUCH_INTERVAL
                                ? now - JG_ACCOUNT_SESSION_TOUCH_INTERVAL
                                : 0U;
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
        status = sqlite3_bind_int64(statement, 3, (sqlite3_int64)cutoff);
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
        !jg_account_remote_address_valid(remote_family, remote_address) ||
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
        result = jg_database_transaction_begin_read(database);
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
        result = jg_account_load_identity_authorization(
            database->handle, record.user_id, &permissions, &totp_enabled);
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

/** @brief Persist bounded activity for one previously validated session. */
int jg_account_session_touch(struct jg_database *database,
                             const uint8_t *session,
                             size_t session_size,
                             uint64_t now)
{
    uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE];
    bool transaction_open = false;
    int result = 0;

    if (database == NULL || session == NULL ||
        session_size != JG_AUTH_SECRET_TEXT_SIZE - 1U || now == 0U ||
        now > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = jg_auth_secret_digest(session, session_size, digest);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
        transaction_open = result == 0;
    }
    if (result == 0) {
        result = touch_session(database->handle, digest, now);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
        transaction_open = result != 0;
    }
    if (result != 0 && transaction_open) {
        (void)jg_database_transaction_rollback(database);
    }
    sodium_memzero(digest, sizeof(digest));
    return result;
}

/** @brief Reauthorize one deferred session without retaining its plaintext. */
int jg_account_session_reauthorize(
    struct jg_database *database,
    const uint8_t session_digest[JG_AUTH_SECRET_DIGEST_SIZE],
    uint64_t now,
    uint64_t inactivity_timeout,
    enum jg_policy_address_family remote_family,
    const uint8_t *remote_address,
    struct jg_account_identity *identity)
{
    struct session_record record;
    uint32_t permissions = 0U;
    bool totp_enabled = false;
    bool transaction_open = false;
    int authorization_result = 0;
    int result = 0;

    if (identity == NULL) {
        return -EINVAL;
    }
    (void)memset(identity, 0, sizeof(*identity));
    (void)memset(&record, 0, sizeof(record));
    if (database == NULL || session_digest == NULL || now == 0U ||
        now > (uint64_t)INT64_MAX ||
        !jg_account_remote_address_valid(remote_family, remote_address)) {
        return -EINVAL;
    }
    if (inactivity_timeout < JG_ACCOUNT_SESSION_INACTIVITY_MIN ||
        inactivity_timeout > JG_ACCOUNT_SESSION_INACTIVITY_MAX) {
        return -ERANGE;
    }
    result = jg_database_transaction_begin_read(database);
    transaction_open = result == 0;
    if (result == 0) {
        result = load_session(database->handle, session_digest, &record);
        if (result == -ENOENT) {
            result = 0;
            authorization_result = -EACCES;
        }
    }
    if (result == 0 && authorization_result == 0 &&
        (!record.enabled || record.session_epoch != record.user_session_epoch ||
         record.expires_at <= now || record.last_seen_at > now ||
         now - record.last_seen_at > inactivity_timeout ||
         !session_address_matches(&record, remote_family, remote_address))) {
        authorization_result = -EACCES;
    }
    if (result == 0 && authorization_result == 0) {
        result = jg_account_load_identity_authorization(
            database->handle, record.user_id, &permissions, &totp_enabled);
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
    if (result == 0 && authorization_result == 0) {
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
    sodium_memzero(&record, sizeof(record));
    return result == 0 ? authorization_result : result;
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
