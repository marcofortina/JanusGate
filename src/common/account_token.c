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
    const size_t source_size = jg_account_address_size(config->source_family);
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
        result = jg_account_load_user_authorization(
            database->handle, user_id, &owner_enabled, &owner_permissions);
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
    if (!token_name_valid(token->name) ||
        !jg_account_username_valid(token->username)) {
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

/** @brief Load one API token and current owner by digest or identifier. */
static int load_api_token(sqlite3 *handle,
                          const uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE],
                          uint64_t token_id,
                          struct api_token_record *record)
{
    static const char query[] =
        "SELECT t.id,t.user_id,t.scopes,t.expires_at,t.last_used_at,"
        "t.revoked_at,t.source_family,t.source_address,t.source_prefix,"
        "t.requests_per_minute,u.username,u.enabled,u.force_password_change,"
        "u.revision,u.session_epoch"
        " FROM api_tokens t JOIN users u ON u.id=t.user_id"
        " WHERE t.token_hash=?1 OR t.id=?2;";
    sqlite3_stmt *statement = NULL;
    const char *scopes = NULL;
    const void *source_address = NULL;
    const char *username = NULL;
    int source_size = 0;
    int username_size = 0;
    int status = SQLITE_OK;
    int result;

    (void)memset(record, 0, sizeof(*record));
    if ((digest == NULL) == (token_id == 0U)) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(handle, query, -1, SQLITE_PREPARE_PERSISTENT,
                                &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = digest == NULL ? sqlite3_bind_null(statement, 1)
                                : sqlite3_bind_blob(statement, 1, digest,
                                                    JG_AUTH_SECRET_DIGEST_SIZE,
                                                    SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = token_id == 0U ? sqlite3_bind_null(statement, 2)
                                : sqlite3_bind_int64(statement, 2,
                                                     (sqlite3_int64)token_id);
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
    const size_t remote_size = jg_account_address_size(remote_family);
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
        !jg_account_remote_address_valid(remote_family, remote_address) ||
        remote_family == JG_POLICY_ADDRESS_NONE) {
        return -EINVAL;
    }
    result = jg_auth_secret_digest(token, token_size, digest);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
        transaction_open = result == 0;
    }
    if (result == 0) {
        result = load_api_token(database->handle, digest, 0U, &record);
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
        result = jg_account_load_identity_authorization(
            database->handle, record.user_id, &role_permissions, &ignored_totp);
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

/** @brief Reauthorize one deferred API token without retaining its secret. */
int jg_account_token_reauthorize(struct jg_database *database,
                                 uint64_t token_id,
                                 uint64_t now,
                                 enum jg_policy_address_family remote_family,
                                 const uint8_t *remote_address,
                                 struct jg_account_identity *identity)
{
    struct api_token_record record;
    uint32_t role_permissions = 0U;
    bool ignored_totp = false;
    bool transaction_open = false;
    int authorization_result = 0;
    int result = 0;

    if (identity == NULL) {
        return -EINVAL;
    }
    (void)memset(identity, 0, sizeof(*identity));
    (void)memset(&record, 0, sizeof(record));
    if (database == NULL || token_id == 0U || token_id > (uint64_t)INT64_MAX ||
        now == 0U || now > (uint64_t)INT64_MAX ||
        !jg_account_remote_address_valid(remote_family, remote_address) ||
        remote_family == JG_POLICY_ADDRESS_NONE) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin_read(database);
    transaction_open = result == 0;
    if (result == 0) {
        result = load_api_token(database->handle, NULL, token_id, &record);
        if (result == -ENOENT || result == -EACCES) {
            result = 0;
            authorization_result = -EACCES;
        }
    }
    if (result == 0 && authorization_result == 0 &&
        (!record.enabled || record.force_password_change ||
         (record.has_expiry && record.expires_at <= now) ||
         !source_network_matches(&record, remote_family, remote_address))) {
        authorization_result = -EACCES;
    }
    if (result == 0 && authorization_result == 0) {
        result = jg_account_load_identity_authorization(
            database->handle, record.user_id, &role_permissions, &ignored_totp);
    }
    if (result == 0 && authorization_result == 0) {
        role_permissions &= record.scoped_permissions;
        if (role_permissions == 0U) {
            authorization_result = -EACCES;
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
    if (result == 0 && authorization_result == 0) {
        identity->user_id = record.user_id;
        (void)memcpy(identity->username, record.username,
                     strlen(record.username) + 1U);
        identity->permissions = role_permissions;
        identity->revision = record.revision;
        identity->session_epoch = record.session_epoch;
        identity->mfa_complete = true;
    }
    sodium_memzero(&record, sizeof(record));
    return result == 0 ? authorization_result : result;
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
