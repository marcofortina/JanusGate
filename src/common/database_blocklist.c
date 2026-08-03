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
#include <strings.h>

#include <sqlite3.h>

#include "database_internal.h"
#include "janusgate/checked.h"

/** @brief Return persistent text for one source enforcement mode. */
static const char *enforcement_text(enum jg_policy_enforcement enforcement)
{
    return enforcement == JG_POLICY_ENFORCE
               ? "enforce"
               : (enforcement == JG_POLICY_OBSERVE ? "observe" : NULL);
}

/** @brief Decode one persistent source enforcement mode. */
static int decode_enforcement(const char *text,
                              enum jg_policy_enforcement *enforcement)
{
    if (strcmp(text, "enforce") == 0) {
        *enforcement = JG_POLICY_ENFORCE;
        return 0;
    }
    if (strcmp(text, "observe") == 0) {
        *enforcement = JG_POLICY_OBSERVE;
        return 0;
    }
    return -EILSEQ;
}

/** @brief Decode one persistent blocklist syntax name. */
static int decode_blocklist_format(const char *text,
                                   enum jg_blocklist_format *format)
{
    if (strcmp(text, "domain") == 0) {
        *format = JG_BLOCKLIST_FORMAT_DOMAIN;
    } else if (strcmp(text, "hosts") == 0) {
        *format = JG_BLOCKLIST_FORMAT_HOSTS;
    } else if (strcmp(text, "category") == 0) {
        *format = JG_BLOCKLIST_FORMAT_CATEGORY;
    } else if (strcmp(text, "rpz") == 0) {
        *format = JG_BLOCKLIST_FORMAT_RPZ;
    } else if (strcmp(text, "json") == 0) {
        *format = JG_BLOCKLIST_FORMAT_JSON;
    } else {
        return -EILSEQ;
    }
    return 0;
}

/** @brief Decode one persistent blocklist health name. */
static int decode_blocklist_health(const char *text,
                                   enum jg_database_blocklist_health *health)
{
    if (strcmp(text, "unknown") == 0) {
        *health = JG_DATABASE_BLOCKLIST_UNKNOWN;
    } else if (strcmp(text, "healthy") == 0) {
        *health = JG_DATABASE_BLOCKLIST_HEALTHY;
    } else if (strcmp(text, "degraded") == 0) {
        *health = JG_DATABASE_BLOCKLIST_DEGRADED;
    } else if (strcmp(text, "failed") == 0) {
        *health = JG_DATABASE_BLOCKLIST_FAILED;
    } else {
        return -EILSEQ;
    }
    return 0;
}

/** @brief Decode the integer fields of one blocklist-source row. */
static int decode_blocklist_source_integers(
    sqlite3_stmt *statement,
    struct jg_database_blocklist_source *source)
{
    static const int state_columns[] = {22, 23, 24, 25, 27, 28};
    uint64_t config[8U];
    uint64_t state[6U];
    size_t index = 0U;
    int result = 0;

    for (index = 0U; index < 8U && result == 0; ++index) {
        result = jg_database_column_unsigned(statement, (int)index + 10,
                                             &config[index]);
    }
    for (index = 0U; index < 3U && result == 0; ++index) {
        result = jg_database_column_optional_unsigned(
            statement, state_columns[index], &state[index]);
    }
    for (; index < 6U && result == 0; ++index) {
        result = jg_database_column_unsigned(statement, state_columns[index],
                                             &state[index]);
    }
    if (result != 0 || config[0U] < 300U || config[0U] > 2592000U ||
        config[1U] == 0U || config[1U] > SIZE_MAX || config[2U] < config[1U] ||
        config[2U] > SIZE_MAX || config[3U] == 0U || config[3U] > INT32_MAX ||
        config[4U] == 0U || config[4U] > INT32_MAX || config[5U] > 20U ||
        config[6U] == 0U || config[7U] < config[6U] || state[3U] > UINT32_MAX ||
        state[4U] > SIZE_MAX || state[5U] > SIZE_MAX) {
        return result != 0 ? result : -EILSEQ;
    }
    source->update_interval_seconds = config[0U];
    source->max_download_bytes = (size_t)config[1U];
    source->max_decompressed_bytes = (size_t)config[2U];
    source->connect_timeout_ms = config[3U] > JG_BLOCKLIST_CONNECT_TIMEOUT_MAX
                                     ? JG_BLOCKLIST_CONNECT_TIMEOUT_MAX
                                     : (uint32_t)config[3U];
    source->transfer_timeout_ms = config[4U] > JG_BLOCKLIST_TRANSFER_TIMEOUT_MAX
                                      ? JG_BLOCKLIST_TRANSFER_TIMEOUT_MAX
                                      : (uint32_t)config[4U];
    source->redirect_limit = (uint32_t)config[5U];
    source->retry_base_seconds = config[6U];
    source->retry_max_seconds = config[7U];
    source->last_attempt_at = state[0U];
    source->last_success_at = state[1U];
    source->next_attempt_at = state[2U];
    source->consecutive_failures = (uint32_t)state[3U];
    source->active_entries = (size_t)state[4U];
    source->rejected_entries = (size_t)state[5U];
    return 0;
}

/** @brief Decode one selected blocklist source and update-state row. */
static int decode_blocklist_source(sqlite3_stmt *statement,
                                   struct jg_database_blocklist_source *source)
{
    const char *text = NULL;
    size_t text_length = 0U;
    uint64_t id = 0U;
    uint64_t revision = 0U;
    uint64_t created_at = 0U;
    uint64_t updated_at = 0U;
    uint64_t strict_mode = 0U;
    uint64_t enabled = 0U;
    int result = 0;

    (void)memset(source, 0, sizeof(*source));
    result = jg_database_column_unsigned(statement, 0, &id);
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 1, &revision);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 2, &created_at);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 3, &updated_at);
    }
    if (result == 0) {
        result = jg_database_column_optional_text(statement, 4, source->name,
                                                  sizeof(source->name));
    }
    if (result == 0) {
        result = jg_database_column_optional_text(statement, 5, source->url,
                                                  sizeof(source->url));
    }
    if (result == 0) {
        result = jg_database_column_optional_text(
            statement, 6, source->signature_url, sizeof(source->signature_url));
    }
    if (result == 0) {
        result =
            jg_database_column_required_text(statement, 7, &text, &text_length);
    }
    if (result == 0) {
        result = decode_blocklist_format(text, &source->format);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 8, &strict_mode);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 9, &enabled);
    }
    if (result == 0) {
        result = decode_blocklist_source_integers(statement, source);
    }
    if (result == 0) {
        result = jg_database_column_optional_blob(
            statement, 18, source->sha256_pin, sizeof(source->sha256_pin),
            &source->has_sha256_pin);
    }
    if (result == 0) {
        result = jg_database_column_optional_blob(
            statement, 19, source->ed25519_public_key,
            sizeof(source->ed25519_public_key), &source->has_signature);
    }
    if (result == 0) {
        result = jg_database_column_optional_text(statement, 20, source->etag,
                                                  sizeof(source->etag));
    }
    if (result == 0) {
        result = jg_database_column_optional_text(
            statement, 21, source->last_modified,
            sizeof(source->last_modified));
    }
    if (result == 0) {
        result = jg_database_column_optional_blob(
            statement, 26, source->active_checksum,
            sizeof(source->active_checksum), &source->has_active_checksum);
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 29, &text,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_blocklist_health(text, &source->health);
    }
    if (result == 0) {
        result = jg_database_column_optional_text(
            statement, 30, source->last_error, sizeof(source->last_error));
    }
    if (result == 0) {
        result = jg_database_column_required_text(statement, 31, &text,
                                                  &text_length);
    }
    if (result == 0) {
        result = decode_enforcement(text, &source->enforcement);
    }
    if (result == 0 &&
        (id == 0U || revision == 0U || updated_at < created_at ||
         source->name[0U] == '\0' ||
         !jg_utf8_text_valid((const uint8_t *)source->name,
                             strlen(source->name), false) ||
         (source->url[0U] != '\0' &&
          (source->url[8U] == '\0' ||
           strncasecmp(source->url, "https://", 8U) != 0 ||
           !jg_utf8_text_valid((const uint8_t *)source->url,
                               strlen(source->url), false))) ||
         (source->url[0U] == '\0' && source->has_signature) ||
         ((source->signature_url[0U] != '\0') != source->has_signature) ||
         (source->signature_url[0U] != '\0' &&
          (source->signature_url[8U] == '\0' ||
           strncasecmp(source->signature_url, "https://", 8U) != 0 ||
           !jg_utf8_text_valid((const uint8_t *)source->signature_url,
                               strlen(source->signature_url), false))) ||
         (strict_mode != 0U && strict_mode != 1U) ||
         (enabled != 0U && enabled != 1U) ||
         (!source->has_active_checksum && source->active_entries != 0U))) {
        result = -EILSEQ;
    }
    if (result == 0) {
        source->id = id;
        source->revision = revision;
        source->created_at = created_at;
        source->updated_at = updated_at;
        source->mode =
            strict_mode != 0U ? JG_BLOCKLIST_STRICT : JG_BLOCKLIST_TOLERANT;
        source->enabled = enabled != 0U;
    }
    return result;
}

/** @brief Read one stable identifier-ordered page of blocklist sources. */
int jg_database_list_blocklist_sources(
    struct jg_database *database,
    uint64_t after_id,
    size_t limit,
    struct jg_database_blocklist_source *sources,
    size_t *count,
    bool *has_more)
{
    static const char query[] =
        "SELECT s.id,s.revision,s.created_at,s.updated_at,s.name,s.url,"
        "s.signature_url,s.format,s.strict_mode,s.enabled,s.update_interval,"
        "s.max_download_bytes,s.max_decompressed_bytes,s.connect_timeout_ms,"
        "s.transfer_timeout_ms,s.redirect_limit,s.retry_base_seconds,"
        "s.retry_max_seconds,s.sha256_pin,s.ed25519_public_key,st.etag,"
        "st.last_modified,st.last_attempt_at,st.last_success_at,"
        "st.next_attempt_at,COALESCE(st.consecutive_failures,0),"
        "st.active_checksum,COALESCE(st.active_entries,0),"
        "COALESCE(st.rejected_entries,0),COALESCE(st.health,'unknown'),"
        "st.last_error,s.enforcement FROM blocklist_sources AS s LEFT JOIN "
        "blocklist_source_status AS st ON st.source_id=s.id WHERE s.id>?1 "
        "ORDER BY s.id LIMIT ?2;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    bool more = false;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || after_id > (uint64_t)INT64_MAX || limit == 0U ||
        limit > JG_DATABASE_POLICY_PAGE_MAX || sources == NULL ||
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
        result = decode_blocklist_source(statement, &sources[index]);
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

/** @brief Return the persistent name of one blocklist input syntax. */
static const char *blocklist_format_text(enum jg_blocklist_format format)
{
    switch (format) {
    case JG_BLOCKLIST_FORMAT_DOMAIN:
        return "domain";
    case JG_BLOCKLIST_FORMAT_HOSTS:
        return "hosts";
    case JG_BLOCKLIST_FORMAT_CATEGORY:
        return "category";
    case JG_BLOCKLIST_FORMAT_RPZ:
        return "rpz";
    case JG_BLOCKLIST_FORMAT_JSON:
        return "json";
    }
    return NULL;
}

/** @brief Validate and measure one bounded administrative string. */
static int validate_source_text(const char *text,
                                size_t maximum,
                                size_t *length)
{
    size_t size = 0U;

    if (text == NULL) {
        return -EINVAL;
    }
    size = strnlen(text, maximum + 1U);
    if (size == 0U || size > maximum) {
        return -EINVAL;
    }
    if (!jg_utf8_text_valid((const uint8_t *)text, size, false)) {
        return -EILSEQ;
    }
    if (length != NULL) {
        *length = size;
    }
    return 0;
}

/** @brief Check that one bounded URL explicitly selects HTTPS. */
static bool source_https_url(const char *url, size_t length)
{
    return length > 8U && strncasecmp(url, "https://", 8U) == 0;
}

/** @brief Validate one blocklist-source configuration before persistence. */
static int validate_blocklist_source_config(
    const struct jg_database_blocklist_source_config *config)
{
    size_t url_length = 0U;
    size_t signature_url_length = 0U;
    int result = 0;

    if (config == NULL || blocklist_format_text(config->format) == NULL ||
        enforcement_text(config->enforcement) == NULL ||
        (config->mode != JG_BLOCKLIST_STRICT &&
         config->mode != JG_BLOCKLIST_TOLERANT) ||
        config->update_interval_seconds < 300U ||
        config->update_interval_seconds > 2592000U ||
        config->max_download_bytes == 0U ||
        config->max_download_bytes > (size_t)INT64_MAX ||
        config->max_decompressed_bytes < config->max_download_bytes ||
        config->max_decompressed_bytes > (size_t)INT64_MAX ||
        config->connect_timeout_ms == 0U ||
        config->connect_timeout_ms > JG_BLOCKLIST_CONNECT_TIMEOUT_MAX ||
        config->transfer_timeout_ms == 0U ||
        config->transfer_timeout_ms > JG_BLOCKLIST_TRANSFER_TIMEOUT_MAX ||
        config->redirect_limit > 20U || config->retry_base_seconds == 0U ||
        config->retry_base_seconds > config->retry_max_seconds ||
        config->retry_max_seconds > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = validate_source_text(config->name, JG_DATABASE_BLOCKLIST_NAME_MAX,
                                  NULL);
    if (result == 0 && config->url != NULL) {
        result = validate_source_text(
            config->url, JG_DATABASE_BLOCKLIST_URL_MAX, &url_length);
        if (result == 0 && !source_https_url(config->url, url_length)) {
            result = -EINVAL;
        }
    }
    if (result == 0 && config->has_signature) {
        result = validate_source_text(config->signature_url,
                                      JG_DATABASE_BLOCKLIST_URL_MAX,
                                      &signature_url_length);
        if (result == 0 &&
            (!source_https_url(config->signature_url, signature_url_length) ||
             config->url == NULL)) {
            result = -EINVAL;
        }
    } else if (result == 0 && config->signature_url != NULL) {
        result = -EINVAL;
    }
    return result;
}

/** @brief Bind one validated blocklist-source configuration. */
static int bind_blocklist_source_config(
    sqlite3_stmt *statement,
    const struct jg_database_blocklist_source_config *config)
{
    int status = sqlite3_reset(statement);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        result = jg_database_sqlite_result(sqlite3_clear_bindings(statement));
    }
    if (result == 0) {
        status =
            sqlite3_bind_text(statement, 1, config->name, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = config->url == NULL
                     ? sqlite3_bind_null(statement, 2)
                     : sqlite3_bind_text(statement, 2, config->url, -1,
                                         SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = config->signature_url == NULL
                     ? sqlite3_bind_null(statement, 3)
                     : sqlite3_bind_text(statement, 3, config->signature_url,
                                         -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 4,
                                   blocklist_format_text(config->format), -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 5,
                                  config->mode == JG_BLOCKLIST_STRICT ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 6, config->enabled ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(
            statement, 7, (sqlite3_int64)config->update_interval_seconds);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 8,
                                    (sqlite3_int64)config->max_download_bytes);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(
            statement, 9, (sqlite3_int64)config->max_decompressed_bytes);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int(statement, 10, (int)config->connect_timeout_ms);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int(statement, 11, (int)config->transfer_timeout_ms);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 12, (int)config->redirect_limit);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 13,
                                    (sqlite3_int64)config->retry_base_seconds);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 14,
                                    (sqlite3_int64)config->retry_max_seconds);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = config->has_sha256_pin
                     ? sqlite3_bind_blob(statement, 15, config->sha256_pin,
                                         (int)sizeof(config->sha256_pin),
                                         SQLITE_TRANSIENT)
                     : sqlite3_bind_null(statement, 15);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            config->has_signature
                ? sqlite3_bind_blob(statement, 16, config->ed25519_public_key,
                                    (int)sizeof(config->ed25519_public_key),
                                    SQLITE_TRANSIENT)
                : sqlite3_bind_null(statement, 16);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 17,
                                   enforcement_text(config->enforcement), -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    return result;
}

/** @brief Read one blocklist source by its exact identifier. */
static int read_blocklist_source(struct jg_database *database,
                                 uint64_t source_id,
                                 struct jg_database_blocklist_source *source)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_blocklist_sources(
        database, source_id - 1U, 1U, source, &count, &has_more);

    (void)has_more;
    if (result == 0 && (count != 1U || source->id != source_id)) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Create one blocklist source and its empty update state. */
int jg_database_create_blocklist_source(
    struct jg_database *database,
    const struct jg_database_blocklist_source_config *config,
    struct jg_database_blocklist_source *created)
{
    static const char insert[] =
        "INSERT INTO blocklist_sources("
        "name,url,signature_url,format,strict_mode,enabled,update_interval,"
        "max_download_bytes,max_decompressed_bytes,connect_timeout_ms,"
        "transfer_timeout_ms,redirect_limit,retry_base_seconds,"
        "retry_max_seconds,sha256_pin,ed25519_public_key,created_at,updated_at"
        ",enforcement) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,"
        "?14,?15,?16,unixepoch(),unixepoch(),?17);";
    struct jg_database_blocklist_source source;
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 identifier = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || created == NULL) {
        return -EINVAL;
    }
    (void)memset(created, 0, sizeof(*created));
    result = validate_blocklist_source_config(config);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_blocklist_source_config(statement, config);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_CONSTRAINT_UNIQUE) {
            result = -EEXIST;
        } else {
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
    if (result == 0) {
        identifier = sqlite3_last_insert_rowid(database->handle);
        if (identifier <= 0) {
            result = -EIO;
        }
    }
    if (result == 0) {
        result = jg_database_execute_sql(
            database->handle, "INSERT INTO blocklist_source_status(source_id)"
                              " VALUES(last_insert_rowid());");
    }
    if (result == 0) {
        result = read_blocklist_source(database, (uint64_t)identifier, &source);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        *created = source;
    }
    return result;
}

/** @brief Replace one blocklist source at its expected revision. */
int jg_database_update_blocklist_source(
    struct jg_database *database,
    uint64_t source_id,
    const struct jg_database_blocklist_source_config *config,
    uint64_t expected_revision,
    struct jg_database_blocklist_source *updated)
{
    static const char revision_query[] =
        "SELECT revision FROM blocklist_sources WHERE id=?1;";
    static const char update[] =
        "UPDATE blocklist_sources SET name=?1,url=?2,signature_url=?3,"
        "format=?4,strict_mode=?5,enabled=?6,update_interval=?7,"
        "max_download_bytes=?8,max_decompressed_bytes=?9,"
        "connect_timeout_ms=?10,transfer_timeout_ms=?11,redirect_limit=?12,"
        "retry_base_seconds=?13,retry_max_seconds=?14,sha256_pin=?15,"
        "ed25519_public_key=?16,enforcement=?17,updated_at=unixepoch(),"
        "revision=revision+1 WHERE id=?18 AND revision=?19 "
        "AND revision<9223372036854775807;";
    struct jg_database_blocklist_source source;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || source_id == 0U ||
        source_id > (uint64_t)INT64_MAX || expected_revision == 0U ||
        expected_revision > (uint64_t)INT64_MAX || updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result = validate_blocklist_source_config(config);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_blocklist_source_config(statement, config);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 18, (sqlite3_int64)source_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 19,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_CONSTRAINT_UNIQUE) {
            result = -EEXIST;
        } else {
            result =
                status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
        }
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_write_conflict(database->handle, revision_query,
                                            source_id, expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = read_blocklist_source(database, source_id, &source);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        *updated = source;
    }
    return result;
}

/** @brief Delete one blocklist source at its expected revision. */
int jg_database_delete_blocklist_source(struct jg_database *database,
                                        uint64_t source_id,
                                        uint64_t expected_revision)
{
    static const char revision_query[] =
        "SELECT revision FROM blocklist_sources WHERE id=?1;";
    static const char remove[] =
        "DELETE FROM blocklist_sources WHERE id=?1 AND revision=?2;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || source_id == 0U ||
        source_id > (uint64_t)INT64_MAX || expected_revision == 0U ||
        expected_revision > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = jg_database_transaction_begin(database);
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, remove, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)source_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result =
            jg_database_write_conflict(database->handle, revision_query,
                                       source_id, expected_revision, false);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    return result;
}

/** @brief Validate one retained HTTP validator against header injection. */
static bool blocklist_validator_valid(const char *value, size_t maximum)
{
    size_t length = 0U;

    if (value == NULL) {
        return false;
    }
    while (length <= maximum && value[length] != '\0') {
        const uint8_t byte = (uint8_t)value[length];

        if (byte < UINT8_C(0x20) || byte > UINT8_C(0x7e)) {
            return false;
        }
        ++length;
    }
    return length <= maximum;
}

/** @brief Validate one successful blocklist update before persistence. */
static int validate_blocklist_activation(
    uint64_t source_id,
    uint64_t expected_revision,
    const struct jg_blocklist *blocklist,
    const struct jg_blocklist_remote_state *state,
    const struct jg_blocklist_report *report,
    struct jg_blocklist_info *info)
{
    int result = 0;

    if (source_id == 0U || source_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX ||
        blocklist == NULL || state == NULL || report == NULL || info == NULL ||
        state->last_attempt_at == 0U ||
        state->last_success_at != state->last_attempt_at ||
        state->next_attempt_at < state->last_success_at ||
        state->consecutive_failures != 0U ||
        !blocklist_validator_valid(state->etag, JG_BLOCKLIST_ETAG_MAX) ||
        !blocklist_validator_valid(state->last_modified,
                                   JG_BLOCKLIST_LAST_MODIFIED_MAX)) {
        return -EINVAL;
    }
    if (state->last_attempt_at > (uint64_t)INT64_MAX ||
        state->next_attempt_at > (uint64_t)INT64_MAX) {
        return -EOVERFLOW;
    }
    result = jg_blocklist_get_info(blocklist, info);
    if (result == 0 && (info->entry_count > JG_DATABASE_POLICY_RULE_LIMIT ||
                        info->entry_count > (size_t)INT64_MAX ||
                        report->records_rejected > (size_t)INT64_MAX)) {
        result = -EOVERFLOW;
    }
    if (result == 0) {
        result = validate_source_text(info->attribution,
                                      JG_BLOCKLIST_ATTRIBUTION_MAX, NULL);
    }
    return result;
}

/** @brief Bind and execute one imported blocklist domain-rule insert. */
static int insert_blocklist_entry(sqlite3_stmt *statement,
                                  uint64_t source_id,
                                  uint64_t updated_at,
                                  const char *attribution,
                                  const struct jg_blocklist_entry *entry)
{
    int status = sqlite3_reset(statement);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        result = jg_database_sqlite_result(sqlite3_clear_bindings(statement));
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)source_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 2, entry->domain, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_text(statement, 3, attribution, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 4, entry->category, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 5, (sqlite3_int64)updated_at);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    return result;
}

/** @brief Persist successful remote state and active-list metadata. */
static int store_blocklist_success(
    sqlite3 *handle,
    uint64_t source_id,
    const struct jg_blocklist_remote_state *state,
    const struct jg_blocklist_info *info,
    const struct jg_blocklist_report *report)
{
    static const char update[] =
        "INSERT INTO blocklist_source_status("
        "source_id,etag,last_modified,last_attempt_at,last_success_at,"
        "next_attempt_at,consecutive_failures,active_checksum,active_entries,"
        "rejected_entries,health,last_error"
        ") VALUES(?1,?2,?3,?4,?5,?6,0,?7,?8,?9,'healthy',NULL)"
        " ON CONFLICT(source_id) DO UPDATE SET etag=excluded.etag,"
        "last_modified=excluded.last_modified,"
        "last_attempt_at=excluded.last_attempt_at,"
        "last_success_at=excluded.last_success_at,"
        "next_attempt_at=excluded.next_attempt_at,consecutive_failures=0,"
        "active_checksum=excluded.active_checksum,"
        "active_entries=excluded.active_entries,"
        "rejected_entries=excluded.rejected_entries,health='healthy',"
        "last_error=NULL;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)source_id);
    }
    if (status == SQLITE_OK) {
        status = state->etag[0U] == '\0'
                     ? sqlite3_bind_null(statement, 2)
                     : sqlite3_bind_text(statement, 2, state->etag, -1,
                                         SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = state->last_modified[0U] == '\0'
                     ? sqlite3_bind_null(statement, 3)
                     : sqlite3_bind_text(statement, 3, state->last_modified, -1,
                                         SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 4,
                                    (sqlite3_int64)state->last_attempt_at);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 5,
                                    (sqlite3_int64)state->last_success_at);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 6,
                                    (sqlite3_int64)state->next_attempt_at);
    }
    if (status == SQLITE_OK) {
        status =
            sqlite3_bind_blob(statement, 7, info->checksum,
                              (int)sizeof(info->checksum), SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status =
            sqlite3_bind_int64(statement, 8, (sqlite3_int64)info->entry_count);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 9,
                                    (sqlite3_int64)report->records_rejected);
    }
    if (result == 0) {
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

/** @brief Atomically activate one completely imported blocklist. */
int jg_database_activate_blocklist(
    struct jg_database *database,
    uint64_t source_id,
    uint64_t expected_revision,
    const struct jg_blocklist *blocklist,
    const struct jg_blocklist_remote_state *state,
    const struct jg_blocklist_report *report)
{
    static const char revision_query[] =
        "SELECT revision FROM blocklist_sources WHERE id=?1;";
    static const char insert[] =
        "INSERT INTO domain_rules("
        "blocklist_source_id,domain,match_type,effect,source,scope_type,"
        "attribution,enabled,updated_at,target,category"
        ") VALUES(?1,?2,'suffix','block','blocklist','global',?3,1,?5,'dns',"
        "?4);";
    static const char remove[] =
        "DELETE FROM domain_rules WHERE blocklist_source_id=?1;";
    struct jg_blocklist_info info;
    sqlite3_stmt *insert_statement = NULL;
    sqlite3_stmt *remove_statement = NULL;
    size_t index = 0U;
    uint64_t revision = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = validate_blocklist_activation(source_id, expected_revision,
                                           blocklist, state, report, &info);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        result = jg_database_read_revision(database->handle, revision_query,
                                           source_id, &revision);
    }
    if (result == 0 && revision != expected_revision) {
        result = -EAGAIN;
    }
    if (result == 0) {
        status = sqlite3_prepare_v3(database->handle, remove, -1,
                                    SQLITE_PREPARE_PERSISTENT,
                                    &remove_statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int64(remove_statement, 1, (sqlite3_int64)source_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(remove_statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_prepare_v3(database->handle, insert, -1,
                                    SQLITE_PREPARE_PERSISTENT,
                                    &insert_statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    for (index = 0U; result == 0 && index < info.entry_count; ++index) {
        struct jg_blocklist_entry entry;

        result = jg_blocklist_get_entry(blocklist, index, &entry);
        if (result == 0) {
            result = insert_blocklist_entry(insert_statement, source_id,
                                            state->last_success_at,
                                            info.attribution, &entry);
        }
    }
    if (result == 0) {
        result = store_blocklist_success(database->handle, source_id, state,
                                         &info, report);
    }
    if (insert_statement != NULL) {
        status = sqlite3_finalize(insert_statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (remove_statement != NULL) {
        status = sqlite3_finalize(remove_statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    return result;
}

/** @brief Validate one completed not-modified or failed update attempt. */
static int validate_blocklist_attempt(
    uint64_t source_id,
    uint64_t expected_revision,
    const struct jg_blocklist_remote_state *state,
    bool successful,
    const char *error)
{
    int result = 0;

    if (source_id == 0U || source_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX ||
        state == NULL || state->last_attempt_at == 0U ||
        state->next_attempt_at < state->last_attempt_at ||
        (state->last_success_at != 0U &&
         state->last_success_at > state->last_attempt_at) ||
        !blocklist_validator_valid(state->etag, JG_BLOCKLIST_ETAG_MAX) ||
        !blocklist_validator_valid(state->last_modified,
                                   JG_BLOCKLIST_LAST_MODIFIED_MAX) ||
        (successful && (error != NULL || state->consecutive_failures != 0U ||
                        state->last_success_at != state->last_attempt_at)) ||
        (!successful && (error == NULL || state->consecutive_failures == 0U))) {
        return -EINVAL;
    }
    if (state->last_attempt_at > (uint64_t)INT64_MAX ||
        state->last_success_at > (uint64_t)INT64_MAX ||
        state->next_attempt_at > (uint64_t)INT64_MAX) {
        return -EOVERFLOW;
    }
    if (!successful) {
        result =
            validate_source_text(error, JG_DATABASE_BLOCKLIST_ERROR_MAX, NULL);
    }
    return result;
}

/** @brief Upsert one completed blocklist attempt without replacing entries. */
static int store_blocklist_attempt(
    sqlite3 *handle,
    uint64_t source_id,
    const struct jg_blocklist_remote_state *state,
    bool successful,
    const char *error)
{
    static const char update[] =
        "INSERT INTO blocklist_source_status("
        "source_id,etag,last_modified,last_attempt_at,last_success_at,"
        "next_attempt_at,consecutive_failures,health,last_error"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,"
        "CASE WHEN ?8=1 THEN 'healthy' ELSE 'failed' END,?9)"
        " ON CONFLICT(source_id) DO UPDATE SET etag=excluded.etag,"
        "last_modified=excluded.last_modified,"
        "last_attempt_at=excluded.last_attempt_at,"
        "last_success_at=excluded.last_success_at,"
        "next_attempt_at=excluded.next_attempt_at,"
        "consecutive_failures=excluded.consecutive_failures,"
        "health=CASE WHEN ?8=1 THEN 'healthy' "
        "WHEN active_checksum IS NULL THEN 'failed' ELSE 'degraded' END,"
        "last_error=excluded.last_error;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)source_id);
    }
    if (status == SQLITE_OK) {
        status = state->etag[0U] == '\0'
                     ? sqlite3_bind_null(statement, 2)
                     : sqlite3_bind_text(statement, 2, state->etag, -1,
                                         SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = state->last_modified[0U] == '\0'
                     ? sqlite3_bind_null(statement, 3)
                     : sqlite3_bind_text(statement, 3, state->last_modified, -1,
                                         SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 4,
                                    (sqlite3_int64)state->last_attempt_at);
    }
    if (status == SQLITE_OK) {
        status = state->last_success_at == 0U
                     ? sqlite3_bind_null(statement, 5)
                     : sqlite3_bind_int64(
                           statement, 5, (sqlite3_int64)state->last_success_at);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 6,
                                    (sqlite3_int64)state->next_attempt_at);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 7,
                                    (sqlite3_int64)state->consecutive_failures);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(statement, 8, successful ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = successful ? sqlite3_bind_null(statement, 9)
                            : sqlite3_bind_text(statement, 9, error, -1,
                                                SQLITE_TRANSIENT);
    }
    if (result == 0) {
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

/** @brief Persist one completed blocklist attempt without replacing entries. */
int jg_database_record_blocklist_attempt(
    struct jg_database *database,
    uint64_t source_id,
    uint64_t expected_revision,
    const struct jg_blocklist_remote_state *state,
    bool successful,
    const char *error)
{
    struct jg_database_blocklist_source source;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = validate_blocklist_attempt(source_id, expected_revision, state,
                                        successful, error);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        result = read_blocklist_source(database, source_id, &source);
    }
    if (result == 0 && source.revision != expected_revision) {
        result = -EAGAIN;
    }
    if (result == 0 && successful && !source.has_active_checksum) {
        result = -ENOENT;
    }
    if (result == 0) {
        result = store_blocklist_attempt(database->handle, source_id, state,
                                         successful, error);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    return result;
}
