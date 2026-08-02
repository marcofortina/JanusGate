/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "blocklist_update.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "database_internal.h"

/** @brief Load one exact source without exposing database paging to callers. */
static int load_source(struct jg_database *database,
                       uint64_t source_id,
                       struct jg_database_blocklist_source *source)
{
    size_t count = 0U;
    bool has_more = false;
    int result = 0;

    if (source_id == 0U) {
        return -EINVAL;
    }
    result = jg_database_list_blocklist_sources(database, source_id - 1U, 1U,
                                                source, &count, &has_more);
    (void)has_more;
    if (result == 0 && (count != 1U || source->id != source_id)) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Reconstruct one remote updater state from persistent source data. */
static void copy_remote_state(const struct jg_database_blocklist_source *source,
                              struct jg_blocklist_remote_state *state)
{
    jg_blocklist_remote_state_init(state);
    (void)snprintf(state->etag, sizeof(state->etag), "%s", source->etag);
    (void)snprintf(state->last_modified, sizeof(state->last_modified), "%s",
                   source->last_modified);
    state->last_attempt_at = source->last_attempt_at;
    state->last_success_at = source->last_success_at;
    state->next_attempt_at = source->next_attempt_at;
    state->consecutive_failures = source->consecutive_failures;
}

/** @brief Build one complete remote configuration from persistent source data.
 */
static void copy_remote_config(
    const struct jg_database_blocklist_source *source,
    struct jg_blocklist_remote_config *config)
{
    (void)memset(config, 0, sizeof(*config));
    config->url = source->url;
    config->signature_url =
        source->has_signature ? source->signature_url : NULL;
    config->format = source->format;
    config->mode = source->mode;
    config->attribution = source->name;
    jg_blocklist_limits_default(&config->import_limits);
    config->import_limits.max_file_bytes = source->max_decompressed_bytes;
    config->import_limits.max_entries = JG_DATABASE_POLICY_RULE_LIMIT;
    config->max_download_bytes = source->max_download_bytes;
    config->connect_timeout_ms = source->connect_timeout_ms;
    config->transfer_timeout_ms = source->transfer_timeout_ms;
    config->redirect_limit = source->redirect_limit;
    config->update_interval_seconds = source->update_interval_seconds;
    config->retry_base_seconds = source->retry_base_seconds;
    config->retry_max_seconds = source->retry_max_seconds;
    config->has_sha256_pin = source->has_sha256_pin;
    (void)memcpy(config->sha256_pin, source->sha256_pin,
                 sizeof(config->sha256_pin));
    config->has_signature = source->has_signature;
    (void)memcpy(config->ed25519_public_key, source->ed25519_public_key,
                 sizeof(config->ed25519_public_key));
}

/** @brief Return a stable description suitable for source health and audit. */
const char *jg_blocklist_update_error(int result)
{
    switch (result) {
    case -EINVAL:
        return "The remote source configuration is invalid.";
    case -EACCES:
        return "Blocklist transport or content verification failed.";
    case -EFBIG:
        return "The downloaded blocklist exceeds its configured size limit.";
    case -ETIMEDOUT:
        return "The blocklist update timed out.";
    case -EPROTO:
        return "The remote server returned an unexpected response.";
    case -EILSEQ:
        return "The blocklist contains invalid text.";
    case -EMSGSIZE:
        return "A blocklist record exceeds its configured line limit.";
    case -E2BIG:
        return "The blocklist exceeds its configured entry limit.";
    case -ENOMEM:
        return "The blocklist update exhausted available memory.";
    default:
        return "The remote blocklist update failed.";
    }
}

/** @brief Return a stable description for rejected local blocklist content. */
const char *jg_blocklist_import_error(int result)
{
    switch (result) {
    case -EINVAL:
        return "The uploaded blocklist contains an invalid record.";
    case -EILSEQ:
        return "The uploaded blocklist contains invalid text.";
    case -EFBIG:
        return "The uploaded blocklist exceeds its configured size limit.";
    case -EMSGSIZE:
        return "An uploaded blocklist record exceeds its line limit.";
    case -E2BIG:
        return "The uploaded blocklist exceeds its entry limit.";
    case -ENOMEM:
        return "The blocklist import exhausted available memory.";
    default:
        return "The uploaded blocklist could not be imported.";
    }
}

/** @brief Fetch one source and optionally complete its state transaction. */
static int update_source(struct jg_database *database,
                         uint64_t source_id,
                         uint64_t expected_revision,
                         uint64_t now,
                         jg_blocklist_update_completion completion,
                         void *context,
                         struct jg_blocklist_update_result *result)
{
    struct jg_blocklist_remote_config config;
    struct jg_blocklist_remote_state state;
    struct jg_blocklist *blocklist = NULL;
    int persist_result = 0;

    if (database == NULL || source_id == 0U || expected_revision == 0U ||
        now == 0U || result == NULL) {
        return -EINVAL;
    }
    (void)memset(result, 0, sizeof(*result));
    persist_result = load_source(database, source_id, &result->source);
    if (persist_result != 0) {
        return persist_result;
    }
    if (result->source.revision != expected_revision) {
        return -EAGAIN;
    }
    if (result->source.url[0U] == '\0') {
        return -EINVAL;
    }

    copy_remote_config(&result->source, &config);
    copy_remote_state(&result->source, &state);
    result->attempted = true;
    result->attempt_result = jg_blocklist_remote_update(
        &config, &state, now, &result->status, &blocklist, &result->report);
    persist_result = jg_database_transaction_begin(database);
    if (persist_result == 0 && result->attempt_result == 0 &&
        result->status == JG_BLOCKLIST_REMOTE_UPDATED) {
        persist_result = jg_database_activate_blocklist(
            database, source_id, expected_revision, blocklist, &state,
            &result->report.import);
        result->activated = persist_result == 0;
    } else if (persist_result == 0 && result->attempt_result == 0) {
        persist_result = jg_database_record_blocklist_attempt(
            database, source_id, expected_revision, &state, true, NULL);
    } else if (persist_result == 0) {
        persist_result = jg_database_record_blocklist_attempt(
            database, source_id, expected_revision, &state, false,
            jg_blocklist_update_error(result->attempt_result));
    }
    jg_blocklist_destroy(blocklist);
    if (persist_result == 0) {
        persist_result = load_source(database, source_id, &result->source);
    }
    if (persist_result == 0 && completion != NULL) {
        persist_result = completion(context, result);
    }
    if (persist_result == 0) {
        persist_result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    return persist_result;
}

/** @brief Fetch one source and persist its complete resulting state. */
int jg_blocklist_update(struct jg_database *database,
                        uint64_t source_id,
                        uint64_t expected_revision,
                        uint64_t now,
                        struct jg_blocklist_update_result *result)
{
    return update_source(database, source_id, expected_revision, now, NULL,
                         NULL, result);
}

/** @brief Fetch one source and commit caller completion work with its state. */
int jg_blocklist_update_complete(struct jg_database *database,
                                 uint64_t source_id,
                                 uint64_t expected_revision,
                                 uint64_t now,
                                 jg_blocklist_update_completion completion,
                                 void *context,
                                 struct jg_blocklist_update_result *result)
{
    if (completion == NULL) {
        return -EINVAL;
    }
    return update_source(database, source_id, expected_revision, now,
                         completion, context, result);
}

/** @brief Parse one local source and persist its complete resulting state. */
int jg_blocklist_import_local(struct jg_database *database,
                              uint64_t source_id,
                              uint64_t expected_revision,
                              const uint8_t *data,
                              size_t data_size,
                              uint64_t now,
                              struct jg_blocklist_update_result *result)
{
    struct jg_blocklist_remote_state state;
    struct jg_blocklist_limits limits;
    struct jg_blocklist *blocklist = NULL;
    int persist_result = 0;

    if (database == NULL || source_id == 0U || expected_revision == 0U ||
        data == NULL || now == 0U || result == NULL) {
        return -EINVAL;
    }
    (void)memset(result, 0, sizeof(*result));
    persist_result = load_source(database, source_id, &result->source);
    if (persist_result != 0) {
        return persist_result;
    }
    if (result->source.revision != expected_revision) {
        return -EAGAIN;
    }
    if (result->source.url[0U] != '\0') {
        return -EINVAL;
    }

    jg_blocklist_limits_default(&limits);
    limits.max_file_bytes = result->source.max_decompressed_bytes;
    limits.max_entries = JG_DATABASE_POLICY_RULE_LIMIT;
    result->attempted = true;
    result->report.body_size = data_size;
    result->attempt_result = jg_blocklist_import(
        data, data_size, result->source.format, result->source.mode,
        result->source.name, &limits, &blocklist, &result->report.import);

    jg_blocklist_remote_state_init(&state);
    state.last_attempt_at = now;
    state.next_attempt_at = now;
    if (result->attempt_result == 0) {
        state.last_success_at = now;
        persist_result = jg_database_activate_blocklist(
            database, source_id, expected_revision, blocklist, &state,
            &result->report.import);
        result->activated = persist_result == 0;
    } else {
        state.last_success_at = result->source.last_success_at;
        state.consecutive_failures =
            result->source.consecutive_failures == UINT32_MAX
                ? UINT32_MAX
                : result->source.consecutive_failures + 1U;
        persist_result = jg_database_record_blocklist_attempt(
            database, source_id, expected_revision, &state, false,
            jg_blocklist_import_error(result->attempt_result));
    }
    jg_blocklist_destroy(blocklist);
    if (persist_result == 0) {
        persist_result = load_source(database, source_id, &result->source);
    }
    return persist_result;
}
