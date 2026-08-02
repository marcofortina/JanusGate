/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file blocklist_update.h
 * @brief Persistent orchestration of remote and local blocklist updates.
 */

#ifndef JANUSGATE_DAEMON_BLOCKLIST_UPDATE_H
#define JANUSGATE_DAEMON_BLOCKLIST_UPDATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/blocklist_remote.h"
#include "janusgate/database.h"

/**
 * @brief Complete outcome of one blocklist source update.
 */
struct jg_blocklist_update_result {
    /** Latest persistent source state, or the state used by a failed commit. */
    struct jg_database_blocklist_source source;
    /** Transport and import measurements for the attempt. */
    struct jg_blocklist_remote_report report;
    /** Successful remote outcome; unused for local imports. */
    enum jg_blocklist_remote_status status;
    /** Transfer, verification, or import result. */
    int attempt_result;
    /** Whether source input was processed. */
    bool attempted;
    /** Whether a new imported list was activated atomically. */
    bool activated;
};

/** Completion invoked inside the source-state transaction. */
typedef int (*jg_blocklist_update_completion)(
    void *context,
    const struct jg_blocklist_update_result *result);

/**
 * @brief Refresh and persist one exact remote blocklist source.
 *
 * Remote failures are recorded as source health and returned through
 * `result->attempt_result`; the function itself returns zero when that failed
 * attempt was persisted successfully.
 *
 * @param[in,out] database Open database.
 * @param[in] source_id Persistent positive source identifier.
 * @param[in] expected_revision Source revision selected by the caller.
 * @param[in] now Current Unix time in seconds.
 * @param[out] result Receives the complete attempt outcome.
 *
 * @return 0 when the attempt and its resulting state were persisted.
 * @return -EINVAL for invalid arguments or a local-only source.
 * @return -ENOENT when the source does not exist.
 * @return -EAGAIN when the source revision changed.
 * @return A negative errno-style persistence error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Performs a bounded HTTPS update and atomically persists either
 * a new list or the resulting source health.
 */
int jg_blocklist_update(struct jg_database *database,
                        uint64_t source_id,
                        uint64_t expected_revision,
                        uint64_t now,
                        struct jg_blocklist_update_result *result);

/**
 * @brief Refresh one source and commit its state with caller completion work.
 *
 * Network transfer and parsing finish before the transaction begins. The
 * completion normally publishes and audits the resulting state; its failure
 * rolls back the persistent update.
 *
 * @param[in,out] database Open database.
 * @param[in] source_id Persistent positive source identifier.
 * @param[in] expected_revision Source revision selected by the caller.
 * @param[in] now Current Unix time in seconds.
 * @param[in] completion Required completion callback.
 * @param[in,out] context Opaque callback state.
 * @param[out] result Receives the complete attempt outcome.
 *
 * @return 0 when the state and completion work were committed together.
 * @return A negative errno-style validation, persistence, or callback error.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
int jg_blocklist_update_complete(struct jg_database *database,
                                 uint64_t source_id,
                                 uint64_t expected_revision,
                                 uint64_t now,
                                 jg_blocklist_update_completion completion,
                                 void *context,
                                 struct jg_blocklist_update_result *result);

/**
 * @brief Import and persist one exact local blocklist source.
 *
 * Invalid input is recorded as source health and returned through
 * `result->attempt_result`; the function itself returns zero when that failed
 * attempt was persisted successfully.
 *
 * @param[in,out] database Open database.
 * @param[in] source_id Persistent positive source identifier.
 * @param[in] expected_revision Source revision selected by the caller.
 * @param[in] data Exact uploaded blocklist bytes.
 * @param[in] data_size Uploaded byte count.
 * @param[in] now Current Unix time in seconds.
 * @param[out] result Receives the complete attempt outcome.
 *
 * @return 0 when the attempt and its resulting state were persisted.
 * @return -EINVAL for invalid arguments or a remote source.
 * @return -ENOENT when the source does not exist.
 * @return -EAGAIN when the source revision changed.
 * @return A negative errno-style persistence error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Parses bounded caller bytes and atomically persists either a
 * new list or the resulting source health.
 */
int jg_blocklist_import_local(struct jg_database *database,
                              uint64_t source_id,
                              uint64_t expected_revision,
                              const uint8_t *data,
                              size_t data_size,
                              uint64_t now,
                              struct jg_blocklist_update_result *result);

/**
 * @brief Import one local source with caller completion in its transaction.
 *
 * Parsing finishes before the transaction begins. The required completion can
 * publish and audit the resulting state; its failure restores the prior source
 * and policy data.
 *
 * @param[in,out] database Open database.
 * @param[in] source_id Persistent positive source identifier.
 * @param[in] expected_revision Source revision selected by the caller.
 * @param[in] data Exact uploaded blocklist bytes.
 * @param[in] data_size Uploaded byte count.
 * @param[in] now Current Unix time in seconds.
 * @param[in] completion Required completion callback.
 * @param[in,out] context Opaque callback state.
 * @param[out] result Receives the complete attempt outcome.
 *
 * @return 0 when source state and completion work were committed together.
 * @return A negative errno-style validation, persistence, or callback error.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
int jg_blocklist_import_local_complete(
    struct jg_database *database,
    uint64_t source_id,
    uint64_t expected_revision,
    const uint8_t *data,
    size_t data_size,
    uint64_t now,
    jg_blocklist_update_completion completion,
    void *context,
    struct jg_blocklist_update_result *result);

/**
 * @brief Return a stable administrative description for an update failure.
 *
 * @param[in] result Negative errno-style remote update result.
 *
 * @return Nonempty static English text.
 *
 * @thread_safety This function is reentrant.
 */
const char *jg_blocklist_update_error(int result);

/**
 * @brief Return a stable administrative description for an import failure.
 *
 * @param[in] result Negative errno-style blocklist import result.
 *
 * @return Nonempty static English text.
 *
 * @thread_safety This function is reentrant.
 */
const char *jg_blocklist_import_error(int result);

#endif
