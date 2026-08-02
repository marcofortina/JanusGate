/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file blocklist_remote.h
 * @brief Verified HTTPS retrieval and scheduling for remote blocklists.
 *
 * Configuration strings remain caller-owned for the duration of an update.
 * State is caller-owned and persists validators and retry scheduling between
 * attempts. A returned blocklist is newly owned and does not replace any
 * active list until the caller explicitly publishes it.
 *
 * @thread_safety One state object must be used by one thread at a time.
 * Distinct state objects may update concurrently.
 *
 * @error_handling Functions return zero on a completed update check and
 * negative errno-style values on validation, transport, verification, or
 * import failure.
 */

#ifndef JANUSGATE_BLOCKLIST_REMOTE_H
#define JANUSGATE_BLOCKLIST_REMOTE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/blocklist.h"
#include "janusgate/version.h"

/** Maximum retained HTTP ETag bytes excluding its terminator. */
#define JG_BLOCKLIST_ETAG_MAX 1024U

/** Maximum retained Last-Modified bytes excluding its terminator. */
#define JG_BLOCKLIST_LAST_MODIFIED_MAX 128U

/** Maximum TCP and TLS connection timeout in milliseconds. */
#define JG_BLOCKLIST_CONNECT_TIMEOUT_MAX 30000U

/** Maximum complete remote transfer timeout in milliseconds. */
#define JG_BLOCKLIST_TRANSFER_TIMEOUT_MAX 300000U

/**
 * @brief Result of a successful remote update check.
 */
enum jg_blocklist_remote_status {
    /** HTTP 200 produced a verified new immutable blocklist. */
    JG_BLOCKLIST_REMOTE_UPDATED = 1,
    /** HTTP 304 confirmed that the active source remains current. */
    JG_BLOCKLIST_REMOTE_NOT_MODIFIED = 2
};

/**
 * @brief Persistent scheduling and HTTP validator state.
 */
struct jg_blocklist_remote_state {
    /** Validator sent through If-None-Match. */
    char etag[JG_BLOCKLIST_ETAG_MAX + 1U];
    /** Validator sent through If-Modified-Since. */
    char last_modified[JG_BLOCKLIST_LAST_MODIFIED_MAX + 1U];
    /** Unix time of the latest attempted update. */
    uint64_t last_attempt_at;
    /** Unix time of the latest successful update check. */
    uint64_t last_success_at;
    /** Earliest Unix time for the next scheduled attempt. */
    uint64_t next_attempt_at;
    /** Consecutive failed attempts since the latest success. */
    uint32_t consecutive_failures;
};

/**
 * @brief Complete secure remote-source configuration.
 */
struct jg_blocklist_remote_config {
    /** HTTPS URL of the blocklist body. */
    const char *url;
    /** Optional HTTPS URL of a raw 64-byte detached Ed25519 signature. */
    const char *signature_url;
    /** Input syntax passed to the blocklist importer. */
    enum jg_blocklist_format format;
    /** Strict or tolerant import behavior. */
    enum jg_blocklist_mode mode;
    /** Source attribution retained by the imported list. */
    const char *attribution;
    /** Nonzero decompressed import and parser limits. */
    struct jg_blocklist_limits import_limits;
    /** Maximum advertised compressed response bytes in `[1, INT64_MAX]`. */
    size_t max_download_bytes;
    /** TCP and TLS connection timeout in the supported millisecond range. */
    uint32_t connect_timeout_ms;
    /** Complete transfer timeout in the supported millisecond range. */
    uint32_t transfer_timeout_ms;
    /** Maximum followed HTTPS redirects in `[0, 20]`. */
    uint32_t redirect_limit;
    /** Normal successful update interval in seconds; zero is invalid. */
    uint64_t update_interval_seconds;
    /** Initial retry delay in seconds; zero is invalid. */
    uint64_t retry_base_seconds;
    /** Maximum retry delay, not less than @ref retry_base_seconds. */
    uint64_t retry_max_seconds;
    /** Whether @ref sha256_pin must match the downloaded body. */
    bool has_sha256_pin;
    /** Expected decompressed import-body SHA-256 digest. */
    uint8_t sha256_pin[32U];
    /** Whether a detached signature and public key are required. */
    bool has_signature;
    /** Ed25519 public verification key. */
    uint8_t ed25519_public_key[32U];
};

/**
 * @brief Details of one completed or failed remote attempt.
 */
struct jg_blocklist_remote_report {
    /** HTTP status code, or zero when no response was received. */
    long http_status;
    /** Downloaded decompressed import-body bytes. */
    size_t body_size;
    /** Import statistics for a verified HTTP 200 response. */
    struct jg_blocklist_report import;
};

/**
 * @brief Clear persistent remote-source state.
 *
 * @param[out] state State structure to initialize; null is ignored.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC void jg_blocklist_remote_state_init(
    struct jg_blocklist_remote_state *state);

/**
 * @brief Determine whether a scheduled source is due.
 *
 * @param[in] state Persistent source state.
 * @param[in] now Current Unix time in seconds.
 *
 * @return `true` when no delay remains.
 * @return `false` for a null state or an update scheduled after @p now.
 *
 * @thread_safety Concurrent access to the same state requires synchronization.
 */
JG_PUBLIC bool jg_blocklist_remote_due(
    const struct jg_blocklist_remote_state *state,
    uint64_t now);

/**
 * @brief Fetch, verify, and import one remote blocklist update.
 *
 * Only HTTPS to public-unicast destinations is permitted for the original
 * URL, every redirect, and the optional signature URL. Certificate and
 * hostname verification cannot be disabled, and environment proxy settings
 * are ignored. HTTP validators are committed to @p state only after complete
 * success. A failed attempted transfer updates retry scheduling but preserves
 * existing validators. Argument validation failures leave @p state unchanged.
 *
 * @param[in] config Secure source configuration.
 * @param[in,out] state Persistent validators and retry schedule.
 * @param[in] now Current Unix time in seconds.
 * @param[out] status Receives updated or not-modified status on success and
 * remains unchanged on failure.
 * @param[out] blocklist Receives a new owned list for an updated response;
 * is set to null for not-modified and every failure.
 * @param[out] report Receives attempt details; null discards them.
 *
 * @return 0 when an update check completed successfully.
 * @return -EINVAL for invalid configuration or arguments.
 * @return -EACCES for a non-public destination or TLS, digest, or signature
 * verification failure.
 * @return -EFBIG when transfer limits are exceeded.
 * @return -ETIMEDOUT for connection or transfer timeout.
 * @return -EPROTO for an unexpected HTTP response.
 * @return A negative errno-style import or transport error otherwise.
 *
 * @thread_safety Distinct configuration and state objects may be used
 * concurrently.
 *
 * @side_effects Performs HTTPS requests, updates scheduling state, initializes
 * libcurl and libsodium, and allocates a blocklist after complete validation.
 */
JG_PUBLIC int jg_blocklist_remote_update(
    const struct jg_blocklist_remote_config *config,
    struct jg_blocklist_remote_state *state,
    uint64_t now,
    enum jg_blocklist_remote_status *status,
    struct jg_blocklist **blocklist,
    struct jg_blocklist_remote_report *report);

#endif
