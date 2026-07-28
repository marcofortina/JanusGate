/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file audit.h
 * @brief Append-only administrative audit records with hash-chain checking.
 *
 * Each event hash covers every semantic field and the preceding event hash.
 *
 * @thread_safety The caller must serialize access to each database object.
 *
 * @error_handling Functions return zero on success and negative errno-style
 * values on validation, storage, or cryptographic failure.
 */

#ifndef JANUSGATE_AUDIT_H
#define JANUSGATE_AUDIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Bytes in one audit-chain digest. */
#define JG_AUDIT_HASH_SIZE 32U

/** Largest accepted audit source text excluding its terminator. */
#define JG_AUDIT_SOURCE_MAX 255U

/** Largest accepted audit action excluding its terminator. */
#define JG_AUDIT_ACTION_MAX 128U

/** Largest accepted audit object type excluding its terminator. */
#define JG_AUDIT_OBJECT_TYPE_MAX 128U

/** Largest accepted audit object identifier excluding its terminator. */
#define JG_AUDIT_OBJECT_ID_MAX 255U

/** Largest accepted canonical detail document excluding its terminator. */
#define JG_AUDIT_DETAILS_MAX 4096U

/** Largest accepted request identifier excluding its terminator. */
#define JG_AUDIT_REQUEST_ID_MAX 128U

/** Largest audit page returned by one management query. */
#define JG_AUDIT_PAGE_MAX 5U

/** Opaque database connection declared by database.h. */
struct jg_database;

/** Authenticated origin of an administrative operation. */
enum jg_audit_actor_type {
    /** Internal service operation without a user identity. */
    JG_AUDIT_ACTOR_SYSTEM = 1,
    /** Authenticated local user. */
    JG_AUDIT_ACTOR_USER = 2,
    /** Authenticated API token. */
    JG_AUDIT_ACTOR_TOKEN = 3
};

/** Complete semantic content of one new audit event. */
struct jg_audit_event {
    /** Unix timestamp in seconds. */
    uint64_t occurred_at;
    /** Authenticated actor kind. */
    enum jg_audit_actor_type actor_type;
    /** Whether actor_id is present. Required for users and tokens. */
    bool has_actor_id;
    /** Persistent user or token identifier. */
    uint64_t actor_id;
    /** Bounded origin such as a local socket or remote address. */
    const char *source;
    /** Stable operation name. */
    const char *action;
    /** Stable affected object type. */
    const char *object_type;
    /** Optional bounded affected object identifier. */
    const char *object_id;
    /** Canonical bounded detail document, normally JSON. */
    const char *details;
    /** Whether previous_revision is present. */
    bool has_previous_revision;
    /** Object revision before the operation. */
    uint64_t previous_revision;
    /** Whether new_revision is present. */
    bool has_new_revision;
    /** Object revision after the operation. */
    uint64_t new_revision;
    /** Whether the attempted operation succeeded. */
    bool success;
    /** Bounded request correlation identifier; may be empty. */
    const char *request_id;
};

/** Identity and chain values assigned to an appended event. */
struct jg_audit_append_result {
    /** Positive persistent event identifier. */
    uint64_t event_id;
    /** Previous digest, all zero for the first event. */
    uint8_t previous_hash[JG_AUDIT_HASH_SIZE];
    /** Digest assigned to the appended event. */
    uint8_t event_hash[JG_AUDIT_HASH_SIZE];
};

/** Result of verifying a complete persistent audit chain. */
struct jg_audit_verification {
    /** Number of records inspected, including the first invalid record. */
    uint64_t records_inspected;
    /** Whether every inspected record and chain link is valid. */
    bool valid;
    /** First invalid persistent identifier, or zero for a valid chain. */
    uint64_t first_invalid_id;
};

/**
 * @brief One immutable audit record safe for administration surfaces.
 */
struct jg_audit_record {
    /** Persistent positive event identifier. */
    uint64_t event_id;
    /** Unix timestamp in seconds. */
    uint64_t occurred_at;
    /** Authenticated actor kind. */
    enum jg_audit_actor_type actor_type;
    /** Whether actor_id is present. */
    bool has_actor_id;
    /** Persistent actor identifier. */
    uint64_t actor_id;
    /** Whether previous_revision is present. */
    bool has_previous_revision;
    /** Object revision before the operation. */
    uint64_t previous_revision;
    /** Whether new_revision is present. */
    bool has_new_revision;
    /** Object revision after the operation. */
    uint64_t new_revision;
    /** Whether the attempted operation succeeded. */
    bool success;
    /** Whether this is the first chain record without a previous digest. */
    bool first;
    /** Previous event digest when @ref first is false. */
    uint8_t previous_hash[JG_AUDIT_HASH_SIZE];
    /** Digest assigned to this event. */
    uint8_t event_hash[JG_AUDIT_HASH_SIZE];
    /** Bounded operation source. */
    char source[JG_AUDIT_SOURCE_MAX + 1U];
    /** Stable operation name. */
    char action[JG_AUDIT_ACTION_MAX + 1U];
    /** Stable affected object type. */
    char object_type[JG_AUDIT_OBJECT_TYPE_MAX + 1U];
    /** Optional affected object identifier. */
    char object_id[JG_AUDIT_OBJECT_ID_MAX + 1U];
    /** Exact bounded canonical detail document. */
    char details[JG_AUDIT_DETAILS_MAX + 1U];
    /** Request correlation identifier. */
    char request_id[JG_AUDIT_REQUEST_ID_MAX + 1U];
};

/**
 * @brief Append one administrative event to the persistent hash chain.
 *
 * The latest chain digest is read and the new event is inserted under one
 * immediate transaction.
 *
 * @param[in] database Open database.
 * @param[in] event Valid bounded semantic event.
 * @param[out] append_result Receives the new event identity and hashes; null
 * discards them.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid event content.
 * @return -EOVERFLOW for values SQLite cannot represent.
 * @return A negative errno-style value for another failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Appends exactly one persistent record on success.
 */
JG_PUBLIC int jg_database_audit_append(
    struct jg_database *database,
    const struct jg_audit_event *event,
    struct jg_audit_append_result *append_result);

/**
 * @brief List immutable audit records from newest to oldest.
 *
 * @param[in] database Open database.
 * @param[in] offset Zero-based page offset.
 * @param[out] records Receives up to @p capacity records.
 * @param[in] capacity Requested page size from one through
 * JG_AUDIT_PAGE_MAX.
 * @param[out] count Receives the number of returned records.
 * @param[out] total Receives the total number of audit records.
 *
 * @return 0 on success.
 * @return -EINVAL for an invalid argument or pagination.
 * @return -EILSEQ for invalid persistent audit content.
 * @return A negative errno-style SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_audit_list(struct jg_database *database,
                                     uint64_t offset,
                                     struct jg_audit_record *records,
                                     size_t capacity,
                                     size_t *count,
                                     uint64_t *total);

/**
 * @brief Verify every persistent audit record and hash-chain link.
 *
 * A broken chain is reported through `verification.valid == false`; it does
 * not prevent the caller from receiving the first affected record.
 *
 * @param[in] database Open database.
 * @param[out] verification Receives the verification result.
 *
 * @return 0 when verification completed, including a detected invalid chain.
 * @return -EINVAL for a null argument.
 * @return A negative errno-style value for a storage or cryptographic failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_audit_verify(
    struct jg_database *database,
    struct jg_audit_verification *verification);

#endif
