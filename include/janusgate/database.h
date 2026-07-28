/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file database.h
 * @brief Secure SQLite lifecycle and ordered schema migrations.
 *
 * A database object exclusively owns one SQLite connection. Opening validates
 * filesystem permissions, configures bounded locking, enables foreign keys
 * and WAL mode, checks integrity, and applies missing migrations.
 *
 * @thread_safety A database object must be used by one thread at a time.
 * Distinct objects follow SQLite's normal locking rules.
 *
 * @error_handling Functions return zero on success and negative errno-style
 * values on failure. A failed open leaves the output pointer null.
 */

#ifndef JANUSGATE_DATABASE_H
#define JANUSGATE_DATABASE_H

#include <stddef.h>
#include <stdint.h>

#include "janusgate/policy.h"
#include "janusgate/version.h"

/** Current persistent schema version. */
#define JG_DATABASE_SCHEMA_VERSION 1U

/** Largest accepted SQLite busy timeout in milliseconds. */
#define JG_DATABASE_BUSY_TIMEOUT_MAX 60000U

/** Maximum active domain rules accepted from persistent storage. */
#define JG_DATABASE_POLICY_RULE_LIMIT 1000000U

/** Opaque owned database connection. */
struct jg_database;

/**
 * @brief Open, validate, and migrate a persistent database.
 *
 * The path must be absolute. Its parent directory must not be group- or
 * world-writable. New files are created with mode 0600; existing files must
 * already be regular files with that exact mode.
 *
 * @param[in] path Absolute database path.
 * @param[in] busy_timeout_ms Busy timeout from 1 through
 * JG_DATABASE_BUSY_TIMEOUT_MAX.
 * @param[out] database Receives the owned connection.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -EACCES for insecure ownership, permissions, or access.
 * @return -EILSEQ for corrupt persistent data.
 * @return -ENOTSUP for a newer schema version.
 * @return -ENOMEM when allocation fails.
 * @return -EIO for another storage failure.
 *
 * @thread_safety Concurrent opens of different files are safe.
 *
 * @side_effects May create the database, WAL files, a last-known-good backup,
 * and migrated persistent content.
 */
JG_PUBLIC int jg_database_open(const char *path,
                               uint32_t busy_timeout_ms,
                               struct jg_database **database);

/**
 * @brief Close an owned database connection.
 *
 * @param[in,out] database Database to close, or null.
 *
 * @thread_safety The caller must exclude concurrent access.
 */
JG_PUBLIC void jg_database_close(struct jg_database *database);

/**
 * @brief Read the active persistent schema version.
 *
 * @param[in] database Open database.
 * @param[out] version Receives the schema version.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_schema_version(struct jg_database *database,
                                         uint32_t *version);

/**
 * @brief Run SQLite's full integrity check.
 *
 * @param[in] database Open database.
 *
 * @return 0 when SQLite reports a valid database.
 * @return -EINVAL for a null database.
 * @return -EILSEQ when integrity validation fails.
 * @return A negative errno-style value for another SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_check_integrity(struct jg_database *database);

/**
 * @brief Atomically replace every active persistent domain rule.
 *
 * All inputs are validated before the write transaction begins. Domains are
 * stored in normalized IDNA2008 A-label form. A failed validation or write
 * leaves the preceding rule set unchanged.
 *
 * @param[in] database Open database.
 * @param[in] rules Rules to persist, or null when @p rule_count is zero.
 * @param[in] rule_count Number of input rules, bounded by
 * JG_DATABASE_POLICY_RULE_LIMIT.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or rule content.
 * @return -EOVERFLOW for unsupported identifiers or packed sizes.
 * @return -ENOMEM when allocation fails.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Replaces the complete active `domain_rules` table in one
 * transaction.
 */
JG_PUBLIC int jg_database_replace_domain_rules(
    struct jg_database *database,
    const struct jg_policy_rule_input *rules,
    size_t rule_count);

/**
 * @brief Load active rules into a new immutable policy snapshot.
 *
 * A read transaction copies a single consistent database view before the
 * snapshot is constructed.
 *
 * @param[in] database Open database.
 * @param[in] generation Nonzero generation assigned to the new snapshot.
 * @param[out] snapshot Receives the owned immutable snapshot.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument or zero generation.
 * @return -EOVERFLOW when stored data exceeds configured limits.
 * @return -ENOMEM when allocation fails.
 * @return -EILSEQ for invalid stored rule data.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Initializes policy hashing and obtains random bytes through
 * the snapshot builder.
 */
JG_PUBLIC int jg_database_load_policy_snapshot(
    struct jg_database *database,
    uint64_t generation,
    struct jg_policy_snapshot **snapshot);

#endif
