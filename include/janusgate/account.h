/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file account.h
 * @brief Transactional local-account and first-boot identity operations.
 *
 * Account operations use an open caller-owned database and never retain
 * plaintext credentials. Issued bootstrap secrets are returned once while
 * only their fixed digest is persisted.
 *
 * @thread_safety Calls using the same database require external
 * serialization. Distinct database connections follow SQLite locking.
 *
 * @error_handling Functions return zero on success and negative errno-style
 * values. Output secrets and identifiers are cleared on failure.
 */

#ifndef JANUSGATE_ACCOUNT_H
#define JANUSGATE_ACCOUNT_H

#include <stddef.h>
#include <stdint.h>

#include "janusgate/auth.h"
#include "janusgate/database.h"
#include "janusgate/version.h"

/** Maximum local username bytes excluding the null terminator. */
#define JG_ACCOUNT_USERNAME_MAX 128U

/** Smallest accepted bootstrap-token lifetime in seconds. */
#define JG_ACCOUNT_BOOTSTRAP_LIFETIME_MIN 60U

/** Largest accepted bootstrap-token lifetime in seconds. */
#define JG_ACCOUNT_BOOTSTRAP_LIFETIME_MAX 86400U

/**
 * @brief Issue or rotate the one-time first-boot bootstrap credential.
 *
 * Issuance is permitted only while the database contains no users. An
 * existing unconsumed bootstrap credential is atomically replaced.
 *
 * @param[in,out] database Open database.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[in] lifetime Credential lifetime in the supported range.
 * @param[out] token Receives the one-time printable credential.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument, zero time, or invalid lifetime.
 * @return -EOVERFLOW when the expiry cannot be represented.
 * @return -EEXIST when at least one user already exists.
 * @return A negative errno-style cryptographic or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Replaces the persistent bootstrap digest transactionally.
 */
JG_PUBLIC int jg_account_bootstrap_issue(struct jg_database *database,
                                         uint64_t now,
                                         uint64_t lifetime,
                                         char token[JG_AUTH_SECRET_TEXT_SIZE]);

/**
 * @brief Consume bootstrap access while creating the first administrator.
 *
 * The token verification, user insert, administrator-role assignment, and
 * token consumption share one write transaction. The password is hashed with
 * Argon2id before persistence.
 *
 * @param[in,out] database Open database.
 * @param[in] token Candidate bootstrap credential bytes.
 * @param[in] token_size Number of bytes in @p token.
 * @param[in] username New administrator username.
 * @param[in] password New administrator password bytes.
 * @param[in] password_size Number of bytes in @p password.
 * @param[in] password_policy Valid Argon2id password policy.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] user_id Receives the new nonzero user identifier.
 *
 * @return 0 on success.
 * @return -EINVAL for a null or malformed input.
 * @return -EACCES for an invalid, expired, or consumed token.
 * @return -EEXIST when any user already exists.
 * @return A negative errno-style hashing or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Creates the first administrator and consumes the bootstrap
 * credential atomically.
 */
JG_PUBLIC int jg_account_create_initial_administrator(
    struct jg_database *database,
    const uint8_t *token,
    size_t token_size,
    const char *username,
    const uint8_t *password,
    size_t password_size,
    const struct jg_auth_password_policy *password_policy,
    uint64_t now,
    uint64_t *user_id);

#endif
