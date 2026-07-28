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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/access.h"
#include "janusgate/auth.h"
#include "janusgate/database.h"
#include "janusgate/version.h"

/** Maximum local username bytes excluding the null terminator. */
#define JG_ACCOUNT_USERNAME_MAX 128U

/** Smallest accepted bootstrap-token lifetime in seconds. */
#define JG_ACCOUNT_BOOTSTRAP_LIFETIME_MIN 60U

/** Largest accepted bootstrap-token lifetime in seconds. */
#define JG_ACCOUNT_BOOTSTRAP_LIFETIME_MAX 86400U

/** Maximum persistent consecutive login failures. */
#define JG_ACCOUNT_FAILED_LOGIN_MAX 1000000U

/** Maximum account lock delay in seconds. */
#define JG_ACCOUNT_LOCK_DELAY_MAX 3600U

/** Smallest accepted absolute web-session lifetime in seconds. */
#define JG_ACCOUNT_SESSION_LIFETIME_MIN 300U

/** Largest accepted absolute web-session lifetime in seconds. */
#define JG_ACCOUNT_SESSION_LIFETIME_MAX 604800U

/** Smallest accepted web-session inactivity timeout in seconds. */
#define JG_ACCOUNT_SESSION_INACTIVITY_MIN 60U

/** Largest accepted web-session inactivity timeout in seconds. */
#define JG_ACCOUNT_SESSION_INACTIVITY_MAX 86400U

/** Minimum interval between persistent session activity writes. */
#define JG_ACCOUNT_SESSION_TOUCH_INTERVAL 60U

/**
 * @brief Authenticated local identity returned to management services.
 */
struct jg_account_identity {
    /** Persistent nonzero user identifier. */
    uint64_t user_id;
    /** Canonical local username. */
    char username[JG_ACCOUNT_USERNAME_MAX + 1U];
    /** Union of permissions assigned by persistent roles. */
    uint32_t permissions;
    /** Current optimistic-concurrency revision. */
    uint64_t revision;
    /** Epoch copied into new sessions for global revocation. */
    uint64_t session_epoch;
    /** Whether the user must change the password before other operations. */
    bool force_password_change;
    /** Whether TOTP is required for this user. */
    bool totp_enabled;
};

/**
 * @brief One-time plaintext values returned when a web session is issued.
 */
struct jg_account_session_tokens {
    /** Opaque session identifier placed only in a secure cookie. */
    char session[JG_AUTH_SECRET_TEXT_SIZE];
    /** Opaque CSRF value sent outside the cookie on state changes. */
    char csrf[JG_AUTH_SECRET_TEXT_SIZE];
    /** Absolute Unix expiry timestamp. */
    uint64_t expires_at;
};

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

/**
 * @brief Authenticate one enabled local user with persistent rate limiting.
 *
 * An incorrect password increments the failure counter and applies an
 * exponentially increasing lock delay capped at
 * @ref JG_ACCOUNT_LOCK_DELAY_MAX. Successful authentication clears failure
 * state, records the login time, and upgrades an obsolete Argon2id hash.
 *
 * @param[in,out] database Open database.
 * @param[in] username Candidate local username.
 * @param[in] password Candidate password bytes.
 * @param[in] password_size Number of bytes in @p password.
 * @param[in] password_policy Current Argon2id password policy.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] identity Receives the authenticated identity.
 *
 * @return 0 on successful password authentication.
 * @return -EINVAL for a null or malformed input.
 * @return -ERANGE when the candidate exceeds the absolute password bound.
 * @return -EACCES for an unknown, disabled, or incorrectly authenticated user.
 * @return -EAGAIN while the account lock delay is active.
 * @return A negative errno-style hashing or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Updates login failure or success state transactionally.
 */
JG_PUBLIC int jg_account_authenticate(
    struct jg_database *database,
    const char *username,
    const uint8_t *password,
    size_t password_size,
    const struct jg_auth_password_policy *password_policy,
    uint64_t now,
    struct jg_account_identity *identity);

/**
 * @brief Issue one persistent web session for an authenticated identity.
 *
 * Only digests of the session and CSRF values are stored. When a remote
 * address is supplied, subsequent validation requires the exact same address.
 *
 * @param[in,out] database Open database.
 * @param[in] identity Authenticated enabled identity.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[in] lifetime Absolute session lifetime in the supported range.
 * @param[in] remote_family IPv4, IPv6, or `JG_POLICY_ADDRESS_NONE`.
 * @param[in] remote_address Network-order address, required for IPv4/IPv6.
 * @param[out] tokens Receives one-time session and CSRF values.
 *
 * @return 0 on success.
 * @return -EINVAL for a null or inconsistent input.
 * @return -ERANGE for an invalid lifetime.
 * @return -EACCES when the identity is disabled or its epoch is stale.
 * @return A negative errno-style cryptographic or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Inserts one persistent session and obtains random bytes.
 */
JG_PUBLIC int jg_account_session_issue(
    struct jg_database *database,
    const struct jg_account_identity *identity,
    uint64_t now,
    uint64_t lifetime,
    enum jg_policy_address_family remote_family,
    const uint8_t *remote_address,
    struct jg_account_session_tokens *tokens);

/**
 * @brief Validate a web session and optionally its CSRF token.
 *
 * Session validation checks user enablement, absolute lifetime, inactivity,
 * remote-address binding, and the user's current revocation epoch. Successful
 * activity is persisted at a bounded interval.
 *
 * @param[in,out] database Open database.
 * @param[in] session Exact opaque session bytes.
 * @param[in] session_size Number of bytes in @p session.
 * @param[in] csrf Candidate CSRF bytes, or null when not required.
 * @param[in] csrf_size Number of bytes in @p csrf.
 * @param[in] require_csrf Whether a matching CSRF value is mandatory.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[in] inactivity_timeout Accepted idle seconds.
 * @param[in] remote_family Current IPv4, IPv6, or unavailable family.
 * @param[in] remote_address Current network-order address when available.
 * @param[out] identity Receives the current authorized identity.
 *
 * @return 0 for a valid session.
 * @return -EINVAL for a null or inconsistent input.
 * @return -ERANGE for an invalid inactivity timeout.
 * @return -EACCES for an unknown, expired, revoked, address-mismatched, or
 * CSRF-invalid session.
 * @return A negative errno-style SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects May advance the persistent last-seen timestamp.
 */
JG_PUBLIC int jg_account_session_validate(
    struct jg_database *database,
    const uint8_t *session,
    size_t session_size,
    const uint8_t *csrf,
    size_t csrf_size,
    bool require_csrf,
    uint64_t now,
    uint64_t inactivity_timeout,
    enum jg_policy_address_family remote_family,
    const uint8_t *remote_address,
    struct jg_account_identity *identity);

/**
 * @brief Revoke one opaque web session idempotently.
 *
 * @param[in,out] database Open database.
 * @param[in] session Exact opaque session bytes.
 * @param[in] session_size Number of bytes in @p session.
 *
 * @return 0 when the session was absent or removed.
 * @return -EINVAL for invalid input.
 * @return A negative errno-style digest or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Deletes a matching persistent session.
 */
JG_PUBLIC int jg_account_session_revoke(struct jg_database *database,
                                        const uint8_t *session,
                                        size_t session_size);

/**
 * @brief Revoke every current and outstanding session for one user.
 *
 * The user's session epoch and revision are incremented before all stored
 * sessions are deleted in the same transaction.
 *
 * @param[in,out] database Open database.
 * @param[in] user_id Nonzero persistent user identifier.
 *
 * @return 0 on success.
 * @return -EINVAL for a null database or zero identifier.
 * @return -ENOENT when the user does not exist.
 * @return A negative errno-style SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Invalidates every session issued under the old epoch.
 */
JG_PUBLIC int jg_account_sessions_revoke_all(struct jg_database *database,
                                             uint64_t user_id);

#endif
