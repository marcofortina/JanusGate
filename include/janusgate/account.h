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

/** Largest local-user page returned by one management query. */
#define JG_ACCOUNT_USER_PAGE_MAX 100U

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

/** Maximum API-token display-name bytes excluding the null terminator. */
#define JG_ACCOUNT_TOKEN_NAME_MAX 128U

/** Largest API-token page returned by one management query. */
#define JG_ACCOUNT_TOKEN_PAGE_MAX 100U

/** Smallest accepted API-token request limit per minute. */
#define JG_ACCOUNT_TOKEN_RATE_MIN 1U

/** Largest accepted API-token request limit per minute. */
#define JG_ACCOUNT_TOKEN_RATE_MAX 60000U

/** Number of one-time recovery codes issued when TOTP is enabled. */
#define JG_ACCOUNT_RECOVERY_CODE_COUNT 10U

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
    /** Whether required multifactor authentication has been completed. */
    bool mfa_complete;
};

/**
 * @brief Persistent local-user state returned to administration surfaces.
 */
struct jg_account_user {
    /** Persistent nonzero user identifier. */
    uint64_t user_id;
    /** Canonical local username. */
    char username[JG_ACCOUNT_USERNAME_MAX + 1U];
    /** Exactly one fixed backend role. */
    enum jg_access_role role;
    /** Current optimistic-concurrency revision. */
    uint64_t revision;
    /** Creation Unix timestamp. */
    uint64_t created_at;
    /** Last password-change Unix timestamp. */
    uint64_t password_changed_at;
    /** Last successful login timestamp, or zero when absent. */
    uint64_t last_login_at;
    /** Current lock expiry timestamp, or zero when unlocked. */
    uint64_t locked_until;
    /** Persistent consecutive login failures. */
    uint32_t failed_logins;
    /** Whether authentication is permitted. */
    bool enabled;
    /** Whether a password change is required after login. */
    bool force_password_change;
    /** Whether TOTP is enabled. */
    bool totp_enabled;
};

/**
 * @brief Mutable state accepted by a local-user administration update.
 */
struct jg_account_user_update {
    /** Exactly one fixed backend role. */
    enum jg_access_role role;
    /** Whether authentication remains permitted. */
    bool enabled;
    /** Whether the next login must change its password. */
    bool force_password_change;
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
 * @brief Validated configuration used when issuing one API token.
 */
struct jg_account_token_config {
    /** Nonempty administrative display name borrowed during the call. */
    const char *name;
    /** Nonzero API scope permissions limited by the owning user's roles. */
    uint32_t permissions;
    /** Absolute Unix expiry, or zero for no expiry. */
    uint64_t expires_at;
    /** Optional source-network family. */
    enum jg_policy_address_family source_family;
    /** Network-order source prefix address. */
    uint8_t source_address[16U];
    /** Significant source prefix bits, or zero without a restriction. */
    uint8_t source_prefix;
    /** Per-token requests accepted in one minute. */
    uint32_t requests_per_minute;
};

/**
 * @brief One-time plaintext API-token issuance result.
 */
struct jg_account_api_token {
    /** Persistent nonzero token identifier. */
    uint64_t token_id;
    /** Opaque token displayed only by the creation operation. */
    char secret[JG_AUTH_SECRET_TEXT_SIZE];
};

/**
 * @brief Persistent API-token metadata safe for administration surfaces.
 */
struct jg_account_token_record {
    /** Persistent nonzero token identifier. */
    uint64_t token_id;
    /** Owning nonzero local-user identifier. */
    uint64_t user_id;
    /** Current optimistic-concurrency revision. */
    uint64_t revision;
    /** Creation Unix timestamp. */
    uint64_t created_at;
    /** Absolute expiry timestamp, or zero when absent. */
    uint64_t expires_at;
    /** Last successful use timestamp, or zero when unused. */
    uint64_t last_used_at;
    /** Revocation timestamp, or zero while active. */
    uint64_t revoked_at;
    /** Granted backend permissions. */
    uint32_t permissions;
    /** Per-token requests accepted in one minute. */
    uint32_t requests_per_minute;
    /** Optional source-network family. */
    enum jg_policy_address_family source_family;
    /** Canonical network-order source prefix address. */
    uint8_t source_address[16U];
    /** Significant source prefix bits. */
    uint8_t source_prefix;
    /** Administrative display name. */
    char name[JG_ACCOUNT_TOKEN_NAME_MAX + 1U];
    /** Current owning username. */
    char username[JG_ACCOUNT_USERNAME_MAX + 1U];
};

/**
 * @brief One-time TOTP enrollment material.
 */
struct jg_account_totp_provisioning {
    /** Canonical Base32 secret suitable for an `otpauth` URI. */
    char secret[JG_AUTH_TOTP_SECRET_TEXT_SIZE];
};

/**
 * @brief One-time recovery codes returned when TOTP is confirmed.
 */
struct jg_account_recovery_codes {
    /** Independent opaque recovery values shown exactly once. */
    char codes[JG_ACCOUNT_RECOVERY_CODE_COUNT][JG_AUTH_SECRET_TEXT_SIZE];
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
 * @brief List local users in stable username order.
 *
 * @param[in] database Open database.
 * @param[in] offset Zero-based page offset.
 * @param[out] users Receives up to @p capacity user records.
 * @param[in] capacity Requested page size from one through
 * JG_ACCOUNT_USER_PAGE_MAX.
 * @param[out] count Receives the number of returned records.
 * @param[out] total Receives the total number of local users.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument or invalid capacity.
 * @return -EOVERFLOW when pagination or persistent values cannot be
 * represented.
 * @return -EILSEQ when a user has invalid persistent role state.
 * @return A negative errno-style SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_account_user_list(struct jg_database *database,
                                   uint64_t offset,
                                   struct jg_account_user *users,
                                   size_t capacity,
                                   size_t *count,
                                   uint64_t *total);

/**
 * @brief Create one enabled local user with exactly one role.
 *
 * @param[in,out] database Open database.
 * @param[in] username New unique local username.
 * @param[in] password Initial password bytes.
 * @param[in] password_size Number of bytes in @p password.
 * @param[in] password_policy Valid Argon2id password policy.
 * @param[in] role Initial fixed backend role.
 * @param[in] force_password_change Whether the first login must change its
 * password.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] user Receives the created persistent state.
 *
 * @return 0 on success.
 * @return -EINVAL for a null or malformed input.
 * @return -EEXIST when the username is already present.
 * @return A negative errno-style hashing or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Creates the user and its role assignment transactionally.
 */
JG_PUBLIC int jg_account_user_create(
    struct jg_database *database,
    const char *username,
    const uint8_t *password,
    size_t password_size,
    const struct jg_auth_password_policy *password_policy,
    enum jg_access_role role,
    bool force_password_change,
    uint64_t now,
    struct jg_account_user *user);

/**
 * @brief Update one local user's role and authentication state.
 *
 * Role and enablement changes invalidate every current web session. Disabling
 * a user also revokes every current API token. The final enabled
 * administrator cannot be disabled or assigned another role.
 *
 * @param[in,out] database Open database.
 * @param[in] user_id Existing nonzero user identifier.
 * @param[in] expected_revision Current revision supplied by the caller.
 * @param[in] update Complete replacement state.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] user Receives the updated persistent state.
 *
 * @return 0 on success.
 * @return -EINVAL for a null or malformed input.
 * @return -ENOENT when the user does not exist.
 * @return -ESTALE when @p expected_revision is no longer current.
 * @return -EPERM when the update would remove the final enabled
 * administrator.
 * @return A negative errno-style SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Updates role and state and revokes affected credentials
 * transactionally.
 */
JG_PUBLIC int jg_account_user_update(
    struct jg_database *database,
    uint64_t user_id,
    uint64_t expected_revision,
    const struct jg_account_user_update *update,
    uint64_t now,
    struct jg_account_user *user);

/**
 * @brief Replace one local user's password and revoke current credentials.
 *
 * @param[in,out] database Open database.
 * @param[in] user_id Existing nonzero user identifier.
 * @param[in] expected_revision Current revision supplied by the caller.
 * @param[in] password Replacement password bytes.
 * @param[in] password_size Number of bytes in @p password.
 * @param[in] password_policy Valid Argon2id password policy.
 * @param[in] force_password_change Whether the user must replace this password
 * after login.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] user Receives the updated persistent state.
 *
 * @return 0 on success.
 * @return -EINVAL for a null or malformed input.
 * @return -ENOENT when the user does not exist.
 * @return -ESTALE when @p expected_revision is no longer current.
 * @return A negative errno-style hashing or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Replaces the password, clears login failures, and revokes all
 * web sessions and API tokens transactionally.
 */
JG_PUBLIC int jg_account_user_reset_password(
    struct jg_database *database,
    uint64_t user_id,
    uint64_t expected_revision,
    const uint8_t *password,
    size_t password_size,
    const struct jg_auth_password_policy *password_policy,
    bool force_password_change,
    uint64_t now,
    struct jg_account_user *user);

/**
 * @brief Remove one local user's TOTP and recovery credentials.
 *
 * @param[in,out] database Open database.
 * @param[in] user_id Existing nonzero user identifier.
 * @param[in] expected_revision Current revision supplied by the caller.
 * @param[out] user Receives the updated persistent state.
 *
 * @return 0 on success.
 * @return -EINVAL for a null or malformed input.
 * @return -ENOENT when the user or TOTP credential does not exist.
 * @return -ESTALE when @p expected_revision is no longer current.
 * @return A negative errno-style SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Deletes TOTP and recovery material and invalidates every web
 * session transactionally.
 */
JG_PUBLIC int jg_account_user_disable_totp(struct jg_database *database,
                                           uint64_t user_id,
                                           uint64_t expected_revision,
                                           struct jg_account_user *user);

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

/**
 * @brief Issue one scoped API token for an enabled local user.
 *
 * The requested scopes must be a subset of the user's current role
 * permissions. Only a fixed digest of the returned secret is persisted.
 *
 * @param[in,out] database Open database.
 * @param[in] user_id Owning nonzero user identifier.
 * @param[in] config Complete token configuration.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] token Receives the persistent identifier and one-time secret.
 *
 * @return 0 on success.
 * @return -EINVAL for a null, malformed, or unsupported input.
 * @return -EACCES when the user is disabled or lacks requested permissions.
 * @return -ENOENT when the user does not exist.
 * @return A negative errno-style cryptographic or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Inserts one persistent token and obtains random bytes.
 */
JG_PUBLIC int jg_account_token_issue(
    struct jg_database *database,
    uint64_t user_id,
    const struct jg_account_token_config *config,
    uint64_t now,
    struct jg_account_api_token *token);

/**
 * @brief List API-token metadata in stable identifier order.
 *
 * Secret hashes and plaintext token material are never included.
 *
 * @param[in] database Open database.
 * @param[in] offset Zero-based page offset.
 * @param[out] tokens Receives up to @p capacity records.
 * @param[in] capacity Requested page size from one through
 * JG_ACCOUNT_TOKEN_PAGE_MAX.
 * @param[out] count Receives the number of returned records.
 * @param[out] total Receives the total number of persistent tokens.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument or invalid pagination.
 * @return -EILSEQ for invalid persistent token metadata.
 * @return A negative errno-style SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_account_token_list(struct jg_database *database,
                                    uint64_t offset,
                                    struct jg_account_token_record *tokens,
                                    size_t capacity,
                                    size_t *count,
                                    uint64_t *total);

/**
 * @brief Read one API token's safe administrative metadata.
 *
 * @param[in] database Open database.
 * @param[in] token_id Persistent nonzero token identifier.
 * @param[out] token Receives metadata without hash or plaintext secret.
 *
 * @return 0 on success.
 * @return -EINVAL for an invalid argument.
 * @return -ENOENT when the token does not exist.
 * @return -EILSEQ for invalid persistent token metadata.
 * @return A negative errno-style SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_account_token_get(struct jg_database *database,
                                   uint64_t token_id,
                                   struct jg_account_token_record *token);

/**
 * @brief Authenticate one API token and return its current identity.
 *
 * Role permissions and persistent token scopes are intersected on every
 * authentication. Optional source-network and expiry restrictions are
 * enforced before the token's last-use timestamp is advanced.
 *
 * @param[in,out] database Open database.
 * @param[in] token Opaque API-token bytes.
 * @param[in] token_size Number of bytes in @p token.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[in] remote_family Current IPv4 or IPv6 source family.
 * @param[in] remote_address Current network-order source address.
 * @param[out] identity Receives the authorized owning identity.
 * @param[out] token_id Receives the persistent token identifier.
 * @param[out] requests_per_minute Receives the persistent rate limit.
 *
 * @return 0 on successful token authentication.
 * @return -EINVAL for a null or inconsistent input.
 * @return -EACCES for an unknown, expired, revoked, disabled, or
 * source-mismatched token.
 * @return A negative errno-style digest or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects May advance the persistent last-use timestamp.
 */
JG_PUBLIC int jg_account_token_validate(
    struct jg_database *database,
    const uint8_t *token,
    size_t token_size,
    uint64_t now,
    enum jg_policy_address_family remote_family,
    const uint8_t *remote_address,
    struct jg_account_identity *identity,
    uint64_t *token_id,
    uint32_t *requests_per_minute);

/**
 * @brief Revoke one API token idempotently.
 *
 * @param[in,out] database Open database.
 * @param[in] token_id Persistent nonzero token identifier.
 * @param[in] now Current Unix timestamp in seconds.
 *
 * @return 0 when the token was already revoked or is revoked now.
 * @return -EINVAL for invalid arguments.
 * @return -ENOENT when the token does not exist.
 * @return A negative errno-style SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Sets the revocation timestamp and increments token revision.
 */
JG_PUBLIC int jg_account_token_revoke(struct jg_database *database,
                                      uint64_t token_id,
                                      uint64_t now);

/**
 * @brief Begin TOTP enrollment for one enabled user.
 *
 * The new secret is encrypted with the appliance-local key before storage and
 * remains disabled until explicitly confirmed. Existing enabled enrollment
 * cannot be overwritten.
 *
 * @param[in,out] database Open database.
 * @param[in] user_id Enabled nonzero user identifier.
 * @param[in] key Appliance-local TOTP encryption key.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] provisioning Receives the one-time Base32 secret.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -ENOENT when the user does not exist.
 * @return -EACCES when the user is disabled.
 * @return -EEXIST when TOTP is already enabled.
 * @return A negative errno-style cryptographic or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Stores one disabled encrypted TOTP credential.
 */
JG_PUBLIC int jg_account_totp_provision(
    struct jg_database *database,
    uint64_t user_id,
    const uint8_t key[JG_AUTH_TOTP_KEY_SIZE],
    uint64_t now,
    struct jg_account_totp_provisioning *provisioning);

/**
 * @brief Confirm pending TOTP enrollment and issue recovery codes.
 *
 * The TOTP code must match the pending encrypted secret. Enabling MFA,
 * storing hashed recovery codes, advancing the user epoch, and revoking
 * existing sessions occur in one transaction.
 *
 * @param[in,out] database Open database.
 * @param[in] user_id Enrolling nonzero user identifier.
 * @param[in] key Appliance-local TOTP encryption key.
 * @param[in] code Six-digit TOTP value.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] recovery_codes Receives one-time recovery values.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or code range.
 * @return -EACCES for an incorrect code or disabled user.
 * @return -ENOENT when no pending enrollment exists.
 * @return -EALREADY when TOTP is already enabled.
 * @return A negative errno-style cryptographic or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Enables TOTP and revokes existing sessions transactionally.
 */
JG_PUBLIC int jg_account_totp_confirm(
    struct jg_database *database,
    uint64_t user_id,
    const uint8_t key[JG_AUTH_TOTP_KEY_SIZE],
    uint32_t code,
    uint64_t now,
    struct jg_account_recovery_codes *recovery_codes);

/**
 * @brief Complete password authentication with a TOTP code.
 *
 * The supplied password identity must still match the user's current
 * revision and session epoch.
 *
 * @param[in,out] database Open database.
 * @param[in] password_identity Identity returned by password authentication.
 * @param[in] key Appliance-local TOTP encryption key.
 * @param[in] code Six-digit TOTP value.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] identity Receives an MFA-complete current identity.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or code range.
 * @return -EACCES for an incorrect code or stale identity.
 * @return -ENOENT when no enabled TOTP credential exists.
 * @return A negative errno-style cryptographic or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_account_totp_authenticate(
    struct jg_database *database,
    const struct jg_account_identity *password_identity,
    const uint8_t key[JG_AUTH_TOTP_KEY_SIZE],
    uint32_t code,
    uint64_t now,
    struct jg_account_identity *identity);

/**
 * @brief Complete password authentication with one recovery code.
 *
 * A matching recovery code is marked used in the same transaction that
 * validates the current user identity and can never authenticate again.
 *
 * @param[in,out] database Open database.
 * @param[in] password_identity Identity returned by password authentication.
 * @param[in] recovery_code Exact opaque recovery-code bytes.
 * @param[in] recovery_code_size Number of bytes in @p recovery_code.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] identity Receives an MFA-complete current identity.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments.
 * @return -EACCES for an unknown, used, or stale recovery credential.
 * @return A negative errno-style digest or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Marks one matching recovery code used transactionally.
 */
JG_PUBLIC int jg_account_recovery_authenticate(
    struct jg_database *database,
    const struct jg_account_identity *password_identity,
    const uint8_t *recovery_code,
    size_t recovery_code_size,
    uint64_t now,
    struct jg_account_identity *identity);

/**
 * @brief Disable TOTP and invalidate existing sessions for one user.
 *
 * @param[in,out] database Open database.
 * @param[in] user_id Nonzero persistent user identifier.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -ENOENT when the user or TOTP credential does not exist.
 * @return A negative errno-style SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Deletes TOTP and recovery material and advances the user epoch.
 */
JG_PUBLIC int jg_account_totp_disable(struct jg_database *database,
                                      uint64_t user_id);

#endif
