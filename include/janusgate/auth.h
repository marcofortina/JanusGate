/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file auth.h
 * @brief Password hashing and opaque authentication-secret primitives.
 *
 * Passwords are hashed with Argon2id. Issued secrets contain 256 random bits
 * encoded as unpadded URL-safe Base64; callers persist only their digest.
 *
 * @thread_safety Every function is reentrant.
 *
 * @error_handling Functions return zero on success and negative errno-style
 * values on failure. Output buffers are cleared before an error is returned.
 */

#ifndef JANUSGATE_AUTH_H
#define JANUSGATE_AUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Smallest accepted password in bytes. */
#define JG_AUTH_PASSWORD_MIN 12U

/** Largest accepted password in bytes. */
#define JG_AUTH_PASSWORD_MAX 256U

/** Bytes reserved for a portable encoded Argon2id hash, including null. */
#define JG_AUTH_PASSWORD_HASH_SIZE 128U

/** Raw bytes in every issued opaque authentication secret. */
#define JG_AUTH_SECRET_BYTES 32U

/** Bytes in an encoded opaque secret, including its null terminator. */
#define JG_AUTH_SECRET_TEXT_SIZE 44U

/** Bytes in the persistent digest of an opaque secret. */
#define JG_AUTH_SECRET_DIGEST_SIZE 32U

/** Raw random bytes in one TOTP secret. */
#define JG_AUTH_TOTP_SECRET_SIZE 32U

/** Canonical unpadded Base32 bytes for one TOTP secret, including null. */
#define JG_AUTH_TOTP_SECRET_TEXT_SIZE 53U

/** Seconds in one TOTP counter period. */
#define JG_AUTH_TOTP_PERIOD 30U

/** Decimal digits in one JanusGate TOTP code. */
#define JG_AUTH_TOTP_DIGITS 6U

/** Largest accepted verification window on either side of the current step. */
#define JG_AUTH_TOTP_WINDOW_MAX 10U

/** Bytes in the appliance-local key used to protect TOTP secrets. */
#define JG_AUTH_TOTP_KEY_SIZE 32U

/** Bytes in one independently random TOTP encryption nonce. */
#define JG_AUTH_TOTP_NONCE_SIZE 24U

/** Bytes in one authenticated encrypted TOTP secret. */
#define JG_AUTH_TOTP_CIPHERTEXT_SIZE 48U

/** Minimum accepted Argon2id memory cost. */
#define JG_AUTH_MEMORY_MIN (8U * 1024U * 1024U)

/** Maximum accepted Argon2id memory cost. */
#define JG_AUTH_MEMORY_MAX (1024U * 1024U * 1024U)

/** Minimum accepted Argon2id computation cost. */
#define JG_AUTH_OPERATIONS_MIN 2U

/** Maximum accepted Argon2id computation cost. */
#define JG_AUTH_OPERATIONS_MAX 10U

/** Configurable password policy and Argon2id resource limits. */
struct jg_auth_password_policy {
    /** Minimum accepted password bytes. */
    size_t minimum_length;
    /** Maximum accepted password bytes. */
    size_t maximum_length;
    /** Argon2id computation cost. */
    uint64_t operations;
    /** Argon2id working-memory bytes. */
    size_t memory;
};

/**
 * @brief Initialize a secure password policy suitable for interactive login.
 *
 * @param[out] policy Policy to initialize; null is ignored.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC void jg_auth_password_policy_default(
    struct jg_auth_password_policy *policy);

/**
 * @brief Hash one password with Argon2id.
 *
 * @param[in] policy Valid password and resource policy.
 * @param[in] password Password bytes, which need not be null-terminated.
 * @param[in] password_size Number of bytes in @p password.
 * @param[out] encoded_hash Receives a portable null-terminated hash.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument or invalid policy.
 * @return -ERANGE when the password violates the configured length policy.
 * @return -ENOMEM when hashing resources cannot be allocated.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_auth_password_hash(
    const struct jg_auth_password_policy *policy,
    const uint8_t *password,
    size_t password_size,
    char encoded_hash[JG_AUTH_PASSWORD_HASH_SIZE]);

/**
 * @brief Verify a password and report whether its hash should be upgraded.
 *
 * An incorrect password is a successful verification operation with
 * `valid == false`; it is not reported as a processing error.
 *
 * @param[in] policy Current valid password and resource policy.
 * @param[in] password Candidate password bytes.
 * @param[in] password_size Number of bytes in @p password.
 * @param[in] encoded_hash Portable Argon2id hash.
 * @param[out] valid Receives whether the password matches.
 * @param[out] needs_rehash Receives whether a matching hash uses old costs.
 *
 * @return 0 when verification was performed.
 * @return -EINVAL for a null argument, malformed hash, or invalid policy.
 * @return -ERANGE when the candidate exceeds the absolute password limit.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_auth_password_verify(
    const struct jg_auth_password_policy *policy,
    const uint8_t *password,
    size_t password_size,
    const char encoded_hash[JG_AUTH_PASSWORD_HASH_SIZE],
    bool *valid,
    bool *needs_rehash);

/**
 * @brief Generate a new opaque secret and its persistent digest.
 *
 * @param[out] secret Receives unpadded URL-safe Base64 shown to the caller
 * once.
 * @param[out] digest Receives the digest suitable for persistent storage.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -EIO when the cryptographic provider cannot initialize.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Obtains random bytes from the operating system.
 */
JG_PUBLIC int jg_auth_secret_issue(char secret[JG_AUTH_SECRET_TEXT_SIZE],
                                   uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE]);

/**
 * @brief Compute the persistent digest of an opaque secret.
 *
 * @param[in] secret Nonempty secret bytes.
 * @param[in] secret_size Number of bytes in @p secret.
 * @param[out] digest Receives the fixed-size digest.
 *
 * @return 0 on success.
 * @return -EINVAL for a null or empty input.
 * @return -EIO when the cryptographic provider cannot initialize.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_auth_secret_digest(const uint8_t *secret,
                                    size_t secret_size,
                                    uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE]);

/**
 * @brief Compare two persistent secret digests in constant time.
 *
 * @param[in] left First digest.
 * @param[in] right Second digest.
 *
 * @return `true` only when both nonnull digests are identical.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC bool jg_auth_secret_digest_equal(
    const uint8_t left[JG_AUTH_SECRET_DIGEST_SIZE],
    const uint8_t right[JG_AUTH_SECRET_DIGEST_SIZE]);

/**
 * @brief Generate one TOTP secret and its canonical Base32 representation.
 *
 * The text form is unpadded uppercase Base32 suitable for an `otpauth` URI.
 * The caller must encrypt the raw secret before persistent storage and clear
 * both representations as soon as provisioning finishes.
 *
 * @param[out] secret Receives 256 random secret bits.
 * @param[out] encoded Receives the null-terminated Base32 representation.
 *
 * @return 0 on success.
 * @return -EINVAL for a null output.
 * @return -EIO when the cryptographic provider cannot initialize.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Obtains random bytes from the operating system.
 */
JG_PUBLIC int jg_auth_totp_secret_issue(
    uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE],
    char encoded[JG_AUTH_TOTP_SECRET_TEXT_SIZE]);

/**
 * @brief Decode one exact canonical JanusGate TOTP secret.
 *
 * @param[in] encoded Null-terminated uppercase unpadded Base32 text.
 * @param[out] secret Receives the decoded secret.
 *
 * @return 0 on success.
 * @return -EINVAL for a null, malformed, noncanonical, or incorrectly sized
 * representation.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_auth_totp_secret_decode(
    const char encoded[JG_AUTH_TOTP_SECRET_TEXT_SIZE],
    uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE]);

/**
 * @brief Generate the six-digit TOTP code for one Unix timestamp.
 *
 * Codes use a 30-second moving counter and HMAC-SHA-256.
 *
 * @param[in] secret Exact raw TOTP secret.
 * @param[in] timestamp Unix timestamp in seconds.
 * @param[out] code Receives a value from 0 through 999999.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -EIO when the cryptographic provider cannot initialize.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_auth_totp_generate(
    const uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE],
    uint64_t timestamp,
    uint32_t *code);

/**
 * @brief Verify one TOTP code within a bounded symmetric time window.
 *
 * @param[in] secret Exact raw TOTP secret.
 * @param[in] timestamp Current Unix timestamp in seconds.
 * @param[in] code Candidate value from 0 through 999999.
 * @param[in] window Accepted counter steps before and after the current step,
 * at most @ref JG_AUTH_TOTP_WINDOW_MAX.
 * @param[out] valid Receives whether one counter in the window matched.
 *
 * @return 0 when verification was performed.
 * @return -EINVAL for a null argument or invalid code.
 * @return -ERANGE when @p window exceeds the supported bound.
 * @return -EIO when the cryptographic provider cannot initialize.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_auth_totp_verify(
    const uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE],
    uint64_t timestamp,
    uint32_t code,
    uint32_t window,
    bool *valid);

/**
 * @brief Encrypt one TOTP secret for persistent storage.
 *
 * XChaCha20-Poly1305 authenticates the ciphertext and a fresh random nonce.
 * The appliance-local key must be stored separately from the database with
 * mode 0600 and must never be exposed through administration responses.
 *
 * @param[in] key Exact appliance-local encryption key.
 * @param[in] secret Exact raw TOTP secret.
 * @param[out] nonce Receives the random public nonce.
 * @param[out] ciphertext Receives the authenticated ciphertext.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -EIO when the cryptographic provider cannot initialize or encrypt.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Obtains a random nonce from the operating system.
 */
JG_PUBLIC int jg_auth_totp_encrypt(
    const uint8_t key[JG_AUTH_TOTP_KEY_SIZE],
    const uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE],
    uint8_t nonce[JG_AUTH_TOTP_NONCE_SIZE],
    uint8_t ciphertext[JG_AUTH_TOTP_CIPHERTEXT_SIZE]);

/**
 * @brief Authenticate and decrypt one persistent TOTP secret.
 *
 * @param[in] key Exact appliance-local encryption key.
 * @param[in] nonce Persistent public nonce.
 * @param[in] ciphertext Persistent authenticated ciphertext.
 * @param[out] secret Receives the plaintext only after authentication.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -EBADMSG when authentication fails.
 * @return -EIO when the cryptographic provider cannot initialize.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_auth_totp_decrypt(
    const uint8_t key[JG_AUTH_TOTP_KEY_SIZE],
    const uint8_t nonce[JG_AUTH_TOTP_NONCE_SIZE],
    const uint8_t ciphertext[JG_AUTH_TOTP_CIPHERTEXT_SIZE],
    uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE]);

#endif
