/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/auth.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sodium.h>

/** @brief Initialize the cryptographic provider. */
static int initialize_crypto(void)
{
    return sodium_init() < 0 ? -EIO : 0;
}

/** @brief Validate password-policy bounds supported by this release. */
static bool password_policy_valid(const struct jg_auth_password_policy *policy)
{
    return policy != NULL && policy->minimum_length >= JG_AUTH_PASSWORD_MIN &&
           policy->maximum_length <= JG_AUTH_PASSWORD_MAX &&
           policy->minimum_length <= policy->maximum_length &&
           policy->operations >= JG_AUTH_OPERATIONS_MIN &&
           policy->operations <= JG_AUTH_OPERATIONS_MAX &&
           policy->memory >= JG_AUTH_MEMORY_MIN &&
           policy->memory <= JG_AUTH_MEMORY_MAX;
}

/** @brief Determine whether an encoded hash is bounded and terminated. */
static bool encoded_hash_valid(
    const char encoded_hash[JG_AUTH_PASSWORD_HASH_SIZE])
{
    return encoded_hash != NULL &&
           memchr(encoded_hash, '\0', JG_AUTH_PASSWORD_HASH_SIZE) != NULL;
}

/** @brief Initialize a secure interactive password policy. */
void jg_auth_password_policy_default(struct jg_auth_password_policy *policy)
{
    if (policy != NULL) {
        policy->minimum_length = JG_AUTH_PASSWORD_MIN;
        policy->maximum_length = JG_AUTH_PASSWORD_MAX;
        policy->operations = crypto_pwhash_OPSLIMIT_INTERACTIVE;
        policy->memory = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    }
}

/** @brief Hash one validated password with Argon2id. */
int jg_auth_password_hash(const struct jg_auth_password_policy *policy,
                          const uint8_t *password,
                          size_t password_size,
                          char encoded_hash[JG_AUTH_PASSWORD_HASH_SIZE])
{
    int result = 0;

    if (encoded_hash == NULL) {
        return -EINVAL;
    }
    (void)memset(encoded_hash, 0, JG_AUTH_PASSWORD_HASH_SIZE);
    if (!password_policy_valid(policy) || password == NULL) {
        return -EINVAL;
    }
    if (password_size < policy->minimum_length ||
        password_size > policy->maximum_length) {
        return -ERANGE;
    }
    result = initialize_crypto();
    if (result != 0) {
        return result;
    }
    if (crypto_pwhash_str_alg(encoded_hash, (const char *)password,
                              (unsigned long long)password_size,
                              policy->operations, policy->memory,
                              crypto_pwhash_ALG_ARGON2ID13) != 0) {
        (void)memset(encoded_hash, 0, JG_AUTH_PASSWORD_HASH_SIZE);
        return -ENOMEM;
    }
    return 0;
}

/** @brief Verify one password against a bounded Argon2id hash. */
int jg_auth_password_verify(const struct jg_auth_password_policy *policy,
                            const uint8_t *password,
                            size_t password_size,
                            const char encoded_hash[JG_AUTH_PASSWORD_HASH_SIZE],
                            bool *valid,
                            bool *needs_rehash)
{
    int rehash = 0;
    int result = 0;

    if (valid == NULL || needs_rehash == NULL) {
        return -EINVAL;
    }
    *valid = false;
    *needs_rehash = false;
    if (!password_policy_valid(policy) || password == NULL ||
        !encoded_hash_valid(encoded_hash)) {
        return -EINVAL;
    }
    if (password_size > JG_AUTH_PASSWORD_MAX) {
        return -ERANGE;
    }
    result = initialize_crypto();
    if (result != 0) {
        return result;
    }
    rehash = crypto_pwhash_str_needs_rehash(encoded_hash, policy->operations,
                                            policy->memory);
    if (rehash < 0) {
        return -EINVAL;
    }
    if (crypto_pwhash_str_verify(encoded_hash, (const char *)password,
                                 (unsigned long long)password_size) != 0) {
        return 0;
    }
    *valid = true;
    *needs_rehash = rehash != 0;
    return 0;
}

/** @brief Compute one fixed digest for an opaque secret. */
int jg_auth_secret_digest(const uint8_t *secret,
                          size_t secret_size,
                          uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE])
{
    int result = 0;

    if (digest == NULL) {
        return -EINVAL;
    }
    (void)memset(digest, 0, JG_AUTH_SECRET_DIGEST_SIZE);
    if (secret == NULL || secret_size == 0U) {
        return -EINVAL;
    }
    result = initialize_crypto();
    if (result != 0) {
        return result;
    }
    if (crypto_generichash(digest, JG_AUTH_SECRET_DIGEST_SIZE, secret,
                           (unsigned long long)secret_size, NULL, 0U) != 0) {
        return -EIO;
    }
    return 0;
}

/** @brief Generate and hash one opaque authentication secret. */
int jg_auth_secret_issue(char secret[JG_AUTH_SECRET_TEXT_SIZE],
                         uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE])
{
    uint8_t random[JG_AUTH_SECRET_BYTES];
    int result = 0;

    if (secret == NULL || digest == NULL) {
        return -EINVAL;
    }
    (void)memset(secret, 0, JG_AUTH_SECRET_TEXT_SIZE);
    (void)memset(digest, 0, JG_AUTH_SECRET_DIGEST_SIZE);
    result = initialize_crypto();
    if (result != 0) {
        return result;
    }
    randombytes_buf(random, sizeof(random));
    if (sodium_bin2base64(secret, JG_AUTH_SECRET_TEXT_SIZE, random,
                          sizeof(random),
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        result = -EIO;
    } else {
        result = jg_auth_secret_digest((const uint8_t *)secret,
                                       JG_AUTH_SECRET_TEXT_SIZE - 1U, digest);
    }
    sodium_memzero(random, sizeof(random));
    if (result != 0) {
        (void)memset(secret, 0, JG_AUTH_SECRET_TEXT_SIZE);
        (void)memset(digest, 0, JG_AUTH_SECRET_DIGEST_SIZE);
    }
    return result;
}

/** @brief Compare two persistent secret digests in constant time. */
bool jg_auth_secret_digest_equal(
    const uint8_t left[JG_AUTH_SECRET_DIGEST_SIZE],
    const uint8_t right[JG_AUTH_SECRET_DIGEST_SIZE])
{
    return left != NULL && right != NULL &&
           sodium_memcmp(left, right, JG_AUTH_SECRET_DIGEST_SIZE) == 0;
}
