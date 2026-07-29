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

_Static_assert(JG_AUTH_TOTP_KEY_SIZE ==
                   crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
               "TOTP key size must match XChaCha20-Poly1305");
_Static_assert(JG_AUTH_TOTP_NONCE_SIZE ==
                   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
               "TOTP nonce size must match XChaCha20-Poly1305");
_Static_assert(JG_AUTH_TOTP_CIPHERTEXT_SIZE ==
                   JG_AUTH_TOTP_SECRET_SIZE +
                       crypto_aead_xchacha20poly1305_ietf_ABYTES,
               "TOTP ciphertext must include its authentication tag");

/** Alphabet used by canonical unpadded TOTP secret encoding. */
static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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

/** @brief Encode a fixed-size TOTP secret as canonical unpadded Base32. */
static void totp_secret_encode(const uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE],
                               char encoded[JG_AUTH_TOTP_SECRET_TEXT_SIZE])
{
    uint32_t bits = 0U;
    unsigned int bit_count = 0U;
    size_t output_index = 0U;

    for (size_t index = 0U; index < JG_AUTH_TOTP_SECRET_SIZE; ++index) {
        bits = (bits << 8U) | secret[index];
        bit_count += 8U;
        while (bit_count >= 5U) {
            bit_count -= 5U;
            encoded[output_index] =
                base32_alphabet[(bits >> bit_count) & UINT32_C(0x1f)];
            ++output_index;
        }
    }
    if (bit_count != 0U) {
        encoded[output_index] =
            base32_alphabet[(bits << (5U - bit_count)) & UINT32_C(0x1f)];
        ++output_index;
    }
    encoded[output_index] = '\0';
}

/** @brief Return one canonical Base32 symbol value or a negative error. */
static int base32_value(char character)
{
    if (character >= 'A' && character <= 'Z') {
        return character - 'A';
    }
    if (character >= '2' && character <= '7') {
        return character - '2' + 26;
    }
    return -EINVAL;
}

/** @brief Generate one random TOTP secret and its provisioning text. */
int jg_auth_totp_secret_issue(uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE],
                              char encoded[JG_AUTH_TOTP_SECRET_TEXT_SIZE])
{
    int result = 0;

    if (secret == NULL || encoded == NULL) {
        return -EINVAL;
    }
    (void)memset(secret, 0, JG_AUTH_TOTP_SECRET_SIZE);
    (void)memset(encoded, 0, JG_AUTH_TOTP_SECRET_TEXT_SIZE);
    result = initialize_crypto();
    if (result == 0) {
        randombytes_buf(secret, JG_AUTH_TOTP_SECRET_SIZE);
        totp_secret_encode(secret, encoded);
    }
    return result;
}

/** @brief Decode one exact canonical unpadded Base32 TOTP secret. */
int jg_auth_totp_secret_decode(
    const char encoded[JG_AUTH_TOTP_SECRET_TEXT_SIZE],
    uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE])
{
    uint32_t bits = 0U;
    unsigned int bit_count = 0U;
    size_t output_index = 0U;
    size_t input_index = 0U;
    int value = 0;
    int result = 0;

    if (encoded == NULL || secret == NULL) {
        return -EINVAL;
    }
    (void)memset(secret, 0, JG_AUTH_TOTP_SECRET_SIZE);
    if (encoded[JG_AUTH_TOTP_SECRET_TEXT_SIZE - 1U] != '\0') {
        return -EINVAL;
    }
    while (input_index < JG_AUTH_TOTP_SECRET_TEXT_SIZE - 1U &&
           encoded[input_index] != '\0') {
        value = base32_value(encoded[input_index]);
        if (value < 0) {
            result = value;
            break;
        }
        bits = (bits << 5U) | (uint32_t)value;
        bit_count += 5U;
        if (bit_count >= 8U) {
            bit_count -= 8U;
            if (output_index >= JG_AUTH_TOTP_SECRET_SIZE) {
                result = -EINVAL;
                break;
            }
            secret[output_index] = (uint8_t)(bits >> bit_count);
            ++output_index;
        }
        ++input_index;
    }
    if (result == 0 && (input_index != JG_AUTH_TOTP_SECRET_TEXT_SIZE - 1U ||
                        output_index != JG_AUTH_TOTP_SECRET_SIZE ||
                        (bits & ((UINT32_C(1) << bit_count) - 1U)) != 0U)) {
        result = -EINVAL;
    }
    if (result != 0) {
        sodium_memzero(secret, JG_AUTH_TOTP_SECRET_SIZE);
    }
    return result;
}

/** @brief Generate one HMAC-SHA-256 TOTP code for a moving counter. */
static int totp_generate_counter(const uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE],
                                 uint64_t counter,
                                 uint32_t *code)
{
    crypto_auth_hmacsha256_state state;
    uint8_t digest[crypto_auth_hmacsha256_BYTES];
    uint8_t message[8U];
    size_t offset = 0U;
    uint32_t binary = 0U;
    int result = initialize_crypto();

    if (result != 0) {
        return result;
    }
    for (size_t index = 0U; index < sizeof(message); ++index) {
        message[sizeof(message) - index - 1U] =
            (uint8_t)(counter >> (index * 8U));
    }
    if (crypto_auth_hmacsha256_init(&state, secret, JG_AUTH_TOTP_SECRET_SIZE) !=
            0 ||
        crypto_auth_hmacsha256_update(&state, message, sizeof(message)) != 0 ||
        crypto_auth_hmacsha256_final(&state, digest) != 0) {
        sodium_memzero(&state, sizeof(state));
        sodium_memzero(digest, sizeof(digest));
        return -EIO;
    }
    offset = digest[sizeof(digest) - 1U] & UINT8_C(0x0f);
    binary = ((uint32_t)(digest[offset] & UINT8_C(0x7f)) << 24U) |
             ((uint32_t)digest[offset + 1U] << 16U) |
             ((uint32_t)digest[offset + 2U] << 8U) |
             (uint32_t)digest[offset + 3U];
    *code = binary % UINT32_C(1000000);
    sodium_memzero(&state, sizeof(state));
    sodium_memzero(digest, sizeof(digest));
    return 0;
}

/** @brief Generate one TOTP code for a Unix timestamp. */
int jg_auth_totp_generate(const uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE],
                          uint64_t timestamp,
                          uint32_t *code)
{
    if (secret == NULL || code == NULL) {
        return -EINVAL;
    }
    *code = 0U;
    return totp_generate_counter(secret, timestamp / JG_AUTH_TOTP_PERIOD, code);
}

/** @brief Format one TOTP code as six fixed decimal bytes. */
static void format_totp_code(uint32_t code, uint8_t output[JG_AUTH_TOTP_DIGITS])
{
    for (size_t index = JG_AUTH_TOTP_DIGITS; index > 0U; --index) {
        output[index - 1U] = (uint8_t)('0' + (code % 10U));
        code /= 10U;
    }
}

/** @brief Verify a TOTP code across one bounded counter window. */
int jg_auth_totp_verify(const uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE],
                        uint64_t timestamp,
                        uint32_t code,
                        uint32_t window,
                        bool *valid)
{
    uint8_t candidate[JG_AUTH_TOTP_DIGITS];
    uint8_t expected[JG_AUTH_TOTP_DIGITS];
    const uint64_t counter = timestamp / JG_AUTH_TOTP_PERIOD;
    uint64_t first = counter > window ? counter - window : 0U;
    uint64_t last;
    uint32_t expected_code = 0U;
    int result = 0;

    if (valid == NULL) {
        return -EINVAL;
    }
    *valid = false;
    if (secret == NULL || code >= UINT32_C(1000000)) {
        return -EINVAL;
    }
    if (window > JG_AUTH_TOTP_WINDOW_MAX) {
        return -ERANGE;
    }
    last = window > UINT64_MAX - counter ? UINT64_MAX : counter + window;
    format_totp_code(code, candidate);
    for (uint64_t current = first; result == 0 && current <= last; ++current) {
        result = totp_generate_counter(secret, current, &expected_code);
        if (result == 0) {
            format_totp_code(expected_code, expected);
            *valid |=
                sodium_memcmp(candidate, expected, sizeof(candidate)) == 0;
        }
        if (current == UINT64_MAX) {
            break;
        }
    }
    sodium_memzero(expected, sizeof(expected));
    return result;
}

/** @brief Encrypt one TOTP secret with a fresh XChaCha20-Poly1305 nonce. */
int jg_auth_totp_encrypt(const uint8_t key[JG_AUTH_TOTP_KEY_SIZE],
                         const uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE],
                         uint8_t nonce[JG_AUTH_TOTP_NONCE_SIZE],
                         uint8_t ciphertext[JG_AUTH_TOTP_CIPHERTEXT_SIZE])
{
    unsigned long long ciphertext_size = 0U;
    int result = 0;

    if (key == NULL || secret == NULL || nonce == NULL || ciphertext == NULL) {
        return -EINVAL;
    }
    (void)memset(nonce, 0, JG_AUTH_TOTP_NONCE_SIZE);
    (void)memset(ciphertext, 0, JG_AUTH_TOTP_CIPHERTEXT_SIZE);
    result = initialize_crypto();
    if (result != 0) {
        return result;
    }
    randombytes_buf(nonce, JG_AUTH_TOTP_NONCE_SIZE);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, &ciphertext_size, secret, JG_AUTH_TOTP_SECRET_SIZE,
            NULL, 0U, NULL, nonce, key) != 0 ||
        ciphertext_size != JG_AUTH_TOTP_CIPHERTEXT_SIZE) {
        sodium_memzero(nonce, JG_AUTH_TOTP_NONCE_SIZE);
        sodium_memzero(ciphertext, JG_AUTH_TOTP_CIPHERTEXT_SIZE);
        return -EIO;
    }
    return 0;
}

/** @brief Authenticate and decrypt one persistent TOTP secret. */
int jg_auth_totp_decrypt(const uint8_t key[JG_AUTH_TOTP_KEY_SIZE],
                         const uint8_t nonce[JG_AUTH_TOTP_NONCE_SIZE],
                         const uint8_t ciphertext[JG_AUTH_TOTP_CIPHERTEXT_SIZE],
                         uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE])
{
    unsigned long long secret_size = 0U;
    int result = 0;

    if (key == NULL || nonce == NULL || ciphertext == NULL || secret == NULL) {
        return -EINVAL;
    }
    (void)memset(secret, 0, JG_AUTH_TOTP_SECRET_SIZE);
    result = initialize_crypto();
    if (result != 0) {
        return result;
    }
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            secret, &secret_size, NULL, ciphertext,
            JG_AUTH_TOTP_CIPHERTEXT_SIZE, NULL, 0U, nonce, key) != 0) {
        sodium_memzero(secret, JG_AUTH_TOTP_SECRET_SIZE);
        return -EBADMSG;
    }
    if (secret_size != JG_AUTH_TOTP_SECRET_SIZE) {
        sodium_memzero(secret, JG_AUTH_TOTP_SECRET_SIZE);
        return -EIO;
    }
    return 0;
}
