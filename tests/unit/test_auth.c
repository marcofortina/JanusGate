/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "janusgate/auth.h"

int jg_test_auth(void);

/** @brief Verify password hashing, rejection, and cost upgrades. */
static void test_password_hashing(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    static const uint8_t incorrect[] = "incorrect horse battery staple";
    struct jg_auth_password_policy policy;
    struct jg_auth_password_policy upgraded;
    char encoded[JG_AUTH_PASSWORD_HASH_SIZE];
    bool valid = false;
    bool needs_rehash = false;

    (void)state;
    jg_auth_password_policy_default(&policy);
    assert_int_equal(jg_auth_password_hash(&policy, password,
                                           sizeof(password) - 1U, encoded),
                     0);
    assert_string_not_equal(encoded, (const char *)password);
    assert_int_equal(jg_auth_password_verify(&policy, password,
                                             sizeof(password) - 1U, encoded,
                                             &valid, &needs_rehash),
                     0);
    assert_true(valid);
    assert_false(needs_rehash);

    assert_int_equal(jg_auth_password_verify(&policy, incorrect,
                                             sizeof(incorrect) - 1U, encoded,
                                             &valid, &needs_rehash),
                     0);
    assert_false(valid);
    assert_false(needs_rehash);

    upgraded = policy;
    ++upgraded.operations;
    assert_int_equal(jg_auth_password_verify(&upgraded, password,
                                             sizeof(password) - 1U, encoded,
                                             &valid, &needs_rehash),
                     0);
    assert_true(valid);
    assert_true(needs_rehash);
}

/** @brief Verify strict password-policy and input bounds. */
static void test_password_validation(void **state)
{
    static const uint8_t short_password[] = "too short";
    struct jg_auth_password_policy policy;
    char encoded[JG_AUTH_PASSWORD_HASH_SIZE];
    char invalid[JG_AUTH_PASSWORD_HASH_SIZE] = "invalid";
    bool valid = false;
    bool needs_rehash = false;

    (void)state;
    jg_auth_password_policy_default(&policy);
    assert_int_equal(jg_auth_password_hash(&policy, short_password,
                                           sizeof(short_password) - 1U,
                                           encoded),
                     -ERANGE);
    policy.memory = JG_AUTH_MEMORY_MIN - 1U;
    assert_int_equal(jg_auth_password_hash(&policy, short_password,
                                           sizeof(short_password) - 1U,
                                           encoded),
                     -EINVAL);
    jg_auth_password_policy_default(&policy);
    assert_int_equal(jg_auth_password_verify(&policy, short_password,
                                             sizeof(short_password) - 1U,
                                             invalid, &valid, &needs_rehash),
                     -EINVAL);
}

/** @brief Verify opaque-secret uniqueness and deterministic digesting. */
static void test_opaque_secrets(void **state)
{
    char first[JG_AUTH_SECRET_TEXT_SIZE];
    char second[JG_AUTH_SECRET_TEXT_SIZE];
    uint8_t first_digest[JG_AUTH_SECRET_DIGEST_SIZE];
    uint8_t repeated_digest[JG_AUTH_SECRET_DIGEST_SIZE];
    uint8_t second_digest[JG_AUTH_SECRET_DIGEST_SIZE];

    (void)state;
    assert_int_equal(jg_auth_secret_issue(first, first_digest), 0);
    assert_int_equal(jg_auth_secret_issue(second, second_digest), 0);
    assert_int_equal(strlen(first), JG_AUTH_SECRET_TEXT_SIZE - 1U);
    assert_int_equal(strlen(second), JG_AUTH_SECRET_TEXT_SIZE - 1U);
    assert_string_not_equal(first, second);
    assert_false(jg_auth_secret_digest_equal(first_digest, second_digest));

    assert_int_equal(jg_auth_secret_digest((const uint8_t *)first,
                                           strlen(first), repeated_digest),
                     0);
    assert_true(jg_auth_secret_digest_equal(first_digest, repeated_digest));
    assert_false(jg_auth_secret_digest_equal(NULL, repeated_digest));
}

/** @brief Verify canonical TOTP provisioning and RFC-compatible codes. */
static void test_totp(void **state)
{
    static const uint8_t vector[JG_AUTH_TOTP_SECRET_SIZE] =
        "12345678901234567890123456789012";
    uint8_t issued[JG_AUTH_TOTP_SECRET_SIZE];
    uint8_t decoded[JG_AUTH_TOTP_SECRET_SIZE];
    char encoded[JG_AUTH_TOTP_SECRET_TEXT_SIZE];
    uint32_t code = 0U;
    bool valid = false;

    (void)state;
    assert_int_equal(jg_auth_totp_secret_issue(issued, encoded), 0);
    assert_int_equal(strlen(encoded), JG_AUTH_TOTP_SECRET_TEXT_SIZE - 1U);
    assert_int_equal(jg_auth_totp_secret_decode(encoded, decoded), 0);
    assert_memory_equal(decoded, issued, sizeof(decoded));

    assert_int_equal(jg_auth_totp_generate(vector, 59U, &code), 0);
    assert_int_equal(code, 119246U);
    assert_int_equal(jg_auth_totp_verify(vector, 59U, code, 0U, &valid), 0);
    assert_true(valid);
    assert_int_equal(jg_auth_totp_verify(vector, 89U, code, 1U, &valid), 0);
    assert_true(valid);
    assert_int_equal(jg_auth_totp_verify(vector, 90U, code, 0U, &valid), 0);
    assert_false(valid);
}

/** @brief Verify rejection of malformed TOTP inputs and unsafe windows. */
static void test_totp_validation(void **state)
{
    uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE] = {0};
    char encoded[JG_AUTH_TOTP_SECRET_TEXT_SIZE] = {0};
    bool valid = false;

    (void)state;
    (void)memset(encoded, 'A', sizeof(encoded) - 1U);
    encoded[0U] = 'a';
    assert_int_equal(jg_auth_totp_secret_decode(encoded, secret), -EINVAL);
    assert_int_equal(jg_auth_totp_verify(secret, 0U, 1000000U, 0U, &valid),
                     -EINVAL);
    assert_int_equal(jg_auth_totp_verify(secret, 0U, 0U,
                                         JG_AUTH_TOTP_WINDOW_MAX + 1U, &valid),
                     -ERANGE);
}

/** @brief Run the authentication primitive test group. */
int jg_test_auth(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_password_hashing),
        cmocka_unit_test(test_password_validation),
        cmocka_unit_test(test_opaque_secrets),
        cmocka_unit_test(test_totp),
        cmocka_unit_test(test_totp_validation),
    };

    return cmocka_run_group_tests_name("auth", tests, NULL, NULL);
}
