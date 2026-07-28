/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <sqlite3.h>

#include "janusgate/account.h"

int jg_test_account(void);

/** @brief Create one private temporary account database path. */
static void make_account_database_path(char *directory,
                                       size_t directory_size,
                                       char *path,
                                       size_t path_size)
{
    const char template[] = "/tmp/janusgate-account-XXXXXX";
    int written = 0;

    assert_true(directory_size >= sizeof(template));
    (void)snprintf(directory, directory_size, "%s", template);
    assert_non_null(mkdtemp(directory));
    written = snprintf(path, path_size, "%s/janusgate.db", directory);
    assert_true(written > 0);
    assert_true((size_t)written < path_size);
}

/** @brief Remove one account test database and its SQLite side files. */
static void remove_account_database(const char *directory, const char *path)
{
    char auxiliary[512U];
    int written = snprintf(auxiliary, sizeof(auxiliary), "%s-wal", path);

    if (written > 0 && (size_t)written < sizeof(auxiliary)) {
        (void)unlink(auxiliary);
    }
    written = snprintf(auxiliary, sizeof(auxiliary), "%s-shm", path);
    if (written > 0 && (size_t)written < sizeof(auxiliary)) {
        (void)unlink(auxiliary);
    }
    (void)unlink(path);
    (void)rmdir(directory);
}

/** @brief Verify one-time bootstrap and atomic administrator creation. */
static void test_initial_administrator(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    char directory[64U];
    char path[512U];
    char token[JG_AUTH_SECRET_TEXT_SIZE];
    char incorrect[JG_AUTH_SECRET_TEXT_SIZE];
    struct jg_auth_password_policy password_policy;
    struct jg_database *database = NULL;
    sqlite3_stmt *statement = NULL;
    sqlite3 *inspection = NULL;
    uint64_t user_id = 0U;

    (void)state;
    make_account_database_path(directory, sizeof(directory), path,
                               sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_account_bootstrap_issue(database, 100U, 300U, token),
                     0);
    assert_int_equal(strlen(token), JG_AUTH_SECRET_TEXT_SIZE - 1U);
    (void)memcpy(incorrect, token, sizeof(incorrect));
    incorrect[0U] = incorrect[0U] == 'A' ? 'B' : 'A';
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_create_initial_administrator(
                         database, (const uint8_t *)incorrect,
                         strlen(incorrect), "administrator", password,
                         sizeof(password) - 1U, &password_policy, 101U,
                         &user_id),
                     -EACCES);
    assert_int_equal(user_id, 0U);
    assert_int_equal(jg_account_create_initial_administrator(
                         database, (const uint8_t *)token, strlen(token),
                         "administrator", password, sizeof(password) - 1U,
                         &password_policy, 101U, &user_id),
                     0);
    assert_true(user_id > 0U);
    assert_int_equal(jg_account_bootstrap_issue(database, 102U, 300U, token),
                     -EEXIST);
    jg_database_close(database);

    assert_int_equal(
        sqlite3_open_v2(path, &inspection, SQLITE_OPEN_READONLY, NULL),
        SQLITE_OK);
    assert_int_equal(
        sqlite3_prepare_v2(
            inspection,
            "SELECT u.username,u.password_hash,r.name,b.consumed_at"
            " FROM users u"
            " JOIN user_roles ur ON ur.user_id=u.id"
            " JOIN roles r ON r.id=ur.role_id"
            " JOIN bootstrap_credentials b ON b.id=1;",
            -1, &statement, NULL),
        SQLITE_OK);
    assert_int_equal(sqlite3_step(statement), SQLITE_ROW);
    assert_string_equal((const char *)sqlite3_column_text(statement, 0),
                        "administrator");
    assert_string_not_equal((const char *)sqlite3_column_text(statement, 1),
                            (const char *)password);
    assert_string_equal((const char *)sqlite3_column_text(statement, 2),
                        "administrator");
    assert_int_equal(sqlite3_column_int64(statement, 3), 101);
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
    assert_int_equal(sqlite3_close(inspection), SQLITE_OK);
    remove_account_database(directory, path);
}

/** @brief Verify expiration and validation of bootstrap credentials. */
static void test_bootstrap_expiration(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    char directory[64U];
    char path[512U];
    char token[JG_AUTH_SECRET_TEXT_SIZE];
    struct jg_auth_password_policy password_policy;
    struct jg_database *database = NULL;
    uint64_t user_id = 0U;

    (void)state;
    make_account_database_path(directory, sizeof(directory), path,
                               sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(
        jg_account_bootstrap_issue(
            database, 100U, JG_ACCOUNT_BOOTSTRAP_LIFETIME_MIN - 1U, token),
        -EINVAL);
    assert_int_equal(
        jg_account_bootstrap_issue(database, 100U,
                                   JG_ACCOUNT_BOOTSTRAP_LIFETIME_MIN, token),
        0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_create_initial_administrator(
                         database, (const uint8_t *)token, strlen(token),
                         "administrator", password, sizeof(password) - 1U,
                         &password_policy,
                         100U + JG_ACCOUNT_BOOTSTRAP_LIFETIME_MIN, &user_id),
                     -EACCES);
    assert_int_equal(user_id, 0U);
    jg_database_close(database);
    remove_account_database(directory, path);
}

/** @brief Verify login state, role loading, and exponential account locks. */
static void test_password_authentication(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    static const uint8_t incorrect[] = "incorrect horse battery staple";
    char directory[64U];
    char path[512U];
    char token[JG_AUTH_SECRET_TEXT_SIZE];
    struct jg_auth_password_policy password_policy;
    struct jg_account_identity identity;
    struct jg_database *database = NULL;
    sqlite3_stmt *statement = NULL;
    sqlite3 *inspection = NULL;
    uint64_t user_id = 0U;

    (void)state;
    make_account_database_path(directory, sizeof(directory), path,
                               sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_account_bootstrap_issue(database, 100U, 300U, token),
                     0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_create_initial_administrator(
                         database, (const uint8_t *)token, strlen(token),
                         "administrator", password, sizeof(password) - 1U,
                         &password_policy, 101U, &user_id),
                     0);
    assert_int_equal(jg_account_authenticate(database, "administrator",
                                             incorrect, sizeof(incorrect) - 1U,
                                             &password_policy, 110U, &identity),
                     -EACCES);
    assert_int_equal(jg_account_authenticate(database, "administrator",
                                             password, sizeof(password) - 1U,
                                             &password_policy, 110U, &identity),
                     -EAGAIN);
    assert_int_equal(jg_account_authenticate(database, "administrator",
                                             password, sizeof(password) - 1U,
                                             &password_policy, 111U, &identity),
                     0);
    assert_int_equal(identity.user_id, user_id);
    assert_string_equal(identity.username, "administrator");
    assert_int_equal(identity.permissions, JG_ACCESS_PERMISSION_ALL);
    assert_false(identity.force_password_change);
    assert_false(identity.totp_enabled);
    assert_int_equal(jg_account_authenticate(database, "missing", password,
                                             sizeof(password) - 1U,
                                             &password_policy, 112U, &identity),
                     -EACCES);
    jg_database_close(database);

    assert_int_equal(
        sqlite3_open_v2(path, &inspection, SQLITE_OPEN_READONLY, NULL),
        SQLITE_OK);
    assert_int_equal(
        sqlite3_prepare_v2(inspection,
                           "SELECT failed_logins,locked_until,last_login_at"
                           " FROM users WHERE id=?1;",
                           -1, &statement, NULL),
        SQLITE_OK);
    assert_int_equal(sqlite3_bind_int64(statement, 1, (sqlite3_int64)user_id),
                     SQLITE_OK);
    assert_int_equal(sqlite3_step(statement), SQLITE_ROW);
    assert_int_equal(sqlite3_column_int(statement, 0), 0);
    assert_int_equal(sqlite3_column_type(statement, 1), SQLITE_NULL);
    assert_int_equal(sqlite3_column_int64(statement, 2), 111);
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
    assert_int_equal(sqlite3_close(inspection), SQLITE_OK);
    remove_account_database(directory, path);
}

/** @brief Verify CSRF, idle expiry, address binding, and global revocation. */
static void test_web_sessions(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    static const uint8_t remote[4U] = {192U, 0U, 2U, 10U};
    static const uint8_t other_remote[4U] = {192U, 0U, 2U, 11U};
    char directory[64U];
    char path[512U];
    char token[JG_AUTH_SECRET_TEXT_SIZE];
    struct jg_account_session_tokens session;
    struct jg_auth_password_policy password_policy;
    struct jg_account_identity identity;
    struct jg_account_identity validated;
    struct jg_database *database = NULL;
    uint64_t user_id = 0U;

    (void)state;
    make_account_database_path(directory, sizeof(directory), path,
                               sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_account_bootstrap_issue(database, 100U, 300U, token),
                     0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_create_initial_administrator(
                         database, (const uint8_t *)token, strlen(token),
                         "administrator", password, sizeof(password) - 1U,
                         &password_policy, 101U, &user_id),
                     0);
    assert_int_equal(jg_account_authenticate(database, "administrator",
                                             password, sizeof(password) - 1U,
                                             &password_policy, 110U, &identity),
                     0);
    assert_int_equal(jg_account_session_issue(database, &identity, 110U,
                                              JG_ACCOUNT_SESSION_LIFETIME_MIN,
                                              JG_POLICY_ADDRESS_IPV4, remote,
                                              &session),
                     0);
    assert_int_equal(strlen(session.session), JG_AUTH_SECRET_TEXT_SIZE - 1U);
    assert_int_equal(strlen(session.csrf), JG_AUTH_SECRET_TEXT_SIZE - 1U);
    assert_int_equal(jg_account_session_validate(
                         database, (const uint8_t *)session.session,
                         strlen(session.session), (const uint8_t *)session.csrf,
                         strlen(session.csrf), true, 111U,
                         JG_ACCOUNT_SESSION_INACTIVITY_MIN,
                         JG_POLICY_ADDRESS_IPV4, remote, &validated),
                     0);
    assert_int_equal(validated.user_id, identity.user_id);
    session.csrf[0U] = session.csrf[0U] == 'A' ? 'B' : 'A';
    assert_int_equal(jg_account_session_validate(
                         database, (const uint8_t *)session.session,
                         strlen(session.session), (const uint8_t *)session.csrf,
                         strlen(session.csrf), true, 112U,
                         JG_ACCOUNT_SESSION_INACTIVITY_MIN,
                         JG_POLICY_ADDRESS_IPV4, remote, &validated),
                     -EACCES);
    assert_int_equal(jg_account_session_validate(
                         database, (const uint8_t *)session.session,
                         strlen(session.session), NULL, 0U, false, 112U,
                         JG_ACCOUNT_SESSION_INACTIVITY_MIN,
                         JG_POLICY_ADDRESS_IPV4, other_remote, &validated),
                     -EACCES);
    assert_int_equal(jg_account_session_validate(
                         database, (const uint8_t *)session.session,
                         strlen(session.session), NULL, 0U, false,
                         110U + JG_ACCOUNT_SESSION_INACTIVITY_MIN + 1U,
                         JG_ACCOUNT_SESSION_INACTIVITY_MIN,
                         JG_POLICY_ADDRESS_IPV4, remote, &validated),
                     -EACCES);
    assert_int_equal(jg_account_sessions_revoke_all(database, user_id), 0);
    assert_int_equal(
        jg_account_session_validate(database, (const uint8_t *)session.session,
                                    strlen(session.session), NULL, 0U, false,
                                    113U, JG_ACCOUNT_SESSION_INACTIVITY_MIN,
                                    JG_POLICY_ADDRESS_IPV4, remote, &validated),
        -EACCES);
    assert_int_equal(jg_account_session_revoke(database,
                                               (const uint8_t *)session.session,
                                               strlen(session.session)),
                     0);
    assert_int_equal(jg_account_session_revoke(database,
                                               (const uint8_t *)session.session,
                                               strlen(session.session)),
                     0);
    jg_database_close(database);
    remove_account_database(directory, path);
}

/** @brief Verify API-token scopes, source policy, use tracking, and revocation.
 */
static void test_api_tokens(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    static const uint8_t remote[4U] = {192U, 0U, 2U, 10U};
    static const uint8_t other_remote[4U] = {198U, 51U, 100U, 10U};
    char directory[64U];
    char path[512U];
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    struct jg_account_token_config config = {
        .name = "automation",
        .permissions = JG_ACCESS_STATUS_READ | JG_ACCESS_POLICY_READ,
        .source_family = JG_POLICY_ADDRESS_IPV4,
        .source_address = {192U, 0U, 2U, 99U},
        .source_prefix = 24U,
        .requests_per_minute = 120U,
    };
    struct jg_account_api_token token;
    struct jg_auth_password_policy password_policy;
    struct jg_account_identity identity;
    struct jg_database *database = NULL;
    uint32_t requests_per_minute = 0U;
    uint64_t authenticated_token_id = 0U;
    uint64_t user_id = 0U;

    (void)state;
    make_account_database_path(directory, sizeof(directory), path,
                               sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(
        jg_account_bootstrap_issue(database, 100U, 300U, bootstrap), 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_create_initial_administrator(
                         database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator", password,
                         sizeof(password) - 1U, &password_policy, 101U,
                         &user_id),
                     0);
    assert_int_equal(
        jg_account_token_issue(database, user_id, &config, 110U, &token), 0);
    assert_true(token.token_id > 0U);
    assert_int_equal(strlen(token.secret), JG_AUTH_SECRET_TEXT_SIZE - 1U);
    assert_int_equal(jg_account_token_validate(
                         database, (const uint8_t *)token.secret,
                         strlen(token.secret), 111U, JG_POLICY_ADDRESS_IPV4,
                         remote, &identity, &authenticated_token_id,
                         &requests_per_minute),
                     0);
    assert_int_equal(authenticated_token_id, token.token_id);
    assert_int_equal(requests_per_minute, 120U);
    assert_int_equal(identity.permissions, config.permissions);
    assert_int_equal(jg_account_token_validate(
                         database, (const uint8_t *)token.secret,
                         strlen(token.secret), 112U, JG_POLICY_ADDRESS_IPV4,
                         other_remote, &identity, &authenticated_token_id,
                         &requests_per_minute),
                     -EACCES);
    assert_int_equal(jg_account_token_revoke(database, token.token_id, 113U),
                     0);
    assert_int_equal(jg_account_token_revoke(database, token.token_id, 114U),
                     0);
    assert_int_equal(jg_account_token_validate(
                         database, (const uint8_t *)token.secret,
                         strlen(token.secret), 115U, JG_POLICY_ADDRESS_IPV4,
                         remote, &identity, &authenticated_token_id,
                         &requests_per_minute),
                     -EACCES);
    jg_database_close(database);
    remove_account_database(directory, path);
}

/** @brief Run the first-boot account unit-test group. */
int jg_test_account(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_initial_administrator),
        cmocka_unit_test(test_bootstrap_expiration),
        cmocka_unit_test(test_password_authentication),
        cmocka_unit_test(test_web_sessions),
        cmocka_unit_test(test_api_tokens),
    };

    return cmocka_run_group_tests_name("account", tests, NULL, NULL);
}
