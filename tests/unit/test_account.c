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
    static const uint8_t expected_network[4U] = {192U, 0U, 2U, 0U};
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
    struct jg_account_token_record records[2U];
    struct jg_auth_password_policy password_policy;
    struct jg_account_identity identity;
    struct jg_database *database = NULL;
    uint32_t requests_per_minute = 0U;
    uint64_t authenticated_token_id = 0U;
    uint64_t user_id = 0U;
    uint64_t total = 0U;
    size_t count = 0U;

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
    assert_int_equal(
        jg_account_token_list(database, 0U, records, 2U, &count, &total), 0);
    assert_int_equal(count, 1U);
    assert_int_equal(total, 1U);
    assert_int_equal(records[0U].token_id, token.token_id);
    assert_int_equal(records[0U].user_id, user_id);
    assert_string_equal(records[0U].username, "administrator");
    assert_string_equal(records[0U].name, "automation");
    assert_int_equal(records[0U].permissions, config.permissions);
    assert_int_equal(records[0U].source_family, JG_POLICY_ADDRESS_IPV4);
    assert_memory_equal(records[0U].source_address, expected_network,
                        sizeof(expected_network));
    assert_int_equal(records[0U].source_prefix, 24U);
    assert_int_equal(records[0U].last_used_at, 111U);
    assert_int_equal(records[0U].revoked_at, 0U);
    assert_int_equal(records[0U].revision, 1U);
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
    assert_int_equal(
        jg_account_token_list(database, 0U, records, 2U, &count, &total), 0);
    assert_int_equal(records[0U].revoked_at, 113U);
    assert_int_equal(records[0U].revision, 2U);
    assert_int_equal(jg_account_token_validate(
                         database, (const uint8_t *)token.secret,
                         strlen(token.secret), 115U, JG_POLICY_ADDRESS_IPV4,
                         remote, &identity, &authenticated_token_id,
                         &requests_per_minute),
                     -EACCES);
    jg_database_close(database);
    remove_account_database(directory, path);
}

/** @brief Verify user and role client-certificate mappings and revocation. */
static void test_mtls_mappings(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    char directory[64U];
    char path[512U];
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    struct jg_account_mtls_mapping_config config = {
        .subject = "CN=home-lab-client",
        .issuer = "CN=home-lab-ca",
        .not_before = 100U,
        .not_after = 1000U,
    };
    struct jg_account_mtls_mapping mappings[4U];
    struct jg_account_mtls_mapping created;
    struct jg_account_mtls_mapping loaded;
    struct jg_auth_password_policy password_policy;
    struct jg_database *database = NULL;
    uint8_t unknown_fingerprint[32U] = {0};
    size_t count = 0U;
    uint64_t total = 0U;
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

    config.user_id = user_id;
    config.fingerprint_sha256[0U] = 1U;
    assert_int_equal(
        jg_account_mtls_mapping_create(database, &config, 110U, &created), 0);
    assert_true(created.mapping_id > 0U);
    assert_int_equal(created.user_id, user_id);
    assert_int_equal(created.role, JG_ACCESS_ROLE_NONE);
    assert_string_equal(created.username, "administrator");
    assert_int_equal(
        jg_account_mtls_mapping_create(database, &config, 110U, &loaded),
        -EEXIST);

    config.user_id = 0U;
    config.role = JG_ACCESS_ROLE_ADMINISTRATOR;
    config.fingerprint_sha256[0U] = 2U;
    assert_int_equal(
        jg_account_mtls_mapping_create(database, &config, 111U, &loaded), 0);
    assert_int_equal(loaded.role, JG_ACCESS_ROLE_ADMINISTRATOR);
    assert_int_equal(loaded.user_id, 0U);
    assert_int_equal(jg_account_mtls_mapping_list(database, 0U, mappings, 4U,
                                                  &count, &total),
                     0);
    assert_int_equal(count, 2U);
    assert_int_equal(total, 2U);
    assert_int_equal(
        jg_account_mtls_mapping_authorize(
            database, mappings[0U].fingerprint_sha256, user_id, 120U),
        0);
    assert_int_equal(
        jg_account_mtls_mapping_authorize(
            database, mappings[1U].fingerprint_sha256, user_id, 120U),
        0);
    assert_int_equal(jg_account_mtls_mapping_authorize(
                         database, unknown_fingerprint, user_id, 120U),
                     -EACCES);

    assert_int_equal(
        jg_account_mtls_mapping_revoke(database, created.mapping_id, 121U), 0);
    assert_int_equal(
        jg_account_mtls_mapping_revoke(database, created.mapping_id, 122U), 0);
    assert_int_equal(
        jg_account_mtls_mapping_get(database, created.mapping_id, &loaded), 0);
    assert_int_equal(loaded.revoked_at, 121U);
    assert_int_equal(loaded.revision, 2U);
    assert_int_equal(jg_account_mtls_mapping_authorize(
                         database, created.fingerprint_sha256, user_id, 123U),
                     -EACCES);

    config.role = JG_ACCESS_ROLE_NONE;
    config.user_id = user_id + 100U;
    config.fingerprint_sha256[0U] = 3U;
    assert_int_equal(
        jg_account_mtls_mapping_create(database, &config, 124U, &loaded),
        -ENOENT);
    config.user_id = user_id;
    config.not_after = 123U;
    assert_int_equal(
        jg_account_mtls_mapping_create(database, &config, 124U, &loaded),
        -EACCES);

    jg_database_close(database);
    remove_account_database(directory, path);
}

/** @brief Verify transactional local-user administration and revocation. */
static void test_user_administration(void **state)
{
    static const uint8_t administrator_password[] =
        "correct horse battery staple";
    static const uint8_t operator_password[] =
        "operator password is suitably long";
    static const uint8_t replacement_password[] =
        "replacement password is suitably long";
    static const uint8_t remote[4U] = {192U, 0U, 2U, 10U};
    char directory[64U];
    char path[512U];
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    struct jg_account_user users[4U];
    struct jg_account_user administrator;
    struct jg_account_user operator_user;
    struct jg_account_user updated;
    struct jg_account_user_update update = {
        .role = JG_ACCESS_ROLE_AUDITOR,
        .enabled = true,
        .force_password_change = true,
    };
    struct jg_account_session_tokens session;
    struct jg_account_token_config token_config = {
        .name = "auditor integration",
        .permissions = JG_ACCESS_STATUS_READ,
        .requests_per_minute = 60U,
    };
    struct jg_account_api_token api_token;
    struct jg_auth_password_policy password_policy;
    struct jg_account_identity identity;
    struct jg_database *database = NULL;
    size_t count = 0U;
    uint64_t total = 0U;
    uint64_t administrator_id = 0U;
    uint64_t token_id = 0U;
    uint32_t token_rate = 0U;

    (void)state;
    make_account_database_path(directory, sizeof(directory), path,
                               sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(
        jg_account_bootstrap_issue(database, 100U, 300U, bootstrap), 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_create_initial_administrator(
                         database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator",
                         administrator_password,
                         sizeof(administrator_password) - 1U, &password_policy,
                         101U, &administrator_id),
                     0);
    assert_int_equal(
        jg_account_user_list(database, 0U, users, 4U, &count, &total), 0);
    assert_int_equal(count, 1U);
    assert_int_equal(total, 1U);
    administrator = users[0U];

    assert_int_equal(jg_account_user_create(
                         database, "operator", operator_password,
                         sizeof(operator_password) - 1U, &password_policy,
                         JG_ACCESS_ROLE_OPERATOR, false, 102U, &operator_user),
                     0);
    assert_int_equal(operator_user.role, JG_ACCESS_ROLE_OPERATOR);
    assert_true(operator_user.enabled);
    assert_false(operator_user.force_password_change);
    assert_int_equal(
        jg_account_user_create(database, "operator", operator_password,
                               sizeof(operator_password) - 1U, &password_policy,
                               JG_ACCESS_ROLE_AUDITOR, false, 103U, &updated),
        -EEXIST);
    assert_int_equal(
        jg_account_user_list(database, 0U, users, 4U, &count, &total), 0);
    assert_int_equal(count, 2U);
    assert_int_equal(total, 2U);
    assert_string_equal(users[0U].username, "administrator");
    assert_string_equal(users[1U].username, "operator");

    assert_int_equal(jg_account_authenticate(database, "operator",
                                             operator_password,
                                             sizeof(operator_password) - 1U,
                                             &password_policy, 110U, &identity),
                     0);
    assert_int_equal(jg_account_session_issue(database, &identity, 110U,
                                              JG_ACCOUNT_SESSION_LIFETIME_MIN,
                                              JG_POLICY_ADDRESS_NONE, NULL,
                                              &session),
                     0);
    update.enabled = false;
    update.role = JG_ACCESS_ROLE_OPERATOR;
    update.force_password_change = false;
    assert_int_equal(jg_account_user_update(database, administrator.user_id,
                                            administrator.revision, &update,
                                            111U, &updated),
                     -EPERM);

    update.enabled = true;
    update.role = JG_ACCESS_ROLE_AUDITOR;
    update.force_password_change = true;
    assert_int_equal(jg_account_user_update(database, operator_user.user_id,
                                            operator_user.revision, &update,
                                            112U, &updated),
                     0);
    assert_int_equal(updated.role, JG_ACCESS_ROLE_AUDITOR);
    assert_true(updated.force_password_change);
    assert_int_equal(updated.revision, operator_user.revision + 1U);
    assert_int_equal(
        jg_account_session_validate(database, (const uint8_t *)session.session,
                                    strlen(session.session), NULL, 0U, false,
                                    113U, JG_ACCOUNT_SESSION_INACTIVITY_MIN,
                                    JG_POLICY_ADDRESS_NONE, NULL, &identity),
        -EACCES);
    assert_int_equal(jg_account_user_update(database, operator_user.user_id,
                                            operator_user.revision, &update,
                                            113U, &operator_user),
                     -ESTALE);

    assert_int_equal(jg_account_token_issue(database, updated.user_id,
                                            &token_config, 114U, &api_token),
                     0);
    assert_int_equal(jg_account_user_reset_password(
                         database, updated.user_id, updated.revision,
                         replacement_password,
                         sizeof(replacement_password) - 1U, &password_policy,
                         false, 115U, &operator_user),
                     0);
    assert_false(operator_user.force_password_change);
    assert_int_equal(operator_user.revision, updated.revision + 1U);
    assert_int_equal(jg_account_token_validate(
                         database, (const uint8_t *)api_token.secret,
                         strlen(api_token.secret), 116U, JG_POLICY_ADDRESS_IPV4,
                         remote, &identity, &token_id, &token_rate),
                     -EACCES);
    assert_int_equal(jg_account_authenticate(database, "operator",
                                             operator_password,
                                             sizeof(operator_password) - 1U,
                                             &password_policy, 116U, &identity),
                     -EACCES);
    assert_int_equal(jg_account_authenticate(database, "operator",
                                             replacement_password,
                                             sizeof(replacement_password) - 1U,
                                             &password_policy, 117U, &identity),
                     0);
    assert_int_equal(identity.permissions,
                     jg_access_role_permissions(JG_ACCESS_ROLE_AUDITOR));

    jg_database_close(database);
    remove_account_database(directory, path);
}

/** @brief Verify encrypted TOTP enrollment and one-time recovery login. */
static void test_multifactor_authentication(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    char directory[64U];
    char path[512U];
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    uint8_t key[JG_AUTH_TOTP_KEY_SIZE] = {0};
    uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE];
    struct jg_account_totp_provisioning provisioning;
    struct jg_account_recovery_codes recovery_codes;
    struct jg_account_session_tokens session;
    struct jg_auth_password_policy password_policy;
    struct jg_account_identity password_identity;
    struct jg_account_identity mfa_identity;
    struct jg_account_user users[1U];
    struct jg_account_user updated;
    struct jg_database *database = NULL;
    size_t count = 0U;
    uint64_t total = 0U;
    uint64_t user_id = 0U;
    uint32_t code = 0U;

    (void)state;
    key[0U] = 1U;
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
        jg_account_totp_provision(database, user_id, key, 110U, &provisioning),
        0);
    assert_int_equal(jg_auth_totp_secret_decode(provisioning.secret, secret),
                     0);
    assert_int_equal(jg_auth_totp_generate(secret, 120U, &code), 0);
    assert_int_equal(jg_account_totp_confirm(database, user_id, key, code, 120U,
                                             &recovery_codes),
                     0);
    assert_int_equal(strlen(recovery_codes.codes[0U]),
                     JG_AUTH_SECRET_TEXT_SIZE - 1U);

    assert_int_equal(jg_account_authenticate(database, "administrator",
                                             password, sizeof(password) - 1U,
                                             &password_policy, 121U,
                                             &password_identity),
                     0);
    assert_true(password_identity.totp_enabled);
    assert_false(password_identity.mfa_complete);
    assert_int_equal(
        jg_account_session_issue(database, &password_identity, 121U,
                                 JG_ACCOUNT_SESSION_LIFETIME_MIN,
                                 JG_POLICY_ADDRESS_NONE, NULL, &session),
        -EACCES);
    assert_int_equal(jg_account_totp_authenticate(database, &password_identity,
                                                  key, (code + 1U) % 1000000U,
                                                  121U, &mfa_identity),
                     -EACCES);
    assert_int_equal(jg_account_totp_authenticate(database, &password_identity,
                                                  key, code, 121U,
                                                  &mfa_identity),
                     0);
    assert_true(mfa_identity.mfa_complete);
    assert_int_equal(jg_account_session_issue(database, &mfa_identity, 121U,
                                              JG_ACCOUNT_SESSION_LIFETIME_MIN,
                                              JG_POLICY_ADDRESS_NONE, NULL,
                                              &session),
                     0);

    assert_int_equal(jg_account_recovery_authenticate(
                         database, &password_identity,
                         (const uint8_t *)recovery_codes.codes[0U],
                         strlen(recovery_codes.codes[0U]), 122U, &mfa_identity),
                     0);
    assert_true(mfa_identity.mfa_complete);
    assert_int_equal(jg_account_recovery_authenticate(
                         database, &password_identity,
                         (const uint8_t *)recovery_codes.codes[0U],
                         strlen(recovery_codes.codes[0U]), 123U, &mfa_identity),
                     -EACCES);
    assert_int_equal(
        jg_account_user_list(database, 0U, users, 1U, &count, &total), 0);
    assert_int_equal(count, 1U);
    assert_int_equal(total, 1U);
    assert_int_equal(jg_account_user_disable_totp(
                         database, user_id, users[0U].revision + 1U, &updated),
                     -ESTALE);
    assert_int_equal(jg_account_totp_disable(database, user_id), 0);
    assert_int_equal(jg_account_authenticate(database, "administrator",
                                             password, sizeof(password) - 1U,
                                             &password_policy, 124U,
                                             &password_identity),
                     0);
    assert_false(password_identity.totp_enabled);
    assert_true(password_identity.mfa_complete);

    assert_int_equal(
        jg_account_totp_provision(database, user_id, key, 130U, &provisioning),
        0);
    assert_int_equal(jg_auth_totp_secret_decode(provisioning.secret, secret),
                     0);
    assert_int_equal(jg_auth_totp_generate(secret, 150U, &code), 0);
    assert_int_equal(jg_account_totp_confirm(database, user_id, key, code, 150U,
                                             &recovery_codes),
                     0);
    assert_int_equal(
        jg_account_user_list(database, 0U, users, 1U, &count, &total), 0);
    assert_true(users[0U].totp_enabled);
    assert_int_equal(
        jg_account_user_disable_totp(database, user_id, 0U, &updated), -EINVAL);
    assert_int_equal(jg_account_user_disable_totp(database, user_id,
                                                  users[0U].revision, &updated),
                     0);
    assert_false(updated.totp_enabled);
    assert_int_equal(updated.revision, users[0U].revision + 1U);
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
        cmocka_unit_test(test_mtls_mappings),
        cmocka_unit_test(test_user_administration),
        cmocka_unit_test(test_multifactor_authentication),
    };

    return cmocka_run_group_tests_name("account", tests, NULL, NULL);
}
