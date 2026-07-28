/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmocka.h>
#include <sqlite3.h>

#include "janusgate/database.h"

int jg_test_database(void);

/** @brief Create one private temporary directory and database path. */
static void make_database_path(char *directory,
                               size_t directory_size,
                               char *path,
                               size_t path_size)
{
    const char template[] = "/tmp/janusgate-db-XXXXXX";
    int written = 0;

    assert_true(directory_size >= sizeof(template));
    (void)snprintf(directory, directory_size, "%s", template);
    assert_non_null(mkdtemp(directory));
    written = snprintf(path, path_size, "%s/janusgate.db", directory);
    assert_true(written > 0);
    assert_true((size_t)written < path_size);
}

/** @brief Remove SQLite files and their private temporary directory. */
static void remove_database(const char *directory, const char *path)
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
    written = snprintf(auxiliary, sizeof(auxiliary), "%s.lkg", path);
    if (written > 0 && (size_t)written < sizeof(auxiliary)) {
        (void)unlink(auxiliary);
    }
    (void)unlink(path);
    (void)rmdir(directory);
}

/** @brief Check that one named table exists in a SQLite schema. */
static bool table_exists(sqlite3 *handle, const char *name)
{
    static const char query[] =
        "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1;";
    sqlite3_stmt *statement = NULL;
    bool exists = false;

    assert_int_equal(sqlite3_prepare_v2(handle, query, -1, &statement, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_bind_text(statement, 1, name, -1, SQLITE_STATIC),
                     SQLITE_OK);
    exists = sqlite3_step(statement) == SQLITE_ROW;
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
    return exists;
}

/** @brief Set user_version through a prepared SQLite statement. */
static void set_schema_version(sqlite3 *handle, uint32_t version)
{
    sqlite3_stmt *statement = NULL;
    const char *sql = version == 2U ? "PRAGMA user_version=2;" : NULL;

    assert_non_null(sql);
    assert_int_equal(sqlite3_prepare_v2(handle, sql, -1, &statement, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_step(statement), SQLITE_DONE);
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
}

/** @brief Construct a valid global rule for database round-trip tests. */
static struct jg_policy_rule_input make_rule(uint64_t id,
                                             const char *domain,
                                             bool include_subdomains,
                                             enum jg_policy_effect effect,
                                             enum jg_policy_source source)
{
    struct jg_policy_rule_input rule;

    (void)memset(&rule, 0, sizeof(rule));
    rule.id = id;
    rule.domain = domain;
    rule.include_subdomains = include_subdomains;
    rule.effect = effect;
    rule.source = source;
    rule.scope.type = JG_POLICY_SCOPE_GLOBAL;
    rule.attribution = "database test";
    return rule;
}

/** @brief Verify initial migration, permissions, schema, and reopening. */
static void test_initial_migration(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_database *database = NULL;
    struct stat metadata;
    sqlite3 *inspection = NULL;
    uint32_t version = 0U;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_non_null(database);
    assert_int_equal(jg_database_schema_version(database, &version), 0);
    assert_int_equal(version, JG_DATABASE_SCHEMA_VERSION);
    assert_int_equal(jg_database_check_integrity(database), 0);
    assert_int_equal(stat(path, &metadata), 0);
    assert_int_equal(metadata.st_mode & 0777U, S_IRUSR | S_IWUSR);
    jg_database_close(database);

    assert_int_equal(
        sqlite3_open_v2(path, &inspection, SQLITE_OPEN_READONLY, NULL),
        SQLITE_OK);
    assert_true(table_exists(inspection, "schema_migrations"));
    assert_true(table_exists(inspection, "domain_rules"));
    assert_true(table_exists(inspection, "blocklist_sources"));
    assert_true(table_exists(inspection, "users"));
    assert_true(table_exists(inspection, "audit_events"));
    assert_true(table_exists(inspection, "certificate_metadata"));
    assert_int_equal(sqlite3_close(inspection), SQLITE_OK);

    database = NULL;
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify rejection of a database created by a newer release. */
static void test_newer_schema_rejected(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_database *database = NULL;
    sqlite3 *handle = NULL;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    jg_database_close(database);

    assert_int_equal(
        sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE, NULL), SQLITE_OK);
    set_schema_version(handle, 2U);
    assert_int_equal(sqlite3_close(handle), SQLITE_OK);

    database = NULL;
    assert_int_equal(jg_database_open(path, 1000U, &database), -ENOTSUP);
    assert_null(database);
    remove_database(directory, path);
}

/** @brief Verify rejection of writable parents and exposed database files. */
static void test_insecure_permissions_rejected(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_database *database = NULL;
    int descriptor = -1;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(chmod(directory, 0770U), 0);
    assert_int_equal(jg_database_open(path, 1000U, &database), -EACCES);
    assert_null(database);
    assert_int_equal(chmod(directory, 0700U), 0);

    descriptor = open(path, O_RDWR | O_CREAT | O_EXCL, 0644U);
    assert_true(descriptor >= 0);
    assert_int_equal(close(descriptor), 0);
    assert_int_equal(jg_database_open(path, 1000U, &database), -EACCES);
    assert_null(database);
    remove_database(directory, path);
}

/** @brief Verify atomic policy replacement and immutable snapshot loading. */
static void test_policy_round_trip(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_policy_rule_input rules[3U];
    struct jg_policy_rule_input invalid;
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_policy_snapshot_info info;
    struct jg_policy_client client;
    struct jg_policy_match match;
    struct jg_database *database = NULL;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);

    rules[0] = make_rule(10U, "Example.ORG.", true, JG_POLICY_BLOCK,
                         JG_POLICY_SOURCE_BLOCKLIST);
    rules[1] = make_rule(5U, "safe.example.org", true, JG_POLICY_ALLOW,
                         JG_POLICY_SOURCE_EXPLICIT);
    rules[2] = make_rule(3U, "blocked.example.org", false, JG_POLICY_ALLOW,
                         JG_POLICY_SOURCE_EXPLICIT);
    rules[2].scope.type = JG_POLICY_SCOPE_VLAN;
    rules[2].scope.value.vlan_id = 7U;
    assert_int_equal(jg_database_replace_domain_rules(database, rules, 3U), 0);
    assert_int_equal(jg_database_load_policy_snapshot(database, 9U, &snapshot),
                     0);
    assert_int_equal(jg_policy_snapshot_get_info(snapshot, &info), 0);
    assert_int_equal(info.generation, 9U);
    assert_int_equal(info.rule_count, 3U);

    assert_int_equal(
        jg_policy_match_domain(snapshot, "host.example.org", NULL, &match), 0);
    assert_int_equal(match.effect, JG_POLICY_BLOCK);
    assert_int_equal(match.rule_id, 10U);
    assert_int_equal(
        jg_policy_match_domain(snapshot, "www.safe.example.org", NULL, &match),
        0);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    assert_int_equal(match.rule_id, 5U);

    (void)memset(&client, 0, sizeof(client));
    client.has_vlan = true;
    client.vlan_id = 7U;
    assert_int_equal(jg_policy_match_domain(snapshot, "blocked.example.org",
                                            &client, &match),
                     0);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    assert_int_equal(match.rule_id, 3U);
    jg_policy_snapshot_destroy(snapshot);

    invalid = make_rule(1U, "invalid.example", false, JG_POLICY_ALLOW,
                        JG_POLICY_SOURCE_BLOCKLIST);
    assert_true(jg_database_replace_domain_rules(database, &invalid, 1U) < 0);
    snapshot = NULL;
    assert_int_equal(jg_database_load_policy_snapshot(database, 10U, &snapshot),
                     0);
    assert_int_equal(
        jg_policy_match_domain(snapshot, "host.example.org", NULL, &match), 0);
    assert_int_equal(match.rule_id, 10U);

    jg_policy_snapshot_destroy(snapshot);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Run the SQLite lifecycle and migration test group. */
int jg_test_database(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_initial_migration),
        cmocka_unit_test(test_newer_schema_rejected),
        cmocka_unit_test(test_insecure_permissions_rejected),
        cmocka_unit_test(test_policy_round_trip),
    };

    return cmocka_run_group_tests_name("database", tests, NULL, NULL);
}
