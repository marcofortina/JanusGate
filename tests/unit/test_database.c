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
#include <inttypes.h>
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

/** @brief Check that one named column exists in a SQLite table. */
static bool column_exists(sqlite3 *handle,
                          const char *table,
                          const char *column)
{
    static const char query[] =
        "SELECT 1 FROM pragma_table_info(?1) WHERE name=?2;";
    sqlite3_stmt *statement = NULL;
    bool exists = false;

    assert_int_equal(sqlite3_prepare_v2(handle, query, -1, &statement, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_bind_text(statement, 1, table, -1, SQLITE_STATIC),
                     SQLITE_OK);
    assert_int_equal(sqlite3_bind_text(statement, 2, column, -1, SQLITE_STATIC),
                     SQLITE_OK);
    exists = sqlite3_step(statement) == SQLITE_ROW;
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
    return exists;
}

/** @brief Set user_version through a prepared SQLite statement. */
static void set_schema_version(sqlite3 *handle, uint32_t version)
{
    char sql[64U];
    sqlite3_stmt *statement = NULL;
    int written = 0;

    written =
        snprintf(sql, sizeof(sql), "PRAGMA user_version=%" PRIu32 ";", version);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(sql));
    assert_int_equal(sqlite3_prepare_v2(handle, sql, -1, &statement, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_step(statement), SQLITE_DONE);
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
}

/** @brief Add retained policy tables predating current migrations. */
static void add_legacy_policy_rules(sqlite3 *handle)
{
    static const char schema[] =
        "CREATE TABLE policy_groups(id INTEGER PRIMARY KEY) STRICT;"
        "CREATE TABLE domain_rules ("
        "id INTEGER PRIMARY KEY,group_id INTEGER,blocklist_source_id INTEGER,"
        "domain TEXT NOT NULL,match_type TEXT NOT NULL,effect TEXT NOT NULL,"
        "source TEXT NOT NULL,scope_type TEXT NOT NULL,scope_value BLOB,"
        "prefix_length INTEGER,vlan_id INTEGER,attribution TEXT NOT NULL,"
        "enabled INTEGER NOT NULL,updated_at INTEGER NOT NULL) STRICT;"
        "INSERT INTO domain_rules("
        "id,domain,match_type,effect,source,scope_type,attribution,enabled,"
        "updated_at) VALUES("
        "1,'legacy.example','exact','block','explicit','global','legacy',1,10"
        ");"
        "CREATE TABLE destination_rules ("
        "id INTEGER PRIMARY KEY,group_id INTEGER,effect TEXT NOT NULL,"
        "protocol TEXT NOT NULL,family INTEGER,address BLOB,"
        "prefix_length INTEGER,port INTEGER,attribution TEXT NOT NULL,"
        "enabled INTEGER NOT NULL) STRICT;"
        "INSERT INTO destination_rules("
        "id,effect,protocol,port,attribution,enabled"
        ") VALUES(2,'block','tcp',853,'legacy',1);";

    assert_int_equal(sqlite3_exec(handle, schema, NULL, NULL, NULL), SQLITE_OK);
}

/** @brief Add retained blocklist tables predating current migrations. */
static void add_legacy_blocklist_sources(sqlite3 *handle)
{
    static const char schema[] =
        "CREATE TABLE blocklist_sources ("
        "id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,url TEXT,"
        "format TEXT NOT NULL,strict_mode INTEGER NOT NULL DEFAULT 1,"
        "enabled INTEGER NOT NULL DEFAULT 1,update_interval INTEGER NOT NULL,"
        "max_download_bytes INTEGER NOT NULL,"
        "max_decompressed_bytes INTEGER NOT NULL,sha256_pin BLOB,"
        "ed25519_public_key BLOB,created_at INTEGER NOT NULL,"
        "updated_at INTEGER NOT NULL) STRICT;"
        "CREATE TABLE blocklist_source_status ("
        "source_id INTEGER PRIMARY KEY REFERENCES blocklist_sources(id),"
        "etag TEXT,last_modified TEXT,last_attempt_at INTEGER,"
        "last_success_at INTEGER,next_attempt_at INTEGER,"
        "consecutive_failures INTEGER NOT NULL DEFAULT 0,"
        "active_checksum BLOB,active_entries INTEGER NOT NULL DEFAULT 0,"
        "health TEXT NOT NULL DEFAULT 'unknown',last_error TEXT) STRICT;";

    assert_int_equal(sqlite3_exec(handle, schema, NULL, NULL, NULL), SQLITE_OK);
}

/** @brief Create the retained version-one identity schema fixture. */
static void create_version_one_fixture(const char *path)
{
    static const char schema[] =
        "CREATE TABLE schema_migrations ("
        "version INTEGER PRIMARY KEY,applied_at INTEGER NOT NULL) STRICT;"
        "CREATE TABLE roles ("
        "id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,"
        "permissions TEXT NOT NULL) STRICT;"
        "CREATE TABLE users ("
        "id INTEGER PRIMARY KEY,username TEXT NOT NULL UNIQUE,"
        "password_hash TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,"
        "failed_logins INTEGER NOT NULL DEFAULT 0,locked_until INTEGER,"
        "created_at INTEGER NOT NULL,password_changed_at INTEGER NOT NULL"
        ") STRICT;"
        "CREATE TABLE api_tokens ("
        "id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),"
        "name TEXT NOT NULL,token_hash BLOB NOT NULL UNIQUE,scopes TEXT NOT "
        "NULL,created_at INTEGER NOT NULL,expires_at INTEGER,last_used_at "
        "INTEGER,revoked_at INTEGER) STRICT;"
        "CREATE TABLE web_sessions ("
        "id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),"
        "session_hash BLOB NOT NULL UNIQUE,csrf_hash BLOB NOT NULL,"
        "created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,"
        "last_seen_at INTEGER NOT NULL,remote_address BLOB) STRICT;"
        "CREATE TABLE audit_events ("
        "id INTEGER PRIMARY KEY,occurred_at INTEGER NOT NULL,"
        "actor_type TEXT NOT NULL,actor_id INTEGER,action TEXT NOT NULL,"
        "object_type TEXT NOT NULL,object_id TEXT,details TEXT NOT NULL,"
        "previous_hash BLOB,event_hash BLOB NOT NULL UNIQUE) STRICT;"
        "INSERT INTO roles(id,name,permissions) VALUES"
        "(1,'administrator','all'),(2,'operator','operate'),"
        "(3,'auditor','read');"
        "INSERT INTO users(id,username,password_hash,created_at,"
        "password_changed_at) VALUES(7,'legacy','hash',10,10);"
        "INSERT INTO schema_migrations(version,applied_at) VALUES(1,10);"
        "PRAGMA user_version=1;";
    sqlite3 *handle = NULL;

    assert_int_equal(sqlite3_open_v2(path, &handle,
                                     SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                                     NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_exec(handle, schema, NULL, NULL, NULL), SQLITE_OK);
    add_legacy_policy_rules(handle);
    add_legacy_blocklist_sources(handle);
    assert_int_equal(sqlite3_close(handle), SQLITE_OK);
    assert_int_equal(chmod(path, S_IRUSR | S_IWUSR), 0);
}

/** @brief Create the retained version-two policy schema fixture. */
static void create_version_two_fixture(const char *path)
{
    static const char schema[] =
        "CREATE TABLE schema_migrations ("
        "version INTEGER PRIMARY KEY,applied_at INTEGER NOT NULL) STRICT;"
        "CREATE TABLE users(id INTEGER PRIMARY KEY) STRICT;"
        "CREATE TABLE web_sessions ("
        "id INTEGER PRIMARY KEY,"
        "user_id INTEGER NOT NULL REFERENCES users(id),"
        "session_hash BLOB NOT NULL UNIQUE,"
        "csrf_hash BLOB NOT NULL,"
        "created_at INTEGER NOT NULL,"
        "expires_at INTEGER NOT NULL,"
        "last_seen_at INTEGER NOT NULL,"
        "remote_address BLOB"
        ") STRICT;"
        "INSERT INTO schema_migrations(version,applied_at) VALUES(1,10),(2,20);"
        "PRAGMA user_version=2;";
    sqlite3 *handle = NULL;

    assert_int_equal(sqlite3_open_v2(path, &handle,
                                     SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                                     NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_exec(handle, schema, NULL, NULL, NULL), SQLITE_OK);
    add_legacy_policy_rules(handle);
    add_legacy_blocklist_sources(handle);
    assert_int_equal(sqlite3_close(handle), SQLITE_OK);
    assert_int_equal(chmod(path, S_IRUSR | S_IWUSR), 0);
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

/** @brief Construct a valid global destination rule for database tests. */
static struct jg_policy_destination_rule_input make_destination_rule(
    uint64_t id,
    enum jg_policy_effect effect)
{
    struct jg_policy_destination_rule_input rule;

    (void)memset(&rule, 0, sizeof(rule));
    rule.id = id;
    rule.effect = effect;
    rule.source = JG_POLICY_SOURCE_EXPLICIT;
    rule.transport = JG_POLICY_TRANSPORT_ANY;
    rule.scope.type = JG_POLICY_SCOPE_GLOBAL;
    rule.attribution = "database test";
    return rule;
}

/** @brief Construct a complete inline-network configuration for storage. */
static struct jg_network_config make_network_config(void)
{
    struct jg_network_config config = {
        .bridge = "br-data",
        .ingress = "eth0",
        .egress = "eth1",
        .management = "eth2",
        .queue_first = 100U,
        .queue_count = 4U,
        .queue_length = 4096U,
        .failure_mode = JG_NETWORK_FAIL_OPEN,
        .multicast_snooping = true,
        .queue_cpu_fanout = true,
    };

    return config;
}

/** @brief Assert equality of every semantic network configuration field. */
static void assert_network_config_equal(
    const struct jg_network_config *actual,
    const struct jg_network_config *expected)
{
    assert_string_equal(actual->bridge, expected->bridge);
    assert_string_equal(actual->ingress, expected->ingress);
    assert_string_equal(actual->egress, expected->egress);
    assert_string_equal(actual->management, expected->management);
    assert_int_equal(actual->bridge_mtu, expected->bridge_mtu);
    assert_int_equal(actual->queue_first, expected->queue_first);
    assert_int_equal(actual->queue_count, expected->queue_count);
    assert_int_equal(actual->queue_length, expected->queue_length);
    assert_int_equal(actual->failure_mode, expected->failure_mode);
    assert_int_equal(actual->stp, expected->stp);
    assert_int_equal(actual->multicast_snooping, expected->multicast_snooping);
    assert_int_equal(actual->queue_cpu_fanout, expected->queue_cpu_fanout);
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
    assert_true(table_exists(inspection, "bootstrap_credentials"));
    assert_true(column_exists(inspection, "domain_rules", "revision"));
    assert_true(column_exists(inspection, "domain_rules", "category"));
    assert_true(column_exists(inspection, "destination_rules", "revision"));
    assert_true(column_exists(inspection, "blocklist_sources", "revision"));
    assert_true(
        column_exists(inspection, "blocklist_sources", "signature_url"));
    assert_true(column_exists(inspection, "blocklist_source_status",
                              "rejected_entries"));
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
    set_schema_version(handle, JG_DATABASE_SCHEMA_VERSION + 1U);
    assert_int_equal(sqlite3_close(handle), SQLITE_OK);

    database = NULL;
    assert_int_equal(jg_database_open(path, 1000U, &database), -ENOTSUP);
    assert_null(database);
    remove_database(directory, path);
}

/** @brief Verify ordered upgrade and backup of a version-one database. */
static void test_version_one_migration(void **state)
{
    char directory[64U];
    char path[512U];
    char backup_path[520U];
    struct jg_database *database = NULL;
    sqlite3_stmt *statement = NULL;
    sqlite3 *inspection = NULL;
    struct stat metadata;
    uint32_t version = 0U;
    int written = 0;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    create_version_one_fixture(path);
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_schema_version(database, &version), 0);
    assert_int_equal(version, JG_DATABASE_SCHEMA_VERSION);
    jg_database_close(database);

    written = snprintf(backup_path, sizeof(backup_path), "%s.lkg", path);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(backup_path));
    assert_int_equal(stat(backup_path, &metadata), 0);
    assert_int_equal(metadata.st_mode & 0777U, S_IRUSR | S_IWUSR);

    assert_int_equal(
        sqlite3_open_v2(path, &inspection, SQLITE_OPEN_READONLY, NULL),
        SQLITE_OK);
    assert_true(column_exists(inspection, "users", "force_password_change"));
    assert_true(column_exists(inspection, "users", "session_epoch"));
    assert_true(column_exists(inspection, "api_tokens", "source_address"));
    assert_true(column_exists(inspection, "web_sessions", "session_epoch"));
    assert_true(column_exists(inspection, "audit_events", "request_id"));
    assert_true(column_exists(inspection, "domain_rules", "target"));
    assert_true(column_exists(inspection, "domain_rules", "revision"));
    assert_true(column_exists(inspection, "domain_rules", "category"));
    assert_true(column_exists(inspection, "destination_rules", "source"));
    assert_true(column_exists(inspection, "destination_rules", "scope_type"));
    assert_true(column_exists(inspection, "destination_rules", "revision"));
    assert_true(column_exists(inspection, "blocklist_sources", "revision"));
    assert_true(
        column_exists(inspection, "blocklist_sources", "signature_url"));
    assert_true(column_exists(inspection, "blocklist_source_status",
                              "rejected_entries"));
    assert_true(table_exists(inspection, "totp_credentials"));
    assert_true(table_exists(inspection, "recovery_codes"));
    assert_true(table_exists(inspection, "mtls_mappings"));
    assert_int_equal(
        sqlite3_prepare_v2(inspection,
                           "SELECT force_password_change,last_login_at,"
                           "revision,session_epoch FROM users WHERE id=7;",
                           -1, &statement, NULL),
        SQLITE_OK);
    assert_int_equal(sqlite3_step(statement), SQLITE_ROW);
    assert_int_equal(sqlite3_column_int(statement, 0), 1);
    assert_int_equal(sqlite3_column_type(statement, 1), SQLITE_NULL);
    assert_int_equal(sqlite3_column_int(statement, 2), 1);
    assert_int_equal(sqlite3_column_int(statement, 3), 1);
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
    assert_int_equal(
        sqlite3_prepare_v2(inspection,
                           "SELECT target FROM domain_rules WHERE id=1;", -1,
                           &statement, NULL),
        SQLITE_OK);
    assert_int_equal(sqlite3_step(statement), SQLITE_ROW);
    assert_string_equal((const char *)sqlite3_column_text(statement, 0), "dns");
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
    assert_int_equal(
        sqlite3_prepare_v2(inspection,
                           "SELECT source,scope_type FROM destination_rules "
                           "WHERE id=2;",
                           -1, &statement, NULL),
        SQLITE_OK);
    assert_int_equal(sqlite3_step(statement), SQLITE_ROW);
    assert_string_equal((const char *)sqlite3_column_text(statement, 0),
                        "explicit");
    assert_string_equal((const char *)sqlite3_column_text(statement, 1),
                        "global");
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
    assert_int_equal(sqlite3_close(inspection), SQLITE_OK);
    remove_database(directory, path);
}

/** @brief Verify the retained version-two policy migration. */
static void test_version_two_migration(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_database *database = NULL;
    sqlite3_stmt *statement = NULL;
    sqlite3 *inspection = NULL;
    uint32_t version = 0U;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    create_version_two_fixture(path);
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_schema_version(database, &version), 0);
    assert_int_equal(version, JG_DATABASE_SCHEMA_VERSION);
    jg_database_close(database);

    assert_int_equal(
        sqlite3_open_v2(path, &inspection, SQLITE_OPEN_READONLY, NULL),
        SQLITE_OK);
    assert_true(column_exists(inspection, "domain_rules", "target"));
    assert_int_equal(
        sqlite3_prepare_v2(inspection,
                           "SELECT target FROM domain_rules WHERE id=1;", -1,
                           &statement, NULL),
        SQLITE_OK);
    assert_int_equal(sqlite3_step(statement), SQLITE_ROW);
    assert_string_equal((const char *)sqlite3_column_text(statement, 0), "dns");
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
    assert_int_equal(sqlite3_close(inspection), SQLITE_OK);
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
    struct jg_policy_rule_input rules[4U];
    struct jg_policy_rule_input invalid;
    struct jg_policy_rule_input mutable_rule;
    struct jg_policy_destination_rule_input destination_rules[2U];
    struct jg_policy_destination_rule_input invalid_destination;
    struct jg_policy_destination_rule_input mutable_destination;
    struct jg_database_domain_rule domain_page[2U];
    struct jg_database_domain_rule created_rule;
    struct jg_database_domain_rule updated_rule;
    struct jg_database_destination_rule destination_page[1U];
    struct jg_database_destination_rule created_destination;
    struct jg_database_destination_rule updated_destination;
    struct jg_policy_destination destination = {
        .transport = JG_POLICY_TRANSPORT_TCP,
        .address_family = JG_POLICY_ADDRESS_IPV4,
        .address = {203U, 0U, 113U, 53U},
        .port = 853U,
    };
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_policy_snapshot_info info;
    struct jg_policy_client client;
    struct jg_policy_match match;
    struct jg_policy_destination_match destination_match;
    struct jg_database *database = NULL;
    size_t page_count = 0U;
    bool has_more = false;

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
    rules[3] = make_rule(12U, "resolver.example", true, JG_POLICY_BLOCK,
                         JG_POLICY_SOURCE_EXPLICIT);
    rules[3].target = JG_POLICY_DOMAIN_TLS_SNI;
    assert_int_equal(jg_database_replace_domain_rules(database, rules, 4U), 0);
    destination_rules[0] = make_destination_rule(20U, JG_POLICY_BLOCK);
    destination_rules[0].has_port = true;
    destination_rules[0].port = 853U;
    destination_rules[1] = make_destination_rule(21U, JG_POLICY_ALLOW);
    destination_rules[1].transport = JG_POLICY_TRANSPORT_TCP;
    destination_rules[1].has_address = true;
    destination_rules[1].address_family = JG_POLICY_ADDRESS_IPV4;
    (void)memcpy(destination_rules[1].address, destination.address, 4U);
    destination_rules[1].prefix_length = 32U;
    destination_rules[1].has_port = true;
    destination_rules[1].port = 853U;
    destination_rules[1].scope.type = JG_POLICY_SCOPE_VLAN;
    destination_rules[1].scope.value.vlan_id = 7U;
    assert_int_equal(
        jg_database_replace_destination_rules(database, destination_rules, 2U),
        0);
    assert_int_equal(jg_database_list_domain_rules(
                         database, 0U, 2U, domain_page, &page_count, &has_more),
                     0);
    assert_int_equal(page_count, 2U);
    assert_true(has_more);
    assert_int_equal(domain_page[0U].id, 3U);
    assert_int_equal(domain_page[0U].revision, 1U);
    assert_true(domain_page[0U].updated_at > 0U);
    assert_int_equal(domain_page[0U].scope.type, JG_POLICY_SCOPE_VLAN);
    assert_int_equal(domain_page[0U].scope.value.vlan_id, 7U);
    assert_int_equal(domain_page[1U].id, 5U);
    assert_string_equal(domain_page[1U].domain, "safe.example.org");
    assert_string_equal(domain_page[1U].attribution, "database test");
    assert_string_equal(domain_page[1U].category, "");
    assert_int_equal(jg_database_list_domain_rules(
                         database, 5U, 2U, domain_page, &page_count, &has_more),
                     0);
    assert_int_equal(page_count, 2U);
    assert_false(has_more);
    assert_int_equal(domain_page[0U].id, 10U);
    assert_string_equal(domain_page[0U].domain, "example.org");
    assert_int_equal(domain_page[1U].id, 12U);
    assert_int_equal(domain_page[1U].target, JG_POLICY_DOMAIN_TLS_SNI);
    assert_int_equal(jg_database_list_destination_rules(database, 0U, 1U,
                                                        destination_page,
                                                        &page_count, &has_more),
                     0);
    assert_int_equal(page_count, 1U);
    assert_true(has_more);
    assert_int_equal(destination_page[0U].id, 20U);
    assert_int_equal(destination_page[0U].revision, 1U);
    assert_true(destination_page[0U].has_port);
    assert_int_equal(destination_page[0U].port, 853U);
    assert_int_equal(jg_database_list_destination_rules(database, 20U, 1U,
                                                        destination_page,
                                                        &page_count, &has_more),
                     0);
    assert_int_equal(page_count, 1U);
    assert_false(has_more);
    assert_int_equal(destination_page[0U].id, 21U);
    assert_true(destination_page[0U].has_address);
    assert_int_equal(destination_page[0U].scope.type, JG_POLICY_SCOPE_VLAN);
    assert_int_equal(jg_database_list_domain_rules(
                         database, 0U, 0U, domain_page, &page_count, &has_more),
                     -EINVAL);
    assert_int_equal(jg_database_load_policy_snapshot(database, 9U, &snapshot),
                     0);
    assert_int_equal(jg_policy_snapshot_get_info(snapshot, &info), 0);
    assert_int_equal(info.generation, 9U);
    assert_int_equal(info.rule_count, 4U);
    assert_int_equal(info.destination_rule_count, 2U);

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
    assert_int_equal(jg_policy_match_visible_sni(
                         snapshot, "doh.resolver.example", NULL, &match),
                     0);
    assert_int_equal(match.effect, JG_POLICY_BLOCK);
    assert_int_equal(match.rule_id, 12U);
    assert_int_equal(jg_policy_match_destination(snapshot, &destination,
                                                 &client, &destination_match),
                     0);
    assert_int_equal(destination_match.effect, JG_POLICY_ALLOW);
    assert_int_equal(destination_match.rule_id, 21U);
    client.vlan_id = 8U;
    assert_int_equal(jg_policy_match_destination(snapshot, &destination,
                                                 &client, &destination_match),
                     0);
    assert_int_equal(destination_match.effect, JG_POLICY_BLOCK);
    assert_int_equal(destination_match.rule_id, 20U);
    jg_policy_snapshot_destroy(snapshot);

    invalid = make_rule(1U, "invalid.example", false, JG_POLICY_ALLOW,
                        JG_POLICY_SOURCE_BLOCKLIST);
    assert_true(jg_database_replace_domain_rules(database, &invalid, 1U) < 0);
    invalid_destination = destination_rules[0];
    invalid_destination.has_port = false;
    assert_true(jg_database_replace_destination_rules(
                    database, &invalid_destination, 1U) < 0);
    snapshot = NULL;
    assert_int_equal(jg_database_load_policy_snapshot(database, 10U, &snapshot),
                     0);
    assert_int_equal(
        jg_policy_match_domain(snapshot, "host.example.org", NULL, &match), 0);
    assert_int_equal(match.rule_id, 10U);
    assert_int_equal(jg_policy_match_destination(snapshot, &destination, NULL,
                                                 &destination_match),
                     0);
    assert_int_equal(destination_match.rule_id, 20U);

    jg_policy_snapshot_destroy(snapshot);
    mutable_rule = make_rule(0U, "New.Example.", false, JG_POLICY_BLOCK,
                             JG_POLICY_SOURCE_EXPLICIT);
    assert_int_equal(jg_database_create_domain_rule(database, &mutable_rule,
                                                    false, &created_rule),
                     0);
    assert_true(created_rule.id > 12U);
    assert_int_equal(created_rule.revision, 1U);
    assert_string_equal(created_rule.domain, "new.example");
    assert_false(created_rule.enabled);
    mutable_rule.id = created_rule.id;
    mutable_rule.domain = "Updated.Example.";
    mutable_rule.include_subdomains = true;
    assert_int_equal(jg_database_update_domain_rule(database, &mutable_rule,
                                                    true, created_rule.revision,
                                                    &updated_rule),
                     0);
    assert_int_equal(updated_rule.id, created_rule.id);
    assert_int_equal(updated_rule.revision, 2U);
    assert_string_equal(updated_rule.domain, "updated.example");
    assert_true(updated_rule.include_subdomains);
    assert_true(updated_rule.enabled);
    assert_int_equal(jg_database_update_domain_rule(database, &mutable_rule,
                                                    true, created_rule.revision,
                                                    &updated_rule),
                     -EAGAIN);
    mutable_rule.id = INT64_MAX;
    assert_int_equal(jg_database_update_domain_rule(database, &mutable_rule,
                                                    true, 1U, &updated_rule),
                     -ENOENT);
    assert_int_equal(jg_database_delete_domain_rule(database, created_rule.id,
                                                    created_rule.revision),
                     -EAGAIN);
    assert_int_equal(
        jg_database_delete_domain_rule(database, created_rule.id, 2U), 0);
    assert_int_equal(
        jg_database_delete_domain_rule(database, created_rule.id, 2U), -ENOENT);
    mutable_rule.id = 1U;
    assert_int_equal(jg_database_create_domain_rule(database, &mutable_rule,
                                                    true, &created_rule),
                     -EINVAL);
    mutable_destination = make_destination_rule(0U, JG_POLICY_BLOCK);
    mutable_destination.has_address = true;
    mutable_destination.address_family = JG_POLICY_ADDRESS_IPV4;
    mutable_destination.address[0U] = 203U;
    mutable_destination.address[1U] = 0U;
    mutable_destination.address[2U] = 113U;
    mutable_destination.address[3U] = 99U;
    mutable_destination.prefix_length = 24U;
    assert_int_equal(
        jg_database_create_destination_rule(database, &mutable_destination,
                                            false, &created_destination),
        0);
    assert_true(created_destination.id > 21U);
    assert_int_equal(created_destination.revision, 1U);
    assert_false(created_destination.enabled);
    assert_true(created_destination.has_address);
    assert_int_equal(created_destination.address[3U], 0U);
    mutable_destination.id = created_destination.id;
    mutable_destination.has_port = true;
    mutable_destination.port = 443U;
    assert_int_equal(jg_database_update_destination_rule(
                         database, &mutable_destination, true,
                         created_destination.revision, &updated_destination),
                     0);
    assert_int_equal(updated_destination.revision, 2U);
    assert_true(updated_destination.enabled);
    assert_true(updated_destination.has_port);
    assert_int_equal(updated_destination.port, 443U);
    assert_int_equal(jg_database_update_destination_rule(
                         database, &mutable_destination, true,
                         created_destination.revision, &updated_destination),
                     -EAGAIN);
    mutable_destination.id = INT64_MAX;
    assert_int_equal(
        jg_database_update_destination_rule(database, &mutable_destination,
                                            true, 1U, &updated_destination),
        -ENOENT);
    assert_int_equal(
        jg_database_delete_destination_rule(database, created_destination.id,
                                            created_destination.revision),
        -EAGAIN);
    assert_int_equal(jg_database_delete_destination_rule(
                         database, created_destination.id, 2U),
                     0);
    assert_int_equal(jg_database_delete_destination_rule(
                         database, created_destination.id, 2U),
                     -ENOENT);
    mutable_destination.id = 1U;
    assert_int_equal(
        jg_database_create_destination_rule(database, &mutable_destination,
                                            true, &created_destination),
        -EINVAL);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify that enabled encrypted-DNS endpoints become block rules. */
static void test_encrypted_dns_endpoint_policy(void **state)
{
    static const char endpoints[] =
        "INSERT INTO encrypted_dns_sources(id,name,url,enabled,updated_at)"
        " VALUES"
        "(1,'trusted resolver feed','https://resolver.example/list',1,10),"
        "(2,'disabled resolver feed','https://disabled.example/list',0,10);"
        "INSERT INTO encrypted_dns_endpoints("
        "source_id,family,address,port,transport"
        ") VALUES"
        "(1,4,x'CB007135',443,'tcp'),"
        "(1,6,x'20010DB8000000000000000000000053',853,'udp'),"
        "(2,4,x'C0000235',443,'tcp');";
    char directory[64U];
    char path[512U];
    struct jg_policy_destination destination = {
        .transport = JG_POLICY_TRANSPORT_TCP,
        .address_family = JG_POLICY_ADDRESS_IPV4,
        .address = {203U, 0U, 113U, 53U},
        .port = 443U,
    };
    struct jg_policy_destination_match match;
    struct jg_policy_snapshot_info info;
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_database *database = NULL;
    sqlite3 *handle = NULL;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    jg_database_close(database);

    assert_int_equal(
        sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE, NULL), SQLITE_OK);
    assert_int_equal(sqlite3_exec(handle, endpoints, NULL, NULL, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_close(handle), SQLITE_OK);

    database = NULL;
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_load_policy_snapshot(database, 1U, &snapshot),
                     0);
    assert_int_equal(jg_policy_snapshot_get_info(snapshot, &info), 0);
    assert_int_equal(info.destination_rule_count, 2U);
    assert_int_equal(
        jg_policy_match_destination(snapshot, &destination, NULL, &match), 0);
    assert_true(match.matched);
    assert_int_equal(match.effect, JG_POLICY_BLOCK);
    assert_int_equal(match.source, JG_POLICY_SOURCE_BLOCKLIST);
    assert_true((match.rule_id & (UINT64_C(1) << 63U)) != 0U);
    assert_string_equal(match.attribution, "trusted resolver feed");

    destination.address[0U] = 192U;
    destination.address[1U] = 0U;
    destination.address[2U] = 2U;
    assert_int_equal(
        jg_policy_match_destination(snapshot, &destination, NULL, &match), 0);
    assert_false(match.matched);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    jg_policy_snapshot_destroy(snapshot);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify atomic network configuration persistence and validation. */
static void test_network_configuration(void **state)
{
    static const char corrupt[] = "UPDATE system_settings SET value='invalid'"
                                  " WHERE key='network.configuration';";
    char directory[64U];
    char path[512U];
    struct jg_network_config expected = make_network_config();
    struct jg_network_config loaded;
    struct jg_database *database = NULL;
    sqlite3 *handle = NULL;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_load_network_config(database, &loaded),
                     -ENOENT);
    assert_int_equal(jg_database_store_network_config(database, &expected), 0);
    assert_int_equal(jg_database_load_network_config(database, &loaded), 0);
    assert_network_config_equal(&loaded, &expected);
    jg_database_close(database);

    assert_int_equal(
        sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE, NULL), SQLITE_OK);
    assert_int_equal(sqlite3_exec(handle, corrupt, NULL, NULL, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_close(handle), SQLITE_OK);

    database = NULL;
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_load_network_config(database, &loaded),
                     -EILSEQ);
    assert_int_equal(jg_database_store_network_config(database, NULL), -EINVAL);
    assert_int_equal(jg_database_load_network_config(NULL, &loaded), -EINVAL);
    assert_int_equal(jg_database_load_network_config(database, NULL), -EINVAL);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify persistent blocked-query response policy round trips. */
static void test_dns_response_configuration(void **state)
{
    static const char corrupt[] = "UPDATE system_settings SET value='invalid'"
                                  " WHERE key='dns.response';";
    char directory[64U];
    char path[512U];
    struct jg_dns_response_config expected;
    struct jg_dns_response_config loaded;
    struct jg_database *database = NULL;
    sqlite3 *handle = NULL;

    (void)state;
    jg_dns_response_config_default(&expected);
    expected.action = JG_DNS_BLOCK_SINKHOLE;
    expected.has_ipv4_sinkhole = true;
    expected.ipv4_sinkhole[0U] = 192U;
    expected.ipv4_sinkhole[2U] = 2U;
    expected.ipv4_sinkhole[3U] = 80U;
    expected.sinkhole_ttl = 300U;

    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_load_dns_response_config(database, &loaded),
                     -ENOENT);
    assert_int_equal(jg_database_store_dns_response_config(database, &expected),
                     0);
    assert_int_equal(jg_database_load_dns_response_config(database, &loaded),
                     0);
    assert_int_equal(loaded.action, expected.action);
    assert_true(loaded.has_ipv4_sinkhole);
    assert_memory_equal(loaded.ipv4_sinkhole, expected.ipv4_sinkhole, 4U);
    assert_int_equal(loaded.sinkhole_ttl, expected.sinkhole_ttl);
    jg_database_close(database);

    assert_int_equal(
        sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE, NULL), SQLITE_OK);
    assert_int_equal(sqlite3_exec(handle, corrupt, NULL, NULL, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_close(handle), SQLITE_OK);
    database = NULL;
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_load_dns_response_config(database, &loaded),
                     -EILSEQ);
    assert_int_equal(jg_database_store_dns_response_config(database, NULL),
                     -EINVAL);
    assert_int_equal(jg_database_load_dns_response_config(NULL, &loaded),
                     -EINVAL);
    assert_int_equal(jg_database_load_dns_response_config(database, NULL),
                     -EINVAL);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify stable paging and complete blocklist-source decoding. */
static void test_blocklist_source_page(void **state)
{
    static const char sources[] =
        "INSERT INTO blocklist_sources("
        "id,name,url,format,strict_mode,enabled,update_interval,"
        "max_download_bytes,max_decompressed_bytes,sha256_pin,"
        "ed25519_public_key,created_at,updated_at,signature_url,"
        "connect_timeout_ms,transfer_timeout_ms,redirect_limit,"
        "retry_base_seconds,retry_max_seconds,revision) VALUES("
        "2,'remote','https://lists.example/domains','hosts',0,1,3600,"
        "1024,4096,X'000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f',"
        "X'1f1e1d1c1b1a19181716151413121110"
        "0f0e0d0c0b0a09080706050403020100',10,20,"
        "'https://lists.example/domains.sig',5000,30000,3,60,900,4),("
        "9,'local',NULL,'domain',1,0,86400,2048,8192,NULL,NULL,30,30,NULL,"
        "10000,60000,0,300,3600,1);"
        "INSERT INTO blocklist_source_status("
        "source_id,etag,last_modified,last_attempt_at,last_success_at,"
        "next_attempt_at,consecutive_failures,active_checksum,active_entries,"
        "health,last_error,rejected_entries) VALUES("
        "2,'\"revision-4\"','Mon, 27 Jul 2026 10:00:00 GMT',100,90,160,2,"
        "X'01010101010101010101010101010101"
        "01010101010101010101010101010101',42,'degraded','timeout',3);";
    char directory[64U];
    char path[512U];
    struct jg_database_blocklist_source page[1U];
    struct jg_database *database = NULL;
    sqlite3 *handle = NULL;
    size_t count = 0U;
    bool has_more = false;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    jg_database_close(database);
    assert_int_equal(
        sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE, NULL), SQLITE_OK);
    assert_int_equal(sqlite3_exec(handle, sources, NULL, NULL, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_close(handle), SQLITE_OK);
    database = NULL;
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);

    assert_int_equal(jg_database_list_blocklist_sources(database, 0U, 1U, page,
                                                        &count, &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_true(has_more);
    assert_int_equal(page[0U].id, 2U);
    assert_int_equal(page[0U].revision, 4U);
    assert_string_equal(page[0U].name, "remote");
    assert_string_equal(page[0U].url, "https://lists.example/domains");
    assert_string_equal(page[0U].signature_url,
                        "https://lists.example/domains.sig");
    assert_int_equal(page[0U].format, JG_BLOCKLIST_FORMAT_HOSTS);
    assert_int_equal(page[0U].mode, JG_BLOCKLIST_TOLERANT);
    assert_true(page[0U].enabled);
    assert_true(page[0U].has_sha256_pin);
    assert_true(page[0U].has_signature);
    assert_true(page[0U].has_active_checksum);
    assert_int_equal(page[0U].active_entries, 42U);
    assert_int_equal(page[0U].rejected_entries, 3U);
    assert_int_equal(page[0U].health, JG_DATABASE_BLOCKLIST_DEGRADED);
    assert_string_equal(page[0U].last_error, "timeout");

    assert_int_equal(jg_database_list_blocklist_sources(database, 2U, 1U, page,
                                                        &count, &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_false(has_more);
    assert_int_equal(page[0U].id, 9U);
    assert_string_equal(page[0U].name, "local");
    assert_string_equal(page[0U].url, "");
    assert_false(page[0U].enabled);
    assert_false(page[0U].has_active_checksum);
    assert_int_equal(page[0U].health, JG_DATABASE_BLOCKLIST_UNKNOWN);
    assert_int_equal(jg_database_list_blocklist_sources(database, 0U, 0U, page,
                                                        &count, &has_more),
                     -EINVAL);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Build one valid remote blocklist-source configuration. */
static struct jg_database_blocklist_source_config make_blocklist_source(void)
{
    struct jg_database_blocklist_source_config config;
    size_t index = 0U;

    (void)memset(&config, 0, sizeof(config));
    config.name = "Threat domains";
    config.url = "https://lists.example/domains";
    config.signature_url = "https://lists.example/domains.sig";
    config.format = JG_BLOCKLIST_FORMAT_DOMAIN;
    config.mode = JG_BLOCKLIST_TOLERANT;
    config.enabled = true;
    config.update_interval_seconds = 3600U;
    config.max_download_bytes = 1024U * 1024U;
    config.max_decompressed_bytes = 4U * 1024U * 1024U;
    config.connect_timeout_ms = 5000U;
    config.transfer_timeout_ms = 30000U;
    config.redirect_limit = 3U;
    config.retry_base_seconds = 60U;
    config.retry_max_seconds = 3600U;
    config.has_sha256_pin = true;
    config.has_signature = true;
    for (index = 0U; index < sizeof(config.sha256_pin); ++index) {
        config.sha256_pin[index] = (uint8_t)index;
        config.ed25519_public_key[index] = (uint8_t)(31U - index);
    }
    return config;
}

/** @brief Verify atomic blocklist-source creation and validation. */
static void test_blocklist_source_creation(void **state)
{
    static const char invalid_utf8[] = {'b', 'a', 'd', (char)0xc0, '\0'};
    char directory[64U];
    char path[512U];
    struct jg_database_blocklist_source_config config = make_blocklist_source();
    struct jg_database_blocklist_source created;
    struct jg_database_blocklist_source duplicate;
    struct jg_database_blocklist_source updated;
    struct jg_database *database = NULL;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(
        jg_database_create_blocklist_source(database, &config, &created), 0);
    assert_true(created.id > 0U);
    assert_int_equal(created.revision, 1U);
    assert_string_equal(created.name, config.name);
    assert_string_equal(created.url, config.url);
    assert_int_equal(created.mode, config.mode);
    assert_true(created.enabled);
    assert_true(created.has_sha256_pin);
    assert_memory_equal(created.sha256_pin, config.sha256_pin,
                        sizeof(created.sha256_pin));
    assert_true(created.has_signature);
    assert_memory_equal(created.ed25519_public_key, config.ed25519_public_key,
                        sizeof(created.ed25519_public_key));
    assert_int_equal(created.health, JG_DATABASE_BLOCKLIST_UNKNOWN);
    assert_int_equal(
        jg_database_create_blocklist_source(database, &config, &duplicate),
        -EEXIST);

    config.name = invalid_utf8;
    assert_int_equal(
        jg_database_create_blocklist_source(database, &config, &duplicate),
        -EILSEQ);
    config.name = "Invalid transport";
    config.url = "http://lists.example/domains";
    assert_int_equal(
        jg_database_create_blocklist_source(database, &config, &duplicate),
        -EINVAL);
    config.url = NULL;
    assert_int_equal(
        jg_database_create_blocklist_source(database, &config, &duplicate),
        -EINVAL);
    config.signature_url = NULL;
    config.has_signature = false;
    assert_int_equal(
        jg_database_create_blocklist_source(database, &config, &duplicate), 0);
    assert_string_equal(duplicate.url, "");
    assert_false(duplicate.has_signature);

    config = make_blocklist_source();
    config.name = "Updated threat domains";
    config.enabled = false;
    config.update_interval_seconds = 7200U;
    assert_int_equal(
        jg_database_update_blocklist_source(database, created.id, &config,
                                            created.revision, &updated),
        0);
    assert_int_equal(updated.id, created.id);
    assert_int_equal(updated.revision, 2U);
    assert_string_equal(updated.name, config.name);
    assert_false(updated.enabled);
    assert_int_equal(updated.update_interval_seconds, 7200U);
    assert_int_equal(
        jg_database_update_blocklist_source(database, created.id, &config,
                                            created.revision, &updated),
        -EAGAIN);
    config.name = duplicate.name;
    assert_int_equal(jg_database_update_blocklist_source(database, created.id,
                                                         &config, 2U, &updated),
                     -EEXIST);
    assert_int_equal(jg_database_delete_blocklist_source(database, created.id,
                                                         created.revision),
                     -EAGAIN);
    assert_int_equal(
        jg_database_delete_blocklist_source(database, created.id, 2U), 0);
    assert_int_equal(
        jg_database_delete_blocklist_source(database, created.id, 2U), -ENOENT);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify atomic imported-entry and last-known-good activation. */
static void test_blocklist_activation(void **state)
{
    static const uint8_t input[] = "alpha.example,advertising\n"
                                   "bad domain\n"
                                   "beta.example,tracking\n";
    char directory[64U];
    char path[512U];
    struct jg_database_blocklist_source_config config = make_blocklist_source();
    struct jg_database_blocklist_source source;
    struct jg_database_blocklist_source updated;
    struct jg_database_domain_rule rules[2U];
    struct jg_blocklist_remote_state remote;
    struct jg_blocklist_report report;
    struct jg_blocklist_limits limits;
    struct jg_blocklist *blocklist = NULL;
    struct jg_database *database = NULL;
    size_t count = 0U;
    bool has_more = false;

    (void)state;
    config.name = "Activation source";
    config.signature_url = NULL;
    config.has_signature = false;
    config.has_sha256_pin = false;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(
        jg_database_create_blocklist_source(database, &config, &source), 0);
    jg_blocklist_limits_default(&limits);
    assert_int_equal(jg_blocklist_import(input, sizeof(input) - 1U,
                                         JG_BLOCKLIST_FORMAT_CATEGORY,
                                         JG_BLOCKLIST_TOLERANT, source.name,
                                         &limits, &blocklist, &report),
                     0);
    assert_int_equal(report.records_rejected, 1U);
    jg_blocklist_remote_state_init(&remote);
    (void)snprintf(remote.etag, sizeof(remote.etag), "%s", "\"active-1\"");
    remote.last_attempt_at = 100U;
    remote.last_success_at = 100U;
    remote.next_attempt_at = 3700U;
    assert_int_equal(jg_database_activate_blocklist(database, source.id,
                                                    source.revision, blocklist,
                                                    &remote, &report),
                     0);
    assert_int_equal(jg_database_list_domain_rules(database, 0U, 2U, rules,
                                                   &count, &has_more),
                     0);
    assert_int_equal(count, 2U);
    assert_false(has_more);
    assert_string_equal(rules[0U].domain, "alpha.example");
    assert_string_equal(rules[0U].category, "advertising");
    assert_string_equal(rules[0U].attribution, source.name);
    assert_true(rules[0U].include_subdomains);
    assert_int_equal(rules[0U].source, JG_POLICY_SOURCE_BLOCKLIST);
    assert_string_equal(rules[1U].domain, "beta.example");
    assert_string_equal(rules[1U].category, "tracking");
    assert_int_equal(jg_database_list_blocklist_sources(
                         database, 0U, 1U, &updated, &count, &has_more),
                     0);
    assert_true(updated.has_active_checksum);
    assert_int_equal(updated.active_entries, 2U);
    assert_int_equal(updated.rejected_entries, 1U);
    assert_int_equal(updated.health, JG_DATABASE_BLOCKLIST_HEALTHY);
    assert_string_equal(updated.etag, "\"active-1\"");

    config.enabled = false;
    assert_int_equal(
        jg_database_update_blocklist_source(database, source.id, &config,
                                            source.revision, &updated),
        0);
    assert_int_equal(jg_database_activate_blocklist(database, source.id,
                                                    source.revision, blocklist,
                                                    &remote, &report),
                     -EAGAIN);
    jg_blocklist_destroy(blocklist);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Run the SQLite lifecycle and migration test group. */
int jg_test_database(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_initial_migration),
        cmocka_unit_test(test_newer_schema_rejected),
        cmocka_unit_test(test_version_one_migration),
        cmocka_unit_test(test_version_two_migration),
        cmocka_unit_test(test_insecure_permissions_rejected),
        cmocka_unit_test(test_policy_round_trip),
        cmocka_unit_test(test_encrypted_dns_endpoint_policy),
        cmocka_unit_test(test_network_configuration),
        cmocka_unit_test(test_dns_response_configuration),
        cmocka_unit_test(test_blocklist_source_page),
        cmocka_unit_test(test_blocklist_source_creation),
        cmocka_unit_test(test_blocklist_activation),
    };

    return cmocka_run_group_tests_name("database", tests, NULL, NULL);
}
