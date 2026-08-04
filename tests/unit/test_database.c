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

#include "database_internal.h"

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
    written = snprintf(auxiliary, sizeof(auxiliary), "%s.recovery", path);
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

/** @brief Open one serialized SQLite snapshot without taking ownership. */
static sqlite3 *open_snapshot(uint8_t *data, size_t data_size)
{
    sqlite3 *snapshot = NULL;

    assert_true(data_size <= (size_t)INT64_MAX);
    assert_int_equal(sqlite3_open(":memory:", &snapshot), SQLITE_OK);
    assert_int_equal(sqlite3_deserialize(snapshot, "main", data,
                                         (sqlite3_int64)data_size,
                                         (sqlite3_int64)data_size, 0U),
                     SQLITE_OK);
    return snapshot;
}

/** @brief Count every record in one trusted table. */
static sqlite3_int64 row_count(sqlite3 *handle, const char *table)
{
    char query[128U];
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 count = 0;
    int written =
        snprintf(query, sizeof(query), "SELECT count(*) FROM %s;", table);

    assert_true(written > 0);
    assert_true((size_t)written < sizeof(query));
    assert_int_equal(sqlite3_prepare_v2(handle, query, -1, &statement, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_step(statement), SQLITE_ROW);
    count = sqlite3_column_int64(statement, 0);
    assert_int_equal(sqlite3_step(statement), SQLITE_DONE);
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
    return count;
}

/** @brief Assert one trusted scalar query returns the expected text. */
static void assert_text_value(sqlite3 *handle,
                              const char *query,
                              const char *expected)
{
    sqlite3_stmt *statement = NULL;
    const unsigned char *actual = NULL;

    assert_int_equal(sqlite3_prepare_v2(handle, query, -1, &statement, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_step(statement), SQLITE_ROW);
    actual = sqlite3_column_text(statement, 0);
    assert_non_null(actual);
    assert_string_equal((const char *)actual, expected);
    assert_int_equal(sqlite3_step(statement), SQLITE_DONE);
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
}

/** @brief Assert one trusted scalar query returns the expected integer. */
static void assert_integer_value(sqlite3 *handle,
                                 const char *query,
                                 sqlite3_int64 expected)
{
    sqlite3_stmt *statement = NULL;

    assert_int_equal(sqlite3_prepare_v2(handle, query, -1, &statement, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_step(statement), SQLITE_ROW);
    assert_int_equal(sqlite3_column_int64(statement, 0), expected);
    assert_int_equal(sqlite3_step(statement), SQLITE_DONE);
    assert_int_equal(sqlite3_finalize(statement), SQLITE_OK);
}

/** @brief Find whether one byte sequence occurs inside another. */
static bool snapshot_contains(const uint8_t *data,
                              size_t data_size,
                              const uint8_t *needle,
                              size_t needle_size)
{
    size_t offset = 0U;

    if (needle_size == 0U || needle_size > data_size) {
        return false;
    }
    for (offset = 0U; offset <= data_size - needle_size; ++offset) {
        if (memcmp(data + offset, needle, needle_size) == 0) {
            return true;
        }
    }
    return false;
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
        "CREATE TABLE audit_events ("
        "id INTEGER PRIMARY KEY,occurred_at INTEGER NOT NULL,"
        "actor_type TEXT NOT NULL,actor_id INTEGER,action TEXT NOT NULL,"
        "object_type TEXT NOT NULL,object_id TEXT,details TEXT NOT NULL,"
        "previous_hash BLOB,event_hash BLOB NOT NULL UNIQUE,"
        "source TEXT NOT NULL DEFAULT 'local',previous_revision INTEGER,"
        "new_revision INTEGER,success INTEGER NOT NULL DEFAULT 1,"
        "request_id TEXT NOT NULL DEFAULT '') STRICT;"
        "CREATE TABLE mtls_mappings ("
        "id INTEGER PRIMARY KEY,fingerprint_sha256 BLOB NOT NULL UNIQUE,"
        "user_id INTEGER REFERENCES users(id),role_id INTEGER,"
        "enabled INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL) "
        "STRICT;"
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
    rule.statistics_id[0U] = 1U;
    rule.statistics_id[15U] = (uint8_t)id;
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
    rule.statistics_id[0U] = 2U;
    rule.statistics_id[15U] = (uint8_t)id;
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
    assert_true(table_exists(inspection, "network_configuration"));
    assert_true(column_exists(inspection, "network_configuration", "revision"));
    assert_true(table_exists(inspection, "logging_configuration"));
    assert_true(column_exists(inspection, "logging_configuration", "revision"));
    assert_true(table_exists(inspection, "management_operations"));
    assert_true(
        column_exists(inspection, "management_operations", "actor_type"));
    assert_true(
        column_exists(inspection, "management_operations", "requested_action"));
    assert_true(table_exists(inspection, "policy_sync_state"));
    assert_true(table_exists(inspection, "policy_configuration"));
    assert_true(table_exists(inspection, "policy_scope_modes"));
    assert_true(table_exists(inspection, "policy_statistics_configuration"));
    assert_true(table_exists(inspection, "alert_configuration"));
    assert_true(table_exists(inspection, "alert_incidents"));
    assert_true(table_exists(inspection, "alert_outbox"));
    assert_true(table_exists(inspection, "policy_rule_stats"));
    assert_true(table_exists(inspection, "policy_traffic_stats"));
    assert_true(table_exists(inspection, "policy_impact_buckets"));
    assert_true(table_exists(inspection, "policy_traffic_buckets"));
    assert_true(column_exists(inspection, "policy_groups", "enforcement"));
    assert_true(column_exists(inspection, "blocklist_sources", "enforcement"));
    assert_true(column_exists(inspection, "domain_rules", "enforcement"));
    assert_true(column_exists(inspection, "destination_rules", "enforcement"));
    assert_text_value(inspection,
                      "SELECT enforcement FROM policy_configuration WHERE "
                      "id=1;",
                      "enforce");
    assert_integer_value(
        inspection,
        "SELECT retention_enabled FROM policy_statistics_configuration "
        "WHERE id=1;",
        1);
    assert_integer_value(
        inspection,
        "SELECT retention_months FROM policy_statistics_configuration "
        "WHERE id=1;",
        12);
    assert_int_equal(sqlite3_close(inspection), SQLITE_OK);

    database = NULL;
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify the singleton durable management-operation lifecycle. */
static void test_management_operation(void **state)
{
    static const uint8_t payload[] = {0x01U, 0x02U, 0x03U};
    static const struct jg_database_operation_context context = {
        .actor_type = JG_AUDIT_ACTOR_USER,
        .has_actor_id = true,
        .actor_id = 42U,
        .source = "192.0.2.10",
        .request_id = "request-1",
        .requested_action = "certificate.install",
    };
    char directory[64U];
    char path[512U];
    struct jg_database *database = NULL;
    struct jg_database_operation operation;
    struct jg_database_operation_context invalid = context;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_operation_load(database, &operation), -ENOENT);
    assert_int_equal(
        jg_database_operation_prepare(database, "certificate_install", payload,
                                      sizeof(payload), &context, 123U),
        0);
    assert_int_equal(jg_database_operation_prepare(database,
                                                   "another_operation", NULL,
                                                   0U, &context, 124U),
                     -EBUSY);
    assert_int_equal(jg_database_operation_load(database, &operation), 0);
    assert_string_equal(operation.kind, "certificate_install");
    assert_int_equal(operation.created_at, 123U);
    assert_int_equal(operation.payload_size, sizeof(payload));
    assert_memory_equal(operation.payload, payload, sizeof(payload));
    assert_int_equal(operation.actor_type, JG_AUDIT_ACTOR_USER);
    assert_true(operation.has_actor_id);
    assert_int_equal(operation.actor_id, 42U);
    assert_string_equal(operation.source, "192.0.2.10");
    assert_string_equal(operation.request_id, "request-1");
    assert_string_equal(operation.requested_action, "certificate.install");
    assert_false(operation.ready);
    assert_int_equal(jg_database_operation_mark_ready(database), 0);
    assert_int_equal(jg_database_operation_mark_ready(database), -ENOENT);
    assert_int_equal(jg_database_operation_load(database, &operation), 0);
    assert_true(operation.ready);
    assert_int_equal(jg_database_operation_clear(database), 0);
    assert_int_equal(jg_database_operation_clear(database), -ENOENT);
    assert_int_equal(jg_database_operation_prepare(database, "Invalid", NULL,
                                                   0U, &context, 1U),
                     -EINVAL);
    assert_int_equal(jg_database_operation_prepare(database, "operation", NULL,
                                                   1U, &context, 1U),
                     -EINVAL);
    invalid.has_actor_id = false;
    assert_int_equal(jg_database_operation_prepare(database, "operation", NULL,
                                                   0U, &invalid, 1U),
                     -EINVAL);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify persistent desired and applied policy revisions. */
static void test_policy_sync_state(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_database_policy_sync sync;
    struct jg_database *database = NULL;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_policy_sync_load(database, &sync), 0);
    assert_int_equal(sync.desired_revision, 1U);
    assert_int_equal(sync.applied_revision, 1U);
    assert_string_equal(sync.last_error, "");

    assert_int_equal(jg_database_policy_sync_advance(database, 100U, &sync), 0);
    assert_int_equal(sync.desired_revision, 2U);
    assert_int_equal(sync.applied_revision, 1U);
    assert_int_equal(
        jg_database_policy_sync_record(database, sync.desired_revision, false,
                                       "runtime_reload_failed", 101U, &sync),
        0);
    assert_int_equal(sync.last_attempt_at, 101U);
    assert_string_equal(sync.last_error, "runtime_reload_failed");
    assert_int_equal(
        jg_database_policy_sync_record(database, 1U, true, NULL, 102U, &sync),
        -EAGAIN);
    assert_int_equal(
        jg_database_policy_sync_record(database, 2U, true, NULL, 103U, &sync),
        0);
    assert_int_equal(sync.desired_revision, sync.applied_revision);
    assert_int_equal(sync.last_attempt_at, 103U);
    assert_string_equal(sync.last_error, "");

    assert_int_equal(jg_database_transaction_begin(database), 0);
    assert_int_equal(jg_database_policy_sync_advance(database, 104U, &sync), 0);
    assert_int_equal(sync.desired_revision, 3U);
    assert_int_equal(jg_database_transaction_rollback(database), 0);
    assert_int_equal(jg_database_policy_sync_load(database, &sync), 0);
    assert_int_equal(sync.desired_revision, 2U);
    assert_int_equal(sync.applied_revision, 2U);

    assert_int_equal(jg_database_policy_sync_load(NULL, &sync), -EINVAL);
    assert_int_equal(jg_database_policy_sync_advance(database, 0U, NULL),
                     -EINVAL);
    assert_int_equal(
        jg_database_policy_sync_record(database, 2U, false, NULL, 104U, &sync),
        -EINVAL);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify full and secret-free in-memory database snapshots. */
static void test_database_export(void **state)
{
    static const char sensitive_records[] =
        "INSERT INTO system_settings(key,value,updated_at)"
        " VALUES('appliance.name','gateway',10);"
        "INSERT INTO users(id,username,password_hash,created_at,"
        "password_changed_at) VALUES(1,'admin','secret-hash',10,10);"
        "INSERT INTO user_roles(user_id,role_id) VALUES(1,1);"
        "INSERT INTO api_tokens(id,user_id,name,token_hash,scopes,created_at)"
        " VALUES(1,1,'automation',zeroblob(32),'all',10);"
        "INSERT INTO web_sessions(id,user_id,session_hash,csrf_hash,created_at,"
        "expires_at,last_seen_at) VALUES(1,1,zeroblob(32),zeroblob(32),10,"
        "20,10);"
        "INSERT INTO totp_credentials(user_id,secret_ciphertext,nonce,"
        "created_at) VALUES(1,zeroblob(16),zeroblob(24),10);"
        "INSERT INTO recovery_codes(user_id,code_hash,created_at)"
        " VALUES(1,zeroblob(32),10);"
        "INSERT INTO mtls_mappings(id,fingerprint_sha256,user_id,created_at)"
        " VALUES(1,zeroblob(32),1,10);"
        "INSERT INTO bootstrap_credentials(id,token_hash,created_at,expires_at)"
        " VALUES(1,zeroblob(32),10,20);"
        "INSERT INTO audit_events(id,occurred_at,actor_type,action,"
        "object_type,details,event_hash) "
        "VALUES(1,10,'system','test','database',"
        "'{}',zeroblob(32));"
        "INSERT INTO operational_events(id,occurred_at,severity,component,"
        "code,message,details) VALUES(1,10,'info','database','test','test',"
        "'{}');"
        "INSERT INTO backup_metadata(id,created_at,kind,path,checksum,"
        "schema_version,size_bytes) VALUES(1,10,'configuration','/backup',"
        "zeroblob(32),1,100);"
        "INSERT INTO management_operations(id,kind,state,payload,created_at)"
        " VALUES(1,'test_operation','ready',x'0102',10);"
        "INSERT INTO domain_rules(id,domain,match_type,effect,source,"
        "scope_type,attribution,enabled,updated_at,target,revision,category,"
        "enforcement,statistics_id) VALUES(1,'example.test','exact','block',"
        "'explicit','global','database export test',1,10,'dns',1,'',"
        "'enforce',x'01000000000000000000000000000001');"
        "INSERT INTO policy_rule_stats(dimension,statistics_id,rule_id,"
        "match_count,"
        "decision_count,would_block_count,enforced_block_count,"
        "allow_decision_count,shadowed_count,first_hit_at,last_hit_at)"
        " VALUES('domain',x'01000000000000000000000000000001',1,3,2,1,1,"
        "1,1,10,20);"
        "INSERT INTO policy_traffic_stats(id,request_count,matched_count,"
        "would_block_count,enforced_block_count,first_request_at,"
        "last_request_at) VALUES(1,4,3,1,1,10,20);"
        "INSERT INTO policy_impact_buckets(bucket_start,dimension,"
        "statistics_id,rule_id,"
        "path,client_family,client_address,client_mac,vlan_id,domain,"
        "query_type,match_count,decision_count,would_block_count,"
        "enforced_block_count,allow_decision_count,shadowed_count)"
        " VALUES(0,'domain',x'01000000000000000000000000000001',1,'dns',4,"
        "x'c000020a',x'001122334455',7,"
        "'example.test',1,3,2,1,1,1,1);"
        "INSERT INTO policy_traffic_buckets(bucket_start,path,request_count,"
        "matched_count,would_block_count,enforced_block_count)"
        " VALUES(0,'dns',4,3,1,1);";
    static const char *const private_tables[] = {
        "users",
        "user_roles",
        "api_tokens",
        "web_sessions",
        "totp_credentials",
        "recovery_codes",
        "mtls_mappings",
        "bootstrap_credentials",
        "audit_events",
        "operational_events",
        "backup_metadata",
        "management_operations",
        "policy_rule_stats",
        "policy_traffic_stats",
        "policy_impact_buckets",
        "policy_traffic_buckets",
    };
    char directory[64U];
    char path[512U];
    struct jg_database *database = NULL;
    struct jg_database_restore_report report;
    sqlite3 *writer = NULL;
    sqlite3 *snapshot = NULL;
    uint8_t *data = NULL;
    uint8_t *full_data = NULL;
    uint8_t *inspection_data = NULL;
    size_t data_size = 0U;
    size_t full_data_size = 0U;
    size_t inspection_data_size = 0U;
    size_t index = 0U;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    jg_database_close(database);
    database = NULL;
    assert_int_equal(sqlite3_open(path, &writer), SQLITE_OK);
    assert_int_equal(sqlite3_exec(writer, sensitive_records, NULL, NULL, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_close(writer), SQLITE_OK);
    writer = NULL;
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);

    assert_int_equal(jg_database_export(database, true, &data, &data_size), 0);
    snapshot = open_snapshot(data, data_size);
    for (index = 0U;
         index < sizeof(private_tables) / sizeof(private_tables[0U]); ++index) {
        assert_int_equal(row_count(snapshot, private_tables[index]), 1);
    }
    assert_int_equal(row_count(snapshot, "system_settings"), 1);
    assert_int_equal(sqlite3_close(snapshot), SQLITE_OK);
    snapshot = NULL;
    jg_database_export_clear(data, data_size);
    data = NULL;
    data_size = 0U;

    assert_int_equal(jg_database_export(database, false, &data, &data_size), 0);
    snapshot = open_snapshot(data, data_size);
    for (index = 0U;
         index < sizeof(private_tables) / sizeof(private_tables[0U]); ++index) {
        assert_int_equal(row_count(snapshot, private_tables[index]), 0);
    }
    assert_int_equal(row_count(snapshot, "system_settings"), 1);
    assert_int_equal(sqlite3_close(snapshot), SQLITE_OK);
    assert_false(snapshot_contains(data, data_size,
                                   (const uint8_t *)"secret-hash",
                                   sizeof("secret-hash") - 1U));

    assert_int_equal(sqlite3_open(path, &writer), SQLITE_OK);
    assert_int_equal(
        sqlite3_exec(writer,
                     "UPDATE system_settings SET value='changed';"
                     "UPDATE users SET password_hash='current-hash';"
                     "UPDATE policy_rule_stats SET match_count=9;",
                     NULL, NULL, NULL),
        SQLITE_OK);
    assert_int_equal(sqlite3_close(writer), SQLITE_OK);
    writer = NULL;
    assert_int_equal(
        jg_database_restore(database, data, data_size, false, true, &report),
        0);
    assert_true(report.changes);
    assert_int_equal(report.schema_version, JG_DATABASE_SCHEMA_VERSION);
    assert_int_equal(jg_database_export(database, true, &inspection_data,
                                        &inspection_data_size),
                     0);
    snapshot = open_snapshot(inspection_data, inspection_data_size);
    assert_text_value(snapshot,
                      "SELECT value FROM system_settings"
                      " WHERE key='appliance.name';",
                      "changed");
    assert_int_equal(sqlite3_close(snapshot), SQLITE_OK);
    snapshot = NULL;
    jg_database_export_clear(inspection_data, inspection_data_size);
    inspection_data = NULL;
    inspection_data_size = 0U;

    assert_int_equal(
        jg_database_restore(database, data, data_size, false, false, &report),
        0);
    assert_true(report.changes);
    assert_int_equal(
        jg_database_export(database, true, &full_data, &full_data_size), 0);
    snapshot = open_snapshot(full_data, full_data_size);
    assert_text_value(snapshot,
                      "SELECT value FROM system_settings"
                      " WHERE key='appliance.name';",
                      "gateway");
    assert_text_value(snapshot, "SELECT password_hash FROM users WHERE id=1;",
                      "current-hash");
    assert_int_equal(row_count(snapshot, "management_operations"), 1);
    assert_integer_value(snapshot,
                         "SELECT match_count FROM policy_rule_stats WHERE "
                         "dimension='domain' AND rule_id=1;",
                         9);
    assert_int_equal(sqlite3_close(snapshot), SQLITE_OK);
    snapshot = NULL;
    jg_database_export_clear(data, data_size);
    data = NULL;
    data_size = 0U;

    assert_int_equal(sqlite3_open(path, &writer), SQLITE_OK);
    assert_int_equal(
        sqlite3_exec(
            writer,
            "UPDATE system_settings SET value='changed-again';"
            "UPDATE users SET password_hash='replacement-hash';"
            "UPDATE policy_rule_stats SET match_count=11;"
            "INSERT INTO backup_metadata(id,created_at,kind,path,"
            "checksum,schema_version,size_bytes) VALUES("
            "2,20,'full','backup-2.jgb',zeroblob(32),9,200);"
            "INSERT INTO audit_events(id,occurred_at,actor_type,"
            "action,object_type,details,event_hash) VALUES("
            "2,20,'system','restore','database','{}',"
            "x'"
            "0100000000000000000000000000000000000000000000000000000000000000'"
            ");"
            "INSERT INTO operational_events(id,occurred_at,severity,"
            "component,code,message,details) VALUES("
            "2,20,'info','database','restore','restore','{}');",
            NULL, NULL, NULL),
        SQLITE_OK);
    assert_int_equal(sqlite3_close(writer), SQLITE_OK);
    writer = NULL;
    assert_int_equal(jg_database_restore(database, full_data, full_data_size,
                                         true, false, &report),
                     0);
    assert_true(report.changes);
    jg_database_export_clear(full_data, full_data_size);
    full_data = NULL;
    full_data_size = 0U;
    assert_int_equal(jg_database_export(database, true, &inspection_data,
                                        &inspection_data_size),
                     0);
    snapshot = open_snapshot(inspection_data, inspection_data_size);
    assert_text_value(snapshot,
                      "SELECT value FROM system_settings"
                      " WHERE key='appliance.name';",
                      "gateway");
    assert_text_value(snapshot, "SELECT password_hash FROM users WHERE id=1;",
                      "current-hash");
    assert_int_equal(row_count(snapshot, "backup_metadata"), 2);
    assert_int_equal(row_count(snapshot, "audit_events"), 2);
    assert_int_equal(row_count(snapshot, "operational_events"), 2);
    assert_integer_value(snapshot,
                         "SELECT match_count FROM policy_rule_stats WHERE "
                         "dimension='domain' AND rule_id=1;",
                         9);
    assert_int_equal(sqlite3_close(snapshot), SQLITE_OK);
    jg_database_export_clear(inspection_data, inspection_data_size);

    assert_int_equal(jg_database_export(NULL, false, &data, &data_size),
                     -EINVAL);
    assert_int_equal(jg_database_export(database, false, NULL, &data_size),
                     -EINVAL);
    assert_int_equal(jg_database_export(database, false, &data, NULL), -EINVAL);
    assert_int_equal(
        jg_database_restore(NULL, data, data_size, false, false, &report),
        -EINVAL);
    assert_int_equal(
        jg_database_restore(database, NULL, 0U, false, false, &report),
        -EINVAL);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify persistent backup metadata creation and pagination. */
static void test_backup_metadata(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_database *database = NULL;
    struct jg_database_backup input = {
        .id = 0U,
        .created_at = 100U,
        .kind = JG_BACKUP_CONFIGURATION,
        .filename = "backup-1.jgb",
        .schema_version = JG_DATABASE_SCHEMA_VERSION,
        .size_bytes = 4096U,
    };
    struct jg_database_backup created;
    struct jg_database_backup loaded;
    struct jg_database_backup page[1U];
    size_t count = 0U;
    bool has_more = false;
    bool exists = false;
    size_t index = 0U;

    (void)state;
    for (index = 0U; index < sizeof(input.checksum); ++index) {
        input.checksum[index] = (uint8_t)index;
    }
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_create_backup(database, &input, &created), 0);
    assert_true(created.id > 0U);
    assert_string_equal(created.filename, input.filename);
    assert_int_equal(jg_database_load_backup(database, created.id, &loaded), 0);
    assert_int_equal(loaded.id, created.id);
    assert_int_equal(loaded.kind, JG_BACKUP_CONFIGURATION);
    assert_int_equal(loaded.created_at, input.created_at);
    assert_int_equal(loaded.schema_version, input.schema_version);
    assert_int_equal(loaded.size_bytes, input.size_bytes);
    assert_memory_equal(loaded.checksum, input.checksum,
                        sizeof(input.checksum));
    assert_int_equal(
        jg_database_backup_filename_exists(database, input.filename, &exists),
        0);
    assert_true(exists);
    assert_int_equal(jg_database_backup_filename_exists(
                         database, "backup-missing.jgb", &exists),
                     0);
    assert_false(exists);

    input.created_at = 200U;
    input.kind = JG_BACKUP_FULL;
    (void)snprintf(input.filename, sizeof(input.filename), "backup-2.jgb");
    assert_int_equal(jg_database_create_backup(database, &input, &created), 0);
    assert_int_equal(
        jg_database_list_backups(database, 0U, 1U, page, &count, &has_more), 0);
    assert_int_equal(count, 1U);
    assert_true(has_more);
    assert_int_equal(page[0U].kind, JG_BACKUP_CONFIGURATION);
    assert_int_equal(jg_database_list_backups(database, page[0U].id, 1U, page,
                                              &count, &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_false(has_more);
    assert_int_equal(page[0U].kind, JG_BACKUP_FULL);
    assert_int_equal(jg_database_load_backup(database, UINT64_MAX, &loaded),
                     -EINVAL);
    assert_int_equal(
        jg_database_load_backup(database, created.id + 1U, &loaded), -ENOENT);
    input.id = 1U;
    assert_int_equal(jg_database_create_backup(database, &input, &created),
                     -EINVAL);
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
    assert_true(table_exists(inspection, "network_configuration"));
    assert_true(column_exists(inspection, "network_configuration", "revision"));
    assert_true(table_exists(inspection, "logging_configuration"));
    assert_true(column_exists(inspection, "logging_configuration", "revision"));
    assert_true(table_exists(inspection, "policy_configuration"));
    assert_true(table_exists(inspection, "policy_scope_modes"));
    assert_true(table_exists(inspection, "policy_statistics_configuration"));
    assert_true(table_exists(inspection, "policy_rule_stats"));
    assert_true(table_exists(inspection, "policy_traffic_stats"));
    assert_true(table_exists(inspection, "policy_impact_buckets"));
    assert_true(table_exists(inspection, "policy_traffic_buckets"));
    assert_true(column_exists(inspection, "policy_groups", "enforcement"));
    assert_true(column_exists(inspection, "blocklist_sources", "enforcement"));
    assert_true(column_exists(inspection, "domain_rules", "enforcement"));
    assert_true(column_exists(inspection, "destination_rules", "enforcement"));
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

/** @brief Verify global and scoped policy-mode persistence. */
static void test_policy_modes(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_database_policy_config global;
    struct jg_database_policy_scope_mode_config config;
    struct jg_database_policy_scope_mode first;
    struct jg_database_policy_scope_mode second;
    struct jg_database_policy_scope_mode page[1U];
    struct jg_policy_rule_input rule;
    struct jg_policy_client client;
    struct jg_policy_match match;
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_database *database = NULL;
    uint64_t first_id = 0U;
    uint64_t first_revision = 0U;
    size_t count = 0U;
    bool has_more = false;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);

    assert_int_equal(jg_database_load_policy_config(database, &global), 0);
    assert_int_equal(global.enforcement, JG_POLICY_ENFORCE);
    assert_int_equal(global.revision, 1U);
    assert_int_equal(jg_database_replace_policy_config(
                         database, JG_POLICY_OBSERVE, global.revision, &global),
                     0);
    assert_int_equal(global.enforcement, JG_POLICY_OBSERVE);
    assert_int_equal(global.revision, 2U);
    rule = make_rule(1U, "preview.example", true, JG_POLICY_BLOCK,
                     JG_POLICY_SOURCE_EXPLICIT);
    assert_int_equal(jg_database_replace_domain_rules(database, &rule, 1U), 0);
    assert_int_equal(jg_database_load_policy_snapshot(database, 1U, &snapshot),
                     0);
    assert_int_equal(
        jg_policy_match_domain(snapshot, "host.preview.example", NULL, &match),
        0);
    assert_true(match.would_have_blocked);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    jg_policy_snapshot_destroy(snapshot);
    snapshot = NULL;
    assert_int_equal(jg_database_replace_policy_config(
                         database, JG_POLICY_ENFORCE, global.revision, &global),
                     0);
    assert_int_equal(global.revision, 3U);
    assert_int_equal(jg_database_replace_policy_config(
                         database, JG_POLICY_OBSERVE, 2U, &global),
                     -EAGAIN);
    assert_int_equal(
        jg_database_replace_policy_config(
            database, (enum jg_policy_enforcement)99, global.revision, &global),
        -EINVAL);

    (void)memset(&config, 0, sizeof(config));
    config.name = "VLAN 30 preview";
    config.enforcement = JG_POLICY_OBSERVE;
    config.scope.type = JG_POLICY_SCOPE_VLAN;
    config.scope.value.vlan_id = 30U;
    config.enabled = true;
    assert_int_equal(
        jg_database_create_policy_scope_mode(database, &config, &first), 0);
    assert_int_equal(first.revision, 1U);
    assert_string_equal(first.name, config.name);
    assert_int_equal(first.enforcement, JG_POLICY_OBSERVE);
    assert_int_equal(first.scope.value.vlan_id, 30U);
    assert_true(first.enabled);
    assert_int_equal(jg_database_load_policy_snapshot(database, 2U, &snapshot),
                     0);
    (void)memset(&client, 0, sizeof(client));
    client.has_vlan = true;
    client.vlan_id = 30U;
    assert_int_equal(
        jg_policy_match_domain(snapshot, "preview.example", &client, &match),
        0);
    assert_true(match.would_have_blocked);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    client.vlan_id = 31U;
    assert_int_equal(
        jg_policy_match_domain(snapshot, "preview.example", &client, &match),
        0);
    assert_false(match.would_have_blocked);
    assert_int_equal(match.effect, JG_POLICY_BLOCK);
    jg_policy_snapshot_destroy(snapshot);
    snapshot = NULL;
    assert_int_equal(
        jg_database_create_policy_scope_mode(database, &config, &second),
        -EEXIST);

    config.name = "Lab clients";
    config.scope.type = JG_POLICY_SCOPE_IPV4;
    config.scope.value.network.address[0U] = 192U;
    config.scope.value.network.address[1U] = 0U;
    config.scope.value.network.address[2U] = 2U;
    config.scope.value.network.address[3U] = 129U;
    config.scope.value.network.prefix_length = 24U;
    assert_int_equal(
        jg_database_create_policy_scope_mode(database, &config, &second), 0);
    assert_int_equal(second.scope.value.network.address[3U], 0U);
    assert_int_equal(jg_database_list_policy_scope_modes(database, 0U, 1U, page,
                                                         &count, &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_true(has_more);
    assert_int_equal(page[0U].id, first.id);
    assert_int_equal(jg_database_list_policy_scope_modes(
                         database, first.id, 1U, page, &count, &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_false(has_more);
    assert_int_equal(page[0U].id, second.id);

    (void)memset(&config, 0, sizeof(config));
    config.name = "VLAN 31 enforced";
    config.enforcement = JG_POLICY_ENFORCE;
    config.scope.type = JG_POLICY_SCOPE_VLAN;
    config.scope.value.vlan_id = 31U;
    assert_int_equal(jg_database_update_policy_scope_mode(
                         database, first.id, &config, first.revision, &first),
                     0);
    assert_int_equal(first.revision, 2U);
    assert_false(first.enabled);
    first_id = first.id;
    first_revision = first.revision;
    assert_int_equal(jg_database_update_policy_scope_mode(database, first_id,
                                                          &config, 1U, &first),
                     -EAGAIN);
    assert_int_equal(
        jg_database_delete_policy_scope_mode(database, first_id, 1U), -EAGAIN);
    assert_int_equal(jg_database_delete_policy_scope_mode(database, first_id,
                                                          first_revision),
                     0);
    assert_int_equal(jg_database_delete_policy_scope_mode(database, first_id,
                                                          first_revision),
                     -ENOENT);

    config.name = "invalid global";
    config.scope.type = JG_POLICY_SCOPE_GLOBAL;
    assert_int_equal(
        jg_database_create_policy_scope_mode(database, &config, &first),
        -EINVAL);
    assert_int_equal(jg_database_list_policy_scope_modes(database, 0U, 0U, page,
                                                         &count, &has_more),
                     -EINVAL);

    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify policy-group observation, promotion, and disabling. */
static void test_policy_groups(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_database_policy_group_config config = {
        .name = "Staged security rules",
        .description = "Rules awaiting impact review",
        .enforcement = JG_POLICY_OBSERVE,
        .enabled = true,
    };
    struct jg_database_policy_group group;
    struct jg_database_policy_group updated;
    struct jg_database_policy_group page[1U];
    struct jg_database_domain_rule domain_page[1U];
    struct jg_database_destination_rule destination_page[1U];
    struct jg_policy_rule_input rule;
    struct jg_policy_destination_rule_input destination_rule;
    struct jg_policy_destination destination = {
        .transport = JG_POLICY_TRANSPORT_TCP,
        .address_family = JG_POLICY_ADDRESS_IPV4,
        .address = {203U, 0U, 113U, 45U},
        .port = 443U,
    };
    struct jg_policy_match match;
    struct jg_policy_destination_match destination_match;
    struct jg_policy_snapshot_info info;
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_database *database = NULL;
    size_t count = 0U;
    bool has_more = false;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_create_policy_group(database, &config, &group),
                     0);
    assert_true(group.id > 0U);
    assert_int_equal(group.revision, 1U);
    assert_string_equal(group.name, config.name);
    assert_string_equal(group.description, config.description);
    assert_int_equal(group.enforcement, JG_POLICY_OBSERVE);
    assert_true(group.enabled);
    assert_int_equal(
        jg_database_create_policy_group(database, &config, &updated), -EEXIST);

    rule = make_rule(40U, "staged.example", true, JG_POLICY_BLOCK,
                     JG_POLICY_SOURCE_EXPLICIT);
    rule.group_id = group.id;
    assert_int_equal(jg_database_replace_domain_rules(database, &rule, 1U), 0);
    destination_rule = make_destination_rule(50U, JG_POLICY_BLOCK);
    destination_rule.group_id = group.id;
    destination_rule.has_port = true;
    destination_rule.port = 443U;
    assert_int_equal(
        jg_database_replace_destination_rules(database, &destination_rule, 1U),
        0);
    assert_int_equal(jg_database_list_policy_groups(database, 0U, 1U, page,
                                                    &count, &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_false(has_more);
    assert_int_equal(page[0U].domain_rule_count, 1U);
    assert_int_equal(page[0U].destination_rule_count, 1U);
    assert_int_equal(jg_database_list_domain_rules(
                         database, 0U, 1U, domain_page, &count, &has_more),
                     0);
    assert_int_equal(domain_page[0U].group_id, group.id);
    assert_int_equal(jg_database_list_destination_rules(
                         database, 0U, 1U, destination_page, &count, &has_more),
                     0);
    assert_int_equal(destination_page[0U].group_id, group.id);

    assert_int_equal(jg_database_load_policy_snapshot(database, 1U, &snapshot),
                     0);
    assert_int_equal(
        jg_policy_match_domain(snapshot, "host.staged.example", NULL, &match),
        0);
    assert_true(match.would_have_blocked);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    assert_int_equal(jg_policy_match_destination(snapshot, &destination, NULL,
                                                 &destination_match),
                     0);
    assert_true(destination_match.would_have_blocked);
    assert_int_equal(destination_match.effect, JG_POLICY_ALLOW);
    jg_policy_snapshot_destroy(snapshot);
    snapshot = NULL;

    config.enforcement = JG_POLICY_ENFORCE;
    assert_int_equal(jg_database_update_policy_group(
                         database, group.id, &config, group.revision, &updated),
                     0);
    assert_int_equal(updated.revision, 2U);
    assert_int_equal(jg_database_load_policy_snapshot(database, 2U, &snapshot),
                     0);
    assert_int_equal(
        jg_policy_match_domain(snapshot, "staged.example", NULL, &match), 0);
    assert_false(match.would_have_blocked);
    assert_int_equal(match.effect, JG_POLICY_BLOCK);
    jg_policy_snapshot_destroy(snapshot);
    snapshot = NULL;

    config.enabled = false;
    assert_int_equal(jg_database_update_policy_group(database, group.id,
                                                     &config, updated.revision,
                                                     &updated),
                     0);
    assert_int_equal(updated.revision, 3U);
    assert_int_equal(jg_database_load_policy_snapshot(database, 3U, &snapshot),
                     0);
    assert_int_equal(jg_policy_snapshot_get_info(snapshot, &info), 0);
    assert_int_equal(info.rule_count, 0U);
    assert_int_equal(info.destination_rule_count, 0U);
    jg_policy_snapshot_destroy(snapshot);

    assert_int_equal(jg_database_delete_policy_group(database, group.id, 2U),
                     -EAGAIN);
    assert_int_equal(
        jg_database_delete_policy_group(database, group.id, updated.revision),
        0);
    assert_int_equal(jg_database_list_domain_rules(
                         database, 0U, 1U, domain_page, &count, &has_more),
                     0);
    assert_int_equal(count, 0U);
    assert_int_equal(jg_database_list_destination_rules(
                         database, 0U, 1U, destination_page, &count, &has_more),
                     0);
    assert_int_equal(count, 0U);
    config.name = "";
    assert_int_equal(jg_database_create_policy_group(database, &config, &group),
                     -EINVAL);

    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify policy-statistic aggregation and bounded detail cleanup. */
static void test_policy_statistics(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_policy_traffic_sample traffic[2U] = {
        {
            .occurred_at = 3600U,
            .path = JG_POLICY_STATS_DNS,
            .matched = true,
            .would_block = true,
        },
        {
            .occurred_at = 5184000U,
            .path = JG_POLICY_STATS_DNS,
            .matched = true,
            .would_block = true,
            .enforced_block = true,
        },
    };
    struct jg_policy_rule_sample rules[4U] = {
        {
            .occurred_at = 3600U,
            .dimension = JG_POLICY_STATS_DOMAIN,
            .rule_id = 10U,
            .path = JG_POLICY_STATS_DNS,
            .domain = "blocked.example",
            .query_type = 1U,
            .decision = true,
            .would_block = true,
        },
        {
            .occurred_at = 5184000U,
            .dimension = JG_POLICY_STATS_DOMAIN,
            .rule_id = 10U,
            .path = JG_POLICY_STATS_DNS,
            .domain = "blocked.example",
            .query_type = 1U,
            .decision = true,
            .would_block = true,
            .enforced_block = true,
        },
        {
            .occurred_at = 5184000U,
            .dimension = JG_POLICY_STATS_DOMAIN,
            .rule_id = 11U,
            .path = JG_POLICY_STATS_DNS,
            .domain = "allowed.example",
            .query_type = 28U,
            .decision = true,
            .allow_decision = true,
        },
        {
            .occurred_at = 5184000U,
            .dimension = JG_POLICY_STATS_DESTINATION,
            .rule_id = 20U,
            .path = JG_POLICY_STATS_NETWORK_DESTINATION,
            .domain = "",
            .would_block = true,
            .enforced_block = true,
            .shadowed = true,
        },
    };
    struct jg_policy_rule_sample invalid_rule;
    struct jg_policy_traffic_sample invalid_traffic;
    struct jg_policy_stats_config config;
    struct jg_policy_traffic_stats traffic_stats;
    struct jg_policy_rule_stats rule_stats[2U];
    struct jg_policy_stats_cleanup_report report;
    struct jg_database *database = NULL;
    size_t count = 0U;
    bool has_more = false;

    (void)state;
    rules[0U].statistics_id[0U] = 1U;
    rules[0U].statistics_id[15U] = 10U;
    rules[1U].statistics_id[0U] = 1U;
    rules[1U].statistics_id[15U] = 10U;
    rules[2U].statistics_id[0U] = 1U;
    rules[2U].statistics_id[15U] = 11U;
    rules[3U].statistics_id[0U] = 2U;
    rules[3U].statistics_id[15U] = 20U;
    rules[0U].client.has_mac = true;
    rules[0U].client.mac[0U] = 0x02U;
    rules[0U].client.address_family = JG_POLICY_ADDRESS_IPV4;
    rules[0U].client.address[0U] = 192U;
    rules[0U].client.address[1U] = 0U;
    rules[0U].client.address[2U] = 2U;
    rules[0U].client.address[3U] = 10U;
    rules[0U].client.has_vlan = true;
    rules[0U].client.vlan_id = 30U;
    rules[1U].client = rules[0U].client;
    rules[2U].client = rules[0U].client;
    rules[3U].client = rules[0U].client;

    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(
        jg_database_load_policy_traffic_stats(database, &traffic_stats),
        -ENOENT);
    assert_int_equal(jg_database_load_policy_stats_config(database, &config),
                     0);
    assert_true(config.retention_enabled);
    assert_int_equal(config.retention_months,
                     JG_POLICY_STATS_RETENTION_DEFAULT);
    assert_int_equal(config.revision, 1U);
    assert_int_equal(jg_database_update_policy_stats_config(database, true, 1U,
                                                            config.revision,
                                                            7000000U, &config),
                     0);
    assert_int_equal(config.retention_months, 1U);
    assert_int_equal(config.revision, 2U);
    assert_int_equal(config.updated_at, 7000000U);
    assert_int_equal(jg_database_update_policy_stats_config(
                         database, true, 1U, 1U, 7000001U, &config),
                     -EAGAIN);
    assert_int_equal(jg_database_update_policy_stats_config(
                         database, true, 0U, 2U, 7000001U, &config),
                     -EINVAL);

    assert_int_equal(
        jg_database_record_policy_stats(database, traffic, 2U, rules, 4U), 0);
    assert_int_equal(
        jg_database_load_policy_traffic_stats(database, &traffic_stats), 0);
    assert_int_equal(traffic_stats.request_count, 2U);
    assert_int_equal(traffic_stats.matched_count, 2U);
    assert_int_equal(traffic_stats.would_block_count, 2U);
    assert_int_equal(traffic_stats.enforced_block_count, 1U);
    assert_int_equal(traffic_stats.first_request_at, 3600U);
    assert_int_equal(traffic_stats.last_request_at, 5184000U);
    assert_int_equal(
        jg_database_list_policy_rule_stats(database, JG_POLICY_STATS_DOMAIN, 0U,
                                           2U, rule_stats, &count, &has_more),
        0);
    assert_int_equal(count, 2U);
    assert_false(has_more);
    assert_int_equal(rule_stats[0U].rule_id, 10U);
    assert_int_equal(rule_stats[0U].match_count, 2U);
    assert_int_equal(rule_stats[0U].decision_count, 2U);
    assert_int_equal(rule_stats[0U].would_block_count, 2U);
    assert_int_equal(rule_stats[0U].enforced_block_count, 1U);
    assert_int_equal(rule_stats[0U].allow_decision_count, 0U);
    assert_int_equal(rule_stats[0U].shadowed_count, 0U);
    assert_int_equal(rule_stats[0U].first_hit_at, 3600U);
    assert_int_equal(rule_stats[0U].last_hit_at, 5184000U);
    assert_int_equal(rule_stats[1U].rule_id, 11U);
    assert_int_equal(rule_stats[1U].match_count, 1U);
    assert_int_equal(rule_stats[1U].allow_decision_count, 1U);
    assert_int_equal(jg_database_list_policy_rule_stats(
                         database, JG_POLICY_STATS_DESTINATION, 0U, 1U,
                         rule_stats, &count, &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_int_equal(rule_stats[0U].rule_id, 20U);
    assert_int_equal(rule_stats[0U].decision_count, 0U);
    assert_int_equal(rule_stats[0U].enforced_block_count, 1U);
    assert_int_equal(rule_stats[0U].shadowed_count, 1U);

    invalid_traffic = traffic[1U];
    invalid_traffic.would_block = false;
    assert_int_equal(jg_database_record_policy_stats(database, &invalid_traffic,
                                                     1U, NULL, 0U),
                     -EINVAL);
    invalid_rule = rules[0U];
    invalid_rule.shadowed = true;
    assert_int_equal(
        jg_database_record_policy_stats(database, NULL, 0U, &invalid_rule, 1U),
        -EINVAL);
    assert_int_equal(
        jg_database_record_policy_stats(database, NULL, 0U, NULL, 0U), -EINVAL);

    assert_int_equal(
        jg_database_preview_policy_stats_cleanup(database, 7776000U, &report),
        0);
    assert_int_equal(report.cutoff_at, 5097600U);
    assert_int_equal(report.impact_rows, 1U);
    assert_int_equal(report.traffic_rows, 1U);
    assert_false(report.complete);
    assert_int_equal(
        jg_database_cleanup_policy_stats(database, 7776000U, 1U, &report), 0);
    assert_int_equal(report.deleted_impact_rows, 1U);
    assert_int_equal(report.deleted_traffic_rows, 0U);
    assert_false(report.complete);
    assert_int_equal(row_count(database->handle, "policy_impact_buckets"), 3U);
    assert_int_equal(row_count(database->handle, "policy_traffic_buckets"), 2U);
    assert_int_equal(
        jg_database_cleanup_policy_stats(database, 7776000U, 1U, &report), 0);
    assert_int_equal(report.deleted_impact_rows, 0U);
    assert_int_equal(report.deleted_traffic_rows, 1U);
    assert_true(report.complete);
    assert_int_equal(row_count(database->handle, "policy_impact_buckets"), 3U);
    assert_int_equal(row_count(database->handle, "policy_traffic_buckets"), 1U);
    assert_int_equal(jg_database_load_policy_stats_config(database, &config),
                     0);
    assert_int_equal(config.last_cleanup_at, 7776000U);
    assert_int_equal(
        jg_database_load_policy_traffic_stats(database, &traffic_stats), 0);
    assert_int_equal(traffic_stats.request_count, 2U);
    assert_int_equal(
        jg_database_list_policy_rule_stats(database, JG_POLICY_STATS_DOMAIN, 0U,
                                           2U, rule_stats, &count, &has_more),
        0);
    assert_int_equal(rule_stats[0U].match_count, 2U);

    assert_int_equal(
        jg_database_cleanup_policy_stats(database, 7776000U, 0U, &report),
        -EINVAL);
    assert_int_equal(jg_database_list_policy_rule_stats(
                         database, (enum jg_policy_stats_dimension)99, 0U, 1U,
                         rule_stats, &count, &has_more),
                     -EINVAL);
    assert_int_equal(
        sqlite3_exec(database->handle,
                     "UPDATE policy_rule_stats SET enforced_block_count=3 "
                     "WHERE dimension='domain' AND rule_id=10;",
                     NULL, NULL, NULL),
        SQLITE_OK);
    assert_int_equal(
        jg_database_list_policy_rule_stats(database, JG_POLICY_STATS_DOMAIN, 0U,
                                           2U, rule_stats, &count, &has_more),
        -EILSEQ);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify retained impact and conservative rule relationships. */
static void test_policy_analysis(void **state)
{
    char directory[64U];
    char path[512U];
    struct jg_policy_rule_input domain_rules[4U];
    struct jg_policy_destination_rule_input destination_rules[3U];
    struct jg_policy_rule_input disabled_input;
    struct jg_database_domain_rule disabled_rule;
    struct jg_policy_rule_sample samples[3U] = {
        {
            .occurred_at = 3600U,
            .dimension = JG_POLICY_STATS_DOMAIN,
            .rule_id = 10U,
            .path = JG_POLICY_STATS_DNS,
            .domain = "first.example.org",
            .query_type = 1U,
            .decision = true,
            .would_block = true,
            .enforced_block = true,
        },
        {
            .occurred_at = 7200U,
            .dimension = JG_POLICY_STATS_DOMAIN,
            .rule_id = 10U,
            .path = JG_POLICY_STATS_TLS_SNI,
            .domain = "second.example.org",
            .decision = true,
            .would_block = true,
        },
        {
            .occurred_at = 7200U,
            .dimension = JG_POLICY_STATS_DESTINATION,
            .rule_id = 20U,
            .path = JG_POLICY_STATS_NETWORK_DESTINATION,
            .domain = "",
            .decision = true,
            .would_block = true,
            .enforced_block = true,
        },
    };
    struct jg_policy_rule_stats stats;
    struct jg_policy_rule_impact impact;
    struct jg_policy_client_impact clients[2U];
    struct jg_policy_rule_relations relations;
    struct jg_database *database = NULL;
    size_t client_count = 0U;
    bool has_stats = false;

    (void)state;
    domain_rules[0U] = make_rule(10U, "example.org", true, JG_POLICY_BLOCK,
                                 JG_POLICY_SOURCE_BLOCKLIST);
    domain_rules[1U] = make_rule(11U, "safe.example.org", false,
                                 JG_POLICY_ALLOW, JG_POLICY_SOURCE_EXPLICIT);
    domain_rules[2U] = domain_rules[0U];
    domain_rules[2U].id = 12U;
    domain_rules[2U].statistics_id[15U] = 12U;
    domain_rules[3U] = make_rule(13U, "example.org", true, JG_POLICY_ALLOW,
                                 JG_POLICY_SOURCE_EXPLICIT);
    destination_rules[0U] = make_destination_rule(20U, JG_POLICY_BLOCK);
    destination_rules[0U].has_port = true;
    destination_rules[0U].port = 443U;
    destination_rules[1U] = destination_rules[0U];
    destination_rules[1U].id = 21U;
    destination_rules[1U].statistics_id[15U] = 21U;
    destination_rules[2U] = make_destination_rule(22U, JG_POLICY_ALLOW);
    destination_rules[2U].has_port = true;
    destination_rules[2U].port = 443U;
    (void)memcpy(samples[0U].statistics_id, domain_rules[0U].statistics_id,
                 sizeof(samples[0U].statistics_id));
    (void)memcpy(samples[1U].statistics_id, domain_rules[0U].statistics_id,
                 sizeof(samples[1U].statistics_id));
    (void)memcpy(samples[2U].statistics_id, destination_rules[0U].statistics_id,
                 sizeof(samples[2U].statistics_id));
    disabled_input = make_rule(0U, "disabled.example", false, JG_POLICY_BLOCK,
                               JG_POLICY_SOURCE_EXPLICIT);

    samples[0U].client.address_family = JG_POLICY_ADDRESS_IPV4;
    samples[0U].client.address[0U] = 192U;
    samples[0U].client.address[1U] = 0U;
    samples[0U].client.address[2U] = 2U;
    samples[0U].client.address[3U] = 10U;
    samples[0U].client.has_vlan = true;
    samples[0U].client.vlan_id = 30U;
    samples[1U].client = samples[0U].client;
    samples[1U].client.address[3U] = 11U;
    samples[1U].client.vlan_id = 31U;
    samples[2U].client = samples[0U].client;

    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(
        jg_database_replace_domain_rules(database, domain_rules, 4U), 0);
    assert_int_equal(
        jg_database_replace_destination_rules(database, destination_rules, 3U),
        0);
    assert_int_equal(jg_database_create_domain_rule(database, &disabled_input,
                                                    false, &disabled_rule),
                     0);
    assert_int_equal(
        jg_database_record_policy_stats(database, NULL, 0U, samples, 3U), 0);

    assert_int_equal(jg_database_load_policy_rule_impact(
                         database, JG_POLICY_STATS_DOMAIN, 10U, &stats,
                         &has_stats, &impact, clients, 2U, &client_count),
                     0);
    assert_true(has_stats);
    assert_int_equal(stats.match_count, 2U);
    assert_int_equal(stats.would_block_count, 2U);
    assert_int_equal(stats.enforced_block_count, 1U);
    assert_int_equal(impact.distinct_client_count, 2U);
    assert_int_equal(impact.distinct_vlan_count, 2U);
    assert_int_equal(impact.distinct_domain_count, 2U);
    assert_int_equal(impact.dns_match_count, 1U);
    assert_int_equal(impact.tls_sni_match_count, 1U);
    assert_int_equal(impact.destination_match_count, 0U);
    assert_int_equal(client_count, 2U);
    assert_int_equal(clients[0U].address[3U], 11U);
    assert_int_equal(clients[0U].vlan_id, 31U);
    assert_int_equal(clients[0U].last_hit_at, 7200U);
    assert_int_equal(clients[1U].address[3U], 10U);
    assert_int_equal(clients[1U].vlan_id, 30U);

    assert_int_equal(jg_database_load_policy_rule_impact(
                         database, JG_POLICY_STATS_DOMAIN, 11U, &stats,
                         &has_stats, &impact, clients, 2U, &client_count),
                     0);
    assert_false(has_stats);
    assert_int_equal(impact.distinct_client_count, 0U);
    assert_int_equal(client_count, 0U);

    assert_int_equal(jg_database_analyze_policy_rule(
                         database, JG_POLICY_STATS_DOMAIN, 10U, &relations),
                     0);
    assert_int_equal(relations.duplicate_count, 1U);
    assert_int_equal(relations.duplicate_ids[0U], 12U);
    assert_int_equal(relations.conflict_count, 1U);
    assert_int_equal(relations.conflict_ids[0U], 13U);
    assert_int_equal(relations.shadowing_count, 1U);
    assert_int_equal(relations.shadowing_ids[0U], 13U);
    assert_int_equal(relations.allow_exception_count, 2U);
    assert_int_equal(relations.allow_exception_ids[0U], 11U);
    assert_int_equal(relations.allow_exception_ids[1U], 13U);
    assert_false(relations.unreachable);
    assert_false(relations.truncated);

    assert_int_equal(jg_database_analyze_policy_rule(
                         database, JG_POLICY_STATS_DOMAIN, 12U, &relations),
                     0);
    assert_true(relations.unreachable);
    assert_false(relations.disabled);
    assert_int_equal(
        jg_database_analyze_policy_rule(database, JG_POLICY_STATS_DOMAIN,
                                        disabled_rule.id, &relations),
        0);
    assert_true(relations.unreachable);
    assert_true(relations.disabled);

    assert_int_equal(
        jg_database_analyze_policy_rule(database, JG_POLICY_STATS_DESTINATION,
                                        20U, &relations),
        0);
    assert_int_equal(relations.duplicate_count, 1U);
    assert_int_equal(relations.duplicate_ids[0U], 21U);
    assert_int_equal(relations.conflict_count, 1U);
    assert_int_equal(relations.conflict_ids[0U], 22U);
    assert_int_equal(relations.shadowing_count, 1U);
    assert_int_equal(relations.shadowing_ids[0U], 22U);
    assert_int_equal(relations.allow_exception_count, 1U);
    assert_int_equal(relations.allow_exception_ids[0U], 22U);
    assert_false(relations.unreachable);
    assert_int_equal(
        jg_database_analyze_policy_rule(database, JG_POLICY_STATS_DESTINATION,
                                        21U, &relations),
        0);
    assert_true(relations.unreachable);

    assert_int_equal(
        jg_database_analyze_policy_rule(database, JG_POLICY_STATS_DOMAIN,
                                        UINT64_C(999999), &relations),
        -ENOENT);
    assert_int_equal(jg_database_load_policy_rule_impact(
                         database, (enum jg_policy_stats_dimension)99, 10U,
                         &stats, &has_stats, &impact, clients, 2U,
                         &client_count),
                     -EINVAL);
    assert_int_equal(jg_database_load_policy_rule_impact(
                         database, JG_POLICY_STATS_DOMAIN, 10U, &stats,
                         &has_stats, &impact, clients, 0U, &client_count),
                     -EINVAL);

    jg_database_close(database);
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
    uint8_t domain_statistics_id[JG_POLICY_RULE_IDENTITY_SIZE];
    uint8_t destination_statistics_id[JG_POLICY_RULE_IDENTITY_SIZE];
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
    rules[3].enforcement = JG_POLICY_OBSERVE;
    assert_int_equal(jg_database_replace_domain_rules(database, rules, 4U), 0);
    destination_rules[0] = make_destination_rule(20U, JG_POLICY_BLOCK);
    destination_rules[0].enforcement = JG_POLICY_OBSERVE;
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
    assert_int_equal(domain_page[1U].enforcement, JG_POLICY_OBSERVE);
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
    assert_int_equal(destination_page[0U].enforcement, JG_POLICY_OBSERVE);
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
    assert_true(match.would_have_blocked);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
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
    assert_true(destination_match.would_have_blocked);
    assert_int_equal(destination_match.effect, JG_POLICY_ALLOW);
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
    mutable_rule.enforcement = JG_POLICY_OBSERVE;
    assert_int_equal(jg_database_create_domain_rule(database, &mutable_rule,
                                                    false, &created_rule),
                     0);
    assert_true(created_rule.id > 12U);
    assert_int_equal(created_rule.revision, 1U);
    assert_string_equal(created_rule.domain, "new.example");
    assert_false(created_rule.enabled);
    assert_int_equal(created_rule.enforcement, JG_POLICY_OBSERVE);
    (void)memcpy(domain_statistics_id, created_rule.statistics_id,
                 sizeof(domain_statistics_id));
    mutable_rule.id = created_rule.id;
    mutable_rule.enforcement = JG_POLICY_ENFORCE;
    assert_int_equal(jg_database_update_domain_rule(database, &mutable_rule,
                                                    true, created_rule.revision,
                                                    &updated_rule),
                     0);
    assert_memory_equal(updated_rule.statistics_id, domain_statistics_id,
                        sizeof(domain_statistics_id));
    mutable_rule.domain = "Updated.Example.";
    mutable_rule.include_subdomains = true;
    assert_int_equal(jg_database_update_domain_rule(database, &mutable_rule,
                                                    true, updated_rule.revision,
                                                    &updated_rule),
                     0);
    assert_int_equal(updated_rule.id, created_rule.id);
    assert_int_equal(updated_rule.revision, 3U);
    assert_memory_not_equal(updated_rule.statistics_id, domain_statistics_id,
                            sizeof(domain_statistics_id));
    assert_string_equal(updated_rule.domain, "updated.example");
    assert_true(updated_rule.include_subdomains);
    assert_true(updated_rule.enabled);
    assert_int_equal(updated_rule.enforcement, JG_POLICY_ENFORCE);
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
        jg_database_delete_domain_rule(database, created_rule.id, 3U), 0);
    assert_int_equal(
        jg_database_delete_domain_rule(database, created_rule.id, 2U), -ENOENT);
    mutable_rule.id = 1U;
    assert_int_equal(jg_database_create_domain_rule(database, &mutable_rule,
                                                    true, &created_rule),
                     -EINVAL);
    mutable_destination = make_destination_rule(0U, JG_POLICY_BLOCK);
    mutable_destination.enforcement = JG_POLICY_OBSERVE;
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
    assert_int_equal(created_destination.enforcement, JG_POLICY_OBSERVE);
    assert_true(created_destination.has_address);
    assert_int_equal(created_destination.address[3U], 0U);
    (void)memcpy(destination_statistics_id, created_destination.statistics_id,
                 sizeof(destination_statistics_id));
    mutable_destination.id = created_destination.id;
    mutable_destination.enforcement = JG_POLICY_ENFORCE;
    assert_int_equal(jg_database_update_destination_rule(
                         database, &mutable_destination, true,
                         created_destination.revision, &updated_destination),
                     0);
    assert_memory_equal(updated_destination.statistics_id,
                        destination_statistics_id,
                        sizeof(destination_statistics_id));
    mutable_destination.has_port = true;
    mutable_destination.port = 443U;
    assert_int_equal(jg_database_update_destination_rule(
                         database, &mutable_destination, true,
                         updated_destination.revision, &updated_destination),
                     0);
    assert_int_equal(updated_destination.revision, 3U);
    assert_memory_not_equal(updated_destination.statistics_id,
                            destination_statistics_id,
                            sizeof(destination_statistics_id));
    assert_true(updated_destination.enabled);
    assert_true(updated_destination.has_port);
    assert_int_equal(updated_destination.port, 443U);
    assert_int_equal(updated_destination.enforcement, JG_POLICY_ENFORCE);
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
                         database, created_destination.id, 3U),
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
    static const char corrupt[] =
        "UPDATE network_configuration SET value="
        "'00000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000' WHERE id=1;";
    char directory[64U];
    char path[512U];
    struct jg_network_config expected = make_network_config();
    struct jg_network_config loaded;
    struct jg_database_network_config record;
    struct jg_database_network_config updated;
    struct jg_database *database = NULL;
    sqlite3 *handle = NULL;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_load_network_config(database, &loaded),
                     -ENOENT);
    assert_int_equal(jg_database_load_network_config_record(database, &record),
                     -ENOENT);
    assert_int_equal(jg_database_store_network_config(database, &expected), 0);
    assert_int_equal(jg_database_load_network_config(database, &loaded), 0);
    assert_network_config_equal(&loaded, &expected);
    assert_int_equal(jg_database_load_network_config_record(database, &record),
                     0);
    assert_int_equal(record.revision, 1U);
    assert_network_config_equal(&record.config, &expected);
    expected.queue_length = 8192U;
    assert_int_equal(jg_database_replace_network_config(
                         database, &expected, record.revision, &updated),
                     0);
    assert_int_equal(updated.revision, 2U);
    assert_network_config_equal(&updated.config, &expected);
    assert_int_equal(jg_database_replace_network_config(
                         database, &record.config, record.revision, &updated),
                     -EAGAIN);
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
    assert_int_equal(jg_database_load_network_config_record(NULL, &record),
                     -EINVAL);
    assert_int_equal(jg_database_load_network_config_record(database, NULL),
                     -EINVAL);
    assert_int_equal(
        jg_database_replace_network_config(database, &expected, 0U, &updated),
        -EINVAL);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify durable checkpoint creation, restoration, and removal. */
static void test_recovery_checkpoint(void **state)
{
    const struct jg_network_config original = {
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
    struct jg_network_config changed = original;
    struct jg_network_config loaded;
    char directory[64U];
    char path[512U];
    char checkpoint[544U];
    char sentinel[544U];
    struct jg_database *database = NULL;
    int descriptor = -1;
    int written = 0;

    (void)state;
    changed.queue_length = 8192U;
    changed.failure_mode = JG_NETWORK_FAIL_CLOSED;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    written = snprintf(checkpoint, sizeof(checkpoint), "%s.recovery", path);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(checkpoint));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_store_network_config(database, &original), 0);
    assert_int_equal(jg_database_recovery_checkpoint_create(database), 0);
    assert_int_equal(access(checkpoint, F_OK), 0);
    assert_int_equal(jg_database_store_network_config(database, &changed), 0);
    assert_int_equal(jg_database_load_network_config(database, &loaded), 0);
    assert_int_equal(loaded.queue_length, changed.queue_length);

    assert_int_equal(jg_database_recovery_checkpoint_restore(database), 0);
    assert_int_equal(jg_database_load_network_config(database, &loaded), 0);
    assert_int_equal(loaded.queue_length, original.queue_length);
    assert_int_equal(loaded.failure_mode, original.failure_mode);
    assert_int_equal(jg_database_recovery_checkpoint_remove(database), 0);
    assert_int_equal(access(checkpoint, F_OK), -1);
    assert_int_equal(errno, ENOENT);
    assert_int_equal(jg_database_recovery_checkpoint_remove(database), -ENOENT);

    written = snprintf(sentinel, sizeof(sentinel), "%s.sentinel", path);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(sentinel));
    descriptor = open(sentinel, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert_true(descriptor >= 0);
    assert_int_equal(close(descriptor), 0);
    assert_int_equal(symlink(sentinel, checkpoint), 0);
    assert_int_equal(jg_database_recovery_checkpoint_remove(database), 0);
    assert_int_equal(access(checkpoint, F_OK), -1);
    assert_int_equal(errno, ENOENT);
    assert_int_equal(access(sentinel, F_OK), 0);
    assert_int_equal(unlink(sentinel), 0);

    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify migration of a retained version-eight network setting. */
static void test_network_configuration_migration(void **state)
{
    static const char downgrade[] =
        "INSERT INTO system_settings(key,value,updated_at) "
        "SELECT 'network.configuration',value,updated_at "
        "FROM network_configuration WHERE id=1;"
        "DROP TABLE alert_outbox;"
        "DROP TABLE alert_incidents;"
        "DROP TABLE alert_configuration;"
        "DROP TABLE policy_traffic_buckets;"
        "DROP TABLE policy_impact_buckets;"
        "DROP TABLE policy_traffic_stats;"
        "DROP TABLE policy_rule_stats;"
        "DROP TABLE policy_statistics_configuration;"
        "DROP TABLE policy_scope_modes;"
        "DROP TABLE policy_configuration;"
        "ALTER TABLE destination_rules DROP COLUMN enforcement;"
        "ALTER TABLE domain_rules DROP COLUMN enforcement;"
        "ALTER TABLE blocklist_sources DROP COLUMN enforcement;"
        "ALTER TABLE policy_groups DROP COLUMN revision;"
        "ALTER TABLE policy_groups DROP COLUMN enforcement;"
        "DROP TABLE management_operations;"
        "DROP TABLE policy_sync_state;"
        "DROP TABLE logging_configuration;"
        "DROP TABLE network_configuration;"
        "ALTER TABLE mtls_mappings RENAME TO mtls_mappings_v12;"
        "CREATE TABLE mtls_mappings ("
        "id INTEGER PRIMARY KEY,fingerprint_sha256 BLOB NOT NULL UNIQUE "
        "CHECK(length(fingerprint_sha256)=32),"
        "user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,"
        "role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,"
        "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),"
        "created_at INTEGER NOT NULL CHECK(created_at >= 0),"
        "CHECK((user_id IS NULL) <> (role_id IS NULL))) STRICT;"
        "INSERT INTO mtls_mappings(id,fingerprint_sha256,user_id,role_id,"
        "enabled,created_at) SELECT id,fingerprint_sha256,user_id,role_id,"
        "enabled,created_at FROM mtls_mappings_v12;"
        "DROP TABLE mtls_mappings_v12;"
        "DELETE FROM schema_migrations WHERE version>=9;"
        "PRAGMA user_version=8;";
    char directory[64U];
    char path[512U];
    const struct jg_network_config expected = make_network_config();
    struct jg_database_network_config record;
    struct jg_database *database = NULL;
    sqlite3 *handle = NULL;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_store_network_config(database, &expected), 0);
    jg_database_close(database);

    assert_int_equal(
        sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE, NULL), SQLITE_OK);
    assert_int_equal(sqlite3_exec(handle, downgrade, NULL, NULL, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_close(handle), SQLITE_OK);

    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_load_network_config_record(database, &record),
                     0);
    assert_int_equal(record.revision, 1U);
    assert_network_config_equal(&record.config, &expected);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Verify persistent logging configuration and revision conflicts. */
static void test_logging_configuration(void **state)
{
    static const char corrupt[] =
        "UPDATE logging_configuration SET value='{\"unknown\":true}'"
        " WHERE id=1;";
    char directory[64U];
    char path[512U];
    struct jg_database_logging_config record;
    struct jg_database_logging_config updated;
    struct jg_logging_config replacement;
    struct jg_database *database = NULL;
    sqlite3 *handle = NULL;

    (void)state;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_load_logging_config(database, &record), 0);
    assert_int_equal(record.revision, 1U);
    assert_int_equal(record.config.global_level, JG_LOG_INFO);
    assert_false(record.config.include_identifiers);

    replacement = record.config;
    replacement.global_level = JG_LOG_DEBUG;
    replacement.diagnostic_until = UINT64_C(2000000000);
    replacement.destinations = JG_LOG_DESTINATION_STDERR;
    assert_int_equal(jg_database_replace_logging_config(
                         database, &replacement, record.revision, &updated),
                     0);
    assert_int_equal(updated.revision, 2U);
    assert_int_equal(updated.config.global_level, JG_LOG_DEBUG);
    assert_int_equal(jg_database_replace_logging_config(
                         database, &record.config, record.revision, &updated),
                     -EAGAIN);
    assert_int_equal(jg_database_load_logging_config(NULL, &record), -EINVAL);
    assert_int_equal(jg_database_load_logging_config(database, NULL), -EINVAL);
    assert_int_equal(jg_database_replace_logging_config(database, &replacement,
                                                        0U, &updated),
                     -EINVAL);
    jg_database_close(database);

    assert_int_equal(
        sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE, NULL), SQLITE_OK);
    assert_int_equal(sqlite3_exec(handle, corrupt, NULL, NULL, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_close(handle), SQLITE_OK);
    database = NULL;
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(jg_database_load_logging_config(database, &record),
                     -EILSEQ);
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
        "'https://lists.example/"
        "domains.sig',2147483647,2147483647,3,60,900,4),("
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
    assert_int_equal(page[0U].connect_timeout_ms,
                     JG_BLOCKLIST_CONNECT_TIMEOUT_MAX);
    assert_int_equal(page[0U].transfer_timeout_ms,
                     JG_BLOCKLIST_TRANSFER_TIMEOUT_MAX);
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

    config.name = "Excessive timeout";
    config.connect_timeout_ms = JG_BLOCKLIST_CONNECT_TIMEOUT_MAX + 1U;
    assert_int_equal(
        jg_database_create_blocklist_source(database, &config, &duplicate),
        -EINVAL);
    config = make_blocklist_source();

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
    struct jg_database_blocklist_source empty;
    struct jg_database_blocklist_source updated;
    struct jg_database_domain_rule rules[2U];
    struct jg_blocklist_remote_state remote;
    struct jg_blocklist_report report;
    struct jg_blocklist_limits limits;
    struct jg_blocklist *blocklist = NULL;
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_policy_match match;
    struct jg_policy_rule_sample sample = {
        .occurred_at = 100U,
        .dimension = JG_POLICY_STATS_DOMAIN,
        .path = JG_POLICY_STATS_DNS,
        .domain = "alpha.example",
        .query_type = 1U,
        .decision = true,
        .would_block = true,
    };
    struct jg_policy_rule_stats statistics;
    struct jg_database *database = NULL;
    uint8_t statistics_id[JG_POLICY_RULE_IDENTITY_SIZE];
    size_t count = 0U;
    bool has_more = false;

    (void)state;
    config.name = "Activation source";
    config.enforcement = JG_POLICY_OBSERVE;
    config.signature_url = NULL;
    config.has_signature = false;
    config.has_sha256_pin = false;
    make_database_path(directory, sizeof(directory), path, sizeof(path));
    assert_int_equal(jg_database_open(path, 1000U, &database), 0);
    assert_int_equal(
        jg_database_create_blocklist_source(database, &config, &source), 0);
    assert_int_equal(source.enforcement, JG_POLICY_OBSERVE);
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
    sample.rule_id = rules[0U].id;
    (void)memcpy(sample.statistics_id, rules[0U].statistics_id,
                 sizeof(sample.statistics_id));
    (void)memcpy(statistics_id, rules[0U].statistics_id, sizeof(statistics_id));
    assert_int_equal(
        jg_database_record_policy_stats(database, NULL, 0U, &sample, 1U), 0);
    remote.last_attempt_at = 150U;
    remote.last_success_at = 150U;
    remote.next_attempt_at = 3750U;
    assert_int_equal(jg_database_activate_blocklist(database, source.id,
                                                    source.revision, blocklist,
                                                    &remote, &report),
                     0);
    assert_int_equal(jg_database_list_domain_rules(database, 0U, 2U, rules,
                                                   &count, &has_more),
                     0);
    assert_memory_equal(rules[0U].statistics_id, statistics_id,
                        sizeof(statistics_id));
    assert_int_equal(
        jg_database_list_policy_rule_stats(database, JG_POLICY_STATS_DOMAIN, 0U,
                                           1U, &statistics, &count, &has_more),
        0);
    assert_int_equal(count, 1U);
    assert_int_equal(statistics.rule_id, rules[0U].id);
    assert_int_equal(statistics.match_count, 1U);
    assert_int_equal(jg_database_list_blocklist_sources(
                         database, 0U, 1U, &updated, &count, &has_more),
                     0);
    assert_true(updated.has_active_checksum);
    assert_int_equal(updated.active_entries, 2U);
    assert_int_equal(updated.rejected_entries, 1U);
    assert_int_equal(updated.health, JG_DATABASE_BLOCKLIST_HEALTHY);
    assert_string_equal(updated.etag, "\"active-1\"");

    remote.last_attempt_at = 200U;
    remote.next_attempt_at = 260U;
    remote.consecutive_failures = 1U;
    assert_int_equal(jg_database_record_blocklist_attempt(
                         database, source.id, source.revision, &remote, false,
                         "transfer timed out"),
                     0);
    assert_int_equal(jg_database_list_blocklist_sources(
                         database, 0U, 1U, &updated, &count, &has_more),
                     0);
    assert_true(updated.has_active_checksum);
    assert_int_equal(updated.active_entries, 2U);
    assert_int_equal(updated.health, JG_DATABASE_BLOCKLIST_DEGRADED);
    assert_string_equal(updated.last_error, "transfer timed out");
    remote.last_attempt_at = 260U;
    remote.last_success_at = 260U;
    remote.next_attempt_at = 3860U;
    remote.consecutive_failures = 0U;
    assert_int_equal(jg_database_record_blocklist_attempt(database, source.id,
                                                          source.revision,
                                                          &remote, true, NULL),
                     0);
    assert_int_equal(jg_database_list_blocklist_sources(
                         database, 0U, 1U, &updated, &count, &has_more),
                     0);
    assert_int_equal(updated.health, JG_DATABASE_BLOCKLIST_HEALTHY);
    assert_string_equal(updated.last_error, "");
    assert_int_equal(jg_database_load_policy_snapshot(database, 50U, &snapshot),
                     0);
    assert_int_equal(
        jg_policy_match_domain(snapshot, "www.alpha.example", NULL, &match), 0);
    assert_true(match.matched);
    assert_true(match.would_have_blocked);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    jg_policy_snapshot_destroy(snapshot);
    snapshot = NULL;

    config.enforcement = JG_POLICY_ENFORCE;
    assert_int_equal(
        jg_database_update_blocklist_source(database, source.id, &config,
                                            source.revision, &updated),
        0);
    assert_int_equal(updated.enforcement, JG_POLICY_ENFORCE);
    assert_int_equal(jg_database_load_policy_snapshot(database, 51U, &snapshot),
                     0);
    assert_int_equal(
        jg_policy_match_domain(snapshot, "www.alpha.example", NULL, &match), 0);
    assert_false(match.would_have_blocked);
    assert_int_equal(match.effect, JG_POLICY_BLOCK);
    jg_policy_snapshot_destroy(snapshot);
    snapshot = NULL;

    config.enabled = false;
    assert_int_equal(
        jg_database_update_blocklist_source(database, source.id, &config,
                                            updated.revision, &updated),
        0);
    assert_int_equal(jg_database_load_policy_snapshot(database, 52U, &snapshot),
                     0);
    assert_int_equal(
        jg_policy_match_domain(snapshot, "www.alpha.example", NULL, &match), 0);
    assert_false(match.matched);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    jg_policy_snapshot_destroy(snapshot);
    snapshot = NULL;
    assert_int_equal(jg_database_activate_blocklist(database, source.id,
                                                    source.revision, blocklist,
                                                    &remote, &report),
                     -EAGAIN);

    config.name = "Empty source";
    config.enabled = true;
    assert_int_equal(
        jg_database_create_blocklist_source(database, &config, &empty), 0);
    remote.last_attempt_at = 400U;
    remote.last_success_at = 0U;
    remote.next_attempt_at = 460U;
    remote.consecutive_failures = 1U;
    assert_int_equal(jg_database_record_blocklist_attempt(
                         database, empty.id, empty.revision, &remote, false,
                         "connection refused"),
                     0);
    assert_int_equal(jg_database_list_blocklist_sources(
                         database, source.id, 1U, &updated, &count, &has_more),
                     0);
    assert_int_equal(updated.id, empty.id);
    assert_false(updated.has_active_checksum);
    assert_int_equal(updated.health, JG_DATABASE_BLOCKLIST_FAILED);
    remote.last_attempt_at = 460U;
    remote.last_success_at = 460U;
    remote.next_attempt_at = 4060U;
    remote.consecutive_failures = 0U;
    assert_int_equal(jg_database_record_blocklist_attempt(database, empty.id,
                                                          empty.revision,
                                                          &remote, true, NULL),
                     -ENOENT);
    jg_blocklist_destroy(blocklist);
    jg_database_close(database);
    remove_database(directory, path);
}

/** @brief Run the SQLite lifecycle and migration test group. */
int jg_test_database(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_initial_migration),
        cmocka_unit_test(test_database_export),
        cmocka_unit_test(test_backup_metadata),
        cmocka_unit_test(test_management_operation),
        cmocka_unit_test(test_policy_sync_state),
        cmocka_unit_test(test_newer_schema_rejected),
        cmocka_unit_test(test_version_one_migration),
        cmocka_unit_test(test_version_two_migration),
        cmocka_unit_test(test_insecure_permissions_rejected),
        cmocka_unit_test(test_policy_modes),
        cmocka_unit_test(test_policy_groups),
        cmocka_unit_test(test_policy_statistics),
        cmocka_unit_test(test_policy_analysis),
        cmocka_unit_test(test_policy_round_trip),
        cmocka_unit_test(test_encrypted_dns_endpoint_policy),
        cmocka_unit_test(test_network_configuration),
        cmocka_unit_test(test_recovery_checkpoint),
        cmocka_unit_test(test_network_configuration_migration),
        cmocka_unit_test(test_logging_configuration),
        cmocka_unit_test(test_dns_response_configuration),
        cmocka_unit_test(test_blocklist_source_page),
        cmocka_unit_test(test_blocklist_source_creation),
        cmocka_unit_test(test_blocklist_activation),
    };

    return cmocka_run_group_tests_name("database", tests, NULL, NULL);
}
