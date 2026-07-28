/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "janusgate/database.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sqlite3.h>

#include "database_internal.h"
#include "janusgate/checked.h"
#include "janusgate/domain.h"

/** One ordered schema migration. */
struct database_migration {
    uint32_t version;
    const char *const *sql;
    size_t sql_count;
};

/** Foundation tables for schema version one. */
static const char migration_1_foundation[] =
    "CREATE TABLE schema_migrations ("
    "version INTEGER PRIMARY KEY CHECK(version > 0),"
    "applied_at INTEGER NOT NULL CHECK(applied_at >= 0)"
    ") STRICT;"
    "CREATE TABLE system_settings ("
    "key TEXT PRIMARY KEY CHECK(length(key) BETWEEN 1 AND 128),"
    "value TEXT NOT NULL,"
    "updated_at INTEGER NOT NULL CHECK(updated_at >= 0)"
    ") STRICT;"
    "CREATE TABLE interfaces ("
    "id INTEGER PRIMARY KEY,"
    "name TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 15),"
    "role TEXT NOT NULL CHECK(role IN ('data_in','data_out','management')),"
    "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))"
    ") STRICT;"
    "CREATE TABLE management_addresses ("
    "id INTEGER PRIMARY KEY,"
    "interface_id INTEGER NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,"
    "family INTEGER NOT NULL CHECK(family IN (4,6)),"
    "address BLOB NOT NULL,"
    "prefix_length INTEGER NOT NULL,"
    "gateway BLOB,"
    "CHECK((family=4 AND length(address)=4 AND prefix_length BETWEEN 0 AND 32 "
    "AND (gateway IS NULL OR length(gateway)=4)) OR "
    "(family=6 AND length(address)=16 AND prefix_length BETWEEN 0 AND 128 "
    "AND (gateway IS NULL OR length(gateway)=16))),"
    "UNIQUE(interface_id,family,address,prefix_length)"
    ") STRICT;"
    "CREATE TABLE policy_groups ("
    "id INTEGER PRIMARY KEY,"
    "name TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 128),"
    "description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 1024),"
    "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),"
    "created_at INTEGER NOT NULL CHECK(created_at >= 0),"
    "updated_at INTEGER NOT NULL CHECK(updated_at >= created_at)"
    ") STRICT;";

/** Blocklist source tables for schema version one. */
static const char migration_1_sources[] =
    "CREATE TABLE blocklist_sources ("
    "id INTEGER PRIMARY KEY,"
    "name TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 128),"
    "url TEXT CHECK(url IS NULL OR length(url) BETWEEN 1 AND 2048),"
    "format TEXT NOT NULL CHECK(format IN "
    "('domain','hosts','category','rpz','json')),"
    "strict_mode INTEGER NOT NULL DEFAULT 1 CHECK(strict_mode IN (0,1)),"
    "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),"
    "update_interval INTEGER NOT NULL CHECK(update_interval BETWEEN 300 AND "
    "2592000),"
    "max_download_bytes INTEGER NOT NULL CHECK(max_download_bytes > 0),"
    "max_decompressed_bytes INTEGER NOT NULL "
    "CHECK(max_decompressed_bytes >= max_download_bytes),"
    "sha256_pin BLOB CHECK(sha256_pin IS NULL OR length(sha256_pin)=32),"
    "ed25519_public_key BLOB "
    "CHECK(ed25519_public_key IS NULL OR length(ed25519_public_key)=32),"
    "created_at INTEGER NOT NULL CHECK(created_at >= 0),"
    "updated_at INTEGER NOT NULL CHECK(updated_at >= created_at)"
    ") STRICT;"
    "CREATE TABLE blocklist_source_status ("
    "source_id INTEGER PRIMARY KEY REFERENCES blocklist_sources(id) ON DELETE "
    "CASCADE,"
    "etag TEXT CHECK(etag IS NULL OR length(etag) <= 1024),"
    "last_modified TEXT CHECK(last_modified IS NULL OR length(last_modified) "
    "<= 128),"
    "last_attempt_at INTEGER CHECK(last_attempt_at IS NULL OR last_attempt_at "
    ">= 0),"
    "last_success_at INTEGER CHECK(last_success_at IS NULL OR last_success_at "
    ">= 0),"
    "next_attempt_at INTEGER CHECK(next_attempt_at IS NULL OR next_attempt_at "
    ">= 0),"
    "consecutive_failures INTEGER NOT NULL DEFAULT 0 "
    "CHECK(consecutive_failures >= 0),"
    "active_checksum BLOB "
    "CHECK(active_checksum IS NULL OR length(active_checksum)=32),"
    "active_entries INTEGER NOT NULL DEFAULT 0 CHECK(active_entries >= 0),"
    "health TEXT NOT NULL DEFAULT 'unknown' "
    "CHECK(health IN ('unknown','healthy','degraded','failed')),"
    "last_error TEXT CHECK(last_error IS NULL OR length(last_error) <= 2048)"
    ") STRICT;";

/** Policy rule and encrypted-DNS tables for schema version one. */
static const char migration_1_policy[] =
    "CREATE TABLE domain_rules ("
    "id INTEGER PRIMARY KEY,"
    "group_id INTEGER REFERENCES policy_groups(id) ON DELETE CASCADE,"
    "blocklist_source_id INTEGER REFERENCES blocklist_sources(id) ON DELETE "
    "CASCADE,"
    "domain TEXT NOT NULL CHECK(length(domain) BETWEEN 1 AND 253),"
    "match_type TEXT NOT NULL CHECK(match_type IN ('exact','suffix')),"
    "effect TEXT NOT NULL CHECK(effect IN ('allow','block')),"
    "source TEXT NOT NULL CHECK(source IN "
    "('explicit','blocklist','emergency')),"
    "scope_type TEXT NOT NULL "
    "CHECK(scope_type IN ('global','mac','ipv4','ipv6','vlan')),"
    "scope_value BLOB,"
    "prefix_length INTEGER,"
    "vlan_id INTEGER,"
    "attribution TEXT NOT NULL CHECK(length(attribution) BETWEEN 1 AND 255),"
    "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),"
    "updated_at INTEGER NOT NULL CHECK(updated_at >= 0),"
    "CHECK((source='blocklist' AND effect='block') OR "
    "(source='emergency' AND effect='allow') OR source='explicit'),"
    "CHECK((scope_type='global' AND scope_value IS NULL AND "
    "prefix_length IS NULL AND vlan_id IS NULL) OR "
    "(scope_type='mac' AND length(scope_value)=6 AND "
    "prefix_length IS NULL AND vlan_id IS NULL) OR "
    "(scope_type='ipv4' AND length(scope_value)=4 AND "
    "prefix_length BETWEEN 0 AND 32 AND vlan_id IS NULL) OR "
    "(scope_type='ipv6' AND length(scope_value)=16 AND "
    "prefix_length BETWEEN 0 AND 128 AND vlan_id IS NULL) OR "
    "(scope_type='vlan' AND scope_value IS NULL AND "
    "prefix_length IS NULL AND vlan_id BETWEEN 0 AND 4094))"
    ") STRICT;"
    "CREATE INDEX domain_rules_domain_idx ON domain_rules(domain) WHERE "
    "enabled=1;"
    "CREATE TABLE destination_rules ("
    "id INTEGER PRIMARY KEY,"
    "group_id INTEGER REFERENCES policy_groups(id) ON DELETE CASCADE,"
    "effect TEXT NOT NULL CHECK(effect IN ('allow','block')),"
    "protocol TEXT NOT NULL CHECK(protocol IN ('any','tcp','udp')),"
    "family INTEGER CHECK(family IS NULL OR family IN (4,6)),"
    "address BLOB,"
    "prefix_length INTEGER,"
    "port INTEGER CHECK(port IS NULL OR port BETWEEN 1 AND 65535),"
    "attribution TEXT NOT NULL CHECK(length(attribution) BETWEEN 1 AND 255),"
    "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),"
    "CHECK(address IS NOT NULL OR port IS NOT NULL),"
    "CHECK(address IS NULL OR "
    "(family=4 AND length(address)=4 AND prefix_length BETWEEN 0 AND 32) OR "
    "(family=6 AND length(address)=16 AND prefix_length BETWEEN 0 AND 128))"
    ") STRICT;"
    "CREATE TABLE encrypted_dns_sources ("
    "id INTEGER PRIMARY KEY,"
    "name TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 128),"
    "url TEXT NOT NULL CHECK(length(url) BETWEEN 1 AND 2048),"
    "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),"
    "updated_at INTEGER NOT NULL CHECK(updated_at >= 0)"
    ") STRICT;"
    "CREATE TABLE encrypted_dns_endpoints ("
    "source_id INTEGER NOT NULL REFERENCES encrypted_dns_sources(id) ON DELETE "
    "CASCADE,"
    "family INTEGER NOT NULL CHECK(family IN (4,6)),"
    "address BLOB NOT NULL,"
    "port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),"
    "transport TEXT NOT NULL CHECK(transport IN ('tcp','udp')),"
    "CHECK((family=4 AND length(address)=4) OR "
    "(family=6 AND length(address)=16)),"
    "PRIMARY KEY(source_id,family,address,port,transport)"
    ") STRICT;";

/** Identity and session tables for schema version one. */
static const char migration_1_identity[] =
    "CREATE TABLE roles ("
    "id INTEGER PRIMARY KEY,"
    "name TEXT NOT NULL UNIQUE "
    "CHECK(name IN ('administrator','operator','auditor')),"
    "permissions TEXT NOT NULL"
    ") STRICT;"
    "CREATE TABLE users ("
    "id INTEGER PRIMARY KEY,"
    "username TEXT NOT NULL UNIQUE CHECK(length(username) BETWEEN 1 AND 128),"
    "password_hash TEXT NOT NULL CHECK(length(password_hash) BETWEEN 1 AND "
    "512),"
    "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),"
    "failed_logins INTEGER NOT NULL DEFAULT 0 CHECK(failed_logins >= 0),"
    "locked_until INTEGER CHECK(locked_until IS NULL OR locked_until >= 0),"
    "created_at INTEGER NOT NULL CHECK(created_at >= 0),"
    "password_changed_at INTEGER NOT NULL CHECK(password_changed_at >= "
    "created_at)"
    ") STRICT;"
    "CREATE TABLE user_roles ("
    "user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
    "role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,"
    "PRIMARY KEY(user_id,role_id)"
    ") STRICT;"
    "CREATE TABLE api_tokens ("
    "id INTEGER PRIMARY KEY,"
    "user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
    "name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),"
    "token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash)=32),"
    "scopes TEXT NOT NULL,"
    "created_at INTEGER NOT NULL CHECK(created_at >= 0),"
    "expires_at INTEGER CHECK(expires_at IS NULL OR expires_at >= created_at),"
    "last_used_at INTEGER CHECK(last_used_at IS NULL OR last_used_at >= "
    "created_at),"
    "revoked_at INTEGER CHECK(revoked_at IS NULL OR revoked_at >= created_at)"
    ") STRICT;"
    "CREATE TABLE web_sessions ("
    "id INTEGER PRIMARY KEY,"
    "user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
    "session_hash BLOB NOT NULL UNIQUE CHECK(length(session_hash)=32),"
    "csrf_hash BLOB NOT NULL CHECK(length(csrf_hash)=32),"
    "created_at INTEGER NOT NULL CHECK(created_at >= 0),"
    "expires_at INTEGER NOT NULL CHECK(expires_at >= created_at),"
    "last_seen_at INTEGER NOT NULL CHECK(last_seen_at >= created_at),"
    "remote_address BLOB CHECK(remote_address IS NULL OR "
    "length(remote_address) IN (4,16))"
    ") STRICT;";

/** Event, certificate, and backup tables for schema version one. */
static const char migration_1_records[] =
    "CREATE TABLE audit_events ("
    "id INTEGER PRIMARY KEY,"
    "occurred_at INTEGER NOT NULL CHECK(occurred_at >= 0),"
    "actor_type TEXT NOT NULL CHECK(actor_type IN ('system','user','token')),"
    "actor_id INTEGER,"
    "action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 128),"
    "object_type TEXT NOT NULL CHECK(length(object_type) BETWEEN 1 AND 128),"
    "object_id TEXT,"
    "details TEXT NOT NULL,"
    "previous_hash BLOB CHECK(previous_hash IS NULL OR "
    "length(previous_hash)=32),"
    "event_hash BLOB NOT NULL UNIQUE CHECK(length(event_hash)=32)"
    ") STRICT;"
    "CREATE TABLE operational_events ("
    "id INTEGER PRIMARY KEY,"
    "occurred_at INTEGER NOT NULL CHECK(occurred_at >= 0),"
    "severity TEXT NOT NULL "
    "CHECK(severity IN ('debug','info','warning','error','critical')),"
    "component TEXT NOT NULL CHECK(length(component) BETWEEN 1 AND 128),"
    "code TEXT NOT NULL CHECK(length(code) BETWEEN 1 AND 128),"
    "message TEXT NOT NULL CHECK(length(message) BETWEEN 1 AND 2048),"
    "details TEXT NOT NULL"
    ") STRICT;"
    "CREATE INDEX operational_events_time_idx ON "
    "operational_events(occurred_at);"
    "CREATE TABLE certificate_metadata ("
    "id INTEGER PRIMARY KEY,"
    "purpose TEXT NOT NULL CHECK(length(purpose) BETWEEN 1 AND 128),"
    "certificate_path TEXT NOT NULL CHECK(length(certificate_path) BETWEEN 1 "
    "AND 4096),"
    "private_key_path TEXT CHECK(private_key_path IS NULL OR "
    "length(private_key_path) BETWEEN 1 AND 4096),"
    "fingerprint_sha256 BLOB NOT NULL CHECK(length(fingerprint_sha256)=32),"
    "not_before INTEGER NOT NULL CHECK(not_before >= 0),"
    "not_after INTEGER NOT NULL CHECK(not_after > not_before)"
    ") STRICT;"
    "CREATE TABLE backup_metadata ("
    "id INTEGER PRIMARY KEY,"
    "created_at INTEGER NOT NULL CHECK(created_at >= 0),"
    "kind TEXT NOT NULL CHECK(kind IN ('configuration','full')),"
    "path TEXT NOT NULL CHECK(length(path) BETWEEN 1 AND 4096),"
    "checksum BLOB NOT NULL CHECK(length(checksum)=32),"
    "schema_version INTEGER NOT NULL CHECK(schema_version > 0),"
    "size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0)"
    ") STRICT;"
    "INSERT INTO roles(id,name,permissions) VALUES"
    "(1,'administrator','all'),"
    "(2,'operator','operate'),"
    "(3,'auditor','read');"
    "INSERT INTO schema_migrations(version,applied_at) VALUES(1,unixepoch());"
    "PRAGMA user_version=1;";

/** Ordered statement groups composing schema version one. */
static const char *const migration_1[] = {
    migration_1_foundation, migration_1_sources, migration_1_policy,
    migration_1_identity,   migration_1_records,
};

/** Authentication and audit extensions for schema version two. */
static const char migration_2_identity[] =
    "ALTER TABLE users ADD COLUMN force_password_change INTEGER NOT NULL "
    "DEFAULT 1 CHECK(force_password_change IN (0,1));"
    "ALTER TABLE users ADD COLUMN last_login_at INTEGER "
    "CHECK(last_login_at IS NULL OR last_login_at >= created_at);"
    "ALTER TABLE users ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 "
    "CHECK(revision > 0);"
    "ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 1 "
    "CHECK(session_epoch > 0);"
    "ALTER TABLE api_tokens RENAME TO api_tokens_v1;"
    "CREATE TABLE api_tokens ("
    "id INTEGER PRIMARY KEY,"
    "user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
    "name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),"
    "token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash)=32),"
    "scopes TEXT NOT NULL,"
    "created_at INTEGER NOT NULL CHECK(created_at >= 0),"
    "expires_at INTEGER CHECK(expires_at IS NULL OR expires_at >= created_at),"
    "last_used_at INTEGER CHECK(last_used_at IS NULL OR last_used_at >= "
    "created_at),"
    "revoked_at INTEGER CHECK(revoked_at IS NULL OR revoked_at >= created_at),"
    "source_family INTEGER CHECK(source_family IS NULL OR "
    "source_family IN (4,6)),"
    "source_address BLOB,"
    "source_prefix INTEGER,"
    "requests_per_minute INTEGER NOT NULL DEFAULT 60 "
    "CHECK(requests_per_minute BETWEEN 1 AND 60000),"
    "revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),"
    "CHECK((source_family IS NULL AND source_address IS NULL AND "
    "source_prefix IS NULL) OR "
    "(source_family=4 AND length(source_address)=4 AND "
    "source_prefix BETWEEN 0 AND 32) OR "
    "(source_family=6 AND length(source_address)=16 AND "
    "source_prefix BETWEEN 0 AND 128))"
    ") STRICT;"
    "INSERT INTO api_tokens(id,user_id,name,token_hash,scopes,created_at,"
    "expires_at,last_used_at,revoked_at) "
    "SELECT id,user_id,name,token_hash,scopes,created_at,expires_at,"
    "last_used_at,revoked_at FROM api_tokens_v1;"
    "DROP TABLE api_tokens_v1;"
    "CREATE TABLE totp_credentials ("
    "user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,"
    "secret_ciphertext BLOB NOT NULL CHECK(length(secret_ciphertext) >= 16),"
    "nonce BLOB NOT NULL CHECK(length(nonce)=24),"
    "enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),"
    "created_at INTEGER NOT NULL CHECK(created_at >= 0)"
    ") STRICT;"
    "CREATE TABLE recovery_codes ("
    "user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
    "code_hash BLOB NOT NULL CHECK(length(code_hash)=32),"
    "created_at INTEGER NOT NULL CHECK(created_at >= 0),"
    "used_at INTEGER CHECK(used_at IS NULL OR used_at >= created_at),"
    "PRIMARY KEY(user_id,code_hash)"
    ") STRICT;"
    "CREATE TABLE mtls_mappings ("
    "id INTEGER PRIMARY KEY,"
    "fingerprint_sha256 BLOB NOT NULL UNIQUE "
    "CHECK(length(fingerprint_sha256)=32),"
    "user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,"
    "role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,"
    "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),"
    "created_at INTEGER NOT NULL CHECK(created_at >= 0),"
    "CHECK((user_id IS NULL) <> (role_id IS NULL))"
    ") STRICT;";

/** Administrative provenance fields for schema version two. */
static const char migration_2_audit[] =
    "ALTER TABLE audit_events ADD COLUMN source TEXT NOT NULL DEFAULT 'local' "
    "CHECK(length(source) BETWEEN 1 AND 255);"
    "ALTER TABLE audit_events ADD COLUMN previous_revision INTEGER "
    "CHECK(previous_revision IS NULL OR previous_revision > 0);"
    "ALTER TABLE audit_events ADD COLUMN new_revision INTEGER "
    "CHECK(new_revision IS NULL OR new_revision > 0);"
    "ALTER TABLE audit_events ADD COLUMN success INTEGER NOT NULL DEFAULT 1 "
    "CHECK(success IN (0,1));"
    "ALTER TABLE audit_events ADD COLUMN request_id TEXT NOT NULL DEFAULT '' "
    "CHECK(length(request_id) <= 128);"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(2,unixepoch());"
    "PRAGMA user_version=2;";

/** Ordered statement groups composing schema version two. */
static const char *const migration_2[] = {
    migration_2_identity,
    migration_2_audit,
};

/** Separate DNS and visible-SNI rules in schema version three. */
static const char migration_3_policy[] =
    "ALTER TABLE domain_rules ADD COLUMN target TEXT NOT NULL DEFAULT 'dns' "
    "CHECK(target IN ('dns','tls_sni'));"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(3,unixepoch());"
    "PRAGMA user_version=3;";

/** Ordered statement groups composing schema version three. */
static const char *const migration_3[] = {
    migration_3_policy,
};

/** Add complete provenance and client scopes to destination rules. */
static const char migration_4_policy[] =
    "ALTER TABLE destination_rules RENAME TO destination_rules_v3;"
    "CREATE TABLE destination_rules ("
    "id INTEGER PRIMARY KEY,"
    "group_id INTEGER REFERENCES policy_groups(id) ON DELETE CASCADE,"
    "effect TEXT NOT NULL CHECK(effect IN ('allow','block')),"
    "source TEXT NOT NULL CHECK(source IN "
    "('explicit','blocklist','emergency')),"
    "protocol TEXT NOT NULL CHECK(protocol IN ('any','tcp','udp')),"
    "family INTEGER,"
    "address BLOB,"
    "prefix_length INTEGER,"
    "port INTEGER CHECK(port IS NULL OR port BETWEEN 1 AND 65535),"
    "scope_type TEXT NOT NULL "
    "CHECK(scope_type IN ('global','mac','ipv4','ipv6','vlan')),"
    "scope_value BLOB,"
    "scope_prefix_length INTEGER,"
    "scope_vlan_id INTEGER,"
    "attribution TEXT NOT NULL CHECK(length(attribution) BETWEEN 1 AND 255),"
    "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),"
    "updated_at INTEGER NOT NULL CHECK(updated_at >= 0),"
    "CHECK((source='blocklist' AND effect='block') OR "
    "(source='emergency' AND effect='allow') OR source='explicit'),"
    "CHECK(address IS NOT NULL OR port IS NOT NULL),"
    "CHECK((address IS NULL AND family IS NULL AND prefix_length IS NULL) OR "
    "(family=4 AND length(address)=4 AND prefix_length BETWEEN 0 AND 32) OR "
    "(family=6 AND length(address)=16 AND prefix_length BETWEEN 0 AND 128)),"
    "CHECK((scope_type='global' AND scope_value IS NULL AND "
    "scope_prefix_length IS NULL AND scope_vlan_id IS NULL) OR "
    "(scope_type='mac' AND length(scope_value)=6 AND "
    "scope_prefix_length IS NULL AND scope_vlan_id IS NULL) OR "
    "(scope_type='ipv4' AND length(scope_value)=4 AND "
    "scope_prefix_length BETWEEN 0 AND 32 AND scope_vlan_id IS NULL) OR "
    "(scope_type='ipv6' AND length(scope_value)=16 AND "
    "scope_prefix_length BETWEEN 0 AND 128 AND scope_vlan_id IS NULL) OR "
    "(scope_type='vlan' AND scope_value IS NULL AND "
    "scope_prefix_length IS NULL AND scope_vlan_id BETWEEN 0 AND 4094))"
    ") STRICT;"
    "INSERT INTO destination_rules("
    "id,group_id,effect,source,protocol,family,address,prefix_length,port,"
    "scope_type,attribution,enabled,updated_at"
    ") SELECT id,group_id,effect,'explicit',protocol,family,address,"
    "prefix_length,port,'global',attribution,enabled,unixepoch() "
    "FROM destination_rules_v3;"
    "DROP TABLE destination_rules_v3;"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(4,unixepoch());"
    "PRAGMA user_version=4;";

/** Ordered statement groups composing schema version four. */
static const char *const migration_4[] = {
    migration_4_policy,
};

/** Session revocation and first-boot credentials for schema version five. */
static const char migration_5_identity[] =
    "ALTER TABLE web_sessions ADD COLUMN session_epoch INTEGER NOT NULL "
    "DEFAULT 1 CHECK(session_epoch > 0);"
    "CREATE TABLE bootstrap_credentials ("
    "id INTEGER PRIMARY KEY CHECK(id=1),"
    "token_hash BLOB NOT NULL CHECK(length(token_hash)=32),"
    "created_at INTEGER NOT NULL CHECK(created_at >= 0),"
    "expires_at INTEGER NOT NULL CHECK(expires_at > created_at),"
    "consumed_at INTEGER CHECK(consumed_at IS NULL OR "
    "consumed_at BETWEEN created_at AND expires_at)"
    ") STRICT;"
    "CREATE INDEX web_sessions_expiry_idx ON web_sessions(expires_at);"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(5,unixepoch());"
    "PRAGMA user_version=5;";

/** Ordered statement groups composing schema version five. */
static const char *const migration_5[] = {
    migration_5_identity,
};

/** Ordered migration sequence. */
static const struct database_migration migrations[] = {
    {1U, migration_1, sizeof(migration_1) / sizeof(migration_1[0])},
    {2U, migration_2, sizeof(migration_2) / sizeof(migration_2[0])},
    {3U, migration_3, sizeof(migration_3) / sizeof(migration_3[0])},
    {4U, migration_4, sizeof(migration_4) / sizeof(migration_4[0])},
    {5U, migration_5, sizeof(migration_5) / sizeof(migration_5[0])},
};

/** @brief Translate a SQLite result to the public errno-style contract. */
int jg_database_sqlite_result(int status)
{
    switch (status & 0xff) {
    case SQLITE_OK:
    case SQLITE_DONE:
    case SQLITE_ROW:
        return 0;
    case SQLITE_BUSY:
    case SQLITE_LOCKED:
        return -EBUSY;
    case SQLITE_NOMEM:
        return -ENOMEM;
    case SQLITE_AUTH:
    case SQLITE_CANTOPEN:
    case SQLITE_PERM:
    case SQLITE_READONLY:
        return -EACCES;
    case SQLITE_CORRUPT:
    case SQLITE_NOTADB:
        return -EILSEQ;
    default:
        return -EIO;
    }
}

/** @brief Execute a trusted SQL batch as individually prepared statements. */
static int execute_sql(sqlite3 *handle, const char *sql)
{
    const char *cursor = sql;
    int result = 0;

    while (result == 0 && cursor != NULL && *cursor != '\0') {
        sqlite3_stmt *statement = NULL;
        const char *tail = NULL;
        int status = sqlite3_prepare_v3(
            handle, cursor, -1, SQLITE_PREPARE_PERSISTENT, &statement, &tail);

        result = jg_database_sqlite_result(status);
        if (result == 0 && statement != NULL) {
            do {
                status = sqlite3_step(statement);
            } while (status == SQLITE_ROW);
            result = jg_database_sqlite_result(status);
        }
        if (statement != NULL) {
            status = sqlite3_finalize(statement);
            if (result == 0) {
                result = jg_database_sqlite_result(status);
            }
        }
        cursor = tail;
    }
    return result;
}

/** @brief Validate the immediate parent directory of a database path. */
static int validate_parent(const char *path)
{
    const char *separator = NULL;
    char *parent = NULL;
    size_t parent_length = 0U;
    int descriptor = -1;
    int result = 0;
    struct stat metadata;

    if (path == NULL || path[0] != '/' || path[1] == '\0') {
        return -EINVAL;
    }
    separator = strrchr(path, '/');
    if (separator == NULL || separator[1] == '\0') {
        return -EINVAL;
    }
    parent_length = separator == path ? 1U : (size_t)(separator - path);
    parent = malloc(parent_length + 1U);
    if (parent == NULL) {
        return -ENOMEM;
    }
    (void)memcpy(parent, path, parent_length);
    parent[parent_length] = '\0';

    descriptor = open(parent, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    free(parent);
    if (descriptor < 0) {
        return -errno;
    }
    if (fstat(descriptor, &metadata) != 0) {
        result = -errno;
    } else if (!S_ISDIR(metadata.st_mode) ||
               (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
               (geteuid() != 0U && metadata.st_uid != geteuid())) {
        result = -EACCES;
    }
    (void)close(descriptor);
    return result;
}

/** @brief Create a private database file or validate an existing one. */
static int prepare_file(const char *path, bool *created)
{
    int descriptor =
        open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
             S_IRUSR | S_IWUSR);
    int result = 0;
    struct stat metadata;

    *created = descriptor >= 0;
    if (descriptor < 0 && errno == EEXIST) {
        descriptor = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    }
    if (descriptor < 0) {
        return -errno;
    }
    if (*created && fchmod(descriptor, S_IRUSR | S_IWUSR) != 0) {
        result = -errno;
    } else if (fstat(descriptor, &metadata) != 0) {
        result = -errno;
    } else if (!S_ISREG(metadata.st_mode) ||
               (geteuid() != 0U && metadata.st_uid != geteuid()) ||
               (metadata.st_mode & 0777U) != (S_IRUSR | S_IWUSR)) {
        result = -EACCES;
    }
    (void)close(descriptor);
    return result;
}

/** @brief Read PRAGMA user_version through a prepared statement. */
static int read_version(sqlite3 *handle, uint32_t *version)
{
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, "PRAGMA user_version;", -1, 0U,
                                    &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            const sqlite3_int64 value = sqlite3_column_int64(statement, 0);

            if (value < 0 || value > (sqlite3_int64)UINT32_MAX) {
                result = -EILSEQ;
            } else {
                *version = (uint32_t)value;
            }
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Enable WAL mode and verify that SQLite selected it. */
static int enable_wal(sqlite3 *handle)
{
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, "PRAGMA journal_mode=WAL;", -1, 0U,
                                    &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            const char *mode = (const char *)sqlite3_column_text(statement, 0);

            if (mode == NULL || strcmp(mode, "wal") != 0) {
                result = -EIO;
            }
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Determine whether a version-zero database contains user objects. */
static int database_is_empty(sqlite3 *handle, bool *empty)
{
    static const char query[] =
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%';";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, query, -1, 0U, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            *empty = sqlite3_column_int64(statement, 0) == 0;
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Construct a path by appending a fixed suffix. */
static char *path_with_suffix(const char *path, const char *suffix)
{
    const size_t path_length = strlen(path);
    const size_t suffix_length = strlen(suffix);
    size_t allocation_size = 0U;
    char *combined = NULL;

    if (!jg_size_add(path_length, suffix_length, &allocation_size) ||
        !jg_size_add(allocation_size, 1U, &allocation_size)) {
        return NULL;
    }
    combined = malloc(allocation_size);
    if (combined != NULL) {
        (void)memcpy(combined, path, path_length);
        (void)memcpy(combined + path_length, suffix, suffix_length + 1U);
    }
    return combined;
}

/** @brief Atomically write a last-known-good SQLite backup. */
static int backup_database(const struct jg_database *database)
{
    sqlite3 *target = NULL;
    sqlite3_backup *backup = NULL;
    char *backup_path = path_with_suffix(database->path, ".lkg");
    char *temporary_path = path_with_suffix(database->path, ".lkg.XXXXXX");
    int descriptor = -1;
    int status;
    int result = 0;

    if (backup_path == NULL || temporary_path == NULL) {
        result = -ENOMEM;
    }
    if (result == 0) {
        descriptor = mkstemp(temporary_path);
        if (descriptor < 0) {
            result = -errno;
        }
    }
    if (descriptor >= 0) {
        if (fchmod(descriptor, S_IRUSR | S_IWUSR) != 0) {
            result = -errno;
        }
        if (close(descriptor) != 0 && result == 0) {
            result = -errno;
        }
    }
    if (result == 0) {
        status = sqlite3_open_v2(temporary_path, &target,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX |
                                     SQLITE_OPEN_NOFOLLOW,
                                 NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        backup = sqlite3_backup_init(target, "main", database->handle, "main");
        if (backup == NULL) {
            result = jg_database_sqlite_result(sqlite3_errcode(target));
        }
    }
    if (result == 0) {
        status = sqlite3_backup_step(backup, -1);
        if (status != SQLITE_DONE) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (backup != NULL) {
        status = sqlite3_backup_finish(backup);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (target != NULL) {
        status = sqlite3_close(target);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0 && rename(temporary_path, backup_path) != 0) {
        result = -errno;
    }
    if (result != 0 && temporary_path != NULL) {
        (void)unlink(temporary_path);
    }
    free(temporary_path);
    free(backup_path);
    return result;
}

/** @brief Apply every missing migration transactionally and in order. */
static int migrate_database(struct jg_database *database,
                            uint32_t current_version)
{
    size_t index = 0U;
    int result = 0;

    if (current_version > 0U && current_version < JG_DATABASE_SCHEMA_VERSION) {
        result = backup_database(database);
    }
    for (index = 0U;
         result == 0 && index < sizeof(migrations) / sizeof(migrations[0]);
         ++index) {
        if (migrations[index].version <= current_version) {
            continue;
        }
        result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
        for (size_t sql_index = 0U;
             result == 0 && sql_index < migrations[index].sql_count;
             ++sql_index) {
            result =
                execute_sql(database->handle, migrations[index].sql[sql_index]);
        }
        if (result == 0) {
            result = execute_sql(database->handle, "COMMIT;");
        } else {
            (void)execute_sql(database->handle, "ROLLBACK;");
        }
        if (result == 0) {
            current_version = migrations[index].version;
        }
    }
    if (result == 0 && current_version != JG_DATABASE_SCHEMA_VERSION) {
        result = -EILSEQ;
    }
    return result;
}

/** @brief Run SQLite's full integrity check on an open database. */
int jg_database_check_integrity(struct jg_database *database)
{
    sqlite3_stmt *statement = NULL;
    int status;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, "PRAGMA integrity_check;", -1,
                                0U, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            const char *message =
                (const char *)sqlite3_column_text(statement, 0);

            if (message == NULL || strcmp(message, "ok") != 0) {
                result = -EILSEQ;
            }
        }
    }
    if (result == 0 && sqlite3_step(statement) != SQLITE_DONE) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Open, secure, configure, and migrate a persistent database. */
int jg_database_open(const char *path,
                     uint32_t busy_timeout_ms,
                     struct jg_database **database)
{
    struct jg_database *opened = NULL;
    uint32_t version = 0U;
    bool created = false;
    bool empty = false;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    *database = NULL;
    if (path == NULL || busy_timeout_ms == 0U ||
        busy_timeout_ms > JG_DATABASE_BUSY_TIMEOUT_MAX) {
        return -EINVAL;
    }
    result = validate_parent(path);
    if (result == 0) {
        result = prepare_file(path, &created);
    }
    if (result == 0) {
        opened = calloc(1U, sizeof(*opened));
        if (opened == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        opened->path = strdup(path);
        if (opened->path == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        const int status =
            sqlite3_open_v2(path, &opened->handle,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX |
                                SQLITE_OPEN_NOFOLLOW,
                            NULL);

        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = jg_database_sqlite_result(
            sqlite3_extended_result_codes(opened->handle, 1));
    }
    if (result == 0) {
        result = jg_database_sqlite_result(
            sqlite3_busy_timeout(opened->handle, (int)busy_timeout_ms));
    }
    if (result == 0) {
        result = jg_database_sqlite_result(sqlite3_db_config(
            opened->handle, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL));
    }
    if (result == 0) {
        result = execute_sql(opened->handle, "PRAGMA foreign_keys=ON;"
                                             "PRAGMA trusted_schema=OFF;"
                                             "PRAGMA synchronous=FULL;");
    }
    if (result == 0) {
        result = enable_wal(opened->handle);
    }
    if (result == 0) {
        result = jg_database_check_integrity(opened);
    }
    if (result == 0) {
        result = read_version(opened->handle, &version);
    }
    if (result == 0 && version > JG_DATABASE_SCHEMA_VERSION) {
        result = -ENOTSUP;
    }
    if (result == 0 && version == 0U) {
        result = database_is_empty(opened->handle, &empty);
        if (result == 0 && !empty) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        result = migrate_database(opened, version);
    }
    if (result == 0) {
        result = jg_database_check_integrity(opened);
    }
    if (result != 0) {
        jg_database_close(opened);
        if (created) {
            (void)unlink(path);
        }
        return result;
    }
    *database = opened;
    return 0;
}

/** @brief Close an owned database connection and release its path. */
void jg_database_close(struct jg_database *database)
{
    if (database == NULL) {
        return;
    }
    if (database->handle != NULL) {
        (void)sqlite3_close_v2(database->handle);
    }
    free(database->path);
    free(database);
}

/** @brief Read the schema version from an open database. */
int jg_database_schema_version(struct jg_database *database, uint32_t *version)
{
    if (database == NULL || version == NULL) {
        return -EINVAL;
    }
    return read_version(database->handle, version);
}

/** @brief Parse a required SQLite text column without embedded null bytes. */
static int required_text(sqlite3_stmt *statement,
                         int column,
                         const char **text,
                         size_t *length)
{
    const unsigned char *value = NULL;
    int byte_count = 0;

    if (sqlite3_column_type(statement, column) != SQLITE_TEXT) {
        return -EILSEQ;
    }
    value = sqlite3_column_text(statement, column);
    byte_count = sqlite3_column_bytes(statement, column);
    if (value == NULL || byte_count <= 0 ||
        memchr(value, '\0', (size_t)byte_count) != NULL) {
        return -EILSEQ;
    }
    *text = (const char *)value;
    *length = (size_t)byte_count;
    return 0;
}

/** @brief Return one lowercase hexadecimal digit. */
static char hex_digit(uint8_t value)
{
    static const char digits[] = "0123456789abcdef";

    return digits[value & UINT8_C(0x0f)];
}

/** @brief Encode fixed-size bytes as canonical lowercase hexadecimal text. */
static void encode_hex(const uint8_t *wire, size_t wire_size, char *text)
{
    size_t index = 0U;

    for (index = 0U; index < wire_size; ++index) {
        text[index * 2U] = hex_digit((uint8_t)(wire[index] >> 4U));
        text[index * 2U + 1U] = hex_digit(wire[index]);
    }
    text[wire_size * 2U] = '\0';
}

/** @brief Decode one lowercase hexadecimal digit. */
static bool decode_hex_digit(char digit, uint8_t *value)
{
    if (digit >= '0' && digit <= '9') {
        *value = (uint8_t)(digit - '0');
        return true;
    }
    if (digit >= 'a' && digit <= 'f') {
        *value = (uint8_t)(digit - 'a') + 10U;
        return true;
    }
    return false;
}

/** @brief Decode canonical lowercase hexadecimal text into fixed-size bytes. */
static int decode_hex(const char *text,
                      size_t text_size,
                      uint8_t *wire,
                      size_t wire_size)
{
    size_t index = 0U;

    if (text_size != wire_size * 2U) {
        return -EILSEQ;
    }
    for (index = 0U; index < wire_size; ++index) {
        uint8_t high = 0U;
        uint8_t low = 0U;

        if (!decode_hex_digit(text[index * 2U], &high) ||
            !decode_hex_digit(text[index * 2U + 1U], &low)) {
            return -EILSEQ;
        }
        wire[index] = (uint8_t)((uint8_t)(high << 4U) | low);
    }
    return 0;
}

/** @brief Atomically persist one validated network configuration. */
int jg_database_store_network_config(struct jg_database *database,
                                     const struct jg_network_config *config)
{
    static const char statement_text[] =
        "INSERT INTO system_settings(key,value,updated_at)"
        " VALUES('network.configuration',?1,unixepoch())"
        " ON CONFLICT(key) DO UPDATE SET"
        " value=excluded.value,updated_at=excluded.updated_at;";
    char text[JG_NETWORK_CONFIG_WIRE_SIZE * 2U + 1U];
    uint8_t wire[JG_NETWORK_CONFIG_WIRE_SIZE];
    sqlite3_stmt *statement = NULL;
    size_t encoded_size = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result =
        jg_network_config_encode(config, wire, sizeof(wire), &encoded_size);
    if (result != 0) {
        return result;
    }
    if (encoded_size != sizeof(wire)) {
        return -EIO;
    }
    encode_hex(wire, sizeof(wire), text);
    status = sqlite3_prepare_v3(database->handle, statement_text, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, text, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Load one validated persistent network configuration. */
int jg_database_load_network_config(struct jg_database *database,
                                    struct jg_network_config *config)
{
    static const char query[] = "SELECT value FROM system_settings"
                                " WHERE key='network.configuration';";
    uint8_t wire[JG_NETWORK_CONFIG_WIRE_SIZE];
    struct jg_network_config loaded;
    sqlite3_stmt *statement = NULL;
    const char *text = NULL;
    size_t text_size = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || config == NULL) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = required_text(statement, 0, &text, &text_size);
    }
    if (result == 0) {
        result = decode_hex(text, text_size, wire, sizeof(wire));
    }
    if (result == 0 &&
        jg_network_config_decode(wire, sizeof(wire), &loaded) != 0) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *config = loaded;
    }
    return result;
}

/** @brief Atomically persist one validated DNS response configuration. */
int jg_database_store_dns_response_config(
    struct jg_database *database,
    const struct jg_dns_response_config *config)
{
    static const char statement_text[] =
        "INSERT INTO system_settings(key,value,updated_at)"
        " VALUES('dns.response',?1,unixepoch())"
        " ON CONFLICT(key) DO UPDATE SET"
        " value=excluded.value,updated_at=excluded.updated_at;";
    char text[JG_DNS_RESPONSE_CONFIG_WIRE_SIZE * 2U + 1U];
    uint8_t wire[JG_DNS_RESPONSE_CONFIG_WIRE_SIZE];
    sqlite3_stmt *statement = NULL;
    size_t encoded_size = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = jg_dns_response_config_encode(config, wire, sizeof(wire),
                                           &encoded_size);
    if (result != 0) {
        return result;
    }
    if (encoded_size != sizeof(wire)) {
        return -EIO;
    }
    encode_hex(wire, sizeof(wire), text);
    status = sqlite3_prepare_v3(database->handle, statement_text, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, text, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Load one validated persistent DNS response configuration. */
int jg_database_load_dns_response_config(struct jg_database *database,
                                         struct jg_dns_response_config *config)
{
    static const char query[] = "SELECT value FROM system_settings"
                                " WHERE key='dns.response';";
    uint8_t wire[JG_DNS_RESPONSE_CONFIG_WIRE_SIZE];
    struct jg_dns_response_config loaded;
    sqlite3_stmt *statement = NULL;
    const char *text = NULL;
    size_t text_size = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || config == NULL) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = required_text(statement, 0, &text, &text_size);
    }
    if (result == 0) {
        result = decode_hex(text, text_size, wire, sizeof(wire));
    }
    if (result == 0 &&
        jg_dns_response_config_decode(wire, sizeof(wire), &loaded) != 0) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *config = loaded;
    }
    return result;
}

/** @brief Return the persistent text representation of a policy effect. */
static const char *effect_text(enum jg_policy_effect effect)
{
    return effect == JG_POLICY_ALLOW ? "allow" : "block";
}

/** @brief Return the persistent text representation of a transport selector. */
static const char *transport_text(enum jg_policy_transport transport)
{
    switch (transport) {
    case JG_POLICY_TRANSPORT_ANY:
        return "any";
    case JG_POLICY_TRANSPORT_TCP:
        return "tcp";
    case JG_POLICY_TRANSPORT_UDP:
        return "udp";
    default:
        return NULL;
    }
}

/** @brief Return the persistent text representation of a domain target. */
static const char *target_text(enum jg_policy_domain_target target)
{
    switch (target) {
    case JG_POLICY_DOMAIN_DNS:
        return "dns";
    case JG_POLICY_DOMAIN_TLS_SNI:
        return "tls_sni";
    default:
        return NULL;
    }
}

/** @brief Return the persistent text representation of a policy source. */
static const char *source_text(enum jg_policy_source source)
{
    switch (source) {
    case JG_POLICY_SOURCE_BLOCKLIST:
        return "blocklist";
    case JG_POLICY_SOURCE_EXPLICIT:
        return "explicit";
    case JG_POLICY_SOURCE_EMERGENCY:
        return "emergency";
    case JG_POLICY_SOURCE_DEFAULT:
    default:
        return NULL;
    }
}

/** @brief Return the persistent text representation of a policy scope. */
static const char *scope_text(enum jg_policy_scope_type type)
{
    switch (type) {
    case JG_POLICY_SCOPE_GLOBAL:
        return "global";
    case JG_POLICY_SCOPE_MAC:
        return "mac";
    case JG_POLICY_SCOPE_IPV4:
        return "ipv4";
    case JG_POLICY_SCOPE_IPV6:
        return "ipv6";
    case JG_POLICY_SCOPE_VLAN:
        return "vlan";
    default:
        return NULL;
    }
}

/** @brief Mask host bits from one policy network before persistence. */
static void canonical_network(uint8_t *output,
                              const uint8_t *input,
                              size_t address_size,
                              uint8_t prefix_length)
{
    const size_t complete_bytes = (size_t)prefix_length / 8U;
    const uint8_t remaining_bits = (uint8_t)(prefix_length % 8U);
    size_t first_clear_byte = complete_bytes;

    (void)memset(output, 0, 16U);
    (void)memcpy(output, input, address_size);
    if (remaining_bits != 0U) {
        const uint8_t mask = (uint8_t)(UINT8_C(0xff) << (8U - remaining_bits));

        output[complete_bytes] &= mask;
        first_clear_byte = complete_bytes + 1U;
    }
    if (first_clear_byte < address_size) {
        (void)memset(output + first_clear_byte, 0,
                     address_size - first_clear_byte);
    }
}

/** @brief Validate a complete replacement rule set before opening a
 * transaction. */
static int validate_domain_rules(const struct jg_policy_rule_input *rules,
                                 size_t rule_count)
{
    struct jg_policy_snapshot *validation = NULL;
    size_t index = 0U;
    int result = 0;

    if (rule_count > JG_DATABASE_POLICY_RULE_LIMIT ||
        (rule_count != 0U && rules == NULL)) {
        return -EINVAL;
    }
    for (index = 0U; index < rule_count; ++index) {
        if (rules[index].id > (uint64_t)INT64_MAX) {
            return -EOVERFLOW;
        }
    }
    result = jg_policy_snapshot_build(rules, rule_count, 1U, &validation);
    jg_policy_snapshot_destroy(validation);
    return result;
}

/** @brief Bind a validated policy scope to one domain-rule insert. */
static int bind_scope(sqlite3_stmt *statement,
                      const struct jg_policy_scope *scope,
                      int type_parameter,
                      int value_parameter,
                      int prefix_parameter,
                      int vlan_parameter)
{
    uint8_t address[16U];
    const char *type = scope_text(scope->type);
    int status = SQLITE_OK;

    if (type == NULL) {
        return -EINVAL;
    }
    status =
        sqlite3_bind_text(statement, type_parameter, type, -1, SQLITE_STATIC);
    if (status != SQLITE_OK) {
        return jg_database_sqlite_result(status);
    }
    switch (scope->type) {
    case JG_POLICY_SCOPE_GLOBAL:
        break;
    case JG_POLICY_SCOPE_MAC:
        status = sqlite3_bind_blob(statement, value_parameter, scope->value.mac,
                                   6, SQLITE_TRANSIENT);
        break;
    case JG_POLICY_SCOPE_IPV4:
        canonical_network(address, scope->value.network.address, 4U,
                          scope->value.network.prefix_length);
        status = sqlite3_bind_blob(statement, value_parameter, address, 4,
                                   SQLITE_TRANSIENT);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, prefix_parameter,
                                      scope->value.network.prefix_length);
        }
        break;
    case JG_POLICY_SCOPE_IPV6:
        canonical_network(address, scope->value.network.address, 16U,
                          scope->value.network.prefix_length);
        status = sqlite3_bind_blob(statement, value_parameter, address, 16,
                                   SQLITE_TRANSIENT);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, prefix_parameter,
                                      scope->value.network.prefix_length);
        }
        break;
    case JG_POLICY_SCOPE_VLAN:
        status =
            sqlite3_bind_int(statement, vlan_parameter, scope->value.vlan_id);
        break;
    default:
        return -EINVAL;
    }
    return jg_database_sqlite_result(status);
}

/** @brief Bind and insert one validated domain rule. */
static int insert_domain_rule(sqlite3_stmt *statement,
                              const struct jg_policy_rule_input *rule)
{
    char normalized[JG_DOMAIN_NAME_MAX + 1U];
    const char *persistent_source = source_text(rule->source);
    const char *persistent_target = target_text(rule->target);
    int status = sqlite3_reset(statement);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        result = jg_database_sqlite_result(sqlite3_clear_bindings(statement));
    }
    if (result == 0) {
        result =
            jg_domain_normalize(rule->domain, normalized, sizeof(normalized));
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)rule->id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_text(statement, 2, normalized, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(
            statement, 3, rule->include_subdomains ? "suffix" : "exact", -1,
            SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 4, effect_text(rule->effect), -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && persistent_source != NULL) {
        status = sqlite3_bind_text(statement, 5, persistent_source, -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        result = -EINVAL;
    }
    if (result == 0) {
        result = bind_scope(statement, &rule->scope, 6, 7, 8, 9);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 10, rule->attribution, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && persistent_target != NULL) {
        status = sqlite3_bind_text(statement, 11, persistent_target, -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        result = -EINVAL;
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    return result;
}

/** @brief Atomically replace every active persistent domain rule. */
int jg_database_replace_domain_rules(struct jg_database *database,
                                     const struct jg_policy_rule_input *rules,
                                     size_t rule_count)
{
    static const char insert[] =
        "INSERT INTO domain_rules("
        "id,domain,match_type,effect,source,scope_type,scope_value,"
        "prefix_length,vlan_id,attribution,enabled,updated_at,target"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,unixepoch(),?11);";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    int status;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = validate_domain_rules(rules, rule_count);
    if (result == 0) {
        result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    }
    if (result == 0) {
        result = execute_sql(database->handle, "DELETE FROM domain_rules;");
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    for (index = 0U; result == 0 && index < rule_count; ++index) {
        result = insert_domain_rule(statement, &rules[index]);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = execute_sql(database->handle, "COMMIT;");
    } else {
        (void)execute_sql(database->handle, "ROLLBACK;");
    }
    return result;
}

/** @brief Validate destination rules before opening a write transaction. */
static int validate_destination_rules(
    const struct jg_policy_destination_rule_input *rules,
    size_t rule_count)
{
    struct jg_policy_snapshot *validation = NULL;
    size_t index = 0U;
    int result = 0;

    if (rule_count > JG_DATABASE_POLICY_RULE_LIMIT ||
        (rule_count != 0U && rules == NULL)) {
        return -EINVAL;
    }
    for (index = 0U; index < rule_count; ++index) {
        if (rules[index].id > (uint64_t)INT64_MAX) {
            return -EOVERFLOW;
        }
    }
    result = jg_policy_snapshot_build_complete(NULL, 0U, rules, rule_count, 1U,
                                               &validation);
    jg_policy_snapshot_destroy(validation);
    return result;
}

/** @brief Bind and insert one validated destination rule. */
static int insert_destination_rule(
    sqlite3_stmt *statement,
    const struct jg_policy_destination_rule_input *rule)
{
    uint8_t address[16U];
    const char *persistent_source = source_text(rule->source);
    const char *persistent_transport = transport_text(rule->transport);
    int status = sqlite3_reset(statement);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        result = jg_database_sqlite_result(sqlite3_clear_bindings(statement));
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)rule->id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 2, effect_text(rule->effect), -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && persistent_source != NULL) {
        status = sqlite3_bind_text(statement, 3, persistent_source, -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        result = -EINVAL;
    }
    if (result == 0 && persistent_transport != NULL) {
        status = sqlite3_bind_text(statement, 4, persistent_transport, -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    } else if (result == 0) {
        result = -EINVAL;
    }
    if (result == 0 && rule->has_address) {
        const size_t address_size =
            rule->address_family == JG_POLICY_ADDRESS_IPV4 ? 4U : 16U;

        canonical_network(address, rule->address, address_size,
                          rule->prefix_length);
        status = sqlite3_bind_int(statement, 5, (int)rule->address_family);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_blob(statement, 6, address, (int)address_size,
                                       SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, 7, rule->prefix_length);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && rule->has_port) {
        status = sqlite3_bind_int(statement, 8, rule->port);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_scope(statement, &rule->scope, 9, 10, 11, 12);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 13, rule->attribution, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    return result;
}

/** @brief Atomically replace every active persistent destination rule. */
int jg_database_replace_destination_rules(
    struct jg_database *database,
    const struct jg_policy_destination_rule_input *rules,
    size_t rule_count)
{
    static const char insert[] =
        "INSERT INTO destination_rules("
        "id,effect,source,protocol,family,address,prefix_length,port,"
        "scope_type,scope_value,scope_prefix_length,scope_vlan_id,"
        "attribution,enabled,updated_at"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,1,"
        "unixepoch());";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = validate_destination_rules(rules, rule_count);
    if (result == 0) {
        result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    }
    if (result == 0) {
        result =
            execute_sql(database->handle, "DELETE FROM destination_rules;");
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    for (index = 0U; result == 0 && index < rule_count; ++index) {
        result = insert_destination_rule(statement, &rules[index]);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = execute_sql(database->handle, "COMMIT;");
    } else {
        (void)execute_sql(database->handle, "ROLLBACK;");
    }
    return result;
}

/** @brief Decode a persistent policy effect. */
static int decode_effect(const char *text, enum jg_policy_effect *effect)
{
    if (strcmp(text, "allow") == 0) {
        *effect = JG_POLICY_ALLOW;
        return 0;
    }
    if (strcmp(text, "block") == 0) {
        *effect = JG_POLICY_BLOCK;
        return 0;
    }
    return -EILSEQ;
}

/** @brief Decode a persistent policy source. */
static int decode_source(const char *text, enum jg_policy_source *source)
{
    if (strcmp(text, "blocklist") == 0) {
        *source = JG_POLICY_SOURCE_BLOCKLIST;
        return 0;
    }
    if (strcmp(text, "explicit") == 0) {
        *source = JG_POLICY_SOURCE_EXPLICIT;
        return 0;
    }
    if (strcmp(text, "emergency") == 0) {
        *source = JG_POLICY_SOURCE_EMERGENCY;
        return 0;
    }
    return -EILSEQ;
}

/** @brief Decode one persistent transport selector. */
static int decode_transport(const char *text,
                            enum jg_policy_transport *transport)
{
    if (strcmp(text, "any") == 0) {
        *transport = JG_POLICY_TRANSPORT_ANY;
        return 0;
    }
    if (strcmp(text, "tcp") == 0) {
        *transport = JG_POLICY_TRANSPORT_TCP;
        return 0;
    }
    if (strcmp(text, "udp") == 0) {
        *transport = JG_POLICY_TRANSPORT_UDP;
        return 0;
    }
    return -EILSEQ;
}

/** @brief Decode a persistent domain-policy target. */
static int decode_target(const char *text, enum jg_policy_domain_target *target)
{
    if (strcmp(text, "dns") == 0) {
        *target = JG_POLICY_DOMAIN_DNS;
        return 0;
    }
    if (strcmp(text, "tls_sni") == 0) {
        *target = JG_POLICY_DOMAIN_TLS_SNI;
        return 0;
    }
    return -EILSEQ;
}

/** @brief Decode and validate one persistent client scope. */
static int decode_scope(sqlite3_stmt *statement,
                        const char *type,
                        int value_column,
                        int prefix_column,
                        int vlan_column,
                        struct jg_policy_scope *scope)
{
    const void *value = sqlite3_column_blob(statement, value_column);
    const int value_size = sqlite3_column_bytes(statement, value_column);

    (void)memset(scope, 0, sizeof(*scope));
    if (strcmp(type, "global") == 0) {
        scope->type = JG_POLICY_SCOPE_GLOBAL;
        return sqlite3_column_type(statement, value_column) == SQLITE_NULL &&
                       sqlite3_column_type(statement, prefix_column) ==
                           SQLITE_NULL &&
                       sqlite3_column_type(statement, vlan_column) ==
                           SQLITE_NULL
                   ? 0
                   : -EILSEQ;
    }
    if (strcmp(type, "mac") == 0 && value != NULL && value_size == 6) {
        scope->type = JG_POLICY_SCOPE_MAC;
        (void)memcpy(scope->value.mac, value, 6U);
        return 0;
    }
    if (strcmp(type, "ipv4") == 0 && value != NULL && value_size == 4 &&
        sqlite3_column_type(statement, prefix_column) == SQLITE_INTEGER) {
        const int prefix = sqlite3_column_int(statement, prefix_column);

        if (prefix >= 0 && prefix <= 32) {
            scope->type = JG_POLICY_SCOPE_IPV4;
            (void)memcpy(scope->value.network.address, value, 4U);
            scope->value.network.prefix_length = (uint8_t)prefix;
            return 0;
        }
    }
    if (strcmp(type, "ipv6") == 0 && value != NULL && value_size == 16 &&
        sqlite3_column_type(statement, prefix_column) == SQLITE_INTEGER) {
        const int prefix = sqlite3_column_int(statement, prefix_column);

        if (prefix >= 0 && prefix <= 128) {
            scope->type = JG_POLICY_SCOPE_IPV6;
            (void)memcpy(scope->value.network.address, value, 16U);
            scope->value.network.prefix_length = (uint8_t)prefix;
            return 0;
        }
    }
    if (strcmp(type, "vlan") == 0 &&
        sqlite3_column_type(statement, vlan_column) == SQLITE_INTEGER) {
        const int vlan_id = sqlite3_column_int(statement, vlan_column);

        if (vlan_id >= 0 && vlan_id <= 4094) {
            scope->type = JG_POLICY_SCOPE_VLAN;
            scope->value.vlan_id = (uint16_t)vlan_id;
            return 0;
        }
    }
    return -EILSEQ;
}

/** @brief Decode one selected database row into snapshot-builder input. */
static int decode_domain_rule(sqlite3_stmt *statement,
                              struct jg_policy_rule_input *rule,
                              char *strings,
                              size_t strings_size,
                              size_t *cursor)
{
    const char *domain = NULL;
    const char *match_type = NULL;
    const char *effect = NULL;
    const char *source = NULL;
    const char *scope = NULL;
    const char *attribution = NULL;
    const char *target = NULL;
    size_t domain_length = 0U;
    size_t text_length = 0U;
    size_t attribution_length = 0U;
    sqlite3_int64 identifier = 0;
    int result = 0;

    if (sqlite3_column_type(statement, 0) != SQLITE_INTEGER) {
        return -EILSEQ;
    }
    identifier = sqlite3_column_int64(statement, 0);
    if (identifier <= 0) {
        return -EILSEQ;
    }
    result = required_text(statement, 1, &domain, &domain_length);
    if (result == 0 && !jg_domain_is_normalized(domain)) {
        result = -EILSEQ;
    }
    if (result == 0) {
        result = required_text(statement, 2, &match_type, &text_length);
    }
    if (result == 0) {
        if (strcmp(match_type, "suffix") == 0) {
            rule->include_subdomains = true;
        } else if (strcmp(match_type, "exact") != 0) {
            result = -EILSEQ;
        }
    }
    if (result == 0) {
        result = required_text(statement, 3, &effect, &text_length);
    }
    if (result == 0) {
        result = decode_effect(effect, &rule->effect);
    }
    if (result == 0) {
        result = required_text(statement, 4, &source, &text_length);
    }
    if (result == 0) {
        result = decode_source(source, &rule->source);
    }
    if (result == 0) {
        result = required_text(statement, 5, &scope, &text_length);
    }
    if (result == 0) {
        result = decode_scope(statement, scope, 6, 7, 8, &rule->scope);
    }
    if (result == 0) {
        result = required_text(statement, 9, &attribution, &attribution_length);
    }
    if (result == 0) {
        result = required_text(statement, 10, &target, &text_length);
    }
    if (result == 0) {
        result = decode_target(target, &rule->target);
    }
    if (result == 0 &&
        (!jg_range_valid(*cursor, domain_length + 1U, strings_size) ||
         !jg_range_valid(*cursor + domain_length + 1U, attribution_length + 1U,
                         strings_size))) {
        result = -EOVERFLOW;
    }
    if (result == 0) {
        rule->id = (uint64_t)identifier;
        rule->domain = strings + *cursor;
        (void)memcpy(strings + *cursor, domain, domain_length);
        strings[*cursor + domain_length] = '\0';
        *cursor += domain_length + 1U;
        rule->attribution = strings + *cursor;
        (void)memcpy(strings + *cursor, attribution, attribution_length);
        strings[*cursor + attribution_length] = '\0';
        *cursor += attribution_length + 1U;
    }
    return result;
}

/** @brief Decode one persistent destination address and prefix. */
static int decode_destination_address(
    sqlite3_stmt *statement,
    struct jg_policy_destination_rule_input *rule)
{
    const int address_type = sqlite3_column_type(statement, 5);

    if (address_type == SQLITE_NULL) {
        return sqlite3_column_type(statement, 4) == SQLITE_NULL &&
                       sqlite3_column_type(statement, 6) == SQLITE_NULL
                   ? 0
                   : -EILSEQ;
    }
    if (address_type == SQLITE_BLOB &&
        sqlite3_column_type(statement, 4) == SQLITE_INTEGER &&
        sqlite3_column_type(statement, 6) == SQLITE_INTEGER) {
        const int family = sqlite3_column_int(statement, 4);
        const int prefix = sqlite3_column_int(statement, 6);
        const int address_size = sqlite3_column_bytes(statement, 5);
        const void *address = sqlite3_column_blob(statement, 5);

        if ((family == 4 && address_size == 4 && prefix >= 0 && prefix <= 32) ||
            (family == 6 && address_size == 16 && prefix >= 0 &&
             prefix <= 128)) {
            rule->has_address = true;
            rule->address_family = (enum jg_policy_address_family)family;
            rule->prefix_length = (uint8_t)prefix;
            (void)memcpy(rule->address, address, (size_t)address_size);
            return 0;
        }
    }
    return -EILSEQ;
}

/** @brief Decode one selected destination-rule database row. */
static int decode_destination_rule(
    sqlite3_stmt *statement,
    struct jg_policy_destination_rule_input *rule,
    char *strings,
    size_t strings_size,
    size_t *cursor)
{
    const char *effect = NULL;
    const char *source = NULL;
    const char *transport = NULL;
    const char *scope = NULL;
    const char *attribution = NULL;
    size_t text_length = 0U;
    size_t attribution_length = 0U;
    sqlite3_int64 identifier = 0;
    int result = 0;

    if (sqlite3_column_type(statement, 0) != SQLITE_INTEGER) {
        return -EILSEQ;
    }
    identifier = sqlite3_column_int64(statement, 0);
    if (identifier <= 0) {
        return -EILSEQ;
    }
    result = required_text(statement, 1, &effect, &text_length);
    if (result == 0) {
        result = decode_effect(effect, &rule->effect);
    }
    if (result == 0) {
        result = required_text(statement, 2, &source, &text_length);
    }
    if (result == 0) {
        result = decode_source(source, &rule->source);
    }
    if (result == 0) {
        result = required_text(statement, 3, &transport, &text_length);
    }
    if (result == 0) {
        result = decode_transport(transport, &rule->transport);
    }
    if (result == 0) {
        result = decode_destination_address(statement, rule);
    }
    if (result == 0 && sqlite3_column_type(statement, 7) != SQLITE_NULL) {
        const int port = sqlite3_column_int(statement, 7);

        if (sqlite3_column_type(statement, 7) != SQLITE_INTEGER || port <= 0 ||
            port > 65535) {
            result = -EILSEQ;
        } else {
            rule->has_port = true;
            rule->port = (uint16_t)port;
        }
    }
    if (result == 0 && !rule->has_address && !rule->has_port) {
        result = -EILSEQ;
    }
    if (result == 0) {
        result = required_text(statement, 8, &scope, &text_length);
    }
    if (result == 0) {
        result = decode_scope(statement, scope, 9, 10, 11, &rule->scope);
    }
    if (result == 0) {
        result =
            required_text(statement, 12, &attribution, &attribution_length);
    }
    if (result == 0 &&
        !jg_range_valid(*cursor, attribution_length + 1U, strings_size)) {
        result = -EOVERFLOW;
    }
    if (result == 0) {
        rule->id = (uint64_t)identifier;
        rule->attribution = strings + *cursor;
        (void)memcpy(strings + *cursor, attribution, attribution_length);
        strings[*cursor + attribution_length] = '\0';
        *cursor += attribution_length + 1U;
    }
    return result;
}

/** @brief Read active rule counts and packed-string bytes. */
static int read_policy_size(sqlite3 *handle,
                            size_t *rule_count,
                            size_t *strings_size)
{
    static const char query[] =
        "SELECT count(*),coalesce(sum("
        "length(CAST(domain AS BLOB))+length(CAST(attribution AS BLOB))+2),0)"
        " FROM domain_rules WHERE enabled=1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, query, -1, 0U, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            const sqlite3_int64 count = sqlite3_column_int64(statement, 0);
            const sqlite3_int64 bytes = sqlite3_column_int64(statement, 1);

            if (count < 0 ||
                count > (sqlite3_int64)JG_DATABASE_POLICY_RULE_LIMIT ||
                bytes < 0 || (uint64_t)bytes > (uint64_t)SIZE_MAX) {
                result = -EOVERFLOW;
            } else {
                *rule_count = (size_t)count;
                *strings_size = (size_t)bytes;
            }
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Read active destination-rule count and attribution bytes. */
static int read_destination_policy_size(sqlite3 *handle,
                                        size_t *rule_count,
                                        size_t *strings_size)
{
    static const char query[] = "SELECT count(*),coalesce(sum("
                                "length(CAST(attribution AS BLOB))+1),0)"
                                " FROM destination_rules WHERE enabled=1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, query, -1, 0U, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            const sqlite3_int64 count = sqlite3_column_int64(statement, 0);
            const sqlite3_int64 bytes = sqlite3_column_int64(statement, 1);

            if (count < 0 ||
                count > (sqlite3_int64)JG_DATABASE_POLICY_RULE_LIMIT ||
                bytes < 0 || (uint64_t)bytes > (uint64_t)SIZE_MAX) {
                result = -EOVERFLOW;
            } else {
                *rule_count = (size_t)count;
                *strings_size = (size_t)bytes;
            }
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Read enabled encrypted-DNS endpoint count and attribution bytes. */
static int read_encrypted_endpoint_size(sqlite3 *handle,
                                        size_t *rule_count,
                                        size_t *strings_size)
{
    static const char query[] =
        "SELECT count(*),coalesce(sum(length(CAST(s.name AS BLOB))+1),0)"
        " FROM encrypted_dns_endpoints e"
        " JOIN encrypted_dns_sources s ON s.id=e.source_id"
        " WHERE s.enabled=1;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(handle, query, -1, 0U, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        } else {
            const sqlite3_int64 count = sqlite3_column_int64(statement, 0);
            const sqlite3_int64 bytes = sqlite3_column_int64(statement, 1);

            if (count < 0 ||
                count > (sqlite3_int64)JG_DATABASE_POLICY_RULE_LIMIT ||
                bytes < 0 || (uint64_t)bytes > (uint64_t)SIZE_MAX) {
                result = -EOVERFLOW;
            } else {
                *rule_count = (size_t)count;
                *strings_size = (size_t)bytes;
            }
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Copy one consistent active-rule view into caller-owned storage. */
static int read_domain_rules(sqlite3 *handle,
                             struct jg_policy_rule_input *rules,
                             size_t rule_count,
                             char *strings,
                             size_t strings_size)
{
    static const char query[] =
        "SELECT id,domain,match_type,effect,source,scope_type,scope_value,"
        "prefix_length,vlan_id,attribution,target FROM domain_rules "
        "WHERE enabled=1 ORDER BY id;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    size_t cursor = 0U;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (index >= rule_count) {
            result = -EILSEQ;
        } else {
            result = decode_domain_rule(statement, &rules[index], strings,
                                        strings_size, &cursor);
            ++index;
        }
    }
    if (result == 0 && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && (index != rule_count || cursor != strings_size)) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Copy one consistent active destination-rule view. */
static int read_destination_rules(
    sqlite3 *handle,
    struct jg_policy_destination_rule_input *rules,
    size_t rule_count,
    char *strings,
    size_t strings_size)
{
    static const char query[] =
        "SELECT id,effect,source,protocol,family,address,prefix_length,port,"
        "scope_type,scope_value,scope_prefix_length,scope_vlan_id,attribution "
        "FROM destination_rules WHERE enabled=1 ORDER BY id;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    size_t cursor = 0U;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (index >= rule_count) {
            result = -EILSEQ;
        } else {
            result = decode_destination_rule(statement, &rules[index], strings,
                                             strings_size, &cursor);
            ++index;
        }
    }
    if (result == 0 && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && (index != rule_count || cursor != strings_size)) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Copy enabled encrypted-DNS endpoints into destination-rule input. */
static int read_encrypted_endpoints(
    sqlite3 *handle,
    struct jg_policy_destination_rule_input *rules,
    size_t rule_count,
    char *strings,
    size_t strings_size)
{
    static const char query[] =
        "SELECT s.name,e.family,e.address,e.port,e.transport"
        " FROM encrypted_dns_endpoints e"
        " JOIN encrypted_dns_sources s ON s.id=e.source_id"
        " WHERE s.enabled=1"
        " ORDER BY s.id,e.family,e.address,e.port,e.transport;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    size_t cursor = 0U;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        const char *attribution = NULL;
        const char *transport = NULL;
        const void *address = sqlite3_column_blob(statement, 2);
        const int address_size = sqlite3_column_bytes(statement, 2);
        const int family = sqlite3_column_int(statement, 1);
        const int port = sqlite3_column_int(statement, 3);
        size_t attribution_size = 0U;
        size_t text_size = 0U;

        if (index >= rule_count ||
            sqlite3_column_type(statement, 1) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 2) != SQLITE_BLOB ||
            sqlite3_column_type(statement, 3) != SQLITE_INTEGER || port <= 0 ||
            port > 65535 ||
            !((family == 4 && address_size == 4) ||
              (family == 6 && address_size == 16))) {
            result = -EILSEQ;
        }
        if (result == 0) {
            result =
                required_text(statement, 0, &attribution, &attribution_size);
        }
        if (result == 0) {
            result = required_text(statement, 4, &transport, &text_size);
        }
        if (result == 0) {
            result = decode_transport(transport, &rules[index].transport);
        }
        if (result == 0 && rules[index].transport != JG_POLICY_TRANSPORT_TCP &&
            rules[index].transport != JG_POLICY_TRANSPORT_UDP) {
            result = -EILSEQ;
        }
        if (result == 0 &&
            !jg_range_valid(cursor, attribution_size + 1U, strings_size)) {
            result = -EOVERFLOW;
        }
        if (result == 0) {
            rules[index].id = (UINT64_C(1) << 63U) | (uint64_t)(index + 1U);
            rules[index].effect = JG_POLICY_BLOCK;
            rules[index].source = JG_POLICY_SOURCE_BLOCKLIST;
            rules[index].has_address = true;
            rules[index].address_family = (enum jg_policy_address_family)family;
            (void)memcpy(rules[index].address, address, (size_t)address_size);
            rules[index].prefix_length = family == 4 ? 32U : 128U;
            rules[index].has_port = true;
            rules[index].port = (uint16_t)port;
            rules[index].scope.type = JG_POLICY_SCOPE_GLOBAL;
            rules[index].attribution = strings + cursor;
            (void)memcpy(strings + cursor, attribution, attribution_size);
            strings[cursor + attribution_size] = '\0';
            cursor += attribution_size + 1U;
            ++index;
        }
    }
    if (result == 0 && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (result == 0 && (index != rule_count || cursor != strings_size)) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Load active persistent rules into a new immutable snapshot. */
int jg_database_load_policy_snapshot(struct jg_database *database,
                                     uint64_t generation,
                                     struct jg_policy_snapshot **snapshot)
{
    struct jg_policy_rule_input *rules = NULL;
    struct jg_policy_destination_rule_input *destination_rules = NULL;
    char *strings = NULL;
    char *destination_strings = NULL;
    size_t rule_count = 0U;
    size_t destination_rule_count = 0U;
    size_t encrypted_endpoint_count = 0U;
    size_t complete_destination_count = 0U;
    size_t strings_size = 0U;
    size_t destination_strings_size = 0U;
    size_t encrypted_strings_size = 0U;
    size_t complete_destination_strings_size = 0U;
    size_t rules_size = 0U;
    size_t destination_rules_size = 0U;
    int result = 0;

    if (snapshot == NULL) {
        return -EINVAL;
    }
    *snapshot = NULL;
    if (database == NULL || generation == 0U) {
        return -EINVAL;
    }
    result = execute_sql(database->handle, "BEGIN;");
    if (result == 0) {
        result = read_policy_size(database->handle, &rule_count, &strings_size);
    }
    if (result == 0) {
        result = read_destination_policy_size(database->handle,
                                              &destination_rule_count,
                                              &destination_strings_size);
    }
    if (result == 0) {
        result = read_encrypted_endpoint_size(database->handle,
                                              &encrypted_endpoint_count,
                                              &encrypted_strings_size);
    }
    if (result == 0 &&
        (!jg_size_add(destination_rule_count, encrypted_endpoint_count,
                      &complete_destination_count) ||
         complete_destination_count > JG_DATABASE_POLICY_RULE_LIMIT ||
         !jg_size_add(destination_strings_size, encrypted_strings_size,
                      &complete_destination_strings_size))) {
        result = -EOVERFLOW;
    }
    if (result == 0 &&
        !jg_size_multiply(rule_count, sizeof(*rules), &rules_size)) {
        result = -EOVERFLOW;
    }
    if (result == 0 && !jg_size_multiply(complete_destination_count,
                                         sizeof(*destination_rules),
                                         &destination_rules_size)) {
        result = -EOVERFLOW;
    }
    if (result == 0 && rule_count != 0U) {
        rules = calloc(1U, rules_size);
        strings = malloc(strings_size);
        if (rules == NULL || strings == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0 && complete_destination_count != 0U) {
        destination_rules = calloc(1U, destination_rules_size);
        destination_strings = malloc(complete_destination_strings_size);
        if (destination_rules == NULL || destination_strings == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = read_domain_rules(database->handle, rules, rule_count, strings,
                                   strings_size);
    }
    if (result == 0) {
        result = read_destination_rules(
            database->handle, destination_rules, destination_rule_count,
            destination_strings, destination_strings_size);
    }
    if (result == 0 && encrypted_endpoint_count != 0U) {
        result = read_encrypted_endpoints(
            database->handle, destination_rules + destination_rule_count,
            encrypted_endpoint_count,
            destination_strings + destination_strings_size,
            encrypted_strings_size);
    }
    if (result == 0) {
        result = execute_sql(database->handle, "COMMIT;");
    } else {
        (void)execute_sql(database->handle, "ROLLBACK;");
    }
    if (result == 0) {
        result = jg_policy_snapshot_build_complete(
            rules, rule_count, destination_rules, complete_destination_count,
            generation, snapshot);
    }
    free(destination_strings);
    free(destination_rules);
    free(strings);
    free(rules);
    return result;
}
