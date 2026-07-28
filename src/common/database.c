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
#include <strings.h>
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

/** Add optimistic-concurrency revisions to mutable policy rules. */
static const char migration_6_policy[] =
    "ALTER TABLE domain_rules ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 "
    "CHECK(revision > 0);"
    "ALTER TABLE destination_rules ADD COLUMN revision INTEGER NOT NULL "
    "DEFAULT 1 CHECK(revision > 0);"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(6,unixepoch());"
    "PRAGMA user_version=6;";

/** Ordered statement groups composing schema version six. */
static const char *const migration_6[] = {
    migration_6_policy,
};

/** Complete remote blocklist scheduling and concurrency metadata. */
static const char migration_7_blocklists[] =
    "ALTER TABLE blocklist_sources ADD COLUMN signature_url TEXT "
    "CHECK(signature_url IS NULL OR length(signature_url) BETWEEN 1 AND 2048);"
    "ALTER TABLE blocklist_sources ADD COLUMN connect_timeout_ms INTEGER NOT "
    "NULL DEFAULT 5000 CHECK(connect_timeout_ms BETWEEN 1 AND 2147483647);"
    "ALTER TABLE blocklist_sources ADD COLUMN transfer_timeout_ms INTEGER NOT "
    "NULL DEFAULT 30000 CHECK(transfer_timeout_ms BETWEEN 1 AND 2147483647);"
    "ALTER TABLE blocklist_sources ADD COLUMN redirect_limit INTEGER NOT NULL "
    "DEFAULT 5 CHECK(redirect_limit BETWEEN 0 AND 20);"
    "ALTER TABLE blocklist_sources ADD COLUMN retry_base_seconds INTEGER NOT "
    "NULL DEFAULT 60 CHECK(retry_base_seconds > 0);"
    "ALTER TABLE blocklist_sources ADD COLUMN retry_max_seconds INTEGER NOT "
    "NULL DEFAULT 3600 CHECK(retry_max_seconds >= retry_base_seconds);"
    "ALTER TABLE blocklist_sources ADD COLUMN revision INTEGER NOT NULL "
    "DEFAULT 1 CHECK(revision > 0);"
    "ALTER TABLE blocklist_source_status ADD COLUMN rejected_entries INTEGER "
    "NOT NULL DEFAULT 0 CHECK(rejected_entries >= 0);"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(7,unixepoch());"
    "PRAGMA user_version=7;";

/** Ordered statement groups composing schema version seven. */
static const char *const migration_7[] = {
    migration_7_blocklists,
};

/** Preserve imported blocklist category metadata. */
static const char migration_8_blocklists[] =
    "ALTER TABLE domain_rules ADD COLUMN category TEXT NOT NULL DEFAULT '' "
    "CHECK(length(CAST(category AS BLOB)) <= 128);"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(8,unixepoch());"
    "PRAGMA user_version=8;";

/** Ordered statement groups composing schema version eight. */
static const char *const migration_8[] = {
    migration_8_blocklists,
};

/** Ordered migration sequence. */
static const struct database_migration migrations[] = {
    {1U, migration_1, sizeof(migration_1) / sizeof(migration_1[0])},
    {2U, migration_2, sizeof(migration_2) / sizeof(migration_2[0])},
    {3U, migration_3, sizeof(migration_3) / sizeof(migration_3[0])},
    {4U, migration_4, sizeof(migration_4) / sizeof(migration_4[0])},
    {5U, migration_5, sizeof(migration_5) / sizeof(migration_5[0])},
    {6U, migration_6, sizeof(migration_6) / sizeof(migration_6[0])},
    {7U, migration_7, sizeof(migration_7) / sizeof(migration_7[0])},
    {8U, migration_8, sizeof(migration_8) / sizeof(migration_8[0])},
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

/** @brief Copy one nullable text column into bounded record storage. */
static int copy_optional_text(sqlite3_stmt *statement,
                              int column,
                              char *destination,
                              size_t capacity)
{
    const unsigned char *text = NULL;
    int byte_count = 0;

    if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
        destination[0U] = '\0';
        return 0;
    }
    if (sqlite3_column_type(statement, column) != SQLITE_TEXT) {
        return -EILSEQ;
    }
    text = sqlite3_column_text(statement, column);
    byte_count = sqlite3_column_bytes(statement, column);
    if (text == NULL || byte_count < 0 || (size_t)byte_count >= capacity ||
        memchr(text, '\0', (size_t)byte_count) != NULL) {
        return -EILSEQ;
    }
    (void)memcpy(destination, text, (size_t)byte_count);
    destination[byte_count] = '\0';
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

/** @brief Bind one validated domain rule to a prepared write statement. */
static int bind_domain_rule(sqlite3_stmt *statement,
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
        status = rule->id == 0U ? sqlite3_bind_null(statement, 1)
                                : sqlite3_bind_int64(statement, 1,
                                                     (sqlite3_int64)rule->id);
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
        result = bind_domain_rule(statement, &rules[index]);
        if (result == 0) {
            status = sqlite3_step(statement);
            result =
                status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
        }
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

/** @brief Bind one validated destination rule to a prepared write statement. */
static int bind_destination_rule(
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
        status = rule->id == 0U ? sqlite3_bind_null(statement, 1)
                                : sqlite3_bind_int64(statement, 1,
                                                     (sqlite3_int64)rule->id);
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
        result = bind_destination_rule(statement, &rules[index]);
        if (result == 0) {
            status = sqlite3_step(statement);
            result =
                status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
        }
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

/** @brief Decode enabled, modification time, and revision columns. */
static int decode_rule_metadata(sqlite3_stmt *statement,
                                int enabled_column,
                                int updated_at_column,
                                int revision_column,
                                bool *enabled,
                                uint64_t *updated_at,
                                uint64_t *revision)
{
    sqlite3_int64 persistent_updated_at = 0;
    sqlite3_int64 persistent_revision = 0;
    int persistent_enabled = 0;

    if (sqlite3_column_type(statement, enabled_column) != SQLITE_INTEGER ||
        sqlite3_column_type(statement, updated_at_column) != SQLITE_INTEGER ||
        sqlite3_column_type(statement, revision_column) != SQLITE_INTEGER) {
        return -EILSEQ;
    }
    persistent_enabled = sqlite3_column_int(statement, enabled_column);
    persistent_updated_at = sqlite3_column_int64(statement, updated_at_column);
    persistent_revision = sqlite3_column_int64(statement, revision_column);
    if ((persistent_enabled != 0 && persistent_enabled != 1) ||
        persistent_updated_at < 0 || persistent_revision <= 0) {
        return -EILSEQ;
    }
    *enabled = persistent_enabled != 0;
    *updated_at = (uint64_t)persistent_updated_at;
    *revision = (uint64_t)persistent_revision;
    return 0;
}

/** @brief Decode one persistent domain rule into an owned record. */
static int decode_domain_record(sqlite3_stmt *statement,
                                struct jg_database_domain_rule *record)
{
    char strings[JG_DOMAIN_NAME_MAX + JG_POLICY_ATTRIBUTION_MAX + 2U];
    struct jg_policy_rule_input rule;
    size_t cursor = 0U;
    int result = 0;

    (void)memset(&rule, 0, sizeof(rule));
    (void)memset(record, 0, sizeof(*record));
    result =
        decode_domain_rule(statement, &rule, strings, sizeof(strings), &cursor);
    if (result == 0) {
        result = decode_rule_metadata(statement, 11, 12, 13, &record->enabled,
                                      &record->updated_at, &record->revision);
    }
    if (result == 0 && sqlite3_column_type(statement, 14) != SQLITE_TEXT) {
        result = -EILSEQ;
    }
    if (result == 0) {
        result = copy_optional_text(statement, 14, record->category,
                                    sizeof(record->category));
    }
    if (result == 0 && !jg_utf8_text_valid((const uint8_t *)record->category,
                                           strlen(record->category), true)) {
        result = -EILSEQ;
    }
    if (result == 0) {
        record->id = rule.id;
        record->include_subdomains = rule.include_subdomains;
        record->effect = rule.effect;
        record->source = rule.source;
        record->target = rule.target;
        record->scope = rule.scope;
        (void)memcpy(record->domain, rule.domain, strlen(rule.domain) + 1U);
        (void)memcpy(record->attribution, rule.attribution,
                     strlen(rule.attribution) + 1U);
    }
    return result;
}

/** @brief Decode one persistent destination rule into an owned record. */
static int decode_destination_record(
    sqlite3_stmt *statement,
    struct jg_database_destination_rule *record)
{
    char strings[JG_POLICY_ATTRIBUTION_MAX + 1U];
    struct jg_policy_destination_rule_input rule;
    size_t cursor = 0U;
    int result = 0;

    (void)memset(&rule, 0, sizeof(rule));
    (void)memset(record, 0, sizeof(*record));
    result = decode_destination_rule(statement, &rule, strings, sizeof(strings),
                                     &cursor);
    if (result == 0) {
        result = decode_rule_metadata(statement, 13, 14, 15, &record->enabled,
                                      &record->updated_at, &record->revision);
    }
    if (result == 0) {
        record->id = rule.id;
        record->effect = rule.effect;
        record->source = rule.source;
        record->transport = rule.transport;
        record->has_address = rule.has_address;
        record->address_family = rule.address_family;
        (void)memcpy(record->address, rule.address, sizeof(record->address));
        record->prefix_length = rule.prefix_length;
        record->has_port = rule.has_port;
        record->port = rule.port;
        record->scope = rule.scope;
        (void)memcpy(record->attribution, rule.attribution,
                     strlen(rule.attribution) + 1U);
    }
    return result;
}

/** @brief Decode one required nonnegative integer column. */
static int decode_unsigned(sqlite3_stmt *statement, int column, uint64_t *value)
{
    sqlite3_int64 persistent = 0;

    if (sqlite3_column_type(statement, column) != SQLITE_INTEGER) {
        return -EILSEQ;
    }
    persistent = sqlite3_column_int64(statement, column);
    if (persistent < 0) {
        return -EILSEQ;
    }
    *value = (uint64_t)persistent;
    return 0;
}

/** @brief Decode a nullable nonnegative integer as zero when absent. */
static int decode_optional_unsigned(sqlite3_stmt *statement,
                                    int column,
                                    uint64_t *value)
{
    if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
        *value = 0U;
        return 0;
    }
    return decode_unsigned(statement, column, value);
}

/** @brief Decode one optional fixed-size binary column. */
static int decode_optional_blob(sqlite3_stmt *statement,
                                int column,
                                uint8_t *destination,
                                size_t expected_size,
                                bool *present)
{
    const void *blob = NULL;

    if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
        *present = false;
        return 0;
    }
    blob = sqlite3_column_blob(statement, column);
    if (sqlite3_column_type(statement, column) != SQLITE_BLOB || blob == NULL ||
        sqlite3_column_bytes(statement, column) != (int)expected_size) {
        return -EILSEQ;
    }
    (void)memcpy(destination, blob, expected_size);
    *present = true;
    return 0;
}

/** @brief Decode one persistent blocklist syntax name. */
static int decode_blocklist_format(const char *text,
                                   enum jg_blocklist_format *format)
{
    if (strcmp(text, "domain") == 0) {
        *format = JG_BLOCKLIST_FORMAT_DOMAIN;
    } else if (strcmp(text, "hosts") == 0) {
        *format = JG_BLOCKLIST_FORMAT_HOSTS;
    } else if (strcmp(text, "category") == 0) {
        *format = JG_BLOCKLIST_FORMAT_CATEGORY;
    } else if (strcmp(text, "rpz") == 0) {
        *format = JG_BLOCKLIST_FORMAT_RPZ;
    } else if (strcmp(text, "json") == 0) {
        *format = JG_BLOCKLIST_FORMAT_JSON;
    } else {
        return -EILSEQ;
    }
    return 0;
}

/** @brief Decode one persistent blocklist health name. */
static int decode_blocklist_health(const char *text,
                                   enum jg_database_blocklist_health *health)
{
    if (strcmp(text, "unknown") == 0) {
        *health = JG_DATABASE_BLOCKLIST_UNKNOWN;
    } else if (strcmp(text, "healthy") == 0) {
        *health = JG_DATABASE_BLOCKLIST_HEALTHY;
    } else if (strcmp(text, "degraded") == 0) {
        *health = JG_DATABASE_BLOCKLIST_DEGRADED;
    } else if (strcmp(text, "failed") == 0) {
        *health = JG_DATABASE_BLOCKLIST_FAILED;
    } else {
        return -EILSEQ;
    }
    return 0;
}

/** @brief Decode the integer fields of one blocklist-source row. */
static int decode_blocklist_source_integers(
    sqlite3_stmt *statement,
    struct jg_database_blocklist_source *source)
{
    static const int state_columns[] = {22, 23, 24, 25, 27, 28};
    uint64_t config[8U];
    uint64_t state[6U];
    size_t index = 0U;
    int result = 0;

    for (index = 0U; index < 8U && result == 0; ++index) {
        result = decode_unsigned(statement, (int)index + 10, &config[index]);
    }
    for (index = 0U; index < 3U && result == 0; ++index) {
        result = decode_optional_unsigned(statement, state_columns[index],
                                          &state[index]);
    }
    for (; index < 6U && result == 0; ++index) {
        result =
            decode_unsigned(statement, state_columns[index], &state[index]);
    }
    if (result != 0 || config[0U] < 300U || config[0U] > 2592000U ||
        config[1U] == 0U || config[1U] > SIZE_MAX || config[2U] < config[1U] ||
        config[2U] > SIZE_MAX || config[3U] == 0U || config[3U] > INT32_MAX ||
        config[4U] == 0U || config[4U] > INT32_MAX || config[5U] > 20U ||
        config[6U] == 0U || config[7U] < config[6U] || state[3U] > UINT32_MAX ||
        state[4U] > SIZE_MAX || state[5U] > SIZE_MAX) {
        return result != 0 ? result : -EILSEQ;
    }
    source->update_interval_seconds = config[0U];
    source->max_download_bytes = (size_t)config[1U];
    source->max_decompressed_bytes = (size_t)config[2U];
    source->connect_timeout_ms = (uint32_t)config[3U];
    source->transfer_timeout_ms = (uint32_t)config[4U];
    source->redirect_limit = (uint32_t)config[5U];
    source->retry_base_seconds = config[6U];
    source->retry_max_seconds = config[7U];
    source->last_attempt_at = state[0U];
    source->last_success_at = state[1U];
    source->next_attempt_at = state[2U];
    source->consecutive_failures = (uint32_t)state[3U];
    source->active_entries = (size_t)state[4U];
    source->rejected_entries = (size_t)state[5U];
    return 0;
}

/** @brief Decode one selected blocklist source and update-state row. */
static int decode_blocklist_source(sqlite3_stmt *statement,
                                   struct jg_database_blocklist_source *source)
{
    const char *text = NULL;
    size_t text_length = 0U;
    uint64_t id = 0U;
    uint64_t revision = 0U;
    uint64_t created_at = 0U;
    uint64_t updated_at = 0U;
    uint64_t strict_mode = 0U;
    uint64_t enabled = 0U;
    int result = 0;

    (void)memset(source, 0, sizeof(*source));
    result = decode_unsigned(statement, 0, &id);
    if (result == 0) {
        result = decode_unsigned(statement, 1, &revision);
    }
    if (result == 0) {
        result = decode_unsigned(statement, 2, &created_at);
    }
    if (result == 0) {
        result = decode_unsigned(statement, 3, &updated_at);
    }
    if (result == 0) {
        result = copy_optional_text(statement, 4, source->name,
                                    sizeof(source->name));
    }
    if (result == 0) {
        result =
            copy_optional_text(statement, 5, source->url, sizeof(source->url));
    }
    if (result == 0) {
        result = copy_optional_text(statement, 6, source->signature_url,
                                    sizeof(source->signature_url));
    }
    if (result == 0) {
        result = required_text(statement, 7, &text, &text_length);
    }
    if (result == 0) {
        result = decode_blocklist_format(text, &source->format);
    }
    if (result == 0) {
        result = decode_unsigned(statement, 8, &strict_mode);
    }
    if (result == 0) {
        result = decode_unsigned(statement, 9, &enabled);
    }
    if (result == 0) {
        result = decode_blocklist_source_integers(statement, source);
    }
    if (result == 0) {
        result = decode_optional_blob(statement, 18, source->sha256_pin,
                                      sizeof(source->sha256_pin),
                                      &source->has_sha256_pin);
    }
    if (result == 0) {
        result = decode_optional_blob(statement, 19, source->ed25519_public_key,
                                      sizeof(source->ed25519_public_key),
                                      &source->has_signature);
    }
    if (result == 0) {
        result = copy_optional_text(statement, 20, source->etag,
                                    sizeof(source->etag));
    }
    if (result == 0) {
        result = copy_optional_text(statement, 21, source->last_modified,
                                    sizeof(source->last_modified));
    }
    if (result == 0) {
        result = decode_optional_blob(statement, 26, source->active_checksum,
                                      sizeof(source->active_checksum),
                                      &source->has_active_checksum);
    }
    if (result == 0) {
        result = required_text(statement, 29, &text, &text_length);
    }
    if (result == 0) {
        result = decode_blocklist_health(text, &source->health);
    }
    if (result == 0) {
        result = copy_optional_text(statement, 30, source->last_error,
                                    sizeof(source->last_error));
    }
    if (result == 0 &&
        (id == 0U || revision == 0U || updated_at < created_at ||
         source->name[0U] == '\0' ||
         !jg_utf8_text_valid((const uint8_t *)source->name,
                             strlen(source->name), false) ||
         (source->url[0U] != '\0' &&
          (source->url[8U] == '\0' ||
           strncasecmp(source->url, "https://", 8U) != 0 ||
           !jg_utf8_text_valid((const uint8_t *)source->url,
                               strlen(source->url), false))) ||
         (source->url[0U] == '\0' && source->has_signature) ||
         ((source->signature_url[0U] != '\0') != source->has_signature) ||
         (source->signature_url[0U] != '\0' &&
          (source->signature_url[8U] == '\0' ||
           strncasecmp(source->signature_url, "https://", 8U) != 0 ||
           !jg_utf8_text_valid((const uint8_t *)source->signature_url,
                               strlen(source->signature_url), false))) ||
         (strict_mode != 0U && strict_mode != 1U) ||
         (enabled != 0U && enabled != 1U) ||
         (!source->has_active_checksum && source->active_entries != 0U))) {
        result = -EILSEQ;
    }
    if (result == 0) {
        source->id = id;
        source->revision = revision;
        source->created_at = created_at;
        source->updated_at = updated_at;
        source->mode =
            strict_mode != 0U ? JG_BLOCKLIST_STRICT : JG_BLOCKLIST_TOLERANT;
        source->enabled = enabled != 0U;
    }
    return result;
}

/** @brief Read one stable identifier-ordered page of blocklist sources. */
int jg_database_list_blocklist_sources(
    struct jg_database *database,
    uint64_t after_id,
    size_t limit,
    struct jg_database_blocklist_source *sources,
    size_t *count,
    bool *has_more)
{
    static const char query[] =
        "SELECT s.id,s.revision,s.created_at,s.updated_at,s.name,s.url,"
        "s.signature_url,s.format,s.strict_mode,s.enabled,s.update_interval,"
        "s.max_download_bytes,s.max_decompressed_bytes,s.connect_timeout_ms,"
        "s.transfer_timeout_ms,s.redirect_limit,s.retry_base_seconds,"
        "s.retry_max_seconds,s.sha256_pin,s.ed25519_public_key,st.etag,"
        "st.last_modified,st.last_attempt_at,st.last_success_at,"
        "st.next_attempt_at,COALESCE(st.consecutive_failures,0),"
        "st.active_checksum,COALESCE(st.active_entries,0),"
        "COALESCE(st.rejected_entries,0),COALESCE(st.health,'unknown'),"
        "st.last_error FROM blocklist_sources AS s LEFT JOIN "
        "blocklist_source_status AS st ON st.source_id=s.id WHERE s.id>?1 "
        "ORDER BY s.id LIMIT ?2;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    bool more = false;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || after_id > (uint64_t)INT64_MAX || limit == 0U ||
        limit > JG_DATABASE_POLICY_PAGE_MAX || sources == NULL ||
        count == NULL || has_more == NULL) {
        return -EINVAL;
    }
    *count = 0U;
    *has_more = false;
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)after_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 2, (int)(limit + 1U));
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (index == limit) {
            more = true;
            break;
        }
        result = decode_blocklist_source(statement, &sources[index]);
        ++index;
    }
    if (result == 0 && !more && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *count = index;
        *has_more = more;
    }
    return result;
}

/** @brief Return the persistent name of one blocklist input syntax. */
static const char *blocklist_format_text(enum jg_blocklist_format format)
{
    switch (format) {
    case JG_BLOCKLIST_FORMAT_DOMAIN:
        return "domain";
    case JG_BLOCKLIST_FORMAT_HOSTS:
        return "hosts";
    case JG_BLOCKLIST_FORMAT_CATEGORY:
        return "category";
    case JG_BLOCKLIST_FORMAT_RPZ:
        return "rpz";
    case JG_BLOCKLIST_FORMAT_JSON:
        return "json";
    }
    return NULL;
}

/** @brief Validate and measure one bounded administrative string. */
static int validate_source_text(const char *text,
                                size_t maximum,
                                size_t *length)
{
    size_t size = 0U;

    if (text == NULL) {
        return -EINVAL;
    }
    size = strnlen(text, maximum + 1U);
    if (size == 0U || size > maximum) {
        return -EINVAL;
    }
    if (!jg_utf8_text_valid((const uint8_t *)text, size, false)) {
        return -EILSEQ;
    }
    if (length != NULL) {
        *length = size;
    }
    return 0;
}

/** @brief Check that one bounded URL explicitly selects HTTPS. */
static bool source_https_url(const char *url, size_t length)
{
    return length > 8U && strncasecmp(url, "https://", 8U) == 0;
}

/** @brief Validate one blocklist-source configuration before persistence. */
static int validate_blocklist_source_config(
    const struct jg_database_blocklist_source_config *config)
{
    size_t url_length = 0U;
    size_t signature_url_length = 0U;
    int result = 0;

    if (config == NULL || blocklist_format_text(config->format) == NULL ||
        (config->mode != JG_BLOCKLIST_STRICT &&
         config->mode != JG_BLOCKLIST_TOLERANT) ||
        config->update_interval_seconds < 300U ||
        config->update_interval_seconds > 2592000U ||
        config->max_download_bytes == 0U ||
        config->max_download_bytes > (size_t)INT64_MAX ||
        config->max_decompressed_bytes < config->max_download_bytes ||
        config->max_decompressed_bytes > (size_t)INT64_MAX ||
        config->connect_timeout_ms == 0U ||
        config->connect_timeout_ms > (uint32_t)INT32_MAX ||
        config->transfer_timeout_ms == 0U ||
        config->transfer_timeout_ms > (uint32_t)INT32_MAX ||
        config->redirect_limit > 20U || config->retry_base_seconds == 0U ||
        config->retry_base_seconds > config->retry_max_seconds ||
        config->retry_max_seconds > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = validate_source_text(config->name, JG_DATABASE_BLOCKLIST_NAME_MAX,
                                  NULL);
    if (result == 0 && config->url != NULL) {
        result = validate_source_text(
            config->url, JG_DATABASE_BLOCKLIST_URL_MAX, &url_length);
        if (result == 0 && !source_https_url(config->url, url_length)) {
            result = -EINVAL;
        }
    }
    if (result == 0 && config->has_signature) {
        result = validate_source_text(config->signature_url,
                                      JG_DATABASE_BLOCKLIST_URL_MAX,
                                      &signature_url_length);
        if (result == 0 &&
            (!source_https_url(config->signature_url, signature_url_length) ||
             config->url == NULL)) {
            result = -EINVAL;
        }
    } else if (result == 0 && config->signature_url != NULL) {
        result = -EINVAL;
    }
    return result;
}

/** @brief Bind one validated blocklist-source configuration. */
static int bind_blocklist_source_config(
    sqlite3_stmt *statement,
    const struct jg_database_blocklist_source_config *config)
{
    int status = sqlite3_reset(statement);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        result = jg_database_sqlite_result(sqlite3_clear_bindings(statement));
    }
    if (result == 0) {
        status =
            sqlite3_bind_text(statement, 1, config->name, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = config->url == NULL
                     ? sqlite3_bind_null(statement, 2)
                     : sqlite3_bind_text(statement, 2, config->url, -1,
                                         SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = config->signature_url == NULL
                     ? sqlite3_bind_null(statement, 3)
                     : sqlite3_bind_text(statement, 3, config->signature_url,
                                         -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 4,
                                   blocklist_format_text(config->format), -1,
                                   SQLITE_STATIC);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 5,
                                  config->mode == JG_BLOCKLIST_STRICT ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 6, config->enabled ? 1 : 0);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(
            statement, 7, (sqlite3_int64)config->update_interval_seconds);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 8,
                                    (sqlite3_int64)config->max_download_bytes);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(
            statement, 9, (sqlite3_int64)config->max_decompressed_bytes);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int(statement, 10, (int)config->connect_timeout_ms);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int(statement, 11, (int)config->transfer_timeout_ms);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 12, (int)config->redirect_limit);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 13,
                                    (sqlite3_int64)config->retry_base_seconds);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 14,
                                    (sqlite3_int64)config->retry_max_seconds);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = config->has_sha256_pin
                     ? sqlite3_bind_blob(statement, 15, config->sha256_pin,
                                         (int)sizeof(config->sha256_pin),
                                         SQLITE_TRANSIENT)
                     : sqlite3_bind_null(statement, 15);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            config->has_signature
                ? sqlite3_bind_blob(statement, 16, config->ed25519_public_key,
                                    (int)sizeof(config->ed25519_public_key),
                                    SQLITE_TRANSIENT)
                : sqlite3_bind_null(statement, 16);
        result = jg_database_sqlite_result(status);
    }
    return result;
}

/** @brief Read one blocklist source by its exact identifier. */
static int read_blocklist_source(struct jg_database *database,
                                 uint64_t source_id,
                                 struct jg_database_blocklist_source *source)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_blocklist_sources(
        database, source_id - 1U, 1U, source, &count, &has_more);

    (void)has_more;
    if (result == 0 && (count != 1U || source->id != source_id)) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Read one record revision or report an absent identifier. */
static int read_revision(sqlite3 *handle,
                         const char *query,
                         uint64_t identifier,
                         uint64_t *revision)
{
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)identifier);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW ||
                   sqlite3_column_type(statement, 0) != SQLITE_INTEGER ||
                   sqlite3_column_int64(statement, 0) <= 0) {
            result = status == SQLITE_ROW ? -EILSEQ
                                          : jg_database_sqlite_result(status);
        } else {
            *revision = (uint64_t)sqlite3_column_int64(statement, 0);
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

/** @brief Classify a failed optimistic record write. */
static int write_conflict(sqlite3 *handle,
                          const char *query,
                          uint64_t identifier,
                          uint64_t expected_revision,
                          bool revision_must_advance)
{
    uint64_t revision = 0U;
    int result = read_revision(handle, query, identifier, &revision);

    if (result == 0 && revision != expected_revision) {
        result = -EAGAIN;
    } else if (result == 0 && revision_must_advance) {
        result = -EOVERFLOW;
    } else if (result == 0) {
        result = -EIO;
    }
    return result;
}

/** @brief Create one blocklist source and its empty update state. */
int jg_database_create_blocklist_source(
    struct jg_database *database,
    const struct jg_database_blocklist_source_config *config,
    struct jg_database_blocklist_source *created)
{
    static const char insert[] =
        "INSERT INTO blocklist_sources("
        "name,url,signature_url,format,strict_mode,enabled,update_interval,"
        "max_download_bytes,max_decompressed_bytes,connect_timeout_ms,"
        "transfer_timeout_ms,redirect_limit,retry_base_seconds,"
        "retry_max_seconds,sha256_pin,ed25519_public_key,created_at,updated_at"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,"
        "unixepoch(),unixepoch());";
    struct jg_database_blocklist_source source;
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 identifier = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || created == NULL) {
        return -EINVAL;
    }
    (void)memset(created, 0, sizeof(*created));
    result = validate_blocklist_source_config(config);
    if (result == 0) {
        result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_blocklist_source_config(statement, config);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_CONSTRAINT_UNIQUE) {
            result = -EEXIST;
        } else {
            result =
                status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        identifier = sqlite3_last_insert_rowid(database->handle);
        if (identifier <= 0) {
            result = -EIO;
        }
    }
    if (result == 0) {
        result = execute_sql(database->handle,
                             "INSERT INTO blocklist_source_status(source_id)"
                             " VALUES(last_insert_rowid());");
    }
    if (result == 0) {
        result = read_blocklist_source(database, (uint64_t)identifier, &source);
    }
    if (result == 0) {
        result = execute_sql(database->handle, "COMMIT;");
    } else {
        (void)execute_sql(database->handle, "ROLLBACK;");
    }
    if (result == 0) {
        *created = source;
    }
    return result;
}

/** @brief Replace one blocklist source at its expected revision. */
int jg_database_update_blocklist_source(
    struct jg_database *database,
    uint64_t source_id,
    const struct jg_database_blocklist_source_config *config,
    uint64_t expected_revision,
    struct jg_database_blocklist_source *updated)
{
    static const char revision_query[] =
        "SELECT revision FROM blocklist_sources WHERE id=?1;";
    static const char update[] =
        "UPDATE blocklist_sources SET name=?1,url=?2,signature_url=?3,"
        "format=?4,strict_mode=?5,enabled=?6,update_interval=?7,"
        "max_download_bytes=?8,max_decompressed_bytes=?9,"
        "connect_timeout_ms=?10,transfer_timeout_ms=?11,redirect_limit=?12,"
        "retry_base_seconds=?13,retry_max_seconds=?14,sha256_pin=?15,"
        "ed25519_public_key=?16,updated_at=unixepoch(),revision=revision+1 "
        "WHERE id=?17 AND revision=?18 AND revision<9223372036854775807;";
    struct jg_database_blocklist_source source;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || source_id == 0U ||
        source_id > (uint64_t)INT64_MAX || expected_revision == 0U ||
        expected_revision > (uint64_t)INT64_MAX || updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result = validate_blocklist_source_config(config);
    if (result == 0) {
        result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_blocklist_source_config(statement, config);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 17, (sqlite3_int64)source_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 18,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_CONSTRAINT_UNIQUE) {
            result = -EEXIST;
        } else {
            result =
                status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
        }
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = write_conflict(database->handle, revision_query, source_id,
                                expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = read_blocklist_source(database, source_id, &source);
    }
    if (result == 0) {
        result = execute_sql(database->handle, "COMMIT;");
    } else {
        (void)execute_sql(database->handle, "ROLLBACK;");
    }
    if (result == 0) {
        *updated = source;
    }
    return result;
}

/** @brief Delete one blocklist source at its expected revision. */
int jg_database_delete_blocklist_source(struct jg_database *database,
                                        uint64_t source_id,
                                        uint64_t expected_revision)
{
    static const char revision_query[] =
        "SELECT revision FROM blocklist_sources WHERE id=?1;";
    static const char remove[] =
        "DELETE FROM blocklist_sources WHERE id=?1 AND revision=?2;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || source_id == 0U ||
        source_id > (uint64_t)INT64_MAX || expected_revision == 0U ||
        expected_revision > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, remove, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)source_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = write_conflict(database->handle, revision_query, source_id,
                                expected_revision, false);
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

/** @brief Validate one retained HTTP validator against header injection. */
static bool blocklist_validator_valid(const char *value, size_t maximum)
{
    size_t length = 0U;

    if (value == NULL) {
        return false;
    }
    while (length <= maximum && value[length] != '\0') {
        const uint8_t byte = (uint8_t)value[length];

        if (byte < UINT8_C(0x20) || byte > UINT8_C(0x7e)) {
            return false;
        }
        ++length;
    }
    return length <= maximum;
}

/** @brief Validate one successful blocklist update before persistence. */
static int validate_blocklist_activation(
    uint64_t source_id,
    uint64_t expected_revision,
    const struct jg_blocklist *blocklist,
    const struct jg_blocklist_remote_state *state,
    const struct jg_blocklist_report *report,
    struct jg_blocklist_info *info)
{
    int result = 0;

    if (source_id == 0U || source_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX ||
        blocklist == NULL || state == NULL || report == NULL || info == NULL ||
        state->last_attempt_at == 0U ||
        state->last_success_at != state->last_attempt_at ||
        state->next_attempt_at < state->last_success_at ||
        state->consecutive_failures != 0U ||
        !blocklist_validator_valid(state->etag, JG_BLOCKLIST_ETAG_MAX) ||
        !blocklist_validator_valid(state->last_modified,
                                   JG_BLOCKLIST_LAST_MODIFIED_MAX)) {
        return -EINVAL;
    }
    if (state->last_attempt_at > (uint64_t)INT64_MAX ||
        state->next_attempt_at > (uint64_t)INT64_MAX) {
        return -EOVERFLOW;
    }
    result = jg_blocklist_get_info(blocklist, info);
    if (result == 0 && (info->entry_count > JG_DATABASE_POLICY_RULE_LIMIT ||
                        info->entry_count > (size_t)INT64_MAX ||
                        report->records_rejected > (size_t)INT64_MAX)) {
        result = -EOVERFLOW;
    }
    if (result == 0) {
        result = validate_source_text(info->attribution,
                                      JG_BLOCKLIST_ATTRIBUTION_MAX, NULL);
    }
    return result;
}

/** @brief Bind and execute one imported blocklist domain-rule insert. */
static int insert_blocklist_entry(sqlite3_stmt *statement,
                                  uint64_t source_id,
                                  uint64_t updated_at,
                                  const char *attribution,
                                  const struct jg_blocklist_entry *entry)
{
    int status = sqlite3_reset(statement);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        result = jg_database_sqlite_result(sqlite3_clear_bindings(statement));
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)source_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 2, entry->domain, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_text(statement, 3, attribution, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_text(statement, 4, entry->category, -1,
                                   SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 5, (sqlite3_int64)updated_at);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    return result;
}

/** @brief Persist successful remote state and active-list metadata. */
static int store_blocklist_success(
    sqlite3 *handle,
    uint64_t source_id,
    const struct jg_blocklist_remote_state *state,
    const struct jg_blocklist_info *info,
    const struct jg_blocklist_report *report)
{
    static const char update[] =
        "INSERT INTO blocklist_source_status("
        "source_id,etag,last_modified,last_attempt_at,last_success_at,"
        "next_attempt_at,consecutive_failures,active_checksum,active_entries,"
        "rejected_entries,health,last_error"
        ") VALUES(?1,?2,?3,?4,?5,?6,0,?7,?8,?9,'healthy',NULL)"
        " ON CONFLICT(source_id) DO UPDATE SET etag=excluded.etag,"
        "last_modified=excluded.last_modified,"
        "last_attempt_at=excluded.last_attempt_at,"
        "last_success_at=excluded.last_success_at,"
        "next_attempt_at=excluded.next_attempt_at,consecutive_failures=0,"
        "active_checksum=excluded.active_checksum,"
        "active_entries=excluded.active_entries,"
        "rejected_entries=excluded.rejected_entries,health='healthy',"
        "last_error=NULL;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)source_id);
    }
    if (status == SQLITE_OK) {
        status = state->etag[0U] == '\0'
                     ? sqlite3_bind_null(statement, 2)
                     : sqlite3_bind_text(statement, 2, state->etag, -1,
                                         SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = state->last_modified[0U] == '\0'
                     ? sqlite3_bind_null(statement, 3)
                     : sqlite3_bind_text(statement, 3, state->last_modified, -1,
                                         SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 4,
                                    (sqlite3_int64)state->last_attempt_at);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 5,
                                    (sqlite3_int64)state->last_success_at);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 6,
                                    (sqlite3_int64)state->next_attempt_at);
    }
    if (status == SQLITE_OK) {
        status =
            sqlite3_bind_blob(statement, 7, info->checksum,
                              (int)sizeof(info->checksum), SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status =
            sqlite3_bind_int64(statement, 8, (sqlite3_int64)info->entry_count);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 9,
                                    (sqlite3_int64)report->records_rejected);
    }
    if (result == 0) {
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

/** @brief Atomically activate one completely imported blocklist. */
int jg_database_activate_blocklist(
    struct jg_database *database,
    uint64_t source_id,
    uint64_t expected_revision,
    const struct jg_blocklist *blocklist,
    const struct jg_blocklist_remote_state *state,
    const struct jg_blocklist_report *report)
{
    static const char revision_query[] =
        "SELECT revision FROM blocklist_sources WHERE id=?1;";
    static const char insert[] =
        "INSERT INTO domain_rules("
        "blocklist_source_id,domain,match_type,effect,source,scope_type,"
        "attribution,enabled,updated_at,target,category"
        ") VALUES(?1,?2,'suffix','block','blocklist','global',?3,1,?5,'dns',"
        "?4);";
    static const char remove[] =
        "DELETE FROM domain_rules WHERE blocklist_source_id=?1;";
    struct jg_blocklist_info info;
    sqlite3_stmt *insert_statement = NULL;
    sqlite3_stmt *remove_statement = NULL;
    size_t index = 0U;
    uint64_t revision = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = validate_blocklist_activation(source_id, expected_revision,
                                           blocklist, state, report, &info);
    if (result == 0) {
        result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    }
    if (result == 0) {
        result = read_revision(database->handle, revision_query, source_id,
                               &revision);
    }
    if (result == 0 && revision != expected_revision) {
        result = -EAGAIN;
    }
    if (result == 0) {
        status = sqlite3_prepare_v3(database->handle, remove, -1,
                                    SQLITE_PREPARE_PERSISTENT,
                                    &remove_statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status =
            sqlite3_bind_int64(remove_statement, 1, (sqlite3_int64)source_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(remove_statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_prepare_v3(database->handle, insert, -1,
                                    SQLITE_PREPARE_PERSISTENT,
                                    &insert_statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    for (index = 0U; result == 0 && index < info.entry_count; ++index) {
        struct jg_blocklist_entry entry;

        result = jg_blocklist_get_entry(blocklist, index, &entry);
        if (result == 0) {
            result = insert_blocklist_entry(insert_statement, source_id,
                                            state->last_success_at,
                                            info.attribution, &entry);
        }
    }
    if (result == 0) {
        result = store_blocklist_success(database->handle, source_id, state,
                                         &info, report);
    }
    if (insert_statement != NULL) {
        status = sqlite3_finalize(insert_statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (remove_statement != NULL) {
        status = sqlite3_finalize(remove_statement);
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

/** @brief Validate one completed not-modified or failed update attempt. */
static int validate_blocklist_attempt(
    uint64_t source_id,
    uint64_t expected_revision,
    const struct jg_blocklist_remote_state *state,
    bool successful,
    const char *error)
{
    int result = 0;

    if (source_id == 0U || source_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX ||
        state == NULL || state->last_attempt_at == 0U ||
        state->next_attempt_at < state->last_attempt_at ||
        (state->last_success_at != 0U &&
         state->last_success_at > state->last_attempt_at) ||
        !blocklist_validator_valid(state->etag, JG_BLOCKLIST_ETAG_MAX) ||
        !blocklist_validator_valid(state->last_modified,
                                   JG_BLOCKLIST_LAST_MODIFIED_MAX) ||
        (successful && (error != NULL || state->consecutive_failures != 0U ||
                        state->last_success_at != state->last_attempt_at)) ||
        (!successful && (error == NULL || state->consecutive_failures == 0U))) {
        return -EINVAL;
    }
    if (state->last_attempt_at > (uint64_t)INT64_MAX ||
        state->last_success_at > (uint64_t)INT64_MAX ||
        state->next_attempt_at > (uint64_t)INT64_MAX) {
        return -EOVERFLOW;
    }
    if (!successful) {
        result =
            validate_source_text(error, JG_DATABASE_BLOCKLIST_ERROR_MAX, NULL);
    }
    return result;
}

/** @brief Upsert one completed blocklist attempt without replacing entries. */
static int store_blocklist_attempt(
    sqlite3 *handle,
    uint64_t source_id,
    const struct jg_blocklist_remote_state *state,
    bool successful,
    const char *error)
{
    static const char update[] =
        "INSERT INTO blocklist_source_status("
        "source_id,etag,last_modified,last_attempt_at,last_success_at,"
        "next_attempt_at,consecutive_failures,health,last_error"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,"
        "CASE WHEN ?8=1 THEN 'healthy' ELSE 'failed' END,?9)"
        " ON CONFLICT(source_id) DO UPDATE SET etag=excluded.etag,"
        "last_modified=excluded.last_modified,"
        "last_attempt_at=excluded.last_attempt_at,"
        "last_success_at=excluded.last_success_at,"
        "next_attempt_at=excluded.next_attempt_at,"
        "consecutive_failures=excluded.consecutive_failures,"
        "health=CASE WHEN ?8=1 THEN 'healthy' "
        "WHEN active_checksum IS NULL THEN 'failed' ELSE 'degraded' END,"
        "last_error=excluded.last_error;";
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, update, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)source_id);
    }
    if (status == SQLITE_OK) {
        status = state->etag[0U] == '\0'
                     ? sqlite3_bind_null(statement, 2)
                     : sqlite3_bind_text(statement, 2, state->etag, -1,
                                         SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = state->last_modified[0U] == '\0'
                     ? sqlite3_bind_null(statement, 3)
                     : sqlite3_bind_text(statement, 3, state->last_modified, -1,
                                         SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 4,
                                    (sqlite3_int64)state->last_attempt_at);
    }
    if (status == SQLITE_OK) {
        status = state->last_success_at == 0U
                     ? sqlite3_bind_null(statement, 5)
                     : sqlite3_bind_int64(
                           statement, 5, (sqlite3_int64)state->last_success_at);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 6,
                                    (sqlite3_int64)state->next_attempt_at);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(statement, 7,
                                    (sqlite3_int64)state->consecutive_failures);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(statement, 8, successful ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = successful ? sqlite3_bind_null(statement, 9)
                            : sqlite3_bind_text(statement, 9, error, -1,
                                                SQLITE_TRANSIENT);
    }
    if (result == 0) {
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

/** @brief Persist one completed blocklist attempt without replacing entries. */
int jg_database_record_blocklist_attempt(
    struct jg_database *database,
    uint64_t source_id,
    uint64_t expected_revision,
    const struct jg_blocklist_remote_state *state,
    bool successful,
    const char *error)
{
    struct jg_database_blocklist_source source;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = validate_blocklist_attempt(source_id, expected_revision, state,
                                        successful, error);
    if (result == 0) {
        result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    }
    if (result == 0) {
        result = read_blocklist_source(database, source_id, &source);
    }
    if (result == 0 && source.revision != expected_revision) {
        result = -EAGAIN;
    }
    if (result == 0 && successful && !source.has_active_checksum) {
        result = -ENODATA;
    }
    if (result == 0) {
        result = store_blocklist_attempt(database->handle, source_id, state,
                                         successful, error);
    }
    if (result == 0) {
        result = execute_sql(database->handle, "COMMIT;");
    } else {
        (void)execute_sql(database->handle, "ROLLBACK;");
    }
    return result;
}

/** @brief Read one stable identifier-ordered page of domain rules. */
int jg_database_list_domain_rules(struct jg_database *database,
                                  uint64_t after_id,
                                  size_t limit,
                                  struct jg_database_domain_rule *rules,
                                  size_t *count,
                                  bool *has_more)
{
    static const char query[] =
        "SELECT id,domain,match_type,effect,source,scope_type,scope_value,"
        "prefix_length,vlan_id,attribution,target,enabled,updated_at,revision,"
        "category FROM domain_rules WHERE id>?1 ORDER BY id LIMIT ?2;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    bool more = false;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || after_id > (uint64_t)INT64_MAX || limit == 0U ||
        limit > JG_DATABASE_POLICY_PAGE_MAX || rules == NULL || count == NULL ||
        has_more == NULL) {
        return -EINVAL;
    }
    *count = 0U;
    *has_more = false;
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)after_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 2, (int)(limit + 1U));
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (index == limit) {
            more = true;
            break;
        }
        result = decode_domain_record(statement, &rules[index]);
        ++index;
    }
    if (result == 0 && !more && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *count = index;
        *has_more = more;
    }
    return result;
}

/** @brief Validate one new or replacement domain rule. */
static int validate_domain_rule(const struct jg_policy_rule_input *rule,
                                bool creating)
{
    struct jg_policy_rule_input validation;

    if (rule == NULL) {
        return -EINVAL;
    }
    if (creating && rule->id != 0U) {
        return -EINVAL;
    }
    if (!creating && (rule->id == 0U || rule->id > (uint64_t)INT64_MAX)) {
        return -EINVAL;
    }
    validation = *rule;
    if (creating) {
        validation.id = 1U;
    }
    return validate_domain_rules(&validation, 1U);
}

/** @brief Read one domain record by its exact identifier. */
static int read_domain_record(struct jg_database *database,
                              uint64_t rule_id,
                              struct jg_database_domain_rule *record)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_domain_rules(database, rule_id - 1U, 1U,
                                               record, &count, &has_more);

    (void)has_more;
    if (result == 0 && (count != 1U || record->id != rule_id)) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Create one persistent domain rule with an assigned identifier. */
int jg_database_create_domain_rule(struct jg_database *database,
                                   const struct jg_policy_rule_input *rule,
                                   bool enabled,
                                   struct jg_database_domain_rule *created)
{
    static const char insert[] =
        "INSERT INTO domain_rules("
        "id,domain,match_type,effect,source,scope_type,scope_value,"
        "prefix_length,vlan_id,attribution,enabled,updated_at,target"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?12,unixepoch(),?11);";
    struct jg_database_domain_rule record;
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 identifier = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || created == NULL) {
        return -EINVAL;
    }
    (void)memset(created, 0, sizeof(*created));
    result = validate_domain_rule(rule, true);
    if (result == 0) {
        result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_domain_rule(statement, rule);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 12, enabled ? 1 : 0);
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
    if (result == 0) {
        identifier = sqlite3_last_insert_rowid(database->handle);
        if (identifier <= 0) {
            result = -EIO;
        } else {
            result =
                read_domain_record(database, (uint64_t)identifier, &record);
        }
    }
    if (result == 0) {
        result = execute_sql(database->handle, "COMMIT;");
    } else {
        (void)execute_sql(database->handle, "ROLLBACK;");
    }
    if (result == 0) {
        *created = record;
    }
    return result;
}

/** @brief Replace one domain rule at its expected revision. */
int jg_database_update_domain_rule(struct jg_database *database,
                                   const struct jg_policy_rule_input *rule,
                                   bool enabled,
                                   uint64_t expected_revision,
                                   struct jg_database_domain_rule *updated)
{
    static const char revision_query[] =
        "SELECT revision FROM domain_rules WHERE id=?1;";
    static const char update[] =
        "UPDATE domain_rules SET domain=?2,match_type=?3,effect=?4,source=?5,"
        "scope_type=?6,scope_value=?7,prefix_length=?8,vlan_id=?9,"
        "attribution=?10,target=?11,enabled=?12,updated_at=unixepoch(),"
        "revision=revision+1 WHERE id=?1 AND revision=?13"
        " AND revision<9223372036854775807;";
    struct jg_database_domain_rule record;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || expected_revision == 0U ||
        expected_revision > (uint64_t)INT64_MAX || updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result = validate_domain_rule(rule, false);
    if (result == 0) {
        result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_domain_rule(statement, rule);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 12, enabled ? 1 : 0);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 13,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = write_conflict(database->handle, revision_query, rule->id,
                                expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = read_domain_record(database, rule->id, &record);
    }
    if (result == 0) {
        result = execute_sql(database->handle, "COMMIT;");
    } else {
        (void)execute_sql(database->handle, "ROLLBACK;");
    }
    if (result == 0) {
        *updated = record;
    }
    return result;
}

/** @brief Delete one domain rule at its expected revision. */
int jg_database_delete_domain_rule(struct jg_database *database,
                                   uint64_t rule_id,
                                   uint64_t expected_revision)
{
    static const char revision_query[] =
        "SELECT revision FROM domain_rules WHERE id=?1;";
    static const char remove[] =
        "DELETE FROM domain_rules WHERE id=?1 AND revision=?2;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || rule_id == 0U || rule_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, remove, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)rule_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = write_conflict(database->handle, revision_query, rule_id,
                                expected_revision, false);
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

/** @brief Read one stable identifier-ordered page of destination rules. */
int jg_database_list_destination_rules(
    struct jg_database *database,
    uint64_t after_id,
    size_t limit,
    struct jg_database_destination_rule *rules,
    size_t *count,
    bool *has_more)
{
    static const char query[] =
        "SELECT id,effect,source,protocol,family,address,prefix_length,port,"
        "scope_type,scope_value,scope_prefix_length,scope_vlan_id,attribution,"
        "enabled,updated_at,revision FROM destination_rules WHERE id>?1"
        " ORDER BY id LIMIT ?2;";
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    bool more = false;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || after_id > (uint64_t)INT64_MAX || limit == 0U ||
        limit > JG_DATABASE_POLICY_PAGE_MAX || rules == NULL || count == NULL ||
        has_more == NULL) {
        return -EINVAL;
    }
    *count = 0U;
    *has_more = false;
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)after_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 2, (int)(limit + 1U));
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        if (index == limit) {
            more = true;
            break;
        }
        result = decode_destination_record(statement, &rules[index]);
        ++index;
    }
    if (result == 0 && !more && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *count = index;
        *has_more = more;
    }
    return result;
}

/** @brief Validate one new or replacement destination rule. */
static int validate_destination_rule(
    const struct jg_policy_destination_rule_input *rule,
    bool creating)
{
    struct jg_policy_destination_rule_input validation;

    if (rule == NULL) {
        return -EINVAL;
    }
    if (creating && rule->id != 0U) {
        return -EINVAL;
    }
    if (!creating && (rule->id == 0U || rule->id > (uint64_t)INT64_MAX)) {
        return -EINVAL;
    }
    validation = *rule;
    if (creating) {
        validation.id = 1U;
    }
    return validate_destination_rules(&validation, 1U);
}

/** @brief Read one destination record by its exact identifier. */
static int read_destination_record(struct jg_database *database,
                                   uint64_t rule_id,
                                   struct jg_database_destination_rule *record)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_destination_rules(database, rule_id - 1U, 1U,
                                                    record, &count, &has_more);

    (void)has_more;
    if (result == 0 && (count != 1U || record->id != rule_id)) {
        result = -ENOENT;
    }
    return result;
}

/** @brief Create one destination rule with an assigned identifier. */
int jg_database_create_destination_rule(
    struct jg_database *database,
    const struct jg_policy_destination_rule_input *rule,
    bool enabled,
    struct jg_database_destination_rule *created)
{
    static const char insert[] =
        "INSERT INTO destination_rules("
        "id,effect,source,protocol,family,address,prefix_length,port,"
        "scope_type,scope_value,scope_prefix_length,scope_vlan_id,"
        "attribution,enabled,updated_at"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,"
        "unixepoch());";
    struct jg_database_destination_rule record;
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 identifier = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || created == NULL) {
        return -EINVAL;
    }
    (void)memset(created, 0, sizeof(*created));
    result = validate_destination_rule(rule, true);
    if (result == 0) {
        result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, insert, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_destination_rule(statement, rule);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 14, enabled ? 1 : 0);
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
    if (result == 0) {
        identifier = sqlite3_last_insert_rowid(database->handle);
        if (identifier <= 0) {
            result = -EIO;
        } else {
            result = read_destination_record(database, (uint64_t)identifier,
                                             &record);
        }
    }
    if (result == 0) {
        result = execute_sql(database->handle, "COMMIT;");
    } else {
        (void)execute_sql(database->handle, "ROLLBACK;");
    }
    if (result == 0) {
        *created = record;
    }
    return result;
}

/** @brief Replace one destination rule at its expected revision. */
int jg_database_update_destination_rule(
    struct jg_database *database,
    const struct jg_policy_destination_rule_input *rule,
    bool enabled,
    uint64_t expected_revision,
    struct jg_database_destination_rule *updated)
{
    static const char revision_query[] =
        "SELECT revision FROM destination_rules WHERE id=?1;";
    static const char update[] =
        "UPDATE destination_rules SET effect=?2,source=?3,protocol=?4,"
        "family=?5,address=?6,prefix_length=?7,port=?8,scope_type=?9,"
        "scope_value=?10,scope_prefix_length=?11,scope_vlan_id=?12,"
        "attribution=?13,enabled=?14,updated_at=unixepoch(),"
        "revision=revision+1 WHERE id=?1 AND revision=?15"
        " AND revision<9223372036854775807;";
    struct jg_database_destination_rule record;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || expected_revision == 0U ||
        expected_revision > (uint64_t)INT64_MAX || updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result = validate_destination_rule(rule, false);
    if (result == 0) {
        result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_destination_rule(statement, rule);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 14, enabled ? 1 : 0);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 15,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = write_conflict(database->handle, revision_query, rule->id,
                                expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = read_destination_record(database, rule->id, &record);
    }
    if (result == 0) {
        result = execute_sql(database->handle, "COMMIT;");
    } else {
        (void)execute_sql(database->handle, "ROLLBACK;");
    }
    if (result == 0) {
        *updated = record;
    }
    return result;
}

/** @brief Delete one destination rule at its expected revision. */
int jg_database_delete_destination_rule(struct jg_database *database,
                                        uint64_t rule_id,
                                        uint64_t expected_revision)
{
    static const char revision_query[] =
        "SELECT revision FROM destination_rules WHERE id=?1;";
    static const char remove[] =
        "DELETE FROM destination_rules WHERE id=?1 AND revision=?2;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || rule_id == 0U || rule_id > (uint64_t)INT64_MAX ||
        expected_revision == 0U || expected_revision > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    result = execute_sql(database->handle, "BEGIN IMMEDIATE;");
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, remove, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)rule_id);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = write_conflict(database->handle, revision_query, rule_id,
                                expected_revision, false);
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
