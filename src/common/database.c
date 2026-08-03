/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "janusgate/database.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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

#include <sodium.h>
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

/** Sensitive tables excluded from configuration-only snapshots. */
static const char scrub_sensitive_data[] = "DELETE FROM web_sessions;"
                                           "DELETE FROM api_tokens;"
                                           "DELETE FROM recovery_codes;"
                                           "DELETE FROM totp_credentials;"
                                           "DELETE FROM mtls_mappings;"
                                           "DELETE FROM user_roles;"
                                           "DELETE FROM users;"
                                           "DELETE FROM bootstrap_credentials;"
                                           "DELETE FROM audit_events;"
                                           "DELETE FROM operational_events;"
                                           "DELETE FROM policy_rule_stats;"
                                           "DELETE FROM policy_traffic_stats;"
                                           "DELETE FROM policy_impact_buckets;"
                                           "DELETE FROM policy_traffic_buckets;"
                                           "DELETE FROM alert_incidents;"
                                           "DELETE FROM alert_outbox;"
                                           "UPDATE alert_configuration SET "
                                           "webhook_enabled=0,"
                                           "webhook_secret_ciphertext=NULL,"
                                           "webhook_secret_nonce=NULL;"
                                           "DELETE FROM backup_metadata;"
                                           "DELETE FROM management_operations;";

/** Sensitive tables preserved across a configuration restore. */
static const char preserve_sensitive_data[] =
    "DELETE FROM main.web_sessions;"
    "DELETE FROM main.api_tokens;"
    "DELETE FROM main.recovery_codes;"
    "DELETE FROM main.totp_credentials;"
    "DELETE FROM main.mtls_mappings;"
    "DELETE FROM main.user_roles;"
    "DELETE FROM main.users;"
    "DELETE FROM main.bootstrap_credentials;"
    "DELETE FROM main.audit_events;"
    "DELETE FROM main.operational_events;"
    "DELETE FROM main.policy_rule_stats;"
    "DELETE FROM main.policy_traffic_stats;"
    "DELETE FROM main.policy_impact_buckets;"
    "DELETE FROM main.policy_traffic_buckets;"
    "DELETE FROM main.alert_incidents;"
    "DELETE FROM main.alert_outbox;"
    "DELETE FROM main.backup_metadata;"
    "DELETE FROM main.management_operations;"
    "INSERT INTO main.users SELECT * FROM retained.users;"
    "INSERT INTO main.user_roles SELECT * FROM retained.user_roles;"
    "INSERT INTO main.api_tokens SELECT * FROM retained.api_tokens;"
    "INSERT INTO main.web_sessions SELECT * FROM retained.web_sessions;"
    "INSERT INTO main.totp_credentials SELECT * FROM retained.totp_credentials;"
    "INSERT INTO main.recovery_codes SELECT * FROM retained.recovery_codes;"
    "INSERT INTO main.mtls_mappings SELECT * FROM retained.mtls_mappings;"
    "INSERT INTO main.bootstrap_credentials "
    "SELECT * FROM retained.bootstrap_credentials;"
    "INSERT INTO main.audit_events SELECT * FROM retained.audit_events;"
    "INSERT INTO main.operational_events "
    "SELECT * FROM retained.operational_events;"
    "INSERT INTO main.policy_rule_stats SELECT * FROM "
    "retained.policy_rule_stats;"
    "INSERT INTO main.policy_traffic_stats "
    "SELECT * FROM retained.policy_traffic_stats;"
    "INSERT INTO main.policy_impact_buckets "
    "SELECT * FROM retained.policy_impact_buckets;"
    "INSERT INTO main.policy_traffic_buckets "
    "SELECT * FROM retained.policy_traffic_buckets;"
    "INSERT INTO main.alert_incidents SELECT * FROM retained.alert_incidents;"
    "INSERT INTO main.alert_outbox SELECT * FROM retained.alert_outbox;"
    "UPDATE main.alert_configuration SET "
    "webhook_enabled=(SELECT webhook_enabled FROM "
    "retained.alert_configuration WHERE id=1),"
    "webhook_url=(SELECT webhook_url FROM retained.alert_configuration "
    "WHERE id=1),"
    "webhook_ca_pem=(SELECT webhook_ca_pem FROM "
    "retained.alert_configuration WHERE id=1),"
    "webhook_timeout_seconds=(SELECT webhook_timeout_seconds FROM "
    "retained.alert_configuration WHERE id=1),"
    "webhook_secret_ciphertext=(SELECT webhook_secret_ciphertext FROM "
    "retained.alert_configuration WHERE id=1),"
    "webhook_secret_nonce=(SELECT webhook_secret_nonce FROM "
    "retained.alert_configuration WHERE id=1);"
    "INSERT INTO main.backup_metadata SELECT * FROM retained.backup_metadata;"
    "INSERT INTO main.management_operations "
    "SELECT * FROM retained.management_operations;";

/** Append-only operational history retained across every restore mode. */
static const char preserve_restore_history_data[] =
    "DELETE FROM main.audit_events;"
    "DELETE FROM main.operational_events;"
    "DELETE FROM main.backup_metadata;"
    "DELETE FROM main.management_operations;"
    "DELETE FROM main.alert_incidents;"
    "DELETE FROM main.alert_outbox;"
    "INSERT INTO main.audit_events SELECT * FROM retained.audit_events;"
    "INSERT INTO main.operational_events "
    "SELECT * FROM retained.operational_events;"
    "INSERT INTO main.backup_metadata SELECT * FROM retained.backup_metadata;"
    "INSERT INTO main.management_operations "
    "SELECT * FROM retained.management_operations;"
    "INSERT INTO main.alert_incidents SELECT * FROM retained.alert_incidents;"
    "INSERT INTO main.alert_outbox SELECT * FROM retained.alert_outbox;";

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

/** Normalize network configuration with optimistic-concurrency metadata. */
static const char migration_9_settings[] =
    "CREATE TABLE IF NOT EXISTS system_settings ("
    "key TEXT PRIMARY KEY CHECK(length(key) BETWEEN 1 AND 128),"
    "value TEXT NOT NULL,"
    "updated_at INTEGER NOT NULL CHECK(updated_at >= 0)"
    ") STRICT;"
    "CREATE TABLE network_configuration ("
    "id INTEGER PRIMARY KEY CHECK(id=1),"
    "value TEXT NOT NULL CHECK(length(value)=168),"
    "revision INTEGER NOT NULL CHECK(revision > 0),"
    "updated_at INTEGER NOT NULL CHECK(updated_at >= 0)"
    ") STRICT;"
    "INSERT INTO network_configuration(id,value,revision,updated_at) "
    "SELECT 1,value,1,updated_at FROM system_settings "
    "WHERE key='network.configuration';"
    "DELETE FROM system_settings WHERE key='network.configuration';"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(9,unixepoch());"
    "PRAGMA user_version=9;";

/** Ordered statement groups composing schema version nine. */
static const char *const migration_9[] = {
    migration_9_settings,
};

/** Add bounded operational logging configuration. */
static const char migration_10_logging[] =
    "CREATE TABLE logging_configuration ("
    "id INTEGER PRIMARY KEY CHECK(id=1),"
    "value TEXT NOT NULL CHECK(length(CAST(value AS BLOB)) BETWEEN 1 AND 4096),"
    "revision INTEGER NOT NULL CHECK(revision > 0),"
    "updated_at INTEGER NOT NULL CHECK(updated_at >= 0)"
    ") STRICT;"
    "INSERT INTO logging_configuration(id,value,revision,updated_at) VALUES("
    "1,'{\"destinations\":[\"stderr\",\"syslog\"],"
    "\"diagnostic_until\":0,\"global_level\":\"info\","
    "\"include_identifiers\":false,\"overrides\":[],"
    "\"rate_limit_per_second\":100,\"trace_capacity\":16}',1,unixepoch());"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(10,unixepoch());"
    "PRAGMA user_version=10;";

/** Ordered statement groups composing schema version ten. */
static const char *const migration_10[] = {
    migration_10_logging,
};

/** Extend audit provenance with trusted local administrators. */
static const char migration_11_audit[] =
    "ALTER TABLE audit_events RENAME TO audit_events_v10;"
    "CREATE TABLE audit_events ("
    "id INTEGER PRIMARY KEY,"
    "occurred_at INTEGER NOT NULL CHECK(occurred_at >= 0),"
    "actor_type TEXT NOT NULL "
    "CHECK(actor_type IN ('system','user','token','local')),"
    "actor_id INTEGER,"
    "action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 128),"
    "object_type TEXT NOT NULL CHECK(length(object_type) BETWEEN 1 AND 128),"
    "object_id TEXT,"
    "details TEXT NOT NULL,"
    "previous_hash BLOB CHECK(previous_hash IS NULL OR "
    "length(previous_hash)=32),"
    "event_hash BLOB NOT NULL UNIQUE CHECK(length(event_hash)=32),"
    "source TEXT NOT NULL DEFAULT 'local' "
    "CHECK(length(source) BETWEEN 1 AND 255),"
    "previous_revision INTEGER "
    "CHECK(previous_revision IS NULL OR previous_revision > 0),"
    "new_revision INTEGER CHECK(new_revision IS NULL OR new_revision > 0),"
    "success INTEGER NOT NULL DEFAULT 1 CHECK(success IN (0,1)),"
    "request_id TEXT NOT NULL DEFAULT '' CHECK(length(request_id) <= 128)"
    ") STRICT;"
    "INSERT INTO audit_events SELECT * FROM audit_events_v10;"
    "DROP TABLE audit_events_v10;"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(11,unixepoch());"
    "PRAGMA user_version=11;";

/** Ordered statement groups composing schema version eleven. */
static const char *const migration_11[] = {
    migration_11_audit,
};

/** Persist inspectable and revocable client-certificate mappings. */
static const char migration_12_mtls[] =
    "ALTER TABLE mtls_mappings ADD COLUMN subject TEXT NOT NULL DEFAULT '' "
    "CHECK(length(subject) <= 1023);"
    "ALTER TABLE mtls_mappings ADD COLUMN issuer TEXT NOT NULL DEFAULT '' "
    "CHECK(length(issuer) <= 1023);"
    "ALTER TABLE mtls_mappings ADD COLUMN not_before INTEGER NOT NULL DEFAULT "
    "0 "
    "CHECK(not_before >= 0);"
    "ALTER TABLE mtls_mappings ADD COLUMN not_after INTEGER NOT NULL DEFAULT 0 "
    "CHECK(not_after >= not_before);"
    "ALTER TABLE mtls_mappings ADD COLUMN revoked_at INTEGER "
    "CHECK(revoked_at IS NULL OR revoked_at >= created_at);"
    "ALTER TABLE mtls_mappings ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 "
    "CHECK(revision > 0);"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(12,unixepoch());"
    "PRAGMA user_version=12;";

/** Ordered statement groups composing schema version twelve. */
static const char *const migration_12[] = {
    migration_12_mtls,
};

/** Persist one crash-recoverable cross-resource management operation. */
static const char migration_13_operations[] =
    "CREATE TABLE management_operations ("
    "id INTEGER PRIMARY KEY CHECK(id=1),"
    "kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 64),"
    "state TEXT NOT NULL CHECK(state='preparing' OR state='ready'),"
    "payload BLOB NOT NULL CHECK(length(payload)<=4096),"
    "created_at INTEGER NOT NULL CHECK(created_at>=0)"
    ") STRICT;"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(13,unixepoch());"
    "PRAGMA user_version=13;";

/** Ordered statement groups composing schema version thirteen. */
static const char *const migration_13[] = {
    migration_13_operations,
};

/** Persist policy publication health across runtime restarts. */
static const char migration_14_policy_sync[] =
    "CREATE TABLE policy_sync_state ("
    "id INTEGER PRIMARY KEY CHECK(id=1),"
    "desired_revision INTEGER NOT NULL CHECK(desired_revision>0),"
    "applied_revision INTEGER NOT NULL CHECK(applied_revision>0),"
    "last_attempt_at INTEGER NOT NULL CHECK(last_attempt_at>=0),"
    "last_error TEXT CHECK(last_error IS NULL OR "
    "length(last_error) BETWEEN 1 AND 128),"
    "updated_at INTEGER NOT NULL CHECK(updated_at>=0),"
    "CHECK(applied_revision<=desired_revision)"
    ") STRICT;"
    "INSERT INTO policy_sync_state(id,desired_revision,applied_revision,"
    "last_attempt_at,last_error,updated_at)"
    " VALUES(1,1,1,0,NULL,unixepoch());"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(14,unixepoch());"
    "PRAGMA user_version=14;";

/** Ordered statement groups composing schema version fourteen. */
static const char *const migration_14[] = {
    migration_14_policy_sync,
};

/** Retain the initiating actor and request with recoverable operations. */
static const char migration_15_operation_provenance[] =
    "ALTER TABLE management_operations ADD COLUMN actor_type TEXT NOT NULL "
    "DEFAULT 'system' CHECK(actor_type IN "
    "('system','user','token','local'));"
    "ALTER TABLE management_operations ADD COLUMN actor_id INTEGER "
    "CHECK((actor_type IN ('user','token') AND actor_id>0) OR "
    "(actor_type IN ('system','local') AND actor_id IS NULL));"
    "ALTER TABLE management_operations ADD COLUMN source TEXT NOT NULL "
    "DEFAULT 'local' CHECK(length(source) BETWEEN 1 AND 255);"
    "ALTER TABLE management_operations ADD COLUMN request_id TEXT NOT NULL "
    "DEFAULT '' CHECK(length(request_id)<=128);"
    "ALTER TABLE management_operations ADD COLUMN requested_action TEXT NOT "
    "NULL DEFAULT 'management.operation.unknown' "
    "CHECK(length(requested_action) BETWEEN 1 AND 128);"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(15,unixepoch());"
    "PRAGMA user_version=15;";

/** Ordered statement groups composing schema version fifteen. */
static const char *const migration_15[] = {
    migration_15_operation_provenance,
};

/** Add persistent observe-only policy controls at every supported level. */
static const char migration_16_policy_enforcement[] =
    "CREATE TABLE policy_configuration ("
    "id INTEGER PRIMARY KEY CHECK(id=1),"
    "enforcement TEXT NOT NULL CHECK(enforcement IN ('enforce','observe')),"
    "revision INTEGER NOT NULL CHECK(revision>0),"
    "updated_at INTEGER NOT NULL CHECK(updated_at>=0)"
    ") STRICT;"
    "INSERT INTO policy_configuration(id,enforcement,revision,updated_at)"
    " VALUES(1,'enforce',1,unixepoch());"
    "ALTER TABLE policy_groups ADD COLUMN enforcement TEXT NOT NULL "
    "DEFAULT 'enforce' CHECK(enforcement IN ('enforce','observe'));"
    "ALTER TABLE policy_groups ADD COLUMN revision INTEGER NOT NULL "
    "DEFAULT 1 CHECK(revision>0);"
    "ALTER TABLE blocklist_sources ADD COLUMN enforcement TEXT NOT NULL "
    "DEFAULT 'enforce' CHECK(enforcement IN ('enforce','observe'));"
    "ALTER TABLE domain_rules ADD COLUMN enforcement TEXT NOT NULL "
    "DEFAULT 'enforce' CHECK(enforcement IN ('enforce','observe'));"
    "ALTER TABLE destination_rules ADD COLUMN enforcement TEXT NOT NULL "
    "DEFAULT 'enforce' CHECK(enforcement IN ('enforce','observe'));"
    "CREATE TABLE policy_scope_modes ("
    "id INTEGER PRIMARY KEY,"
    "name TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 128),"
    "enforcement TEXT NOT NULL CHECK(enforcement IN ('enforce','observe')),"
    "scope_type TEXT NOT NULL "
    "CHECK(scope_type IN ('mac','ipv4','ipv6','vlan')),"
    "scope_value BLOB,"
    "prefix_length INTEGER,"
    "vlan_id INTEGER,"
    "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),"
    "revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),"
    "created_at INTEGER NOT NULL CHECK(created_at>=0),"
    "updated_at INTEGER NOT NULL CHECK(updated_at>=created_at),"
    "CHECK((scope_type='mac' AND length(scope_value)=6 AND "
    "prefix_length IS NULL AND vlan_id IS NULL) OR "
    "(scope_type='ipv4' AND length(scope_value)=4 AND "
    "prefix_length BETWEEN 0 AND 32 AND vlan_id IS NULL) OR "
    "(scope_type='ipv6' AND length(scope_value)=16 AND "
    "prefix_length BETWEEN 0 AND 128 AND vlan_id IS NULL) OR "
    "(scope_type='vlan' AND scope_value IS NULL AND "
    "prefix_length IS NULL AND vlan_id BETWEEN 0 AND 4094))"
    ") STRICT;"
    "CREATE INDEX policy_scope_modes_enabled_idx ON policy_scope_modes(id) "
    "WHERE enabled=1 AND enforcement='observe';"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(16,unixepoch());"
    "PRAGMA user_version=16;";

/** Ordered statement groups composing schema version sixteen. */
static const char *const migration_16[] = {
    migration_16_policy_enforcement,
};

/** Add bounded policy-impact aggregates and configurable detail retention. */
static const char migration_17_policy_statistics[] =
    "CREATE TABLE policy_statistics_configuration("
    "id INTEGER PRIMARY KEY CHECK(id=1),"
    "retention_enabled INTEGER NOT NULL CHECK(retention_enabled IN (0,1)),"
    "retention_months INTEGER NOT NULL CHECK(retention_months BETWEEN 1 AND "
    "120),"
    "revision INTEGER NOT NULL CHECK(revision>0),"
    "updated_at INTEGER NOT NULL CHECK(updated_at>=0),"
    "last_cleanup_at INTEGER NOT NULL DEFAULT 0 CHECK(last_cleanup_at>=0)"
    ") STRICT;"
    "INSERT INTO policy_statistics_configuration("
    "id,retention_enabled,retention_months,revision,updated_at)"
    " VALUES(1,1,12,1,unixepoch());"
    "CREATE TABLE policy_rule_stats("
    "dimension TEXT NOT NULL CHECK(dimension IN ('domain','destination')),"
    "rule_id INTEGER NOT NULL CHECK(rule_id>0),"
    "match_count INTEGER NOT NULL DEFAULT 0 CHECK(match_count>=0),"
    "decision_count INTEGER NOT NULL DEFAULT 0 CHECK(decision_count>=0),"
    "would_block_count INTEGER NOT NULL DEFAULT 0 CHECK(would_block_count>=0),"
    "enforced_block_count INTEGER NOT NULL DEFAULT 0 "
    "CHECK(enforced_block_count>=0),"
    "allow_decision_count INTEGER NOT NULL DEFAULT 0 "
    "CHECK(allow_decision_count>=0),"
    "shadowed_count INTEGER NOT NULL DEFAULT 0 CHECK(shadowed_count>=0),"
    "first_hit_at INTEGER NOT NULL CHECK(first_hit_at>=0),"
    "last_hit_at INTEGER NOT NULL CHECK(last_hit_at>=first_hit_at),"
    "PRIMARY KEY(dimension,rule_id)"
    ") WITHOUT ROWID,STRICT;"
    "CREATE TABLE policy_traffic_stats("
    "id INTEGER PRIMARY KEY CHECK(id=1),"
    "request_count INTEGER NOT NULL DEFAULT 0 CHECK(request_count>=0),"
    "matched_count INTEGER NOT NULL DEFAULT 0 CHECK(matched_count>=0),"
    "would_block_count INTEGER NOT NULL DEFAULT 0 CHECK(would_block_count>=0),"
    "enforced_block_count INTEGER NOT NULL DEFAULT 0 "
    "CHECK(enforced_block_count>=0),"
    "first_request_at INTEGER NOT NULL CHECK(first_request_at>=0),"
    "last_request_at INTEGER NOT NULL CHECK(last_request_at>=first_request_at)"
    ") STRICT;"
    "CREATE TABLE policy_impact_buckets("
    "bucket_start INTEGER NOT NULL CHECK(bucket_start>=0 AND "
    "bucket_start%3600=0),"
    "dimension TEXT NOT NULL CHECK(dimension IN ('domain','destination')),"
    "rule_id INTEGER NOT NULL CHECK(rule_id>0),"
    "path TEXT NOT NULL CHECK(path IN ('dns','tls_sni','destination')),"
    "client_family INTEGER NOT NULL CHECK(client_family IN (0,4,6)),"
    "client_address BLOB NOT NULL CHECK((client_family=0 AND "
    "length(client_address)=0) OR (client_family=4 AND "
    "length(client_address)=4) OR (client_family=6 AND "
    "length(client_address)=16)),"
    "client_mac BLOB NOT NULL CHECK(length(client_mac) IN (0,6)),"
    "vlan_id INTEGER NOT NULL CHECK(vlan_id BETWEEN -1 AND 4094),"
    "domain TEXT NOT NULL CHECK(length(domain)<=253),"
    "query_type INTEGER NOT NULL CHECK(query_type BETWEEN 0 AND 65535),"
    "match_count INTEGER NOT NULL DEFAULT 0 CHECK(match_count>=0),"
    "decision_count INTEGER NOT NULL DEFAULT 0 CHECK(decision_count>=0),"
    "would_block_count INTEGER NOT NULL DEFAULT 0 CHECK(would_block_count>=0),"
    "enforced_block_count INTEGER NOT NULL DEFAULT 0 "
    "CHECK(enforced_block_count>=0),"
    "allow_decision_count INTEGER NOT NULL DEFAULT 0 "
    "CHECK(allow_decision_count>=0),"
    "shadowed_count INTEGER NOT NULL DEFAULT 0 CHECK(shadowed_count>=0),"
    "PRIMARY KEY(bucket_start,dimension,rule_id,path,client_family,"
    "client_address,client_mac,vlan_id,domain,query_type)"
    ") WITHOUT ROWID,STRICT;"
    "CREATE INDEX policy_impact_rule_time_idx ON "
    "policy_impact_buckets(dimension,rule_id,bucket_start);"
    "CREATE INDEX policy_impact_time_idx ON "
    "policy_impact_buckets(bucket_start);"
    "CREATE TABLE policy_traffic_buckets("
    "bucket_start INTEGER NOT NULL CHECK(bucket_start>=0 AND "
    "bucket_start%3600=0),"
    "path TEXT NOT NULL CHECK(path IN ('dns','tls_sni','destination')),"
    "request_count INTEGER NOT NULL DEFAULT 0 CHECK(request_count>=0),"
    "matched_count INTEGER NOT NULL DEFAULT 0 CHECK(matched_count>=0),"
    "would_block_count INTEGER NOT NULL DEFAULT 0 CHECK(would_block_count>=0),"
    "enforced_block_count INTEGER NOT NULL DEFAULT 0 "
    "CHECK(enforced_block_count>=0),"
    "PRIMARY KEY(bucket_start,path)"
    ") WITHOUT ROWID,STRICT;"
    "CREATE INDEX policy_traffic_time_idx ON "
    "policy_traffic_buckets(bucket_start);"
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(17,unixepoch());"
    "PRAGMA user_version=17;";

/** Ordered statement groups composing schema version seventeen. */
static const char *const migration_17[] = {
    migration_17_policy_statistics,
};

/** Add persistent alert configuration, incidents, and delivery outbox. */
static const char migration_18_configuration[] =
    "CREATE TABLE alert_configuration("
    "id INTEGER PRIMARY KEY CHECK(id=1),"
    "enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),"
    "evaluation_interval_seconds INTEGER NOT NULL "
    "CHECK(evaluation_interval_seconds BETWEEN 30 AND 3600),"
    "certificate_warning_days INTEGER NOT NULL "
    "CHECK(certificate_warning_days BETWEEN 1 AND 365),"
    "source_failure_threshold INTEGER NOT NULL "
    "CHECK(source_failure_threshold BETWEEN 1 AND 100),"
    "source_stale_seconds INTEGER NOT NULL "
    "CHECK(source_stale_seconds BETWEEN 300 AND 2592000),"
    "filesystem_minimum_percent INTEGER NOT NULL "
    "CHECK(filesystem_minimum_percent BETWEEN 1 AND 50),"
    "filesystem_minimum_bytes INTEGER NOT NULL "
    "CHECK(filesystem_minimum_bytes BETWEEN 0 AND 1099511627776),"
    "queue_window_seconds INTEGER NOT NULL "
    "CHECK(queue_window_seconds BETWEEN 60 AND 3600),"
    "queue_drop_threshold INTEGER NOT NULL "
    "CHECK(queue_drop_threshold BETWEEN 1 AND 1000000000),"
    "authentication_window_seconds INTEGER NOT NULL "
    "CHECK(authentication_window_seconds BETWEEN 60 AND 3600),"
    "authentication_failure_threshold INTEGER NOT NULL "
    "CHECK(authentication_failure_threshold BETWEEN 1 AND 1000000000),"
    "webhook_enabled INTEGER NOT NULL CHECK(webhook_enabled IN (0,1)),"
    "webhook_url TEXT CHECK(webhook_url IS NULL OR "
    "length(webhook_url) BETWEEN 1 AND 2048),"
    "webhook_ca_pem TEXT CHECK(webhook_ca_pem IS NULL OR "
    "length(webhook_ca_pem) BETWEEN 1 AND 65536),"
    "webhook_timeout_seconds INTEGER NOT NULL "
    "CHECK(webhook_timeout_seconds BETWEEN 1 AND 30),"
    "webhook_secret_ciphertext BLOB CHECK(webhook_secret_ciphertext IS NULL "
    "OR length(webhook_secret_ciphertext)=48),"
    "webhook_secret_nonce BLOB CHECK(webhook_secret_nonce IS NULL OR "
    "length(webhook_secret_nonce)=24),"
    "revision INTEGER NOT NULL CHECK(revision>0),"
    "updated_at INTEGER NOT NULL CHECK(updated_at>=0),"
    "CHECK((webhook_secret_ciphertext IS NULL)="
    "(webhook_secret_nonce IS NULL)),"
    "CHECK(webhook_enabled=0 OR (webhook_url IS NOT NULL AND "
    "webhook_secret_ciphertext IS NOT NULL))"
    ") STRICT;"
    "INSERT INTO alert_configuration("
    "id,enabled,evaluation_interval_seconds,certificate_warning_days,"
    "source_failure_threshold,source_stale_seconds,"
    "filesystem_minimum_percent,filesystem_minimum_bytes,"
    "queue_window_seconds,queue_drop_threshold,"
    "authentication_window_seconds,authentication_failure_threshold,"
    "webhook_enabled,webhook_timeout_seconds,revision,updated_at"
    ") VALUES(1,1,60,30,3,3600,10,268435456,300,1,300,20,0,10,1,"
    "unixepoch());";

/** Persistent incident state for schema version eighteen. */
static const char migration_18_incidents[] =
    "CREATE TABLE alert_incidents("
    "id INTEGER PRIMARY KEY,"
    "alert_key TEXT NOT NULL CHECK(length(alert_key) BETWEEN 1 AND 160),"
    "type TEXT NOT NULL CHECK(type IN "
    "('appliance_degraded','policy_unsynchronized','audit_unverifiable',"
    "'certificate_expiring','source_unhealthy','filesystem_low_space',"
    "'queue_drops','authentication_failures')),"
    "resource TEXT NOT NULL CHECK(length(resource) BETWEEN 1 AND 128),"
    "severity TEXT NOT NULL CHECK(severity IN "
    "('warning','error','critical')),"
    "state TEXT NOT NULL CHECK(state IN ('open','resolved')),"
    "summary TEXT NOT NULL CHECK(length(summary) BETWEEN 1 AND 512),"
    "details TEXT NOT NULL CHECK(length(details) BETWEEN 2 AND 4096),"
    "opened_at INTEGER NOT NULL CHECK(opened_at>=0),"
    "updated_at INTEGER NOT NULL CHECK(updated_at>=opened_at),"
    "resolved_at INTEGER CHECK(resolved_at IS NULL OR "
    "resolved_at>=opened_at),"
    "occurrences INTEGER NOT NULL DEFAULT 1 CHECK(occurrences>0)"
    ") STRICT;"
    "CREATE UNIQUE INDEX alert_incidents_open_key_idx ON "
    "alert_incidents(alert_key) WHERE state='open';"
    "CREATE INDEX alert_incidents_state_time_idx ON "
    "alert_incidents(state,updated_at DESC,id DESC);";

/** Bounded asynchronous delivery queue for schema version eighteen. */
static const char migration_18_outbox[] =
    "CREATE TABLE alert_outbox("
    "id INTEGER PRIMARY KEY,"
    "incident_id INTEGER REFERENCES alert_incidents(id) ON DELETE SET NULL,"
    "kind TEXT NOT NULL CHECK(kind IN ('incident','event')),"
    "event_code TEXT NOT NULL CHECK(length(event_code) BETWEEN 1 AND 128),"
    "transition TEXT NOT NULL CHECK(transition IN "
    "('open','resolved','event')),"
    "payload TEXT NOT NULL CHECK(length(payload) BETWEEN 2 AND 8192),"
    "status TEXT NOT NULL CHECK(status IN "
    "('pending','delivered','abandoned')),"
    "created_at INTEGER NOT NULL CHECK(created_at>=0),"
    "next_attempt_at INTEGER NOT NULL CHECK(next_attempt_at>=created_at),"
    "attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 20),"
    "delivered_at INTEGER CHECK(delivered_at IS NULL OR "
    "delivered_at>=created_at),"
    "last_error TEXT CHECK(last_error IS NULL OR length(last_error)<=512)"
    ") STRICT;"
    "CREATE INDEX alert_outbox_due_idx ON "
    "alert_outbox(status,next_attempt_at,id);";

/** Complete schema-version marker for migration eighteen. */
static const char migration_18_version[] =
    "INSERT INTO schema_migrations(version,applied_at) "
    "VALUES(18,unixepoch());"
    "PRAGMA user_version=18;";

/** Ordered statement groups composing schema version eighteen. */
static const char *const migration_18[] = {
    migration_18_configuration,
    migration_18_incidents,
    migration_18_outbox,
    migration_18_version,
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
    {9U, migration_9, sizeof(migration_9) / sizeof(migration_9[0])},
    {10U, migration_10, sizeof(migration_10) / sizeof(migration_10[0])},
    {11U, migration_11, sizeof(migration_11) / sizeof(migration_11[0])},
    {12U, migration_12, sizeof(migration_12) / sizeof(migration_12[0])},
    {13U, migration_13, sizeof(migration_13) / sizeof(migration_13[0])},
    {14U, migration_14, sizeof(migration_14) / sizeof(migration_14[0])},
    {15U, migration_15, sizeof(migration_15) / sizeof(migration_15[0])},
    {16U, migration_16, sizeof(migration_16) / sizeof(migration_16[0])},
    {17U, migration_17, sizeof(migration_17) / sizeof(migration_17[0])},
    {18U, migration_18, sizeof(migration_18) / sizeof(migration_18[0])},
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
int jg_database_execute_sql(sqlite3 *handle, const char *sql)
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

/** @brief Enter a transaction scope with the requested outermost mode. */
static int transaction_begin(struct jg_database *database, const char *sql)
{
    int result = 0;

    if (database == NULL || database->transaction_depth == UINT_MAX) {
        return database == NULL ? -EINVAL : -EOVERFLOW;
    }
    if (database->transaction_depth == 0U) {
        result = jg_database_execute_sql(database->handle, sql);
    }
    if (result == 0) {
        ++database->transaction_depth;
    }
    return result;
}

/** @brief Enter a write transaction scope, nesting within an existing scope. */
int jg_database_transaction_begin(struct jg_database *database)
{
    return transaction_begin(database, "BEGIN IMMEDIATE;");
}

/** @brief Enter a read transaction scope, nesting within an existing scope. */
int jg_database_transaction_begin_read(struct jg_database *database)
{
    return transaction_begin(database, "BEGIN;");
}

/** @brief Commit one transaction scope and persist the outermost scope. */
int jg_database_transaction_commit(struct jg_database *database)
{
    int result = 0;

    if (database == NULL || database->transaction_depth == 0U) {
        return -EINVAL;
    }
    if (database->transaction_depth == 1U) {
        result = jg_database_execute_sql(database->handle, "COMMIT;");
    }
    if (result == 0) {
        --database->transaction_depth;
    }
    return result;
}

/** @brief Roll back every active transaction scope. */
int jg_database_transaction_rollback(struct jg_database *database)
{
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    if (database->transaction_depth > 0U) {
        result = jg_database_execute_sql(database->handle, "ROLLBACK;");
        if (result == 0) {
            database->transaction_depth = 0U;
        }
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

/** @brief Synchronize the directory entry containing one absolute path. */
static int sync_parent_directory(const char *path)
{
    const char *separator = NULL;
    size_t length = 0U;
    char *parent = NULL;
    int descriptor = -1;
    int result = 0;

    if (path == NULL || path[0U] != '/') {
        return -EINVAL;
    }
    separator = strrchr(path, '/');
    if (separator == NULL || separator[1U] == '\0') {
        return -EINVAL;
    }
    length = separator == path ? 1U : (size_t)(separator - path);
    parent = malloc(length + 1U);
    if (parent == NULL) {
        return -ENOMEM;
    }
    (void)memcpy(parent, path, length);
    parent[length] = '\0';
    descriptor = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    free(parent);
    if (descriptor < 0) {
        return -errno;
    }
    if (fsync(descriptor) != 0) {
        result = -errno;
    }
    if (close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    return result;
}

/** @brief Copy one complete SQLite schema into another connection. */
static int copy_database(sqlite3 *target,
                         const char *target_schema,
                         sqlite3 *source,
                         const char *source_schema)
{
    sqlite3_backup *backup =
        sqlite3_backup_init(target, target_schema, source, source_schema);
    int result = 0;
    int status;

    if (backup == NULL) {
        return jg_database_sqlite_result(sqlite3_errcode(target));
    }
    status = sqlite3_backup_step(backup, -1);
    if (status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    status = sqlite3_backup_finish(backup);
    if (result == 0) {
        result = jg_database_sqlite_result(status);
    }
    return result;
}

/** @brief Atomically write one synchronized SQLite database copy. */
static int backup_database(const struct jg_database *database,
                           const char *suffix)
{
    sqlite3 *target = NULL;
    char temporary_suffix[64U];
    char *backup_path = NULL;
    char *temporary_path = NULL;
    int descriptor = -1;
    int status;
    int result = 0;
    int written = snprintf(temporary_suffix, sizeof(temporary_suffix),
                           "%s.XXXXXX", suffix);

    if (written <= 0 || (size_t)written >= sizeof(temporary_suffix)) {
        result = -EINVAL;
    }
    if (result == 0) {
        backup_path = path_with_suffix(database->path, suffix);
        temporary_path = path_with_suffix(database->path, temporary_suffix);
    }
    if (result == 0 && (backup_path == NULL || temporary_path == NULL)) {
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
        descriptor = -1;
    }
    if (result == 0) {
        status = sqlite3_open_v2(temporary_path, &target,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX |
                                     SQLITE_OPEN_NOFOLLOW,
                                 NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = copy_database(target, "main", database->handle, "main");
    }
    if (target != NULL) {
        status = sqlite3_close(target);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        descriptor = open(temporary_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0) {
            result = -errno;
        }
    }
    if (descriptor >= 0) {
        if (fsync(descriptor) != 0) {
            result = -errno;
        }
        if (close(descriptor) != 0 && result == 0) {
            result = -errno;
        }
    }
    if (result == 0 && rename(temporary_path, backup_path) != 0) {
        result = -errno;
    }
    if (result == 0) {
        result = sync_parent_directory(backup_path);
    }
    if (result != 0 && temporary_path != NULL) {
        (void)unlink(temporary_path);
    }
    free(temporary_path);
    free(backup_path);
    return result;
}

/** @brief Create the durable cross-resource recovery checkpoint. */
int jg_database_recovery_checkpoint_create(const struct jg_database *database)
{
    return database == NULL ? -EINVAL : backup_database(database, ".recovery");
}

/** @brief Remove the durable cross-resource recovery checkpoint. */
int jg_database_recovery_checkpoint_remove(const struct jg_database *database)
{
    char *path = NULL;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    path = path_with_suffix(database->path, ".recovery");
    if (path == NULL) {
        return -ENOMEM;
    }
    if (unlink(path) != 0) {
        result = -errno;
    }
    if (result == 0) {
        result = sync_parent_directory(path);
    }
    free(path);
    return result;
}

/** @brief Apply every missing migration transactionally and in order. */
static int migrate_database(struct jg_database *database,
                            uint32_t current_version)
{
    size_t index = 0U;
    int result = 0;

    if (current_version > 0U && current_version < JG_DATABASE_SCHEMA_VERSION) {
        result = backup_database(database, ".lkg");
    }
    for (index = 0U;
         result == 0 && index < sizeof(migrations) / sizeof(migrations[0]);
         ++index) {
        if (migrations[index].version <= current_version) {
            continue;
        }
        result = jg_database_transaction_begin(database);
        for (size_t sql_index = 0U;
             result == 0 && sql_index < migrations[index].sql_count;
             ++sql_index) {
            result = jg_database_execute_sql(database->handle,
                                             migrations[index].sql[sql_index]);
        }
        if (result == 0) {
            result = jg_database_transaction_commit(database);
        } else {
            (void)jg_database_transaction_rollback(database);
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

/** @brief Run SQLite's full integrity check on one connection. */
static int check_database_integrity(sqlite3 *handle)
{
    sqlite3_stmt *statement = NULL;
    int status;
    int result = 0;

    status = sqlite3_prepare_v3(handle, "PRAGMA integrity_check;", -1, 0U,
                                &statement, NULL);
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

/** @brief Remove sensitive records and residual bytes from one snapshot. */
static int scrub_database(sqlite3 *handle)
{
    int result = jg_database_execute_sql(handle, "PRAGMA secure_delete=ON;");

    if (result == 0) {
        result = jg_database_execute_sql(handle, scrub_sensitive_data);
    }
    if (result == 0) {
        result = jg_database_execute_sql(handle, "VACUUM;");
    }
    return result;
}

/** @brief Serialize one standalone SQLite connection image. */
static int serialize_database(sqlite3 *handle,
                              uint8_t **data,
                              size_t *data_size)
{
    sqlite3_int64 serialized_size = 0;
    unsigned char *serialized = NULL;
    int result = 0;

    *data = NULL;
    *data_size = 0U;
    serialized = sqlite3_serialize(handle, "main", &serialized_size, 0U);
    if (serialized == NULL) {
        result = -ENOMEM;
    } else if (serialized_size < 100) {
        result = -EILSEQ;
    } else if ((uint64_t)serialized_size > (uint64_t)SIZE_MAX) {
        result = -EOVERFLOW;
    } else {
        /* Mark the snapshot as independent from an external WAL file. */
        serialized[18U] = 1U;
        serialized[19U] = 1U;
    }
    if (result == 0) {
        *data = serialized;
        *data_size = (size_t)serialized_size;
    } else if (serialized != NULL) {
        if (serialized_size > 0 &&
            (uint64_t)serialized_size <= (uint64_t)SIZE_MAX) {
            jg_secure_clear(serialized, (size_t)serialized_size);
        }
        sqlite3_free(serialized);
    }
    return result;
}

/** @brief Open one owned, resizable SQLite image in memory. */
static int open_database_image(const uint8_t *data,
                               size_t data_size,
                               sqlite3 **handle)
{
    static const uint8_t sqlite_magic[16U] = "SQLite format 3";
    unsigned char *owned = NULL;
    sqlite3 *opened = NULL;
    int status;
    int result = 0;

    *handle = NULL;
    if (data_size < 100U ||
        memcmp(data, sqlite_magic, sizeof(sqlite_magic)) != 0 ||
        data[18U] != 1U || data[19U] != 1U || data_size > (size_t)INT64_MAX) {
        return -EILSEQ;
    }
    owned = sqlite3_malloc64((sqlite3_uint64)data_size);
    if (owned == NULL) {
        return -ENOMEM;
    }
    (void)memcpy(owned, data, data_size);
    status = sqlite3_open_v2(":memory:", &opened,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                 SQLITE_OPEN_FULLMUTEX,
                             NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_deserialize(
            opened, "main", owned, (sqlite3_int64)data_size,
            (sqlite3_int64)data_size,
            SQLITE_DESERIALIZE_FREEONCLOSE | SQLITE_DESERIALIZE_RESIZEABLE);
        result = jg_database_sqlite_result(status);
        if (result == 0) {
            owned = NULL;
        }
    }
    if (result != 0 && opened != NULL) {
        (void)sqlite3_close(opened);
        opened = NULL;
    }
    if (owned != NULL) {
        sqlite3_free(owned);
    }
    *handle = opened;
    return result;
}

/** @brief Retain selected current tables inside a replacement snapshot. */
static int preserve_current_tables(sqlite3 *replacement,
                                   sqlite3 *current,
                                   const char *statements)
{
    int result =
        jg_database_execute_sql(replacement, "ATTACH ':memory:' AS retained;");

    if (result == 0) {
        result = copy_database(replacement, "retained", current, "main");
    }
    if (result == 0) {
        result = jg_database_execute_sql(replacement, "BEGIN IMMEDIATE;");
    }
    if (result == 0) {
        result = jg_database_execute_sql(replacement, statements);
    }
    if (result == 0) {
        result = jg_database_execute_sql(replacement, "COMMIT;");
    } else {
        (void)jg_database_execute_sql(replacement, "ROLLBACK;");
    }
    if (jg_database_execute_sql(replacement, "DETACH retained;") != 0 &&
        result == 0) {
        result = -EIO;
    }
    return result;
}

/** @brief Apply one replacement with an automatic in-memory rollback. */
static int replace_database(sqlite3 *current, sqlite3 *replacement)
{
    sqlite3 *checkpoint = NULL;
    uint32_t version = 0U;
    bool replacement_started = false;
    int status;
    int result;

    status = sqlite3_open_v2(":memory:", &checkpoint,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                 SQLITE_OPEN_FULLMUTEX,
                             NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        result = copy_database(checkpoint, "main", current, "main");
    }
    if (result == 0) {
        replacement_started = true;
        result = copy_database(current, "main", replacement, "main");
    }
    if (result == 0) {
        result = check_database_integrity(current);
    }
    if (result == 0) {
        result = read_version(current, &version);
    }
    if (result == 0 && version != JG_DATABASE_SCHEMA_VERSION) {
        result = -EILSEQ;
    }
    if (result != 0 && replacement_started) {
        int rollback_result =
            copy_database(current, "main", checkpoint, "main");

        if (rollback_result == 0) {
            rollback_result = check_database_integrity(current);
        }
        if (rollback_result != 0) {
            result = -EIO;
        }
    }
    if (checkpoint != NULL) {
        status = sqlite3_close(checkpoint);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Replace the current database from its durable recovery checkpoint. */
int jg_database_recovery_checkpoint_restore(struct jg_database *database)
{
    sqlite3 *checkpoint = NULL;
    char *path = NULL;
    struct stat metadata;
    uint32_t version = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    path = path_with_suffix(database->path, ".recovery");
    if (path == NULL) {
        return -ENOMEM;
    }
    if (lstat(path, &metadata) != 0) {
        result = -errno;
    } else if (!S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid() ||
               (metadata.st_mode & 0777U) != (S_IRUSR | S_IWUSR)) {
        result = -EACCES;
    }
    if (result == 0) {
        status = sqlite3_open_v2(path, &checkpoint,
                                 SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX |
                                     SQLITE_OPEN_NOFOLLOW,
                                 NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = check_database_integrity(checkpoint);
    }
    if (result == 0) {
        result = read_version(checkpoint, &version);
    }
    if (result == 0 && version != JG_DATABASE_SCHEMA_VERSION) {
        result = -EILSEQ;
    }
    if (result == 0) {
        result = replace_database(database->handle, checkpoint);
    }
    if (checkpoint != NULL) {
        status = sqlite3_close(checkpoint);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    free(path);
    return result;
}

/** @brief Run SQLite's full integrity check on an open database. */
int jg_database_check_integrity(struct jg_database *database)
{
    if (database == NULL) {
        return -EINVAL;
    }
    return check_database_integrity(database->handle);
}

/** @brief Export a consistent full or configuration-only SQLite snapshot. */
int jg_database_export(struct jg_database *database,
                       bool include_sensitive,
                       uint8_t **data,
                       size_t *data_size)
{
    sqlite3 *snapshot = NULL;
    int status;
    int result = 0;

    if (database == NULL || data == NULL || data_size == NULL) {
        return -EINVAL;
    }
    *data = NULL;
    *data_size = 0U;
    status = sqlite3_open_v2(":memory:", &snapshot,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                 SQLITE_OPEN_FULLMUTEX,
                             NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        result = copy_database(snapshot, "main", database->handle, "main");
    }
    if (result == 0 && !include_sensitive) {
        result = scrub_database(snapshot);
    }
    if (result == 0) {
        result = serialize_database(snapshot, data, data_size);
    }
    if (snapshot != NULL) {
        status = sqlite3_close(snapshot);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result != 0 && *data != NULL) {
        jg_database_export_clear(*data, *data_size);
        *data = NULL;
        *data_size = 0U;
    }
    return result;
}

/** @brief Securely erase and release an exported database snapshot. */
void jg_database_export_clear(uint8_t *data, size_t data_size)
{
    if (data != NULL) {
        jg_secure_clear(data, data_size);
        sqlite3_free(data);
    }
}

/** @brief Validate, compare, and optionally restore one SQLite snapshot. */
int jg_database_restore(struct jg_database *database,
                        const uint8_t *data,
                        size_t data_size,
                        bool include_sensitive,
                        bool dry_run,
                        struct jg_database_restore_report *report)
{
    sqlite3 *replacement = NULL;
    uint8_t *current_data = NULL;
    uint8_t *replacement_data = NULL;
    size_t current_size = 0U;
    size_t replacement_size = 0U;
    uint32_t version = 0U;
    int result = 0;

    if (database == NULL || data == NULL || report == NULL) {
        return -EINVAL;
    }
    (void)memset(report, 0, sizeof(*report));
    if (sodium_init() < 0) {
        return -EIO;
    }
    result = open_database_image(data, data_size, &replacement);
    if (result == 0) {
        result = check_database_integrity(replacement);
    }
    if (result == 0) {
        result = read_version(replacement, &version);
    }
    if (result == 0 && version != JG_DATABASE_SCHEMA_VERSION) {
        result = -ENOTSUP;
    }
    if (result == 0 && !include_sensitive) {
        result = scrub_database(replacement);
    }
    if (result == 0 && include_sensitive) {
        result = preserve_current_tables(replacement, database->handle,
                                         preserve_restore_history_data);
    }
    if (result == 0) {
        result = jg_database_export(database, include_sensitive, &current_data,
                                    &current_size);
    }
    if (result == 0) {
        result = serialize_database(replacement, &replacement_data,
                                    &replacement_size);
    }
    if (result == 0) {
        report->schema_version = version;
        report->current_size = current_size;
        report->replacement_size = replacement_size;
        (void)crypto_hash_sha256(report->current_checksum, current_data,
                                 (unsigned long long)current_size);
        (void)crypto_hash_sha256(report->replacement_checksum, replacement_data,
                                 (unsigned long long)replacement_size);
        report->changes = current_size != replacement_size ||
                          sodium_memcmp(report->current_checksum,
                                        report->replacement_checksum,
                                        sizeof(report->current_checksum)) != 0;
    }
    if (result == 0 && report->changes && !dry_run && !include_sensitive) {
        result = preserve_current_tables(replacement, database->handle,
                                         preserve_sensitive_data);
    }
    if (result == 0 && report->changes && !dry_run) {
        result = replace_database(database->handle, replacement);
    }
    jg_database_export_clear(replacement_data, replacement_size);
    jg_database_export_clear(current_data, current_size);
    if (replacement != NULL) {
        const int status = sqlite3_close(replacement);

        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result != 0) {
        (void)memset(report, 0, sizeof(*report));
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
        opened->busy_timeout_ms = busy_timeout_ms;
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
        result =
            jg_database_execute_sql(opened->handle, "PRAGMA foreign_keys=ON;"
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

/** @brief Open an independent connection to the same database file. */
int jg_database_open_peer(const struct jg_database *database,
                          struct jg_database **peer)
{
    if (database == NULL || peer == NULL) {
        return -EINVAL;
    }
    return jg_database_open(database->path, database->busy_timeout_ms, peer);
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
int jg_database_column_required_text(sqlite3_stmt *statement,
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
int jg_database_column_optional_text(sqlite3_stmt *statement,
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

/** @brief Decode one required nonnegative integer column. */
int jg_database_column_unsigned(sqlite3_stmt *statement,
                                int column,
                                uint64_t *value)
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
int jg_database_column_optional_unsigned(sqlite3_stmt *statement,
                                         int column,
                                         uint64_t *value)
{
    if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
        *value = 0U;
        return 0;
    }
    return jg_database_column_unsigned(statement, column, value);
}

/** @brief Decode one optional fixed-size binary column. */
int jg_database_column_optional_blob(sqlite3_stmt *statement,
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

/** @brief Read one record revision or report an absent identifier. */
int jg_database_read_revision(sqlite3 *handle,
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
int jg_database_write_conflict(sqlite3 *handle,
                               const char *query,
                               uint64_t identifier,
                               uint64_t expected_revision,
                               bool revision_must_advance)
{
    uint64_t revision = 0U;
    int result =
        jg_database_read_revision(handle, query, identifier, &revision);

    if (result == 0 && revision != expected_revision) {
        result = -EAGAIN;
    } else if (result == 0 && revision_must_advance) {
        result = -EOVERFLOW;
    } else if (result == 0) {
        result = -EIO;
    }
    return result;
}
