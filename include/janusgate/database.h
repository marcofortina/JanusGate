/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file database.h
 * @brief Secure SQLite lifecycle and ordered schema migrations.
 *
 * A database object exclusively owns one SQLite connection. Opening validates
 * filesystem permissions, configures bounded locking, enables foreign keys
 * and WAL mode, checks integrity, and applies missing migrations.
 *
 * @thread_safety A database object must be used by one thread at a time.
 * Distinct objects follow SQLite's normal locking rules.
 *
 * @error_handling Functions return zero on success and negative errno-style
 * values on failure. A failed open leaves the output pointer null.
 */

#ifndef JANUSGATE_DATABASE_H
#define JANUSGATE_DATABASE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/backup.h"
#include "janusgate/blocklist.h"
#include "janusgate/blocklist_remote.h"
#include "janusgate/dns_policy.h"
#include "janusgate/logging.h"
#include "janusgate/network.h"
#include "janusgate/policy.h"
#include "janusgate/version.h"

/** Current persistent schema version. */
#define JG_DATABASE_SCHEMA_VERSION 12U

/** Largest accepted SQLite busy timeout in milliseconds. */
#define JG_DATABASE_BUSY_TIMEOUT_MAX 60000U

/** Maximum active domain rules accepted from persistent storage. */
#define JG_DATABASE_POLICY_RULE_LIMIT 1000000U

/** Maximum number of policy records returned by one database page. */
#define JG_DATABASE_POLICY_PAGE_MAX 100U

/** Maximum blocklist source name bytes excluding the terminator. */
#define JG_DATABASE_BLOCKLIST_NAME_MAX 128U

/** Maximum stored source URL bytes excluding the terminator. */
#define JG_DATABASE_BLOCKLIST_URL_MAX 2048U

/** Maximum stored blocklist update error bytes excluding the terminator. */
#define JG_DATABASE_BLOCKLIST_ERROR_MAX 2048U

/** Maximum backup metadata records returned by one page. */
#define JG_DATABASE_BACKUP_PAGE_MAX 100U

/**
 * @brief Persistent health classification for one blocklist source.
 */
enum jg_database_blocklist_health {
    /** No update has completed. */
    JG_DATABASE_BLOCKLIST_UNKNOWN = 0,
    /** The latest scheduled update completed successfully. */
    JG_DATABASE_BLOCKLIST_HEALTHY = 1,
    /** Updates are failing while a last-known-good list remains active. */
    JG_DATABASE_BLOCKLIST_DEGRADED = 2,
    /** No usable list is active after repeated failures. */
    JG_DATABASE_BLOCKLIST_FAILED = 3
};

/** Opaque owned database connection. */
struct jg_database;

/** Summary of a validated database restore or dry run. */
struct jg_database_restore_report {
    /** Restored database schema version. */
    uint32_t schema_version;
    /** Current comparison snapshot bytes. */
    size_t current_size;
    /** Replacement comparison snapshot bytes. */
    size_t replacement_size;
    /** SHA-256 digest of the current comparison snapshot. */
    uint8_t current_checksum[32U];
    /** SHA-256 digest of the replacement comparison snapshot. */
    uint8_t replacement_checksum[32U];
    /** Whether the selected backup would change persistent state. */
    bool changes;
};

/** Self-contained persistent backup metadata. */
struct jg_database_backup {
    /** Stable positive backup identifier. */
    uint64_t id;
    /** Archive creation time as Unix seconds. */
    uint64_t created_at;
    /** Configuration or encrypted full backup. */
    enum jg_backup_kind kind;
    /** Plain archive filename in the configured backup directory. */
    char filename[JG_BACKUP_FILENAME_MAX + 1U];
    /** SHA-256 archive checksum. */
    uint8_t checksum[32U];
    /** Source database schema version. */
    uint32_t schema_version;
    /** Complete archive bytes. */
    size_t size_bytes;
};
/**
 * @brief Self-contained persistent network-configuration record.
 */
struct jg_database_network_config {
    /** Complete validated inline-network configuration. */
    struct jg_network_config config;
    /** Monotonic optimistic-concurrency revision. */
    uint64_t revision;
    /** Last modification time as Unix seconds. */
    uint64_t updated_at;
};

/**
 * @brief Self-contained persistent logging configuration.
 */
struct jg_database_logging_config {
    /** Complete validated operational logging configuration. */
    struct jg_logging_config config;
    /** Monotonic optimistic-concurrency revision. */
    uint64_t revision;
    /** Last modification time as Unix seconds. */
    uint64_t updated_at;
};

/**
 * @brief Self-contained persistent domain-rule record.
 */
struct jg_database_domain_rule {
    /** Stable positive rule identifier. */
    uint64_t id;
    /** Monotonic optimistic-concurrency revision. */
    uint64_t revision;
    /** Last modification time as Unix seconds. */
    uint64_t updated_at;
    /** Canonical IDNA2008 A-label domain. */
    char domain[JG_DOMAIN_NAME_MAX + 1U];
    /** Human-readable rule provenance. */
    char attribution[JG_POLICY_ATTRIBUTION_MAX + 1U];
    /** Imported category, empty for administrator-authored rules. */
    char category[JG_BLOCKLIST_CATEGORY_MAX + 1U];
    /** Whether descendants at DNS label boundaries also match. */
    bool include_subdomains;
    /** Whether the rule participates in active policy. */
    bool enabled;
    /** Allow or block action. */
    enum jg_policy_effect effect;
    /** Rule origin and precedence class. */
    enum jg_policy_source source;
    /** DNS or visible TLS-SNI matching context. */
    enum jg_policy_domain_target target;
    /** Global or client-specific applicability. */
    struct jg_policy_scope scope;
};

/**
 * @brief Self-contained persistent destination-rule record.
 */
struct jg_database_destination_rule {
    /** Stable positive rule identifier. */
    uint64_t id;
    /** Monotonic optimistic-concurrency revision. */
    uint64_t revision;
    /** Last modification time as Unix seconds. */
    uint64_t updated_at;
    /** Human-readable rule provenance. */
    char attribution[JG_POLICY_ATTRIBUTION_MAX + 1U];
    /** Allow or block action. */
    enum jg_policy_effect effect;
    /** Rule origin and precedence class. */
    enum jg_policy_source source;
    /** Any, TCP, or UDP transport selector. */
    enum jg_policy_transport transport;
    /** Whether an address prefix participates in matching. */
    bool has_address;
    /** Address family when @ref has_address is true. */
    enum jg_policy_address_family address_family;
    /** Canonical network address; IPv4 uses the first four bytes. */
    uint8_t address[16U];
    /** Significant leading address bits. */
    uint8_t prefix_length;
    /** Whether a destination port participates in matching. */
    bool has_port;
    /** Destination port when @ref has_port is true. */
    uint16_t port;
    /** Global or client-specific applicability. */
    struct jg_policy_scope scope;
    /** Whether the rule participates in active policy. */
    bool enabled;
};

/**
 * @brief Caller-owned configuration for one local or remote blocklist source.
 */
struct jg_database_blocklist_source_config {
    /** Unique human-readable source name. */
    const char *name;
    /** HTTPS update URL, or null for a local source. */
    const char *url;
    /** Optional HTTPS detached-signature URL. */
    const char *signature_url;
    /** Imported list syntax. */
    enum jg_blocklist_format format;
    /** Strict or tolerant record handling. */
    enum jg_blocklist_mode mode;
    /** Whether source entries participate in active policy. */
    bool enabled;
    /** Normal remote update interval in seconds. */
    uint64_t update_interval_seconds;
    /** Maximum compressed download bytes. */
    size_t max_download_bytes;
    /** Maximum decompressed import bytes. */
    size_t max_decompressed_bytes;
    /** TCP and TLS connection timeout in the supported millisecond range. */
    uint32_t connect_timeout_ms;
    /** Complete transfer timeout in the supported millisecond range. */
    uint32_t transfer_timeout_ms;
    /** Maximum followed HTTPS redirects. */
    uint32_t redirect_limit;
    /** Initial failed-update retry delay in seconds. */
    uint64_t retry_base_seconds;
    /** Maximum failed-update retry delay in seconds. */
    uint64_t retry_max_seconds;
    /** Whether @ref sha256_pin is configured. */
    bool has_sha256_pin;
    /** Expected downloaded-body SHA-256 digest. */
    uint8_t sha256_pin[JG_BLOCKLIST_CHECKSUM_SIZE];
    /** Whether detached Ed25519 verification is required. */
    bool has_signature;
    /** Ed25519 public verification key. */
    uint8_t ed25519_public_key[32U];
};

/**
 * @brief Self-contained persistent blocklist source and update state.
 */
struct jg_database_blocklist_source {
    /** Stable positive source identifier. */
    uint64_t id;
    /** Monotonic optimistic-concurrency revision. */
    uint64_t revision;
    /** Creation time as Unix seconds. */
    uint64_t created_at;
    /** Last configuration modification time as Unix seconds. */
    uint64_t updated_at;
    /** Unique human-readable source name. */
    char name[JG_DATABASE_BLOCKLIST_NAME_MAX + 1U];
    /** HTTPS update URL, empty for a local source. */
    char url[JG_DATABASE_BLOCKLIST_URL_MAX + 1U];
    /** Detached-signature URL, empty when unused. */
    char signature_url[JG_DATABASE_BLOCKLIST_URL_MAX + 1U];
    /** Imported list syntax. */
    enum jg_blocklist_format format;
    /** Strict or tolerant record handling. */
    enum jg_blocklist_mode mode;
    /** Whether source entries participate in active policy. */
    bool enabled;
    /** Normal remote update interval in seconds. */
    uint64_t update_interval_seconds;
    /** Maximum compressed download bytes. */
    size_t max_download_bytes;
    /** Maximum decompressed import bytes. */
    size_t max_decompressed_bytes;
    /** Effective bounded TCP and TLS connection timeout in milliseconds. */
    uint32_t connect_timeout_ms;
    /** Effective bounded complete transfer timeout in milliseconds. */
    uint32_t transfer_timeout_ms;
    /** Maximum followed HTTPS redirects. */
    uint32_t redirect_limit;
    /** Initial failed-update retry delay. */
    uint64_t retry_base_seconds;
    /** Maximum failed-update retry delay. */
    uint64_t retry_max_seconds;
    /** Whether @ref sha256_pin is configured. */
    bool has_sha256_pin;
    /** Expected downloaded-body SHA-256 digest. */
    uint8_t sha256_pin[JG_BLOCKLIST_CHECKSUM_SIZE];
    /** Whether detached Ed25519 verification is required. */
    bool has_signature;
    /** Ed25519 public verification key. */
    uint8_t ed25519_public_key[32U];
    /** HTTP validator sent through If-None-Match. */
    char etag[JG_BLOCKLIST_ETAG_MAX + 1U];
    /** HTTP validator sent through If-Modified-Since. */
    char last_modified[JG_BLOCKLIST_LAST_MODIFIED_MAX + 1U];
    /** Latest attempted update time, or zero. */
    uint64_t last_attempt_at;
    /** Latest successful update time, or zero. */
    uint64_t last_success_at;
    /** Earliest next scheduled update time, or zero. */
    uint64_t next_attempt_at;
    /** Consecutive failed attempts. */
    uint32_t consecutive_failures;
    /** Whether @ref active_checksum identifies a last-known-good list. */
    bool has_active_checksum;
    /** Canonical checksum of the active list. */
    uint8_t active_checksum[JG_BLOCKLIST_CHECKSUM_SIZE];
    /** Active unique entry count. */
    size_t active_entries;
    /** Records rejected by the active import. */
    size_t rejected_entries;
    /** Current source health. */
    enum jg_database_blocklist_health health;
    /** Latest bounded update error, empty after success. */
    char last_error[JG_DATABASE_BLOCKLIST_ERROR_MAX + 1U];
};

/**
 * @brief Open, validate, and migrate a persistent database.
 *
 * The path must be absolute. Its parent directory must not be group- or
 * world-writable. New files are created with mode 0600; existing files must
 * already be regular files with that exact mode.
 *
 * @param[in] path Absolute database path.
 * @param[in] busy_timeout_ms Busy timeout from 1 through
 * JG_DATABASE_BUSY_TIMEOUT_MAX.
 * @param[out] database Receives the owned connection.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -EACCES for insecure ownership, permissions, or access.
 * @return -EILSEQ for corrupt persistent data.
 * @return -ENOTSUP for a newer schema version.
 * @return -ENOMEM when allocation fails.
 * @return -EIO for another storage failure.
 *
 * @thread_safety Concurrent opens of different files are safe.
 *
 * @side_effects May create the database, WAL files, a last-known-good backup,
 * and migrated persistent content.
 */
JG_PUBLIC int jg_database_open(const char *path,
                               uint32_t busy_timeout_ms,
                               struct jg_database **database);

/**
 * @brief Close an owned database connection.
 *
 * @param[in,out] database Database to close, or null.
 *
 * @thread_safety The caller must exclude concurrent access.
 */
JG_PUBLIC void jg_database_close(struct jg_database *database);

/**
 * @brief Read the active persistent schema version.
 *
 * @param[in] database Open database.
 * @param[out] version Receives the schema version.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_schema_version(struct jg_database *database,
                                         uint32_t *version);

/**
 * @brief Run SQLite's full integrity check.
 *
 * @param[in] database Open database.
 *
 * @return 0 when SQLite reports a valid database.
 * @return -EINVAL for a null database.
 * @return -EILSEQ when integrity validation fails.
 * @return A negative errno-style value for another SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_check_integrity(struct jg_database *database);

/**
 * @brief Export a consistent SQLite snapshot directly into memory.
 *
 * Configuration snapshots retain appliance settings while excluding users,
 * credentials, sessions, tokens, events, and backup history. Full snapshots
 * retain every database record. No plaintext temporary file is created.
 *
 * @param[in] database Open database.
 * @param[in] include_sensitive Whether to retain authentication and event data.
 * @param[out] data Receives the SQLite snapshot.
 * @param[out] data_size Receives the snapshot size in bytes.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -EILSEQ when SQLite produces an invalid snapshot.
 * @return -EOVERFLOW when the snapshot does not fit in memory address space.
 * @return -ENOMEM when allocation fails.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Allocates @p data, which must be released with
 * jg_database_export_clear().
 */
JG_PUBLIC int jg_database_export(struct jg_database *database,
                                 bool include_sensitive,
                                 uint8_t **data,
                                 size_t *data_size);

/**
 * @brief Securely erase and release an exported database snapshot.
 *
 * @param[in,out] data Snapshot returned by jg_database_export(), or null.
 * @param[in] data_size Snapshot size in bytes.
 */
JG_PUBLIC void jg_database_export_clear(uint8_t *data, size_t data_size);

/**
 * @brief Validate and transactionally restore an in-memory SQLite snapshot.
 *
 * A configuration restore preserves current users, credentials, sessions,
 * tokens and client-certificate mappings. Both modes retain the append-only
 * audit and operational history as well as the current backup catalog, so
 * stored archives remain reachable and restore activity cannot erase evidence.
 * A full restore replaces every other table. Both modes validate schema and
 * integrity, create an in-memory rollback checkpoint, and restore that
 * checkpoint if replacement fails.
 *
 * @param[in] database Open destination database.
 * @param[in] data SQLite replacement snapshot.
 * @param[in] data_size Replacement snapshot bytes.
 * @param[in] include_sensitive Whether to replace sensitive state.
 * @param[in] dry_run Whether to validate and compare without applying.
 * @param[out] report Receives comparison hashes and sizes.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments.
 * @return -EILSEQ when integrity validation fails.
 * @return -ENOTSUP for an incompatible schema version.
 * @return -ENOMEM when allocation fails.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must exclude every concurrent database user.
 *
 * @side_effects Replaces persistent database content unless @p dry_run is
 * true. No plaintext temporary file is created.
 */
JG_PUBLIC int jg_database_restore(struct jg_database *database,
                                  const uint8_t *data,
                                  size_t data_size,
                                  bool include_sensitive,
                                  bool dry_run,
                                  struct jg_database_restore_report *report);

/**
 * @brief Record one successfully stored backup archive.
 *
 * @param[in] database Open database.
 * @param[in] backup Validated metadata with a zero identifier.
 * @param[out] created Receives metadata with its assigned identifier.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments or metadata.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Inserts one backup metadata record.
 */
JG_PUBLIC int jg_database_create_backup(struct jg_database *database,
                                        const struct jg_database_backup *backup,
                                        struct jg_database_backup *created);

/**
 * @brief Load one backup metadata record by identifier.
 *
 * @param[in] database Open database.
 * @param[in] backup_id Positive persistent identifier.
 * @param[out] backup Receives the self-contained metadata.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments.
 * @return -ENOENT when the identifier does not exist.
 * @return -EILSEQ for invalid persistent content.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_load_backup(struct jg_database *database,
                                      uint64_t backup_id,
                                      struct jg_database_backup *backup);

/**
 * @brief Read one stable identifier-ordered page of backup metadata.
 *
 * @param[in] database Open database.
 * @param[in] after_id Exclusive identifier cursor, or zero.
 * @param[in] limit Page size from one through JG_DATABASE_BACKUP_PAGE_MAX.
 * @param[out] backups Array with room for at least @p limit records.
 * @param[out] count Number of records written.
 * @param[out] has_more Whether another record follows the page.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments.
 * @return -EILSEQ for invalid persistent content.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_list_backups(struct jg_database *database,
                                       uint64_t after_id,
                                       size_t limit,
                                       struct jg_database_backup *backups,
                                       size_t *count,
                                       bool *has_more);

/**
 * @brief Atomically persist the complete inline-network configuration.
 *
 * The validated, versioned wire representation is stored as canonical
 * lowercase hexadecimal text in the settings table.
 *
 * @param[in] database Open database.
 * @param[in] config Network configuration to validate and persist.
 *
 * @return 0 on success.
 * @return -EINVAL or -ERANGE for invalid arguments or configuration.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Inserts or replaces one persistent setting atomically.
 */
JG_PUBLIC int jg_database_store_network_config(
    struct jg_database *database,
    const struct jg_network_config *config);

/**
 * @brief Load and validate the persistent inline-network configuration.
 *
 * @param[in] database Open database.
 * @param[out] config Receives the complete validated configuration.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -ENOENT when setup has not stored a network configuration.
 * @return -EILSEQ when the persistent representation is not canonical.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_load_network_config(struct jg_database *database,
                                              struct jg_network_config *config);

/**
 * @brief Load a network configuration with concurrency metadata.
 *
 * @param[in] database Open database.
 * @param[out] record Receives the validated configuration and metadata.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -ENOENT when setup has not stored a network configuration.
 * @return -EILSEQ when persistent data is malformed.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_load_network_config_record(
    struct jg_database *database,
    struct jg_database_network_config *record);

/**
 * @brief Replace a network configuration at its expected revision.
 *
 * @param[in] database Open database.
 * @param[in] config Complete validated replacement configuration.
 * @param[in] expected_revision Revision observed by the caller.
 * @param[out] updated Receives the replacement and advanced revision.
 *
 * @return 0 on success.
 * @return -EINVAL or -ERANGE for invalid input.
 * @return -ENOENT when no configuration has been stored.
 * @return -EAGAIN when the persistent revision has changed.
 * @return -EOVERFLOW when the revision cannot advance.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Replaces the configuration and advances its revision
 * atomically.
 */
JG_PUBLIC int jg_database_replace_network_config(
    struct jg_database *database,
    const struct jg_network_config *config,
    uint64_t expected_revision,
    struct jg_database_network_config *updated);

/**
 * @brief Load persistent logging configuration and concurrency metadata.
 *
 * @param[in] database Open database.
 * @param[out] record Receives validated configuration and metadata.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -ENOENT when the configuration is absent.
 * @return -EILSEQ when persistent data is malformed.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_load_logging_config(
    struct jg_database *database,
    struct jg_database_logging_config *record);

/**
 * @brief Replace logging configuration at its expected revision.
 *
 * @param[in] database Open database.
 * @param[in] config Complete validated replacement configuration.
 * @param[in] expected_revision Revision observed by the caller.
 * @param[out] updated Receives the replacement and advanced revision.
 *
 * @return 0 on success.
 * @return -EINVAL or -ERANGE for invalid input.
 * @return -ENOENT when the configuration is absent.
 * @return -EAGAIN when the persistent revision has changed.
 * @return -EOVERFLOW when the revision cannot advance.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Replaces the configuration and advances its revision
 * atomically.
 */
JG_PUBLIC int jg_database_replace_logging_config(
    struct jg_database *database,
    const struct jg_logging_config *config,
    uint64_t expected_revision,
    struct jg_database_logging_config *updated);

/**
 * @brief Atomically persist blocked UDP DNS response policy.
 *
 * @param[in] database Open database.
 * @param[in] config Response policy to validate and persist.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or configuration.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_store_dns_response_config(
    struct jg_database *database,
    const struct jg_dns_response_config *config);

/**
 * @brief Load persistent blocked UDP DNS response policy.
 *
 * @param[in] database Open database.
 * @param[out] config Receives the validated response policy.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -ENOENT when no response policy has been stored.
 * @return -EILSEQ when persistent content is not canonical.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_load_dns_response_config(
    struct jg_database *database,
    struct jg_dns_response_config *config);

/**
 * @brief Atomically replace every active persistent domain rule.
 *
 * All inputs are validated before the write transaction begins. Domains are
 * stored in normalized IDNA2008 A-label form. A failed validation or write
 * leaves the preceding rule set unchanged.
 *
 * @param[in] database Open database.
 * @param[in] rules Rules to persist, or null when @p rule_count is zero.
 * @param[in] rule_count Number of input rules, bounded by
 * JG_DATABASE_POLICY_RULE_LIMIT.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or rule content.
 * @return -EOVERFLOW for unsupported identifiers or packed sizes.
 * @return -ENOMEM when allocation fails.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Replaces the complete active `domain_rules` table in one
 * transaction.
 */
JG_PUBLIC int jg_database_replace_domain_rules(
    struct jg_database *database,
    const struct jg_policy_rule_input *rules,
    size_t rule_count);

/**
 * @brief Create one persistent domain rule with an assigned identifier.
 *
 * The input identifier must be zero. The returned record contains revision
 * one and the normalized domain.
 *
 * @param[in] database Open database.
 * @param[in] rule Domain rule whose identifier is zero.
 * @param[in] enabled Whether the rule participates in active policy.
 * @param[out] created Created self-contained record.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or rule content.
 * @return -ENOMEM when validation allocation fails.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Inserts one persistent domain rule atomically.
 */
JG_PUBLIC int jg_database_create_domain_rule(
    struct jg_database *database,
    const struct jg_policy_rule_input *rule,
    bool enabled,
    struct jg_database_domain_rule *created);

/**
 * @brief Replace one domain rule at its expected revision.
 *
 * @param[in] database Open database.
 * @param[in] rule Complete replacement with the persistent identifier.
 * @param[in] enabled Whether the rule participates in active policy.
 * @param[in] expected_revision Revision observed by the caller.
 * @param[out] updated Updated self-contained record.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or rule content.
 * @return -ENOENT when the identifier does not exist.
 * @return -EAGAIN when the persistent revision has changed.
 * @return -EOVERFLOW when the revision cannot advance.
 * @return A negative errno-style value for another failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Replaces one rule and increments its revision atomically.
 */
JG_PUBLIC int jg_database_update_domain_rule(
    struct jg_database *database,
    const struct jg_policy_rule_input *rule,
    bool enabled,
    uint64_t expected_revision,
    struct jg_database_domain_rule *updated);

/**
 * @brief Delete one domain rule at its expected revision.
 *
 * @param[in] database Open database.
 * @param[in] rule_id Persistent positive identifier.
 * @param[in] expected_revision Revision observed by the caller.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -ENOENT when the identifier does not exist.
 * @return -EAGAIN when the persistent revision has changed.
 * @return A negative errno-style value for another failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Deletes one persistent rule atomically.
 */
JG_PUBLIC int jg_database_delete_domain_rule(struct jg_database *database,
                                             uint64_t rule_id,
                                             uint64_t expected_revision);

/**
 * @brief Atomically replace every active persistent destination rule.
 *
 * @param[in] database Open database.
 * @param[in] rules Rules to persist, or null when @p rule_count is zero.
 * @param[in] rule_count Number of input rules, bounded by
 * JG_DATABASE_POLICY_RULE_LIMIT.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or rule content.
 * @return -EOVERFLOW for unsupported identifiers or packed sizes.
 * @return -ENOMEM when allocation fails.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Replaces the complete active `destination_rules` table in one
 * transaction.
 */
JG_PUBLIC int jg_database_replace_destination_rules(
    struct jg_database *database,
    const struct jg_policy_destination_rule_input *rules,
    size_t rule_count);

/**
 * @brief Create one destination rule with an assigned identifier.
 *
 * The input identifier must be zero. The returned record contains revision
 * one and a canonical network prefix.
 *
 * @param[in] database Open database.
 * @param[in] rule Destination rule whose identifier is zero.
 * @param[in] enabled Whether the rule participates in active policy.
 * @param[out] created Created self-contained record.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or rule content.
 * @return -ENOMEM when validation allocation fails.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Inserts one persistent destination rule atomically.
 */
JG_PUBLIC int jg_database_create_destination_rule(
    struct jg_database *database,
    const struct jg_policy_destination_rule_input *rule,
    bool enabled,
    struct jg_database_destination_rule *created);

/**
 * @brief Replace one destination rule at its expected revision.
 *
 * @param[in] database Open database.
 * @param[in] rule Complete replacement with the persistent identifier.
 * @param[in] enabled Whether the rule participates in active policy.
 * @param[in] expected_revision Revision observed by the caller.
 * @param[out] updated Updated self-contained record.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or rule content.
 * @return -ENOENT when the identifier does not exist.
 * @return -EAGAIN when the persistent revision has changed.
 * @return -EOVERFLOW when the revision cannot advance.
 * @return A negative errno-style value for another failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Replaces one rule and increments its revision atomically.
 */
JG_PUBLIC int jg_database_update_destination_rule(
    struct jg_database *database,
    const struct jg_policy_destination_rule_input *rule,
    bool enabled,
    uint64_t expected_revision,
    struct jg_database_destination_rule *updated);

/**
 * @brief Delete one destination rule at its expected revision.
 *
 * @param[in] database Open database.
 * @param[in] rule_id Persistent positive identifier.
 * @param[in] expected_revision Revision observed by the caller.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -ENOENT when the identifier does not exist.
 * @return -EAGAIN when the persistent revision has changed.
 * @return A negative errno-style value for another failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Deletes one persistent rule atomically.
 */
JG_PUBLIC int jg_database_delete_destination_rule(struct jg_database *database,
                                                  uint64_t rule_id,
                                                  uint64_t expected_revision);

/**
 * @brief Create one persistent blocklist source.
 *
 * An empty update-state record is created in the same transaction. The
 * returned source has revision one and unknown health.
 *
 * @param[in] database Open database.
 * @param[in] config Complete validated source configuration.
 * @param[out] created Created self-contained source and state.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments, bounds, or relationships.
 * @return -EILSEQ for invalid UTF-8 administrative text.
 * @return -EEXIST when the source name is already used.
 * @return A negative errno-style value for another failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Inserts one source and its update state atomically.
 */
JG_PUBLIC int jg_database_create_blocklist_source(
    struct jg_database *database,
    const struct jg_database_blocklist_source_config *config,
    struct jg_database_blocklist_source *created);

/**
 * @brief Replace one blocklist source at its expected revision.
 *
 * Operational update state and active last-known-good entries are preserved.
 *
 * @param[in] database Open database.
 * @param[in] source_id Persistent positive source identifier.
 * @param[in] config Complete replacement configuration.
 * @param[in] expected_revision Revision observed by the caller.
 * @param[out] updated Updated self-contained source and state.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments, bounds, or relationships.
 * @return -EILSEQ for invalid UTF-8 administrative text.
 * @return -EEXIST when another source already uses the requested name.
 * @return -ENOENT when the identifier does not exist.
 * @return -EAGAIN when the persistent revision has changed.
 * @return -EOVERFLOW when the revision cannot advance.
 * @return A negative errno-style value for another failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Replaces one source configuration and advances its revision
 * atomically.
 */
JG_PUBLIC int jg_database_update_blocklist_source(
    struct jg_database *database,
    uint64_t source_id,
    const struct jg_database_blocklist_source_config *config,
    uint64_t expected_revision,
    struct jg_database_blocklist_source *updated);

/**
 * @brief Delete one blocklist source at its expected revision.
 *
 * Associated update state and imported blocklist rules are removed through
 * referential cascades in the same transaction.
 *
 * @param[in] database Open database.
 * @param[in] source_id Persistent positive source identifier.
 * @param[in] expected_revision Revision observed by the caller.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -ENOENT when the identifier does not exist.
 * @return -EAGAIN when the persistent revision has changed.
 * @return A negative errno-style value for another failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Deletes the source, status, and associated imported rules
 * atomically.
 */
JG_PUBLIC int jg_database_delete_blocklist_source(struct jg_database *database,
                                                  uint64_t source_id,
                                                  uint64_t expected_revision);

/**
 * @brief Atomically activate one completely imported blocklist.
 *
 * Existing entries for the source remain active unless every replacement row
 * and the successful update state can be committed together.
 *
 * @param[in] database Open database.
 * @param[in] source_id Persistent positive source identifier.
 * @param[in] expected_revision Source revision used for the import.
 * @param[in] blocklist Fully validated immutable blocklist.
 * @param[in] state Successful remote scheduling and validator state.
 * @param[in] report Import report associated with @p blocklist.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or inconsistent successful state.
 * @return -ENOENT when the source does not exist.
 * @return -EAGAIN when the source configuration changed during the import.
 * @return -EOVERFLOW when values cannot be represented persistently.
 * @return A negative errno-style value for another failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Replaces the source's domain rules and successful update state
 * in one transaction.
 */
JG_PUBLIC int jg_database_activate_blocklist(
    struct jg_database *database,
    uint64_t source_id,
    uint64_t expected_revision,
    const struct jg_blocklist *blocklist,
    const struct jg_blocklist_remote_state *state,
    const struct jg_blocklist_report *report);

/**
 * @brief Persist a not-modified or failed blocklist update attempt.
 *
 * A successful attempt confirms an existing last-known-good list after HTTP
 * 304. A failed attempt preserves that list and marks the source degraded, or
 * failed when no active list exists.
 *
 * @param[in] database Open database.
 * @param[in] source_id Persistent positive source identifier.
 * @param[in] expected_revision Source revision used for the attempt.
 * @param[in] state Completed remote scheduling and validator state.
 * @param[in] successful Whether the server confirmed the active list.
 * @param[in] error Nonempty failure description, or null on success.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or inconsistent attempt state.
 * @return -ENOENT when success is reported without an active list.
 * @return -ENOENT when the source does not exist.
 * @return -EAGAIN when the source configuration changed during the attempt.
 * @return -EOVERFLOW when timestamps cannot be represented persistently.
 * @return A negative errno-style value for another failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Updates scheduling, validators, health, and the latest error
 * atomically without replacing active entries.
 */
JG_PUBLIC int jg_database_record_blocklist_attempt(
    struct jg_database *database,
    uint64_t source_id,
    uint64_t expected_revision,
    const struct jg_blocklist_remote_state *state,
    bool successful,
    const char *error);

/**
 * @brief Read one stable identifier-ordered page of blocklist sources.
 *
 * Pass the last identifier returned by the preceding page as @p after_id, or
 * zero for the first page. Configuration and latest update state are returned
 * together.
 *
 * @param[in] database Open database.
 * @param[in] after_id Exclusive identifier cursor.
 * @param[in] limit Requested page size from one through
 * JG_DATABASE_POLICY_PAGE_MAX.
 * @param[out] sources Array with room for at least @p limit records.
 * @param[out] count Number of records written to @p sources.
 * @param[out] has_more Whether another record follows this page.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -EILSEQ for invalid persistent content.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_list_blocklist_sources(
    struct jg_database *database,
    uint64_t after_id,
    size_t limit,
    struct jg_database_blocklist_source *sources,
    size_t *count,
    bool *has_more);

/**
 * @brief Read one stable identifier-ordered page of persistent domain rules.
 *
 * Pass the last identifier returned by the preceding page as @p after_id, or
 * zero for the first page. Disabled rules are included.
 *
 * @param[in] database Open database.
 * @param[in] after_id Exclusive identifier cursor.
 * @param[in] limit Requested page size from one through
 * JG_DATABASE_POLICY_PAGE_MAX.
 * @param[out] rules Array with room for at least @p limit records.
 * @param[out] count Number of records written to @p rules.
 * @param[out] has_more Whether another record follows this page.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -EILSEQ for invalid persistent content.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_list_domain_rules(
    struct jg_database *database,
    uint64_t after_id,
    size_t limit,
    struct jg_database_domain_rule *rules,
    size_t *count,
    bool *has_more);

/**
 * @brief Read one stable identifier-ordered page of destination rules.
 *
 * Pass the last identifier returned by the preceding page as @p after_id, or
 * zero for the first page. Disabled rules are included.
 *
 * @param[in] database Open database.
 * @param[in] after_id Exclusive identifier cursor.
 * @param[in] limit Requested page size from one through
 * JG_DATABASE_POLICY_PAGE_MAX.
 * @param[out] rules Array with room for at least @p limit records.
 * @param[out] count Number of records written to @p rules.
 * @param[out] has_more Whether another record follows this page.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -EILSEQ for invalid persistent content.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_list_destination_rules(
    struct jg_database *database,
    uint64_t after_id,
    size_t limit,
    struct jg_database_destination_rule *rules,
    size_t *count,
    bool *has_more);

/**
 * @brief Load active rules into a new immutable policy snapshot.
 *
 * A read transaction copies a single consistent database view before the
 * snapshot is constructed.
 *
 * @param[in] database Open database.
 * @param[in] generation Nonzero generation assigned to the new snapshot.
 * @param[out] snapshot Receives the owned immutable snapshot.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument or zero generation.
 * @return -EOVERFLOW when stored data exceeds configured limits.
 * @return -ENOMEM when allocation fails.
 * @return -EILSEQ for invalid stored rule data.
 * @return A negative errno-style value for a SQLite failure.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Initializes policy hashing and obtains random bytes through
 * the snapshot builder.
 */
JG_PUBLIC int jg_database_load_policy_snapshot(
    struct jg_database *database,
    uint64_t generation,
    struct jg_policy_snapshot **snapshot);

#endif
