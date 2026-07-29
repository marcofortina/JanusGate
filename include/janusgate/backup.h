/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file backup.h
 * @brief Versioned configuration and encrypted full-backup archives.
 */

#ifndef JANUSGATE_BACKUP_H
#define JANUSGATE_BACKUP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Current backup archive format version. */
#define JG_BACKUP_FORMAT_VERSION 1U

/** Maximum combined uncompressed backup payload. */
#define JG_BACKUP_PAYLOAD_MAX (256U * 1024U * 1024U)

/** Minimum full-backup passphrase bytes. */
#define JG_BACKUP_PASSPHRASE_MIN 8U

/** Maximum full-backup passphrase bytes. */
#define JG_BACKUP_PASSPHRASE_MAX 1024U

/** Default private backup archive directory. */
#define JG_BACKUP_DEFAULT_DIRECTORY "/var/lib/janusgate/backups"

/** Maximum backup filename bytes excluding the terminator. */
#define JG_BACKUP_FILENAME_MAX 128U

/** Backup archive content class. */
enum jg_backup_kind {
    /** Appliance configuration without authentication secrets. */
    JG_BACKUP_CONFIGURATION = 1,
    /** Complete sensitive state protected by authenticated encryption. */
    JG_BACKUP_FULL = 2
};

/** Validated public backup manifest. */
struct jg_backup_info {
    /** Configuration or encrypted full backup. */
    enum jg_backup_kind kind;
    /** Archive format version. */
    uint16_t format_version;
    /** Oldest archive reader version accepted by the writer. */
    uint16_t compatible_version_min;
    /** Newest archive reader version accepted by the writer. */
    uint16_t compatible_version_max;
    /** Source database schema version. */
    uint32_t schema_version;
    /** Archive creation time as Unix seconds. */
    uint64_t created_at;
    /** Embedded SQLite snapshot bytes. */
    size_t database_size;
    /** Embedded certificate PEM bytes. */
    size_t certificate_size;
    /** Complete archive bytes. */
    size_t archive_size;
    /** SHA-256 checksum over the manifest and stored payload. */
    uint8_t checksum[32U];
    /** Whether the stored payload uses authenticated encryption. */
    bool encrypted;
};

/**
 * @brief Opened backup contents owned as one contiguous allocation.
 *
 * @ref certificate points inside the allocation beginning at @ref database.
 * Release both views with jg_backup_contents_clear().
 */
struct jg_backup_contents {
    /** Validated archive manifest. */
    struct jg_backup_info info;
    /** Owned SQLite snapshot. */
    uint8_t *database;
    /** SQLite snapshot bytes. */
    size_t database_size;
    /** Certificate PEM view, or null when absent. */
    uint8_t *certificate;
    /** Certificate PEM bytes. */
    size_t certificate_size;
};

/**
 * @brief Create a versioned configuration or encrypted full-backup archive.
 *
 * Configuration backups require no passphrase. Full backups require an
 * explicit passphrase and protect the complete payload with Argon2id and
 * XChaCha20-Poly1305. All processing occurs in memory.
 *
 * @param[in] kind Backup content class.
 * @param[in] database SQLite snapshot.
 * @param[in] database_size SQLite snapshot bytes.
 * @param[in] certificate Optional certificate PEM.
 * @param[in] certificate_size Certificate PEM bytes.
 * @param[in] passphrase Full-backup passphrase, otherwise null.
 * @param[in] passphrase_size Passphrase bytes, otherwise zero.
 * @param[in] created_at Creation time as Unix seconds.
 * @param[in] schema_version Source database schema version.
 * @param[out] archive Receives the owned archive.
 * @param[out] archive_size Receives the archive size in bytes.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments.
 * @return -EOVERFLOW when a size exceeds the supported limit.
 * @return -ENOMEM when allocation or key derivation fails.
 * @return -EIO when cryptographic initialization fails.
 *
 * @thread_safety This function is reentrant after process initialization.
 *
 * @side_effects Allocates @p archive, which must be released with
 * jg_backup_data_clear().
 */
JG_PUBLIC int jg_backup_create(enum jg_backup_kind kind,
                               const uint8_t *database,
                               size_t database_size,
                               const uint8_t *certificate,
                               size_t certificate_size,
                               const char *passphrase,
                               size_t passphrase_size,
                               uint64_t created_at,
                               uint32_t schema_version,
                               uint8_t **archive,
                               size_t *archive_size);

/**
 * @brief Validate and inspect a backup archive without opening its payload.
 *
 * @param[in] archive Complete archive.
 * @param[in] archive_size Archive bytes.
 * @param[out] info Receives the validated public manifest.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -EILSEQ for malformed structure.
 * @return -EBADMSG for a checksum mismatch.
 * @return -ENOTSUP for an incompatible format.
 * @return -EOVERFLOW for an unsupported archive size.
 *
 * @thread_safety This function is reentrant after process initialization.
 */
JG_PUBLIC int jg_backup_inspect(const uint8_t *archive,
                                size_t archive_size,
                                struct jg_backup_info *info);

/**
 * @brief Validate, authenticate, and open a backup archive in memory.
 *
 * Configuration archives require no passphrase. Full archives require the
 * original passphrase.
 *
 * @param[in] archive Complete archive.
 * @param[in] archive_size Archive bytes.
 * @param[in] passphrase Full-backup passphrase, otherwise null.
 * @param[in] passphrase_size Passphrase bytes, otherwise zero.
 * @param[out] contents Receives owned plaintext contents.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments.
 * @return -EACCES for an incorrect full-backup passphrase.
 * @return -EILSEQ for malformed structure.
 * @return -EBADMSG for a checksum mismatch.
 * @return -ENOTSUP for an incompatible format.
 * @return -EOVERFLOW for an unsupported archive size.
 * @return -ENOMEM when allocation or key derivation fails.
 *
 * @thread_safety This function is reentrant after process initialization.
 *
 * @side_effects Allocates plaintext memory, which must be released with
 * jg_backup_contents_clear().
 */
JG_PUBLIC int jg_backup_open(const uint8_t *archive,
                             size_t archive_size,
                             const char *passphrase,
                             size_t passphrase_size,
                             struct jg_backup_contents *contents);

/**
 * @brief Atomically store one new archive in a private directory.
 *
 * The directory must be absolute, owned by the effective user, and accessible
 * only by its owner. Existing destinations are never replaced.
 *
 * @param[in] directory Private backup directory.
 * @param[in] filename Plain filename without path separators.
 * @param[in] archive Complete archive.
 * @param[in] archive_size Archive bytes.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments.
 * @return -EACCES for insecure directory or destination metadata.
 * @return -EEXIST when the destination already exists.
 * @return A negative errno-style file error otherwise.
 *
 * @thread_safety Concurrent storage is safe for distinct filenames.
 *
 * @side_effects Creates and synchronizes one mode-0600 regular file.
 */
JG_PUBLIC int jg_backup_store(const char *directory,
                              const char *filename,
                              const uint8_t *archive,
                              size_t archive_size);

/**
 * @brief Load one securely stored archive into memory.
 *
 * @param[in] directory Private backup directory.
 * @param[in] filename Plain filename without path separators.
 * @param[out] archive Receives the owned archive.
 * @param[out] archive_size Receives the archive size in bytes.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments.
 * @return -EACCES for insecure directory or archive metadata.
 * @return A negative errno-style file or allocation error otherwise.
 *
 * @thread_safety Concurrent loads of immutable archives are safe.
 *
 * @side_effects Allocates @p archive, which must be released with
 * jg_backup_data_clear().
 */
JG_PUBLIC int jg_backup_load(const char *directory,
                             const char *filename,
                             uint8_t **archive,
                             size_t *archive_size);

/**
 * @brief Securely remove one stored backup archive.
 *
 * @param[in] directory Private backup directory.
 * @param[in] filename Plain filename without path separators.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments.
 * @return -EACCES for insecure directory or archive metadata.
 * @return A negative errno-style file error otherwise.
 *
 * @thread_safety Concurrent access to the same filename is unsupported.
 *
 * @side_effects Unlinks and synchronizes one archive directory entry.
 */
JG_PUBLIC int jg_backup_remove(const char *directory, const char *filename);

/**
 * @brief Securely erase and release an archive buffer.
 *
 * @param[in,out] data Owned archive, or null.
 * @param[in] data_size Archive bytes.
 */
JG_PUBLIC void jg_backup_data_clear(uint8_t *data, size_t data_size);

/**
 * @brief Securely erase and release opened backup contents.
 *
 * @param[in,out] contents Opened contents, or null.
 */
JG_PUBLIC void jg_backup_contents_clear(struct jg_backup_contents *contents);

#endif
