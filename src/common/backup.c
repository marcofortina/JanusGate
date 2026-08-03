/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "janusgate/backup.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sodium.h>

#include "janusgate/checked.h"

/** Legacy version-one serialized header bytes. */
#define BACKUP_V1_HEADER_SIZE 144U

/** Version-one header bytes preceding its checksum. */
#define BACKUP_V1_AUTHENTICATED_HEADER_SIZE 112U

/** Current serialized header bytes. */
#define BACKUP_HEADER_SIZE 160U

/** Current header bytes preceding its checksum. */
#define BACKUP_AUTHENTICATED_HEADER_SIZE 128U

/** Encrypted-payload flag. */
#define BACKUP_FLAG_ENCRYPTED 1U

/** Fixed Argon2id operation count. */
#define BACKUP_KDF_OPERATIONS 2U

/** Fixed Argon2id memory cost in bytes. */
#define BACKUP_KDF_MEMORY (64U * 1024U * 1024U)

/** Backup header field offsets. */
enum backup_header_offset {
    BACKUP_OFFSET_MAGIC = 0,
    BACKUP_OFFSET_VERSION = 8,
    BACKUP_OFFSET_HEADER_SIZE = 10,
    BACKUP_OFFSET_KIND = 12,
    BACKUP_OFFSET_FLAGS = 13,
    BACKUP_OFFSET_COMPATIBLE_MIN = 14,
    BACKUP_OFFSET_COMPATIBLE_MAX = 16,
    BACKUP_OFFSET_RESERVED = 18,
    BACKUP_OFFSET_CREATED_AT = 20,
    BACKUP_OFFSET_SCHEMA_VERSION = 28,
    BACKUP_OFFSET_DATABASE_SIZE = 32,
    BACKUP_OFFSET_CERTIFICATE_SIZE = 40,
    BACKUP_OFFSET_PAYLOAD_SIZE = 48,
    BACKUP_OFFSET_KDF_OPERATIONS = 56,
    BACKUP_OFFSET_KDF_MEMORY = 64,
    BACKUP_OFFSET_SALT = 72,
    BACKUP_OFFSET_NONCE = 88,
    BACKUP_OFFSET_TOTP_KEY_SIZE = 112,
    BACKUP_OFFSET_CLIENT_CA_SIZE = 120,
    BACKUP_OFFSET_CHECKSUM = 128
};

/** Decoded physical layout for one supported archive version. */
struct backup_layout {
    size_t header_size;
    size_t authenticated_header_size;
    size_t checksum_offset;
};

/** Exact archive magic. */
static const uint8_t backup_magic[8U] = {'J', 'G', 'B', 'A',
                                         'C', 'K', 'U', 'P'};

/** @brief Write one unsigned 16-bit integer in network byte order. */
static void write_u16(uint8_t *destination, uint16_t value)
{
    destination[0U] = (uint8_t)(value >> 8U);
    destination[1U] = (uint8_t)value;
}

/** @brief Write one unsigned 32-bit integer in network byte order. */
static void write_u32(uint8_t *destination, uint32_t value)
{
    destination[0U] = (uint8_t)(value >> 24U);
    destination[1U] = (uint8_t)(value >> 16U);
    destination[2U] = (uint8_t)(value >> 8U);
    destination[3U] = (uint8_t)value;
}

/** @brief Write one unsigned 64-bit integer in network byte order. */
static void write_u64(uint8_t *destination, uint64_t value)
{
    size_t index = 0U;

    for (index = 0U; index < sizeof(value); ++index) {
        destination[index] =
            (uint8_t)(value >> ((sizeof(value) - index - 1U) * 8U));
    }
}

/** @brief Read one unsigned 16-bit network-order integer. */
static uint16_t read_u16(const uint8_t *source)
{
    return (uint16_t)((uint16_t)source[0U] << 8U) | (uint16_t)source[1U];
}

/** @brief Read one unsigned 32-bit network-order integer. */
static uint32_t read_u32(const uint8_t *source)
{
    return ((uint32_t)source[0U] << 24U) | ((uint32_t)source[1U] << 16U) |
           ((uint32_t)source[2U] << 8U) | (uint32_t)source[3U];
}

/** @brief Read one unsigned 64-bit network-order integer. */
static uint64_t read_u64(const uint8_t *source)
{
    uint64_t value = 0U;
    size_t index = 0U;

    for (index = 0U; index < sizeof(value); ++index) {
        value = (value << 8U) | (uint64_t)source[index];
    }
    return value;
}

/** @brief Initialize libsodium once for backup operations. */
static int initialize_crypto(void)
{
    return sodium_init() < 0 ? -EIO : 0;
}

/** @brief Validate one untrusted backup filename. */
static bool filename_valid(const char *filename)
{
    const size_t length =
        filename == NULL ? 0U : strnlen(filename, JG_BACKUP_FILENAME_MAX + 1U);
    size_t index = 0U;

    if (length == 0U || length > JG_BACKUP_FILENAME_MAX ||
        filename[0U] == '.') {
        return false;
    }
    for (index = 0U; index < length; ++index) {
        const char character = filename[index];
        const bool valid = (character >= 'a' && character <= 'z') ||
                           (character >= 'A' && character <= 'Z') ||
                           (character >= '0' && character <= '9') ||
                           character == '-' || character == '_' ||
                           character == '.';

        if (!valid) {
            return false;
        }
    }
    return true;
}

/** @brief Return whether one name is an exact private staging filename. */
static bool staging_filename(const char *filename)
{
    static const char prefix[] = ".janusgate-";
    const size_t prefix_size = sizeof(prefix) - 1U;

    if (filename == NULL || strlen(filename) != prefix_size + 16U ||
        memcmp(filename, prefix, prefix_size) != 0) {
        return false;
    }
    for (size_t index = prefix_size; filename[index] != '\0'; ++index) {
        if (!((filename[index] >= '0' && filename[index] <= '9') ||
              (filename[index] >= 'a' && filename[index] <= 'f'))) {
            return false;
        }
    }
    return true;
}

/** @brief Return whether one name follows the generated archive convention. */
bool jg_backup_generated_filename_valid(const char *filename)
{
    static const char prefix[] = "backup-";
    static const char suffix[] = ".jgb";
    const size_t length = filename == NULL ? 0U : strlen(filename);
    const size_t prefix_size = sizeof(prefix) - 1U;
    const size_t suffix_size = sizeof(suffix) - 1U;
    const char *separator = NULL;

    if (length <= prefix_size + 1U + 16U + suffix_size ||
        length > JG_BACKUP_FILENAME_MAX ||
        memcmp(filename, prefix, prefix_size) != 0 ||
        memcmp(filename + length - suffix_size, suffix, suffix_size) != 0) {
        return false;
    }
    separator = filename + length - suffix_size - 17U;
    if (*separator != '-') {
        return false;
    }
    for (const char *cursor = filename + prefix_size; cursor < separator;
         ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
    }
    for (const char *cursor = separator + 1U;
         cursor < filename + length - suffix_size; ++cursor) {
        if (!((*cursor >= '0' && *cursor <= '9') ||
              (*cursor >= 'a' && *cursor <= 'f'))) {
            return false;
        }
    }
    return true;
}

/** @brief Open and validate one owner-private backup directory. */
static int open_directory(const char *directory, int *descriptor)
{
    struct stat metadata;
    int opened;

    if (directory == NULL || descriptor == NULL || directory[0U] != '/' ||
        directory[1U] == '\0' || strlen(directory) >= PATH_MAX) {
        return -EINVAL;
    }
    *descriptor = -1;
    opened = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (opened < 0) {
        return -errno;
    }
    if (fstat(opened, &metadata) != 0) {
        const int result = -errno;

        (void)close(opened);
        return result;
    }
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != geteuid() ||
        (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0U) {
        (void)close(opened);
        return -EACCES;
    }
    *descriptor = opened;
    return 0;
}

/** @brief Validate one opened private regular archive file. */
static int validate_archive_file(int descriptor,
                                 struct stat *metadata,
                                 bool require_nonempty)
{
    if (fstat(descriptor, metadata) != 0) {
        return -errno;
    }
    if (!S_ISREG(metadata->st_mode) || metadata->st_uid != geteuid() ||
        (metadata->st_mode & 0777U) != (S_IRUSR | S_IWUSR) ||
        metadata->st_nlink != 1U ||
        (require_nonempty && metadata->st_size <= 0)) {
        return -EACCES;
    }
    return 0;
}

/** @brief Write every byte to one regular file descriptor. */
static int write_all(int descriptor, const uint8_t *data, size_t data_size)
{
    size_t offset = 0U;

    while (offset < data_size) {
        const ssize_t written =
            write(descriptor, data + offset, data_size - offset);

        if (written > 0) {
            offset += (size_t)written;
        } else if (written == 0) {
            return -EIO;
        } else if (errno != EINTR) {
            return -errno;
        }
    }
    return 0;
}

/** @brief Read exactly one bounded regular file. */
static int read_all(int descriptor, uint8_t *data, size_t data_size)
{
    size_t offset = 0U;

    while (offset < data_size) {
        const ssize_t received =
            read(descriptor, data + offset, data_size - offset);

        if (received > 0) {
            offset += (size_t)received;
        } else if (received == 0) {
            return -EIO;
        } else if (errno != EINTR) {
            return -errno;
        }
    }
    return 0;
}

/** @brief Validate a passphrase for the selected backup kind. */
static int validate_passphrase(enum jg_backup_kind kind,
                               const char *passphrase,
                               size_t passphrase_size)
{
    if (kind == JG_BACKUP_CONFIGURATION) {
        return passphrase == NULL && passphrase_size == 0U ? 0 : -EINVAL;
    }
    if (kind != JG_BACKUP_FULL || passphrase == NULL ||
        passphrase_size < JG_BACKUP_PASSPHRASE_MIN ||
        passphrase_size > JG_BACKUP_PASSPHRASE_MAX) {
        return -EINVAL;
    }
    return 0;
}

/** @brief Decode the physical header layout of one supported archive. */
static int decode_layout(const uint8_t *archive,
                         size_t archive_size,
                         struct backup_layout *layout)
{
    uint16_t version = 0U;
    uint16_t header_size = 0U;

    if (archive == NULL || layout == NULL ||
        archive_size < BACKUP_OFFSET_HEADER_SIZE + sizeof(uint16_t)) {
        return -EILSEQ;
    }
    version = read_u16(archive + BACKUP_OFFSET_VERSION);
    header_size = read_u16(archive + BACKUP_OFFSET_HEADER_SIZE);
    if (version == 1U && header_size == BACKUP_V1_HEADER_SIZE) {
        layout->header_size = BACKUP_V1_HEADER_SIZE;
        layout->authenticated_header_size = BACKUP_V1_AUTHENTICATED_HEADER_SIZE;
        layout->checksum_offset = BACKUP_V1_AUTHENTICATED_HEADER_SIZE;
    } else if (version == JG_BACKUP_FORMAT_VERSION &&
               header_size == BACKUP_HEADER_SIZE) {
        layout->header_size = BACKUP_HEADER_SIZE;
        layout->authenticated_header_size = BACKUP_AUTHENTICATED_HEADER_SIZE;
        layout->checksum_offset = BACKUP_OFFSET_CHECKSUM;
    } else if (version == 1U || version == JG_BACKUP_FORMAT_VERSION) {
        return -EILSEQ;
    } else {
        return -ENOTSUP;
    }
    return archive_size >= layout->header_size ? 0 : -EILSEQ;
}

/** @brief Compute the archive checksum without its checksum field. */
static void compute_checksum(const uint8_t *archive,
                             size_t archive_size,
                             const struct backup_layout *layout,
                             uint8_t checksum[crypto_hash_sha256_BYTES])
{
    crypto_hash_sha256_state state;

    (void)crypto_hash_sha256_init(&state);
    (void)crypto_hash_sha256_update(&state, archive,
                                    layout->authenticated_header_size);
    (void)crypto_hash_sha256_update(
        &state, archive + layout->header_size,
        (unsigned long long)(archive_size - layout->header_size));
    (void)crypto_hash_sha256_final(&state, checksum);
}

/** @brief Validate and decode one fixed backup manifest. */
static int parse_manifest(const uint8_t *archive,
                          size_t archive_size,
                          struct jg_backup_info *info,
                          struct backup_layout *layout)
{
    uint64_t encoded_database_size = 0U;
    uint64_t encoded_certificate_size = 0U;
    uint64_t encoded_totp_key_size = 0U;
    uint64_t encoded_client_ca_size = 0U;
    uint64_t encoded_payload_size = 0U;
    uint64_t kdf_operations = 0U;
    uint64_t kdf_memory = 0U;
    size_t expected_plaintext_size = 0U;
    size_t expected_payload_size = 0U;
    size_t expected_archive_size = 0U;
    uint8_t flags = 0U;
    int result = decode_layout(archive, archive_size, layout);

    if (result != 0) {
        return result;
    }
    if (sodium_memcmp(archive + BACKUP_OFFSET_MAGIC, backup_magic,
                      sizeof(backup_magic)) != 0) {
        return -EILSEQ;
    }
    info->format_version = read_u16(archive + BACKUP_OFFSET_VERSION);
    if (read_u16(archive + BACKUP_OFFSET_RESERVED) != 0U) {
        return -EILSEQ;
    }
    info->compatible_version_min =
        read_u16(archive + BACKUP_OFFSET_COMPATIBLE_MIN);
    info->compatible_version_max =
        read_u16(archive + BACKUP_OFFSET_COMPATIBLE_MAX);
    if (info->compatible_version_min == 0U ||
        info->compatible_version_min > info->format_version ||
        info->compatible_version_max < info->format_version ||
        info->format_version > JG_BACKUP_FORMAT_VERSION) {
        return -ENOTSUP;
    }
    info->kind = (enum jg_backup_kind)archive[BACKUP_OFFSET_KIND];
    flags = archive[BACKUP_OFFSET_FLAGS];
    info->encrypted = flags == BACKUP_FLAG_ENCRYPTED;
    if ((info->kind == JG_BACKUP_CONFIGURATION && flags != 0U) ||
        (info->kind == JG_BACKUP_FULL && flags != BACKUP_FLAG_ENCRYPTED) ||
        (info->kind != JG_BACKUP_CONFIGURATION &&
         info->kind != JG_BACKUP_FULL)) {
        return -EILSEQ;
    }
    info->created_at = read_u64(archive + BACKUP_OFFSET_CREATED_AT);
    info->schema_version = read_u32(archive + BACKUP_OFFSET_SCHEMA_VERSION);
    if (info->schema_version == 0U) {
        return -EILSEQ;
    }
    encoded_database_size = read_u64(archive + BACKUP_OFFSET_DATABASE_SIZE);
    encoded_certificate_size =
        read_u64(archive + BACKUP_OFFSET_CERTIFICATE_SIZE);
    if (info->format_version >= 2U) {
        encoded_totp_key_size = read_u64(archive + BACKUP_OFFSET_TOTP_KEY_SIZE);
        encoded_client_ca_size =
            read_u64(archive + BACKUP_OFFSET_CLIENT_CA_SIZE);
    }
    encoded_payload_size = read_u64(archive + BACKUP_OFFSET_PAYLOAD_SIZE);
    if (encoded_database_size == 0U ||
        encoded_database_size > JG_BACKUP_PAYLOAD_MAX ||
        encoded_certificate_size > JG_BACKUP_PAYLOAD_MAX ||
        encoded_totp_key_size > JG_BACKUP_PAYLOAD_MAX ||
        encoded_client_ca_size > JG_BACKUP_PAYLOAD_MAX ||
        encoded_database_size > SIZE_MAX ||
        encoded_certificate_size > SIZE_MAX ||
        encoded_totp_key_size > SIZE_MAX || encoded_client_ca_size > SIZE_MAX) {
        return -EOVERFLOW;
    }
    if ((info->kind == JG_BACKUP_CONFIGURATION &&
         (encoded_totp_key_size != 0U || encoded_client_ca_size != 0U)) ||
        (info->kind == JG_BACKUP_FULL && info->format_version >= 2U &&
         encoded_totp_key_size != JG_AUTH_TOTP_KEY_SIZE)) {
        return -EILSEQ;
    }
    if (!jg_size_add((size_t)encoded_database_size,
                     (size_t)encoded_certificate_size,
                     &expected_plaintext_size) ||
        !jg_size_add(expected_plaintext_size, (size_t)encoded_totp_key_size,
                     &expected_plaintext_size) ||
        !jg_size_add(expected_plaintext_size, (size_t)encoded_client_ca_size,
                     &expected_plaintext_size) ||
        expected_plaintext_size > JG_BACKUP_PAYLOAD_MAX) {
        return -EOVERFLOW;
    }
    expected_payload_size = expected_plaintext_size;
    if (info->encrypted &&
        !jg_size_add(expected_payload_size,
                     crypto_aead_xchacha20poly1305_ietf_ABYTES,
                     &expected_payload_size)) {
        return -EOVERFLOW;
    }
    if (encoded_payload_size != (uint64_t)expected_payload_size ||
        !jg_size_add(layout->header_size, expected_payload_size,
                     &expected_archive_size) ||
        expected_archive_size != archive_size) {
        return -EILSEQ;
    }
    kdf_operations = read_u64(archive + BACKUP_OFFSET_KDF_OPERATIONS);
    kdf_memory = read_u64(archive + BACKUP_OFFSET_KDF_MEMORY);
    if ((!info->encrypted && (kdf_operations != 0U || kdf_memory != 0U)) ||
        (info->encrypted && (kdf_operations != BACKUP_KDF_OPERATIONS ||
                             kdf_memory != BACKUP_KDF_MEMORY))) {
        return -EILSEQ;
    }
    if (!info->encrypted &&
        (!sodium_is_zero(archive + BACKUP_OFFSET_SALT,
                         crypto_pwhash_SALTBYTES) ||
         !sodium_is_zero(archive + BACKUP_OFFSET_NONCE,
                         crypto_aead_xchacha20poly1305_ietf_NPUBBYTES))) {
        return -EILSEQ;
    }
    info->database_size = (size_t)encoded_database_size;
    info->certificate_size = (size_t)encoded_certificate_size;
    info->totp_key_size = (size_t)encoded_totp_key_size;
    info->client_ca_size = (size_t)encoded_client_ca_size;
    info->archive_size = archive_size;
    info->portable = info->kind == JG_BACKUP_FULL &&
                     info->format_version >= 2U &&
                     info->totp_key_size == JG_AUTH_TOTP_KEY_SIZE;
    (void)memcpy(info->checksum, archive + layout->checksum_offset,
                 sizeof(info->checksum));
    return 0;
}

/** @brief Create a versioned configuration or encrypted full archive. */
int jg_backup_create(enum jg_backup_kind kind,
                     const struct jg_backup_payload *payload,
                     const char *passphrase,
                     size_t passphrase_size,
                     uint64_t created_at,
                     uint32_t schema_version,
                     uint8_t **archive,
                     size_t *archive_size)
{
    uint8_t salt[crypto_pwhash_SALTBYTES] = {0U};
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {0U};
    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES] = {0U};
    uint8_t *plaintext = NULL;
    size_t plaintext_size = 0U;
    size_t payload_size = 0U;
    size_t total_size = 0U;
    size_t offset = 0U;
    unsigned long long encrypted_size = 0U;
    int result;

    if (archive == NULL || archive_size == NULL || payload == NULL) {
        return -EINVAL;
    }
    *archive = NULL;
    *archive_size = 0U;
    result = validate_passphrase(kind, passphrase, passphrase_size);
    if (result != 0 || payload->database == NULL ||
        payload->database_size == 0U ||
        (payload->certificate == NULL) != (payload->certificate_size == 0U) ||
        (payload->totp_key == NULL) != (payload->totp_key_size == 0U) ||
        (payload->client_ca == NULL) != (payload->client_ca_size == 0U) ||
        (kind == JG_BACKUP_CONFIGURATION &&
         (payload->totp_key_size != 0U || payload->client_ca_size != 0U)) ||
        (kind == JG_BACKUP_FULL &&
         payload->totp_key_size != JG_AUTH_TOTP_KEY_SIZE) ||
        schema_version == 0U) {
        return -EINVAL;
    }
    if (!jg_size_add(payload->database_size, payload->certificate_size,
                     &plaintext_size) ||
        !jg_size_add(plaintext_size, payload->totp_key_size, &plaintext_size) ||
        !jg_size_add(plaintext_size, payload->client_ca_size,
                     &plaintext_size) ||
        plaintext_size > JG_BACKUP_PAYLOAD_MAX) {
        return -EOVERFLOW;
    }
    payload_size = plaintext_size;
    if (kind == JG_BACKUP_FULL &&
        !jg_size_add(payload_size, crypto_aead_xchacha20poly1305_ietf_ABYTES,
                     &payload_size)) {
        return -EOVERFLOW;
    }
    if (!jg_size_add(BACKUP_HEADER_SIZE, payload_size, &total_size)) {
        return -EOVERFLOW;
    }
    result = initialize_crypto();
    if (result != 0) {
        return result;
    }
    *archive = calloc(1U, total_size);
    if (*archive == NULL) {
        return -ENOMEM;
    }
    (void)memcpy(*archive + BACKUP_OFFSET_MAGIC, backup_magic,
                 sizeof(backup_magic));
    write_u16(*archive + BACKUP_OFFSET_VERSION, JG_BACKUP_FORMAT_VERSION);
    write_u16(*archive + BACKUP_OFFSET_HEADER_SIZE, BACKUP_HEADER_SIZE);
    (*archive)[BACKUP_OFFSET_KIND] = (uint8_t)kind;
    (*archive)[BACKUP_OFFSET_FLAGS] =
        kind == JG_BACKUP_FULL ? BACKUP_FLAG_ENCRYPTED : 0U;
    write_u16(*archive + BACKUP_OFFSET_COMPATIBLE_MIN,
              JG_BACKUP_FORMAT_VERSION);
    write_u16(*archive + BACKUP_OFFSET_COMPATIBLE_MAX,
              JG_BACKUP_FORMAT_VERSION);
    write_u64(*archive + BACKUP_OFFSET_CREATED_AT, created_at);
    write_u32(*archive + BACKUP_OFFSET_SCHEMA_VERSION, schema_version);
    write_u64(*archive + BACKUP_OFFSET_DATABASE_SIZE, payload->database_size);
    write_u64(*archive + BACKUP_OFFSET_CERTIFICATE_SIZE,
              payload->certificate_size);
    write_u64(*archive + BACKUP_OFFSET_PAYLOAD_SIZE, payload_size);
    write_u64(*archive + BACKUP_OFFSET_TOTP_KEY_SIZE, payload->totp_key_size);
    write_u64(*archive + BACKUP_OFFSET_CLIENT_CA_SIZE, payload->client_ca_size);

    if (kind == JG_BACKUP_CONFIGURATION) {
        (void)memcpy(*archive + BACKUP_HEADER_SIZE, payload->database,
                     payload->database_size);
        if (payload->certificate_size > 0U) {
            (void)memcpy(*archive + BACKUP_HEADER_SIZE + payload->database_size,
                         payload->certificate, payload->certificate_size);
        }
    } else {
        write_u64(*archive + BACKUP_OFFSET_KDF_OPERATIONS,
                  BACKUP_KDF_OPERATIONS);
        write_u64(*archive + BACKUP_OFFSET_KDF_MEMORY, BACKUP_KDF_MEMORY);
        randombytes_buf(salt, sizeof(salt));
        randombytes_buf(nonce, sizeof(nonce));
        (void)memcpy(*archive + BACKUP_OFFSET_SALT, salt, sizeof(salt));
        (void)memcpy(*archive + BACKUP_OFFSET_NONCE, nonce, sizeof(nonce));
        plaintext = malloc(plaintext_size);
        if (plaintext == NULL) {
            result = -ENOMEM;
        }
        if (result == 0) {
            (void)memcpy(plaintext, payload->database, payload->database_size);
            offset = payload->database_size;
            if (payload->certificate_size > 0U) {
                (void)memcpy(plaintext + offset, payload->certificate,
                             payload->certificate_size);
                offset += payload->certificate_size;
            }
            (void)memcpy(plaintext + offset, payload->totp_key,
                         payload->totp_key_size);
            offset += payload->totp_key_size;
            if (payload->client_ca_size > 0U) {
                (void)memcpy(plaintext + offset, payload->client_ca,
                             payload->client_ca_size);
            }
            if (crypto_pwhash(key, sizeof(key), passphrase,
                              (unsigned long long)passphrase_size, salt,
                              BACKUP_KDF_OPERATIONS, BACKUP_KDF_MEMORY,
                              crypto_pwhash_ALG_ARGON2ID13) != 0) {
                result = -ENOMEM;
            }
        }
        if (result == 0 &&
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                *archive + BACKUP_HEADER_SIZE, &encrypted_size, plaintext,
                (unsigned long long)plaintext_size, *archive,
                BACKUP_AUTHENTICATED_HEADER_SIZE, NULL, nonce, key) != 0) {
            result = -EIO;
        }
        if (result == 0 && encrypted_size != payload_size) {
            result = -EIO;
        }
    }
    if (result == 0) {
        const struct backup_layout layout = {
            .header_size = BACKUP_HEADER_SIZE,
            .authenticated_header_size = BACKUP_AUTHENTICATED_HEADER_SIZE,
            .checksum_offset = BACKUP_OFFSET_CHECKSUM,
        };

        compute_checksum(*archive, total_size, &layout,
                         *archive + BACKUP_OFFSET_CHECKSUM);
        *archive_size = total_size;
    } else {
        jg_backup_data_clear(*archive, total_size);
        *archive = NULL;
    }
    if (plaintext != NULL) {
        sodium_memzero(plaintext, plaintext_size);
        free(plaintext);
    }
    sodium_memzero(key, sizeof(key));
    sodium_memzero(salt, sizeof(salt));
    sodium_memzero(nonce, sizeof(nonce));
    return result;
}

/** @brief Validate and inspect one backup manifest and checksum. */
int jg_backup_inspect(const uint8_t *archive,
                      size_t archive_size,
                      struct jg_backup_info *info)
{
    struct backup_layout layout;
    int result;

    if (archive == NULL || info == NULL) {
        return -EINVAL;
    }
    (void)memset(info, 0, sizeof(*info));
    result = initialize_crypto();
    if (result == 0) {
        result = parse_manifest(archive, archive_size, info, &layout);
    }
    if (result == 0) {
        uint8_t checksum[crypto_hash_sha256_BYTES];

        compute_checksum(archive, archive_size, &layout, checksum);
        if (sodium_memcmp(checksum, info->checksum, sizeof(checksum)) != 0) {
            result = -EBADMSG;
        }
        sodium_memzero(checksum, sizeof(checksum));
    }
    if (result != 0) {
        (void)memset(info, 0, sizeof(*info));
    }
    return result;
}

/** @brief Validate, authenticate, and open one backup payload. */
int jg_backup_open(const uint8_t *archive,
                   size_t archive_size,
                   const char *passphrase,
                   size_t passphrase_size,
                   struct jg_backup_contents *contents)
{
    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES] = {0U};
    struct backup_layout layout;
    const uint8_t *salt = NULL;
    const uint8_t *nonce = NULL;
    size_t plaintext_size = 0U;
    unsigned long long decrypted_size = 0U;
    int result;

    if (archive == NULL || contents == NULL) {
        return -EINVAL;
    }
    (void)memset(contents, 0, sizeof(*contents));
    result = jg_backup_inspect(archive, archive_size, &contents->info);
    if (result == 0) {
        result = decode_layout(archive, archive_size, &layout);
    }
    if (result == 0) {
        result = validate_passphrase(contents->info.kind, passphrase,
                                     passphrase_size);
    }
    if (result == 0 &&
        !jg_size_add(contents->info.database_size,
                     contents->info.certificate_size, &plaintext_size)) {
        result = -EOVERFLOW;
    }
    if (result == 0 &&
        (!jg_size_add(plaintext_size, contents->info.totp_key_size,
                      &plaintext_size) ||
         !jg_size_add(plaintext_size, contents->info.client_ca_size,
                      &plaintext_size))) {
        result = -EOVERFLOW;
    }
    if (result == 0) {
        contents->database_size = contents->info.database_size;
        contents->certificate_size = contents->info.certificate_size;
        contents->totp_key_size = contents->info.totp_key_size;
        contents->client_ca_size = contents->info.client_ca_size;
        salt = archive + BACKUP_OFFSET_SALT;
        nonce = archive + BACKUP_OFFSET_NONCE;
        contents->database = malloc(plaintext_size);
        if (contents->database == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0 && !contents->info.encrypted) {
        (void)memcpy(contents->database, archive + layout.header_size,
                     plaintext_size);
    }
    if (result == 0 && contents->info.encrypted) {
        if (crypto_pwhash(key, sizeof(key), passphrase,
                          (unsigned long long)passphrase_size, salt,
                          BACKUP_KDF_OPERATIONS, BACKUP_KDF_MEMORY,
                          crypto_pwhash_ALG_ARGON2ID13) != 0) {
            result = -ENOMEM;
        }
        if (result == 0 &&
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                contents->database, &decrypted_size, NULL,
                archive + layout.header_size,
                (unsigned long long)(archive_size - layout.header_size),
                archive, layout.authenticated_header_size, nonce, key) != 0) {
            result = -EACCES;
        }
        if (result == 0 && decrypted_size != plaintext_size) {
            result = -EILSEQ;
        }
    }
    sodium_memzero(key, sizeof(key));
    if (result == 0) {
        if (contents->certificate_size > 0U) {
            contents->certificate =
                contents->database + contents->database_size;
        }
        if (contents->totp_key_size > 0U) {
            contents->totp_key = contents->database + contents->database_size +
                                 contents->certificate_size;
        }
        if (contents->client_ca_size > 0U) {
            contents->client_ca = contents->database + contents->database_size +
                                  contents->certificate_size +
                                  contents->totp_key_size;
        }
    } else {
        jg_backup_contents_clear(contents);
    }
    return result;
}

/** @brief Atomically store one new private backup archive. */
int jg_backup_store(const char *directory,
                    const char *filename,
                    const uint8_t *archive,
                    size_t archive_size)
{
    char temporary[64U] = {0};
    uint64_t random = 0U;
    int directory_descriptor = -1;
    int descriptor = -1;
    int result;

    if (!filename_valid(filename) || archive == NULL ||
        archive_size < BACKUP_V1_HEADER_SIZE ||
        archive_size > JG_BACKUP_PAYLOAD_MAX + BACKUP_HEADER_SIZE +
                           crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return -EINVAL;
    }
    result = initialize_crypto();
    if (result == 0) {
        result = open_directory(directory, &directory_descriptor);
    }
    if (result == 0) {
        int written;

        randombytes_buf(&random, sizeof(random));
        written = snprintf(temporary, sizeof(temporary),
                           ".janusgate-%016" PRIx64, random);
        if (written <= 0 || (size_t)written >= sizeof(temporary)) {
            result = -EOVERFLOW;
        }
    }
    if (result == 0) {
        descriptor =
            openat(directory_descriptor, temporary,
                   O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                   S_IRUSR | S_IWUSR);
        if (descriptor < 0) {
            result = -errno;
        }
    }
    if (result == 0) {
        result = write_all(descriptor, archive, archive_size);
    }
    if (result == 0 && fsync(descriptor) != 0) {
        result = -errno;
    }
    if (descriptor >= 0 && close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    if (result == 0 && linkat(directory_descriptor, temporary,
                              directory_descriptor, filename, 0) != 0) {
        result = -errno;
    }
    if (directory_descriptor >= 0 && temporary[0U] != '\0') {
        (void)unlinkat(directory_descriptor, temporary, 0);
    }
    if (result == 0 && fsync(directory_descriptor) != 0) {
        result = -errno;
    }
    if (directory_descriptor >= 0 && close(directory_descriptor) != 0 &&
        result == 0) {
        result = -errno;
    }
    sodium_memzero(&random, sizeof(random));
    return result;
}

/** @brief Load one secure private backup archive. */
int jg_backup_load(const char *directory,
                   const char *filename,
                   uint8_t **archive,
                   size_t *archive_size)
{
    struct stat metadata = {0};
    int directory_descriptor = -1;
    int descriptor = -1;
    int result;

    if (!filename_valid(filename) || archive == NULL || archive_size == NULL) {
        return -EINVAL;
    }
    *archive = NULL;
    *archive_size = 0U;
    result = open_directory(directory, &directory_descriptor);
    if (result == 0) {
        descriptor = openat(directory_descriptor, filename,
                            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0) {
            result = -errno;
        }
    }
    if (result == 0) {
        result = validate_archive_file(descriptor, &metadata, true);
    }
    if (result == 0 &&
        ((uint64_t)metadata.st_size < BACKUP_V1_HEADER_SIZE ||
         (uint64_t)metadata.st_size >
             (uint64_t)JG_BACKUP_PAYLOAD_MAX + BACKUP_HEADER_SIZE +
                 crypto_aead_xchacha20poly1305_ietf_ABYTES ||
         (uint64_t)metadata.st_size > SIZE_MAX)) {
        result = -EOVERFLOW;
    }
    if (result == 0) {
        *archive = malloc((size_t)metadata.st_size);
        if (*archive == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = read_all(descriptor, *archive, (size_t)metadata.st_size);
    }
    if (descriptor >= 0 && close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    if (directory_descriptor >= 0 && close(directory_descriptor) != 0 &&
        result == 0) {
        result = -errno;
    }
    if (result == 0) {
        *archive_size = (size_t)metadata.st_size;
    } else {
        jg_backup_data_clear(
            *archive, metadata.st_size > 0 ? (size_t)metadata.st_size : 0U);
        *archive = NULL;
    }
    return result;
}

/** @brief Remove one secure private backup archive. */
int jg_backup_remove(const char *directory, const char *filename)
{
    struct stat metadata;
    int directory_descriptor = -1;
    int descriptor = -1;
    int result;

    if (!filename_valid(filename)) {
        return -EINVAL;
    }
    result = open_directory(directory, &directory_descriptor);
    if (result == 0) {
        descriptor = openat(directory_descriptor, filename,
                            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0) {
            result = -errno;
        }
    }
    if (result == 0) {
        result = validate_archive_file(descriptor, &metadata, false);
    }
    if (descriptor >= 0 && close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    if (result == 0 && unlinkat(directory_descriptor, filename, 0) != 0) {
        result = -errno;
    }
    if (result == 0 && fsync(directory_descriptor) != 0) {
        result = -errno;
    }
    if (directory_descriptor >= 0 && close(directory_descriptor) != 0 &&
        result == 0) {
        result = -errno;
    }
    return result;
}

/** @brief Remove abandoned private staging and generated archive files. */
int jg_backup_reconcile(const char *directory,
                        jg_backup_retain_callback retain,
                        void *context,
                        size_t *removed)
{
    DIR *entries = NULL;
    int directory_descriptor = -1;
    int scan_descriptor = -1;
    size_t removed_count = 0U;
    int result = 0;

    if (retain == NULL) {
        return -EINVAL;
    }
    if (removed != NULL) {
        *removed = 0U;
    }
    result = open_directory(directory, &directory_descriptor);
    if (result == 0) {
        scan_descriptor = dup(directory_descriptor);
        if (scan_descriptor < 0) {
            result = -errno;
        }
    }
    if (result == 0) {
        entries = fdopendir(scan_descriptor);
        if (entries == NULL) {
            result = -errno;
            (void)close(scan_descriptor);
        }
    }
    while (result == 0 && entries != NULL) {
        struct dirent *entry = NULL;
        struct stat metadata;
        bool remove_entry = false;
        bool retain_entry = true;

        errno = 0;
        entry = readdir(entries);
        if (entry == NULL) {
            if (errno != 0) {
                result = -errno;
            }
            break;
        }
        remove_entry = staging_filename(entry->d_name);
        if (!remove_entry &&
            jg_backup_generated_filename_valid(entry->d_name)) {
            result = retain(context, entry->d_name, &retain_entry);
            remove_entry = result == 0 && !retain_entry;
        }
        if (result == 0 && remove_entry &&
            fstatat(directory_descriptor, entry->d_name, &metadata,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            result = errno == ENOENT ? 0 : -errno;
            remove_entry = false;
        }
        if (result == 0 && remove_entry &&
            (!S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid() ||
             (metadata.st_mode & 0777U) != (S_IRUSR | S_IWUSR))) {
            remove_entry = false;
        }
        if (result == 0 && remove_entry) {
            if (unlinkat(directory_descriptor, entry->d_name, 0) == 0) {
                ++removed_count;
            } else if (errno != ENOENT) {
                result = -errno;
            }
        }
    }
    if (entries != NULL && closedir(entries) != 0 && result == 0) {
        result = -errno;
    }
    if (result == 0 && removed_count > 0U && fsync(directory_descriptor) != 0) {
        result = -errno;
    }
    if (directory_descriptor >= 0 && close(directory_descriptor) != 0 &&
        result == 0) {
        result = -errno;
    }
    if (result == 0 && removed != NULL) {
        *removed = removed_count;
    }
    return result;
}

/** @brief Securely erase and release one backup archive. */
void jg_backup_data_clear(uint8_t *data, size_t data_size)
{
    if (data != NULL) {
        sodium_memzero(data, data_size);
        free(data);
    }
}

/** @brief Securely erase and release opened backup contents. */
void jg_backup_contents_clear(struct jg_backup_contents *contents)
{
    size_t plaintext_size = 0U;

    if (contents == NULL) {
        return;
    }
    if (contents->database != NULL &&
        jg_size_add(contents->database_size, contents->certificate_size,
                    &plaintext_size) &&
        jg_size_add(plaintext_size, contents->totp_key_size, &plaintext_size) &&
        jg_size_add(plaintext_size, contents->client_ca_size,
                    &plaintext_size)) {
        sodium_memzero(contents->database, plaintext_size);
    }
    if (contents->database != NULL) {
        free(contents->database);
    }
    sodium_memzero(contents, sizeof(*contents));
}
