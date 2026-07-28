/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/backup.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "janusgate/checked.h"

/** Serialized backup header bytes. */
#define BACKUP_HEADER_SIZE 144U

/** Header bytes authenticated by the archive checksum and full-backup AEAD. */
#define BACKUP_AUTHENTICATED_HEADER_SIZE 112U

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
    BACKUP_OFFSET_CHECKSUM = 112
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

/** @brief Compute the archive checksum without its checksum field. */
static void compute_checksum(const uint8_t *archive,
                             size_t archive_size,
                             uint8_t checksum[crypto_hash_sha256_BYTES])
{
    crypto_hash_sha256_state state;

    (void)crypto_hash_sha256_init(&state);
    (void)crypto_hash_sha256_update(&state, archive,
                                    BACKUP_AUTHENTICATED_HEADER_SIZE);
    (void)crypto_hash_sha256_update(
        &state, archive + BACKUP_HEADER_SIZE,
        (unsigned long long)(archive_size - BACKUP_HEADER_SIZE));
    (void)crypto_hash_sha256_final(&state, checksum);
}

/** @brief Validate and decode one fixed backup manifest. */
static int parse_manifest(const uint8_t *archive,
                          size_t archive_size,
                          struct jg_backup_info *info)
{
    uint64_t encoded_database_size;
    uint64_t encoded_certificate_size;
    uint64_t encoded_payload_size;
    uint64_t expected_plaintext_size;
    uint64_t expected_payload_size;
    uint64_t kdf_operations;
    uint64_t kdf_memory;
    uint8_t flags;
    size_t expected_archive_size = 0U;

    if (archive_size < BACKUP_HEADER_SIZE) {
        return -EILSEQ;
    }
    if (sodium_memcmp(archive + BACKUP_OFFSET_MAGIC, backup_magic,
                      sizeof(backup_magic)) != 0) {
        return -EILSEQ;
    }
    info->format_version = read_u16(archive + BACKUP_OFFSET_VERSION);
    if (info->format_version != JG_BACKUP_FORMAT_VERSION) {
        return -ENOTSUP;
    }
    if (read_u16(archive + BACKUP_OFFSET_HEADER_SIZE) != BACKUP_HEADER_SIZE ||
        read_u16(archive + BACKUP_OFFSET_RESERVED) != 0U) {
        return -EILSEQ;
    }
    info->compatible_version_min =
        read_u16(archive + BACKUP_OFFSET_COMPATIBLE_MIN);
    info->compatible_version_max =
        read_u16(archive + BACKUP_OFFSET_COMPATIBLE_MAX);
    if (info->compatible_version_min == 0U ||
        info->compatible_version_min > JG_BACKUP_FORMAT_VERSION ||
        info->compatible_version_max < JG_BACKUP_FORMAT_VERSION) {
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
    encoded_payload_size = read_u64(archive + BACKUP_OFFSET_PAYLOAD_SIZE);
    if (encoded_database_size == 0U ||
        encoded_database_size > JG_BACKUP_PAYLOAD_MAX ||
        encoded_certificate_size > JG_BACKUP_PAYLOAD_MAX ||
        encoded_database_size > UINT64_MAX - encoded_certificate_size) {
        return -EOVERFLOW;
    }
    expected_plaintext_size = encoded_database_size + encoded_certificate_size;
    if (expected_plaintext_size > JG_BACKUP_PAYLOAD_MAX ||
        expected_plaintext_size > SIZE_MAX) {
        return -EOVERFLOW;
    }
    expected_payload_size = expected_plaintext_size;
    if (info->encrypted) {
        expected_payload_size += crypto_aead_xchacha20poly1305_ietf_ABYTES;
    }
    if (encoded_payload_size != expected_payload_size ||
        encoded_payload_size > SIZE_MAX ||
        !jg_size_add(BACKUP_HEADER_SIZE, (size_t)encoded_payload_size,
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
    info->archive_size = archive_size;
    (void)memcpy(info->checksum, archive + BACKUP_OFFSET_CHECKSUM,
                 sizeof(info->checksum));
    return 0;
}

/** @brief Create a versioned configuration or encrypted full archive. */
int jg_backup_create(enum jg_backup_kind kind,
                     const uint8_t *database,
                     size_t database_size,
                     const uint8_t *certificate,
                     size_t certificate_size,
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
    unsigned long long encrypted_size = 0U;
    int result;

    if (archive == NULL || archive_size == NULL) {
        return -EINVAL;
    }
    *archive = NULL;
    *archive_size = 0U;
    result = validate_passphrase(kind, passphrase, passphrase_size);
    if (result != 0 || database == NULL || database_size == 0U ||
        (certificate == NULL) != (certificate_size == 0U) ||
        schema_version == 0U) {
        return -EINVAL;
    }
    if (!jg_size_add(database_size, certificate_size, &plaintext_size) ||
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
    write_u64(*archive + BACKUP_OFFSET_DATABASE_SIZE, database_size);
    write_u64(*archive + BACKUP_OFFSET_CERTIFICATE_SIZE, certificate_size);
    write_u64(*archive + BACKUP_OFFSET_PAYLOAD_SIZE, payload_size);

    if (kind == JG_BACKUP_CONFIGURATION) {
        (void)memcpy(*archive + BACKUP_HEADER_SIZE, database, database_size);
        if (certificate_size > 0U) {
            (void)memcpy(*archive + BACKUP_HEADER_SIZE + database_size,
                         certificate, certificate_size);
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
            (void)memcpy(plaintext, database, database_size);
            if (certificate_size > 0U) {
                (void)memcpy(plaintext + database_size, certificate,
                             certificate_size);
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
        compute_checksum(*archive, total_size,
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
    int result;

    if (archive == NULL || info == NULL) {
        return -EINVAL;
    }
    (void)memset(info, 0, sizeof(*info));
    result = initialize_crypto();
    if (result == 0) {
        result = parse_manifest(archive, archive_size, info);
    }
    if (result == 0) {
        uint8_t checksum[crypto_hash_sha256_BYTES];

        compute_checksum(archive, archive_size, checksum);
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
        result = validate_passphrase(contents->info.kind, passphrase,
                                     passphrase_size);
    }
    if (result == 0 &&
        !jg_size_add(contents->info.database_size,
                     contents->info.certificate_size, &plaintext_size)) {
        result = -EOVERFLOW;
    }
    if (result == 0) {
        contents->database_size = contents->info.database_size;
        contents->certificate_size = contents->info.certificate_size;
        salt = archive + BACKUP_OFFSET_SALT;
        nonce = archive + BACKUP_OFFSET_NONCE;
        contents->database = malloc(plaintext_size);
        if (contents->database == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0 && !contents->info.encrypted) {
        (void)memcpy(contents->database, archive + BACKUP_HEADER_SIZE,
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
                archive + BACKUP_HEADER_SIZE,
                (unsigned long long)(archive_size - BACKUP_HEADER_SIZE),
                archive, BACKUP_AUTHENTICATED_HEADER_SIZE, nonce, key) != 0) {
            result = -EKEYREJECTED;
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
    } else {
        jg_backup_contents_clear(contents);
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
                    &plaintext_size)) {
        sodium_memzero(contents->database, plaintext_size);
    }
    if (contents->database != NULL) {
        free(contents->database);
    }
    sodium_memzero(contents, sizeof(*contents));
}
