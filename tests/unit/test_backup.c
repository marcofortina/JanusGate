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
#include <sodium.h>

#include "janusgate/backup.h"

int jg_test_backup(void);

/** One generated archive filename retained by reconciliation tests. */
struct backup_retention {
    const char *filename;
};

/** @brief Retain only the configured generated archive filename. */
static int retain_backup(void *context, const char *filename, bool *retain)
{
    const struct backup_retention *retention = context;

    *retain = strcmp(filename, retention->filename) == 0;
    return 0;
}

/** @brief Create one owner-private test file containing one byte. */
static void create_private_file(const char *path)
{
    static const uint8_t value = 1U;
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    assert_true(descriptor >= 0);
    assert_int_equal(write(descriptor, &value, sizeof(value)), sizeof(value));
    assert_int_equal(close(descriptor), 0);
}

/** @brief Find whether a byte sequence occurs inside another byte sequence. */
static bool contains_bytes(const uint8_t *data,
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

/** @brief Write one test integer in network byte order. */
static void write_test_u64(uint8_t *destination, uint64_t value)
{
    for (size_t index = 0U; index < sizeof(value); ++index) {
        destination[index] =
            (uint8_t)(value >> ((sizeof(value) - index - 1U) * 8U));
    }
}

/** @brief Build one deterministic version-one configuration fixture. */
static uint8_t *create_v1_archive(size_t *archive_size)
{
    static const uint8_t database[] = "legacy-v1";
    static const uint8_t magic[] = {'J', 'G', 'B', 'A', 'C', 'K', 'U', 'P'};
    const size_t header_size = 144U;
    const size_t authenticated_size = 112U;
    uint8_t *archive = calloc(1U, header_size + sizeof(database) - 1U);
    crypto_hash_sha256_state checksum;

    assert_non_null(archive);
    (void)memcpy(archive, magic, sizeof(magic));
    archive[9U] = 1U;
    archive[10U] = (uint8_t)(header_size >> 8U);
    archive[11U] = (uint8_t)header_size;
    archive[12U] = JG_BACKUP_CONFIGURATION;
    archive[15U] = 1U;
    archive[17U] = 1U;
    write_test_u64(archive + 20U, 1234U);
    archive[31U] = 9U;
    write_test_u64(archive + 32U, sizeof(database) - 1U);
    write_test_u64(archive + 48U, sizeof(database) - 1U);
    (void)memcpy(archive + header_size, database, sizeof(database) - 1U);
    assert_int_equal(crypto_hash_sha256_init(&checksum), 0);
    assert_int_equal(
        crypto_hash_sha256_update(&checksum, archive, authenticated_size), 0);
    assert_int_equal(crypto_hash_sha256_update(&checksum, archive + header_size,
                                               sizeof(database) - 1U),
                     0);
    assert_int_equal(crypto_hash_sha256_final(&checksum, archive + 112U), 0);
    *archive_size = header_size + sizeof(database) - 1U;
    return archive;
}

/** @brief Verify current readers retain version-one archive compatibility. */
static void test_version_one_compatibility(void **state)
{
    static const uint8_t database[] = "legacy-v1";
    struct jg_backup_info info;
    struct jg_backup_contents contents;
    uint8_t *archive = NULL;
    size_t archive_size = 0U;

    (void)state;
    archive = create_v1_archive(&archive_size);
    assert_int_equal(jg_backup_inspect(archive, archive_size, &info), 0);
    assert_int_equal(info.format_version, 1U);
    assert_false(info.portable);
    assert_int_equal(info.totp_key_size, 0U);
    assert_int_equal(info.client_ca_size, 0U);
    assert_int_equal(jg_backup_open(archive, archive_size, NULL, 0U, &contents),
                     0);
    assert_memory_equal(contents.database, database, sizeof(database) - 1U);
    jg_backup_contents_clear(&contents);
    jg_backup_data_clear(archive, archive_size);
}

/** @brief Verify configuration archive framing and checksum validation. */
static void test_configuration_archive(void **state)
{
    static const uint8_t database[] = "SQLite configuration snapshot";
    static const uint8_t certificate[] =
        "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n";
    struct jg_backup_info info;
    struct jg_backup_contents contents;
    const struct jg_backup_payload payload = {
        .database = database,
        .database_size = sizeof(database) - 1U,
        .certificate = certificate,
        .certificate_size = sizeof(certificate) - 1U,
    };
    uint8_t *archive = NULL;
    size_t archive_size = 0U;

    (void)state;
    assert_int_equal(jg_backup_create(JG_BACKUP_CONFIGURATION, &payload, NULL,
                                      0U, 1000U, 9U, &archive, &archive_size),
                     0);
    assert_non_null(archive);
    assert_true(archive_size > sizeof(database) + sizeof(certificate));
    assert_int_equal(jg_backup_inspect(archive, archive_size, &info), 0);
    assert_int_equal(info.kind, JG_BACKUP_CONFIGURATION);
    assert_int_equal(info.format_version, JG_BACKUP_FORMAT_VERSION);
    assert_int_equal(info.compatible_version_min, JG_BACKUP_FORMAT_VERSION);
    assert_int_equal(info.compatible_version_max, JG_BACKUP_FORMAT_VERSION);
    assert_int_equal(info.schema_version, 9U);
    assert_int_equal(info.created_at, 1000U);
    assert_int_equal(info.database_size, sizeof(database) - 1U);
    assert_int_equal(info.certificate_size, sizeof(certificate) - 1U);
    assert_int_equal(info.totp_key_size, 0U);
    assert_int_equal(info.client_ca_size, 0U);
    assert_int_equal(info.archive_size, archive_size);
    assert_false(info.encrypted);
    assert_false(info.portable);

    assert_int_equal(jg_backup_open(archive, archive_size, NULL, 0U, &contents),
                     0);
    assert_memory_equal(contents.database, database, sizeof(database) - 1U);
    assert_memory_equal(contents.certificate, certificate,
                        sizeof(certificate) - 1U);
    jg_backup_contents_clear(&contents);
    assert_null(contents.database);
    assert_null(contents.certificate);
    jg_backup_data_clear(archive, archive_size);
}

/** @brief Verify Argon2id and XChaCha20-Poly1305 full-backup protection. */
static void test_encrypted_archive(void **state)
{
    static const uint8_t database[] = "SQLite snapshot with credentials";
    static const uint8_t private_certificate[] =
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n";
    static const char passphrase[] = "minimum phrase!!";
    static const uint8_t client_ca[] =
        "-----BEGIN CERTIFICATE-----\nclient-ca\n-----END CERTIFICATE-----\n";
    uint8_t totp_key[JG_AUTH_TOTP_KEY_SIZE];
    struct jg_backup_info info;
    struct jg_backup_contents contents;
    struct jg_backup_payload payload = {
        .database = database,
        .database_size = sizeof(database) - 1U,
        .certificate = private_certificate,
        .certificate_size = sizeof(private_certificate) - 1U,
        .totp_key = totp_key,
        .totp_key_size = sizeof(totp_key),
        .client_ca = client_ca,
        .client_ca_size = sizeof(client_ca) - 1U,
    };
    uint8_t *archive = NULL;
    size_t archive_size = 0U;

    (void)state;
    (void)memset(totp_key, 0x5a, sizeof(totp_key));
    assert_int_equal(sizeof(passphrase) - 1U, JG_BACKUP_PASSPHRASE_MIN);
    assert_int_equal(jg_backup_create(JG_BACKUP_FULL, &payload, passphrase,
                                      sizeof(passphrase) - 1U, 2000U, 9U,
                                      &archive, &archive_size),
                     0);
    assert_int_equal(jg_backup_inspect(archive, archive_size, &info), 0);
    assert_int_equal(info.kind, JG_BACKUP_FULL);
    assert_true(info.encrypted);
    assert_true(info.portable);
    assert_int_equal(info.totp_key_size, sizeof(totp_key));
    assert_int_equal(info.client_ca_size, sizeof(client_ca) - 1U);
    assert_false(
        contains_bytes(archive, archive_size, database, sizeof(database) - 1U));
    assert_false(contains_bytes(archive, archive_size, private_certificate,
                                sizeof(private_certificate) - 1U));
    assert_false(
        contains_bytes(archive, archive_size, totp_key, sizeof(totp_key)));
    assert_false(contains_bytes(archive, archive_size, client_ca,
                                sizeof(client_ca) - 1U));
    assert_int_equal(jg_backup_open(archive, archive_size, "wrong passphrase",
                                    sizeof("wrong passphrase") - 1U, &contents),
                     -EACCES);
    assert_int_equal(jg_backup_open(archive, archive_size, passphrase,
                                    sizeof(passphrase) - 1U, &contents),
                     0);
    assert_memory_equal(contents.database, database, sizeof(database) - 1U);
    assert_memory_equal(contents.certificate, private_certificate,
                        sizeof(private_certificate) - 1U);
    assert_memory_equal(contents.totp_key, totp_key, sizeof(totp_key));
    assert_memory_equal(contents.client_ca, client_ca, sizeof(client_ca) - 1U);
    jg_backup_contents_clear(&contents);
    jg_backup_data_clear(archive, archive_size);
}

/** @brief Verify malformed, tampered, and invalid archives are rejected. */
static void test_archive_rejection(void **state)
{
    static const uint8_t database[] = "database";
    static const char passphrase[] = "long enough passphrase";
    static const char short_passphrase[] = "minimum phrase!";
    uint8_t totp_key[JG_AUTH_TOTP_KEY_SIZE];
    struct jg_backup_payload payload = {
        .database = database,
        .database_size = sizeof(database) - 1U,
    };
    struct jg_backup_info info;
    struct jg_backup_contents contents;
    uint8_t *archive = NULL;
    uint8_t *tampered = NULL;
    size_t archive_size = 0U;

    (void)state;
    (void)memset(totp_key, 0x31, sizeof(totp_key));
    assert_int_equal(sizeof(short_passphrase) - 1U,
                     JG_BACKUP_PASSPHRASE_MIN - 1U);
    assert_int_equal(jg_backup_create(JG_BACKUP_CONFIGURATION, &payload, NULL,
                                      0U, 1U, 9U, &archive, &archive_size),
                     0);
    tampered = malloc(archive_size);
    assert_non_null(tampered);
    (void)memcpy(tampered, archive, archive_size);
    tampered[archive_size - 1U] ^= 1U;
    assert_int_equal(jg_backup_inspect(tampered, archive_size, &info),
                     -EBADMSG);
    (void)memcpy(tampered, archive, archive_size);
    tampered[0U] ^= 1U;
    assert_int_equal(jg_backup_inspect(tampered, archive_size, &info), -EILSEQ);
    (void)memcpy(tampered, archive, archive_size);
    tampered[8U] = 0U;
    tampered[9U] = 3U;
    assert_int_equal(jg_backup_inspect(tampered, archive_size, &info),
                     -ENOTSUP);
    assert_int_equal(jg_backup_inspect(archive, archive_size - 1U, &info),
                     -EILSEQ);
    free(tampered);
    jg_backup_data_clear(archive, archive_size);

    assert_int_equal(jg_backup_create(JG_BACKUP_CONFIGURATION, &payload,
                                      "unexpected", sizeof("unexpected") - 1U,
                                      1U, 9U, &archive, &archive_size),
                     -EINVAL);
    payload.totp_key = totp_key;
    payload.totp_key_size = sizeof(totp_key);
    assert_int_equal(jg_backup_create(JG_BACKUP_FULL, &payload,
                                      short_passphrase,
                                      sizeof(short_passphrase) - 1U, 1U, 9U,
                                      &archive, &archive_size),
                     -EINVAL);
    assert_int_equal(jg_backup_create(JG_BACKUP_FULL, &payload, passphrase,
                                      sizeof(passphrase) - 1U, 1U, 0U, &archive,
                                      &archive_size),
                     -EINVAL);
    payload.totp_key_size = sizeof(totp_key) - 1U;
    assert_int_equal(jg_backup_create(JG_BACKUP_FULL, &payload, passphrase,
                                      sizeof(passphrase) - 1U, 1U, 9U, &archive,
                                      &archive_size),
                     -EINVAL);
    assert_int_equal(jg_backup_inspect(NULL, 0U, &info), -EINVAL);
    assert_int_equal(jg_backup_inspect(database, sizeof(database), NULL),
                     -EINVAL);
    assert_int_equal(jg_backup_open(NULL, 0U, NULL, 0U, &contents), -EINVAL);
    jg_backup_contents_clear(NULL);
    jg_backup_data_clear(NULL, 0U);
}

/** @brief Verify private atomic archive storage and metadata checks. */
static void test_archive_storage(void **state)
{
    static const uint8_t database[] = "stored database";
    char directory[] = "/tmp/janusgate-backup-XXXXXX";
    char path[256U];
    char link_path[256U];
    const struct jg_backup_payload payload = {
        .database = database,
        .database_size = sizeof(database) - 1U,
    };
    uint8_t *archive = NULL;
    uint8_t *loaded = NULL;
    size_t archive_size = 0U;
    size_t loaded_size = 0U;
    int written;

    (void)state;
    assert_non_null(mkdtemp(directory));
    assert_int_equal(jg_backup_create(JG_BACKUP_CONFIGURATION, &payload, NULL,
                                      0U, 1U, 9U, &archive, &archive_size),
                     0);
    assert_int_equal(
        jg_backup_store(directory, "backup-1.jgb", archive, archive_size), 0);
    assert_int_equal(
        jg_backup_store(directory, "backup-1.jgb", archive, archive_size),
        -EEXIST);
    assert_int_equal(
        jg_backup_load(directory, "backup-1.jgb", &loaded, &loaded_size), 0);
    assert_int_equal(loaded_size, archive_size);
    assert_memory_equal(loaded, archive, archive_size);
    jg_backup_data_clear(loaded, loaded_size);
    loaded = NULL;
    loaded_size = 0U;

    written = snprintf(path, sizeof(path), "%s/backup-1.jgb", directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(path));
    assert_int_equal(chmod(path, 0644), 0);
    assert_int_equal(
        jg_backup_load(directory, "backup-1.jgb", &loaded, &loaded_size),
        -EACCES);
    assert_int_equal(chmod(path, 0600), 0);
    written =
        snprintf(link_path, sizeof(link_path), "%s/backup-link.jgb", directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(link_path));
    assert_int_equal(symlink("backup-1.jgb", link_path), 0);
    assert_true(jg_backup_load(directory, "backup-link.jgb", &loaded,
                               &loaded_size) < 0);
    assert_int_equal(
        jg_backup_store(directory, "../escape", archive, archive_size),
        -EINVAL);
    assert_int_equal(jg_backup_remove(directory, "backup-1.jgb"), 0);
    assert_int_equal(
        jg_backup_load(directory, "backup-1.jgb", &loaded, &loaded_size),
        -ENOENT);
    assert_int_equal(unlink(link_path), 0);
    assert_int_equal(rmdir(directory), 0);
    jg_backup_data_clear(archive, archive_size);
}

/** @brief Verify reconciliation removes only abandoned private files. */
static void test_archive_reconciliation(void **state)
{
    static const char staging_name[] = ".janusgate-0123456789abcdef";
    static const char orphan_name[] = "backup-100-0123456789abcdef.jgb";
    static const char retained_name[] = "backup-101-fedcba9876543210.jgb";
    static const char linked_name[] = "backup-102-0011223344556677.jgb";
    static const char foreign_name[] = "operator-note.txt";
    struct backup_retention retention = {.filename = retained_name};
    const char *private_names[] = {
        staging_name,
        orphan_name,
        retained_name,
        foreign_name,
    };
    char directory[] = "/tmp/janusgate-reconcile-XXXXXX";
    char path[256U];
    char linked_path[256U];
    struct stat metadata;
    size_t removed = 0U;

    (void)state;
    assert_non_null(mkdtemp(directory));
    for (size_t index = 0U;
         index < sizeof(private_names) / sizeof(private_names[0U]); ++index) {
        assert_true(snprintf(path, sizeof(path), "%s/%s", directory,
                             private_names[index]) > 0);
        create_private_file(path);
    }
    assert_true(snprintf(linked_path, sizeof(linked_path), "%s/%s", directory,
                         linked_name) > 0);
    assert_int_equal(symlink(foreign_name, linked_path), 0);
    assert_int_equal(
        jg_backup_reconcile(directory, retain_backup, &retention, &removed), 0);
    assert_int_equal(removed, 2U);
    for (size_t index = 0U; index < 2U; ++index) {
        assert_true(snprintf(path, sizeof(path), "%s/%s", directory,
                             private_names[index]) > 0);
        assert_int_equal(access(path, F_OK), -1);
        assert_int_equal(errno, ENOENT);
    }
    for (size_t index = 2U;
         index < sizeof(private_names) / sizeof(private_names[0U]); ++index) {
        assert_true(snprintf(path, sizeof(path), "%s/%s", directory,
                             private_names[index]) > 0);
        assert_int_equal(access(path, F_OK), 0);
        assert_int_equal(unlink(path), 0);
    }
    assert_int_equal(lstat(linked_path, &metadata), 0);
    assert_true(S_ISLNK(metadata.st_mode));
    assert_int_equal(unlink(linked_path), 0);
    assert_int_equal(rmdir(directory), 0);
}

/** @brief Run the backup archive test group. */
int jg_test_backup(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_version_one_compatibility),
        cmocka_unit_test(test_configuration_archive),
        cmocka_unit_test(test_encrypted_archive),
        cmocka_unit_test(test_archive_rejection),
        cmocka_unit_test(test_archive_storage),
        cmocka_unit_test(test_archive_reconciliation),
    };

    return cmocka_run_group_tests_name("backup", tests, NULL, NULL);
}
