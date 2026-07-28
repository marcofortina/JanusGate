/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "janusgate/backup.h"

int jg_test_backup(void);

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

/** @brief Verify configuration archive framing and checksum validation. */
static void test_configuration_archive(void **state)
{
    static const uint8_t database[] = "SQLite configuration snapshot";
    static const uint8_t certificate[] =
        "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n";
    struct jg_backup_info info;
    struct jg_backup_contents contents;
    uint8_t *archive = NULL;
    size_t archive_size = 0U;

    (void)state;
    assert_int_equal(jg_backup_create(JG_BACKUP_CONFIGURATION, database,
                                      sizeof(database) - 1U, certificate,
                                      sizeof(certificate) - 1U, NULL, 0U, 1000U,
                                      9U, &archive, &archive_size),
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
    assert_int_equal(info.archive_size, archive_size);
    assert_false(info.encrypted);

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
    static const char passphrase[] = "correct horse battery staple";
    struct jg_backup_info info;
    struct jg_backup_contents contents;
    uint8_t *archive = NULL;
    size_t archive_size = 0U;

    (void)state;
    assert_int_equal(
        jg_backup_create(JG_BACKUP_FULL, database, sizeof(database) - 1U,
                         private_certificate, sizeof(private_certificate) - 1U,
                         passphrase, sizeof(passphrase) - 1U, 2000U, 9U,
                         &archive, &archive_size),
        0);
    assert_int_equal(jg_backup_inspect(archive, archive_size, &info), 0);
    assert_int_equal(info.kind, JG_BACKUP_FULL);
    assert_true(info.encrypted);
    assert_false(
        contains_bytes(archive, archive_size, database, sizeof(database) - 1U));
    assert_false(contains_bytes(archive, archive_size, private_certificate,
                                sizeof(private_certificate) - 1U));
    assert_int_equal(jg_backup_open(archive, archive_size, "wrong passphrase",
                                    sizeof("wrong passphrase") - 1U, &contents),
                     -EKEYREJECTED);
    assert_int_equal(jg_backup_open(archive, archive_size, passphrase,
                                    sizeof(passphrase) - 1U, &contents),
                     0);
    assert_memory_equal(contents.database, database, sizeof(database) - 1U);
    assert_memory_equal(contents.certificate, private_certificate,
                        sizeof(private_certificate) - 1U);
    jg_backup_contents_clear(&contents);
    jg_backup_data_clear(archive, archive_size);
}

/** @brief Verify malformed, tampered, and invalid archives are rejected. */
static void test_archive_rejection(void **state)
{
    static const uint8_t database[] = "database";
    static const char passphrase[] = "long enough passphrase";
    struct jg_backup_info info;
    struct jg_backup_contents contents;
    uint8_t *archive = NULL;
    uint8_t *tampered = NULL;
    size_t archive_size = 0U;

    (void)state;
    assert_int_equal(jg_backup_create(JG_BACKUP_CONFIGURATION, database,
                                      sizeof(database) - 1U, NULL, 0U, NULL, 0U,
                                      1U, 9U, &archive, &archive_size),
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
    tampered[9U] = 2U;
    assert_int_equal(jg_backup_inspect(tampered, archive_size, &info),
                     -ENOTSUP);
    assert_int_equal(jg_backup_inspect(archive, archive_size - 1U, &info),
                     -EILSEQ);
    free(tampered);
    jg_backup_data_clear(archive, archive_size);

    assert_int_equal(jg_backup_create(JG_BACKUP_CONFIGURATION, database,
                                      sizeof(database) - 1U, NULL, 0U,
                                      "unexpected", sizeof("unexpected") - 1U,
                                      1U, 9U, &archive, &archive_size),
                     -EINVAL);
    assert_int_equal(jg_backup_create(JG_BACKUP_FULL, database,
                                      sizeof(database) - 1U, NULL, 0U, "short",
                                      sizeof("short") - 1U, 1U, 9U, &archive,
                                      &archive_size),
                     -EINVAL);
    assert_int_equal(jg_backup_create(JG_BACKUP_FULL, database,
                                      sizeof(database) - 1U, NULL, 0U,
                                      passphrase, sizeof(passphrase) - 1U, 1U,
                                      0U, &archive, &archive_size),
                     -EINVAL);
    assert_int_equal(jg_backup_inspect(NULL, 0U, &info), -EINVAL);
    assert_int_equal(jg_backup_inspect(database, sizeof(database), NULL),
                     -EINVAL);
    assert_int_equal(jg_backup_open(NULL, 0U, NULL, 0U, &contents), -EINVAL);
    jg_backup_contents_clear(NULL);
    jg_backup_data_clear(NULL, 0U);
}

/** @brief Run the backup archive test group. */
int jg_test_backup(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_configuration_archive),
        cmocka_unit_test(test_encrypted_archive),
        cmocka_unit_test(test_archive_rejection),
    };

    return cmocka_run_group_tests_name("backup", tests, NULL, NULL);
}
