/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <zlib.h>

#include "janusgate/diagnostic.h"

int jg_test_diagnostic(void);

/** Exact uncompressed test archive bytes for two small files. */
#define TEST_TAR_SIZE (6U * 512U)

/** @brief Inflate one gzip stream into a fixed test tar buffer. */
static void inflate_archive(uint8_t *archive,
                            size_t archive_size,
                            uint8_t tar[TEST_TAR_SIZE])
{
    z_stream stream;

    (void)memset(&stream, 0, sizeof(stream));
    assert_int_equal(inflateInit2(&stream, 15 + 32), Z_OK);
    stream.next_in = archive;
    stream.avail_in = (uInt)archive_size;
    stream.next_out = tar;
    stream.avail_out = TEST_TAR_SIZE;
    assert_int_equal(inflate(&stream, Z_FINISH), Z_STREAM_END);
    assert_int_equal(stream.total_out, TEST_TAR_SIZE);
    assert_int_equal(inflateEnd(&stream), Z_OK);
}

/** @brief Verify portable headers, exact content, and gzip round trip. */
static void test_archive(void **state)
{
    static const uint8_t manifest[] = "{\"format\":1}\n";
    static const uint8_t status[] = "{\"healthy\":true}\n";
    const struct jg_diagnostic_entry entries[] = {
        {
            .name = "manifest.json",
            .data = manifest,
            .size = sizeof(manifest) - 1U,
        },
        {
            .name = "status.json",
            .data = status,
            .size = sizeof(status) - 1U,
        },
    };
    uint8_t tar[TEST_TAR_SIZE];
    uint8_t *archive = NULL;
    size_t archive_size = 0U;

    (void)state;
    assert_int_equal(jg_diagnostic_archive_create(
                         entries, sizeof(entries) / sizeof(entries[0U]), 1234U,
                         &archive, &archive_size),
                     0);
    assert_non_null(archive);
    assert_true(archive_size > 10U);
    assert_int_equal(archive[0U], 0x1f);
    assert_int_equal(archive[1U], 0x8b);
    inflate_archive(archive, archive_size, tar);
    assert_memory_equal(tar, "manifest.json", sizeof("manifest.json") - 1U);
    assert_memory_equal(tar + 257U, "ustar", sizeof("ustar") - 1U);
    assert_memory_equal(tar + 512U, manifest, sizeof(manifest) - 1U);
    assert_memory_equal(tar + 1024U, "status.json", sizeof("status.json") - 1U);
    assert_memory_equal(tar + 1536U, status, sizeof(status) - 1U);
    jg_diagnostic_archive_destroy(archive);
}

/** @brief Verify bounded names, unique entries, sizes, and arguments. */
static void test_validation(void **state)
{
    static const uint8_t content[] = "x";
    struct jg_diagnostic_entry entries[2U] = {
        {
            .name = "status.json",
            .data = content,
            .size = sizeof(content) - 1U,
        },
        {
            .name = "status.json",
            .data = content,
            .size = sizeof(content) - 1U,
        },
    };
    uint8_t *archive = NULL;
    size_t archive_size = 0U;

    (void)state;
    assert_int_equal(
        jg_diagnostic_archive_create(NULL, 1U, 1U, &archive, &archive_size),
        -EINVAL);
    assert_int_equal(
        jg_diagnostic_archive_create(entries, 0U, 1U, &archive, &archive_size),
        -EINVAL);
    assert_int_equal(
        jg_diagnostic_archive_create(entries, 2U, 0U, &archive, &archive_size),
        -EINVAL);
    assert_int_equal(
        jg_diagnostic_archive_create(entries, 2U, 1U, &archive, &archive_size),
        -EINVAL);
    entries[1U].name = "../private";
    assert_int_equal(
        jg_diagnostic_archive_create(entries, 2U, 1U, &archive, &archive_size),
        -EINVAL);
    entries[1U].name = "empty.json";
    entries[1U].data = NULL;
    entries[1U].size = 1U;
    assert_int_equal(
        jg_diagnostic_archive_create(entries, 2U, 1U, &archive, &archive_size),
        -EINVAL);
    entries[1U].size = JG_DIAGNOSTIC_CONTENT_SIZE_MAX;
    entries[1U].data = content;
    assert_int_equal(
        jg_diagnostic_archive_create(entries, 2U, 1U, &archive, &archive_size),
        -EMSGSIZE);
    assert_null(archive);
    assert_int_equal(archive_size, 0U);
    jg_diagnostic_archive_destroy(NULL);
}

/** @brief Run the diagnostic archive test group. */
int jg_test_diagnostic(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_archive),
        cmocka_unit_test(test_validation),
    };

    return cmocka_run_group_tests_name("diagnostic", tests, NULL, NULL);
}
