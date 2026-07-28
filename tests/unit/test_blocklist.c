/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>

#include <cmocka.h>

#include "janusgate/blocklist.h"

int jg_test_blocklist(void);

/** @brief Verify plain-domain normalization, sorting, and deduplication. */
static void test_domain_format(void **state)
{
    static const uint8_t input[] = "# source\n"
                                   "Example.ORG.\n"
                                   "Bücher.example\n"
                                   "example.org\n";
    static const uint8_t reordered[] = "example.org\n"
                                       "xn--bcher-kva.example\n";
    struct jg_blocklist *first = NULL;
    struct jg_blocklist *second = NULL;
    struct jg_blocklist_info first_info;
    struct jg_blocklist_info second_info;
    struct jg_blocklist_entry entry;
    struct jg_blocklist_report report;

    (void)state;
    assert_int_equal(jg_blocklist_import(input, sizeof(input) - 1U,
                                         JG_BLOCKLIST_FORMAT_DOMAIN,
                                         JG_BLOCKLIST_STRICT, "plain source",
                                         NULL, &first, &report),
                     0);
    assert_int_equal(report.records_seen, 4U);
    assert_int_equal(report.entries_parsed, 3U);
    assert_int_equal(report.duplicates_removed, 1U);
    assert_int_equal(jg_blocklist_get_info(first, &first_info), 0);
    assert_int_equal(first_info.entry_count, 2U);
    assert_string_equal(first_info.attribution, "plain source");
    assert_int_equal(jg_blocklist_get_entry(first, 0U, &entry), 0);
    assert_string_equal(entry.domain, "example.org");
    assert_string_equal(entry.category, "");
    assert_int_equal(jg_blocklist_get_entry(first, 1U, &entry), 0);
    assert_string_equal(entry.domain, "xn--bcher-kva.example");

    assert_int_equal(jg_blocklist_import(reordered, sizeof(reordered) - 1U,
                                         JG_BLOCKLIST_FORMAT_DOMAIN,
                                         JG_BLOCKLIST_STRICT, "other source",
                                         NULL, &second, &report),
                     0);
    assert_int_equal(jg_blocklist_get_info(second, &second_info), 0);
    assert_memory_equal(first_info.checksum, second_info.checksum,
                        JG_BLOCKLIST_CHECKSUM_SIZE);

    jg_blocklist_destroy(second);
    jg_blocklist_destroy(first);
}

/** @brief Verify hosts-file aliases and categorized domain records. */
static void test_hosts_and_category_formats(void **state)
{
    static const uint8_t hosts[] =
        "0.0.0.0 ads.example tracker.example # aliases\n"
        ":: bad.example\n";
    static const uint8_t categories[] = "ads.example,advertising\n"
                                        "malware.example\tPubblicità\n"
                                        "ads.example,zzz\n";
    struct jg_blocklist *blocklist = NULL;
    struct jg_blocklist_info info;
    struct jg_blocklist_entry entry;

    (void)state;
    assert_int_equal(jg_blocklist_import(hosts, sizeof(hosts) - 1U,
                                         JG_BLOCKLIST_FORMAT_HOSTS,
                                         JG_BLOCKLIST_STRICT, "hosts source",
                                         NULL, &blocklist, NULL),
                     0);
    assert_int_equal(jg_blocklist_get_info(blocklist, &info), 0);
    assert_int_equal(info.entry_count, 3U);
    jg_blocklist_destroy(blocklist);

    blocklist = NULL;
    assert_int_equal(jg_blocklist_import(categories, sizeof(categories) - 1U,
                                         JG_BLOCKLIST_FORMAT_CATEGORY,
                                         JG_BLOCKLIST_STRICT, "category source",
                                         NULL, &blocklist, NULL),
                     0);
    assert_int_equal(jg_blocklist_get_info(blocklist, &info), 0);
    assert_int_equal(info.entry_count, 2U);
    assert_int_equal(jg_blocklist_get_entry(blocklist, 0U, &entry), 0);
    assert_string_equal(entry.domain, "ads.example");
    assert_string_equal(entry.category, "advertising");
    assert_int_equal(jg_blocklist_get_entry(blocklist, 1U, &entry), 0);
    assert_string_equal(entry.category, "Pubblicità");
    jg_blocklist_destroy(blocklist);
}

/** @brief Verify supported RPZ blocking records and ignored zone metadata. */
static void test_rpz_format(void **state)
{
    static const uint8_t input[] =
        "$TTL 60\n"
        "@ IN SOA localhost. root.localhost. 1 60 60 60 60\n"
        "@ IN NS localhost.\n"
        "bad.example. 60 IN CNAME .\n"
        "drop.example. CNAME rpz-drop.\n";
    struct jg_blocklist *blocklist = NULL;
    struct jg_blocklist_info info;

    (void)state;
    assert_int_equal(jg_blocklist_import(input, sizeof(input) - 1U,
                                         JG_BLOCKLIST_FORMAT_RPZ,
                                         JG_BLOCKLIST_STRICT, "rpz source",
                                         NULL, &blocklist, NULL),
                     0);
    assert_int_equal(jg_blocklist_get_info(blocklist, &info), 0);
    assert_int_equal(info.entry_count, 2U);
    jg_blocklist_destroy(blocklist);
}

/** @brief Verify the versioned JSON blocklist representation. */
static void test_json_format(void **state)
{
    static const uint8_t input[] =
        "{\"version\":1,\"entries\":["
        "{\"domain\":\"Example.org\",\"category\":\"ads\"},"
        "{\"domain\":\"malware.example\"}]}";
    struct jg_blocklist *blocklist = NULL;
    struct jg_blocklist_info info;
    struct jg_blocklist_entry entry;

    (void)state;
    assert_int_equal(jg_blocklist_import(input, sizeof(input) - 1U,
                                         JG_BLOCKLIST_FORMAT_JSON,
                                         JG_BLOCKLIST_STRICT, "json source",
                                         NULL, &blocklist, NULL),
                     0);
    assert_int_equal(jg_blocklist_get_info(blocklist, &info), 0);
    assert_int_equal(info.entry_count, 2U);
    assert_int_equal(jg_blocklist_get_entry(blocklist, 0U, &entry), 0);
    assert_string_equal(entry.domain, "example.org");
    assert_string_equal(entry.category, "ads");
    jg_blocklist_destroy(blocklist);
}

/** @brief Verify strict rejection, tolerant skipping, and resource bounds. */
static void test_errors_and_limits(void **state)
{
    static const uint8_t input[] = "valid.example\n"
                                   "bad..example\n"
                                   "other.example\n";
    static const uint8_t embedded_null[] = {'a', '.', 'b', '\0', 'x'};
    struct jg_blocklist_limits limits;
    struct jg_blocklist_report report;
    struct jg_blocklist_info info;
    struct jg_blocklist *blocklist = NULL;

    (void)state;
    assert_true(jg_blocklist_import(input, sizeof(input) - 1U,
                                    JG_BLOCKLIST_FORMAT_DOMAIN,
                                    JG_BLOCKLIST_STRICT, "strict source", NULL,
                                    &blocklist, &report) < 0);
    assert_null(blocklist);
    assert_int_equal(report.first_error_record, 2U);

    assert_int_equal(
        jg_blocklist_import(input, sizeof(input) - 1U,
                            JG_BLOCKLIST_FORMAT_DOMAIN, JG_BLOCKLIST_TOLERANT,
                            "tolerant source", NULL, &blocklist, &report),
        0);
    assert_int_equal(report.records_rejected, 1U);
    assert_int_equal(jg_blocklist_get_info(blocklist, &info), 0);
    assert_int_equal(info.entry_count, 2U);
    jg_blocklist_destroy(blocklist);

    jg_blocklist_limits_default(&limits);
    limits.max_line_bytes = 5U;
    blocklist = NULL;
    assert_int_equal(
        jg_blocklist_import(input, sizeof(input) - 1U,
                            JG_BLOCKLIST_FORMAT_DOMAIN, JG_BLOCKLIST_TOLERANT,
                            "bounded source", &limits, &blocklist, &report),
        0);
    assert_int_equal(report.records_rejected, 3U);
    jg_blocklist_destroy(blocklist);

    blocklist = NULL;
    assert_int_equal(jg_blocklist_import(embedded_null, sizeof(embedded_null),
                                         JG_BLOCKLIST_FORMAT_DOMAIN,
                                         JG_BLOCKLIST_TOLERANT, "null source",
                                         NULL, &blocklist, NULL),
                     -EILSEQ);
    assert_null(blocklist);
}

/** @brief Run the bounded blocklist import test group. */
int jg_test_blocklist(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_domain_format),
        cmocka_unit_test(test_hosts_and_category_formats),
        cmocka_unit_test(test_rpz_format),
        cmocka_unit_test(test_json_format),
        cmocka_unit_test(test_errors_and_limits),
    };

    return cmocka_run_group_tests_name("blocklist", tests, NULL, NULL);
}
