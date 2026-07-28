/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

#include "janusgate/dns.h"

int jg_test_dns(void);

static const uint8_t simple_query[] = {
    0x12U, 0x34U, 0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x07U, 'E',   'x',   'a',   'm',   'p',   'l',   'e',
    0x03U, 'O',   'R',   'G',   0x00U, 0x00U, 0x01U, 0x00U, 0x01U,
};

/** @brief Verify parsing of one ordinary uncompressed DNS question. */
static void test_simple_question(void **state)
{
    struct jg_dns_message parsed;

    (void)state;
    assert_int_equal(
        jg_dns_parse_query(simple_query, sizeof(simple_query), &parsed),
        JG_DNS_OK);
    assert_int_equal(parsed.id, UINT16_C(0x1234));
    assert_int_equal(parsed.question_count, 1U);
    assert_string_equal(parsed.questions[0].name, "example.org");
    assert_int_equal(parsed.questions[0].type, 1U);
    assert_int_equal(parsed.questions[0].class_code, 1U);
}

/** @brief Verify backward compression pointers across multiple questions. */
static void test_compressed_questions(void **state)
{
    const uint8_t message[] = {
        0x00U, 0x01U, 0x01U, 0x00U, 0x00U, 0x02U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x07U, 'e',   'x',   'a',   'm',   'p',   'l',   'e',
        0x03U, 'o',   'r',   'g',   0x00U, 0x00U, 0x01U, 0x00U, 0x01U, 0x03U,
        'w',   'w',   'w',   0xc0U, 0x0cU, 0x00U, 0x1cU, 0x00U, 0x01U,
    };
    struct jg_dns_message parsed;

    (void)state;
    assert_int_equal(jg_dns_parse_query(message, sizeof(message), &parsed),
                     JG_DNS_OK);
    assert_int_equal(parsed.question_count, 2U);
    assert_string_equal(parsed.questions[1].name, "www.example.org");
    assert_int_equal(parsed.questions[1].type, 28U);
}

/** @brief Verify recognition of one valid EDNS0 OPT record. */
static void test_edns_record(void **state)
{
    const uint8_t message[] = {
        0x00U, 0x01U, 0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x01U, 0x01U, 'a',   0x00U, 0x00U, 0x41U, 0x00U, 0x01U, 0x00U,
        0x00U, 0x29U, 0x04U, 0xd0U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    };
    struct jg_dns_message parsed;

    (void)state;
    assert_int_equal(jg_dns_parse_query(message, sizeof(message), &parsed),
                     JG_DNS_OK);
    assert_true(parsed.has_edns0);
}

/** @brief Verify rejection of invalid pointers and truncated messages. */
static void test_pointer_and_length_failures(void **state)
{
    uint8_t forward_pointer[18U] = {
        0x00U, 0x01U, 0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0xc0U, 0x0eU, 0x00U, 0x01U, 0x00U, 0x01U,
    };
    struct jg_dns_message parsed;

    (void)state;
    assert_int_equal(
        jg_dns_parse_query(forward_pointer, sizeof(forward_pointer), &parsed),
        JG_DNS_MALFORMED);
    assert_int_equal(
        jg_dns_parse_query(simple_query, sizeof(simple_query) - 1U, &parsed),
        JG_DNS_TRUNCATED);
    forward_pointer[2] = 0x09U;
    assert_int_equal(
        jg_dns_parse_query(forward_pointer, sizeof(forward_pointer), &parsed),
        JG_DNS_BAD_OPCODE);
}

/** @brief Run the DNS parser test group. */
int jg_test_dns(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_simple_question),
        cmocka_unit_test(test_compressed_questions),
        cmocka_unit_test(test_edns_record),
        cmocka_unit_test(test_pointer_and_length_failures),
    };

    return cmocka_run_group_tests_name("dns", tests, NULL, NULL);
}
