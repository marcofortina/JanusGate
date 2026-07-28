/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

#include "janusgate/checked.h"

int jg_test_checked(void);

/** @brief Verify successful arithmetic and overflow rejection. */
static void test_size_arithmetic(void **state)
{
    size_t value = 7U;

    (void)state;
    assert_true(jg_size_add(20U, 22U, &value));
    assert_int_equal(value, 42U);
    assert_false(jg_size_add(SIZE_MAX, 1U, &value));
    assert_int_equal(value, 42U);
    assert_false(jg_size_add(1U, 1U, NULL));

    assert_true(jg_size_multiply(6U, 7U, &value));
    assert_int_equal(value, 42U);
    assert_false(jg_size_multiply(SIZE_MAX, 2U, &value));
    assert_int_equal(value, 42U);
    assert_true(jg_size_multiply(0U, SIZE_MAX, &value));
    assert_int_equal(value, 0U);
}

/** @brief Verify half-open range validation at buffer boundaries. */
static void test_ranges(void **state)
{
    (void)state;
    assert_true(jg_range_valid(0U, 0U, 0U));
    assert_true(jg_range_valid(4U, 4U, 8U));
    assert_true(jg_range_valid(8U, 0U, 8U));
    assert_false(jg_range_valid(9U, 0U, 8U));
    assert_false(jg_range_valid(SIZE_MAX, 2U, SIZE_MAX));
}

/** @brief Verify bounded network-order integer reads and writes. */
static void test_network_access(void **state)
{
    uint8_t data[] = {0x12U, 0x34U, 0x56U, 0x78U, 0x00U, 0x00U};
    uint8_t wide_data[8U] = {0U};
    uint16_t short_value = 0U;
    uint32_t long_value = 0U;
    uint64_t wide_value = 0U;

    (void)state;
    assert_true(jg_read_u16_be(data, sizeof(data), 0U, &short_value));
    assert_int_equal(short_value, UINT16_C(0x1234));
    assert_true(jg_read_u32_be(data, sizeof(data), 0U, &long_value));
    assert_int_equal(long_value, UINT32_C(0x12345678));
    assert_false(jg_read_u32_be(data, sizeof(data), 3U, &long_value));
    assert_true(jg_write_u16_be(data, sizeof(data), 4U, UINT16_C(0xabcd)));
    assert_int_equal(data[4], 0xab);
    assert_int_equal(data[5], 0xcd);
    assert_true(jg_write_u32_be(data, sizeof(data), 1U, UINT32_C(0x89abcdef)));
    assert_true(jg_read_u32_be(data, sizeof(data), 1U, &long_value));
    assert_int_equal(long_value, UINT32_C(0x89abcdef));
    assert_true(jg_write_u64_be(wide_data, sizeof(wide_data), 0U,
                                UINT64_C(0x0123456789abcdef)));
    assert_true(jg_read_u64_be(wide_data, sizeof(wide_data), 0U, &wide_value));
    assert_int_equal(wide_value, UINT64_C(0x0123456789abcdef));
    assert_false(jg_read_u64_be(wide_data, sizeof(wide_data), 1U, &wide_value));
    assert_false(jg_write_u64_be(wide_data, sizeof(wide_data), 1U, wide_value));
}

/** @brief Verify that secure clearing overwrites every requested byte. */
static void test_secure_clear(void **state)
{
    uint8_t secret[] = {1U, 2U, 3U, 4U};
    size_t index = 0U;

    (void)state;
    jg_secure_clear(secret, sizeof(secret));
    for (index = 0U; index < sizeof(secret); ++index) {
        assert_int_equal(secret[index], 0U);
    }
    jg_secure_clear(NULL, 0U);
}

/** @brief Run the checked-arithmetic and byte-access test group. */
int jg_test_checked(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_size_arithmetic),
        cmocka_unit_test(test_ranges),
        cmocka_unit_test(test_network_access),
        cmocka_unit_test(test_secure_clear),
    };

    return cmocka_run_group_tests_name("checked", tests, NULL, NULL);
}
