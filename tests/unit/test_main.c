/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

int jg_test_checked(void);
int jg_test_dns(void);
int jg_test_domain(void);
int jg_test_packet(void);

/** @brief Run every unit-test group and combine their exit status. */
int main(void)
{
    int result = jg_test_checked();

    result |= jg_test_domain();
    result |= jg_test_dns();
    result |= jg_test_packet();
    return result;
}
