/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

int jg_test_checked(void);

/** @brief Run every unit-test group and combine their exit status. */
int main(void)
{
    return jg_test_checked();
}
