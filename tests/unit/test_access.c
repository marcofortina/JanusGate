/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "janusgate/access.h"

int jg_test_access(void);

/** @brief Verify fixed role boundaries required by backend authorization. */
static void test_roles(void **state)
{
    const uint32_t administrator =
        jg_access_role_permissions(JG_ACCESS_ROLE_ADMINISTRATOR);
    const uint32_t operator_permissions =
        jg_access_role_permissions(JG_ACCESS_ROLE_OPERATOR);
    const uint32_t auditor = jg_access_role_permissions(JG_ACCESS_ROLE_AUDITOR);

    (void)state;
    assert_int_equal(administrator, JG_ACCESS_PERMISSION_ALL);
    assert_true(jg_access_grants(operator_permissions, JG_ACCESS_POLICY_WRITE));
    assert_false(
        jg_access_grants(operator_permissions, JG_ACCESS_ACCESS_WRITE));
    assert_true(jg_access_grants(auditor, JG_ACCESS_AUDIT_READ));
    assert_false(jg_access_grants(auditor, JG_ACCESS_POLICY_WRITE));
    assert_int_equal(jg_access_role_permissions(JG_ACCESS_ROLE_NONE), 0U);
}

/** @brief Verify token scopes parse and format without semantic drift. */
static void test_scope_round_trip(void **state)
{
    static const char unordered[] = "operate,status:read,policy:read";
    static const char canonical[] = "status:read,policy:read,operate";
    char output[JG_ACCESS_SCOPE_TEXT_MAX + 1U];
    uint32_t permissions = 0U;

    (void)state;
    assert_int_equal(jg_access_scope_parse(unordered, &permissions), 0);
    assert_true(jg_access_grants(permissions, JG_ACCESS_STATUS_READ));
    assert_true(jg_access_grants(permissions, JG_ACCESS_OPERATE));
    assert_false(jg_access_grants(permissions, JG_ACCESS_POLICY_WRITE));
    assert_int_equal(
        jg_access_scope_format(permissions, output, sizeof(output)), 0);
    assert_string_equal(output, canonical);
}

/** @brief Verify rejection of ambiguous scopes and insufficient output. */
static void test_scope_validation(void **state)
{
    char output[8U] = "content";
    uint32_t permissions = 0U;

    (void)state;
    assert_int_equal(jg_access_scope_parse("", &permissions), -EINVAL);
    assert_int_equal(
        jg_access_scope_parse("status:read,status:read", &permissions),
        -EINVAL);
    assert_int_equal(jg_access_scope_parse("status:read ", &permissions),
                     -EINVAL);
    assert_int_equal(jg_access_scope_parse("unknown", &permissions), -EINVAL);
    assert_int_equal(jg_access_scope_format(JG_ACCESS_PERMISSION_ALL, output,
                                            sizeof(output)),
                     -ENOSPC);
    assert_string_equal(output, "");
    assert_false(jg_access_grants(JG_ACCESS_PERMISSION_ALL, 0U));
}

/** @brief Run the backend-authorization unit-test group. */
int jg_test_access(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_roles),
        cmocka_unit_test(test_scope_round_trip),
        cmocka_unit_test(test_scope_validation),
    };

    return cmocka_run_group_tests_name("access", tests, NULL, NULL);
}
