/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

#include "janusgate/domain.h"

int jg_test_domain(void);

/** @brief Verify ASCII case folding and trailing-root removal. */
static void test_ascii_normalization(void **state)
{
    char output[JG_DOMAIN_NAME_MAX + 1U];

    (void)state;
    assert_int_equal(
        jg_domain_normalize("Example.ORG.", output, sizeof(output)), 0);
    assert_string_equal(output, "example.org");
    assert_true(jg_domain_is_normalized("example.org"));
    assert_false(jg_domain_is_normalized("Example.org"));
}

/** @brief Verify IDNA2008 conversion of administrator Unicode input. */
static void test_idna_normalization(void **state)
{
    char output[JG_DOMAIN_NAME_MAX + 1U];

    (void)state;
    assert_int_equal(
        jg_domain_normalize("Bücher.example", output, sizeof(output)), 0);
    assert_string_equal(output, "xn--bcher-kva.example");
}

/** @brief Verify rejection of empty, malformed, and oversized domains. */
static void test_invalid_domains(void **state)
{
    char output[32U];

    (void)state;
    assert_true(jg_domain_normalize("", output, sizeof(output)) < 0);
    assert_true(jg_domain_normalize(".", output, sizeof(output)) < 0);
    assert_true(jg_domain_normalize("bad..example", output, sizeof(output)) <
                0);
    assert_true(jg_domain_normalize("-bad.example", output, sizeof(output)) <
                0);
    assert_true(jg_domain_normalize("toolong.example", output, 4U) < 0);
    assert_string_equal(output, "");
}

/** @brief Verify strict validation of already normalized policy names. */
static void test_normalized_validation(void **state)
{
    (void)state;
    assert_true(jg_domain_is_normalized("example.org"));
    assert_true(jg_domain_is_normalized("xn--bcher-kva.example"));
    assert_false(jg_domain_is_normalized("Example.org"));
    assert_false(jg_domain_is_normalized("example.org."));
    assert_false(jg_domain_is_normalized("bad..example"));
    assert_false(jg_domain_is_normalized("-bad.example"));
}

/** @brief Verify exact and label-boundary suffix matching semantics. */
static void test_label_boundary_matching(void **state)
{
    (void)state;
    assert_true(jg_domain_matches("example.org", "example.org", false));
    assert_true(jg_domain_matches("www.example.org", "example.org", true));
    assert_false(jg_domain_matches("www.example.org", "example.org", false));
    assert_false(jg_domain_matches("notexample.org", "example.org", true));
    assert_false(jg_domain_matches("Example.org", "example.org", true));
}

/** @brief Run the domain normalization and matching test group. */
int jg_test_domain(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ascii_normalization),
        cmocka_unit_test(test_idna_normalization),
        cmocka_unit_test(test_invalid_domains),
        cmocka_unit_test(test_normalized_validation),
        cmocka_unit_test(test_label_boundary_matching),
    };

    return cmocka_run_group_tests_name("domain", tests, NULL, NULL);
}
