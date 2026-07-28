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

#include "janusgate/policy.h"

int jg_test_policy(void);

/** Construct a valid global rule with concise test defaults. */
static struct jg_policy_rule_input make_rule(uint64_t id,
                                             const char *domain,
                                             bool include_subdomains,
                                             enum jg_policy_effect effect,
                                             enum jg_policy_source source)
{
    struct jg_policy_rule_input rule;

    (void)memset(&rule, 0, sizeof(rule));
    rule.id = id;
    rule.domain = domain;
    rule.include_subdomains = include_subdomains;
    rule.effect = effect;
    rule.source = source;
    rule.scope.type = JG_POLICY_SCOPE_GLOBAL;
    rule.attribution = "unit test";
    return rule;
}

/** @brief Verify mandated rule precedence and client-scope selection. */
static void test_precedence_and_scopes(void **state)
{
    struct jg_policy_rule_input rules[7U];
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_policy_client client;
    struct jg_policy_match match;

    (void)state;
    rules[0] = make_rule(60U, "example.org", true, JG_POLICY_BLOCK,
                         JG_POLICY_SOURCE_BLOCKLIST);
    rules[1] = make_rule(50U, "ads.example.org", false, JG_POLICY_BLOCK,
                         JG_POLICY_SOURCE_EXPLICIT);
    rules[2] = make_rule(20U, "ads.example.org", false, JG_POLICY_ALLOW,
                         JG_POLICY_SOURCE_EXPLICIT);
    rules[2].scope.type = JG_POLICY_SCOPE_VLAN;
    rules[2].scope.value.vlan_id = 10U;
    rules[3] = make_rule(30U, "trusted.example.org", true, JG_POLICY_ALLOW,
                         JG_POLICY_SOURCE_EXPLICIT);
    rules[4] = make_rule(40U, "intranet.example.org", true, JG_POLICY_BLOCK,
                         JG_POLICY_SOURCE_EXPLICIT);
    rules[4].scope.type = JG_POLICY_SCOPE_IPV4;
    rules[4].scope.value.network.address[0] = 192U;
    rules[4].scope.value.network.address[1] = 0U;
    rules[4].scope.value.network.address[2] = 2U;
    rules[4].scope.value.network.address[3] = 99U;
    rules[4].scope.value.network.prefix_length = 24U;
    rules[5] = make_rule(11U, "locked.example.org", false, JG_POLICY_BLOCK,
                         JG_POLICY_SOURCE_EXPLICIT);
    rules[6] = make_rule(10U, "locked.example.org", false, JG_POLICY_ALLOW,
                         JG_POLICY_SOURCE_EMERGENCY);

    assert_int_equal(jg_policy_snapshot_build(rules, 7U, 8U, &snapshot), 0);
    assert_non_null(snapshot);

    (void)memset(&client, 0, sizeof(client));
    client.has_vlan = true;
    client.vlan_id = 10U;
    assert_int_equal(
        jg_policy_match_domain(snapshot, "ads.example.org", &client, &match),
        0);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    assert_int_equal(match.rule_id, 20U);

    client.vlan_id = 11U;
    assert_int_equal(
        jg_policy_match_domain(snapshot, "ads.example.org", &client, &match),
        0);
    assert_int_equal(match.effect, JG_POLICY_BLOCK);
    assert_int_equal(match.rule_id, 50U);

    assert_int_equal(jg_policy_match_domain(snapshot, "www.trusted.example.org",
                                            &client, &match),
                     0);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    assert_int_equal(match.rule_id, 30U);

    (void)memset(&client, 0, sizeof(client));
    client.address_family = JG_POLICY_ADDRESS_IPV4;
    client.address[0] = 192U;
    client.address[1] = 0U;
    client.address[2] = 2U;
    client.address[3] = 7U;
    assert_int_equal(jg_policy_match_domain(snapshot,
                                            "host.intranet.example.org",
                                            &client, &match),
                     0);
    assert_int_equal(match.rule_id, 40U);

    client.address[2] = 3U;
    assert_int_equal(jg_policy_match_domain(snapshot,
                                            "host.intranet.example.org",
                                            &client, &match),
                     0);
    assert_int_equal(match.rule_id, 60U);

    assert_int_equal(
        jg_policy_match_domain(snapshot, "locked.example.org", NULL, &match),
        0);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    assert_int_equal(match.source, JG_POLICY_SOURCE_EMERGENCY);
    assert_int_equal(match.rule_id, 10U);

    assert_int_equal(
        jg_policy_match_domain(snapshot, "unrelated.test", NULL, &match), 0);
    assert_false(match.matched);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    assert_int_equal(match.source, JG_POLICY_SOURCE_DEFAULT);
    assert_null(match.domain);

    jg_policy_snapshot_destroy(snapshot);
}

/** @brief Verify normalized deduplication and layout-independent checksums. */
static void test_deduplication_and_canonical_checksum(void **state)
{
    struct jg_policy_rule_input first[3U];
    struct jg_policy_rule_input second[3U];
    struct jg_policy_snapshot *left = NULL;
    struct jg_policy_snapshot *right = NULL;
    struct jg_policy_snapshot_info left_info;
    struct jg_policy_snapshot_info right_info;
    struct jg_policy_match match;

    (void)state;
    first[0] = make_rule(9U, "Example.ORG.", true, JG_POLICY_BLOCK,
                         JG_POLICY_SOURCE_EXPLICIT);
    first[1] = make_rule(4U, "example.org", true, JG_POLICY_BLOCK,
                         JG_POLICY_SOURCE_EXPLICIT);
    first[2] = make_rule(7U, "scoped.example", false, JG_POLICY_ALLOW,
                         JG_POLICY_SOURCE_EXPLICIT);
    first[2].scope.type = JG_POLICY_SCOPE_IPV4;
    first[2].scope.value.network.address[0] = 192U;
    first[2].scope.value.network.address[1] = 0U;
    first[2].scope.value.network.address[2] = 2U;
    first[2].scope.value.network.address[3] = 99U;
    first[2].scope.value.network.prefix_length = 24U;

    second[0] = first[2];
    second[0].scope.value.network.address[3] = 1U;
    second[1] = first[1];
    second[2] = first[0];

    assert_int_equal(jg_policy_snapshot_build(first, 3U, 1U, &left), 0);
    assert_int_equal(jg_policy_snapshot_build(second, 3U, 2U, &right), 0);
    assert_int_equal(jg_policy_snapshot_get_info(left, &left_info), 0);
    assert_int_equal(jg_policy_snapshot_get_info(right, &right_info), 0);
    assert_int_equal(left_info.rule_count, 2U);
    assert_int_equal(right_info.rule_count, 2U);
    assert_memory_equal(left_info.checksum, right_info.checksum,
                        JG_POLICY_CHECKSUM_SIZE);

    assert_int_equal(
        jg_policy_match_domain(left, "www.example.org", NULL, &match), 0);
    assert_int_equal(match.rule_id, 4U);
    assert_string_equal(match.domain, "example.org");

    jg_policy_snapshot_destroy(right);
    jg_policy_snapshot_destroy(left);
}

/** @brief Verify default allow behavior and invalid-rule rejection. */
static void test_empty_snapshot_and_invalid_rules(void **state)
{
    struct jg_policy_rule_input invalid = make_rule(
        1U, "example.org", false, JG_POLICY_ALLOW, JG_POLICY_SOURCE_BLOCKLIST);
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_policy_snapshot_info info;
    struct jg_policy_match match;

    (void)state;
    assert_int_equal(jg_policy_snapshot_build(NULL, 0U, 1U, &snapshot), 0);
    assert_int_equal(jg_policy_snapshot_get_info(snapshot, &info), 0);
    assert_int_equal(info.rule_count, 0U);
    assert_int_equal(
        jg_policy_match_domain(snapshot, "example.org", NULL, &match), 0);
    assert_false(match.matched);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    jg_policy_snapshot_destroy(snapshot);

    snapshot = NULL;
    assert_true(jg_policy_snapshot_build(&invalid, 1U, 1U, &snapshot) < 0);
    assert_null(snapshot);
    invalid = make_rule(1U, "example.org", false, JG_POLICY_BLOCK,
                        JG_POLICY_SOURCE_EXPLICIT);
    invalid.scope.type = JG_POLICY_SCOPE_IPV6;
    invalid.scope.value.network.prefix_length = 129U;
    assert_true(jg_policy_snapshot_build(&invalid, 1U, 1U, &snapshot) < 0);
    assert_null(snapshot);
}

/** @brief Verify strict isolation between DNS and visible-SNI rules. */
static void test_domain_target_isolation(void **state)
{
    struct jg_policy_rule_input rules[3U];
    struct jg_policy_rule_input invalid;
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_policy_match match;

    (void)state;
    rules[0] = make_rule(1U, "example.org", true, JG_POLICY_BLOCK,
                         JG_POLICY_SOURCE_BLOCKLIST);
    rules[1] = make_rule(2U, "resolver.example", true, JG_POLICY_BLOCK,
                         JG_POLICY_SOURCE_EXPLICIT);
    rules[1].target = JG_POLICY_DOMAIN_TLS_SNI;
    rules[2] = make_rule(3U, "resolver.example", true, JG_POLICY_ALLOW,
                         JG_POLICY_SOURCE_EXPLICIT);

    assert_int_equal(jg_policy_snapshot_build(rules, 3U, 1U, &snapshot), 0);
    assert_int_equal(
        jg_policy_match_domain(snapshot, "doh.resolver.example", NULL, &match),
        0);
    assert_true(match.matched);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    assert_int_equal(match.rule_id, 3U);
    assert_int_equal(jg_policy_match_visible_sni(
                         snapshot, "doh.resolver.example", NULL, &match),
                     0);
    assert_true(match.matched);
    assert_int_equal(match.effect, JG_POLICY_BLOCK);
    assert_int_equal(match.rule_id, 2U);
    assert_int_equal(
        jg_policy_match_visible_sni(snapshot, "ads.example.org", NULL, &match),
        0);
    assert_false(match.matched);
    assert_int_equal(match.effect, JG_POLICY_ALLOW);
    jg_policy_snapshot_destroy(snapshot);

    invalid = rules[0];
    invalid.target = JG_POLICY_DOMAIN_TLS_SNI;
    snapshot = NULL;
    assert_int_equal(jg_policy_snapshot_build(&invalid, 1U, 1U, &snapshot),
                     -EINVAL);
    assert_null(snapshot);
}

/** @brief Run the immutable policy snapshot and matcher test group. */
int jg_test_policy(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_precedence_and_scopes),
        cmocka_unit_test(test_deduplication_and_canonical_checksum),
        cmocka_unit_test(test_empty_snapshot_and_invalid_rules),
        cmocka_unit_test(test_domain_target_isolation),
    };

    return cmocka_run_group_tests_name("policy", tests, NULL, NULL);
}
