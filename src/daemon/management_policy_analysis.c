/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_policy_analysis.c
 * @brief Read-only policy-impact and static-analysis API.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <jansson.h>

#include "janusgate/access.h"
#include "janusgate/database.h"

/** Minimal persistent rule metadata needed by one analysis response. */
struct analysis_rule {
    enum jg_policy_effect effect;
    enum jg_policy_enforcement enforcement;
    enum jg_policy_source source;
    bool enabled;
};

/** @brief Return the external policy-action spelling. */
static const char *effect_name(enum jg_policy_effect effect)
{
    return effect == JG_POLICY_ALLOW
               ? "allow"
               : (effect == JG_POLICY_BLOCK ? "block" : NULL);
}

/** @brief Return the external enforcement spelling. */
static const char *enforcement_name(enum jg_policy_enforcement enforcement)
{
    return enforcement == JG_POLICY_ENFORCE
               ? "enforce"
               : (enforcement == JG_POLICY_OBSERVE ? "observe" : NULL);
}

/** @brief Return the external policy-source spelling. */
static const char *source_name(enum jg_policy_source source)
{
    switch (source) {
    case JG_POLICY_SOURCE_BLOCKLIST:
        return "blocklist";
    case JG_POLICY_SOURCE_EXPLICIT:
        return "explicit";
    case JG_POLICY_SOURCE_EMERGENCY:
        return "emergency";
    default:
        return NULL;
    }
}

/** @brief Load one exact persistent rule into common metadata. */
static int load_analysis_rule(struct jg_database *database,
                              enum jg_policy_stats_dimension dimension,
                              uint64_t rule_id,
                              struct analysis_rule *rule)
{
    size_t count = 0U;
    bool has_more = false;
    int result = 0;

    if (dimension == JG_POLICY_STATS_DOMAIN) {
        struct jg_database_domain_rule record;

        result = jg_database_list_domain_rules(database, rule_id - 1U, 1U,
                                               &record, &count, &has_more);
        if (result == 0 && (count != 1U || record.id != rule_id)) {
            result = -ENOENT;
        }
        if (result == 0) {
            rule->effect = record.effect;
            rule->enforcement = record.enforcement;
            rule->source = record.source;
            rule->enabled = record.enabled;
        }
    } else {
        struct jg_database_destination_rule record;

        result = jg_database_list_destination_rules(database, rule_id - 1U, 1U,
                                                    &record, &count, &has_more);
        if (result == 0 && (count != 1U || record.id != rule_id)) {
            result = -ENOENT;
        }
        if (result == 0) {
            rule->effect = record.effect;
            rule->enforcement = record.enforcement;
            rule->source = record.source;
            rule->enabled = record.enabled;
        }
    }
    (void)has_more;
    return result;
}

/** @brief Convert one bounded identifier collection to JSON. */
static json_t *identifier_array(const uint64_t *identifiers, size_t count)
{
    json_t *values = json_array();

    if (values == NULL) {
        return NULL;
    }
    for (size_t index = 0U; index < count; ++index) {
        if (json_array_append_new(
                values, json_integer((json_int_t)identifiers[index])) != 0) {
            json_decref(values);
            return NULL;
        }
    }
    return values;
}

/** @brief Convert one retained client-impact record to JSON. */
static json_t *client_impact_json(const struct jg_policy_client_impact *client)
{
    char address[INET6_ADDRSTRLEN];
    char mac[18U];
    json_t *body = json_object();
    const char *address_text = NULL;
    int written = 0;

    if (client->address_family != JG_POLICY_ADDRESS_NONE) {
        const int family = client->address_family == JG_POLICY_ADDRESS_IPV4
                               ? AF_INET
                               : AF_INET6;

        address_text =
            inet_ntop(family, client->address, address, sizeof(address));
    }
    if (client->has_mac) {
        written = snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                           client->mac[0U], client->mac[1U], client->mac[2U],
                           client->mac[3U], client->mac[4U], client->mac[5U]);
    }
    if (body == NULL ||
        (client->address_family != JG_POLICY_ADDRESS_NONE &&
         address_text == NULL) ||
        (client->has_mac && (written <= 0 || (size_t)written >= sizeof(mac))) ||
        json_object_set_new(body, "address",
                            address_text == NULL
                                ? json_null()
                                : json_string(address_text)) != 0 ||
        json_object_set_new(body, "mac",
                            client->has_mac ? json_string(mac) : json_null()) !=
            0 ||
        json_object_set_new(body, "vlan",
                            client->has_vlan
                                ? json_integer((json_int_t)client->vlan_id)
                                : json_null()) != 0 ||
        set_counter(body, "match_count", client->match_count) != 0 ||
        set_counter(body, "would_block_count", client->would_block_count) !=
            0 ||
        set_optional_timestamp(body, "last_hit_at", client->last_hit_at) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Serialize lifetime counters and effective outcomes. */
static json_t *lifetime_json(const struct jg_policy_rule_stats *stats,
                             bool present)
{
    json_t *body = json_object();
    const uint64_t observed =
        present ? stats->would_block_count - stats->enforced_block_count : 0U;

    if (body == NULL ||
        set_counter(body, "match_count", present ? stats->match_count : 0U) !=
            0 ||
        set_counter(body, "decision_count",
                    present ? stats->decision_count : 0U) != 0 ||
        set_counter(body, "would_block_count",
                    present ? stats->would_block_count : 0U) != 0 ||
        set_counter(body, "enforced_block_count",
                    present ? stats->enforced_block_count : 0U) != 0 ||
        set_counter(body, "observed_block_count", observed) != 0 ||
        set_counter(body, "allow_decision_count",
                    present ? stats->allow_decision_count : 0U) != 0 ||
        set_counter(body, "shadowed_count",
                    present ? stats->shadowed_count : 0U) != 0 ||
        set_optional_timestamp(body, "first_hit_at",
                               present ? stats->first_hit_at : 0U) != 0 ||
        set_optional_timestamp(body, "last_hit_at",
                               present ? stats->last_hit_at : 0U) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Serialize retained cardinalities and inspection-path counts. */
static json_t *retained_impact_json(const struct jg_policy_rule_impact *impact)
{
    json_t *body = json_object();

    if (body == NULL ||
        set_counter(body, "distinct_client_count",
                    impact->distinct_client_count) != 0 ||
        set_counter(body, "distinct_vlan_count", impact->distinct_vlan_count) !=
            0 ||
        set_counter(body, "distinct_domain_count",
                    impact->distinct_domain_count) != 0 ||
        set_counter(body, "dns_match_count", impact->dns_match_count) != 0 ||
        set_counter(body, "tls_sni_match_count", impact->tls_sni_match_count) !=
            0 ||
        set_counter(body, "destination_match_count",
                    impact->destination_match_count) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Serialize conservative static-analysis findings. */
static json_t *relations_json(const struct jg_policy_rule_relations *relations)
{
    json_t *duplicates =
        identifier_array(relations->duplicate_ids, relations->duplicate_count);
    json_t *conflicts =
        identifier_array(relations->conflict_ids, relations->conflict_count);
    json_t *shadowed_by =
        identifier_array(relations->shadowing_ids, relations->shadowing_count);
    json_t *exceptions = identifier_array(relations->allow_exception_ids,
                                          relations->allow_exception_count);
    json_t *body = json_object();

    if (duplicates == NULL || conflicts == NULL || shadowed_by == NULL ||
        exceptions == NULL || body == NULL ||
        json_object_set(body, "duplicates", duplicates) != 0 ||
        json_object_set(body, "conflicts", conflicts) != 0 ||
        json_object_set(body, "shadowed_by", shadowed_by) != 0 ||
        json_object_set(body, "allow_exceptions", exceptions) != 0 ||
        json_object_set_new(body, "unreachable",
                            json_boolean(relations->unreachable)) != 0 ||
        json_object_set_new(body, "disabled",
                            json_boolean(relations->disabled)) != 0 ||
        json_object_set_new(body, "truncated",
                            json_boolean(relations->truncated)) != 0) {
        json_decref(body);
        body = NULL;
    }
    json_decref(exceptions);
    json_decref(shadowed_by);
    json_decref(conflicts);
    json_decref(duplicates);
    return body;
}

/** @brief Return impact and conservative findings for one policy rule. */
int handle_policy_rule_analysis(struct jg_management *management,
                                const struct management_request *request,
                                const struct remote_address *remote,
                                enum jg_policy_stats_dimension dimension,
                                uint64_t rule_id,
                                uint64_t now,
                                uint8_t *output,
                                size_t output_size,
                                size_t *written)
{
    struct authenticated_actor actor;
    struct analysis_rule rule;
    struct jg_policy_rule_stats stats;
    struct jg_policy_rule_impact impact;
    struct jg_policy_client_impact clients[JG_POLICY_ANALYSIS_RELATED_MAX];
    struct jg_policy_rule_relations relations;
    struct jg_policy_traffic_stats traffic;
    const char *dimension_name =
        dimension == JG_POLICY_STATS_DOMAIN ? "domain" : "destination";
    const char *action = NULL;
    const char *enforcement = NULL;
    const char *source = NULL;
    json_t *body = NULL;
    json_t *lifetime = NULL;
    json_t *retained = NULL;
    json_t *findings = NULL;
    json_t *client_items = NULL;
    size_t client_count = 0U;
    bool has_stats = false;
    bool has_traffic = false;
    bool cleanup_candidate = false;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_POLICY_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "Policy analysis does not accept parameters.",
                             request->request_id, output, output_size, written);
    }
    result =
        load_analysis_rule(management->database, dimension, rule_id, &rule);
    if (result == -ENOENT) {
        return respond_error(404, "rule_not_found",
                             "The policy rule does not exist.",
                             request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = jg_database_load_policy_rule_impact(
            management->database, dimension, rule_id, &stats, &has_stats,
            &impact, clients, JG_POLICY_ANALYSIS_RELATED_MAX, &client_count);
    }
    if (result == 0) {
        result = jg_database_analyze_policy_rule(
            management->database, dimension, rule_id, &relations);
    }
    if (result == 0) {
        result = jg_database_load_policy_traffic_stats(management->database,
                                                       &traffic);
        has_traffic = result == 0;
        if (result == -ENOENT) {
            result = 0;
        }
    }
    if (result != 0) {
        return respond_error(500, "policy_analysis_unavailable",
                             "The policy analysis could not be completed.",
                             request->request_id, output, output_size, written);
    }
    action = effect_name(rule.effect);
    enforcement = enforcement_name(rule.enforcement);
    source = source_name(rule.source);
    cleanup_candidate =
        !has_stats && rule.enabled && rule.source == JG_POLICY_SOURCE_EXPLICIT;
    body = json_object();
    lifetime = lifetime_json(&stats, has_stats);
    retained = retained_impact_json(&impact);
    findings = relations_json(&relations);
    client_items = json_array();
    if (action == NULL || enforcement == NULL || source == NULL ||
        body == NULL || lifetime == NULL || retained == NULL ||
        findings == NULL || client_items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < client_count; ++index) {
        json_t *client = client_impact_json(&clients[index]);

        if (client == NULL ||
            json_array_append_new(client_items, client) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "dimension", json_string(dimension_name)) !=
             0 ||
         json_object_set_new(body, "rule_id",
                             json_integer((json_int_t)rule_id)) != 0 ||
         json_object_set_new(body, "configured_action", json_string(action)) !=
             0 ||
         json_object_set_new(body, "configured_enforcement",
                             json_string(enforcement)) != 0 ||
         json_object_set_new(body, "source", json_string(source)) != 0 ||
         json_object_set_new(body, "enabled", json_boolean(rule.enabled)) !=
             0 ||
         json_object_set(body, "lifetime", lifetime) != 0 ||
         json_object_set(body, "retained_detail", retained) != 0 ||
         json_object_set(body, "clients", client_items) != 0 ||
         json_object_set(body, "findings", findings) != 0 ||
         json_object_set_new(
             body, "possible_false_positive",
             json_boolean(has_stats && stats.would_block_count >
                                           stats.enforced_block_count)) != 0 ||
         json_object_set_new(body, "cleanup_candidate",
                             json_boolean(cleanup_candidate)) != 0 ||
         json_object_set_new(body, "cleanup_reason",
                             cleanup_candidate ? json_string("never_used")
                                               : json_null()) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0 && has_traffic && traffic.request_count > 0U) {
        const double percentage =
            100.0 * (double)stats.match_count / (double)traffic.request_count;

        if (json_object_set_new(body, "traffic_percentage",
                                json_real(percentage)) != 0) {
            result = -ENOMEM;
        }
    } else if (result == 0 && json_object_set_new(body, "traffic_percentage",
                                                  json_null()) != 0) {
        result = -ENOMEM;
    }
    json_decref(client_items);
    json_decref(findings);
    json_decref(retained);
    json_decref(lifetime);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}
