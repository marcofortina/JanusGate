/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file database_policy_analysis.c
 * @brief Bounded policy-impact and conservative static rule analysis.
 */

#include "janusgate/database.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sqlite3.h>

#include "database_internal.h"

/** Largest signed identifier accepted by the persistent schema. */
#define POLICY_ANALYSIS_ID_MAX UINT64_C(9223372036854775807)

/** @brief Return the persistent dimension spelling. */
static const char *dimension_text(enum jg_policy_stats_dimension dimension)
{
    return dimension == JG_POLICY_STATS_DOMAIN
               ? "domain"
               : (dimension == JG_POLICY_STATS_DESTINATION ? "destination"
                                                           : NULL);
}

/** @brief Decode one optional lifetime-statistics row. */
static int load_lifetime_stats(struct jg_database *database,
                               enum jg_policy_stats_dimension dimension,
                               uint64_t rule_id,
                               struct jg_policy_rule_stats *stats,
                               bool *present)
{
    struct jg_policy_rule_stats candidate;
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_policy_rule_stats(
        database, dimension, rule_id - 1U, 1U, &candidate, &count, &has_more);

    (void)has_more;
    *present = result == 0 && count == 1U && candidate.rule_id == rule_id;
    if (*present) {
        *stats = candidate;
    }
    return result;
}

/** @brief Load retained aggregate cardinalities for one rule. */
static int load_detail_impact(struct jg_database *database,
                              const char *dimension,
                              uint64_t rule_id,
                              struct jg_policy_rule_impact *impact)
{
    static const char query[] =
        "SELECT count(DISTINCT printf('%d:%s:%s:%d',client_family,"
        "hex(client_address),hex(client_mac),vlan_id)),"
        "count(DISTINCT CASE WHEN vlan_id>=0 THEN vlan_id END),"
        "count(DISTINCT CASE WHEN domain<>'' THEN domain END),"
        "coalesce(sum(CASE WHEN path='dns' THEN match_count ELSE 0 END),0),"
        "coalesce(sum(CASE WHEN path='tls_sni' THEN match_count ELSE 0 END),0),"
        "coalesce(sum(CASE WHEN path='destination' THEN match_count ELSE 0 "
        "END),0) FROM policy_impact_buckets WHERE dimension=?1 AND rule_id=?2;";
    uint64_t *const values[6U] = {
        &impact->distinct_client_count, &impact->distinct_vlan_count,
        &impact->distinct_domain_count, &impact->dns_match_count,
        &impact->tls_sni_match_count,   &impact->destination_match_count,
    };
    sqlite3_stmt *statement = NULL;
    int status =
        sqlite3_prepare_v3(database->handle, query, -1,
                           SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, dimension, -1, SQLITE_STATIC);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)rule_id);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_ROW ? 0 : jg_database_sqlite_result(status);
    }
    for (size_t index = 0U; result == 0 && index < 6U; ++index) {
        result =
            jg_database_column_unsigned(statement, (int)index, values[index]);
    }
    if (result == 0 && sqlite3_step(statement) != SQLITE_DONE) {
        result = -EIO;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Decode one grouped client-impact row. */
static int decode_client_impact(sqlite3_stmt *statement,
                                struct jg_policy_client_impact *client)
{
    const int family = sqlite3_column_int(statement, 0);
    const int address_size = sqlite3_column_bytes(statement, 1);
    const int mac_size = sqlite3_column_bytes(statement, 2);
    const int vlan = sqlite3_column_int(statement, 3);
    const void *address = sqlite3_column_blob(statement, 1);
    const void *mac = sqlite3_column_blob(statement, 2);
    int result = 0;

    (void)memset(client, 0, sizeof(*client));
    if (!((family == 0 && address_size == 0) ||
          (family == 4 && address_size == 4) ||
          (family == 6 && address_size == 16)) ||
        (mac_size != 0 && mac_size != 6) || vlan < -1 || vlan > 4094) {
        return -EILSEQ;
    }
    client->address_family = (enum jg_policy_address_family)family;
    if (address_size > 0) {
        (void)memcpy(client->address, address, (size_t)address_size);
    }
    client->has_mac = mac_size == 6;
    if (client->has_mac) {
        (void)memcpy(client->mac, mac, 6U);
    }
    client->has_vlan = vlan >= 0;
    if (client->has_vlan) {
        client->vlan_id = (uint16_t)vlan;
    }
    result = jg_database_column_unsigned(statement, 4, &client->match_count);
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 5,
                                             &client->would_block_count);
    }
    if (result == 0) {
        result =
            jg_database_column_unsigned(statement, 6, &client->last_hit_at);
    }
    return result;
}

/** @brief Load the most active retained client identities for one rule. */
static int load_client_impacts(struct jg_database *database,
                               const char *dimension,
                               uint64_t rule_id,
                               struct jg_policy_client_impact *clients,
                               size_t limit,
                               size_t *count)
{
    static const char query[] =
        "SELECT client_family,client_address,client_mac,vlan_id,"
        "sum(match_count),sum(would_block_count),max(bucket_start) FROM "
        "policy_impact_buckets WHERE dimension=?1 AND rule_id=?2 GROUP BY "
        "client_family,client_address,client_mac,vlan_id ORDER BY "
        "sum(match_count) DESC,max(bucket_start) DESC LIMIT ?3;";
    sqlite3_stmt *statement = NULL;
    size_t used = 0U;
    int status =
        sqlite3_prepare_v3(database->handle, query, -1,
                           SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, dimension, -1, SQLITE_STATIC);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)rule_id);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, 3, (int)limit);
        }
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        result = decode_client_impact(statement, &clients[used]);
        ++used;
    }
    if (result == 0 && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *count = used;
    }
    return result;
}

/** @brief Load lifetime and retained-detail impact for one rule. */
int jg_database_load_policy_rule_impact(
    struct jg_database *database,
    enum jg_policy_stats_dimension dimension,
    uint64_t rule_id,
    struct jg_policy_rule_stats *stats,
    bool *has_stats,
    struct jg_policy_rule_impact *impact,
    struct jg_policy_client_impact *clients,
    size_t client_limit,
    size_t *client_count)
{
    const char *name = dimension_text(dimension);
    int result = 0;

    if (database == NULL || name == NULL || rule_id == 0U ||
        rule_id > POLICY_ANALYSIS_ID_MAX || stats == NULL ||
        has_stats == NULL || impact == NULL || clients == NULL ||
        client_limit == 0U || client_limit > JG_POLICY_ANALYSIS_RELATED_MAX ||
        client_count == NULL) {
        return -EINVAL;
    }
    (void)memset(stats, 0, sizeof(*stats));
    (void)memset(impact, 0, sizeof(*impact));
    *client_count = 0U;
    result =
        load_lifetime_stats(database, dimension, rule_id, stats, has_stats);
    if (result == 0) {
        result = load_detail_impact(database, name, rule_id, impact);
    }
    if (result == 0) {
        result = load_client_impacts(database, name, rule_id, clients,
                                     client_limit, client_count);
    }
    return result;
}

/** @brief Read one bounded identifier relation query. */
static int load_relation_ids(struct jg_database *database,
                             const char *query,
                             uint64_t rule_id,
                             uint64_t ids[JG_POLICY_ANALYSIS_RELATED_MAX],
                             size_t *count,
                             bool *truncated)
{
    sqlite3_stmt *statement = NULL;
    size_t used = 0U;
    int status =
        sqlite3_prepare_v3(database->handle, query, -1,
                           SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)rule_id);
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW) {
        uint64_t identifier = 0U;

        result = jg_database_column_unsigned(statement, 0, &identifier);
        if (result == 0 && identifier == 0U) {
            result = -EILSEQ;
        }
        if (result == 0 && used < JG_POLICY_ANALYSIS_RELATED_MAX) {
            ids[used] = identifier;
        }
        ++used;
    }
    if (result == 0 && status != SQLITE_DONE) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *truncated = *truncated || used > JG_POLICY_ANALYSIS_RELATED_MAX;
        *count = used > JG_POLICY_ANALYSIS_RELATED_MAX
                     ? JG_POLICY_ANALYSIS_RELATED_MAX
                     : used;
    }
    return result;
}

/** @brief Read whether one persistent rule exists and is enabled. */
static int load_rule_enabled(struct jg_database *database,
                             enum jg_policy_stats_dimension dimension,
                             uint64_t rule_id,
                             bool *enabled)
{
    const char *query = dimension == JG_POLICY_STATS_DOMAIN
                            ? "SELECT enabled FROM domain_rules WHERE id=?1;"
                            : "SELECT enabled FROM destination_rules WHERE "
                              "id=?1;";
    sqlite3_stmt *statement = NULL;
    int status =
        sqlite3_prepare_v3(database->handle, query, -1,
                           SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)rule_id);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result =
            status == SQLITE_ROW
                ? 0
                : (status == SQLITE_DONE ? -ENOENT
                                         : jg_database_sqlite_result(status));
    }
    if (result == 0) {
        const int value = sqlite3_column_int(statement, 0);

        if (value != 0 && value != 1) {
            result = -EILSEQ;
        } else {
            *enabled = value == 1;
        }
    }
    if (result == 0 && sqlite3_step(statement) != SQLITE_DONE) {
        result = -EIO;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Analyze exact and suffix relationships for one domain rule. */
static int analyze_domain_rule(struct jg_database *database,
                               uint64_t rule_id,
                               struct jg_policy_rule_relations *relations)
{
    static const char duplicates[] =
        "SELECT c.id FROM domain_rules t JOIN domain_rules c ON c.id<>t.id "
        "AND c.domain=t.domain AND c.match_type=t.match_type AND "
        "c.target=t.target AND c.effect=t.effect AND c.source=t.source AND "
        "c.enforcement=t.enforcement AND c.scope_type=t.scope_type AND "
        "c.scope_value IS t.scope_value AND c.prefix_length IS "
        "t.prefix_length AND c.vlan_id IS t.vlan_id AND c.attribution="
        "t.attribution AND c.group_id IS t.group_id AND "
        "c.blocklist_source_id IS t.blocklist_source_id AND "
        "c.enabled=t.enabled WHERE t.id=?1 ORDER BY c.id LIMIT 17;";
    static const char conflicts[] =
        "SELECT c.id FROM domain_rules t JOIN domain_rules c ON c.id<>t.id "
        "AND c.domain=t.domain AND c.match_type=t.match_type AND "
        "c.target=t.target AND c.scope_type=t.scope_type AND "
        "c.scope_value IS t.scope_value AND c.prefix_length IS "
        "t.prefix_length AND c.vlan_id IS t.vlan_id WHERE t.id=?1 AND "
        "t.enabled=1 AND c.enabled=1 AND c.effect<>t.effect ORDER BY c.id "
        "LIMIT 17;";
    static const char shadowing[] =
        "SELECT c.id FROM domain_rules t JOIN domain_rules c ON c.id<>t.id "
        "AND c.domain=t.domain AND c.match_type=t.match_type AND "
        "c.target=t.target AND c.scope_type=t.scope_type AND "
        "c.scope_value IS t.scope_value AND c.prefix_length IS "
        "t.prefix_length AND c.vlan_id IS t.vlan_id WHERE t.id=?1 AND "
        "t.enabled=1 AND c.enabled=1 AND ((CASE WHEN c.source='emergency' "
        "THEN 6 WHEN c.source='explicit' AND c.effect='allow' AND "
        "c.scope_type<>'global' THEN 5 WHEN c.source='explicit' AND "
        "c.effect='allow' THEN 4 WHEN c.source='explicit' AND "
        "c.effect='block' AND c.scope_type<>'global' THEN 3 WHEN "
        "c.source='explicit' AND c.effect='block' THEN 2 ELSE 1 END) > "
        "(CASE WHEN t.source='emergency' THEN 6 WHEN t.source='explicit' "
        "AND t.effect='allow' AND t.scope_type<>'global' THEN 5 WHEN "
        "t.source='explicit' AND t.effect='allow' THEN 4 WHEN "
        "t.source='explicit' AND t.effect='block' AND "
        "t.scope_type<>'global' THEN 3 WHEN t.source='explicit' AND "
        "t.effect='block' THEN 2 ELSE 1 END) OR ((CASE WHEN "
        "c.source='emergency' THEN 6 WHEN c.source='explicit' AND "
        "c.effect='allow' AND c.scope_type<>'global' THEN 5 WHEN "
        "c.source='explicit' AND c.effect='allow' THEN 4 WHEN "
        "c.source='explicit' AND c.effect='block' AND "
        "c.scope_type<>'global' THEN 3 WHEN c.source='explicit' AND "
        "c.effect='block' THEN 2 ELSE 1 END)=(CASE WHEN "
        "t.source='emergency' THEN 6 WHEN t.source='explicit' AND "
        "t.effect='allow' AND t.scope_type<>'global' THEN 5 WHEN "
        "t.source='explicit' AND t.effect='allow' THEN 4 WHEN "
        "t.source='explicit' AND t.effect='block' AND "
        "t.scope_type<>'global' THEN 3 WHEN t.source='explicit' AND "
        "t.effect='block' THEN 2 ELSE 1 END) AND c.id<t.id)) ORDER BY c.id "
        "LIMIT 17;";
    static const char exceptions[] =
        "SELECT c.id FROM domain_rules t JOIN domain_rules c ON c.id<>t.id "
        "AND c.target=t.target AND c.scope_type=t.scope_type AND "
        "c.scope_value IS t.scope_value AND c.prefix_length IS "
        "t.prefix_length AND c.vlan_id IS t.vlan_id WHERE t.id=?1 AND "
        "t.enabled=1 AND c.enabled=1 AND c.effect<>t.effect AND ((t.effect="
        "'allow' AND c.effect='block' AND c.match_type='suffix' AND "
        "(t.domain=c.domain OR (length(t.domain)>length(c.domain) AND "
        "substr(t.domain,-length(c.domain)-1)='.'||c.domain))) OR "
        "(t.effect='block' AND c.effect='allow' AND t.match_type='suffix' "
        "AND (c.domain=t.domain OR (length(c.domain)>length(t.domain) AND "
        "substr(c.domain,-length(t.domain)-1)='.'||t.domain)))) ORDER BY c.id "
        "LIMIT 17;";
    int result = load_relation_ids(
        database, duplicates, rule_id, relations->duplicate_ids,
        &relations->duplicate_count, &relations->truncated);

    if (result == 0) {
        result = load_relation_ids(
            database, conflicts, rule_id, relations->conflict_ids,
            &relations->conflict_count, &relations->truncated);
    }
    if (result == 0) {
        result = load_relation_ids(
            database, shadowing, rule_id, relations->shadowing_ids,
            &relations->shadowing_count, &relations->truncated);
    }
    if (result == 0) {
        result = load_relation_ids(
            database, exceptions, rule_id, relations->allow_exception_ids,
            &relations->allow_exception_count, &relations->truncated);
    }
    return result;
}

/** @brief Analyze exact relationships for one destination rule. */
static int analyze_destination_rule(struct jg_database *database,
                                    uint64_t rule_id,
                                    struct jg_policy_rule_relations *relations)
{
    static const char exact_predicate[] =
        "c.protocol=t.protocol AND c.family IS t.family AND c.address IS "
        "t.address AND c.prefix_length IS t.prefix_length AND c.port IS "
        "t.port AND c.scope_type=t.scope_type AND c.scope_value IS "
        "t.scope_value AND c.scope_prefix_length IS t.scope_prefix_length "
        "AND c.scope_vlan_id IS t.scope_vlan_id";
    char duplicates[1536U];
    char conflicts[1280U];
    char shadowing[3072U];
    int written = snprintf(
        duplicates, sizeof(duplicates),
        "SELECT c.id FROM destination_rules t JOIN destination_rules c ON "
        "c.id<>t.id AND %s AND c.effect=t.effect AND c.source=t.source AND "
        "c.enforcement=t.enforcement AND c.attribution=t.attribution AND "
        "c.group_id IS t.group_id AND c.enabled=t.enabled WHERE t.id=?1 "
        "ORDER BY c.id LIMIT 17;",
        exact_predicate);
    int result = 0;

    if (written <= 0 || (size_t)written >= sizeof(duplicates)) {
        return -ENOMEM;
    }
    written = snprintf(
        conflicts, sizeof(conflicts),
        "SELECT c.id FROM destination_rules t JOIN destination_rules c ON "
        "c.id<>t.id AND %s WHERE t.id=?1 AND t.enabled=1 AND c.enabled=1 "
        "AND c.effect<>t.effect ORDER BY c.id LIMIT 17;",
        exact_predicate);
    if (written <= 0 || (size_t)written >= sizeof(conflicts)) {
        return -ENOMEM;
    }
    written = snprintf(
        shadowing, sizeof(shadowing),
        "SELECT c.id FROM destination_rules t JOIN destination_rules c ON "
        "c.id<>t.id AND %s WHERE t.id=?1 AND t.enabled=1 AND c.enabled=1 "
        "AND ((CASE WHEN c.source='emergency' THEN 6 WHEN "
        "c.source='explicit' AND c.effect='allow' AND "
        "c.scope_type<>'global' THEN 5 WHEN c.source='explicit' AND "
        "c.effect='allow' THEN 4 WHEN c.source='explicit' AND "
        "c.effect='block' AND c.scope_type<>'global' THEN 3 WHEN "
        "c.source='explicit' AND c.effect='block' THEN 2 ELSE 1 END) > "
        "(CASE WHEN t.source='emergency' THEN 6 WHEN t.source='explicit' "
        "AND t.effect='allow' AND t.scope_type<>'global' THEN 5 WHEN "
        "t.source='explicit' AND t.effect='allow' THEN 4 WHEN "
        "t.source='explicit' AND t.effect='block' AND "
        "t.scope_type<>'global' THEN 3 WHEN t.source='explicit' AND "
        "t.effect='block' THEN 2 ELSE 1 END) OR ((CASE WHEN "
        "c.source='emergency' THEN 6 WHEN c.source='explicit' AND "
        "c.effect='allow' AND c.scope_type<>'global' THEN 5 WHEN "
        "c.source='explicit' AND c.effect='allow' THEN 4 WHEN "
        "c.source='explicit' AND c.effect='block' AND "
        "c.scope_type<>'global' THEN 3 WHEN c.source='explicit' AND "
        "c.effect='block' THEN 2 ELSE 1 END)=(CASE WHEN "
        "t.source='emergency' THEN 6 WHEN t.source='explicit' AND "
        "t.effect='allow' AND t.scope_type<>'global' THEN 5 WHEN "
        "t.source='explicit' AND t.effect='allow' THEN 4 WHEN "
        "t.source='explicit' AND t.effect='block' AND "
        "t.scope_type<>'global' THEN 3 WHEN t.source='explicit' AND "
        "t.effect='block' THEN 2 ELSE 1 END) AND c.id<t.id)) ORDER BY c.id "
        "LIMIT 17;",
        exact_predicate);
    if (written <= 0 || (size_t)written >= sizeof(shadowing)) {
        return -ENOMEM;
    }
    result = load_relation_ids(
        database, duplicates, rule_id, relations->duplicate_ids,
        &relations->duplicate_count, &relations->truncated);
    if (result == 0) {
        result = load_relation_ids(
            database, conflicts, rule_id, relations->conflict_ids,
            &relations->conflict_count, &relations->truncated);
    }
    if (result == 0) {
        result = load_relation_ids(
            database, shadowing, rule_id, relations->shadowing_ids,
            &relations->shadowing_count, &relations->truncated);
    }
    if (result == 0) {
        relations->allow_exception_count = relations->conflict_count;
        (void)memcpy(relations->allow_exception_ids, relations->conflict_ids,
                     relations->conflict_count * sizeof(uint64_t));
    }
    return result;
}

/** @brief Analyze provable static relationships for one persistent rule. */
int jg_database_analyze_policy_rule(struct jg_database *database,
                                    enum jg_policy_stats_dimension dimension,
                                    uint64_t rule_id,
                                    struct jg_policy_rule_relations *relations)
{
    bool enabled = false;
    int result = 0;

    if (database == NULL || dimension_text(dimension) == NULL ||
        rule_id == 0U || rule_id > POLICY_ANALYSIS_ID_MAX ||
        relations == NULL) {
        return -EINVAL;
    }
    (void)memset(relations, 0, sizeof(*relations));
    result = load_rule_enabled(database, dimension, rule_id, &enabled);
    if (result == 0) {
        relations->disabled = !enabled;
        result = dimension == JG_POLICY_STATS_DOMAIN
                     ? analyze_domain_rule(database, rule_id, relations)
                     : analyze_destination_rule(database, rule_id, relations);
    }
    if (result == 0) {
        relations->unreachable = relations->disabled;
        for (size_t index = 0U;
             !relations->unreachable && index < relations->duplicate_count;
             ++index) {
            relations->unreachable = relations->duplicate_ids[index] < rule_id;
        }
    }
    return result;
}
