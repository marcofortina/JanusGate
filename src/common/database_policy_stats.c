/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/database.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sqlite3.h>

#include "database_internal.h"

/** Largest signed value representable by persistent statistic counters. */
#define POLICY_STATS_COUNTER_MAX UINT64_C(9223372036854775807)

/** @brief Return the persistent name for one statistics dimension. */
static const char *dimension_text(enum jg_policy_stats_dimension dimension)
{
    switch (dimension) {
    case JG_POLICY_STATS_DOMAIN:
        return "domain";
    case JG_POLICY_STATS_DESTINATION:
        return "destination";
    default:
        return NULL;
    }
}

/** @brief Decode one persistent statistics dimension. */
static int decode_dimension(const char *text,
                            enum jg_policy_stats_dimension *dimension)
{
    if (strcmp(text, "domain") == 0) {
        *dimension = JG_POLICY_STATS_DOMAIN;
        return 0;
    }
    if (strcmp(text, "destination") == 0) {
        *dimension = JG_POLICY_STATS_DESTINATION;
        return 0;
    }
    return -EILSEQ;
}

/** @brief Return the persistent name for one traffic inspection path. */
static const char *path_text(enum jg_policy_stats_path path)
{
    switch (path) {
    case JG_POLICY_STATS_DNS:
        return "dns";
    case JG_POLICY_STATS_TLS_SNI:
        return "tls_sni";
    case JG_POLICY_STATS_NETWORK_DESTINATION:
        return "destination";
    default:
        return NULL;
    }
}

/** @brief Validate client identity before persistent encoding. */
static bool client_valid(const struct jg_policy_client *client)
{
    return client != NULL &&
           (client->address_family == JG_POLICY_ADDRESS_NONE ||
            client->address_family == JG_POLICY_ADDRESS_IPV4 ||
            client->address_family == JG_POLICY_ADDRESS_IPV6) &&
           (!client->has_vlan || client->vlan_id <= 4094U);
}

/** @brief Validate one request-level traffic sample. */
static bool traffic_sample_valid(const struct jg_policy_traffic_sample *sample)
{
    return sample != NULL && sample->occurred_at <= POLICY_STATS_COUNTER_MAX &&
           path_text(sample->path) != NULL &&
           (!sample->would_block || sample->matched) &&
           (!sample->enforced_block || sample->would_block);
}

/** @brief Validate one matching-rule impact sample. */
static bool rule_sample_valid(const struct jg_policy_rule_sample *sample)
{
    const bool domain_dimension =
        sample != NULL && sample->dimension == JG_POLICY_STATS_DOMAIN;
    const bool destination_dimension =
        sample != NULL && sample->dimension == JG_POLICY_STATS_DESTINATION;

    if (sample == NULL || (!domain_dimension && !destination_dimension) ||
        sample->rule_id == 0U || sample->rule_id > POLICY_STATS_COUNTER_MAX ||
        sample->occurred_at > POLICY_STATS_COUNTER_MAX ||
        path_text(sample->path) == NULL || !client_valid(&sample->client) ||
        sample->domain == NULL || sample->decision == sample->shadowed ||
        (sample->enforced_block &&
         (!sample->decision || !sample->would_block)) ||
        (sample->allow_decision && (!sample->decision || sample->would_block ||
                                    sample->enforced_block))) {
        return false;
    }
    if (domain_dimension) {
        return jg_domain_is_normalized(sample->domain) &&
               ((sample->path == JG_POLICY_STATS_DNS &&
                 sample->query_type != 0U) ||
                (sample->path == JG_POLICY_STATS_TLS_SNI &&
                 sample->query_type == 0U));
    }
    return sample->path == JG_POLICY_STATS_NETWORK_DESTINATION &&
           sample->domain[0U] == '\0' && sample->query_type == 0U;
}

/** @brief Reset a prepared write statement after one completed row. */
static int reset_statement(sqlite3_stmt *statement)
{
    int status = sqlite3_reset(statement);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_clear_bindings(statement);
        result = jg_database_sqlite_result(status);
    }
    return result;
}

/** @brief Execute one fully bound write statement and prepare its reuse. */
static int execute_write(sqlite3_stmt *statement)
{
    const int status = sqlite3_step(statement);

    if (status != SQLITE_DONE) {
        return jg_database_sqlite_result(status);
    }
    return reset_statement(statement);
}

/** @brief Bind one validated traffic sample to both traffic statements. */
static int bind_traffic(sqlite3_stmt *lifetime,
                        sqlite3_stmt *detail,
                        const struct jg_policy_traffic_sample *sample)
{
    const sqlite3_int64 occurred_at = (sqlite3_int64)sample->occurred_at;
    const sqlite3_int64 bucket_start = occurred_at - occurred_at % 3600;
    const char *path = path_text(sample->path);
    int status = sqlite3_bind_int(lifetime, 1, sample->matched ? 1 : 0);

    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(lifetime, 2, sample->would_block ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(lifetime, 3, sample->enforced_block ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(lifetime, 4, occurred_at);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(detail, 1, bucket_start);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_text(detail, 2, path, -1, SQLITE_STATIC);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(detail, 3, sample->matched ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(detail, 4, sample->would_block ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(detail, 5, sample->enforced_block ? 1 : 0);
    }
    return jg_database_sqlite_result(status);
}

/** @brief Bind one validated matching-rule sample to both rule statements. */
static int bind_rule(sqlite3_stmt *lifetime,
                     sqlite3_stmt *detail,
                     const struct jg_policy_rule_sample *sample)
{
    static const uint8_t empty_blob = 0U;
    const sqlite3_int64 occurred_at = (sqlite3_int64)sample->occurred_at;
    const sqlite3_int64 bucket_start = occurred_at - occurred_at % 3600;
    const char *dimension = dimension_text(sample->dimension);
    const char *path = path_text(sample->path);
    const int address_size =
        sample->client.address_family == JG_POLICY_ADDRESS_IPV4
            ? 4
            : (sample->client.address_family == JG_POLICY_ADDRESS_IPV6 ? 16
                                                                       : 0);
    const void *address =
        address_size == 0 ? &empty_blob : sample->client.address;
    const void *mac = sample->client.has_mac ? sample->client.mac : &empty_blob;
    const int mac_size = sample->client.has_mac ? 6 : 0;
    const int vlan_id =
        sample->client.has_vlan ? (int)sample->client.vlan_id : -1;
    int status = sqlite3_bind_text(lifetime, 1, dimension, -1, SQLITE_STATIC);

    if (status == SQLITE_OK) {
        status =
            sqlite3_bind_int64(lifetime, 2, (sqlite3_int64)sample->rule_id);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(lifetime, 3, sample->decision ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(lifetime, 4, sample->would_block ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(lifetime, 5, sample->enforced_block ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(lifetime, 6, sample->allow_decision ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(lifetime, 7, sample->shadowed ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(lifetime, 8, occurred_at);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(detail, 1, bucket_start);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_text(detail, 2, dimension, -1, SQLITE_STATIC);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int64(detail, 3, (sqlite3_int64)sample->rule_id);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_text(detail, 4, path, -1, SQLITE_STATIC);
    }
    if (status == SQLITE_OK) {
        status =
            sqlite3_bind_int(detail, 5, (int)sample->client.address_family);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_blob(detail, 6, address, address_size,
                                   SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_blob(detail, 7, mac, mac_size, SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(detail, 8, vlan_id);
    }
    if (status == SQLITE_OK) {
        status =
            sqlite3_bind_text(detail, 9, sample->domain, -1, SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(detail, 10, (int)sample->query_type);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(detail, 11, sample->decision ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(detail, 12, sample->would_block ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(detail, 13, sample->enforced_block ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(detail, 14, sample->allow_decision ? 1 : 0);
    }
    if (status == SQLITE_OK) {
        status = sqlite3_bind_int(detail, 15, sample->shadowed ? 1 : 0);
    }
    return jg_database_sqlite_result(status);
}

/** @brief Finalize every statement in one policy-statistics write batch. */
static int finalize_writes(sqlite3_stmt *statements[4U], int result)
{
    size_t index = 0U;

    for (index = 0U; index < 4U; ++index) {
        if (statements[index] != NULL) {
            const int status = sqlite3_finalize(statements[index]);

            if (result == 0) {
                result = jg_database_sqlite_result(status);
            }
        }
    }
    return result;
}

/** @brief Atomically add bounded request and matching-rule sample batches. */
int jg_database_record_policy_stats(
    struct jg_database *database,
    const struct jg_policy_traffic_sample *traffic,
    size_t traffic_count,
    const struct jg_policy_rule_sample *rules,
    size_t rule_count)
{
    static const char traffic_lifetime[] =
        "INSERT INTO policy_traffic_stats(id,request_count,matched_count,"
        "would_block_count,enforced_block_count,first_request_at,"
        "last_request_at) VALUES(1,1,?1,?2,?3,?4,?4) ON CONFLICT(id) DO "
        "UPDATE SET request_count=CASE WHEN request_count<"
        "9223372036854775807 THEN request_count+1 ELSE request_count END,"
        "matched_count=CASE WHEN excluded.matched_count=1 AND matched_count<"
        "9223372036854775807 THEN matched_count+1 ELSE matched_count END,"
        "would_block_count=CASE WHEN excluded.would_block_count=1 AND "
        "would_block_count<9223372036854775807 THEN would_block_count+1 ELSE "
        "would_block_count END,enforced_block_count=CASE WHEN "
        "excluded.enforced_block_count=1 AND enforced_block_count<"
        "9223372036854775807 THEN enforced_block_count+1 ELSE "
        "enforced_block_count END,first_request_at=min(first_request_at,"
        "excluded.first_request_at),last_request_at=max(last_request_at,"
        "excluded.last_request_at);";
    static const char traffic_detail[] =
        "INSERT INTO policy_traffic_buckets(bucket_start,path,request_count,"
        "matched_count,would_block_count,enforced_block_count) VALUES(?1,?2,"
        "1,?3,?4,?5) ON CONFLICT(bucket_start,path) DO UPDATE SET "
        "request_count=CASE WHEN request_count<9223372036854775807 THEN "
        "request_count+1 ELSE request_count END,matched_count=CASE WHEN "
        "excluded.matched_count=1 AND matched_count<9223372036854775807 THEN "
        "matched_count+1 ELSE matched_count END,would_block_count=CASE WHEN "
        "excluded.would_block_count=1 AND would_block_count<"
        "9223372036854775807 THEN would_block_count+1 ELSE would_block_count "
        "END,enforced_block_count=CASE WHEN excluded.enforced_block_count=1 "
        "AND enforced_block_count<9223372036854775807 THEN "
        "enforced_block_count+1 ELSE enforced_block_count END;";
    static const char rule_lifetime[] =
        "INSERT INTO policy_rule_stats(dimension,rule_id,match_count,"
        "decision_count,would_block_count,enforced_block_count,"
        "allow_decision_count,shadowed_count,first_hit_at,last_hit_at) VALUES("
        "?1,?2,1,?3,?4,?5,?6,?7,?8,?8) ON CONFLICT(dimension,rule_id) DO "
        "UPDATE SET match_count=CASE WHEN match_count<9223372036854775807 "
        "THEN match_count+1 ELSE match_count END,decision_count=CASE WHEN "
        "excluded.decision_count=1 AND decision_count<9223372036854775807 "
        "THEN decision_count+1 ELSE decision_count END,would_block_count=CASE "
        "WHEN excluded.would_block_count=1 AND would_block_count<"
        "9223372036854775807 THEN would_block_count+1 ELSE would_block_count "
        "END,enforced_block_count=CASE WHEN excluded.enforced_block_count=1 "
        "AND enforced_block_count<9223372036854775807 THEN "
        "enforced_block_count+1 ELSE enforced_block_count END,"
        "allow_decision_count=CASE WHEN excluded.allow_decision_count=1 AND "
        "allow_decision_count<9223372036854775807 THEN allow_decision_count+1 "
        "ELSE allow_decision_count END,shadowed_count=CASE WHEN "
        "excluded.shadowed_count=1 AND shadowed_count<9223372036854775807 "
        "THEN shadowed_count+1 ELSE shadowed_count END,first_hit_at=min("
        "first_hit_at,excluded.first_hit_at),last_hit_at=max(last_hit_at,"
        "excluded.last_hit_at);";
    static const char rule_detail[] =
        "INSERT INTO policy_impact_buckets(bucket_start,dimension,rule_id,"
        "path,client_family,client_address,client_mac,vlan_id,domain,"
        "query_type,match_count,decision_count,would_block_count,"
        "enforced_block_count,allow_decision_count,shadowed_count) VALUES(?1,"
        "?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?12,?13,?14,?15) ON CONFLICT "
        "DO UPDATE SET match_count=CASE WHEN match_count<9223372036854775807 "
        "THEN match_count+1 ELSE match_count END,decision_count=CASE WHEN "
        "excluded.decision_count=1 AND decision_count<9223372036854775807 "
        "THEN decision_count+1 ELSE decision_count END,would_block_count=CASE "
        "WHEN excluded.would_block_count=1 AND would_block_count<"
        "9223372036854775807 THEN would_block_count+1 ELSE would_block_count "
        "END,enforced_block_count=CASE WHEN excluded.enforced_block_count=1 "
        "AND enforced_block_count<9223372036854775807 THEN "
        "enforced_block_count+1 ELSE enforced_block_count END,"
        "allow_decision_count=CASE WHEN excluded.allow_decision_count=1 AND "
        "allow_decision_count<9223372036854775807 THEN allow_decision_count+1 "
        "ELSE allow_decision_count END,shadowed_count=CASE WHEN "
        "excluded.shadowed_count=1 AND shadowed_count<9223372036854775807 "
        "THEN shadowed_count+1 ELSE shadowed_count END;";
    const char *const queries[4U] = {traffic_lifetime, traffic_detail,
                                     rule_lifetime, rule_detail};
    sqlite3_stmt *statements[4U] = {NULL, NULL, NULL, NULL};
    size_t index = 0U;
    int result = 0;

    if (database == NULL || traffic_count > JG_POLICY_STATS_BATCH_MAX ||
        rule_count > JG_POLICY_STATS_BATCH_MAX ||
        (traffic_count > 0U && traffic == NULL) ||
        (rule_count > 0U && rules == NULL) ||
        (traffic_count == 0U && rule_count == 0U)) {
        return -EINVAL;
    }
    for (index = 0U; index < traffic_count; ++index) {
        if (!traffic_sample_valid(&traffic[index])) {
            return -EINVAL;
        }
    }
    for (index = 0U; index < rule_count; ++index) {
        if (!rule_sample_valid(&rules[index])) {
            return -EINVAL;
        }
    }
    result = jg_database_transaction_begin(database);
    for (index = 0U; result == 0 && index < 4U; ++index) {
        const int status = sqlite3_prepare_v3(database->handle, queries[index],
                                              -1, SQLITE_PREPARE_PERSISTENT,
                                              &statements[index], NULL);

        result = jg_database_sqlite_result(status);
    }
    for (index = 0U; result == 0 && index < traffic_count; ++index) {
        result = bind_traffic(statements[0U], statements[1U], &traffic[index]);
        if (result == 0) {
            result = execute_write(statements[0U]);
        }
        if (result == 0) {
            result = execute_write(statements[1U]);
        }
    }
    for (index = 0U; result == 0 && index < rule_count; ++index) {
        result = bind_rule(statements[2U], statements[3U], &rules[index]);
        if (result == 0) {
            result = execute_write(statements[2U]);
        }
        if (result == 0) {
            result = execute_write(statements[3U]);
        }
    }
    result = finalize_writes(statements, result);
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    return result;
}

/** @brief Load lifetime request-level policy counters. */
int jg_database_load_policy_traffic_stats(struct jg_database *database,
                                          struct jg_policy_traffic_stats *stats)
{
    static const char query[] =
        "SELECT request_count,matched_count,would_block_count,"
        "enforced_block_count,first_request_at,last_request_at FROM "
        "policy_traffic_stats WHERE id=1;";
    uint64_t *const values[6U] = {
        stats == NULL ? NULL : &stats->request_count,
        stats == NULL ? NULL : &stats->matched_count,
        stats == NULL ? NULL : &stats->would_block_count,
        stats == NULL ? NULL : &stats->enforced_block_count,
        stats == NULL ? NULL : &stats->first_request_at,
        stats == NULL ? NULL : &stats->last_request_at,
    };
    sqlite3_stmt *statement = NULL;
    size_t index = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || stats == NULL) {
        return -EINVAL;
    }
    (void)memset(stats, 0, sizeof(*stats));
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        result =
            status == SQLITE_ROW
                ? 0
                : (status == SQLITE_DONE ? -ENOENT
                                         : jg_database_sqlite_result(status));
    }
    for (index = 0U; result == 0 && index < 6U; ++index) {
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

/** @brief Decode one lifetime rule-statistics row. */
static int decode_rule_stats(sqlite3_stmt *statement,
                             struct jg_policy_rule_stats *stats)
{
    const char *dimension = NULL;
    size_t dimension_size = 0U;
    uint64_t *const values[8U] = {
        &stats->rule_id,
        &stats->match_count,
        &stats->decision_count,
        &stats->would_block_count,
        &stats->enforced_block_count,
        &stats->allow_decision_count,
        &stats->shadowed_count,
        &stats->first_hit_at,
    };
    size_t index = 0U;
    int result = jg_database_column_required_text(statement, 0, &dimension,
                                                  &dimension_size);

    (void)dimension_size;
    if (result == 0) {
        result = decode_dimension(dimension, &stats->dimension);
    }
    for (index = 0U; result == 0 && index < 8U; ++index) {
        result = jg_database_column_unsigned(statement, (int)index + 1,
                                             values[index]);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 9, &stats->last_hit_at);
    }
    if (result == 0 && (stats->rule_id == 0U || stats->match_count == 0U ||
                        stats->last_hit_at < stats->first_hit_at)) {
        result = -EILSEQ;
    }
    return result;
}

/** @brief Read one identifier-ordered page of lifetime rule counters. */
int jg_database_list_policy_rule_stats(struct jg_database *database,
                                       enum jg_policy_stats_dimension dimension,
                                       uint64_t after_rule_id,
                                       size_t limit,
                                       struct jg_policy_rule_stats *stats,
                                       size_t *count,
                                       bool *has_more)
{
    static const char query[] =
        "SELECT dimension,rule_id,match_count,decision_count,would_block_count,"
        "enforced_block_count,allow_decision_count,shadowed_count,first_hit_at,"
        "last_hit_at FROM policy_rule_stats WHERE dimension=?1 AND rule_id>?2 "
        "ORDER BY rule_id LIMIT ?3;";
    const char *name = dimension_text(dimension);
    sqlite3_stmt *statement = NULL;
    size_t used = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || name == NULL ||
        after_rule_id > POLICY_STATS_COUNTER_MAX || limit == 0U ||
        limit > JG_POLICY_STATS_PAGE_MAX || stats == NULL || count == NULL ||
        has_more == NULL) {
        return -EINVAL;
    }
    *count = 0U;
    *has_more = false;
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, name, -1, SQLITE_STATIC);
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_int64(statement, 2, (sqlite3_int64)after_rule_id);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 3, (sqlite3_int64)limit + 1);
        }
        result = jg_database_sqlite_result(status);
    }
    while (result == 0 && (status = sqlite3_step(statement)) == SQLITE_ROW &&
           used <= limit) {
        if (used < limit) {
            (void)memset(&stats[used], 0, sizeof(stats[used]));
            result = decode_rule_stats(statement, &stats[used]);
        }
        ++used;
    }
    if (result == 0 && status != SQLITE_DONE && status != SQLITE_ROW) {
        result = jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *has_more = used > limit;
        *count = used > limit ? limit : used;
    }
    return result;
}
