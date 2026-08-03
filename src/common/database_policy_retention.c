/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/database.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sqlite3.h>

#include "database_internal.h"

/** Largest signed value accepted by the persistent statistics schema. */
#define POLICY_STATS_VALUE_MAX UINT64_C(9223372036854775807)

/** @brief Decode the singleton retention configuration row. */
static int decode_config(sqlite3_stmt *statement,
                         struct jg_policy_stats_config *config)
{
    uint64_t retention_months = 0U;
    uint64_t revision = 0U;
    uint64_t updated_at = 0U;
    uint64_t last_cleanup_at = 0U;
    const int enabled = sqlite3_column_int(statement, 0);
    int result = jg_database_column_unsigned(statement, 1, &retention_months);

    if (result == 0) {
        result = jg_database_column_unsigned(statement, 2, &revision);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 3, &updated_at);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 4, &last_cleanup_at);
    }
    if (result == 0 &&
        ((enabled != 0 && enabled != 1) ||
         retention_months < JG_POLICY_STATS_RETENTION_MIN ||
         retention_months > JG_POLICY_STATS_RETENTION_MAX || revision == 0U)) {
        result = -EILSEQ;
    }
    if (result == 0) {
        config->retention_enabled = enabled != 0;
        config->retention_months = (uint32_t)retention_months;
        config->revision = revision;
        config->updated_at = updated_at;
        config->last_cleanup_at = last_cleanup_at;
    }
    return result;
}

/** @brief Load persistent detailed-statistics retention configuration. */
int jg_database_load_policy_stats_config(struct jg_database *database,
                                         struct jg_policy_stats_config *config)
{
    static const char query[] =
        "SELECT retention_enabled,retention_months,revision,updated_at,"
        "last_cleanup_at FROM policy_statistics_configuration WHERE id=1;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || config == NULL) {
        return -EINVAL;
    }
    (void)memset(config, 0, sizeof(*config));
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        result =
            status == SQLITE_ROW
                ? decode_config(statement, config)
                : (status == SQLITE_DONE ? -EILSEQ
                                         : jg_database_sqlite_result(status));
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

/** @brief Replace retention configuration at its expected revision. */
int jg_database_update_policy_stats_config(
    struct jg_database *database,
    bool retention_enabled,
    uint32_t retention_months,
    uint64_t expected_revision,
    uint64_t updated_at,
    struct jg_policy_stats_config *updated)
{
    static const char update[] =
        "UPDATE policy_statistics_configuration SET retention_enabled=?1,"
        "retention_months=?2,revision=revision+1,updated_at=?3 WHERE id=1 AND "
        "revision=?4 AND revision<9223372036854775807;";
    static const char revision_query[] =
        "SELECT revision FROM policy_statistics_configuration WHERE id=?1;";
    struct jg_policy_stats_config record;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || retention_months < JG_POLICY_STATS_RETENTION_MIN ||
        retention_months > JG_POLICY_STATS_RETENTION_MAX ||
        expected_revision == 0U || expected_revision > POLICY_STATS_VALUE_MAX ||
        updated_at > POLICY_STATS_VALUE_MAX || updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result = jg_database_transaction_begin(database);
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_int(statement, 1, retention_enabled ? 1 : 0);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int(statement, 2, (int)retention_months);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_int64(statement, 3, (sqlite3_int64)updated_at);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 4,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_write_conflict(database->handle, revision_query,
                                            1U, expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        statement = NULL;
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = jg_database_load_policy_stats_config(database, &record);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    if (result == 0) {
        *updated = record;
    }
    return result;
}

/** @brief Derive the retention cutoff using SQLite calendar arithmetic. */
static int retention_cutoff(struct jg_database *database,
                            uint64_t now,
                            uint32_t retention_months,
                            uint64_t *cutoff)
{
    static const char query[] = "SELECT max(0,unixepoch(?1,'unixepoch',?2));";
    char modifier[32U];
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 value = 0;
    int written = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (now > POLICY_STATS_VALUE_MAX || cutoff == NULL) {
        return -EINVAL;
    }
    written = snprintf(modifier, sizeof(modifier), "-%" PRIu32 " months",
                       retention_months);
    if (written <= 0 || (size_t)written >= sizeof(modifier)) {
        return -EOVERFLOW;
    }
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)now);
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_text(statement, 2, modifier, -1, SQLITE_TRANSIENT);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW ||
            sqlite3_column_type(statement, 0) != SQLITE_INTEGER) {
            result = status == SQLITE_ROW ? -ERANGE
                                          : jg_database_sqlite_result(status);
        } else {
            value = sqlite3_column_int64(statement, 0);
            if (value < 0) {
                result = -EIO;
            }
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
    if (result == 0) {
        *cutoff = (uint64_t)value;
    }
    return result;
}

/** @brief Count expired detail rows in both statistics bucket tables. */
static int count_expired(struct jg_database *database,
                         uint64_t cutoff,
                         struct jg_policy_stats_cleanup_report *report)
{
    static const char query[] =
        "SELECT (SELECT count(*) FROM policy_impact_buckets WHERE "
        "bucket_start<?1),(SELECT count(*) FROM policy_traffic_buckets WHERE "
        "bucket_start<?1);";
    sqlite3_stmt *statement = NULL;
    int status =
        sqlite3_prepare_v3(database->handle, query, -1,
                           SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)cutoff);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_ROW ? jg_database_column_unsigned(
                                            statement, 0, &report->impact_rows)
                                      : jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result =
            jg_database_column_unsigned(statement, 1, &report->traffic_rows);
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

/** @brief Preview detailed rows eligible under the retention configuration. */
int jg_database_preview_policy_stats_cleanup(
    struct jg_database *database,
    uint64_t now,
    struct jg_policy_stats_cleanup_report *report)
{
    struct jg_policy_stats_config config;
    uint64_t cutoff = 0U;
    int result = 0;

    if (database == NULL || now > POLICY_STATS_VALUE_MAX || report == NULL) {
        return -EINVAL;
    }
    (void)memset(report, 0, sizeof(*report));
    result = jg_database_transaction_begin_read(database);
    if (result == 0) {
        result = jg_database_load_policy_stats_config(database, &config);
    }
    if (result == 0) {
        result =
            retention_cutoff(database, now, config.retention_months, &cutoff);
    }
    if (result == 0) {
        report->cutoff_at = cutoff;
        result = count_expired(database, cutoff, report);
    }
    if (result == 0) {
        report->complete =
            report->impact_rows == 0U && report->traffic_rows == 0U;
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    return result;
}

/** @brief Delete one bounded set of oldest detail rows. */
static int delete_expired(sqlite3 *handle,
                          const char *query,
                          uint64_t cutoff,
                          size_t limit,
                          uint64_t *deleted)
{
    sqlite3_stmt *statement = NULL;
    int status = sqlite3_prepare_v3(
        handle, query, -1, SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    int result = jg_database_sqlite_result(status);

    if (result == 0) {
        status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)cutoff);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2, (sqlite3_int64)limit);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0) {
        const sqlite3_int64 changes = sqlite3_changes64(handle);

        if (changes < 0) {
            result = -EIO;
        } else {
            *deleted = (uint64_t)changes;
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Remove one bounded batch of expired detail without lifetime loss. */
int jg_database_cleanup_policy_stats(
    struct jg_database *database,
    uint64_t now,
    size_t batch_size,
    struct jg_policy_stats_cleanup_report *report)
{
    static const char delete_impact[] =
        "DELETE FROM policy_impact_buckets WHERE (bucket_start,dimension,"
        "rule_id,path,client_family,client_address,client_mac,vlan_id,domain,"
        "query_type) IN (SELECT bucket_start,dimension,rule_id,path,"
        "client_family,client_address,client_mac,vlan_id,domain,query_type "
        "FROM policy_impact_buckets WHERE bucket_start<?1 ORDER BY "
        "bucket_start LIMIT ?2);";
    static const char delete_traffic[] =
        "DELETE FROM policy_traffic_buckets WHERE (bucket_start,path) IN "
        "(SELECT bucket_start,path FROM policy_traffic_buckets WHERE "
        "bucket_start<?1 ORDER BY bucket_start LIMIT ?2);";
    static const char mark_complete[] =
        "UPDATE policy_statistics_configuration SET last_cleanup_at=?1 "
        "WHERE id=1;";
    struct jg_policy_stats_cleanup_report remaining;
    size_t available = batch_size;
    int result = 0;

    if (database == NULL || now > POLICY_STATS_VALUE_MAX || batch_size == 0U ||
        batch_size > JG_POLICY_STATS_CLEANUP_BATCH_MAX || report == NULL) {
        return -EINVAL;
    }
    (void)memset(report, 0, sizeof(*report));
    result = jg_database_transaction_begin(database);
    if (result == 0) {
        result =
            jg_database_preview_policy_stats_cleanup(database, now, report);
    }
    if (result == 0 && report->impact_rows > 0U) {
        result =
            delete_expired(database->handle, delete_impact, report->cutoff_at,
                           available, &report->deleted_impact_rows);
        available -= (size_t)report->deleted_impact_rows;
    }
    if (result == 0 && available > 0U && report->traffic_rows > 0U) {
        result =
            delete_expired(database->handle, delete_traffic, report->cutoff_at,
                           available, &report->deleted_traffic_rows);
    }
    if (result == 0) {
        (void)memset(&remaining, 0, sizeof(remaining));
        remaining.cutoff_at = report->cutoff_at;
        result = count_expired(database, report->cutoff_at, &remaining);
    }
    if (result == 0) {
        report->complete =
            remaining.impact_rows == 0U && remaining.traffic_rows == 0U;
    }
    if (result == 0 && report->complete) {
        sqlite3_stmt *statement = NULL;
        int status =
            sqlite3_prepare_v3(database->handle, mark_complete, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);

        result = jg_database_sqlite_result(status);
        if (result == 0) {
            status = sqlite3_bind_int64(statement, 1, (sqlite3_int64)now);
            result = jg_database_sqlite_result(status);
        }
        if (result == 0) {
            status = sqlite3_step(statement);
            result =
                status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
        }
        if (statement != NULL) {
            status = sqlite3_finalize(statement);
            if (result == 0) {
                result = jg_database_sqlite_result(status);
            }
        }
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
    }
    return result;
}
