/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_policy_statistics.c
 * @brief Policy-statistics storage and cleanup administration.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "janusgate/access.h"
#include "janusgate/audit.h"
#include "janusgate/database.h"

/** @brief Serialize lifetime traffic counters, including an empty lifetime. */
static json_t *traffic_json(const struct jg_policy_traffic_stats *stats,
                            bool present)
{
    json_t *body = json_object();

    if (body == NULL ||
        set_counter(body, "request_count",
                    present ? stats->request_count : 0U) != 0 ||
        set_counter(body, "matched_count",
                    present ? stats->matched_count : 0U) != 0 ||
        set_counter(body, "would_block_count",
                    present ? stats->would_block_count : 0U) != 0 ||
        set_counter(body, "enforced_block_count",
                    present ? stats->enforced_block_count : 0U) != 0 ||
        set_optional_timestamp(body, "first_request_at",
                               present ? stats->first_request_at : 0U) != 0 ||
        set_optional_timestamp(body, "last_request_at",
                               present ? stats->last_request_at : 0U) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Serialize the detailed policy-statistics storage policy. */
static json_t *retention_json(const struct jg_policy_stats_config *config)
{
    json_t *body = json_object();

    if (body == NULL ||
        json_object_set_new(body, "retention_enabled",
                            json_boolean(config->retention_enabled)) != 0 ||
        json_object_set_new(
            body, "retention_months",
            json_integer((json_int_t)config->retention_months)) != 0 ||
        json_object_set_new(body, "detail_enabled",
                            json_boolean(config->detail_enabled)) != 0 ||
        set_counter(body, "detail_max_rows", config->detail_max_rows) != 0 ||
        set_counter(body, "detail_max_rows_per_rule_hour",
                    config->detail_max_rows_per_rule_hour) != 0 ||
        set_counter(body, "detail_max_domains_per_rule_hour",
                    config->detail_max_domains_per_rule_hour) != 0 ||
        set_counter(body, "maximum_database_bytes",
                    config->maximum_database_bytes) != 0 ||
        set_counter(body, "minimum_free_bytes", config->minimum_free_bytes) !=
            0 ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)config->revision)) != 0 ||
        set_optional_timestamp(body, "updated_at", config->updated_at) != 0 ||
        set_optional_timestamp(body, "last_cleanup_at",
                               config->last_cleanup_at) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Serialize storage configuration and lifetime traffic counters. */
static json_t *statistics_json(const struct jg_policy_stats_config *config,
                               const struct jg_policy_stats_storage *storage,
                               const struct jg_policy_traffic_stats *traffic,
                               bool has_traffic)
{
    json_t *lifetime = traffic_json(traffic, has_traffic);
    json_t *storage_body = json_object();
    json_t *body = retention_json(config);

    if (storage_body == NULL ||
        set_counter(storage_body, "detail_rows", storage->detail_rows) != 0 ||
        set_counter(storage_body, "estimated_bytes",
                    storage->estimated_bytes) != 0 ||
        set_counter(storage_body, "cardinality_dropped",
                    storage->cardinality_dropped) != 0 ||
        set_counter(storage_body, "storage_dropped",
                    storage->storage_dropped) != 0 ||
        json_object_set_new(storage_body, "storage_suspended",
                            json_boolean(storage->storage_suspended)) != 0 ||
        lifetime == NULL || body == NULL ||
        json_object_set(body, "lifetime", lifetime) != 0 ||
        json_object_set(body, "storage", storage_body) != 0) {
        json_decref(body);
        body = NULL;
    }
    json_decref(storage_body);
    json_decref(lifetime);
    return body;
}

/** @brief Serialize one detailed-statistics cleanup preview or result. */
static json_t *cleanup_json(const struct jg_policy_stats_cleanup_report *report,
                            bool preview)
{
    json_t *body = json_object();

    if (body == NULL ||
        json_object_set_new(body, "preview", json_boolean(preview)) != 0 ||
        set_optional_timestamp(body, "cutoff_at", report->cutoff_at) != 0 ||
        set_counter(body, "eligible_impact_rows", report->impact_rows) != 0 ||
        set_counter(body, "eligible_traffic_rows", report->traffic_rows) != 0 ||
        set_counter(body, "deleted_impact_rows", report->deleted_impact_rows) !=
            0 ||
        set_counter(body, "deleted_traffic_rows",
                    report->deleted_traffic_rows) != 0 ||
        json_object_set_new(body, "complete", json_boolean(report->complete)) !=
            0 ||
        json_object_set_new(body, "lifetime_preserved", json_true()) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Append one statistics-administration audit event. */
static int append_statistics_audit(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   const struct authenticated_actor *actor,
                                   const char *action,
                                   const char *object_id,
                                   json_t *details,
                                   bool has_previous_revision,
                                   uint64_t previous_revision,
                                   bool has_new_revision,
                                   uint64_t new_revision,
                                   uint64_t now)
{
    char source_address[INET6_ADDRSTRLEN];
    char *encoded = NULL;
    struct jg_audit_event event;
    int result = 0;

    if (inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source_address,
                  sizeof(source_address)) == NULL) {
        return -EINVAL;
    }
    encoded = json_dumps(details, JSON_COMPACT | JSON_SORT_KEYS);
    if (encoded == NULL) {
        return -ENOMEM;
    }
    event = (struct jg_audit_event){
        .occurred_at = now,
        .actor_type = actor_audit_type(actor),
        .has_actor_id = actor_has_identifier(actor),
        .actor_id = actor->actor_id,
        .source = source_address,
        .action = action,
        .object_type = "policy_statistics",
        .object_id = object_id,
        .details = encoded,
        .has_previous_revision = has_previous_revision,
        .previous_revision = previous_revision,
        .has_new_revision = has_new_revision,
        .new_revision = new_revision,
        .success = true,
        .request_id = request->request_id,
    };
    result = jg_database_audit_append(management->database, &event, NULL);
    free(encoded);
    return result;
}

/** @brief Load lifetime traffic while treating no samples as an empty set. */
static int load_traffic(struct jg_database *database,
                        struct jg_policy_traffic_stats *traffic,
                        bool *present)
{
    int result = jg_database_load_policy_traffic_stats(database, traffic);

    *present = result == 0;
    if (result == -ENOENT) {
        (void)memset(traffic, 0, sizeof(*traffic));
        result = 0;
    }
    return result;
}

/** @brief Return or replace the detailed policy-statistics storage policy. */
int handle_policy_statistics(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written)
{
    static const char *const fields[] = {
        "revision",
        "retention_enabled",
        "retention_months",
        "detail_enabled",
        "detail_max_rows",
        "detail_max_rows_per_rule_hour",
        "detail_max_domains_per_rule_hour",
        "maximum_database_bytes",
        "minimum_free_bytes",
    };
    struct authenticated_actor actor;
    struct jg_policy_stats_config config = {0};
    struct jg_policy_stats_config_update update = {0};
    struct jg_policy_stats_storage storage = {0};
    struct jg_policy_traffic_stats traffic = {0};
    const bool updating = strcmp(request->method, "PUT") == 0;
    uint64_t revision = 0U;
    uint64_t months = 0U;
    uint64_t detail_max_rows = 0U;
    uint64_t detail_max_rows_per_rule_hour = 0U;
    uint64_t detail_max_domains_per_rule_hour = 0U;
    uint64_t maximum_database_bytes = 0U;
    uint64_t minimum_free_bytes = 0U;
    bool has_traffic = false;
    bool mutation_open = false;
    json_t *body = NULL;
    int result = authenticate_actor(
        management, request, remote, updating,
        updating ? JG_ACCESS_POLICY_WRITE : JG_ACCESS_POLICY_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        (!updating && strcmp(request->method, "GET") != 0) ||
        (!updating && json_object_size(request->body) != 0U)) {
        return respond_error(400, "invalid_request",
                             "The policy-statistics request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (!updating) {
        result =
            jg_database_load_policy_stats_config(management->database, &config);
    } else {
        if (!fields_allowed(request->body, fields, 9U) ||
            !required_identifier(request->body, "revision", &revision) ||
            !required_boolean(request->body, "retention_enabled",
                              &update.retention_enabled) ||
            !required_unsigned(request->body, "retention_months",
                               JG_POLICY_STATS_RETENTION_MAX, &months) ||
            months < JG_POLICY_STATS_RETENTION_MIN ||
            !required_boolean(request->body, "detail_enabled",
                              &update.detail_enabled) ||
            !required_unsigned(request->body, "detail_max_rows",
                               JG_POLICY_STATS_DETAIL_ROWS_MAX,
                               &detail_max_rows) ||
            detail_max_rows < JG_POLICY_STATS_DETAIL_ROWS_MIN ||
            !required_unsigned(request->body, "detail_max_rows_per_rule_hour",
                               JG_POLICY_STATS_RULE_HOUR_ROWS_MAX,
                               &detail_max_rows_per_rule_hour) ||
            detail_max_rows_per_rule_hour <
                JG_POLICY_STATS_RULE_HOUR_ROWS_MIN ||
            !required_unsigned(request->body,
                               "detail_max_domains_per_rule_hour",
                               JG_POLICY_STATS_RULE_HOUR_DOMAINS_MAX,
                               &detail_max_domains_per_rule_hour) ||
            detail_max_domains_per_rule_hour <
                JG_POLICY_STATS_RULE_HOUR_DOMAINS_MIN ||
            !required_unsigned(request->body, "maximum_database_bytes",
                               JG_POLICY_STATS_DATABASE_BYTES_MAX,
                               &maximum_database_bytes) ||
            maximum_database_bytes < JG_POLICY_STATS_DATABASE_BYTES_MIN ||
            !required_unsigned(request->body, "minimum_free_bytes",
                               JG_POLICY_STATS_FREE_BYTES_MAX,
                               &minimum_free_bytes)) {
            return respond_error(
                400, "invalid_body",
                "The policy-statistics storage policy is not valid.",
                request->request_id, output, output_size, written);
        }
        update.retention_months = (uint32_t)months;
        update.detail_max_rows = detail_max_rows;
        update.detail_max_rows_per_rule_hour =
            (uint32_t)detail_max_rows_per_rule_hour;
        update.detail_max_domains_per_rule_hour =
            (uint32_t)detail_max_domains_per_rule_hour;
        update.maximum_database_bytes = maximum_database_bytes;
        update.minimum_free_bytes = minimum_free_bytes;
        result = audited_mutation_begin(management);
        if (result == 0) {
            mutation_open = true;
            result = jg_database_update_policy_stats_config(
                management->database, &update, revision, now, &config);
        }
        if (result != 0 && mutation_open) {
            result = audited_mutation_check(management, result);
            mutation_open = false;
        }
        if (result == 0) {
            body = retention_json(&config);
            if (body == NULL) {
                result = -ENOMEM;
            }
        }
        if (result == 0) {
            result = append_statistics_audit(
                management, request, remote, &actor,
                "policy.statistics.storage.update", "storage", body, true,
                revision, true, config.revision, now);
        }
        if (mutation_open) {
            result = audited_mutation_finish(management, result, false);
        }
    }
    if (result == -EAGAIN) {
        json_decref(body);
        return respond_error(409, "revision_conflict",
                             "The statistics storage policy has changed.",
                             request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = jg_database_load_policy_stats_storage(management->database,
                                                       &storage);
    }
    if (result == 0) {
        result = load_traffic(management->database, &traffic, &has_traffic);
    }
    if (result == 0) {
        json_decref(body);
        body = statistics_json(&config, &storage, &traffic, has_traffic);
        if (body == NULL) {
            result = -ENOMEM;
        }
    }
    if (result != 0) {
        json_decref(body);
        return respond_error(
            500, "policy_statistics_failed",
            "The policy-statistics storage policy could not be processed.",
            request->request_id, output, output_size, written);
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Preview or execute one detailed-statistics cleanup batch. */
int handle_policy_statistics_cleanup(struct jg_management *management,
                                     const struct management_request *request,
                                     const struct remote_address *remote,
                                     uint64_t now,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *written)
{
    static const char *const preview_fields[] = {"preview"};
    static const char *const cleanup_fields[] = {"preview", "batch_size"};
    struct authenticated_actor actor;
    struct jg_policy_stats_cleanup_report report = {0};
    uint64_t batch_size = 0U;
    bool preview = false;
    bool mutation_open = false;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        !required_boolean(request->body, "preview", &preview) ||
        (preview && !fields_allowed(request->body, preview_fields, 1U)) ||
        (!preview &&
         (!fields_allowed(request->body, cleanup_fields, 2U) ||
          !required_unsigned(request->body, "batch_size",
                             JG_POLICY_STATS_CLEANUP_BATCH_MAX, &batch_size) ||
          batch_size == 0U))) {
        return respond_error(
            400, "invalid_body",
            "The policy-statistics cleanup request is not valid.",
            request->request_id, output, output_size, written);
    }
    if (preview) {
        result = jg_database_preview_policy_stats_cleanup(management->database,
                                                          now, &report);
    } else {
        result = audited_mutation_begin(management);
        if (result == 0) {
            mutation_open = true;
            result = jg_database_cleanup_policy_stats(
                management->database, now, (size_t)batch_size, &report);
        }
        if (result != 0 && mutation_open) {
            result = audited_mutation_check(management, result);
            mutation_open = false;
        }
    }
    if (result == 0) {
        body = cleanup_json(&report, preview);
        if (body == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0 && !preview) {
        result = append_statistics_audit(management, request, remote, &actor,
                                         "policy.statistics.cleanup", "detail",
                                         body, false, 0U, false, 0U, now);
    }
    if (mutation_open) {
        result = audited_mutation_finish(management, result, false);
    }
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "policy_statistics_cleanup_failed",
                             "Policy-statistics detail could not be cleaned.",
                             request->request_id, output, output_size, written);
    }
    return encode_response(200, body, NULL, output, output_size, written);
}
