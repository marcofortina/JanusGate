/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file commands_policy.c
 * @brief Policy and blocklist administration commands.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>

#include "cli_internal.h"
#include "janusgate/policy_stats.h"

/** @brief Map one CLI policy kind to its API collection and array field. */
static int policy_collection(const char *kind,
                             const char **path,
                             const char **array_name)
{
    if (strcmp(kind, "domain") == 0) {
        *path = "/api/v1/domains";
        *array_name = "domains";
        return 0;
    }
    if (strcmp(kind, "destination") == 0) {
        *path = "/api/v1/policies/destinations";
        *array_name = "destination_rules";
        return 0;
    }
    if (strcmp(kind, "group") == 0) {
        *path = "/api/v1/policies/groups";
        *array_name = "groups";
        return 0;
    }
    if (strcmp(kind, "scope") == 0) {
        *path = "/api/v1/policies/scopes";
        *array_name = "scope_modes";
        return 0;
    }
    return -EINVAL;
}

/** @brief Fetch one exact policy rule and return an owned JSON object. */
static int fetch_policy_rule(const struct cli_options *options,
                             const char *token,
                             const char *kind,
                             uint64_t identifier,
                             json_t **rule)
{
    const char *collection = NULL;
    const char *array_name = NULL;
    char query[96U];
    json_t *page = NULL;
    json_t *rules = NULL;
    json_t *candidate = NULL;
    json_t *value = NULL;
    int result = policy_collection(kind, &collection, &array_name);

    *rule = NULL;
    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    (void)snprintf(query, sizeof(query), "after_id=%llu&limit=1",
                   (unsigned long long)(identifier - 1U));
    result = jg_cli_fetch_api_object(options, token, collection, query, &page);
    if (result == CLI_EXIT_SUCCESS) {
        rules = json_object_get(page, array_name);
        candidate = json_array_get(rules, 0U);
        value = json_object_get(candidate, "id");
        if (!json_is_integer(value) ||
            (uint64_t)json_integer_value(value) != identifier) {
            (void)fprintf(stderr, "janusgatectl: policy rule not found\n");
            result = CLI_EXIT_FAILURE;
        } else {
            *rule = json_deep_copy(candidate);
            if (*rule == NULL) {
                result = CLI_EXIT_FAILURE;
            }
        }
    }
    json_decref(page);
    return result;
}

/** @brief List both policy-rule collections as one stable document. */
static int run_policy_list(const struct cli_options *options, const char *token)
{
    json_t *domains = NULL;
    json_t *destinations = NULL;
    json_t *mode = NULL;
    json_t *groups = NULL;
    json_t *scopes = NULL;
    json_t *body = NULL;
    int result = jg_cli_fetch_api_object(options, token, "/api/v1/domains",
                                         NULL, &domains);

    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_fetch_api_object(options, token,
                                         "/api/v1/policies/destinations", NULL,
                                         &destinations);
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_fetch_api_object(options, token,
                                         "/api/v1/policies/mode", NULL, &mode);
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_fetch_api_object(
            options, token, "/api/v1/policies/groups", NULL, &groups);
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_fetch_api_object(
            options, token, "/api/v1/policies/scopes", NULL, &scopes);
    }
    if (result == CLI_EXIT_SUCCESS) {
        body = json_object();
        if (body == NULL ||
            json_object_set(body, "domain_rules", domains) != 0 ||
            json_object_set(body, "destination_rules", destinations) != 0 ||
            json_object_set(body, "mode", mode) != 0 ||
            json_object_set(body, "groups", groups) != 0 ||
            json_object_set(body, "scope_modes", scopes) != 0) {
            result = CLI_EXIT_FAILURE;
        } else {
            result = jg_cli_present_object(options, body);
        }
    }
    json_decref(body);
    json_decref(scopes);
    json_decref(groups);
    json_decref(mode);
    json_decref(destinations);
    json_decref(domains);
    return result;
}

/** @brief Read or replace snapshot-wide enforcement. */
static int run_policy_mode(const struct cli_options *options,
                           const char *token,
                           const char *file)
{
    json_t *current = NULL;
    json_t *body = NULL;
    json_t *revision = NULL;
    int result = 0;

    if (file == NULL) {
        result = jg_cli_fetch_api_object(
            options, token, "/api/v1/policies/mode", NULL, &current);
        if (result == CLI_EXIT_SUCCESS) {
            result = jg_cli_present_object(options, current);
        }
        json_decref(current);
        return result;
    }
    body = jg_cli_read_json_object(file, &result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: policy-mode document: %s\n",
                      strerror(-result));
        return result == -EINVAL || result == -EMSGSIZE ? CLI_EXIT_USAGE
                                                        : CLI_EXIT_FAILURE;
    }
    result = jg_cli_fetch_api_object(options, token, "/api/v1/policies/mode",
                                     NULL, &current);
    revision = json_object_get(current, "revision");
    if (result == CLI_EXIT_SUCCESS &&
        (!json_is_integer(revision) ||
         json_object_set(body, "revision", revision) != 0)) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(options, token, "policy mode", "PUT",
                                         "/api/v1/policies/mode", body);
    }
    json_decref(current);
    json_decref(body);
    return result;
}

/** @brief Read or replace detailed policy-statistics storage policy. */
static int run_policy_statistics(const struct cli_options *options,
                                 const char *token,
                                 const char *file)
{
    static const char path[] = "/api/v1/policies/statistics";
    json_t *current = NULL;
    json_t *body = NULL;
    json_t *revision = NULL;
    int result = 0;

    if (file == NULL) {
        result = jg_cli_fetch_api_object(options, token, path, NULL, &current);
        if (result == CLI_EXIT_SUCCESS) {
            result = jg_cli_present_object(options, current);
        }
        json_decref(current);
        return result;
    }
    body = jg_cli_read_json_object(file, &result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: policy-statistics document: %s\n",
                      strerror(-result));
        return result == -EINVAL || result == -EMSGSIZE ? CLI_EXIT_USAGE
                                                        : CLI_EXIT_FAILURE;
    }
    result = jg_cli_fetch_api_object(options, token, path, NULL, &current);
    revision = json_object_get(current, "revision");
    if (result == CLI_EXIT_SUCCESS &&
        (!json_is_integer(revision) ||
         json_object_set(body, "revision", revision) != 0)) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(options, token, "policy statistics",
                                         "PUT", path, body);
    }
    json_decref(current);
    json_decref(body);
    return result;
}

/** @brief Preview or run one bounded detailed-statistics cleanup batch. */
static int run_policy_cleanup(const struct cli_options *options,
                              const char *token,
                              bool preview)
{
    json_t *body = json_object();
    int result = CLI_EXIT_SUCCESS;

    if (!preview && !jg_cli_destructive_operation_confirmed(
                        options, "Remove expired policy-statistics detail")) {
        result = CLI_EXIT_FAILURE;
    }
    if (body == NULL ||
        json_object_set_new(body, "preview", json_boolean(preview)) != 0 ||
        (!preview &&
         json_object_set_new(body, "batch_size",
                             json_integer(JG_POLICY_STATS_CLEANUP_BATCH_MAX)) !=
             0)) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(
            options, token,
            preview ? "policy cleanup preview" : "policy cleanup", "POST",
            "/api/v1/policies/statistics/cleanup", body);
    }
    json_decref(body);
    return result;
}

/** @brief Display one exact domain or destination policy rule. */
static int run_policy_show(const struct cli_options *options,
                           const char *token,
                           const char *kind,
                           const char *identifier_text)
{
    json_t *rule = NULL;
    uint64_t identifier = 0U;
    int result = jg_cli_parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_policy_rule(options, token, kind, identifier, &rule);
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, rule);
    }
    json_decref(rule);
    return result;
}

/** @brief Display impact and conservative findings for one policy rule. */
static int run_policy_analysis(const struct cli_options *options,
                               const char *token,
                               const char *kind,
                               const char *identifier_text)
{
    const char *collection = NULL;
    const char *array_name = NULL;
    char path[160U];
    json_t *analysis = NULL;
    uint64_t identifier = 0U;
    int result = jg_cli_parse_identifier(identifier_text, &identifier);
    int written = 0;

    if (result != 0 ||
        (strcmp(kind, "domain") != 0 && strcmp(kind, "destination") != 0) ||
        policy_collection(kind, &collection, &array_name) != 0) {
        return CLI_EXIT_USAGE;
    }
    (void)array_name;
    written = snprintf(path, sizeof(path), "%s/%llu/analysis", collection,
                       (unsigned long long)identifier);
    if (written <= 0 || (size_t)written >= sizeof(path)) {
        return CLI_EXIT_FAILURE;
    }
    result = jg_cli_fetch_api_object(options, token, path, NULL, &analysis);
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, analysis);
    }
    json_decref(analysis);
    return result;
}

/** @brief Build one exact API path for a typed policy rule. */
static int policy_rule_path(const char *kind,
                            uint64_t identifier,
                            char *path,
                            size_t path_size)
{
    const char *collection = NULL;
    const char *array_name = NULL;
    int written = 0;

    if (policy_collection(kind, &collection, &array_name) != 0) {
        return -EINVAL;
    }
    (void)array_name;
    written = snprintf(path, path_size, "%s/%llu", collection,
                       (unsigned long long)identifier);
    return written > 0 && (size_t)written < path_size ? 0 : -ENOSPC;
}

/** @brief Create or replace one typed policy rule from a JSON document. */
static int run_policy_write(const struct cli_options *options,
                            const char *token,
                            const char *operation,
                            const char *kind,
                            const char *identifier_text,
                            const char *file)
{
    const char *collection = NULL;
    const char *array_name = NULL;
    char path[128U];
    json_t *body = NULL;
    json_t *current = NULL;
    json_t *revision = NULL;
    uint64_t identifier = 0U;
    int result = policy_collection(kind, &collection, &array_name);

    (void)array_name;
    if (result != 0 ||
        (identifier_text != NULL &&
         jg_cli_parse_identifier(identifier_text, &identifier) != 0)) {
        return CLI_EXIT_USAGE;
    }
    body = jg_cli_read_json_object(file, &result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: policy document: %s\n",
                      strerror(-result));
        return result == -EINVAL || result == -EMSGSIZE ? CLI_EXIT_USAGE
                                                        : CLI_EXIT_FAILURE;
    }
    if (identifier_text == NULL) {
        (void)snprintf(path, sizeof(path), "%s", collection);
    } else {
        result = fetch_policy_rule(options, token, kind, identifier, &current);
        revision = json_object_get(current, "revision");
        if (result == CLI_EXIT_SUCCESS &&
            (!json_is_integer(revision) ||
             json_object_set(body, "revision", revision) != 0 ||
             policy_rule_path(kind, identifier, path, sizeof(path)) != 0)) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(
            options, token,
            strcmp(operation, "add") == 0 ? "policy add" : "policy update",
            strcmp(operation, "add") == 0 ? "POST" : "PATCH", path, body);
    }
    json_decref(current);
    json_decref(body);
    return result;
}

/** @brief Delete one revision-bound typed policy rule. */
static int run_policy_remove(const struct cli_options *options,
                             const char *token,
                             const char *kind,
                             const char *identifier_text)
{
    char path[128U];
    json_t *rule = NULL;
    json_t *revision = NULL;
    json_t *body = NULL;
    uint64_t identifier = 0U;
    int result = jg_cli_parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_policy_rule(options, token, kind, identifier, &rule);
    if (result == CLI_EXIT_SUCCESS && !jg_cli_destructive_operation_confirmed(
                                          options, "Remove the policy rule")) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        revision = json_object_get(rule, "revision");
        body = json_object();
        if (!json_is_integer(revision) || body == NULL ||
            json_object_set(body, "revision", revision) != 0 ||
            policy_rule_path(kind, identifier, path, sizeof(path)) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(options, token, "policy remove",
                                         "DELETE", path, body);
    }
    json_decref(body);
    json_decref(rule);
    return result;
}

/** @brief Explain one policy decision from a JSON document. */
static int run_policy_explanation(const struct cli_options *options,
                                  const char *token,
                                  const char *file)
{
    json_t *body = NULL;
    int result = 0;

    body = jg_cli_read_json_object(file, &result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: policy query document: %s\n",
                      strerror(-result));
        return result == -EINVAL || result == -EMSGSIZE ? CLI_EXIT_USAGE
                                                        : CLI_EXIT_FAILURE;
    }
    result = jg_cli_send_api_request(options, token, "policy explain", "POST",
                                     "/api/v1/policies/simulate", body);
    json_decref(body);
    return result;
}

/** @brief Run one recognized policy administration command. */
int jg_cli_run_policy_command(const struct cli_options *options,
                              int argc,
                              char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (argc == 2 && strcmp(argv[1], "list") == 0) {
        result = run_policy_list(options, token);
    } else if (strcmp(argv[1], "mode") == 0) {
        result = run_policy_mode(options, token, argc == 3 ? argv[2] : NULL);
    } else if (strcmp(argv[1], "statistics") == 0) {
        result =
            run_policy_statistics(options, token, argc == 3 ? argv[2] : NULL);
    } else if (strcmp(argv[1], "cleanup") == 0) {
        result =
            run_policy_cleanup(options, token, strcmp(argv[2], "preview") == 0);
    } else if (strcmp(argv[1], "show") == 0) {
        result = run_policy_show(options, token, argv[2], argv[3]);
    } else if (strcmp(argv[1], "analyze") == 0) {
        result = run_policy_analysis(options, token, argv[2], argv[3]);
    } else if (strcmp(argv[1], "add") == 0) {
        result =
            run_policy_write(options, token, "add", argv[2], NULL, argv[3]);
    } else if (strcmp(argv[1], "update") == 0) {
        result = run_policy_write(options, token, "update", argv[2], argv[3],
                                  argv[4]);
    } else if (strcmp(argv[1], "remove") == 0) {
        result = run_policy_remove(options, token, argv[2], argv[3]);
    } else {
        result = run_policy_explanation(options, token, argv[2]);
    }
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Create one global DNS domain rule from a CLI shorthand. */
static int run_domain_create(const struct cli_options *options,
                             const char *token,
                             const char *action,
                             const char *domain)
{
    json_t *body = json_object();
    json_t *scope = json_object();
    int result = 0;

    if (body == NULL || scope == NULL ||
        json_object_set_new(scope, "type", json_string("global")) != 0 ||
        json_object_set_new(body, "domain", json_string(domain)) != 0 ||
        json_object_set_new(body, "include_subdomains", json_true()) != 0 ||
        json_object_set_new(body, "action", json_string(action)) != 0 ||
        json_object_set_new(body, "target", json_string("dns")) != 0 ||
        json_object_set(body, "scope", scope) != 0 ||
        json_object_set_new(body, "attribution", json_string("janusgatectl")) !=
            0 ||
        json_object_set_new(body, "enabled", json_true()) != 0) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(
            options, token,
            strcmp(action, "block") == 0 ? "domain block" : "domain allow",
            "POST", "/api/v1/domains", body);
    }
    json_decref(scope);
    json_decref(body);
    return result;
}

/** @brief Run one recognized domain-policy shorthand command. */
int jg_cli_run_domain_command(const struct cli_options *options, char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "remove") == 0) {
        result = run_policy_remove(options, token, "domain", argv[2]);
    } else {
        result = run_domain_create(options, token, argv[1], argv[2]);
    }
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Fetch one exact blocklist source and return an owned object. */
static int fetch_source(const struct cli_options *options,
                        const char *token,
                        uint64_t identifier,
                        json_t **source)
{
    char query[96U];
    json_t *page = NULL;
    json_t *sources = NULL;
    json_t *candidate = NULL;
    json_t *value = NULL;
    int result = 0;

    *source = NULL;
    (void)snprintf(query, sizeof(query), "after_id=%llu&limit=1",
                   (unsigned long long)(identifier - 1U));
    result = jg_cli_fetch_api_object(options, token, "/api/v1/sources", query,
                                     &page);
    if (result == CLI_EXIT_SUCCESS) {
        sources = json_object_get(page, "sources");
        candidate = json_array_get(sources, 0U);
        value = json_object_get(candidate, "id");
        if (!json_is_integer(value) ||
            (uint64_t)json_integer_value(value) != identifier) {
            (void)fprintf(stderr, "janusgatectl: blocklist source not found\n");
            result = CLI_EXIT_FAILURE;
        } else {
            *source = json_deep_copy(candidate);
            if (*source == NULL) {
                result = CLI_EXIT_FAILURE;
            }
        }
    }
    json_decref(page);
    return result;
}

/** @brief Remove read-only source-state fields before an update. */
static void retain_source_configuration(json_t *source)
{
    static const char *const read_only[] = {
        "id",
        "created_at",
        "updated_at",
        "etag",
        "last_modified",
        "last_attempt_at",
        "last_success_at",
        "next_attempt_at",
        "consecutive_failures",
        "active_checksum",
        "active_entries",
        "rejected_entries",
        "health",
        "last_error",
    };

    for (size_t index = 0U; index < sizeof(read_only) / sizeof(read_only[0U]);
         ++index) {
        json_object_del(source, read_only[index]);
    }
}

/** @brief List blocklist-source configuration and update health. */
static int run_source_list(const struct cli_options *options, const char *token)
{
    json_t *body = NULL;
    int result =
        jg_cli_fetch_api_object(options, token, "/api/v1/sources", NULL, &body);

    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Add or replace one blocklist-source JSON configuration. */
static int run_source_write(const struct cli_options *options,
                            const char *token,
                            const char *operation,
                            const char *identifier_text,
                            const char *file)
{
    char path[96U];
    json_t *body = NULL;
    json_t *source = NULL;
    json_t *revision = NULL;
    uint64_t identifier = 0U;
    int result = 0;

    if (identifier_text != NULL &&
        jg_cli_parse_identifier(identifier_text, &identifier) != 0) {
        return CLI_EXIT_USAGE;
    }
    body = jg_cli_read_json_object(file, &result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: source document: %s\n",
                      strerror(-result));
        return result == -EINVAL || result == -EMSGSIZE ? CLI_EXIT_USAGE
                                                        : CLI_EXIT_FAILURE;
    }
    if (identifier_text == NULL) {
        (void)snprintf(path, sizeof(path), "/api/v1/sources");
    } else {
        result = fetch_source(options, token, identifier, &source);
        revision = json_object_get(source, "revision");
        if (result == CLI_EXIT_SUCCESS &&
            (!json_is_integer(revision) ||
             json_object_set(body, "revision", revision) != 0)) {
            result = CLI_EXIT_FAILURE;
        }
        (void)snprintf(path, sizeof(path), "/api/v1/sources/%llu",
                       (unsigned long long)identifier);
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(
            options, token,
            strcmp(operation, "add") == 0 ? "source add" : "source update",
            strcmp(operation, "add") == 0 ? "POST" : "PATCH", path, body);
    }
    json_decref(source);
    json_decref(body);
    return result;
}

/** @brief Refresh, enable, or disable one blocklist source. */
static int run_source_operation(const struct cli_options *options,
                                const char *token,
                                const char *operation,
                                const char *identifier_text)
{
    char path[128U];
    json_t *source = NULL;
    json_t *revision = NULL;
    json_t *body = NULL;
    uint64_t identifier = 0U;
    int result = jg_cli_parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_source(options, token, identifier, &source);
    revision = json_object_get(source, "revision");
    if (result == CLI_EXIT_SUCCESS && !json_is_integer(revision)) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS && strcmp(operation, "refresh") == 0) {
        body = json_object();
        if (body == NULL || json_object_set(body, "revision", revision) != 0) {
            result = CLI_EXIT_FAILURE;
        }
        (void)snprintf(path, sizeof(path), "/api/v1/sources/%llu/refresh",
                       (unsigned long long)identifier);
    } else if (result == CLI_EXIT_SUCCESS) {
        body = json_deep_copy(source);
        if (body == NULL) {
            result = CLI_EXIT_FAILURE;
        } else {
            retain_source_configuration(body);
            if (json_object_set_new(
                    body, "enabled",
                    json_boolean(strcmp(operation, "enable") == 0)) != 0) {
                result = CLI_EXIT_FAILURE;
            }
        }
        (void)snprintf(path, sizeof(path), "/api/v1/sources/%llu",
                       (unsigned long long)identifier);
    }
    if (result == CLI_EXIT_SUCCESS && strcmp(operation, "refresh") == 0) {
        json_t *completed = NULL;

        result = jg_cli_post_api_job(options, token, path, body, &completed);
        if (result == CLI_EXIT_SUCCESS) {
            result = jg_cli_present_object(options, completed);
        }
        json_decref(completed);
    } else if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(options, token, operation, "PATCH",
                                         path, body);
    }
    json_decref(body);
    json_decref(source);
    return result;
}

/** @brief Run one recognized blocklist-source administration command. */
int jg_cli_run_source_command(const struct cli_options *options,
                              int argc,
                              char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (argc == 2) {
        result = run_source_list(options, token);
    } else if (strcmp(argv[1], "add") == 0) {
        result = run_source_write(options, token, "add", NULL, argv[2]);
    } else if (strcmp(argv[1], "update") == 0) {
        result = run_source_write(options, token, "update", argv[2], argv[3]);
    } else {
        result = run_source_operation(options, token, argv[1], argv[2]);
    }
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Import one local source payload with its current revision. */
static int run_blocklist_import(const struct cli_options *options,
                                const char *token,
                                const char *identifier_text,
                                const char *file)
{
    char *text = NULL;
    json_t *source = NULL;
    json_t *revision = NULL;
    json_t *body = NULL;
    size_t text_size = 0U;
    uint64_t identifier = 0U;
    int result = jg_cli_parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_source(options, token, identifier, &source);
    if (result == CLI_EXIT_SUCCESS) {
        text = jg_cli_read_text(file, &text_size, &result);
        if (text == NULL) {
            (void)fprintf(stderr, "janusgatectl: blocklist input: %s\n",
                          strerror(-result));
            result = result == -EINVAL || result == -EMSGSIZE
                         ? CLI_EXIT_USAGE
                         : CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        revision = json_object_get(source, "revision");
        body = json_object();
        if (!json_is_integer(revision) || body == NULL ||
            json_object_set_new(body, "source_id",
                                json_integer((json_int_t)identifier)) != 0 ||
            json_object_set(body, "revision", revision) != 0 ||
            json_object_set_new(body, "content",
                                json_stringn(text, text_size)) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        json_t *completed = NULL;

        result = jg_cli_post_api_job(options, token, "/api/v1/blocklists", body,
                                     &completed);
        if (result == CLI_EXIT_SUCCESS) {
            result = jg_cli_present_object(options, completed);
        }
        json_decref(completed);
    }
    json_decref(body);
    json_decref(source);
    if (text != NULL) {
        sodium_memzero(text, text_size);
        free(text);
    }
    return result;
}

/** @brief Export active blocklist-derived domain rules as JSON. */
static int run_blocklist_export(const struct cli_options *options,
                                const char *token)
{
    json_t *exported = json_object();
    json_t *domains = json_array();
    uint64_t after_id = 0U;
    bool more = true;
    int result = exported == NULL || domains == NULL ? CLI_EXIT_FAILURE
                                                     : CLI_EXIT_SUCCESS;

    while (result == CLI_EXIT_SUCCESS && more) {
        char query[96U];
        json_t *page = NULL;
        json_t *items = NULL;
        json_t *next = NULL;

        (void)snprintf(query, sizeof(query), "after_id=%llu&limit=100",
                       (unsigned long long)after_id);
        result = jg_cli_fetch_api_object(options, token, "/api/v1/domains",
                                         query, &page);
        if (result == CLI_EXIT_SUCCESS) {
            items = json_object_get(page, "domains");
            for (size_t index = 0U; index < json_array_size(items); ++index) {
                json_t *item = json_array_get(items, index);
                const char *source =
                    json_string_value(json_object_get(item, "source"));

                if (source != NULL && strcmp(source, "blocklist") == 0 &&
                    json_array_append(domains, item) != 0) {
                    result = CLI_EXIT_FAILURE;
                    break;
                }
            }
            more = json_is_true(json_object_get(page, "has_more"));
            next = json_object_get(page, "next_after_id");
            if (result == CLI_EXIT_SUCCESS && more &&
                (!json_is_integer(next) ||
                 json_integer_value(next) <= (json_int_t)after_id)) {
                result = CLI_EXIT_FAILURE;
            } else if (result == CLI_EXIT_SUCCESS && more) {
                after_id = (uint64_t)json_integer_value(next);
            }
        }
        json_decref(page);
    }
    if (result == CLI_EXIT_SUCCESS &&
        json_object_set(exported, "domains", domains) != 0) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, exported);
    }
    json_decref(domains);
    json_decref(exported);
    return result;
}

/** @brief Run one recognized blocklist administration command. */
int jg_cli_run_blocklist_command(const struct cli_options *options,
                                 int argc,
                                 char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "list") == 0) {
        result = run_source_list(options, token);
    } else if (strcmp(argv[1], "export") == 0) {
        result = run_blocklist_export(options, token);
    } else {
        result = run_blocklist_import(options, token, argv[2], argv[3]);
    }
    (void)argc;
    sodium_memzero(token, sizeof(token));
    return result;
}
