/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file commands_alerting.c
 * @brief Native alerting administration commands.
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>

#include "cli_internal.h"

/** @brief Load one token and present a successful GET response. */
static int fetch_and_present(const struct cli_options *options,
                             const char *token,
                             const char *path,
                             const char *query)
{
    json_t *body = NULL;
    int result = jg_cli_fetch_api_object(options, token, path, query, &body);

    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Add the current server revision to one replacement document. */
static int add_current_revision(const struct cli_options *options,
                                const char *token,
                                json_t *replacement)
{
    json_t *current = NULL;
    json_t *revision = NULL;
    int result = jg_cli_fetch_api_object(
        options, token, "/api/v1/alerts/configuration", NULL, &current);

    if (result == CLI_EXIT_SUCCESS) {
        revision = json_object_get(current, "revision");
        if (!json_is_integer(revision) ||
            json_object_set(replacement, "revision", revision) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    json_decref(current);
    return result;
}

/** @brief Replace alert configuration from one bounded JSON document. */
static int set_configuration(const struct cli_options *options,
                             const char *token,
                             const char *path)
{
    json_t *body = NULL;
    int read_result = 0;
    int result = 0;

    body = jg_cli_read_json_object(path, &read_result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: alert configuration: %s\n",
                      strerror(-read_result));
        return read_result == -EINVAL || read_result == -EMSGSIZE
                   ? CLI_EXIT_USAGE
                   : CLI_EXIT_FAILURE;
    }
    result = add_current_revision(options, token, body);
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(options, token,
                                         "alert configuration set", "PUT",
                                         "/api/v1/alerts/configuration", body);
    }
    json_decref(body);
    return result;
}

/** @brief Rotate the HMAC secret at the current configuration revision. */
static int rotate_webhook_secret(const struct cli_options *options,
                                 const char *token)
{
    json_t *body = json_object();
    int result = body == NULL ? CLI_EXIT_FAILURE : CLI_EXIT_SUCCESS;

    if (result == CLI_EXIT_SUCCESS) {
        result = add_current_revision(options, token, body);
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(options, token, "alert webhook rotate",
                                         "POST",
                                         "/api/v1/alerts/webhook/secret", body);
    }
    json_decref(body);
    return result;
}

/** @brief Enqueue one webhook test notification. */
static int test_webhook(const struct cli_options *options, const char *token)
{
    json_t *body = json_object();
    int result = body == NULL ? CLI_EXIT_FAILURE : CLI_EXIT_SUCCESS;

    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(options, token, "alert webhook test",
                                         "POST", "/api/v1/alerts/webhook/test",
                                         body);
    }
    json_decref(body);
    return result;
}

/** @brief Inspect and configure native alerting and webhook delivery. */
int jg_cli_run_alert_command(const struct cli_options *options,
                             int argc,
                             char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "list") == 0) {
        result = fetch_and_present(options, token, "/api/v1/alerts",
                                   argc == 3 ? argv[2] : NULL);
    } else if (strcmp(argv[1], "configuration") == 0 &&
               strcmp(argv[2], "show") == 0) {
        result = fetch_and_present(options, token,
                                   "/api/v1/alerts/configuration", NULL);
    } else if (strcmp(argv[1], "configuration") == 0) {
        result = set_configuration(options, token, argv[3]);
    } else if (strcmp(argv[2], "rotate") == 0) {
        result = rotate_webhook_secret(options, token);
    } else {
        result = test_webhook(options, token);
    }
    sodium_memzero(token, sizeof(token));
    return result;
}
