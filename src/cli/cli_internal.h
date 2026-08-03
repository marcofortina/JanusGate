/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file cli_internal.h
 * @brief Internal command helpers shared by the administration client.
 */

#ifndef JANUSGATE_CLI_INTERNAL_H
#define JANUSGATE_CLI_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include <janusgate/auth.h>

/** Successful command completion. */
#define CLI_EXIT_SUCCESS 0

/** Transport, protocol, or generic API failure. */
#define CLI_EXIT_FAILURE 1

/** Invalid command-line usage. */
#define CLI_EXIT_USAGE 2

/** Authentication or authorization failure. */
#define CLI_EXIT_AUTH 3

/** Revision or transaction conflict. */
#define CLI_EXIT_CONFLICT 4

/** Required service is unhealthy or unavailable. */
#define CLI_EXIT_UNAVAILABLE 5

/** Parsed process-wide command options. */
struct cli_options {
    /** Local management Unix socket. */
    const char *socket_path;
    /** Remote management API endpoint. */
    const char *endpoint;
    /** Private bearer-token file. */
    const char *token_file;
    /** Private backup-passphrase file. */
    const char *passphrase_file;
    /** Remote API client certificate. */
    const char *client_certificate;
    /** Remote API client private key. */
    const char *client_key;
    /** Trusted remote API certificate authorities. */
    const char *ca_file;
    /** Remote request timeout in seconds. */
    unsigned timeout_seconds;
    /** Whether the local socket was selected explicitly. */
    bool socket_set;
    /** Whether output uses compact JSON. */
    bool json;
    /** Whether successful output is suppressed. */
    bool quiet;
    /** Whether transport details are reported. */
    bool verbose;
    /** Whether destructive operations are pre-approved. */
    bool yes;
    /** Whether full backups include private key material. */
    bool include_private_key;
    /** Whether command help was requested. */
    bool help;
    /** Whether version information was requested. */
    bool version;
};

/** @brief Parse one nonzero decimal resource identifier. */
int jg_cli_parse_identifier(const char *text, uint64_t *identifier);

/** @brief Read and report the configured private API token. */
int load_token(const struct cli_options *options,
               char token[JG_AUTH_SECRET_TEXT_SIZE]);

/** @brief Read one bounded JSON object from a file or standard input. */
json_t *jg_cli_read_json_object(const char *path, int *result);

/** @brief Read one bounded text file or standard input. */
char *jg_cli_read_text(const char *path, size_t *text_size, int *result);

/** @brief Execute one API-backed CLI command through the selected transport. */
int jg_cli_run_api_command(const struct cli_options *options,
                           const char *command);

/** @brief Send and present one JSON management request. */
int jg_cli_send_api_request(const struct cli_options *options,
                            const char *token,
                            const char *command,
                            const char *method,
                            const char *path,
                            json_t *body);

/** @brief Fetch and decode one successful JSON API object. */
int jg_cli_fetch_api_object(const struct cli_options *options,
                            const char *token,
                            const char *path,
                            const char *query,
                            json_t **object);

/** @brief Send one JSON body and decode a successful JSON response. */
int jg_cli_post_api_object(const struct cli_options *options,
                           const char *token,
                           const char *path,
                           json_t *request_body,
                           json_t **response_body);

/** @brief Submit one asynchronous API request and wait for its result body. */
int jg_cli_post_api_job(const struct cli_options *options,
                        const char *token,
                        const char *path,
                        json_t *request_body,
                        json_t **response_body);

/** @brief Present one locally assembled JSON result. */
int jg_cli_present_object(const struct cli_options *options, json_t *object);

/** @brief Confirm a destructive operation unless approval was already given. */
bool jg_cli_destructive_operation_confirmed(const struct cli_options *options,
                                            const char *message);

/** @brief Run one recognized network administration command. */
int jg_cli_run_network_command(const struct cli_options *options,
                               int argc,
                               char **argv);

/** @brief Run one recognized policy administration command. */
int jg_cli_run_policy_command(const struct cli_options *options,
                              int argc,
                              char **argv);

/** @brief Run one recognized domain-policy shorthand command. */
int jg_cli_run_domain_command(const struct cli_options *options, char **argv);

/** @brief Run one recognized blocklist-source administration command. */
int jg_cli_run_source_command(const struct cli_options *options,
                              int argc,
                              char **argv);

/** @brief Run one recognized blocklist administration command. */
int jg_cli_run_blocklist_command(const struct cli_options *options,
                                 int argc,
                                 char **argv);

/** @brief Run one recognized local-user administration command. */
int jg_cli_run_user_command(const struct cli_options *options,
                            int argc,
                            char **argv);

/** @brief Run one recognized API-token administration command. */
int jg_cli_run_token_command(const struct cli_options *options,
                             int argc,
                             char **argv);

/** @brief Run one recognized server-certificate administration command. */
int jg_cli_run_certificate_command(const struct cli_options *options,
                                   int argc,
                                   char **argv);

/** @brief Run one recognized mTLS administration command. */
int jg_cli_run_mtls_command(const struct cli_options *options,
                            int argc,
                            char **argv);

/** @brief Run one recognized backup administration command. */
int jg_cli_run_backup_command(const struct cli_options *options,
                              int argc,
                              char **argv);

/** @brief Validate or reload persistent appliance configuration. */
int jg_cli_run_config_command(const struct cli_options *options,
                              const char *operation);

/** @brief Show, replace, or inspect bounded operational logging state. */
int jg_cli_run_logging_command(const struct cli_options *options,
                               int argc,
                               char **argv);

/** @brief Inspect and configure native alerting and webhook delivery. */
int jg_cli_run_alert_command(const struct cli_options *options,
                             int argc,
                             char **argv);

/** @brief Create, verify, and store one sanitized diagnostic archive. */
int jg_cli_run_diagnostics_create(const struct cli_options *options);

/** @brief Query operational events or immutable audit records. */
int jg_cli_run_record_command(const struct cli_options *options,
                              int argc,
                              char **argv);

/** @brief Confirm and request one authenticated appliance lifecycle action. */
int jg_cli_run_system_command(const struct cli_options *options,
                              const char *family,
                              const char *operation);

#endif
