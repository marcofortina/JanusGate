/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file commands_identity.c
 * @brief Identity and certificate administration commands.
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
#include "janusgate/certificate.h"

/** @brief Fetch one exact local user from stable paginated API results. */
static int fetch_user(const struct cli_options *options,
                      const char *token,
                      uint64_t identifier,
                      json_t **user)
{
    uint64_t offset = 0U;
    bool more = true;
    int result = CLI_EXIT_SUCCESS;

    *user = NULL;
    while (result == CLI_EXIT_SUCCESS && more && *user == NULL) {
        char query[96U];
        json_t *page = NULL;
        json_t *users = NULL;
        json_t *next = NULL;

        (void)snprintf(query, sizeof(query), "offset=%llu&limit=100",
                       (unsigned long long)offset);
        result = jg_cli_fetch_api_object(options, token, "/api/v1/users", query,
                                         &page);
        if (result == CLI_EXIT_SUCCESS) {
            users = json_object_get(page, "users");
            if (!json_is_array(users)) {
                result = CLI_EXIT_FAILURE;
            }
        }
        for (size_t index = 0U;
             result == CLI_EXIT_SUCCESS && index < json_array_size(users);
             ++index) {
            json_t *candidate = json_array_get(users, index);
            json_t *value = json_object_get(candidate, "id");

            if (json_is_integer(value) &&
                (uint64_t)json_integer_value(value) == identifier) {
                *user = json_deep_copy(candidate);
                if (*user == NULL) {
                    result = CLI_EXIT_FAILURE;
                }
            }
        }
        if (result == CLI_EXIT_SUCCESS && *user == NULL) {
            next = json_object_get(page, "next_offset");
            more = !json_is_null(next);
            if (more && (!json_is_integer(next) ||
                         json_integer_value(next) <= (json_int_t)offset)) {
                result = CLI_EXIT_FAILURE;
            } else if (more) {
                offset = (uint64_t)json_integer_value(next);
            }
        }
        json_decref(page);
    }
    if (result == CLI_EXIT_SUCCESS && *user == NULL) {
        (void)fprintf(stderr, "janusgatectl: local user not found\n");
        result = CLI_EXIT_FAILURE;
    }
    return result;
}

/** @brief List the first stable page of local-user administration state. */
static int run_user_list(const struct cli_options *options, const char *token)
{
    json_t *body = NULL;
    int result = jg_cli_fetch_api_object(options, token, "/api/v1/users",
                                         "limit=100", &body);

    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Add or update one local user from an exact JSON document. */
static int run_user_write(const struct cli_options *options,
                          const char *token,
                          const char *operation,
                          const char *identifier_text,
                          const char *file)
{
    const bool add = strcmp(operation, "add") == 0;
    const bool password = strcmp(operation, "password") == 0;
    char path[128U];
    json_t *body = NULL;
    json_t *user = NULL;
    json_t *revision = NULL;
    uint64_t identifier = 0U;
    int result = CLI_EXIT_SUCCESS;
    int read_result = 0;

    if (!add && jg_cli_parse_identifier(identifier_text, &identifier) != 0) {
        return CLI_EXIT_USAGE;
    }
    if (!add) {
        result = fetch_user(options, token, identifier, &user);
    }
    if (result == CLI_EXIT_SUCCESS && password &&
        !jg_cli_destructive_operation_confirmed(
            options, "Replace the user's password")) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        body = jg_cli_read_json_object(file, &read_result);
        if (body == NULL) {
            (void)fprintf(stderr, "janusgatectl: user document: %s\n",
                          strerror(-read_result));
            result = read_result == -EINVAL || read_result == -EMSGSIZE
                         ? CLI_EXIT_USAGE
                         : CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS && !add) {
        revision = json_object_get(user, "revision");
        if (!json_is_integer(revision) ||
            json_object_set(body, "revision", revision) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (add) {
        (void)snprintf(path, sizeof(path), "/api/v1/users");
    } else if (password) {
        (void)snprintf(path, sizeof(path), "/api/v1/users/%llu/password",
                       (unsigned long long)identifier);
    } else {
        (void)snprintf(path, sizeof(path), "/api/v1/users/%llu",
                       (unsigned long long)identifier);
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(
            options, token,
            add ? "user add" : (password ? "user password" : "user update"),
            add || password ? "POST" : "PATCH", path, body);
    }
    json_decref(user);
    json_decref(body);
    return result;
}

/** @brief Disable one local user while preserving its remaining state. */
static int run_user_disable(const struct cli_options *options,
                            const char *token,
                            const char *identifier_text)
{
    char path[96U];
    json_t *user = NULL;
    json_t *body = NULL;
    json_t *revision = NULL;
    json_t *role = NULL;
    json_t *force_password_change = NULL;
    uint64_t identifier = 0U;
    int result = jg_cli_parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_user(options, token, identifier, &user);
    if (result == CLI_EXIT_SUCCESS && !jg_cli_destructive_operation_confirmed(
                                          options, "Disable the local user")) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        revision = json_object_get(user, "revision");
        role = json_object_get(user, "role");
        force_password_change = json_object_get(user, "force_password_change");
        body = json_object();
        if (!json_is_integer(revision) || !json_is_string(role) ||
            !json_is_boolean(force_password_change) || body == NULL ||
            json_object_set(body, "revision", revision) != 0 ||
            json_object_set(body, "role", role) != 0 ||
            json_object_set_new(body, "enabled", json_false()) != 0 ||
            json_object_set(body, "force_password_change",
                            force_password_change) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        (void)snprintf(path, sizeof(path), "/api/v1/users/%llu",
                       (unsigned long long)identifier);
        result = jg_cli_send_api_request(options, token, "user disable",
                                         "PATCH", path, body);
    }
    json_decref(body);
    json_decref(user);
    return result;
}

/** @brief Remove one local user's TOTP and recovery credentials. */
static int run_user_totp_disable(const struct cli_options *options,
                                 const char *token,
                                 const char *identifier_text)
{
    char path[sizeof("/api/v1/users/18446744073709551615/totp")];
    json_t *user = NULL;
    json_t *body = NULL;
    json_t *revision = NULL;
    uint64_t identifier = 0U;
    int result = jg_cli_parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_user(options, token, identifier, &user);
    if (result == CLI_EXIT_SUCCESS &&
        !jg_cli_destructive_operation_confirmed(
            options, "Remove the user's TOTP credentials")) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        revision = json_object_get(user, "revision");
        body = json_object();
        if (!json_is_integer(revision) || body == NULL ||
            json_object_set(body, "revision", revision) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        (void)snprintf(path, sizeof(path), "/api/v1/users/%llu/totp",
                       (unsigned long long)identifier);
        result = jg_cli_send_api_request(options, token, "user totp", "DELETE",
                                         path, body);
    }
    json_decref(body);
    json_decref(user);
    return result;
}

/** @brief Run one recognized local-user administration command. */
int jg_cli_run_user_command(const struct cli_options *options,
                            int argc,
                            char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "list") == 0) {
        result = run_user_list(options, token);
    } else if (strcmp(argv[1], "add") == 0) {
        result = run_user_write(options, token, "add", NULL, argv[2]);
    } else if (strcmp(argv[1], "update") == 0 ||
               strcmp(argv[1], "password") == 0) {
        result = run_user_write(options, token, argv[1], argv[2], argv[3]);
    } else if (strcmp(argv[1], "disable") == 0) {
        result = run_user_disable(options, token, argv[2]);
    } else {
        result = run_user_totp_disable(options, token, argv[2]);
    }
    (void)argc;
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief List the first stable page of API-token metadata. */
static int run_token_list(const struct cli_options *options, const char *token)
{
    json_t *body = NULL;
    int result = jg_cli_fetch_api_object(options, token, "/api/v1/tokens",
                                         "limit=100", &body);

    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Issue one scoped API token from an exact JSON document. */
static int run_token_create(const struct cli_options *options,
                            const char *token,
                            const char *file)
{
    json_t *body = NULL;
    int read_result = 0;
    int result = CLI_EXIT_SUCCESS;

    body = jg_cli_read_json_object(file, &read_result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: token document: %s\n",
                      strerror(-read_result));
        return read_result == -EINVAL || read_result == -EMSGSIZE
                   ? CLI_EXIT_USAGE
                   : CLI_EXIT_FAILURE;
    }
    result = jg_cli_send_api_request(options, token, "token create", "POST",
                                     "/api/v1/tokens", body);
    json_decref(body);
    return result;
}

/** @brief Revoke one API token after an explicit destructive confirmation. */
static int run_token_revoke(const struct cli_options *options,
                            const char *token,
                            const char *identifier_text)
{
    char path[sizeof("/api/v1/tokens/18446744073709551615")];
    json_t *body = NULL;
    uint64_t identifier = 0U;
    int result = jg_cli_parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    if (!jg_cli_destructive_operation_confirmed(options,
                                                "Revoke the API token")) {
        return CLI_EXIT_FAILURE;
    }
    body = json_object();
    if (body == NULL) {
        return CLI_EXIT_FAILURE;
    }
    (void)snprintf(path, sizeof(path), "/api/v1/tokens/%llu",
                   (unsigned long long)identifier);
    result = jg_cli_send_api_request(options, token, "token revoke", "DELETE",
                                     path, body);
    json_decref(body);
    return result;
}

/** @brief Run one recognized API-token administration command. */
int jg_cli_run_token_command(const struct cli_options *options,
                             int argc,
                             char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "list") == 0) {
        result = run_token_list(options, token);
    } else if (strcmp(argv[1], "create") == 0) {
        result = run_token_create(options, token, argv[2]);
    } else {
        result = run_token_revoke(options, token, argv[2]);
    }
    (void)argc;
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Inspect current public server-certificate metadata. */
static int run_certificate_show(const struct cli_options *options,
                                const char *token)
{
    json_t *body = NULL;
    int result = jg_cli_fetch_api_object(options, token, "/api/v1/certificates",
                                         NULL, &body);

    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Install one certificate document against the current fingerprint. */
static int run_certificate_install(const struct cli_options *options,
                                   const char *token,
                                   const char *file)
{
    json_t *current = NULL;
    json_t *certificate = NULL;
    json_t *fingerprint = NULL;
    json_t *body = NULL;
    int read_result = 0;
    int result = jg_cli_fetch_api_object(options, token, "/api/v1/certificates",
                                         NULL, &current);

    if (result == CLI_EXIT_SUCCESS &&
        !jg_cli_destructive_operation_confirmed(
            options, "Replace the server certificate")) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        body = jg_cli_read_json_object(file, &read_result);
        if (body == NULL) {
            (void)fprintf(stderr, "janusgatectl: certificate document: %s\n",
                          strerror(-read_result));
            result = read_result == -EINVAL || read_result == -EMSGSIZE
                         ? CLI_EXIT_USAGE
                         : CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        certificate = json_object_get(current, "certificate");
        fingerprint = json_object_get(certificate, "fingerprint_sha256");
        if (!json_is_string(fingerprint) ||
            json_object_set(body, "expected_fingerprint", fingerprint) != 0 ||
            (json_object_get(body, "private_key") == NULL &&
             json_object_set_new(body, "private_key", json_null()) != 0)) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(options, token, "certificate install",
                                         "POST", "/api/v1/certificates/install",
                                         body);
    }
    json_decref(body);
    json_decref(current);
    return result;
}

/** @brief Create one CSR from a bounded local JSON document. */
static int run_certificate_csr(const struct cli_options *options,
                               const char *token,
                               const char *file)
{
    json_t *body = NULL;
    json_t *completed = NULL;
    int read_result = 0;
    int result = CLI_EXIT_SUCCESS;

    body = jg_cli_read_json_object(file, &read_result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: CSR document: %s\n",
                      strerror(-read_result));
        return read_result == -EINVAL || read_result == -EMSGSIZE
                   ? CLI_EXIT_USAGE
                   : CLI_EXIT_FAILURE;
    }
    result = jg_cli_post_api_job(options, token, "/api/v1/certificates/csr",
                                 body, &completed);
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, completed);
    }
    json_decref(completed);
    json_decref(body);
    return result;
}

/** @brief Run one recognized server-certificate administration command. */
int jg_cli_run_certificate_command(const struct cli_options *options,
                                   int argc,
                                   char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "show") == 0) {
        result = run_certificate_show(options, token);
    } else if (strcmp(argv[1], "install") == 0) {
        result = run_certificate_install(options, token, argv[2]);
    } else {
        result = run_certificate_csr(options, token, argv[2]);
    }
    (void)argc;
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Show the current remote client-authority trust store. */
static int run_mtls_ca_show(const struct cli_options *options,
                            const char *token)
{
    json_t *body = NULL;
    int result = jg_cli_fetch_api_object(
        options, token, "/api/v1/mtls/authorities", NULL, &body);

    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Install one bounded client-authority PEM bundle. */
static int run_mtls_ca_install(const struct cli_options *options,
                               const char *token,
                               const char *file)
{
    char *pem = NULL;
    size_t pem_size = 0U;
    json_t *body = NULL;
    int read_result = 0;
    int result = CLI_EXIT_SUCCESS;

    if (!jg_cli_destructive_operation_confirmed(
            options, "Replace the remote client CA trust store")) {
        return CLI_EXIT_FAILURE;
    }
    pem = jg_cli_read_text(file, &pem_size, &read_result);
    if (pem == NULL || pem_size > JG_CERTIFICATE_PEM_MAX) {
        (void)fprintf(stderr, "janusgatectl: client CA bundle: %s\n",
                      strerror(pem == NULL ? -read_result : EFBIG));
        free(pem);
        return read_result == -EINVAL || read_result == -EMSGSIZE ||
                       pem_size > JG_CERTIFICATE_PEM_MAX
                   ? CLI_EXIT_USAGE
                   : CLI_EXIT_FAILURE;
    }
    body = json_object();
    if (body == NULL || json_object_set_new(body, "certificate_authorities",
                                            json_stringn(pem, pem_size)) != 0) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        result =
            jg_cli_send_api_request(options, token, "mTLS CA install", "PUT",
                                    "/api/v1/mtls/authorities", body);
    }
    json_decref(body);
    free(pem);
    return result;
}

/** @brief Remove the remote client-authority trust store. */
static int run_mtls_ca_remove(const struct cli_options *options,
                              const char *token)
{
    json_t *body = NULL;
    int result = CLI_EXIT_SUCCESS;

    if (!jg_cli_destructive_operation_confirmed(
            options, "Remove the remote client CA trust store")) {
        return CLI_EXIT_FAILURE;
    }
    body = json_object();
    if (body == NULL) {
        return CLI_EXIT_FAILURE;
    }
    result = jg_cli_send_api_request(options, token, "mTLS CA remove", "DELETE",
                                     "/api/v1/mtls/authorities", body);
    json_decref(body);
    return result;
}

/** @brief List persistent client-certificate identity mappings. */
static int run_mtls_mapping_list(const struct cli_options *options,
                                 const char *token)
{
    json_t *body = NULL;
    int result = jg_cli_fetch_api_object(
        options, token, "/api/v1/mtls/mappings", "limit=100", &body);

    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Return whether one CLI role is valid for an mTLS mapping. */
static bool mtls_role_valid(const char *role)
{
    return strcmp(role, "administrator") == 0 ||
           strcmp(role, "operator") == 0 || strcmp(role, "auditor") == 0;
}

/** @brief Create one client-certificate mapping from a PEM leaf. */
static int run_mtls_mapping_add(const struct cli_options *options,
                                const char *token,
                                const char *file,
                                const char *target_kind,
                                const char *target)
{
    char *pem = NULL;
    size_t pem_size = 0U;
    uint64_t user_id = 0U;
    json_t *body = NULL;
    int read_result = 0;
    int result = CLI_EXIT_SUCCESS;

    if ((strcmp(target_kind, "user") == 0 &&
         jg_cli_parse_identifier(target, &user_id) != 0) ||
        (strcmp(target_kind, "role") == 0 && !mtls_role_valid(target)) ||
        (strcmp(target_kind, "user") != 0 &&
         strcmp(target_kind, "role") != 0)) {
        return CLI_EXIT_USAGE;
    }
    pem = jg_cli_read_text(file, &pem_size, &read_result);
    if (pem == NULL || pem_size > JG_CERTIFICATE_PEM_MAX) {
        (void)fprintf(stderr, "janusgatectl: client certificate: %s\n",
                      strerror(pem == NULL ? -read_result : EFBIG));
        free(pem);
        return read_result == -EINVAL || read_result == -EMSGSIZE ||
                       pem_size > JG_CERTIFICATE_PEM_MAX
                   ? CLI_EXIT_USAGE
                   : CLI_EXIT_FAILURE;
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "certificate", json_stringn(pem, pem_size)) !=
            0 ||
        json_object_set_new(body, "user_id",
                            user_id == 0U
                                ? json_null()
                                : json_integer((json_int_t)user_id)) != 0 ||
        json_object_set_new(body, "role",
                            user_id == 0U ? json_string(target)
                                          : json_null()) != 0) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_send_api_request(options, token, "mTLS mapping add",
                                         "POST", "/api/v1/mtls/mappings", body);
    }
    json_decref(body);
    free(pem);
    return result;
}

/** @brief Revoke one persistent client-certificate mapping. */
static int run_mtls_mapping_revoke(const struct cli_options *options,
                                   const char *token,
                                   const char *identifier_text)
{
    char path[96U];
    uint64_t identifier = 0U;
    json_t *body = NULL;
    int written = 0;
    int result = jg_cli_parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    if (!jg_cli_destructive_operation_confirmed(
            options, "Revoke the client-certificate mapping")) {
        return CLI_EXIT_FAILURE;
    }
    written = snprintf(path, sizeof(path), "/api/v1/mtls/mappings/%llu",
                       (unsigned long long)identifier);
    body = json_object();
    if (written <= 0 || (size_t)written >= sizeof(path) || body == NULL) {
        json_decref(body);
        return CLI_EXIT_FAILURE;
    }
    result = jg_cli_send_api_request(options, token, "mTLS mapping revoke",
                                     "DELETE", path, body);
    json_decref(body);
    return result;
}

/** @brief Run one recognized mTLS administration command. */
int jg_cli_run_mtls_command(const struct cli_options *options,
                            int argc,
                            char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "ca") == 0 && strcmp(argv[2], "show") == 0) {
        result = run_mtls_ca_show(options, token);
    } else if (strcmp(argv[1], "ca") == 0 && strcmp(argv[2], "install") == 0) {
        result = run_mtls_ca_install(options, token, argv[3]);
    } else if (strcmp(argv[1], "ca") == 0) {
        result = run_mtls_ca_remove(options, token);
    } else if (strcmp(argv[2], "list") == 0) {
        result = run_mtls_mapping_list(options, token);
    } else if (strcmp(argv[2], "add") == 0) {
        result =
            run_mtls_mapping_add(options, token, argv[3], argv[4], argv[5]);
    } else {
        result = run_mtls_mapping_revoke(options, token, argv[3]);
    }
    (void)argc;
    sodium_memzero(token, sizeof(token));
    return result;
}
