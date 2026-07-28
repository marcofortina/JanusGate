/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "client.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "janusgate/ipc.h"
#include "janusgate/ipc_client.h"

/** Largest accepted CLI query string. */
#define CLI_QUERY_SIZE_MAX 256U

/** Stable media type used by JSON management responses. */
static const char json_content_type[] = "application/json; charset=utf-8";

/** Stable media type used by Prometheus management responses. */
static const char metrics_content_type[] =
    "text/plain; version=0.0.4; charset=utf-8";

/** @brief Return whether one byte is visible seven-bit ASCII. */
static bool visible_ascii(char character)
{
    const uint8_t value = (uint8_t)character;

    return value > UINT8_C(0x20) && value < UINT8_C(0x7f);
}

/** @brief Validate one supported management method. */
static bool method_valid(const char *method)
{
    return method != NULL &&
           (strcmp(method, "GET") == 0 || strcmp(method, "POST") == 0 ||
            strcmp(method, "PATCH") == 0 || strcmp(method, "DELETE") == 0);
}

/** @brief Validate a bounded API path without a query or fragment. */
static bool path_valid(const char *path)
{
    static const char prefix[] = "/api/v1/";
    size_t index = 0U;

    if (path == NULL || strncmp(path, prefix, sizeof(prefix) - 1U) != 0) {
        return false;
    }
    while (index <= 255U && path[index] != '\0') {
        if (!visible_ascii(path[index]) || path[index] == '?' ||
            path[index] == '#') {
            return false;
        }
        ++index;
    }
    return index >= sizeof(prefix) && index <= 255U;
}

/** @brief Validate a bounded query without a leading question mark. */
static bool query_valid(const char *query)
{
    size_t index = 0U;

    if (query == NULL) {
        return true;
    }
    while (index <= CLI_QUERY_SIZE_MAX && query[index] != '\0') {
        if (!visible_ascii(query[index]) || query[index] == '#') {
            return false;
        }
        ++index;
    }
    return index <= CLI_QUERY_SIZE_MAX;
}

/** @brief Check whether one response uses only allowlisted envelope fields. */
static bool response_fields_valid(json_t *response)
{
    const char *name = NULL;
    json_t *value = NULL;

    if (!json_is_object(response)) {
        return false;
    }
    json_object_foreach(response, name, value)
    {
        (void)value;
        if (strcmp(name, "status") != 0 && strcmp(name, "body") != 0 &&
            strcmp(name, "content_type") != 0 && strcmp(name, "text") != 0) {
            return false;
        }
    }
    return true;
}

/** @brief Decode one exact daemon management response envelope. */
int jg_cli_response_decode(const void *data,
                           size_t data_size,
                           struct jg_cli_response *response)
{
    json_error_t error;
    json_t *root = NULL;
    json_t *status = NULL;
    json_t *body = NULL;
    json_t *content_type = NULL;
    json_t *text = NULL;
    json_int_t status_value = 0;
    int result = 0;

    if (data == NULL || data_size == 0U || response == NULL ||
        response->body != NULL) {
        return -EINVAL;
    }
    root = json_loadb(data, data_size, JSON_REJECT_DUPLICATES, &error);
    if (!response_fields_valid(root)) {
        result = -EPROTO;
    }
    if (result == 0) {
        status = json_object_get(root, "status");
        body = json_object_get(root, "body");
        content_type = json_object_get(root, "content_type");
        text = json_object_get(root, "text");
        if (!json_is_integer(status) ||
            !((json_is_object(body) && content_type == NULL && text == NULL) ||
              (body == NULL && json_is_string(content_type) &&
               json_is_string(text)))) {
            result = -EPROTO;
        }
    }
    if (result == 0) {
        status_value = json_integer_value(status);
        if (status_value < 100 || status_value > 599) {
            result = -EPROTO;
        }
    }
    if (result == 0 && body != NULL) {
        response->body = json_dumps(body, JSON_COMPACT | JSON_SORT_KEYS);
        if (response->body == NULL) {
            result = -ENOMEM;
        } else {
            response->body_size = strlen(response->body);
            response->status = (int)status_value;
            (void)memcpy(response->content_type, json_content_type,
                         sizeof(json_content_type));
        }
    }
    if (result == 0 && text != NULL) {
        const char *type = json_string_value(content_type);
        const char *value = json_string_value(text);
        const size_t value_size = json_string_length(text);

        if (strcmp(type, metrics_content_type) != 0 ||
            memchr(value, '\0', value_size) != NULL) {
            result = -EPROTO;
        } else {
            response->body = malloc(value_size + 1U);
            if (response->body == NULL) {
                result = -ENOMEM;
            } else {
                (void)memcpy(response->body, value, value_size);
                response->body[value_size] = '\0';
                response->body_size = value_size;
                response->status = (int)status_value;
                (void)memcpy(response->content_type, metrics_content_type,
                             sizeof(metrics_content_type));
            }
        }
    }
    json_decref(root);
    if (result != 0) {
        jg_cli_response_clear(response);
    }
    return result;
}

/** @brief Serialize one local authenticated management request. */
static int build_envelope(const char *token,
                          const char *method,
                          const char *path,
                          const char *query,
                          json_t *body,
                          struct jg_cli_response *response,
                          char **encoded,
                          size_t *encoded_size)
{
    uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE];
    json_t *envelope = NULL;
    int result = 0;

    *encoded = NULL;
    *encoded_size = 0U;
    result = jg_auth_secret_issue(response->request_id, digest);
    sodium_memzero(digest, sizeof(digest));
    if (result == 0) {
        envelope = json_object();
        if (envelope == NULL ||
            json_object_set_new(envelope, "request_id",
                                json_string(response->request_id)) != 0 ||
            json_object_set_new(envelope, "method", json_string(method)) != 0 ||
            json_object_set_new(envelope, "path", json_string(path)) != 0 ||
            json_object_set_new(envelope, "query",
                                json_string(query == NULL ? "" : query)) != 0 ||
            json_object_set_new(envelope, "host", json_string("localhost")) !=
                0 ||
            json_object_set_new(envelope, "origin", json_string("")) != 0 ||
            json_object_set_new(envelope, "remote_address",
                                json_string("127.0.0.1")) != 0 ||
            json_object_set_new(envelope, "session", json_string("")) != 0 ||
            json_object_set_new(envelope, "csrf", json_string("")) != 0 ||
            json_object_set_new(envelope, "bearer", json_string(token)) != 0 ||
            json_object_set(envelope, "body", body) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        *encoded = json_dumps(envelope, JSON_COMPACT | JSON_SORT_KEYS);
        if (*encoded == NULL) {
            result = -ENOMEM;
        } else {
            *encoded_size = strlen(*encoded);
            if (*encoded_size == 0U || *encoded_size > JG_IPC_MAX_BODY_SIZE) {
                sodium_memzero(*encoded, *encoded_size);
                free(*encoded);
                *encoded = NULL;
                *encoded_size = 0U;
                result = -EMSGSIZE;
            }
        }
    }
    json_decref(envelope);
    return result;
}

/** @brief Perform one authenticated management request over local IPC. */
int jg_cli_local_request(const char *socket_path,
                         const char *token,
                         const char *method,
                         const char *path,
                         const char *query,
                         json_t *body,
                         struct jg_cli_response *response)
{
    uint8_t daemon_response[JG_IPC_MAX_BODY_SIZE];
    char *envelope = NULL;
    size_t envelope_size = 0U;
    size_t daemon_response_size = 0U;
    int result = 0;

    if (socket_path == NULL || socket_path[0U] != '/' || token == NULL ||
        strlen(token) != JG_AUTH_SECRET_TEXT_SIZE - 1U ||
        !method_valid(method) || !path_valid(path) || !query_valid(query) ||
        !json_is_object(body) || response == NULL || response->body != NULL) {
        return -EINVAL;
    }
    result = build_envelope(token, method, path, query, body, response,
                            &envelope, &envelope_size);
    if (result == 0) {
        result = jg_ipc_client_call(socket_path, JG_IPC_MANAGEMENT_REQUEST,
                                    (const uint8_t *)envelope, envelope_size,
                                    daemon_response, sizeof(daemon_response),
                                    &daemon_response_size);
    }
    if (envelope != NULL) {
        sodium_memzero(envelope, envelope_size);
        free(envelope);
    }
    if (result == 0) {
        result = jg_cli_response_decode(daemon_response, daemon_response_size,
                                        response);
    }
    sodium_memzero(daemon_response, daemon_response_size);
    if (result != 0) {
        jg_cli_response_clear(response);
    }
    return result;
}

/** @brief Erase and release one CLI response. */
void jg_cli_response_clear(struct jg_cli_response *response)
{
    if (response == NULL) {
        return;
    }
    if (response->body != NULL) {
        sodium_memzero(response->body, response->body_size);
        free(response->body);
    }
    sodium_memzero(response, sizeof(*response));
}
