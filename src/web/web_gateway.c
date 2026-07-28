/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "web_gateway.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <civetweb.h>
#include <jansson.h>
#include <sodium.h>

#include "janusgate/auth.h"
#include "janusgate/ipc.h"
#include "janusgate/ipc_client.h"

/** Exact name of the browser session cookie. */
static const char session_cookie_name[] = "janusgate_session";

/** @brief Return a bounded string length or one past the maximum. */
static size_t bounded_length(const char *text, size_t maximum)
{
    size_t length = 0U;

    if (text == NULL) {
        return maximum + 1U;
    }
    while (length <= maximum && text[length] != '\0') {
        ++length;
    }
    return length;
}

/** @brief Validate one request identifier accepted by the daemon. */
static bool request_id_valid(const char *request_id)
{
    const size_t length =
        bounded_length(request_id, JG_AUTH_SECRET_TEXT_SIZE - 1U);

    if (length == 0U || length > JG_AUTH_SECRET_TEXT_SIZE - 1U) {
        return false;
    }
    for (size_t index = 0U; index < length; ++index) {
        const uint8_t character = (uint8_t)request_id[index];

        if (!((character >= (uint8_t)'a' && character <= (uint8_t)'z') ||
              (character >= (uint8_t)'A' && character <= (uint8_t)'Z') ||
              (character >= (uint8_t)'0' && character <= (uint8_t)'9') ||
              character == (uint8_t)'-' || character == (uint8_t)'_')) {
            return false;
        }
    }
    return true;
}

/** @brief Generate one opaque correlation identifier. */
static int generate_request_id(char request_id[JG_AUTH_SECRET_TEXT_SIZE])
{
    uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE];
    const int result = jg_auth_secret_issue(request_id, digest);

    sodium_memzero(digest, sizeof(digest));
    return result;
}

/** @brief Assign a valid inbound or freshly randomized request identifier. */
static int assign_request_id(const struct mg_connection *connection,
                             char request_id[JG_AUTH_SECRET_TEXT_SIZE])
{
    const char *supplied = mg_get_header(connection, "X-Request-ID");

    if (supplied != NULL) {
        if (!request_id_valid(supplied)) {
            return -EINVAL;
        }
        (void)memcpy(request_id, supplied, strlen(supplied) + 1U);
        return 0;
    }
    return generate_request_id(request_id);
}

/** @brief Serialize one consistent JSON error into an owned response. */
static int set_error_response(struct jg_web_gateway_response *response,
                              int status,
                              const char *code,
                              const char *message)
{
    json_t *root = json_object();
    json_t *error = json_object();
    int result = 0;

    if (root == NULL || error == NULL ||
        json_object_set_new(error, "code", json_string(code)) != 0 ||
        json_object_set_new(error, "message", json_string(message)) != 0 ||
        json_object_set_new(error, "request_id",
                            json_string(response->request_id)) != 0 ||
        json_object_set(root, "error", error) != 0) {
        result = -ENOMEM;
    }
    if (result == 0) {
        response->body = json_dumps(root, JSON_COMPACT | JSON_SORT_KEYS);
        if (response->body == NULL) {
            result = -ENOMEM;
        } else {
            response->body_size = strlen(response->body);
            response->status = status;
        }
    }
    json_decref(error);
    json_decref(root);
    return result;
}

/** @brief Recognize JSON content types accepted for state changes. */
static bool content_type_valid(const char *content_type)
{
    return content_type != NULL &&
           (strcmp(content_type, "application/json") == 0 ||
            strcmp(content_type, "application/json; charset=utf-8") == 0);
}

/** @brief Read and strictly decode one bounded JSON object body. */
static int read_json_body(struct mg_connection *connection,
                          const struct mg_request_info *request,
                          uint32_t maximum_body_size,
                          json_t **body)
{
    const bool body_required = strcmp(request->request_method, "POST") == 0 ||
                               strcmp(request->request_method, "PUT") == 0 ||
                               strcmp(request->request_method, "PATCH") == 0;
    uint8_t *data = NULL;
    size_t offset = 0U;
    json_error_t error;
    int result = 0;

    *body = NULL;
    if (!body_required) {
        if (request->content_length > 0) {
            return -EINVAL;
        }
        *body = json_object();
        return *body == NULL ? -ENOMEM : 0;
    }
    if (!content_type_valid(mg_get_header(connection, "Content-Type")) ||
        request->content_length <= 0 ||
        (uint64_t)request->content_length > maximum_body_size) {
        return -EINVAL;
    }
    data = malloc((size_t)request->content_length);
    if (data == NULL) {
        return -ENOMEM;
    }
    while (result == 0 && offset < (size_t)request->content_length) {
        const int count = mg_read(connection, data + offset,
                                  (size_t)request->content_length - offset);

        if (count < 0) {
            result = -EIO;
        } else if (count == 0) {
            result = -EMSGSIZE;
        } else {
            offset += (size_t)count;
        }
    }
    if (result == 0) {
        *body = json_loadb((const char *)data, offset, JSON_REJECT_DUPLICATES,
                           &error);
        if (!json_is_object(*body)) {
            json_decref(*body);
            *body = NULL;
            result = -EINVAL;
        }
    }
    sodium_memzero(data, (size_t)request->content_length);
    free(data);
    return result;
}

/** @brief Copy one optional bounded header or an empty string. */
static int optional_header(const struct mg_connection *connection,
                           const char *name,
                           size_t maximum,
                           const char **value)
{
    const char *header = mg_get_header(connection, name);

    *value = header == NULL ? "" : header;
    return bounded_length(*value, maximum) <= maximum ? 0 : -EINVAL;
}

/** @brief Parse exactly one named cookie while rejecting duplicates. */
static int find_session_cookie(const struct mg_connection *connection,
                               char session[JG_AUTH_SECRET_TEXT_SIZE])
{
    const char *cookies = mg_get_header(connection, "Cookie");
    const size_t name_size = sizeof(session_cookie_name) - 1U;
    bool found = false;

    session[0U] = '\0';
    if (cookies == NULL) {
        return 0;
    }
    while (*cookies != '\0') {
        const char *end = strchr(cookies, ';');
        const char *equals = NULL;
        size_t field_size =
            end == NULL ? strlen(cookies) : (size_t)(end - cookies);

        while (field_size > 0U && (*cookies == ' ' || *cookies == '\t')) {
            ++cookies;
            --field_size;
        }
        while (field_size > 0U && (cookies[field_size - 1U] == ' ' ||
                                   cookies[field_size - 1U] == '\t')) {
            --field_size;
        }
        equals = memchr(cookies, '=', field_size);
        if (equals != NULL && (size_t)(equals - cookies) == name_size &&
            memcmp(cookies, session_cookie_name, name_size) == 0) {
            const size_t value_size = field_size - name_size - 1U;

            if (found || value_size != JG_AUTH_SECRET_TEXT_SIZE - 1U) {
                return -EINVAL;
            }
            (void)memcpy(session, equals + 1, value_size);
            session[value_size] = '\0';
            found = true;
        }
        if (end == NULL) {
            break;
        }
        cookies = end + 1;
    }
    return 0;
}

/** @brief Extract one exact bearer token without retaining its scheme. */
static int find_bearer_token(const struct mg_connection *connection,
                             char bearer[JG_AUTH_SECRET_TEXT_SIZE])
{
    static const char prefix[] = "Bearer ";
    const char *authorization = mg_get_header(connection, "Authorization");

    bearer[0U] = '\0';
    if (authorization == NULL) {
        return 0;
    }
    if (strlen(authorization) !=
            sizeof(prefix) - 1U + JG_AUTH_SECRET_TEXT_SIZE - 1U ||
        memcmp(authorization, prefix, sizeof(prefix) - 1U) != 0) {
        return -EINVAL;
    }
    (void)memcpy(bearer, authorization + sizeof(prefix) - 1U,
                 JG_AUTH_SECRET_TEXT_SIZE);
    return 0;
}

/** @brief Build one compact validated daemon request envelope. */
static int build_envelope(const struct mg_connection *connection,
                          const struct mg_request_info *request,
                          const struct jg_web_gateway_response *response,
                          json_t *body,
                          char **encoded,
                          size_t *encoded_size)
{
    const char *host = mg_get_header(connection, "Host");
    const char *origin = NULL;
    const char *csrf = NULL;
    char session[JG_AUTH_SECRET_TEXT_SIZE];
    char bearer[JG_AUTH_SECRET_TEXT_SIZE];
    json_t *envelope = NULL;
    int result = optional_header(connection, "Origin", 256U, &origin);

    *encoded = NULL;
    *encoded_size = 0U;
    if (result == 0) {
        result = optional_header(connection, "X-CSRF-Token",
                                 JG_AUTH_SECRET_TEXT_SIZE - 1U, &csrf);
    }
    if (result == 0) {
        result = find_session_cookie(connection, session);
    }
    if (result == 0) {
        result = find_bearer_token(connection, bearer);
    }
    if (result == 0 && (host == NULL || bounded_length(host, 128U) > 128U ||
                        bounded_length(request->remote_addr, 47U) > 47U)) {
        result = -EINVAL;
    }
    if (result == 0) {
        envelope = json_object();
        if (envelope == NULL ||
            json_object_set_new(envelope, "request_id",
                                json_string(response->request_id)) != 0 ||
            json_object_set_new(envelope, "method",
                                json_string(request->request_method)) != 0 ||
            json_object_set_new(envelope, "path",
                                json_string(request->local_uri)) != 0 ||
            json_object_set_new(envelope, "host", json_string(host)) != 0 ||
            json_object_set_new(envelope, "origin", json_string(origin)) != 0 ||
            json_object_set_new(envelope, "remote_address",
                                json_string(request->remote_addr)) != 0 ||
            json_object_set_new(envelope, "session", json_string(session)) !=
                0 ||
            json_object_set_new(envelope, "csrf", json_string(csrf)) != 0 ||
            json_object_set_new(envelope, "bearer", json_string(bearer)) != 0 ||
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
                free(*encoded);
                *encoded = NULL;
                *encoded_size = 0U;
                result = -EMSGSIZE;
            }
        }
    }
    sodium_memzero(session, sizeof(session));
    sodium_memzero(bearer, sizeof(bearer));
    json_decref(envelope);
    return result;
}

/** @brief Check whether a daemon response uses only the stable fields. */
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
            strcmp(name, "set_session") != 0 &&
            strcmp(name, "clear_session") != 0) {
            return false;
        }
    }
    return true;
}

/** @brief Validate and copy one complete daemon management response. */
static int parse_daemon_response(const uint8_t *data,
                                 size_t data_size,
                                 struct jg_web_gateway_response *response)
{
    json_error_t error;
    json_t *root = json_loadb((const char *)data, data_size,
                              JSON_REJECT_DUPLICATES, &error);
    json_t *status = NULL;
    json_t *body = NULL;
    json_t *set_session = NULL;
    json_t *clear_session = NULL;
    json_int_t status_value = 0;
    int result = 0;

    if (!response_fields_valid(root)) {
        result = -EPROTO;
    }
    if (result == 0) {
        status = json_object_get(root, "status");
        body = json_object_get(root, "body");
        set_session = json_object_get(root, "set_session");
        clear_session = json_object_get(root, "clear_session");
        if (!json_is_integer(status) || !json_is_object(body) ||
            (set_session != NULL && !json_is_string(set_session)) ||
            (clear_session != NULL && !json_is_true(clear_session)) ||
            (set_session != NULL && clear_session != NULL)) {
            result = -EPROTO;
        }
    }
    if (result == 0) {
        status_value = json_integer_value(status);
        if (status_value < 100 || status_value > 599) {
            result = -EPROTO;
        }
    }
    if (result == 0 && set_session != NULL) {
        const char *session = json_string_value(set_session);

        if (json_string_length(set_session) != JG_AUTH_SECRET_TEXT_SIZE - 1U) {
            result = -EPROTO;
        } else {
            (void)memcpy(response->session, session, JG_AUTH_SECRET_TEXT_SIZE);
            response->cookie_action = JG_WEB_COOKIE_SET;
        }
    }
    if (result == 0 && clear_session != NULL) {
        response->cookie_action = JG_WEB_COOKIE_CLEAR;
    }
    if (result == 0) {
        response->body = json_dumps(body, JSON_COMPACT | JSON_SORT_KEYS);
        if (response->body == NULL) {
            result = -ENOMEM;
        } else {
            response->body_size = strlen(response->body);
            response->status = (int)status_value;
        }
    }
    json_decref(root);
    return result;
}

/** @brief Determine whether one method is implemented by the API gateway. */
static bool method_valid(const char *method)
{
    return method != NULL &&
           (strcmp(method, "GET") == 0 || strcmp(method, "POST") == 0 ||
            strcmp(method, "PUT") == 0 || strcmp(method, "PATCH") == 0 ||
            strcmp(method, "DELETE") == 0);
}

/** @brief Translate one strict HTTPS request through authenticated local IPC.
 */
int jg_web_gateway_process(struct mg_connection *connection,
                           const char *control_socket_path,
                           uint32_t maximum_body_size,
                           struct jg_web_gateway_response *response)
{
    const struct mg_request_info *request = NULL;
    uint8_t daemon_response[JG_IPC_MAX_BODY_SIZE];
    json_t *body = NULL;
    char *envelope = NULL;
    size_t envelope_size = 0U;
    size_t daemon_response_size = 0U;
    int result = 0;

    if (connection == NULL || control_socket_path == NULL || response == NULL) {
        return -EINVAL;
    }
    (void)memset(response, 0, sizeof(*response));
    result = assign_request_id(connection, response->request_id);
    if (result == -EINVAL) {
        if (generate_request_id(response->request_id) != 0) {
            return -ENOMEM;
        }
        result = set_error_response(response, 400, "invalid_request_id",
                                    "The request identifier is not valid.");
        return result;
    }
    if (result != 0) {
        return -ENOMEM;
    }
    request = mg_get_request_info(connection);
    if (request == NULL || request->local_uri == NULL ||
        !method_valid(request->request_method) ||
        request->query_string != NULL) {
        return set_error_response(response, 400, "invalid_request",
                                  "The API request is not valid.");
    }
    result = read_json_body(connection, request, maximum_body_size, &body);
    if (result != 0) {
        return set_error_response(
            response, result == -ENOMEM ? 500 : 400,
            result == -ENOMEM ? "internal_error" : "invalid_body",
            result == -ENOMEM ? "The request could not be processed."
                              : "A bounded JSON object body is required.");
    }
    result = build_envelope(connection, request, response, body, &envelope,
                            &envelope_size);
    json_decref(body);
    if (result != 0) {
        return set_error_response(
            response, result == -ENOMEM ? 500 : 400,
            result == -ENOMEM ? "internal_error" : "invalid_request",
            result == -ENOMEM ? "The request could not be processed."
                              : "The API request is not valid.");
    }
    result = jg_ipc_client_call(control_socket_path, JG_IPC_MANAGEMENT_REQUEST,
                                (const uint8_t *)envelope, envelope_size,
                                daemon_response, sizeof(daemon_response),
                                &daemon_response_size);
    sodium_memzero(envelope, envelope_size);
    free(envelope);
    if (result != 0) {
        return set_error_response(
            response, 503, "management_unavailable",
            "The management service is temporarily unavailable.");
    }
    result =
        parse_daemon_response(daemon_response, daemon_response_size, response);
    sodium_memzero(daemon_response, daemon_response_size);
    if (result != 0) {
        jg_web_gateway_response_clear(response);
        if (assign_request_id(connection, response->request_id) != 0) {
            return -ENOMEM;
        }
        return set_error_response(
            response, 502, "invalid_management_response",
            "The management service returned an invalid response.");
    }
    return 0;
}

/** @brief Clear authentication material and free a gateway response. */
void jg_web_gateway_response_clear(struct jg_web_gateway_response *response)
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
