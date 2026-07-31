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

/** Largest raw API query string forwarded to the daemon. */
#define WEB_QUERY_SIZE_MAX 256U

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
            (void)memcpy(response->content_type,
                         "application/json; charset=utf-8",
                         sizeof("application/json; charset=utf-8"));
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
    const bool body_optional = strcmp(request->request_method, "DELETE") == 0;
    uint8_t *data = NULL;
    size_t offset = 0U;
    json_error_t error;
    int result = 0;

    *body = NULL;
    if (!body_required && (!body_optional || request->content_length == 0)) {
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

/** @brief Validate a bounded visible-ASCII API query string. */
static bool query_valid(const char *query)
{
    const size_t length =
        query == NULL ? 0U : bounded_length(query, WEB_QUERY_SIZE_MAX);

    if (length > WEB_QUERY_SIZE_MAX) {
        return false;
    }
    for (size_t index = 0U; index < length; ++index) {
        const uint8_t character = (uint8_t)query[index];

        if (character <= UINT8_C(0x20) || character >= UINT8_C(0x7f) ||
            character == (uint8_t)'#') {
            return false;
        }
    }
    return true;
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

/** @brief Validate one exact printable SHA-256 certificate fingerprint. */
static bool fingerprint_valid(const char *fingerprint)
{
    if (fingerprint == NULL || strlen(fingerprint) != 64U) {
        return false;
    }
    for (size_t index = 0U; index < 64U; ++index) {
        const char character = fingerprint[index];

        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f') ||
              (character >= 'A' && character <= 'F'))) {
            return false;
        }
    }
    return true;
}

/** @brief Build one compact validated daemon request envelope. */
static int build_envelope(const struct mg_connection *connection,
                          const struct mg_request_info *request,
                          const struct jg_web_gateway_response *response,
                          enum jg_web_gateway_mode mode,
                          const char *client_certificate,
                          json_t *body,
                          char **encoded,
                          size_t *encoded_size)
{
    const char *host = mg_get_header(connection, "Host");
    const char *query =
        request->query_string == NULL ? "" : request->query_string;
    const char *origin = NULL;
    const char *csrf = NULL;
    char session[JG_AUTH_SECRET_TEXT_SIZE];
    char bearer[JG_AUTH_SECRET_TEXT_SIZE];
    json_t *envelope = NULL;
    int result = mode == JG_WEB_GATEWAY_BROWSER
                     ? optional_header(connection, "Origin", 256U, &origin)
                     : 0;

    *encoded = NULL;
    *encoded_size = 0U;
    session[0U] = '\0';
    bearer[0U] = '\0';
    if (mode == JG_WEB_GATEWAY_REMOTE_API) {
        origin = "";
        csrf = "";
    }
    if (result == 0 && mode == JG_WEB_GATEWAY_BROWSER) {
        result = optional_header(connection, "X-CSRF-Token",
                                 JG_AUTH_SECRET_TEXT_SIZE - 1U, &csrf);
    }
    if (result == 0) {
        result = find_session_cookie(connection, session);
    }
    if (result == 0) {
        result = find_bearer_token(connection, bearer);
    }
    if (result == 0 &&
        ((mode == JG_WEB_GATEWAY_BROWSER && bearer[0U] != '\0') ||
         (mode == JG_WEB_GATEWAY_REMOTE_API &&
          (session[0U] != '\0' || bearer[0U] == '\0' ||
           !fingerprint_valid(client_certificate))) ||
         (mode != JG_WEB_GATEWAY_BROWSER &&
          mode != JG_WEB_GATEWAY_REMOTE_API))) {
        result = -EACCES;
    }
    if (result == 0 && (host == NULL || bounded_length(host, 128U) > 128U ||
                        bounded_length(request->remote_addr, 47U) > 47U ||
                        !query_valid(query))) {
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
            json_object_set_new(envelope, "query", json_string(query)) != 0 ||
            json_object_set_new(envelope, "host", json_string(host)) != 0 ||
            json_object_set_new(envelope, "origin", json_string(origin)) != 0 ||
            json_object_set_new(envelope, "remote_address",
                                json_string(request->remote_addr)) != 0 ||
            json_object_set_new(envelope, "session", json_string(session)) !=
                0 ||
            json_object_set_new(envelope, "csrf", json_string(csrf)) != 0 ||
            json_object_set_new(envelope, "bearer", json_string(bearer)) != 0 ||
            json_object_set_new(envelope, "client_certificate",
                                json_string(mode == JG_WEB_GATEWAY_REMOTE_API
                                                ? client_certificate
                                                : "")) != 0 ||
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
            strcmp(name, "content_type") != 0 && strcmp(name, "text") != 0 &&
            strcmp(name, "set_session") != 0 &&
            strcmp(name, "clear_session") != 0) {
            return false;
        }
    }
    return true;
}

/** @brief Validate and copy one complete daemon management response. */
int jg_web_gateway_decode_response(const uint8_t *data,
                                   size_t data_size,
                                   struct jg_web_gateway_response *response)
{
    json_error_t error;
    json_t *root = NULL;
    json_t *status = NULL;
    json_t *body = NULL;
    json_t *content_type = NULL;
    json_t *text = NULL;
    json_t *set_session = NULL;
    json_t *clear_session = NULL;
    json_int_t status_value = 0;
    int result = 0;

    if (data == NULL || data_size == 0U || response == NULL ||
        response->body != NULL) {
        return -EINVAL;
    }
    root = json_loadb((const char *)data, data_size, JSON_REJECT_DUPLICATES,
                      &error);
    if (!response_fields_valid(root)) {
        result = -EPROTO;
    }
    if (result == 0) {
        status = json_object_get(root, "status");
        body = json_object_get(root, "body");
        content_type = json_object_get(root, "content_type");
        text = json_object_get(root, "text");
        set_session = json_object_get(root, "set_session");
        clear_session = json_object_get(root, "clear_session");
        if (!json_is_integer(status) ||
            !((json_is_object(body) && content_type == NULL && text == NULL) ||
              (body == NULL && json_is_string(content_type) &&
               json_is_string(text))) ||
            (set_session != NULL && !json_is_string(set_session)) ||
            (clear_session != NULL && !json_is_true(clear_session)) ||
            (set_session != NULL && clear_session != NULL) ||
            (body == NULL && (set_session != NULL || clear_session != NULL))) {
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
    if (result == 0 && body != NULL) {
        response->body = json_dumps(body, JSON_COMPACT | JSON_SORT_KEYS);
        if (response->body == NULL) {
            result = -ENOMEM;
        } else {
            response->body_size = strlen(response->body);
            response->status = (int)status_value;
            (void)memcpy(response->content_type,
                         "application/json; charset=utf-8",
                         sizeof("application/json; charset=utf-8"));
        }
    }
    if (result == 0 && text != NULL) {
        static const char prometheus_type[] =
            "text/plain; version=0.0.4; charset=utf-8";
        const char *media_type = json_string_value(content_type);
        const char *text_value = json_string_value(text);
        const size_t text_size = json_string_length(text);

        if (strcmp(media_type, prometheus_type) != 0 ||
            memchr(text_value, '\0', text_size) != NULL) {
            result = -EPROTO;
        } else {
            response->body = malloc(text_size + 1U);
            if (response->body == NULL) {
                result = -ENOMEM;
            } else {
                (void)memcpy(response->body, text_value, text_size);
                response->body[text_size] = '\0';
                response->body_size = text_size;
                response->status = (int)status_value;
                (void)memcpy(response->content_type, prometheus_type,
                             sizeof(prometheus_type));
            }
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
                           enum jg_web_gateway_mode mode,
                           const char *client_certificate,
                           struct jg_web_gateway_response *response)
{
    const struct mg_request_info *request = NULL;
    uint8_t *daemon_response = NULL;
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
        !method_valid(request->request_method)) {
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
    result =
        build_envelope(connection, request, response, mode, client_certificate,
                       body, &envelope, &envelope_size);
    json_decref(body);
    if (result != 0) {
        return set_error_response(
            response,
            result == -ENOMEM   ? 500
            : result == -EACCES ? 401
                                : 400,
            result == -ENOMEM   ? "internal_error"
            : result == -EACCES ? "authentication_required"
                                : "invalid_request",
            result == -ENOMEM ? "The request could not be processed."
            : result == -EACCES
                ? "The listener requires its designated authentication."
                : "The API request is not valid.");
    }
    daemon_response = malloc(JG_IPC_MAX_BODY_SIZE);
    if (daemon_response == NULL) {
        sodium_memzero(envelope, envelope_size);
        free(envelope);
        return set_error_response(response, 500, "internal_error",
                                  "The request could not be processed.");
    }
    result = jg_ipc_client_call(control_socket_path, JG_IPC_MANAGEMENT_REQUEST,
                                (const uint8_t *)envelope, envelope_size,
                                daemon_response, JG_IPC_MAX_BODY_SIZE,
                                &daemon_response_size);
    sodium_memzero(envelope, envelope_size);
    free(envelope);
    if (result != 0) {
        sodium_memzero(daemon_response, JG_IPC_MAX_BODY_SIZE);
        free(daemon_response);
        return set_error_response(
            response, 503, "management_unavailable",
            "The management service is temporarily unavailable.");
    }
    result = jg_web_gateway_decode_response(daemon_response,
                                            daemon_response_size, response);
    sodium_memzero(daemon_response, JG_IPC_MAX_BODY_SIZE);
    free(daemon_response);
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
