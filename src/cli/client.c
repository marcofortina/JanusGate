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

#include <curl/curl.h>
#include <sodium.h>

#include "janusgate/ipc.h"
#include "janusgate/ipc_client.h"

/** Largest accepted CLI query string. */
#define CLI_QUERY_SIZE_MAX 256U

/** Largest accepted HTTPS origin bytes excluding the terminator. */
#define CLI_ENDPOINT_SIZE_MAX 2048U

/** Stable media type used by JSON management responses. */
static const char json_content_type[] = "application/json; charset=utf-8";

/** Stable media type used by Prometheus management responses. */
static const char metrics_content_type[] =
    "text/plain; version=0.0.4; charset=utf-8";

/** Bounded body accumulated by the libcurl write callback. */
struct remote_body {
    char *data;
    size_t size;
};

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

/** @brief Validate an HTTPS origin without credentials, paths, or queries. */
static bool endpoint_valid(const char *endpoint)
{
    static const char prefix[] = "https://";
    size_t size = 0U;

    if (endpoint == NULL ||
        strncmp(endpoint, prefix, sizeof(prefix) - 1U) != 0) {
        return false;
    }
    while (size <= CLI_ENDPOINT_SIZE_MAX && endpoint[size] != '\0') {
        if (!visible_ascii(endpoint[size])) {
            return false;
        }
        ++size;
    }
    if (size <= sizeof(prefix) - 1U || size > CLI_ENDPOINT_SIZE_MAX ||
        endpoint[sizeof(prefix) - 1U] == '/' ||
        endpoint[sizeof(prefix) - 1U] == ':' ||
        strchr(endpoint + sizeof(prefix) - 1U, '@') != NULL ||
        strchr(endpoint, '?') != NULL || strchr(endpoint, '#') != NULL ||
        strchr(endpoint, '\\') != NULL) {
        return false;
    }
    const char *slash = strchr(endpoint + sizeof(prefix) - 1U, '/');

    return slash == NULL || slash[1U] == '\0';
}

/** @brief Validate an optional absolute file path. */
static bool optional_path_valid(const char *path)
{
    return path == NULL || path[0U] == '/';
}

/** @brief Translate one libcurl transport result to errno style. */
static int curl_result(CURLcode status)
{
    switch (status) {
    case CURLE_OK:
        return 0;
    case CURLE_OPERATION_TIMEDOUT:
        return -ETIMEDOUT;
    case CURLE_OUT_OF_MEMORY:
        return -ENOMEM;
    case CURLE_PEER_FAILED_VERIFICATION:
    case CURLE_SSL_CERTPROBLEM:
    case CURLE_SSL_CONNECT_ERROR:
        return -EACCES;
    case CURLE_UNSUPPORTED_PROTOCOL:
    case CURLE_URL_MALFORMAT:
        return -EINVAL;
    case CURLE_WRITE_ERROR:
        return -EMSGSIZE;
    default:
        return -EIO;
    }
}

/** @brief Append bounded HTTPS response bytes. */
static size_t receive_remote_body(char *data,
                                  size_t element_size,
                                  size_t element_count,
                                  void *context)
{
    struct remote_body *body = context;
    size_t received = 0U;
    char *updated = NULL;

    if (element_count != 0U && element_size > SIZE_MAX / element_count) {
        return 0U;
    }
    received = element_size * element_count;
    if (received > JG_IPC_MAX_BODY_SIZE - body->size) {
        return 0U;
    }
    updated = realloc(body->data, body->size + received + 1U);
    if (updated == NULL) {
        return 0U;
    }
    body->data = updated;
    (void)memcpy(body->data + body->size, data, received);
    body->size += received;
    body->data[body->size] = '\0';
    return received;
}

/** @brief Initialize conservative remote-management defaults. */
void jg_cli_remote_config_default(struct jg_cli_remote_config *config)
{
    if (config == NULL) {
        return;
    }
    *config = (struct jg_cli_remote_config){
        .timeout_seconds = JG_CLI_REMOTE_TIMEOUT_DEFAULT,
    };
}

/** @brief Validate one complete remote-management configuration. */
int jg_cli_remote_config_validate(const struct jg_cli_remote_config *config)
{
    if (config == NULL || !endpoint_valid(config->endpoint) ||
        config->token == NULL ||
        strlen(config->token) != JG_AUTH_SECRET_TEXT_SIZE - 1U ||
        !optional_path_valid(config->client_certificate) ||
        !optional_path_valid(config->client_key) ||
        !optional_path_valid(config->ca_file) ||
        ((config->client_certificate == NULL) !=
         (config->client_key == NULL))) {
        return -EINVAL;
    }
    return config->timeout_seconds == 0U ||
                   config->timeout_seconds > JG_CLI_REMOTE_TIMEOUT_MAX
               ? -ERANGE
               : 0;
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

/** @brief Validate and normalize one remote HTTP response. */
int jg_cli_http_response_decode(long status,
                                const char *content_type,
                                const void *data,
                                size_t data_size,
                                struct jg_cli_response *response)
{
    json_error_t error;
    json_t *body = NULL;
    int result = 0;

    if (status < 100L || status > 599L || content_type == NULL ||
        data == NULL || data_size == 0U || data_size > JG_IPC_MAX_BODY_SIZE ||
        response == NULL || response->body != NULL) {
        return -EINVAL;
    }
    if (strcmp(content_type, "application/json") == 0 ||
        strcmp(content_type, json_content_type) == 0) {
        body = json_loadb(data, data_size, JSON_REJECT_DUPLICATES, &error);
        if (!json_is_object(body)) {
            result = -EPROTO;
        } else {
            response->body = json_dumps(body, JSON_COMPACT | JSON_SORT_KEYS);
            if (response->body == NULL) {
                result = -ENOMEM;
            } else {
                response->body_size = strlen(response->body);
                (void)memcpy(response->content_type, json_content_type,
                             sizeof(json_content_type));
            }
        }
        json_decref(body);
    } else if (strcmp(content_type, metrics_content_type) == 0 &&
               memchr(data, '\0', data_size) == NULL) {
        response->body = malloc(data_size + 1U);
        if (response->body == NULL) {
            result = -ENOMEM;
        } else {
            (void)memcpy(response->body, data, data_size);
            response->body[data_size] = '\0';
            response->body_size = data_size;
            (void)memcpy(response->content_type, metrics_content_type,
                         sizeof(metrics_content_type));
        }
    } else {
        result = -EPROTO;
    }
    if (result == 0) {
        response->status = (int)status;
    } else {
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
    uint8_t *daemon_response = NULL;
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
    daemon_response = malloc(JG_IPC_MAX_BODY_SIZE);
    if (daemon_response == NULL) {
        return -ENOMEM;
    }
    result = build_envelope(token, method, path, query, body, response,
                            &envelope, &envelope_size);
    if (result == 0) {
        result = jg_ipc_client_call(socket_path, JG_IPC_MANAGEMENT_REQUEST,
                                    (const uint8_t *)envelope, envelope_size,
                                    daemon_response, JG_IPC_MAX_BODY_SIZE,
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
    free(daemon_response);
    if (result != 0) {
        jg_cli_response_clear(response);
    }
    return result;
}

/** @brief Build one bounded remote API URL. */
static int build_remote_url(const char *endpoint,
                            const char *path,
                            const char *query,
                            char **url)
{
    const size_t endpoint_size = strlen(endpoint);
    const bool trailing_slash = endpoint[endpoint_size - 1U] == '/';
    const size_t path_size = strlen(path);
    const size_t query_size = query == NULL ? 0U : strlen(query);
    const size_t required = endpoint_size - (trailing_slash ? 1U : 0U) +
                            path_size + (query_size == 0U ? 0U : 1U) +
                            query_size;
    size_t offset = 0U;

    if (required > SIZE_MAX - 1U) {
        return -EOVERFLOW;
    }
    *url = malloc(required + 1U);
    if (*url == NULL) {
        return -ENOMEM;
    }
    offset = endpoint_size - (trailing_slash ? 1U : 0U);
    (void)memcpy(*url, endpoint, offset);
    (void)memcpy(*url + offset, path, path_size);
    offset += path_size;
    if (query_size != 0U) {
        (*url)[offset++] = '?';
        (void)memcpy(*url + offset, query, query_size);
        offset += query_size;
    }
    (*url)[offset] = '\0';
    return 0;
}

/** @brief Append one HTTP request header while preserving prior entries. */
static int append_header(struct curl_slist **headers,
                         const char *name,
                         const char *value)
{
    const size_t name_size = strlen(name);
    const size_t value_size = strlen(value);
    char *line = NULL;
    struct curl_slist *updated = NULL;

    if (name_size > SIZE_MAX - value_size - 3U) {
        return -EOVERFLOW;
    }
    line = malloc(name_size + value_size + 3U);
    if (line == NULL) {
        return -ENOMEM;
    }
    (void)memcpy(line, name, name_size);
    line[name_size] = ':';
    line[name_size + 1U] = ' ';
    (void)memcpy(line + name_size + 2U, value, value_size + 1U);
    updated = curl_slist_append(*headers, line);
    sodium_memzero(line, name_size + value_size + 3U);
    free(line);
    if (updated == NULL) {
        return -ENOMEM;
    }
    *headers = updated;
    return 0;
}

/** @brief Erase header values before releasing their curl list. */
static void clear_headers(struct curl_slist *headers)
{
    struct curl_slist *current = headers;

    while (current != NULL) {
        if (current->data != NULL) {
            sodium_memzero(current->data, strlen(current->data));
        }
        current = current->next;
    }
    curl_slist_free_all(headers);
}

/** @brief Perform one authenticated management request over HTTPS. */
int jg_cli_remote_request(const struct jg_cli_remote_config *config,
                          const char *method,
                          const char *path,
                          const char *query,
                          json_t *body,
                          struct jg_cli_response *response)
{
    struct remote_body received = {0};
    uint8_t digest[JG_AUTH_SECRET_DIGEST_SIZE];
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    char authorization[sizeof("Bearer ") + JG_AUTH_SECRET_TEXT_SIZE];
    char *encoded = NULL;
    char *url = NULL;
    char *content_type = NULL;
    long status = 0L;
    CURLcode curl_status = CURLE_OK;
    bool curl_initialized = false;
    int result = jg_cli_remote_config_validate(config);

    if (result == 0 &&
        (!method_valid(method) || !path_valid(path) || !query_valid(query) ||
         !json_is_object(body) || response == NULL || response->body != NULL)) {
        result = -EINVAL;
    }
    if (result == 0) {
        result = jg_auth_secret_issue(response->request_id, digest);
        sodium_memzero(digest, sizeof(digest));
    }
    if (result == 0) {
        result = build_remote_url(config->endpoint, path, query, &url);
    }
    if (result == 0 && strcmp(method, "GET") != 0) {
        encoded = json_dumps(body, JSON_COMPACT | JSON_SORT_KEYS);
        if (encoded == NULL) {
            result = -ENOMEM;
        } else if (strlen(encoded) > JG_IPC_MAX_BODY_SIZE) {
            result = -EMSGSIZE;
        }
    }
    if (result == 0) {
        (void)memcpy(authorization, "Bearer ", sizeof("Bearer ") - 1U);
        (void)memcpy(authorization + sizeof("Bearer ") - 1U, config->token,
                     JG_AUTH_SECRET_TEXT_SIZE);
        result = append_header(&headers, "Accept", "application/json");
    }
    if (result == 0) {
        result = append_header(&headers, "Authorization", authorization);
    }
    if (result == 0) {
        result = append_header(&headers, "X-Request-ID", response->request_id);
    }
    if (result == 0 && encoded != NULL) {
        result = append_header(&headers, "Content-Type", "application/json");
    }
    if (result == 0 && curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        result = -EIO;
    } else if (result == 0) {
        curl_initialized = true;
    }
    if (result == 0) {
        curl = curl_easy_init();
        if (curl == NULL) {
            result = -ENOMEM;
        }
    }
#define JG_CLI_CURL_SETOPT(option, value)                                      \
    do {                                                                       \
        if (result == 0) {                                                     \
            curl_status = curl_easy_setopt(curl, (option), (value));           \
            result = curl_result(curl_status);                                 \
        }                                                                      \
    } while (false)
    JG_CLI_CURL_SETOPT(CURLOPT_URL, url);
    JG_CLI_CURL_SETOPT(CURLOPT_PROTOCOLS_STR, "https");
    JG_CLI_CURL_SETOPT(CURLOPT_FOLLOWLOCATION, 0L);
    JG_CLI_CURL_SETOPT(CURLOPT_CONNECTTIMEOUT, (long)config->timeout_seconds);
    JG_CLI_CURL_SETOPT(CURLOPT_TIMEOUT, (long)config->timeout_seconds);
    JG_CLI_CURL_SETOPT(CURLOPT_SSL_VERIFYPEER, 1L);
    JG_CLI_CURL_SETOPT(CURLOPT_SSL_VERIFYHOST, 2L);
    JG_CLI_CURL_SETOPT(CURLOPT_NOSIGNAL, 1L);
    JG_CLI_CURL_SETOPT(CURLOPT_ACCEPT_ENCODING, "");
    JG_CLI_CURL_SETOPT(CURLOPT_USERAGENT, "janusgatectl/0.1");
    JG_CLI_CURL_SETOPT(CURLOPT_CUSTOMREQUEST, method);
    JG_CLI_CURL_SETOPT(CURLOPT_HTTPHEADER, headers);
    JG_CLI_CURL_SETOPT(CURLOPT_WRITEFUNCTION, receive_remote_body);
    JG_CLI_CURL_SETOPT(CURLOPT_WRITEDATA, &received);
    if (encoded != NULL) {
        JG_CLI_CURL_SETOPT(CURLOPT_POSTFIELDS, encoded);
        JG_CLI_CURL_SETOPT(CURLOPT_POSTFIELDSIZE_LARGE,
                           (curl_off_t)strlen(encoded));
    }
    if (result == 0 && config->client_certificate != NULL) {
        JG_CLI_CURL_SETOPT(CURLOPT_SSLCERT, config->client_certificate);
        JG_CLI_CURL_SETOPT(CURLOPT_SSLKEY, config->client_key);
    }
    if (result == 0 && config->ca_file != NULL) {
        JG_CLI_CURL_SETOPT(CURLOPT_CAINFO, config->ca_file);
    }
#undef JG_CLI_CURL_SETOPT
    if (result == 0) {
        curl_status = curl_easy_perform(curl);
        result = curl_result(curl_status);
    }
    if (result == 0) {
        curl_status = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        result = curl_result(curl_status);
    }
    if (result == 0) {
        curl_status =
            curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
        result = curl_result(curl_status);
    }
    if (result == 0) {
        result = jg_cli_http_response_decode(
            status, content_type, received.data, received.size, response);
    }
    if (curl != NULL) {
        curl_easy_cleanup(curl);
    }
    clear_headers(headers);
    if (curl_initialized) {
        curl_global_cleanup();
    }
    sodium_memzero(authorization, sizeof(authorization));
    if (encoded != NULL) {
        sodium_memzero(encoded, strlen(encoded));
        free(encoded);
    }
    if (received.data != NULL) {
        sodium_memzero(received.data, received.size);
        free(received.data);
    }
    free(url);
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
