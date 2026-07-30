/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "web_server.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <civetweb.h>

#include "web_gateway.h"

/** Largest static administration asset accepted by the server. */
#define JG_WEB_ASSET_SIZE_MAX (2U * 1024U * 1024U)

/** Shared security headers excluding optional HSTS. */
static const char security_headers[] =
    "Content-Security-Policy: default-src 'self'; script-src 'self'; "
    "style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "Permissions-Policy: camera=(), microphone=(), geolocation=(), "
    "payment=(), usb=()\r\n"
    "X-Frame-Options: DENY\r\n";

/** Fixed HSTS policy enabled only after setup is complete. */
static const char hsts_header[] =
    "Strict-Transport-Security: max-age=31536000\r\n";

/** One allowlisted local administration asset. */
struct web_asset {
    const char *uri;
    const char *relative_path;
    const char *content_type;
    bool sensitive;
};

/** Local files reachable through the management listener. */
static const struct web_asset web_assets[] = {
    {"/", "index.html", "text/html; charset=utf-8", true},
    {"/index.html", "index.html", "text/html; charset=utf-8", true},
    {"/css/app.css", "css/app.css", "text/css; charset=utf-8", false},
    {"/js/app.js", "js/app.js", "text/javascript; charset=utf-8", false},
    {"/js/api.js", "js/api.js", "text/javascript; charset=utf-8", false},
    {"/js/dashboard.js", "js/dashboard.js", "text/javascript; charset=utf-8",
     false},
    {"/js/network.js", "js/network.js", "text/javascript; charset=utf-8",
     false},
    {"/js/policies.js", "js/policies.js", "text/javascript; charset=utf-8",
     false},
    {"/js/ui.js", "js/ui.js", "text/javascript; charset=utf-8", false},
    {"/manifest.webmanifest", "manifest.webmanifest",
     "application/manifest+json", false},
    {"/icons/shield.svg", "icons/shield.svg", "image/svg+xml", false},
};

/** Complete ownership of one CivetWeb server. */
struct jg_web_server {
    struct mg_context *context;
    struct jg_web_config config;
    char *listen_address;
    char *certificate_path;
    char *web_root;
    char *control_socket_path;
};

/** @brief Initialize secure first-boot web defaults. */
void jg_web_config_default(struct jg_web_config *config)
{
    if (config != NULL) {
        *config = (struct jg_web_config){
            .listen_address = JG_WEB_DEFAULT_ADDRESS,
            .port = JG_WEB_DEFAULT_PORT,
            .certificate_path = JG_WEB_DEFAULT_CERTIFICATE,
            .web_root = JG_WEB_DEFAULT_ROOT,
            .control_socket_path = JG_CONTROL_SOCKET_PATH,
            .max_request_size = 65536U,
            .worker_count = 8U,
            .hsts = false,
        };
    }
}

/** @brief Check that one path is absolute and free of control bytes. */
static bool absolute_path_valid(const char *path)
{
    size_t size = 0U;

    if (path == NULL || path[0U] != '/' || path[1U] == '\0') {
        return false;
    }
    while (size < PATH_MAX && path[size] != '\0') {
        const uint8_t character = (uint8_t)path[size];

        if (character < UINT8_C(0x20) || character == UINT8_C(0x7f)) {
            return false;
        }
        ++size;
    }
    return size > 1U && size < PATH_MAX;
}

/** @brief Validate a numeric non-wildcard management address. */
static int address_family(const char *address)
{
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (address == NULL) {
        return AF_UNSPEC;
    }
    if (inet_pton(AF_INET, address, &ipv4) == 1) {
        const uint32_t host = ntohl(ipv4.s_addr);

        if (host == 0U ||
            (host & UINT32_C(0xf0000000)) == UINT32_C(0xe0000000)) {
            return AF_UNSPEC;
        }
        return AF_INET;
    }
    if (inet_pton(AF_INET6, address, &ipv6) == 1 &&
        !IN6_IS_ADDR_UNSPECIFIED(&ipv6) && !IN6_IS_ADDR_MULTICAST(&ipv6)) {
        return AF_INET6;
    }
    return AF_UNSPEC;
}

/** @brief Validate complete HTTPS process configuration. */
int jg_web_config_validate(const struct jg_web_config *config)
{
    if (config == NULL || address_family(config->listen_address) == AF_UNSPEC ||
        config->port == 0U || !absolute_path_valid(config->certificate_path) ||
        !absolute_path_valid(config->web_root) ||
        !absolute_path_valid(config->control_socket_path)) {
        return -EINVAL;
    }
    if (config->max_request_size < 4096U ||
        config->max_request_size > JG_WEB_REQUEST_SIZE_MAX ||
        config->worker_count < 2U || config->worker_count > 64U) {
        return -ERANGE;
    }
    return 0;
}

/** @brief Build one exact TLS-only CivetWeb listener expression. */
int jg_web_build_listener(const struct jg_web_config *config,
                          char *output,
                          size_t output_size)
{
    const int family =
        config == NULL ? AF_UNSPEC : address_family(config->listen_address);
    int written = 0;
    int result = jg_web_config_validate(config);

    if (output == NULL) {
        return -EINVAL;
    }
    if (output_size != 0U) {
        output[0U] = '\0';
    }
    if (result != 0) {
        return result;
    }
    if (family == AF_INET6) {
        written = snprintf(output, output_size, "[%s]:%us",
                           config->listen_address, (unsigned int)config->port);
    } else {
        written = snprintf(output, output_size, "%s:%us",
                           config->listen_address, (unsigned int)config->port);
    }
    return written < 0 || (size_t)written >= output_size ? -ENOSPC : 0;
}

/** @brief Duplicate one required bounded configuration string. */
static int duplicate_string(const char *input, char **output)
{
    const size_t size = strlen(input) + 1U;

    *output = malloc(size);
    if (*output == NULL) {
        return -ENOMEM;
    }
    (void)memcpy(*output, input, size);
    return 0;
}

/** @brief Validate one secure regular certificate PEM without symlinks. */
static int validate_certificate(const char *path)
{
    struct stat metadata;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int result = 0;

    if (descriptor < 0) {
        return -errno;
    }
    if (fstat(descriptor, &metadata) != 0) {
        result = -errno;
    } else if (!S_ISREG(metadata.st_mode) ||
               (metadata.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) != 0U) {
        result = -EACCES;
    }
    if (close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    return result;
}

/** @brief Validate the installed asset root against writable substitution. */
static int validate_web_root(const char *path)
{
    struct stat metadata;

    if (lstat(path, &metadata) != 0) {
        return -errno;
    }
    if (!S_ISDIR(metadata.st_mode) ||
        (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0U ||
        (metadata.st_uid != 0U && metadata.st_uid != geteuid())) {
        return -EACCES;
    }
    return 0;
}

/** @brief Find one request header case-insensitively through CivetWeb. */
static const char *request_header(const struct mg_connection *connection,
                                  const char *name)
{
    return mg_get_header(connection, name);
}

/** @brief Validate the request Host against the configured listener address. */
static bool host_valid(const struct mg_connection *connection,
                       const struct jg_web_config *config)
{
    const char *host = request_header(connection, "Host");
    char expected[INET6_ADDRSTRLEN + 16U];
    char expected_without_port[INET6_ADDRSTRLEN + 4U];
    int written = 0;

    if (host == NULL) {
        return false;
    }
    if (address_family(config->listen_address) == AF_INET6) {
        written = snprintf(expected, sizeof(expected), "[%s]:%u",
                           config->listen_address, (unsigned int)config->port);
        (void)snprintf(expected_without_port, sizeof(expected_without_port),
                       "[%s]", config->listen_address);
    } else {
        written = snprintf(expected, sizeof(expected), "%s:%u",
                           config->listen_address, (unsigned int)config->port);
        (void)snprintf(expected_without_port, sizeof(expected_without_port),
                       "%s", config->listen_address);
    }
    return written > 0 && (size_t)written < sizeof(expected) &&
           (strcmp(host, expected) == 0 ||
            strcmp(host, expected_without_port) == 0);
}

/** @brief Write a complete bounded HTTP response header. */
static int send_header(struct mg_connection *connection,
                       int status,
                       const char *reason,
                       const char *content_type,
                       uint64_t content_length,
                       bool sensitive,
                       bool hsts,
                       const char *extra_headers)
{
    int written = mg_printf(
        connection,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %llu\r\n"
        "Cache-Control: %s\r\n"
        "%s%s%s"
        "Connection: close\r\n\r\n",
        status, reason, content_type, (unsigned long long)content_length,
        sensitive ? "no-store" : "no-cache", security_headers,
        hsts ? hsts_header : "", extra_headers);

    return written < 0 ? -EIO : 0;
}

/** @brief Send one fixed JSON response with all management headers. */
static int send_json(struct mg_connection *connection,
                     int status,
                     const char *reason,
                     const char *body,
                     bool hsts)
{
    const size_t body_size = strlen(body);
    int result = send_header(connection, status, reason,
                             "application/json; charset=utf-8", body_size, true,
                             hsts, "");

    if (result == 0 &&
        mg_write(connection, body, body_size) != (int)body_size) {
        result = -EIO;
    }
    return result;
}

/** @brief Find an allowlisted static asset by exact clean URI. */
static const struct web_asset *find_asset(const char *uri)
{
    for (size_t index = 0U; index < sizeof(web_assets) / sizeof(web_assets[0U]);
         ++index) {
        if (strcmp(uri, web_assets[index].uri) == 0) {
            return &web_assets[index];
        }
    }
    return NULL;
}

/** @brief Stream one verified regular asset without path traversal. */
static int send_asset(struct mg_connection *connection,
                      const struct jg_web_config *config,
                      const struct web_asset *asset,
                      bool head_only)
{
    char path[PATH_MAX];
    uint8_t buffer[16384U];
    struct stat metadata;
    int descriptor = -1;
    int written = snprintf(path, sizeof(path), "%s/%s", config->web_root,
                           asset->relative_path);
    int result = 0;

    if (written < 0 || (size_t)written >= sizeof(path)) {
        return -ENAMETOOLONG;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return -errno;
    }
    if (fstat(descriptor, &metadata) != 0) {
        result = -errno;
    } else if (!S_ISREG(metadata.st_mode) || metadata.st_size < 0 ||
               (uint64_t)metadata.st_size > JG_WEB_ASSET_SIZE_MAX) {
        result = -EACCES;
    }
    if (result == 0) {
        result = send_header(connection, 200, "OK", asset->content_type,
                             (uint64_t)metadata.st_size, asset->sensitive,
                             config->hsts, "");
    }
    while (result == 0 && !head_only) {
        const ssize_t received = read(descriptor, buffer, sizeof(buffer));

        if (received < 0) {
            result = -errno;
        } else if (received == 0) {
            break;
        } else if (mg_write(connection, buffer, (size_t)received) !=
                   (int)received) {
            result = -EPIPE;
        }
    }
    (void)close(descriptor);
    return result;
}

/** @brief Return a conservative reason phrase for one gateway status. */
static const char *status_reason(int status)
{
    switch (status) {
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 204:
        return "No Content";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 409:
        return "Conflict";
    case 412:
        return "Precondition Failed";
    case 413:
        return "Content Too Large";
    case 415:
        return "Unsupported Media Type";
    case 422:
        return "Unprocessable Content";
    case 429:
        return "Too Many Requests";
    case 500:
        return "Internal Server Error";
    case 502:
        return "Bad Gateway";
    case 503:
        return "Service Unavailable";
    default:
        return "Management Response";
    }
}

/** @brief Build safe response-only headers for one gateway result. */
static int gateway_headers(const struct jg_web_gateway_response *response,
                           char *headers,
                           size_t headers_size)
{
    const char *cookie = "";
    char cookie_header[256U] = "";
    int written = 0;

    if (response->cookie_action == JG_WEB_COOKIE_SET) {
        written = snprintf(
            cookie_header, sizeof(cookie_header),
            "Set-Cookie: janusgate_session=%s; Path=/; Secure; HttpOnly; "
            "SameSite=Strict\r\n",
            response->session);
        if (written < 0 || (size_t)written >= sizeof(cookie_header)) {
            return -ENOSPC;
        }
        cookie = cookie_header;
    } else if (response->cookie_action == JG_WEB_COOKIE_CLEAR) {
        cookie = "Set-Cookie: janusgate_session=; Path=/; Max-Age=0; Secure; "
                 "HttpOnly; SameSite=Strict\r\n";
    }
    written = snprintf(headers, headers_size,
                       "X-Request-ID: %s\r\n"
                       "Vary: Cookie, Authorization\r\n"
                       "%s",
                       response->request_id, cookie);
    return written < 0 || (size_t)written >= headers_size ? -ENOSPC : 0;
}

/** @brief Process and send one validated management API response. */
static int send_gateway_response(struct mg_connection *connection,
                                 const struct jg_web_server *server)
{
    struct jg_web_gateway_response response;
    char headers[512U];
    int result =
        jg_web_gateway_process(connection, server->config.control_socket_path,
                               server->config.max_request_size, &response);
    int status = 500;

    if (result == 0) {
        result = gateway_headers(&response, headers, sizeof(headers));
    }
    if (result == 0) {
        status = response.status;
        result =
            send_header(connection, response.status,
                        status_reason(response.status), response.content_type,
                        response.body_size, true, server->config.hsts, headers);
    }
    if (result == 0 && response.body_size != 0U &&
        mg_write(connection, response.body, response.body_size) !=
            (int)response.body_size) {
        result = -EPIPE;
    }
    jg_web_gateway_response_clear(&response);
    if (result != 0 && result != -EPIPE) {
        (void)send_json(connection, 500, "Internal Server Error",
                        "{\"error\":{\"code\":\"internal_error\","
                        "\"message\":\"The request could not be "
                        "processed.\"}}\n",
                        server->config.hsts);
    }
    return result == 0 ? status : 500;
}

/** @brief Dispatch one HTTPS management request. */
static int handle_request(struct mg_connection *connection, void *context)
{
    const struct jg_web_server *server = context;
    const struct mg_request_info *request = mg_get_request_info(connection);
    const struct web_asset *asset = NULL;
    bool head_only = false;
    int result = 0;
    int status = 200;

    if (request == NULL || request->local_uri == NULL ||
        request->request_method == NULL || request->is_ssl != 1 ||
        !host_valid(connection, &server->config)) {
        (void)send_json(connection, 400, "Bad Request",
                        "{\"error\":{\"code\":\"invalid_request\","
                        "\"message\":\"The request is not valid.\"}}\n",
                        server->config.hsts);
        return 400;
    }
    if (strcmp(request->local_uri, "/healthz") == 0) {
        if (strcmp(request->request_method, "GET") != 0) {
            (void)send_json(connection, 405, "Method Not Allowed",
                            "{\"error\":{\"code\":\"method_not_allowed\","
                            "\"message\":\"The method is not allowed.\"}}\n",
                            server->config.hsts);
            return 405;
        }
        result =
            send_json(connection, 200, "OK",
                      "{\"status\":\"ok\",\"service\":\"janusgate-web\"}\n",
                      server->config.hsts);
        return result == 0 ? 200 : 500;
    }
    if (strncmp(request->local_uri, "/api/v1/", sizeof("/api/v1/") - 1U) == 0) {
        return send_gateway_response(connection, server);
    }
    asset = find_asset(request->local_uri);
    if (asset == NULL) {
        (void)send_json(connection, 404, "Not Found",
                        "{\"error\":{\"code\":\"not_found\","
                        "\"message\":\"The resource was not found.\"}}\n",
                        server->config.hsts);
        return 404;
    }
    head_only = strcmp(request->request_method, "HEAD") == 0;
    if (!head_only && strcmp(request->request_method, "GET") != 0) {
        (void)send_json(connection, 405, "Method Not Allowed",
                        "{\"error\":{\"code\":\"method_not_allowed\","
                        "\"message\":\"The method is not allowed.\"}}\n",
                        server->config.hsts);
        return 405;
    }
    result = send_asset(connection, &server->config, asset, head_only);
    if (result != 0) {
        status = result == -ENOENT ? 404 : 500;
        if (result != -EPIPE) {
            (void)send_json(
                connection, status,
                status == 404 ? "Not Found" : "Internal Server Error",
                status == 404
                    ? "{\"error\":{\"code\":\"not_found\","
                      "\"message\":\"The resource was not found.\"}}\n"
                    : "{\"error\":{\"code\":\"internal_error\","
                      "\"message\":\"The resource could not be read.\"}}\n",
                server->config.hsts);
        }
    }
    return status;
}

/** @brief Copy configuration strings into server-owned storage. */
static int own_config(struct jg_web_server *server,
                      const struct jg_web_config *config)
{
    int result =
        duplicate_string(config->listen_address, &server->listen_address);

    if (result == 0) {
        result = duplicate_string(config->certificate_path,
                                  &server->certificate_path);
    }
    if (result == 0) {
        result = duplicate_string(config->web_root, &server->web_root);
    }
    if (result == 0) {
        result = duplicate_string(config->control_socket_path,
                                  &server->control_socket_path);
    }
    if (result == 0) {
        server->config = *config;
        server->config.listen_address = server->listen_address;
        server->config.certificate_path = server->certificate_path;
        server->config.web_root = server->web_root;
        server->config.control_socket_path = server->control_socket_path;
    }
    return result;
}

/** @brief Start one TLS-only CivetWeb management context. */
int jg_web_server_start(const struct jg_web_config *config,
                        struct jg_web_server **server)
{
    struct jg_web_server *started = NULL;
    struct mg_callbacks callbacks;
    char listener[INET6_ADDRSTRLEN + 16U];
    char request_size[16U];
    char worker_count[8U];
    const char *options[31U];
    size_t option = 0U;
    int result = 0;

    if (server == NULL) {
        return -EINVAL;
    }
    *server = NULL;
    result = jg_web_config_validate(config);
    if (result == 0) {
        result = validate_certificate(config->certificate_path);
    }
    if (result == 0) {
        result = validate_web_root(config->web_root);
    }
    if (result == 0) {
        result = jg_web_build_listener(config, listener, sizeof(listener));
    }
    if (result == 0) {
        started = calloc(1U, sizeof(*started));
        if (started == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = own_config(started, config);
    }
    if (result == 0) {
        (void)snprintf(request_size, sizeof(request_size), "%u",
                       (unsigned int)config->max_request_size);
        (void)snprintf(worker_count, sizeof(worker_count), "%u",
                       (unsigned int)config->worker_count);
        options[option++] = "listening_ports";
        options[option++] = listener;
        options[option++] = "ssl_certificate";
        options[option++] = started->certificate_path;
        options[option++] = "ssl_protocol_version";
        options[option++] = "4";
        options[option++] = "ssl_cipher_list";
        options[option++] = "ECDHE-ECDSA-AES256-GCM-SHA384:"
                            "ECDHE-RSA-AES256-GCM-SHA384:"
                            "ECDHE-ECDSA-AES128-GCM-SHA256:"
                            "ECDHE-RSA-AES128-GCM-SHA256";
        options[option++] = "ssl_short_trust";
        options[option++] = "yes";
        options[option++] = "enable_directory_listing";
        options[option++] = "no";
        options[option++] = "enable_webdav";
        options[option++] = "no";
        options[option++] = "enable_keep_alive";
        options[option++] = "yes";
        options[option++] = "keep_alive_timeout_ms";
        options[option++] = "5000";
        options[option++] = "request_timeout_ms";
        options[option++] = "15000";
        options[option++] = "max_request_size";
        options[option++] = request_size;
        options[option++] = "num_threads";
        options[option++] = worker_count;
        options[option++] = "decode_url";
        options[option++] = "yes";
        options[option++] = "tcp_nodelay";
        options[option++] = "1";
        options[option] = NULL;
        (void)memset(&callbacks, 0, sizeof(callbacks));
        started->context = mg_start(&callbacks, started, options);
        if (started->context == NULL) {
            result = -EIO;
        }
    }
    if (result == 0) {
        mg_set_request_handler(started->context, "/", handle_request, started);
        *server = started;
    } else {
        jg_web_server_destroy(started);
    }
    return result;
}

/** @brief Stop CivetWeb and release every server-owned string. */
void jg_web_server_destroy(struct jg_web_server *server)
{
    if (server == NULL) {
        return;
    }
    if (server->context != NULL) {
        mg_stop(server->context);
    }
    free(server->web_root);
    free(server->control_socket_path);
    free(server->certificate_path);
    free(server->listen_address);
    free(server);
}
