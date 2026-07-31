/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file web_gateway.h
 * @brief Strict HTTPS-to-daemon management request translation.
 */

#ifndef JANUSGATE_WEB_GATEWAY_H
#define JANUSGATE_WEB_GATEWAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/auth.h"

struct mg_connection;

/** Maximum response content-type bytes excluding the terminator. */
#define JG_WEB_CONTENT_TYPE_MAX 79U

/** Authentication boundary represented by one HTTPS listener. */
enum jg_web_gateway_mode {
    /** Browser-only listener using secure sessions and CSRF protection. */
    JG_WEB_GATEWAY_BROWSER = 1,
    /** Automation-only listener using mTLS and bearer tokens. */
    JG_WEB_GATEWAY_REMOTE_API = 2
};

/** Cookie mutation requested by one daemon management response. */
enum jg_web_cookie_action {
    /** Preserve the browser's current session cookie. */
    JG_WEB_COOKIE_PRESERVE = 0,
    /** Set a newly issued opaque session cookie. */
    JG_WEB_COOKIE_SET = 1,
    /** Expire the current session cookie. */
    JG_WEB_COOKIE_CLEAR = 2
};

/** Complete owned API response ready for secure HTTP serialization. */
struct jg_web_gateway_response {
    /** HTTP response status. */
    int status;
    /** Correlation identifier returned in the response header and errors. */
    char request_id[JG_AUTH_SECRET_TEXT_SIZE];
    /** Cookie action selected by the daemon. */
    enum jg_web_cookie_action cookie_action;
    /** New opaque session identifier when cookie_action is SET. */
    char session[JG_AUTH_SECRET_TEXT_SIZE];
    /** Validated response media type. */
    char content_type[JG_WEB_CONTENT_TYPE_MAX + 1U];
    /** Heap-owned response body. */
    char *body;
    /** Exact JSON response bytes excluding any terminator. */
    size_t body_size;
};

/**
 * @brief Translate one HTTPS API request through the local control socket.
 *
 * @param[in,out] connection CivetWeb connection borrowed for the call.
 * @param[in] control_socket_path Absolute daemon control-socket path.
 * @param[in] maximum_body_size Maximum accepted JSON request bytes.
 * @param[in] mode Authentication boundary of the accepting listener.
 * @param[in] client_certificate SHA-256 peer-certificate fingerprint for the
 * remote API, or null for the browser listener.
 * @param[out] response Receives an owned validated API response.
 *
 * @return 0 when @p response contains an HTTP-level result.
 * @return -EINVAL for invalid arguments.
 * @return -ENOMEM when no safe response can be allocated.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Reads the bounded request body and performs one local IPC
 * exchange.
 */
int jg_web_gateway_process(struct mg_connection *connection,
                           const char *control_socket_path,
                           uint32_t maximum_body_size,
                           enum jg_web_gateway_mode mode,
                           const char *client_certificate,
                           struct jg_web_gateway_response *response);

/**
 * @brief Decode one trusted-boundary daemon response envelope.
 *
 * The response body must be null on entry. Existing request-identifier state
 * is preserved while an allowlisted JSON or Prometheus representation is
 * populated.
 *
 * @param[in] data Exact daemon response bytes.
 * @param[in] data_size Response byte count.
 * @param[in,out] response Initialized destination with a null body.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -EPROTO for an invalid response envelope.
 * @return -ENOMEM when response storage cannot be allocated.
 *
 * @thread_safety This function is reentrant.
 */
int jg_web_gateway_decode_response(const uint8_t *data,
                                   size_t data_size,
                                   struct jg_web_gateway_response *response);

/**
 * @brief Clear and release one gateway response body.
 *
 * @param[in,out] response Response to release; null is accepted.
 *
 * @thread_safety The response must not be used concurrently.
 */
void jg_web_gateway_response_clear(struct jg_web_gateway_response *response);

#endif
