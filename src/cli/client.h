/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file client.h
 * @brief Authenticated management transport used by janusgatectl.
 */

#ifndef JANUSGATE_CLI_CLIENT_H
#define JANUSGATE_CLI_CLIENT_H

#include <stddef.h>

#include <jansson.h>

#include "janusgate/auth.h"

/** Maximum accepted response media-type bytes excluding the terminator. */
#define JG_CLI_CONTENT_TYPE_MAX 79U

/** One owned management response ready for CLI presentation. */
struct jg_cli_response {
    /** HTTP-equivalent response status. */
    int status;
    /** Correlation identifier assigned to the request. */
    char request_id[JG_AUTH_SECRET_TEXT_SIZE];
    /** Validated response media type. */
    char content_type[JG_CLI_CONTENT_TYPE_MAX + 1U];
    /** Heap-owned response body. */
    char *body;
    /** Exact response bytes excluding the terminator. */
    size_t body_size;
};

/**
 * @brief Perform one authenticated management request over local IPC.
 *
 * @param[in] socket_path Absolute daemon control-socket path.
 * @param[in] token Exact opaque API token.
 * @param[in] method Supported uppercase HTTP method.
 * @param[in] path Absolute path under `/api/v1/`.
 * @param[in] query Optional query without a leading question mark.
 * @param[in] body JSON object borrowed for the duration of the call.
 * @param[out] response Zero-initialized destination receiving owned data.
 *
 * @return 0 when @p response contains an API result.
 * @return A negative errno-style validation, allocation, transport, or
 * protocol error otherwise.
 *
 * @thread_safety Calls use independent local connections.
 *
 * @side_effects Opens one Unix-domain connection and consumes one token
 * request from the server-side rate limit.
 */
int jg_cli_local_request(const char *socket_path,
                         const char *token,
                         const char *method,
                         const char *path,
                         const char *query,
                         json_t *body,
                         struct jg_cli_response *response);

/**
 * @brief Decode one exact daemon management response envelope.
 *
 * This trust-boundary helper is public within the CLI component so malformed
 * response handling can be tested independently of a live daemon.
 *
 * @param[in] data Exact response bytes.
 * @param[in] data_size Response byte count.
 * @param[in,out] response Initialized destination with a null body.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -EPROTO for malformed or unsupported response fields.
 * @return -ENOMEM when response storage cannot be allocated.
 *
 * @thread_safety This function is reentrant.
 */
int jg_cli_response_decode(const void *data,
                           size_t data_size,
                           struct jg_cli_response *response);

/**
 * @brief Erase and release one CLI response.
 *
 * @param[in,out] response Response to clear; null is accepted.
 *
 * @thread_safety The response must not be used concurrently.
 */
void jg_cli_response_clear(struct jg_cli_response *response);

#endif
