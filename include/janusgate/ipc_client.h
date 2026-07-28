/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file ipc_client.h
 * @brief Bounded synchronous client for JanusGate local protocols.
 */

#ifndef JANUSGATE_IPC_CLIENT_H
#define JANUSGATE_IPC_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "janusgate/ipc.h"
#include "janusgate/version.h"

/**
 * @brief Exchange one request on an already connected local socket.
 *
 * The response direction, operation, and request identifier are verified
 * before its protocol error is translated to a negative errno-style result.
 *
 * @param[in] socket_fd Connected Unix-domain `SOCK_SEQPACKET` socket.
 * @param[in] operation Allowlisted operation.
 * @param[in] request_body Operation body, or null when its size is zero.
 * @param[in] request_size Number of request body bytes.
 * @param[out] response_body Response destination, or null when capacity is
 * zero.
 * @param[in] response_capacity Available response bytes.
 * @param[out] response_size Receives response body bytes.
 *
 * @return 0 on a successful remote response.
 * @return A negative errno-style validation, transport, protocol, capacity,
 * or remote operation error otherwise.
 *
 * @thread_safety Distinct connected sockets are independent.
 *
 * @side_effects Sends one request and receives one response.
 */
JG_PUBLIC int jg_ipc_client_exchange(int socket_fd,
                                     enum jg_ipc_operation operation,
                                     const uint8_t *request_body,
                                     size_t request_size,
                                     uint8_t *response_body,
                                     size_t response_capacity,
                                     size_t *response_size);

/**
 * @brief Connect and perform one bounded request on a local socket path.
 *
 * @param[in] socket_path Absolute Unix-domain socket path.
 * @param[in] operation Allowlisted operation.
 * @param[in] request_body Operation body, or null when its size is zero.
 * @param[in] request_size Number of request body bytes.
 * @param[out] response_body Response destination, or null when capacity is
 * zero.
 * @param[in] response_capacity Available response bytes.
 * @param[out] response_size Receives response body bytes.
 *
 * @return 0 on a successful remote response.
 * @return A negative errno-style validation, connection, protocol, capacity,
 * or remote operation error otherwise.
 *
 * @thread_safety Calls use independent short-lived connections.
 *
 * @side_effects Opens and closes one Unix-domain socket.
 */
JG_PUBLIC int jg_ipc_client_call(const char *socket_path,
                                 enum jg_ipc_operation operation,
                                 const uint8_t *request_body,
                                 size_t request_size,
                                 uint8_t *response_body,
                                 size_t response_capacity,
                                 size_t *response_size);

#endif
