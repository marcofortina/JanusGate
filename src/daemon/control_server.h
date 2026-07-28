/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file control_server.h
 * @brief Authenticated request handling for the daemon control socket.
 */

#ifndef JANUSGATE_DAEMON_CONTROL_SERVER_H
#define JANUSGATE_DAEMON_CONTROL_SERVER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "daemon_runtime.h"
#include "janusgate/ipc.h"

/**
 * @brief Validate and dispatch one decoded daemon-control request.
 *
 * The caller supplies response-body storage so the returned message owns no
 * dynamic memory. Requests are handled sequentially by the control server,
 * which serializes policy reload writers.
 *
 * @param[in,out] runtime Packet runtime, or null for ping-only dispatch.
 * @param[in] request Decoded request message.
 * @param[out] response Receives the correlated protocol response.
 * @param[out] response_body Storage for a typed response body.
 * @param[in] response_capacity Available response body bytes.
 * @param[out] response_size Receives the populated body bytes.
 *
 * @return 0 when a response was produced.
 * @return -EINVAL for invalid arguments or an unusable request envelope.
 * @return -ENOSPC when response storage cannot hold daemon status.
 *
 * @thread_safety Policy-changing calls require external serialization.
 */
int jg_control_process_request(struct jg_daemon_runtime *runtime,
                               const struct jg_ipc_message *request,
                               struct jg_ipc_message *response,
                               uint8_t *response_body,
                               size_t response_capacity,
                               size_t *response_size);

/**
 * @brief Authenticate and service one connected local control peer.
 *
 * Root and @p allowed_uid are accepted. Exactly one bounded request and one
 * response are exchanged. Ancillary file descriptors are rejected and
 * closed. The caller retains ownership of @p socket_fd.
 *
 * @param[in] socket_fd Connected Unix-domain `SOCK_SEQPACKET` socket.
 * @param[in] allowed_uid Dedicated web service user identifier.
 * @param[in,out] runtime Running packet runtime, or null for ping-only tests.
 *
 * @return 0 on a completed exchange.
 * @return -EACCES when peer credentials are not authorized.
 * @return -EMSGSIZE for an oversized packet.
 * @return A negative errno-style socket or decoder error otherwise.
 *
 * @thread_safety Connections must be dispatched serially while they can
 * mutate policy.
 */
int jg_control_handle_connection(int socket_fd,
                                 uid_t allowed_uid,
                                 struct jg_daemon_runtime *runtime);

#endif
