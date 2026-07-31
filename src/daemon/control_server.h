/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file control_server.h
 * @brief Authenticated request handling for the daemon control socket.
 */

#ifndef JANUSGATE_DAEMON_CONTROL_SERVER_H
#define JANUSGATE_DAEMON_CONTROL_SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "daemon_runtime.h"
#include "janusgate/ipc.h"

/** Opaque running or stopped daemon control server. */
struct jg_control_server;

/**
 * @brief Validate and dispatch one decoded daemon-control request.
 *
 * The caller supplies response-body storage so the returned message owns no
 * dynamic memory. Requests are handled sequentially by the control server,
 * which serializes policy reload writers.
 *
 * @param[in,out] runtime Packet runtime, or null for ping-only dispatch.
 * @param[in] request Decoded request message.
 * @param[in] local_administrator Whether peer credentials identify root.
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
                               bool local_administrator,
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

/**
 * @brief Open the fixed control socket and start its serial server thread.
 *
 * @param[in,out] runtime Running packet runtime.
 * @param[in] owner_uid Dedicated policy service user identifier.
 * @param[in] allowed_uid Dedicated web service user identifier.
 * @param[in] socket_gid Dedicated local-control group identifier.
 * @param[out] server Receives the owned running server.
 *
 * @return 0 on success.
 * @return -EINVAL for a null runtime or destination or a root service
 * identity.
 * @return A negative errno-style directory, socket, allocation, or thread
 * error otherwise.
 *
 * @thread_safety Only one server may own @ref JG_CONTROL_SOCKET_PATH.
 *
 * @side_effects Creates a Unix-domain socket and starts one control thread.
 */
int jg_control_server_start(struct jg_daemon_runtime *runtime,
                            uid_t owner_uid,
                            uid_t allowed_uid,
                            gid_t socket_gid,
                            struct jg_control_server **server);

/**
 * @brief Request a stop, join the server thread, and report its result.
 *
 * @param[in,out] server Running or stopped control server.
 *
 * @return 0 after an orderly stop.
 * @return -EINVAL for a null server.
 * @return The first negative notification, thread, or server error otherwise.
 *
 * @thread_safety Exactly one control thread may stop the server.
 */
int jg_control_server_stop(struct jg_control_server *server);

/**
 * @brief Stop if necessary and release one control server.
 *
 * @param[in,out] server Server to release; null is accepted.
 *
 * @thread_safety No other operation may use the server concurrently.
 *
 * @side_effects Stops the thread, closes sockets, and removes the owned path.
 */
void jg_control_server_destroy(struct jg_control_server *server);

#endif
