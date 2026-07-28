/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file netd.h
 * @brief Internal server contract for the privileged network helper.
 */

#ifndef JANUSGATE_NETD_H
#define JANUSGATE_NETD_H

#include <sys/types.h>

#include "janusgate/ipc.h"
#include "janusgate/network.h"

/**
 * @brief Validate and dispatch one decoded network-helper request.
 *
 * The response always correlates to the request and owns no dynamic storage.
 *
 * @param[in] request Decoded request message.
 * @param[out] response Receives a protocol response.
 *
 * @return 0 when a response was produced.
 * @return -EINVAL when the arguments or request envelope are unusable.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Network-validation requests inspect current links through a
 * short-lived rtnetlink socket.
 */
int jg_netd_process_request(const struct jg_ipc_message *request,
                            struct jg_ipc_message *response);

/**
 * @brief Authenticate and service one connected local peer.
 *
 * Exactly one bounded request and one response are exchanged. The caller
 * retains ownership of @p socket_fd and must close it.
 *
 * @param[in] socket_fd Connected Unix-domain `SOCK_SEQPACKET` socket.
 * @param[in] allowed_uid Sole peer user identifier accepted by the helper.
 *
 * @return 0 on a completed exchange.
 * @return -EACCES when `SO_PEERCRED` does not match @p allowed_uid.
 * @return -EMSGSIZE for an oversized packet.
 * @return A negative errno-style socket or decoder error otherwise.
 *
 * @thread_safety Distinct connected sockets may be serviced concurrently.
 */
int jg_netd_handle_connection(int socket_fd, uid_t allowed_uid);

/**
 * @brief Apply bridge and nftables state as one network transaction.
 *
 * The nftables replacement is the final step. If it fails atomically, the
 * bridge checkpoint is restored before returning.
 *
 * @param[in] config Validated complete inline-network configuration.
 *
 * @return 0 on success.
 * @return -EUCLEAN when bridge restoration fails.
 * @return A negative errno-style validation, rtnetlink, or nftables error
 * otherwise.
 *
 * @thread_safety State-changing calls require external serialization.
 *
 * @side_effects Updates and, on failure, restores owned kernel network state.
 */
int jg_netd_apply_network(const struct jg_network_config *config);

/**
 * @brief Run the fixed-path privileged network-helper server.
 *
 * The server creates @ref JG_NETD_SOCKET_PATH, accepts only @p allowed_uid,
 * imposes send and receive timeouts, and removes its socket during an orderly
 * shutdown.
 *
 * @param[in] allowed_uid Dedicated JanusGate service user identifier.
 * @param[in] socket_gid Group receiving access to the socket.
 *
 * @return 0 after SIGINT or SIGTERM.
 * @return -EINVAL when @p allowed_uid is root.
 * @return A negative errno-style setup or accept error otherwise.
 *
 * @thread_safety Only one server may own the fixed socket path.
 *
 * @side_effects Creates a runtime directory and Unix-domain socket, installs
 * signal handlers, changes their ownership and mode, and accepts clients.
 */
int jg_netd_run(uid_t allowed_uid, gid_t socket_gid);

#endif
