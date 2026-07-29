/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file netd_client.h
 * @brief Bounded client for the privileged network-helper protocol.
 */

#ifndef JANUSGATE_DAEMON_NETD_CLIENT_H
#define JANUSGATE_DAEMON_NETD_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/ipc.h"
#include "janusgate/network.h"

/**
 * @brief Exchange one request on an already connected helper socket.
 *
 * The current helper operations return no body. The response direction,
 * operation, request identifier, and empty body are verified before its
 * protocol error is translated.
 *
 * @param[in] socket_fd Connected Unix-domain `SOCK_SEQPACKET` socket.
 * @param[in] operation Allowlisted helper operation.
 * @param[in] body Operation-specific body, or null when @p body_size is zero.
 * @param[in] body_size Number of body bytes.
 *
 * @return 0 on a successful helper response.
 * @return A negative errno-style validation, transport, protocol, or remote
 * operation error otherwise.
 *
 * @thread_safety Distinct connected sockets are independent.
 *
 * @side_effects Sends one request and receives one response.
 */
int jg_netd_client_exchange(int socket_fd,
                            enum jg_ipc_operation operation,
                            const uint8_t *body,
                            size_t body_size);

/**
 * @brief Validate one network configuration through the fixed helper socket.
 *
 * @param[in] config Complete proposed network configuration.
 *
 * @return 0 when both static and live-system validation succeed.
 * @return A negative errno-style encoding, connection, protocol, or remote
 * validation error otherwise.
 *
 * @thread_safety Calls use independent short-lived connections.
 *
 * @side_effects Connects to @ref JG_NETD_SOCKET_PATH without changing network
 * state.
 */
int jg_netd_client_validate(const struct jg_network_config *config);

/**
 * @brief Apply one network configuration through the fixed helper socket.
 *
 * @param[in] config Complete validated network configuration.
 *
 * @return 0 when the helper applies the transaction.
 * @return A negative errno-style encoding, connection, protocol, or remote
 * operation error otherwise.
 *
 * @thread_safety Calls use independent short-lived connections.
 *
 * @side_effects Connects to @ref JG_NETD_SOCKET_PATH and may change the
 * JanusGate-owned kernel network state.
 */
int jg_netd_client_apply(const struct jg_network_config *config);

/**
 * @brief Confirm the pending helper network transaction.
 *
 * @return 0 when the helper consumes the pending checkpoint.
 * @return A negative errno-style connection, protocol, conflict, or remote
 * operation error otherwise.
 *
 * @thread_safety Calls use independent short-lived connections.
 */
int jg_netd_client_confirm(void);

/**
 * @brief Roll back the pending helper network transaction.
 *
 * @return 0 when the helper restores and consumes the pending checkpoint.
 * @return A negative errno-style connection, protocol, conflict, or remote
 * operation error otherwise.
 *
 * @thread_safety Calls use independent short-lived connections.
 */
int jg_netd_client_rollback(void);

/**
 * @brief Read the helper's confirmed and optional pending network state.
 *
 * @param[out] state Receives a decoded self-contained state snapshot.
 *
 * @return 0 on success.
 * @return -EINVAL for a null output.
 * @return A negative errno-style connection, protocol, decoding, or remote
 * operation error otherwise.
 *
 * @thread_safety Calls use independent short-lived connections.
 */
int jg_netd_client_state(struct jg_network_state *state);

/**
 * @brief Request a privileged appliance reboot or poweroff.
 *
 * @param[in] poweroff Select poweroff when true and reboot when false.
 *
 * @return 0 when the helper accepts the operation.
 * @return A negative errno-style connection, protocol, or remote error
 * otherwise.
 *
 * @thread_safety Calls use an independent short-lived connection.
 *
 * @side_effects Reboots or powers off the host after the response is sent.
 */
int jg_netd_client_power(bool poweroff);

#endif
