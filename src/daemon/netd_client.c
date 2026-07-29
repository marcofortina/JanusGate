/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "netd_client.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "janusgate/ipc_client.h"

/** @brief Exchange one helper request requiring an empty response body. */
int jg_netd_client_exchange(int socket_fd,
                            enum jg_ipc_operation operation,
                            const uint8_t *body,
                            size_t body_size)
{
    size_t response_size = 0U;

    return jg_ipc_client_exchange(socket_fd, operation, body, body_size, NULL,
                                  0U, &response_size);
}

/** @brief Send one encoded configuration to the fixed helper socket. */
static int call_network_operation(enum jg_ipc_operation operation,
                                  const struct jg_network_config *config)
{
    uint8_t body[JG_NETWORK_CONFIG_WIRE_SIZE];
    size_t body_size = 0U;
    size_t response_size = 0U;
    int result =
        jg_network_config_encode(config, body, sizeof(body), &body_size);

    if (result == 0) {
        result = jg_ipc_client_call(JG_NETD_SOCKET_PATH, operation, body,
                                    body_size, NULL, 0U, &response_size);
    }
    return result;
}

/** @brief Validate one configuration through a short-lived connection. */
int jg_netd_client_validate(const struct jg_network_config *config)
{
    return call_network_operation(JG_IPC_NETWORK_VALIDATE, config);
}

/** @brief Apply one configuration through a short-lived helper connection. */
int jg_netd_client_apply(const struct jg_network_config *config)
{
    return call_network_operation(JG_IPC_NETWORK_APPLY, config);
}

/** @brief Send one bodyless operation through a short-lived connection. */
static int call_empty_operation(enum jg_ipc_operation operation)
{
    size_t response_size = 0U;

    return jg_ipc_client_call(JG_NETD_SOCKET_PATH, operation, NULL, 0U, NULL,
                              0U, &response_size);
}

/** @brief Confirm the current pending helper transaction. */
int jg_netd_client_confirm(void)
{
    return call_empty_operation(JG_IPC_NETWORK_CONFIRM);
}

/** @brief Roll back the current pending helper transaction. */
int jg_netd_client_rollback(void)
{
    return call_empty_operation(JG_IPC_NETWORK_ROLLBACK);
}

/** @brief Read and decode the helper's transactional network state. */
int jg_netd_client_state(struct jg_network_state *state)
{
    uint8_t body[JG_NETWORK_STATE_WIRE_SIZE];
    size_t body_size = 0U;
    int result = 0;

    if (state == NULL) {
        return -EINVAL;
    }
    (void)memset(state, 0, sizeof(*state));
    result = jg_ipc_client_call(JG_NETD_SOCKET_PATH, JG_IPC_NETWORK_STATE, NULL,
                                0U, body, sizeof(body), &body_size);
    if (result == 0) {
        result = jg_network_state_decode(body, body_size, state);
    }
    return result;
}

/** @brief Request one allowlisted host power operation. */
int jg_netd_client_power(bool poweroff)
{
    return call_empty_operation(poweroff ? JG_IPC_SYSTEM_POWEROFF
                                         : JG_IPC_SYSTEM_REBOOT);
}
