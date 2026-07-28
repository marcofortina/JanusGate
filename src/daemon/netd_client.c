/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "netd_client.h"

#include <stddef.h>
#include <stdint.h>

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

/** @brief Apply one configuration through a short-lived helper connection. */
int jg_netd_client_apply(const struct jg_network_config *config)
{
    uint8_t body[JG_NETWORK_CONFIG_WIRE_SIZE];
    size_t body_size = 0U;
    size_t response_size = 0U;
    int result =
        jg_network_config_encode(config, body, sizeof(body), &body_size);

    if (result == 0) {
        result = jg_ipc_client_call(JG_NETD_SOCKET_PATH, JG_IPC_NETWORK_APPLY,
                                    body, body_size, NULL, 0U, &response_size);
    }
    return result;
}
