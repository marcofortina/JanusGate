/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "netd_client.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

/** Maximum wait for one helper request or response. */
#define JG_NETD_CLIENT_TIMEOUT_SECONDS 5

/** Single request identifier required by one-request helper connections. */
#define JG_NETD_CLIENT_REQUEST_ID UINT64_C(1)

/** @brief Translate one stable remote error to an errno-style result. */
static int remote_error(enum jg_ipc_error error)
{
    switch (error) {
    case JG_IPC_ERROR_NONE:
        return 0;
    case JG_IPC_ERROR_MALFORMED:
        return -EPROTO;
    case JG_IPC_ERROR_VERSION:
        return -EPROTONOSUPPORT;
    case JG_IPC_ERROR_UNAUTHORIZED:
        return -EACCES;
    case JG_IPC_ERROR_UNSUPPORTED:
        return -ENOTSUP;
    case JG_IPC_ERROR_INVALID:
        return -EINVAL;
    case JG_IPC_ERROR_CONFLICT:
        return -EBUSY;
    case JG_IPC_ERROR_TIMEOUT:
        return -ETIMEDOUT;
    case JG_IPC_ERROR_SYSTEM:
    default:
        return -EIO;
    }
}

/** @brief Exchange one exact request and correlated empty response. */
int jg_netd_client_exchange(int socket_fd,
                            enum jg_ipc_operation operation,
                            const uint8_t *body,
                            size_t body_size)
{
    uint8_t data[JG_IPC_MAX_MESSAGE_SIZE];
    const struct jg_ipc_message request = {
        .kind = JG_IPC_REQUEST,
        .operation = operation,
        .request_id = JG_NETD_CLIENT_REQUEST_ID,
        .error = JG_IPC_ERROR_NONE,
        .body = body,
        .body_size = body_size,
    };
    struct jg_ipc_message response;
    size_t encoded_size = 0U;
    ssize_t transferred = 0;
    int result = 0;

    if (socket_fd < 0) {
        return -EINVAL;
    }
    result = jg_ipc_encode(&request, data, sizeof(data), &encoded_size);
    if (result != 0) {
        return result;
    }
    transferred = send(socket_fd, data, encoded_size, MSG_NOSIGNAL);
    if (transferred < 0) {
        return -errno;
    }
    if ((size_t)transferred != encoded_size) {
        return -EIO;
    }
    transferred = recv(socket_fd, data, sizeof(data), MSG_TRUNC);
    if (transferred < 0) {
        return -errno;
    }
    if (transferred == 0) {
        return -ECONNRESET;
    }
    if ((size_t)transferred > sizeof(data)) {
        return -EMSGSIZE;
    }
    result = jg_ipc_decode(data, (size_t)transferred, &response);
    if (result != 0) {
        return result;
    }
    if (response.kind != JG_IPC_RESPONSE ||
        response.operation != request.operation ||
        response.request_id != request.request_id || response.body_size != 0U) {
        return -EPROTO;
    }
    return remote_error(response.error);
}

/** @brief Open the fixed helper socket with bounded blocking time. */
static int connect_helper(void)
{
    const struct timeval timeout = {
        .tv_sec = JG_NETD_CLIENT_TIMEOUT_SECONDS,
        .tv_usec = 0,
    };
    struct sockaddr_un address;
    int socket_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    int result = 0;

    if (socket_fd < 0) {
        return -errno;
    }
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   (socklen_t)sizeof(timeout)) != 0 ||
        setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   (socklen_t)sizeof(timeout)) != 0) {
        result = -errno;
    }
    (void)memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (sizeof(JG_NETD_SOCKET_PATH) > sizeof(address.sun_path)) {
        result = -ENAMETOOLONG;
    } else {
        (void)memcpy(address.sun_path, JG_NETD_SOCKET_PATH,
                     sizeof(JG_NETD_SOCKET_PATH));
    }
    if (result == 0 && connect(socket_fd, (const struct sockaddr *)&address,
                               (socklen_t)sizeof(address)) != 0) {
        result = -errno;
    }
    if (result != 0) {
        (void)close(socket_fd);
        return result;
    }
    return socket_fd;
}

/** @brief Apply one configuration through a short-lived helper connection. */
int jg_netd_client_apply(const struct jg_network_config *config)
{
    uint8_t body[JG_NETWORK_CONFIG_WIRE_SIZE];
    size_t body_size = 0U;
    int socket_fd = -1;
    int result =
        jg_network_config_encode(config, body, sizeof(body), &body_size);

    if (result == 0) {
        socket_fd = connect_helper();
        if (socket_fd < 0) {
            result = socket_fd;
        }
    }
    if (result == 0) {
        result = jg_netd_client_exchange(socket_fd, JG_IPC_NETWORK_APPLY, body,
                                         body_size);
    }
    if (socket_fd >= 0) {
        (void)close(socket_fd);
    }
    return result;
}
