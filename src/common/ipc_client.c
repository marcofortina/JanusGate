/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "janusgate/ipc_client.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

/** Maximum wait for one local request or response. */
#define JG_IPC_CLIENT_TIMEOUT_SECONDS 5

/** Single identifier sufficient for one-request connections. */
#define JG_IPC_CLIENT_REQUEST_ID UINT64_C(1)

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

/** @brief Exchange one exact request and correlated response. */
int jg_ipc_client_exchange(int socket_fd,
                           enum jg_ipc_operation operation,
                           const uint8_t *request_body,
                           size_t request_size,
                           uint8_t *response_body,
                           size_t response_capacity,
                           size_t *response_size)
{
    uint8_t data[JG_IPC_MAX_MESSAGE_SIZE];
    const struct jg_ipc_message request = {
        .kind = JG_IPC_REQUEST,
        .operation = operation,
        .request_id = JG_IPC_CLIENT_REQUEST_ID,
        .error = JG_IPC_ERROR_NONE,
        .body = request_body,
        .body_size = request_size,
    };
    struct jg_ipc_message response;
    size_t encoded_size = 0U;
    ssize_t transferred = 0;
    int result = 0;

    if (socket_fd < 0 || response_size == NULL ||
        (response_capacity != 0U && response_body == NULL)) {
        return -EINVAL;
    }
    *response_size = 0U;
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
        response.request_id != request.request_id ||
        (response.error != JG_IPC_ERROR_NONE && response.body_size != 0U)) {
        return -EPROTO;
    }
    result = remote_error(response.error);
    if (result != 0) {
        return result;
    }
    if (response.body_size > response_capacity) {
        return -ENOSPC;
    }
    if (response.body_size != 0U) {
        (void)memcpy(response_body, response.body, response.body_size);
    }
    *response_size = response.body_size;
    return 0;
}

/** @brief Open one fixed-timeout local sequential-packet connection. */
static int connect_local(const char *socket_path)
{
    const struct timeval timeout = {
        .tv_sec = JG_IPC_CLIENT_TIMEOUT_SECONDS,
        .tv_usec = 0,
    };
    struct sockaddr_un address;
    size_t path_size = 0U;
    int socket_fd = -1;
    int result = 0;

    if (socket_path == NULL || socket_path[0] != '/') {
        return -EINVAL;
    }
    path_size = strnlen(socket_path, sizeof(address.sun_path));
    if (path_size == 0U || path_size >= sizeof(address.sun_path)) {
        return -ENAMETOOLONG;
    }
    socket_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
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
    (void)memcpy(address.sun_path, socket_path, path_size + 1U);
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

/** @brief Connect, exchange one request, and close the local socket. */
int jg_ipc_client_call(const char *socket_path,
                       enum jg_ipc_operation operation,
                       const uint8_t *request_body,
                       size_t request_size,
                       uint8_t *response_body,
                       size_t response_capacity,
                       size_t *response_size)
{
    int socket_fd = -1;
    int result = 0;

    if (response_size == NULL) {
        return -EINVAL;
    }
    socket_fd = connect_local(socket_path);
    if (socket_fd < 0) {
        return socket_fd;
    }
    result =
        jg_ipc_client_exchange(socket_fd, operation, request_body, request_size,
                               response_body, response_capacity, response_size);
    (void)close(socket_fd);
    return result;
}
