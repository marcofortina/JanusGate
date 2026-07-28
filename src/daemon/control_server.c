/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "control_server.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <unistd.h>

#include "control_protocol.h"

/** @brief Convert one daemon operation failure to a stable protocol error. */
static enum jg_ipc_error operation_error(int result)
{
    if (result == 0) {
        return JG_IPC_ERROR_NONE;
    }
    if (result == -EPROTONOSUPPORT) {
        return JG_IPC_ERROR_VERSION;
    }
    if (result == -EINVAL || result == -ERANGE) {
        return JG_IPC_ERROR_INVALID;
    }
    if (result == -EBUSY || result == -EOVERFLOW) {
        return JG_IPC_ERROR_CONFLICT;
    }
    if (result == -ETIMEDOUT) {
        return JG_IPC_ERROR_TIMEOUT;
    }
    return JG_IPC_ERROR_SYSTEM;
}

/** @brief Validate and dispatch one decoded daemon request. */
int jg_control_process_request(struct jg_daemon_runtime *runtime,
                               const struct jg_ipc_message *request,
                               struct jg_ipc_message *response,
                               uint8_t *response_body,
                               size_t response_capacity,
                               size_t *response_size)
{
    struct jg_daemon_runtime_stats stats;
    int result;

    if (request == NULL || response == NULL || response_body == NULL ||
        response_size == NULL || request->request_id == 0U ||
        request->operation < JG_IPC_PING ||
        request->operation > JG_IPC_DAEMON_STATUS ||
        request->body_size > JG_IPC_MAX_BODY_SIZE ||
        (request->body_size != 0U && request->body == NULL)) {
        return -EINVAL;
    }
    *response_size = 0U;
    *response = (struct jg_ipc_message){
        .kind = JG_IPC_RESPONSE,
        .operation = request->operation,
        .request_id = request->request_id,
        .error = JG_IPC_ERROR_NONE,
    };
    if (request->kind != JG_IPC_REQUEST ||
        request->error != JG_IPC_ERROR_NONE) {
        response->error = JG_IPC_ERROR_MALFORMED;
    } else if (request->operation == JG_IPC_PING) {
        if (request->body_size != 0U) {
            response->error = JG_IPC_ERROR_MALFORMED;
        }
    } else if (request->operation == JG_IPC_POLICY_RELOAD) {
        if (request->body_size != 0U) {
            response->error = JG_IPC_ERROR_MALFORMED;
        } else if (runtime == NULL) {
            response->error = JG_IPC_ERROR_SYSTEM;
        } else {
            result = jg_daemon_runtime_reload_policy(runtime);
            response->error = operation_error(result);
        }
    } else if (request->operation == JG_IPC_DAEMON_STATUS) {
        if (request->body_size != 0U) {
            response->error = JG_IPC_ERROR_MALFORMED;
        } else if (runtime == NULL) {
            response->error = JG_IPC_ERROR_SYSTEM;
        } else {
            result = jg_daemon_runtime_get_stats(runtime, &stats);
            if (result == 0) {
                result = jg_daemon_status_encode(
                    &stats, response_body, response_capacity, response_size);
            }
            if (result == -ENOSPC) {
                return result;
            }
            response->error = operation_error(result);
            if (result == 0) {
                response->body = response_body;
                response->body_size = *response_size;
            }
        }
    } else {
        response->error = JG_IPC_ERROR_UNSUPPORTED;
    }
    return 0;
}

/** @brief Verify one control peer through Linux socket credentials. */
static int authenticate_peer(int socket_fd, uid_t allowed_uid)
{
    struct ucred credentials;
    socklen_t credentials_size = (socklen_t)sizeof(credentials);

    if (getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &credentials,
                   &credentials_size) != 0) {
        return -errno;
    }
    if (credentials_size != sizeof(credentials)) {
        return -EPROTO;
    }
    return credentials.uid == 0U || credentials.uid == allowed_uid ? 0
                                                                   : -EACCES;
}

/** @brief Close every descriptor received in ancillary socket data. */
static void close_received_descriptors(struct msghdr *message)
{
    struct cmsghdr *header = CMSG_FIRSTHDR(message);

    while (header != NULL) {
        if (header->cmsg_level == SOL_SOCKET &&
            header->cmsg_type == SCM_RIGHTS &&
            header->cmsg_len >= CMSG_LEN(0U)) {
            const size_t descriptor_bytes = header->cmsg_len - CMSG_LEN(0U);

            for (size_t offset = 0U; offset + sizeof(int) <= descriptor_bytes;
                 offset += sizeof(int)) {
                int descriptor = -1;

                (void)memcpy(&descriptor,
                             (const uint8_t *)CMSG_DATA(header) + offset,
                             sizeof(descriptor));
                if (descriptor >= 0) {
                    (void)close(descriptor);
                }
            }
        }
        header = CMSG_NXTHDR(message, header);
    }
}

/** @brief Receive one packet while rejecting ancillary file descriptors. */
static int receive_request(int socket_fd,
                           uint8_t *data,
                           size_t data_size,
                           size_t *received_size)
{
    uint8_t control[CMSG_SPACE(sizeof(int))];
    struct iovec payload = {
        .iov_base = data,
        .iov_len = data_size,
    };
    struct msghdr message;
    ssize_t received = 0;

    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &payload;
    message.msg_iovlen = 1U;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    received = recvmsg(socket_fd, &message, MSG_TRUNC | MSG_CMSG_CLOEXEC);
    if (received < 0) {
        return -errno;
    }
    if (received == 0) {
        return -ECONNRESET;
    }
    if ((message.msg_flags & MSG_CTRUNC) != 0 || message.msg_controllen != 0U) {
        close_received_descriptors(&message);
        return -EPROTO;
    }
    if ((size_t)received > data_size) {
        return -EMSGSIZE;
    }
    *received_size = (size_t)received;
    return 0;
}

/** @brief Authenticate and exchange one bounded control request. */
int jg_control_handle_connection(int socket_fd,
                                 uid_t allowed_uid,
                                 struct jg_daemon_runtime *runtime)
{
    uint8_t request_data[JG_IPC_MAX_MESSAGE_SIZE];
    uint8_t response_data[JG_IPC_MAX_MESSAGE_SIZE];
    struct jg_ipc_message request;
    struct jg_ipc_message response;
    size_t request_size = 0U;
    size_t response_size = 0U;
    ssize_t sent = 0;
    int result = 0;

    if (socket_fd < 0) {
        return -EINVAL;
    }
    result = authenticate_peer(socket_fd, allowed_uid);
    if (result == 0) {
        result = receive_request(socket_fd, request_data, sizeof(request_data),
                                 &request_size);
    }
    if (result == 0) {
        result = jg_ipc_decode(request_data, request_size, &request);
    }
    if (result == 0) {
        uint8_t response_body[JG_DAEMON_STATUS_WIRE_SIZE];
        size_t response_body_size = 0U;

        result = jg_control_process_request(
            runtime, &request, &response, response_body, sizeof(response_body),
            &response_body_size);
        if (result == 0) {
            result = jg_ipc_encode(&response, response_data,
                                   sizeof(response_data), &response_size);
        }
    }
    if (result != 0) {
        return result;
    }
    sent = send(socket_fd, response_data, response_size, MSG_NOSIGNAL);
    if (sent < 0) {
        return -errno;
    }
    return (size_t)sent == response_size ? 0 : -EIO;
}
