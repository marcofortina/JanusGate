/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "netd.h"

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "janusgate/network.h"
#include "rtnetlink.h"

/** Runtime directory containing privileged local-control sockets. */
#define JG_RUNTIME_DIRECTORY "/run/janusgate"

/** Maximum wait for one local request or response. */
#define JG_NETD_IO_TIMEOUT_SECONDS 5

/** Process-wide orderly-shutdown request set by signal handlers. */
static volatile sig_atomic_t stop_requested = 0;

/** @brief Convert a typed-body decoding result into a protocol error. */
static enum jg_ipc_error body_error(int result)
{
    if (result == -EPROTONOSUPPORT) {
        return JG_IPC_ERROR_VERSION;
    }
    if (result == -EPROTO || result == -EMSGSIZE) {
        return JG_IPC_ERROR_MALFORMED;
    }
    if (result == -EBUSY || result == -ENOENT) {
        return JG_IPC_ERROR_CONFLICT;
    }
    if (result == -EINVAL || result == -ERANGE || result == -ENODEV ||
        result == -EEXIST || result == -EACCES || result == -EADDRINUSE) {
        return JG_IPC_ERROR_INVALID;
    }
    return JG_IPC_ERROR_SYSTEM;
}

/** @brief Validate and dispatch one decoded helper request. */
int jg_netd_process_request(const struct jg_ipc_message *request,
                            struct jg_ipc_message *response)
{
    struct jg_network_config config;
    int result;

    if (request == NULL || response == NULL || request->request_id == 0U ||
        request->operation < JG_IPC_PING ||
        request->operation > JG_IPC_DAEMON_STATUS ||
        request->body_size > JG_IPC_MAX_BODY_SIZE ||
        (request->body_size != 0U && request->body == NULL)) {
        return -EINVAL;
    }

    response->kind = JG_IPC_RESPONSE;
    response->operation = request->operation;
    response->request_id = request->request_id;
    response->error = JG_IPC_ERROR_NONE;
    response->body = NULL;
    response->body_size = 0U;

    if (request->kind != JG_IPC_REQUEST ||
        request->error != JG_IPC_ERROR_NONE) {
        response->error = JG_IPC_ERROR_MALFORMED;
    } else if (request->operation == JG_IPC_PING) {
        if (request->body_size != 0U) {
            response->error = JG_IPC_ERROR_MALFORMED;
        }
    } else if (request->operation == JG_IPC_NETWORK_VALIDATE ||
               request->operation == JG_IPC_NETWORK_APPLY) {
        result = jg_network_config_decode(request->body, request->body_size,
                                          &config);
        if (result == 0 && request->operation == JG_IPC_NETWORK_VALIDATE) {
            result = jg_netd_validate_live_config(&config, NULL);
        } else if (result == 0) {
            result = jg_netd_apply_network(&config);
        }
        if (result != 0) {
            response->error = body_error(result);
        }
    } else if (request->operation == JG_IPC_NETWORK_CONFIRM ||
               request->operation == JG_IPC_NETWORK_ROLLBACK) {
        if (request->body_size != 0U) {
            response->error = JG_IPC_ERROR_MALFORMED;
        } else {
            result = request->operation == JG_IPC_NETWORK_CONFIRM
                         ? jg_netd_confirm_network()
                         : jg_netd_rollback_network();
            if (result != 0) {
                response->error = body_error(result);
            }
        }
    } else {
        response->error = JG_IPC_ERROR_UNSUPPORTED;
    }
    return 0;
}

/** @brief Verify one connected peer through Linux socket credentials. */
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
    return credentials.uid == allowed_uid ? 0 : -EACCES;
}

/** @brief Close every file descriptor received in ancillary socket data. */
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

    if (data == NULL || received_size == NULL) {
        return -EINVAL;
    }
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

/** @brief Authenticate and exchange one bounded request and response. */
int jg_netd_handle_connection(int socket_fd, uid_t allowed_uid)
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
    if (result != 0) {
        return result;
    }
    result = receive_request(socket_fd, request_data, sizeof(request_data),
                             &request_size);
    if (result == 0) {
        result = jg_ipc_decode(request_data, request_size, &request);
    }
    if (result == 0) {
        result = jg_netd_process_request(&request, &response);
    }
    if (result == 0) {
        result = jg_ipc_encode(&response, response_data, sizeof(response_data),
                               &response_size);
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

/** @brief Create or validate the fixed root-owned runtime directory. */
static int prepare_runtime_directory(gid_t socket_gid)
{
    struct stat status;

    if (mkdir(JG_RUNTIME_DIRECTORY, 0750) != 0 && errno != EEXIST) {
        return -errno;
    }
    if (lstat(JG_RUNTIME_DIRECTORY, &status) != 0) {
        return -errno;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != 0U ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0U) {
        return -EACCES;
    }
    if (chown(JG_RUNTIME_DIRECTORY, 0U, socket_gid) != 0 ||
        chmod(JG_RUNTIME_DIRECTORY, 0750) != 0) {
        return -errno;
    }
    return 0;
}

/** @brief Remove only a stale root-owned socket at the fixed path. */
static int remove_stale_socket(void)
{
    struct stat status;

    if (lstat(JG_NETD_SOCKET_PATH, &status) != 0) {
        return errno == ENOENT ? 0 : -errno;
    }
    if (!S_ISSOCK(status.st_mode) || status.st_uid != 0U) {
        return -EEXIST;
    }
    return unlink(JG_NETD_SOCKET_PATH) == 0 ? 0 : -errno;
}

/** @brief Open and permission the fixed local listening socket. */
static int open_server_socket(gid_t socket_gid)
{
    struct sockaddr_un address;
    int socket_fd = -1;
    int result = prepare_runtime_directory(socket_gid);

    if (result == 0) {
        result = remove_stale_socket();
    }
    if (result == 0) {
        socket_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (socket_fd < 0) {
            result = -errno;
        }
    }
    if (result == 0) {
        (void)memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        if (sizeof(JG_NETD_SOCKET_PATH) > sizeof(address.sun_path)) {
            result = -ENAMETOOLONG;
        } else {
            (void)memcpy(address.sun_path, JG_NETD_SOCKET_PATH,
                         sizeof(JG_NETD_SOCKET_PATH));
        }
    }
    if (result == 0 && bind(socket_fd, (const struct sockaddr *)&address,
                            (socklen_t)sizeof(address)) != 0) {
        result = -errno;
    }
    if (result == 0 &&
        (chown(JG_NETD_SOCKET_PATH, 0U, socket_gid) != 0 ||
         chmod(JG_NETD_SOCKET_PATH, 0660) != 0 || listen(socket_fd, 16) != 0)) {
        result = -errno;
    }
    if (result != 0 && socket_fd >= 0) {
        (void)close(socket_fd);
        (void)unlink(JG_NETD_SOCKET_PATH);
        socket_fd = -1;
    }
    return result == 0 ? socket_fd : result;
}

/** @brief Impose bounded blocking time on one connected client. */
static int configure_client_socket(int socket_fd)
{
    const struct timeval timeout = {
        .tv_sec = JG_NETD_IO_TIMEOUT_SECONDS,
        .tv_usec = 0,
    };

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0 ||
        setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) != 0) {
        return -errno;
    }
    return 0;
}

/** @brief Request an orderly server stop from an asynchronous signal. */
static void request_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

/** @brief Install minimal termination handlers without automatic restart. */
static int install_signal_handlers(void)
{
    struct sigaction action;

    (void)memset(&action, 0, sizeof(action));
    action.sa_handler = request_stop;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        return -errno;
    }
    return 0;
}

/** @brief Run the authenticated fixed-path network-helper service. */
int jg_netd_run(uid_t allowed_uid, gid_t socket_gid)
{
    int server_fd = -1;
    int result = 0;

    if (allowed_uid == 0U) {
        return -EINVAL;
    }
    stop_requested = 0;
    result = install_signal_handlers();
    if (result == 0) {
        server_fd = open_server_socket(socket_gid);
        if (server_fd < 0) {
            result = server_fd;
        }
    }
    while (result == 0 && stop_requested == 0) {
        const int client_fd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC);

        if (client_fd < 0) {
            if (errno != EINTR) {
                result = -errno;
            }
        } else {
            if (configure_client_socket(client_fd) == 0) {
                (void)jg_netd_handle_connection(client_fd, allowed_uid);
            }
            (void)close(client_fd);
        }
    }
    if (server_fd >= 0) {
        (void)close(server_fd);
        (void)unlink(JG_NETD_SOCKET_PATH);
    }
    return result;
}
