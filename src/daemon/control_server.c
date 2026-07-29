/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "control_server.h"

#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <poll.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "janusgate/checked.h"

#include "control_protocol.h"
#include "netd_client.h"

/** Runtime directory containing local-control sockets. */
#define JG_RUNTIME_DIRECTORY "/run/janusgate"

/** Policy-daemon-owned directory containing its control socket. */
#define JG_CONTROL_RUNTIME_DIRECTORY "/run/janusgate/control"

/** Maximum wait for one local request or response. */
#define JG_CONTROL_IO_TIMEOUT_SECONDS 5

/** Interval between scheduled-source checks. */
#define JG_CONTROL_UPDATE_INTERVAL_SECONDS 30U

/** Complete ownership and thread state for one daemon control server. */
struct jg_control_server {
    struct jg_daemon_runtime *runtime;
    pthread_t thread;
    atomic_int result;
    uid_t allowed_uid;
    int server_fd;
    int stop_fd;
    bool thread_started;
    bool joined;
    bool owns_path;
};

/** Heap-backed storage for one maximum-sized control exchange. */
struct control_connection_buffers {
    uint8_t request[JG_IPC_MAX_MESSAGE_SIZE];
    uint8_t response[JG_IPC_MAX_MESSAGE_SIZE];
    uint8_t response_body[JG_IPC_MAX_BODY_SIZE];
};

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
        request->operation > JG_IPC_MANAGEMENT_REQUEST ||
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
    } else if (request->operation == JG_IPC_MANAGEMENT_REQUEST) {
        if (request->body_size == 0U) {
            response->error = JG_IPC_ERROR_MALFORMED;
        } else if (runtime == NULL) {
            response->error = JG_IPC_ERROR_SYSTEM;
        } else {
            result = jg_daemon_runtime_process_management(
                runtime, request->body, request->body_size, response_body,
                response_capacity, response_size);
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

/** @brief Close the descriptor accepted by the bounded control buffer. */
static void close_received_descriptor(struct msghdr *message)
{
    struct cmsghdr *header = CMSG_FIRSTHDR(message);

    if (header != NULL && header->cmsg_level == SOL_SOCKET &&
        header->cmsg_type == SCM_RIGHTS &&
        header->cmsg_len >= CMSG_LEN(sizeof(int))) {
        int descriptor = -1;

        (void)memcpy(&descriptor, CMSG_DATA(header), sizeof(descriptor));
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
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
        close_received_descriptor(&message);
        return -EPROTO;
    }
    if ((size_t)received > data_size) {
        return -EMSGSIZE;
    }
    *received_size = (size_t)received;
    return 0;
}

/** @brief Execute one lifecycle action only after its response is delivered. */
static int perform_system_action(struct jg_daemon_runtime *runtime)
{
    const enum jg_system_action action =
        jg_daemon_runtime_take_system_action(runtime);

    if (action == JG_SYSTEM_ACTION_RESTART) {
        return jg_daemon_runtime_request_stop(runtime);
    }
    if (action == JG_SYSTEM_ACTION_REBOOT ||
        action == JG_SYSTEM_ACTION_POWEROFF) {
        return jg_netd_client_power(action == JG_SYSTEM_ACTION_POWEROFF);
    }
    return 0;
}

/** @brief Authenticate and exchange one bounded control request. */
int jg_control_handle_connection(int socket_fd,
                                 uid_t allowed_uid,
                                 struct jg_daemon_runtime *runtime)
{
    struct control_connection_buffers *buffers = NULL;
    struct jg_ipc_message request;
    struct jg_ipc_message response;
    size_t request_size = 0U;
    size_t response_size = 0U;
    ssize_t sent = 0;
    int result = 0;

    if (socket_fd < 0) {
        return -EINVAL;
    }
    buffers = malloc(sizeof(*buffers));
    if (buffers == NULL) {
        return -ENOMEM;
    }
    result = authenticate_peer(socket_fd, allowed_uid);
    if (result == 0) {
        result = receive_request(socket_fd, buffers->request,
                                 sizeof(buffers->request), &request_size);
    }
    if (result == 0) {
        result = jg_ipc_decode(buffers->request, request_size, &request);
    }
    if (result == 0) {
        size_t response_body_size = 0U;

        result = jg_control_process_request(
            runtime, &request, &response, buffers->response_body,
            sizeof(buffers->response_body), &response_body_size);
        if (result == 0) {
            result = jg_ipc_encode(&response, buffers->response,
                                   sizeof(buffers->response), &response_size);
        }
    }
    if (result == 0) {
        sent = send(socket_fd, buffers->response, response_size, MSG_NOSIGNAL);
        if (sent < 0) {
            result = -errno;
        } else if ((size_t)sent != response_size) {
            result = -EIO;
        }
    }
    if (result == 0) {
        result = perform_system_action(runtime);
    }
    jg_secure_clear(buffers, sizeof(*buffers));
    free(buffers);
    return result;
}

/** @brief Notify the server thread through its level-triggered event. */
static int notify_stop(struct jg_control_server *server)
{
    const uint64_t notification = 1U;
    const ssize_t written =
        write(server->stop_fd, &notification, sizeof(notification));

    if (written == (ssize_t)sizeof(notification) ||
        (written < 0 && errno == EAGAIN)) {
        return 0;
    }
    return written < 0 ? -errno : -EIO;
}

/** @brief Create and secure shared and daemon-owned runtime directories. */
static int prepare_runtime_directory(uid_t owner_uid, gid_t socket_gid)
{
    struct stat status;
    bool control_directory_created = false;

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
    if (mkdir(JG_CONTROL_RUNTIME_DIRECTORY, 0750) == 0) {
        control_directory_created = true;
    } else if (errno != EEXIST) {
        return -errno;
    }
    if (lstat(JG_CONTROL_RUNTIME_DIRECTORY, &status) != 0) {
        return -errno;
    }
    if (!S_ISDIR(status.st_mode) ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0U) {
        return -EACCES;
    }
    if (control_directory_created &&
        (chmod(JG_CONTROL_RUNTIME_DIRECTORY, 0750) != 0 ||
         chown(JG_CONTROL_RUNTIME_DIRECTORY, owner_uid, socket_gid) != 0)) {
        return -errno;
    }
    if (control_directory_created &&
        lstat(JG_CONTROL_RUNTIME_DIRECTORY, &status) != 0) {
        return -errno;
    }
    if (status.st_uid != owner_uid || status.st_gid != socket_gid ||
        (status.st_mode & 0777U) != 0750U) {
        return -EACCES;
    }
    return 0;
}

/** @brief Remove only a stale daemon-owned control socket. */
static int remove_stale_socket(uid_t owner_uid)
{
    struct stat status;

    if (lstat(JG_CONTROL_SOCKET_PATH, &status) != 0) {
        return errno == ENOENT ? 0 : -errno;
    }
    if (!S_ISSOCK(status.st_mode) || status.st_uid != owner_uid) {
        return -EEXIST;
    }
    return unlink(JG_CONTROL_SOCKET_PATH) == 0 ? 0 : -errno;
}

/** @brief Open and permission the fixed non-blocking listening socket. */
static int open_server_socket(uid_t owner_uid,
                              gid_t socket_gid,
                              bool *owns_path)
{
    struct sockaddr_un address;
    int socket_fd = -1;
    int result = prepare_runtime_directory(owner_uid, socket_gid);

    if (result == 0) {
        result = remove_stale_socket(owner_uid);
    }
    if (result == 0) {
        socket_fd =
            socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (socket_fd < 0) {
            result = -errno;
        }
    }
    if (result == 0) {
        (void)memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        if (sizeof(JG_CONTROL_SOCKET_PATH) > sizeof(address.sun_path)) {
            result = -ENAMETOOLONG;
        } else {
            (void)memcpy(address.sun_path, JG_CONTROL_SOCKET_PATH,
                         sizeof(JG_CONTROL_SOCKET_PATH));
        }
    }
    if (result == 0 && bind(socket_fd, (const struct sockaddr *)&address,
                            (socklen_t)sizeof(address)) != 0) {
        result = -errno;
    } else if (result == 0) {
        *owns_path = true;
    }
    if (result == 0 &&
        (chmod(JG_CONTROL_SOCKET_PATH, 0660) != 0 ||
         chown(JG_CONTROL_SOCKET_PATH, owner_uid, socket_gid) != 0 ||
         listen(socket_fd, 16) != 0)) {
        result = -errno;
    }
    if (result != 0 && socket_fd >= 0) {
        (void)close(socket_fd);
        socket_fd = -1;
    }
    return result == 0 ? socket_fd : result;
}

/** @brief Impose bounded blocking time on one connected peer. */
static int configure_client_socket(int socket_fd)
{
    const struct timeval timeout = {
        .tv_sec = JG_CONTROL_IO_TIMEOUT_SECONDS,
        .tv_usec = 0,
    };

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   (socklen_t)sizeof(timeout)) != 0 ||
        setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   (socklen_t)sizeof(timeout)) != 0) {
        return -errno;
    }
    return 0;
}

/** @brief Read one nonnegative clock value as whole seconds. */
static int clock_seconds(clockid_t clock_id, uint64_t *seconds)
{
    struct timespec value;

    if (clock_gettime(clock_id, &value) != 0) {
        return -errno;
    }
    if (value.tv_sec < 0) {
        return -EIO;
    }
    *seconds = (uint64_t)value.tv_sec;
    return 0;
}

/** @brief Run due source updates and schedule the next bounded check. */
static int update_blocklists(struct jg_control_server *server,
                             uint64_t monotonic_now,
                             uint64_t *next_check)
{
    uint64_t wall_now = 0U;
    int result = clock_seconds(CLOCK_REALTIME, &wall_now);

    if (result == 0 && wall_now == 0U) {
        result = -EIO;
    }
    if (result == 0) {
        result = jg_daemon_runtime_update_blocklists(server->runtime, wall_now,
                                                     NULL);
    }
    if (result == 0) {
        *next_check =
            monotonic_now > UINT64_MAX - JG_CONTROL_UPDATE_INTERVAL_SECONDS
                ? UINT64_MAX
                : monotonic_now + JG_CONTROL_UPDATE_INTERVAL_SECONDS;
    }
    return result;
}

/** @brief Accept and service peers until the stop event becomes readable. */
static int serve_connections(struct jg_control_server *server)
{
    struct pollfd descriptors[2U] = {
        {.fd = server->server_fd, .events = POLLIN},
        {.fd = server->stop_fd, .events = POLLIN},
    };
    uint64_t next_update_check = 0U;
    int result = 0;

    while (result == 0) {
        uint64_t monotonic_now = 0U;
        int timeout_ms = 0;
        int ready = 0;

        result = clock_seconds(CLOCK_MONOTONIC, &monotonic_now);
        if (result == 0 && monotonic_now >= next_update_check) {
            result =
                update_blocklists(server, monotonic_now, &next_update_check);
        }
        if (result != 0) {
            break;
        }
        timeout_ms =
            next_update_check - monotonic_now > (uint64_t)INT_MAX / 1000U
                ? INT_MAX
                : (int)((next_update_check - monotonic_now) * 1000U);
        ready = poll(descriptors, 2U, timeout_ms);

        if (ready < 0) {
            if (errno != EINTR) {
                result = -errno;
            }
        } else if ((descriptors[1U].revents & POLLIN) != 0) {
            break;
        } else if ((descriptors[0U].revents & POLLIN) != 0) {
            const int client_fd =
                accept4(server->server_fd, NULL, NULL, SOCK_CLOEXEC);

            if (client_fd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    result = -errno;
                }
            } else {
                if (configure_client_socket(client_fd) == 0) {
                    (void)jg_control_handle_connection(
                        client_fd, server->allowed_uid, server->runtime);
                }
                (void)close(client_fd);
            }
        } else if (descriptors[0U].revents != 0 ||
                   descriptors[1U].revents != 0) {
            result = -EIO;
        }
    }
    return result;
}

/** @brief Run the serial control loop and stop packet workers on failure. */
static void *run_server(void *context)
{
    struct jg_control_server *server = context;
    const int result = serve_connections(server);

    atomic_store_explicit(&server->result, result, memory_order_release);
    if (result != 0) {
        (void)jg_daemon_runtime_request_stop(server->runtime);
    }
    return NULL;
}

/** @brief Close descriptors, remove the owned path, and release state. */
static void release_server(struct jg_control_server *server)
{
    if (server == NULL) {
        return;
    }
    if (server->server_fd >= 0) {
        (void)close(server->server_fd);
    }
    if (server->stop_fd >= 0) {
        (void)close(server->stop_fd);
    }
    if (server->owns_path) {
        (void)unlink(JG_CONTROL_SOCKET_PATH);
    }
    free(server);
}

/** @brief Open the fixed control socket and start its serial thread. */
int jg_control_server_start(struct jg_daemon_runtime *runtime,
                            uid_t owner_uid,
                            uid_t allowed_uid,
                            gid_t socket_gid,
                            struct jg_control_server **server)
{
    struct jg_control_server *started = NULL;
    int result = 0;

    if (server == NULL) {
        return -EINVAL;
    }
    *server = NULL;
    if (runtime == NULL || owner_uid == 0U || allowed_uid == 0U) {
        return -EINVAL;
    }
    started = calloc(1U, sizeof(*started));
    if (started == NULL) {
        return -ENOMEM;
    }
    started->runtime = runtime;
    started->allowed_uid = allowed_uid;
    started->server_fd = -1;
    started->stop_fd = -1;
    atomic_init(&started->result, 0);
    started->stop_fd = eventfd(0U, EFD_CLOEXEC | EFD_NONBLOCK);
    if (started->stop_fd < 0) {
        result = -errno;
    }
    if (result == 0) {
        started->server_fd =
            open_server_socket(owner_uid, socket_gid, &started->owns_path);
        if (started->server_fd < 0) {
            result = started->server_fd;
        }
    }
    if (result == 0) {
        result = pthread_create(&started->thread, NULL, run_server, started);
        if (result == 0) {
            started->thread_started = true;
        } else {
            result = -result;
        }
    }
    if (result != 0) {
        release_server(started);
        return result;
    }
    *server = started;
    return 0;
}

/** @brief Stop, join, and report one control-server thread. */
int jg_control_server_stop(struct jg_control_server *server)
{
    int result = 0;

    if (server == NULL) {
        return -EINVAL;
    }
    if (server->joined) {
        return atomic_load_explicit(&server->result, memory_order_acquire);
    }
    result = notify_stop(server);
    if (server->thread_started) {
        const int join_result = pthread_join(server->thread, NULL);

        server->thread_started = false;
        if (result == 0 && join_result != 0) {
            result = -join_result;
        }
    }
    server->joined = true;
    if (result == 0) {
        result = atomic_load_explicit(&server->result, memory_order_acquire);
    }
    return result;
}

/** @brief Stop and release one complete control server. */
void jg_control_server_destroy(struct jg_control_server *server)
{
    if (server == NULL) {
        return;
    }
    if (!server->joined) {
        (void)jg_control_server_stop(server);
    }
    release_server(server);
}
