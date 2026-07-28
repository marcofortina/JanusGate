/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cmocka.h>

#include "janusgate/ipc_client.h"

int jg_test_ipc_client(void);

/** One fixed response returned by a mock local endpoint. */
struct mock_exchange {
    int socket_fd;
    int result;
};

/** @brief Receive one request and return a correlated three-byte body. */
static void *serve_response(void *context)
{
    static const uint8_t body[3U] = {1U, 2U, 3U};
    struct mock_exchange *exchange = context;
    uint8_t data[JG_IPC_MAX_MESSAGE_SIZE];
    struct jg_ipc_message request;
    struct jg_ipc_message response;
    size_t encoded_size = 0U;
    ssize_t transferred = recv(exchange->socket_fd, data, sizeof(data), 0);

    exchange->result = transferred < 0
                           ? -errno
                           : jg_ipc_decode(data, (size_t)transferred, &request);
    if (exchange->result == 0) {
        response = (struct jg_ipc_message){
            .kind = JG_IPC_RESPONSE,
            .operation = request.operation,
            .request_id = request.request_id,
            .error = JG_IPC_ERROR_NONE,
            .body = body,
            .body_size = sizeof(body),
        };
        exchange->result =
            jg_ipc_encode(&response, data, sizeof(data), &encoded_size);
    }
    if (exchange->result == 0) {
        transferred =
            send(exchange->socket_fd, data, encoded_size, MSG_NOSIGNAL);
        if (transferred < 0) {
            exchange->result = -errno;
        } else if ((size_t)transferred != encoded_size) {
            exchange->result = -EIO;
        }
    }
    return NULL;
}

/** @brief Verify bounded response copying on a connected socket. */
static void test_exchange(void **state)
{
    struct mock_exchange exchange = {.socket_fd = -1};
    uint8_t response[3U] = {0};
    const uint8_t expected[3U] = {1U, 2U, 3U};
    int sockets[2U] = {-1, -1};
    size_t response_size = 0U;
    pthread_t thread;

    (void)state;
    assert_int_equal(
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets), 0);
    exchange.socket_fd = sockets[1U];
    assert_int_equal(pthread_create(&thread, NULL, serve_response, &exchange),
                     0);
    assert_int_equal(jg_ipc_client_exchange(sockets[0U], JG_IPC_DAEMON_STATUS,
                                            NULL, 0U, response,
                                            sizeof(response), &response_size),
                     0);
    assert_int_equal(response_size, sizeof(response));
    assert_memory_equal(response, expected, sizeof(expected));
    assert_int_equal(pthread_join(thread, NULL), 0);
    assert_int_equal(exchange.result, 0);
    assert_int_equal(close(sockets[0U]), 0);
    assert_int_equal(close(sockets[1U]), 0);
}

/** @brief Verify conservative local-client argument rejection. */
static void test_arguments(void **state)
{
    size_t response_size = 0U;

    (void)state;
    assert_int_equal(jg_ipc_client_exchange(-1, JG_IPC_PING, NULL, 0U, NULL, 0U,
                                            &response_size),
                     -EINVAL);
    assert_int_equal(jg_ipc_client_call("relative", JG_IPC_PING, NULL, 0U, NULL,
                                        0U, &response_size),
                     -EINVAL);
    assert_int_equal(jg_ipc_client_call(JG_CONTROL_SOCKET_PATH, JG_IPC_PING,
                                        NULL, 0U, NULL, 0U, NULL),
                     -EINVAL);
}

/** @brief Run the bounded local IPC client test group. */
int jg_test_ipc_client(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_exchange),
        cmocka_unit_test(test_arguments),
    };

    return cmocka_run_group_tests_name("IPC client", tests, NULL, NULL);
}
