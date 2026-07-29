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

#include "control_protocol.h"
#include "control_server.h"
#include "netd_client.h"

int jg_test_control_server(void);

/** One control exchange executed by a test thread. */
struct control_exchange {
    uid_t allowed_uid;
    int socket_fd;
    int result;
};

/** @brief Service one authenticated control request. */
static void *serve_request(void *context)
{
    struct control_exchange *exchange = context;

    exchange->result = jg_control_handle_connection(
        exchange->socket_fd, exchange->allowed_uid, NULL);
    return NULL;
}

/** @brief Verify pure dispatch envelopes and allowlisted operations. */
static void test_dispatch(void **state)
{
    uint8_t response_body[JG_DAEMON_STATUS_WIRE_SIZE];
    const uint8_t unexpected = 1U;
    struct jg_ipc_message request = {
        .kind = JG_IPC_REQUEST,
        .operation = JG_IPC_PING,
        .request_id = 7U,
        .error = JG_IPC_ERROR_NONE,
    };
    struct jg_ipc_message response;
    size_t response_size = 0U;

    (void)state;
    assert_int_equal(
        jg_control_process_request(NULL, &request, &response, response_body,
                                   sizeof(response_body), &response_size),
        0);
    assert_int_equal(response.error, JG_IPC_ERROR_NONE);
    assert_int_equal(response_size, 0U);

    request.body = &unexpected;
    request.body_size = 1U;
    assert_int_equal(
        jg_control_process_request(NULL, &request, &response, response_body,
                                   sizeof(response_body), &response_size),
        0);
    assert_int_equal(response.error, JG_IPC_ERROR_MALFORMED);
    request.body = NULL;
    request.body_size = 0U;
    request.operation = JG_IPC_POLICY_RELOAD;
    assert_int_equal(
        jg_control_process_request(NULL, &request, &response, response_body,
                                   sizeof(response_body), &response_size),
        0);
    assert_int_equal(response.error, JG_IPC_ERROR_SYSTEM);
    request.operation = JG_IPC_NETWORK_STATE;
    assert_int_equal(
        jg_control_process_request(NULL, &request, &response, response_body,
                                   sizeof(response_body), &response_size),
        0);
    assert_int_equal(response.error, JG_IPC_ERROR_UNSUPPORTED);
}

/** @brief Verify an authenticated bounded control-socket exchange. */
static void test_connection(void **state)
{
    struct control_exchange exchange = {
        .allowed_uid = geteuid(),
        .socket_fd = -1,
    };
    int sockets[2U] = {-1, -1};
    pthread_t thread;

    (void)state;
    assert_int_equal(
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets), 0);
    exchange.socket_fd = sockets[1U];
    assert_int_equal(pthread_create(&thread, NULL, serve_request, &exchange),
                     0);
    assert_int_equal(
        jg_netd_client_exchange(sockets[0U], JG_IPC_PING, NULL, 0U), 0);
    assert_int_equal(pthread_join(thread, NULL), 0);
    assert_int_equal(exchange.result, 0);
    assert_int_equal(close(sockets[0U]), 0);
    assert_int_equal(close(sockets[1U]), 0);
    assert_int_equal(jg_control_handle_connection(-1, geteuid(), NULL),
                     -EINVAL);
}

/** @brief Verify null-safe server lifecycle arguments. */
static void test_lifecycle_arguments(void **state)
{
    struct jg_control_server *server = NULL;

    (void)state;
    assert_int_equal(jg_control_server_start(NULL, 1U, 1U, 1U, &server),
                     -EINVAL);
    assert_null(server);
    assert_int_equal(jg_control_server_start(NULL, 1U, 1U, 1U, NULL), -EINVAL);
    assert_int_equal(jg_control_server_stop(NULL), -EINVAL);
    jg_control_server_destroy(NULL);
}

/** @brief Run the authenticated daemon control test group. */
int jg_test_control_server(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dispatch),
        cmocka_unit_test(test_connection),
        cmocka_unit_test(test_lifecycle_arguments),
    };

    return cmocka_run_group_tests_name("control server", tests, NULL, NULL);
}
