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

#include "netd.h"
#include "netd_client.h"

int jg_test_netd_client(void);

/** One authenticated helper exchange executed by a test thread. */
struct helper_exchange {
    uid_t allowed_uid;
    int socket_fd;
    int result;
};

/** @brief Service one authenticated test request. */
static void *serve_request(void *context)
{
    struct helper_exchange *exchange = context;

    exchange->result =
        jg_netd_handle_connection(exchange->socket_fd, exchange->allowed_uid);
    return NULL;
}

/** @brief Exchange one request while a helper thread services its peer. */
static int exchange_request(enum jg_ipc_operation operation)
{
    struct helper_exchange exchange = {
        .allowed_uid = geteuid(),
        .socket_fd = -1,
    };
    int sockets[2U] = {-1, -1};
    pthread_t thread;
    int result = 0;

    assert_int_equal(
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets), 0);
    exchange.socket_fd = sockets[1U];
    assert_int_equal(pthread_create(&thread, NULL, serve_request, &exchange),
                     0);
    result = jg_netd_client_exchange(sockets[0U], operation, NULL, 0U);
    assert_int_equal(pthread_join(thread, NULL), 0);
    assert_int_equal(exchange.result, 0);
    assert_int_equal(close(sockets[0U]), 0);
    assert_int_equal(close(sockets[1U]), 0);
    return result;
}

/** @brief Verify successful correlation and remote error translation. */
static void test_exchange(void **state)
{
    (void)state;
    assert_int_equal(exchange_request(JG_IPC_PING), 0);
    assert_int_equal(exchange_request(JG_IPC_NETWORK_STATE), -ENOTSUP);
}

/** @brief Verify conservative client argument and encoding rejection. */
static void test_arguments(void **state)
{
    struct jg_network_config config = {0};

    (void)state;
    assert_int_equal(jg_netd_client_exchange(-1, JG_IPC_PING, NULL, 0U),
                     -EINVAL);
    assert_int_equal(jg_netd_client_exchange(0, JG_IPC_PING, NULL,
                                             JG_IPC_MAX_BODY_SIZE + 1U),
                     -EINVAL);
    assert_int_equal(jg_netd_client_validate(&config), -EINVAL);
    assert_int_equal(jg_netd_client_validate(NULL), -EINVAL);
    assert_int_equal(jg_netd_client_apply(&config), -EINVAL);
    assert_int_equal(jg_netd_client_apply(NULL), -EINVAL);
}

/** @brief Run the privileged helper client test group. */
int jg_test_netd_client(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_exchange),
        cmocka_unit_test(test_arguments),
    };

    return cmocka_run_group_tests_name("netd client", tests, NULL, NULL);
}
