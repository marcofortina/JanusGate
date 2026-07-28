/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>

#include <sys/socket.h>
#include <unistd.h>

#include <cmocka.h>

#include "janusgate/ipc.h"
#include "janusgate/network.h"
#include "netd.h"

int jg_test_netd(void);

/** @brief Build one valid network configuration for helper requests. */
static struct jg_network_config test_config(void)
{
    const struct jg_network_config config = {
        .bridge = "br-data",
        .ingress = "eth0",
        .egress = "eth1",
        .management = "eth2",
        .bridge_mtu = 1500U,
        .queue_first = 100U,
        .queue_count = 2U,
        .queue_length = 4096U,
        .failure_mode = JG_NETWORK_FAIL_OPEN,
        .multicast_snooping = true,
        .queue_cpu_fanout = true,
    };

    return config;
}

/** @brief Encode one request into caller-owned transport storage. */
static size_t encode_request(enum jg_ipc_operation operation,
                             const uint8_t *body,
                             size_t body_size,
                             uint8_t *output,
                             size_t output_size)
{
    const struct jg_ipc_message request = {
        .kind = JG_IPC_REQUEST,
        .operation = operation,
        .request_id = 42U,
        .error = JG_IPC_ERROR_NONE,
        .body = body,
        .body_size = body_size,
    };
    size_t encoded_size = 0U;

    assert_int_equal(
        jg_ipc_encode(&request, output, output_size, &encoded_size), 0);
    return encoded_size;
}

/** @brief Verify ping, typed validation, and unsupported-operation responses.
 */
static void test_request_dispatch(void **state)
{
    const struct jg_network_config config = test_config();
    uint8_t body[JG_NETWORK_CONFIG_WIRE_SIZE] = {0U};
    struct jg_ipc_message request = {
        .kind = JG_IPC_REQUEST,
        .operation = JG_IPC_PING,
        .request_id = 7U,
        .error = JG_IPC_ERROR_NONE,
    };
    struct jg_ipc_message response;
    size_t body_size = 0U;

    (void)state;
    assert_int_equal(jg_netd_process_request(&request, &response), 0);
    assert_int_equal(response.kind, JG_IPC_RESPONSE);
    assert_int_equal(response.request_id, request.request_id);
    assert_int_equal(response.error, JG_IPC_ERROR_NONE);

    request.body = body;
    request.body_size = 1U;
    assert_int_equal(jg_netd_process_request(&request, &response), 0);
    assert_int_equal(response.error, JG_IPC_ERROR_MALFORMED);

    assert_int_equal(
        jg_network_config_encode(&config, body, sizeof(body), &body_size), 0);
    request.operation = JG_IPC_NETWORK_VALIDATE;
    request.body_size = body_size;
    assert_int_equal(jg_netd_process_request(&request, &response), 0);
    assert_int_equal(response.error, JG_IPC_ERROR_NONE);

    body[1] = 2U;
    assert_int_equal(jg_netd_process_request(&request, &response), 0);
    assert_int_equal(response.error, JG_IPC_ERROR_VERSION);
    body[1] = 1U;

    request.operation = JG_IPC_NETWORK_APPLY;
    assert_int_equal(jg_netd_process_request(&request, &response), 0);
    assert_int_equal(response.error, JG_IPC_ERROR_UNSUPPORTED);
}

/** @brief Verify authenticated `SOCK_SEQPACKET` request exchange. */
static void test_authenticated_connection(void **state)
{
    uint8_t request_data[JG_IPC_HEADER_SIZE] = {0U};
    uint8_t response_data[JG_IPC_HEADER_SIZE] = {0U};
    struct jg_ipc_message response;
    int sockets[2] = {-1, -1};
    size_t request_size = 0U;
    ssize_t received = 0;

    (void)state;
    assert_int_equal(
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets), 0);
    request_size = encode_request(JG_IPC_PING, NULL, 0U, request_data,
                                  sizeof(request_data));
    assert_int_equal(send(sockets[0], request_data, request_size, 0),
                     (ssize_t)request_size);
    assert_int_equal(jg_netd_handle_connection(sockets[1], geteuid()), 0);
    received = recv(sockets[0], response_data, sizeof(response_data), 0);
    assert_int_equal(received, (ssize_t)sizeof(response_data));
    assert_int_equal(jg_ipc_decode(response_data, (size_t)received, &response),
                     0);
    assert_int_equal(response.error, JG_IPC_ERROR_NONE);
    assert_int_equal(close(sockets[1]), 0);
    assert_int_equal(close(sockets[0]), 0);
}

/** @brief Verify rejection of a peer outside the service identity. */
static void test_unauthorized_connection(void **state)
{
    uint8_t request_data[JG_IPC_HEADER_SIZE] = {0U};
    const uid_t unexpected_uid = geteuid() == 0U ? 1U : 0U;
    int sockets[2] = {-1, -1};
    size_t request_size = 0U;

    (void)state;
    assert_int_equal(
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets), 0);
    request_size = encode_request(JG_IPC_PING, NULL, 0U, request_data,
                                  sizeof(request_data));
    assert_int_equal(send(sockets[0], request_data, request_size, 0),
                     (ssize_t)request_size);
    assert_int_equal(jg_netd_handle_connection(sockets[1], unexpected_uid),
                     -EACCES);
    assert_int_equal(close(sockets[1]), 0);
    assert_int_equal(close(sockets[0]), 0);
}

/** @brief Verify rejection of oversized and ancillary-bearing packets. */
static void test_transport_boundaries(void **state)
{
    uint8_t oversized[JG_IPC_MAX_MESSAGE_SIZE + 1U] = {0U};
    uint8_t request_data[JG_IPC_HEADER_SIZE] = {0U};
    uint8_t control[CMSG_SPACE(sizeof(int))] = {0U};
    struct iovec payload;
    struct msghdr message;
    struct cmsghdr *header = NULL;
    int sockets[2] = {-1, -1};
    size_t request_size = 0U;

    (void)state;
    assert_int_equal(
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets), 0);
    assert_int_equal(send(sockets[0], oversized, sizeof(oversized), 0),
                     (ssize_t)sizeof(oversized));
    assert_int_equal(jg_netd_handle_connection(sockets[1], geteuid()),
                     -EMSGSIZE);
    assert_int_equal(close(sockets[1]), 0);
    assert_int_equal(close(sockets[0]), 0);

    assert_int_equal(
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets), 0);
    request_size = encode_request(JG_IPC_PING, NULL, 0U, request_data,
                                  sizeof(request_data));
    payload.iov_base = request_data;
    payload.iov_len = request_size;
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &payload;
    message.msg_iovlen = 1U;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    header = CMSG_FIRSTHDR(&message);
    assert_non_null(header);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    (void)memcpy(CMSG_DATA(header), &sockets[0], sizeof(sockets[0]));
    assert_int_equal(sendmsg(sockets[0], &message, 0), (ssize_t)request_size);
    assert_int_equal(jg_netd_handle_connection(sockets[1], geteuid()), -EPROTO);
    assert_int_equal(close(sockets[1]), 0);
    assert_int_equal(close(sockets[0]), 0);
}

/** @brief Run the privileged-helper protocol test group. */
int jg_test_netd(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_request_dispatch),
        cmocka_unit_test(test_authenticated_connection),
        cmocka_unit_test(test_unauthorized_connection),
        cmocka_unit_test(test_transport_boundaries),
    };

    return cmocka_run_group_tests_name("netd", tests, NULL, NULL);
}
