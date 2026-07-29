/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>

#include <cmocka.h>

#include "janusgate/ipc.h"

int jg_test_ipc(void);

/** @brief Verify request framing and borrowed-body decoding. */
static void test_request_round_trip(void **state)
{
    static const uint8_t body[] = {0x10U, 0x20U, 0x30U};
    struct jg_ipc_message request = {
        .kind = JG_IPC_REQUEST,
        .operation = JG_IPC_NETWORK_VALIDATE,
        .request_id = UINT64_C(0x0123456789abcdef),
        .error = JG_IPC_ERROR_NONE,
        .body = body,
        .body_size = sizeof(body),
    };
    uint8_t encoded[JG_IPC_HEADER_SIZE + sizeof(body)] = {0U};
    struct jg_ipc_message decoded;
    size_t encoded_size = 0U;

    (void)state;
    assert_int_equal(
        jg_ipc_encode(&request, encoded, sizeof(encoded), &encoded_size), 0);
    assert_int_equal(encoded_size, sizeof(encoded));
    assert_memory_equal(encoded, "JGIP", 4U);
    assert_int_equal(encoded[5], JG_IPC_VERSION);
    assert_int_equal(encoded[7], JG_IPC_REQUEST);
    assert_int_equal(encoded[9], JG_IPC_NETWORK_VALIDATE);
    assert_int_equal(encoded[17], 0x23);
    assert_int_equal(encoded[23], 0xef);

    assert_int_equal(jg_ipc_decode(encoded, encoded_size, &decoded), 0);
    assert_int_equal(decoded.kind, request.kind);
    assert_int_equal(decoded.operation, request.operation);
    assert_int_equal(decoded.request_id, request.request_id);
    assert_int_equal(decoded.error, request.error);
    assert_int_equal(decoded.body_size, sizeof(body));
    assert_ptr_equal(decoded.body, encoded + JG_IPC_HEADER_SIZE);
    assert_memory_equal(decoded.body, body, sizeof(body));

    request.operation = JG_IPC_SYSTEM_POWEROFF;
    assert_int_equal(
        jg_ipc_encode(&request, encoded, sizeof(encoded), &encoded_size), 0);
    assert_int_equal(jg_ipc_decode(encoded, encoded_size, &decoded), 0);
    assert_int_equal(decoded.operation, JG_IPC_SYSTEM_POWEROFF);
}

/** @brief Verify response errors and empty operation bodies. */
static void test_response_round_trip(void **state)
{
    const struct jg_ipc_message response = {
        .kind = JG_IPC_RESPONSE,
        .operation = JG_IPC_NETWORK_APPLY,
        .request_id = 42U,
        .error = JG_IPC_ERROR_CONFLICT,
    };
    uint8_t encoded[JG_IPC_HEADER_SIZE] = {0U};
    struct jg_ipc_message decoded;
    size_t encoded_size = 0U;

    (void)state;
    assert_int_equal(
        jg_ipc_encode(&response, encoded, sizeof(encoded), &encoded_size), 0);
    assert_int_equal(jg_ipc_decode(encoded, encoded_size, &decoded), 0);
    assert_int_equal(decoded.kind, JG_IPC_RESPONSE);
    assert_int_equal(decoded.error, JG_IPC_ERROR_CONFLICT);
    assert_int_equal(decoded.body_size, 0U);
}

/** @brief Verify encoder rejection and destination bounds. */
static void test_encode_errors(void **state)
{
    static const uint8_t body = 0U;
    struct jg_ipc_message message = {
        .kind = JG_IPC_REQUEST,
        .operation = JG_IPC_PING,
        .request_id = 1U,
        .error = JG_IPC_ERROR_NONE,
        .body = &body,
        .body_size = 1U,
    };
    uint8_t encoded[JG_IPC_HEADER_SIZE + 1U] = {0U};
    size_t encoded_size = 0U;

    (void)state;
    assert_int_equal(
        jg_ipc_encode(&message, encoded, sizeof(encoded) - 1U, &encoded_size),
        -ENOSPC);
    message.request_id = 0U;
    assert_int_equal(
        jg_ipc_encode(&message, encoded, sizeof(encoded), &encoded_size),
        -EINVAL);
    message.request_id = 1U;
    message.error = JG_IPC_ERROR_INVALID;
    assert_int_equal(
        jg_ipc_encode(&message, encoded, sizeof(encoded), &encoded_size),
        -EINVAL);
    message.error = JG_IPC_ERROR_NONE;
    message.body = NULL;
    assert_int_equal(
        jg_ipc_encode(&message, encoded, sizeof(encoded), &encoded_size),
        -EINVAL);
    message.body = &body;
    message.body_size = JG_IPC_MAX_BODY_SIZE + 1U;
    assert_int_equal(
        jg_ipc_encode(&message, encoded, sizeof(encoded), &encoded_size),
        -EMSGSIZE);
}

/** @brief Verify decoder rejection of corrupted structural fields. */
static void test_decode_errors(void **state)
{
    const struct jg_ipc_message request = {
        .kind = JG_IPC_REQUEST,
        .operation = JG_IPC_PING,
        .request_id = 1U,
        .error = JG_IPC_ERROR_NONE,
    };
    uint8_t encoded[JG_IPC_HEADER_SIZE + 1U] = {0U};
    struct jg_ipc_message decoded;
    size_t encoded_size = 0U;

    (void)state;
    assert_int_equal(
        jg_ipc_encode(&request, encoded, sizeof(encoded), &encoded_size), 0);

    encoded[0] = 'X';
    assert_int_equal(jg_ipc_decode(encoded, encoded_size, &decoded), -EPROTO);
    encoded[0] = 'J';

    encoded[5] = 2U;
    assert_int_equal(jg_ipc_decode(encoded, encoded_size, &decoded),
                     -EPROTONOSUPPORT);
    encoded[5] = JG_IPC_VERSION;

    encoded[7] = 9U;
    assert_int_equal(jg_ipc_decode(encoded, encoded_size, &decoded), -EPROTO);
    encoded[7] = JG_IPC_REQUEST;

    encoded[9] = 0U;
    assert_int_equal(jg_ipc_decode(encoded, encoded_size, &decoded), -EPROTO);
    encoded[9] = JG_IPC_PING;

    encoded[11] = JG_IPC_ERROR_INVALID;
    assert_int_equal(jg_ipc_decode(encoded, encoded_size, &decoded), -EPROTO);
    encoded[11] = JG_IPC_ERROR_NONE;

    encoded[27] = 1U;
    assert_int_equal(jg_ipc_decode(encoded, encoded_size, &decoded), -EPROTO);
    encoded[27] = 0U;

    encoded[15] = 1U;
    assert_int_equal(jg_ipc_decode(encoded, encoded_size, &decoded), -EMSGSIZE);
    encoded[15] = 0U;

    assert_int_equal(jg_ipc_decode(encoded, encoded_size + 1U, &decoded),
                     -EMSGSIZE);
    assert_int_equal(jg_ipc_decode(encoded, JG_IPC_HEADER_SIZE - 1U, &decoded),
                     -EMSGSIZE);
    assert_int_equal(jg_ipc_decode(NULL, encoded_size, &decoded), -EINVAL);
}

/** @brief Run the versioned control-frame codec test group. */
int jg_test_ipc(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_request_round_trip),
        cmocka_unit_test(test_response_round_trip),
        cmocka_unit_test(test_encode_errors),
        cmocka_unit_test(test_decode_errors),
    };

    return cmocka_run_group_tests_name("ipc", tests, NULL, NULL);
}
