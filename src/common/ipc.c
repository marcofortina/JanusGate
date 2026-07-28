/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/ipc.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "janusgate/checked.h"

/** Header offsets in the stable binary representation. */
enum header_offset {
    MAGIC_OFFSET = 0,
    VERSION_OFFSET = 4,
    KIND_OFFSET = 6,
    OPERATION_OFFSET = 8,
    ERROR_OFFSET = 10,
    BODY_SIZE_OFFSET = 12,
    REQUEST_ID_OFFSET = 16,
    RESERVED_OFFSET = 24
};

/** Fixed protocol discriminator. */
static const uint8_t ipc_magic[4U] = {'J', 'G', 'I', 'P'};

/** @brief Determine whether a message kind is supported. */
static bool kind_valid(enum jg_ipc_kind kind)
{
    return kind == JG_IPC_REQUEST || kind == JG_IPC_RESPONSE;
}

/** @brief Determine whether an operation is allowlisted. */
static bool operation_valid(enum jg_ipc_operation operation)
{
    return operation >= JG_IPC_PING && operation <= JG_IPC_MANAGEMENT_REQUEST;
}

/** @brief Determine whether a response error has a stable wire value. */
static bool error_valid(enum jg_ipc_error error)
{
    return error >= JG_IPC_ERROR_NONE && error <= JG_IPC_ERROR_SYSTEM;
}

/** @brief Validate relationships in a host-order message. */
static int validate_message(const struct jg_ipc_message *message)
{
    if (message == NULL || !kind_valid(message->kind) ||
        !operation_valid(message->operation) || message->request_id == 0U ||
        !error_valid(message->error) ||
        (message->kind == JG_IPC_REQUEST &&
         message->error != JG_IPC_ERROR_NONE) ||
        (message->body_size != 0U && message->body == NULL)) {
        return -EINVAL;
    }
    return message->body_size > JG_IPC_MAX_BODY_SIZE ? -EMSGSIZE : 0;
}

/** @brief Encode one bounded architecture-independent control frame. */
int jg_ipc_encode(const struct jg_ipc_message *message,
                  uint8_t *output,
                  size_t output_size,
                  size_t *encoded_size)
{
    size_t message_size = 0U;
    int result = validate_message(message);

    if (output == NULL || encoded_size == NULL) {
        return -EINVAL;
    }
    if (result != 0) {
        return result;
    }
    if (!jg_size_add(JG_IPC_HEADER_SIZE, message->body_size, &message_size)) {
        return -EMSGSIZE;
    }
    if (output_size < message_size) {
        return -ENOSPC;
    }

    (void)memcpy(output + MAGIC_OFFSET, ipc_magic, sizeof(ipc_magic));
    (void)jg_write_u16_be(output, output_size, VERSION_OFFSET,
                          (uint16_t)JG_IPC_VERSION);
    (void)jg_write_u16_be(output, output_size, KIND_OFFSET,
                          (uint16_t)message->kind);
    (void)jg_write_u16_be(output, output_size, OPERATION_OFFSET,
                          (uint16_t)message->operation);
    (void)jg_write_u16_be(output, output_size, ERROR_OFFSET,
                          (uint16_t)message->error);
    (void)jg_write_u32_be(output, output_size, BODY_SIZE_OFFSET,
                          (uint32_t)message->body_size);
    (void)jg_write_u64_be(output, output_size, REQUEST_ID_OFFSET,
                          message->request_id);
    (void)jg_write_u32_be(output, output_size, RESERVED_OFFSET, 0U);
    if (message->body_size != 0U) {
        (void)memcpy(output + JG_IPC_HEADER_SIZE, message->body,
                     message->body_size);
    }
    *encoded_size = message_size;
    return 0;
}

/** @brief Decode one exact bounded architecture-independent control frame. */
int jg_ipc_decode(const uint8_t *data,
                  size_t data_size,
                  struct jg_ipc_message *message)
{
    struct jg_ipc_message decoded;
    uint64_t request_id = 0U;
    uint32_t body_size = 0U;
    uint32_t reserved = 0U;
    uint16_t version = 0U;
    uint16_t kind = 0U;
    uint16_t operation = 0U;
    uint16_t error = 0U;
    size_t expected_size = 0U;

    if (data == NULL || message == NULL) {
        return -EINVAL;
    }
    if (data_size < JG_IPC_HEADER_SIZE) {
        return -EMSGSIZE;
    }
    if (memcmp(data + MAGIC_OFFSET, ipc_magic, sizeof(ipc_magic)) != 0 ||
        !jg_read_u16_be(data, data_size, VERSION_OFFSET, &version) ||
        !jg_read_u16_be(data, data_size, KIND_OFFSET, &kind) ||
        !jg_read_u16_be(data, data_size, OPERATION_OFFSET, &operation) ||
        !jg_read_u16_be(data, data_size, ERROR_OFFSET, &error) ||
        !jg_read_u32_be(data, data_size, BODY_SIZE_OFFSET, &body_size) ||
        !jg_read_u64_be(data, data_size, REQUEST_ID_OFFSET, &request_id) ||
        !jg_read_u32_be(data, data_size, RESERVED_OFFSET, &reserved)) {
        return -EPROTO;
    }
    if (version != JG_IPC_VERSION) {
        return -EPROTONOSUPPORT;
    }
    if ((size_t)body_size > JG_IPC_MAX_BODY_SIZE ||
        !jg_size_add(JG_IPC_HEADER_SIZE, (size_t)body_size, &expected_size) ||
        expected_size != data_size) {
        return -EMSGSIZE;
    }

    decoded.kind = (enum jg_ipc_kind)kind;
    decoded.operation = (enum jg_ipc_operation)operation;
    decoded.request_id = request_id;
    decoded.error = (enum jg_ipc_error)error;
    decoded.body = data + JG_IPC_HEADER_SIZE;
    decoded.body_size = (size_t)body_size;
    if (reserved != 0U || validate_message(&decoded) != 0) {
        return -EPROTO;
    }
    *message = decoded;
    return 0;
}
