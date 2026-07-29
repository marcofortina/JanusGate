/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file ipc.h
 * @brief Architecture-independent framing for local control protocols.
 *
 * Messages use a fixed network-byte-order header followed by one typed,
 * operation-specific body. Encoding copies caller-owned body bytes into the
 * destination. Decoding returns a body view borrowed from the input buffer.
 *
 * @thread_safety Every function is reentrant and accesses only caller-owned
 * storage.
 *
 * @error_handling Functions return zero on success and negative errno-style
 * values for invalid arguments, unsupported versions, malformed frames, and
 * insufficient storage.
 */

#ifndef JANUSGATE_IPC_H
#define JANUSGATE_IPC_H

#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Current local-control protocol version. */
#define JG_IPC_VERSION 1U

/** Fixed encoded header bytes. */
#define JG_IPC_HEADER_SIZE 28U

/** Maximum operation-specific body bytes. */
#define JG_IPC_MAX_BODY_SIZE 65536U

/** Maximum complete encoded message bytes. */
#define JG_IPC_MAX_MESSAGE_SIZE (JG_IPC_HEADER_SIZE + JG_IPC_MAX_BODY_SIZE)

/** Directory containing JanusGate local-control sockets. */
#if defined(__OpenBSD__)
#define JG_RUNTIME_DIRECTORY "/var/run/janusgate"
#else
#define JG_RUNTIME_DIRECTORY "/run/janusgate"
#endif

/** Policy-daemon-owned directory containing its control socket. */
#define JG_CONTROL_RUNTIME_DIRECTORY JG_RUNTIME_DIRECTORY "/control"

/** Fixed local socket exposed by the privileged network helper. */
#define JG_NETD_SOCKET_PATH JG_RUNTIME_DIRECTORY "/netd.sock"

/** Fixed local socket exposed by the main policy daemon. */
#define JG_CONTROL_SOCKET_PATH JG_CONTROL_RUNTIME_DIRECTORY "/control.sock"

/**
 * @brief Direction and semantics of one protocol message.
 */
enum jg_ipc_kind {
    /** Client request requiring one correlated response. */
    JG_IPC_REQUEST = 1,
    /** Server response carrying the same request identifier. */
    JG_IPC_RESPONSE = 2
};

/**
 * @brief Allowlisted operations understood by the privileged network helper.
 */
enum jg_ipc_operation {
    /** Verify protocol liveness without changing state. */
    JG_IPC_PING = 1,
    /** Validate a complete proposed network configuration. */
    JG_IPC_NETWORK_VALIDATE = 2,
    /** Apply a previously validated network configuration transactionally. */
    JG_IPC_NETWORK_APPLY = 3,
    /** Confirm a pending management-network transaction. */
    JG_IPC_NETWORK_CONFIRM = 4,
    /** Restore the latest pending network checkpoint. */
    JG_IPC_NETWORK_ROLLBACK = 5,
    /** Return the effective JanusGate-owned network state. */
    JG_IPC_NETWORK_STATE = 6,
    /** Remove only JanusGate-owned runtime network objects. */
    JG_IPC_NETWORK_REMOVE = 7,
    /** Reload persistent policy into a new immutable daemon snapshot. */
    JG_IPC_POLICY_RELOAD = 8,
    /** Return one aggregate daemon status and counter snapshot. */
    JG_IPC_DAEMON_STATUS = 9,
    /** Process one authenticated management API request. */
    JG_IPC_MANAGEMENT_REQUEST = 10,
    /** Reboot the appliance after an authenticated management request. */
    JG_IPC_SYSTEM_REBOOT = 11,
    /** Power off the appliance after an authenticated management request. */
    JG_IPC_SYSTEM_POWEROFF = 12
};

/**
 * @brief Stable protocol-level response errors.
 */
enum jg_ipc_error {
    /** Operation completed successfully. */
    JG_IPC_ERROR_NONE = 0,
    /** Frame or typed body is malformed. */
    JG_IPC_ERROR_MALFORMED = 1,
    /** Requested protocol version is unsupported. */
    JG_IPC_ERROR_VERSION = 2,
    /** Peer credentials are not authorized. */
    JG_IPC_ERROR_UNAUTHORIZED = 3,
    /** Operation is not implemented by this endpoint. */
    JG_IPC_ERROR_UNSUPPORTED = 4,
    /** Proposed state violates a configuration invariant. */
    JG_IPC_ERROR_INVALID = 5,
    /** Current state conflicts with the requested transaction. */
    JG_IPC_ERROR_CONFLICT = 6,
    /** Operation exceeded its configured deadline. */
    JG_IPC_ERROR_TIMEOUT = 7,
    /** A required operating-system operation failed. */
    JG_IPC_ERROR_SYSTEM = 8
};

/**
 * @brief Host-order view of one complete local-control message.
 */
struct jg_ipc_message {
    /** Request or response direction. */
    enum jg_ipc_kind kind;
    /** Allowlisted operation code. */
    enum jg_ipc_operation operation;
    /** Nonzero identifier copied from request to response. */
    uint64_t request_id;
    /** Protocol result; requests must use @ref JG_IPC_ERROR_NONE. */
    enum jg_ipc_error error;
    /** Operation-specific body, borrowed by decoded messages. */
    const uint8_t *body;
    /** Body bytes in `[0, JG_IPC_MAX_BODY_SIZE]`. */
    size_t body_size;
};

/**
 * @brief Encode one validated local-control message.
 *
 * The wire representation includes the current protocol version, fixed magic,
 * exact body length, and a zero reserved field. The caller retains ownership
 * of @p message and its body.
 *
 * @param[in] message Complete host-order message.
 * @param[out] output Destination for the encoded frame.
 * @param[in] output_size Available destination bytes.
 * @param[out] encoded_size Receives the complete encoded byte count.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid pointers, identifiers, enum values, or bodies.
 * @return -EMSGSIZE when the body exceeds @ref JG_IPC_MAX_BODY_SIZE.
 * @return -ENOSPC when @p output is too small.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Writes exactly the reported bytes to @p output on success.
 */
JG_PUBLIC int jg_ipc_encode(const struct jg_ipc_message *message,
                            uint8_t *output,
                            size_t output_size,
                            size_t *encoded_size);

/**
 * @brief Decode and validate one exact local-control frame.
 *
 * Unknown operations, nonzero reserved data, trailing bytes, and request
 * frames carrying a response error are rejected. On success, @p message
 * borrows its body from @p data and remains valid only while that buffer is
 * unchanged.
 *
 * @param[in] data Exact complete encoded frame.
 * @param[in] data_size Number of bytes available in @p data.
 * @param[out] message Receives the decoded host-order view.
 *
 * @return 0 on success.
 * @return -EINVAL for null arguments.
 * @return -EPROTONOSUPPORT for a non-current protocol version.
 * @return -EPROTO for invalid magic, enums, reserved data, or relationships.
 * @return -EMSGSIZE for a truncated, oversized, or trailing frame.
 *
 * @thread_safety This function is reentrant. Concurrent readers may decode
 * the same immutable input buffer.
 */
JG_PUBLIC int jg_ipc_decode(const uint8_t *data,
                            size_t data_size,
                            struct jg_ipc_message *message);

#endif
