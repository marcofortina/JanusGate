/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management.h
 * @brief Serialized management API processing inside the policy daemon.
 */

#ifndef JANUSGATE_DAEMON_MANAGEMENT_H
#define JANUSGATE_DAEMON_MANAGEMENT_H

#include <stddef.h>
#include <stdint.h>

#include "janusgate/auth.h"
#include "janusgate/database.h"

/** Opaque owner of management authentication state. */
struct jg_management;

/** Packet runtime borrowed for status and operational actions. */
struct jg_daemon_runtime;

/**
 * @brief Create management state around a borrowed database.
 *
 * @param[in,out] database Open database borrowed for the complete lifetime.
 * @param[in] totp_key_path Secure regular file containing exactly one raw
 * TOTP protection key.
 * @param[in] runtime Packet runtime borrowed for the complete lifetime; null
 * is accepted by isolated authentication tests.
 * @param[out] management Receives the owned management state.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return -EACCES for insecure key ownership or permissions.
 * @return A negative errno-style file or allocation error otherwise.
 *
 * @thread_safety The caller must serialize all calls using @p database.
 */
int jg_management_create(struct jg_database *database,
                         const char *totp_key_path,
                         struct jg_daemon_runtime *runtime,
                         struct jg_management **management);

/**
 * @brief Process one bounded canonical management request.
 *
 * The request and response use the internal JSON envelope documented with the
 * local-control protocol. Authentication secrets remain inside the local
 * trusted boundary.
 *
 * @param[in,out] management Management state.
 * @param[in] request Exact request JSON bytes.
 * @param[in] request_size Request byte count.
 * @param[out] response Destination for the response JSON.
 * @param[in] response_size Available response bytes.
 * @param[out] written Receives the exact response byte count.
 *
 * @return 0 when an HTTP-level response was encoded.
 * @return -EINVAL for invalid pointers.
 * @return -ENOSPC when response storage is insufficient.
 * @return A negative errno-style clock or serialization error otherwise.
 *
 * @thread_safety Calls must be externally serialized.
 */
int jg_management_process(struct jg_management *management,
                          const uint8_t *request,
                          size_t request_size,
                          uint8_t *response,
                          size_t response_size,
                          size_t *written);

/**
 * @brief Clear secrets and release management state.
 *
 * @param[in,out] management State to release, or null.
 *
 * @thread_safety No concurrent operation may use @p management.
 */
void jg_management_destroy(struct jg_management *management);

#endif
