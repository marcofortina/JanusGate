/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management.h
 * @brief Serialized management API processing inside the policy daemon.
 */

#ifndef JANUSGATE_DAEMON_MANAGEMENT_H
#define JANUSGATE_DAEMON_MANAGEMENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/auth.h"
#include "janusgate/database.h"

/** Opaque owner of management authentication state. */
struct jg_management;

/** Packet runtime borrowed for status and operational actions. */
struct jg_daemon_runtime;

/** Deferred host lifecycle action accepted by the management API. */
enum jg_system_action {
    /** No lifecycle action is pending. */
    JG_SYSTEM_ACTION_NONE = 0,
    /** Restart the main JanusGate service. */
    JG_SYSTEM_ACTION_RESTART,
    /** Reboot the appliance. */
    JG_SYSTEM_ACTION_REBOOT,
    /** Power off the appliance. */
    JG_SYSTEM_ACTION_POWEROFF
};

/**
 * @brief Validate one complete internal management request envelope.
 *
 * This boundary check applies the same size, JSON, field, host, address, and
 * identifier rules used before request authentication and dispatch.
 *
 * @param[in] request_data Exact request JSON bytes.
 * @param[in] request_size Request byte count.
 *
 * @return 0 when the envelope is valid.
 * @return -EINVAL when bytes, JSON structure, or fields are invalid.
 *
 * @thread_safety This function is reentrant.
 */
int jg_management_request_validate(const uint8_t *request_data,
                                   size_t request_size);

/**
 * @brief Create management state around a borrowed database.
 *
 * @param[in,out] database Open database borrowed for the complete lifetime.
 * @param[in] totp_key_path Secure regular file containing exactly one raw
 * TOTP protection key.
 * @param[in] certificate_path Absolute combined server certificate PEM path.
 * @param[in] client_ca_path Absolute trusted client-certificate authority
 * bundle path.
 * @param[in] backup_directory Absolute owner-private archive directory.
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
                         const char *certificate_path,
                         const char *client_ca_path,
                         const char *backup_directory,
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
 * @param[in] request_data Exact request JSON bytes.
 * @param[in] request_size Request byte count.
 * @param[in] local_administrator Whether the caller was authenticated as the
 * privileged local Unix-socket administrator.
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
                          const uint8_t *request_data,
                          size_t request_size,
                          bool local_administrator,
                          uint8_t *response,
                          size_t response_size,
                          size_t *written);

/**
 * @brief Queue a scan of every enabled remote blocklist source currently due.
 *
 * At most one scheduled scan is queued or running. Remote transfers and their
 * database work execute on the bounded management worker so the control
 * server remains available.
 *
 * @param[in,out] management Management state.
 * @param[in] now Current Unix time in seconds.
 * @param[out] attempts Receives zero because execution is asynchronous; null
 * discards it.
 *
 * @return 0 when a scan was queued or one is already pending.
 * @return -EINVAL for invalid arguments.
 * @return -EROFS while consistency recovery suspends management mutations.
 * @return A negative errno-style database, audit, allocation, or publication
 * error otherwise.
 *
 * @thread_safety Calls must be serialized with
 * `jg_management_process()`.
 *
 * @side_effects Schedules bounded HTTPS requests that update persistent source
 * health, append audit events, and may publish new policy generations.
 */
int jg_management_update_due_blocklists(struct jg_management *management,
                                        uint64_t now,
                                        size_t *attempts);

/**
 * @brief Consume one deferred authenticated lifecycle action.
 *
 * @param[in,out] management Management state.
 *
 * @return The pending action, or @ref JG_SYSTEM_ACTION_NONE.
 *
 * @thread_safety Calls must be serialized with
 * `jg_management_process()`.
 *
 * @side_effects Clears the pending action.
 */
enum jg_system_action jg_management_take_system_action(
    struct jg_management *management);

/**
 * @brief Clear secrets and release management state.
 *
 * @param[in,out] management State to release, or null.
 *
 * @thread_safety No concurrent operation may use @p management.
 */
void jg_management_destroy(struct jg_management *management);

#endif
