/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file access.h
 * @brief Shared role permissions and canonical API-token scopes.
 *
 * Permission masks are plain values without owned storage. Scope parsing and
 * formatting use a fixed vocabulary and canonical order so every management
 * surface reaches the same backend authorization decision.
 *
 * @thread_safety Every function is reentrant.
 *
 * @error_handling Fallible functions return zero on success and a negative
 * errno-style value for invalid or insufficient input.
 */

#ifndef JANUSGATE_ACCESS_H
#define JANUSGATE_ACCESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Maximum canonical token-scope bytes excluding the null terminator. */
#define JG_ACCESS_SCOPE_TEXT_MAX 192U

/**
 * @brief Fixed backend role assigned to a local identity.
 */
enum jg_access_role {
    /** Invalid or absent role. */
    JG_ACCESS_ROLE_NONE = 0,
    /** Full appliance administration. */
    JG_ACCESS_ROLE_ADMINISTRATOR = 1,
    /** Policy and operational administration without access ownership. */
    JG_ACCESS_ROLE_OPERATOR = 2,
    /** Read-only operational, policy, event, and audit access. */
    JG_ACCESS_ROLE_AUDITOR = 3
};

/**
 * @brief Independently enforceable backend permission.
 */
enum jg_access_permission {
    /** Read appliance status and health. */
    JG_ACCESS_STATUS_READ = 1U << 0U,
    /** Read policy and source configuration. */
    JG_ACCESS_POLICY_READ = 1U << 1U,
    /** Change policy and source configuration. */
    JG_ACCESS_POLICY_WRITE = 1U << 2U,
    /** Read filtering and operational events. */
    JG_ACCESS_EVENTS_READ = 1U << 3U,
    /** Read and export the audit chain. */
    JG_ACCESS_AUDIT_READ = 1U << 4U,
    /** Perform bounded runtime operations such as refresh or reload. */
    JG_ACCESS_OPERATE = 1U << 5U,
    /** Change network configuration. */
    JG_ACCESS_NETWORK_WRITE = 1U << 6U,
    /** Manage users, roles, sessions, and API tokens. */
    JG_ACCESS_ACCESS_WRITE = 1U << 7U,
    /** Manage certificates, mTLS, and security policy. */
    JG_ACCESS_SECURITY_WRITE = 1U << 8U,
    /** Create or restore appliance backups. */
    JG_ACCESS_BACKUPS_WRITE = 1U << 9U,
    /** Restart services, reboot, or shut down the appliance. */
    JG_ACCESS_SYSTEM_WRITE = 1U << 10U,
    /** Read authenticated metrics. */
    JG_ACCESS_METRICS_READ = 1U << 11U
};

/** Bit mask containing every defined backend permission. */
#define JG_ACCESS_PERMISSION_ALL UINT32_C(0x00000fff)

/**
 * @brief Return the complete permission mask assigned to one role.
 *
 * @param[in] role Fixed backend role.
 *
 * @return The role permission mask, or zero for an invalid role.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC uint32_t jg_access_role_permissions(enum jg_access_role role);

/**
 * @brief Parse a comma-separated canonical API-token scope list.
 *
 * Scope names are case-sensitive, must not contain whitespace, and may occur
 * only once. Input order is unrestricted; formatting always restores the
 * canonical order.
 *
 * @param[in] text Nonempty null-terminated scope list.
 * @param[out] permissions Receives the corresponding nonzero permission mask.
 *
 * @return 0 on success.
 * @return -EINVAL for a null, empty, overlong, duplicate, or unknown scope.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_access_scope_parse(const char *text, uint32_t *permissions);

/**
 * @brief Format a nonempty permission mask as canonical token scopes.
 *
 * @param[in] permissions Nonzero mask containing only defined permissions.
 * @param[out] output Destination for the null-terminated scope list.
 * @param[in] output_size Available destination bytes.
 *
 * @return 0 on success.
 * @return -EINVAL for an invalid mask or null output.
 * @return -ENOSPC when @p output is too small.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_access_scope_format(uint32_t permissions,
                                     char *output,
                                     size_t output_size);

/**
 * @brief Determine whether a permission mask authorizes an operation.
 *
 * @param[in] granted Permissions granted by both identity role and token.
 * @param[in] required Nonzero permissions required by an operation.
 *
 * @return `true` only when both masks are valid and every required bit is
 * granted.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC bool jg_access_grants(uint32_t granted, uint32_t required);

#endif
