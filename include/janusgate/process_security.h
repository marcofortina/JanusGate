/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file process_security.h
 * @brief Process-level privilege and system-call confinement.
 *
 * The functions in this module change process credentials or kernel security
 * state. Callers retain ownership of all arguments. Successful restrictions
 * are irreversible for the lifetime of the process.
 *
 * Calls that change credentials must be externally serialized. System-call
 * restrictions use the native operating-system facility. Errors are returned
 * as negative errno-style values.
 */

#ifndef JANUSGATE_PROCESS_SECURITY_H
#define JANUSGATE_PROCESS_SECURITY_H

/** Supported long-running service confinement profiles. */
enum jg_process_profile {
    /** Policy daemon startup and packet-processing privileges. */
    JG_PROCESS_PROFILE_DAEMON = 0,
    /** Privileged bridge, packet-filter, and appliance lifecycle helper. */
    JG_PROCESS_PROFILE_NETD,
    /** Unprivileged HTTPS management service. */
    JG_PROCESS_PROFILE_WEB
};

/**
 * @brief Disable privilege growth and secret-bearing core dumps.
 *
 * @return 0 on success.
 * @return A negative errno-style kernel or resource-limit error otherwise.
 *
 * @thread_safety Call before creating worker threads.
 *
 * @side_effects Disables privilege growth and core dumps using the strongest
 * native controls available.
 */
int jg_process_harden(void);

/**
 * @brief Restrict process privileges to one service minimum.
 *
 * @param[in] profile Service profile selecting the required capability set.
 *
 * @return 0 on success.
 * @return -EINVAL for an unknown profile.
 * @return A negative errno-style platform-security error otherwise.
 *
 * @thread_safety Call before starting concurrent work.
 *
 * @side_effects Restricts operating-system privileges where separate
 * capability sets are available.
 */
int jg_process_restrict_capabilities(enum jg_process_profile profile);

/**
 * @brief Permanently assume one dedicated local service identity.
 *
 * Supplementary groups are initialized from the account database before the
 * real, effective, and saved group and user identifiers are replaced. All
 * platform privileges are cleared after the transition.
 *
 * @param[in] user_name Existing non-root account name.
 *
 * @return 0 on success.
 * @return -EINVAL for a null, empty, or root identity.
 * @return -ENOENT when the identity does not exist.
 * @return A negative errno-style account or credential error otherwise.
 *
 * @thread_safety Calls must be externally serialized.
 *
 * @side_effects Irreversibly changes process credentials and privileges.
 */
int jg_process_drop_privileges(const char *user_name);

/**
 * @brief Install one service-specific native system-call allowlist.
 *
 * @param[in] profile Service profile selecting additional allowed calls.
 *
 * @return 0 on success.
 * @return -EINVAL for an unknown profile.
 * @return A negative errno-style platform-security error otherwise.
 *
 * @thread_safety Apply after starting service threads; the native restriction
 * covers the process.
 *
 * @side_effects Permanently rejects calls outside the selected allowlist.
 */
int jg_process_apply_system_call_filter(enum jg_process_profile profile);

#endif
