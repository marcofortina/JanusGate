/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file account_internal.h
 * @brief Internal helpers shared by account storage modules.
 */

#ifndef JANUSGATE_ACCOUNT_INTERNAL_H
#define JANUSGATE_ACCOUNT_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

#include "janusgate/account.h"

/** @brief Validate one conservative ASCII local username. */
bool jg_account_username_valid(const char *username);

/** @brief Convert one persistent role identifier to its public value. */
enum jg_access_role jg_account_role_from_id(sqlite3_int64 role_id);

/** @brief Validate one assignable fixed backend role. */
bool jg_account_role_valid(enum jg_access_role role);

/** @brief Load one user by identifier in the administrative row shape. */
int jg_account_load_user(sqlite3 *handle,
                         uint64_t user_id,
                         struct jg_account_user *user);

/** @brief Load the role union and enabled TOTP state for one user. */
int jg_account_load_identity_authorization(sqlite3 *handle,
                                           uint64_t user_id,
                                           uint32_t *permissions,
                                           bool *totp_enabled);

/** @brief Read current user authorization and enablement. */
int jg_account_load_user_authorization(sqlite3 *handle,
                                       uint64_t user_id,
                                       bool *enabled,
                                       uint32_t *permissions);

/** @brief Return the network-order byte count for a supported address. */
size_t jg_account_address_size(enum jg_policy_address_family family);

/** @brief Validate one optional exact remote-address binding. */
bool jg_account_remote_address_valid(enum jg_policy_address_family family,
                                     const uint8_t *address);

#endif
