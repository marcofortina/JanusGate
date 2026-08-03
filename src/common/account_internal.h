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

/** @brief Load the role union and enabled TOTP state for one user. */
int jg_account_load_identity_authorization(sqlite3 *handle,
                                           uint64_t user_id,
                                           uint32_t *permissions,
                                           bool *totp_enabled);

/** @brief Return the network-order byte count for a supported address. */
size_t jg_account_address_size(enum jg_policy_address_family family);

/** @brief Validate one optional exact remote-address binding. */
bool jg_account_remote_address_valid(enum jg_policy_address_family family,
                                     const uint8_t *address);

#endif
