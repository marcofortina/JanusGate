/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file diagnostic_bundle.h
 * @brief Sanitized appliance diagnostic bundle collection.
 */

#ifndef JANUSGATE_DAEMON_DIAGNOSTIC_BUNDLE_H
#define JANUSGATE_DAEMON_DIAGNOSTIC_BUNDLE_H

#include <stddef.h>
#include <stdint.h>

#include "daemon_runtime.h"
#include "janusgate/database.h"

/**
 * @brief Collect one allowlisted in-memory diagnostic archive.
 *
 * @param[in,out] database Open persistent database.
 * @param[in] runtime Running packet runtime.
 * @param[in] created_at Nonzero Unix creation time.
 * @param[out] archive Receives the owned gzip-compressed tar archive.
 * @param[out] archive_size Receives the compressed byte count.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments.
 * @return A negative errno-style collection, serialization, allocation, or
 * archive error otherwise.
 *
 * @thread_safety Calls must be serialized with other management operations.
 *
 * @side_effects Reads fixed operating-system status sources and runs a
 * database integrity check without changing persistent or runtime state.
 */
int jg_diagnostic_bundle_create(struct jg_database *database,
                                const struct jg_daemon_runtime *runtime,
                                uint64_t created_at,
                                uint8_t **archive,
                                size_t *archive_size);

#endif
