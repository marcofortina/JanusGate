/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file nftables.h
 * @brief Internal generation and application of owned packet-filter state.
 */

#ifndef JANUSGATE_NETD_NFTABLES_H
#define JANUSGATE_NETD_NFTABLES_H

#include <stdbool.h>
#include <stddef.h>

#include "janusgate/network.h"

/** Fixed bridge-family table owned by JanusGate. */
#define JG_NETD_NFT_TABLE "janusgate"

/** Ownership comment required before an existing table may be changed. */
#define JG_NETD_NFT_COMMENT "JanusGate owned table"

/** Maximum constructed nftables transaction bytes including its terminator. */
#define JG_NETD_NFT_RULESET_MAX 8192U

/**
 * @brief Generate the complete bounded JanusGate packet-filter transaction.
 *
 * Only fixed syntax and validated interface names and queue numbers are
 * emitted. Callers cannot supply statements, object names, or expressions.
 *
 * @param[in] config Validated inline-network configuration.
 * @param[in] replace_owned Whether to flush a verified existing owned table.
 * @param[out] output Destination receiving a null-terminated transaction.
 * @param[in] output_size Available destination bytes.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or configuration.
 * @return -ERANGE for an unsafe configuration value.
 * @return -ENOSPC when @p output is too small.
 *
 * @thread_safety This function is reentrant.
 */
int jg_netd_build_nft_rules(const struct jg_network_config *config,
                            bool replace_owned,
                            char *output,
                            size_t output_size);

/**
 * @brief Create or replace the owned native packet-filter state.
 *
 * An existing table is changed only when its table-level ownership comment
 * matches @ref JG_NETD_NFT_COMMENT. No unrelated table is flushed or deleted.
 *
 * @param[in] config Validated inline-network configuration.
 *
 * @return 0 on successful atomic replacement.
 * @return -EEXIST when the fixed table name is not owned by JanusGate.
 * @return A negative errno-style validation or packet-filter error otherwise.
 *
 * @thread_safety Calls require external serialization with other packet-filter
 * management.
 *
 * @side_effects Replaces only JanusGate-owned packet-filter state.
 */
int jg_netd_apply_nft_rules(const struct jg_network_config *config);

/**
 * @brief Remove owned native packet-filter state when present.
 *
 * @return 0 when the table is absent or removed.
 * @return -EEXIST when the fixed table name is not owned by JanusGate.
 * @return A negative errno-style packet-filter error otherwise.
 *
 * @thread_safety Calls require external serialization with other packet-filter
 * management.
 *
 * @side_effects Deletes only verified JanusGate-owned packet-filter state.
 */
int jg_netd_remove_nft_rules(void);

#endif
