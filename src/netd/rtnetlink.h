/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file rtnetlink.h
 * @brief Internal rtnetlink inspection for validated network transactions.
 */

#ifndef JANUSGATE_NETD_RTNETLINK_H
#define JANUSGATE_NETD_RTNETLINK_H

#include <stdbool.h>
#include <stdint.h>

#include "janusgate/network.h"

/** Stable alias marking the bridge as owned by JanusGate. */
#define JG_NETD_BRIDGE_ALIAS "JanusGate data bridge"

/**
 * @brief Bounded effective state of one Linux network link.
 */
struct jg_netd_link {
    /** Kernel interface index. */
    uint32_t index;
    /** Kernel interface index of the current master, or zero. */
    uint32_t master_index;
    /** Current link MTU. */
    uint32_t mtu;
    /** Whether the link kind is `bridge`. */
    bool bridge;
    /** Whether the fixed JanusGate ownership alias is present. */
    bool owned;
};

/**
 * @brief Query one allowlisted interface through rtnetlink.
 *
 * @param[in] name Validated null-terminated interface name.
 * @param[out] link Receives current kernel link state.
 *
 * @return 0 on success.
 * @return -ENODEV when the interface does not exist.
 * @return -EPROTO for a malformed kernel response.
 * @return A negative errno-style netlink error otherwise.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Opens a short-lived `NETLINK_ROUTE` socket.
 */
int jg_netd_query_link(const char *name, struct jg_netd_link *link);

/**
 * @brief Validate a proposed configuration against current kernel links.
 *
 * Existing data ports may be free or attached to the configured owned bridge;
 * foreign masters are rejected. An explicit bridge MTU cannot exceed either
 * data-port MTU. The management interface may never be attached to the data
 * bridge.
 *
 * @param[in] config Structurally validated network configuration.
 * @param[out] effective_mtu Receives the explicit MTU or safe port minimum;
 * null discards it.
 *
 * @return 0 when activation is safe.
 * @return -ENODEV when a required physical interface is absent.
 * @return -EEXIST when the bridge name belongs to another link.
 * @return -EBUSY when a data port belongs to another master.
 * @return -ERANGE when port or requested MTU is unsafe.
 * @return A negative errno-style query error otherwise.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Reads effective link state through rtnetlink.
 */
int jg_netd_validate_live_config(const struct jg_network_config *config,
                                 uint32_t *effective_mtu);

#endif
