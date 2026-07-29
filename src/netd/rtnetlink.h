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
    /** Current kernel interface flags. */
    uint32_t flags;
    /** Whether the link kind is `bridge`. */
    bool bridge;
    /** Whether the fixed JanusGate ownership alias is present. */
    bool owned;
    /** Current bridge spanning-tree setting. */
    bool stp;
    /** Current bridge multicast-snooping setting. */
    bool multicast_snooping;
    /** Whether both bridge settings were present in the response. */
    bool bridge_settings_valid;
};

/**
 * @brief Complete prior bridge state retained for cross-subsystem rollback.
 */
struct jg_netd_bridge_checkpoint {
    /** Prior bridge state, meaningful when @ref bridge_existed is true. */
    struct jg_netd_link bridge;
    /** Prior ingress-port master and administrative state. */
    struct jg_netd_link ingress;
    /** Prior egress-port master and administrative state. */
    struct jg_netd_link egress;
    /** Bridge index created or reused by the completed transaction. */
    uint32_t bridge_index;
    /** MTU selected during validation. */
    uint32_t effective_mtu;
    /** Whether the owned bridge existed before the transaction. */
    bool bridge_existed;
    /** Whether this checkpoint may be restored exactly once. */
    bool valid;
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
 * @return -EADDRINUSE when a data link has an IP address.
 * @return -ERANGE when port or requested MTU is unsafe.
 * @return A negative errno-style query error otherwise.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Reads effective link state through rtnetlink.
 */
int jg_netd_validate_live_config(const struct jg_network_config *config,
                                 uint32_t *effective_mtu);

/**
 * @brief Apply the owned data bridge as a rollback-safe transaction.
 *
 * The function creates or reconfigures only the allowlisted owned bridge,
 * attaches exactly the two configured data ports, and brings the three links
 * up. Any failed step restores the prior port masters, link state, MTU, and
 * bridge settings.
 *
 * @param[in] config Structurally and operationally valid configuration.
 * @param[out] checkpoint Receives prior state for a later cross-subsystem
 * rollback. It contains no owned resources.
 *
 * @return 0 when the bridge transaction completed.
 * @return -EUCLEAN when an apply error was followed by failed rollback.
 * @return A negative errno-style validation or rtnetlink error otherwise.
 *
 * @thread_safety Calls affecting the same links require external
 * serialization.
 *
 * @side_effects Creates, updates, or restores JanusGate-owned network links.
 */
int jg_netd_apply_bridge(const struct jg_network_config *config,
                         struct jg_netd_bridge_checkpoint *checkpoint);

/**
 * @brief Restore a successfully captured bridge checkpoint.
 *
 * @param[in,out] checkpoint Prior state returned by
 * `jg_netd_apply_bridge()`. It is invalidated after successful restoration.
 *
 * @return 0 when prior state was restored.
 * @return -EINVAL for a null or already consumed checkpoint.
 * @return A negative errno-style rtnetlink error otherwise.
 *
 * @thread_safety Calls affecting the same links require external
 * serialization.
 *
 * @side_effects Restores or removes JanusGate-owned network links.
 */
int jg_netd_restore_bridge(struct jg_netd_bridge_checkpoint *checkpoint);

#endif
