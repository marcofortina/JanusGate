/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "rtnetlink.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

/** Ample fixed request capacity for the bounded attributes emitted here. */
#define JG_RTNL_REQUEST_CAPACITY 1024U

/** Aligned storage for one bounded rtnetlink mutation request. */
union request_buffer {
    struct nlmsghdr alignment;
    uint8_t data[JG_RTNL_REQUEST_CAPACITY];
};

/** Short-lived serialized rtnetlink mutation channel. */
struct rtnl_connection {
    struct mnl_socket *socket;
    uint8_t *response;
    size_t response_size;
    unsigned int port_id;
    unsigned int sequence;
};

/** @brief Open one bounded rtnetlink mutation channel. */
static int open_connection(struct rtnl_connection *connection)
{
    const struct timeval timeout = {
        .tv_sec = 2,
        .tv_usec = 0,
    };
    int result = 0;

    (void)memset(connection, 0, sizeof(*connection));
    connection->response_size = (size_t)MNL_SOCKET_BUFFER_SIZE;
    connection->response = calloc(connection->response_size, 1U);
    if (connection->response == NULL) {
        return -ENOMEM;
    }
    connection->socket = mnl_socket_open(NETLINK_ROUTE);
    if (connection->socket == NULL) {
        result = -errno;
    }
    if (result == 0 &&
        setsockopt(mnl_socket_get_fd(connection->socket), SOL_SOCKET,
                   SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        result = -errno;
    }
    if (result == 0 &&
        mnl_socket_bind(connection->socket, 0U, MNL_SOCKET_AUTOPID) < 0) {
        result = -errno;
    }
    if (result == 0) {
        connection->port_id = mnl_socket_get_portid(connection->socket);
    } else {
        if (connection->socket != NULL) {
            (void)mnl_socket_close(connection->socket);
        }
        free(connection->response);
        (void)memset(connection, 0, sizeof(*connection));
    }
    return result;
}

/** @brief Close one rtnetlink mutation channel. */
static void close_connection(struct rtnl_connection *connection)
{
    if (connection->socket != NULL) {
        (void)mnl_socket_close(connection->socket);
    }
    free(connection->response);
    (void)memset(connection, 0, sizeof(*connection));
}

/** @brief Send one mutation and consume its correlated kernel ACK. */
static int execute_request(struct rtnl_connection *connection,
                           struct nlmsghdr *request)
{
    int callback = MNL_CB_OK;
    ssize_t received = 0;

    ++connection->sequence;
    if (connection->sequence == 0U) {
        ++connection->sequence;
    }
    request->nlmsg_seq = connection->sequence;
    if (mnl_socket_sendto(connection->socket, request, request->nlmsg_len) <
        0) {
        return -errno;
    }
    while (callback > MNL_CB_STOP) {
        received = mnl_socket_recvfrom(connection->socket, connection->response,
                                       connection->response_size);
        if (received < 0) {
            return -errno;
        }
        callback =
            mnl_cb_run(connection->response, (size_t)received,
                       connection->sequence, connection->port_id, NULL, NULL);
        if (callback < 0) {
            return -errno;
        }
    }
    return 0;
}

/** @brief Start one zeroed link mutation request. */
static struct nlmsghdr *begin_link_request(union request_buffer *buffer,
                                           uint16_t type,
                                           uint16_t flags,
                                           uint32_t interface_index)
{
    struct nlmsghdr *header = NULL;
    struct ifinfomsg *interface = NULL;

    (void)memset(buffer, 0, sizeof(*buffer));
    header = mnl_nlmsg_put_header(buffer->data);
    header->nlmsg_type = type;
    header->nlmsg_flags = (uint16_t)(NLM_F_REQUEST | NLM_F_ACK | flags);
    interface = mnl_nlmsg_put_extra_header(header, sizeof(*interface));
    interface->ifi_family = AF_UNSPEC;
    interface->ifi_index = (int)interface_index;
    return header;
}

/** @brief Create one down, empty, explicitly owned Linux bridge. */
static int create_bridge(struct rtnl_connection *connection,
                         const struct jg_network_config *config)
{
    union request_buffer buffer;
    struct nlmsghdr *header = begin_link_request(
        &buffer, RTM_NEWLINK, (uint16_t)(NLM_F_CREATE | NLM_F_EXCL), 0U);
    struct nlattr *link_info = NULL;

    mnl_attr_put_strz(header, IFLA_IFNAME, config->bridge);
    mnl_attr_put_strz(header, IFLA_IFALIAS, JG_NETD_BRIDGE_ALIAS);
    link_info = mnl_attr_nest_start(header, IFLA_LINKINFO);
    mnl_attr_put_strz(header, IFLA_INFO_KIND, "bridge");
    mnl_attr_nest_end(header, link_info);
    return execute_request(connection, header);
}

/** @brief Apply MTU and mutable owned-bridge behavior. */
static int configure_bridge(struct rtnl_connection *connection,
                            uint32_t bridge_index,
                            uint32_t mtu,
                            bool stp,
                            bool multicast_snooping)
{
    union request_buffer buffer;
    struct nlmsghdr *header =
        begin_link_request(&buffer, RTM_NEWLINK, 0U, bridge_index);
    struct nlattr *link_info = NULL;
    struct nlattr *link_data = NULL;

    mnl_attr_put_u32(header, IFLA_MTU, mtu);
    mnl_attr_put_strz(header, IFLA_IFALIAS, JG_NETD_BRIDGE_ALIAS);
    link_info = mnl_attr_nest_start(header, IFLA_LINKINFO);
    mnl_attr_put_strz(header, IFLA_INFO_KIND, "bridge");
    link_data = mnl_attr_nest_start(header, IFLA_INFO_DATA);
    mnl_attr_put_u32(header, IFLA_BR_STP_STATE, stp ? 1U : 0U);
    mnl_attr_put_u8(header, IFLA_BR_MCAST_SNOOPING,
                    multicast_snooping ? 1U : 0U);
    mnl_attr_nest_end(header, link_data);
    mnl_attr_nest_end(header, link_info);
    return execute_request(connection, header);
}

/** @brief Attach or detach one link from a bridge master. */
static int set_master(struct rtnl_connection *connection,
                      uint32_t interface_index,
                      uint32_t master_index)
{
    union request_buffer buffer;
    struct nlmsghdr *header =
        begin_link_request(&buffer, RTM_NEWLINK, 0U, interface_index);

    mnl_attr_put_u32(header, IFLA_MASTER, master_index);
    return execute_request(connection, header);
}

/** @brief Change only the administrative UP flag of one link. */
static int set_link_up(struct rtnl_connection *connection,
                       uint32_t interface_index,
                       bool up)
{
    union request_buffer buffer;
    struct nlmsghdr *header =
        begin_link_request(&buffer, RTM_NEWLINK, 0U, interface_index);
    struct ifinfomsg *interface = mnl_nlmsg_get_payload(header);

    interface->ifi_change = IFF_UP;
    interface->ifi_flags = up ? IFF_UP : 0U;
    return execute_request(connection, header);
}

/** @brief Delete one link by kernel interface index. */
static int delete_link(struct rtnl_connection *connection,
                       uint32_t interface_index)
{
    union request_buffer buffer;
    struct nlmsghdr *header =
        begin_link_request(&buffer, RTM_DELLINK, 0U, interface_index);

    return execute_request(connection, header);
}

/** @brief Capture all state required for complete bridge rollback. */
static int capture_snapshot(const struct jg_network_config *config,
                            struct jg_netd_bridge_checkpoint *snapshot)
{
    int result = jg_netd_validate_live_config(config, &snapshot->effective_mtu);

    if (result == 0) {
        result = jg_netd_query_link(config->ingress, &snapshot->ingress);
    }
    if (result == 0) {
        result = jg_netd_query_link(config->egress, &snapshot->egress);
    }
    if (result == 0) {
        result = jg_netd_query_link(config->bridge, &snapshot->bridge);
        if (result == 0) {
            snapshot->bridge_existed = true;
        } else if (result == -ENODEV) {
            result = 0;
        }
    }
    return result;
}

/** @brief Retain the first rollback failure while continuing restoration. */
static void retain_failure(int operation_result, int *rollback_result)
{
    if (operation_result != 0 && *rollback_result == 0) {
        *rollback_result = operation_result;
    }
}

/** @brief Restore captured link ownership, configuration, and state. */
static int rollback_bridge(struct rtnl_connection *connection,
                           const struct jg_netd_bridge_checkpoint *snapshot)
{
    int rollback_result = 0;

    retain_failure(set_master(connection, snapshot->ingress.index,
                              snapshot->ingress.master_index),
                   &rollback_result);
    retain_failure(set_master(connection, snapshot->egress.index,
                              snapshot->egress.master_index),
                   &rollback_result);
    retain_failure(set_link_up(connection, snapshot->ingress.index,
                               (snapshot->ingress.flags & IFF_UP) != 0U),
                   &rollback_result);
    retain_failure(set_link_up(connection, snapshot->egress.index,
                               (snapshot->egress.flags & IFF_UP) != 0U),
                   &rollback_result);
    if (snapshot->bridge_existed) {
        retain_failure(configure_bridge(connection, snapshot->bridge.index,
                                        snapshot->bridge.mtu,
                                        snapshot->bridge.stp,
                                        snapshot->bridge.multicast_snooping),
                       &rollback_result);
        retain_failure(set_link_up(connection, snapshot->bridge.index,
                                   (snapshot->bridge.flags & IFF_UP) != 0U),
                       &rollback_result);
    } else {
        retain_failure(snapshot->bridge_index == 0U
                           ? -ENODEV
                           : delete_link(connection, snapshot->bridge_index),
                       &rollback_result);
    }
    return rollback_result;
}

/** @brief Apply one owned data-bridge transaction with complete rollback. */
int jg_netd_apply_bridge(const struct jg_network_config *config,
                         struct jg_netd_bridge_checkpoint *checkpoint)
{
    struct jg_netd_bridge_checkpoint snapshot = {0};
    struct jg_netd_link effective_bridge = {0};
    struct rtnl_connection connection = {0};
    bool mutation_started = false;
    int rollback_result = 0;
    int result = 0;

    if (checkpoint == NULL) {
        return -EINVAL;
    }
    (void)memset(checkpoint, 0, sizeof(*checkpoint));
    result = capture_snapshot(config, &snapshot);
    if (result == 0) {
        result = open_connection(&connection);
    }
    if (result == 0 && !snapshot.bridge_existed) {
        result = create_bridge(&connection, config);
        mutation_started = result == 0;
    }
    if (result == 0) {
        result = jg_netd_query_link(config->bridge, &effective_bridge);
        if (result == 0) {
            snapshot.bridge_index = effective_bridge.index;
        }
    }
    if (result != 0 && mutation_started && !snapshot.bridge_existed) {
        const unsigned int discovered_index = if_nametoindex(config->bridge);

        if (discovered_index != 0U) {
            snapshot.bridge_index = (uint32_t)discovered_index;
        }
    }
    if (result == 0) {
        mutation_started = true;
        result = configure_bridge(&connection, snapshot.bridge_index,
                                  snapshot.effective_mtu, config->stp,
                                  config->multicast_snooping);
    }
    if (result == 0) {
        result = set_master(&connection, snapshot.ingress.index,
                            snapshot.bridge_index);
    }
    if (result == 0) {
        result = set_master(&connection, snapshot.egress.index,
                            snapshot.bridge_index);
    }
    if (result == 0) {
        result = set_link_up(&connection, snapshot.ingress.index, true);
    }
    if (result == 0) {
        result = set_link_up(&connection, snapshot.egress.index, true);
    }
    if (result == 0) {
        result = set_link_up(&connection, snapshot.bridge_index, true);
    }
    if (result != 0 && mutation_started) {
        rollback_result = rollback_bridge(&connection, &snapshot);
    }
    if (connection.socket != NULL) {
        close_connection(&connection);
    }
    if (result == 0) {
        snapshot.valid = true;
        *checkpoint = snapshot;
    }
    return rollback_result == 0 ? result : -EUCLEAN;
}

/** @brief Restore and consume one prior bridge checkpoint. */
int jg_netd_restore_bridge(struct jg_netd_bridge_checkpoint *checkpoint)
{
    struct rtnl_connection connection = {0};
    int result = 0;

    if (checkpoint == NULL || !checkpoint->valid) {
        return -EINVAL;
    }
    result = open_connection(&connection);
    if (result == 0) {
        result = rollback_bridge(&connection, checkpoint);
    }
    if (connection.socket != NULL) {
        close_connection(&connection);
    }
    if (result == 0) {
        checkpoint->valid = false;
    }
    return result;
}
