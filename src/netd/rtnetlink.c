/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "rtnetlink.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

/** State accumulated while decoding one `RTM_NEWLINK` response. */
struct link_query {
    struct jg_netd_link link;
    bool received;
    int error;
};

/** @brief Bound the wait for one kernel rtnetlink response. */
static int configure_netlink_timeout(struct mnl_socket *socket)
{
    const struct timeval timeout = {
        .tv_sec = 1,
        .tv_usec = 0,
    };

    if (setsockopt(mnl_socket_get_fd(socket), SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0) {
        return -errno;
    }
    return 0;
}

/** @brief Decode nested link-kind attributes. */
static int decode_link_info(const struct nlattr *attribute, void *user_data)
{
    struct link_query *query = user_data;
    const uint16_t type = mnl_attr_get_type(attribute);

    if (mnl_attr_type_valid(attribute, IFLA_INFO_MAX) < 0) {
        return MNL_CB_OK;
    }
    if (type == IFLA_INFO_KIND) {
        if (mnl_attr_validate(attribute, MNL_TYPE_NUL_STRING) < 0) {
            query->error = -EPROTO;
            return MNL_CB_ERROR;
        }
        query->link.bridge = strcmp(mnl_attr_get_str(attribute), "bridge") == 0;
    }
    return MNL_CB_OK;
}

/** @brief Decode relevant top-level link attributes. */
static int decode_link_attribute(const struct nlattr *attribute,
                                 void *user_data)
{
    struct link_query *query = user_data;
    const uint16_t type = mnl_attr_get_type(attribute);

    if (mnl_attr_type_valid(attribute, IFLA_MAX) < 0) {
        return MNL_CB_OK;
    }
    if (type == IFLA_MTU || type == IFLA_MASTER) {
        if (mnl_attr_validate(attribute, MNL_TYPE_U32) < 0) {
            query->error = -EPROTO;
            return MNL_CB_ERROR;
        }
        if (type == IFLA_MTU) {
            query->link.mtu = mnl_attr_get_u32(attribute);
        } else {
            query->link.master_index = mnl_attr_get_u32(attribute);
        }
    } else if (type == IFLA_IFALIAS) {
        if (mnl_attr_validate(attribute, MNL_TYPE_NUL_STRING) < 0) {
            query->error = -EPROTO;
            return MNL_CB_ERROR;
        }
        query->link.owned =
            strcmp(mnl_attr_get_str(attribute), JG_NETD_BRIDGE_ALIAS) == 0;
    } else if (type == IFLA_LINKINFO &&
               mnl_attr_parse_nested(attribute, decode_link_info, query) < 0) {
        if (query->error == 0) {
            query->error = -EPROTO;
        }
        return MNL_CB_ERROR;
    }
    return MNL_CB_OK;
}

/** @brief Decode the single link message matching one query. */
static int decode_link_message(const struct nlmsghdr *header, void *user_data)
{
    struct link_query *query = user_data;
    const struct ifinfomsg *interface = mnl_nlmsg_get_payload(header);

    if (header->nlmsg_type != RTM_NEWLINK || interface->ifi_index <= 0) {
        query->error = -EPROTO;
        return MNL_CB_ERROR;
    }
    query->link.index = (uint32_t)interface->ifi_index;
    if (mnl_attr_parse(header, (unsigned int)sizeof(*interface),
                       decode_link_attribute, query) < 0) {
        if (query->error == 0) {
            query->error = -EPROTO;
        }
        return MNL_CB_ERROR;
    }
    if (query->link.mtu == 0U) {
        query->error = -EPROTO;
        return MNL_CB_ERROR;
    }
    query->received = true;
    return MNL_CB_STOP;
}

/** @brief Exchange one link query over a short-lived rtnetlink socket. */
static int query_link_index(uint32_t interface_index, struct jg_netd_link *link)
{
    const unsigned int sequence = 1U;
    const size_t buffer_size = (size_t)MNL_SOCKET_BUFFER_SIZE;
    uint8_t *buffer = NULL;
    struct link_query query = {0};
    struct mnl_socket *socket = NULL;
    struct nlmsghdr *header = NULL;
    struct ifinfomsg *interface = NULL;
    unsigned int port_id = 0U;
    ssize_t received = 0;
    int callback = MNL_CB_OK;
    int result = 0;

    if (interface_index > (uint32_t)INT_MAX) {
        return -ERANGE;
    }
    buffer = calloc(buffer_size, 1U);
    if (buffer == NULL) {
        return -ENOMEM;
    }
    header = mnl_nlmsg_put_header(buffer);
    header->nlmsg_type = RTM_GETLINK;
    header->nlmsg_flags = NLM_F_REQUEST;
    header->nlmsg_seq = sequence;
    interface = mnl_nlmsg_put_extra_header(header, sizeof(*interface));
    interface->ifi_family = AF_UNSPEC;
    interface->ifi_index = (int)interface_index;

    socket = mnl_socket_open(NETLINK_ROUTE);
    if (socket == NULL) {
        result = -errno;
    }
    if (result == 0) {
        result = configure_netlink_timeout(socket);
    }
    if (result == 0 && mnl_socket_bind(socket, 0U, MNL_SOCKET_AUTOPID) < 0) {
        result = -errno;
    }
    if (result == 0) {
        port_id = mnl_socket_get_portid(socket);
        if (mnl_socket_sendto(socket, header, header->nlmsg_len) < 0) {
            result = -errno;
        }
    }
    if (result == 0) {
        received = mnl_socket_recvfrom(socket, buffer, buffer_size);
        if (received < 0) {
            result = -errno;
        }
    }
    if (result == 0) {
        callback = mnl_cb_run(buffer, (size_t)received, sequence, port_id,
                              decode_link_message, &query);
        if (callback < 0) {
            result = query.error != 0 ? query.error : -errno;
        } else if (!query.received) {
            result = -ENODEV;
        }
    }
    if (socket != NULL) {
        (void)mnl_socket_close(socket);
    }
    free(buffer);
    if (result == 0) {
        *link = query.link;
    }
    return result;
}

/** @brief Query one named link through rtnetlink. */
int jg_netd_query_link(const char *name, struct jg_netd_link *link)
{
    unsigned int interface_index = 0U;

    if (name == NULL || link == NULL) {
        return -EINVAL;
    }
    errno = 0;
    interface_index = if_nametoindex(name);
    if (interface_index == 0U) {
        return errno == 0 ? -ENODEV : -errno;
    }
    return query_link_index((uint32_t)interface_index, link);
}

/** @brief Validate proposed topology and MTU against effective links. */
int jg_netd_validate_live_config(const struct jg_network_config *config,
                                 uint32_t *effective_mtu)
{
    struct jg_netd_link bridge = {0};
    struct jg_netd_link ingress = {0};
    struct jg_netd_link egress = {0};
    struct jg_netd_link management = {0};
    bool bridge_exists = false;
    uint32_t safe_mtu = 0U;
    int result = jg_network_config_validate(config);

    if (result == 0) {
        result = jg_netd_query_link(config->ingress, &ingress);
    }
    if (result == 0) {
        result = jg_netd_query_link(config->egress, &egress);
    }
    if (result == 0) {
        result = jg_netd_query_link(config->management, &management);
    }
    if (result == 0) {
        result = jg_netd_query_link(config->bridge, &bridge);
        if (result == 0) {
            bridge_exists = true;
            if (!bridge.bridge || !bridge.owned) {
                result = -EEXIST;
            }
        } else if (result == -ENODEV) {
            result = 0;
        }
    }
    if (result == 0 &&
        ((ingress.master_index != 0U &&
          (!bridge_exists || ingress.master_index != bridge.index)) ||
         (egress.master_index != 0U &&
          (!bridge_exists || egress.master_index != bridge.index)))) {
        result = -EBUSY;
    }
    if (result == 0 && bridge_exists &&
        management.master_index == bridge.index) {
        result = -EINVAL;
    }
    if (result == 0) {
        safe_mtu = ingress.mtu < egress.mtu ? ingress.mtu : egress.mtu;
        if (safe_mtu < 1280U ||
            (config->bridge_mtu != 0U && config->bridge_mtu > safe_mtu)) {
            result = -ERANGE;
        } else if (config->bridge_mtu != 0U) {
            safe_mtu = config->bridge_mtu;
        }
    }
    if (result == 0 && effective_mtu != NULL) {
        *effective_mtu = safe_mtu;
    }
    return result;
}
