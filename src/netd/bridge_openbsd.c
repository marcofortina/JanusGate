/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "rtnetlink.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ifaddrs.h>
#include <net/if.h>
// clang-format off
#include <netinet/in.h>
#include <netinet/if_ether.h>
// clang-format on

/* OpenBSD bridge declarations require the Ethernet definitions above. */
#include <net/if_bridge.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <unistd.h>

/** @brief Copy one already validated interface name into a kernel request. */
static void copy_name(char destination[IFNAMSIZ], const char *source)
{
    (void)memset(destination, 0, IFNAMSIZ);
    (void)memcpy(destination, source, strlen(source));
}

/** @brief Open one short-lived interface control socket. */
static int open_control_socket(void)
{
    const int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    return descriptor < 0 ? -errno : descriptor;
}

/** @brief Query whether a named interface is one bridge member. */
static int member_flags(int descriptor,
                        const char *bridge,
                        const char *member,
                        uint32_t *flags)
{
    struct ifbreq request;

    (void)memset(&request, 0, sizeof(request));
    copy_name(request.ifbr_name, bridge);
    copy_name(request.ifbr_ifsname, member);
    if (ioctl(descriptor, SIOCBRDGGIFFLGS, &request) != 0) {
        return -errno;
    }
    if (flags != NULL) {
        *flags = request.ifbr_ifsflags;
    }
    return 0;
}

/** @brief Determine one interface's current bridge master by inspection. */
static int find_master(int descriptor,
                       const char *member,
                       uint32_t *master_index)
{
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *current = NULL;
    int result = 0;

    *master_index = 0U;
    if (getifaddrs(&addresses) != 0) {
        return -errno;
    }
    for (current = addresses; current != NULL && result == 0;
         current = current->ifa_next) {
        const char *candidate = current->ifa_name;
        unsigned index = 0U;

        if (candidate == NULL || strcmp(candidate, member) == 0) {
            continue;
        }
        if (member_flags(descriptor, candidate, member, NULL) == 0) {
            index = if_nametoindex(candidate);
            result = index == 0U ? -ENODEV : 0;
            *master_index = (uint32_t)index;
        }
    }
    freeifaddrs(addresses);
    return result;
}

/** @brief Determine whether one data interface owns an IP address. */
static int link_has_address(const char *name, bool *has_address)
{
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *current = NULL;

    *has_address = false;
    if (getifaddrs(&addresses) != 0) {
        return -errno;
    }
    for (current = addresses; current != NULL; current = current->ifa_next) {
        if (current->ifa_name != NULL && current->ifa_addr != NULL &&
            strcmp(current->ifa_name, name) == 0 &&
            (current->ifa_addr->sa_family == AF_INET ||
             current->ifa_addr->sa_family == AF_INET6)) {
            *has_address = true;
            break;
        }
    }
    freeifaddrs(addresses);
    return 0;
}

/** @brief Query one interface description and compare its ownership marker. */
static int query_owned(int descriptor, const char *name, bool *owned)
{
    char description[IFDESCRSIZE] = {0};
    struct ifreq request;

    (void)memset(&request, 0, sizeof(request));
    copy_name(request.ifr_name, name);
    request.ifr_data = description;
    if (ioctl(descriptor, SIOCGIFDESCR, &request) != 0) {
        return -errno;
    }
    *owned = strcmp(description, JG_NETD_BRIDGE_ALIAS) == 0;
    return 0;
}

/** @brief Determine whether one name identifies an OpenBSD bridge clone. */
static bool bridge_name_valid(const char *name)
{
    size_t index = strlen("bridge");

    if (strncmp(name, "bridge", index) != 0 || name[index] == '\0') {
        return false;
    }
    while (name[index] != '\0') {
        if (name[index] < '0' || name[index] > '9') {
            return false;
        }
        ++index;
    }
    return true;
}

/** @brief Determine whether one interface is an OpenBSD bridge. */
static int query_bridge(int descriptor, const char *name, bool *bridge)
{
    struct ifbifconf request;

    (void)memset(&request, 0, sizeof(request));
    copy_name(request.ifbic_name, name);
    if (ioctl(descriptor, SIOCBRDGIFS, &request) == 0) {
        *bridge = true;
        return 0;
    }
    if (errno == ENOTTY) {
        *bridge = false;
        return 0;
    }
    return -errno;
}

/** @brief Query one bounded effective OpenBSD interface state. */
int jg_netd_query_link(const char *name, struct jg_netd_link *link)
{
    struct ifreq request;
    unsigned index = 0U;
    int descriptor = -1;
    int result = 0;

    if (name == NULL || link == NULL || strlen(name) > JG_INTERFACE_NAME_MAX) {
        return -EINVAL;
    }
    (void)memset(link, 0, sizeof(*link));
    index = if_nametoindex(name);
    if (index == 0U) {
        return -ENODEV;
    }
    descriptor = open_control_socket();
    if (descriptor < 0) {
        return descriptor;
    }
    (void)memset(&request, 0, sizeof(request));
    copy_name(request.ifr_name, name);
    if (ioctl(descriptor, SIOCGIFFLAGS, &request) != 0) {
        result = -errno;
    } else {
        link->flags = (uint32_t)(uint16_t)request.ifr_flags;
    }
    (void)memset(&request, 0, sizeof(request));
    copy_name(request.ifr_name, name);
    if (result == 0 && ioctl(descriptor, SIOCGIFMTU, &request) != 0) {
        result = -errno;
    } else if (result == 0 && request.ifr_mtu <= 0) {
        result = -ERANGE;
    } else if (result == 0) {
        link->mtu = (uint32_t)request.ifr_mtu;
    }
    if (result == 0) {
        result = find_master(descriptor, name, &link->master_index);
    }
    if (result == 0) {
        result = query_bridge(descriptor, name, &link->bridge);
    }
    if (result == 0 && link->bridge) {
        result = query_owned(descriptor, name, &link->owned);
        link->bridge_settings_valid = result == 0;
    }
    link->index = (uint32_t)index;
    (void)close(descriptor);
    return result;
}

/** @brief Validate OpenBSD-specific packet queue and bridge capabilities. */
static int validate_platform_options(const struct jg_network_config *config)
{
    if (!bridge_name_valid(config->bridge)) {
        return -EINVAL;
    }
    return config->bridge_mtu == 0U && config->queue_count == 1U &&
                   config->failure_mode == JG_NETWORK_FAIL_CLOSED &&
                   !config->queue_cpu_fanout && !config->multicast_snooping
               ? 0
               : -ENOTSUP;
}

/** @brief Validate a proposed configuration against current OpenBSD links. */
int jg_netd_validate_live_config(const struct jg_network_config *config,
                                 uint32_t *effective_mtu)
{
    struct jg_netd_link bridge = {0};
    struct jg_netd_link ingress = {0};
    struct jg_netd_link egress = {0};
    struct jg_netd_link management = {0};
    bool ingress_addressed = false;
    bool egress_addressed = false;
    uint32_t selected_mtu = 0U;
    int bridge_result = 0;
    int result = jg_network_config_validate(config);

    if (result == 0) {
        result = validate_platform_options(config);
    }
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
        bridge_result = jg_netd_query_link(config->bridge, &bridge);
        if (bridge_result != 0 && bridge_result != -ENODEV) {
            result = bridge_result;
        } else if (bridge_result == 0 && (!bridge.bridge || !bridge.owned)) {
            result = -EEXIST;
        }
    }
    if (result == 0 &&
        ((ingress.master_index != 0U &&
          (bridge_result != 0 || ingress.master_index != bridge.index)) ||
         (egress.master_index != 0U &&
          (bridge_result != 0 || egress.master_index != bridge.index)))) {
        result = -EBUSY;
    }
    if (result == 0 && bridge_result == 0 &&
        management.master_index == bridge.index) {
        result = -EADDRINUSE;
    }
    if (result == 0) {
        result = link_has_address(config->ingress, &ingress_addressed);
    }
    if (result == 0) {
        result = link_has_address(config->egress, &egress_addressed);
    }
    if (result == 0 && (ingress_addressed || egress_addressed)) {
        result = -EADDRINUSE;
    }
    if (result == 0) {
        selected_mtu = ingress.mtu < egress.mtu ? ingress.mtu : egress.mtu;
    }
    if (result == 0 && effective_mtu != NULL) {
        *effective_mtu = selected_mtu;
    }
    return result;
}

/** @brief Change one interface's administrative state without other flags. */
static int set_up(int descriptor, const char *name, bool up)
{
    struct ifreq request;

    (void)memset(&request, 0, sizeof(request));
    copy_name(request.ifr_name, name);
    if (ioctl(descriptor, SIOCGIFFLAGS, &request) != 0) {
        return -errno;
    }
    request.ifr_flags = up ? (short)(request.ifr_flags | IFF_UP)
                           : (short)(request.ifr_flags & (short)~IFF_UP);
    return ioctl(descriptor, SIOCSIFFLAGS, &request) == 0 ? 0 : -errno;
}

/** @brief Set the fixed bridge ownership description. */
static int set_owned(int descriptor, const char *name)
{
    struct ifreq request;
    char description[] = JG_NETD_BRIDGE_ALIAS;

    (void)memset(&request, 0, sizeof(request));
    copy_name(request.ifr_name, name);
    request.ifr_data = description;
    return ioctl(descriptor, SIOCSIFDESCR, &request) == 0 ? 0 : -errno;
}

/** @brief Create or destroy one bridge clone by its validated name. */
static int mutate_bridge(int descriptor,
                         const char *name,
                         unsigned long request)
{
    struct ifreq interface;

    (void)memset(&interface, 0, sizeof(interface));
    copy_name(interface.ifr_name, name);
    return ioctl(descriptor, request, &interface) == 0 ? 0 : -errno;
}

/** @brief Attach or detach one member from one bridge. */
static int mutate_member(int descriptor,
                         const char *bridge,
                         const char *member,
                         unsigned long operation)
{
    struct ifbreq request;

    (void)memset(&request, 0, sizeof(request));
    copy_name(request.ifbr_name, bridge);
    copy_name(request.ifbr_ifsname, member);
    if (ioctl(descriptor, operation, &request) == 0) {
        return 0;
    }
    if (operation == SIOCBRDGADD && errno == EEXIST) {
        return 0;
    }
    if (operation == SIOCBRDGDEL &&
        (errno == ENOENT || errno == ENXIO || errno == ESRCH)) {
        return 0;
    }
    return -errno;
}

/** @brief Enable or disable STP on one existing bridge member. */
static int set_member_stp(int descriptor,
                          const char *bridge,
                          const char *member,
                          bool enabled)
{
    struct ifbreq request;

    (void)memset(&request, 0, sizeof(request));
    copy_name(request.ifbr_name, bridge);
    copy_name(request.ifbr_ifsname, member);
    if (ioctl(descriptor, SIOCBRDGGIFFLGS, &request) != 0) {
        return -errno;
    }
    if (enabled) {
        request.ifbr_ifsflags |= IFBIF_STP;
    } else {
        request.ifbr_ifsflags &= ~(uint32_t)IFBIF_STP;
    }
    return ioctl(descriptor, SIOCBRDGSIFFLGS, &request) == 0 ? 0 : -errno;
}

/** @brief Retain the first rollback failure while continuing restoration. */
static void retain_failure(int operation_result, int *rollback_result)
{
    if (operation_result != 0 && *rollback_result == 0) {
        *rollback_result = operation_result;
    }
}

/** @brief Restore one port's prior bridge membership and state. */
static void restore_port(int descriptor,
                         const char *active_bridge,
                         const char *port,
                         const struct jg_netd_link *prior,
                         int *result)
{
    char prior_bridge[IFNAMSIZ] = {0};

    retain_failure(mutate_member(descriptor, active_bridge, port, SIOCBRDGDEL),
                   result);
    if (prior->master_index != 0U) {
        if (if_indextoname(prior->master_index, prior_bridge) == NULL) {
            retain_failure(-ENODEV, result);
        } else {
            retain_failure(
                mutate_member(descriptor, prior_bridge, port, SIOCBRDGADD),
                result);
        }
    }
    retain_failure(set_up(descriptor, port, (prior->flags & IFF_UP) != 0U),
                   result);
}

/** @brief Restore all link state represented by one bridge checkpoint. */
static int rollback_bridge(int descriptor,
                           const char *bridge_name,
                           const char *ingress_name,
                           const char *egress_name,
                           const struct jg_netd_bridge_checkpoint *snapshot)
{
    int result = 0;

    restore_port(descriptor, bridge_name, ingress_name, &snapshot->ingress,
                 &result);
    restore_port(descriptor, bridge_name, egress_name, &snapshot->egress,
                 &result);
    if (snapshot->bridge_existed) {
        if (snapshot->ingress.master_index == snapshot->bridge.index) {
            retain_failure(set_member_stp(descriptor, bridge_name, ingress_name,
                                          snapshot->ingress.stp),
                           &result);
        }
        if (snapshot->egress.master_index == snapshot->bridge.index) {
            retain_failure(set_member_stp(descriptor, bridge_name, egress_name,
                                          snapshot->egress.stp),
                           &result);
        }
        retain_failure(set_up(descriptor, bridge_name,
                              (snapshot->bridge.flags & IFF_UP) != 0U),
                       &result);
    } else {
        retain_failure(mutate_bridge(descriptor, bridge_name, SIOCIFDESTROY),
                       &result);
    }
    return result;
}

/** @brief Apply one owned OpenBSD data-bridge transaction. */
int jg_netd_apply_bridge(const struct jg_network_config *config,
                         struct jg_netd_bridge_checkpoint *checkpoint)
{
    struct jg_netd_bridge_checkpoint snapshot = {0};
    int descriptor = -1;
    int rollback_result = 0;
    int result = 0;
    bool modified = false;

    if (checkpoint == NULL) {
        return -EINVAL;
    }
    (void)memset(checkpoint, 0, sizeof(*checkpoint));
    result = jg_netd_validate_live_config(config, &snapshot.effective_mtu);
    if (result == 0) {
        result = jg_netd_query_link(config->ingress, &snapshot.ingress);
    }
    if (result == 0) {
        result = jg_netd_query_link(config->egress, &snapshot.egress);
    }
    if (result == 0) {
        result = jg_netd_query_link(config->bridge, &snapshot.bridge);
        if (result == 0) {
            snapshot.bridge_existed = true;
        } else if (result == -ENODEV) {
            result = 0;
        }
    }
    if (result == 0) {
        descriptor = open_control_socket();
        if (descriptor < 0) {
            result = descriptor;
        }
    }
    if (result == 0 && snapshot.bridge_existed &&
        snapshot.ingress.master_index == snapshot.bridge.index) {
        uint32_t flags = 0U;

        result =
            member_flags(descriptor, config->bridge, config->ingress, &flags);
        snapshot.ingress.stp = (flags & IFBIF_STP) != 0U;
    }
    if (result == 0 && snapshot.bridge_existed &&
        snapshot.egress.master_index == snapshot.bridge.index) {
        uint32_t flags = 0U;

        result =
            member_flags(descriptor, config->bridge, config->egress, &flags);
        snapshot.egress.stp = (flags & IFBIF_STP) != 0U;
    }
    if (result == 0 && !snapshot.bridge_existed) {
        result = mutate_bridge(descriptor, config->bridge, SIOCIFCREATE);
        if (result == 0) {
            modified = true;
        }
    }
    if (result == 0) {
        snapshot.bridge_index = snapshot.bridge_existed
                                    ? snapshot.bridge.index
                                    : (uint32_t)if_nametoindex(config->bridge);
        if (snapshot.bridge_index == 0U) {
            result = -ENODEV;
        }
    }
    if (result == 0) {
        result = set_owned(descriptor, config->bridge);
        if (result == 0) {
            modified = true;
        }
    }
    if (result == 0) {
        result = mutate_member(descriptor, config->bridge, config->ingress,
                               SIOCBRDGADD);
    }
    if (result == 0) {
        result = mutate_member(descriptor, config->bridge, config->egress,
                               SIOCBRDGADD);
    }
    if (result == 0) {
        result = set_member_stp(descriptor, config->bridge, config->ingress,
                                config->stp);
    }
    if (result == 0) {
        result = set_member_stp(descriptor, config->bridge, config->egress,
                                config->stp);
    }
    if (result == 0) {
        result = set_up(descriptor, config->ingress, true);
    }
    if (result == 0) {
        result = set_up(descriptor, config->egress, true);
    }
    if (result == 0) {
        result = set_up(descriptor, config->bridge, true);
    }
    if (descriptor >= 0 && result != 0 && modified) {
        rollback_result =
            rollback_bridge(descriptor, config->bridge, config->ingress,
                            config->egress, &snapshot);
    }
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    if (result == 0) {
        snapshot.valid = true;
        *checkpoint = snapshot;
    }
    return rollback_result == 0 ? result : -EIO;
}

/** @brief Restore and consume one prior OpenBSD bridge checkpoint. */
int jg_netd_restore_bridge(struct jg_netd_bridge_checkpoint *checkpoint)
{
    char bridge[IFNAMSIZ] = {0};
    char ingress[IFNAMSIZ] = {0};
    char egress[IFNAMSIZ] = {0};
    int descriptor = -1;
    int result = 0;

    if (checkpoint == NULL || !checkpoint->valid ||
        if_indextoname(checkpoint->bridge_index, bridge) == NULL ||
        if_indextoname(checkpoint->ingress.index, ingress) == NULL ||
        if_indextoname(checkpoint->egress.index, egress) == NULL) {
        return -EINVAL;
    }
    descriptor = open_control_socket();
    if (descriptor < 0) {
        return descriptor;
    }
    result = rollback_bridge(descriptor, bridge, ingress, egress, checkpoint);
    (void)close(descriptor);
    if (result == 0) {
        checkpoint->valid = false;
    }
    return result;
}
