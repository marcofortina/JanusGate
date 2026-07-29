/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "nftables.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/** Fixed PF anchor exclusively managed by JanusGate. */
#define JG_NETD_PF_ANCHOR "janusgate"

/** @brief Validate the packet-filter capabilities exposed by OpenBSD. */
static int validate_pf_config(const struct jg_network_config *config)
{
    int result = jg_network_config_validate(config);

    if (result != 0) {
        return result;
    }
    return config->queue_count == 1U &&
                   config->failure_mode == JG_NETWORK_FAIL_CLOSED &&
                   !config->queue_cpu_fanout && !config->multicast_snooping
               ? 0
               : -ENOTSUP;
}

/** @brief Write one complete buffer while preserving the first error. */
static int send_all(int descriptor, const char *data, size_t data_size)
{
    size_t written = 0U;

    while (written < data_size) {
        const ssize_t result =
            send(descriptor, data + written, data_size - written, MSG_NOSIGNAL);

        if (result > 0) {
            written += (size_t)result;
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            return result == 0 ? -EIO : -errno;
        }
    }
    return 0;
}

/** @brief Wait for one fixed child and require successful termination. */
static int wait_success(pid_t child)
{
    int status = 0;
    pid_t waited = -1;

    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        return -errno;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -EIO;
}

/** @brief Load one complete ruleset into the fixed PF anchor. */
static int load_anchor(const char *rules)
{
    int input[2U] = {-1, -1};
    pid_t child = -1;
    int result = 0;

    if (rules == NULL) {
        return -EINVAL;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, input) != 0) {
        return -errno;
    }
    child = fork();
    if (child < 0) {
        result = -errno;
    } else if (child == 0) {
        if (dup2(input[0U], STDIN_FILENO) < 0) {
            _exit(126);
        }
        (void)close(input[0U]);
        (void)close(input[1U]);
        execl("/sbin/pfctl", "pfctl", "-a", JG_NETD_PF_ANCHOR, "-f", "-",
              (char *)NULL);
        _exit(127);
    }
    (void)close(input[0U]);
    if (child > 0) {
        result = send_all(input[1U], rules, strlen(rules));
    }
    (void)close(input[1U]);
    if (child > 0) {
        const int wait_result = wait_success(child);

        if (result == 0) {
            result = wait_result;
        }
    }
    return result;
}

/** @brief Flush every rule and object inside the fixed PF anchor. */
static int flush_anchor(void)
{
    pid_t child = fork();

    if (child < 0) {
        return -errno;
    }
    if (child == 0) {
        execl("/sbin/pfctl", "pfctl", "-a", JG_NETD_PF_ANCHOR, "-F", "all",
              (char *)NULL);
        _exit(127);
    }
    return wait_success(child);
}

/** @brief Generate one complete bounded PF anchor ruleset. */
int jg_netd_build_nft_rules(const struct jg_network_config *config,
                            bool replace_owned,
                            char *output,
                            size_t output_size)
{
    int written = 0;
    int result = 0;

    (void)replace_owned;
    if (output == NULL) {
        return -EINVAL;
    }
    result = validate_pf_config(config);
    if (result != 0) {
        return result;
    }
    written =
        snprintf(output, output_size,
                 "pass in quick on %s inet proto { tcp udp } from any to any "
                 "port { 53 443 853 } no state divert-packet port %u\n"
                 "pass in quick on %s inet6 proto { tcp udp } from any to any "
                 "port { 53 443 853 } no state divert-packet port %u\n",
                 config->ingress, (unsigned)config->queue_first,
                 config->ingress, (unsigned)config->queue_first);
    return written < 0 || (size_t)written >= output_size ? -ENOSPC : 0;
}

/** @brief Atomically replace the fixed PF anchor contents. */
int jg_netd_apply_nft_rules(const struct jg_network_config *config)
{
    char rules[JG_NETD_NFT_RULESET_MAX];
    int result = jg_netd_build_nft_rules(config, true, rules, sizeof(rules));

    return result == 0 ? load_anchor(rules) : result;
}

/** @brief Remove all state from the fixed PF anchor. */
int jg_netd_remove_nft_rules(void)
{
    return flush_anchor();
}
