/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "control_protocol.h"
#include "janusgate/ipc_client.h"
#include "janusgate/version.h"

/** @brief Print the stable command synopsis. */
static void print_usage(FILE *output)
{
    (void)fprintf(output, "usage: janusgatectl [--json] ping\n"
                          "       janusgatectl [--json] status\n"
                          "       janusgatectl [--json] policy reload\n"
                          "       janusgatectl --version\n");
}

/** @brief Execute one control operation requiring an empty response body. */
static int call_empty(enum jg_ipc_operation operation)
{
    size_t response_size = 0U;

    return jg_ipc_client_call(JG_CONTROL_SOCKET_PATH, operation, NULL, 0U, NULL,
                              0U, &response_size);
}

/** @brief Fetch and decode one aggregate daemon status snapshot. */
static int fetch_status(struct jg_daemon_runtime_stats *stats)
{
    uint8_t response[JG_DAEMON_STATUS_WIRE_SIZE];
    size_t response_size = 0U;
    int result =
        jg_ipc_client_call(JG_CONTROL_SOCKET_PATH, JG_IPC_DAEMON_STATUS, NULL,
                           0U, response, sizeof(response), &response_size);

    if (result == 0) {
        result = jg_daemon_status_decode(response, response_size, stats);
    }
    return result;
}

/** @brief Print the principal daemon state for an interactive operator. */
static void print_status_human(const struct jg_daemon_runtime_stats *stats)
{
    (void)printf("Policy generation: %" PRIu64 "\n", stats->policy_generation);
    (void)printf("Queue packets:     %" PRIu64 "\n", stats->queues.packets);
    (void)printf("Queue accepted:    %" PRIu64 "\n", stats->queues.accepted);
    (void)printf("Queue dropped:     %" PRIu64 "\n", stats->queues.dropped);
    (void)printf("Policy allowed:    %" PRIu64 "\n", stats->dataplane.accepted);
    (void)printf("Policy blocked:    %" PRIu64 "\n", stats->dataplane.blocked);
    (void)printf("Malformed:         %" PRIu64 "\n",
                 stats->dataplane.malformed);
    (void)printf("TCP resets:        %" PRIu64 "\n",
                 stats->dataplane.tcp_resets);
    (void)printf("Internal errors:   %" PRIu64 "\n",
                 stats->dataplane.internal_errors);
    (void)printf("DNS drop:          %" PRIu64 "\n",
                 stats->dataplane.dns_dropped);
    (void)printf("DNS REFUSED:       %" PRIu64 "\n",
                 stats->dataplane.dns_refused);
    (void)printf("DNS NXDOMAIN:      %" PRIu64 "\n",
                 stats->dataplane.dns_nxdomain);
    (void)printf("DNS sinkhole:      %" PRIu64 "\n",
                 stats->dataplane.dns_sinkholed);
    (void)printf("SNI inspected:     %" PRIu64 "\n",
                 stats->dataplane.sni_inspected);
    (void)printf("SNI unavailable:   %" PRIu64 "\n",
                 stats->dataplane.sni_encrypted_or_unavailable);
    (void)printf("Queue overflows:   %" PRIu64 "\n", stats->queues.overflows);
}

/** @brief Print every daemon counter with stable machine-readable names. */
static void print_status_json(const struct jg_daemon_runtime_stats *stats)
{
    (void)printf(
        "{"
        "\"policy_generation\":%" PRIu64 ","
        "\"queues\":{"
        "\"packets\":%" PRIu64 ",\"accepted\":%" PRIu64 ","
        "\"dropped\":%" PRIu64 ",\"malformed\":%" PRIu64 ","
        "\"overflows\":%" PRIu64 ",\"message_errors\":%" PRIu64 ","
        "\"verdict_errors\":%" PRIu64 "},"
        "\"dataplane\":{"
        "\"packets\":%" PRIu64 ",\"accepted\":%" PRIu64 ","
        "\"blocked\":%" PRIu64 ",\"malformed\":%" PRIu64 ","
        "\"fragments\":%" PRIu64 ",\"streams\":%" PRIu64 ","
        "\"tcp_resets\":%" PRIu64 ",\"internal_errors\":%" PRIu64 ","
        "\"sni_inspected\":%" PRIu64 ","
        "\"sni_encrypted_or_unavailable\":%" PRIu64 ","
        "\"dns_actions\":{\"drop\":%" PRIu64 ",\"refused\":%" PRIu64 ","
        "\"nxdomain\":%" PRIu64 ",\"sinkhole\":%" PRIu64 "}},"
        "\"fragments\":{"
        "\"stored\":%" PRIu64 ",\"duplicates\":%" PRIu64 ","
        "\"completed\":%" PRIu64 ",\"malformed\":%" PRIu64 ","
        "\"overlaps\":%" PRIu64 ",\"exhausted\":%" PRIu64 ","
        "\"timeouts\":%" PRIu64 "},"
        "\"tcp_streams\":{"
        "\"buffered\":%" PRIu64 ",\"duplicates\":%" PRIu64 ","
        "\"messages\":%" PRIu64 ",\"closed\":%" PRIu64 ","
        "\"malformed\":%" PRIu64 ",\"conflicts\":%" PRIu64 ","
        "\"exhausted\":%" PRIu64 ",\"timeouts\":%" PRIu64 "},"
        "\"output\":{\"sent\":%" PRIu64 ",\"errors\":%" PRIu64 "}"
        "}\n",
        stats->policy_generation, stats->queues.packets, stats->queues.accepted,
        stats->queues.dropped, stats->queues.malformed, stats->queues.overflows,
        stats->queues.message_errors, stats->queues.verdict_errors,
        stats->dataplane.packets, stats->dataplane.accepted,
        stats->dataplane.blocked, stats->dataplane.malformed,
        stats->dataplane.fragments, stats->dataplane.streams,
        stats->dataplane.tcp_resets, stats->dataplane.internal_errors,
        stats->dataplane.sni_inspected,
        stats->dataplane.sni_encrypted_or_unavailable,
        stats->dataplane.dns_dropped, stats->dataplane.dns_refused,
        stats->dataplane.dns_nxdomain, stats->dataplane.dns_sinkholed,
        stats->fragments.stored, stats->fragments.duplicates,
        stats->fragments.completed, stats->fragments.malformed,
        stats->fragments.overlaps, stats->fragments.exhausted,
        stats->fragments.timeouts, stats->tcp_streams.buffered,
        stats->tcp_streams.duplicates, stats->tcp_streams.messages,
        stats->tcp_streams.closed, stats->tcp_streams.malformed,
        stats->tcp_streams.conflicts, stats->tcp_streams.exhausted,
        stats->tcp_streams.timeouts, stats->output.sent, stats->output.errors);
}

/** @brief Run one parsed local administration command. */
static int run_command(int argc, char **argv, bool json, bool *recognized)
{
    struct jg_daemon_runtime_stats stats;
    int result = 0;

    *recognized = true;
    if (argc == 1 && strcmp(argv[0], "ping") == 0) {
        result = call_empty(JG_IPC_PING);
        if (result == 0) {
            if (json) {
                (void)puts("{\"ok\":true}");
            } else {
                (void)puts("ok");
            }
        }
    } else if (argc == 1 && strcmp(argv[0], "status") == 0) {
        result = fetch_status(&stats);
        if (result == 0) {
            if (json) {
                print_status_json(&stats);
            } else {
                print_status_human(&stats);
            }
        }
    } else if (argc == 2 && strcmp(argv[0], "policy") == 0 &&
               strcmp(argv[1], "reload") == 0) {
        result = call_empty(JG_IPC_POLICY_RELOAD);
        if (result == 0) {
            if (json) {
                (void)puts("{\"reloaded\":true}");
            } else {
                (void)puts("policy reloaded");
            }
        }
    } else {
        *recognized = false;
    }
    return result;
}

/** @brief Run the local JanusGate administration client. */
int main(int argc, char **argv)
{
    bool json = false;
    bool recognized = false;
    int argument = 1;
    int result = 0;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        (void)printf("janusgatectl %s\n", jg_version_string());
        return 0;
    }
    if (argument < argc && strcmp(argv[argument], "--json") == 0) {
        json = true;
        ++argument;
    }
    result = run_command(argc - argument, argv + argument, json, &recognized);
    if (!recognized) {
        print_usage(stderr);
        return 2;
    }
    if (result != 0) {
        (void)fprintf(stderr, "janusgatectl: %s\n", strerror(-result));
        return 1;
    }
    return 0;
}
