/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <civetweb.h>

#include "janusgate/logging.h"
#include "janusgate/process_security.h"
#include "janusgate/version.h"
#include "web_server.h"

/** @brief Print the stable HTTPS service command synopsis. */
static void print_usage(FILE *output)
{
    (void)fprintf(
        output,
        "usage: janusgate-web [--listen-address ADDRESS] [--port PORT]\n"
        "                     [--api-port PORT] [--certificate PATH]\n"
        "                     [--client-ca PATH] [--web-root PATH]\n"
        "                     [--socket PATH] [--hsts]\n"
        "       janusgate-web --version\n");
}

/** @brief Parse one nonzero decimal 16-bit port. */
static int parse_port(const char *text, uint16_t *port)
{
    char *end = NULL;
    unsigned long value = 0UL;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0UL ||
        value > UINT16_MAX) {
        return -EINVAL;
    }
    *port = (uint16_t)value;
    return 0;
}

/** @brief Parse bounded process-local web-service options. */
static int parse_options(int argc, char **argv, struct jg_web_config *config)
{
    int argument = 1;
    int result = 0;

    while (result == 0 && argument < argc) {
        if (strcmp(argv[argument], "--hsts") == 0) {
            config->hsts = true;
            ++argument;
        } else if (argument + 1 >= argc) {
            result = -EINVAL;
        } else if (strcmp(argv[argument], "--listen-address") == 0) {
            config->listen_address = argv[argument + 1];
            argument += 2;
        } else if (strcmp(argv[argument], "--port") == 0) {
            result = parse_port(argv[argument + 1], &config->port);
            argument += 2;
        } else if (strcmp(argv[argument], "--api-port") == 0) {
            result = parse_port(argv[argument + 1], &config->api_port);
            argument += 2;
        } else if (strcmp(argv[argument], "--certificate") == 0) {
            config->certificate_path = argv[argument + 1];
            argument += 2;
        } else if (strcmp(argv[argument], "--client-ca") == 0) {
            config->client_ca_path = argv[argument + 1];
            argument += 2;
        } else if (strcmp(argv[argument], "--web-root") == 0) {
            config->web_root = argv[argument + 1];
            argument += 2;
        } else if (strcmp(argv[argument], "--socket") == 0) {
            config->control_socket_path = argv[argument + 1];
            argument += 2;
        } else {
            result = -EINVAL;
        }
    }
    if (result == 0) {
        result = jg_web_config_validate(config);
    }
    return result;
}

/** @brief Block termination signals before CivetWeb creates workers. */
static int block_shutdown_signals(sigset_t *signals)
{
    int result = 0;

    if (sigemptyset(signals) != 0 || sigaddset(signals, SIGINT) != 0 ||
        sigaddset(signals, SIGTERM) != 0) {
        return -errno;
    }
    result = sigprocmask(SIG_BLOCK, signals, NULL);
    return result == 0 ? 0 : -errno;
}

/** @brief Run the unprivileged HTTPS management service. */
int main(int argc, char **argv)
{
    struct jg_web_config config;
    struct jg_web_server *server = NULL;
    struct jg_logging_config logging;
    sigset_t signals;
    unsigned initialized = 0U;
    int signal_number = 0;
    int wait_result = 0;
    int result = 0;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        (void)printf("janusgate-web %s\n", jg_version_string());
        return 0;
    }
    jg_web_config_default(&config);
    result = parse_options(argc, argv, &config);
    if (result != 0) {
        print_usage(stderr);
        return 2;
    }
    if (geteuid() == 0U) {
        (void)fprintf(stderr, "janusgate-web: refusing to run as root\n");
        return 1;
    }
    (void)umask(0077);
    jg_logging_config_default(&logging);
    result = jg_logging_initialize("janusgate-web", &logging);
    if (result != 0) {
        (void)fprintf(stderr, "janusgate-web: initialize logging: %s\n",
                      strerror(-result));
        return 1;
    }
    result = jg_process_harden();
    if (result == 0) {
        result = jg_process_restrict_capabilities(JG_PROCESS_PROFILE_WEB);
    }
    if (result == 0) {
        result = block_shutdown_signals(&signals);
    }
    if (result == 0) {
        initialized = mg_init_library(MG_FEATURES_TLS);
        if ((initialized & MG_FEATURES_TLS) == 0U) {
            result = -ENOTSUP;
        }
    }
    if (result == 0) {
        result = jg_web_server_start(&config, &server);
    }
    if (result == 0) {
        result = jg_process_apply_system_call_filter(JG_PROCESS_PROFILE_WEB);
    }
    if (result == 0) {
        (void)jg_log_emit(JG_LOG_INFO, "web", "web.started", NULL,
                          "HTTPS management service started", NULL);
        wait_result = sigwait(&signals, &signal_number);
        if (wait_result != 0) {
            result = -wait_result;
        }
    }
    (void)signal_number;
    jg_web_server_destroy(server);
    if (initialized != 0U) {
        (void)mg_exit_library();
    }
    if (result != 0) {
        char details[64U];

        (void)snprintf(details, sizeof(details), "{\"error_number\":%d}",
                       -result);
        (void)jg_log_emit(JG_LOG_ERROR, "web", "web.failed", NULL,
                          "HTTPS management service failed", details);
        jg_logging_shutdown();
        return 1;
    }
    (void)jg_log_emit(JG_LOG_INFO, "web", "web.stopped", NULL,
                      "HTTPS management service stopped", NULL);
    jg_logging_shutdown();
    return 0;
}
