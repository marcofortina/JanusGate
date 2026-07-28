/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>

#include "daemon_runtime.h"
#include "janusgate/version.h"

/** Signals synchronously owned by the daemon control thread. */
struct shutdown_waiter {
    struct jg_daemon_runtime *runtime;
    sigset_t signals;
    int result;
};

/** @brief Block termination signals before any worker thread is created. */
static int block_shutdown_signals(sigset_t *signals)
{
    int result = 0;

    if (signals == NULL || sigemptyset(signals) != 0 ||
        sigaddset(signals, SIGINT) != 0 || sigaddset(signals, SIGTERM) != 0 ||
        sigaddset(signals, SIGUSR1) != 0) {
        return -errno;
    }
    result = pthread_sigmask(SIG_BLOCK, signals, NULL);
    return result == 0 ? 0 : -result;
}

/** @brief Convert process termination signals into an orderly runtime stop. */
static void *wait_for_shutdown(void *context)
{
    struct shutdown_waiter *waiter = context;
    int signal_number = 0;

    while (waiter->result == 0) {
        const int wait_result = sigwait(&waiter->signals, &signal_number);

        if (wait_result != 0) {
            waiter->result = -wait_result;
        } else if (signal_number == SIGUSR1) {
            break;
        } else {
            waiter->result = jg_daemon_runtime_request_stop(waiter->runtime);
        }
    }
    return NULL;
}

/** @brief Run the main data-plane and policy daemon. */
int main(int argc, char **argv)
{
    struct jg_daemon_runtime_config config;
    struct jg_daemon_runtime *runtime = NULL;
    struct shutdown_waiter waiter;
    pthread_t signal_thread;
    bool signal_thread_started = false;
    int result = 0;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        (void)printf("janusgated %s\n", jg_version_string());
        return 0;
    }
    if (argc != 1) {
        (void)fprintf(stderr, "usage: janusgated [--version]\n");
        return 2;
    }

    (void)umask(0077);
    jg_daemon_runtime_config_default(&config);
    waiter = (struct shutdown_waiter){
        .runtime = NULL,
        .result = 0,
    };
    result = block_shutdown_signals(&waiter.signals);
    if (result == 0) {
        result = jg_daemon_runtime_start(&config, &runtime);
    }
    if (result == 0) {
        waiter.runtime = runtime;
        result =
            pthread_create(&signal_thread, NULL, wait_for_shutdown, &waiter);
        if (result == 0) {
            signal_thread_started = true;
        } else {
            result = -result;
        }
    }
    if (result == 0) {
        result = jg_daemon_runtime_wait(runtime);
    } else if (runtime != NULL) {
        (void)jg_daemon_runtime_request_stop(runtime);
    }
    if (signal_thread_started) {
        const int wake_result = pthread_kill(signal_thread, SIGUSR1);
        const int join_result = pthread_join(signal_thread, NULL);

        if (result == 0 && wake_result != 0) {
            result = -wake_result;
        }
        if (result == 0 && join_result != 0) {
            result = -join_result;
        }
        if (result == 0 && waiter.result != 0) {
            result = waiter.result;
        }
    }
    jg_daemon_runtime_destroy(runtime);
    if (result != 0) {
        (void)fprintf(stderr, "janusgated: %s\n", strerror(-result));
        return 1;
    }
    return 0;
}
