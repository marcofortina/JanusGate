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

#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>

#include "control_server.h"
#include "daemon_runtime.h"
#include "janusgate/identity.h"
#include "janusgate/process_security.h"
#include "janusgate/version.h"

/** Signals synchronously owned by the daemon control thread. */
struct shutdown_waiter {
    struct jg_daemon_runtime *runtime;
    sigset_t signals;
    int result;
};

/** @brief Resolve service identities and the shared control-socket group. */
static int resolve_control_identity(uid_t *service_uid,
                                    uid_t *web_uid,
                                    gid_t *control_gid)
{
    const struct passwd *service_identity = NULL;
    const struct passwd *web_identity = NULL;
    const struct group *control_group = NULL;

    if (service_uid == NULL || web_uid == NULL || control_gid == NULL) {
        return -EINVAL;
    }
    errno = 0;
    service_identity = getpwnam(JG_SERVICE_USER);
    if (service_identity == NULL) {
        return errno == 0 ? -ENOENT : -errno;
    }
    if (service_identity->pw_uid == 0U) {
        return -EINVAL;
    }
    *service_uid = service_identity->pw_uid;
    errno = 0;
    web_identity = getpwnam(JG_WEB_SERVICE_USER);
    if (web_identity == NULL) {
        return errno == 0 ? -ENOENT : -errno;
    }
    if (web_identity->pw_uid == 0U) {
        return -EINVAL;
    }
    errno = 0;
    control_group = getgrnam(JG_CONTROL_GROUP);
    if (control_group == NULL) {
        return errno == 0 ? -ENOENT : -errno;
    }
    *web_uid = web_identity->pw_uid;
    *control_gid = control_group->gr_gid;
    return 0;
}

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
    struct jg_control_server *control_server = NULL;
    struct shutdown_waiter waiter;
    pthread_t signal_thread;
    uid_t service_uid = 0U;
    uid_t web_uid = 0U;
    gid_t control_gid = 0U;
    bool signal_thread_started = false;
    const char *operation = "harden process";
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
    result = jg_process_harden();
    if (result == 0) {
        operation = "restrict capabilities";
        result = jg_process_restrict_capabilities(JG_PROCESS_PROFILE_DAEMON);
    }
    if (result == 0) {
        operation = "resolve service identities";
        result = resolve_control_identity(&service_uid, &web_uid, &control_gid);
    }
    if (result == 0) {
        operation = "block shutdown signals";
        result = block_shutdown_signals(&waiter.signals);
    }
    if (result == 0) {
        operation = "start packet runtime";
        result = jg_daemon_runtime_start(&config, &runtime);
    }
    if (result == 0) {
        operation = "start control service";
        result = jg_control_server_start(runtime, service_uid, web_uid,
                                         control_gid, &control_server);
    }
    if (result == 0) {
        operation = "drop privileges";
        result = jg_process_drop_privileges(JG_SERVICE_USER);
    }
    if (result == 0) {
        operation = "install system-call filter";
        result = jg_process_apply_seccomp(JG_PROCESS_PROFILE_DAEMON);
    }
    if (result == 0) {
        waiter.runtime = runtime;
        operation = "start signal waiter";
        result =
            pthread_create(&signal_thread, NULL, wait_for_shutdown, &waiter);
        if (result == 0) {
            signal_thread_started = true;
        } else {
            result = -result;
        }
    }
    if (result == 0) {
        operation = "run packet workers";
        result = jg_daemon_runtime_wait(runtime);
    } else if (runtime != NULL) {
        (void)jg_daemon_runtime_request_stop(runtime);
    }
    if (control_server != NULL) {
        const int control_result = jg_control_server_stop(control_server);

        if (result == 0 && control_result != 0) {
            operation = "stop control service";
            result = control_result;
        }
    }
    if (signal_thread_started) {
        const int wake_result = pthread_kill(signal_thread, SIGUSR1);
        const int join_result = pthread_join(signal_thread, NULL);

        if (result == 0 && wake_result != 0) {
            operation = "wake signal waiter";
            result = -wake_result;
        }
        if (result == 0 && join_result != 0) {
            operation = "join signal waiter";
            result = -join_result;
        }
        if (result == 0 && waiter.result != 0) {
            operation = "handle shutdown";
            result = waiter.result;
        }
    }
    jg_control_server_destroy(control_server);
    jg_daemon_runtime_destroy(runtime);
    if (result != 0) {
        (void)fprintf(stderr, "janusgated: %s: %s\n", operation,
                      strerror(-result));
        return 1;
    }
    return 0;
}
