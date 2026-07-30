/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "netd.h"

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <unistd.h>

#include "janusgate/identity.h"
#include "janusgate/logging.h"
#include "janusgate/process_security.h"
#include "janusgate/version.h"

/** @brief Resolve the dedicated service and local-control identities. */
static int resolve_service_identity(uid_t *user_id, gid_t *control_group_id)
{
    const struct passwd *identity = NULL;
    const struct group *control_group = NULL;

    if (user_id == NULL || control_group_id == NULL) {
        return -EINVAL;
    }
    errno = 0;
    identity = getpwnam(JG_SERVICE_USER);
    if (identity == NULL) {
        return errno == 0 ? -ENOENT : -errno;
    }
    if (identity->pw_uid == 0U) {
        return -EINVAL;
    }
    errno = 0;
    control_group = getgrnam(JG_CONTROL_GROUP);
    if (control_group == NULL) {
        return errno == 0 ? -ENOENT : -errno;
    }
    *user_id = identity->pw_uid;
    *control_group_id = control_group->gr_gid;
    return 0;
}

/** @brief Run the privileged network-helper command. */
int main(int argc, char **argv)
{
    uid_t service_uid = 0U;
    gid_t control_gid = 0U;
    struct jg_logging_config logging;
    int result = 0;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        (void)printf("janusgate-netd %s\n", jg_version_string());
        return 0;
    }
    if (argc != 1) {
        (void)fprintf(stderr, "usage: janusgate-netd [--version]\n");
        return 2;
    }
    if (geteuid() != 0U) {
        (void)fprintf(stderr, "janusgate-netd must run as root\n");
        return 1;
    }

    (void)umask(0077);
    jg_logging_config_default(&logging);
    result = jg_logging_initialize("janusgate-netd", &logging);
    if (result != 0) {
        (void)fprintf(stderr, "janusgate-netd: initialize logging: %s\n",
                      strerror(-result));
        return 1;
    }
    result = jg_process_harden();
    if (result == 0) {
        result = jg_process_restrict_capabilities(JG_PROCESS_PROFILE_NETD);
    }
    if (result == 0) {
        result = resolve_service_identity(&service_uid, &control_gid);
    }
    if (result == 0) {
        (void)jg_log_emit(JG_LOG_INFO, "network", "network.started", NULL,
                          "Network helper started", NULL);
        result = jg_netd_run(service_uid, control_gid);
    }
    if (result != 0) {
        char details[64U];

        (void)snprintf(details, sizeof(details), "{\"error_number\":%d}",
                       -result);
        (void)jg_log_emit(JG_LOG_ERROR, "network", "network.failed", NULL,
                          "Network helper failed", details);
        jg_logging_shutdown();
        return 1;
    }
    (void)jg_log_emit(JG_LOG_INFO, "network", "network.stopped", NULL,
                      "Network helper stopped", NULL);
    jg_logging_shutdown();
    return 0;
}
