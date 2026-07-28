/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "netd.h"

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <unistd.h>

#include "janusgate/version.h"

/** Dedicated unprivileged identity permitted to call the network helper. */
#define JG_SERVICE_USER "janusgate"

/** @brief Resolve the dedicated service identity without accepting root. */
static int resolve_service_identity(uid_t *user_id, gid_t *group_id)
{
    const struct passwd *identity = NULL;

    if (user_id == NULL || group_id == NULL) {
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
    *user_id = identity->pw_uid;
    *group_id = identity->pw_gid;
    return 0;
}

/** @brief Run the privileged network-helper command. */
int main(int argc, char **argv)
{
    uid_t service_uid = 0U;
    gid_t service_gid = 0U;
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
    result = resolve_service_identity(&service_uid, &service_gid);
    if (result == 0) {
        result = jg_netd_run(service_uid, service_gid);
    }
    if (result != 0) {
        (void)fprintf(stderr, "janusgate-netd: %s\n", strerror(-result));
        return 1;
    }
    return 0;
}
