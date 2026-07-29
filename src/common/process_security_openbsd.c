/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/process_security.h"

#include <errno.h>

#include <grp.h>
#include <pwd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

/** Validate one process-profile enumeration value. */
static int validate_profile(enum jg_process_profile profile)
{
    return profile >= JG_PROCESS_PROFILE_DAEMON &&
                   profile <= JG_PROCESS_PROFILE_WEB
               ? 0
               : -EINVAL;
}

/** @brief Disable secret-bearing core-dump creation. */
int jg_process_harden(void)
{
    const struct rlimit core_limit = {
        .rlim_cur = 0U,
        .rlim_max = 0U,
    };

    return setrlimit(RLIMIT_CORE, &core_limit) == 0 ? 0 : -errno;
}

/** @brief Validate a profile on a system without separate capability sets. */
int jg_process_restrict_capabilities(enum jg_process_profile profile)
{
    return validate_profile(profile);
}

/** @brief Permanently assume one dedicated non-root service identity. */
int jg_process_drop_privileges(const char *user_name)
{
    const struct passwd *identity = NULL;
    uid_t user_id = 0U;
    gid_t group_id = 0U;

    if (user_name == NULL || user_name[0] == '\0') {
        return -EINVAL;
    }
    errno = 0;
    identity = getpwnam(user_name);
    if (identity == NULL) {
        return errno == 0 ? -ENOENT : -errno;
    }
    if (identity->pw_uid == 0U || identity->pw_gid == 0U) {
        return -EINVAL;
    }
    user_id = identity->pw_uid;
    group_id = identity->pw_gid;
    if (initgroups(user_name, group_id) != 0 ||
        setresgid(group_id, group_id, group_id) != 0 ||
        setresuid(user_id, user_id, user_id) != 0) {
        return -errno;
    }
    return getuid() == user_id && geteuid() == user_id &&
                   getgid() == group_id && getegid() == group_id
               ? 0
               : -EPERM;
}

/** @brief Install the available pledge promises for one service profile. */
int jg_process_apply_system_call_filter(enum jg_process_profile profile)
{
    const char *promises = NULL;
    int result = validate_profile(profile);

    if (result != 0) {
        return result;
    }
    if (profile == JG_PROCESS_PROFILE_DAEMON) {
        promises = "stdio rpath wpath cpath fattr flock inet unix dns bpf";
    } else if (profile == JG_PROCESS_PROFILE_NETD) {
        /* pledge exposes no promise for the required bridge and MTU ioctls. */
        return 0;
    } else {
        promises = "stdio rpath inet unix dns";
    }
    return pledge(promises, NULL) == 0 ? 0 : -errno;
}
