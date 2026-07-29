/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _GNU_SOURCE

#include "janusgate/process_security.h"

#include <errno.h>
#include <stddef.h>

#include <grp.h>
#include <pwd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/prctl.h>
#include <seccomp.h>

/** Number of elements in one fixed array. */
#define ARRAY_SIZE(values) (sizeof(values) / sizeof((values)[0]))

/** System calls shared by all long-running service profiles. */
static const char *const common_system_calls[] = {
    "_llseek",
    "access",
    "arch_prctl",
    "brk",
    "clock_gettime",
    "clock_gettime64",
    "clock_nanosleep",
    "clock_nanosleep_time64",
    "clone",
    "clone3",
    "close",
    "close_range",
    "dup",
    "dup2",
    "dup3",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "epoll_pwait2",
    "epoll_wait",
    "eventfd",
    "eventfd2",
    "exit",
    "exit_group",
    "faccessat",
    "faccessat2",
    "fcntl",
    "fcntl64",
    "fstat",
    "fstat64",
    "fstatat64",
    "futex",
    "futex_time64",
    "getcwd",
    "getdents64",
    "getegid",
    "geteuid",
    "getgid",
    "getpeername",
    "getpid",
    "getppid",
    "getrandom",
    "getresgid",
    "getresuid",
    "getrlimit",
    "getrusage",
    "getsockname",
    "getsockopt",
    "gettid",
    "gettimeofday",
    "getuid",
    "ioctl",
    "kill",
    "lseek",
    "lstat",
    "lstat64",
    "madvise",
    "membarrier",
    "mmap",
    "mmap2",
    "mprotect",
    "mremap",
    "munmap",
    "nanosleep",
    "newfstatat",
    "open",
    "openat",
    "pipe",
    "pipe2",
    "poll",
    "ppoll",
    "ppoll_time64",
    "prctl",
    "pread64",
    "preadv",
    "preadv2",
    "pselect6",
    "pselect6_time64",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "read",
    "readlink",
    "readlinkat",
    "readv",
    "recv",
    "recvfrom",
    "recvmmsg",
    "recvmmsg_time64",
    "recvmsg",
    "restart_syscall",
    "rseq",
    "rt_sigaction",
    "rt_sigpending",
    "rt_sigprocmask",
    "rt_sigreturn",
    "rt_sigtimedwait",
    "rt_sigtimedwait_time64",
    "sched_getaffinity",
    "sched_yield",
    "select",
    "send",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "set_robust_list",
    "setsockopt",
    "set_tid_address",
    "shutdown",
    "sigaltstack",
    "socket",
    "socketcall",
    "socketpair",
    "stat",
    "stat64",
    "statx",
    "sysinfo",
    "tgkill",
    "time",
    "uname",
    "write",
    "writev",
};

/** Persistent-state and network calls needed by the policy daemon. */
static const char *const daemon_system_calls[] = {
    "accept",  "accept4",   "bind",      "chmod",     "chown",
    "connect", "fallocate", "fchmod",    "fchown",    "fdatasync",
    "flock",   "fsync",     "ftruncate", "listen",    "mkdir",
    "mkdirat", "rename",    "renameat",  "renameat2", "sched_setaffinity",
    "statfs",  "unlink",    "unlinkat",
};

/** Kernel-network and lifecycle calls needed by the privileged helper. */
static const char *const netd_system_calls[] = {
    "accept", "accept4", "bind", "chmod",  "chown",
    "listen", "reboot",  "sync", "unlink", "unlinkat",
};

/** Static-content and local-control calls needed by the HTTPS service. */
static const char *const web_system_calls[] = {
    "accept", "accept4", "bind", "connect", "listen", "sendfile", "sendfile64",
};

/** Validate one process-profile enumeration value. */
static int validate_profile(enum jg_process_profile profile)
{
    return profile >= JG_PROCESS_PROFILE_DAEMON &&
                   profile <= JG_PROCESS_PROFILE_WEB
               ? 0
               : -EINVAL;
}

/** Clear all current capability sets without changing credentials. */
static int clear_capabilities(void)
{
    cap_t capabilities = cap_init();
    int result = 0;

    if (capabilities == NULL) {
        return -errno;
    }
    if (cap_set_proc(capabilities) != 0) {
        result = -errno;
    }
    if (cap_free(capabilities) != 0 && result == 0) {
        result = -errno;
    }
    return result;
}

/** Replace effective and permitted capabilities with one exact list. */
static int install_capabilities(const cap_value_t *values, size_t count)
{
    cap_t capabilities = cap_init();
    int result = 0;

    if (capabilities == NULL) {
        return -errno;
    }
    if (count != 0U && (cap_set_flag(capabilities, CAP_EFFECTIVE, (int)count,
                                     values, CAP_SET) != 0 ||
                        cap_set_flag(capabilities, CAP_PERMITTED, (int)count,
                                     values, CAP_SET) != 0)) {
        result = -errno;
    }
    if (result == 0 && cap_set_proc(capabilities) != 0) {
        result = -errno;
    }
    if (cap_free(capabilities) != 0 && result == 0) {
        result = -errno;
    }
    return result;
}

/** Add each system-call name available on the current architecture. */
static int allow_system_calls(scmp_filter_ctx filter,
                              const char *const *names,
                              size_t count)
{
    size_t index = 0U;
    int result = 0;

    for (index = 0U; result == 0 && index < count; ++index) {
        const int system_call = seccomp_syscall_resolve_name(names[index]);

        if (system_call != __NR_SCMP_ERROR) {
            result = seccomp_rule_add(filter, SCMP_ACT_ALLOW, system_call, 0U);
        }
    }
    return result;
}

/** Select and add the calls unique to one service profile. */
static int allow_profile_system_calls(scmp_filter_ctx filter,
                                      enum jg_process_profile profile)
{
    if (profile == JG_PROCESS_PROFILE_DAEMON) {
        return allow_system_calls(filter, daemon_system_calls,
                                  ARRAY_SIZE(daemon_system_calls));
    }
    if (profile == JG_PROCESS_PROFILE_NETD) {
        return allow_system_calls(filter, netd_system_calls,
                                  ARRAY_SIZE(netd_system_calls));
    }
    if (profile == JG_PROCESS_PROFILE_WEB) {
        return allow_system_calls(filter, web_system_calls,
                                  ARRAY_SIZE(web_system_calls));
    }
    return -EINVAL;
}

/** @brief Disable process privilege growth and core-dump creation. */
int jg_process_harden(void)
{
    const struct rlimit core_limit = {
        .rlim_cur = 0U,
        .rlim_max = 0U,
    };

    if (setrlimit(RLIMIT_CORE, &core_limit) != 0 ||
        prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0) {
        return -errno;
    }
    return 0;
}

/** @brief Restrict current capabilities to one service minimum. */
int jg_process_restrict_capabilities(enum jg_process_profile profile)
{
    static const cap_value_t daemon_capabilities[] = {
        CAP_CHOWN,   CAP_DAC_OVERRIDE, CAP_NET_ADMIN,
        CAP_NET_RAW, CAP_SETGID,       CAP_SETUID,
    };
    static const cap_value_t netd_capabilities[] = {
        CAP_CHOWN,
        CAP_NET_ADMIN,
        CAP_SYS_BOOT,
    };
    int result = validate_profile(profile);

    if (result != 0) {
        return result;
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0L, 0L, 0L) != 0 &&
        errno != EINVAL) {
        return -errno;
    }
    if (profile == JG_PROCESS_PROFILE_DAEMON) {
        return install_capabilities(daemon_capabilities,
                                    ARRAY_SIZE(daemon_capabilities));
    }
    if (profile == JG_PROCESS_PROFILE_NETD) {
        return install_capabilities(netd_capabilities,
                                    ARRAY_SIZE(netd_capabilities));
    }
    return clear_capabilities();
}

/** @brief Permanently assume one dedicated non-root service identity. */
int jg_process_drop_privileges(const char *user_name)
{
    const struct passwd *identity = NULL;
    uid_t user_id = 0U;
    gid_t group_id = 0U;
    int result = 0;

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
    result = clear_capabilities();
    if (result == 0 && (getuid() != user_id || geteuid() != user_id ||
                        getgid() != group_id || getegid() != group_id)) {
        result = -EPERM;
    }
    return result;
}

/** @brief Install one synchronized service system-call allowlist. */
int jg_process_apply_seccomp(enum jg_process_profile profile)
{
    scmp_filter_ctx filter = NULL;
    int result = validate_profile(profile);

    if (result != 0) {
        return result;
    }
    filter = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (filter == NULL) {
        return errno == 0 ? -ENOMEM : -errno;
    }
    result = seccomp_attr_set(filter, SCMP_FLTATR_CTL_TSYNC, 1U);
    if (result == 0) {
        result = allow_system_calls(filter, common_system_calls,
                                    ARRAY_SIZE(common_system_calls));
    }
    if (result == 0) {
        result = allow_profile_system_calls(filter, profile);
    }
    if (result == 0) {
        result = seccomp_load(filter);
    }
    seccomp_release(filter);
    return result;
}
