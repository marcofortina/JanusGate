/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <signal.h>
#include <sys/socket.h>
#if !defined(__OpenBSD__)
#include <sys/prctl.h>
#include <sys/ptrace.h>
#endif
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

#include "janusgate/process_security.h"

int jg_test_process_security(void);

/** @brief Verify irreversible process flags inside an isolated child. */
static void test_process_hardening(void **state)
{
    pid_t child = -1;
    int status = 0;

    (void)state;
    child = fork();
    assert_true(child >= 0);
    if (child == 0) {
        struct rlimit core_limit;

        if (jg_process_harden() != 0 ||
#if !defined(__OpenBSD__)
            prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) != 1 ||
            prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L) != 0 ||
#endif
            getrlimit(RLIMIT_CORE, &core_limit) != 0 ||
            core_limit.rlim_cur != 0U || core_limit.rlim_max != 0U) {
            _exit(1);
        }
        _exit(0);
    }
    assert_int_equal(waitpid(child, &status, 0), child);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
}

/** @brief Verify an allowlisted call and one forbidden system operation. */
static void test_system_call_filter(void **state)
{
    pid_t child = -1;
    int status = 0;

    (void)state;
    child = fork();
    assert_true(child >= 0);
    if (child == 0) {
        if (jg_process_harden() != 0 ||
            jg_process_apply_system_call_filter(JG_PROCESS_PROFILE_WEB) != 0 ||
            getpid() <= 0 || getgroups(0, NULL) < 0) {
            _exit(1);
        }
#if defined(__OpenBSD__)
        (void)socket(AF_ROUTE, SOCK_RAW, 0);
        _exit(2);
#else
        errno = 0;
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != -1 || errno != EPERM) {
            _exit(2);
        }
        _exit(0);
#endif
    }
    assert_int_equal(waitpid(child, &status, 0), child);
#if defined(__OpenBSD__)
    assert_true(WIFSIGNALED(status));
    assert_int_equal(WTERMSIG(status), SIGABRT);
#else
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
#endif
}

/** @brief Verify strict rejection of unknown process profiles. */
static void test_invalid_profiles(void **state)
{
    const enum jg_process_profile invalid_profile = (enum jg_process_profile)99;

    (void)state;
    assert_int_equal(jg_process_restrict_capabilities(invalid_profile),
                     -EINVAL);
    assert_int_equal(jg_process_apply_system_call_filter(invalid_profile),
                     -EINVAL);
    assert_int_equal(jg_process_drop_privileges(NULL), -EINVAL);
    assert_int_equal(jg_process_drop_privileges(""), -EINVAL);
}

/** @brief Run process hardening and confinement tests. */
int jg_test_process_security(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_process_hardening),
        cmocka_unit_test(test_system_call_filter),
        cmocka_unit_test(test_invalid_profiles),
    };

    return cmocka_run_group_tests_name("process-security", tests, NULL, NULL);
}
