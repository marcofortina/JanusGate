/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

int jg_test_blocklist(void);
int jg_test_blocklist_remote(void);
int jg_test_checked(void);
int jg_test_database(void);
int jg_test_dataplane(void);
int jg_test_dns(void);
int jg_test_domain(void);
int jg_test_ipc(void);
int jg_test_network(void);
int jg_test_netd(void);
int jg_test_nfqueue(void);
int jg_test_packet(void);
int jg_test_policy(void);

/** @brief Run every unit-test group and combine their exit status. */
int main(void)
{
    int result = jg_test_blocklist();

    result |= jg_test_blocklist_remote();
    result |= jg_test_checked();
    result |= jg_test_database();
    result |= jg_test_dataplane();
    result |= jg_test_dns();
    result |= jg_test_domain();
    result |= jg_test_ipc();
    result |= jg_test_network();
    result |= jg_test_netd();
    result |= jg_test_nfqueue();
    result |= jg_test_packet();
    result |= jg_test_policy();
    return result;
}
