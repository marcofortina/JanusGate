/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

int jg_test_access(void);
int jg_test_account(void);
int jg_test_audit(void);
int jg_test_auth(void);
int jg_test_backup(void);
int jg_test_blocklist(void);
int jg_test_blocklist_remote(void);
int jg_test_blocklist_update(void);
int jg_test_certificate(void);
int jg_test_checked(void);
int jg_test_cli_client(void);
int jg_test_control_protocol(void);
int jg_test_control_server(void);
int jg_test_database(void);
int jg_test_dataplane(void);
int jg_test_dataplane_worker(void);
int jg_test_daemon_runtime(void);
int jg_test_diagnostic(void);
int jg_test_dns(void);
int jg_test_dns_response(void);
int jg_test_domain(void);
int jg_test_event(void);
int jg_test_fragment(void);
int jg_test_ipc(void);
int jg_test_ipc_client(void);
int jg_test_metrics(void);
int jg_test_management(void);
int jg_test_netd_client(void);
int jg_test_network(void);
int jg_test_netd(void);
int jg_test_nfqueue(void);
int jg_test_packet_output(void);
int jg_test_packet(void);
int jg_test_policy(void);
int jg_test_policy_store(void);
int jg_test_process_security(void);
int jg_test_tcp_reset(void);
int jg_test_tcp_stream(void);
int jg_test_tls_client_hello(void);
int jg_test_web_server(void);

/** @brief Run every unit-test group and combine their exit status. */
int main(void)
{
    int result = jg_test_access();

    result |= jg_test_account();
    result |= jg_test_audit();
    result |= jg_test_auth();
    result |= jg_test_backup();
    result |= jg_test_blocklist();
    result |= jg_test_blocklist_remote();
    result |= jg_test_blocklist_update();
    result |= jg_test_certificate();
    result |= jg_test_checked();
    result |= jg_test_cli_client();
    result |= jg_test_control_protocol();
    result |= jg_test_control_server();
    result |= jg_test_database();
    result |= jg_test_diagnostic();
    result |= jg_test_dataplane();
    result |= jg_test_dataplane_worker();
    result |= jg_test_daemon_runtime();
    result |= jg_test_dns();
    result |= jg_test_dns_response();
    result |= jg_test_domain();
    result |= jg_test_event();
    result |= jg_test_fragment();
    result |= jg_test_ipc();
    result |= jg_test_ipc_client();
    result |= jg_test_metrics();
    result |= jg_test_management();
    result |= jg_test_netd_client();
    result |= jg_test_network();
    result |= jg_test_netd();
    result |= jg_test_nfqueue();
    result |= jg_test_packet_output();
    result |= jg_test_packet();
    result |= jg_test_policy();
    result |= jg_test_policy_store();
    result |= jg_test_process_security();
    result |= jg_test_tcp_reset();
    result |= jg_test_tcp_stream();
    result |= jg_test_tls_client_hello();
    result |= jg_test_web_server();
    return result;
}
