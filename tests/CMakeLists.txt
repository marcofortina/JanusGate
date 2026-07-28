# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)

add_executable(
  janusgate-unit-tests
  unit/test_access.c
  unit/test_account.c
  unit/test_audit.c
  unit/test_auth.c
  unit/test_blocklist.c
  unit/test_blocklist_remote.c
  unit/test_blocklist_update.c
  unit/test_main.c
  unit/test_checked.c
  unit/test_cli_client.c
  unit/test_control_protocol.c
  unit/test_control_server.c
  unit/test_database.c
  unit/test_dataplane.c
  unit/test_dataplane_worker.c
  unit/test_daemon_runtime.c
  unit/test_dns.c
  unit/test_dns_response.c
  unit/test_domain.c
  unit/test_event.c
  unit/test_fragment.c
  unit/test_ipc.c
  unit/test_ipc_client.c
  unit/test_metrics.c
  unit/test_management.c
  unit/test_netd_client.c
  unit/test_network.c
  unit/test_netd.c
  unit/test_nfqueue.c
  unit/test_packet_output.c
  unit/test_packet.c
  unit/test_policy.c
  unit/test_policy_store.c
  unit/test_tcp_reset.c
  unit/test_tcp_stream.c
  unit/test_tls_client_hello.c)
target_sources(janusgate-unit-tests PRIVATE unit/test_web_server.c)
target_link_libraries(
  janusgate-unit-tests
  PRIVATE JanusGate::common janusgate-daemon-core janusgate-netd-core
          janusgate-cli-core janusgate-web-core
          PkgConfig::CMOCKA PkgConfig::JANSSON PkgConfig::SQLITE3)
janusgate_apply_compiler_options(janusgate-unit-tests)

add_test(NAME unit COMMAND janusgate-unit-tests)
add_test(NAME cli-version COMMAND janusgatectl --version)
add_test(NAME web-version COMMAND janusgate-web --version)
set_tests_properties(unit PROPERTIES TIMEOUT 30)
