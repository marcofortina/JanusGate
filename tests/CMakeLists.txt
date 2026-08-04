# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)

configure_file(
  "${CMAKE_SOURCE_DIR}/config/janusgate.conf.example"
  "${CMAKE_CURRENT_BINARY_DIR}/janusgate-setup.conf"
  COPYONLY)
file(
  CHMOD "${CMAKE_CURRENT_BINARY_DIR}/janusgate-setup.conf"
  PERMISSIONS OWNER_READ OWNER_WRITE)

add_executable(
  janusgate-unit-tests
  unit/test_access.c
  unit/test_account.c
  unit/test_alert.c
  unit/test_audit.c
  unit/test_auth.c
  unit/test_backup.c
  unit/test_blocklist.c
  unit/test_blocklist_remote.c
  unit/test_blocklist_update.c
  unit/test_certificate.c
  unit/test_main.c
  unit/test_checked.c
  unit/test_cli_client.c
  unit/test_control_protocol.c
  unit/test_control_server.c
  unit/test_database.c
  unit/test_diagnostic.c
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
  unit/test_logging.c
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
  unit/test_policy_stats_collector.c
  unit/test_process_security.c
  unit/test_tcp_reset.c
  unit/test_tcp_stream.c
  unit/test_tls_client_hello.c)
target_sources(janusgate-unit-tests PRIVATE unit/test_web_server.c)
target_link_libraries(
  janusgate-unit-tests
  PRIVATE JanusGate::common janusgate-daemon-core janusgate-netd-core
          janusgate-cli-core janusgate-web-core
          PkgConfig::CMOCKA PkgConfig::JANSSON PkgConfig::SQLITE3)
target_include_directories(
  janusgate-unit-tests PRIVATE "${CMAKE_SOURCE_DIR}/src/common")
target_compile_definitions(
  janusgate-unit-tests
  PRIVATE JANUSGATE_TEST_PYTHON="${Python3_EXECUTABLE}"
          JANUSGATE_TEST_WEBHOOK_SERVER="${CMAKE_CURRENT_SOURCE_DIR}/helpers/webhook_server.py")
janusgate_apply_compiler_options(janusgate-unit-tests)

add_test(NAME unit COMMAND janusgate-unit-tests)
add_test(NAME cli-version COMMAND janusgatectl --version)
add_test(NAME cli-help COMMAND janusgatectl --help)
add_test(NAME web-version COMMAND janusgate-web --version)
add_test(NAME setup-version COMMAND janusgate-setup --version)
add_test(NAME setup-help COMMAND janusgate-setup --help)
add_test(
  NAME setup-config
  COMMAND janusgate-setup --config
          "${CMAKE_CURRENT_BINARY_DIR}/janusgate-setup.conf" --image-build
          --validate-only)
if(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set_tests_properties(unit PROPERTIES TIMEOUT 300)
else()
  set_tests_properties(unit PROPERTIES TIMEOUT 120)
endif()

add_executable(janusgate-integration-tests integration/test_pipeline.c)
target_link_libraries(
  janusgate-integration-tests
  PRIVATE JanusGate::common janusgate-daemon-core)
janusgate_apply_compiler_options(janusgate-integration-tests)
add_test(NAME integration COMMAND janusgate-integration-tests)
set_tests_properties(integration PROPERTIES LABELS "integration" TIMEOUT 30)

if(JANUSGATE_ENABLE_FUZZING)
  add_subdirectory(fuzz)
endif()

if(JANUSGATE_BUILD_BENCHMARKS)
  add_subdirectory(performance)
endif()
