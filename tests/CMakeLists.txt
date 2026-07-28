# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)

add_executable(
  janusgate-unit-tests
  unit/test_blocklist.c
  unit/test_blocklist_remote.c
  unit/test_main.c
  unit/test_checked.c
  unit/test_database.c
  unit/test_dns.c
  unit/test_domain.c
  unit/test_ipc.c
  unit/test_packet.c
  unit/test_policy.c)
target_link_libraries(
  janusgate-unit-tests
  PRIVATE JanusGate::common PkgConfig::CMOCKA PkgConfig::SQLITE3)
janusgate_apply_compiler_options(janusgate-unit-tests)

add_test(NAME unit COMMAND janusgate-unit-tests)
set_tests_properties(unit PROPERTIES TIMEOUT 30)
