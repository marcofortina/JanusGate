# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set(JANUSGATE_FUZZ_CORPUS_DIRECTORY
    "${CMAKE_CURRENT_BINARY_DIR}/corpora")

add_custom_command(
  OUTPUT "${JANUSGATE_FUZZ_CORPUS_DIRECTORY}/.ready"
  COMMAND
    "${Python3_EXECUTABLE}"
    "${CMAKE_SOURCE_DIR}/scripts/prepare-fuzz-corpora.py"
    "${CMAKE_SOURCE_DIR}/tests/fixtures" "${JANUSGATE_FUZZ_CORPUS_DIRECTORY}"
  COMMAND "${CMAKE_COMMAND}" -E touch
          "${JANUSGATE_FUZZ_CORPUS_DIRECTORY}/.ready"
  DEPENDS "${CMAKE_SOURCE_DIR}/scripts/prepare-fuzz-corpora.py"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/backup-header.hex"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/blocked-dns.hex"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/dns-query.hex"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/ipc-ping.hex"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/ipv4-fragment.hex"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/ipv6-extension.hex"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/tcp-dns.hex"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/tls-client-hello.hex"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/blocklist.txt"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/hosts.txt"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/policy.rpz"
          "${CMAKE_SOURCE_DIR}/tests/fixtures/management-request.json"
  VERBATIM)
add_custom_target(
  janusgate-fuzz-corpora
  DEPENDS "${JANUSGATE_FUZZ_CORPUS_DIRECTORY}/.ready")

function(janusgate_add_fuzzer target target_id)
  add_executable("${target}" fuzz_target.c)
  target_compile_definitions("${target}" PRIVATE "JG_FUZZ_TARGET=${target_id}")
  target_compile_options("${target}" PRIVATE -fsanitize=fuzzer)
  target_link_options("${target}" PRIVATE -fsanitize=fuzzer)
  target_link_libraries(
    "${target}" PRIVATE JanusGate::common janusgate-daemon-core
                        PkgConfig::JANSSON)
  janusgate_apply_compiler_options("${target}")
  add_dependencies("${target}" janusgate-fuzz-corpora)
  add_test(
    NAME "${target}-smoke"
    COMMAND
      "${target}" -runs=256 -max_len=65536 -timeout=10
      "${JANUSGATE_FUZZ_CORPUS_DIRECTORY}/${target}")
  set_tests_properties("${target}-smoke" PROPERTIES LABELS "fuzz" TIMEOUT 60)
endfunction()

janusgate_add_fuzzer(janusgate-fuzz-packet 1)
janusgate_add_fuzzer(janusgate-fuzz-ipv6-extensions 2)
janusgate_add_fuzzer(janusgate-fuzz-dns 3)
janusgate_add_fuzzer(janusgate-fuzz-dns-name 4)
janusgate_add_fuzzer(janusgate-fuzz-tcp-dns 5)
janusgate_add_fuzzer(janusgate-fuzz-tcp-reassembly 6)
janusgate_add_fuzzer(janusgate-fuzz-fragments 7)
janusgate_add_fuzzer(janusgate-fuzz-tls-client-hello 8)
janusgate_add_fuzzer(janusgate-fuzz-blocklist-line 9)
janusgate_add_fuzzer(janusgate-fuzz-hosts 10)
janusgate_add_fuzzer(janusgate-fuzz-rpz 11)
janusgate_add_fuzzer(janusgate-fuzz-control-protocol 12)
janusgate_add_fuzzer(janusgate-fuzz-rest-json 13)
janusgate_add_fuzzer(janusgate-fuzz-backup-manifest 14)
