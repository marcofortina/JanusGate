# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

cmake_minimum_required(VERSION 3.25)

project(
  JanusGate
  VERSION 0.1.3
  DESCRIPTION "Transparent inline DNS policy appliance"
  HOMEPAGE_URL "https://github.com/marcofortina/JanusGate"
  LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(CTest)
include(CompilerOptions)
include(ProjectMetadata)

find_package(Threads REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)
find_package(ZLIB REQUIRED)
find_package(PkgConfig REQUIRED)
find_path(CIVETWEB_INCLUDE_DIR NAMES civetweb.h REQUIRED)
find_library(CIVETWEB_LIBRARY NAMES civetweb REQUIRED)
pkg_check_modules(IDN2 REQUIRED IMPORTED_TARGET libidn2)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(JANSSON REQUIRED IMPORTED_TARGET jansson)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  pkg_check_modules(LIBCAP REQUIRED IMPORTED_TARGET libcap)
  pkg_check_modules(LIBSECCOMP REQUIRED IMPORTED_TARGET libseccomp)
  pkg_check_modules(MNL REQUIRED IMPORTED_TARGET libmnl)
  pkg_check_modules(NETFILTER_QUEUE REQUIRED IMPORTED_TARGET
                    libnetfilter_queue)
  pkg_check_modules(NFTABLES REQUIRED IMPORTED_TARGET libnftables)
  set(janusgate_process_security_source src/common/process_security.c)
  set(janusgate_nfqueue_source src/daemon/nfqueue.c)
  set(janusgate_packet_output_source src/daemon/packet_output.c)
  set(janusgate_netd_sources
      src/netd/bridge.c
      src/netd/nftables.c
      src/netd/rtnetlink.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  include(CheckCSourceRuns)
  set(CMAKE_REQUIRED_INCLUDES "${CIVETWEB_INCLUDE_DIR}")
  set(CMAKE_REQUIRED_LIBRARIES "${CIVETWEB_LIBRARY}")
  check_c_source_runs(
    "#include <civetweb.h>
     /* Verify the runtime feature required by every Web listener. */
     int main(void) {
       unsigned features = mg_init_library(MG_FEATURES_TLS);
       if (features != 0U) {
         mg_exit_library();
       }
       return (features & MG_FEATURES_TLS) != 0U ? 0 : 1;
     }"
    JANUSGATE_CIVETWEB_HAS_TLS)
  unset(CMAKE_REQUIRED_INCLUDES)
  unset(CMAKE_REQUIRED_LIBRARIES)
  if(NOT JANUSGATE_CIVETWEB_HAS_TLS)
    message(FATAL_ERROR
            "CivetWeb must provide TLS; see docs/build.md for OpenBSD")
  endif()
  set(janusgate_process_security_source
      src/common/process_security_openbsd.c)
  set(janusgate_nfqueue_source src/daemon/nfqueue_openbsd.c)
  set(janusgate_packet_output_source src/daemon/packet_output_openbsd.c)
  set(janusgate_netd_sources
      src/netd/bridge_openbsd.c
      src/netd/nftables_openbsd.c)
else()
  message(FATAL_ERROR "JanusGate supports Linux and OpenBSD")
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(JANUSGATE_HARDENING "Enable compiler and linker hardening" ON)
option(JANUSGATE_WARNINGS_AS_ERRORS "Treat project warnings as errors" ON)
option(JANUSGATE_ENABLE_SANITIZERS "Enable address and undefined-behavior checks" OFF)
option(JANUSGATE_ENABLE_COVERAGE "Enable source coverage instrumentation" OFF)
option(JANUSGATE_ENABLE_FUZZING "Build libFuzzer parser targets" OFF)
option(JANUSGATE_BUILD_DOCUMENTATION "Build the Doxygen reference" ON)
option(JANUSGATE_BUILD_BENCHMARKS "Build the performance benchmark suite" OFF)
set(JANUSGATE_SOURCE_COMMIT
    ""
    CACHE STRING "Source revision to embed when Git metadata is unavailable")

if(JANUSGATE_ENABLE_FUZZING AND NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "JANUSGATE_ENABLE_FUZZING requires Clang")
endif()
if(JANUSGATE_BUILD_BENCHMARKS AND NOT BUILD_TESTING)
  message(FATAL_ERROR "JANUSGATE_BUILD_BENCHMARKS requires BUILD_TESTING")
endif()
if(JANUSGATE_BUILD_DOCUMENTATION)
  find_package(Doxygen 1.9 REQUIRED dot)
endif()

janusgate_collect_build_metadata()

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/janusgate/version.h"
  @ONLY)
if(JANUSGATE_BUILD_DOCUMENTATION)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in"
    "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile"
    @ONLY)
endif()
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Uninstall.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/Uninstall.cmake"
  @ONLY)

add_library(
  janusgate-common STATIC
  src/common/access.c
  src/common/account.c
  src/common/account_mtls.c
  src/common/account_session.c
  src/common/account_token.c
  src/common/account_totp.c
  src/common/audit.c
  src/common/auth.c
  src/common/backup.c
  src/common/blocklist.c
  src/common/blocklist_remote.c
  src/common/certificate.c
  src/common/checked.c
  src/common/database.c
  src/common/database_backup.c
  src/common/database_blocklist.c
  src/common/database_configuration.c
  src/common/database_operation.c
  src/common/database_policy.c
  src/common/database_policy_mode.c
  src/common/diagnostic.c
  src/common/dns.c
  src/common/dns_policy.c
  src/common/domain.c
  src/common/event.c
  src/common/ipc.c
  src/common/ipc_client.c
  src/common/logging.c
  src/common/network.c
  src/common/packet.c
  src/common/policy.c
  ${janusgate_process_security_source}
  src/common/tls_client_hello.c
  src/common/version.c)
add_library(JanusGate::common ALIAS janusgate-common)
target_include_directories(
  janusgate-common
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>"
         "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
         "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
target_link_libraries(
  janusgate-common
  PUBLIC OpenSSL::Crypto PkgConfig::IDN2 PkgConfig::SODIUM Threads::Threads
         ZLIB::ZLIB)
target_link_libraries(
  janusgate-common
  PRIVATE PkgConfig::CURL PkgConfig::JANSSON PkgConfig::SQLITE3)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(
    janusgate-common PRIVATE PkgConfig::LIBCAP PkgConfig::LIBSECCOMP)
endif()
janusgate_apply_compiler_options(janusgate-common)

add_library(
  janusgate-control-protocol STATIC
  src/daemon/control_protocol.c
  src/daemon/metrics.c)
target_include_directories(
  janusgate-control-protocol
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/daemon>")
target_link_libraries(janusgate-control-protocol PUBLIC JanusGate::common)
janusgate_apply_compiler_options(janusgate-control-protocol)

add_library(
  janusgate-daemon-core STATIC
  src/daemon/blocklist_update.c
  src/daemon/control_server.c
  src/daemon/dataplane.c
  src/daemon/dataplane_worker.c
  src/daemon/daemon_runtime.c
  src/daemon/diagnostic_bundle.c
  src/daemon/dns_response.c
  src/daemon/fragment.c
  src/daemon/management.c
  src/daemon/management_backup.c
  src/daemon/management_blocklist.c
  src/daemon/management_certificate.c
  src/daemon/management_consistency.c
  src/daemon/management_identity.c
  src/daemon/management_jobs.c
  src/daemon/management_logging.c
  src/daemon/management_network.c
  src/daemon/management_policy.c
  src/daemon/management_recovery.c
  src/daemon/management_system.c
  src/daemon/netd_client.c
  ${janusgate_nfqueue_source}
  src/daemon/nfqueue_group.c
  ${janusgate_packet_output_source}
  src/daemon/policy_store.c
  src/daemon/tcp_reset.c
  src/daemon/tcp_stream.c)
target_include_directories(
  janusgate-daemon-core
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/daemon>"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/common")
target_link_libraries(
  janusgate-daemon-core
  PUBLIC JanusGate::common janusgate-control-protocol Threads::Threads
  PRIVATE PkgConfig::JANSSON)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(janusgate-daemon-core
                        PRIVATE PkgConfig::MNL PkgConfig::NETFILTER_QUEUE)
endif()
janusgate_apply_compiler_options(janusgate-daemon-core)

add_library(
  janusgate-netd-core STATIC
  ${janusgate_netd_sources}
  src/netd/server.c
  src/netd/transaction.c)
target_include_directories(
  janusgate-netd-core
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/netd>")
target_link_libraries(janusgate-netd-core PUBLIC JanusGate::common)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(
    janusgate-netd-core PRIVATE PkgConfig::MNL PkgConfig::NFTABLES)
endif()
janusgate_apply_compiler_options(janusgate-netd-core)

add_executable(janusgate-netd src/netd/main.c)
target_link_libraries(janusgate-netd PRIVATE janusgate-netd-core)
janusgate_apply_compiler_options(janusgate-netd)

add_executable(janusgated src/daemon/main.c)
target_link_libraries(janusgated PRIVATE janusgate-daemon-core)
janusgate_apply_compiler_options(janusgated)

add_library(janusgate-cli-core STATIC src/cli/client.c)
target_include_directories(
  janusgate-cli-core
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/cli>")
target_link_libraries(
  janusgate-cli-core
  PUBLIC JanusGate::common
  PRIVATE PkgConfig::CURL PkgConfig::JANSSON)
janusgate_apply_compiler_options(janusgate-cli-core)

add_executable(
  janusgatectl
  src/cli/commands_appliance.c
  src/cli/commands_identity.c
  src/cli/commands_policy.c
  src/cli/main.c)
target_link_libraries(
  janusgatectl
  PRIVATE JanusGate::common janusgate-cli-core janusgate-control-protocol
          PkgConfig::JANSSON)
janusgate_apply_compiler_options(janusgatectl)

add_library(
  janusgate-web-core STATIC
  src/web/web_gateway.c
  src/web/web_server.c)
target_include_directories(
  janusgate-web-core
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/web>"
  PRIVATE "${CIVETWEB_INCLUDE_DIR}")
target_link_libraries(
  janusgate-web-core PUBLIC JanusGate::common
  PRIVATE "${CIVETWEB_LIBRARY}" PkgConfig::JANSSON)
janusgate_apply_compiler_options(janusgate-web-core)

add_executable(janusgate-web src/web/main.c)
target_include_directories(janusgate-web PRIVATE "${CIVETWEB_INCLUDE_DIR}")
target_link_libraries(
  janusgate-web PRIVATE janusgate-web-core "${CIVETWEB_LIBRARY}")
if(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set_property(TARGET janusgate-web PROPERTY INSTALL_RPATH_USE_LINK_PATH TRUE)
endif()
janusgate_apply_compiler_options(janusgate-web)

add_executable(janusgate-setup src/setup/main.c)
target_link_libraries(
  janusgate-setup PRIVATE JanusGate::common PkgConfig::JANSSON)
janusgate_apply_compiler_options(janusgate-setup)

install(
  TARGETS janusgate-common
  EXPORT JanusGateTargets
  ARCHIVE COMPONENT development)
install(
  FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/access.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/account.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/audit.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/auth.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/backup.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/checked.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/blocklist.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/blocklist_remote.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/certificate.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/database.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/diagnostic.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/dns.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/dns_policy.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/domain.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/event.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/identity.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/ipc.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/ipc_client.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/logging.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/network.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/packet.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/policy.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/process_security.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/tls_client_hello.h"
        "${CMAKE_CURRENT_BINARY_DIR}/include/janusgate/version.h"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/janusgate"
  COMPONENT development)
install(
  TARGETS janusgate-netd janusgated janusgate-web janusgate-setup
  RUNTIME DESTINATION "${CMAKE_INSTALL_SBINDIR}"
  COMPONENT runtime)
install(
  TARGETS janusgatectl
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  COMPONENT runtime)
install(
  DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/web/"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/janusgate/web"
  COMPONENT runtime)
install(
  FILES "${CMAKE_CURRENT_SOURCE_DIR}/api/openapi.yaml"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/janusgate/api"
  COMPONENT development)
install(
  DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/docs/html"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/doc/janusgate"
  COMPONENT development
  OPTIONAL)
install(
  FILES "${CMAKE_CURRENT_SOURCE_DIR}/docs/man/janusgatectl.1"
  DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
  COMPONENT runtime)
install(
  FILES "${CMAKE_CURRENT_SOURCE_DIR}/docs/man/janusgated.8"
        "${CMAKE_CURRENT_SOURCE_DIR}/docs/man/janusgate-netd.8"
        "${CMAKE_CURRENT_SOURCE_DIR}/docs/man/janusgate-web.8"
        "${CMAKE_CURRENT_SOURCE_DIR}/docs/man/janusgate-setup.8"
  DESTINATION "${CMAKE_INSTALL_MANDIR}/man8"
  COMPONENT runtime)
install(
  FILES "${CMAKE_CURRENT_SOURCE_DIR}/completions/bash/janusgatectl"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/bash-completion/completions"
  COMPONENT runtime)
install(
  FILES "${CMAKE_CURRENT_SOURCE_DIR}/completions/zsh/_janusgatectl"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/zsh/site-functions"
  COMPONENT runtime)
install(
  FILES "${CMAKE_CURRENT_SOURCE_DIR}/completions/fish/janusgatectl.fish"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/fish/vendor_completions.d"
  COMPONENT runtime)
install(
  FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/janusgate"
  COMPONENT runtime)
if(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  install(
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/config/janusgate.openbsd.conf.example"
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/janusgate"
    RENAME janusgate.conf.example
    COMPONENT runtime)
  install(
    PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/init/openbsd/janusgate_netd"
             "${CMAKE_CURRENT_SOURCE_DIR}/init/openbsd/janusgated"
             "${CMAKE_CURRENT_SOURCE_DIR}/init/openbsd/janusgate_web"
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/rc.d"
    COMPONENT runtime)
else()
  install(
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/config/janusgate.conf.example"
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/janusgate"
    COMPONENT runtime)
  install(
    PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/init/openrc/janusgate-netd"
             "${CMAKE_CURRENT_SOURCE_DIR}/init/openrc/janusgated"
             "${CMAKE_CURRENT_SOURCE_DIR}/init/openrc/janusgate-web"
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/init.d"
    COMPONENT runtime)
  install(
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/init/systemd/janusgate-netd.service"
          "${CMAKE_CURRENT_SOURCE_DIR}/init/systemd/janusgated.service"
          "${CMAKE_CURRENT_SOURCE_DIR}/init/systemd/janusgate-web.service"
    DESTINATION "lib/systemd/system"
    COMPONENT runtime)
  install(
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/config/tmpfiles/janusgate.conf"
    DESTINATION "lib/tmpfiles.d"
    COMPONENT runtime)
  install(
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/config/sysusers/janusgate.conf"
    DESTINATION "lib/sysusers.d"
    COMPONENT runtime)
  install(
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/config/logrotate/janusgate"
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/logrotate.d"
    COMPONENT runtime)
endif()
install(
  EXPORT JanusGateTargets
  NAMESPACE JanusGate::
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/JanusGate"
  COMPONENT development)

add_custom_target(
  format-check
  COMMAND "${CMAKE_COMMAND}" "-DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FormatCheck.cmake"
  VERBATIM)

add_custom_target(
  static-analysis
  COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/scripts/run-static-analysis.py"
          "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}"
  USES_TERMINAL
  VERBATIM)

add_custom_target(
  uninstall
  COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/Uninstall.cmake"
  VERBATIM)

add_custom_target(
  function-docs-check
  COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-function-docs.py"
          "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}"
  VERBATIM)

if(JANUSGATE_BUILD_DOCUMENTATION)
  add_custom_target(
    doxygen
    COMMAND "${DOXYGEN_EXECUTABLE}" "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile"
    BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/docs/html/index.html"
    DEPENDS function-docs-check
    VERBATIM)
endif()

add_custom_target(
  openapi-check
  COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate-openapi.py"
          "${CMAKE_CURRENT_SOURCE_DIR}/api/openapi.yaml"
  VERBATIM)

add_custom_target(
  web-assets-check
  COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate-web-assets.py"
          "${CMAKE_CURRENT_SOURCE_DIR}"
  VERBATIM)

add_custom_target(
  man-check
  COMMAND "${CMAKE_COMMAND}" "-DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ManpageCheck.cmake"
  VERBATIM)

add_custom_target(
  namespace-lab
  COMMAND
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/namespace-lab/run-all.sh"
    --build-directory "${CMAKE_CURRENT_BINARY_DIR}"
  DEPENDS janusgate-integration-tests
  USES_TERMINAL
  VERBATIM)

set(janusgate_check_dependencies
    janusgate-netd
    janusgated
    janusgate-web
    janusgate-setup
    janusgatectl
    man-check
    openapi-check
    web-assets-check)
if(BUILD_TESTING)
  list(APPEND janusgate_check_dependencies janusgate-integration-tests
              janusgate-unit-tests)
endif()
if(JANUSGATE_BUILD_DOCUMENTATION)
  list(APPEND janusgate_check_dependencies doxygen)
endif()
add_custom_target(
  check
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure
  DEPENDS ${janusgate_check_dependencies}
  USES_TERMINAL)

if(BUILD_TESTING)
  add_subdirectory(tests)
  add_test(
    NAME openapi
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate-openapi.py"
            "${CMAKE_CURRENT_SOURCE_DIR}/api/openapi.yaml")
  add_test(
    NAME man-pages
    COMMAND "${CMAKE_COMMAND}" "-DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ManpageCheck.cmake")
  add_test(
    NAME web-assets
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate-web-assets.py"
            "${CMAKE_CURRENT_SOURCE_DIR}")
endif()

set(CPACK_PACKAGE_NAME "janusgate")
set(CPACK_PACKAGE_VENDOR "Marco Fortina")
set(CPACK_PACKAGE_CONTACT "marco_fortina@hotmail.it")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "janusgate-${PROJECT_VERSION}")
set(
  CPACK_SOURCE_IGNORE_FILES
  "/build[^/]*/;/.git/;/out/;/packaging/alpine/APKBUILD$;~$;${CPACK_SOURCE_IGNORE_FILES}"
)
include(CPack)
