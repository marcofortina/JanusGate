# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

cmake_minimum_required(VERSION 3.25)

project(
  JanusGate
  VERSION 0.1.0
  DESCRIPTION "Transparent inline DNS policy appliance"
  HOMEPAGE_URL "https://github.com/marcofortina/JanusGate"
  LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(CTest)
include(CompilerOptions)
include(ProjectMetadata)

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(IDN2 REQUIRED IMPORTED_TARGET libidn2)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(JANSSON REQUIRED IMPORTED_TARGET jansson)
pkg_check_modules(MNL REQUIRED IMPORTED_TARGET libmnl)
pkg_check_modules(NETFILTER_QUEUE REQUIRED IMPORTED_TARGET libnetfilter_queue)
pkg_check_modules(NFTABLES REQUIRED IMPORTED_TARGET libnftables)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(JANUSGATE_HARDENING "Enable compiler and linker hardening" ON)
option(JANUSGATE_WARNINGS_AS_ERRORS "Treat project warnings as errors" ON)
option(JANUSGATE_ENABLE_SANITIZERS "Enable address and undefined-behavior checks" OFF)
option(JANUSGATE_ENABLE_COVERAGE "Enable source coverage instrumentation" OFF)

janusgate_collect_build_metadata()

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/janusgate/version.h"
  @ONLY)

add_library(
  janusgate-common STATIC
  src/common/blocklist.c
  src/common/blocklist_remote.c
  src/common/checked.c
  src/common/database.c
  src/common/dns.c
  src/common/domain.c
  src/common/ipc.c
  src/common/network.c
  src/common/packet.c
  src/common/policy.c
  src/common/version.c)
add_library(JanusGate::common ALIAS janusgate-common)
target_include_directories(
  janusgate-common
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>"
         "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
         "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
target_link_libraries(janusgate-common PUBLIC PkgConfig::IDN2 PkgConfig::SODIUM)
target_link_libraries(
  janusgate-common
  PRIVATE PkgConfig::CURL PkgConfig::JANSSON PkgConfig::SQLITE3)
janusgate_apply_compiler_options(janusgate-common)

add_library(
  janusgate-daemon-core STATIC
  src/daemon/control_server.c
  src/daemon/dataplane.c
  src/daemon/dataplane_worker.c
  src/daemon/control_protocol.c
  src/daemon/daemon_runtime.c
  src/daemon/fragment.c
  src/daemon/netd_client.c
  src/daemon/nfqueue.c
  src/daemon/nfqueue_group.c
  src/daemon/packet_output.c
  src/daemon/policy_store.c
  src/daemon/tcp_reset.c
  src/daemon/tcp_stream.c)
target_include_directories(
  janusgate-daemon-core
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/daemon>")
target_link_libraries(
  janusgate-daemon-core
  PUBLIC JanusGate::common Threads::Threads
  PRIVATE PkgConfig::NETFILTER_QUEUE)
janusgate_apply_compiler_options(janusgate-daemon-core)

add_library(
  janusgate-netd-core STATIC
  src/netd/bridge.c
  src/netd/nftables.c
  src/netd/rtnetlink.c
  src/netd/server.c
  src/netd/transaction.c)
target_include_directories(
  janusgate-netd-core
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/netd>")
target_link_libraries(
  janusgate-netd-core
  PUBLIC JanusGate::common
  PRIVATE PkgConfig::MNL PkgConfig::NFTABLES)
janusgate_apply_compiler_options(janusgate-netd-core)

add_executable(janusgate-netd src/netd/main.c)
target_link_libraries(janusgate-netd PRIVATE janusgate-netd-core)
janusgate_apply_compiler_options(janusgate-netd)

add_executable(janusgated src/daemon/main.c)
target_link_libraries(janusgated PRIVATE janusgate-daemon-core)
janusgate_apply_compiler_options(janusgated)

install(
  TARGETS janusgate-common
  EXPORT JanusGateTargets
  ARCHIVE COMPONENT development)
install(
  FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/checked.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/blocklist.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/blocklist_remote.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/database.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/dns.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/domain.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/ipc.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/network.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/packet.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/janusgate/policy.h"
        "${CMAKE_CURRENT_BINARY_DIR}/include/janusgate/version.h"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/janusgate"
  COMPONENT development)
install(
  TARGETS janusgate-netd janusgated
  RUNTIME DESTINATION "${CMAKE_INSTALL_SBINDIR}"
  COMPONENT runtime)
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
  check
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure
  DEPENDS janusgate-netd janusgated janusgate-unit-tests
  USES_TERMINAL)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

set(CPACK_PACKAGE_NAME "janusgate")
set(CPACK_PACKAGE_VENDOR "Marco Fortina")
set(CPACK_PACKAGE_CONTACT "marco_fortina@hotmail.it")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES "/build[^/]*/;/.git/;~$;${CPACK_SOURCE_IGNORE_FILES}")
include(CPack)
