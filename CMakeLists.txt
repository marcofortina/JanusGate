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

add_library(janusgate-common STATIC src/common/version.c)
add_library(JanusGate::common ALIAS janusgate-common)
target_include_directories(
  janusgate-common
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>"
         "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
         "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
janusgate_apply_compiler_options(janusgate-common)

install(
  TARGETS janusgate-common
  EXPORT JanusGateTargets
  ARCHIVE COMPONENT development)
install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/include/janusgate/version.h"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/janusgate"
  COMPONENT development)
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
  DEPENDS janusgate-common
  USES_TERMINAL)

set(CPACK_PACKAGE_NAME "janusgate")
set(CPACK_PACKAGE_VENDOR "Marco Fortina")
set(CPACK_PACKAGE_CONTACT "marco_fortina@hotmail.it")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES "/build[^/]*/;/.git/;~$;${CPACK_SOURCE_IGNORE_FILES}")
include(CPack)
