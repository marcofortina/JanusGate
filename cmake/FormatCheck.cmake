# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

find_program(CLANG_FORMAT_EXECUTABLE NAMES clang-format REQUIRED)

file(
  GLOB_RECURSE format_sources
  LIST_DIRECTORIES false
  "${PROJECT_SOURCE_DIR}/include/*.h"
  "${PROJECT_SOURCE_DIR}/include/*.in"
  "${PROJECT_SOURCE_DIR}/src/*.c"
  "${PROJECT_SOURCE_DIR}/tests/*.c")

foreach(source IN LISTS format_sources)
  execute_process(
    COMMAND "${CLANG_FORMAT_EXECUTABLE}" --dry-run --Werror "${source}"
    RESULT_VARIABLE format_result)
  if(NOT format_result EQUAL 0)
    message(FATAL_ERROR "Formatting check failed: ${source}")
  endif()
endforeach()

