# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

function(janusgate_collect_build_metadata)
  execute_process(
    COMMAND git rev-parse --verify --short=12 HEAD
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    RESULT_VARIABLE git_result
    OUTPUT_VARIABLE git_commit
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
  if(NOT git_result EQUAL 0)
    set(git_commit "uncommitted")
  endif()

  string(TIMESTAMP build_timestamp "%Y-%m-%dT%H:%M:%SZ" UTC)

  set(JANUSGATE_BUILD_COMMIT "${git_commit}" PARENT_SCOPE)
  set(JANUSGATE_BUILD_TIMESTAMP "${build_timestamp}" PARENT_SCOPE)
  set(JANUSGATE_BUILD_COMPILER "${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}"
      PARENT_SCOPE)
  set(JANUSGATE_BUILD_TARGET "${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_SYSTEM_NAME}"
      PARENT_SCOPE)
endfunction()

