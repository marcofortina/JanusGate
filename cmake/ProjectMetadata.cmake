# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

function(janusgate_collect_build_metadata)
  set(source_commit "${JANUSGATE_SOURCE_COMMIT}")
  if(source_commit STREQUAL "")
    execute_process(
      COMMAND git rev-parse --verify HEAD
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      RESULT_VARIABLE git_result
      OUTPUT_VARIABLE source_commit
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET)
    if(NOT git_result EQUAL 0)
      set(source_commit "unknown")
    endif()
  else()
    string(LENGTH "${source_commit}" source_commit_length)
    if(NOT source_commit MATCHES "^[0-9a-f]+$"
       OR source_commit_length LESS 7
       OR source_commit_length GREATER 64)
      message(
        FATAL_ERROR "JANUSGATE_SOURCE_COMMIT must be a lowercase Git hash")
    endif()
  endif()

  string(TIMESTAMP build_timestamp "%Y-%m-%dT%H:%M:%SZ" UTC)

  set(JANUSGATE_BUILD_COMMIT "${source_commit}" PARENT_SCOPE)
  set(JANUSGATE_BUILD_TIMESTAMP "${build_timestamp}" PARENT_SCOPE)
  set(JANUSGATE_BUILD_COMPILER "${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}"
      PARENT_SCOPE)
  set(JANUSGATE_BUILD_TARGET "${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_SYSTEM_NAME}"
      PARENT_SCOPE)
endfunction()
