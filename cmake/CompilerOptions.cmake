# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

include(CheckCCompilerFlag)
include(CheckLinkerFlag)

function(janusgate_add_supported_compile_options target)
  foreach(option IN LISTS ARGN)
    string(MAKE_C_IDENTIFIER "${option}" option_id)
    set(cache_name "JANUSGATE_C_FLAG_${option_id}")
    check_c_compiler_flag("${option}" "${cache_name}")
    if(${cache_name})
      target_compile_options("${target}" PRIVATE "${option}")
    endif()
  endforeach()
endfunction()

function(janusgate_add_supported_link_options target)
  foreach(option IN LISTS ARGN)
    string(MAKE_C_IDENTIFIER "${option}" option_id)
    set(cache_name "JANUSGATE_LINK_FLAG_${option_id}")
    check_linker_flag(C "${option}" "${cache_name}")
    if(${cache_name})
      target_link_options("${target}" PRIVATE "${option}")
    endif()
  endforeach()
endfunction()

function(janusgate_apply_compiler_options target)
  janusgate_add_supported_compile_options(
    "${target}"
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wshadow
    -Wstrict-prototypes
    -Wmissing-prototypes
    -Wold-style-definition
    -Wcast-align
    -Wcast-qual
    -Wwrite-strings
    -Wundef
    -Wpointer-arith
    -Wvla
    -Wformat=2
    -Wformat-security
    -Werror=format-security
    -fno-common
    -fno-strict-overflow
    -fvisibility=hidden)

  if(JANUSGATE_WARNINGS_AS_ERRORS)
    janusgate_add_supported_compile_options("${target}" -Werror)
  endif()

  if(JANUSGATE_HARDENING)
    janusgate_add_supported_compile_options(
      "${target}" -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE)
    janusgate_add_supported_link_options(
      "${target}" -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
  endif()

  if(JANUSGATE_ENABLE_SANITIZERS)
    check_linker_flag(
      C "-fsanitize=address,undefined" JANUSGATE_SANITIZER_LINK_SUPPORTED)
    if(NOT JANUSGATE_SANITIZER_LINK_SUPPORTED)
      message(FATAL_ERROR "The selected C compiler cannot build with the required sanitizers")
    endif()
    target_compile_options(
      "${target}" PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options("${target}" PRIVATE -fsanitize=address,undefined)
  endif()

  if(JANUSGATE_ENABLE_COVERAGE)
    check_linker_flag(C "--coverage" JANUSGATE_COVERAGE_SUPPORTED)
    if(NOT JANUSGATE_COVERAGE_SUPPORTED)
      message(FATAL_ERROR "The selected C compiler does not support coverage instrumentation")
    endif()
    target_compile_options("${target}" PRIVATE --coverage)
    target_link_options("${target}" PRIVATE --coverage)
  endif()
endfunction()
