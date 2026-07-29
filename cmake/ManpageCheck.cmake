# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

find_program(GROFF_EXECUTABLE NAMES groff REQUIRED)
find_program(BASH_EXECUTABLE NAMES bash REQUIRED)
find_program(ZSH_EXECUTABLE NAMES zsh)
find_program(FISH_EXECUTABLE NAMES fish)

file(
  GLOB man_pages
  LIST_DIRECTORIES false
  "${PROJECT_SOURCE_DIR}/docs/man/*.[1-9]")

if(NOT man_pages)
  message(FATAL_ERROR "No manual pages were found")
endif()

foreach(page IN LISTS man_pages)
  execute_process(
    COMMAND "${GROFF_EXECUTABLE}" -man -z "${page}"
    RESULT_VARIABLE page_result)
  if(NOT page_result EQUAL 0)
    message(FATAL_ERROR "Manual-page validation failed: ${page}")
  endif()
endforeach()

execute_process(
  COMMAND "${BASH_EXECUTABLE}" -n
          "${PROJECT_SOURCE_DIR}/completions/bash/janusgatectl"
  RESULT_VARIABLE bash_result)
if(NOT bash_result EQUAL 0)
  message(FATAL_ERROR "Bash completion validation failed")
endif()

if(ZSH_EXECUTABLE)
  execute_process(
    COMMAND "${ZSH_EXECUTABLE}" -n
            "${PROJECT_SOURCE_DIR}/completions/zsh/_janusgatectl"
    RESULT_VARIABLE zsh_result)
  if(NOT zsh_result EQUAL 0)
    message(FATAL_ERROR "Zsh completion validation failed")
  endif()
endif()

if(FISH_EXECUTABLE)
  execute_process(
    COMMAND "${FISH_EXECUTABLE}" -n
            "${PROJECT_SOURCE_DIR}/completions/fish/janusgatectl.fish"
    RESULT_VARIABLE fish_result)
  if(NOT fish_result EQUAL 0)
    message(FATAL_ERROR "Fish completion validation failed")
  endif()
endif()
