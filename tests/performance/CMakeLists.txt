# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

add_executable(janusgate-policy-benchmark benchmark_policy.c)
target_link_libraries(
  janusgate-policy-benchmark PRIVATE JanusGate::common janusgate-daemon-core)
janusgate_apply_compiler_options(janusgate-policy-benchmark)

add_custom_target(
  performance
  COMMAND janusgate-policy-benchmark --enforce
  DEPENDS janusgate-policy-benchmark
  USES_TERMINAL
  VERBATIM)
