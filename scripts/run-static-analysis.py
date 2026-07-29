# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Run the mandatory C static analyzers with stable project checks."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


CLANG_CHECKS = ",".join(
    (
        "-*",
        "clang-analyzer-core.*",
        "clang-analyzer-deadcode.*",
        "clang-analyzer-nullability.*",
        "clang-analyzer-unix.*",
        "bugprone-infinite-loop",
        "bugprone-misplaced-widening-cast",
        "bugprone-posix-return",
        "bugprone-signed-char-misuse",
        "bugprone-sizeof-expression",
        "bugprone-suspicious-memory-comparison",
        "bugprone-undefined-memory-manipulation",
    )
)


class AnalysisError(RuntimeError):
    """Report an unavailable analyzer or a failed analysis pass."""


def required_program(name: str) -> str:
    """Resolve one required executable or raise a concise error."""
    path = shutil.which(name)
    if path is None:
        raise AnalysisError(f"static analysis requires {name}")
    return path


def run(command: list[str], label: str) -> None:
    """Run one analyzer and fail when it reports a project finding."""
    print(f"Running {label}...", flush=True)
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise AnalysisError(f"{label} failed with status {result.returncode}")


def run_clang_tidy(source_directory: Path, build_directory: Path) -> None:
    """Analyze every production translation unit with focused Clang checks."""
    source = re.escape(str(source_directory.resolve()))
    jobs = min(os.cpu_count() or 1, 4)
    command = [
        required_program("run-clang-tidy"),
        "-quiet",
        "-j",
        str(jobs),
        "-p",
        str(build_directory),
        f"-checks={CLANG_CHECKS}",
        "-warnings-as-errors=*",
        f"-header-filter=^{source}/(include|src)/",
        rf"^{source}/src/.*\.c$",
    ]
    run(command, "clang-tidy")


def run_cppcheck(build_directory: Path) -> None:
    """Analyze the configured production build with Cppcheck."""
    command = [
        required_program("cppcheck"),
        f"--project={build_directory / 'compile_commands.json'}",
        "--enable=warning,performance,portability",
        "--check-level=normal",
        "--error-exitcode=1",
        "--suppress=missingIncludeSystem",
        "--quiet",
    ]
    run(command, "cppcheck")


def parse_arguments() -> argparse.Namespace:
    """Parse the source and configured build directory arguments."""
    parser = argparse.ArgumentParser(
        description="Run JanusGate static analysis checks."
    )
    parser.add_argument("source_directory", type=Path)
    parser.add_argument("build_directory", type=Path)
    return parser.parse_args()


def main() -> int:
    """Validate inputs and run both mandatory analyzers."""
    arguments = parse_arguments()
    database = arguments.build_directory / "compile_commands.json"
    if not database.is_file():
        print("static analysis requires compile_commands.json", file=sys.stderr)
        return 1
    try:
        run_clang_tidy(arguments.source_directory, arguments.build_directory)
        run_cppcheck(arguments.build_directory)
    except (AnalysisError, OSError) as error:
        print(f"Static analysis failed: {error}", file=sys.stderr)
        return 1
    print("Static analysis passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
