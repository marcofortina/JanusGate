# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Require an immediately preceding Doxygen comment for every C function."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


BINDING = re.compile(
    r"^(?P<path>.+\.c):(?P<line>[1-9][0-9]*):[1-9][0-9]*: "
    r'note: "function" binds here$',
    re.MULTILINE,
)


class DocumentationError(ValueError):
    """Report one missing or unusable function-documentation invariant."""


def source_files(source_directory: Path) -> list[Path]:
    """Return every production and test C source in stable order."""
    files: list[Path] = []
    for relative_directory in ("src", "tests"):
        files.extend((source_directory / relative_directory).rglob("*.c"))
    return sorted(files)


def function_lines(clang_query: str, build_directory: Path, source: Path) -> list[int]:
    """Return definition start lines reported by the Clang AST matcher."""
    query = (
        "match functionDecl(isDefinition(), isExpansionInMainFile())"
        '.bind("function")'
    )
    command = [
        clang_query,
        "-p",
        str(build_directory),
        "-c",
        "set bind-root false",
        "-c",
        "set output diag",
        "-c",
        query,
        str(source),
    ]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        raise DocumentationError(
            f"Clang could not inspect {source}:\n{result.stdout.rstrip()}"
        )

    expected = source.resolve()
    lines = {
        int(match.group("line"))
        for match in BINDING.finditer(result.stdout)
        if Path(match.group("path")).resolve() == expected
    }
    return sorted(lines)


def has_preceding_doxygen(lines: list[str], definition_line: int) -> bool:
    """Check that one definition directly follows a Doxygen block."""
    previous = definition_line - 2
    if previous < 0 or not lines[previous].strip().endswith("*/"):
        return False
    if lines[previous].lstrip().startswith("/**"):
        return True

    cursor = previous - 1
    while cursor >= 0:
        stripped = lines[cursor].lstrip()
        if stripped.startswith("/**"):
            return True
        if not stripped.startswith("*"):
            return False
        cursor -= 1
    return False


def validate_source(
    clang_query: str, build_directory: Path, source: Path
) -> tuple[int, list[int]]:
    """Validate all function definitions in one C translation unit."""
    contents = source.read_text(encoding="utf-8").splitlines()
    definitions = function_lines(clang_query, build_directory, source)
    missing = [
        line for line in definitions if not has_preceding_doxygen(contents, line)
    ]
    return len(definitions), missing


def parse_arguments() -> argparse.Namespace:
    """Parse source and configured build directory arguments."""
    parser = argparse.ArgumentParser(
        description="Check immediately preceding C function documentation."
    )
    parser.add_argument("source_directory", type=Path)
    parser.add_argument("build_directory", type=Path)
    return parser.parse_args()


def main() -> int:
    """Validate production and test definitions with the Clang AST."""
    arguments = parse_arguments()
    clang_query = shutil.which("clang-query")
    if clang_query is None:
        print("Function documentation check requires clang-query.", file=sys.stderr)
        return 1
    if not (arguments.build_directory / "compile_commands.json").is_file():
        print(
            "Function documentation check requires compile_commands.json.",
            file=sys.stderr,
        )
        return 1

    total = 0
    failures: list[str] = []
    try:
        for source in source_files(arguments.source_directory):
            count, missing = validate_source(
                clang_query, arguments.build_directory, source
            )
            total += count
            failures.extend(f"{source}:{line}" for line in missing)
    except (DocumentationError, OSError, UnicodeError) as error:
        print(f"Function documentation check failed: {error}", file=sys.stderr)
        return 1

    if failures:
        print(
            "Function definitions without an immediately preceding " "Doxygen comment:",
            file=sys.stderr,
        )
        print("\n".join(failures), file=sys.stderr)
        return 1
    if total == 0:
        print("Function documentation check found no definitions.", file=sys.stderr)
        return 1

    print(f"Function documentation check passed: {total} definitions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
