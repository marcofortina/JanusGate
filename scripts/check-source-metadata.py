#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Validate licensing metadata for every authored repository file."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


LICENSE_IDENTIFIER = "AGPL-3.0-or-later"
COPYRIGHT = "Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>"


def repository_files(root: Path) -> list[Path]:
    """Return tracked and untracked authored files in stable order."""
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        check=True,
        capture_output=True,
    )
    names = result.stdout.decode("utf-8").split("\0")
    return [root / name for name in sorted(filter(None, names))]


def validate_license(root: Path, errors: list[str]) -> None:
    """Validate the single canonical root license without duplicating it."""
    license_path = root / "LICENSE"
    if not license_path.is_file():
        errors.append("LICENSE: canonical project license is missing")
        return
    text = license_path.read_text(encoding="utf-8")
    if "GNU AFFERO GENERAL PUBLIC LICENSE" not in text or (
        "Version 3, 19 November 2007" not in text
    ):
        errors.append("LICENSE: expected GNU Affero General Public License v3")


def validate_path(root: Path, path: Path, errors: list[str]) -> None:
    """Validate one authored path and its inline source metadata."""
    relative = path.relative_to(root).as_posix()
    if relative == "LICENSE":
        return
    if relative.startswith("LICENSES/") or relative.endswith(".license"):
        errors.append(f"{relative}: license copies and sidecars are forbidden")
        return
    try:
        contents = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        errors.append(f"{relative}: binary authored files require review")
        return
    if LICENSE_IDENTIFIER not in contents:
        errors.append(f"{relative}: missing {LICENSE_IDENTIFIER}")
    if COPYRIGHT not in contents:
        errors.append(f"{relative}: missing project copyright")


def main() -> int:
    """Validate the canonical license and every authored file."""
    root = Path(__file__).resolve().parent.parent
    errors: list[str] = []

    validate_license(root, errors)
    try:
        paths = repository_files(root)
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as error:
        print(f"Source metadata check failed: {error}", file=sys.stderr)
        return 1
    for path in paths:
        validate_path(root, path, errors)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"Source metadata check passed: {len(paths)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
