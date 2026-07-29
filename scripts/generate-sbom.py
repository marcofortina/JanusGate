#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Create a deterministic SPDX 2.3 JSON software bill of materials."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


DEPENDENCIES = (
    ("CivetWeb", None, "MIT"),
    ("OpenSSL", "openssl", "Apache-2.0"),
    ("zlib", "zlib", "Zlib"),
    ("libidn2", "libidn2", "LGPL-3.0-or-later OR GPL-2.0-or-later"),
    ("libcurl", "libcurl", "curl"),
    ("Jansson", "jansson", "MIT"),
    ("libcap", "libcap", "BSD-3-Clause OR GPL-2.0-only"),
    ("libseccomp", "libseccomp", "LGPL-2.1-only"),
    ("libmnl", "libmnl", "LGPL-2.1-only"),
    ("libnetfilter_queue", "libnetfilter_queue", "GPL-2.0-or-later"),
    ("libnfnetlink", "libnfnetlink", "GPL-2.0-or-later"),
    ("libnftables", "libnftables", "GPL-2.0-only"),
    ("libsodium", "libsodium", "ISC"),
    ("SQLite", "sqlite3", "blessing"),
)


def git(root: Path, *arguments: str) -> str:
    """Return stripped text from one read-only Git query."""
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def source_files(root: Path) -> list[Path]:
    """Return repository files included in the source SBOM."""
    names = git(root, "ls-files", "-z").split("\0")
    return [root / name for name in sorted(filter(None, names))]


def digest(path: Path, algorithm: str) -> str:
    """Hash one file without loading it completely into memory."""
    value = hashlib.new(algorithm)
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def spdx_id(prefix: str, value: str) -> str:
    """Create one stable SPDX identifier from arbitrary text."""
    suffix = hashlib.sha1(value.encode("utf-8")).hexdigest()[:16]
    return f"SPDXRef-{prefix}-{suffix}"


def dependency_version(module: str | None) -> str | None:
    """Return an installed pkg-config version when available."""
    if module is None:
        return None
    result = subprocess.run(
        ["pkg-config", "--modversion", module],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def creation_time(root: Path) -> str:
    """Return a reproducible UTC creation timestamp."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        epoch = git(root, "log", "-1", "--format=%ct")
    value = datetime.fromtimestamp(int(epoch), timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def file_entries(root: Path, paths: list[Path]) -> tuple[list[dict], list[str]]:
    """Build SPDX file entries and return their SHA-1 values."""
    entries = []
    sha1_values = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        sha1 = digest(path, "sha1")
        sha1_values.append(sha1)
        entries.append(
            {
                "SPDXID": spdx_id("File", relative),
                "fileName": f"./{relative}",
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": sha1},
                    {
                        "algorithm": "SHA256",
                        "checksumValue": digest(path, "sha256"),
                    },
                ],
                "licenseConcluded": "AGPL-3.0-or-later",
                "licenseInfoInFiles": ["AGPL-3.0-or-later"],
                "copyrightText": (
                    "Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>"
                ),
            }
        )
    return entries, sha1_values


def create_document(root: Path) -> dict:
    """Create the complete SPDX document for the current source revision."""
    revision = git(root, "rev-parse", "HEAD")
    version = git(root, "describe", "--tags", "--always", "--dirty")
    paths = source_files(root)
    files, sha1_values = file_entries(root, paths)
    project_id = "SPDXRef-Package-JanusGate"
    packages = [
        {
            "SPDXID": project_id,
            "name": "JanusGate",
            "versionInfo": version,
            "downloadLocation": "https://github.com/marcofortina/JanusGate",
            "filesAnalyzed": True,
            "packageVerificationCode": {
                "packageVerificationCodeValue": hashlib.sha1(
                    "".join(sorted(sha1_values)).encode("ascii")
                ).hexdigest()
            },
            "licenseConcluded": "AGPL-3.0-or-later",
            "licenseDeclared": "AGPL-3.0-or-later",
            "copyrightText": (
                "Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>"
            ),
        }
    ]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": project_id,
        }
    ]
    for entry in files:
        relationships.append(
            {
                "spdxElementId": project_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": entry["SPDXID"],
            }
        )
    for name, module, declared_license in DEPENDENCIES:
        identifier = spdx_id("Package", name)
        package = {
            "SPDXID": identifier,
            "name": name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": declared_license,
            "copyrightText": "NOASSERTION",
        }
        version_value = dependency_version(module)
        if version_value is not None:
            package["versionInfo"] = version_value
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": project_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": identifier,
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"JanusGate-{revision[:12]}",
        "documentNamespace": (
            f"https://github.com/marcofortina/JanusGate/spdx/{revision}"
        ),
        "creationInfo": {
            "created": creation_time(root),
            "creators": ["Tool: JanusGate generate-sbom.py"],
        },
        "documentDescribes": [project_id],
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }


def parse_arguments() -> argparse.Namespace:
    """Parse the required output path."""
    parser = argparse.ArgumentParser(description="Create the JanusGate SPDX SBOM.")
    parser.add_argument("output", type=Path)
    return parser.parse_args()


def main() -> int:
    """Create and write one deterministic SPDX JSON document."""
    arguments = parse_arguments()
    root = Path(__file__).resolve().parent.parent
    document = create_document(root)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"SPDX SBOM: {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
