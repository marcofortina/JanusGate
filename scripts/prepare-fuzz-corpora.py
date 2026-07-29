# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Prepare deterministic per-target libFuzzer seed corpora."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


CORPORA = {
    "janusgate-fuzz-packet": ("blocked-dns.hex",),
    "janusgate-fuzz-ipv6-extensions": ("ipv6-extension.hex",),
    "janusgate-fuzz-dns": ("dns-query.hex",),
    "janusgate-fuzz-dns-name": ("dns-query.hex",),
    "janusgate-fuzz-tcp-dns": ("tcp-dns.hex",),
    "janusgate-fuzz-tcp-reassembly": ("tcp-dns.hex",),
    "janusgate-fuzz-fragments": ("ipv4-fragment.hex",),
    "janusgate-fuzz-tls-client-hello": ("tls-client-hello.hex",),
    "janusgate-fuzz-blocklist-line": ("blocklist.txt",),
    "janusgate-fuzz-hosts": ("hosts.txt",),
    "janusgate-fuzz-rpz": ("policy.rpz",),
    "janusgate-fuzz-control-protocol": ("ipc-ping.hex",),
    "janusgate-fuzz-rest-json": ("management-request.json",),
    "janusgate-fuzz-backup-manifest": ("backup-header.hex",),
}


def decode_hex(path: Path) -> bytes:
    """Decode whitespace-separated hexadecimal fixture bytes."""
    fields = [
        line.partition("#")[0] for line in path.read_text(encoding="ascii").splitlines()
    ]
    return bytes.fromhex(" ".join(fields))


def copy_fixture(source: Path, destination: Path) -> None:
    """Copy text fixtures and decode files carrying hexadecimal wire bytes."""
    if source.suffix == ".hex":
        destination.write_bytes(decode_hex(source))
    elif source.suffix == ".json":
        lines = source.read_text(encoding="utf-8").splitlines()
        destination.write_text(
            "\n".join(line for line in lines if not line.startswith("# ")) + "\n",
            encoding="utf-8",
        )
    else:
        shutil.copyfile(source, destination)


def prepare(source_directory: Path, output_directory: Path) -> None:
    """Create every stable corpus directory from reviewed test fixtures."""
    for target, names in CORPORA.items():
        target_directory = output_directory / target
        target_directory.mkdir(parents=True, exist_ok=True)
        for index, name in enumerate(names):
            copy_fixture(
                source_directory / name,
                target_directory / f"seed-{index:02d}",
            )


def parse_arguments() -> argparse.Namespace:
    """Parse fixture source and corpus output directories."""
    parser = argparse.ArgumentParser(
        description="Prepare deterministic JanusGate fuzz corpora."
    )
    parser.add_argument("source_directory", type=Path)
    parser.add_argument("output_directory", type=Path)
    return parser.parse_args()


def main() -> int:
    """Prepare all corpora or report an invalid fixture."""
    arguments = parse_arguments()
    try:
        prepare(arguments.source_directory, arguments.output_directory)
    except (OSError, ValueError) as error:
        print(f"Corpus preparation failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
