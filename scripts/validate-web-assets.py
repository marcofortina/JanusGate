#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Validate WebGUI navigation, module imports, and static-asset exposure."""

from __future__ import annotations

import argparse
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path


ASSET_ENTRY = re.compile(
    r'\{\s*"(?P<uri>/[^"]*)",\s*"(?P<path>[^"]+)"', re.MULTILINE
)
MODULE_IMPORT = re.compile(r'\bfrom\s+["\'](?P<path>\./[^"\']+)["\']')
PAGE_ENTRY = re.compile(r'\[\s*"(?P<name>[a-z0-9-]+)"\s*,')
PAGE_REGISTRY = re.compile(
    r"const\s+pages\s*=\s*new\s+Map\s*\(\s*\[(?P<entries>.*?)\]\s*\)",
    re.DOTALL,
)


class ApplicationMarkup(HTMLParser):
    """Collect navigable pages and local assets from the application shell."""

    def __init__(self) -> None:
        """Initialize empty markup collections."""
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.pages: list[str] = []
        self.assets: list[str] = []

    def handle_starttag(
        self, tag: str, attributes: list[tuple[str, str | None]]
    ) -> None:
        """Collect relevant attributes from one start tag."""
        values = dict(attributes)
        link = values.get("data-page-link")
        identifier = values.get("id")

        if link:
            self.links.append(link)
        if "data-page" in values and identifier and identifier.startswith("page-"):
            self.pages.append(identifier[len("page-") :])
        for name in ("href", "src"):
            value = values.get(name)
            if value and value.startswith("/"):
                self.assets.append(value)


def duplicates(values: list[str]) -> list[str]:
    """Return repeated values in stable order."""
    seen: set[str] = set()
    repeated: set[str] = set()

    for value in values:
        if value in seen:
            repeated.add(value)
        seen.add(value)
    return sorted(repeated)


def parse_markup(path: Path) -> ApplicationMarkup:
    """Parse the application shell as HTML."""
    parser = ApplicationMarkup()

    parser.feed(path.read_text(encoding="utf-8"))
    parser.close()
    return parser


def parse_allowlist(path: Path) -> dict[str, str]:
    """Return static server URI-to-file mappings."""
    mappings: dict[str, str] = {}

    for match in ASSET_ENTRY.finditer(path.read_text(encoding="utf-8")):
        uri = match.group("uri")
        if uri in mappings:
            raise ValueError(f"duplicate server asset URI: {uri}")
        mappings[uri] = match.group("path")
    if not mappings:
        raise ValueError("server static-asset allowlist is empty")
    return mappings


def manifest_assets(path: Path) -> list[str]:
    """Return local paths referenced by the web manifest."""
    document = json.loads(path.read_text(encoding="utf-8"))
    assets = [document.get("start_url")]

    for icon in document.get("icons", []):
        if isinstance(icon, dict):
            assets.append(icon.get("src"))
    return [
        value
        for value in assets
        if isinstance(value, str) and value.startswith("/")
    ]


def module_graph(directory: Path, errors: list[str]) -> dict[Path, set[Path]]:
    """Resolve every relative JavaScript import inside the WebGUI root."""
    graph: dict[Path, set[Path]] = {}

    for module in sorted(directory.glob("*.js")):
        dependencies: set[Path] = set()
        contents = module.read_text(encoding="utf-8")
        for match in MODULE_IMPORT.finditer(contents):
            dependency = (module.parent / match.group("path")).resolve()
            if not dependency.is_file():
                errors.append(
                    f"{module.name}: missing imported module "
                    f"{match.group('path')}"
                )
            else:
                dependencies.add(dependency)
        graph[module.resolve()] = dependencies
    return graph


def reachable_modules(graph: dict[Path, set[Path]], entry: Path) -> set[Path]:
    """Return every module reachable from one entry point."""
    reachable: set[Path] = set()
    pending = [entry.resolve()]

    while pending:
        module = pending.pop()
        if module in reachable:
            continue
        reachable.add(module)
        pending.extend(graph.get(module, set()))
    return reachable


def application_pages(path: Path) -> list[str]:
    """Return page identifiers registered by the application router."""
    contents = path.read_text(encoding="utf-8")
    registry = PAGE_REGISTRY.search(contents)

    if registry is None:
        raise ValueError("application page registry was not found")
    return [
        match.group("name")
        for match in PAGE_ENTRY.finditer(registry.group("entries"))
    ]


def validate(root: Path) -> list[str]:
    """Return every structural WebGUI validation error."""
    web = root / "web"
    javascript = web / "js"
    errors: list[str] = []

    try:
        markup = parse_markup(web / "index.html")
        allowlist = parse_allowlist(root / "src/web/web_server.c")
        registered_pages = application_pages(javascript / "app.js")
        referenced_assets = set(markup.assets)
        referenced_assets.update(manifest_assets(web / "manifest.webmanifest"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return [str(error)]

    if duplicates(markup.links):
        errors.append(f"duplicate navigation pages: {duplicates(markup.links)}")
    if duplicates(markup.pages):
        errors.append(f"duplicate page sections: {duplicates(markup.pages)}")
    if duplicates(registered_pages):
        errors.append(
            f"duplicate application pages: {duplicates(registered_pages)}"
        )
    if set(markup.links) != set(markup.pages):
        errors.append(
            "navigation and page sections differ: "
            f"{sorted(set(markup.links) ^ set(markup.pages))}"
        )
    if set(markup.links) != set(registered_pages):
        errors.append(
            "navigation and application registry differ: "
            f"{sorted(set(markup.links) ^ set(registered_pages))}"
        )

    for uri in sorted(referenced_assets):
        if uri not in allowlist:
            errors.append(f"browser asset is not allowlisted: {uri}")
    for uri, relative in sorted(allowlist.items()):
        if not (web / relative).is_file():
            errors.append(f"{uri}: allowlisted file is missing: {relative}")

    graph = module_graph(javascript, errors)
    expected_modules = set(graph)
    reachable = reachable_modules(graph, javascript / "app.js")
    if expected_modules != reachable:
        errors.append(
            "JavaScript modules are not reachable from app.js: "
            f"{sorted(path.name for path in expected_modules - reachable)}"
        )
    allowlisted_files = set(allowlist.values())
    for module in sorted(expected_modules):
        relative = module.relative_to(web.resolve()).as_posix()
        if relative not in allowlisted_files:
            errors.append(f"JavaScript module is not allowlisted: {relative}")
    return errors


def main() -> int:
    """Validate one JanusGate source tree."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    arguments = parser.parse_args()
    root = arguments.source.resolve()

    errors = validate(root)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("WebGUI asset validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
