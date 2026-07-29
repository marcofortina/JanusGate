# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Validate the committed JanusGate OpenAPI 3.1 contract."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Iterator

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


HTTP_METHODS = frozenset(
    {"delete", "get", "head", "options", "patch", "post", "put", "trace"}
)
PATH_PARAMETER = re.compile(r"{([^{}]+)}")


class ContractError(ValueError):
    """Report one invalid OpenAPI contract invariant."""


class UniqueKeyLoader(yaml.SafeLoader):
    """Load safe YAML while rejecting duplicate mapping keys."""


def construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    """Construct one mapping and reject ambiguous duplicate keys."""
    mapping: dict[Any, Any] = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ContractError(
                f"duplicate key {key!r} at line {key_node.start_mark.line + 1}"
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping
)


def require_mapping(value: Any, location: str) -> dict[str, Any]:
    """Return one mapping or report its contract location."""
    if not isinstance(value, dict):
        raise ContractError(f"{location} must be a mapping")
    return value


def require_nonempty_string(value: Any, location: str) -> str:
    """Return one nonempty string or report its contract location."""
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{location} must be a nonempty string")
    return value


def walk(value: Any, location: str = "$") -> Iterator[tuple[str, Any]]:
    """Yield every node with a stable diagnostic location."""
    yield location, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, f"{location}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{location}/{index}")


def resolve_local_reference(document: dict[str, Any], reference: str) -> Any:
    """Resolve one RFC 6901 fragment without permitting external input."""
    if not reference.startswith("#/"):
        raise ContractError(f"external reference is not permitted: {reference}")

    current: Any = document
    for encoded_part in reference[2:].split("/"):
        part = encoded_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise ContractError(f"unresolved reference: {reference}")
        current = current[part]
    return current


def validate_references(document: dict[str, Any]) -> None:
    """Require every reference to resolve inside the committed contract."""
    for location, value in walk(document):
        if isinstance(value, dict) and "$ref" in value:
            reference = require_nonempty_string(value["$ref"], f"{location}/$ref")
            resolve_local_reference(document, reference)


def parameter_identity(
    document: dict[str, Any], parameter: Any, location: str
) -> tuple[str, str, bool]:
    """Return the name, placement, and requirement of one parameter."""
    item = require_mapping(parameter, location)
    if "$ref" in item:
        item = require_mapping(
            resolve_local_reference(
                document,
                require_nonempty_string(item["$ref"], f"{location}/$ref"),
            ),
            location,
        )
    name = require_nonempty_string(item.get("name"), f"{location}/name")
    placement = require_nonempty_string(item.get("in"), f"{location}/in")
    return name, placement, item.get("required") is True


def validate_path_parameters(
    document: dict[str, Any],
    path: str,
    path_item: dict[str, Any],
    operation: dict[str, Any],
    location: str,
) -> None:
    """Match every path template variable to one required parameter."""
    declared: set[str] = set()
    path_parameters = path_item.get("parameters", [])
    operation_parameters = operation.get("parameters", [])

    if not isinstance(path_parameters, list) or not isinstance(
        operation_parameters, list
    ):
        raise ContractError(f"{location}/parameters must be a list")
    parameters = path_parameters + operation_parameters
    for index, parameter in enumerate(parameters):
        name, placement, required = parameter_identity(
            document, parameter, f"{location}/parameters/{index}"
        )
        if placement == "path":
            if not required:
                raise ContractError(
                    f"{location}: path parameter {name!r} must be required"
                )
            declared.add(name)

    expected = set(PATH_PARAMETER.findall(path))
    if declared != expected:
        raise ContractError(
            f"{location}: path parameters are {sorted(declared)}, "
            f"expected {sorted(expected)}"
        )


def validate_operations(document: dict[str, Any]) -> None:
    """Validate path structure, operation metadata, and response coverage."""
    paths = require_mapping(document.get("paths"), "$/paths")
    declared_tags = {
        require_nonempty_string(item.get("name"), "$/tags/name")
        for item in document.get("tags", [])
        if isinstance(item, dict)
    }
    operation_ids: set[str] = set()

    if not paths:
        raise ContractError("$/paths must not be empty")
    for path, raw_path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise ContractError(f"invalid API path: {path!r}")
        path_item = require_mapping(raw_path_item, f"$/paths/{path}")
        for method, raw_operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            location = f"$/paths/{path}/{method}"
            operation = require_mapping(raw_operation, location)
            operation_id = require_nonempty_string(
                operation.get("operationId"), f"{location}/operationId"
            )
            require_nonempty_string(operation.get("summary"), f"{location}/summary")
            if operation_id in operation_ids:
                raise ContractError(f"duplicate operationId: {operation_id}")
            operation_ids.add(operation_id)

            tags = operation.get("tags")
            if not isinstance(tags, list) or len(tags) != 1:
                raise ContractError(f"{location}/tags must contain one tag")
            tag = require_nonempty_string(tags[0], f"{location}/tags/0")
            if tag not in declared_tags:
                raise ContractError(f"{location} uses undeclared tag {tag!r}")

            responses = require_mapping(
                operation.get("responses"), f"{location}/responses"
            )
            if "default" not in responses:
                raise ContractError(f"{location} must document error responses")
            if not any(
                isinstance(status, str) and status.startswith("2")
                for status in responses
            ):
                raise ContractError(f"{location} must document a success response")
            validate_path_parameters(document, path, path_item, operation, location)

    if not operation_ids:
        raise ContractError("the contract contains no operations")


def validate_component_schemas(document: dict[str, Any]) -> None:
    """Check every Schema Object against the JSON Schema 2020-12 meta-schema."""
    components = require_mapping(document.get("components"), "$/components")
    schemas = require_mapping(components.get("schemas"), "$/components/schemas")

    for name, schema in schemas.items():
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as error:
            raise ContractError(
                f"invalid component schema {name!r}: {error.message}"
            ) from error


def validate_document(document: dict[str, Any]) -> None:
    """Validate all project-level OpenAPI contract invariants."""
    version = require_nonempty_string(document.get("openapi"), "$/openapi")
    if not version.startswith("3.1."):
        raise ContractError(f"$/openapi must select version 3.1, found {version!r}")

    info = require_mapping(document.get("info"), "$/info")
    require_nonempty_string(info.get("title"), "$/info/title")
    require_nonempty_string(info.get("version"), "$/info/version")
    if not isinstance(document.get("servers"), list) or not document["servers"]:
        raise ContractError("$/servers must contain at least one server")
    if not isinstance(document.get("security"), list):
        raise ContractError("$/security must be a list")

    validate_references(document)
    validate_operations(document)
    validate_component_schemas(document)


def load_document(path: Path) -> dict[str, Any]:
    """Load one UTF-8 OpenAPI YAML document with strict mapping keys."""
    try:
        with path.open("r", encoding="utf-8") as stream:
            document = yaml.load(stream, Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ContractError(f"cannot load {path}: {error}") from error
    return require_mapping(document, "$")


def parse_arguments() -> argparse.Namespace:
    """Parse the validator command line."""
    parser = argparse.ArgumentParser(
        description="Validate the JanusGate OpenAPI 3.1 contract."
    )
    parser.add_argument("contract", type=Path, help="OpenAPI YAML file")
    return parser.parse_args()


def main() -> int:
    """Validate the requested contract and return a conventional status."""
    arguments = parse_arguments()
    try:
        document = load_document(arguments.contract)
        validate_document(document)
    except ContractError as error:
        print(f"OpenAPI validation failed: {error}", file=sys.stderr)
        return 1
    print(f"OpenAPI validation passed: {arguments.contract}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
