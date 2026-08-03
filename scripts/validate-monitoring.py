#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Validate the shipped Prometheus and Grafana integration assets."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml


METRIC_PATTERN = re.compile(r"\bjanusgate_[a-z0-9_]+\b")


def load_yaml(path: Path) -> Any:
    """Load one required YAML document."""
    with path.open("r", encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def require_mapping(value: Any, description: str) -> dict[str, Any]:
    """Return a mapping or reject the malformed asset."""
    if not isinstance(value, dict):
        raise ValueError(f"{description} must be a mapping")
    return value


def validate_scrape_configuration(document: Any) -> None:
    """Validate the security-sensitive JanusGate scrape job fields."""
    root = require_mapping(document, "Prometheus configuration")
    jobs = root.get("scrape_configs")
    if not isinstance(jobs, list):
        raise ValueError("Prometheus scrape_configs must be a list")
    matches = [
        require_mapping(job, "Prometheus scrape job")
        for job in jobs
        if isinstance(job, dict) and job.get("job_name") == "janusgate"
    ]
    if len(matches) != 1:
        raise ValueError("Prometheus must define exactly one janusgate job")
    job = matches[0]
    authorization = require_mapping(job.get("authorization"), "authorization")
    tls = require_mapping(job.get("tls_config"), "tls_config")
    if job.get("scheme") != "https" or job.get("metrics_path") != "/api/v1/metrics":
        raise ValueError("JanusGate scraping must use the HTTPS metrics API")
    if authorization.get("type") != "Bearer" or not authorization.get(
        "credentials_file"
    ):
        raise ValueError("JanusGate scraping must load a bearer token from a file")
    for field in ("ca_file", "cert_file", "key_file", "server_name"):
        if not tls.get(field):
            raise ValueError(f"JanusGate tls_config requires {field}")
    if tls.get("insecure_skip_verify"):
        raise ValueError("JanusGate server-certificate validation cannot be disabled")


def validate_rules(document: Any) -> None:
    """Validate stable alert names and required rule content."""
    root = require_mapping(document, "Prometheus rules")
    groups = root.get("groups")
    if not isinstance(groups, list) or not groups:
        raise ValueError("Prometheus rules must contain groups")
    names: set[str] = set()
    for group_value in groups:
        group = require_mapping(group_value, "Prometheus rule group")
        rules = group.get("rules")
        if not isinstance(rules, list) or not rules:
            raise ValueError("every Prometheus rule group must contain rules")
        for rule_value in rules:
            rule = require_mapping(rule_value, "Prometheus alert rule")
            name = rule.get("alert")
            annotations = require_mapping(rule.get("annotations"), "rule annotations")
            if not isinstance(name, str) or not name or name in names:
                raise ValueError("Prometheus alert names must be unique and non-empty")
            if not isinstance(rule.get("expr"), str) or not rule["expr"].strip():
                raise ValueError(f"Prometheus alert {name} requires an expression")
            if not annotations.get("summary") or not annotations.get("description"):
                raise ValueError(f"Prometheus alert {name} requires runbook text")
            names.add(name)


def validate_dashboard(document: Any) -> None:
    """Validate dashboard identity, variables, panels, and Prometheus queries."""
    root = require_mapping(document, "Grafana dashboard")
    panels = root.get("panels")
    variables = require_mapping(root.get("templating"), "dashboard templating").get(
        "list"
    )
    if root.get("uid") != "janusgate-appliance" or not isinstance(panels, list):
        raise ValueError("Grafana dashboard identity or panels are invalid")
    if len(panels) < 8 or not isinstance(variables, list):
        raise ValueError("Grafana dashboard lacks the operational overview")
    variable_names = {
        variable.get("name") for variable in variables if isinstance(variable, dict)
    }
    if variable_names != {"datasource", "job", "instance"}:
        raise ValueError("Grafana dashboard variables are incomplete")
    identifiers: set[int] = set()
    for panel_value in panels:
        panel = require_mapping(panel_value, "Grafana panel")
        identifier = panel.get("id")
        targets = panel.get("targets")
        if not isinstance(identifier, int) or identifier in identifiers:
            raise ValueError("Grafana panel identifiers must be unique integers")
        if not panel.get("title") or not isinstance(targets, list) or not targets:
            raise ValueError(f"Grafana panel {identifier} has no query")
        for target_value in targets:
            target = require_mapping(target_value, "Grafana target")
            if not isinstance(target.get("expr"), str) or not target["expr"].strip():
                raise ValueError(f"Grafana panel {identifier} has an empty query")
        identifiers.add(identifier)


def validate_metric_references(root: Path, paths: list[Path]) -> None:
    """Reject integration queries which name metrics JanusGate does not emit."""
    implementation = (root / "src/daemon/metrics.c").read_text(encoding="utf-8")
    known = set(METRIC_PATTERN.findall(implementation))
    referenced: set[str] = set()
    for path in paths:
        referenced.update(METRIC_PATTERN.findall(path.read_text(encoding="utf-8")))
    unknown = sorted(referenced - known)
    if unknown:
        raise ValueError(f"unknown JanusGate metrics: {', '.join(unknown)}")


def main() -> int:
    """Validate all monitoring assets in this source tree."""
    root = Path(__file__).resolve().parent.parent
    scrape = root / "monitoring/prometheus/janusgate.yml.example"
    rules = root / "monitoring/prometheus/janusgate.rules.yml"
    dashboard = root / "monitoring/grafana/janusgate-dashboard.json"
    try:
        validate_scrape_configuration(load_yaml(scrape))
        validate_rules(load_yaml(rules))
        validate_dashboard(json.loads(dashboard.read_text(encoding="utf-8")))
        validate_metric_references(root, [rules, dashboard])
    except (
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as error:
        print(f"Monitoring asset validation failed: {error}", file=sys.stderr)
        return 1
    print("Monitoring asset validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
