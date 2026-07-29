<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# JanusGate release notes

## 0.1.0

Initial production baseline of the JanusGate transparent inline DNS policy
appliance.

- Enforces domain, destination, encrypted-DNS endpoint, and visible-SNI policy
  for bridged IPv4, IPv6, VLAN, UDP, and TCP traffic.
- Provides transactional network configuration, atomic policy reload,
  authenticated local and HTTPS administration, audit records, metrics,
  backup, restore, diagnostics, and certificate management.
- Ships Alpine packages and VM assembly together with reproducible x86_64 and
  AArch64 Buildroot firmware definitions.
- Includes deterministic unit, integration, security, fuzz, sanitizer,
  performance, static-analysis, documentation, SBOM, and image quality gates.

The encrypted payload of VPN tunnels, encrypted client hello, and general
HTTPS traffic is deliberately not intercepted.
