<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# JanusGate release notes

## 0.1.2

Hardening release for authenticated administration, recoverable mutations, and
runtime consistency.

- Uses opaque, owner-bound administration jobs with dequeue-time
  reauthorization, bounded retention, and fair scheduling.
- Queues certificate requests instead of blocking the management worker.
- Journals and compensates cross-resource mutations, preserves recovery
  snapshots, and suspends further mutations when consistency cannot be
  restored safely.
- Persists policy publication state and exposes retryable runtime divergence in
  appliance health.
- Rejects unsuitable HTTPS server identities before activation and retries a
  failed listener activation from a clean state.
- Reports transactional audit failures without claiming that rolled-back
  mutations took effect.

## 0.1.1

Maintenance release consolidating the management, certificate, and appliance
runtime boundaries introduced in the initial production baseline.

- Commits SQLite-only mutations and their audit records atomically.
- Moves remote-source updates and other blocking administration work into
  bounded, observable job queues.
- Authorizes the configured management hostname and validates mapped client
  certificates against the active trust chain and client-authentication use.
- Preflights HTTPS listener changes before replacing a working listener.
- Verifies the installed CivetWeb runtime on OpenBSD and records end-to-end
  HTTPS forwarding measurements for the x86_64 appliance.

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
