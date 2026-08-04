<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# JanusGate release notes

## 0.2.1

Maintenance release completing the persistence, restore, and delivery safety
of the policy-observability and native-alerting subsystems.

- Gives policy statistics immutable rule identities, including deterministic
  identities for refreshed blocklist entries, so lifetime history cannot be
  inherited by an unrelated rule.
- Quiesces and drains the statistics collector across restore generations,
  rejects stale queued samples, and exposes restore-specific drop metrics.
- Bounds detailed statistics by total rows, per-rule hourly rows, distinct
  domains, database size, and filesystem reserve while retaining lifetime
  aggregates; detailed collection can be disabled independently.
- Claims webhook deliveries durably, performs verified HTTPS outside the
  management mutation gate, recovers interrupted claims, and computes retry
  timing from each completed attempt.
- Uses globally unique webhook event identities and restores webhook transport
  and outbox state coherently while retaining current operational history.
- Separates alert evaluation and webhook delivery health in Prometheus,
  Alertmanager, and Grafana, and initializes libcurl once per process.

## 0.2.0

Feature release for staged policy rollout, explainable impact, portable
recovery, and integrated appliance monitoring.

- Adds persistent observe-only enforcement globally and by rule, source,
  group, client, network, MAC address, or VLAN without automatic expiry.
- Explains configured and effective decisions, records lifetime rule hits and
  retained client impact, and identifies conservative conflicts, duplicates,
  shadowing, reachability, and allow exceptions for operator review.
- Provides configurable detailed-statistics retention and previewed bounded
  cleanup without deleting lifetime aggregates or changing policy.
- Makes encrypted full backups portable with the identity protection key,
  public client trust, explicit server-key handling, serialized restore, and
  audited recovery checkpoints.
- Adds persistent native incidents for appliance consistency, policy
  synchronization, audit integrity, certificate expiry, source health,
  filesystem headroom, queue transport failures, and rejected credentials.
- Delivers incident transitions through a durable, deduplicated HTTPS webhook
  outbox with HMAC signatures, bounded retry, and private-CA support.
- Exposes stable fixed-cardinality Prometheus metrics, Alertmanager rules, and
  a provisionable Grafana appliance dashboard over least-privilege mTLS
  monitoring access.
- Completes WebGUI, CLI, API, documentation, shell completion, Linux, and
  OpenBSD administration paths for the new policy and alerting workflows.

## 0.1.3

Maintenance release improving restore safety and simplifying internal
subsystem boundaries.

- Serializes applied restores and retains the provenance of automatic recovery
  checkpoints.
- Creates backup archives crash consistently, audits recovery checkpoints, and
  warns administrators before full-appliance restores.
- Isolates control-plane state, durable recovery, authenticated jobs, and
  backup operations behind focused management modules.
- Separates management, database, and account operations by responsibility
  while preserving their public interfaces and persistent schema.
- Organizes policy, identity, and appliance CLI commands and separates
  certificate and blocklist management without changing their behavior.
- Documents restore recovery semantics and the resulting audit trail.

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
