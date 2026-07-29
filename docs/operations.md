<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Operations

## Startup and readiness

Services start in dependency order: `janusgate-netd`, `janusgated`, then
`janusgate-web`. Confirm all three, run `janusgatectl --socket
/run/janusgate/control.sock ping`, inspect `health`, and verify one allowed and
one blocked test name before admitting production traffic.

Do not treat HTTPS readiness alone as proof of policy enforcement. Monitor the
active policy generation, queue bindings, worker count, last source refresh,
and the selected fail-open or fail-closed mode.

## Monitoring and capacity

Collect the management metrics endpoint over the dedicated network. Alert on
queue drops, parse failures, state-limit rejections, source refresh failures,
audit verification failure, certificate expiry, repeated authentication
failures, low persistent storage, and service restart loops.

Size queue count to available CPUs and traffic, then load-test the actual
hardware. Keep TCP flows, per-source flows, reassembly bytes, fragments, source
downloads, decompressed bytes, policy rules, sessions, and event retention
within configured bounds. The reference policy benchmark is described in
[Performance](performance.md).

## Policy source updates

Use HTTPS sources, a bounded download size, an explicit schedule, and a
reviewed attribution. A refresh parses into a candidate snapshot; invalid or
oversized input does not replace the active generation. Review additions and
false positives before enabling broad sources. Keep local allow exceptions
small and documented.

## Backups and certificates

Create configuration backups after reviewed changes and encrypted full backups
before upgrades. Store passphrases separately and test restoration on an
isolated appliance. Restrict private-key backups to cases that require them.

Monitor certificate expiry. Install certificate and key together; JanusGate
checks their match and rolls back a failed reload. Retain console access while
changing the management address or certificate trust chain.

## Troubleshooting

1. Check link state, interface roles, bridge membership, and management
   separation.
2. Check service state and local `ping`.
3. Inspect health, queue counters, active policy generation, and recent events.
4. Validate configuration and audit history.
5. Create a diagnostic bundle and review its sanitized contents.
6. Use [Recovery](recovery.md) only when normal transactional rollback cannot
   restore service.

An absent daemon behaves according to the configured queue failure mode.
Switching modes changes the availability/security trade-off and must be an
explicit incident decision.
