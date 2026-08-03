<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Operations

## Startup and readiness

Services start in dependency order: `janusgate-netd`, `janusgated`, then
`janusgate-web`. Confirm all three, run `janusgatectl --socket
/run/janusgate/control/control.sock ping` on Linux or
`janusgatectl --socket /var/run/janusgate/control/control.sock ping` on
OpenBSD, inspect `health`, and verify one allowed and one blocked test name
before admitting production traffic.

Do not treat HTTPS readiness alone as proof of policy enforcement. Monitor the
active policy generation, queue bindings, worker count, last source refresh,
and the selected fail-open or fail-closed mode.

## Monitoring and capacity

Collect the authenticated management metrics endpoint over the dedicated
network with a mapped mTLS identity and a token restricted to `metrics:read`.
Use the shipped Prometheus scrape job and rules with Alertmanager, and import
the Grafana dashboard. The complete setup, native incident semantics, signed
webhook contract, and private-CA procedure are documented in
[Monitoring and native alerting](monitoring.md).

Native evaluation retains deduplicated `open` and `resolved` incidents for
management degradation, policy synchronization, audit integrity, certificate
expiry, source health, JanusGate filesystem headroom, queue transport failure,
and repeated authentication failure. Review the incident detail before
changing thresholds. Intentional packet-policy drops are not queue failures.

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
before upgrades. Use a unique passphrase of at least 16 characters, store it
separately, export the archive through the local socket, and test restoration
on an isolated appliance. A current full archive carries the database, TOTP
protection key, and public client CA bundle; restrict server-private-key
inclusion to cases that require complete TLS identity recovery. Use the local
console for full restores: restored identities can invalidate the remote
session, token, or client-certificate mapping before its job result is read.
Keep transfer directories owned by the JanusGate service account with no group
or other access, and move exported archives into separately controlled
off-appliance storage after verification.

Monitor certificate expiry. Install certificate and key together; JanusGate
checks their match before replacement. Retain a recovery copy and console
access while changing OS-owned management addressing or the certificate trust
chain. A WebGUI certificate change preflights all listener files before it
stops the active generation; failed preflight leaves the active listeners
running. A later activation failure does not automatically roll back the
installed files.

Treat the remote client CA key as offline trust material. Review mappings and
tokens independently, revoke both when retiring an automation identity, and
test TCP 9443 with a valid and an unmapped certificate after trust changes.
Private and home-lab CA procedures are in [Remote API](remote-api.md).

## Operational logging

`janusgated` emits one JSON object per record to stderr, syslog, or both.
Production defaults to `info`, 100 records per second, and a 16-record
in-memory window. The web and network-helper processes use the same structured
format for conservative lifecycle and failure events.

| Level | Intended use | Normal operation |
| --- | --- | --- |
| `error` | Failed operations requiring attention | Retained |
| `warning` | Recoverable degradation | Retained |
| `info` | Lifecycle and reviewed configuration changes | Default |
| `debug` | Detailed temporary diagnosis | Must expire |
| `trace` | Fine-grained request or packet decisions | Must expire |

The System page shows the active configuration and counters. Operators may
inspect retained traces; administrators may change the configuration. Use a
narrow component override instead of raising the global level:

| Component | Evidence |
| --- | --- |
| `management` | Method, path, status, and request correlation ID |
| `dataplane` | Queue, verdict, reason, rule ID, and flow correlation ID |
| `runtime` | Enforcement lifecycle |

The CLI exposes the same state:

```sh
janusgatectl --endpoint https://192.168.77.1:9443 \
  --token-file /secure/janusgate.token \
  --client-cert /secure/operator.pem --client-key /secure/operator.key \
  --ca-file /secure/root-ca.pem logging show
janusgatectl --endpoint https://192.168.77.1:9443 \
  --token-file /secure/janusgate.token \
  --client-cert /secure/operator.pem --client-key /secure/operator.key \
  --ca-file /secure/root-ca.pem logging traces
```

`logging set FILE` reads the current revision and applies a strict document.
This example traces management requests for 15 minutes while retaining
identifier redaction:

```json
{
  "global_level": "info",
  "destinations": ["syslog"],
  "rate_limit_per_second": 100,
  "trace_capacity": 16,
  "diagnostic_duration_seconds": 900,
  "include_identifiers": false,
  "overrides": [
    {
      "component": "management",
      "level": "trace"
    }
  ]
}
```

Use a `dataplane=trace` override only while reproducing a packet-policy
decision. The packet payload is never logged. Domain and client fields remain
`[redacted]` unless an administrator explicitly enables identifiers; that
choice is valid only inside the same expiring diagnostic interval.

Applying any logging configuration clears the in-memory window and counters.
Expiration clamps `debug` and `trace` to `info` without requiring a service
restart. Set `global_level` to `info`, clear diagnostic overrides, set the
duration to zero, and disable identifiers to return explicitly to production
settings. Syslog and service-supervisor retention remain external to
JanusGate and must be configured separately.

## Troubleshooting

Use the least invasive evidence first:

1. Check physical link state, interface roles, bridge membership, and
   management separation.
2. Check all three services and the local control-socket `ping`.
3. Inspect `health`, `status`, metrics, recent events, policy generation, and
   the audit chain.
4. Run policy simulation before tracing a suspected rule decision.
5. Enable one component trace for 5–15 minutes, reproduce once, then match the
   correlation ID across records.
6. Restore production logging or allow the diagnostic interval to expire.
7. Create and inspect a diagnostic bundle before escalating.

| Symptom | Check first | Focus |
| --- | --- | --- |
| Traffic does not pass | Links, bridge, health | Network and queues |
| Wrong domain verdict | Policy simulation | Dataplane reason and rule |
| API operation fails | Request ID and audit | Management correlation |
| Queue loss | Metrics and status | Load and capacity |
| Source refresh fails | Source health and events | URL, limits, schedule |
| Policy not synchronized | `health` revisions | Reload configuration |
| Trace is empty | `logging show` | Expiry, level, capacity |
| Syslog is empty | Destinations | Platform logger |

`diagnostics create` adds `logging.json` and a maximum of 16 recent
`traces.json` records to the bounded archive. Trace detail objects are removed
from that archive even when live identifier inclusion was enabled. Review the
manifest and every included document before sharing it.

An absent daemon behaves according to the configured queue failure mode.
Switching modes changes the availability/security trade-off and must be an
explicit incident decision.

Use [Recovery](recovery.md) only when normal transactional rollback cannot
restore service.
