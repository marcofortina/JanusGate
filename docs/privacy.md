<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Privacy

DNS names, source addresses, user identities, policy matches, and
administrative actions can reveal sensitive behavior. Collect only what is
needed for operation and incident response.

JanusGate separates counters, bounded operational events, and tamper-evident
administrative audit records. Operators should choose the least detailed event
mode that meets their purpose, use short retention for client-identifying
events, and prefer aggregate counters for routine monitoring. Audit retention
should follow the organization's accountability requirement.

## Logging and trace privacy

Operational records contain a timestamp, severity, process, component, stable
event code, message, and a correlation ID when applicable. Request bodies,
packet payloads, credentials, and complete authentication headers are not
recorded.

Secret-named detail fields are always redacted recursively. Domain and client
identifiers are separately redacted by default. An administrator can include
identifiers only while `debug` or `trace` is configured with an automatic
expiration of 60–3600 seconds. When that interval expires, diagnostic levels
are clamped to `info` and identifiers are redacted again.

The live trace window holds at most 32 process-local records in memory. It is
cleared on configuration replacement and process restart. Its rate limiter is
independent of packet counters; suppressed-record counts remain visible so an
operator knows that the trace is incomplete.

Live trace access requires the operator permission, and changing logging
requires administrator system-write permission. Administrative changes are
revision-checked and appended to the audit chain. Audit records are separate
from operational verbosity and cannot be disabled through logging settings.

Diagnostic archives include the active logging configuration and trace
metadata, but always remove trace detail objects. Stderr capture and syslog
forwarding may retain records longer than the in-memory window; their access,
transport, rotation, and deletion are the deployer's responsibility.

Do not place passwords, API tokens, session cookies, TOTP seeds, backup
passphrases, private keys, or complete request bodies in logs. Remote list
credentials and TLS material must remain in restricted files. Diagnostic
bundles omit or redact secret fields, but an operator must still inspect a
bundle before sharing it.

Access to management data should be limited by role and by network placement.
Use HTTPS with a trusted certificate; consider mTLS for high-value
deployments. Forward logs only to an authorized destination over a protected
channel, and document who can query events or export backups.

Blocking by domain necessarily exposes classic DNS names to the appliance.
JanusGate does not decrypt application TLS. Attempts to gain visibility by
forcing all users away from encrypted transports have their own privacy and
policy consequences and must be an explicit organizational decision.

Applicable notice, retention, access, deletion, and lawful-use obligations
depend on the deployment jurisdiction and organization. JanusGate supplies
technical controls, not legal authorization.
