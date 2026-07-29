<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Security policy

## Supported versions

Security fixes are provided for the latest released JanusGate version. The
default branch receives the fix first and is not itself a production support
channel. Appliance operators should also track Alpine, Buildroot, Linux, and
library security updates.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting for this repository. Include:

- affected version and source revision;
- deployment type and architecture;
- concise impact and prerequisites;
- reproducible steps or a minimal test;
- relevant logs with credentials, client data, private keys, and internal
  addresses removed;
- whether the issue is already public or actively exploited.

Do not test against systems or data you do not own or have explicit permission
to assess. Avoid persistence, service disruption, data access beyond the
minimum proof, and public disclosure while the report is under review.

## Response and disclosure

Receipt is normally acknowledged within five business days. The maintainer
will reproduce and classify the issue, coordinate a fix and regression test,
prepare affected-version guidance, and agree on a disclosure date with the
reporter when practical. Complex dependency or hardware issues may require
upstream coordination.

A release addressing a confirmed vulnerability will describe affected
versions, impact, mitigation, upgrade steps, and credit when requested.
Security changes are not considered complete without a focused regression
test. No absolute remediation deadline is promised, but high-impact issues are
prioritized over feature work.

## Operational incidents

For suspected compromise, isolate management access, retain logs and the audit
chain, revoke sessions and tokens, rotate credentials and private keys, verify
the software and configuration from trusted media, and restore only reviewed
backups. See [Recovery](docs/recovery.md).
