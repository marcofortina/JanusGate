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
