<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Web administration

The administration site is served over HTTPS on the dedicated management
interface. The factory state exposes only account bootstrap. After the first
administrator is created, normal authentication and role checks apply.

## Authentication

Sign in with a username, password, and TOTP code when enabled. The browser
receives a secure, HTTP-only, same-site session cookie. State-changing
requests also require the session CSRF value. Operators can change their
password, provision or disable TOTP, inspect the current session, and sign out.

Browser login attempts are bounded per IPv4 address or IPv6 /64 and across the
appliance. Incorrect passwords receive an increasing retry delay, while a
correct password can still clear that state so an attacker cannot lock out an
administrator by username alone. Closing a browser does not replace an
explicit sign-out on a shared workstation.

## Dashboard and policy

The dashboard shows service health, policy generation, queue and flow
counters, recent events, and active configuration. Policy pages provide:

- destination and domain rule listing, creation, editing, and removal;
- exact-domain and optional subdomain behavior;
- global and scoped allow or block effects;
- UDP DNS actions: drop, REFUSED, NXDOMAIN, or sinkhole;
- policy simulation before activation;
- persistent observe-only rollout globally or by rule, source, group, client,
  network, MAC address, or VLAN;
- rule impact with lifetime hits, retained clients, traffic percentage, and
  conservative relationship findings;
- bounded detailed-statistics storage with cleanup preview;
- local blocklist import and export;
- remote source creation, update, enable, disable, and refresh.

Every write carries the revision last read by the browser. A concurrent change
returns a conflict instead of silently overwriting newer state.
Remote downloads, local imports, backup creation and restore, and diagnostic
archive creation run on a fixed-capacity management queue. The WebGUI follows
each retained job until completion while short status and policy requests
remain available.

The health response also compares the newest persistent policy revision with
the revision published to the daemon. If publication fails, further mutations
are suspended and the dashboard identifies the pending revision. Use **System
> Reload configuration** to validate and retry publication; successful reload
clears the durable inconsistency state.

### Staged policy rollout

Choose **Observe** when creating a prospective blocking rule, or apply
observe-only mode to its source, policy group, the global policy, or a client,
network, MAC, or VLAN scope. Matching traffic remains allowed while JanusGate
records the configured action, responsible rule, affected clients, and
would-block outcome. The setting is persistent and does not expire.

After representative traffic has passed, select **Impact** on the rule. Review
its lifetime and retained counts, traffic percentage, clients, duplicates,
conflicts, shadowing, reachability, allow exceptions, and possible false
positives. These findings are decision support and can conservatively omit an
ambiguous relationship. JanusGate never edits or deletes a rule in response.
Adjust, disable, or remove the rule, or change it to **Enforce** only after the
observed impact is acceptable.

The statistics-storage panel preserves lifetime aggregates and defaults to
three months of detailed hourly impact. Administrators can configure
retention, row and domain cardinality, database and free-space budgets, and
whether detail is collected. Cleanup is previewable and bounded. Reaching a
limit stops only new detail; lifetime counters remain active.

## Network

The network page displays bridge roles, the separate management-interface
role, queue layout, MTU, failure mode, and optional encrypted-DNS controls.
Validate a proposed document first. Applying bridge or packet-selection
changes starts a confirmation window; confirm the working path or let
JanusGate restore the previous configuration.

Management addressing, routes, and the HTTPS listen address are owned by the
deployment operating system and are not changed by this page. Keep local
console access and update those values together when moving the appliance to a
different management network.

## Alerts and external monitoring

The **Alerts** page lists persistent incidents newest first and filters by
state or fixed type. Selecting **Details** shows the responsible resource,
severity, lifecycle timestamps, occurrence count, and bounded condition data.
Operators and auditors can inspect this state; only administrators can replace
thresholds or webhook settings.

The configuration covers evaluation cadence, certificate lifetime, remote
source failures and staleness, free space across JanusGate filesystems, queue
transport failures, and rejected authentication attempts. Changes are
revision checked. Native evaluation deduplicates repeated conditions and
retains both opening and resolution; it never hides an intentional policy
block inside the queue-failure counter.

For external delivery, rotate and securely copy the one-time HMAC secret,
configure an HTTPS receiver and optional private CA bundle, save the settings,
then send a test. The page reports whether secret material exists but never
reveals it again. Prometheus, Alertmanager, and Grafana setup is documented in
[Monitoring and native alerting](monitoring.md).

## Identities and access

Administrators can list, add, update, or disable users; reset passwords; remove
TOTP enrollment; and create or revoke scoped API tokens. Token secret material
is returned only at creation. Use the least privileged role and scope that
supports the task.

## Certificates and remote API trust

The certificate page displays the active certificate, installs a matching PEM
certificate/key pair transactionally, and creates certificate-signing
requests. It also installs or removes the remote client CA bundle, lists its
authorities, creates user- or role-bound client-certificate mappings, and
revokes those mappings. Private, self-hosted, home-lab, and public CAs are
supported. New mappings are validated for TLS client authentication against
the currently installed trust store. HTTPS listeners reload automatically
after certificate or trust changes made through the WebGUI. Installation
validates and atomically
replaces files, but a listener activation failure does not roll those files
back automatically. The HTTPS service preflights the complete TLS state and
retries one clean listener generation after an activation failure; retain
console access and a known-good pair for failures outside that boundary.

Browser login remains protected by password and optional TOTP and never
requests a client certificate. The separate TCP 9443 automation listener
requires both a trusted mapped client certificate and an API token. See
[Remote API](remote-api.md) for the complete trust model and an OpenSSL
home-lab CA example.

## Backups and diagnostics

Configuration backups exclude private secrets. Full backups are encrypted
with a passphrase of at least 16 characters. A current full backup is portable:
its encrypted payload contains the complete database, the TOTP protection key,
and the installed public client CA bundle. It may include the server private
key only when explicitly requested. Treat the archive as authentication
material and keep its passphrase separately.

The interface can create, inspect, and restore backups. Restore validates the
archive, manifest, paths, schema, and integrity before replacing state. An
applied restore waits for active management writes, excludes new writes until
completion, and leaves authenticated reads and job polling available.
JanusGate creates and audits an automatic pre-restore checkpoint; the restore
audit identifies that checkpoint.

A full restore replaces users, sessions, API tokens, TOTP credentials, and
client-certificate mappings. It can therefore invalidate the browser session
or remote API identity that started it before the final job result is read.
Prefer the local console and `janusgatectl` for full recovery restores.
The privileged local CLI also exports a verified archive to an absolute
private path and imports an off-appliance archive under a new local ID. These
transfer operations are intentionally unavailable through the browser and the
remote API. See [Recovery](recovery.md) for the supported procedure.

Diagnostics create a bounded archive containing versions, sanitized
configuration, recent service information, and selected logs. Review it before
sharing. Event and audit pages support bounded filters; audit verification
checks the complete hash chain.

## Operational logging and troubleshooting

The System page reports the global level, diagnostic expiry, retained count,
and rate-limit suppression. Operators can inspect the bounded trace window.
Administrators can select destinations and capacity, set exact management,
dataplane, or runtime overrides, and enable diagnostic verbosity for at most
one hour.

Domain and client identifiers are redacted by default. Enabling them requires
an explicit confirmation and an expiring debug or trace configuration. The
page preserves component overrides created through the CLI or API even when
they are not among its built-in controls. See [Operations](operations.md) for
the bounded troubleshooting workflow and [Privacy](privacy.md) before sharing
any output.

## Service and appliance operations

Configuration reload and service restart are separate operations. Reboot and
shutdown require an administrator role and explicit confirmation. Prefer
orderly shutdown before removing power.

The canonical request and response schemas are in
[`api/openapi.yaml`](../api/openapi.yaml). Equivalent command-line operations
are listed in [CLI](cli.md).
