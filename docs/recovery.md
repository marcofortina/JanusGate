<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Recovery

Keep local console access, a recent configuration backup, the matching full
backup passphrase, and a known-good image before making high-impact changes.

## Network rollback and management recovery

An applied JanusGate bridge or packet-selection change remains provisional
until confirmed. Verify data forwarding while retaining the existing
management connection, then run:

```sh
janusgatectl network confirm
```

If the change is not healthy, wait for automatic rollback or use the local
console and `network rollback`. Do not attach the management interface to the
data bridge as a workaround.

Management addresses, routes, and the HTTPS listen address are OS-owned and
are outside that transaction. Recover an inaccessible management address from
the local console by restoring the deployment network configuration and
matching service bind address; then verify that the certificate covers the
restored identity.

## Service and configuration recovery

Use local `janusgatectl --socket /run/janusgate/control/control.sock ping`
(or the corresponding `/var/run` path on OpenBSD) to separate
web or certificate failure from daemon failure. Validate configuration before
reload. If a service will not start, inspect its log and permissions, retain a
copy of the failing state, and restore the last reviewed configuration rather
than editing the database directly.

## Database recovery

Never replace the live database file while JanusGate is running. Normal
recovery uses `janusgatectl backup restore ID` while the daemon is available,
so archive paths, manifest, schema, integrity, and revision rules are checked.
The applied phase waits for active management writes, prevents new writes, and
creates an audited pre-restore checkpoint. Reads and local job polling remain
available.

Run full restores from a retained local console through the default Unix
socket. A full restore replaces users, sessions, API tokens, TOTP credentials,
and client-certificate mappings; the remote identity that submitted the job
may therefore be invalid before it can read the result. Only a last-resort
manual database replacement requires stopping every JanusGate service first.
Preserve the damaged database and its write-ahead-log companions before any
manual work, then start the daemon first and verify health and audit state
before starting the web service.

## Management consistency recovery

`health.management` reports whether writes are safe. During a normal applied
restore, `restore_in_progress` is true and `mutations_allowed` is false; new
writes receive `503 restore_in_progress`. This is temporary and does not mark
the appliance degraded. A non-empty `reasons` list identifies a failure that
requires operator attention:

| Reason | Required response |
| --- | --- |
| `database_rollback` | Preserve state; restart and verify database integrity. |
| `external_recovery` | Restart locally; retain files if it persists. |
| `policy_sync` | Validate and run `janusgatectl config reload`. |

Ordinary policy, identity, and configuration writes remain suspended while
management is degraded. Authenticated reads and the explicit validation,
diagnostic, rollback, reload, restart, reboot, and shutdown recovery paths
remain available.

Cross-resource operations retain their original actor, source, request ID, and
requested action in the durable journal. At startup, JanusGate restores or
discards an interrupted operation before starting the job worker, records
`management.operation.recover` or `management.operation.discard`, and removes
the journal and snapshots only after their audit transaction commits. Database
checkpoints use the configured database path plus `.recovery`; certificate,
pending-key, and client-CA snapshots use their configured path plus
`.rollback`. Do not edit or delete these files while an operation is pending.

Backup creation uses the same durable intent. Startup reconciliation removes
only owner-private regular staging files named `.janusgate-` plus 16 lowercase
hexadecimal characters and generated `backup-TIMESTAMP-RANDOM.jgb` archives
that have no committed metadata. It leaves symlinks, insecure files, and
unrecognized names untouched for manual inspection.

Recovery is complete only when `health.management.reasons` is empty,
`mutations_allowed` is true, the audit chain verifies, expected policy and
certificate state are active, and no operation snapshot remains. Repeated
`external_recovery` after a restart requires preserving the files and using
local console diagnostics rather than deleting the journal.

## Certificate recovery

A rejected certificate operation leaves the active pair unchanged. An
accepted operation validates and atomically replaces the files before the web
listener reload. Reload preflight keeps the active listeners running when the
new files are invalid, but does not automatically restore files after a later
activation failure.
If HTTPS cannot start, restore a matching certificate and key from console
with restrictive ownership and modes, validate their public keys with OpenSSL,
and restart only `janusgate-web`. Replace a potentially exposed key rather
than reusing it.

## Firmware data recovery

Buildroot configuration and mutable data reside on the `JANUSGATE_DATA`
partition. Boot trusted recovery media, mount that partition without executing
its contents, copy it before repair, and validate ownership and files before
returning it to service. The SquashFS system partition can be replaced without
erasing data, but versions and migrations must remain compatible.

## Reset

A factory reset is destructive: export any required audit and backup material,
shut down services, remove only the documented JanusGate persistent state, and
rerun `janusgate-setup` with a reviewed image setup document. Reinstalling the
system partition alone is not a reset because persistent state is separate.

After every recovery, verify three-interface separation, bridge forwarding,
one allowed and one blocked DNS query, HTTPS, local and remote CLI, audit
integrity, backup creation, and persistence across an orderly reboot.
