<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Recovery

Keep local console access, a recent configuration backup, the matching full
backup passphrase, and a known-good image before making high-impact changes.

## Management rollback

An applied management-network change remains provisional until confirmed.
Reconnect through the proposed address and run:

```sh
janusgatectl --endpoint https://NEW-ADDRESS network confirm
```

If it is unreachable, wait for automatic rollback or use the local console and
`network rollback`. Do not attach the management interface to the data bridge
as a workaround.

## Service and configuration recovery

Use local `janusgatectl --socket /run/janusgate/control.sock ping` to separate
web or certificate failure from daemon failure. Validate configuration before
reload. If a service will not start, inspect its log and permissions, retain a
copy of the failing state, and restore the last reviewed configuration rather
than editing the database directly.

## Database recovery

Stop all JanusGate services before replacing a database. Preserve the damaged
file and its write-ahead-log companions for analysis. Restore only through the
validated backup operation so archive paths, manifest, schema, integrity, and
revision rules are checked. Start the daemon first, verify health and audit
state, then start the web service.

## Certificate recovery

A rejected certificate operation leaves the active pair unchanged. If HTTPS
cannot start after external file changes, restore a matching certificate and
key from console with restrictive ownership and modes, validate their public
keys with OpenSSL, and restart only `janusgate-web`. Replace a potentially
exposed key rather than reusing it.

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
