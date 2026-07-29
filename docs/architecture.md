<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Architecture

JanusGate is an inline Layer-2 appliance. The data interfaces belong to one
bridge; the management interface remains separate. Ordinary frames stay in
the kernel forwarding path. Linux uses nftables and NFQUEUE for selected DNS
and encrypted-DNS traffic. OpenBSD uses a PF anchor and divert sockets for the
same policy boundary.

```text
LAN ── data-in ──┐                    ┌── data-out ── router
                 ├──── OS bridge ─────┤
                 │       │ selected packets
                 │       v
                 │   policy workers
                 │       │ verdict or response
                 └───────┘

management ── HTTPS ── janusgate-web ── local control socket ── janusgated
                                                           └── janusgate-netd
```

## Processes and privilege

- `janusgated` owns the policy database, immutable policy snapshots, packet
  workers, reassembly state, audit records, metrics, backups, and the local
  control protocol. It runs as the unprivileged `janusgate` account.
- `janusgate-netd` is the narrow privileged helper. It validates every request
  before changing bridge, address, packet selection, or appliance power state.
- `janusgate-web` terminates management HTTPS as `janusgate-web`. It validates
  HTTP limits and forwards structured requests over the local control socket.
- `janusgatectl` uses either that socket for the small local command set or the
  HTTPS API for full administration.
- `janusgate-setup` validates and applies an explicit non-interactive
  installation document.

The web process cannot configure interfaces directly. The data plane cannot
accept unauthenticated web requests. Unix peer credentials, filesystem
permissions, roles, CSRF checks, and revision checks form independent
boundaries.

## State and database

SQLite stores configuration, identities, roles, sessions, tokens, policy
rules, source metadata, events, and the append-only audit chain. Schema
migrations run transactionally. Secrets are hashed or encrypted before
storage; private keys and full backups receive restrictive permissions.

Policy evaluation never queries SQLite per packet. `janusgated` builds a
validated immutable snapshot, publishes it atomically to readers, and retires
the previous generation only after active readers leave it. A failed reload
therefore leaves the last complete policy active.

## IPC

The local protocol uses length-bounded, versioned envelopes on Unix sockets.
The control socket is owned by `janusgate:janusgate-control`; the web account
has group access but no access to the database or private configuration.
Messages reject unknown fields, invalid lengths, trailing data, and
unauthorized operations.

## Deployment

The Alpine appliance uses OpenRC and a writable root filesystem. Buildroot
uses a read-only SquashFS system partition plus an ext4 data partition mounted
at `/data`; configuration, database, certificates, blocklists, audit records,
and logs are bind-mounted from that persistent partition.

OpenBSD installs under `/usr/local`, uses `/var/run/janusgate` for local
sockets, and starts the three processes through native rc.d scripts. The PF
anchor is owned and replaced independently of administrator rules.

Both reference images use the same interface order:

1. data ingress;
2. data egress;
3. management.

See [Packet path](packet-path.md), [Threat model](threat-model.md), and
[Firmware](firmware.md) for the operational details.
