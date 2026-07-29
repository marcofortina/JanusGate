<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Packet path

`janusgate-netd` creates the configured bridge, attaches only the two data
interfaces, applies supported bridge settings, assigns the management address
to the dedicated interface, and installs the native packet-selection policy.

## Kernel selection

The bridge forwards ordinary Ethernet traffic without a user-space copy.
Linux bridge and inet-family nftables chains select:

- UDP and TCP classic DNS on port 53, regardless of resolver address;
- optional DoT on TCP 853 and DoQ on UDP 853;
- configured encrypted-DNS endpoint address sets;
- TLS flows selected for visible ClientHello SNI inspection.

Selected packets enter one of the configured NFQUEUE numbers. Queue fan-out
can distribute flows across workers while preserving per-flow ordering.

On OpenBSD, the owned PF anchor diverts IPv4 and IPv6 TCP or UDP traffic for
ports 53, 443, and 853 to one configured divert port. Other traffic remains in
the kernel path. The daemon evaluates diverted packets against the same
bounded policy and reinjects accepted packets. OpenBSD currently uses one
queue in fail-closed mode.

## Evaluation

Workers validate Ethernet, VLAN, IP, extension, fragmentation, transport, DNS,
and TLS lengths before access. UDP DNS is evaluated immediately. TCP DNS uses
bounded bidirectional reassembly that accepts segmentation and retransmission,
handles bounded out-of-order data, and rejects contradictory overlap.

Policy order is explicit: a matching allow exception wins over a block rule;
more specific scopes are evaluated before global rules. Exact-domain rules do
not imply subdomains unless `include_subdomains` is set. The active snapshot
does not change during an individual evaluation.

## Verdicts and responses

On Linux, allowed traffic receives `NF_ACCEPT` and a drop action receives
`NF_DROP`. On OpenBSD, allowed traffic is reinjected and a drop action is not
reinserted.
Blocked UDP DNS can instead produce REFUSED, NXDOMAIN, or a configured IPv4 or
IPv6 sinkhole answer. The response builder reverses addresses and ports,
preserves the query identifier and relevant question, recalculates checksums,
and then drops the original query. Blocked TCP DNS is dropped and a reset is
emitted when enough flow state is available.

Malformed traffic follows the documented conservative parser decision rather
than being partially interpreted. Fragment and stream state expires on bounded
timers.

## Failure modes

On Linux, fail-open queue bypass preserves forwarding when the daemon is
absent or a queue is full. In fail-closed mode, selected traffic remains
blocked under the same conditions. OpenBSD currently supports fail-closed
operation only. Unselected bridge traffic stays independent of the daemon.
Policy changes atomically replace the JanusGate-owned nftables table or PF
anchor.

The management interface is not attached to the data bridge, and the default
HTTPS listener binds only its configured management address.
