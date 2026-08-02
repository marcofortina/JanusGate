<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Packet path

`janusgate-netd` creates the configured bridge, attaches only the two data
interfaces, applies supported bridge settings, validates the separate
management-interface role, and installs the native packet-selection policy.
The deployment operating system owns management addressing and routing.
HTTPS accepts the numeric listen address and the explicit `--server-name`
value (`janusgate.local` by default) as HTTP Host values.

## Kernel selection

The bridge forwards traffic outside the selection rules without a user-space
copy. Linux bridge and inet-family nftables chains select client-to-upstream
traffic entering the configured ingress interface:

- IPv4 and IPv6 fragments for bounded policy-safe handling;
- UDP and TCP on ports 53, 443, and 853;
- configured encrypted-DNS endpoint address sets;
- configured destination address sets.

TCP 443 can be evaluated through visible TLS ClientHello SNI. UDP 443 receives
destination policy only: JanusGate does not parse QUIC Initial packets or QUIC
TLS SNI. UDP 853 provides standard-port DoQ control without parsing DoQ.

Selected packets enter one of the configured NFQUEUE numbers. Queue fan-out
can distribute flows across workers while preserving per-flow ordering.

On OpenBSD, the owned PF anchor diverts IPv4 and IPv6 TCP or UDP traffic for
ports 53, 443, and 853 to one configured divert port. Other traffic remains in
the kernel path. The daemon evaluates diverted packets against the same
bounded policy and reinjects accepted packets. OpenBSD currently uses one
queue in fail-closed mode.

Layer-2 forwarding remains bidirectional. Native packet selectors normally
send only the client-to-upstream direction to policy workers; response traffic
continues through the bridge without generic user-space inspection.

## Evaluation

Workers validate Ethernet, VLAN, IP, extension, fragmentation, transport, DNS,
and TLS lengths before access. UDP DNS is evaluated immediately. The bounded
TCP stream tracker can model both directions when they are supplied, accepts
segmentation and retransmission, handles bounded out-of-order data, and rejects
contradictory overlap. Installed selectors normally supply only ingress
client-to-upstream packets.

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

The management interface is not attached to the data bridge. The operating
system assigns its address and route; the HTTPS service must be configured to
bind that same numeric address.
