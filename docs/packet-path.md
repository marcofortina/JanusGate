<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Packet path

`janusgate-netd` creates the configured bridge, attaches only the two data
interfaces, applies MTU and bridge settings, assigns the management address to
the dedicated interface, and installs an atomic nftables ruleset.

## Kernel selection

The bridge forwards ordinary Ethernet traffic without a user-space copy.
Bridge and inet-family nftables chains select:

- UDP and TCP classic DNS on port 53, regardless of resolver address;
- optional DoT on TCP 853 and DoQ on UDP 853;
- configured encrypted-DNS endpoint address sets;
- TLS flows selected for visible ClientHello SNI inspection.

Selected packets enter one of the configured NFQUEUE numbers. Queue fan-out
can distribute flows across workers while preserving per-flow ordering.

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

Allowed traffic receives `NF_ACCEPT`. A drop action receives `NF_DROP`.
Blocked UDP DNS can instead produce REFUSED, NXDOMAIN, or a configured IPv4 or
IPv6 sinkhole answer. The response builder reverses addresses and ports,
preserves the query identifier and relevant question, recalculates checksums,
and then drops the original query. Blocked TCP DNS is dropped and a reset is
emitted when enough flow state is available.

Malformed traffic follows the documented conservative parser decision rather
than being partially interpreted. Fragment and stream state expires on bounded
timers.

## Failure modes

In fail-open mode, queue bypass preserves forwarding when the daemon is absent
or a queue is full. In fail-closed mode, selected traffic remains blocked under
the same conditions. Unselected bridge traffic stays independent of the
daemon in both modes. Changing failure mode or queue layout replaces the
nftables transaction atomically.

The management interface is not attached to the data bridge, and the default
HTTPS listener binds only its configured management address.
