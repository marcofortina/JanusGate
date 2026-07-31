<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Threat model

## Assets and boundaries

Protected assets are forwarding availability, policy integrity, administrator
credentials, private keys, configuration, audit history, and the separation
between data and management networks. Trust boundaries exist at both data
interfaces, management HTTPS, remote list downloads, local IPC, persistent
storage, and the software supply chain.

## Considered threats

- Malicious LAN clients may send malformed, fragmented, retransmitted,
  overlapping, or high-rate traffic. Parsers are length-bounded; fragment and
  TCP state have global and per-source limits; queue overflow follows the
  configured fail-open or fail-closed policy.
- Hostile blocklists may contain invalid names, excessive lines, compression
  bombs, or misleading content. Downloads have transport, size, decompression,
  and rule-count limits and are activated only after complete validation.
- Hostile web clients may attempt brute force, CSRF, fixation, path traversal,
  oversized bodies, malformed JSON, host-header abuse, role bypass, or command
  injection. HTTPS limits, origin and CSRF validation, rate limits, strict
  schemas, role checks, and non-shell execution address these cases.
- Stolen operator credentials remain dangerous. Password hashing, optional
  TOTP, session expiration, and audit records protect browser access. Remote
  automation additionally requires a scoped token and a trusted, explicitly
  mapped client certificate; either identity can be revoked independently.
- A compromised `janusgate-web` process is contained by an unprivileged
  account, restricted files, local protocol validation, and the absence of
  direct network-administration capability.
- On OpenBSD, `janusgated` and `janusgate-web` additionally use `pledge`.
  The narrow root network helper validates authenticated local requests but
  cannot use `pledge` because bridge and MTU ioctls are not exposed by a
  promise.
- Queue and connection exhaustion are bounded by queue length, packet-copy
  length, flow counts, reassembly bytes, fragment counts, and timeouts.
- Local symlink and permission attacks are reduced through ownership checks,
  restrictive modes, no-follow creation where applicable, and atomic replace
  operations.
- Dependency substitution is reduced by pinned Buildroot versions and hashes,
  verified Alpine inputs, source metadata checks, SBOM output, and release
  checksums.
- Failed network changes are protected by validation, a confirmation window,
  and rollback. Database and certificate changes use transactional or
  replace-with-rollback workflows.

## Residual risks

JanusGate cannot inspect names hidden inside a full-tunnel VPN, an unidentified
encrypted proxy, DoH to an unknown endpoint, or ECH without another usable
policy signal. Blocking a shared CDN address can affect unrelated services.
Policy decisions are only as good as the configured lists and exceptions.

The appliance is not an intrusion-prevention system and does not inspect
arbitrary application content. It cannot prevent a physical bypass. Hardware
without a bypass relay will normally stop forwarding during power loss.
Fail-open improves availability at the cost of policy enforcement; fail-closed
has the opposite trade-off.

## Security maintenance

Security-sensitive changes require regression tests and local justification
for any static-analysis suppression. See [SECURITY.md](../SECURITY.md) for
reporting and [Recovery](recovery.md) for containment and rollback.
