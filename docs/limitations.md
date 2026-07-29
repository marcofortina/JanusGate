<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Limitations

- Classic UDP and TCP DNS are visible even when directed to arbitrary resolver
  addresses. DoH remains visible only when its endpoint is otherwise
  identified by configured IP or visible SNI policy.
- ECH hides the inner server name. JanusGate cannot recover it without another
  policy signal and does not perform TLS interception.
- Full-tunnel VPNs, encrypted proxies, and unknown tunnels hide their inner
  DNS and application destinations. Blocking the tunnel itself is a separate
  destination-policy decision.
- DoT and DoQ port controls can block standard port 853, but a service can use
  another port or transport.
- Shared CDN and anycast addresses can serve unrelated applications. Broad IP
  blocks may cause collateral loss; prefer domain rules and narrow,
  attributable endpoint sets.
- Sinkhole answers apply only to compatible A or AAAA DNS queries. Drop,
  REFUSED, and NXDOMAIN have different client caching and fallback behavior.
- Inline enforcement depends on physical placement. Alternate paths, wireless
  bypass, direct upstream access, or a recabled link avoid the appliance.
- Generic PCs normally stop forwarding on power loss. Transparent electrical
  bypass requires suitable hardware and is outside the software.
- Fail-open preserves selected traffic when queues or the daemon fail but
  temporarily loses enforcement. Fail-closed preserves policy at the cost of
  availability.
- OpenBSD currently supports one fail-closed divert queue, no CPU fanout, no
  multicast-snooping control, and no explicit bridge MTU override. Its
  unprivileged management service listens on port 8443 by default.
- The management plane is not a replacement for host hardening, patch
  management, protected backups, access review, or physical security.
- Policy lists can be incomplete, stale, overbroad, or legally unsuitable.
  Administrators remain responsible for source review, exceptions, notice,
  retention, and lawful deployment.

JanusGate is a DNS and destination policy appliance, not a general malware
scanner, content-inspection proxy, traffic shaper, or anonymity system.
