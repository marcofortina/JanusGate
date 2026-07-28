<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# JanusGate

JanusGate is a transparent, bidirectional Linux appliance that applies domain
and destination policy to traffic crossing an inline Layer-2 bridge. Classic
DNS sent to arbitrary resolvers remains subject to policy while ordinary
traffic stays in the kernel forwarding path.

The appliance separates packet processing, privileged network configuration,
and HTTPS administration into distinct processes. Its management interface is
never attached to the data bridge.

JanusGate does not decrypt TLS, terminate VPNs, or claim visibility into names
hidden by Encrypted Client Hello or full-tunnel encryption.

## Build

The development build uses CMake, Ninja, and a C17 compiler:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Detailed build, deployment, operation, recovery, and security documentation is
provided under `docs/`.

## License

JanusGate is licensed under the GNU Affero General Public License, version 3 or
later. See `LICENSE`.
