<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Dependencies

JanusGate uses released system libraries and does not vendor third-party source.
CMake fails when a mandatory dependency is unavailable. Release SBOMs record
the installed versions reported by `pkg-config`; image manifests additionally
record their pinned Buildroot, kernel, and source revisions.

## Runtime libraries

| Dependency | Role |
| --- | --- |
| CivetWeb | Management HTTPS server |
| OpenSSL 3.x | Certificates and cryptographic operations |
| zlib | Compressed blocklist decoding |
| libidn2 | Internationalized domain-name conversion |
| libcurl | HTTPS retrieval and remote CLI transport |
| Jansson | JSON configuration, IPC, API, and diagnostics |
| libsodium | Password hashing, secrets, and backup encryption |
| SQLite | Transactional configuration and event storage |
| libcap (Linux) | Capability reduction |
| libseccomp (Linux) | System-call filtering |
| libmnl (Linux) | Netlink transport |
| libnetfilter_queue (Linux) | NFQUEUE packet input and verdicts |
| libnftables (Linux) | Atomic packet-filter transactions |
| libnfnetlink (indirect, Linux) | libnetfilter_queue transport |

POSIX threads and the standard C library come from the target operating system.
Linux builds use the kernel bridge, netlink, nftables, and NFQUEUE ABIs.
OpenBSD builds use the base-system bridge, PF, divert-socket, BPF, `pledge`,
and `unveil` interfaces; those facilities are not copied into the repository.

JanusGate does not link a separate libargon2. The required Argon2id
implementation is the reviewed `crypto_pwhash` interface supplied by
libsodium, avoiding two independent password-hashing providers.

## Build and verification tools

| Dependency | Role |
| --- | --- |
| GCC or Clang | C17 compilation and linking |
| CMake | Configuration, installation, and packaging |
| Ninja | Parallel build execution |
| pkg-config or pkgconf | System dependency discovery |
| Python 3 | Validation, SBOM, analysis, and release tools |
| jsonschema | OpenAPI schema validation |
| PyYAML | YAML parsing |
| CMocka | Unit-test framework |
| Doxygen | C API reference generation |
| Graphviz | Documentation diagrams |
| groff | Manual-page validation |
| Bash and OpenBSD ksh | Completion and `rc.d` syntax validation |
| Clang-Tidy and Clang tooling | Static analysis and formatting |
| Cppcheck | Independent C static analysis |
| ShellCheck | Shell static analysis |
| shfmt | Deterministic shell formatting |
| LCOV | Coverage report capture |

## Packaging and image tools

| Dependency | Role |
| --- | --- |
| Alpine abuild and apk-tools | Package creation and installation |
| Buildroot 2025.02.16 | Reproducible firmware assembly |
| Linux 6.12.98 | Reference firmware kernel |
| musl | Reference firmware C library |
| BusyBox | Base utilities and init |
| OpenRC | Service supervision |
| Syslinux | Alpine image boot loader |
| OVMF | x86_64 Buildroot UEFI firmware |
| QEMU and qemu-img | Boot tests and QCOW2 conversion |
| zstd | Deterministic firmware compression |

Packages pulled into Alpine and Buildroot images retain their upstream licenses
and package metadata. They are system components rather than copied JanusGate
sources. The SPDX JSON emitted by `scripts/generate-sbom.py` is the
machine-readable inventory for each source release.
