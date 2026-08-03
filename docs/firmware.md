<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Images and firmware

## Alpine appliance

Build the CivetWeb and JanusGate APKs from `packaging/alpine`, then create the
raw image as root because loop devices and mounts are required:

```sh
sudo scripts/build-alpine-image.sh \
  --apk /path/to/packages/janusgate-0.2.0-r0.apk
scripts/build-qcow2.sh \
  --raw out/alpine/janusgate-alpine-3.24.1-x86_64.raw
scripts/run-qemu-smoke.sh alpine \
  --image out/alpine/janusgate-alpine-3.24.1-x86_64.qcow2
```

The CivetWeb and `janusgate-openrc` APKs must be in the same directory as the
main package. The image script verifies the Alpine minirootfs, installs the
packages, creates the initial database and certificate, locks direct root
login, installs Syslinux, and records input and image hashes.

## Buildroot reference firmware

Buildroot 2025.02.16, Linux 6.12.98, musl, BusyBox, and all source hashes are
pinned:

```sh
scripts/build-firmware.sh janusgate_x86_64_efi_defconfig --jobs 4
scripts/run-qemu-smoke.sh buildroot-x86_64

scripts/build-firmware.sh janusgate_aarch64_virt_defconfig --jobs 4
scripts/run-qemu-smoke.sh buildroot-aarch64
```

The x86_64 image boots with UEFI. The AArch64 image targets QEMU `virt` with a
VirtIO block device. QEMU tests select software TCG explicitly, so they can run
while another desktop hypervisor is installed or active.

## Image layout and persistence

Buildroot places a read-only SquashFS system in the first partition and an
ext4 `JANUSGATE_DATA` partition in the second. On boot,
`S15janusgate-prepare` mounts persistent configuration, database,
certificates, logs, and backups from `/data`, then performs first-boot setup
once. Later boots reuse the same state.

The generic interface order is:

| Adapter | Role | Default guest interface |
| --- | --- | --- |
| 1 | protected-side data | `eth0` |
| 2 | upstream-side data | `eth1` |
| 3 | management only | `eth2` |

For VirtualBox use three paravirtualized adapters in that order; attach the
first two to the required data networks and the third to a host-only or
dedicated management network. For VMware use VMXNET3 where supported and keep
the same PCI order. Never attach management to the data bridge.

## Hardware adaptation

Start from the closest defconfig. Enable the board boot loader, storage,
console, watchdog, RTC, and NIC drivers while retaining the common bridge,
nftables, NFQUEUE, seccomp, capabilities, IPv4/IPv6, ext4, and SquashFS
settings. Change interface names only in validated configuration. Verify
serial recovery, persistent partition discovery, ordered shutdown, link-loss
behavior, and both failure modes on the target hardware before deployment.

The compressed generic x86_64 firmware is required to remain at or below
128 MiB. Each firmware build emits SHA-256, SHA-512, and a build manifest.
