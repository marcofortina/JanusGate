#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

alpine_version=3.24.1
alpine_branch=v3.24
minirootfs_sha256=41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081
image_size_mib=2048
source_date_epoch=${SOURCE_DATE_EPOCH:-0}
output_directory=out/alpine
cache_directory=out/downloads
package_file=
temporary_directory=
loop_device=
root_partition=
root_mount=
chroot_mounted=false
root_mounted=false

# Print command-line help.
usage()
{
    cat <<'EOF'
usage: scripts/build-alpine-image.sh --apk FILE [options]

Options:
  --apk FILE               JanusGate Alpine package
  --output-directory DIR   artifact directory (default: out/alpine)
  --cache-directory DIR    download cache (default: out/downloads)
  --image-size-mib SIZE    raw disk size (default: 2048)
  --help                    show this help
EOF
}

# Stop with one concise image-build error.
fail()
{
    echo "Alpine image build: $*" >&2
    exit 1
}

# Require one host utility used by the deterministic build.
require_program()
{
    command -v "$1" >/dev/null 2>&1 ||
        fail "required program is unavailable: $1"
}

# Unmount resources and release only objects created by this invocation.
cleanup()
{
    if "$chroot_mounted" && [ -n "$temporary_directory" ]; then
        umount "$temporary_directory/root/dev" >/dev/null 2>&1 || true
        umount "$temporary_directory/root/proc" >/dev/null 2>&1 || true
        umount "$temporary_directory/root/sys" >/dev/null 2>&1 || true
        chroot_mounted=false
    fi
    if "$root_mounted" && [ -n "$root_mount" ]; then
        umount "$root_mount" >/dev/null 2>&1 || true
        root_mounted=false
    fi
    if [ -n "$loop_device" ]; then
        losetup --detach "$loop_device" >/dev/null 2>&1 || true
        loop_device=
    fi
    if [ -n "$temporary_directory" ] &&
        [ -d "$temporary_directory" ]; then
        rm -rf -- "$temporary_directory"
    fi
}
trap cleanup EXIT HUP INT TERM

# Parse image options without accepting positional arguments.
while [ "$#" -gt 0 ]; do
    case $1 in
        --apk)
            [ "$#" -ge 2 ] || fail "--apk requires a value"
            package_file=$2
            shift 2
            ;;
        --output-directory)
            [ "$#" -ge 2 ] || fail "--output-directory requires a value"
            output_directory=$2
            shift 2
            ;;
        --cache-directory)
            [ "$#" -ge 2 ] || fail "--cache-directory requires a value"
            cache_directory=$2
            shift 2
            ;;
        --image-size-mib)
            [ "$#" -ge 2 ] || fail "--image-size-mib requires a value"
            image_size_mib=$2
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

[ -n "$package_file" ] || fail "--apk is required"
[ -f "$package_file" ] || fail "package does not exist: $package_file"
case $image_size_mib in
    *[!0-9]* | "")
        fail "image size must be a positive integer"
        ;;
esac
[ "$image_size_mib" -ge 512 ] || fail "image size must be at least 512 MiB"
[ "$(id -u)" -eq 0 ] || fail "root is required for loop and mount operations"

for program in awk blkid chroot curl dd find install losetup mkfs.ext4 mount \
    realpath sha256sum sfdisk tar touch truncate umount; do
    require_program "$program"
done

project_directory=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
package_file=$(realpath "$package_file")
mkdir -p "$output_directory" "$cache_directory"
output_directory=$(realpath "$output_directory")
cache_directory=$(realpath "$cache_directory")
raw_image="$output_directory/janusgate-alpine-$alpine_version-x86_64.raw"
manifest="$output_directory/janusgate-alpine-$alpine_version-x86_64.json"
[ ! -e "$raw_image" ] || fail "refusing to overwrite: $raw_image"
[ ! -e "$manifest" ] || fail "refusing to overwrite: $manifest"

archive_name="alpine-minirootfs-$alpine_version-x86_64.tar.gz"
archive="$cache_directory/$archive_name"
if [ ! -f "$archive" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 \
        --output "$archive.part" \
        "https://dl-cdn.alpinelinux.org/alpine/$alpine_branch/releases/x86_64/$archive_name"
    mv "$archive.part" "$archive"
fi
printf '%s  %s\n' "$minirootfs_sha256" "$archive" | sha256sum --check -

temporary_directory=$(mktemp -d)
root_directory="$temporary_directory/root"
root_mount="$temporary_directory/disk"
mkdir -p "$root_directory" "$root_mount"
tar --extract --gzip --file "$archive" --directory "$root_directory" \
    --numeric-owner

cat >"$root_directory/etc/apk/repositories" <<EOF
https://dl-cdn.alpinelinux.org/alpine/$alpine_branch/main
https://dl-cdn.alpinelinux.org/alpine/$alpine_branch/community
EOF
cp /etc/resolv.conf "$root_directory/etc/resolv.conf"
mount --bind /dev "$root_directory/dev"
mount -t proc proc "$root_directory/proc"
mount -t sysfs sys "$root_directory/sys"
chroot_mounted=true

chroot "$root_directory" /sbin/apk add --no-cache \
    acpid alpine-base ca-certificates chrony iproute2 linux-virt logrotate \
    nftables openssl syslinux
install -m 0644 "$package_file" "$root_directory/tmp/janusgate.apk"
chroot "$root_directory" /sbin/apk add --allow-untrusted \
    /tmp/janusgate.apk
rm -f "$root_directory/tmp/janusgate.apk"

printf '%s\n' janusgate >"$root_directory/etc/hostname"
install -m 0644 "$project_directory/packaging/alpine/interfaces" \
    "$root_directory/etc/network/interfaces"
install -d -m 0750 "$root_directory/etc/janusgate"
install -m 0600 "$project_directory/packaging/alpine/image-setup.json" \
    "$root_directory/etc/janusgate/image-setup.json"
chroot "$root_directory" /sbin/rc-update add networking boot
chroot "$root_directory" /sbin/rc-update add hostname boot
chroot "$root_directory" /sbin/rc-update add syslog boot
chroot "$root_directory" /sbin/rc-update add chronyd default
chroot "$root_directory" /sbin/rc-update add acpid default
chroot "$root_directory" /usr/sbin/janusgate-setup \
    --config /etc/janusgate/image-setup.json --image-build
chroot "$root_directory" /usr/bin/passwd -l root

umount "$root_directory/dev"
umount "$root_directory/proc"
umount "$root_directory/sys"
chroot_mounted=false
find "$root_directory" -xdev -exec touch -h -d "@$source_date_epoch" {} +

truncate --size "${image_size_mib}M" "$raw_image"
printf 'label: dos\nunit: sectors\n\nstart=2048, type=83, bootable\n' |
    sfdisk "$raw_image"
loop_device=$(losetup --find --show --partscan "$raw_image")
root_partition="${loop_device}p1"
[ -b "$root_partition" ] || root_partition="${loop_device}1"
[ -b "$root_partition" ] || fail "partition device was not created"

E2FSPROGS_FAKE_TIME=$source_date_epoch mkfs.ext4 -F -L JANUSGATE_ROOT \
    -U 6a616e75-7367-4174-8567-617465000001 \
    -E lazy_itable_init=0,lazy_journal_init=0 "$root_partition"
mount "$root_partition" "$root_mount"
root_mounted=true
cp -a "$root_directory/." "$root_mount/"

root_uuid=$(blkid -s UUID -o value "$root_partition")
cat >"$root_mount/etc/fstab" <<EOF
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
UUID=$root_uuid / ext4 defaults,noatime 0 1
EOF
mkdir -p "$root_mount/boot/extlinux"
cat >"$root_mount/boot/extlinux/extlinux.conf" <<EOF
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
DEFAULT janusgate
TIMEOUT 20
SERIAL 0 115200

LABEL janusgate
    LINUX /boot/vmlinuz-virt
    INITRD /boot/initramfs-virt
    APPEND root=UUID=$root_uuid modules=sd-mod,virtio_blk,ext4 console=tty0 console=ttyS0,115200
EOF
mount --bind /dev "$root_mount/dev"
chroot "$root_mount" /sbin/extlinux --install /boot/extlinux
umount "$root_mount/dev"
[ -f "$root_mount/usr/share/syslinux/mbr.bin" ] ||
    fail "syslinux MBR is unavailable"
dd if="$root_mount/usr/share/syslinux/mbr.bin" of="$raw_image" \
    bs=440 count=1 conv=notrunc status=none
sync
umount "$root_mount"
root_mounted=false
losetup --detach "$loop_device"
loop_device=

image_sha256=$(sha256sum "$raw_image" | awk '{print $1}')
package_sha256=$(sha256sum "$package_file" | awk '{print $1}')
cat >"$manifest" <<EOF
{
  "_license": "AGPL-3.0-or-later",
  "_copyright": "Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>",
  "format": "raw",
  "architecture": "x86_64",
  "alpine_version": "$alpine_version",
  "source_date_epoch": $source_date_epoch,
  "image_sha256": "$image_sha256",
  "package_sha256": "$package_sha256",
  "nic_order": ["data-in", "data-out", "management"]
}
EOF

echo "Alpine raw image: $raw_image"
echo "Build manifest: $manifest"
