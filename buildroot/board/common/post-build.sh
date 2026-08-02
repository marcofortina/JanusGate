#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

target_directory=$1

install -d -m 0755 "$target_directory/data"

# Verify that the volatile runtime directory is mounted with bounded options.
grep -Fq 'tmpfs /run tmpfs mode=0755,nosuid,nodev' \
    "$target_directory/etc/fstab"

# Reject incomplete firmware roots before an image can be published.
for path in \
    usr/sbin/janusgated \
    usr/sbin/janusgate-netd \
    usr/sbin/janusgate-web \
    usr/sbin/janusgate-setup \
    usr/bin/janusgatectl \
    etc/init.d/S15janusgate-prepare \
    etc/init.d/S20janusgate-netd \
    etc/init.d/S30janusgated \
    etc/init.d/S50janusgate-web; do
    [ -e "$target_directory/$path" ] || {
        echo "Buildroot post-build: missing $path" >&2
        exit 1
    }
done

# Record the immutable firmware baseline inside the image.
cat >"$target_directory/etc/janusgate/firmware-release" <<EOF
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
JANUSGATE_VERSION=0.1.1
BUILDROOT_VERSION=2025.02.16
LINUX_VERSION=6.12.98
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
EOF
