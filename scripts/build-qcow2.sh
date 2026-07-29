#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

raw_image=
output_image=

# Print command-line help.
usage()
{
    cat <<'EOF'
usage: scripts/build-qcow2.sh --raw FILE [--output FILE]

Convert one verified JanusGate raw disk into a compact QCOW2 image.
EOF
}

# Stop with one concise conversion error.
fail()
{
    echo "QCOW2 build: $*" >&2
    exit 1
}

# Parse exact input and output paths.
while [ "$#" -gt 0 ]; do
    case $1 in
        --raw)
            [ "$#" -ge 2 ] || fail "--raw requires a value"
            raw_image=$2
            shift 2
            ;;
        --output)
            [ "$#" -ge 2 ] || fail "--output requires a value"
            output_image=$2
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

[ -n "$raw_image" ] || fail "--raw is required"
[ -f "$raw_image" ] || fail "raw image does not exist: $raw_image"
command -v qemu-img >/dev/null 2>&1 ||
    fail "required program is unavailable: qemu-img"
command -v sha256sum >/dev/null 2>&1 ||
    fail "required program is unavailable: sha256sum"

if [ -z "$output_image" ]; then
    case $raw_image in
        *.raw)
            output_image=${raw_image%.raw}.qcow2
            ;;
        *)
            output_image=$raw_image.qcow2
            ;;
    esac
fi
[ ! -e "$output_image" ] || fail "refusing to overwrite: $output_image"
output_directory=$(dirname -- "$output_image")
output_name=$(basename -- "$output_image")
mkdir -p "$output_directory"

qemu-img convert -f raw -O qcow2 \
    -o compat=1.1,lazy_refcounts=off "$raw_image" "$output_image"
qemu-img check -f qcow2 "$output_image"
(
    cd "$output_directory"
    sha256sum "$output_name" >"$output_name.sha256"
)

echo "QCOW2 image: $output_image"
echo "Checksum: $output_image.sha256"
