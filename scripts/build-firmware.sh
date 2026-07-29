#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

buildroot_version=2025.02.16
buildroot_sha256=15305e3d366eeaf4a5ecaf2ed42f685fd6af7fe5dbf1f62e1de5f46ee83225e2
jobs=${JANUSGATE_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}
output_directory=

# Print command-line help.
usage()
{
    cat <<'EOF'
usage: scripts/build-firmware.sh DEFCONFIG [options]

Supported defconfigs:
  janusgate_x86_64_efi_defconfig
  janusgate_aarch64_virt_defconfig

Options:
  --output-directory DIR  Buildroot output directory
  --jobs COUNT            parallel build jobs
  --help                  show this help
EOF
}

# Stop with one concise firmware-build error.
fail()
{
    echo "Firmware build: $*" >&2
    exit 1
}

[ "$#" -gt 0 ] || {
    usage >&2
    exit 2
}
defconfig=$1
shift
case $defconfig in
    janusgate_x86_64_efi_defconfig | janusgate_aarch64_virt_defconfig) ;;
    *)
        fail "unsupported defconfig: $defconfig"
        ;;
esac

# Parse optional output and concurrency controls.
while [ "$#" -gt 0 ]; do
    case $1 in
        --output-directory)
            [ "$#" -ge 2 ] || fail "--output-directory requires a value"
            output_directory=$2
            shift 2
            ;;
        --jobs)
            [ "$#" -ge 2 ] || fail "--jobs requires a value"
            jobs=$2
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
case $jobs in
    *[!0-9]* | "")
        fail "job count must be a positive integer"
        ;;
esac
[ "$jobs" -gt 0 ] || fail "job count must be positive"

for program in curl git make realpath sha256sum sha512sum stat tar zstd; do
    command -v "$program" >/dev/null 2>&1 ||
        fail "required program is unavailable: $program"
done

project_directory=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
download_directory="$project_directory/out/downloads"
source_parent="$project_directory/out/buildroot"
archive="$download_directory/buildroot-$buildroot_version.tar.xz"
source_directory="$source_parent/buildroot-$buildroot_version"
if [ -z "$output_directory" ]; then
    output_directory="$source_parent/$defconfig"
fi
mkdir -p "$download_directory" "$source_parent" "$output_directory"
output_directory=$(realpath "$output_directory")

if [ ! -f "$archive" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 \
        --output "$archive.part" \
        "https://buildroot.org/downloads/buildroot-$buildroot_version.tar.xz"
    mv "$archive.part" "$archive"
fi
printf '%s  %s\n' "$buildroot_sha256" "$archive" | sha256sum --check -
if [ ! -d "$source_directory" ]; then
    tar --extract --xz --file "$archive" --directory "$source_parent"
fi

source_date_epoch=${SOURCE_DATE_EPOCH:-$(
    git -C "$project_directory" log -1 --format=%ct
)}
source_commit=$(git -C "$project_directory" rev-parse --verify HEAD)
export SOURCE_DATE_EPOCH="$source_date_epoch"

make -C "$source_directory" O="$output_directory" \
    BR2_EXTERNAL="$project_directory/buildroot" "$defconfig"
make -C "$source_directory" O="$output_directory" \
    BR2_EXTERNAL="$project_directory/buildroot" janusgate-dirclean
make -C "$source_directory" O="$output_directory" \
    BR2_EXTERNAL="$project_directory/buildroot" \
    JANUSGATE_SOURCE_COMMIT="$source_commit" -j"$jobs"

case $defconfig in
    janusgate_x86_64_efi_defconfig)
        image="$output_directory/images/janusgate-x86_64.img"
        ;;
    janusgate_aarch64_virt_defconfig)
        image="$output_directory/images/janusgate-aarch64.img"
        ;;
esac
[ -f "$image" ] || fail "firmware image was not produced: $image"

zstd --quiet --threads=1 --ultra -19 --force "$image" -o "$image.zst"
if [ "$defconfig" = janusgate_x86_64_efi_defconfig ] &&
    [ "$(stat -c %s "$image.zst")" -gt 134217728 ]; then
    fail "compressed x86_64 firmware exceeds 128 MiB"
fi
image_directory=$(dirname -- "$image")
image_name=$(basename -- "$image")
(
    cd "$image_directory"
    sha256sum "$image_name" "$image_name.zst" >SHA256SUMS
    sha512sum "$image_name" "$image_name.zst" >SHA512SUMS
)

cat >"$output_directory/images/build-manifest.json" <<EOF
{
  "_license": "AGPL-3.0-or-later",
  "_copyright": "Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>",
  "buildroot_version": "$buildroot_version",
  "defconfig": "$defconfig",
  "kernel_version": "6.12.98",
  "source_commit": "$source_commit",
  "source_date_epoch": $source_date_epoch,
  "nic_order": ["data-in", "data-out", "management"]
}
EOF

echo "Firmware image: $image"
echo "Build manifest: $output_directory/images/build-manifest.json"
