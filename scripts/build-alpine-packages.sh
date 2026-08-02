#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

output_directory=${1-}
source_directory=${SRCDEST:-}
temporary_directory=

# Stop with one concise package-build error.
fail()
{
    echo "Alpine package build: $*" >&2
    exit 1
}

# Remove only the temporary package directory created by this invocation.
cleanup()
{
    if [ -n "$temporary_directory" ] &&
        [ -d "$temporary_directory" ]; then
        rm -rf -- "$temporary_directory"
    fi
}
trap cleanup EXIT HUP INT TERM

[ "$(id -u)" -ne 0 ] ||
    fail "run as an Alpine abuild user, not root"
[ -n "$output_directory" ] ||
    fail "usage: scripts/build-alpine-packages.sh OUTPUT_DIRECTORY"

for program in abuild git gzip realpath; do
    command -v "$program" >/dev/null 2>&1 ||
        fail "required program is unavailable: $program"
done

project_directory=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if [ -n "$(git -C "$project_directory" status --porcelain)" ]; then
    fail "a clean source tree is required"
fi
[ ! -e "$output_directory" ] ||
    fail "refusing to overwrite: $output_directory"
mkdir -p "$output_directory"
output_directory=$(realpath "$output_directory")
if [ -z "$source_directory" ]; then
    source_directory="$output_directory/sources"
fi
mkdir -p "$source_directory"
source_directory=$(realpath "$source_directory")
export REPODEST="$output_directory"
export SRCDEST="$source_directory"

if [ ! -f "$HOME/.abuild/abuild.conf" ]; then
    abuild-keygen -a -i -n
fi

(
    cd "$project_directory/packaging/alpine/civetweb"
    abuild -r
)
civetweb_package=$(find "$output_directory" -type f \
    -name 'civetweb-[0-9]*.apk' -print | sort | head -n 1)
civetweb_development_package=$(find "$output_directory" -type f \
    -name 'civetweb-dev-[0-9]*.apk' -print | sort | head -n 1)
if [ ! -f "$civetweb_package" ] ||
    [ ! -f "$civetweb_development_package" ]; then
    fail "CivetWeb packages were not produced"
fi
sudo apk add --allow-untrusted \
    "$civetweb_package" "$civetweb_development_package"

source_archive="$source_directory/janusgate-0.1.1.tar.gz"
source_date_epoch=$(git -C "$project_directory" log -1 --format=%ct)
git -C "$project_directory" archive --format=tar \
    --mtime="@$source_date_epoch" --prefix=janusgate-0.1.1/ \
    'HEAD^{tree}' -- . \
    ':(exclude)packaging/alpine/APKBUILD' |
    gzip -n >"$source_archive"

temporary_directory=$(mktemp -d)
package_directory="$temporary_directory/alpine/janusgate"
mkdir -p "$package_directory"
cp "$project_directory/packaging/alpine/APKBUILD" \
    "$project_directory/packaging/alpine/janusgate.pre-install" \
    "$project_directory/packaging/alpine/janusgate.post-install" \
    "$package_directory/"
(
    cd "$package_directory"
    abuild checksum
    JANUSGATE_SOURCE_COMMIT=$(git -C "$project_directory" rev-parse HEAD)
    export JANUSGATE_SOURCE_COMMIT
    abuild -r
)

echo "Alpine packages: $output_directory"
