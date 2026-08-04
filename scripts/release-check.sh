#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

jobs=${JANUSGATE_BUILD_JOBS:-4}
output_directory=${JANUSGATE_RELEASE_OUTPUT:-out/release}
signing_key=${JANUSGATE_SIGNING_KEY:-}
temporary_directory=
release_complete=false
output_created=false

# Stop with one concise release-check error.
fail()
{
    echo "Release check: $*" >&2
    exit 1
}

# Remove only the temporary directory created by this invocation.
cleanup()
{
    if [ -n "$temporary_directory" ] &&
        [ -d "$temporary_directory" ]; then
        rm -rf -- "$temporary_directory"
    fi
    if "$output_created" && ! "$release_complete" &&
        [ -d "$output_directory" ]; then
        rm -rf -- "$output_directory"
    fi
}
trap cleanup EXIT HUP INT TERM

case $jobs in
    *[!0-9]* | "")
        fail "job count must be a positive integer"
        ;;
esac
[ "$jobs" -gt 0 ] || fail "job count must be positive"

for program in clang cmake cppcheck doxygen git gpg gzip ninja python3 \
    run-clang-tidy sha256sum sha512sum shellcheck shfmt tar xargs; do
    command -v "$program" >/dev/null 2>&1 ||
        fail "required program is unavailable: $program"
done

project_directory=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
[ -z "$(git -C "$project_directory" status --porcelain)" ] ||
    fail "working tree is not clean"
if [ -z "$signing_key" ]; then
    signing_key=$(git -C "$project_directory" config --get user.signingkey || true)
fi
[ -n "$signing_key" ] ||
    fail "JANUSGATE_SIGNING_KEY or git user.signingkey is required"
source_date_epoch=$(git -C "$project_directory" log -1 --format=%ct)
export SOURCE_DATE_EPOCH="$source_date_epoch"
case $output_directory in
    /*) ;;
    *)
        output_directory="$project_directory/$output_directory"
        ;;
esac
[ ! -e "$output_directory" ] ||
    fail "refusing to overwrite: $output_directory"
mkdir -p "$output_directory"
output_created=true
temporary_directory=$(mktemp -d)
cd "$project_directory"

python3 "$project_directory/scripts/check-source-metadata.py"
git -C "$project_directory" ls-files -z '*.sh' |
    xargs -0 shellcheck -s sh
git -C "$project_directory" ls-files -z '*.sh' |
    xargs -0 shfmt -d -i 4 -ci -fn

release_build="$temporary_directory/release"
cmake -S "$project_directory" -B "$release_build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DJANUSGATE_BUILD_BENCHMARKS=ON
cmake --build "$release_build" --parallel "$jobs"
ctest --test-dir "$release_build" --output-on-failure
cmake --build "$release_build" \
    --target doxygen format-check openapi-check static-analysis performance \
    --parallel "$jobs"

gcc_sanitizer_build="$temporary_directory/gcc-sanitizers"
cmake -S "$project_directory" -B "$gcc_sanitizer_build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug -DJANUSGATE_BUILD_DOCUMENTATION=OFF \
    -DJANUSGATE_ENABLE_SANITIZERS=ON
cmake --build "$gcc_sanitizer_build" --parallel "$jobs"
ctest --test-dir "$gcc_sanitizer_build" --output-on-failure

clang_sanitizer_build="$temporary_directory/clang-sanitizers"
CC=clang cmake -S "$project_directory" -B "$clang_sanitizer_build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug -DJANUSGATE_BUILD_DOCUMENTATION=OFF \
    -DJANUSGATE_ENABLE_SANITIZERS=ON
cmake --build "$clang_sanitizer_build" --parallel "$jobs"
ctest --test-dir "$clang_sanitizer_build" --output-on-failure

fuzz_build="$temporary_directory/fuzz"
CC=clang cmake -S "$project_directory" -B "$fuzz_build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug -DJANUSGATE_BUILD_DOCUMENTATION=OFF \
    -DJANUSGATE_ENABLE_FUZZING=ON -DJANUSGATE_ENABLE_SANITIZERS=ON
cmake --build "$fuzz_build" --parallel "$jobs"
ctest --test-dir "$fuzz_build" --output-on-failure -L fuzz

python3 "$project_directory/scripts/generate-sbom.py" \
    "$output_directory/janusgate.spdx.json"
archive=janusgate-0.2.1.tar.gz
git archive --format=tar --mtime="@$source_date_epoch" \
    --prefix=janusgate-0.2.1/ 'HEAD^{tree}' -- . \
    ':(exclude)packaging/alpine/APKBUILD' |
    gzip -n >"$output_directory/$archive"
gpg --batch --armor --local-user "$signing_key" --detach-sign \
    "$output_directory/$archive"

cp "$project_directory/api/openapi.yaml" \
    "$output_directory/janusgate-openapi-0.2.1.yaml"
cp "$project_directory/CHANGELOG.md" \
    "$output_directory/janusgate-0.2.1-release-notes.md"
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 \
    --numeric-owner --create --gzip \
    --file="$output_directory/janusgate-0.2.1-doxygen.tar.gz" \
    --directory="$release_build/docs/html" .

python3 - "$release_build/include/janusgate/version.h" \
    "$project_directory/include/janusgate/database.h" \
    "$output_directory/janusgate-0.2.1-build-manifest.json" <<'PY'
import json
import re
import sys
from pathlib import Path

version_header = Path(sys.argv[1]).read_text(encoding="utf-8")
database_header = Path(sys.argv[2]).read_text(encoding="utf-8")


def string_macro(name: str) -> str:
    """Return one quoted build-identity macro."""
    match = re.search(rf'^#define {name} "([^"]*)"$', version_header, re.MULTILINE)
    if match is None:
        raise SystemExit(f"missing build identity: {name}")
    return match.group(1)


schema = re.search(
    r"^#define JG_DATABASE_SCHEMA_VERSION ([0-9]+)U$",
    database_header,
    re.MULTILINE,
)
if schema is None:
    raise SystemExit("missing database schema version")

manifest = {
    "_license": "AGPL-3.0-or-later",
    "_copyright": "Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>",
    "version": string_macro("JANUSGATE_VERSION"),
    "source_commit": string_macro("JANUSGATE_BUILD_COMMIT"),
    "build_timestamp": string_macro("JANUSGATE_BUILD_TIMESTAMP"),
    "compiler": string_macro("JANUSGATE_BUILD_COMPILER"),
    "target": string_macro("JANUSGATE_BUILD_TARGET"),
    "database_schema_version": int(schema.group(1)),
    "sbom": "janusgate.spdx.json",
}
Path(sys.argv[3]).write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

(
    cd "$output_directory"
    set -- janusgate-* janusgate.spdx.json
    sha256sum "$@" >SHA256SUMS
    sha512sum "$@" >SHA512SUMS
)

if [ -n "$(git -C "$project_directory" status --porcelain \
    --untracked-files=no)" ]; then
    fail "tracked source files changed during validation"
fi

release_complete=true
echo "Release check passed"
echo "Release artifacts: $output_directory"
