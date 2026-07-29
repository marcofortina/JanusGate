#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

jobs=${JANUSGATE_BUILD_JOBS:-4}
output_directory=${JANUSGATE_RELEASE_OUTPUT:-out/release}
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

for program in clang cmake cppcheck doxygen git ninja python3 \
    run-clang-tidy sha256sum sha512sum shellcheck shfmt xargs; do
    command -v "$program" >/dev/null 2>&1 ||
        fail "required program is unavailable: $program"
done

project_directory=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
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
cmake --build "$release_build" --target package_source
set -- "$release_build"/janusgate-*.tar.gz
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    fail "exactly one source archive is required"
fi
archive=$1
cp "$archive" "$output_directory/"
(
    cd "$output_directory"
    set -- janusgate-*.tar.gz janusgate.spdx.json
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
