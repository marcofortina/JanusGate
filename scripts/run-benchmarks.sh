#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

rules=${JANUSGATE_BENCHMARK_RULES:-1000000}
lookups=${JANUSGATE_BENCHMARK_LOOKUPS:-200000}
packets=${JANUSGATE_BENCHMARK_PACKETS:-500000}
jobs=${JANUSGATE_BUILD_JOBS:-4}

# Stop with one concise benchmark error.
fail()
{
    echo "Benchmark: $*" >&2
    exit 1
}

for program in cmake git; do
    command -v "$program" >/dev/null 2>&1 ||
        fail "required program is unavailable: $program"
done
for value in "$rules" "$lookups" "$packets" "$jobs"; do
    case $value in
        *[!0-9]* | "")
            fail "counts and job count must be positive integers"
            ;;
    esac
    [ "$value" -gt 0 ] || fail "counts and job count must be positive"
done

project_directory=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
source_date_epoch=${SOURCE_DATE_EPOCH:-$(
    git -C "$project_directory" log -1 --format=%ct
)}
export SOURCE_DATE_EPOCH="$source_date_epoch"

cmake --preset performance -S "$project_directory"
cmake --build --preset performance --target janusgate-policy-benchmark \
    --parallel "$jobs"
benchmark="$project_directory/build/performance/tests/performance/janusgate-policy-benchmark"
exec "$benchmark" \
    --rules "$rules" --lookups "$lookups" --packets "$packets" --enforce
