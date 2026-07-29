<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Build and verification

JanusGate requires CMake 3.25 or newer, Ninja, Python 3, a C17 compiler,
Doxygen with Graphviz, and development packages for CivetWeb, OpenSSL, zlib,
libidn2, libcurl, Jansson, libcap, libseccomp, libmnl,
libnetfilter_queue, libnftables, libsodium, and SQLite.

## Debian or Ubuntu

Install the distribution development packages, then run:

```sh
cmake --preset debug
cmake --build --preset debug --parallel 4
ctest --preset debug --output-on-failure
```

Use `CC=clang cmake --preset debug` in a fresh build directory for a plain
Clang build. All production targets build with strict warnings and warnings as
errors by default.

## Alpine

The `alpine-debug` and `alpine-asan` presets use musl when executed on Alpine:

```sh
cmake --preset alpine-debug
cmake --build --preset alpine-debug --parallel 4
ctest --preset alpine-debug --output-on-failure
```

`packaging/alpine/APKBUILD` builds the release package and runs its tests. The
companion CivetWeb APKBUILD supplies the reviewed library package for the
3.24 appliance branch.

## Sanitizers and fuzzing

`JANUSGATE_ENABLE_SANITIZERS=ON` applies AddressSanitizer and
UndefinedBehaviorSanitizer together, with frame pointers, to every project
target:

```sh
cmake --preset asan
cmake --build --preset asan --parallel 4
ctest --preset asan --output-on-failure

cmake --preset clang-ubsan
cmake --build --preset clang-ubsan --parallel 4
ctest --preset clang-ubsan --output-on-failure
```

The fuzz preset requires Clang and libFuzzer:

```sh
cmake --preset fuzz
cmake --build --preset fuzz --parallel 4
ctest --preset fuzz --output-on-failure -L fuzz
```

Seed corpora are derived deterministically from `tests/fixtures`.

## Quality gates

```sh
cmake --build --preset debug --target doxygen
cmake --build --preset debug --target static-analysis
cmake --build --preset debug --target format-check
cmake --build --preset debug --target openapi-check
python3 scripts/check-source-metadata.py
git ls-files -z '*.sh' | xargs -0 shellcheck -s sh
git ls-files -z '*.sh' | xargs -0 shfmt -d -i 4 -ci -fn
```

The namespace laboratory requires root only for temporary network namespaces
and links:

```sh
sudo tests/namespace-lab/run-all.sh --build-directory build/debug
```

It removes only the interfaces and namespaces created by its own invocation.

## Reproducibility

Build metadata embeds the source revision, compiler, target, and version.
Packaging and firmware scripts derive `SOURCE_DATE_EPOCH` from the source
commit unless it is supplied explicitly. Downloads are pinned by digest,
archives use stable ordering and timestamps, and image manifests record their
inputs. Use the same toolchain and environment when comparing byte-for-byte
artifacts.

`scripts/release-check.sh` runs the complete local source, build, test,
sanitizer, fuzz-smoke, analysis, documentation, benchmark, SBOM, archive, and
checksum gates in temporary directories.
