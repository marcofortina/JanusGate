<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Build and verification

JanusGate requires CMake 3.25 or newer, Ninja, Python 3, a C17 compiler,
Doxygen with Graphviz, and development packages for CivetWeb, OpenSSL, zlib,
libidn2, libcurl, Jansson, libsodium, and SQLite. Linux additionally requires
libcap, libseccomp, libmnl, libnetfilter_queue, and libnftables.

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

## OpenBSD

OpenBSD 7.9 uses the native Clang compiler, bridge and BPF interfaces, PF
divert sockets, `pledge`, and rc.d. Install the required packages with:

```sh
pkg_add bash cmake cmocka curl groff jansson libidn2 libsodium \
  ninja openssl%3.5 py3-jsonschema py3-yaml sqlite3
```

The packaged libcurl uses LibreSSL, while JanusGate requires OpenSSL 3. Loading
both providers in one process is unsafe on OpenBSD. Build the pinned
OpenSSL-backed libcurl in its dedicated runtime directory:

```sh
doas scripts/build-curl.sh /usr/local/libexec/janusgate/curl
curl_prefix=/usr/local/libexec/janusgate/curl
export PKG_CONFIG_PATH="$curl_prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
```

The packaged CivetWeb library omits TLS. Build the pinned, patched TLS variant
in a separate runtime directory before configuring JanusGate:

```sh
doas scripts/build-civetweb.sh /usr/local/libexec/janusgate/civetweb
civetweb_prefix=/usr/local/libexec/janusgate/civetweb
civetweb_library=$(find "$civetweb_prefix/lib" -type f \
  -name 'libcivetweb.so*' -print | sort | tail -n 1)
```

Both scripts verify immutable source inputs; the CivetWeb build also applies
the Alpine security patches used by the appliance package. The `pkg-config`
implementation is part of the base system. Configure the ports OpenSSL and
CivetWeb paths explicitly because the base system TLS library remains
separately available:

```sh
openssl_crypto=$(pkg_info -L openssl |
  awk '/\/libcrypto\.so\.[0-9]+\.[0-9]+$/ { print; exit }')
openssl_include="/usr/local/include/$(basename \
  "$(dirname "$openssl_crypto")")"
cmake -S . -B build/openbsd -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr/local \
  -DCMAKE_INSTALL_SYSCONFDIR=/etc \
  -DCMAKE_INSTALL_LOCALSTATEDIR=/var \
  -DJANUSGATE_BUILD_DOCUMENTATION=OFF \
  -DCIVETWEB_INCLUDE_DIR="$civetweb_prefix/include" \
  -DCIVETWEB_LIBRARY="$civetweb_library" \
  -DOPENSSL_INCLUDE_DIR="$openssl_include" \
  -DOPENSSL_CRYPTO_LIBRARY="$openssl_crypto"
cmake --build build/openbsd --parallel 2
ctest --test-dir build/openbsd --output-on-failure
```

The installer uses `config/janusgate.openbsd.conf.example`, installs binaries
under `/usr/local`, preserves the runtime search paths of ports dependencies,
and enables the supplied rc.d services without starting them. Validate the
installed Web service after staging or installation with
`/usr/local/sbin/janusgate-web --version`.

The purpose, runtime role, and license of each direct dependency are recorded
in [Dependencies](dependencies.md).

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
checksum gates in temporary directories. It signs the source archive with
`JANUSGATE_SIGNING_KEY`, or the configured Git signing key when the variable is
unset, and publishes versioned OpenAPI, Doxygen, release-note, and build
manifest artifacts beside the checksums. The separate appliance-image workflow
builds and boots the Alpine, x86_64, and AArch64 deliverables.
