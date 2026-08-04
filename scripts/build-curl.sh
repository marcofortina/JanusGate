#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

curl_version=8.21.0
curl_sha512=1a1c88d7e52200d0a8879f61868accd7eb7edacb730e09db8e1f741535e9906005c897c2ce39b562c20e1b3ef2c84512f5b4fda9aa50c67e2364c473d15a1f65
install_prefix=${1-}
temporary_directory=
install_created=false
install_complete=false

# Stop with one concise dependency-build error.
fail()
{
    echo "libcurl build: $*" >&2
    exit 1
}

# Remove only files created by this invocation.
cleanup()
{
    if [ -n "$temporary_directory" ] &&
        [ -d "$temporary_directory" ]; then
        rm -rf -- "$temporary_directory"
    fi
    if "$install_created" && ! "$install_complete"; then
        rm -rf -- "$install_prefix"
    fi
}
trap cleanup EXIT HUP INT TERM

# Validate one build input with the native SHA-512 utility.
verify_sha512()
{
    expected=$1
    file=$2
    actual=

    if command -v sha512 >/dev/null 2>&1; then
        actual=$(sha512 -q "$file")
    else
        actual=$(sha512sum "$file" | awk '{ print $1 }')
    fi
    [ "$actual" = "$expected" ] ||
        fail "SHA-512 mismatch: $(basename "$file")"
}

# Locate the ports OpenSSL libraries used by every JanusGate TLS consumer.
configure_openbsd_openssl()
{
    openssl_crypto=$(pkg_info -L openssl |
        awk '/\/libcrypto\.so\.[0-9]+\.[0-9]+$/ { print; exit }')
    openssl_ssl=$(pkg_info -L openssl |
        awk '/\/libssl\.so\.[0-9]+\.[0-9]+$/ { print; exit }')
    if [ -z "$openssl_crypto" ] || [ -z "$openssl_ssl" ]; then
        fail "the OpenSSL 3 package is unavailable"
    fi
    openssl_library_directory=$(dirname "$openssl_crypto")
    openssl_include="/usr/local/include/$(basename \
        "$openssl_library_directory")"
}

[ "$#" -eq 1 ] || fail "usage: scripts/build-curl.sh ABSOLUTE_PREFIX"
case $install_prefix in
    /*) ;;
    *) fail "the installation prefix must be absolute" ;;
esac
case $install_prefix in
    / | /usr | /usr/local)
        fail "refusing an unsafe installation prefix: $install_prefix"
        ;;
esac
[ "$(uname -s)" = OpenBSD ] || fail "this build is required only on OpenBSD"
[ ! -e "$install_prefix" ] || fail "refusing to overwrite: $install_prefix"

for program in awk basename cmake curl dirname mktemp ninja pkg_info tar; do
    command -v "$program" >/dev/null 2>&1 ||
        fail "required program is unavailable: $program"
done
if ! command -v sha512 >/dev/null 2>&1 &&
    ! command -v sha512sum >/dev/null 2>&1; then
    fail "required SHA-512 utility is unavailable"
fi

configure_openbsd_openssl
temporary_directory=$(mktemp -d)
source_archive="$temporary_directory/curl-$curl_version.tar.gz"
source_directory="$temporary_directory/curl-$curl_version"
curl --fail --location --retry 3 --output "$source_archive" \
    "https://curl.se/download/curl-$curl_version.tar.gz"
verify_sha512 "$curl_sha512" "$source_archive"
tar -xzf "$source_archive" -C "$temporary_directory"

mkdir -p "$install_prefix"
install_created=true
cmake -S "$source_directory" -B "$temporary_directory/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DCMAKE_INSTALL_PREFIX="$install_prefix" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_INSTALL_RPATH="$openssl_library_directory" \
    -DBUILD_CURL_EXE=OFF \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_LIBCURL_DOCS=OFF \
    -DBUILD_MISC_DOCS=OFF \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_STATIC_LIBS=OFF \
    -DBUILD_TESTING=OFF \
    -DCURL_BROTLI=OFF \
    -DCURL_USE_LIBPSL=OFF \
    -DCURL_USE_OPENSSL=ON \
    -DCURL_USE_PKGCONFIG=OFF \
    -DCURL_ZLIB=ON \
    -DCURL_ZSTD=OFF \
    -DHTTP_ONLY=ON \
    -DOPENSSL_INCLUDE_DIR="$openssl_include" \
    -DOPENSSL_CRYPTO_LIBRARY="$openssl_crypto" \
    -DOPENSSL_SSL_LIBRARY="$openssl_ssl" \
    -DUSE_LIBIDN2=OFF \
    -DUSE_NGHTTP2=OFF
cmake --build "$temporary_directory/build" --parallel 2
cmake --install "$temporary_directory/build"
test -f "$install_prefix/include/curl/curl.h" ||
    fail "the libcurl header was not installed"
test -f "$install_prefix/lib/pkgconfig/libcurl.pc" ||
    fail "the libcurl pkg-config metadata was not installed"
find "$install_prefix/lib" -type f -name 'libcurl.so*' -print |
    grep -m 1 . >/dev/null ||
    fail "the libcurl shared library was not installed"

install_complete=true
echo "OpenSSL-backed libcurl: $install_prefix"
