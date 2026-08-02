#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

civetweb_version=1.16
aports_commit=dfed50eb92492320e6eda77372e0eec3105c098c
install_prefix=${1-}
temporary_directory=
install_created=false
install_complete=false
openssl_crypto=
openssl_include=
openssl_ssl=

# Stop with one concise dependency-build error.
fail()
{
    echo "CivetWeb build: $*" >&2
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

# Download one immutable build input.
download()
{
    url=$1
    output=$2

    curl --fail --location --retry 3 --output "$output" "$url"
}

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

# Add the ports OpenSSL paths required by an OpenBSD build.
configure_openbsd_openssl()
{
    openssl_crypto=$(pkg_info -L openssl |
        awk '/\/libcrypto\.so\.[0-9]+\.[0-9]+$/ { print; exit }')
    openssl_ssl=$(pkg_info -L openssl |
        awk '/\/libssl\.so\.[0-9]+\.[0-9]+$/ { print; exit }')
    if [ -z "$openssl_crypto" ] || [ -z "$openssl_ssl" ]; then
        fail "the OpenSSL 3 package is unavailable"
    fi
    openssl_include="/usr/local/include/$(basename \
        "$(dirname "$openssl_crypto")")"
}

[ "$#" -eq 1 ] || fail "usage: scripts/build-civetweb.sh ABSOLUTE_PREFIX"
case $install_prefix in
    /*) ;;
    *) fail "the installation prefix must be absolute" ;;
esac
case $install_prefix in
    / | /usr | /usr/local)
        fail "refusing an unsafe installation prefix: $install_prefix"
        ;;
esac
[ ! -e "$install_prefix" ] || fail "refusing to overwrite: $install_prefix"

for program in awk basename cmake curl dirname mktemp ninja patch tar; do
    command -v "$program" >/dev/null 2>&1 ||
        fail "required program is unavailable: $program"
done
if ! command -v sha512 >/dev/null 2>&1 &&
    ! command -v sha512sum >/dev/null 2>&1; then
    fail "required SHA-512 utility is unavailable"
fi

temporary_directory=$(mktemp -d)
source_archive="$temporary_directory/civetweb-$civetweb_version.tar.gz"
cmake_patch="$temporary_directory/CMakeLists.txt.patch"
heap_patch="$temporary_directory/fix-heap-overflow.patch"
url_patch="$temporary_directory/more-robust-url-parsing.patch"
source_directory="$temporary_directory/civetweb-$civetweb_version"

download \
    "https://github.com/civetweb/civetweb/archive/v$civetweb_version/civetweb-$civetweb_version.tar.gz" \
    "$source_archive"
download \
    "https://gitlab.alpinelinux.org/alpine/aports/-/raw/$aports_commit/testing/civetweb/CMakeLists.txt.patch" \
    "$cmake_patch"
download \
    "https://gitlab.alpinelinux.org/alpine/aports/-/raw/$aports_commit/testing/civetweb/fix-heap-overflow.patch" \
    "$heap_patch"
download \
    "https://gitlab.alpinelinux.org/alpine/aports/-/raw/$aports_commit/testing/civetweb/more-robust-url-parsing.patch" \
    "$url_patch"

verify_sha512 \
    a0b943dfc76d7fd47f5a7d2c834fd38ddd4cf01a11730cf2f7cfaf32fea9698f59672f3a0f86ac80e0abc315d94d2367a500d37013f305c87d45e84cf39ca816 \
    "$source_archive"
verify_sha512 \
    da70d66c37aac46478df7f772a5765f1b12177ea4ea2206e0f33696741169eb096edcdef986174785c0504ced97ca10256c91fd4882c5dd23a6b87473f7b60cd \
    "$cmake_patch"
verify_sha512 \
    d48dd1892ab64df0367abff37cf0121fd994f7630d4262d1f06a34076804f9ba01f8eb40eaa14ead8bb5ba779a547c34edd0e48670b1d84dd54ed04ff1861120 \
    "$heap_patch"
verify_sha512 \
    a003769a11d5dcb8eaf308eb218d3c23715b625645c1d112960a8eaa63aa49de17791107716d9516770bc1c025e712b22424b2fc82872a7867222c9e3a5c09b2 \
    "$url_patch"

tar -xzf "$source_archive" -C "$temporary_directory"
for patch_file in "$cmake_patch" "$heap_patch" "$url_patch"; do
    patch -d "$source_directory" -p1 <"$patch_file"
done
rm -f -- "$source_directory/build"

mkdir -p "$install_prefix"
install_created=true
set --
if [ "$(uname -s)" = OpenBSD ]; then
    configure_openbsd_openssl
    set -- \
        "-DOPENSSL_INCLUDE_DIR=$openssl_include" \
        "-DOPENSSL_CRYPTO_LIBRARY=$openssl_crypto" \
        "-DOPENSSL_SSL_LIBRARY=$openssl_ssl"
fi
cmake -S "$source_directory" -B "$temporary_directory/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DCMAKE_INSTALL_PREFIX="$install_prefix" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DBUILD_SHARED_LIBS=ON \
    -DCIVETWEB_ALLOW_WARNINGS=ON \
    -DCIVETWEB_BUILD_TESTING=OFF \
    -DCIVETWEB_DISABLE_CGI=ON \
    -DCIVETWEB_ENABLE_CXX=OFF \
    -DCIVETWEB_ENABLE_DUKTAPE=OFF \
    -DCIVETWEB_ENABLE_LUA=OFF \
    -DCIVETWEB_ENABLE_SERVER_EXECUTABLE=OFF \
    -DCIVETWEB_ENABLE_WEBSOCKETS=OFF \
    -DCIVETWEB_INSTALL_EXECUTABLE=OFF \
    -DCIVETWEB_SSL_OPENSSL_API_1_1=OFF \
    -DCIVETWEB_SSL_OPENSSL_API_3_0=ON \
    -DCIVETWEB_ENABLE_SSL_DYNAMIC_LOADING=OFF \
    "$@"
cmake --build "$temporary_directory/build" --parallel 2
cmake --install "$temporary_directory/build"
test -f "$install_prefix/include/civetweb.h" ||
    fail "the CivetWeb header was not installed"
find "$install_prefix/lib" -type f -name 'libcivetweb.so*' -print |
    grep -m 1 . >/dev/null ||
    fail "the CivetWeb shared library was not installed"

install_complete=true
echo "TLS-enabled CivetWeb: $install_prefix"
