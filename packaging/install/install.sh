#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

build_directory=build/release
config_file=
dry_run=false
unattended=false
network_risk_confirmed=false
system_id=
install_prefix=/usr

# Print command-line help.
usage()
{
    cat <<'EOF'
usage: packaging/install/install.sh --config FILE [options]

Options:
  --build-directory DIR   configured CMake build (default: build/release)
  --config FILE           validated non-interactive setup document
  --dry-run               validate and print actions without installing
  --unattended            suppress the local confirmation question
  --confirm-network-risk  acknowledge management changes over an SSH session
  --help                  show this help
EOF
}

# Stop with one concise installation error.
fail()
{
    echo "janusgate installer: $*" >&2
    exit 1
}

# Print one shell-escaped command for dry-run review.
print_command()
{
    printf '+'
    for argument in "$@"; do
        printf " '%s'" "$(printf '%s' "$argument" | sed "s/'/'\\\\''/g")"
    done
    printf '\n'
}

# Execute one mutation or print it during a dry run.
run()
{
    if "$dry_run"; then
        print_command "$@"
    else
        "$@"
    fi
}

# Require one executable used by the installer.
require_program()
{
    command -v "$1" >/dev/null 2>&1 ||
        fail "required program is unavailable: $1"
}

# Require one exact system-install path in the configured CMake cache.
require_cache_value()
{
    name=$1
    expected=$2
    grep -Eq "^${name}(:[^=]+)?=${expected}$" \
        "$build_directory/CMakeCache.txt" ||
        fail "configure $name=$expected before installation"
}

# Accept only the distributions covered by project packaging.
validate_distribution()
{
    if [ "$(uname -s)" = OpenBSD ]; then
        system_id=openbsd
        install_prefix=/usr/local
        return
    fi
    [ -r /etc/os-release ] || fail "cannot identify the operating system"
    # shellcheck disable=SC1091
    . /etc/os-release
    case ${ID-} in
        alpine | debian | ubuntu)
            system_id=$ID
            ;;
        *)
            fail "supported systems are Alpine, Debian, Ubuntu, and OpenBSD"
            ;;
    esac
}

# Add one existing service user to a supplementary group exactly once.
ensure_membership()
{
    user=$1
    group=$2
    if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fx "$group" \
        >/dev/null 2>&1; then
        return
    fi
    if [ "$system_id" = alpine ]; then
        run addgroup "$user" "$group"
    elif [ "$system_id" = openbsd ]; then
        run usermod -G "$group" "$user"
    else
        run usermod --append --groups "$group" "$user"
    fi
}

# Create the least-privilege service identities when they are absent.
create_identities()
{
    if [ "$system_id" = alpine ]; then
        getent group janusgate-control >/dev/null 2>&1 ||
            run addgroup -S janusgate-control
        getent group janusgate >/dev/null 2>&1 ||
            run addgroup -S janusgate
        getent group janusgate-web >/dev/null 2>&1 ||
            run addgroup -S janusgate-web
        id janusgate >/dev/null 2>&1 ||
            run adduser -S -D -H -h /var/lib/janusgate -s /sbin/nologin \
                -G janusgate janusgate
        id janusgate-web >/dev/null 2>&1 ||
            run adduser -S -D -H -h /var/empty -s /sbin/nologin \
                -G janusgate-web janusgate-web
    elif [ "$system_id" = openbsd ]; then
        getent group janusgate-control >/dev/null 2>&1 ||
            run groupadd janusgate-control
        getent group janusgate >/dev/null 2>&1 ||
            run groupadd janusgate
        getent group janusgate-web >/dev/null 2>&1 ||
            run groupadd janusgate-web
        id janusgate >/dev/null 2>&1 ||
            run useradd -g janusgate -d /var/lib/janusgate \
                -s /sbin/nologin janusgate
        id janusgate-web >/dev/null 2>&1 ||
            run useradd -g janusgate-web -d /var/empty \
                -s /sbin/nologin janusgate-web
    else
        getent group janusgate-control >/dev/null 2>&1 ||
            run groupadd --system janusgate-control
        getent group janusgate >/dev/null 2>&1 ||
            run groupadd --system janusgate
        getent group janusgate-web >/dev/null 2>&1 ||
            run groupadd --system janusgate-web
        id janusgate >/dev/null 2>&1 ||
            run useradd --system --gid janusgate --home-dir /var/lib/janusgate \
                --shell /usr/sbin/nologin janusgate
        id janusgate-web >/dev/null 2>&1 ||
            run useradd --system --gid janusgate-web --home-dir /var/empty \
                --shell /usr/sbin/nologin janusgate-web
    fi
    ensure_membership janusgate janusgate-control
    ensure_membership janusgate-web janusgate-control
}

# Ask for local approval unless unattended operation was selected.
confirm_installation()
{
    "$unattended" && return
    [ -t 0 ] || fail "use --unattended when standard input is not a terminal"
    printf 'Install JanusGate and apply the validated network roles? [y/N] '
    read -r answer
    case $answer in
        y | Y | yes | YES) ;;
        *)
            fail "installation cancelled"
            ;;
    esac
}

# Parse installer options without accepting ambiguous positional arguments.
while [ "$#" -gt 0 ]; do
    case $1 in
        --build-directory)
            [ "$#" -ge 2 ] || fail "--build-directory requires a value"
            build_directory=$2
            shift 2
            ;;
        --config)
            [ "$#" -ge 2 ] || fail "--config requires a value"
            config_file=$2
            shift 2
            ;;
        --dry-run)
            dry_run=true
            shift
            ;;
        --unattended)
            unattended=true
            shift
            ;;
        --confirm-network-risk)
            network_risk_confirmed=true
            shift
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

[ -n "$config_file" ] || fail "--config is required"
[ -r "$config_file" ] || fail "configuration is not readable: $config_file"
[ -f "$build_directory/cmake_install.cmake" ] ||
    fail "configured build is unavailable: $build_directory"
[ -x "$build_directory/janusgate-setup" ] ||
    fail "build janusgate-setup before installation"

require_program cmake
require_program grep
require_program sed
require_program uname
validate_distribution
require_cache_value CMAKE_INSTALL_PREFIX "$install_prefix"
require_cache_value CMAKE_INSTALL_SYSCONFDIR /etc
require_cache_value CMAKE_INSTALL_LOCALSTATEDIR /var

if [ -n "${SSH_CONNECTION-}" ] && ! "$network_risk_confirmed"; then
    fail "refusing network changes over SSH without --confirm-network-risk"
fi
if [ -e /etc/janusgate/janusgate.conf ]; then
    fail "refusing to overwrite unknown /etc/janusgate/janusgate.conf"
fi
if ! "$dry_run" && [ "$(id -u)" -ne 0 ]; then
    fail "installation requires root; use --dry-run for an unprivileged review"
fi

"$build_directory/janusgate-setup" --config "$config_file" --image-build \
    --validate-only
confirm_installation

if "$dry_run"; then
    create_identities
    print_command cmake --install "$build_directory" --prefix "$install_prefix"
    "$build_directory/janusgate-setup" --config "$config_file" --image-build \
        --dry-run
    echo "Dry run complete; no files or network state were changed."
    exit 0
fi

create_identities
cmake --install "$build_directory" --prefix "$install_prefix"
install -d -m 0750 -o janusgate -g janusgate /var/lib/janusgate
rollback_file="/var/lib/janusgate/install-rollback-$(date -u +%Y%m%dT%H%M%SZ).txt"
{
    echo "JanusGate installation rollback"
    echo "Installed from: $build_directory"
    echo "Recovery:"
    echo "  cmake --build '$build_directory' --target uninstall"
    echo "  restore network configuration from the setup rollback record"
} >"$rollback_file"
chmod 0600 "$rollback_file"

"$install_prefix/sbin/janusgate-setup" --config "$config_file" --confirm-network

echo "JanusGate installation complete."
echo "Rollback record: $rollback_file"
echo "Recovery: cmake --build '$build_directory' --target uninstall"
