#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

image=
build_directory=
https_port=${JANUSGATE_QEMU_HTTPS_PORT:-18443}
timeout_seconds=180
temporary_directory=
qemu_pid=

# Print command-line help.
usage()
{
    cat <<'EOF'
usage: scripts/run-qemu-smoke.sh TARGET [options]

Targets:
  alpine
  buildroot-x86_64
  buildroot-aarch64

Options:
  --image FILE           raw or QCOW2 disk image
  --build-directory DIR  Buildroot output directory
  --https-port PORT      host management HTTPS port
  --timeout SECONDS      boot timeout
  --help                 show this help
EOF
}

# Stop with one concise smoke-test error.
fail()
{
    echo "QEMU smoke test: $*" >&2
    exit 1
}

# Stop a surviving QEMU process and remove only this test's temporary files.
cleanup()
{
    if [ -n "$qemu_pid" ] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill -TERM "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    if [ -n "$temporary_directory" ] &&
        [ -d "$temporary_directory" ]; then
        rm -rf -- "$temporary_directory"
    fi
}
trap cleanup EXIT HUP INT TERM

# Send one command to the private QEMU monitor.
send_monitor_command()
{
    python3 - "$monitor_socket" "$1" <<'PY'
import socket
import sys
import time

path = sys.argv[1]
command = sys.argv[2].encode("ascii") + b"\n"
for _ in range(50):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
            monitor.settimeout(5)
            monitor.connect(path)
            response = b""
            while b"(qemu) " not in response:
                chunk = monitor.recv(4096)
                if not chunk:
                    raise OSError("QEMU monitor closed the connection")
                response += chunk
            monitor.sendall(command)
            response = b""
            while b"(qemu) " not in response:
                chunk = monitor.recv(4096)
                if not chunk:
                    raise OSError("QEMU monitor closed the connection")
                response += chunk
        break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("QEMU monitor is unavailable")
PY
}

# Wait for the authenticated management route to reach a stable service.
wait_for_management()
{
    elapsed=0
    while [ "$elapsed" -lt "$timeout_seconds" ]; do
        if ! kill -0 "$qemu_pid" 2>/dev/null; then
            tail -n 240 "$serial_log" >&2
            fail "virtual machine exited before readiness"
        fi
        status=$(curl --insecure --silent --output /dev/null \
            --write-out '%{http_code}' --connect-timeout 2 \
            --header 'Host: 192.168.77.1' \
            "https://127.0.0.1:$https_port/api/v1/status" || true)
        case $status in
            200 | 401 | 403)
                return 0
                ;;
        esac
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

[ "$#" -gt 0 ] || {
    usage >&2
    exit 2
}
target=$1
shift
case $target in
    alpine | buildroot-x86_64 | buildroot-aarch64) ;;
    *)
        fail "unsupported target: $target"
        ;;
esac

# Parse target paths and bounded timing controls.
while [ "$#" -gt 0 ]; do
    case $1 in
        --image)
            [ "$#" -ge 2 ] || fail "--image requires a value"
            image=$2
            shift 2
            ;;
        --build-directory)
            [ "$#" -ge 2 ] || fail "--build-directory requires a value"
            build_directory=$2
            shift 2
            ;;
        --https-port)
            [ "$#" -ge 2 ] || fail "--https-port requires a value"
            https_port=$2
            shift 2
            ;;
        --timeout)
            [ "$#" -ge 2 ] || fail "--timeout requires a value"
            timeout_seconds=$2
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
for number in "$https_port" "$timeout_seconds"; do
    case $number in
        *[!0-9]* | "")
            fail "port and timeout must be positive integers"
            ;;
    esac
done
if [ "$https_port" -le 0 ] || [ "$https_port" -gt 65535 ]; then
    fail "HTTPS port is outside 1..65535"
fi
[ "$timeout_seconds" -ge 30 ] ||
    fail "timeout must be at least 30 seconds"

for program in curl grep python3 sleep tail; do
    command -v "$program" >/dev/null 2>&1 ||
        fail "required program is unavailable: $program"
done

project_directory=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
case $target in
    alpine)
        [ -n "$image" ] ||
            image="$project_directory/out/alpine/janusgate-alpine-3.24.1-x86_64.raw"
        qemu_binary=qemu-system-x86_64
        ;;
    buildroot-x86_64)
        [ -n "$build_directory" ] ||
            build_directory="$project_directory/out/buildroot/janusgate_x86_64_efi_defconfig"
        [ -n "$image" ] ||
            image="$build_directory/images/janusgate-x86_64.img"
        qemu_binary="$build_directory/host/bin/qemu-system-x86_64"
        [ -x "$qemu_binary" ] || qemu_binary=qemu-system-x86_64
        ;;
    buildroot-aarch64)
        [ -n "$build_directory" ] ||
            build_directory="$project_directory/out/buildroot/janusgate_aarch64_virt_defconfig"
        [ -n "$image" ] ||
            image="$build_directory/images/janusgate-aarch64.img"
        qemu_binary="$build_directory/host/bin/qemu-system-aarch64"
        [ -x "$qemu_binary" ] || qemu_binary=qemu-system-aarch64
        ;;
esac
command -v "$qemu_binary" >/dev/null 2>&1 ||
    fail "required program is unavailable: $qemu_binary"
[ -f "$image" ] || fail "image does not exist: $image"

temporary_directory=$(mktemp -d)
serial_log="$temporary_directory/serial.log"
monitor_socket="$temporary_directory/monitor.sock"

# Append three deterministically ordered isolated NIC backends.
set -- \
    -netdev user,id=data_in,net=10.10.1.0/24 \
    -netdev user,id=data_out,net=10.10.2.0/24 \
    -netdev user,id=management,net=192.168.77.0/24,host=192.168.77.254,hostfwd=tcp:127.0.0.1:"$https_port"-192.168.77.1:443

if [ "$target" = buildroot-aarch64 ]; then
    kernel="$build_directory/images/Image"
    [ -f "$kernel" ] || fail "AArch64 kernel does not exist: $kernel"
    "$qemu_binary" -M virt -cpu cortex-a57 -accel tcg,thread=multi \
        -m 1024 -nographic -snapshot \
        -kernel "$kernel" \
        -append "root=/dev/vda1 rootwait ro console=ttyAMA0" \
        -drive if=none,id=root,format=raw,file="$image" \
        -device virtio-blk-device,drive=root \
        "$@" \
        -device virtio-net-device,netdev=management,mac=52:54:00:10:00:03 \
        -device virtio-net-device,netdev=data_out,mac=52:54:00:10:00:02 \
        -device virtio-net-device,netdev=data_in,mac=52:54:00:10:00:01 \
        -monitor unix:"$monitor_socket",server=on,wait=off \
        >"$serial_log" 2>&1 &
else
    disk_format=raw
    case $image in
        *.qcow2)
            disk_format=qcow2
            ;;
    esac
    firmware_arguments=
    if [ "$target" = buildroot-x86_64 ]; then
        for firmware in "$build_directory/images/OVMF.fd" \
            /usr/share/OVMF/OVMF_CODE.fd \
            /usr/share/OVMF/OVMF_CODE_4M.fd \
            /usr/share/ovmf/OVMF.fd \
            /usr/share/qemu/OVMF.fd \
            /usr/share/edk2/x64/OVMF_CODE.fd; do
            if [ -f "$firmware" ]; then
                firmware_arguments=$firmware
                break
            fi
        done
        [ -n "$firmware_arguments" ] ||
            fail "x86_64 UEFI firmware is unavailable"
    fi
    if [ -n "$firmware_arguments" ]; then
        set -- -bios "$firmware_arguments" "$@"
    fi
    "$qemu_binary" -machine q35 -accel tcg,thread=single \
        -icount shift=auto,align=off,sleep=on -m 1024 -nographic \
        -snapshot \
        -drive if=virtio,format="$disk_format",file="$image" \
        "$@" \
        -device virtio-net-pci,netdev=data_in,mac=52:54:00:10:00:01 \
        -device virtio-net-pci,netdev=data_out,mac=52:54:00:10:00:02 \
        -device virtio-net-pci,netdev=management,mac=52:54:00:10:00:03 \
        -monitor unix:"$monitor_socket",server=on,wait=off \
        >"$serial_log" 2>&1 &
fi
qemu_pid=$!

wait_for_management || {
    tail -n 240 "$serial_log" >&2
    fail "management HTTPS did not become ready"
}
if grep -Eiq 'kernel panic|segmentation fault|failed to start' "$serial_log"; then
    tail -n 240 "$serial_log" >&2
    fail "guest log contains a fatal startup error"
fi

# Reset once and require a complete second boot from persistent storage.
boot_count=$(grep -c 'Linux version ' "$serial_log" || true)
send_monitor_command system_reset
elapsed=0
while [ "$(grep -c 'Linux version ' "$serial_log" || true)" -le "$boot_count" ] &&
    [ "$elapsed" -lt "$timeout_seconds" ]; do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        tail -n 240 "$serial_log" >&2
        fail "virtual machine exited during reboot"
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done
[ "$elapsed" -lt "$timeout_seconds" ] || {
    tail -n 240 "$serial_log" >&2
    fail "guest did not reboot"
}
wait_for_management || {
    tail -n 240 "$serial_log" >&2
    fail "management HTTPS did not recover after reboot"
}
if grep -Eiq 'kernel panic|segmentation fault|failed to start' "$serial_log"; then
    tail -n 240 "$serial_log" >&2
    fail "guest log contains a fatal error after reboot"
fi

# Request an orderly ACPI shutdown through the QEMU monitor.
send_monitor_command system_powerdown
elapsed=0
while kill -0 "$qemu_pid" 2>/dev/null &&
    [ "$elapsed" -lt "$timeout_seconds" ]; do
    sleep 1
    elapsed=$((elapsed + 1))
done
if kill -0 "$qemu_pid" 2>/dev/null; then
    tail -n 240 "$serial_log" >&2
    fail "guest did not complete an orderly shutdown"
fi
wait "$qemu_pid"
qemu_pid=

echo "QEMU smoke test passed: $target"
