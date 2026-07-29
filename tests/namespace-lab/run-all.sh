#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

build_directory=${JANUSGATE_BUILD_DIRECTORY:-build/alpine-debug}
case ${1-} in
    --build-directory)
        [ "$#" -eq 2 ] || {
            echo "usage: $0 [--build-directory DIRECTORY]" >&2
            exit 2
        }
        build_directory=$2
        ;;
    "") ;;
    *)
        echo "usage: $0 [--build-directory DIRECTORY]" >&2
        exit 2
        ;;
esac

[ "$(id -u)" -eq 0 ] || {
    echo "namespace lab requires root" >&2
    exit 1
}

for program in ip ping; do
    command -v "$program" >/dev/null 2>&1 || {
        echo "namespace lab requires $program" >&2
        exit 1
    }
done

integration_test=$build_directory/tests/janusgate-integration-tests
[ -x "$integration_test" ] || {
    echo "missing integration executable: $integration_test" >&2
    exit 1
}

token=$(($$ % 100000))
lan_namespace=jg-lan-$token
upstream_namespace=jg-up-$token
management_namespace=jg-mgmt-$token
bridge=jgb$token
data_in=jgi$token
data_out=jgo$token
management_host=jgm$token

cleanup()
{
    ip link del "$bridge" >/dev/null 2>&1 || true
    ip link del "$management_host" >/dev/null 2>&1 || true
    ip netns del "$lan_namespace" >/dev/null 2>&1 || true
    ip netns del "$upstream_namespace" >/dev/null 2>&1 || true
    ip netns del "$management_namespace" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

ip netns add "$lan_namespace"
ip netns add "$upstream_namespace"
ip netns add "$management_namespace"

ip link add "$data_in" type veth peer name lan0 netns "$lan_namespace"
ip link add "$data_out" type veth peer name up0 netns "$upstream_namespace"
ip link add "$management_host" type veth peer name mgmt0 \
    netns "$management_namespace"
ip link add "$bridge" type bridge
ip link set "$data_in" master "$bridge"
ip link set "$data_out" master "$bridge"
ip link set "$bridge" up
ip link set "$data_in" up
ip link set "$data_out" up
ip link set "$management_host" up

ip -n "$lan_namespace" link set lo up
ip -n "$upstream_namespace" link set lo up
ip -n "$management_namespace" link set lo up
ip -n "$lan_namespace" link set lan0 up
ip -n "$upstream_namespace" link set up0 up
ip -n "$management_namespace" link set mgmt0 up

ip -n "$lan_namespace" address add 192.0.2.10/24 dev lan0
ip -n "$upstream_namespace" address add 192.0.2.20/24 dev up0
ip -n "$lan_namespace" -6 address add 2001:db8:1::10/64 dev lan0
ip -n "$upstream_namespace" -6 address add 2001:db8:1::20/64 dev up0
ip address add 192.168.77.1/24 dev "$management_host"
ip -n "$management_namespace" address add 192.168.77.2/24 dev mgmt0

ip netns exec "$lan_namespace" ping -4 -c 2 -W 1 192.0.2.20 >/dev/null
ip netns exec "$upstream_namespace" ping -4 -c 2 -W 1 192.0.2.10 >/dev/null
ip netns exec "$lan_namespace" ping -6 -c 2 -W 1 2001:db8:1::20 >/dev/null

ip -n "$lan_namespace" link add link lan0 name lan0.37 type vlan id 37
ip -n "$upstream_namespace" link add link up0 name up0.37 type vlan id 37
ip -n "$lan_namespace" address add 198.51.100.10/24 dev lan0.37
ip -n "$upstream_namespace" address add 198.51.100.20/24 dev up0.37
ip -n "$lan_namespace" link set lan0.37 up
ip -n "$upstream_namespace" link set up0.37 up
ip netns exec "$lan_namespace" ping -4 -c 2 -W 1 198.51.100.20 >/dev/null

ip -n "$lan_namespace" link set lan0 mtu 1400
ip -n "$upstream_namespace" link set up0 mtu 1400
ip netns exec "$lan_namespace" ping -4 -c 1 -W 1 -s 1300 \
    192.0.2.20 >/dev/null

ip netns exec "$management_namespace" ping -4 -c 1 -W 1 \
    192.168.77.1 >/dev/null
if ip netns exec "$lan_namespace" ping -4 -c 1 -W 1 \
    192.168.77.2 >/dev/null 2>&1; then
    echo "management network leaked into the data bridge" >&2
    exit 1
fi

"$integration_test"
echo "Namespace lab passed: IPv4, IPv6, ARP/ND, VLAN, MTU, and management isolation"
