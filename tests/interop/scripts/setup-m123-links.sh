#!/bin/sh
# M123 netdevs: the rustbgpd PE bundles its CE link into an 802.3ad bond with
# the LACP system and key SR Linux uses for lag1; the CE bonds both PE links.
set -eu
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
case "${1:?pe or ce}" in
    pe)
        ip link add es0 type bond mode 802.3ad miimon 100 lacp_rate fast \
            ad_actor_system 00:00:00:00:01:23 ad_actor_sys_prio 65535
        ip link set eth2 down
        ip link set eth2 master es0
        ip link add br100 type bridge mcast_snooping 0
        ip link add vxlan100 type vxlan id 100 local 10.0.123.1 dev eth1 dstport 4789 nolearning
        ip link set vxlan100 master br100
        bridge link set dev vxlan100 learning off
        ip link set es0 master br100
        for dev in eth2 es0 vxlan100 br100; do ip link set "$dev" up; done
        ;;
    ce)
        ip link add bond0 type bond mode 802.3ad miimon 100 lacp_rate fast
        for dev in eth1 eth2; do
            ip link set "$dev" down
            ip link set "$dev" master bond0
            ip link set "$dev" up
        done
        ip link set bond0 up
        ip addr add 198.18.123.10/24 dev bond0
        ;;
    *) exit 2 ;;
esac
