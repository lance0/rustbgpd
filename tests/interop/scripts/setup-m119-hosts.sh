#!/bin/sh
# Each host has its own network namespace: traffic must cross the two VTEPs.
set -eu
mode=${1:?vtep or client}
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
case "$mode" in
    vtep)
        ip link add brbundle type bridge vlan_filtering 1 vlan_default_pvid 0
        ip link set brbundle up
        host=1
        mac=02:aa:bb:01:19:01
        ;;
    client) host=2; mac=02:aa:bb:01:19:02 ;;
    *) exit 2 ;;
esac
for tag in 10 20; do
    ip netns add "h$tag"
    if [ "$mode" = vtep ]; then
        vni=$((10000 + tag))
        ip link add "vxlan$vni" type vxlan id "$vni" local 10.0.119.1 dev eth1 dstport 4789 nolearning
        ip link set "vxlan$vni" master brbundle up
        bridge vlan add dev brbundle vid "$tag" self
        bridge vlan add dev "vxlan$vni" vid "$tag" pvid untagged
        ip link add "access$tag" type veth peer name "host$tag"
        ip link set "access$tag" master brbundle up
        bridge vlan add dev "access$tag" vid "$tag" pvid untagged
    else
        ip link add link eth1 name "host$tag" type vlan id "$tag"
    fi
    ip link set "host$tag" netns "h$tag"
    ip -n "h$tag" link set lo up
    ip -n "h$tag" link set "host$tag" address "$mac" up
    ip -n "h$tag" addr add "198.18.$tag.$host/24" dev "host$tag"
done
