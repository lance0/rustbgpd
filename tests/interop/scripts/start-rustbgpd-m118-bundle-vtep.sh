#!/bin/sh
# Native devices in a fresh, owned container. The test starts the daemon later.
set -eu

echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
ip link add brbundle type bridge vlan_filtering 1 vlan_default_pvid 0
ip link set brbundle up
for tag in 10 20; do
    vni=$((10000 + tag))
    ip link add "vxlan$vni" type vxlan id "$vni" local 10.0.118.1 dstport 4789 nolearning
    ip link set "vxlan$vni" master brbundle up
    bridge vlan add dev brbundle vid "$tag" self
    bridge vlan add dev "vxlan$vni" vid "$tag"
    ip link add "access$tag" type veth peer name "host$tag"
    ip link set "access$tag" master brbundle up
    ip link set "host$tag" up
    bridge vlan add dev "access$tag" vid "$tag" pvid untagged
done

# This VRF is deliberately not linked to either bundle member.
ip link add vrfnegative type vrf table 10500
ip link set vrfnegative up
ip link add l3vxlan10500 type vxlan id 10500 local 10.0.118.1 dstport 4789 nolearning
ip link set l3vxlan10500 address 02:00:00:01:18:50
ip link set l3vxlan10500 master vrfnegative up
