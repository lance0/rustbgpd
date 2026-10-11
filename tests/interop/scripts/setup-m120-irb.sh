#!/bin/sh
# Preserve the M119 bundle hosts, then attach their SVIs to an IP-VRF.
set -eu
mode=${1:?vtep or client}
sh /usr/local/bin/setup-l2-hosts.sh "$mode"
if [ "$mode" = client ]; then
    for tag in 10 20; do
        ip -n "h$tag" route add default via "198.18.$tag.253"
    done
    exit
fi
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter
ip link add tenant type vrf table 50120
ip link set tenant up
ip link add l3vxlan50120 type vxlan id 50120 local 10.0.119.1 dev eth1 dstport 4789 nolearning
ip link set l3vxlan50120 address 02:00:00:01:20:01 master tenant up
for tag in 10 20; do
    ip link add link brbundle name "svi$tag" type vlan id "$tag"
    ip link set "svi$tag" master tenant up
    ip addr add "198.18.$tag.254/24" dev "svi$tag"
    ip -n "h$tag" route add default via "198.18.$tag.254"
done
# Remote-only prefixes force RT5 forwarding: neither exists on the peer.
for subnet in 121 124; do
    ip link add "remote$subnet" type dummy
    ip link set "remote$subnet" master tenant up
    ip addr add "198.19.$subnet.1/24" dev "remote$subnet"
done
