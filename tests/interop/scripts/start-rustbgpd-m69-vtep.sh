#!/bin/sh
# M69 owns its bridge, VXLAN and a live veth attachment circuit. Restart
# preserves the kernel state left by the preceding daemon lifetime.
set -eu

case "${1:-setup}" in
    setup)
        ip link add br200 type bridge mcast_snooping 0
        ip link set br200 multicast off
        ip link set br200 up
        ip link add vxlan200 type vxlan id 200 dstport 4789 local 10.0.0.1 nolearning
        ip link set vxlan200 master br200
        ip link set vxlan200 multicast off
        ip link set vxlan200 up
        ip link add es0 type veth peer name ce0
        ip link set es0 master br200
        ip link set es0 multicast off
        ip link set ce0 multicast off
        ip link set es0 up
        ip link set ce0 up
        ;;
    restart) ;;
    *) echo "usage: start-rustbgpd-m69-vtep.sh [setup|restart]" >&2; exit 2 ;;
esac

nohup /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml \
    >/var/log/rustbgpd.log 2>&1 &
echo "$!" >/run/rustbgpd/m69.pid
