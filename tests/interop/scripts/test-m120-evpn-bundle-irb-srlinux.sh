#!/usr/bin/env bash
# M120: single-homed bundle-member IRB over tag-zero interface-less Type 5.
set -euo pipefail
TOPO=m120-evpn-bundle-irb-srlinux
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"
VTEP="$RUSTBGPD"
SRL="clab-${TOPO}-srl"
CLIENT="clab-${TOPO}-client"
OUT="${M120_ARTIFACT_DIR:-/tmp/m120}"
ORACLE="$SCRIPT_DIR/m120_bundle_irb_oracle.py"
CAPTURE_IMAGE="${M120_CAPTURE_IMAGE:-bmpsink:m120}"
CAPTURE_CONTAINER="m120-capture-$$"
mkdir -p "$OUT"
srl() { docker exec -u root "$SRL" sr_cli "$@"; }

snapshot() {
    local dir="$OUT/${1:?phase}" tag
    mkdir -p "$dir"
    srl 'info with-context from state network-instance default bgp-rib | as json' > "$dir/srl-rib.json"
    srl 'info with-context from state network-instance tenant | as json' > "$dir/srl-tenant.json"
    srl 'info with-context from state network-instance default route-table | as json' > "$dir/srl-default-fib.json"
    srl 'info with-context from state network-instance default protocols bgp neighbor 10.0.119.1 | as json' > "$dir/srl-peer.json"
    srl 'info with-context from state tunnel-interface vxlan1 | as json' > "$dir/srl-tunnels.json"
    for tag in 10 20; do
        srl "info with-context from state network-instance bd$tag bridge-table | as json" > "$dir/srl-bd$tag.json"
    done
    docker exec "$VTEP" ip -j route show table all > "$dir/kernel-routes.json"
    docker exec "$VTEP" ip -j neigh show > "$dir/kernel-neighbors.json"
    docker exec "$VTEP" bridge fdb show > "$dir/fdb.txt"
    vtep_ctl evpn -j > "$dir/routes.json"
    vtep_ctl evpn instances -j > "$dir/instances.json"
    vtep_ctl evpn vrfs tenant -j > "$dir/ip-vrf.json"
    vtep_ctl evpn runtime -j > "$dir/runtime.json"
    vtep_ctl config effective -j > "$dir/effective-config.json"
    vtep_ctl neighbor 10.0.119.2 -j > "$dir/peer.json"
}
qualify() {
    local phase=${1:?}
    snapshot "$phase" && python3 "$ORACLE" "$OUT/$phase" "${2:-full}"
}
wait_phase() {
    if wait_until 40 1 qualify "$@"; then
        ok "${1:?}: bundle and interface-less route state"
    else
        fail "${1:?}: bundle and interface-less route state"
        exit 1
    fi
}
ping_host() {
    local node=${1:?} tag=${2:?} destination=${3:?} name=${4:?}
    docker exec "$node" ip -n "h$tag" neigh flush all
    docker exec "$node" ip -n "h$tag" -j neigh show > "$OUT/$name-before-neighbors.json"
    jq -e 'length == 0' "$OUT/$name-before-neighbors.json" >/dev/null
    docker exec "$node" ip netns exec "h$tag" ping -c 3 -W 2 -q "$destination" > "$OUT/$name-ping.txt"
    grep -Eq '3 packets transmitted, 3 (packets )?received, 0% packet loss' "$OUT/$name-ping.txt"
    ok "$name: fresh ARP and routed ping"
}
forward() {
    local phase=${1:?} tag
    for tag in 10 20; do
        ping_host "$VTEP" "$tag" 198.19.120.2 "$phase-local-$tag"
        ping_host "$CLIENT" "$tag" 198.19.121.1 "$phase-remote-$tag"
    done
}
finish() {
    local rc=$?
    set +e
    if docker inspect "$CAPTURE_CONTAINER" >/dev/null 2>&1; then
        docker logs "$CAPTURE_CONTAINER" > "$OUT/capture-cleanup.log" 2>&1
        if [ "$(docker inspect -f '{{.State.Running}}' "$CAPTURE_CONTAINER")" = true ]; then
            docker kill --signal=INT "$CAPTURE_CONTAINER" >/dev/null 2>&1
            timeout 15 docker wait "$CAPTURE_CONTAINER" > "$OUT/capture-cleanup.exit" 2>&1
        fi
        if [ ! -f "$OUT/routed.pcap" ]; then
            docker cp "$CAPTURE_CONTAINER:/tmp/m120.pcap" "$OUT/failed-capture.pcap" >/dev/null 2>&1
        fi
        docker rm -f "$CAPTURE_CONTAINER" >/dev/null 2>&1
    fi
    docker exec "$VTEP" cat /var/log/rustbgpd.log > "$OUT/rustbgpd.log" 2>&1
    _cleanup_on_exit
    exit "$rc"
}
trap finish EXIT

preflight
for node in "$VTEP" "$CLIENT"; do
    "$SCRIPT_DIR/../../../scripts/source-id.sh" --check "$(docker inspect -f '{{.Image}}' "$node")"
done
expected_srl='ghcr.io/nokia/srlinux:25.10.1@sha256:bc8112667b5a87bee5039ade65b504ac2ef35511210d0675db6c7b0754e8cc4c'
test "$(docker inspect -f '{{.Image}}' "$SRL")" = "$(docker image inspect -f '{{.Id}}' "$expected_srl")"
srl 'show version' > "$OUT/srl-version.txt"
grep -Fx 'Software Version     : v25.10.1' "$OUT/srl-version.txt"
grep -Fx 'Build Number         : 399-g90c1dbe35ef' "$OUT/srl-version.txt"
resolve_grpc_addr
start_rustbgpd 'echo $$ >/tmp/m120-daemon.pid; exec /usr/local/bin/start-rustbgpd.sh >/var/log/rustbgpd.log 2>&1'
wait_vtep_established 10.0.119.2 'bundle IRB SR Linux'
for tag in 10 20; do
    docker exec "$VTEP" bridge fdb replace 02:aa:bb:01:19:01 dev "access$tag" master static vlan "$tag"
done
wait_phase startup
forward warmup
for tag in 10 20; do
    ping_host "$VTEP" "$tag" "198.18.$tag.2" "warmup-l2-local-$tag"
    ping_host "$CLIENT" "$tag" "198.18.$tag.1" "warmup-l2-remote-$tag"
done
# Freeze the inventory only after gateway and host learning. Each scored
# forwarding probe still starts with an empty host neighbor table.
wait_phase initial
forward initial

# The remote-only destination selects SR Linux's Type 5 /32. State checks
# also validate its /24; this packet probe qualifies the selected host route.
# Kernel lookup and VXLAN bytes must prove the L3VNI and remote Router MAC.
docker exec "$VTEP" ip -j route get 198.19.120.2 vrf tenant > "$OUT/route-get.json"
docker image inspect "$CAPTURE_IMAGE" > "$OUT/capture-image.json"
docker run -d --name "$CAPTURE_CONTAINER" \
    --network "container:$VTEP" --cap-add=NET_ADMIN --cap-add=NET_RAW \
    "$CAPTURE_IMAGE" tshark -p -i eth1 -f 'udp port 4789' -w /tmp/m120.pcap >/dev/null
wait_capture_ready "$CAPTURE_CONTAINER" /tmp/m120.pcap -
ping_host "$VTEP" 10 198.19.120.2 capture
docker kill --signal=INT "$CAPTURE_CONTAINER" >/dev/null
capture_status=$(timeout 15 docker wait "$CAPTURE_CONTAINER")
printf '%s\n' "$capture_status" > "$OUT/capture.exit"
docker logs "$CAPTURE_CONTAINER" > "$OUT/capture.log" 2>&1
docker cp "$CAPTURE_CONTAINER:/tmp/m120.pcap" "$OUT/routed.pcap"
case "$capture_status" in
    0) ;;
    *) cat "$OUT/capture.log" >&2; exit 1 ;;
esac
docker run --rm -v "$OUT:/capture:ro" "$CAPTURE_IMAGE" \
    tshark -r /capture/routed.pcap -Y 'vxlan && icmp.type == 8 && ip.dst == 198.19.120.2' \
    -T fields -e vxlan.vni -e eth.dst > "$OUT/routed-vxlan.tsv"
python3 - "$OUT" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
route = json.loads((root / 'route-get.json').read_text())
assert len(route) == 1 and route[0]['dev'] == 'l3vxlan50120'
assert route[0]['gateway'] == '192.0.2.2'
rows = [line.split('\t') for line in (root / 'routed-vxlan.tsv').read_text().splitlines()]
assert len(rows) == 3, rows
tunnels = json.loads((root / 'initial/srl-tunnels.json').read_text())['tunnel-interface']
l3 = [v for t in tunnels if t['name'] == 'vxlan1' for v in t['vxlan-interface'] if v['index'] == 50120]
assert len(l3) == 1
rmac = l3[0]['egress']['inner-ethernet-header']['used-source-mac'].lower()
assert all(vni == '50120' and mac.split(',')[-1].lower() == rmac for vni, mac in rows), rows
PY
ok 'packet capture proves L3VNI 50120 and the remote Router MAC'

# Withdrawing the remote-only /24 and its exact exported /32 must break the
# routed path while both L2 members and the other prefix pair keep forwarding.
srl --candidate-mode --commit-at-end 'set network-instance tenant protocols bgp-vpn bgp-instance 1 export-policy [ m120-withdraw-120 ]'
wait_phase remote-withdrawn remote-withdrawn
if docker exec "$VTEP" ip netns exec h10 ping -c 3 -W 1 -q 198.19.120.2 > "$OUT/withdrawn-ping.txt" 2>&1; then
    fail 'withdrawn Type 5 destination remained reachable'
    exit 1
fi
grep -Eq '3 packets transmitted, 0 (packets )?received.*100% packet loss' "$OUT/withdrawn-ping.txt"
for tag in 10 20; do
    ping_host "$VTEP" "$tag" 198.19.123.2 "withdrawn-other-prefix-$tag"
    ping_host "$VTEP" "$tag" "198.18.$tag.2" "withdrawn-l2-$tag"
done
srl --candidate-mode --commit-at-end 'delete network-instance tenant protocols bgp-vpn bgp-instance 1 export-policy'
wait_phase restored
forward restored

# Exercise accepted member binding reloads and reject an unsupported mode
# before publication. Neither transition changes the sibling L2 identity.
generation() { vtep_ctl evpn runtime -j | jq -r '.generation'; }
wait_generation() { test "$(generation)" = "${1:?}"; }
before=$(generation)
python3 - "$SCRIPT_DIR/../configs/rustbgpd-m120-bundle-irb.toml" "$OUT" <<'PY'
from pathlib import Path
import sys
base = Path(sys.argv[1]).read_text()
out = Path(sys.argv[2])
(out / 'unlinked.toml').write_text(base.replace('ip_vrf = "tenant"\n', '', 1))
(out / 'unsupported.toml').write_text(base + '\noverlay_index_mode = "gateway_ip"\n')
PY
docker cp "$OUT/unsupported.toml" "$VTEP:/etc/rustbgpd/config.toml"
docker exec "$VTEP" sh -c 'kill -HUP "$(cat /tmp/m120-daemon.pid)"'
wait_until 15 1 docker exec "$VTEP" grep -q 'vlan_aware_bundle ip_vrf' /var/log/rustbgpd.log
test "$(generation)" = "$before"
wait_phase rejected-reload
docker cp "$OUT/unlinked.toml" "$VTEP:/etc/rustbgpd/config.toml"
docker exec "$VTEP" sh -c 'kill -HUP "$(cat /tmp/m120-daemon.pid)"'
wait_until 15 1 wait_generation "$((before + 1))"
wait_phase unlinked
docker exec "$VTEP" cp /etc/rustbgpd/config.source /etc/rustbgpd/config.toml
docker exec "$VTEP" sh -c 'kill -HUP "$(cat /tmp/m120-daemon.pid)"'
wait_until 15 1 wait_generation "$((before + 2))"
wait_phase relinked
forward reloaded
wait_phase final
python3 "$ORACLE" "$OUT" replay
ok 'full route and FDB state restored with no session flap'
print_summary
