#!/usr/bin/env bash
# M119: local SR Linux bundle VTEP import and ARP-driven forwarding receipt.
set -euo pipefail
TOPO=m119-evpn-bundle-vtep-srlinux
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"
VTEP="$RUSTBGPD"
SRL="clab-${TOPO}-srl"
CLIENT="clab-${TOPO}-client"
OUT="${M119_ARTIFACT_DIR:-/tmp/m119}"
ORACLE="$SCRIPT_DIR/m119_bundle_oracle.py"
mkdir -p "$OUT"
srl() { docker exec -u root "$SRL" sr_cli "$@"; }

snapshot() {
    local dir="$OUT/${1:?phase}" tag
    mkdir -p "$dir"
    srl 'info with-context from state network-instance default bgp-rib | as json' > "$dir/srl-rib.json"
    srl 'info with-context from state network-instance default protocols bgp neighbor 10.0.119.1 | as json' > "$dir/srl-peer.json"
    srl 'info with-context from state tunnel-interface vxlan1 | as json' > "$dir/srl-tunnels.json"
    for tag in 10 20; do
        srl "info with-context from state network-instance bd$tag bridge-table | as json" > "$dir/srl-bd$tag.json"
        docker exec "$VTEP" ip -n "h$tag" -j neigh show > "$dir/vtep-h$tag-neighbors.json"
        docker exec "$CLIENT" ip -n "h$tag" -j neigh show > "$dir/client-h$tag-neighbors.json"
    done
    docker exec "$VTEP" bridge fdb show > "$dir/fdb.txt"
    vtep_ctl evpn -j > "$dir/routes.json"
    vtep_ctl evpn instances -j > "$dir/instances.json"
    vtep_ctl neighbor 10.0.119.2 -j > "$dir/peer.json"
}
qualify() {
    local phase=${1:?}
    snapshot "$phase" && python3 "$ORACLE" "$OUT/$phase" "${2:-full}"
}
wait_phase() {
    if wait_until 30 1 qualify "$@"; then
        ok "${1:?} route, vendor import and FDB state"
    else
        fail "${1:?} route, vendor import and FDB state"
        exit 1
    fi
}
flush_neighbors() {
    local node tag side dir=${1:?}
    mkdir -p "$dir"
    for node in "$VTEP" "$CLIENT"; do
        for tag in 10 20; do
            docker exec "$node" ip -n "h$tag" neigh flush all
            side=vtep
            [ "$node" != "$CLIENT" ] || side=client
            docker exec "$node" ip -n "h$tag" -j neigh show > "$dir/before-$side-h$tag-neighbors.json"
            jq -e 'length == 0' "$dir/before-$side-h$tag-neighbors.json" >/dev/null
        done
    done
}
forward() {
    local phase=${1:?} tag node destination
    shift
    mkdir -p "$OUT/$phase"
    for tag in "$@"; do
        for node in "$VTEP" "$CLIENT"; do
            destination=2
            [ "$node" != "$CLIENT" ] || destination=1
            flush_neighbors "$OUT/$phase/$tag-to-$destination"
            docker exec "$node" ip netns exec "h$tag" ping -c 3 -W 2 -q "198.18.$tag.$destination" \
                > "$OUT/$phase/ping-$tag-to-$destination.txt"
            snapshot "$phase/$tag-to-$destination"
            python3 "$ORACLE" "$OUT/$phase/$tag-to-$destination" neighbors "$tag"
            ok "$phase: fresh ARP and ping tag $tag toward host $destination"
        done
    done
}
finish() {
    local rc=$?
    set +e
    docker exec "$VTEP" cat /var/log/rustbgpd.log > "$OUT/rustbgpd.log" 2>&1
    _cleanup_on_exit
    exit "$rc"
}
trap finish EXIT

preflight
# The shared guard checks rustbgpd:dev; this dedicated local image must also
# match the current Rust inputs, by immutable deployed image ID on both nodes.
for node in "$VTEP" "$CLIENT"; do
    "$SCRIPT_DIR/../../../scripts/source-id.sh" --check "$(docker inspect -f '{{.Image}}' "$node")"
done
expected_srl='ghcr.io/nokia/srlinux:25.10.1@sha256:bc8112667b5a87bee5039ade65b504ac2ef35511210d0675db6c7b0754e8cc4c'
test "$(docker inspect -f '{{.Image}}' "$SRL")" = "$(docker image inspect -f '{{.Id}}' "$expected_srl")"
srl 'show version' > "$OUT/srl-version.txt"
grep -Fx 'Software Version     : v25.10.1' "$OUT/srl-version.txt"
grep -Fx 'Build Number         : 399-g90c1dbe35ef' "$OUT/srl-version.txt"
resolve_grpc_addr
start_rustbgpd '/usr/local/bin/start-rustbgpd.sh >/var/log/rustbgpd.log 2>&1'
wait_vtep_established 10.0.119.2 'bundle SR Linux'
for tag in 10 20; do
    docker exec "$VTEP" bridge fdb replace 02:aa:bb:01:19:01 dev "access$tag" master static vlan "$tag"
done
wait_phase initial
forward forwarding 10 20

# Disable only the remote member: both its Type 2 and IMET must disappear.
srl --candidate-mode --commit-at-end 'set network-instance bd10 protocols bgp-evpn bgp-instance 1 admin-state disable'
wait_phase remote-withdrawn remote-withdrawn
forward isolated 20
srl --candidate-mode --commit-at-end 'set network-instance bd10 protocols bgp-evpn bgp-instance 1 admin-state enable'
wait_phase remote-restored
forward restored 10 20

# Withdraw just the local tag-10 MAC; both IMETs and tag 20 must survive.
docker exec "$VTEP" bridge fdb del 02:aa:bb:01:19:01 dev access10 master vlan 10
wait_phase local-withdrawn local-withdrawn
docker exec "$VTEP" bridge fdb replace 02:aa:bb:01:19:01 dev access10 master static vlan 10
wait_phase final
python3 "$ORACLE" "$OUT" replay
ok 'session remained established without a flap throughout withdrawals and restores'
print_summary
