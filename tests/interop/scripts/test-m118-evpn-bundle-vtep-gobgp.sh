#!/usr/bin/env bash
# M118: synthetic bundle VTEP qualification, not a vendor datapath receipt.
set -euo pipefail

TOPO="m118-evpn-bundle-vtep-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

VTEP="$RUSTBGPD"
GOBGP="clab-${TOPO}-gobgp"
OUT="${M118_ARTIFACT_DIR:-/tmp/m118}"
ORACLE="$SCRIPT_DIR/m118_bundle_oracle.py"
LOCAL_MAC="02:aa:bb:01:18:01"
REMOTE_MAC="02:aa:bb:01:18:02"
mkdir -p "$OUT"

gobgp() { docker exec "$GOBGP" gobgp "$@"; }
fdb_snapshot() { docker exec "$VTEP" bridge fdb show > "$OUT/fdb.txt"; }
originated() {
    gobgp global rib -a evpn -j > "$OUT/peer-rib.json" \
        && python3 "$ORACLE" originated "$OUT/peer-rib.json" "$@"
}
received() {
    fdb_snapshot && python3 "$ORACLE" fdb "$OUT/fdb.txt" "$@"
}
negative_drops() {
    vtep_ctl evpn instances -j > "$OUT/instances.json" \
        && vtep_ctl evpn vrfs -j > "$OUT/vrfs.json" \
        && python3 "$ORACLE" drops "$OUT/instances.json" "$OUT/vrfs.json" "$@"
}
retained() {
    vtep_ctl evpn --peer 10.0.118.2 -j > "$OUT/retained-routes.json" \
        && python3 "$ORACLE" retained "$OUT/retained-routes.json"
}
dump_state() {
    gobgp global rib -a evpn -j > "$OUT/final-peer-rib.json" 2>&1 || true
    gobgp neighbor -j > "$OUT/final-peer-session.json" 2>&1 || true
    docker exec "$VTEP" bridge fdb show > "$OUT/final-fdb.txt" 2>&1 || true
    docker exec "$VTEP" ip route show table 10500 > "$OUT/final-vrf-routes.txt" 2>&1 || true
    docker exec "$VTEP" ip route show table all > "$OUT/final-all-routes.txt" 2>&1 || true
    docker exec "$VTEP" cat /var/log/rustbgpd.log > "$OUT/rustbgpd.log" 2>&1 || true
    docker exec "$GOBGP" cat /tmp/gobgpd.log > "$OUT/gobgpd.log" 2>&1 || true
}
finish() {
    local rc=$?
    set +e
    dump_state
    _cleanup_on_exit
    exit "$rc"
}
trap finish EXIT

qualify() {
    local label=${1:?}
    shift
    if wait_until 30 1 "$@"; then
        ok "$label"
    else
        fail "$label"
        return 1
    fi
}

resolve_grpc_addr
test "$(gobgp --version)" = "gobgp version 4.10.0"
docker exec -d "$GOBGP" sh -c 'exec gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
start_rustbgpd /usr/local/bin/start-rustbgpd.sh
wait_vtep_established 10.0.118.2 "bundle EVPN"
baseline_flaps=$(vtep_ctl neighbor 10.0.118.2 -j | jq -er '.flap_count')

# One local MAC under each tag: real Linux attribution drives origination.
for tag in 10 20; do
    docker exec "$VTEP" bridge fdb add "$LOCAL_MAC" dev "access$tag" master static vlan "$tag"
done
qualify "per-member Type 2 and IMET match every decoded NLRI field, RT and VNI" originated
cp "$OUT/peer-rib.json" "$OUT/originated-peer-rib.json"

# The same received MAC must map to two distinct VLAN-scoped rows.
for tag in 10 20; do
    gobgp global rib add -a evpn macadv "$REMOTE_MAC" 0.0.0.0 \
        etag "$tag" label "$((10000 + tag))" rd "10.0.118.2:$tag" \
        rt 65000:100 encap vxlan nexthop 10.0.118.2
done
qualify "same remote MAC programs VLAN 10 and VLAN 20 independently" received
cp "$OUT/fdb.txt" "$OUT/received-fdb.txt"
qualify "ready bundle and independent VRF start with zero drop snapshots" negative_drops zero
cp "$OUT/instances.json" "$OUT/baseline-instances.json"
cp "$OUT/vrfs.json" "$OUT/baseline-vrfs.json"

# Foreign tag, foreign VNI, non-zero ESI and EAD-per-EVI stay in the RIB
# but must never program a bundle member. The L2 drop reasons are snapshots.
gobgp global rib add -a evpn macadv 02:aa:bb:01:ee:01 0.0.0.0 \
    etag 30 label 10010 rd 10.0.118.2:301 rt 65000:100 encap vxlan nexthop 10.0.118.2
gobgp global rib add -a evpn macadv 02:aa:bb:01:ee:02 0.0.0.0 \
    etag 10 label 10030 rd 10.0.118.2:302 rt 65000:100 encap vxlan nexthop 10.0.118.2
gobgp global rib add -a evpn macadv 02:aa:bb:01:ee:03 0.0.0.0 \
    esi arbitrary 01:02:03:04:05:06:07:08:09 etag 10 label 10010 \
    rd 10.0.118.2:303 rt 65000:100 encap vxlan nexthop 10.0.118.2
gobgp global rib add -a evpn a-d esi arbitrary 01:02:03:04:05:06:07:08:09 \
    etag 10 label 10010 rd 10.0.118.2:304 rt 65000:100 encap vxlan nexthop 10.0.118.2

# Bundle rows cannot link an IP-VRF. An independent VRF tests the Type 5 gate.
# GoBGP 4.10.0 rejects a Type 5 without gw; 0.0.0.0 encodes the absent gateway.
gobgp global rib add -a evpn prefix 203.0.118.0/24 gw 0.0.0.0 etag 10 label 10500 \
    rd 10.0.118.2:500 rt 65000:500 encap vxlan nexthop 10.0.118.2 \
    router-mac 02:00:00:01:18:52
qualify "unsupported routes affect only the exact per-member and Type 5 drop reasons" negative_drops
qualify "every unsupported input is observed intact in the received RIB" retained
qualify "negative routes leave both positive FDB members intact" received
# EAD has no MAC: compare every row so unsupported inputs cannot change flood
# entries or any other FDB state outside the named-MAC assertions.
LC_ALL=C sort "$OUT/received-fdb.txt" > "$OUT/baseline-fdb-sorted.txt"
LC_ALL=C sort "$OUT/fdb.txt" > "$OUT/negative-fdb-sorted.txt"
if ! diff -u "$OUT/baseline-fdb-sorted.txt" "$OUT/negative-fdb-sorted.txt" > "$OUT/negative-fdb.diff"; then
    cat "$OUT/negative-fdb.diff"
    fail "unsupported routes altered the complete FDB inventory"
    exit 1
fi
ok "unsupported routes left the complete FDB inventory unchanged"
docker exec "$VTEP" ip route show table 10500 > "$OUT/negative-vrf-routes.txt"
docker exec "$VTEP" ip route show table all > "$OUT/negative-all-routes.txt"
if grep -Fq 203.0.118.0/24 "$OUT/negative-all-routes.txt"; then
    fail "non-zero-tag Type 5 installed a kernel route in any table"
    exit 1
fi
ok "non-zero-tag Type 5 installed no kernel route in any table"
wait_vtep_established 10.0.118.2 "session after unsupported routes"
test "$(vtep_ctl neighbor 10.0.118.2 -j | jq -er '.flap_count')" = "$baseline_flaps"
ok "unsupported routes left the established session's flap count unchanged"

gobgp global rib del -a evpn macadv "$REMOTE_MAC" 0.0.0.0 \
    etag 10 label 10010 rd 10.0.118.2:10 rt 65000:100 encap vxlan nexthop 10.0.118.2
qualify "withdrawing tag 10 removes only its FDB rows; tag 20 survives" received withdrawn
qualify "received withdrawal preserves both local per-tag advertisements" originated
docker exec "$VTEP" bridge fdb del "$LOCAL_MAC" dev access10 master vlan 10
qualify "local tag-10 withdrawal preserves the tag-20 MAC and both IMETs on the peer" originated withdrawn
qualify "local withdrawal leaves the received tag-20 FDB rows intact" received withdrawn
wait_vtep_established 10.0.118.2 "session after member withdrawals"
test "$(vtep_ctl neighbor 10.0.118.2 -j | jq -er '.flap_count')" = "$baseline_flaps"
ok "member withdrawals left the established session's flap count unchanged"
print_summary
