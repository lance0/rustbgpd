#!/usr/bin/env bash
# M123: RFC 9785 Don't-Preempt between rustbgpd and SR Linux 25.10.1 on one
# all-active ES behind a real LACP CE. Each phase snapshots both PEs' state
# into $OUT/<phase> and m123_dont_preempt_oracle.py compares it.
set -euo pipefail
TOPO=m123-evpn-dont-preempt-srlinux
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"
VTEP="$RUSTBGPD"
SRL="clab-${TOPO}-srl"
CE="clab-${TOPO}-ce"
OUT="${M123_ARTIFACT_DIR:-/tmp/m123}"
ORACLE="$SCRIPT_DIR/m123_dont_preempt_oracle.py"
ESI=00:01:23:00:00:00:00:00:00:01
ES='/ system network-instance protocols evpn ethernet-segments bgp-instance 1 ethernet-segment es1'
START='/usr/local/bin/start-rustbgpd.sh >>/var/log/rustbgpd.log 2>&1'
# Control cell: the same config with Don't-Preempt off.
START_CONTROL="sed 's/^df_dont_preempt = true\$/df_dont_preempt = false/' /etc/rustbgpd/config.toml > /tmp/control.toml && exec rustbgpd /tmp/control.toml >>/var/log/rustbgpd.log 2>&1"
mkdir -p "$OUT"

now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
srl() { docker exec -u root "$SRL" sr_cli "$@"; }
srl_commit() { srl --candidate-mode --commit-at-end "$@" > /dev/null; }

snapshot() {
    local dir="$OUT/${1:?phase}"
    mkdir -p "$dir"
    if rustbgpd_running; then
        vtep_ctl evpn es list -j > "$dir/rust-es.json"
        vtep_ctl evpn --route-type 4 -j > "$dir/rust-type4.json"
    else
        echo '{"segments": []}' > "$dir/rust-es.json"
        echo '[]' > "$dir/rust-type4.json"
    fi
    now > "$dir/taken-at"
    srl "info from state $ES | as json" > "$dir/srl-es.json"
    srl 'info from state network-instance default bgp-rib | as json' > "$dir/srl-rib.json"
    docker exec "$CE" cat /proc/net/bonding/bond0 > "$dir/ce-bond.txt"
}
qualify() {
    snapshot "$1" && python3 "$ORACLE" "$OUT/$1" "$2" 2> "$OUT/$1/mismatch.txt"
}
# Bounded: 60 snapshots, each a few CLI round trips.
expect_phase() {
    local phase=${1:?} want=${2:?} what=${3:?}
    if wait_until 60 1 qualify "$phase" "$want"; then
        ok "$phase: $what"
    else
        fail "$phase: $what"
        cat "$OUT/$phase/mismatch.txt" >&2
        exit 1
    fi
}
fact() { jq -c ".${2:?}" "$OUT/${1:?}/facts.json"; }

rustbgpd_stopped() { ! rustbgpd_running; }
stop_rustbgpd() {
    docker exec "$VTEP" sh -c 'kill -TERM "$(pidof rustbgpd)"'
    if ! wait_until 30 1 rustbgpd_stopped; then
        fail "rustbgpd did not exit after SIGTERM"
        exit 1
    fi
}
start() {
    start_rustbgpd "$1"
    wait_vtep_established 10.0.123.2 'SR Linux' || exit 1
}

finish() {
    local rc=$?
    set +e
    docker exec "$VTEP" cat /var/log/rustbgpd.log > "$OUT/rustbgpd.log" 2>&1
    _cleanup_on_exit
    exit "$rc"
}
trap finish EXIT

# The shared guard checks rustbgpd:dev; a local image under another tag must
# match this tree too, by deployed image ID.
for node in "$VTEP" "$CE"; do
    "$SCRIPT_DIR/../../../scripts/source-id.sh" --check "$(docker inspect -f '{{.Image}}' "$node")"
done
expected_srl='ghcr.io/nokia/srlinux:25.10.1@sha256:bc8112667b5a87bee5039ade65b504ac2ef35511210d0675db6c7b0754e8cc4c'
test "$(docker inspect -f '{{.Image}}' "$SRL")" = "$(docker image inspect -f '{{.Id}}' "$expected_srl")"
srl 'show version' > "$OUT/srl-version.txt"
grep -Fx 'Software Version     : v25.10.1' "$OUT/srl-version.txt"
grep -Fx 'Build Number         : 399-g90c1dbe35ef' "$OUT/srl-version.txt"
resolve_grpc_addr

# A phase whose SR Linux role-change stamp pins a later phase first waits for
# that stamp to record its own change (`changed_after` the action) and to
# settle; the later phase then shows SR Linux kept its role in between.
changed_after() { jq -c --arg after "$2" '. + {srl_role_changed_after: $after}' <<< "$1"; }
SRL_ALONE='{"rust_role": null, "srl_role_settled_for": 15, "srl_oper_state": "up", "srl_admin": [100, true],
  "srl_oper": [100, true], "srl_df": {"192.0.2.2": true}, "srl_own_type4": [100, true],
  "ce_bundled_ports": 2}'
# rustbgpd (administrative 200, DP) recovers beside the DP reference PE (100):
# it advertises the reference preference with DP=0 and the DP tie-break keeps
# SR Linux as DF, although rustbgpd has the lower originator IP.
dp_held() {
    jq -cn --argjson since "$1" '{rust_role: "nondf", rust_admin: [200, true],
      rust_advertised: [100, false], rust_recovery_pending: false, rust_drained: false,
      rust_own_type4: [100, false], rust_decoded_srl: [100, true],
      srl_oper: [100, true], srl_df: {"10.0.123.1": false, "192.0.2.2": true},
      srl_decoded_rust: [100, false], srl_role_unchanged_since: $since, ce_bundled_ports: 2}'
}

expect_phase srl-alone "$SRL_ALONE" 'SR Linux alone is DF over a two-port LACP bundle'
since=$(fact srl-alone srl_role_change)

# Restart cell: first boot, then a SIGTERM restart.
start "$START"
expect_phase dp-boot "$(dp_held "$since")" 'booting rustbgpd inherits (100, DP=0); SR Linux stays DF'
stop_rustbgpd
start "$START"
expect_phase dp-restart "$(dp_held "$since")" 'restarted rustbgpd inherits (100, DP=0); SR Linux stays DF'

# Control cell: Don't-Preempt off on both, so the restart preempts.
stop_rustbgpd
srl_commit "set $ES df-election algorithm preference-alg capabilities non-revertive false"
expect_phase control-srl-alone '{"rust_role": null, "srl_admin": [100, false], "srl_oper": [100, false],
  "srl_df": {"192.0.2.2": true}, "srl_own_type4": [100, false]}' 'SR Linux alone is DF without DP'
start "$START_CONTROL"
expect_phase control-preempt '{"rust_role": "df", "rust_admin": [200, false], "rust_advertised": [200, false],
  "rust_recovery_pending": false, "rust_own_type4": [200, false], "rust_decoded_srl": [100, false],
  "srl_oper": [100, false], "srl_df": {"10.0.123.1": true, "192.0.2.2": false},
  "srl_decoded_rust": [200, false]}' 'without DP, restarted rustbgpd preempts SR Linux'

# Back to Don't-Preempt on both before the reference-PE cells.
mark=$(now)
stop_rustbgpd
srl_commit "set $ES df-election algorithm preference-alg capabilities non-revertive true"
expect_phase dp-srl-alone "$(changed_after "$SRL_ALONE" "$mark")" 'SR Linux alone is DF with DP again'
since=$(fact dp-srl-alone srl_role_change)
start "$START"
expect_phase dp-restored "$(dp_held "$since")" 'rustbgpd inherits again after the control cell'

# Drain: SR Linux, the reference PE, loses its CE link; rustbgpd restores
# its administrative values and becomes DF.
mark=$(now)
srl_commit 'set / interface ethernet-1/2 admin-state disable'
expect_phase srl-withdrawn "$(changed_after '{"rust_role": "df", "rust_admin": [200, true],
  "rust_advertised": [200, true], "rust_own_type4": [200, true], "rust_decoded_srl": null,
  "srl_oper_state": "down", "srl_own_type4": null, "srl_decoded_rust": [200, true],
  "ce_bundled_ports": 1, "srl_role_settled_for": 15}' "$mark")" \
  'survivor rustbgpd restores (200, DP=1) and is DF'
since=$(fact srl-withdrawn srl_role_change)

# Reverse: SR Linux now outranks rustbgpd administratively (300) and recovers
# from the link failure. It must inherit rustbgpd's preference with DP=0.
srl_commit "set $ES df-election algorithm preference-alg preference-value 300"
srl_commit 'set / interface ethernet-1/2 admin-state enable'
expect_phase srl-recovered "$(jq -cn --argjson since "$since" '{rust_role: "df", rust_advertised: [200, true],
  rust_recovery_pending: false, rust_own_type4: [200, true], rust_decoded_srl: [200, false],
  srl_oper_state: "up", srl_admin: [300, true], srl_oper: [200, false],
  srl_df: {"10.0.123.1": true, "192.0.2.2": false}, srl_own_type4: [200, false],
  srl_decoded_rust: [200, true], srl_role_unchanged_since: $since, ce_bundled_ports: 2}')" \
  'recovering SR Linux inherits (200, DP=0); rustbgpd keeps DF'

# Drain the reference PE rustbgpd; SR Linux restores (300, DP=1).
mark=$(now)
vtep_ctl evpn es drain "$ESI" > "$OUT/rust-drain.txt"
expect_phase rust-drained "$(changed_after '{"rust_drained": true, "rust_own_type4": null,
  "rust_decoded_srl": [300, true], "srl_admin": [300, true], "srl_oper": [300, true],
  "srl_df": {"192.0.2.2": true}, "srl_own_type4": [300, true], "srl_decoded_rust": null,
  "srl_role_settled_for": 15}' "$mark")" \
  'survivor SR Linux restores (300, DP=1) and is DF'
since=$(fact rust-drained srl_role_change)

# A recovering PE below the reference keeps its administrative values.
vtep_ctl evpn es undrain "$ESI" > "$OUT/rust-undrain.txt"
expect_phase rust-undrained "$(jq -cn --argjson since "$since" '{rust_role: "nondf", rust_drained: false,
  rust_recovery_pending: false, rust_advertised: [200, true], rust_own_type4: [200, true],
  rust_decoded_srl: [300, true], srl_oper: [300, true],
  srl_df: {"10.0.123.1": false, "192.0.2.2": true}, srl_decoded_rust: [200, true],
  srl_role_unchanged_since: $since}')" \
  'lower-preference rustbgpd recovers with (200, DP=1); SR Linux stays DF'

python3 "$ORACLE" replay "$OUT"
ok 'replayed every phase from its retained snapshot'
print_summary
