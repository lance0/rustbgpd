#!/usr/bin/env bash
# M96: real IXP Manager v7.4 render -> atomic local activation and refusal.

set -euo pipefail

STATE=/var/lib/m96-activation
MARKER='m96 literal;touch /tmp/m96-shell-eval'

# This exact executable is copied into the rustbgpd container. The activation
# helper passes MARKER as one literal argv element; no shell command is parsed.
if [ "${1:-}" = internal-activate ]; then
    [ "$#" -eq 2 ] && [ "$2" = "$MARKER" ] || exit 64
    if pid=$(pidof -s rustbgpd 2>/dev/null); then
        kill -HUP "$pid"
    else
        mkdir -p /var/lib/rustbgpd
        nohup /usr/local/bin/rustbgpd "$STATE/current/config.toml" \
            >/dev/null 2>&1 </dev/null &
    fi
    exit 0
fi

TOPO=m96-ixp-manager-activation
RUST=clab-${TOPO}-rustbgpd
FRR=clab-${TOPO}-frr
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
TARGET=$ROOT/target/x86_64-unknown-linux-musl/debug/rs-config-render
BIN=/usr/local/bin/rs-config-render
ACT=/usr/local/bin/m96-activate
ADDR=unix:///var/lib/rustbgpd/grpc.sock
SECRET=mcWsqMdzGwTKt67g
WORK=$(mktemp -d)
cleanup() {
    containerlab destroy -t "$ROOT/tests/interop/m96-ixp-manager-activation-frr.clab.yml" \
        --cleanup >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

fail() { printf 'M96 FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'M96 PASS: %s\n' "$*"; }

for container in "$RUST" "$FRR"; do
    docker inspect "$container" >/dev/null 2>&1 || fail "$container is not running"
done

CAPTURE_OUTPUT="$WORK/capture" \
    "$ROOT/tests/compat/ixp-manager-birdseye/run.sh" >/dev/null
FIXTURE=$WORK/capture/ixp-manager-v7.4-rustbgpd.json
cargo +1.98.0 build --locked --target x86_64-unknown-linux-musl -p rs-config-render
docker cp "$TARGET" "$RUST:$BIN"
docker cp "$0" "$RUST:$ACT"
cp "$FIXTURE" "$WORK/initial.json"
jq '.clients[0].prefixes += ["31.135.160.0/19"]' "$FIXTURE" >"$WORK/hot.json"
jq '.router.router_id = "192.0.2.99"' "$WORK/hot.json" >"$WORK/restart.json"
for input in initial hot restart; do
    docker cp "$WORK/$input.json" "$RUST:/var/lib/m96-$input.json"
done
docker exec "$RUST" sh -c \
    "chmod 700 '$BIN' '$ACT'; chmod 600 /var/lib/m96-*.json; rm -rf '$STATE'; mkdir -m 700 '$STATE'"

render() {
    local name=$1
    docker exec "$RUST" "$BIN" \
        --input-format ixp-manager-v1 \
        --context "/var/lib/m96-$name.json" \
        --out-dir "/var/lib/m96-$name-candidate" \
        --max-prefix-restart-seconds 300 \
        --check-with /usr/local/bin/rustbgpd >/dev/null
}

activate() {
    local candidate=$1 expected=$2 label=$3 initial=${4:-} command=${5:-$ACT}
    local extra=() activation=(--activation-command "$command")
    [ -n "$initial" ] && extra=("$initial")
    if [ "$command" = "$ACT" ]; then
        activation+=(--activation-arg internal-activate --activation-arg "$MARKER")
    fi
    set +e
    docker exec "$RUST" "$BIN" activate \
        --candidate "$candidate" --state-dir "$STATE" \
        --check-with /usr/local/bin/rustbgpd \
        --rbgp /usr/local/bin/rbgp --rbgp-addr "$ADDR" \
        --settle-seconds 20 "${extra[@]}" \
        "${activation[@]}" \
        >"$WORK/$label.output" 2>&1
    local status=$?
    set -e
    [ "$status" -eq "$expected" ] || {
        cat "$WORK/$label.output" >&2
        fail "$label exited $status, expected $expected"
    }
    ! grep -Fq "$SECRET" "$WORK/$label.output" || fail "$label leaked MD5 in output"
}

receipt() {
    docker exec "$RUST" cat "$STATE/activation-receipt.json"
}

current() {
    docker exec "$RUST" readlink "$STATE/current"
}

neighbor() {
    docker exec "$RUST" /usr/local/bin/rbgp --addr "$ADDR" --json neighbor 10.1.0.36
}

has_route() {
    docker exec "$RUST" /usr/local/bin/rbgp --addr "$ADDR" --json \
        rib received 10.1.0.36 2>/dev/null \
        | jq -e --arg prefix "$1" '[.[] | select(.prefix == $prefix)] | length == 1' >/dev/null
}

wait_for() {
    local label=$1
    shift
    for _ in $(seq 1 40); do
        if "$@"; then ok "$label"; return; fi
        sleep 1
    done
    fail "$label did not converge"
}

session_ready() {
    neighbor 2>/dev/null | jq -e '.state == "Established"' >/dev/null
}

runtime_equal() {
    docker exec "$RUST" bash -c \
        "sed 's#\"policy/#\"$STATE/current/policy/#g' '$STATE/current/config.toml' >'$STATE/.m96-compare.toml'; chmod 600 '$STATE/.m96-compare.toml'; /usr/local/bin/rbgp --addr '$ADDR' config diff '$STATE/.m96-compare.toml' >/dev/null 2>&1"
}

private_state() {
    docker exec "$RUST" bash -ec \
        "test \"\$(stat -c %a '$STATE')\" = 700 &&
         test \"\$(stat -c %a '$STATE/activation.lock')\" = 600 &&
         test \"\$(stat -c %a '$STATE/activation-receipt.json')\" = 600 &&
         test -L '$STATE/current' &&
         ! find '$STATE/generations' -type d ! -perm 700 -print -quit | grep -q . &&
         ! find '$STATE/generations' -type f ! -perm 600 -print -quit | grep -q ."
}

start_observer() {
    docker exec "$RUST" rm -f /tmp/m96-observer.stop /tmp/m96-observer.log
    docker exec -d "$RUST" bash -c \
        "while [ ! -e /tmp/m96-observer.stop ]; do readlink '$STATE/current' 2>/dev/null || echo MISSING; done >/tmp/m96-observer.log"
}

stop_observer() {
    local output=$1 restored=${2:-}
    if [ -n "$restored" ]; then
        for _ in $(seq 1 20); do
            docker exec "$RUST" tail -n 1 /tmp/m96-observer.log | grep -Fxq "$restored" && break
            sleep 0.1
        done
    fi
    docker exec "$RUST" touch /tmp/m96-observer.stop
    sleep 1
    docker exec "$RUST" cat /tmp/m96-observer.log >"$output"
}

assert_rollback_order() {
    awk -v old="$2" -v bad="$3" '
        $0 == old && phase == 0 { phase = 1 }
        $0 == bad && phase == 1 { phase = 2 }
        $0 == old && phase == 2 { phase = 3 }
        END { exit phase == 3 ? 0 : 1 }
    ' "$1" || fail "observer missed ordered prior -> candidate -> prior transition"
}

assert_observer() {
    local log=$1 old=$2 new=$3
    grep -Fxq "$old" "$log" || fail "observer missed $old"
    grep -Fxq "$new" "$log" || fail "observer missed $new"
    if grep -Fvx -e "$old" -e "$new" "$log" >/dev/null; then
        fail "observer saw absent or unknown current target"
    fi
}

render initial
activate /var/lib/m96-initial-candidate 0 initial --initial
[ "$(cat "$WORK/initial.output")" = 'activation activated' ] || fail "initial output changed"
receipt >"$WORK/initial-receipt.json"
jq -e '.status == "activated" and .initial == true and .activation_runs == 1
    and .phases.candidate_link.durable == true and .phases.runtime_equal == true' \
    "$WORK/initial-receipt.json" >/dev/null || fail "initial receipt is incomplete"
! grep -Fq "$SECRET" "$WORK/initial-receipt.json" || fail "initial receipt leaked MD5"
private_state || fail "activation state or generation has a public or wrong file type/mode"
docker exec "$RUST" chmod 0644 "$STATE/activation-receipt.json"
if private_state; then fail "private-state probe accepted a public receipt"; fi
docker exec "$RUST" chmod 0600 "$STATE/activation-receipt.json"
private_state || fail "private-state probe did not recover after mode restoration"
docker exec "$RUST" test ! -e /tmp/m96-shell-eval || fail "literal activation argument was shell-evaluated"
wait_for "MD5 FRR session Established" session_ready
wait_for "pinned IXP prefix accepted" has_route 31.135.128.0/19
runtime_equal || fail "initial live config differs from current"

initial_target=$(current)
activation_receipt=$(docker exec "$RUST" sha256sum "$STATE/activation-receipt.json")
activate /var/lib/m96-initial-candidate 0 noop "" /bin/false
[ "$(cat "$WORK/noop.output")" = 'activation noop' ] || fail "no-op output changed"
[ "$(current)" = "$initial_target" ] || fail "no-op moved current"
receipt | jq -e '.status == "noop" and .activation_runs == 0' >/dev/null \
    || fail "no-op receipt is false"
[ "$activation_receipt" != "$(docker exec "$RUST" sha256sum "$STATE/activation-receipt.json")" ] \
    || fail "no-op did not write its receipt last"
ok "identical content is a no-op and /bin/false was not executed"

render hot
start_observer
activate /var/lib/m96-hot-candidate 0 hot
stop_observer "$WORK/hot-observer"
hot_target=$(current)
assert_observer "$WORK/hot-observer" "$initial_target" "$hot_target"
wait_for "hot-added prefix accepted" has_route 31.135.160.0/19
runtime_equal || fail "hot live config differs from current"
ok "changed policy candidate activated through an atomic current transition"

docker exec "$RUST" sh -c "printf '\n# tampered\n' >>/var/lib/m96-hot-candidate/config.toml"
before_tamper=$(current)
receipt_before=$(docker exec "$RUST" sha256sum "$STATE/activation-receipt.json")
activate /var/lib/m96-hot-candidate 2 tamper
[ "$(current)" = "$before_tamper" ] || fail "tamper refusal moved current"
[ "$receipt_before" = "$(docker exec "$RUST" sha256sum "$STATE/activation-receipt.json")" ] \
    || fail "tamper refusal rewrote the last truthful receipt"
ok "tampered rendered candidate refused before publication"

render restart
prior_link=$(current)
docker exec "$RUST" bash -c \
    "find -L '$STATE/current' -type f -print0 | sort -z | xargs -0 sha256sum" \
    >"$WORK/prior-files"
pid_before=$(docker exec "$RUST" pidof -s rustbgpd)
state_before=$(neighbor)
start_observer
activate /var/lib/m96-restart-candidate 4 rollback "" /definitely/missing/m96-activation
stop_observer "$WORK/rollback-observer" "$prior_link"
receipt >"$WORK/rollback-receipt.json"
bad_target="generations/$(jq -r .candidate_sha256 "$WORK/rollback-receipt.json")"
assert_observer "$WORK/rollback-observer" "$prior_link" "$bad_target"
assert_rollback_order "$WORK/rollback-observer" "$prior_link" "$bad_target"
[ "$(current)" = "$prior_link" ] || fail "rollback did not restore exact prior link"
docker exec "$RUST" bash -c \
    "find -L '$STATE/current' -type f -print0 | sort -z | xargs -0 sha256sum" \
    >"$WORK/restored-files"
cmp -s "$WORK/prior-files" "$WORK/restored-files" || fail "rollback changed prior bytes"
runtime_equal || fail "rolled-back runtime differs from prior"
pid_after=$(docker exec "$RUST" pidof -s rustbgpd)
state_after=$(neighbor)
[ "$pid_after" = "$pid_before" ] || fail "daemon PID changed across failed activation"
jq -n --argjson before "$state_before" --argjson after "$state_after" \
    '$before.state == "Established" and (($before.uptime_seconds // 0) > 0)
     and $after.state == "Established"
     and (($before.flap_count // 0) == ($after.flap_count // 0))
     and (($after.uptime_seconds // 0) >= ($before.uptime_seconds // 0))' \
    >/dev/null || fail "FRR session flapped or its handle was replaced"
jq -e '.status == "rolled_back" and .activation_runs == 0
    and .phases.rollback_link.durable == true
    and .phases.candidate_activation_ran == false
    and .phases.rollback_activation_ran == false and .phases.runtime_equal == true' \
    "$WORK/rollback-receipt.json" >/dev/null || fail "rollback receipt is incomplete"
! grep -Fq "$SECRET" "$WORK/rollback-receipt.json" || fail "rollback receipt leaked MD5"
wait_for "route remains accepted after exact rollback" has_route 31.135.128.0/19
wait_for "hot-added route remains accepted after exact rollback" has_route 31.135.160.0/19
private_state || fail "rollback left unsafe state modes"
ok "unspawnable activation restored exact bytes, PID, runtime, and session continuity"

docker exec "$FRR" vtysh -c 'show bgp neighbors 192.0.2.18 json' \
    | jq -e '.["192.0.2.18"].bgpState == "Established"' >/dev/null \
    || fail "FRR does not report the authenticated session Established"
if find "$WORK" \( -name '*.output' -o -name '*receipt.json' \) \
    -exec grep -Fl "$SECRET" {} + | grep -q .; then
    fail "MD5 escaped into helper output or receipts"
fi
ok "M96 real-process activation and pre-effect restoration contract complete"
