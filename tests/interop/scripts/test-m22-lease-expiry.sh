#!/usr/bin/env bash
# M22 lease-expiry leg (local): ADR-0141 owner leases at FRR.
#
# A controller process adds a leased IPv4 /32 blackhole (65535:666, next-hop
# self) and a leased IPv4 FlowSpec discard rule with a 10 s lease and renews
# every 3 s. FRR must hold both across three lease periods. After the
# controller is killed, FRR must keep both until the lease deadline and lose
# both within lease + 5 s, with the session up. A restarted controller's
# renewal is refused and its re-add restores both. No forwarding, remote
# enforcement or scale claim.
#
# Run on a fresh M22 deployment, separately from the other M22 scripts:
#   containerlab deploy -t tests/interop/m22-flowspec-frr.clab.yml
#   bash tests/interop/scripts/test-m22-lease-expiry.sh
TOPO="m22-flowspec-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR="clab-${TOPO}-frr"
LEASE=10
RENEW_EVERY=3
OWNER="m22-lease"
HOST_PREFIX="198.51.100.7/32"
RULE_DEST="203.0.113.7/32"
STATE_DIR="$(mktemp -d /tmp/m22-lease.XXXXXX)"
CONTROLLER_PID=""

lease_on_exit() {
    local exit_code=$?
    trap - EXIT INT TERM HUP
    set +e
    [ -n "$CONTROLLER_PID" ] && kill "$CONTROLLER_PID" 2>/dev/null
    rm -rf "$STATE_DIR"
    _cleanup_on_exit
    exit "$exit_code"
}
trap lease_on_exit EXIT

LEASED_PATH='{
  "path": {"prefix": "198.51.100.7", "prefixLength": 32, "nextHop": "0.0.0.0",
           "communities": [4294902426]},
  "lease": {"owner": "m22-lease", "leaseSeconds": 10}
}'
LEASED_RULE='{
  "rule": {"afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC",
           "components": [{"type": 1, "prefix": "203.0.113.7/32"}],
           "actions": [{"trafficRate": {"rate": 0.0}}]},
  "lease": {"owner": "m22-lease", "leaseSeconds": 10}
}'

# The controller: add both entries under one lease, renew every
# RENEW_EVERY seconds, and on a refused renewal re-add its full state. It
# records each event and the time of every successful add or renewal.
controller() {
    local generation renewed
    log_event() { printf '%s %s\n' "$(date +%s.%N)" "$*" >>"$STATE_DIR/events"; }
    add_all() {
        local out
        out=$(grpcurl_call -d "$LEASED_PATH" "$GRPC_ADDR" \
            rustbgpd.v1.InjectionService/AddLeasedPath 2>&1) || { log_event "add_failed $out"; return 1; }
        generation=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["generation"]))')
        grpcurl_call -d "$LEASED_RULE" "$GRPC_ADDR" \
            rustbgpd.v1.InjectionService/AddLeasedFlowSpec >/dev/null 2>&1 || { log_event "add_rule_failed"; return 1; }
        printf '%s' "$generation" >"$STATE_DIR/generation"
        log_event "added $generation"
        date +%s.%N >"$STATE_DIR/last_ok"
    }
    if [ -s "$STATE_DIR/generation" ]; then
        generation=$(cat "$STATE_DIR/generation")
    else
        add_all || exit 1
    fi
    while true; do
        if renewed=$(grpcurl_call \
            -d "{\"owner\": \"$OWNER\", \"generation\": $generation, \"leaseSeconds\": $LEASE}" \
            "$GRPC_ADDR" rustbgpd.v1.InjectionService/RenewLease 2>&1); then
            log_event "renewed"
            date +%s.%N >"$STATE_DIR/last_ok"
        elif printf '%s' "$renewed" | grep -q FailedPrecondition; then
            log_event "renew_refused"
            add_all || exit 1
        else
            log_event "renew_error $renewed"
        fi
        sleep "$RENEW_EVERY"
    done
}

frr_json() {
    docker exec "$FRR" vtysh -c "$1" 2>/dev/null | python3 -c '
import json, sys
text = sys.stdin.read()
start = text.find("{")
print(json.dumps(json.loads(text[start:])) if start >= 0 else "{}")
'
}

# "both", "none", "host", "rule" or "invalid" for FRR's view.
frr_state() {
    local unicast flowspec host rule
    unicast=$(frr_json "show bgp ipv4 unicast $HOST_PREFIX json") || { echo invalid; return; }
    flowspec=$(frr_json "show bgp ipv4 flowspec json") || { echo invalid; return; }
    host=$(printf '%s' "$unicast" | python3 -c 'import json,sys; print(bool(json.load(sys.stdin).get("paths")))')
    rule=$(printf '%s' "$flowspec" | python3 -c '
import json, sys
routes = json.load(sys.stdin).get("routes") or {}
print(any(sys.argv[1] in key for key in routes))
' "$RULE_DEST")
    case "$host/$rule" in
        True/True) echo both ;;
        False/False) echo none ;;
        True/False) echo host ;;
        False/True) echo rule ;;
        *) echo invalid ;;
    esac
}

wait_state() {
    local want=$1 seconds=$2 state=""
    for _ in $(seq 1 "$seconds"); do
        state=$(frr_state)
        [ "$state" = "$want" ] && { echo "$state"; return 0; }
        sleep 1
    done
    echo "$state"
    return 1
}

main() {
    log "M22 lease expiry: controller leases at FRR"
    resolve_grpc_addr
    start_rustbgpd
    wait_frr_established "$FRR" 10.0.0.1 "FRR" || true

    controller &
    CONTROLLER_PID=$!
    if state=$(wait_state both 20); then
        ok "FRR holds the leased blackhole and FlowSpec rule"
    else
        fail "FRR state '$state' after the leased adds, expected both"
    fi

    # Three lease periods with the controller renewing.
    local held=true
    for _ in $(seq 1 $((3 * LEASE / 2 + 1))); do
        sleep 2
        state=$(frr_state)
        [ "$state" = both ] || { held=false; break; }
    done
    if $held; then
        ok "FRR keeps both across three lease periods while the controller renews"
    else
        fail "FRR state '$state' while the controller was renewing"
    fi

    kill "$CONTROLLER_PID"
    wait "$CONTROLLER_PID" 2>/dev/null || true
    CONTROLLER_PID=""
    local killed last_ok deadline
    killed=$(date +%s.%N)
    last_ok=$(cat "$STATE_DIR/last_ok")
    deadline=$(python3 -c "print($last_ok + $LEASE)")
    log "Controller killed; last renewal $(python3 -c "print(round($killed - $last_ok, 2))") s before"

    # Not before the deadline: hold until one second before it.
    local early=false
    while python3 -c "import sys,time; sys.exit(time.time() >= $deadline - 1)"; do
        state=$(frr_state)
        [ "$state" = both ] || { early=true; break; }
        sleep 1
    done
    if $early; then
        fail "FRR lost the leased entries before the lease deadline (state '$state')"
    else
        ok "FRR keeps both until the lease deadline"
    fi
    if state=$(wait_state none $((LEASE + 5 + 2))) \
        && docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
            | grep -q '"bgpState":"Established"'; then
        local gone
        gone=$(date +%s.%N)
        if python3 -c "import sys; sys.exit(not ($gone <= $killed + $LEASE + 5))"; then
            ok "FRR lost both $(python3 -c "print(round($gone - $deadline, 2))") s after the lease deadline, within lease + 5 s of the kill"
        else
            fail "FRR lost both only $(python3 -c "print(round($gone - $killed, 2))") s after the kill"
        fi
    else
        fail "FRR state '$state' after the lease expired, expected none"
    fi
    local leases
    leases=$(grpcurl_call "$GRPC_ADDR" rustbgpd.v1.InjectionService/ListInjectionLeases 2>/dev/null)
    if printf '%s' "$leases" | python3 -c 'import json,sys; sys.exit(bool(json.load(sys.stdin).get("leases")))'; then
        ok "the lease table is empty after expiry"
    else
        fail "lease table after expiry: $leases"
    fi

    # Restart: the old generation is refused, the re-add restores both.
    controller &
    CONTROLLER_PID=$!
    if state=$(wait_state both 20); then
        ok "the restarted controller restores both at FRR"
    else
        fail "FRR state '$state' after the controller restart"
    fi
    if grep -q renew_refused "$STATE_DIR/events" \
        && [ "$(grep -c '^.* added ' "$STATE_DIR/events")" -eq 2 ]; then
        ok "the restarted controller's renewal was refused and it re-added"
    else
        fail "controller events: $(cat "$STATE_DIR/events")"
    fi
    kill "$CONTROLLER_PID"
    wait "$CONTROLLER_PID" 2>/dev/null || true
    CONTROLLER_PID=""

    print_summary
}

main "$@"
