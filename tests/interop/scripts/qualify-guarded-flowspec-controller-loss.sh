#!/usr/bin/env bash
# Guarded FlowSpec controller-loss qualification (ADR-0144). Local only: it
# is not wired into hosted CI.
#
# Deploys its own copy of the M22 topology (rustbgpd -> FRR, plus the
# rustbgpd source node) on the rustbgpd:guarded-qual image, which must be
# built from this tree:
#
#   docker build --target dev -t rustbgpd:guarded-qual .
#   PHASE=loss  OUT_DIR=/abs/dir bash tests/interop/scripts/qualify-guarded-flowspec-controller-loss.sh
#   PHASE=stall OUT_DIR=/abs/dir bash tests/interop/scripts/qualify-guarded-flowspec-controller-loss.sh
#
# A guarded controller issues a 20 s mutation window every 5 s and renews its
# 30 s lease through the newest one; a legacy controller renews a 10 s lease
# every 3 s. Both stop. The script records the last window's expiry t_w, the
# guarded lease deadline, the guarded rule's local absence, its absence at
# FRR and the session state. A late guarded renewal (lease 60 s) and a late
# legacy renewal (lease 30 s), each sent before its deadline, are the
# negative control: the legacy rule outlives its controller, the guarded one
# does not outlive t_w.
#
# PHASE=stall restarts the daemon with RUSTBGPD_TEST_RIB_INGEST_STALL_MS and
# has the source announce a route 1 s before t_w, so the expiry batch waits
# behind a stalled RIB turn: the lag must appear and stay within S + 5 s.
#
# Bars (PASS / FAIL / INVALID):
#   lease deadline <= t_w (within the list round trip)
#   local absence  <= t_w + 2 s            (loss)
#   local absence  <= t_w + S + 5 s and >= t_w + 2 s   (stall; below that the
#                                           stall did not engage: INVALID)
#   FRR absence    <= local absence + 5 s
#   FRR session Established at the end
#   control: the legacy rule is still at FRR 5 s after its original deadline
#   INVALID also when the late guarded renewal or the lease listing fails, or
#   when reads fail up to a deadline: a failed read never counts as absence.
#
# QUAL_FAULT seeds a fault for the red proofs of the INVALID paths:
#   frr-read    pauses FRR while its absence is polled, so every FRR read fails
#   frr-hang    stops FRR's bgpd and watchfrr instead, so every FRR read blocks
#               until its time bound ends it
#   late-renew  sends the late guarded renewal with a stale generation
#
# Times are wall-clock seconds on this host. A window's expiry is bounded
# from below by the issue request's send time plus its lifetime. Local
# absence is the daemon's own log record of its withdrawal turn; the first
# absent local poll, which a later stalled turn can hold, is kept beside it
# as an upper bound. FRR absence is the receive time of the first poll of
# FRR, made on its own, that no longer shows the rule.
set -uo pipefail

PHASE="${PHASE:?PHASE=loss or PHASE=stall}"
OUT_DIR="${OUT_DIR:?OUT_DIR must name an absolute results directory}"
STALL_MS="${STALL_MS:-8000}"
IMAGE="${IMAGE:-rustbgpd:guarded-qual}"
WINDOW=20
LEASE=30
LEGACY_LEASE=10
OWNER="qual"
RULE="203.0.113.9/32"
LEGACY_RULE="203.0.113.10/32"
STALL_PREFIX="198.51.100.77"
# The daemon log, kept beside the results, records each ingest stall.
DAEMON_LOG_ENV="RUST_LOG=info,rustbgpd_rib::manager=debug"

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT" || exit 1
mkdir -p "$OUT_DIR"
STATE_DIR="$(mktemp -d /tmp/guarded-qual.XXXXXX)"
TOPO="m22-guarded-${PHASE}"
TOPO_FILE="$STATE_DIR/$TOPO.clab.yml"
CONTROLLER_PID=""
LEGACY_PID=""

# The topology is the M22 one under its own name and image, with absolute
# bind paths so it runs from the state directory.
sed -e "s|^name: m22-flowspec-frr|name: $TOPO|" \
    -e "s|image: rustbgpd:dev|image: $IMAGE|" \
    -e "s|\./configs/|$ROOT/tests/interop/configs/|" \
    -e "s|\./scripts/|$ROOT/tests/interop/scripts/|" \
    -e "s|\.\./fixtures/|$ROOT/tests/fixtures/|" \
    tests/interop/m22-flowspec-frr.clab.yml >"$TOPO_FILE"

scripts/source-id.sh --check "$IMAGE" || { echo "INVALID image $IMAGE is not built from this tree"; exit 2; }
containerlab deploy -t "$TOPO_FILE" --reconfigure >"$OUT_DIR/$PHASE-deploy.log" 2>&1 || {
    echo "INVALID containerlab deploy failed; see $OUT_DIR/$PHASE-deploy.log"
    exit 2
}

INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source tests/interop/scripts/test-lib.sh
# test-lib turns on errexit; every step here checks its own result.
set +e

FRR="clab-${TOPO}-frr"
SOURCE="clab-${TOPO}-source"

on_exit() {
    local code=$?
    trap - EXIT INT TERM HUP
    [ -n "$CONTROLLER_PID" ] && kill "$CONTROLLER_PID" 2>/dev/null
    [ -n "$LEGACY_PID" ] && kill "$LEGACY_PID" 2>/dev/null
    fault_end
    docker exec "$RUSTBGPD" cat /var/log/rustbgpd.log >"$OUT_DIR/$PHASE-daemon.log" 2>&1
    [ -f "$STATE_DIR/events" ] && cp "$STATE_DIR/events" "$OUT_DIR/$PHASE-events"
    containerlab destroy -t "$TOPO_FILE" --cleanup >/dev/null 2>&1
    rm -rf "$STATE_DIR"
    exit "$code"
}
trap on_exit EXIT INT TERM HUP

# Send signal $1 to FRR's watchfrr and bgpd (the frr-hang fault).
frr_signal() {
    docker exec "$FRR" sh -c "kill -$1 \$(ps -o pid,comm | awk '\$2 == \"watchfrr\" || \$2 == \"bgpd\" {print \$1}')"
}

# Undo a seeded fault; harmless when none is active.
fault_end() {
    case "${QUAL_FAULT:-}" in
        frr-read) docker unpause "$FRR" >/dev/null 2>&1 ;;
        frr-hang) frr_signal CONT >/dev/null 2>&1 ;;
    esac
}

now() { date +%s.%N; }
calc() { python3 -c "print($*)"; }
event() { printf '%s %s\n' "$(now)" "$*" >>"$STATE_DIR/events"; }

grpc() { grpcurl_call -d "$1" "$GRPC_ADDR" "rustbgpd.v1.InjectionService/$2"; }

rule_json() {
    printf '{"afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC", "components": [{"type": 1, "prefix": "%s"}], "actions": [{"trafficRate": {"rate": 0}}]}' "$1"
}

# The guarded controller: issue a window, add once, then every 5 s issue a
# new window and renew through it. Every issue records its send time, so
# the last line bounds t_w from below.
guarded_controller() {
    local window issued generation
    while true; do
        issued=$(now)
        window=$(grpc "{\"owner\": \"$OWNER\", \"windowSeconds\": $WINDOW}" IssueMutationWindow \
            | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["window"]))') \
            || { event "issue_failed"; sleep 1; continue; }
        printf '%s %s\n' "$issued" "$window" >"$STATE_DIR/window.tmp"
        mv "$STATE_DIR/window.tmp" "$STATE_DIR/window"
        if [ ! -s "$STATE_DIR/generation" ]; then
            generation=$(grpc "{\"rule\": $(rule_json "$RULE"), \"lease\": {\"owner\": \"$OWNER\", \"leaseSeconds\": $LEASE}, \"window\": $window, \"revision\": \"1\"}" \
                AddGuardedFlowSpec | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["generation"]))') \
                || { event "add_failed"; sleep 1; continue; }
            printf '%s' "$generation" >"$STATE_DIR/generation"
            event "guarded_added $generation"
        else
            generation=$(cat "$STATE_DIR/generation")
            grpc "{\"owner\": \"$OWNER\", \"generation\": $generation, \"leaseSeconds\": $LEASE, \"window\": $window}" \
                RenewGuardedLease >/dev/null || event "guarded_renew_failed"
        fi
        sleep 5
    done
}

legacy_controller() {
    local generation
    generation=$(grpc "{\"rule\": $(rule_json "$LEGACY_RULE"), \"lease\": {\"owner\": \"$OWNER-legacy\", \"leaseSeconds\": $LEGACY_LEASE}}" \
        AddLeasedFlowSpec | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["generation"]))') || exit 1
    printf '%s' "$generation" >"$STATE_DIR/legacy_generation"
    while true; do
        grpc "{\"owner\": \"$OWNER-legacy\", \"generation\": $generation, \"leaseSeconds\": $LEGACY_LEASE}" \
            RenewLease >/dev/null && now >"$STATE_DIR/legacy_renewed"
        sleep 3
    done
}

# Each probe prints "present", "absent" or "error". A failed read, or a reply
# without the expected shape, is an error and never counts as absence. Each
# read is bounded by probe_budget; a read that runs out of time is an error.

# Seconds one read may take: what is left before PROBE_DEADLINE (wait_absent
# sets it), at least 0.5 s, else 30 s.
probe_budget() {
    if [ -n "${PROBE_DEADLINE:-}" ]; then
        calc "max(0.5, round($PROBE_DEADLINE - $(now), 2))"
    else
        echo 30
    fi
}

# Run vtysh command $1 in FRR within $2 seconds. The inner timeout ends the
# vtysh process if the outer one has already given up on docker exec.
frr_vtysh() {
    timeout --kill-after=1 "$2" docker exec "$FRR" timeout "$2" vtysh -c "$1"
}

# Whether $1 is among the local rules (0.0.0.0 view). The reply must be the
# acknowledged local-intent view.
local_state() {
    local reply
    reply=$(grpcurl_call -max-time "$(probe_budget)" \
        -d '{"afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC", "receivedPeerAddress": "0.0.0.0"}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListFlowSpecRoutes 2>/dev/null) || { echo error; return; }
    printf '%s' "$reply" | python3 -c '
import json, sys
try:
    reply = json.load(sys.stdin)
except ValueError:
    print("error"); sys.exit()
if reply.get("receivedView") is not True:
    print("error"); sys.exit()
prefixes = {
    component.get("prefix")
    for row in reply.get("receivedRoutes", [])
    for component in row.get("route", {}).get("components", [])
}
print("present" if sys.argv[1] in prefixes else "absent")
' "$1"
}

# Whether FRR's FlowSpec table holds a rule for destination $1. The reply
# must be FRR's JSON table.
frr_state() {
    local reply
    reply=$(frr_vtysh "show bgp ipv4 flowspec json" "$(probe_budget)" 2>/dev/null) || { echo error; return; }
    printf '%s' "$reply" | python3 -c '
import json, sys
text = sys.stdin.read()
start = text.find("{")
try:
    table = json.loads(text[start:]) if start >= 0 else None
except ValueError:
    table = None
if not isinstance(table, dict):
    print("error"); sys.exit()
print("present" if sys.argv[1] in json.dumps(table) else "absent")
' "$1"
}

local_has() { [ "$(local_state "$1")" = present ]; }
frr_has() { [ "$(frr_state "$1")" = present ]; }

frr_established() {
    frr_vtysh "show bgp neighbors 10.0.0.1 json" 10 2>/dev/null \
        | grep -q '"bgpState":"Established"'
}

# Poll $1 (local_state or frr_state) until it reads $2 absent; print the
# receive time of the first absent reply. A read error is retried within the
# deadline. Returns 1 when the rule is still present at the deadline and 2
# when the last read before the deadline failed: absence was never read.
wait_absent() {
    local probe=$1 prefix=$2 limit=$3 state="" errors=0
    local PROBE_DEADLINE=$limit
    while python3 -c "import sys,time; sys.exit(time.time() >= $limit)"; do
        state=$("$probe" "$prefix")
        case "$state" in
            absent)
                [ "$errors" -gt 0 ] && event "$probe read_errors $errors"
                now
                return 0
                ;;
            error) errors=$((errors + 1)) ;;
        esac
        sleep 0.2
    done
    event "$probe read_errors $errors last $state"
    [ "$state" = error ] && return 2
    return 1
}

# The wall time of the daemon's "injection lease expired" line for the
# guarded owner: the end of the RIB turn that withdrew the rule.
withdrawal_time() {
    docker exec "$RUSTBGPD" cat /var/log/rustbgpd.log 2>/dev/null | python3 -c '
import datetime, json, sys
for line in sys.stdin:
    try:
        entry = json.loads(line)
    except ValueError:
        continue
    fields = entry.get("fields", {})
    if fields.get("owner") == sys.argv[1] and fields.get("message", "").startswith("injection lease expired"):
        stamp = datetime.datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
        print(stamp.timestamp())
        sys.exit(0)
sys.exit(1)
' "guarded:$OWNER"
}

verdict() {
    # verdict NAME PASS|FAIL|INVALID DETAIL
    printf '%s %s %s\n' "$1" "$2" "$3" >>"$OUT_DIR/$PHASE-verdicts"
    case "$2" in
        PASS) ok "$1: $3" ;;
        *) fail "$1 $2: $3" ;;
    esac
}

main() {
    : >"$OUT_DIR/$PHASE-verdicts"
    resolve_grpc_addr
    if [ "$PHASE" = stall ]; then
        start_rustbgpd "RUSTBGPD_TEST_RIB_INGEST_STALL_MS=$STALL_MS $DAEMON_LOG_ENV /usr/local/bin/start-rustbgpd.sh >/var/log/rustbgpd.log 2>&1"
        docker exec -d "$SOURCE" sh -c /usr/local/bin/start-rustbgpd.sh
    else
        start_rustbgpd "$DAEMON_LOG_ENV /usr/local/bin/start-rustbgpd.sh >/var/log/rustbgpd.log 2>&1"
    fi
    wait_frr_established "$FRR" 10.0.0.1 "FRR" || { verdict session INVALID "FRR never established"; return; }
    if [ "$PHASE" = stall ]; then
        # Let the startup End-of-RIB batches, each stalled, drain first.
        sleep $(( 3 * STALL_MS / 1000 ))
    fi

    guarded_controller &
    CONTROLLER_PID=$!
    legacy_controller &
    LEGACY_PID=$!
    local deadline
    deadline=$(calc "$(now) + 30")
    until frr_has "$RULE" && frr_has "$LEGACY_RULE"; do
        python3 -c "import sys,time; sys.exit(time.time() >= $deadline)" \
            || { verdict setup INVALID "FRR never held both rules"; return; }
        sleep 0.5
    done
    sleep 12
    kill "$CONTROLLER_PID" "$LEGACY_PID"
    wait "$CONTROLLER_PID" "$LEGACY_PID" 2>/dev/null
    CONTROLLER_PID=""
    LEGACY_PID=""
    local stopped issued window t_w legacy_deadline generation
    stopped=$(now)
    read -r issued window <"$STATE_DIR/window"
    t_w=$(calc "$issued + $WINDOW")
    generation=$(cat "$STATE_DIR/generation")
    legacy_deadline=$(calc "$(cat "$STATE_DIR/legacy_renewed") + $LEGACY_LEASE")
    log "controllers stopped; t_w in $(calc "round($t_w - $stopped, 2)") s"

    # Late renewals, each before its deadline: the legacy one first, as its
    # deadline comes first.
    local legacy_generation legacy_renewed=false
    legacy_generation=$(cat "$STATE_DIR/legacy_generation")
    sleep "$(calc "max(0, $legacy_deadline - 3 - $(now))")"
    if grpc "{\"owner\": \"$OWNER-legacy\", \"generation\": $legacy_generation, \"leaseSeconds\": 30}" RenewLease \
        >/dev/null 2>&1; then
        legacy_renewed=true
        event "late_legacy_renew ok"
    else
        event "late_legacy_renew refused"
    fi
    local renewed list_sent list_recv remaining deadline_hi
    sleep "$(calc "max(0, $t_w - 6 - $(now))")"
    local renew_generation=$generation
    [ "${QUAL_FAULT:-}" = late-renew ] && renew_generation='{"incarnation": "1", "sequence": "1"}'
    if ! renewed=$(grpc "{\"owner\": \"$OWNER\", \"generation\": $renew_generation, \"leaseSeconds\": 60, \"window\": $window}" \
        RenewGuardedLease 2>&1) \
        || ! printf '%s' "$renewed" | python3 -c 'import json,sys; json.load(sys.stdin)["leaseRemainingMs"]' 2>/dev/null; then
        event "late_guarded_renew failed $renewed"
        verdict late_guarded_renew INVALID "the late 60 s guarded renewal did not succeed, so it was not exercised"
        return
    fi
    event "late_guarded_renew $renewed"
    list_sent=$(now)
    if ! remaining=$(grpcurl_call -d "{\"owner\": \"guarded:$OWNER\"}" "$GRPC_ADDR" \
        rustbgpd.v1.InjectionService/ListInjectionLeases \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["leases"][0]["leaseRemainingMs"])'); then
        verdict lease_deadline INVALID "the lease listing could not be read"
        return
    fi
    list_recv=$(now)
    deadline_hi=$(calc "$list_recv + $remaining / 1000")
    if python3 -c "import sys; sys.exit(not ($deadline_hi <= $t_w + ($list_recv - $list_sent) + 0.25))"; then
        verdict lease_deadline PASS "deadline - t_w = $(calc "round($deadline_hi - $t_w, 3)") s after a late 60 s renewal"
    else
        verdict lease_deadline FAIL "deadline - t_w = $(calc "round($deadline_hi - $t_w, 3)") s"
    fi

    if [ "$PHASE" = stall ]; then
        sleep "$(calc "max(0, $t_w - 1 - $(now))")"
        event "stall_trigger"
        grpcurl_call -d "{\"prefix\": \"$STALL_PREFIX\", \"prefixLength\": 32, \"nextHop\": \"0.0.0.0\"}" \
            "$(resolve_ip "$SOURCE"):50051" rustbgpd.v1.InjectionService/AddPath >/dev/null 2>&1 \
            || event "stall_trigger_failed"
    fi

    local local_gone local_polled frr_gone="" limit lag frr_poller
    limit=$(calc "$t_w + $STALL_MS / 1000 + 20")
    # FRR is polled on its own, so a local read held behind a stalled RIB
    # turn cannot delay the FRR observation.
    case "${QUAL_FAULT:-}" in
        frr-read)
            # Seeded fault: every FRR read fails until the deadline.
            event "fault frr-read: pausing FRR"
            docker pause "$FRR" >/dev/null
            ;;
        frr-hang)
            # Seeded fault: every FRR read blocks until it is timed out.
            event "fault frr-hang: stopping watchfrr and bgpd"
            frr_signal STOP
            ;;
    esac
    (wait_absent frr_state "$RULE" "$limit" >"$STATE_DIR/frr_absent"; echo $? >"$STATE_DIR/frr_status") &
    frr_poller=$!
    local local_status=0
    local_polled=$(wait_absent local_state "$RULE" "$limit") || local_status=$?
    if [ "$local_status" -eq 2 ]; then
        wait "$frr_poller"
        verdict local_absence INVALID "local reads failed up to t_w + S + 20 s; absence was never read"
        return
    fi
    if [ "$local_status" -eq 0 ]; then
        wait "$frr_poller"
        fault_end
        frr_gone=$(cat "$STATE_DIR/frr_absent")
        # A read can wait behind a later stalled turn, so the first absent
        # poll only bounds the withdrawal from above; the daemon's record of
        # its withdrawal turn dates it.
        local_gone=$(withdrawal_time) || local_gone=$local_polled
        event "local_absent_polled $local_polled local_absent_logged $local_gone"
        lag=$(calc "round($local_gone - $t_w, 3)")
        if [ "$PHASE" = loss ]; then
            if python3 -c "import sys; sys.exit(not ($lag <= 2))"; then
                verdict local_absence PASS "absent $lag s after t_w (bar 2 s)"
            else
                verdict local_absence FAIL "absent $lag s after t_w (bar 2 s)"
            fi
        elif python3 -c "import sys; sys.exit(not ($lag < 2))"; then
            verdict local_absence INVALID "absent $lag s after t_w: the stall did not engage"
        elif python3 -c "import sys; sys.exit(not ($lag <= $STALL_MS / 1000 + 5))"; then
            verdict local_absence PASS "absent $lag s after t_w behind a $STALL_MS ms stall (bar S + 5 s)"
        else
            verdict local_absence FAIL "absent $lag s after t_w (bar S + 5 s)"
        fi
    else
        verdict local_absence FAIL "still present at t_w + S + 20 s"
        wait "$frr_poller"
        return
    fi
    if [ "$(cat "$STATE_DIR/frr_status")" = 2 ]; then
        verdict frr_absence INVALID "FRR reads failed up to t_w + S + 20 s; absence was never read"
    elif [ -n "$frr_gone" ]; then
        if python3 -c "import sys; sys.exit(not ($frr_gone <= $local_gone + 5))"; then
            verdict frr_absence PASS "absent $(calc "round($frr_gone - $local_gone, 3)") s after local absence (bar 5 s)"
        else
            verdict frr_absence FAIL "absent $(calc "round($frr_gone - $local_gone, 3)") s after local absence"
        fi
    else
        verdict frr_absence FAIL "still at FRR at t_w + S + 20 s"
    fi
    sleep "$(calc "max(0, $legacy_deadline + 5 - $(now))")"
    local legacy_state
    legacy_state=$(frr_state "$LEGACY_RULE")
    if $legacy_renewed && [ "$legacy_state" = present ]; then
        verdict legacy_control PASS "the legacy rule is still at FRR $(calc "round($(now) - $legacy_deadline, 1)") s past its deadline after a late renewal"
    else
        verdict legacy_control INVALID "the late legacy renewal did not extend the legacy rule (renewed=$legacy_renewed, FRR read $legacy_state)"
    fi
    if frr_established; then
        verdict session PASS "FRR session Established throughout"
    else
        verdict session FAIL "FRR session not Established"
    fi
    {
        printf '{"phase": "%s", "stall_ms": %s, "t_w": %s, "stopped": %s, ' "$PHASE" \
            "$([ "$PHASE" = stall ] && echo "$STALL_MS" || echo 0)" "$t_w" "$stopped"
        printf '"lease_deadline_hi": %s, "local_absent": %s, "local_absent_polled": %s, "frr_absent": %s, "legacy_deadline": %s}\n' \
            "$deadline_hi" "$local_gone" "$local_polled" "${frr_gone:-null}" "$legacy_deadline"
    } >"$OUT_DIR/$PHASE.json"
}

main
print_summary
