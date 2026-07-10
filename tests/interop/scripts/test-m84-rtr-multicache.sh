#!/usr/bin/env bash
# M84 interop test — multi-cache RTR/ASPA epoch conformance (LAN-243).
#
# Drives the 8210bis per-cache epoch model (CacheEpoch {version,
# session_id, serial} advanced atomically at validated End of Data,
# retention through reconnect / Cache Reset / v1 fallback, ASPA
# replacement semantics + empty-provider withdrawal) against three
# caches at once:
#
#   routinator — real RTR v2 cache, offline (--no-rir-tals + SLURM
#     local assertions). Reconnect scenario: docker restart gives a
#     new session_id; the client's Serial Query for the old session is
#     answered with a Cache Reset (Routinator 0.15 behavior), and the
#     client must resynchronize while retaining the held data — the
#     routinator-backed route must never flap to not_found.
#   stayrtr — real RTR v1-only cache. Version fallback scenario: a v2
#     Reset Query is answered with a version-0 "Bad protocol version"
#     Error Report; the client must land the shipped v2→v1 fallback
#     and load the cache's data at v1.
#   rtr-v2 — in-repo Python phased server (the only deterministic
#     ASPA source: StayRTR removed ASPA support and Routinator 0.15
#     ignores SLURM aspaAssertions — both verified while building this
#     job). Phases drive: incremental epoch advance, ASPA provider-set
#     REPLACE, ASPA empty-provider withdrawal, and a same-session
#     serial regression that must purge the stale VRP via one Reset
#     Query resync.
#
# Scenario map (issue LAN-243):
#   1. all caches connected, VRPs + ASPA loaded, epoch established at
#      validated EoD                     → test_initial_load
#   2. cache reconnect: data retained, session rotates, no flap
#                                        → test_cache_reconnect
#   3. serial regression: one resync, no stale VRPs
#                                        → test_serial_regression
#   4. version fallback: v1-only cache, data loaded via fallback path
#                                        → test_version_fallback
#   5. ASPA replace + shrink-to-empty    → test_aspa_phases
#
# Known daemon limitation (observed while building this job, NOT
# asserted here): after a v1-fallback session drops (e.g. StayRTR
# restarts), the client re-probes v2 on every reconnect and — because
# the fallback path is gated on holding no epoch — does not re-land
# the v1 fallback until the held data expires (expire_interval later),
# at which point validation briefly flaps before recovery. Repro:
# `docker restart clab-m84-rtr-multicache-stayrtr` after a green run
# and watch "RTR version mismatch: negotiated 2, received 0" repeat
# in the daemon log at the retry interval.
#
# Prerequisites: containerlab deployed, grpcurl + jq on the host.

set -euo pipefail

TOPO="m84-rtr-multicache"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"
ROUTINATOR="clab-${TOPO}-routinator"
STAYRTR="clab-${TOPO}-stayrtr"
RTRV2="clab-${TOPO}-rtr-v2"

ROUTINATOR_IP=""
STAYRTR_IP=""
RTRV2_IP=""

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

patch_rpki_config() {
    ROUTINATOR_IP=$(resolve_ip "$ROUTINATOR")
    STAYRTR_IP=$(resolve_ip "$STAYRTR")
    RTRV2_IP=$(resolve_ip "$RTRV2")
    for pair in "routinator:$ROUTINATOR_IP" "stayrtr:$STAYRTR_IP" "rtr-v2:$RTRV2_IP"; do
        if [ -z "${pair#*:}" ]; then
            echo "ERROR: cannot resolve management IP for ${pair%%:*}" >&2
            exit 1
        fi
    done
    log "caches: routinator=${ROUTINATOR_IP} stayrtr=${STAYRTR_IP} rtr-v2=${RTRV2_IP}"
    docker exec "$RUSTBGPD" sh -c \
        "sed -e 's/ROUTINATOR_ADDR/${ROUTINATOR_IP}/' \
             -e 's/STAYRTR_ADDR/${STAYRTR_IP}/' \
             -e 's/RTRV2_ADDR/${RTRV2_IP}/' \
             /etc/rustbgpd/config.toml > /tmp/config.toml"
}

start_rtr_v2_server() {
    log "Starting phased RTR v2 server..."
    docker exec "$RTRV2" sh -c 'echo 1 > /tmp/rtr-phase'
    docker exec -d "$RTRV2" python3 /usr/local/bin/rtr-v2-server-m84.py
    for i in $(seq 1 15); do
        if docker exec "$RTRV2" sh -c 'cat /tmp/rtr-server-status.json 2>/dev/null' \
            | grep -q '"listening": true'; then
            ok "phased RTR v2 server is listening (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "phased RTR v2 server did not start within 15s"
    return 1
}

set_rtr_phase() {
    local phase=$1
    log "rtr-v2: switching to phase $phase"
    docker exec "$RTRV2" sh -c "echo $phase > /tmp/rtr-phase"
}

# ---------------------------------------------------------------------------
# Observation helpers
# ---------------------------------------------------------------------------

rlog() {
    docker exec "$RUSTBGPD" cat /tmp/rustbgpd.log 2>/dev/null || true
}

# Count daemon log lines carrying a message AND a cache address.
log_count() {
    local message=$1 cache_ip=$2
    rlog | grep -F "\"message\":\"$message\"" | grep -cF "${cache_ip}:3323" || true
}

# Poll until log_count(message, cache) >= want. Non-fatal on failure
# (counts into the summary) so later scenarios still run.
wait_log_count() {
    local message=$1 cache_ip=$2 want=$3 label=$4
    for i in $(seq 1 45); do
        local got
        got=$(log_count "$message" "$cache_ip")
        if [ "$got" -ge "$want" ]; then
            ok "$label (count $got after ${i}s)"
            return 0
        fi
        sleep 1
    done
    fail "$label (want >=$want, got $(log_count "$message" "$cache_ip"))"
}

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"neighbor_address": "10.84.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

# Field of one received route ("missing" when absent).
route_field() {
    local prefix=$1 len=$2 field=$3
    grpc_list_received | jq -r --arg p "$prefix" --argjson l "$len" --arg f "$field" \
        '[.routes[]? | select(.prefix == $p and (.prefixLength // 0) == $l)][0][$f] // "missing"' \
        2>/dev/null || echo "missing"
}

# Poll until a route field reaches the expected value.
assert_route_field() {
    local prefix=$1 len=$2 field=$3 expected=$4
    for i in $(seq 1 45); do
        local got
        got=$(route_field "$prefix" "$len" "$field")
        if [ "$got" = "$expected" ]; then
            ok "$prefix/$len $field = $expected (after ${i}s)"
            return 0
        fi
        sleep 1
    done
    fail "$prefix/$len $field never reached '$expected' (last: '$(route_field "$prefix" "$len" "$field")')"
}

metric() {
    prom_value "$RUSTBGPD" "$1"
}

assert_metric() {
    local name=$1 expected=$2 label=$3
    for i in $(seq 1 45); do
        local got
        got=$(metric "$name")
        if [ "${got:-}" = "$expected" ]; then
            ok "$label ($name = $got, after ${i}s)"
            return 0
        fi
        sleep 1
    done
    fail "$label ($name = '$(metric "$name")', want $expected)"
}

# ---------------------------------------------------------------------------
# Scenario 1 — all caches loaded; epoch advances only at validated EoD
# ---------------------------------------------------------------------------

test_initial_load() {
    log "Scenario 1: all three caches connected, VRPs + ASPA loaded"

    # One completed (EoD-validated) full-table transaction per cache.
    wait_log_count "RTR full table received" "$ROUTINATOR_IP" 1 \
        "routinator epoch established at validated EoD (full table)"
    wait_log_count "RTR full table received" "$STAYRTR_IP" 1 \
        "stayrtr epoch established at validated EoD (full table)"
    wait_log_count "RTR full table received" "$RTRV2_IP" 1 \
        "rtr-v2 epoch established at validated EoD (full table)"

    # Merged tables reflect exactly the three EoD-completed snapshots.
    assert_metric 'bgp_rpki_vrp_count{af="ipv4"}' 3 \
        "merged VRP table = 1 VRP per cache"
    assert_metric 'bgp_aspa_records_total' 1 \
        "merged ASPA table = 1 customer record (rtr-v2)"

    # Per-cache data observable through route validation states.
    assert_route_field 203.0.113.0 24 validationState valid    # routinator VRP
    assert_route_field 192.0.2.0 24 validationState invalid    # rtr-v2 VRP (AS65999)
    assert_route_field 198.18.9.0 24 validationState not_found # no VRP yet anywhere
}

# ---------------------------------------------------------------------------
# Scenario 4 — version fallback (StayRTR is v1-only)
# ---------------------------------------------------------------------------

test_version_fallback() {
    log "Scenario 4: v2 -> v1 fallback against the v1-only cache"

    wait_log_count "RTR server does not support v2, falling back to v1 (no ASPA)" \
        "$STAYRTR_IP" 1 "client took the v1 fallback path for stayrtr"
    wait_log_count "RTR reconnected with fallback version" "$STAYRTR_IP" 1 \
        "client reconnected to stayrtr at the fallback version"

    # Data loaded through the fallback session validates a route.
    assert_route_field 198.51.100.0 24 validationState valid
}

# ---------------------------------------------------------------------------
# Scenario 2 — cache reconnect (routinator restart)
# ---------------------------------------------------------------------------

test_cache_reconnect() {
    log "Scenario 2: routinator restart — retention + session rotation"

    local pre_full_tables poll_file="/tmp/m84-reconnect-poll.$$"
    pre_full_tables=$(log_count "RTR full table received" "$ROUTINATOR_IP")

    # Continuously sample the routinator-backed route's validation
    # state; any not_found/missing sample is a retention violation.
    : > "$poll_file"
    (
        for _ in $(seq 1 120); do
            route_field 203.0.113.0 24 validationState >> "$poll_file"
            sleep 0.5
        done
    ) &
    local poller_pid=$!

    log "Restarting $ROUTINATOR..."
    docker restart "$ROUTINATOR" > /dev/null

    # New server session_id: the client's Serial Query for the old
    # session is answered with a Cache Reset; the client resynchronizes
    # with a Reset Query and lands a fresh epoch at the new EoD.
    wait_log_count "RTR cache reset received, resynchronizing with Reset Query" \
        "$ROUTINATOR_IP" 1 "client saw Cache Reset from restarted routinator"
    wait_log_count "RTR full table received" "$ROUTINATOR_IP" \
        $((pre_full_tables + 1)) \
        "epoch rotated: fresh full-table EoD after restart"

    # A few extra samples after recovery, then stop the poller.
    sleep 3
    kill "$poller_pid" 2>/dev/null || true
    wait "$poller_pid" 2>/dev/null || true

    local samples bad
    samples=$(wc -l < "$poll_file")
    bad=$(grep -cv '^valid$' "$poll_file" || true)
    if [ "$samples" -ge 10 ] && [ "$bad" -eq 0 ]; then
        ok "no validation flap across restart ($samples samples, all valid)"
    else
        fail "validation flapped across restart ($bad of $samples samples not valid: $(sort -u "$poll_file" | tr '\n' ' '))"
    fi
    rm -f "$poll_file"

    assert_route_field 203.0.113.0 24 validationState valid
}

# ---------------------------------------------------------------------------
# Scenario 5 — ASPA: incremental, provider-set replace, shrink to empty
# ---------------------------------------------------------------------------

test_aspa_phases() {
    log "Scenario 5 (+ incremental epoch advance): rtr-v2 phases 2-4"

    local pre_full_tables
    pre_full_tables=$(log_count "RTR full table received" "$RTRV2_IP")

    # Baseline: ASPA 65004 -> [65003, 65099] covers AS_PATH [65003, 65004].
    assert_route_field 198.18.4.0 24 aspaState valid

    # Phase 2: incremental VRP announce — epoch advances at incremental EoD.
    set_rtr_phase 2
    assert_route_field 198.18.9.0 24 validationState valid
    assert_metric 'bgp_rpki_vrp_count{af="ipv4"}' 4 \
        "merged VRP table grew by the incremental announce"

    # Phase 3: ASPA announce 65004 -> [65099] must REPLACE the provider
    # set (a merge would keep 65003 authorized and stay valid).
    set_rtr_phase 3
    assert_route_field 198.18.4.0 24 aspaState invalid
    assert_metric 'bgp_aspa_records_total' 1 \
        "replacement kept exactly one customer record"

    # Phase 4: ASPA withdraw (empty provider set on the wire) removes
    # the customer record entirely.
    set_rtr_phase 4
    assert_route_field 198.18.4.0 24 aspaState unknown
    assert_metric 'bgp_aspa_records_total' 0 \
        "empty-provider withdrawal removed the customer record"

    # All of phases 2-4 must have ridden incremental Serial Query
    # transactions on the existing epoch — no full-table resync.
    local post_full_tables
    post_full_tables=$(log_count "RTR full table received" "$RTRV2_IP")
    if [ "$post_full_tables" -eq "$pre_full_tables" ]; then
        ok "phases 2-4 applied incrementally (no full-table resync)"
    else
        fail "unexpected full-table resync during phases 2-4 ($pre_full_tables -> $post_full_tables)"
    fi
}

# ---------------------------------------------------------------------------
# Scenario 3 — serial regression
# ---------------------------------------------------------------------------

test_serial_regression() {
    log "Scenario 3: same-session serial regression on rtr-v2"

    local pre_full_tables
    pre_full_tables=$(log_count "RTR full table received" "$RTRV2_IP")

    # Phase 5: server serial rolls back 4 -> 1 within the same session.
    # The client must reject the regressed EoD and resync once.
    set_rtr_phase 5
    wait_log_count "RTR End of Data identity mismatch — resynchronizing" \
        "$RTRV2_IP" 1 "client detected the serial regression at EoD"
    wait_log_count "RTR full table received" "$RTRV2_IP" \
        $((pre_full_tables + 1)) "client resynchronized with one Reset Query"

    # Exactly one epoch advance for the resync — no repeated churn.
    sleep 3
    local post_full_tables
    post_full_tables=$(log_count "RTR full table received" "$RTRV2_IP")
    if [ "$post_full_tables" -eq $((pre_full_tables + 1)) ]; then
        ok "epoch advanced exactly once on regression resync"
    else
        fail "expected exactly one resync full table, got $((post_full_tables - pre_full_tables))"
    fi

    # The phase-2 VRP does not exist at the regressed serial: a client
    # that splices instead of replacing would keep it as a stale VRP.
    assert_route_field 198.18.9.0 24 validationState not_found
    assert_metric 'bgp_rpki_vrp_count{af="ipv4"}' 3 \
        "stale VRP purged; other caches' data intact"
    # The surviving rtr-v2 base VRP still validates.
    assert_route_field 192.0.2.0 24 validationState invalid
}

# ---------------------------------------------------------------------------

main() {
    log "M84 interop test: multi-cache RTR/ASPA epoch conformance"
    log "(routinator + stayrtr + phased rtr-v2)"

    resolve_grpc_addr
    patch_rpki_config
    start_rtr_v2_server
    start_rustbgpd "/usr/local/bin/rustbgpd /tmp/config.toml > /tmp/rustbgpd.log 2>&1"

    wait_frr_established "$FRR" "10.84.0.1" "rustbgpd ↔ FRR"

    test_initial_load
    test_version_fallback
    test_cache_reconnect
    test_aspa_phases
    test_serial_regression

    print_summary
}

main
