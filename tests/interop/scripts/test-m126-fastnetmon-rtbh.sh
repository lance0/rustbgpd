#!/usr/bin/env bash
# M126 — FastNetMon Community -> rustbgpd-gobgp-bridge -> rustbgpd -> FRR.
#
# Builds the lab image, deploys the topology, replays an attack pcap that
# crosses FastNetMon's threshold for one IPv4 and one IPv6 host, and checks
# FRR's view of the resulting blackholes through four phases:
#
#   1. ban and unban, with the UPDATE attributes FRR received;
#   2. a rustbgpd restart while banned: FRR holds the bans as Graceful
#      Restart stale routes, drops them at rustbgpd's End-of-RIB and learns
#      them again when the bridge replays them (timed);
#   3. a bridge restart while banned, then unban through the new bridge;
#   4. an unban while rustbgpd is stopped: the stale blackholes stay at FRR
#      until rustbgpd returns, and the bans are not replayed.
#
# Phases 2 and 4 run without the End-of-RIB grace window and record today's
# gap as the control. Phases 5 and 6 repeat them with gr_eor_grace_time set
# on the FRR neighbor:
#
#   5. a rustbgpd restart while banned: FRR never loses either ban, observed
#      every second through the bridge's replay and the End-of-RIB release;
#   6. an unban while rustbgpd is stopped: the stale blackholes stay at FRR
#      until the window releases End-of-RIB, then FRR removes them.
#
# Exit status 0 means every check passed. Control plane only.
#
# Environment:
#   M126_BASE_IMAGE  rustbgpd dev image to build on (default rustbgpd:dev);
#                    it must have been built from this tree.
#   M126_IMAGE       tag for the lab image (default rustbgpd-fnm:m126).
#   M126_LAB         containerlab lab name (default m126-fastnetmon-rtbh), so
#                    two runs on one host do not share containers. Another
#                    name deploys a renamed copy of the topology beside it.
#   KEEP_LAB=1       leave the lab deployed on exit.
#
# Requires docker, containerlab, jq and python3.

set -euo pipefail

TOPO="m126-fastnetmon-rtbh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
LAB_DIR="$REPO_ROOT/tests/interop/$TOPO"
TOPO_FILE="$REPO_ROOT/tests/interop/$TOPO.clab.yml"
M126_BASE_IMAGE="${M126_BASE_IMAGE:-rustbgpd:dev}"
M126_IMAGE="${M126_IMAGE:-rustbgpd-fnm:m126}"
export M126_IMAGE
M126_LAB="${M126_LAB:-$TOPO}"
if [ "$M126_LAB" != "$TOPO" ]; then
    # Beside the original, so its relative bind paths still resolve.
    RUN_TOPO_FILE="$REPO_ROOT/tests/interop/$M126_LAB.clab.yml"
else
    RUN_TOPO_FILE="$TOPO_FILE"
fi
DET="clab-${M126_LAB}-detector"
FRR="clab-${M126_LAB}-frr"
# The bridge's default reconcile interval, used unchanged.
RECONCILE_SECS=30
# Phases 5-6: gr_eor_grace_time on the FRR neighbor. It covers one reconcile
# interval plus margin, stays below the 120 s Restart Time rustbgpd
# advertises, and far below FRR's 360 s stale-path time.
GRACE_SECS=40
V4="203.0.113.7/32"
V6="2001:db8:66::7/128"
V4_NH="10.0.0.1"
V6_NH="2001:db8:126::1"
BLACKHOLE="blackhole" # FRR's name for 65535:666

cd "$REPO_ROOT"
WORK="$(mktemp -d)"
RESULTS="$WORK/results.txt"

pass=0
fail=0
_ts() { date +%H:%M:%S; }
log() { printf '[%s] %s\n' "$(_ts)" "$*"; }
ok() { pass=$((pass + 1)); printf '[%s] PASS %s\n' "$(_ts)" "$*"; }
bad() { fail=$((fail + 1)); printf '[%s] FAIL %s\n' "$(_ts)" "$*"; }
record() { printf '%s\n' "$*" | tee -a "$RESULTS"; }

# shellcheck disable=SC2317  # dump_state and cleanup run from the EXIT trap
dump_state() {
    echo "===== FRR summary =====" >&2
    docker exec "$FRR" vtysh -c 'show bgp summary' >&2 || true
    for f in rustbgpd bridge fastnetmon replay; do
        echo "===== detector /var/log/$f.log (tail) =====" >&2
        docker exec "$DET" tail -n 40 "/var/log/$f.log" >&2 || true
    done
}

# shellcheck disable=SC2317
cleanup() {
    local rc=$?
    if [ "$fail" -gt 0 ] || [ "$rc" -ne 0 ]; then dump_state; fi
    if [ "${KEEP_LAB:-0}" != 1 ]; then
        containerlab destroy -t "$RUN_TOPO_FILE" --cleanup >/dev/null 2>&1 || true
    fi
    if [ "$RUN_TOPO_FILE" != "$TOPO_FILE" ] && [ "${KEEP_LAB:-0}" != 1 ]; then
        rm -f "$RUN_TOPO_FILE"
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

for tool in docker containerlab jq python3; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool not found" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# Image, lab and processes
# ---------------------------------------------------------------------------

log "Checking $M126_BASE_IMAGE was built from this tree"
scripts/source-id.sh --check "$M126_BASE_IMAGE"
log "Building $M126_IMAGE on $M126_BASE_IMAGE"
docker build -q --build-arg "BASE=$M126_BASE_IMAGE" -t "$M126_IMAGE" "$LAB_DIR" >/dev/null
if [ "$RUN_TOPO_FILE" != "$TOPO_FILE" ]; then
    sed "s/^name: $TOPO\$/name: $M126_LAB/" "$TOPO_FILE" >"$RUN_TOPO_FILE"
fi
containerlab destroy -t "$RUN_TOPO_FILE" --cleanup >/dev/null 2>&1 || true
containerlab deploy -t "$RUN_TOPO_FILE" >"$WORK/deploy.log" 2>&1 || { cat "$WORK/deploy.log" >&2; exit 1; }
docker exec "$FRR" touch /etc/frr/vtysh.conf # keep vtysh JSON clean

python3 -I "$LAB_DIR/make_attack_pcap.py" "$WORK/attack.pcap"
docker cp -q "$WORK/attack.pcap" "$DET:/tmp/attack.pcap"
# The same config with the grace window on the FRR neighbor (its last table).
GRACE_CONF=/etc/rustbgpd-grace.toml
{ cat "$LAB_DIR/rustbgpd.toml"; echo "gr_eor_grace_time = $GRACE_SECS"; } >"$WORK/grace.toml"
docker cp -q "$WORK/grace.toml" "$DET:$GRACE_CONF"
docker exec "$DET" rustbgpd --check "$GRACE_CONF" >/dev/null

# Exact PIDs of a process name (/proc comm, 15 characters) in the detector.
pids_of() {
    docker exec "$DET" sh -c 'for p in /proc/[0-9]*; do
        [ "$(cat "$p/comm" 2>/dev/null)" = "$1" ] && echo "${p#/proc/}"; done; true' _ "$1"
}

# Stop the single process with this comm name by its exact PID.
stop_one() {
    local name=$1 pids
    pids=$(pids_of "$name")
    if [ "$(printf '%s\n' "$pids" | grep -c .)" -ne 1 ]; then
        echo "ERROR: expected one $name process, found: ${pids:-none}" >&2
        exit 1
    fi
    docker exec "$DET" sh -c 'kill -TERM "$1"' _ "$pids"
    for _ in $(seq 1 50); do
        [ -z "$(pids_of "$name")" ] && return 0
        sleep 0.2
    done
    echo "ERROR: $name (pid $pids) did not exit" >&2
    exit 1
}

spawn() { # name command...
    local name=$1
    shift
    docker exec -d "$DET" sh -c "exec $* >>/var/log/$name.log 2>&1"
}

start_rustbgpd() { spawn rustbgpd rustbgpd "${1:-/etc/rustbgpd/config.toml}"; }
start_bridge() {
    spawn bridge rustbgpd-gobgp-bridge --listen 127.0.0.1:50051 \
        --daemon unix:///var/lib/rustbgpd/grpc.sock
}
start_fnm() {
    spawn fastnetmon /opt/fastnetmon-community/app/bin/fastnetmon \
        --configuration_file /etc/fastnetmon.conf --log_to_console
}
# 10000 frames/s over two frames: 5000 pps toward each victim, threshold 1000.
start_replay() { spawn replay tcpreplay -q -i fnmmirror0 --pps 10000 --loop 0 /tmp/attack.pcap; }
stop_replay() { stop_one tcpreplay; }

session_up() {
    [ "$(docker exec "$FRR" vtysh -c 'show bgp neighbors 10.0.0.1 json' 2>/dev/null \
        | jq -r '.["10.0.0.1"].bgpState // empty')" = Established ]
}

# "<next hop> blackhole" for the prefix at FRR when the BLACKHOLE community is
# present ("<next hop> <communities>" when it is not), with " stale" appended
# while FRR holds it as a Graceful Restart helper; or ABSENT.
frr_route() {
    local afi=$1 prefix=$2
    docker exec "$FRR" vtysh -c "show bgp $afi unicast $prefix json" 2>/dev/null | jq -r '
        if (.paths // []) | length == 0 then "ABSENT" else
        .paths[0] | "\([.nexthops[]? | select(.scope != "link-local") | .ip][0]) \(
            if any(.community.list[]?; . == "blackhole") then "blackhole"
            else .community.string // "-" end)\(if .stale then " stale" else "" end)"
        end'
}

# Wait until frr_route matches; print the seconds waited. Returns 1 on timeout.
wait_route() {
    local afi=$1 prefix=$2 want=$3 limit=$4 start now
    start=$(date +%s)
    while :; do
        [ "$(frr_route "$afi" "$prefix")" = "$want" ] && { echo $(($(date +%s) - start)); return 0; }
        now=$(date +%s)
        [ $((now - start)) -ge "$limit" ] && return 1
        sleep 1
    done
}

expect_route() { # label afi prefix want limit
    local label=$1 secs
    if secs=$(wait_route "$2" "$3" "$4" "$5"); then
        ok "$label: FRR $3 = '$4' after ${secs}s"
    else
        bad "$label: FRR $3 never became '$4' within $5s (now '$(frr_route "$2" "$3")')"
    fi
}

# Sessions FRR has seen reach Established. The driver raises it on each
# restart it causes; any other change is a flap.
EXPECTED_EST=1

# "<FRR state> <FRR established> <FRR dropped> <rustbgpd established> <rustbgpd flaps>"
# The rustbgpd counters are its bgp_session_established_total and
# bgp_session_flaps_total for FRR, which start at zero with each process.
session_counters() {
    local frr daemon
    frr=$(docker exec "$FRR" vtysh -c 'show bgp neighbors 10.0.0.1 json' 2>/dev/null \
        | jq -r '.["10.0.0.1"] | "\(.bgpState) \(.connectionsEstablished) \(.connectionsDropped)"')
    daemon=$(docker exec "$DET" rbgp metrics 2>/dev/null | awk '
        /^bgp_session_established_total\{peer="10.0.0.2"\}/ { e = $2 }
        /^bgp_session_flaps_total\{peer="10.0.0.2"\}/ { f = $2 }
        END { print (e == "" ? "-" : e), (f == "" ? 0 : f) }')
    echo "$frr $daemon"
}

stable_want() { echo "Established $EXPECTED_EST $((EXPECTED_EST - 1)) 1 0"; }

# The session is up and has not dropped since the driver last restarted
# rustbgpd: FRR's connection counters match, and this rustbgpd process has
# reached Established once and never left it.
session_stable() {
    [ "$(session_counters)" = "$(stable_want)" ]
}

expect_session_stable() { # label
    if session_stable; then
        ok "$1: session Established, no flap"
    else
        bad "$1: session not stable: '$(session_counters)', expected '$(stable_want)'"
    fi
}

expect_banned() { # label limit
    expect_route "$1 (IPv4)" ipv4 "$V4" "$V4_NH $BLACKHOLE" "$2"
    expect_route "$1 (IPv6)" ipv6 "$V6" "$V6_NH $BLACKHOLE" "$2"
    expect_session_stable "$1"
}

expect_stale() { # label limit
    expect_route "$1 (IPv4)" ipv4 "$V4" "$V4_NH $BLACKHOLE stale" "$2"
    expect_route "$1 (IPv6)" ipv6 "$V6" "$V6_NH $BLACKHOLE stale" "$2"
}

expect_unbanned() { # label limit
    expect_route "$1 (IPv4)" ipv4 "$V4" ABSENT "$2"
    expect_route "$1 (IPv6)" ipv6 "$V6" ABSENT "$2"
    expect_session_stable "$1"
}

# Fail if either prefix appears at FRR during the next N seconds.
# Milliseconds from FRR's End-of-RIB to the first blackhole UPDATE after line
# MARK of its log, or 0 when the UPDATE came first (FRR never dropped the ban).
frr_gap_ms() { # mark eor-pattern update-pattern
    docker exec "$FRR" tail -n +"$(($1 + 1))" /tmp/bgpd.log | awk -v e="$2" -v u="$3" '
        # Milliseconds since 1970 of a "YYYY/MM/DD HH:MM:SS.mmm" log line,
        # by days-from-civil, so a gap across midnight stays correct.
        function ms(  d, t, y, m, era, yoe, doy, doe) {
            split($1, d, "/"); split($2, t, /[:.]/)
            y = d[1] - (d[2] <= 2); m = d[2] + 0
            era = int(y / 400); yoe = y - era * 400
            doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d[3] - 1
            doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
            return (((era * 146097 + doe - 719468) * 24 + t[1]) * 60 + t[2]) * 60000 + t[3] * 1000 + t[4]
        }
        index($0, e) && !ne { ne = NR; te = ms() }
        index($0, u) && !nu { nu = NR; tu = ms() }
        END { if (!ne || !nu) print "unknown"; else if (nu < ne) print 0; else print tu - te }'
}

expect_stays_absent() { # label seconds
    local end=$(($(date +%s) + $2)) seen="" unstable=""
    while [ "$(date +%s)" -lt "$end" ]; do
        for spec in "ipv4 $V4" "ipv6 $V6"; do
            # shellcheck disable=SC2086
            [ "$(frr_route $spec)" = ABSENT ] || seen="$seen ${spec#* }"
        done
        # Absence proves nothing over a session that has gone down.
        session_stable || unstable=$(session_counters)
        sleep 1
    done
    if [ -n "$unstable" ]; then
        bad "$1: session not stable during the check: '$unstable'"
    elif [ -z "$seen" ]; then
        ok "$1: neither prefix appeared at FRR for $2s over a stable session"
    else
        bad "$1: reappeared:$seen"
    fi
}

wait_session() { # label limit
    local start secs
    start=$(date +%s)
    while ! session_up; do
        if [ $(($(date +%s) - start)) -ge "$2" ]; then bad "$1: session not Established in $2s"; return 1; fi
        sleep 1
    done
    secs=$(($(date +%s) - start))
    ok "$1: session Established after ${secs}s"
}

# Seconds since the epoch at which FRR logged End-of-RIB from rustbgpd for
# the family ("IPv4" or "IPv6") after the given epoch, or nothing.
frr_eor_after() { # family since
    docker exec "$FRR" sh -c 'grep -a "rcvd End-of-RIB for $1 Unicast from 10.0.0.1" /tmp/bgpd.log || true' _ "$1" |
        while read -r day time _; do
            date -u -d "$day $time" +%s 2>/dev/null || true
        done | awk -v since="$2" '$1 >= since' | head -1
}

# Explicit withdrawals of a prefix that FRR has logged so far.
frr_withdrawals() { # prefix
    docker exec "$FRR" sh -c 'grep -ac "rcvd UPDATE about $1 .* -- withdrawn" /tmp/bgpd.log || true' _ "$1"
}

grace_expired_total() {
    docker exec "$DET" sh -c 'grep -c "End-of-RIB grace window ended at its deadline" /var/log/rustbgpd.log || true'
}

# ---------------------------------------------------------------------------
# Bring-up
# ---------------------------------------------------------------------------

log "FastNetMon: $(docker exec "$DET" /opt/fastnetmon-community/app/bin/fastnetmon --version)"
log "rustbgpd: $(docker exec "$DET" rustbgpd --version)"
log "FRR: $(docker exec "$FRR" vtysh -c 'show version' | head -1)"
start_rustbgpd
start_bridge
wait_session "bring-up" 90
expect_session_stable "bring-up"
start_fnm
sleep 5
expect_unbanned "baseline" 5

# ---------------------------------------------------------------------------
# Phase 1: ban and unban
# ---------------------------------------------------------------------------

log "Phase 1: replay attack, expect ban"
t0=$(date +%s)
start_replay
expect_banned "phase 1 ban" 60
record "phase1_ban_after_replay_start_s=$(($(date +%s) - t0))"
# The attributes on the wire, from FRR's inbound UPDATE debug. FRR's table
# view adds NO_EXPORT itself on receipt of BLACKHOLE (RFC 7999 section 3.2).
for want in "attr: nexthop $V4_NH, origin ?, community blackhole, path 65001" \
    "attr: , origin ?, mp_nexthop $V6_NH, community blackhole, path 65001"; do
    if docker exec "$FRR" grep -qF "rcvd UPDATE w/ $want" /tmp/bgpd.log; then
        ok "phase 1 wire attributes: $want"
    else
        bad "phase 1 wire attributes: no UPDATE with '$want'"
    fi
done
record "frr_v4_communities=$(docker exec "$FRR" vtysh -c "show bgp ipv4 unicast $V4 json" | jq -r '.paths[0].community.string')"
t0=$(date +%s)
stop_replay
log "Phase 1: replay stopped, expect unban"
expect_unbanned "phase 1 unban" 90
record "phase1_unban_after_replay_stop_s=$(($(date +%s) - t0))"

# ---------------------------------------------------------------------------
# Phase 2: rustbgpd restart while banned
# ---------------------------------------------------------------------------

# rustbgpd advertises Graceful Restart by default and FRR is a helper by
# default, so FRR keeps the bans as stale routes while rustbgpd is down. On
# the new session rustbgpd sends End-of-RIB before the bridge's next
# reconcile pass re-adds the bans, so FRR drops them and learns them again.
# The driver records that gap.
log "Phase 2: ban, then restart rustbgpd"
start_replay
expect_banned "phase 2 ban" 60
stop_one rustbgpd
expect_stale "phase 2 daemon stopped, FRR keeps stale bans" 10
sleep 10
expect_stale "phase 2 stale bans held 10s into the outage" 1
mark=$(docker exec "$FRR" sh -c 'wc -l < /tmp/bgpd.log')
start_rustbgpd
t0=$(date +%s)
wait_session "phase 2 restart" 120 || true
EXPECTED_EST=$((EXPECTED_EST + 1))
gap_from=""
gap_withdrawals=""
back=""
wd_before=$(($(frr_withdrawals "$V4") + $(frr_withdrawals "$V6")))
while [ $(($(date +%s) - t0)) -lt $((RECONCILE_SECS + 30)) ]; do
    s4=$(frr_route ipv4 "$V4")
    s6=$(frr_route ipv6 "$V6")
    now=$(($(date +%s) - t0))
    if [ -z "$gap_from" ] && { [ "$s4" = ABSENT ] || [ "$s6" = ABSENT ]; }; then
        gap_from=$now
        # Phase 5's detector: an absence with no explicit withdrawal is the gap.
        gap_withdrawals=$(($(frr_withdrawals "$V4") + $(frr_withdrawals "$V6") - wd_before))
    fi
    if [ "$s4" = "$V4_NH $BLACKHOLE" ] && [ "$s6" = "$V6_NH $BLACKHOLE" ]; then back=$now; break; fi
    sleep 1
done
if [ -n "$back" ]; then
    ok "phase 2 bans replayed by the bridge ${back}s after rustbgpd started"
else
    bad "phase 2 bans not back within $((RECONCILE_SECS + 30))s (now '$s4' / '$s6')"
fi
record "phase2_first_absent_after_start_s=${gap_from:-never}"
record "phase2_withdrawals_before_first_absence=${gap_withdrawals:-n/a}"
record "phase2_bans_back_after_start_s=${back:-never}"
record "phase2_v4_gap_ms=$(frr_gap_ms "$mark" "End-of-RIB for IPv4 Unicast" "attr: nexthop $V4_NH, origin ?, community blackhole")"
record "phase2_v6_gap_ms=$(frr_gap_ms "$mark" "End-of-RIB for IPv6 Unicast" "mp_nexthop $V6_NH, community blackhole")"
stop_replay
expect_unbanned "phase 2 unban after restart" 90

# ---------------------------------------------------------------------------
# Phase 3: bridge restart while banned
# ---------------------------------------------------------------------------

log "Phase 3: ban, then restart the bridge"
start_replay
expect_banned "phase 3 ban" 60
stop_one rustbgpd-gobgp-
expect_banned "phase 3 bridge stopped, bans held" 1
sleep 5
expect_banned "phase 3 bans still held after 5s" 1
start_bridge
t0=$(date +%s)
stop_replay
expect_unbanned "phase 3 unban through the new bridge" 90
record "phase3_unban_after_replay_stop_s=$(($(date +%s) - t0))"

# ---------------------------------------------------------------------------
# Phase 4: unban while rustbgpd is stopped
# ---------------------------------------------------------------------------

log "Phase 4: ban, stop rustbgpd, unban while it is down"
start_replay
expect_banned "phase 4 ban" 60
stop_one rustbgpd
expect_stale "phase 4 daemon stopped" 10
before=$(docker exec "$DET" grep -c 'AddPath request to BGP daemon failed' /var/log/fastnetmon.log || true)
t0=$(date +%s)
stop_replay
log "Phase 4: waiting for FastNetMon's unban attempt to fail"
after=$before
for _ in $(seq 1 90); do
    after=$(docker exec "$DET" grep -c 'AddPath request to BGP daemon failed' /var/log/fastnetmon.log || true)
    [ "$after" -ge $((before + 2)) ] && break
    sleep 1
done
if [ "$after" -ge $((before + 2)) ]; then
    ok "phase 4: FastNetMon's IPv4 and IPv6 withdrawals failed while rustbgpd was down"
else
    bad "phase 4: FastNetMon logged $((after - before)) failed withdrawals, expected 2"
fi
record "phase4_unban_attempt_after_replay_stop_s=$(($(date +%s) - t0))"
expect_stale "phase 4 blackholes linger at FRR after the failed unban" 1
start_rustbgpd
t0=$(date +%s)
wait_session "phase 4 restart" 120 || true
EXPECTED_EST=$((EXPECTED_EST + 1))
expect_unbanned "phase 4 stale bans flushed after restart" 30
record "phase4_flushed_after_start_s=$(($(date +%s) - t0))"
expect_stays_absent "phase 4 after restart (two reconcile intervals)" $((2 * RECONCILE_SECS + 5))

# ---------------------------------------------------------------------------
# Phase 5: rustbgpd restart while banned, End-of-RIB grace window on
# ---------------------------------------------------------------------------

# Phases 1-4 ran with the window off. Every later start uses the grace config,
# and every stop is a planned (marker-backed) restart.
log "Phase 5: ban, then restart rustbgpd with gr_eor_grace_time = $GRACE_SECS"
start_replay
expect_banned "phase 5 ban" 60
stop_one rustbgpd
expect_stale "phase 5 daemon stopped, FRR keeps stale bans" 10
expired_before=$(grace_expired_total)
start_rustbgpd "$GRACE_CONF"
t0=$(date +%s)
wait_session "phase 5 restart" 120 || true
EXPECTED_EST=$((EXPECTED_EST + 1))
absent_at=""
fresh=""
withdrawn=""
# Poll every second through the bridge's replay and past the release. A ban
# may vanish only through an explicit withdrawal UPDATE: FastNetMon 1.2.9
# lifts an IPv6 ban after ban_time even while the attack continues
# ("unban_only_if_attack_finished" is IPv4-only) and bans it again later. An
# absence with no new withdrawal logged since the last poll that saw the ban
# is the End-of-RIB gap this phase guards against.
wd4=$(frr_withdrawals "$V4")
wd6=$(frr_withdrawals "$V6")
while [ $(($(date +%s) - t0)) -lt $((GRACE_SECS + 15)) ]; do
    s4=$(frr_route ipv4 "$V4")
    s6=$(frr_route ipv6 "$V6")
    now=$(($(date +%s) - t0))
    if [ "$s4" = ABSENT ]; then
        if [ "$(frr_withdrawals "$V4")" -gt "$wd4" ]; then withdrawn="$withdrawn ${now}s:v4"; else absent_at=${absent_at:-$now}; fi
    else
        wd4=$(frr_withdrawals "$V4")
    fi
    if [ "$s6" = ABSENT ]; then
        if [ "$(frr_withdrawals "$V6")" -gt "$wd6" ]; then withdrawn="$withdrawn ${now}s:v6"; else absent_at=${absent_at:-$now}; fi
    else
        wd6=$(frr_withdrawals "$V6")
    fi
    if [ -z "$fresh" ] && [ "$s4" = "$V4_NH $BLACKHOLE" ] && [ "$s6" = "$V6_NH $BLACKHOLE" ]; then fresh=$now; fi
    sleep 1
done
if [ -z "$absent_at" ]; then
    ok "phase 5 FRR never lost a ban without a withdrawal over $((GRACE_SECS + 15))s after rustbgpd started (explicit FastNetMon unbans:${withdrawn:- none})"
else
    bad "phase 5 a ban vanished from FRR without a withdrawal ${absent_at}s after rustbgpd started"
fi
if [ -n "$fresh" ] && [ "$fresh" -lt "$GRACE_SECS" ]; then
    ok "phase 5 the bridge's replay refreshed both bans ${fresh}s after start, inside the window"
else
    bad "phase 5 replay did not refresh both bans inside the ${GRACE_SECS}s window (fresh=${fresh:-never})"
fi
eor4=$(frr_eor_after IPv4 "$t0")
eor6=$(frr_eor_after IPv6 "$t0")
if [ -n "$eor4" ] && [ -n "$eor6" ] && [ $((eor4 - t0)) -ge $((GRACE_SECS - 2)) ] &&
    [ $((eor6 - t0)) -ge $((GRACE_SECS - 2)) ]; then
    ok "phase 5 FRR received End-of-RIB at the window's end ($((eor4 - t0))s / $((eor6 - t0))s after start)"
else
    bad "phase 5 End-of-RIB timing: IPv4 ${eor4:-none}, IPv6 ${eor6:-none}, start $t0"
fi
if [ "$(grace_expired_total)" -gt "$expired_before" ]; then
    ok "phase 5 rustbgpd logged the grace-window release"
else
    bad "phase 5 no grace-window release in the rustbgpd log"
fi
expect_banned "phase 5 bans fresh after the release" 1
record "phase5_unexplained_absence_after_start_s=${absent_at:-never}"
record "phase5_explicit_withdrawals_seen=${withdrawn:- none}"
record "phase5_bans_fresh_after_start_s=${fresh:-never}"
record "phase5_eor_after_start_s=$((${eor4:-t0} - t0))"
stop_replay
expect_unbanned "phase 5 unban after restart" 90

# ---------------------------------------------------------------------------
# Phase 6: unban while rustbgpd is stopped, End-of-RIB grace window on
# ---------------------------------------------------------------------------

log "Phase 6: ban, stop rustbgpd, unban while it is down, restart with the window"
start_replay
expect_banned "phase 6 ban" 60
stop_one rustbgpd
expect_stale "phase 6 daemon stopped" 10
before=$(docker exec "$DET" grep -c 'AddPath request to BGP daemon failed' /var/log/fastnetmon.log || true)
stop_replay
after=$before
for _ in $(seq 1 90); do
    after=$(docker exec "$DET" grep -c 'AddPath request to BGP daemon failed' /var/log/fastnetmon.log || true)
    [ "$after" -ge $((before + 2)) ] && break
    sleep 1
done
if [ "$after" -ge $((before + 2)) ]; then
    ok "phase 6: FastNetMon's withdrawals failed while rustbgpd was down"
else
    bad "phase 6: FastNetMon logged $((after - before)) failed withdrawals, expected 2"
fi
start_rustbgpd "$GRACE_CONF"
t0=$(date +%s)
wait_session "phase 6 restart" 120 || true
EXPECTED_EST=$((EXPECTED_EST + 1))
# The lifted bans stay stale until the release, then FRR removes them.
held=""
gone=""
while [ $(($(date +%s) - t0)) -lt $((GRACE_SECS + 20)) ]; do
    s4=$(frr_route ipv4 "$V4")
    s6=$(frr_route ipv6 "$V6")
    now=$(($(date +%s) - t0))
    if [ "$s4" = ABSENT ] && [ "$s6" = ABSENT ]; then gone=$now; break; fi
    if [ "$s4" = "$V4_NH $BLACKHOLE stale" ] && [ "$s6" = "$V6_NH $BLACKHOLE stale" ]; then held=$now; fi
    sleep 1
done
if [ -n "$held" ] && [ "$held" -ge $((GRACE_SECS - 5)) ] && [ -n "$gone" ]; then
    ok "phase 6 lifted bans stayed stale until ${held}s, removed ${gone}s after start (window ${GRACE_SECS}s)"
else
    bad "phase 6 lifted bans: last stale ${held:-never}s, removed ${gone:-never}s, window ${GRACE_SECS}s"
fi
record "phase6_stale_until_s=${held:-never}"
record "phase6_removed_after_start_s=${gone:-never}"
expect_stays_absent "phase 6 after release (one reconcile interval)" $((RECONCILE_SECS + 5))

# ---------------------------------------------------------------------------

echo "----- timings -----"
cat "$RESULTS"
echo "-------------------"
if [ "$fail" -eq 0 ]; then
    echo "M126 PASS ($pass checks)"
    exit 0
fi
echo "M126 FAIL ($fail of $((pass + fail)) checks failed)"
exit 1
