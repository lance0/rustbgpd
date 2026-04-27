#!/usr/bin/env bash
# M33 24-hour soak harness — long-running variant of test-m33-evpn-scale.sh.
#
# Sustains 50k Type 2 EVPN routes + steady-state churn for SOAK_HOURS hours
# and asserts no memory leak, no session flaps, no metric drift. Reuses the
# M33 topology + load binaries unchanged: tester/monitor durations are just
# scaled up via --churn-duration-sec / --observe-sec.
#
# Output: tests/soak/runs/<UTC-timestamp>/
#   - samples.csv     one-row-per-minute timeseries (mem, cpu, rib counts, counters)
#   - soak.log        stdout + stderr from this script
#   - monitor.json    final report from the synthetic observer peer
#   - run.json        run metadata (image SHA, git rev, env at start)
#   - report.json     analyzer verdict (slope, percentiles, gates)
#
# Prerequisites:
#   docker build -t rustbgpd:dev .
#   containerlab deploy -t tests/interop/m33-evpn-scale.clab.yml
#
# Usage:
#   bash tests/soak/run-m33-soak.sh                                 # 24h default
#   SOAK_HOURS=1 bash tests/soak/run-m33-soak.sh                    # smoke (1h)
#   SOAK_HOURS=1 SAMPLE_INTERVAL=30 WARMUP_SEC=300 \
#       CLEANUP=1 bash tests/soak/run-m33-soak.sh                   # smoke + auto-cleanup
#
# Exit codes:
#   0   all gates pass
#   1   one or more gates fail (memory slope, peak, flaps, drops, gRPC, restart)
#   2   harness setup or runtime failure (couldn't start daemon, monitor never converged)

# ---------------------------------------------------------------------------
# Bootstrap — set TOPO + SCRIPT_DIR before sourcing test-lib.sh.
# ---------------------------------------------------------------------------

TOPO="m33-evpn-scale"
SOAK_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_SCRIPT_DIR="$(cd "$SOAK_SCRIPT_DIR/../interop/scripts" && pwd)"

# test-lib.sh's _clab_topology_file() resolves $SCRIPT_DIR/../$TOPO.clab.yml,
# so SCRIPT_DIR must point at tests/interop/scripts/ for the EXIT trap's
# `containerlab destroy` to find the right topology file.
SCRIPT_DIR="$INTEROP_SCRIPT_DIR"

# shellcheck source=../interop/scripts/test-lib.sh
source "$INTEROP_SCRIPT_DIR/test-lib.sh"

# ---------------------------------------------------------------------------
# Config (env-overridable)
# ---------------------------------------------------------------------------

SOAK_HOURS=${SOAK_HOURS:-24}
# SOAK_SEC takes precedence — useful for sub-hour smoke runs that the
# integer SOAK_HOURS knob can't express (e.g. SOAK_SEC=600 for a 10-min
# wiring smoke).
SOAK_SEC=${SOAK_SEC:-$(( SOAK_HOURS * 3600 ))}
WARMUP_SEC=${WARMUP_SEC:-600}
SAMPLE_INTERVAL=${SAMPLE_INTERVAL:-60}
HEALTH_CHECK_INTERVAL=${HEALTH_CHECK_INTERVAL:-300}

COUNT_PER_TESTER=${COUNT_PER_TESTER:-25000}
ADVERTISE_RATE=${ADVERTISE_RATE:-5000}
CHURN_RATE=${CHURN_RATE:-1000}
TESTER_LINGER_SEC=${TESTER_LINGER_SEC:-120}
# Monitor outlives the testers' churn phase by 60s so it doesn't terminate
# mid-final-sample.
MONITOR_OBSERVE_SEC=$(( SOAK_SEC + 60 ))
CONVERGE_TIMEOUT=${CONVERGE_TIMEOUT:-120}

TESTER_A="clab-${TOPO}-tester-a"
TESTER_B="clab-${TOPO}-tester-b"
MONITOR="clab-${TOPO}-monitor"

# ---------------------------------------------------------------------------
# Run directory + logging
# ---------------------------------------------------------------------------

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$SOAK_SCRIPT_DIR/runs/$RUN_ID"
mkdir -p "$RUN_DIR"
CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
RUN_META="$RUN_DIR/run.json"
MONITOR_JSON="$RUN_DIR/monitor.json"
REPORT_JSON="$RUN_DIR/report.json"

# Mirror everything to soak.log from this point on.
exec > >(tee -a "$SOAK_LOG") 2>&1

log "M33 soak run $RUN_ID"
log "  duration:   ${SOAK_HOURS}h (${SOAK_SEC}s)"
log "  warmup:     ${WARMUP_SEC}s"
log "  sample:     every ${SAMPLE_INTERVAL}s"
log "  health:     every ${HEALTH_CHECK_INTERVAL}s"
log "  churn rate: ${CHURN_RATE} rps"
log "  output:     $RUN_DIR"

# Capture run metadata at start.
{
    echo "{"
    printf '  "run_id": "%s",\n' "$RUN_ID"
    printf '  "soak_hours": %d,\n' "$SOAK_HOURS"
    printf '  "warmup_sec": %d,\n' "$WARMUP_SEC"
    printf '  "sample_interval_sec": %d,\n' "$SAMPLE_INTERVAL"
    printf '  "churn_rate_rps": %d,\n' "$CHURN_RATE"
    printf '  "advertise_rate": %d,\n' "$ADVERTISE_RATE"
    printf '  "count_per_tester": %d,\n' "$COUNT_PER_TESTER"
    printf '  "git_rev": "%s",\n' "$(git -C "$SOAK_SCRIPT_DIR/../.." rev-parse HEAD 2>/dev/null || echo unknown)"
    printf '  "image_sha": "%s",\n' "$(docker image inspect rustbgpd:dev --format '{{.Id}}' 2>/dev/null || echo unknown)"
    printf '  "started_at": "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "}"
} > "$RUN_META"

# ---------------------------------------------------------------------------
# Memory unit parser — copies the unit-aware normalization from
# test-m33-evpn-scale.sh so 85.3MiB / 3.0GiB / 512KiB all become MB.
# ---------------------------------------------------------------------------

parse_mem_to_mb() {
    local raw="$1"
    [ -z "$raw" ] && { echo "NaN"; return; }
    awk -v raw="$raw" 'BEGIN {
        n = raw + 0
        unit = raw
        sub(/^[0-9.]*/, "", unit)
        mb = -1
        if      (unit == "B")                       mb = n / 1048576.0
        else if (unit == "KiB" || unit == "kB")     mb = n / 1024.0
        else if (unit == "MiB" || unit == "MB" || unit == "mB") mb = n
        else if (unit == "GiB" || unit == "GB" || unit == "gB") mb = n * 1024.0
        else if (unit == "TiB" || unit == "TB")     mb = n * 1048576.0
        if (mb < 0) print "NaN"
        else printf "%.2f\n", mb
    }'
}

# ---------------------------------------------------------------------------
# Prometheus metric extraction — one curl + awk per sample.
# Returns a single space-delimited line:
#   rib_loc_evpn  adj_out_evpn_total  flaps_total  drops_total  msgs_sent  msgs_recv
# Any field that fails to parse yields "NaN" (gauges) or "0" (counters).
# ---------------------------------------------------------------------------

sample_metrics() {
    local body
    body=$(curl -s --max-time 5 "http://${RR_IP}:9179/metrics" 2>/dev/null) || {
        echo "NaN NaN NaN NaN NaN NaN"
        return
    }
    awk '
        /^bgp_rib_loc_prefixes\{afi_safi="evpn"\}/                          { rib_loc=$2 }
        /^bgp_rib_adj_out_prefixes\{.*afi_safi="evpn".*\}/                  { adj_out += $2 }
        /^bgp_session_flaps_total\{/                                        { flaps   += $2 }
        /^bgp_outbound_route_drops_total\{/                                 { drops   += $2 }
        /^bgp_messages_sent_total\{/                                        { sent    += $2 }
        /^bgp_messages_received_total\{/                                    { recv    += $2 }
        END {
            printf "%s %s %s %s %s %s\n",
                (rib_loc==""?"NaN":rib_loc),
                (adj_out==""?"NaN":adj_out),
                (flaps==""?0:flaps),
                (drops==""?0:drops),
                (sent==""?0:sent),
                (recv==""?0:recv)
        }
    ' <<<"$body"
}

# ---------------------------------------------------------------------------
# Stage 0 — start daemon, resolve gRPC + Prometheus addresses
# ---------------------------------------------------------------------------

resolve_grpc_addr
start_rustbgpd

RR_IP=$(resolve_ip "$RUSTBGPD")
if [ -z "$RR_IP" ]; then
    echo "ERROR: cannot resolve RR IP for Prometheus scrape" >&2
    exit 2
fi
log "Prometheus endpoint: http://${RR_IP}:9179/metrics"

# ---------------------------------------------------------------------------
# Stage 1 — launch monitor (exits when converged_at + observe-sec elapses)
# ---------------------------------------------------------------------------

log "[stage 1] launching monitor (expect=$((COUNT_PER_TESTER * 2)), observe-sec=${MONITOR_OBSERVE_SEC})"
docker exec -d "$MONITOR" sh -c "evpn-monitor \
    --listen 0.0.0.0:179 \
    --local-as 65000 \
    --router-id 10.0.0.20 \
    --expect $((COUNT_PER_TESTER * 2)) \
    --stable-sec 5 \
    --timeout-sec ${CONVERGE_TIMEOUT} \
    --observe-sec ${MONITOR_OBSERVE_SEC} \
    > /tmp/monitor.json 2> /tmp/monitor.log"
sleep 2

# ---------------------------------------------------------------------------
# Stage 2 — launch testers (each runs for the full soak via churn-duration)
# ---------------------------------------------------------------------------

log "[stage 2] launching tester-a (${COUNT_PER_TESTER} routes @ ${ADVERTISE_RATE}/s, churn ${CHURN_RATE}/s for ${SOAK_SEC}s)"
docker exec -d "$TESTER_A" sh -c "evpn-tester \
    --listen 0.0.0.0:179 \
    --local-as 65000 \
    --router-id 10.0.0.11 \
    --count ${COUNT_PER_TESTER} \
    --rate ${ADVERTISE_RATE} \
    --batch 40 \
    --vni 100 \
    --churn-duration-sec ${SOAK_SEC} \
    --churn-rate ${CHURN_RATE} \
    --linger-sec ${TESTER_LINGER_SEC} \
    > /tmp/tester.log 2>&1"

log "[stage 2] launching tester-b (${COUNT_PER_TESTER} routes @ ${ADVERTISE_RATE}/s, churn ${CHURN_RATE}/s for ${SOAK_SEC}s)"
docker exec -d "$TESTER_B" sh -c "evpn-tester \
    --listen 0.0.0.0:179 \
    --local-as 65000 \
    --router-id 10.0.0.12 \
    --count ${COUNT_PER_TESTER} \
    --rate ${ADVERTISE_RATE} \
    --batch 40 \
    --vni 100 \
    --churn-duration-sec ${SOAK_SEC} \
    --churn-rate ${CHURN_RATE} \
    --linger-sec ${TESTER_LINGER_SEC} \
    > /tmp/tester.log 2>&1"

# ---------------------------------------------------------------------------
# Stage 3 — wait for initial convergence (warmup checkpoint)
#
# We can't gate on monitor.json — monitor.rs only emits its JSON report when
# it exits, and with --observe-sec set to SOAK_SEC+60 that's 24h+ from now.
# Poll the RR's Prometheus Loc-RIB gauge instead: when bgp_rib_loc_prefixes
# {afi_safi="evpn"} reaches the expected total, the testers fired and the RR
# absorbed the routes. As a backstop we also accept the monitor's "converged"
# tracing event in /tmp/monitor.log.
# ---------------------------------------------------------------------------

EXPECTED_TOTAL=$((COUNT_PER_TESTER * 2))
log "[stage 3] waiting for RR Loc-RIB EVPN count to reach ${EXPECTED_TOTAL} (timeout ${CONVERGE_TIMEOUT}s)"
warmup_start=$(date +%s)
warmup_deadline=$(( warmup_start + CONVERGE_TIMEOUT + 30 ))
while true; do
    now=$(date +%s)
    if [ "$now" -ge "$warmup_deadline" ]; then
        echo "ERROR: RR never reached ${EXPECTED_TOTAL} EVPN routes within $((CONVERGE_TIMEOUT + 30))s" >&2
        docker cp "${MONITOR}:/tmp/monitor.log" "$RUN_DIR/monitor-pre-converge.log" 2>/dev/null || true
        last_count=$(curl -s --max-time 5 "http://${RR_IP}:9179/metrics" 2>/dev/null \
            | awk '/^bgp_rib_loc_prefixes\{afi_safi="evpn"\}/ { print $2; exit }')
        echo "ERROR: last observed Loc-RIB EVPN count: ${last_count:-<none>}" >&2
        exit 2
    fi
    rib_count=$(curl -s --max-time 5 "http://${RR_IP}:9179/metrics" 2>/dev/null \
        | awk '/^bgp_rib_loc_prefixes\{afi_safi="evpn"\}/ { print $2; exit }')
    # Strip a Prometheus-style trailing ".0" for integer comparison.
    rib_count_int=${rib_count%.*}
    if [ -n "$rib_count_int" ] && [ "$rib_count_int" -ge "$EXPECTED_TOTAL" ] 2>/dev/null; then
        log "initial convergence reached at $((now - warmup_start))s — Loc-RIB EVPN count=${rib_count}"
        break
    fi
    if docker exec "$MONITOR" sh -c 'test -s /tmp/monitor.log && grep -q converged /tmp/monitor.log' 2>/dev/null; then
        log "monitor reported converged at $((now - warmup_start))s (Loc-RIB count was ${rib_count:-<unknown>})"
        break
    fi
    sleep 2
done

# ---------------------------------------------------------------------------
# Stage 4 — start sampler subshell
# ---------------------------------------------------------------------------

log "[stage 4] starting sampler — ${SAMPLE_INTERVAL}s cadence"

# Header on first write.
echo "timestamp,uptime_sec,mem_mb,cpu_pct,grpc_ok,rib_loc_evpn,adj_out_evpn_total,session_flaps_total,outbound_drops_total,msgs_sent_total,msgs_recv_total" > "$CSV"

SOAK_START=$(date +%s)
SAMPLER_RUN_FLAG="$RUN_DIR/.sampler-running"
touch "$SAMPLER_RUN_FLAG"

(
    set +e
    while [ -f "$SAMPLER_RUN_FLAG" ]; do
        ts=$(date +%s)
        uptime=$((ts - SOAK_START))

        mem_cpu=$(docker stats --no-stream --format '{{.MemUsage}}|{{.CPUPerc}}' "$RUSTBGPD" 2>/dev/null || echo '|')
        # MemUsage is "85.3MiB / 125GiB"; we want the first token before " / ".
        mem_raw=${mem_cpu%%|*}
        mem_raw=${mem_raw%% /*}
        mem_raw=${mem_raw// /}
        cpu_pct_raw=${mem_cpu##*|}
        cpu_pct=${cpu_pct_raw%\%}

        mem_mb=$(parse_mem_to_mb "$mem_raw")
        [ -z "$mem_mb" ] && mem_mb="NaN"

        grpc_ok=0
        if grpc_health >/dev/null 2>&1; then
            grpc_ok=1
        fi

        read -r rib_loc adj_out flaps drops sent recv <<<"$(sample_metrics)"

        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$ts" "$uptime" "${mem_mb:-NaN}" "${cpu_pct:-NaN}" "$grpc_ok" \
            "${rib_loc:-NaN}" "${adj_out:-NaN}" \
            "${flaps:-0}" "${drops:-0}" "${sent:-0}" "${recv:-0}" \
            >> "$CSV"

        sleep "$SAMPLE_INTERVAL"
    done
) &
SAMPLER_PID=$!

# ---------------------------------------------------------------------------
# Stage 5 — outer wait loop with periodic health gate
# ---------------------------------------------------------------------------

log "[stage 5] soak running for ${SOAK_HOURS}h (${SOAK_SEC}s); health-checking every ${HEALTH_CHECK_INTERVAL}s"

soak_end=$(( SOAK_START + SOAK_SEC ))
last_health_log=$SOAK_START
consecutive_health_fails=0
abort_reason=""

while true; do
    now=$(date +%s)
    if [ "$now" -ge "$soak_end" ]; then
        log "soak duration reached"
        break
    fi
    # Check health every HEALTH_CHECK_INTERVAL seconds.
    if [ $(( now - last_health_log )) -ge "$HEALTH_CHECK_INTERVAL" ]; then
        if grpc_health >/dev/null 2>&1; then
            consecutive_health_fails=0
            elapsed_h=$(awk -v s=$((now - SOAK_START)) 'BEGIN { printf "%.2f", s/3600.0 }')
            remaining_h=$(awk -v s=$((soak_end - now)) 'BEGIN { printf "%.2f", s/3600.0 }')
            log "health OK at +${elapsed_h}h (${remaining_h}h remaining)"
        else
            consecutive_health_fails=$((consecutive_health_fails + 1))
            log "health FAILED ($consecutive_health_fails consecutive failures)"
            if [ "$consecutive_health_fails" -ge 2 ]; then
                abort_reason="rustbgpd unhealthy for $((consecutive_health_fails * HEALTH_CHECK_INTERVAL))s — aborting soak"
                break
            fi
        fi
        last_health_log=$now
    fi
    # Sleep in 10s chunks so abort signals propagate quickly.
    sleep 10
done

# ---------------------------------------------------------------------------
# Stage 6 — stop sampler, collect monitor JSON
# ---------------------------------------------------------------------------

log "[stage 6] stopping sampler"
rm -f "$SAMPLER_RUN_FLAG"
# Give the sampler one more interval to finish in-flight work.
wait_deadline=$(( $(date +%s) + SAMPLE_INTERVAL + 5 ))
while kill -0 "$SAMPLER_PID" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$wait_deadline" ]; then
        kill "$SAMPLER_PID" 2>/dev/null || true
        break
    fi
    sleep 1
done

# monitor.rs only emits its JSON report on exit (after observe-sec elapses),
# so monitor.json is empty until the binary returns. With observe-sec set to
# SOAK_SEC + 60 the monitor is still running ~60s past our soak deadline.
# Wait up to MONITOR_EXIT_TIMEOUT seconds for the monitor process to exit
# before copying monitor.json out — partial copies are useless.
MONITOR_EXIT_TIMEOUT=${MONITOR_EXIT_TIMEOUT:-180}
log "[stage 6] waiting up to ${MONITOR_EXIT_TIMEOUT}s for monitor binary to exit + flush JSON"
# `docker top` runs on the host (no in-container deps — the runtime image
# is debian-slim with only iproute2, no procps/pgrep). Detect exit by
# observing that evpn-monitor is no longer in the container's process list.
monitor_wait_deadline=$(( $(date +%s) + MONITOR_EXIT_TIMEOUT ))
while [ "$(date +%s)" -lt "$monitor_wait_deadline" ]; do
    if ! docker top "$MONITOR" 2>/dev/null | grep -q evpn-monitor; then
        log "monitor exited"
        break
    fi
    sleep 2
done

log "copying monitor.json + monitor.log out of $MONITOR"
docker cp "${MONITOR}:/tmp/monitor.json" "$MONITOR_JSON" 2>/dev/null || true
docker cp "${MONITOR}:/tmp/monitor.log" "$RUN_DIR/monitor.log" 2>/dev/null || true
if [ ! -s "$MONITOR_JSON" ]; then
    log "WARNING: monitor.json missing or empty — analyzer's monitor summary will be null"
fi

# ---------------------------------------------------------------------------
# Stage 7 — analyze
# ---------------------------------------------------------------------------

if [ -n "$abort_reason" ]; then
    log "[stage 7] soak aborted: $abort_reason"
    log "running analyzer anyway for partial-run report"
fi

log "[stage 7] running analyzer"
analyzer_exit=0
python3 "$SOAK_SCRIPT_DIR/analyze-soak.py" \
    "$CSV" \
    --monitor-json "$MONITOR_JSON" \
    --warmup-sec "$WARMUP_SEC" \
    --soak-hours "$SOAK_HOURS" \
    --output "$REPORT_JSON" \
    || analyzer_exit=$?

if [ "$analyzer_exit" -eq 0 ] && [ -z "$abort_reason" ]; then
    ok "soak completed cleanly — see $REPORT_JSON"
else
    fail "soak gates failed (analyzer exit ${analyzer_exit}${abort_reason:+; aborted: $abort_reason})"
fi

print_summary
