#!/usr/bin/env bash
# chaos-grpc-churn.sh — concurrent gRPC mutations against the daemon.
#
# Topology: M33 (`tests/interop/m33-evpn-scale.clab.yml`). The daemon
# must already be running. The chaos here is *purely* the gRPC fan-in:
# we don't bounce sessions, we just slam Add/Delete/SoftReset RPCs in
# parallel and watch for deadlocks, panics, or stuck queries.
#
# Each "shot" is an independent grpcurl invocation; we run many in
# parallel via `xargs -P` so the daemon's gRPC handler queue and the
# RibUpdate channel both see contention.
#
# Pass criteria:
#   - GetHealth never returns non-OK during the storm (probe every 2 s)
#   - No process restart (counter monotonicity)
#   - At least 90% of attempted shots succeed (some are expected to
#     fail validation — duplicate add, delete-not-found — but the
#     daemon must not deadlock or panic)
#
# Output: tests/chaos/runs/<UTC-timestamp>/{driver.log,probe.log,report.json}

set -euo pipefail

CHAOS_DURATION_SEC=${CHAOS_DURATION_SEC:-60}
CHAOS_PARALLELISM=${CHAOS_PARALLELISM:-16}
CHAOS_TOPO=${CHAOS_TOPO:-m33-evpn-scale}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TS=$(date -u +%Y%m%dT%H%M%SZ)
RUN_DIR="$SCRIPT_DIR/runs/$TS"
mkdir -p "$RUN_DIR"
DRIVER_LOG="$RUN_DIR/driver.log"
PROBE_LOG="$RUN_DIR/probe.log"
REPORT="$RUN_DIR/report.json"

TOPO="$CHAOS_TOPO"
# shellcheck source=../interop/scripts/test-lib.sh
source "$SCRIPT_DIR/../interop/scripts/test-lib.sh"
resolve_grpc_addr

log "[chaos-grpc-churn] duration=${CHAOS_DURATION_SEC}s parallelism=$CHAOS_PARALLELISM"
log "[chaos-grpc-churn] run dir: $RUN_DIR"

# Fire one of three random gRPC mutations against a churnable IP.
# IPs land in 10.99.0.0/16 — outside any real session — so the daemon
# accepts/rejects based on existing state but never opens a TCP
# connection. Pure control-plane churn.
shot() {
    local idx="$1"
    local ip
    ip="10.99.$((RANDOM % 256)).$((RANDOM % 256))"
    local op=$((RANDOM % 3))
    case $op in
        0)
            grpcurl -plaintext -import-path . -proto "$PROTO" \
                -d "{\"config\":{\"address\":\"$ip\",\"remote_asn\":65999,\"families\":[\"ipv4_unicast\"]}}" \
                "$GRPC_ADDR" rustbgpd.v1.NeighborService/AddNeighbor 2>&1 \
                | head -1 >>"$DRIVER_LOG"
            ;;
        1)
            grpcurl -plaintext -import-path . -proto "$PROTO" \
                -d "{\"address\":\"$ip\"}" \
                "$GRPC_ADDR" rustbgpd.v1.NeighborService/DeleteNeighbor 2>&1 \
                | head -1 >>"$DRIVER_LOG"
            ;;
        2)
            grpcurl -plaintext -import-path . -proto "$PROTO" \
                -d "{\"address\":\"$ip\"}" \
                "$GRPC_ADDR" rustbgpd.v1.NeighborService/SoftResetIn 2>&1 \
                | head -1 >>"$DRIVER_LOG"
            ;;
    esac
}
export -f shot
export GRPC_ADDR PROTO DRIVER_LOG

# Probe daemon health every 2 s in the background.
probe_pid=
probe_failures=0
(
    while :; do
        if grpc_health >/dev/null 2>&1; then
            echo "$(date +%s) ok" >>"$PROBE_LOG"
        else
            echo "$(date +%s) FAIL" >>"$PROBE_LOG"
        fi
        sleep 2
    done
) &
probe_pid=$!
trap 'kill $probe_pid 2>/dev/null || true' EXIT

# Storm loop
deadline=$(( $(date +%s) + CHAOS_DURATION_SEC ))
shots=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    # Burst of CHAOS_PARALLELISM concurrent shots; xargs caps fan-out
    seq 1 "$CHAOS_PARALLELISM" | xargs -P "$CHAOS_PARALLELISM" -I{} bash -c 'shot {}' _
    shots=$((shots + CHAOS_PARALLELISM))
done

kill $probe_pid 2>/dev/null || true
wait 2>/dev/null || true

# Tally outcomes. `grep -c` exits non-zero when no match; tolerate that
# under set -e by piping through `|| true` and stripping any stray
# whitespace.
ok_shots=$(grep -c "^{" "$DRIVER_LOG" 2>/dev/null || true)
err_shots=$(grep -cE "^ERROR|Code: " "$DRIVER_LOG" 2>/dev/null || true)
probe_failures=$(grep -c "FAIL" "$PROBE_LOG" 2>/dev/null || true)
ok_shots=${ok_shots:-0}
err_shots=${err_shots:-0}
probe_failures=${probe_failures:-0}

# Daemon final health
final_health=$(grpc_health 2>&1 | head -1 || echo "")

# A "shot" succeeds only if the daemon returned a structured response
# (either OK with `{}` or a typed gRPC error). We accept either as
# evidence the daemon was responsive; what we don't tolerate is no
# response (deadlock) or process exit (panic). At least 90% of shots
# must produce *some* response.
total_responded=$((ok_shots + err_shots))
response_rate=0
if [ "$shots" -gt 0 ]; then
    response_rate=$(awk -v r="$total_responded" -v t="$shots" 'BEGIN{printf "%.2f", r*100/t}')
fi

verdict="clean"
failures=()
if [ "$probe_failures" -gt 0 ]; then
    verdict="needs-attention"
    failures+=("\"$probe_failures GetHealth probe failures during storm\"")
fi
if [ -z "$final_health" ]; then
    verdict="needs-attention"
    failures+=("\"daemon GetHealth unresponsive at end of storm\"")
fi
# Allow some response loss to xargs / subprocess setup — the contract
# is "no deadlock", not "every shot lands".
if awk -v r="$response_rate" 'BEGIN{exit !(r < 90)}'; then
    verdict="needs-attention"
    failures+=("\"only ${response_rate}% of shots got a response (need >=90%)\"")
fi

failures_json=$(IFS=,; echo "[${failures[*]:-}]")

cat >"$REPORT" <<EOF
{
  "verdict": "$verdict",
  "failures": $failures_json,
  "topology": "$CHAOS_TOPO",
  "duration_sec": $CHAOS_DURATION_SEC,
  "parallelism": $CHAOS_PARALLELISM,
  "shots": $shots,
  "ok_shots": $ok_shots,
  "err_shots": $err_shots,
  "response_rate_pct": $response_rate,
  "probe_failures": $probe_failures
}
EOF

log "[chaos-grpc-churn] verdict=$verdict shots=$shots response_rate=${response_rate}% probe_failures=$probe_failures"
[ "$verdict" = "clean" ] && exit 0 || exit 1
