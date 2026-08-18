#!/bin/bash
# phase 0 single A/B run: cleanup, bench with pinned image, concurrent target memory sampling.
# Adapted from rebaseline/run_one.sh; usage: run_one.sh <base|head|c> <run_id>
# base = 515659b1 (ab-base), head = 07f6eb52 (ab-head), c = cbefe848 bridge arm (ab-c)
set -u
SIDE="$1"; RUN="$2"
SCRATCH=<runs>
CTN="bgperf_rustbgpd_target"
IMG="bgperf/rustbgpd:ab-${SIDE}"
LOG="$SCRATCH/${RUN}_${SIDE}.log"
SAMPLES="$SCRATCH/${RUN}_${SIDE}.samples.tsv"

cd <bgperf2> || exit 1
docker rm -f $(docker ps -aq --filter "name=bgperf") >/dev/null 2>&1
docker network rm bgperf2-br >/dev/null 2>&1

# Explicit event-history mode, constant across every run and both sides.
export RUSTBGPD_EVENT_HISTORY=disabled RUSTBGPD_EVENT_HISTORY_OFF=1
# The ab-base daemon (515659b1, pre-v0.63.0) refuses tier enforcement with an
# empty roles map; render the [security.grpc] enforcement="legacy" block its
# own era's harness rendered. Inert for ab-head (v0.63.0 removed the knob).
if [ "$SIDE" = "base" ]; then
    export RUSTBGPD_GRPC_ENFORCEMENT=legacy
else
    unset RUSTBGPD_GRPC_ENFORCEMENT
fi

date -Is > "$LOG"
echo "image: $IMG $(docker inspect -f '{{.Id}}' "$IMG")" >> "$LOG"
# Foreign-load telemetry: owner workloads (cargo/rustc by comm, otherload) must be
# absent for a run to count as clean; loadavg recorded for the classification.
echo "lane-start: load=$(cut -d' ' -f1-3 /proc/loadavg) cargo_rustc=$(ps -C cargo,rustc -o pid= 2>/dev/null | wc -l) otherload=$(ps -C otherload -o pid= 2>/dev/null | wc -l)" >> "$LOG"
.venv/bin/python bgperf2.py bench -t rustbgpd -n 100 -p 1000 --image "$IMG" >> "$LOG" 2>&1 &
BENCH=$!

printf 'ts\tcg_current_bytes\tcg_anon_bytes\tcg_peak_bytes\tptree_rss_kb\tptree_anon_kb\n' > "$SAMPLES"
while kill -0 "$BENCH" 2>/dev/null; do
    PID=$(docker inspect -f '{{.State.Pid}}' "$CTN" 2>/dev/null)
    if [ -n "${PID:-}" ] && [ "$PID" != "0" ] && [ -d "/proc/$PID" ]; then
        CG="/sys/fs/cgroup$(awk -F: 'NR==1{print $3}' /proc/$PID/cgroup 2>/dev/null)"
        cur=$(cat "$CG/memory.current" 2>/dev/null)
        anon=$(awk '$1=="anon"{print $2}' "$CG/memory.stat" 2>/dev/null)
        peak=$(cat "$CG/memory.peak" 2>/dev/null)
        rss=0; panon=0
        for p in $(cat "$CG/cgroup.procs" 2>/dev/null); do
            # smaps_rollup is ptrace-gated for the root-owned container procs;
            # /proc/pid/status VmRSS/RssAnon is world-readable.
            r=$(awk '/^VmRSS:/{print $2}' "/proc/$p/status" 2>/dev/null)
            a=$(awk '/^RssAnon:/{print $2}' "/proc/$p/status" 2>/dev/null)
            rss=$((rss + ${r:-0})); panon=$((panon + ${a:-0}))
        done
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "${cur:-NA}" "${anon:-NA}" "${peak:-NA}" "$rss" "$panon" >> "$SAMPLES"
    fi
    sleep 1
done
wait "$BENCH"; rc=$?
date -Is >> "$LOG"
echo "lane-end: load=$(cut -d' ' -f1-3 /proc/loadavg) cargo_rustc=$(ps -C cargo,rustc -o pid= 2>/dev/null | wc -l) otherload=$(ps -C otherload -o pid= 2>/dev/null | wc -l)" >> "$LOG"
echo "bench-exit: $rc" >> "$LOG"
# Preserve the rendered config + runtime manifest once per side.
if [ ! -f "$SCRATCH/config_${SIDE}.toml" ]; then
    cp /tmp/bgperf2/rustbgpd/config.toml "$SCRATCH/config_${SIDE}.toml" 2>/dev/null
    cp /tmp/bgperf2/runtime-manifest.json "$SCRATCH/runtime-manifest_${SIDE}.json" 2>/dev/null
fi
exit "$rc"
