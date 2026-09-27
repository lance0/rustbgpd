#!/usr/bin/env bash
# Flapstorm failover cell: FLAPSTORM members drop at once while PERCENT% of
# each one's prefixes fail over to alternates from SOURCES other members
# (gen-failover-overlap.py). One daemon run, three harness flap rounds.
#
# Usage: failover_cell.sh <rustbgpd binary> <out dir> <percent> <sources>
# Knobs (env): N_PEERS=700 TOTAL_PREFIXES=400400 PORT=1790 FLAPSTORM=50
#              CONTROL_SECS=30 CORES=12-32,34-39 (daemon and harness share
#              them; taskset list syntax)
#
# Per round the harness prints `flapstorm_failover_csv`: daemon CPU-seconds
# between the close and the last survivor's completion, the
# `distribute_flush` actor-work sum/count over that window, and survivor
# completion p50/max. A daemon built with `rustbgpd-rib/bench-internals`
# also logs one `bench: grouped mixed pass fanout paths` line per mixed
# pass (members on the shared payload vs the per-member walk); the summary
# totals them as `mixed_passes shared_members per_member_walks`.
set -u

[ "$#" -eq 4 ] || { sed -n '2,8p' "$0" >&2; exit 2; }
DAEMON=$(realpath "$1") OUT=$2 PERCENT=$3 SOURCES=$4
N_PEERS="${N_PEERS:-700}"
TOTAL="${TOTAL_PREFIXES:-400400}"
PORT="${PORT:-1790}"
FLAPSTORM="${FLAPSTORM:-50}"
CONTROL_SECS="${CONTROL_SECS:-30}"
CORES="${CORES:-12-32,34-39}"
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="$HERE/../target/release/reloadstall"
[ -x "$DAEMON" ] || { echo "missing daemon binary $DAEMON" >&2; exit 2; }
[ -x "$HARNESS" ] || { echo "missing $HARNESS (cargo build --release -p reloadstall)" >&2; exit 2; }

# Short run dir: the scenario's gRPC UDS path must fit SUN_LEN.
RUN=/tmp/fo-cell
rm -rf "$RUN"
mkdir -p "$RUN" "$OUT" || exit 1
chmod 700 "$RUN" || exit 1
python3 "$HERE/gen-scenario.py" "$N_PEERS" "$RUN" "$PORT" >/dev/null || exit 1
python3 "$HERE/gen-failover-overlap.py" "$N_PEERS" "$TOTAL" "$FLAPSTORM" \
    "$PERCENT" "$SOURCES" "$RUN/overlap.tsv" || exit 1

# The harness's fixed flap round count (FLAP_ROUNDS in src/main.rs).
ROUNDS=3
daemon_pid="" harness_pid="" daemon_rc=""

# Idempotent: signal the daemon by its exact PID, wait up to 60 s, then
# SIGKILL, and reap it once. Sets daemon_rc on the first call only.
stop_daemon() {
    [ -n "$daemon_pid" ] || return 0
    kill "$daemon_pid" 2>/dev/null
    for _ in $(seq 600); do
        kill -0 "$daemon_pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL "$daemon_pid" 2>/dev/null
    wait "$daemon_pid"
    daemon_rc=$?
    daemon_pid=""
}
interrupted() {
    [ -z "$harness_pid" ] || kill "$harness_pid" 2>/dev/null
    stop_daemon
    echo "cell interrupted; daemon stopped (rc=$daemon_rc)" >&2
    exit 130
}
trap interrupted INT TERM
trap stop_daemon EXIT

taskset -c "$CORES" "$DAEMON" "$RUN/config.toml" >"$OUT/daemon.log" 2>&1 &
daemon_pid=$!
sleep 3
if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "daemon died at start (see $OUT/daemon.log)" >&2
    exit 1
fi

RELOADSTALL_OVERLAP_FILE="$RUN/overlap.tsv" \
    RELOADSTALL_FAILOVER_METRICS_ADDR=127.0.0.1:9179 \
    taskset -c "$CORES" "$HARNESS" "$N_PEERS" "$TOTAL" "$PORT" "$daemon_pid" \
    "$RUN/member.rpol" "$RUN/gen-a.rpol" "$RUN/gen-b.rpol" 0 "$CONTROL_SECS" \
    --flapstorm "$FLAPSTORM" >"$OUT/reloadstall.log" 2>&1 &
# A background harness keeps `wait` interruptible, so the INT/TERM trap runs
# promptly instead of after the harness exits on its own.
harness_pid=$!
wait "$harness_pid"
harness_rc=$?
harness_pid=""

stop_daemon
cp "$RUN/overlap.tsv" "$OUT/overlap.tsv" || exit 1

# The cell passes only when the harness, the daemon's shutdown and this
# summary all succeed; a malformed log or missing row fails it.
summary_rc=0
python3 - "$OUT" "$ROUNDS" <<'PY' || summary_rc=$?
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
passes = shared = walks = 0
for line in (out / "daemon.log").read_text(errors="replace").splitlines():
    if "bench: grouped mixed pass fanout paths" not in line:
        continue
    fields = json.loads(line).get("fields", {})
    passes += 1
    shared += int(fields["shared_members"])
    walks += int(fields["per_member_walks"])
lines = (out / "reloadstall.log").read_text().splitlines()
rows = [line for line in lines if line.startswith("flapstorm_failover_csv,")]
rounds = [int(row.split(",")[1]) for row in rows]
if rounds != list(range(1, int(sys.argv[2]) + 1)):
    sys.exit(f"flapstorm_failover_csv rounds {rounds}, want 1..{sys.argv[2]}")
print("\n".join(line for line in lines if line.startswith("flapstorm_failover_csv")))
print(f"mixed_passes={passes} shared_members={shared} per_member_walks={walks}")
PY
echo "harness_rc=$harness_rc daemon_rc=$daemon_rc summary_rc=$summary_rc"
[ "$harness_rc" -eq 0 ] && [ "$daemon_rc" -eq 0 ] && [ "$summary_rc" -eq 0 ]
