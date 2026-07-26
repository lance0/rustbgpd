#!/bin/bash
# Serialized bgperf2 phase runner: quiet-gate -> clean -> bounded run.
# Usage: run-phase.sh <label> <config.yaml> <logfile> <timeout_secs>
SCRATCH=<scratch>
LABEL="$1"; CONFIG="$2"; LOG="$3"; TMO="${4:-5400}"

"$SCRATCH/meta/quiet-gate.sh" "$LABEL" 2>&1 | grep -v "hold-lock present" | tail -5

# orphan cleanup - containers share names between runs
docker rm -f $(docker ps -aq --filter "name=bgperf") >/dev/null 2>&1
docker network rm bgperf2-br >/dev/null 2>&1

{
  echo "=== $LABEL start $(date -u +%H:%M:%S) load=$(cut -d' ' -f1-3 /proc/loadavg) ==="
} > "$LOG"

cd <bgperf2> || exit 1
RUSTBGPD_SOURCE="$SCRATCH/src" timeout "$TMO" \
  <bgperf2>/.venv/bin/python bgperf2.py batch -c "$CONFIG" >> "$LOG" 2>&1
rc=$?
echo "=== ${LABEL}_EXIT=$rc $(date -u +%H:%M:%S) ===" >> "$LOG"

docker rm -f $(docker ps -aq --filter "name=bgperf") >/dev/null 2>&1
docker network rm bgperf2-br >/dev/null 2>&1
echo "$LABEL finished rc=$rc"
