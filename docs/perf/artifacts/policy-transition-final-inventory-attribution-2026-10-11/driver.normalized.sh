#!/usr/bin/env bash
# PREPARED ONLY. Root releases build and timing stages separately.
set -euo pipefail
PREP=<PREPARATION>
OUT=<ARTIFACTS>
INSTRUMENT_REPO=<RUNNER>
ENGINE=<ENGINE_DIRECTORY>/reloadstall
CELL=$INSTRUMENT_REPO/bench/scale/reloadstall/policy_stats_cell.sh
CACHE=<CACHE>
PARENT=6ee2a052607b34a11e8daa2f4a4d4639b5101690
CHILD=aceacb435677291fdb20c2e792f58cb9e4575b74
stage=${1:-}
case "$stage" in build|abba) ;; *) echo 'usage: driver.sh build|abba' >&2; exit 2;; esac
mkdir -p "$OUT/logs" "$OUT/binaries"
[[ ! -e $OUT/logs/$stage.log && ! -e $OUT/logs/$stage.exit ]]
exec >"$OUT/logs/$stage.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$OUT/logs/$stage.exit"' EXIT
cp "$PREP/driver.sh" "$OUT/$stage-driver-as-run.sh"


if [[ $stage == build ]]; then
    cp "$PREP/manifest.json" "$OUT/build-preparation-manifest.json"
    for arm in baseline candidate; do
        tree=<SOURCE_BASELINE>
        expected=$PARENT
        if [[ $arm == candidate ]]; then
            tree=<SOURCE_CANDIDATE>
            expected=$CHILD
        fi
        # Reuse the qualified normal two-package builder and actual closure
        # capture; each arm holds canonical then light then warm-cache build locks.
        bash "$PREP/build-arm.sh" "$arm" "$tree" "$expected" "$CACHE" "$OUT"
    done
    python3 "$PREP/compare-arms.py" "$OUT" >"$OUT/logs/actual-features-build.log" 2>&1
    # Both daemon+CLI builds remain immutable. The cell's rbgp is the ONE
    # baseline CLI for both arms; separate symlink views preserve originals.
    for arm in baseline candidate; do
        mkdir -p "$OUT/cell-binaries/$arm"
        ln -s "$OUT/binaries/$arm/rustbgpd" "$OUT/cell-binaries/$arm/rustbgpd"
        ln -s "$OUT/binaries/baseline/rbgp" "$OUT/cell-binaries/$arm/rbgp"
        (cd "$OUT/cell-binaries/$arm" && sha256sum rustbgpd rbgp >SHA256SUMS)
    done
    exit 0
fi

# Canonical then light is the shared host-wide order; never invert it.
printf '%s waiting for canonical lock\n' "$(date -u +%FT%TZ)"
exec {RUSTBGPD_HOST_LOCK_FD}><LOCK_DIRECTORY>/rustbgpd-host.lock
flock "$RUSTBGPD_HOST_LOCK_FD"
printf '%s canonical acquired; waiting for light lock\n' "$(date -u +%FT%TZ)"
exec {RUSTBGPD_LIGHT_LOCK_FD}><LOCK_DIRECTORY>/rustbgpd-light.lock
flock "$RUSTBGPD_LIGHT_LOCK_FD"
export RUSTBGPD_HOST_LOCK_FD RUSTBGPD_LIGHT_LOCK_FD
printf '%s both locks acquired; checking admission\n' "$(date -u +%FT%TZ)"
ADMISSION=$OUT/logs/abba-admission
mkdir "$ADMISSION"
free -h >"$ADMISSION/free.txt"
df -h "$CACHE" "$ADMISSION" >"$ADMISSION/disk.txt"
ps -eo pid,ppid,comm,args >"$ADMISSION/processes.txt"
docker ps --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}' >"$ADMISSION/containers.txt"
nvidia-smi >"$ADMISSION/gpu.txt"
# Inventory competitors before admission; native quiet gates remain separate.
source "$INSTRUMENT_REPO/bench/scale/host-quiet.sh"
competitors=$(rustbgpd_host_quiet_competitors)
clippy_competitors=$(pgrep -x clippy-driver || true)
[[ -z $clippy_competitors ]] || { printf 'competing clippy processes: %s\n' "$clippy_competitors"; exit 75; }
printf '%s\n' "$competitors" >"$ADMISSION/competitors.txt"
[[ -z $competitors ]] || { printf 'competing processes: %s\n' "$competitors"; exit 75; }
if rg -i 'clab-|rustbgpd|gobgp|gobgpd|frrouting|(^| )bird([ :-]|$)' "$ADMISSION/containers.txt"; then exit 75; fi
python3 - "$CACHE" "$CACHE" "$ADMISSION" <<'PY_RESOURCES'
from pathlib import Path
import shutil
import sys
meminfo=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
available=int(meminfo['MemAvailable'].split()[0])*1024
free=[shutil.disk_usage(path).free for path in sys.argv[1:3]]
Path(sys.argv[3], 'resource-bytes.txt').write_text(f'memory_available={available}\ncache_free={free}\n')
assert available >= 32*1024**3, 'less than32GiB available memory'
assert min(free) >= 20*1024**3, 'less than20GiB cache filesystem free'
PY_RESOURCES

# Hash the frozen engine only after both host locks and admission checks.
sha256sum -c "$PREP/instruments.sha256"
[[ $(git -C "$INSTRUMENT_REPO" rev-parse HEAD) == 591ac39d4b50fc2c647942713a9ea99c0588a51a ]]

[[ $(cat "$OUT/logs/build.exit") == 0 ]]
python3 "$PREP/compare-arms.py" "$OUT" >"$OUT/logs/actual-features-preflight.log" 2>&1
for arm in baseline candidate; do
    [[ $(cat "$OUT/binaries/$arm/build-stage.exit") == 0 && $(cat "$OUT/binaries/$arm/cargo-build.exit") == 0 ]]
    (cd "$OUT/binaries/$arm" && sha256sum -c SHA256SUMS)
    (cd "$OUT/cell-binaries/$arm" && sha256sum -c SHA256SUMS)
done
# shellcheck source=/dev/null
source "$INSTRUMENT_REPO/bench/scale/host-quiet.sh"
export RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=600
date -Is >"$OUT/window-start"
# First default-shape A/B legs are also the execution-compatibility proof.
for leg in baseline-r1 candidate-r1 candidate-r2 baseline-r2; do
    [[ ! -e $OUT/$leg && ! -e $OUT/$leg.exit ]]
    wait_for_rustbgpd_quiet_host "$OUT/$leg.quiet.tsv"
    date -Is >"$OUT/$leg.started"
    rc=0
    env PEERS=1000 PREFIXES=400000 RELOADS=8 CONTROL_SECS=15 QUIESCE_SECS=40 \
        DAEMON_CPUS=2-3 ENGINE_CPUS=4-5 PROBE_CPUS=8-15 PAIR_LEAD=0.110 QUIESCENT_OFFSET=20 \
        bash "$CELL" "$OUT/cell-binaries/${leg%-r?}" "$ENGINE" "$OUT/$leg" \
        >"$OUT/$leg.log" 2>&1 </dev/null || rc=$?
    printf '%s\n' "$rc" >"$OUT/$leg.exit"
    date -Is >"$OUT/$leg.finished"
    ((rc == 0)) || exit "$rc"
    python3 - "$OUT/$leg/summary.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
rows = data['reloads']
if len(rows) != 8 or any(row['rib_transition'].get('outcome') != 'committed'
                         or row['rib_transition'].get('member_count') != 1000 for row in rows):
    raise SystemExit('attribution invalid: expected eight committed 1,000-member transitions')
print('attribution shape: eight committed 1,000-member transitions')
PY
done
sha256sum -c "$PREP/instruments.sha256" >"$OUT/logs/end-instruments.log" 2>&1
for arm in baseline candidate; do
    (cd "$OUT/binaries/$arm" && sha256sum -c SHA256SUMS)
    (cd "$OUT/cell-binaries/$arm" && sha256sum -c SHA256SUMS)
done
date -Is >"$OUT/window-finish"
