#!/usr/bin/env bash
set -euo pipefail
umask 022
ulimit -n 65536
repo=/tmp/policy-noops-source
prep=/tmp/policy-noops-prep
out=/tmp/policy-noops-200-50-F
cd "$repo"
[[ $(git rev-parse HEAD) == 8264351811a80301e747ad217d751942056c0b3c ]]
[[ -z $(git status --porcelain=v1) ]]
[[ ! -e $out ]]
mkdir "$out"
cp "$prep/gate.py" "$prep/run.sh" "$prep/reused-binaries.json" "$out/"
sha256sum target/release/rustbgpd target/release/rbgp \
    bench/scale/target/release/reloadstall >"$out/binaries.sha256"
date -u +%FT%TZ >"$out/started-at"
rc=0
env -i PATH="$PATH" HOME="$HOME" \
    N_PEERS=200 TOTAL_PREFIXES=114400 CHANGED_PEERS=170 \
    PORT=1790 RELOADS=4 CONTROL_SECS=30 \
    GEN_DUALSTACK=1 RELOADSTALL_DUALSTACK=1 \
    RELOADSTALL_IPV4_PREFIXES=57200 \
    GEN_FILTER_COUNT=32 RELOADSTALL_FILTER_COUNT=32 \
    RELOADSTALL_CYCLE_QUIESCE_SECS=20 \
    PROBE_PREFIXES='20.0.0.0/24 3001::/48' ARTIFACTS_DIR="$out" \
    timeout --signal=TERM --kill-after=30s 900s \
    bash bench/scale/matrix/run-matrix.sh rustbgpd \
    >"$out/driver.log" 2>&1 || rc=$?
printf '%s\n' "$rc" >"$out/driver.exit"
date -u +%FT%TZ >"$out/finished-at"
sha256sum -c "$out/binaries.sha256" >"$out/binary-check-after.log"
gate_rc=0
python3 "$out/gate.py" "$out" 200 114400 57200 170 32 \
    >"$out/evidence.json" 2>"$out/gate.stderr.log" || gate_rc=$?
printf '%s\n' "$gate_rc" >"$out/gate.exit"
[[ $rc == 0 && $gate_rc == 0 ]]
