#!/usr/bin/env bash
# Usage: run.sh 200 NEW_OUTPUT BUILD_RECEIPT
#        run.sh 700 NEW_OUTPUT BUILD_RECEIPT PASSED_200_OUTPUT
# This wrapper never builds. See README.md for the required build receipt.
set -euo pipefail
umask 022
ulimit -n 65536
repo=/tmp/readiness-source
prep=/tmp/readiness-acceptance-prep
[[ $# == 3 || $# == 4 ]] || { echo 'see run.sh usage' >&2; exit 2; }
peers=$1
out=$2
build=$3
case "$peers:$#" in
    200:3) total=114400; changed=170; ipv4=57200 ;;
    700:4) total=400400; changed=600; ipv4=200200 ;;
    *) echo 'expected 200 with three args or 700 with four args' >&2; exit 2 ;;
esac
[[ $out == /* && $build == /* && ! -e $out && ! -L $out ]]
[[ $out != "$build"/* ]] || { echo 'output must be outside the build receipt' >&2; exit 2; }
cd "$repo"
for binary in target/release/rustbgpd target/release/rbgp bench/scale/target/release/reloadstall; do
    [[ -x $binary ]] || { echo "missing candidate binary: $repo/$binary" >&2; exit 1; }
done
for component in daemon harness; do
    [[ $(cat "$build/$component.exit") == 0 && -s $build/$component.log ]]
done
[[ -s $build/commands.txt ]]
cmp "$build/before/source.json" "$build/after/source.json"
cmp "$build/before/git-head" "$build/after/git-head"
python3 - "$build/binaries.sha256" <<'PY'
from pathlib import Path
import re
import sys
expected = {'target/release/rustbgpd', 'target/release/rbgp',
            'bench/scale/target/release/reloadstall'}
rows = Path(sys.argv[1]).read_text().splitlines()
matches = [re.fullmatch(r'[0-9a-f]{64}  (.+)', row) for row in rows]
assert len(matches) == 3 and all(matches), 'expected three binary SHA-256 records'
assert {match[1] for match in matches} == expected, 'unexpected binary paths'
PY
sha256sum -c "$build/binaries.sha256"
if [[ $peers == 700 ]]; then
    previous=$4
    [[ $previous == /* ]]
    [[ $(cat "$previous/peers") == 200 ]]
    for exit_file in driver.exit gate.exit provenance.exit; do
        [[ $(cat "$previous/$exit_file") == 0 ]]
    done
    cmp "$previous/binaries.sha256" "$build/binaries.sha256"
    cmp "$previous/source-before/source.json" "$build/after/source.json"
    cmp "$previous/source-before/git-head" "$build/after/git-head"
fi
mkdir "$out"  # Atomic rejection if another process created it after the check.
cp "$prep/gate.py" "$prep/run.sh" "$prep/snapshot.py" "$out/"
cp -r "$build" "$out/build-receipt"
cp "$build/binaries.sha256" "$out/"
printf '%s\n' "$peers" >"$out/peers"
if [[ $peers == 700 ]]; then printf '%s\n' "$previous" >"$out/previous-200"; fi
python3 "$out/snapshot.py" "$out/source-before"
cmp "$out/source-before/source.json" "$build/after/source.json"
cmp "$out/source-before/git-head" "$build/after/git-head"
sha256sum -c "$out/binaries.sha256" >"$out/binary-check-before.log"
date -u +%FT%TZ >"$out/started-at"
rc=0
env -i PATH="$PATH" HOME="$HOME" \
    N_PEERS="$peers" TOTAL_PREFIXES="$total" CHANGED_PEERS="$changed" \
    PORT=1790 RELOADS=4 CONTROL_SECS=30 \
    GEN_DUALSTACK=1 RELOADSTALL_DUALSTACK=1 \
    RELOADSTALL_IPV4_PREFIXES="$ipv4" \
    GEN_FILTER_COUNT=32 RELOADSTALL_FILTER_COUNT=32 \
    RELOADSTALL_CYCLE_QUIESCE_SECS=20 \
    PROBE_PREFIXES='20.0.0.0/24 3001::/48' ARTIFACTS_DIR="$out" \
    timeout --signal=TERM --kill-after=30s 900s \
    bash bench/scale/matrix/run-matrix.sh rustbgpd \
    >"$out/driver.log" 2>&1 || rc=$?
printf '%s\n' "$rc" >"$out/driver.exit"
date -u +%FT%TZ >"$out/finished-at"
# Always retain the raw gate result even if the post-run identity check fails.
gate_rc=0
python3 "$out/gate.py" "$out" "$peers" "$total" "$ipv4" "$changed" 32 \
    >"$out/evidence.json" 2>"$out/gate.stderr.log" || gate_rc=$?
printf '%s\n' "$gate_rc" >"$out/gate.exit"
provenance_rc=0
sha256sum -c "$out/binaries.sha256" >"$out/binary-check-after.log" 2>&1 || provenance_rc=1
python3 "$out/snapshot.py" "$out/source-after" >"$out/source-check-after.log" 2>&1 || provenance_rc=1
for identity in source.json git-head; do
    cmp "$out/source-before/$identity" "$out/source-after/$identity" \
        >>"$out/source-check-after.log" 2>&1 || provenance_rc=1
done
printf '%s\n' "$provenance_rc" >"$out/provenance.exit"
[[ $rc == 0 && $gate_rc == 0 && $provenance_rc == 0 ]]
