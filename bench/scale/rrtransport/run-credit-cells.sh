#!/usr/bin/env bash
# Run every outbound-credit cell of one arm with one rrtransport binary.
#
#   run-credit-cells.sh [--correctness-only] [--reduced] BINARY OUTPUT_DIR [CELL...]
#
# CELL is any of: probes exhaust-unicast exhaust-evpn paused fill-unicast
# fill-evpn fill-vpn fill-flowspec restart-unicast restart-evpn
# restart-churn-unicast restart-churn-evpn (default: all, in that order; the
# restart cells are the RFC 4724 selection release, alone or with churn
# during its drain, whose cell-7 bars read the candidate only). Each cell
# runs in its own systemd user scope with swap fenced (memory.swap.max=0);
# the paused-reader cell gets the fixed 12 GiB limit its bar names, the
# others a 64 GiB safety limit. The runner holds the shared host lock for
# the whole run. A measured run (the default) also passes the quiet-host
# gate before every cell; --correctness-only skips the gate and marks every
# result unusable for a timing bar. A cell that dies leaves
# `<cell>-exit.json`; a paused-reader cell killed by SIGKILL inside its
# limit is recorded as an OOM. Each invocation appends the binary hash and
# its cell list to `provenance.jsonl`, which tells the analyzer what this
# directory attempted. Use one directory per repetition and one binary per
# directory. restart-labeled4 and restart-labeled6 use the same swap-fenced
# scopes and run only when named. The report-only release cells and the
# source-burst and source-burst-control cells (an unpaced source burst
# through real sessions, and its control without healthy updates) and their
# source-burst-small counterparts (100 routes per UPDATE), run only when
# explicitly named. source-burst-two is the two-writer correctness fixture.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../../.." && pwd)
flags=()
while [ $# -gt 0 ]; do
    case $1 in
    --correctness-only | --reduced) flags+=("$1") && shift ;;
    *) break ;;
    esac
done
[ $# -ge 2 ] || {
    sed -n '2,18p' "$0" >&2
    exit 2
}
binary=$(realpath "$1")
output=$2
shift 2
cells=("$@")
[ ${#cells[@]} -gt 0 ] || cells=(probes exhaust-unicast exhaust-evpn paused
    fill-unicast fill-evpn fill-vpn fill-flowspec restart-unicast restart-evpn
    restart-churn-unicast restart-churn-evpn)
# Either flag makes the run a correctness run.
measured=1
[ ${#flags[@]} -eq 0 ] || measured=0

mkdir -p "$output"
exec > >(tee -a "$output/runner.log") 2>&1
# shellcheck source=tests/soak/host-lock.sh
. "$root/tests/soak/host-lock.sh"
acquire_rustbgpd_host_lock
# shellcheck source=bench/scale/host-quiet.sh
. "$here/../host-quiet.sh"
ulimit -n 65536 2>/dev/null || ulimit -n "$(ulimit -Hn)"

sha=$(sha256sum "$binary" | cut -d' ' -f1)
result_of() {
    case $1 in
    release-mixed | release-timer | release-vpn[46] | release-labeled[46]) echo "$1.json" ;;
    source-burst | source-burst-control) echo "$1.json" ;;
    source-burst-two | source-burst-small | source-burst-small-control) echo "$1.json" ;;
    probes) echo probes.json ;;
    paused) echo paused-evpn.json ;;
    exhaust-unicast | exhaust-evpn | restart-unicast | restart-evpn) echo "$1.json" ;;
    restart-churn-unicast | restart-churn-evpn | restart-labeled[46]) echo "$1.json" ;;
    fill-unicast | fill-evpn | fill-vpn | fill-flowspec) echo "$1.json" ;;
    *) return 1 ;;
    esac
}
for cell in "${cells[@]}"; do
    result_of "$cell" >/dev/null || { echo "unknown cell $cell" >&2 && exit 2; }
done
# A rerun into a used directory must leave no earlier result or exit marker
# for any cell it lists, even when it stops before reaching that cell.
for cell in "${cells[@]}"; do
    rm -f "$output/$(result_of "$cell")" "$output/$cell-exit.json"
done
# One line per invocation: the analyzer treats every cell a line lists as
# attempted in this directory, and requires one binary per directory.
listed=$(printf '"%s",' "${cells[@]}")
printf '{"binary": "%s", "sha256": "%s", "measured": %s, "started": "%s", "cells": [%s]}\n' \
    "$binary" "$sha" "$measured" "$(date -u +%FT%TZ)" "${listed%,}" >>"$output/provenance.jsonl"
echo "rrtransport $sha measured=$measured cells=${cells[*]}"

status=0
for cell in "${cells[@]}"; do
    case $cell in
    release-*) args=("credit-$cell" "$output") limit=64G ;;
    source-burst) args=(credit-source-burst "$output") limit=64G ;;
    source-burst-two) args=(credit-source-burst "$output" --two-sources) limit=64G ;;
    source-burst-control) args=(credit-source-burst "$output" --control) limit=64G ;;
    source-burst-small) args=(credit-source-burst "$output" --routes-per-update 100) limit=64G ;;
    source-burst-small-control)
        args=(credit-source-burst "$output" --control --routes-per-update 100) limit=64G
        ;;
    probes) args=(credit-probe "$output") limit=64G ;;
    exhaust-*) args=(credit-exhaust "${cell#exhaust-}" "$output") limit=64G ;;
    restart-churn-*) args=(credit-restart-churn "${cell#restart-churn-}" "$output") limit=64G ;;
    restart-*) args=(credit-restart "${cell#restart-}" "$output") limit=64G ;;
    paused) args=(credit-paused "$output") limit=12G ;;
    fill-*) args=(credit-fill "${cell#fill-}" "$output") limit=64G ;;
    esac
    if [ $measured = 1 ]; then
        wait_for_rustbgpd_quiet_host "$output/quiet-$cell.tsv"
    fi
    echo "$(date -u +%FT%TZ) start $cell"
    code=0
    systemd-run --user --scope --quiet -p MemoryMax="$limit" -p MemorySwapMax=0 -- \
        "$binary" "${args[@]}" "${flags[@]}" >"$output/$cell.log" 2>&1 || code=$?
    echo "$(date -u +%FT%TZ) end $cell exit=$code"
    if [ $code != 0 ]; then
        status=1
        oom=false
        [ "$cell" != paused ] || [ $code != 137 ] || oom=true
        printf '{"cell": "%s", "exit": %d, "oom": %s}\n' "$cell" "$code" "$oom" \
            >"$output/$cell-exit.json"
    fi
done
exit $status
