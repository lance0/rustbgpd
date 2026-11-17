#!/usr/bin/env bash
# Run every outbound-credit cell of one arm with one rrtransport binary.
#
#   run-credit-cells.sh [--correctness-only] [--reduced] BINARY OUTPUT_DIR [CELL...]
#
# CELL is any of: probes exhaust-unicast exhaust-evpn paused fill-unicast
# fill-evpn fill-vpn fill-flowspec (default: all, in that order). Each cell
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
# directory.
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
    sed -n '2,15p' "$0" >&2
    exit 2
}
binary=$(realpath "$1")
output=$2
shift 2
cells=("$@")
[ ${#cells[@]} -gt 0 ] || cells=(probes exhaust-unicast exhaust-evpn paused
    fill-unicast fill-evpn fill-vpn fill-flowspec)
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
    probes) echo probes.json ;;
    paused) echo paused-evpn.json ;;
    exhaust-unicast | exhaust-evpn | fill-unicast | fill-evpn | fill-vpn | fill-flowspec) echo "$1.json" ;;
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
    probes) args=(credit-probe "$output") limit=64G ;;
    exhaust-*) args=(credit-exhaust "${cell#exhaust-}" "$output") limit=64G ;;
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
