#!/usr/bin/env bash
# IXP-matrix RSS sampler (LAN-334): every <interval_s> seconds, sum resident
# memory across the process TREE rooted at <root_pid> into a CSV. OpenBGPD is
# three processes (parent + RDE + SE), so a single-pid readout undercounts.
#
# Usage: rss-sampler.sh <root_pid> <out_csv> [interval_s=5]
#
# Prefers /proc/<pid>/smaps_rollup (precise Rss). That file is 0400, so for
# processes owned by another user (daemons inside containers run as root in
# the host pid namespace) it falls back to VmRSS from /proc/<pid>/status,
# which is world-readable. Runs until the root process exits.
set -u

root=${1:?usage: rss-sampler.sh <root_pid> <out_csv> [interval_s]}
out=${2:?usage: rss-sampler.sh <root_pid> <out_csv> [interval_s]}
interval=${3:-5}

# Walk the tree via /proc/<pid>/task/*/children (works without ps/pgrep and
# without permission on the target processes).
tree() {
    echo "$1"
    local k
    for k in $(cat /proc/"$1"/task/*/children 2>/dev/null); do
        tree "$k"
    done
}

echo "epoch_s,total_rss_kib,pids" >"$out"
# ponytail: liveness via /proc existence, not `kill -0` — kill -0 reports
# EPERM (failure) for other users' live processes, e.g. container daemons.
while [ -d "/proc/$root" ]; do
    total=0
    n=0
    for p in $(tree "$root"); do
        kib=$(awk '/^Rss:/ {s += $2} END {print s + 0}' \
            "/proc/$p/smaps_rollup" 2>/dev/null)
        if [ -z "${kib:-}" ] || [ "$kib" -eq 0 ]; then
            kib=$(awk '/^VmRSS:/ {print $2; exit}' "/proc/$p/status" 2>/dev/null)
        fi
        if [ -n "${kib:-}" ]; then
            total=$((total + kib))
            n=$((n + 1))
        fi
    done
    echo "$(date +%s),$total,$n" >>"$out"
    sleep "$interval"
done
