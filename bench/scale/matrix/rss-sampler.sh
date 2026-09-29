#!/usr/bin/env bash
# IXP-matrix RSS sampler (LAN-334): every <interval_s> seconds, sum resident
# memory across the process TREE rooted at <root_pid> into a CSV. OpenBGPD is
# three processes (parent + RDE + SE), so a single-pid readout undercounts.
#
# Usage: rss-sampler.sh <root_pid> <out_csv> [interval_s=5] [cgroup_dir]
#
# With a cgroup_dir, each row also carries memory.current and memory.stat
# anon/file/file_mapped charges (blank when a read races teardown).
#
# Prefers /proc/<pid>/smaps_rollup (precise Rss). That file is 0400, so for
# processes owned by another user (daemons inside containers run as root in
# the host pid namespace) it falls back to VmRSS from /proc/<pid>/status,
# which is world-readable. Runs until the root process exits.
set -u

root=${1:?usage: rss-sampler.sh <root_pid> <out_csv> [interval_s]}
out=${2:?usage: rss-sampler.sh <root_pid> <out_csv> [interval_s]}
interval=${3:-5}
cgroup=${4:-}

# Walk the tree via /proc/<pid>/task/*/children (works without ps/pgrep and
# without permission on the target processes).
tree() {
    echo "$1"
    local k
    # shellcheck disable=SC2013 # /proc children is a whitespace-delimited PID list.
    for k in $(cat /proc/"$1"/task/*/children 2>/dev/null); do
        tree "$k"
    done
}

if [ -n "$cgroup" ]; then
    echo "epoch_s,total_rss_kib,pids,cg_current_kib,cg_anon_kib,cg_file_kib,cg_file_mapped_kib" >"$out"
else
    echo "epoch_s,total_rss_kib,pids" >"$out"
fi
stat_sample() {
    awk '$1 == "anon" || $1 == "file" || $1 == "file_mapped" {
        if (NF != 2 || $2 !~ /^[0-9]+$/ || seen[$1]++) exit 1
        value[$1] = $2
        count++
    } END {
        if (count != 3) exit 1
        printf "%d,%d,%d", value["anon"] / 1024, value["file"] / 1024, value["file_mapped"] / 1024
    }' "$cgroup/memory.stat"
}
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
    # The root can exit after the loop's /proc liveness check but before its
    # status is read. Do not turn that teardown race into a bogus zero sample.
    if [ "$n" -eq 0 ] || [ "$total" -eq 0 ]; then
        sleep "$interval"
        continue
    fi
    if [ -n "$cgroup" ]; then
        cg_bytes=$(cat "$cgroup/memory.current" 2>/dev/null) || cg_bytes=
        cg_stat=
        if [ -n "$cg_bytes" ]; then
            cg_stat=$(stat_sample) || exit 1
        fi
        echo "$(date +%s),$total,$n,${cg_bytes:+$((cg_bytes / 1024))},${cg_stat:-,,}" >>"$out"
    else
        echo "$(date +%s),$total,$n" >>"$out"
    fi
    sleep "$interval"
done
