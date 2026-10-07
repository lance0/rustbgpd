#!/usr/bin/env bash
# Runs inside a transient delegated user scope (MemorySwapMax=0). Splits the
# scope into runner/ and daemon/ leaf cgroups, moves the measured daemon (not
# its --check invocation) into daemon/ as soon as it appears, samples both, and
# runs the merged runner unchanged. Env: CGOUT, LABEL plus runner inputs.
set -u
CG=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
mkdir -p "$CGOUT"
mkdir "$CG/runner" "$CG/daemon"
echo $$ >"$CG/runner/cgroup.procs"
echo +memory >"$CG/cgroup.subtree_control"
echo 0 >"$CG/daemon/memory.swap.max"
{ echo "scope=$CG"; for f in memory.swap.max memory.max; do
    echo "scope_$f=$(cat "$CG/$f")"; echo "daemon_$f=$(cat "$CG/daemon/$f")"; done; } >"$CGOUT/cgroup-setup.env"

watcher() {
    local dpid='' p comm cmd now last=0 anon file cur
    printf 'monotonic_seconds\tdaemon_current\tdaemon_anon\tdaemon_file\trunner_current\tscope_current\n' >"$CGOUT/cgroup.tsv"
    while :; do
        if [[ -z $dpid ]]; then
            while read -r p; do
                read -r comm <"/proc/$p/comm" 2>/dev/null || continue
                [[ $comm == rustbgpd ]] || continue
                cmd=$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null) || continue
                [[ $cmd == *--check* ]] && continue
                if echo "$p" >"$CG/daemon/cgroup.procs"; then
                    dpid=$p
                    { echo "daemon_pid=$p"; echo "daemon_cmdline=$cmd"
                      echo "moved_monotonic=$(cut -d' ' -f1 /proc/uptime)"
                      grep -E '^(VmRSS|RssAnon|Threads)' "/proc/$p/status" | sed 's/:\s*/_at_move=/'
                      echo "runner_current_at_move=$(cat "$CG/runner/memory.current")"; } >"$CGOUT/daemon-move.env"
                fi
            done <"$CG/runner/cgroup.procs"
        fi
        read -r now _ </proc/uptime
        if [[ ${now%.*} != "$last" ]]; then
            last=${now%.*}
            read -r cur <"$CG/daemon/memory.current"
            anon=$(awk '$1=="anon"{print $2}' "$CG/daemon/memory.stat")
            file=$(awk '$1=="file"{print $2}' "$CG/daemon/memory.stat")
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$now" "$cur" "$anon" "$file" \
                "$(cat "$CG/runner/memory.current")" "$(cat "$CG/memory.current")" >>"$CGOUT/cgroup.tsv"
            [[ -n $dpid && -d /proc/$dpid ]] && cat "$CG/daemon/memory.stat" >"$CGOUT/daemon-memory.stat.last-alive"
            ps -eo comm= | awk '$1=="cargo"||$1=="rustc"||$1=="perf"||$1~/^rrharness/||$1~/^bgperf/{print $1}' \
                | sort -u | paste -sd, - | sed "s/^/$now\t/" | grep -v "	$" >>"$CGOUT/foreign-competitors.tsv" || true
        fi
        sleep 0.01
    done
}
watcher &
WPID=$!
bash "$REPO/docs/perf/run-explain-cache-variant.sh" >"$CGOUT/runner.log" 2>&1
rc=$?
kill "$WPID"; wait "$WPID" 2>/dev/null
{
    echo "runner_rc=$rc"
    for g in daemon runner; do
        echo "${g}_memory_peak_bytes=$(cat "$CG/$g/memory.peak")"
        echo "${g}_swap_peak_bytes=$(cat "$CG/$g/memory.swap.peak")"
        awk -v g="$g" '{print g "_events_" $1 "=" $2}' "$CG/$g/memory.events"
    done
    echo "scope_memory_peak_bytes=$(cat "$CG/memory.peak")"
    echo "scope_swap_peak_bytes=$(cat "$CG/memory.swap.peak")"
    echo "daemon_procs_remaining=$(wc -l <"$CG/daemon/cgroup.procs")"
} >"$CGOUT/cgroup-final.env"
exit "$rc"
