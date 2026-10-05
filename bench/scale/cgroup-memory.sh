#!/usr/bin/env bash
# Cgroup v2 readouts shared by the native and container scale recipes.

# Native daemon memory scope: a transient systemd user scope with swap fenced,
# so the scope's memory.peak (cg_peak) covers every page the daemon charged;
# RSS and VmHWM miss swapped pages and kernel-side charges. Callers may keep
# an RSS/VmHWM-only receipt when no usable user manager is available.
MEMORY_SCOPE=()
memory_scope_launcher() {
    local out=$1
    rm -f "$out"
    MEMORY_SCOPE=(systemd-run --user --scope --quiet -p MemorySwapMax=0 --)
    # shellcheck disable=SC2016 # Expanded by the scoped shell, not here.
    if "${MEMORY_SCOPE[@]}" sh -c 'cg=/sys/fs/cgroup$(sed -n "s/^0:://p" /proc/self/cgroup)
        test -r "$cg/memory.peak" && test "$(cat "$cg/memory.swap.max")" = 0' >/dev/null 2>&1; then
        return 0
    fi
    MEMORY_SCOPE=()
    echo "WARNING: no systemd user scope with a readable memory.peak and memory.swap.max=0; cg_peak will be absent" >&2
    echo "cg_scope: unavailable" >"$out"
}
# Print the daemon's scope cgroup directory once its fence is confirmed.
daemon_scope_cgroup() {
    local cgroup
    cgroup=/sys/fs/cgroup$(sed -n 's/^0:://p' "/proc/$1/cgroup") || return 1
    case $cgroup in *.scope) ;; *) return 1 ;; esac
    [ -r "$cgroup/memory.peak" ] && [ "$(cat "$cgroup/memory.swap.max")" = 0 ] &&
        printf '%s\n' "$cgroup"
}
# The IRR window ends at harness completion, before lifecycle probes.
# Preserve the actual swap peak as well as the configured swap fence.
record_scope_peak() {
    local cgroup=$1 out=$2 peak current swap_max swap_peak
    peak=$(cat "$cgroup/memory.peak") && current=$(cat "$cgroup/memory.current") &&
        swap_max=$(cat "$cgroup/memory.swap.max") &&
        swap_peak=$(cat "$cgroup/memory.swap.peak") || return 1
    [[ $peak =~ ^[0-9]+$ && $current =~ ^[0-9]+$ && $swap_peak =~ ^[0-9]+$ ]] &&
        [ "$swap_max" = 0 ] || return 1
    printf 'cg_peak: %s kB\ncg_current: %s kB\ncg_swap_max: %s\ncg_swap_peak: %s kB\n' \
        $((peak / 1024)) $((current / 1024)) "$swap_max" \
        $(((swap_peak + 1023) / 1024)) >"$out"
}

# A competitor's high-water mark: its container cgroup's memory.peak, read
# before the container is removed. memory.swap.peak is recorded with it: when
# it is 0, none of the container's pages were swapped out during the cell, so
# memory.peak counts every page the container charged. If either file cannot
# be read, the cell records `container_cg: unavailable` and still passes.
record_container_memory() {
    local cgroup=$1 out=$2 peak swap_peak
    if [ -n "$cgroup" ] && peak=$(cat "$cgroup/memory.peak" 2>/dev/null) &&
        swap_peak=$(cat "$cgroup/memory.swap.peak" 2>/dev/null) &&
        [[ $peak =~ ^[0-9]+$ && $swap_peak =~ ^[0-9]+$ ]]; then
        printf 'container_cg_peak: %s kB\ncontainer_cg_swap_peak: %s kB\n' \
            $((peak / 1024)) $(((swap_peak + 1023) / 1024)) >"$out"
    else
        echo "WARNING: no readable container memory.peak/memory.swap.peak${cgroup:+ under $cgroup}; container_cg_peak will be absent" >&2
        echo "container_cg: unavailable" >"$out"
    fi
}
