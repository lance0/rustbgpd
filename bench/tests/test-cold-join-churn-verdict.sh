#!/usr/bin/env bash
# Grade synthetic cold-join-churn timelines: a clean campaign passes, and each
# missed bar or broken run changes that arm's verdict.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
driver="$repo/bench/scale/compare-cold-join-churn.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/cold-join-churn-verdict.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# timeline FILE: 8 passing controls, then 12 passing timed runs per arm.
timeline() {
    local arm cell profile n=0 fallback
    for arm in parent cand; do for cell in clean mixed burst budget-control; do
        echo "T end ctl-$arm-$cell rc=0 compiler_samples=0 mode=$cell fallback=0 worst_wait_us=1 load=1"
    done; done
    for profile in plain policy; do for cell in clean mixed burst; do for arm in parent cand cand parent; do
        n=$((n + 1)); fallback=0; [[ $cell != burst ]] || fallback=1
        printf 'T end %02d-%s-%s-%s rc=0 compiler_samples=0 mode=%s fallback=%d cause=none worst_wait_us=1500 load=1\n' \
            "$n" "$arm" "$profile" "$cell" "$cell" "$fallback"
    done; done; done
}

# expect NAME SED_EXPRESSION PARENT_VERDICT CANDIDATE_VERDICT
expect() {
    timeline | sed -e "$2" > "$tmp/$1"
    [[ -z $2 ]] || ! timeline | cmp -s - "$tmp/$1" || fail "$1: the edit matched no line"
    local got
    got=$(bash "$driver" --verdict "$tmp/$1" | awk '{print $2, $3}' | sort | tr '\n' ' ')
    [[ $got == "arm=cand $4 arm=parent $3 " ]] || fail "$1: got '$got'"
}

expect pass '' PASS PASS
expect mixed-fallback '/ 08-parent-plain-mixed /s/fallback=0/fallback=1 cause=release_fanout/' FAIL PASS
expect slow-clean '/ 02-cand-plain-clean /s/worst_wait_us=1500/worst_wait_us=200001/' PASS FAIL
expect bar-edge '/ 02-cand-plain-clean /s/worst_wait_us=1500/worst_wait_us=200000/' PASS PASS
expect burst-wait-report-only '/ 10-cand-plain-burst /s/worst_wait_us=1500/worst_wait_us=1300000/' PASS PASS
expect clean-fallback '/ 13-parent-policy-clean /s/fallback=0/fallback=1/' FAIL PASS
expect burst-missed '/ 11-cand-plain-burst /s/fallback=1/fallback=0/' PASS INVALID
expect run-failed '/ 05-parent-plain-mixed /s/rc=0/rc=1/' INVALID PASS
expect compiler '/ 06-cand-plain-mixed /s/compiler_samples=0/compiler_samples=3/' PASS INVALID
expect missing-summary '/ 03-cand-plain-clean /s/worst_wait_us=1500//' PASS INVALID
expect missing-run '/ 24-parent-policy-burst /d' INVALID PASS
expect control-failed '/ ctl-cand-burst /s/rc=0/rc=1/' INVALID INVALID
expect control-missing '/ ctl-parent-budget-control /d' INVALID INVALID
expect control-duplicated '/ ctl-cand-mixed /p' INVALID INVALID
expect control-compiler '/ ctl-parent-clean /s/compiler_samples=0/compiler_samples=2/' INVALID INVALID
expect controls-skipped '/ ctl-/d' INVALID INVALID
expect run-duplicated '/ 07-cand-plain-mixed /p' PASS INVALID
expect run-misnumbered '/ 12-parent-plain-burst /s/12-parent/13-parent/' INVALID INVALID
echo "cold-join-churn verdict: all cases passed"
