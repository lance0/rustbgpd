#!/usr/bin/env bash
set -euo pipefail
umask 022
ulimit -n 65536
prep=/tmp/dualstack-campaign-prep
repo=/tmp/dualstack-source
pin=f2e14e675d096e3fd79d81ece3e7885c6f3855e4
out=${CAMPAIGN_ARTIFACTS:?set a fresh absolute CAMPAIGN_ARTIFACTS directory}
selected=${1:?usage: run.sh CELL (see plan.json)}
[[ $out == /* ]]
[[ $(git -C "$repo" rev-parse HEAD) == "$pin" ]]
[[ -z $(git -C "$repo" status --porcelain=v1) ]]
bins=(target/release/rustbgpd target/release/rbgp bench/scale/target/release/reloadstall)
for bin in "${bins[@]}"; do [[ -x $repo/$bin ]]; done
if [[ -e $out ]]; then
    sha256sum -c "$out/binaries.sha256"
    cmp "$prep/run.sh" "$out/run.sh"
    cmp "$prep/gate.py" "$out/gate.py"
else
    mkdir -p "$out"
    sha256sum "${bins[@]/#/$repo/}" >"$out/binaries.sha256"
    cp "$prep/run.sh" "$prep/gate.py" "$out/"
fi
printf 'cell\tpeers\ttotal\tipv4\tipv6\tchanged\tfilter\n' >"$out/plan.tsv"
for rung in 200 700; do
    rounds=(validation)
    total=114400 changed=170
    if [[ $rung == 700 ]]; then rounds=(A B); total=400400; changed=600; fi
    for round in "${rounds[@]}"; do
        for mix in 90 50; do
            ipv4=$((total * mix / 100))
            for shape in P F; do
                filter=0
                [[ $shape == P ]] || filter=32
                name="$rung-$round-$mix-$shape"
                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$rung" "$total" "$ipv4" "$((total-ipv4))" "$changed" "$filter" >>"$out/plan.tsv"
            done
        done
    done
done
previous=''
found=false
while IFS=$'\t' read -r name peers total ipv4 _ipv6 changed filter; do
    [[ $name != cell ]] || continue
    if [[ $name != "$selected" ]]; then previous=$name; continue; fi
    found=true
    if [[ -n $previous ]]; then
        jq -e '.pass == true' "$out/$previous/evidence.json" >/dev/null
    fi
    [[ ! -e $out/$name ]]
    sha256sum -c "$out/binaries.sha256" >"$out/$name-binary-check.log"
    mkdir -p "$out/$name"
    # A clean environment prevents inherited experimental GEN_/RELOADSTALL_ knobs.
    rc=0
    env -i PATH="$PATH" HOME="$HOME" N_PEERS="$peers" TOTAL_PREFIXES="$total" \
        CHANGED_PEERS="$changed" PORT=1790 RELOADS=4 CONTROL_SECS=30 \
        GEN_DUALSTACK=1 RELOADSTALL_DUALSTACK=1 RELOADSTALL_IPV4_PREFIXES="$ipv4" \
        GEN_FILTER_COUNT="$filter" RELOADSTALL_FILTER_COUNT="$filter" \
        RELOADSTALL_CYCLE_QUIESCE_SECS=20 \
        PROBE_PREFIXES='20.0.0.0/24 3001::/48' ARTIFACTS_DIR="$out/$name" \
        bash "$repo/bench/scale/matrix/run-matrix.sh" rustbgpd \
        >"$out/$name/driver.log" 2>&1 || rc=$?
    printf '%s\n' "$rc" >"$out/$name/driver.exit"
    sha256sum -c "$out/binaries.sha256" >>"$out/$name-binary-check.log"
    python3 "$prep/gate.py" "$out/$name" "$peers" "$total" "$ipv4" "$changed" "$filter" \
        >"$out/$name/evidence.json" 2>"$out/$name/gate.stderr.log"
    break
done <"$out/plan.tsv"
[[ $found == true ]]
