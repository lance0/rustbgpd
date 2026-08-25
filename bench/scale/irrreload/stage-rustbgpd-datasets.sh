#!/usr/bin/env bash
# Stage one immutable renderer generation into the live dataset tree. Only
# content-different files are replaced, and each replacement is an atomic
# rename within its destination directory.
set -euo pipefail

run=${1:?usage: stage-rustbgpd-datasets.sh RUN_DIR}
generation=${RELOADSTALL_STAGE_GENERATION:-}
case $generation in
a | b) ;;
*) echo "RELOADSTALL_STAGE_GENERATION must be a or b" >&2; exit 2 ;;
esac

manifest="$run/gen-$generation-datasets.sha256"
source_root="$run/render-$generation"
live_root="$run"
for path in "$run" "$source_root" "$source_root/datasets" "$live_root/datasets"; do
    if [ ! -d "$path" ] || [ -L "$path" ]; then
        echo "dataset stage directory is missing or unsafe: $path" >&2
        exit 1
    fi
done
if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
    echo "dataset generation manifest is missing or unsafe: $manifest" >&2
    exit 1
fi
[ -z "$(find "$source_root/datasets" "$live_root/datasets" -type l -print -quit)" ] || {
    echo "dataset trees must not contain symlinks" >&2
    exit 1
}

expected=$(mktemp "$run/.dataset-roster.XXXXXX")
actual=$(mktemp "$run/.dataset-roster.XXXXXX")
tmp=
cleanup() { rm -f -- "$expected" "$actual" ${tmp:+"$tmp"}; }
trap cleanup EXIT

awk '
    NF != 2 || $1 !~ /^[0-9a-f]{64}$/ || $2 !~ /^datasets\/[A-Za-z0-9_.\/-]+$/ || $2 ~ /(^|\/)\.\.?(\/|$)/ { exit 1 }
    seen[$2]++ { exit 1 }
    { print $2 }
' "$manifest" | sort >"$expected" || {
    echo "dataset generation manifest is malformed" >&2
    exit 1
}
[ -s "$expected" ] || { echo "dataset generation manifest is empty" >&2; exit 1; }
find "$source_root/datasets" -type f -printf 'datasets/%P\n' | sort >"$actual"
cmp -s "$expected" "$actual" || {
    echo "dataset generation source roster differs from its manifest" >&2
    exit 1
}
find "$live_root/datasets" -type f -printf 'datasets/%P\n' | sort >"$actual"
cmp -s "$expected" "$actual" || {
    echo "live dataset roster differs from the generation manifest" >&2
    exit 1
}
(cd "$source_root" && sha256sum --check --strict --status "$manifest") || {
    echo "dataset generation source digest mismatch" >&2
    exit 1
}

changed=0
total=0
while read -r expected_sha relative; do
    source_file="$source_root/$relative"
    live_file="$live_root/$relative"
    live_sha=$(sha256sum -- "$live_file")
    live_sha=${live_sha%% *}
    if [ "$live_sha" != "$expected_sha" ]; then
        tmp=$(mktemp "$(dirname "$live_file")/.dataset-stage.XXXXXX")
        cp -- "$source_file" "$tmp"
        chmod --reference="$source_file" "$tmp"
        mv -T -- "$tmp" "$live_file"
        tmp=
        changed=$((changed + 1))
    fi
    total=$((total + 1))
done <"$manifest"
printf 'dataset-stage generation=%s changed=%s total=%s\n' "$generation" "$changed" "$total"
