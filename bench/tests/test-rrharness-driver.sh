#!/usr/bin/env bash
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
driver="$repo/bench/scale/compare-rrharness.sh"
pin_rel=bench/scale/rebaseline/lan395-run-pin.env
pin="$repo/$pin_rel"

# The retained driver deliberately refuses to measure from any descendant of
# the exact pin commit. Once the receipt documentation is added above that
# commit, run the mechanics suite from a clean detached pin worktree instead
# of weakening the measurement fence for ordinary CI checkouts.
pin_commit=$(git -C "$repo" log -1 --format=%H -- "$pin_rel")
current_commit=$(git -C "$repo" rev-parse --verify HEAD)
if [[ $current_commit != "$pin_commit" ]]; then
  pin_worktree=$(mktemp -d "${TMPDIR:-/tmp}/lan395-pin-worktree.XXXXXX")
  rmdir "$pin_worktree"
  # shellcheck disable=SC2317 # Invoked indirectly by the trap below.
  cleanup_pin_worktree() {
    git -C "$repo" worktree remove --force "$pin_worktree" >/dev/null 2>&1 || true
  }
  trap cleanup_pin_worktree EXIT INT TERM
  git -C "$repo" worktree add --detach "$pin_worktree" "$pin_commit" >/dev/null
  (cd "$pin_worktree" && bench/tests/test-rrharness-driver.sh)
  exit
fi

marker="$repo/.lan395-dirty-probe"
external_driver=$(mktemp "${TMPDIR:-/tmp}/compare-rrharness.XXXXXX")
privacy_fixture=$(mktemp -d "${TMPDIR:-/tmp}/rrharness-privacy.XXXXXX")
cleanup() {
  rm -f "$marker" "$external_driver"
  rm -rf "$privacy_fixture"
}
trap cleanup EXIT INT TERM

pin_value() {
  local key=$1
  awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2) }' "$pin"
}

base=$(pin_value base_commit)
head=$(pin_value head_commit)
[[ -n $base && -n $head ]]

"$driver" --validate-only --base "$base" --head "$head" >/dev/null

set +e
"$driver" --validate-only --base "$head" --head "$head" >/dev/null 2>&1
wrong_ref_rc=$?
set -e
[[ $wrong_ref_rc -eq 2 ]] || {
  printf 'wrong pinned ref returned %s instead of 2\n' "$wrong_ref_rc" >&2
  exit 1
}

cp "$driver" "$external_driver"
chmod +x "$external_driver"
set +e
"$external_driver" --validate-only --base "$base" --head "$head" >/dev/null 2>&1
external_rc=$?
set -e
[[ $external_rc -eq 2 ]] || {
  printf 'external driver returned %s instead of 2\n' "$external_rc" >&2
  exit 1
}

[[ ! -e $marker ]]
touch "$marker"
set +e
"$driver" --validate-only --base "$base" --head "$head" >/dev/null 2>&1
dirty_rc=$?
set -e
rm -f "$marker"
[[ $dirty_rc -eq 1 ]] || {
  printf 'dirty checkout returned %s instead of 1\n' "$dirty_rc" >&2
  exit 1
}

mkdir -p "$privacy_fixture/measurement-sources" "$privacy_fixture/raw"
printf 'pid vocabulary belongs in retained reviewed source\n' \
  >"$privacy_fixture/measurement-sources/source.txt"
if rg -a --no-ignore -n --hidden \
  'https?://[^/@:]+:[^/@]+@|(^|[^[:alpha:]])pid([^[:alpha:]]|$)|user(name)?=' \
  -g '!**/measurement-sources/**' "$privacy_fixture" >/dev/null; then
  printf 'privacy scan did not exclude reviewed measurement source vocabulary\n' >&2
  exit 1
fi
printf 'username=private\n' >"$privacy_fixture/raw/private.txt"
if ! rg -a --no-ignore -n --hidden \
  'https?://[^/@:]+:[^/@]+@|(^|[^[:alpha:]])pid([^[:alpha:]]|$)|user(name)?=' \
  -g '!**/measurement-sources/**' "$privacy_fixture" >/dev/null; then
  printf 'privacy scan did not reject retained private runtime data\n' >&2
  exit 1
fi
printf 'ignored-private.bin\n' >"$privacy_fixture/.ignore"
printf '\000%s/private\n' "$HOME" >"$privacy_fixture/ignored-private.bin"
default_scan_rc=0
rg -a -F -n --hidden -- "$HOME/" "$privacy_fixture" >/dev/null || default_scan_rc=$?
[[ $default_scan_rc -eq 1 ]] || {
  printf 'privacy fixture was not hidden by the default ignore traversal\n' >&2
  exit 1
}
if ! rg -a --no-ignore -F -n --hidden -- "$HOME/" "$privacy_fixture" >/dev/null; then
  printf 'privacy scan did not inspect ignored binary content\n' >&2
  exit 1
fi

rg -F 'privacy scan failed while inspecting' "$driver" >/dev/null || {
  printf 'rrharness driver does not fail closed on privacy scanner errors\n' >&2
  exit 1
}

rg -F 'export PYTHONDONTWRITEBYTECODE=1' "$driver" >/dev/null || {
  printf 'rrharness driver does not disable retained Python bytecode writes\n' >&2
  exit 1
}
mkdir "$privacy_fixture/python-import"
printf 'VALUE = 1\n' >"$privacy_fixture/python-import/probe.py"
PYTHONPATH="$privacy_fixture/python-import" PYTHONDONTWRITEBYTECODE=1 \
  python3 -c 'import probe; assert probe.VALUE == 1'
[[ ! -e $privacy_fixture/python-import/__pycache__ ]] || {
  printf 'Python bytecode cache appeared despite the no-write fence\n' >&2
  exit 1
}

printf 'LAN-395 rrharness driver mechanics passed\n'
