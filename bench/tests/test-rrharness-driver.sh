#!/usr/bin/env bash
set -euo pipefail

# The driver requires a clean invoking checkout, so exercise it from a fresh
# detached worktree at HEAD rather than trusting the caller's tree (CI leaves
# build output around; a developer may have edits in flight).
if [[ -z ${RRHARNESS_DRIVER_TEST_WORKTREE:-} ]]; then
  origin=$(git rev-parse --show-toplevel)
  worktree=$(mktemp -d "${TMPDIR:-/tmp}/rrharness-driver-test.XXXXXX")
  rmdir "$worktree"
  # shellcheck disable=SC2317 # Invoked indirectly by the trap below.
  cleanup_worktree() {
    git -C "$origin" worktree remove --force "$worktree" >/dev/null 2>&1 || true
  }
  trap cleanup_worktree EXIT INT TERM
  git -C "$origin" worktree add --detach "$worktree" HEAD >/dev/null
  (cd "$worktree" && RRHARNESS_DRIVER_TEST_WORKTREE=1 bench/tests/test-rrharness-driver.sh)
  exit
fi

repo=$(git rev-parse --show-toplevel)
driver="$repo/bench/scale/compare-rrharness.sh"
pin="$repo/bench/scale/rebaseline/lan395-run-pin.env"
diff_path=crates/rib/src/manager/distribution/mod.rs

marker="$repo/.rrharness-dirty-probe"
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

expect_rc() {
  local expected=$1 label=$2 rc=0
  shift 2
  "$@" >/dev/null 2>&1 || rc=$?
  [[ $rc -eq $expected ]] || {
    printf '%s returned %s instead of %s\n' "$label" "$rc" "$expected" >&2
    exit 1
  }
}

base=$(pin_value base_commit)
head=$(pin_value head_commit)
[[ -n $base && -n $head ]]
git -C "$repo" cat-file -e "${base}^{commit}"
git -C "$repo" cat-file -e "${head}^{commit}"

"$driver" --help >/dev/null
"$driver" --validate-only --base "$base" --head "$head" >/dev/null
"$driver" --validate-only --base "$base" --head "$head" \
  --pin "$pin" --diff-path "$diff_path" >/dev/null

expect_rc 2 'missing --base' "$driver" --validate-only --head "$head"
expect_rc 2 'identical refs' "$driver" --validate-only --base "$head" --head "$head"
expect_rc 2 'pinned ref drift' "$driver" --validate-only \
  --base "${base}~1" --head "$head" --pin "$pin" --diff-path "$diff_path"
expect_rc 2 '--pin without --diff-path' "$driver" --validate-only \
  --base "$base" --head "$head" --pin "$pin"
expect_rc 2 '--diff-path without --pin' "$driver" --validate-only \
  --base "$base" --head "$head" --diff-path "$diff_path"
expect_rc 2 'pinned diff drift' "$driver" --validate-only \
  --base "$base" --head "$head" --pin "$pin" --diff-path bench/scale/rrharness/README.md

cp "$driver" "$external_driver"
chmod +x "$external_driver"
expect_rc 2 'external driver' "$external_driver" --validate-only --base "$base" --head "$head"

[[ ! -e $marker ]]
touch "$marker"
expect_rc 1 'dirty checkout' "$driver" --validate-only --base "$base" --head "$head"
rm -f "$marker"

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
rg -F 'cargo build --release --locked' "$driver" >/dev/null || {
  printf 'rrharness driver does not build both sides with --release --locked\n' >&2
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

printf 'rrharness driver mechanics passed\n'
