#!/bin/bash -p
set -euo pipefail
[[ $- == *p* ]] || {
  \printf '%s\n' 'error: run-receipt.sh must be executed directly in privileged shell mode' >&2
  \exit 2
}
((${#BASH_ALIASES[@]} == 0)) || {
  \printf '%s\n' 'error: inherited shell aliases are forbidden' >&2
  \printf '  %s\n' "${!BASH_ALIASES[@]}" >&2
  \exit 2
}
[[ ${BASH_SOURCE[0]} == "$0" ]] || {
  \printf '%s\n' 'error: run-receipt.sh must be executed directly, not sourced' >&2
  \exit 2
}
\unalias -a
shopt -u expand_aliases
initial_functions=$(declare -F)
[[ -z $initial_functions ]] || {
  printf '%s\n' 'error: inherited shell functions are forbidden' >&2
  printf '%s\n' "$initial_functions" >&2
  exit 2
}
ambiguous_shell_environment=()
while IFS= read -r -d '' environment_entry; do
  environment_name=${environment_entry%%=*}
  case "$environment_name" in
    BASH_FUNC_*|ZSH_FUNC_*|BASH_ENV|ENV)
      ambiguous_shell_environment+=("$environment_name")
      ;;
  esac
done < <(/usr/bin/env -0)
((${#ambiguous_shell_environment[@]} == 0)) || {
  printf '%s\n' 'error: exported shell functions and shell startup hooks are forbidden' >&2
  printf '  %s\n' "${ambiguous_shell_environment[@]}" >&2
  exit 2
}
export LC_ALL=C
export TZ=UTC
readonly runner_path=/usr/bin:/bin
export PATH=$runner_path
readonly git_command=/usr/bin/git
readonly source_remote=https://github.com/lance0/rustbgpd.git
readonly canonical_baseline_commit=b2ec55f21364978f26662b1ec35fd47ddcfce9a6
readonly canonical_baseline_context_ref=refs/heads/main
readonly canonical_candidate_context_ref=refs/heads/perf/policy-reload-durable-receipt
readonly retained_baseline_ref=refs/receipt/baseline
readonly retained_source_ref=refs/receipt/source
git_environment=(
  /usr/bin/env -i LC_ALL=C TZ=UTC HOME=/nonexistent PATH="$runner_path"
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
)

usage() {
  cat <<'EOF'
Run the retained 700-client x 400,400-route policy reload-stall receipt.

Usage:
  bench/scale/reloadstall/run-receipt.sh \
    --source-sha FULL_40_HEX_COMMIT \
    --output-dir NEW_ABSOLUTE_OR_RELATIVE_DIRECTORY [options]

Options:
  --source-sha SHA            Required exact clean HEAD commit (full 40 hex).
  --output-dir DIR            Required; must not already exist.
  --preflight-wait-seconds N  Wait for load/process gates (default: 900).
  -h, --help                  Show this help.

This is an acceptance run, not a configurable smoke test. It always runs 700
real BGP sessions, 400,400 routes, four reload cycles across two alternating
policy generations, a
30-second control window, and the current-state generation-community completion
contract. It acquires the shared rustbgpd host lock, requires every exposed CPU
frequency policy to use the performance governor, waits for one-minute load
below 2.0, and refuses competing benchmark/build/daemon processes.
EOF
}

source_sha=
output_dir=
preflight_wait_seconds=900
readonly peers=700
readonly prefixes=400400
readonly listen_port=1790
readonly reloads=4
readonly control_seconds=30
readonly load_one_max=2.0
readonly required_governor=performance
readonly build_timeout_seconds=1800
readonly generation_timeout_seconds=60
readonly harness_timeout_seconds=4200
readonly required_toolchain=1.95.0-x86_64-unknown-linux-gnu
readonly build_path=$runner_path

while (($#)); do
  case "$1" in
    --source-sha)
      source_sha=${2:?--source-sha requires a value}
      shift 2
      ;;
    --output-dir)
      output_dir=${2:?--output-dir requires a value}
      shift 2
      ;;
    --preflight-wait-seconds)
      preflight_wait_seconds=${2:?--preflight-wait-seconds requires a value}
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ $source_sha =~ ^[0-9a-f]{40}$ ]] || {
  printf '%s\n' 'error: --source-sha must be a full lowercase 40-hex commit' >&2
  exit 2
}
[[ -n $output_dir ]] || {
  printf '%s\n' 'error: --output-dir is required' >&2
  exit 2
}
[[ $output_dir != */ ]] || {
  printf '%s\n' 'error: --output-dir must not end with /' >&2
  exit 2
}
[[ $preflight_wait_seconds =~ ^[0-9]+$ ]] || {
  printf '%s\n' 'error: --preflight-wait-seconds must be a non-negative integer' >&2
  exit 2
}

for command in \
  awk cat chmod cmp cp date env find flock git id mkdir mktemp python3 readlink \
  rm setsid sha256sum sleep ss stat tail tar timeout touch uname xargs; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'error: required command is missing: %s\n' "$command" >&2
    exit 1
  }
done

repo_root=$("${git_environment[@]}" "$git_command" rev-parse --show-toplevel)
cd "$repo_root"
head_sha=$("${git_environment[@]}" "$git_command" rev-parse --verify 'HEAD^{commit}')
[[ $head_sha == "$source_sha" ]] || {
  printf 'error: clean HEAD must equal --source-sha: HEAD=%s requested=%s\n' \
    "$head_sha" "$source_sha" >&2
  exit 2
}
source_tree=$("${git_environment[@]}" "$git_command" rev-parse "${source_sha}^{tree}")
source_remote_actual=$("${git_environment[@]}" "$git_command" remote get-url origin)
if [[ ! $source_remote_actual =~ ^(git@github\.com:|https://github\.com/|ssh://git@github\.com/)lance0/rustbgpd(\.git)?$ ]]; then
  printf 'error: origin is not the canonical lance0/rustbgpd repository: %s\n' \
    "$source_remote_actual" >&2
  exit 2
fi
source_status=$("${git_environment[@]}" "$git_command" status --porcelain=v1 --untracked-files=normal)
[[ -z $source_status ]] || {
  printf '%s\n' 'error: retained receipt requires a clean invoking worktree' >&2
  printf '%s\n' "$source_status" >&2
  exit 2
}
"${git_environment[@]}" "$git_command" diff --check "$source_sha^" "$source_sha" >/dev/null
PYTHONDONTWRITEBYTECODE=1 \
  python3 "$repo_root/bench/scale/reloadstall/build_fence.py" --environment-only

invoking_uid=$(/usr/bin/id -u)
invoking_home=$(/usr/bin/awk -F: -v uid="$invoking_uid" \
  '$3 == uid { if (found) { duplicate=1; next } print $6; found=1 }
   END { if (duplicate || !found) exit 2 }' /etc/passwd) || {
  printf 'error: cannot resolve one account home for uid %s from /etc/passwd\n' \
    "$invoking_uid" >&2
  exit 2
}
[[ $invoking_home == /* ]] || {
  printf 'error: account home must be absolute: %s\n' "$invoking_home" >&2
  exit 2
}
readonly rustup_command="$invoking_home/.cargo/bin/rustup"
readonly rustup_home="$invoking_home/.rustup"
[[ -f $rustup_command && ! -L $rustup_command && -x $rustup_command ]] || {
  printf 'error: trusted rustup must be a regular non-symlink executable: %s\n' \
    "$rustup_command" >&2
  exit 2
}
rustup_owner=$(/usr/bin/stat -c %u "$rustup_command")
rustup_mode_text=$(/usr/bin/stat -c %a "$rustup_command")
rustup_mode=$((8#$rustup_mode_text))
[[ $rustup_owner == "$invoking_uid" && $((rustup_mode & 0022)) -eq 0 ]] || {
  printf 'error: trusted rustup owner/mode is unsafe: path=%s owner=%s mode=%s\n' \
    "$rustup_command" "$rustup_owner" "$rustup_mode_text" >&2
  exit 2
}
rustup_resolved=$(readlink -f "$rustup_command")
[[ $rustup_resolved == "$rustup_command" ]] || {
  printf 'error: trusted rustup path must resolve to itself: path=%s resolved=%s\n' \
    "$rustup_command" "$rustup_resolved" >&2
  exit 2
}
tool_query_environment=(
  env -i LC_ALL=C TZ=UTC HOME="$invoking_home" RUSTUP_HOME="$rustup_home"
  PATH="$runner_path"
)
"${tool_query_environment[@]}" "$rustup_command" toolchain list \
  | awk -v required="$required_toolchain" \
  '$1 == required { found=1 } END { exit !found }' || {
  printf 'error: exact retained-build toolchain is not installed: %s\n' \
    "$required_toolchain" >&2
  exit 2
}
cargo_command=$("${tool_query_environment[@]}" "$rustup_command" which \
  --toolchain "$required_toolchain" cargo)
rustc_command=$("${tool_query_environment[@]}" "$rustup_command" which \
  --toolchain "$required_toolchain" rustc)
rustdoc_command=$("${tool_query_environment[@]}" "$rustup_command" which \
  --toolchain "$required_toolchain" rustdoc)
cargo_resolved=$(readlink -f "$cargo_command")
rustc_resolved=$(readlink -f "$rustc_command")
rustdoc_resolved=$(readlink -f "$rustdoc_command")
for tool in cargo rustc rustdoc; do
  command_variable="${tool}_command"
  resolved_variable="${tool}_resolved"
  selected=${!command_variable}
  resolved=${!resolved_variable}
  expected="$rustup_home/toolchains/$required_toolchain/bin/$tool"
  [[ $selected == "$expected" && $resolved == "$expected" \
      && -f $resolved && ! -L $resolved && -x $resolved ]] || {
    printf 'error: rustup selected an unexpected %s: selected=%s resolved=%s expected=%s\n' \
      "$tool" "$selected" "$resolved" "$expected" >&2
    exit 2
  }
  tool_owner=$(/usr/bin/stat -c %u "$resolved")
  tool_mode_text=$(/usr/bin/stat -c %a "$resolved")
  tool_mode=$((8#$tool_mode_text))
  [[ $tool_owner == "$invoking_uid" && $((tool_mode & 0022)) -eq 0 ]] || {
    printf 'error: selected %s owner/mode is unsafe: owner=%s mode=%s\n' \
      "$tool" "$tool_owner" "$tool_mode_text" >&2
    exit 2
  }
done
active_toolchain=$required_toolchain
rustc_release=$("${tool_query_environment[@]}" "$rustc_command" -V | awk '{print $2}')
[[ $rustc_release == 1.95.0 ]] || {
  printf 'error: retained-build rustc release mismatch: actual=%s expected=1.95.0\n' \
    "$rustc_release" >&2
  exit 2
}
cargo_release=$("${tool_query_environment[@]}" "$cargo_command" -V | awk '{print $2}')
[[ $cargo_release == 1.95.0 ]] || {
  printf 'error: retained-build cargo release mismatch: actual=%s expected=1.95.0\n' \
    "$cargo_release" >&2
  exit 2
}
rustdoc_release=$("${tool_query_environment[@]}" "$rustdoc_command" -V | awk '{print $2}')
[[ $rustdoc_release == 1.95.0 ]] || {
  printf 'error: retained-build rustdoc release mismatch: actual=%s expected=1.95.0\n' \
    "$rustdoc_release" >&2
  exit 2
}
rustc_sysroot=$("${tool_query_environment[@]}" "$rustc_command" --print sysroot)
[[ $rustc_sysroot == "$rustup_home/toolchains/$required_toolchain" ]] || {
  printf 'error: retained-build sysroot mismatch: actual=%s expected=%s\n' \
    "$rustc_sysroot" "$rustup_home/toolchains/$required_toolchain" >&2
  exit 2
}
[[ ${HOME:-} == /* ]] || {
  printf 'error: HOME must be an absolute path for the retained build: %s\n' \
    "${HOME:-<unset>}" >&2
  exit 2
}
if [[ -n ${RUSTUP_HOME:-} && $RUSTUP_HOME != /* ]]; then
  printf 'error: RUSTUP_HOME must be absolute when set: %s\n' "$RUSTUP_HOME" >&2
  exit 2
fi

case "$output_dir" in
  /*) ;;
  *) output_dir="$repo_root/$output_dir" ;;
esac
[[ ! -e $output_dir ]] || {
  printf 'error: output directory already exists: %s\n' "$output_dir" >&2
  exit 2
}
output_parent=${output_dir%/*}
[[ -n $output_parent ]] || output_parent=/
mkdir -p "$output_parent"
output_parent=$(cd "$output_parent" && pwd)
output_dir="$output_parent/${output_dir##*/}"

host_lock=${RUSTBGPD_HOST_LOCK:-${HOME}/.local/state/rustbgpd-host.lock}
[[ $host_lock == /* ]] || {
  printf 'error: RUSTBGPD_HOST_LOCK must be an absolute path: %s\n' "$host_lock" >&2
  exit 2
}
mkdir -p "${host_lock%/*}"
touch "$host_lock"
exec {host_lock_fd}>"$host_lock"
if ! flock -n "$host_lock_fd"; then
  printf 'error: shared host lock is held: %s\n' "$host_lock" >&2
  exit 75
fi

scratch=$(mktemp -d "${TMPDIR:-/tmp}/rustbgpd-reload-receipt.XXXXXX")
runtime_dir=$(mktemp -d /tmp/rls.XXXXXX)
source_root="$scratch/source"
build_target="$scratch/target"
cargo_home="$scratch/cargo-home"
build_home="$scratch/build-home"
host_name=$(uname -n)
daemon_pid=
health_pid=
harness_pid=
cleanup_active=0

wait_pid_bounded() {
  local pid=$1
  local seconds=$2
  timeout --foreground --signal=TERM --kill-after=1s "$seconds" \
    tail --pid="$pid" -f /dev/null >/dev/null 2>&1
}

terminate_pid_bounded() {
  local label=$1
  local pid=$2
  local seconds=$3
  local scope=${4:-pid}
  local target=$pid
  local rc
  [[ $scope == group ]] && target="-$pid"
  kill -TERM -- "$target" >/dev/null 2>&1 || true
  if ! wait_pid_bounded "$pid" "$seconds"; then
    printf 'cleanup: %s pid %s exceeded %ss; sending KILL\n' \
      "$label" "$pid" "$seconds" >&2
    kill -KILL -- "$target" >/dev/null 2>&1 || true
    wait_pid_bounded "$pid" 2 || true
  fi
  if wait "$pid" >/dev/null 2>&1; then
    rc=0
  else
    rc=$?
  fi
  return "$rc"
}

cleanup() {
  ((cleanup_active == 0)) || return
  cleanup_active=1
  trap - EXIT INT TERM
  set +e
  if [[ -n ${harness_pid:-} ]]; then
    terminate_pid_bounded harness "$harness_pid" 5 group || true
    harness_pid=
  fi
  if [[ -n ${health_pid:-} ]]; then
    touch "$scratch/health.stop" >/dev/null 2>&1 || true
    terminate_pid_bounded health-probe "$health_pid" 12 || true
    health_pid=
  fi
  if [[ -n ${daemon_pid:-} ]]; then
    terminate_pid_bounded daemon "$daemon_pid" 30 group || true
    daemon_pid=
  fi
  chmod -R u+w "$source_root" >/dev/null 2>&1 || true
  rm -rf "$scratch" "$runtime_dir"
}

on_signal() {
  local status=$1
  trap - INT TERM
  exit "$status"
}

trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

mkdir "$output_dir"
mkdir "$output_dir/scenario" "$output_dir/sources" "$source_root" "$build_target" \
  "$cargo_home" "$build_home"
printf '%s' "$source_status" >"$output_dir/source-status.txt"

# Fetch the exact allowed baseline and source object IDs from the hard-coded
# public canonical remote into a fresh bare repository. All retained source
# evidence is then created from those objects, never from mutable branch tips or
# the invoking object store.
source_archive="$output_dir/sources/source.tar"
source_commit_object="$output_dir/sources/source.commit"
source_bundle="$output_dir/sources/source.bundle"
canonical_refs="$output_dir/sources/canonical-refs.txt"
canonical_fetch_evidence="$output_dir/sources/canonical-fetch.txt"
canonical_repo="$scratch/canonical.git"
"${git_environment[@]}" "$git_command" init --bare --quiet "$canonical_repo"
{
  printf '+ %q ' "${git_environment[@]}" "$git_command" -C "$canonical_repo" fetch \
    --no-tags --force "$source_remote" \
    "+$canonical_baseline_commit:$retained_baseline_ref" \
    "+$source_sha:$retained_source_ref"
  printf '\n'
  "${git_environment[@]}" "$git_command" -C "$canonical_repo" fetch \
    --no-tags --force "$source_remote" \
    "+$canonical_baseline_commit:$retained_baseline_ref" \
    "+$source_sha:$retained_source_ref"
} >"$scratch/canonical-fetch.log" 2>&1
canonical_candidate_commit=$("${git_environment[@]}" "$git_command" -C \
  "$canonical_repo" rev-parse "$retained_source_ref^{commit}")
canonical_candidate_tree=$("${git_environment[@]}" "$git_command" -C \
  "$canonical_repo" rev-parse "$retained_source_ref^{tree}")
[[ $canonical_candidate_commit == "$source_sha" \
    && $canonical_candidate_tree == "$source_tree" ]] || {
  printf 'error: canonical candidate mismatch: commit=%s tree=%s requested=%s/%s\n' \
    "$canonical_candidate_commit" "$canonical_candidate_tree" \
    "$source_sha" "$source_tree" >&2
  exit 1
}
"${git_environment[@]}" "$git_command" -C "$canonical_repo" \
  fsck --full --strict >/dev/null
{
  printf 'remote=%s\n' "$source_remote"
  printf 'baseline_commit=%s\n' "$canonical_baseline_commit"
  printf 'baseline_context_ref=%s\n' "$canonical_baseline_context_ref"
  printf 'source_commit=%s\n' "$canonical_candidate_commit"
  printf 'source_tree=%s\n' "$canonical_candidate_tree"
  printf 'candidate_context_ref=%s\n' "$canonical_candidate_context_ref"
  printf 'proof=exact-sha-live-fetch-and-retained-bundle\n'
} >"$canonical_refs"
{
  printf 'command=env -i LC_ALL=C TZ=UTC HOME=/nonexistent PATH=/usr/bin:/bin '
  printf 'GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 '
  printf '/usr/bin/git -C <CANONICAL_REPO> fetch --no-tags --force %s ' \
    "$source_remote"
  printf '+%s:%s +%s:%s\n' \
    "$canonical_baseline_commit" "$retained_baseline_ref" \
    "$source_sha" "$retained_source_ref"
  printf 'fetch=success\n'
  printf 'fsck=success\n'
  printf 'baseline_commit=%s\n' "$canonical_baseline_commit"
  printf 'source_commit=%s\n' "$canonical_candidate_commit"
  printf 'source_tree=%s\n' "$canonical_candidate_tree"
} >"$canonical_fetch_evidence"

"${git_environment[@]}" "$git_command" -C "$canonical_repo" \
  cat-file commit "$retained_source_ref" >"$source_commit_object"
retained_commit_sha=$("${git_environment[@]}" "$git_command" hash-object \
  -t commit "$source_commit_object")
[[ $retained_commit_sha == "$source_sha" ]] || {
  printf 'error: retained commit object mismatch: actual=%s expected=%s\n' \
    "$retained_commit_sha" "$source_sha" >&2
  exit 1
}
retained_commit_tree=$(awk 'NR == 1 && $1 == "tree" { print $2 }' "$source_commit_object")
[[ $retained_commit_tree == "$source_tree" ]] || {
  printf 'error: retained commit tree mismatch: actual=%s expected=%s\n' \
    "$retained_commit_tree" "$source_tree" >&2
  exit 1
}
"${git_environment[@]}" "$git_command" -C "$canonical_repo" archive --format=tar \
  --output="$source_archive" "$retained_source_ref"
archive_commit=$("${git_environment[@]}" "$git_command" get-tar-commit-id \
  <"$source_archive")
[[ $archive_commit == "$source_sha" ]] || {
  printf 'error: source archive commit mismatch: archive=%s expected=%s\n' \
    "$archive_commit" "$source_sha" >&2
  exit 1
}
"${git_environment[@]}" "$git_command" -C "$canonical_repo" bundle create \
  "$source_bundle" "$retained_baseline_ref" "$retained_source_ref"
bundle_baseline=$("${git_environment[@]}" "$git_command" bundle list-heads \
  "$source_bundle" "$retained_baseline_ref")
bundle_candidate=$("${git_environment[@]}" "$git_command" bundle list-heads \
  "$source_bundle" "$retained_source_ref")
bundle_head_count=$("${git_environment[@]}" "$git_command" bundle list-heads \
  "$source_bundle" | awk 'END { print NR }')
[[ $bundle_baseline == "$canonical_baseline_commit $retained_baseline_ref" \
    && $bundle_candidate == "$source_sha $retained_source_ref" \
    && $bundle_head_count -eq 2 ]] || {
  printf 'error: retained canonical bundle refs mismatch: baseline=%s candidate=%s count=%s\n' \
    "$bundle_baseline" "$bundle_candidate" "$bundle_head_count" >&2
  exit 1
}
bundle_check="$scratch/bundle-check.git"
"${git_environment[@]}" "$git_command" init --bare --quiet "$bundle_check"
"${git_environment[@]}" "$git_command" -C "$bundle_check" \
  bundle verify "$source_bundle" \
  >"$scratch/bundle-verify.txt" 2>&1
"${git_environment[@]}" "$git_command" -C "$bundle_check" fetch --quiet \
  "$source_bundle" \
  "$retained_baseline_ref:refs/imported/baseline" \
  "$retained_source_ref:refs/imported/source"
bundle_baseline_commit=$("${git_environment[@]}" "$git_command" -C \
  "$bundle_check" rev-parse refs/imported/baseline)
bundle_commit=$("${git_environment[@]}" "$git_command" -C "$bundle_check" \
  rev-parse refs/imported/source)
bundle_tree=$("${git_environment[@]}" "$git_command" -C "$bundle_check" \
  rev-parse 'refs/imported/source^{tree}')
"${git_environment[@]}" "$git_command" -C "$bundle_check" \
  cat-file commit refs/imported/source \
  >"$scratch/bundle-source.commit"
[[ $bundle_baseline_commit == "$canonical_baseline_commit" \
    && $bundle_commit == "$source_sha" && $bundle_tree == "$source_tree" ]] || {
  printf 'error: fresh-repository bundle mismatch: baseline=%s commit=%s tree=%s\n' \
    "$bundle_baseline_commit" "$bundle_commit" "$bundle_tree" >&2
  exit 1
}
cmp --silent "$source_commit_object" "$scratch/bundle-source.commit"
"${git_environment[@]}" "$git_command" -C "$bundle_check" \
  fsck --full --strict >/dev/null
rm -rf "$bundle_check"
tar --extract --file="$source_archive" --directory="$source_root" \
  --no-same-owner --no-same-permissions
cp "$source_root/bench/scale/reloadstall/gen-scenario.py" \
  "$output_dir/sources/gen-scenario.py"
cp "$source_root/bench/scale/reloadstall/build_fence.py" \
  "$output_dir/sources/build_fence.py"
cp "$source_root/bench/scale/reloadstall/process_fence.py" \
  "$output_dir/sources/process_fence.py"
cp "$source_root/bench/scale/reloadstall/src/main.rs" \
  "$output_dir/sources/reloadstall-main.rs"
cp "$source_root/bench/scale/reloadstall/run-receipt.sh" \
  "$output_dir/sources/run-receipt.sh"
cp "$source_root/bench/scale/reloadstall/validate_receipt.py" \
  "$output_dir/sources/validate_receipt.py"
source_archive_sha256=$(sha256sum "$source_archive" | awk '{print $1}')
source_bundle_sha256=$(sha256sum "$source_bundle" | awk '{print $1}')
find "$source_root" -exec chmod a-w {} +
chmod a-w "$canonical_fetch_evidence" "$canonical_refs" "$source_archive" \
  "$source_bundle" "$source_commit_object"
PYTHONDONTWRITEBYTECODE=1 \
  python3 "$source_root/bench/scale/reloadstall/build_fence.py" \
    --source-root "$source_root" --cargo-home "$cargo_home" \
    --expected-tree "$source_tree" --require-immutable \
    >"$scratch/build-fence.txt"

sanitize_text() {
  local input=$1
  local output=$2
  local pid_value=${3:-}
  SANITIZE_REPO_ROOT=$repo_root SANITIZE_SOURCE_ROOT=$source_root \
  SANITIZE_BUILD_TARGET=$build_target SANITIZE_RUNTIME_DIR=$runtime_dir \
  SANITIZE_BUILD_HOME=$build_home \
  SANITIZE_OUTPUT_DIR=$output_dir SANITIZE_SCRATCH_DIR=$scratch \
  SANITIZE_HOME=${HOME:-} SANITIZE_HOST_LOCK=$host_lock \
  SANITIZE_HOSTNAME=$host_name SANITIZE_CARGO_HOME=$cargo_home \
  SANITIZE_RUSTUP_HOME=$rustup_home SANITIZE_PID=$pid_value \
  python3 - "$input" "$output" <<'PY'
import os
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="strict")
pairs = (
    (os.environ.get("SANITIZE_SOURCE_ROOT", ""), "<SOURCE_ROOT>"),
    (os.environ.get("SANITIZE_BUILD_TARGET", ""), "<BUILD_TARGET>"),
    (os.environ.get("SANITIZE_BUILD_HOME", ""), "<BUILD_HOME>"),
    (os.environ.get("SANITIZE_REPO_ROOT", ""), "<REPO_ROOT>"),
    (os.environ.get("SANITIZE_RUNTIME_DIR", ""), "<RUNTIME_DIR>"),
    (os.environ.get("SANITIZE_OUTPUT_DIR", ""), "<OUTPUT_DIR>"),
    (os.environ.get("SANITIZE_SCRATCH_DIR", ""), "<SCRATCH_DIR>"),
    (os.environ.get("SANITIZE_HOST_LOCK", ""), "<HOST_LOCK>"),
    (os.environ.get("SANITIZE_CARGO_HOME", ""), "<CARGO_HOME>"),
    (os.environ.get("SANITIZE_RUSTUP_HOME", ""), "<RUSTUP_HOME>"),
    (os.environ.get("SANITIZE_HOME", ""), "<HOME>"),
)
for value, marker in sorted(pairs, key=lambda pair: len(pair[0]), reverse=True):
    if value and value != "/":
        text = text.replace(value, marker)
hostname = os.environ.get("SANITIZE_HOSTNAME", "")
if hostname:
    # Tool output is not required to label the node name as a hostname. Replace
    # every case-insensitive occurrence so a bare prompt/banner cannot escape
    # the publication boundary.
    text = re.sub(re.escape(hostname), "<HOSTNAME>", text, flags=re.IGNORECASE)
pid = os.environ.get("SANITIZE_PID", "")
if pid:
    text = re.sub(
        rf"(?i)(\bpid(?:=|[\"': ]+)){re.escape(pid)}\b",
        rf"\g<1><DAEMON_PID>",
        text,
    )
Path(sys.argv[2]).write_text(text, encoding="utf-8")
PY
}

build_daemon_cli=(
  timeout --foreground --signal=TERM --kill-after=30s "$build_timeout_seconds"
  "$cargo_command" build --release --locked --package rustbgpd --bin rustbgpd
  --package rustbgpctl --bin rbgp
)
build_harness=(
  timeout --foreground --signal=TERM --kill-after=30s "$build_timeout_seconds"
  "$cargo_command" build --release --locked
  --manifest-path bench/scale/reloadstall/Cargo.toml
)
build_environment=(
  env -i LC_ALL=C TZ=UTC HOME="$build_home" CARGO_HOME="$cargo_home"
  RUSTUP_HOME="$rustup_home" PATH="$build_path"
  RUSTUP_TOOLCHAIN="$required_toolchain" CARGO_TARGET_DIR="$build_target"
  RUSTC="$rustc_command" RUSTDOC="$rustdoc_command"
)
{
  printf '+ cd %q\n' "$source_root"
  printf '+ '
  printf '%q ' "${build_environment[@]}"
  printf '%q ' "${build_daemon_cli[@]}"
  printf '\n'
  (cd "$source_root" && "${build_environment[@]}" "${build_daemon_cli[@]}")
  printf '+ '
  printf '%q ' "${build_environment[@]}"
  printf '%q ' "${build_harness[@]}"
  printf '\n'
  (cd "$source_root" && "${build_environment[@]}" "${build_harness[@]}")
} >"$scratch/build.raw.log" 2>&1

# Cargo and every build script ran against a non-writable extraction. Rebuild
# its complete Git tree after the build so any attempted content, mode, symlink,
# or inventory mutation fails before a binary can be measured.
PYTHONDONTWRITEBYTECODE=1 \
  python3 "$source_root/bench/scale/reloadstall/build_fence.py" \
    --source-root "$source_root" --cargo-home "$cargo_home" \
    --expected-tree "$source_tree" --require-immutable \
    >"$scratch/build-fence-after.txt"

daemon_bin="$build_target/release/rustbgpd"
cli_bin="$build_target/release/rbgp"
harness_bin="$build_target/release/reloadstall"
for binary in "$daemon_bin" "$cli_bin" "$harness_bin"; do
  [[ -x $binary ]] || {
    printf 'error: expected release binary is missing: %s\n' "$binary" >&2
    exit 1
  }
done

capture_governors() {
  local destination=$1
  local governor governor_file wall_ns
  shopt -s nullglob
  local governor_files=(/sys/devices/system/cpu/cpufreq/policy*/scaling_governor)
  shopt -u nullglob
  ((${#governor_files[@]} > 0)) || {
    printf '%s\n' 'error: no readable CPU frequency policies; cannot prove performance governor' >&2
    return 1
  }
  governor_policy_count=${#governor_files[@]}
  printf 'wall_ns\tpolicy\tgovernor\n' >"$destination"
  for governor_file in "${governor_files[@]}"; do
    [[ -r $governor_file ]] || {
      printf 'error: governor is not readable: %s\n' "$governor_file" >&2
      return 1
    }
    governor=$(<"$governor_file")
    wall_ns=$(date +%s%N)
    printf '%s\t%s\t%s\n' "$wall_ns" \
      "${governor_file%/scaling_governor}" "$governor" >>"$destination"
    [[ $governor == "$required_governor" ]] || {
      printf 'error: %s uses governor %s, expected %s\n' \
        "$governor_file" "$governor" "$required_governor" >&2
      return 1
    }
  done
}

# Fail fast before waiting, then capture a second authoritative snapshot at the
# actual measurement boundary below.
capture_governors "$scratch/governors.initial.tsv"

process_fence=(
  python3 "$source_root/bench/scale/reloadstall/process_fence.py"
  --root "$repo_root" --root "$source_root" --root "$build_target"
)
capture_busy() {
  : >"$scratch/busy.tsv"
  local rc=0
  if PYTHONDONTWRITEBYTECODE=1 "${process_fence[@]}" >"$scratch/busy.tsv"; then
    rc=0
  else
    rc=$?
  fi
  # The exact scanner returns 1 when competitors were found. Any other failure
  # is a broken fence, not an empty process set.
  if ((rc != 0 && rc != 1)); then
    printf 'error: process fence failed with status %s\n' "$rc" >&2
    return "$rc"
  fi
  return 0
}

deadline=$((SECONDS + preflight_wait_seconds))
while true; do
  capture_busy
  load_one=$(awk '{print $1}' /proc/loadavg)
  load_clear=0
  if awk -v value="$load_one" -v limit="$load_one_max" \
    'BEGIN { exit !(value < limit) }'; then
    load_clear=1
  fi
  if [[ ! -s $scratch/busy.tsv && $load_clear -eq 1 ]]; then
    break
  fi
  if ((SECONDS >= deadline)); then
    printf 'error: exclusive-host preflight timed out: load_one=%s (limit %s)\n' \
      "$load_one" "$load_one_max" >&2
    if [[ -s $scratch/busy.tsv ]]; then
      printf '%s\n' 'competing processes:' >&2
      cat "$scratch/busy.tsv" >&2
    fi
    exit 75
  fi
  sleep 5
done

if ss -H -ltn | awk -v suffix=":${listen_port}" '$4 ~ suffix "$" { found=1 } END { exit !found }'; then
  printf 'error: TCP listen port %s is already occupied\n' "$listen_port" >&2
  exit 75
fi
generator=(
  timeout --foreground --signal=TERM --kill-after=5s "$generation_timeout_seconds"
  python3 "$source_root/bench/scale/reloadstall/gen-scenario.py"
  "$peers" "$runtime_dir" "$listen_port"
)
{
  printf '+ '
  printf '%q ' "${generator[@]}"
  printf '\n'
  "${generator[@]}"
} >>"$scratch/build.raw.log" 2>&1
sanitize_text "$runtime_dir/config.toml" "$output_dir/scenario/config.toml"
cp "$runtime_dir/gen-a.rpol" "$output_dir/scenario/gen-a.rpol"
cp "$runtime_dir/gen-b.rpol" "$output_dir/scenario/gen-b.rpol"
cp "$runtime_dir/member.rpol" "$output_dir/scenario/member.initial.rpol"
sanitize_text "$scratch/build.raw.log" "$output_dir/build.log"

runtime_environment=(env -i LC_ALL=C TZ=UTC)
daemon_command=(setsid "${runtime_environment[@]}" RUST_LOG=info "$daemon_bin" "$runtime_dir/config.toml")
health_command=(
  timeout --foreground --signal=TERM --kill-after=1s 10
  "${runtime_environment[@]}" "$cli_bin" --addr "unix://$runtime_dir/grpc.sock" health
)
harness_payload=(
  "$harness_bin" "$peers" "$prefixes" "$listen_port" PLACEHOLDER_PID
  "$runtime_dir/member.rpol" "$runtime_dir/gen-a.rpol" "$runtime_dir/gen-b.rpol"
  "$reloads" "$control_seconds"
)
harness_command=(
  setsid
  timeout --foreground --signal=TERM --kill-after=30s "$harness_timeout_seconds"
  "${runtime_environment[@]}" "${harness_payload[@]}"
)

SOURCE_COMMIT=$source_sha \
python3 - "$output_dir/invocation.json" <<'PY'
import json
import os
import sys

source = "<SOURCE_ROOT>"
target = "<BUILD_TARGET>"
runtime = "<RUNTIME_DIR>"
output = "<OUTPUT_DIR>"
payload = {
    "source_commit": os.environ["SOURCE_COMMIT"],
    "build_cwd": source,
    "build_environment": {
        "CARGO_TARGET_DIR": target,
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": "<BUILD_HOME>",
        "CARGO_HOME": "<CARGO_HOME>",
        "RUSTUP_HOME": "<RUSTUP_HOME>",
        "PATH": "/usr/bin:/bin",
        "RUSTUP_TOOLCHAIN": "1.95.0-x86_64-unknown-linux-gnu",
        "RUSTC": "<RUSTC_COMMAND>",
        "RUSTDOC": "<RUSTDOC_COMMAND>",
        "allowed_cargo_config": f"{source}/.cargo/config.toml",
        "external_cargo_configs": "rejected",
    },
    "process_fence_environment": {"PYTHONDONTWRITEBYTECODE": "1"},
    "runtime_environments": {
        "daemon": {"LC_ALL": "C", "TZ": "UTC", "RUST_LOG": "info"},
        "harness": {"LC_ALL": "C", "TZ": "UTC"},
        "health": {"LC_ALL": "C", "TZ": "UTC"},
    },
    "commands": {
        "canonical_fetch": [
            "/usr/bin/git", "-C", "<CANONICAL_REPO>", "fetch", "--no-tags",
            "--force", "https://github.com/lance0/rustbgpd.git",
            "+b2ec55f21364978f26662b1ec35fd47ddcfce9a6:refs/receipt/baseline",
            f"+{os.environ['SOURCE_COMMIT']}:refs/receipt/source",
        ],
        "archive": [
            "/usr/bin/git", "-C", "<CANONICAL_REPO>", "archive", "--format=tar",
            f"--output={output}/sources/source.tar",
            "refs/receipt/source",
        ],
        "commit_object": [
            "/usr/bin/git", "-C", "<CANONICAL_REPO>", "cat-file", "commit",
            "refs/receipt/source",
        ],
        "bundle": [
            "/usr/bin/git", "-C", "<CANONICAL_REPO>", "bundle", "create",
            f"{output}/sources/source.bundle", "refs/receipt/baseline",
            "refs/receipt/source",
        ],
        "extract": [
            "tar", "--extract", f"--file={output}/sources/source.tar",
            f"--directory={source}", "--no-same-owner", "--no-same-permissions",
        ],
        "build_daemon_cli": [
            "timeout", "--foreground", "--signal=TERM", "--kill-after=30s", "1800",
            "<CARGO_COMMAND>", "build", "--release", "--locked", "--package",
            "rustbgpd", "--bin", "rustbgpd", "--package", "rustbgpctl", "--bin", "rbgp",
        ],
        "build_harness": [
            "timeout", "--foreground", "--signal=TERM", "--kill-after=30s", "1800",
            "<CARGO_COMMAND>", "build", "--release", "--locked",
            "--manifest-path", "bench/scale/reloadstall/Cargo.toml",
        ],
        "build_fence": [
            "python3", f"{source}/bench/scale/reloadstall/build_fence.py",
            "--source-root", source, "--cargo-home", "<CARGO_HOME>",
            "--expected-tree", "<SOURCE_TREE>", "--require-immutable",
        ],
        "generate": [
            "timeout", "--foreground", "--signal=TERM", "--kill-after=5s", "60",
            "python3", f"{source}/bench/scale/reloadstall/gen-scenario.py", "700",
            runtime, "1790",
        ],
        "process_fence": [
            "python3", f"{source}/bench/scale/reloadstall/process_fence.py",
            "--root", "<REPO_ROOT>", "--root", source, "--root", target,
        ],
        "daemon": [
            "setsid", "env", "-i", "LC_ALL=C", "TZ=UTC", "RUST_LOG=info",
            f"{target}/release/rustbgpd", f"{runtime}/config.toml",
        ],
        "health": [
            "timeout", "--foreground", "--signal=TERM", "--kill-after=1s", "10",
            "env", "-i", "LC_ALL=C", "TZ=UTC",
            f"{target}/release/rbgp", "--addr", f"unix://{runtime}/grpc.sock", "health",
        ],
        "harness": [
            "setsid", "timeout", "--foreground", "--signal=TERM", "--kill-after=30s", "4200",
            "env", "-i", "LC_ALL=C", "TZ=UTC", f"{target}/release/reloadstall",
            "700", "400400", "1790", "<DAEMON_PID>", f"{runtime}/member.rpol",
            f"{runtime}/gen-a.rpol", f"{runtime}/gen-b.rpol", "4", "30",
        ],
        "validate": [
            "python3", f"{source}/bench/scale/reloadstall/validate_receipt.py", output,
        ],
    },
    "health_probe": {"timeout_seconds": 10, "interval_milliseconds": 50},
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

verify_exact_sources() {
  local current_archive_sha256 current_bundle_sha256 current_commit_sha current_commit_tree
  current_archive_sha256=$(sha256sum "$source_archive" | awk '{print $1}')
  [[ $current_archive_sha256 == "$source_archive_sha256" ]] || {
    printf 'error: retained source archive changed: actual=%s expected=%s\n' \
      "$current_archive_sha256" "$source_archive_sha256" >&2
    return 1
  }
  current_bundle_sha256=$(sha256sum "$source_bundle" | awk '{print $1}')
  [[ $current_bundle_sha256 == "$source_bundle_sha256" ]] || {
    printf 'error: retained source bundle changed: actual=%s expected=%s\n' \
      "$current_bundle_sha256" "$source_bundle_sha256" >&2
    return 1
  }
  current_commit_sha=$("${git_environment[@]}" "$git_command" hash-object \
    -t commit "$source_commit_object")
  [[ $current_commit_sha == "$source_sha" ]] || {
    printf 'error: retained source commit changed: actual=%s expected=%s\n' \
      "$current_commit_sha" "$source_sha" >&2
    return 1
  }
  current_commit_tree=$(awk 'NR == 1 && $1 == "tree" { print $2 }' \
    "$source_commit_object")
  [[ $current_commit_tree == "$source_tree" ]] || {
    printf 'error: retained source commit/tree binding changed\n' >&2
    return 1
  }
  PYTHONDONTWRITEBYTECODE=1 \
    python3 "$source_root/bench/scale/reloadstall/build_fence.py" \
      --source-root "$source_root" --cargo-home "$cargo_home" \
      --expected-tree "$source_tree" --require-immutable >/dev/null
  cmp --silent "$source_root/bench/scale/reloadstall/gen-scenario.py" \
  "$output_dir/sources/gen-scenario.py"
  cmp --silent "$source_root/bench/scale/reloadstall/build_fence.py" \
    "$output_dir/sources/build_fence.py"
  cmp --silent "$source_root/bench/scale/reloadstall/process_fence.py" \
    "$output_dir/sources/process_fence.py"
  cmp --silent "$source_root/bench/scale/reloadstall/src/main.rs" \
  "$output_dir/sources/reloadstall-main.rs"
  cmp --silent "$source_root/bench/scale/reloadstall/run-receipt.sh" \
  "$output_dir/sources/run-receipt.sh"
  cmp --silent "$source_root/bench/scale/reloadstall/validate_receipt.py" \
  "$output_dir/sources/validate_receipt.py"
}

# This is the authoritative, timestamped measurement-boundary snapshot. All
# retained environment values and the manifest below are derived from it.
verify_exact_sources

preflight_started_wall_ns=$(date +%s%N)
capture_governors "$output_dir/governors.tsv"
capture_busy
process_wall_ns=$(date +%s%N)
if [[ -s $scratch/busy.tsv ]]; then
  printf '%s\n' 'error: competing process appeared at the measurement boundary:' >&2
  cat "$scratch/busy.tsv" >&2
  exit 75
fi
printf 'wall_ns\tprocess\tpid\tcommand\n%s\t<none>\t<none>\t<none>\n' \
  "$process_wall_ns" >"$output_dir/processes.tsv"
load_wall_ns=$(date +%s%N)
load_one=$(awk '{print $1}' /proc/loadavg)
if ! awk -v value="$load_one" -v limit="$load_one_max" \
  'BEGIN { exit !(value < limit) }'; then
  printf 'error: measurement-boundary load_one=%s, expected below %s\n' \
    "$load_one" "$load_one_max" >&2
  exit 75
fi
printf 'wall_ns\tload_one\n%s\t%s\n' "$load_wall_ns" "$load_one" \
  >"$output_dir/load-before.tsv"
preflight_completed_wall_ns=$(date +%s%N)

daemon_start_wall_ns=$(date +%s%N)
"${daemon_command[@]}" >"$scratch/daemon.raw.log" 2>&1 &
daemon_pid=$!
harness_payload[4]=$daemon_pid
harness_command=(
  setsid
  timeout --foreground --signal=TERM --kill-after=30s "$harness_timeout_seconds"
  "${runtime_environment[@]}" "${harness_payload[@]}"
)

ready=0
for _ in {1..600}; do
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    printf '%s\n' 'error: daemon exited before its health endpoint became ready' >&2
    tail -100 "$scratch/daemon.raw.log" >&2 || true
    exit 1
  fi
  if [[ -S $runtime_dir/grpc.sock ]] \
    && timeout --foreground --signal=TERM --kill-after=1s 5 \
      "${health_command[@]}" >"$scratch/initial-health.log" 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done
[[ $ready -eq 1 ]] || {
  printf '%s\n' 'error: daemon health endpoint did not become ready within 60 seconds' >&2
  exit 1
}

printf 'wall_ns\telapsed_us\texit_code\n' >"$output_dir/health.tsv"
: >"$output_dir/health-errors.log"
health_probe() {
  local probe_pid=
  trap 'if [[ -n ${probe_pid:-} ]]; then kill -TERM "$probe_pid" >/dev/null 2>&1 || true; wait "$probe_pid" >/dev/null 2>&1 || true; fi; exit 143' TERM INT
  while [[ ! -e $scratch/health.stop ]] && kill -0 "$daemon_pid" 2>/dev/null; do
    local started ended rc elapsed
    started=$(date +%s%N)
    "${health_command[@]}" >/dev/null 2>>"$output_dir/health-errors.log" &
    probe_pid=$!
    if wait "$probe_pid"; then
      rc=0
    else
      rc=$?
    fi
    probe_pid=
    ended=$(date +%s%N)
    elapsed=$(((ended - started) / 1000))
    ((elapsed > 0)) || elapsed=1
    printf '%s\t%s\t%s\n' "$started" "$elapsed" "$rc" >>"$output_dir/health.tsv"
    sleep 0.05
  done
}
health_probe &
health_pid=$!

"${harness_command[@]}" >"$scratch/harness.raw.log" 2>&1 &
harness_pid=$!
if wait "$harness_pid"; then
  harness_exit=0
else
  harness_exit=$?
fi
harness_pid=
touch "$scratch/health.stop"
if wait_pid_bounded "$health_pid" 12; then
  wait "$health_pid" >/dev/null 2>&1 || true
else
  terminate_pid_bounded health-probe "$health_pid" 12 || true
fi
health_pid=

daemon_alive_after_harness=false
if kill -0 "$daemon_pid" 2>/dev/null; then
  daemon_alive_after_harness=true
fi
cp "$runtime_dir/member.rpol" "$output_dir/scenario/member.final.rpol"
cp "$scratch/daemon.raw.log" "$scratch/daemon.run-window.raw.log"

sanitize_text "$scratch/harness.raw.log" "$output_dir/harness.log" "$daemon_pid"
sanitize_text "$scratch/daemon.run-window.raw.log" "$output_dir/daemon.log" "$daemon_pid"

daemon_exit=1
if [[ $daemon_alive_after_harness == true ]]; then
  if terminate_pid_bounded daemon "$daemon_pid" 30 group; then
    daemon_exit=0
  else
    daemon_exit=$?
  fi
fi
daemon_pid=

[[ $harness_exit -eq 0 ]] || {
  printf 'error: reloadstall exited %s; retained bundle is incomplete: %s\n' \
    "$harness_exit" "$output_dir" >&2
  exit 1
}
[[ $daemon_alive_after_harness == true ]] || {
  printf '%s\n' 'error: daemon exited before the harness completed' >&2
  exit 1
}
[[ $daemon_exit -eq 0 ]] || {
  printf 'error: daemon graceful shutdown exited %s\n' "$daemon_exit" >&2
  exit 1
}

health_samples=$(awk 'END { print NR > 0 ? NR - 1 : 0 }' "$output_dir/health.tsv")
health_failures=$(awk -F '\t' 'NR > 1 && $3 != 0 { failures++ } END { print failures + 0 }' \
  "$output_dir/health.tsv")
[[ $health_samples -gt 0 && $health_failures -eq 0 ]] || {
  printf 'error: health probe samples=%s failures=%s\n' \
    "$health_samples" "$health_failures" >&2
  exit 1
}
[[ ! -s $output_dir/health-errors.log ]] || {
  printf '%s\n' 'error: health probe wrote stderr despite zero exit statuses' >&2
  exit 1
}

{
  printf 'source_commit=%s\n' "$source_sha"
  printf 'source_tree=%s\n' "$source_tree"
  printf 'source_commit_object_sha=%s\n' "$retained_commit_sha"
  printf 'source_archive_sha256=%s\n' "$source_archive_sha256"
  printf 'source_bundle_sha256=%s\n' "$source_bundle_sha256"
  printf 'source_remote=%s\n' "$source_remote"
  printf 'canonical_baseline_context_ref=%s\n' "$canonical_baseline_context_ref"
  printf 'canonical_baseline_commit=%s\n' "$canonical_baseline_commit"
  printf 'canonical_candidate_context_ref=%s\n' "$canonical_candidate_context_ref"
  printf 'canonical_source_commit=%s\n' "$canonical_candidate_commit"
  printf 'canonical_source_tree=%s\n' "$canonical_candidate_tree"
  printf 'canonical_membership_proof=exact-sha-live-fetch-and-retained-bundle\n'
  printf 'build_source_root=<SOURCE_ROOT>\n'
  printf 'build_target_dir=<BUILD_TARGET>\n'
  printf 'host_lock=<HOST_LOCK>\n'
  printf 'runtime_dir=<RUNTIME_DIR>\n'
  printf 'output_dir=<OUTPUT_DIR>\n'
  printf 'cargo_command=%s\n' "$cargo_command"
  printf 'cargo_resolved=%s\n' "$cargo_resolved"
  printf 'rustc_command=%s\n' "$rustc_command"
  printf 'rustc_resolved=%s\n' "$rustc_resolved"
  printf 'rustdoc_command=%s\n' "$rustdoc_command"
  printf 'rustdoc_resolved=%s\n' "$rustdoc_resolved"
  printf 'rustup_command=%s\n' "$rustup_command"
  printf 'rustup_resolved=%s\n' "$rustup_resolved"
  printf 'active_toolchain=%s\n' "$active_toolchain"
  printf 'required_toolchain=%s\n' "$required_toolchain"
  printf 'rustc_sysroot=%s\n' "$rustc_sysroot"
  printf 'allowed_cargo_config=<SOURCE_ROOT>/.cargo/config.toml\n'
  printf 'external_cargo_configs=<none>\n'
  printf 'build_override_fence=clear\n'
  printf 'source_tree_verification=pre-build,post-build,measurement-boundary,post-run\n'
  printf 'build_environment=env -i LC_ALL=C TZ=UTC HOME=<BUILD_HOME> CARGO_HOME=<CARGO_HOME> RUSTUP_HOME=<RUSTUP_HOME> PATH=/usr/bin:/bin RUSTUP_TOOLCHAIN=%s CARGO_TARGET_DIR=<BUILD_TARGET> RUSTC=<RUSTC_COMMAND> RUSTDOC=<RUSTDOC_COMMAND>\n' \
    "$required_toolchain"
  printf 'daemon_environment=env -i LC_ALL=C TZ=UTC RUST_LOG=info\n'
  printf 'harness_environment=env -i LC_ALL=C TZ=UTC\n'
  printf 'health_environment=env -i LC_ALL=C TZ=UTC\n'
  "${git_environment[@]}" "$git_command" -C "$canonical_repo" show --no-patch \
    --format='source_parent=%P%nsource_author_date=%aI%nsource_commit_date=%cI%nsource_subject=%s' \
    "$source_sha"
  "${tool_query_environment[@]}" "$rustc_command" -Vv
  "${tool_query_environment[@]}" "$cargo_command" -V
  "${tool_query_environment[@]}" "$rustdoc_command" -V
  uname -srmo
  if command -v lscpu >/dev/null 2>&1; then
    lscpu
  fi
  if [[ -r /etc/os-release ]]; then
    cat /etc/os-release
  fi
  for variable in \
    RUSTFLAGS RUSTDOCFLAGS RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER \
    CARGO_ENCODED_RUSTFLAGS CARGO_INCREMENTAL CARGO_TARGET_DIR CARGO_HOME \
    RUSTUP_HOME RUSTUP_TOOLCHAIN AR ARFLAGS AS ASFLAGS CC CFLAGS CMAKE \
    CMAKE_FLAGS CPP CPPFLAGS CRATE_CC_NO_DEFAULTS CXX CXXFLAGS LD LDFLAGS \
    LIBCLANG_PATH MAKE MAKEFLAGS NINJA PKG_CONFIG PROTOC RANLIB RANLIBFLAGS \
    RING_PREGENERATE_ASM SOURCE_DATE_EPOCH; do
    printf 'environment_%s=%s\n' "$variable" "${!variable-<unset>}"
  done
  printf 'root_Cargo.lock_sha256=%s\n' \
    "$(sha256sum "$source_root/Cargo.lock" | awk '{print $1}')"
  printf 'reloadstall_Cargo.lock_sha256=%s\n' \
    "$(sha256sum "$source_root/bench/scale/reloadstall/Cargo.lock" | awk '{print $1}')"
  printf 'cargo_tool_sha256=%s\n' "$(sha256sum "$cargo_resolved" | awk '{print $1}')"
  printf 'rustc_tool_sha256=%s\n' "$(sha256sum "$rustc_resolved" | awk '{print $1}')"
  printf 'rustdoc_tool_sha256=%s\n' "$(sha256sum "$rustdoc_resolved" | awk '{print $1}')"
  printf 'rustup_tool_sha256=%s\n' "$(sha256sum "$rustup_resolved" | awk '{print $1}')"
  printf 'rustbgpd_sha256=%s\n' "$(sha256sum "$daemon_bin" | awk '{print $1}')"
  printf 'rbgp_sha256=%s\n' "$(sha256sum "$cli_bin" | awk '{print $1}')"
  printf 'reloadstall_sha256=%s\n' "$(sha256sum "$harness_bin" | awk '{print $1}')"
} >"$scratch/provenance.raw.txt"
sanitize_text "$scratch/provenance.raw.txt" "$output_dir/provenance.txt" "$daemon_pid"

SOURCE_COMMIT=$source_sha SOURCE_TREE=$source_tree \
SOURCE_ARCHIVE_SHA256=$source_archive_sha256 SOURCE_BUNDLE_SHA256=$source_bundle_sha256 \
SOURCE_REMOTE=$source_remote \
CANONICAL_BASELINE_CONTEXT_REF=$canonical_baseline_context_ref \
CANONICAL_BASELINE_COMMIT=$canonical_baseline_commit \
CANONICAL_CANDIDATE_CONTEXT_REF=$canonical_candidate_context_ref \
LOAD_ONE=$load_one PREFLIGHT_STARTED_WALL_NS=$preflight_started_wall_ns \
PREFLIGHT_COMPLETED_WALL_NS=$preflight_completed_wall_ns \
PROCESS_WALL_NS=$process_wall_ns LOAD_WALL_NS=$load_wall_ns \
GOVERNOR_POLICY_COUNT=$governor_policy_count DAEMON_START_WALL_NS=$daemon_start_wall_ns \
HARNESS_EXIT=$harness_exit DAEMON_ALIVE=$daemon_alive_after_harness DAEMON_EXIT=$daemon_exit \
HEALTH_SAMPLES=$health_samples HEALTH_FAILURES=$health_failures \
python3 - "$output_dir/manifest.json" <<'PY'
import json
import os
import sys

manifest = {
    "schema": "rustbgpd-reloadstall-receipt-v1",
    "status": "complete",
    "source": {
        "commit": os.environ["SOURCE_COMMIT"],
        "head": os.environ["SOURCE_COMMIT"],
        "tree": os.environ["SOURCE_TREE"],
        "archive_sha256": os.environ["SOURCE_ARCHIVE_SHA256"],
        "bundle_sha256": os.environ["SOURCE_BUNDLE_SHA256"],
        "remote": os.environ["SOURCE_REMOTE"],
        "canonical": {
            "baseline_commit": os.environ["CANONICAL_BASELINE_COMMIT"],
            "baseline_context_ref": os.environ["CANONICAL_BASELINE_CONTEXT_REF"],
            "candidate_context_ref": os.environ["CANONICAL_CANDIDATE_CONTEXT_REF"],
            "source_commit": os.environ["SOURCE_COMMIT"],
            "proof": "exact-sha-live-fetch-and-retained-bundle",
        },
        "clean": True,
    },
    "runtime_dir": "<RUNTIME_DIR>",
    "output_dir": "<OUTPUT_DIR>",
    "timeouts_seconds": {
        "build_each": 1800,
        "scenario_generation": 60,
        "harness_outer": 4200,
        "stub_connect_open": 15,
        "overall_establishment": 120,
        "initial_convergence": 120,
        "per_reload": 900,
        "quiesce": 20,
    },
    "scenario": {
        "peers": 700,
        "prefixes": 400400,
        "per_peer": 572,
        "expected_unique_prefixes_per_observer": 399828,
        "reloads": 4,
        "control_seconds": 30,
        "listen_port": 1790,
        "completion_contract": "current-state-generation-community-v2",
        "generation_communities": [
            "65500:2000", "65500:1000", "65500:2000", "65500:1000",
        ],
    },
    "environment": {
        "host_lock": "<HOST_LOCK>",
        "load_one": float(os.environ["LOAD_ONE"]),
        "required_governor": "performance",
        "process_gate": "clear",
        "preflight_started_wall_ns": int(os.environ["PREFLIGHT_STARTED_WALL_NS"]),
        "preflight_completed_wall_ns": int(os.environ["PREFLIGHT_COMPLETED_WALL_NS"]),
        "process_wall_ns": int(os.environ["PROCESS_WALL_NS"]),
        "load_wall_ns": int(os.environ["LOAD_WALL_NS"]),
        "governor_policy_count": int(os.environ["GOVERNOR_POLICY_COUNT"]),
        "daemon_start_wall_ns": int(os.environ["DAEMON_START_WALL_NS"]),
    },
    "result": {
        "harness_exit": int(os.environ["HARNESS_EXIT"]),
        "daemon_alive_after_harness": os.environ["DAEMON_ALIVE"] == "true",
        "daemon_exit": int(os.environ["DAEMON_EXIT"]),
        "health_samples": int(os.environ["HEALTH_SAMPLES"]),
        "health_failures": int(os.environ["HEALTH_FAILURES"]),
        "parse_errors": 0,
        "base_withdrawals": 0,
        "marker_conflicts": 0,
        "route_identity_defects": 0,
    },
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

verify_exact_sources
(
  cd "$output_dir"
  find . -type f ! -name SHA256SUMS -printf '%P\0' \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum
) >"$output_dir/SHA256SUMS"

validation_output=$(PYTHONDONTWRITEBYTECODE=1 \
  python3 "$source_root/bench/scale/reloadstall/validate_receipt.py" "$output_dir")
printf 'accepted receipt: %s\n%s\n' "$output_dir" "$validation_output"
