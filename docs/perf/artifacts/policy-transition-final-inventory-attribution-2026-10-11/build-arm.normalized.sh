#!/usr/bin/env bash
# PREPARED ONLY. Run one arm only after root releases its build slot.
# Usage: build-arm.sh baseline|candidate SOURCE_TREE EXACT_SHA CACHE OUT_ROOT
# Source-tree metadata creation and candidate qualification are separate.
set -euo pipefail
[[ $# -eq 5 && ( $1 == baseline || $1 == candidate ) ]] || exit 2
ARM=$1 TREE=$(realpath "$2") SHA=$3 CACHE=$(realpath "$4") OUT=$(realpath -m "$5")
PREP=$(cd "$(dirname "$0")" && pwd)
[[ $SHA =~ ^[0-9a-f]{40}$ ]]
[[ $(git -C "$TREE" rev-parse HEAD) == "$SHA" && -z $(git -C "$TREE" status --porcelain --untracked-files=all) ]]
BASE=6ee2a052607b34a11e8daa2f4a4d4639b5101690
if [[ $ARM == baseline ]]; then [[ $SHA == "$BASE" ]]; fi
git -C "$TREE" merge-base --is-ancestor "$BASE" "$SHA"
DEST=$OUT/binaries/$ARM
[[ ! -e $DEST ]]
mkdir -p "$DEST"
exec >"$DEST/build-driver.log" 2>&1
trap 'exit 143' TERM
trap 'exit 130' INT
finish() { local rc=$?; trap - EXIT; printf '%s\n' "$rc" >"$DEST/build-stage.exit"; date -Is >"$DEST/build-stage.finished"; exit "$rc"; }
trap finish EXIT
date -Is >"$DEST/build-stage.started"
# Canonical then light is the shared host-wide order; never invert it.
printf '%s waiting for canonical lock\n' "$(date -u +%FT%TZ)"
exec {RUSTBGPD_HOST_LOCK_FD}><LOCK_DIRECTORY>/rustbgpd-host.lock
flock "$RUSTBGPD_HOST_LOCK_FD"
printf '%s canonical acquired; waiting for light lock\n' "$(date -u +%FT%TZ)"
exec {RUSTBGPD_LIGHT_LOCK_FD}><LOCK_DIRECTORY>/rustbgpd-light.lock
flock "$RUSTBGPD_LIGHT_LOCK_FD"
export RUSTBGPD_HOST_LOCK_FD RUSTBGPD_LIGHT_LOCK_FD
printf '%s both locks acquired; checking admission\n' "$(date -u +%FT%TZ)"
ADMISSION=$DEST/admission
mkdir "$ADMISSION"
free -h >"$ADMISSION/free.txt"
df -h "$CACHE" "$ADMISSION" >"$ADMISSION/disk.txt"
ps -eo pid,ppid,comm,args >"$ADMISSION/processes.txt"
docker ps --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}' >"$ADMISSION/containers.txt"
nvidia-smi >"$ADMISSION/gpu.txt"
# Inventory competitors before admission; native quiet gates remain separate.
source "$TREE/bench/scale/host-quiet.sh"
competitors=$(rustbgpd_host_quiet_competitors)
clippy_competitors=$(pgrep -x clippy-driver || true)
[[ -z $clippy_competitors ]] || { printf 'competing clippy processes: %s\n' "$clippy_competitors"; exit 75; }
printf '%s\n' "$competitors" >"$ADMISSION/competitors.txt"
[[ -z $competitors ]] || { printf 'competing processes: %s\n' "$competitors"; exit 75; }
if rg -i 'clab-|rustbgpd|gobgp|gobgpd|frrouting|(^| )bird([ :-]|$)' "$ADMISSION/containers.txt"; then exit 75; fi
python3 - "$CACHE" "$CACHE" "$ADMISSION" <<'PY_RESOURCES'
from pathlib import Path
import shutil
import sys
meminfo=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
available=int(meminfo['MemAvailable'].split()[0])*1024
free=[shutil.disk_usage(path).free for path in sys.argv[1:3]]
Path(sys.argv[3], 'resource-bytes.txt').write_text(f'memory_available={available}\ncache_free={free}\n')
assert available >= 32*1024**3, 'less than32GiB available memory'
assert min(free) >= 20*1024**3, 'less than20GiB cache filesystem free'
PY_RESOURCES
# The shared instrument is hashed under the admitted host locks.
sha256sum -c "$PREP/instruments.sha256"
[[ $(git -C <RUNNER> rev-parse HEAD) == 591ac39d4b50fc2c647942713a9ea99c0588a51a ]]
export CARGO_TARGET_DIR=$CACHE RUSTBGPD_BUILD_LOCK=$CACHE/build.lock CARGO_BUILD_JOBS=4
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
source "$TREE/scripts/build-lock.sh"
acquire_rustbgpd_build_lock
printf 'source_worktree=%s\nsource_commit=%s\ncargo_target_dir=%s\ncommand=%s\n' "$TREE" "$SHA" "$CACHE" 'cargo build --release --locked -j 4 -p rustbgpd -p rustbgpctl' >"$DEST/build-identity.txt"
cp "$PREP/build-arm.sh" "$DEST/build-driver-as-run.sh"
cp "$PREP/snapshot-arm.py" "$DEST/snapshot-as-run.py"
rustc -vV >"$DEST/toolchain.txt"
cargo -V >>"$DEST/toolchain.txt"
git -C "$TREE" rev-parse HEAD 'HEAD^{tree}' >"$DEST/source-identity.txt"
git -C "$TREE" diff "$BASE" "$SHA" >"$DEST/source-diff.patch"
git -C "$TREE" diff --exit-code "$BASE" "$SHA" -- Cargo.lock Cargo.toml '**/Cargo.toml'
git -C "$TREE" ls-files -z -- '*.rs' '*.proto' Cargo.toml Cargo.lock '**/Cargo.toml' '**/Cargo.lock' >"$DEST/input-refresh.nul"
(cd "$TREE" && xargs -0 -r touch -- <"$DEST/input-refresh.nul")
date -Is >"$DEST/input-refreshed-at"
sha256sum "$DEST/input-refresh.nul" >"$DEST/input-refresh.sha256"
rc=0
(cd "$TREE" && taskset -c 40-63 cargo build --release --locked -j 4 -p rustbgpd -p rustbgpctl) >"$DEST/build.log" 2>&1 || rc=$?
printf '%s\n' "$rc" >"$DEST/cargo-build.exit"
((rc==0)) || exit "$rc"
[[ -z $(git -C "$TREE" status --porcelain --untracked-files=all) ]]
cp "$CACHE/release/rustbgpd" "$CACHE/release/rbgp" "$DEST/"
(cd "$DEST" && sha256sum rustbgpd rbgp >SHA256SUMS)
"$DEST/rustbgpd" --version >"$DEST/binary-versions.txt"
"$DEST/rbgp" --version >>"$DEST/binary-versions.txt"
# Capture BEFORE any subsequent build changes a shared-cache fingerprint.
python3 "$PREP/snapshot-arm.py" "$CACHE" "$DEST" >"$DEST/actual-capture.log" 2>&1
(cd "$TREE" && cargo tree --locked --offline --target x86_64-unknown-linux-gnu \
    --edges normal,build --prefix depth --no-dedupe --format '{p}|{f}' \
    -p rustbgpd -p rustbgpctl) >"$DEST/normal-build-tree.txt" 2>"$DEST/normal-build-tree.stderr"
python3 - "$TREE" "$DEST" <<'PY'
from pathlib import Path
import sys
source, dest = sys.argv[1:]
p=Path(dest)
(p/'normal-build-tree.normalized.txt').write_text((p/'normal-build-tree.txt').read_text().replace(source,'<SOURCE>'))
PY
(cd "$DEST" && sha256sum normal-build-tree.normalized.txt source-identity.txt build-driver-as-run.sh snapshot-as-run.py >provenance.sha256)
chmod a-w "$DEST/rustbgpd" "$DEST/rbgp" "$DEST/SHA256SUMS"
