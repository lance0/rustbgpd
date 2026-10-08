#!/usr/bin/env bash
# Offline proof for the shared library's image source-id guard.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

stubs=$(mktemp -d)
trap 'rm -rf "$stubs"' EXIT
log="$stubs/docker.log"

# scripts/source-id.sh runs `docker run` in its own process, so the stub is an
# executable on PATH rather than a shell function.
cat >"$stubs/docker" <<'EOF'
#!/bin/sh
echo "$*" >>"$STUB_LOG"
case "$1 $3" in
    "inspect {{.Config.Image}}") echo "$STUB_CONFIG_IMAGE" ;;
    "inspect {{.Image}}") echo sha256:stub-image-id ;;
    run*) echo "$STUB_SOURCE_ID" ;;
esac
EOF
chmod +x "$stubs/docker"

# Source the library as an interop script would. CI and GITHUB_ACTIONS are
# cleared so source-id.sh compares ids instead of skipping under CI.
source_lib() {
    : >"$log"
    env -u CI -u GITHUB_ACTIONS PATH="$stubs:$PATH" STUB_LOG="$log" \
        STUB_CONFIG_IMAGE="$1" STUB_SOURCE_ID="$2" \
        bash -c 'TOPO=source-id-guard; source tests/interop/scripts/test-lib.sh' 2>"$stubs/stderr"
}

tree_id=$(scripts/source-id.sh)

# A rustbgpd:dev container built from another tree stops the run, and the
# check reads the container's image id, not the movable tag.
if source_lib rustbgpd:dev other-tree-id; then
    echo 'mismatched rustbgpd:dev container was accepted' >&2
    exit 1
fi
grep -qx 'run --rm sha256:stub-image-id cat /usr/local/share/rustbgpd/source-id' "$log"
if grep -q '^run .*rustbgpd:dev' "$log"; then
    echo 'source-id check read the tag instead of the image id' >&2
    exit 1
fi
grep -q 'other-tree-id' "$stubs/stderr"
grep -q "$tree_id" "$stubs/stderr"

# The same container built from this tree passes.
source_lib rustbgpd:dev "$tree_id"
grep -q '^run --rm sha256:stub-image-id ' "$log"

# Containers from other images are not checked.
source_lib frrouting/frr:latest other-tree-id
if grep -q '^run' "$log"; then
    echo 'source-id check ran for a non-dev container' >&2
    exit 1
fi

echo 'shared source-id guard: PASS'
