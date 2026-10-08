#!/usr/bin/env bash
# Offline proof for the shared library's image source-id guard.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

stubs=$(mktemp -d)
trap 'rm -rf "$stubs"' EXIT
log="$stubs/docker.log"
lab=clab-source-id-guard

# scripts/source-id.sh runs `docker run` in its own process, so the stub is an
# executable on PATH rather than a shell function. STUB_CONTAINERS lists the
# lab's containers as name|config-image|image-id; STUB_IDS maps an image id
# to the source-id recorded in it as image-id=source-id.
cat >"$stubs/docker" <<'EOF'
#!/bin/sh
echo "$*" >>"$STUB_LOG"
case "$1" in
    ps)
        [ "$3" = label=containerlab=source-id-guard ] || exit 0
        for c in $STUB_CONTAINERS; do echo "${c%%|*}"; done
        ;;
    inspect)
        for name; do :; done
        for c in $STUB_CONTAINERS; do
            [ "${c%%|*}" = "$name" ] || continue
            rest=${c#*|}
            case "$3" in
                "{{.Config.Image}}") echo "${rest%%|*}" ;;
                "{{.Image}}") echo "${rest#*|}" ;;
            esac
            exit 0
        done
        exit 1
        ;;
    run)
        for i in $STUB_IDS; do
            [ "${i%%=*}" = "$3" ] && echo "${i#*=}" && exit 0
        done
        exit 1
        ;;
esac
EOF
chmod +x "$stubs/docker"

# Source the library as an interop script would. CI and GITHUB_ACTIONS are
# cleared so source-id.sh compares ids instead of skipping under CI.
# Usage: source_lib "<containers>" "<image ids>"
source_lib() {
    : >"$log"
    env -u CI -u GITHUB_ACTIONS PATH="$stubs:$PATH" STUB_LOG="$log" \
        STUB_CONTAINERS="$1" STUB_IDS="$2" \
        bash -c 'TOPO=source-id-guard; source tests/interop/scripts/test-lib.sh' 2>"$stubs/stderr"
}
fail() {
    echo "FAIL: $*" >&2
    cat "$stubs/stderr" >&2
    exit 1
}
ran() { grep -q "^run --rm $1 " "$log"; }

tree_id=$(scripts/source-id.sh)
dev="$lab-rustbgpd|rustbgpd:dev|sha256:dev"
released="$lab-rustbgpd|ghcr.io/lance0/rustbgpd@sha256:pinned|sha256:released"
current="$lab-rustbgpd-current|rustbgpd:dev|sha256:current"

# A rustbgpd:dev container built from another tree stops the run, and the
# check reads the container's image id, not the movable tag.
source_lib "$dev" sha256:dev=other-tree-id && fail 'mismatched rustbgpd:dev container was accepted'
ran sha256:dev || fail 'image id was not checked'
! ran rustbgpd:dev || fail 'source-id check read the tag instead of the image id'
grep -q other-tree-id "$stubs/stderr" || fail 'mismatch did not name the image id'
grep -q "$tree_id" "$stubs/stderr" || fail 'mismatch did not name the tree id'

# The same container built from this tree passes.
source_lib "$dev" "sha256:dev=$tree_id" || fail 'matching rustbgpd:dev container was rejected'
ran sha256:dev || fail 'matching image id was not checked'

# Containers from other images are not checked.
source_lib "$released" sha256:released=other-tree-id || fail 'released container was rejected'
! grep -q '^run' "$log" || fail 'source-id check ran for a non-dev container'

# An unreadable image id fails instead of skipping the check.
source_lib "$lab-rustbgpd|rustbgpd:dev|" '' && fail 'empty image id was accepted'
grep -q 'cannot read the image id' "$stubs/stderr" || fail 'empty image id was not reported'

# Mixed-version labs: the rustbgpd:dev container beside the pinned $RUSTBGPD
# is checked too.
source_lib "$released $current" sha256:current=other-tree-id \
    && fail 'mismatched rustbgpd:dev container beside a released one was accepted'
ran sha256:current || fail 'second container was not checked'
source_lib "$released $current" "sha256:current=$tree_id" \
    || fail 'matching rustbgpd:dev container beside a released one was rejected'
! ran sha256:released || fail 'released container was checked'

echo 'shared source-id guard: PASS'
