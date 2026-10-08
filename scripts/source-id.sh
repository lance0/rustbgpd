#!/usr/bin/env bash
# Print a content hash of the Rust build inputs in this tree.
#
# Container images record the value at /usr/local/share/rustbgpd/source-id.
# Check that an image was built from this tree:
#
#   scripts/source-id.sh --check rustbgpd:dev
#
# The check exits non-zero and names both ids on a mismatch. It is skipped
# when CI or GITHUB_ACTIONS is set: hosted runners build from a fresh
# checkout, and the stale-context case it catches comes from reusing a local
# BuildKit context across edits.
#
# Only file paths and contents are hashed, never timestamps, so equal trees
# give equal values. The pruned paths mirror the .dockerignore rules that
# reach inside the hashed directories; scripts/test_source_id.py checks that.
# Any failed step exits non-zero without printing a digest.
set -euo pipefail

image=
if [ "$#" -gt 0 ]; then
    if [ "$#" -ne 2 ] || [ "$1" != --check ] || [ -z "$2" ]; then
        echo "usage: $0 [--check IMAGE]" >&2
        exit 2
    fi
    image=$2
    if [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "source-id: CI run, skipping the $image check" >&2
        exit 0
    fi
fi

cd "$(dirname "$0")/.."
digest=$(
    find Cargo.toml Cargo.lock .cargo src crates proto bench benches examples tools \
        \( -name target -o -path 'bench/scale/matrix/artifacts-*' \) -prune \
        -o -type f -print0 |
        LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum
)
tree_id=${digest%% *}

if [ -z "$image" ]; then
    printf '%s\n' "$tree_id"
    exit 0
fi

if ! image_id=$(docker run --rm "$image" cat /usr/local/share/rustbgpd/source-id); then
    echo "source-id: cannot read the source-id from image $image" >&2
    exit 1
fi
if [ "$image_id" != "$tree_id" ]; then
    cat >&2 <<EOF
source-id: image $image was not built from this tree
  image source-id: ${image_id:-<empty>}
  tree source-id:  $tree_id ($PWD)
Rebuild from this tree. If the rebuilt image keeps the old id, BuildKit
reused a stale context: touch the changed files and rebuild.
EOF
    exit 1
fi
echo "source-id: image $image matches this tree ($tree_id)" >&2
