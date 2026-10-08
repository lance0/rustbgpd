#!/usr/bin/env bash
# Print a content hash of the Rust build inputs in this tree.
#
# Container images record the value at /usr/local/share/rustbgpd/source-id.
# Compare it with this script's output in the tree you meant to build:
#
#   test "$(docker run --rm rustbgpd:dev cat /usr/local/share/rustbgpd/source-id)" \
#     = "$(scripts/source-id.sh)"
#
# Only file paths and contents are hashed, never timestamps, so equal trees
# give equal values. The pruned paths mirror the .dockerignore rules that
# reach inside the hashed directories; scripts/test_source_id.py checks that.
# Any failed step exits non-zero without printing a digest.
set -euo pipefail
cd "$(dirname "$0")/.."
digest=$(
    find Cargo.toml Cargo.lock .cargo src crates proto bench benches examples tools \
        \( -name target -o -path 'bench/scale/matrix/artifacts-*' \) -prune \
        -o -type f -print0 |
        LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum
)
printf '%s\n' "${digest%% *}"
