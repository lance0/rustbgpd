#!/usr/bin/env bash
# Lint the rustbgpd protobuf schemas and reject wire- or JSON-breaking changes
# against BASE_REF (default origin/main) with the pinned buf release.
set -euo pipefail

readonly BUF_VERSION="1.73.0"

case $# in
    0) base=origin/main ;;
    1) base=$1 ;;
    *) echo "usage: $0 [BASE_REF | --lint-only]" >&2; exit 2 ;;
esac

root=$(git rev-parse --show-toplevel)
cd "$root"

# Use buf from PATH only at the exact pinned version; otherwise install the
# checksum-verified release into a per-version directory under the user's home.
buf=$(command -v buf || true)
if [[ -z "$buf" || "$("$buf" --version 2>/dev/null)" != "$BUF_VERSION" ]]; then
    buf_dir="${XDG_DATA_HOME:-$HOME/.local/share}/rustbgpd/buf-${BUF_VERSION}"
    buf="$buf_dir/buf"
    if [[ ! -x "$buf" ]]; then
        echo "installing pinned buf ${BUF_VERSION} into ${buf_dir}" >&2
        # A concurrent run may win the install race; the version check below
        # still rejects anything that is not the pinned binary.
        .github/scripts/install-buf.sh "$buf_dir" || [[ -x "$buf" ]]
    fi
fi
actual=$("$buf" --version)
[[ "$actual" == "$BUF_VERSION" ]] || {
    echo "expected buf ${BUF_VERSION} at ${buf}, found ${actual}" >&2
    exit 1
}

"$buf" lint
echo "buf lint passed"

if [[ "$base" == --lint-only ]]; then
    echo "buf breaking skipped: no base ref"
    exit 0
fi

# Compare against an extracted copy of the base tree's schemas. A base that
# predates buf.yaml is read with the current configuration.
against=$(mktemp -d)
trap 'rm -rf -- "$against"' EXIT
git archive "$base" proto | tar -x -C "$against"
if ! git cat-file -e "$base:buf.yaml" 2>/dev/null; then
    echo "base ${base} has no buf.yaml; comparing with the current configuration"
    cp buf.yaml "$against/buf.yaml"
else
    git show "$base:buf.yaml" >"$against/buf.yaml"
fi
"$buf" breaking --against "$against"
echo "buf breaking passed against $(git rev-parse --short "$base")"
