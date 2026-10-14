#!/usr/bin/env bash
# Install the exact buf release used by scripts/check-proto.sh into a new directory.
set -euo pipefail

BUF_VERSION="1.73.0"
BUF_SHA256="$("$(dirname -- "${BASH_SOURCE[0]}")/archive-pin.sh" "buf-${BUF_VERSION}-Linux-x86_64")"
BUF_URL="https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-Linux-x86_64"

fail() {
    echo "install-buf: $*" >&2
    exit 1
}

download() {
    local url=$1
    local output=$2

    curl --fail --location --silent --show-error \
        --proto '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 120 \
        --retry 3 --retry-delay 1 --retry-max-time 300 --retry-all-errors \
        --output "$output" "$url"
}

[[ $# == 1 ]] || {
    echo "usage: $0 INSTALL_DIR" >&2
    echo "Installs the exact Linux x86_64 buf ${BUF_VERSION} binary into a new directory." >&2
    exit 2
}

if [[ "$(uname -s)-$(uname -m)" != Linux-x86_64 ]]; then
    fail "the pinned buf binary is Linux x86_64 only; install buf ${BUF_VERSION} on PATH instead," \
        "for example: go install github.com/bufbuild/buf/cmd/buf@v${BUF_VERSION}"
fi

destination=$1
[[ -n "$destination" && "$destination" != "/" ]] || fail "INSTALL_DIR must name a directory"
[[ ! -e "$destination" ]] || fail "INSTALL_DIR already exists: $destination"

parent=$(dirname "$destination")
name=$(basename "$destination")
mkdir -p "$parent"
staging=$(mktemp -d "$parent/.${name}.tmp.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT

download "$BUF_URL" "$staging/buf"
printf '%s  %s\n' "$BUF_SHA256" "$staging/buf" | sha256sum --check --status - \
    || fail "checksum mismatch for buf-Linux-x86_64 ${BUF_VERSION}"
chmod 0755 "$staging/buf"
[[ "$("$staging/buf" --version)" == "$BUF_VERSION" ]] || fail "buf version check failed"

mv --no-target-directory "$staging" "$destination"
trap - EXIT
printf 'installed buf %s in %s\n' "$BUF_VERSION" "$destination"
