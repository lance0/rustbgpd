#!/usr/bin/env bash
set -euo pipefail

ACTIONLINT_VERSION="1.7.12"
ACTIONLINT_SHA256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
ACTIONLINT_URL="https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"
RUFF_VERSION="0.16.0"
RUFF_SHA256="98001c995a134d95f9bc83106a7f94b552971b583f1c0ab75fb656a881e13865"
RUFF_URL="https://github.com/astral-sh/ruff/releases/download/${RUFF_VERSION}/ruff-x86_64-unknown-linux-gnu.tar.gz"

usage() {
    echo "usage: $0 INSTALL_DIR" >&2
    echo "Installs the exact Linux amd64 developer linters into a new directory." >&2
}

fail() {
    echo "install-developer-linters: $*" >&2
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

verify_sha256() {
    local archive=$1
    local expected=$2

    printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --status - \
        || fail "checksum mismatch for $(basename "$archive")"
}

extract_binary() {
    local archive=$1
    local member=$2
    local output=$3
    local count

    count=$(tar -tzf "$archive" | grep -Fxc -- "$member" || true)
    [[ "$count" == 1 ]] || fail "archive does not contain exactly one $member"
    tar -xOzf "$archive" "$member" > "$output"
    chmod 0755 "$output"
}

[[ $# == 1 ]] || {
    usage
    exit 2
}

destination=$1
[[ -n "$destination" && "$destination" != "/" ]] || fail "INSTALL_DIR must name a directory"
[[ ! -e "$destination" ]] || fail "INSTALL_DIR already exists: $destination"

parent=$(dirname "$destination")
name=$(basename "$destination")
mkdir -p "$parent"
staging=$(mktemp -d "$parent/.${name}.tmp.XXXXXX")

cleanup() {
    if [[ -n "${staging:-}" && -d "$staging" ]]; then
        find "$staging" -mindepth 1 -delete
        rmdir "$staging"
    fi
}
trap cleanup EXIT

actionlint_archive="$staging/actionlint.tar.gz"
ruff_archive="$staging/ruff.tar.gz"

download "$ACTIONLINT_URL" "$actionlint_archive"
verify_sha256 "$actionlint_archive" "$ACTIONLINT_SHA256"
extract_binary "$actionlint_archive" actionlint "$staging/actionlint"

download "$RUFF_URL" "$ruff_archive"
verify_sha256 "$ruff_archive" "$RUFF_SHA256"
extract_binary "$ruff_archive" \
    ruff-x86_64-unknown-linux-gnu/ruff "$staging/ruff"

actionlint_version=$("$staging/actionlint" -version)
[[ "${actionlint_version%%$'\n'*}" == "$ACTIONLINT_VERSION" ]] \
    || fail "actionlint version check failed"
[[ "$("$staging/ruff" --version)" == "ruff $RUFF_VERSION" ]] \
    || fail "Ruff version check failed"

find "$staging" -type f ! -name actionlint ! -name ruff -delete
mv --no-target-directory "$staging" "$destination"
staging=
trap - EXIT

printf 'installed actionlint %s and Ruff %s in %s\n' \
    "$ACTIONLINT_VERSION" "$RUFF_VERSION" "$destination"
