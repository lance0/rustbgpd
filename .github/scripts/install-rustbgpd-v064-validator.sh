#!/usr/bin/env bash

set -euo pipefail

readonly VERSION=0.64.0
readonly SHA256=bd4829de08d0c50074f9ecd5c351399fae42be06d456b3880a04aa4a7cda1137
readonly URL="https://github.com/lance0/rustbgpd/releases/download/v${VERSION}/rustbgpd-linux-amd64.tar.gz"

install_dir=${1:?usage: install-rustbgpd-v064-validator.sh INSTALL_DIR}
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
archive="$work_dir/rustbgpd-linux-amd64.tar.gz"

mkdir -p "$install_dir"
curl -fsSL --connect-timeout 10 --max-time 120 --output "$archive" "$URL"
printf '%s  %s\n' "$SHA256" "$archive" | sha256sum --check --status
tar -xzf "$archive" -C "$work_dir" rustbgpd
install -m 0755 "$work_dir/rustbgpd" "$install_dir/rustbgpd-v0.64.0"
[[ $("$install_dir/rustbgpd-v0.64.0" --version) == "rustbgpd 0.64.0" ]]
