#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

if [ "${CAPTURE_FIXTURES:-0}" = 1 ] && [ -z "${CAPTURE_OUTPUT:-}" ]; then
  echo "CAPTURE_OUTPUT is required when CAPTURE_FIXTURES=1" >&2
  exit 2
fi
capture_output=${CAPTURE_OUTPUT:-$tmp/capture-output}
mkdir -p "$capture_output"
composer_cache=${XDG_CACHE_HOME:-$HOME/.cache}/rustbgpd-ixp-contract-composer
mkdir -p "$composer_cache"

read_manifest() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
    "$root/contract.json" "$1"
}
birdseye_commit=$(read_manifest birdseye_commit)
ixp_manager_commit=$(read_manifest ixp_manager_commit)

clone_pin() {
  repository=$1
  commit=$2
  destination=$3
  git clone --quiet --filter=blob:none --no-checkout "$repository" "$destination"
  git -C "$destination" fetch --quiet --depth=1 origin "$commit"
  git -C "$destination" checkout --quiet --detach FETCH_HEAD
  actual=$(git -C "$destination" rev-parse HEAD)
  if [ "$actual" != "$commit" ]; then
    echo "pin verification failed: expected $commit, got $actual" >&2
    exit 1
  fi
}

clone_pin https://github.com/inex/birdseye.git "$birdseye_commit" "$tmp/birdseye"
clone_pin https://github.com/inex/IXP-Manager.git "$ixp_manager_commit" "$tmp/ixp-manager"

image=$(docker build --quiet --file "$root/Dockerfile" "$root")
docker run --rm --user "$(id -u):$(id -g)" \
  --env CAPTURE_FIXTURES="${CAPTURE_FIXTURES:-0}" \
  --env CAPTURE_OUTPUT=/capture-output \
  --env COMPOSER_CACHE_DIR=/composer-cache \
  --volume "$root:/harness:ro" \
  --volume "$tmp/birdseye:/upstreams/birdseye" \
  --volume "$tmp/ixp-manager:/upstreams/ixp-manager" \
  --volume "$composer_cache:/composer-cache" \
  --volume "$capture_output:/capture-output" \
  "$image" /harness/run-in-container.sh
