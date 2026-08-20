#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH='' cd -- "$root/../../.." && pwd)
tmp=$(mktemp -d)
network=rustbgpd-ixp-contract-$$
mysql=rustbgpd-ixp-mysql-$$
cleanup() {
  docker rm --force "$mysql" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

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
docker network create "$network" >/dev/null
docker run --detach --name "$mysql" --network "$network" \
  --env MYSQL_ALLOW_EMPTY_PASSWORD=yes --env MYSQL_DATABASE=ixp_ci \
  'mysql:8.4.11@sha256:b3b90af2a6552ae30c266fdb7d5dd55f3afb72404bb78d37fe8a23eb857fd3fb' >/dev/null
for _ in $(seq 1 90); do
  if docker exec "$mysql" mysqladmin ping --host 127.0.0.1 --silent; then break; fi
  sleep 1
done
docker exec "$mysql" mysqladmin ping --host 127.0.0.1 --silent
docker exec -i "$mysql" mysql --user root ixp_ci <"$tmp/ixp-manager/data/ci/ci_test_db.sql"
docker run --rm --user "$(id -u):$(id -g)" \
  --network "$network" \
  --env CAPTURE_FIXTURES="${CAPTURE_FIXTURES:-0}" \
  --env CAPTURE_OUTPUT=/capture-output \
  --env COMPOSER_CACHE_DIR=/composer-cache \
  --env DB_HOST="$mysql" --env DB_PORT=3306 --env DB_DATABASE=ixp_ci \
  --env DB_USERNAME=root --env DB_PASSWORD= \
  --env VIEW_SKIN=rustbgpd-contract --env IXP_NO_TRANSIT_ASNS_OVERRIDE= \
  --env IXP_RPKI_RTR1_HOST=127.0.0.1 --env IXP_RPKI_RTR1_PORT=3323 \
  --env IXP_RPKI_RTR2_HOST= \
  --volume "$root:/harness:ro" \
  --volume "$repo/integrations/ixp-manager/gpl-2.0-only/api/v4/router/server/rustbgpd/json.foil.php:/exporter/json.foil.php:ro" \
  --volume "$tmp/birdseye:/upstreams/birdseye" \
  --volume "$tmp/ixp-manager:/upstreams/ixp-manager" \
  --volume "$composer_cache:/composer-cache" \
  --volume "$capture_output:/capture-output" \
  "$image" /harness/run-in-container.sh

supported="$capture_output/ixp-manager-v7.4-rustbgpd.json"
for capture in config-implicit.json config-ui-filter.json config-skin.json "$supported"; do
  [ -f "$capture_output/$(basename "$capture")" ] || { echo "missing real IXP Manager capture: $capture" >&2; exit 1; }
  chmod 600 "$capture_output/$(basename "$capture")"
done
cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" -p rs-config-render --bin rs-config-render
cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" --bin rustbgpd
for refused in config-implicit.json config-ui-filter.json config-skin.json; do
  out="$tmp/refused-${refused%.json}"
  if "$repo/target/debug/rs-config-render" --input-format ixp-manager-v1 \
    --context "$capture_output/$refused" --out-dir "$out" \
    --max-prefix-restart-seconds 300 --check-with "$repo/target/debug/rustbgpd"; then
    echo "unsupported real IXP Manager capture rendered: $refused" >&2
    exit 1
  fi
  [ ! -e "$out/render-receipt.json" ]
done
candidate="$tmp/candidate"
"$repo/target/debug/rs-config-render" --input-format ixp-manager-v1 \
  --context "$supported" --out-dir "$candidate" \
  --max-prefix-restart-seconds 300 --check-with "$repo/target/debug/rustbgpd" >/dev/null
[ -f "$candidate/render-receipt.json" ]
fixture="$root/fixtures/ixp-manager-v7.4-rustbgpd.json"
if [ "${CAPTURE_FIXTURES:-0}" = 1 ]; then
  : # The real capture already has the fixture's canonical basename.
else
  diff -u "$fixture" "$supported"
fi
cmp "$supported" "$repo/tools/rs-config-render/tests/fixtures/ixp-manager-v1-supported.json"

"$root/run-adapter-consumer.sh" "$tmp/ixp-manager" "$image" >/dev/null
