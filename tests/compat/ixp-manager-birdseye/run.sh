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
cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" -p rustbgpctl --bin rbgp
for refused in config-implicit.json config-skin.json; do
  out="$tmp/refused-${refused%.json}"
  if "$repo/target/debug/rs-config-render" --input-format ixp-manager-v2 \
    --context "$capture_output/$refused" --out-dir "$out" \
    --router-handle b2-rs1-lan1-ipv4 \
    --runtime-state-dir /var/lib/rustbgpd/b2-rs1-lan1-ipv4 \
    --max-prefix-restart-seconds 300 --check-with "$repo/target/debug/rustbgpd"; then
    echo "unsupported real IXP Manager capture rendered: $refused" >&2
    exit 1
  fi
  [ ! -e "$out/render-receipt.json" ]
done
render_v2() {
  input=$1
  output=$2
  "$repo/target/debug/rs-config-render" --input-format ixp-manager-v2 \
    --context "$input" --out-dir "$output" \
    --router-handle b2-rs1-lan1-ipv4 \
    --runtime-state-dir /var/lib/rustbgpd/b2-rs1-lan1-ipv4 \
    --max-prefix-restart-seconds 300 --check-with "$repo/target/debug/rustbgpd" >/dev/null
  [ -f "$output/render-receipt.json" ]
}
candidate_full="$tmp/candidate-full"
candidate_supported="$tmp/candidate-supported"
render_v2 "$capture_output/config-ui-filter.json" "$candidate_full"
render_v2 "$supported" "$candidate_supported"
[ "$(grep -Fxc '    term ui-receive-32 { if route.prefix == 203.0.113.0/24 { prepend as path-first 1 } }' \
  "$candidate_supported/policy/client-1.rpol")" -eq 1 ]
[ "$(grep -Fxc '    term ui-receive-33 { if route.as-path matches "^112_" && route.prefix == 192.175.48.0/24 { prepend as 112 2 } }' \
  "$candidate_supported/policy/client-1.rpol")" -eq 1 ]

legacy="$tmp/candidate-v1"
legacy_input="$tmp/ixp-manager-v1-supported.json"
cp "$repo/tools/rs-config-render/tests/fixtures/ixp-manager-v1-supported.json" "$legacy_input"
chmod 600 "$legacy_input"
"$repo/target/debug/rs-config-render" --input-format ixp-manager-v1 \
  --context "$legacy_input" \
  --out-dir "$legacy" \
  --router-handle b2-rs1-lan1-ipv4 \
  --runtime-state-dir /var/lib/rustbgpd/b2-rs1-lan1-ipv4 \
  --max-prefix-restart-seconds 300 --check-with "$repo/target/debug/rustbgpd" >/dev/null
[ -f "$legacy/render-receipt.json" ]

v3="$tmp/router-config-v3.json"
sed 's#router-config/v2#router-config/v3#' "$supported" >"$v3"
chmod 600 "$v3"
if render_v2 "$v3" "$tmp/candidate-v3"; then
  echo "router-config/v3 unexpectedly rendered" >&2
  exit 1
fi
[ ! -e "$tmp/candidate-v3/render-receipt.json" ]

full_fixture="$repo/tools/rs-config-render/tests/fixtures/ixp-manager-v2-ui-filters.json"
supported_fixture="$repo/tools/rs-config-render/tests/fixtures/ixp-manager-v2-supported.json"
compat_fixture="$root/fixtures/ixp-manager-v7.4-rustbgpd.json"
if [ "${CAPTURE_FIXTURES:-0}" = 1 ]; then
  : # The real supported capture already has the compatibility fixture's basename.
else
  diff -u "$full_fixture" "$capture_output/config-ui-filter.json"
  diff -u "$supported_fixture" "$supported"
  diff -u "$compat_fixture" "$supported"
fi

check_policy() {
  source=$1
  proof=$2
  tests=$3
  cp "$source" "$proof"
  printf '\n%s\n' "$tests" >>"$proof"
  "$repo/target/debug/rbgp" policy check "$proof" >/dev/null
}
check_policy "$candidate_full/policy/client-1.rpol" "$tmp/full-client-1.rpol" '
test full-advertise-accumulates {
    route { prefix 77.72.72.0/21; as-path "1213" }
    expect client-1 == accept with large-community 65501:0:0, large-community 65501:102:112
}
test full-receive-denies-first {
    route { prefix 192.175.48.0/24; as-path "112" }
    expect client-1-receive == reject
}'
check_policy "$candidate_supported/policy/client-1.rpol" "$tmp/supported-client-1.rpol" '
test supported-advertise-prefix-direction {
    route { prefix 77.72.72.0/21; as-path "1213" }
    expect client-1 == accept with large-community 65501:102:112
}
test supported-receive-prepend-then-accept {
    route { prefix 192.175.48.0/24; as-path "112" }
    expect client-1-receive == accept with prepend as 112 2
}
test supported-global-prepend-uses-first-not-origin {
    route { prefix 203.0.113.0/24; as-path "64501 64500" }
    expect client-1-receive == accept with prepend as 64501 1
}
test supported-global-prepend-prefix-miss {
    route { prefix 203.0.114.0/24; as-path "64501 64500" }
    expect client-1-receive == accept
}'

"$root/run-adapter-consumer.sh" "$tmp/ixp-manager" "$image" >/dev/null
