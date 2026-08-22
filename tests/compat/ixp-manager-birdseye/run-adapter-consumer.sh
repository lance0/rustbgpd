#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH='' cd -- "$root/../../.." && pwd)
ixp_manager=${1:?IXP Manager checkout is required}
image=${2:?PHP contract image is required}
birdseye=${3:?Birdseye checkout is required}
database=${4:?IXP Manager MySQL address is required}
capture_output=${CAPTURE_OUTPUT:?capture output directory is required}
tmp=$(mktemp -d)
daemon_pid=
adapter_pid=
cleanup() {
  [ -z "$adapter_pid" ] || kill "$adapter_pid" 2>/dev/null || true
  [ -z "$daemon_pid" ] || kill "$daemon_pid" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" --bin rustbgpd
cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" -p rustbgpctl --bin rbgp
cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" -p birdwatcher-adapter
socket=$tmp/rustbgpd.sock
aliases=$tmp/protocol-aliases
mkdir -p "$tmp/runtime"
printf '%s\n' 'pb_as64496=192.0.2.1@master4' >"$aliases"
cat >"$tmp/rustbgpd.toml" <<EOF
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
runtime_state_dir = "$tmp/runtime"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "$socket"
mode = 0o600

[[neighbors]]
address = "192.0.2.1"
remote_asn = 64496
graceful_restart = false
route_server_client = true
EOF

"$repo/target/debug/rustbgpd" "$tmp/rustbgpd.toml" >"$tmp/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 120); do
  [ -S "$socket" ] && break
  kill -0 "$daemon_pid" 2>/dev/null || { cat "$tmp/daemon.log" >&2; exit 1; }
  sleep 0.1
done
[ -S "$socket" ] || { cat "$tmp/daemon.log" >&2; exit 1; }
"$repo/target/debug/rbgp" --addr "unix://$socket" neighbor 192.0.2.1 disable \
  --reason "pinned down-session contract" >/dev/null

NO_COLOR=1 "$repo/target/debug/birdwatcher-adapter" \
  --grpc-addr "unix://$socket" --listen 127.0.0.1:0 \
  --protocol-alias-file "$aliases" --max-routes 2 \
  >"$tmp/adapter.out" 2>"$tmp/adapter.log" &
adapter_pid=$!
port=
for _ in $(seq 1 120); do
  port=$(grep -o '127\.0\.0\.1:[0-9][0-9]*' "$tmp/adapter.log" | tail -1 | cut -d: -f2 || true)
  [ -z "$port" ] || break
  kill -0 "$adapter_pid" 2>/dev/null || { cat "$tmp/adapter.log" >&2; exit 1; }
  sleep 0.1
done
[ -n "$port" ] || { cat "$tmp/adapter.log" >&2; exit 1; }
curl --silent --fail "http://127.0.0.1:$port/route/192.0.2.0%2F24/protocol/pb_as64496" >/dev/null
run_consumer() {
  protocol=$1
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    --env IXP_MANAGER_ROOT=/upstreams/ixp-manager \
    --env BIRDSEYE_API="http://127.0.0.1:$port" \
    --env EXPECTED_PROTOCOL="$protocol" \
    --volume "$root:/harness:ro" \
    --volume "$ixp_manager:/upstreams/ixp-manager:ro" \
    "$image" php /harness/adapter-consumer.php
}
http_status() {
  curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:$port/protocol/$1"
}
run_consumer pb_as64496

printf '%s\n' 'pb_reloaded_as64496=192.0.2.1@master4' >"$aliases.next"
mv "$aliases.next" "$aliases"
kill -HUP "$adapter_pid"
for _ in $(seq 1 120); do
  [ "$(http_status pb_as64496)" = 404 ] && [ "$(http_status pb_reloaded_as64496)" = 200 ] && break
  kill -0 "$adapter_pid" 2>/dev/null || { cat "$tmp/adapter.log" >&2; exit 1; }
  sleep 0.1
done
[ "$(http_status pb_as64496)" = 404 ] && [ "$(http_status pb_reloaded_as64496)" = 200 ] || exit 1
run_consumer pb_reloaded_as64496

rejected_before=$(grep -c 'reload rejected' "$tmp/adapter.log" || true)
printf '%s\n' 'secret_member=192.0.2.1@master4@secret_peer' >"$aliases.next"
mv "$aliases.next" "$aliases"
kill -HUP "$adapter_pid"
for _ in $(seq 1 120); do
  rejected_after=$(grep -c 'reload rejected' "$tmp/adapter.log" || true)
  [ "$rejected_after" -gt "$rejected_before" ] && break
  kill -0 "$adapter_pid" 2>/dev/null || { cat "$tmp/adapter.log" >&2; exit 1; }
  sleep 0.1
done
[ "$rejected_after" -gt "$rejected_before" ] || { cat "$tmp/adapter.log" >&2; exit 1; }
[ "$(http_status pb_as64496)" = 404 ] && [ "$(http_status pb_reloaded_as64496)" = 200 ] || exit 1
if grep -q 'secret_member\|secret_peer' "$tmp/adapter.log"; then
  exit 1
fi
run_consumer pb_reloaded_as64496

# Both pinned Nagios generators filter routers on api_type = Birdseye, so an
# excluded route server is simply absent from generated monitoring. Point the
# fixture router at the live adapter, render both generators, then run the
# pinned daemon plugin against the _apiurl the generator emitted. The host
# network namespace reaches both the loopback adapter and the MySQL bridge
# address; the pinned IXP Manager database config has no port knob.
docker run --rm --network host --user "$(id -u):$(id -g)" \
  --env IXP_MANAGER_ROOT=/upstreams/ixp-manager \
  --env BIRDSEYE_ROOT=/upstreams/birdseye \
  --env BIRDSEYE_API="http://127.0.0.1:$port" \
  --env DB_HOST="$database" \
  --env DB_DATABASE=ixp_ci --env DB_USERNAME=root --env DB_PASSWORD= \
  --env CAPTURE_OUTPUT=/capture-output \
  --volume "$root:/harness:ro" \
  --volume "$ixp_manager:/upstreams/ixp-manager" \
  --volume "$birdseye:/upstreams/birdseye:ro" \
  --volume "$capture_output:/capture-output" \
  "$image" php /harness/nagios-consumer.php
