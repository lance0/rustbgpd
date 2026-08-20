#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH='' cd -- "$root/../../.." && pwd)
ixp_manager=${1:?IXP Manager checkout is required}
image=${2:?PHP contract image is required}
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
cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" -p birdwatcher-adapter
socket=$tmp/rustbgpd.sock
mkdir -p "$tmp/runtime"
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
EOF

"$repo/target/debug/rustbgpd" "$tmp/rustbgpd.toml" >"$tmp/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 120); do
  [ -S "$socket" ] && break
  kill -0 "$daemon_pid" 2>/dev/null || { cat "$tmp/daemon.log" >&2; exit 1; }
  sleep 0.1
done
[ -S "$socket" ] || { cat "$tmp/daemon.log" >&2; exit 1; }

NO_COLOR=1 "$repo/target/debug/birdwatcher-adapter" \
  --grpc-addr "unix://$socket" --listen 127.0.0.1:0 \
  --protocol-alias pb_as64496=192.0.2.1@master4 --max-routes 2 \
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
docker run --rm --network host --user "$(id -u):$(id -g)" \
  --env IXP_MANAGER_ROOT=/upstreams/ixp-manager \
  --env BIRDSEYE_API="http://127.0.0.1:$port" \
  --volume "$root:/harness:ro" \
  --volume "$ixp_manager:/upstreams/ixp-manager:ro" \
  "$image" php /harness/adapter-consumer.php
