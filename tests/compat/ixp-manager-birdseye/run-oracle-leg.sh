#!/bin/sh
# Populated oracle leg: pinned BIRD 2.0.12 + Bird's Eye 2.1.0 (oracle) and
# rustbgpd + birdwatcher-adapter (live) both peer with the same two ExaBGP
# announcers on one harness network, and the same pinned IXP Manager BirdsEye
# consumer reads both. Writes populated-oracle.raw.json and
# populated-live.raw.json into CAPTURE_OUTPUT; verify_capture.py --populated
# scrubs, pins, and diffs them against the runtime divergence allow-list.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH='' cd -- "$root/../../.." && pwd)
ixp_manager=${1:?IXP Manager checkout is required}
image=${2:?PHP contract image is required}
birdseye=${3:?installed Birdseye checkout is required}
capture_output=${CAPTURE_OUTPUT:?capture output directory is required}
tmp=$(mktemp -d)
network=rustbgpd-ixp-oracle-$$
oracle=rustbgpd-ixp-oracle-$$
announcer_a=rustbgpd-ixp-announcer-as64496-$$
announcer_b=rustbgpd-ixp-announcer-as64497-$$
exabgp='ghcr.io/exa-networks/exabgp@sha256:5554ac053766e66ca3b99eb6b66e83e32113913729a184dcbaf0cc4abd2f4244'
daemon_pid=
adapter_pid=
cleanup() {
  [ -z "$adapter_pid" ] || kill "$adapter_pid" 2>/dev/null || true
  [ -z "$daemon_pid" ] || kill "$daemon_pid" 2>/dev/null || true
  docker rm --force "$oracle" "$announcer_a" "$announcer_b" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" --bin rustbgpd
cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" -p birdwatcher-adapter
oracle_image=$(docker build --quiet --file "$root/Dockerfile.oracle" "$root")
docker network create --subnet 198.51.100.0/24 \
  --ipv6 --subnet 2001:db8:5100::/64 "$network" >/dev/null

# Oracle: the Bird's Eye checkout installed from its committed lockfile earlier
# in the gate, copied in next to the pinned BIRD so the real birdc is local.
docker run --detach --name "$oracle" --network "$network" \
  --ip 198.51.100.3 --ip6 2001:db8:5100::3 "$oracle_image" sleep infinity >/dev/null
[ "$(docker exec "$oracle" bird --version 2>&1)" = 'BIRD version 2.0.12' ]
docker cp "$birdseye/." "$oracle:/birdseye"
docker cp "$root/oracle-bird.conf" "$oracle:/etc/bird/bird.conf"
sed 's#^BIRDC=.*#BIRDC="/usr/sbin/birdc"#; s#^MAX_ROUTES=.*#MAX_ROUTES=100#' \
  "$root/birdseye.env" | docker exec --interactive "$oracle" sh -c 'cat >/birdseye/.env'
docker exec "$oracle" sh -c 'mkdir -p /run/bird && bird -c /etc/bird/bird.conf -s /run/bird/bird.ctl'
docker exec --detach "$oracle" sh -c \
  'cd /birdseye && exec php -d display_errors=0 -d log_errors=1 -S 0.0.0.0:18081 -t public public/index.php >/tmp/birdseye.log 2>&1'
oracle_api=http://198.51.100.3:18081/api

start_announcer() {
  docker run --rm --volume "$root/$2:/etc/exabgp/exabgp.conf:ro" "$exabgp" \
    validate /etc/exabgp/exabgp.conf >/dev/null
  docker run --detach --name "$1" --network "$network" --ip "$3" --ip6 "$4" \
    --env exabgp_tcp_bind="$3 $4" --env exabgp_tcp_port=179 \
    --volume "$root/$2:/etc/exabgp/exabgp.conf:ro" \
    "$exabgp" server /etc/exabgp/exabgp.conf >/dev/null
}
start_announcer "$announcer_a" oracle-announcer-as64496.conf 198.51.100.2 2001:db8:5100::2
start_announcer "$announcer_b" oracle-announcer-as64497.conf 198.51.100.4 2001:db8:5100::4

# Live: same ASN, router ID, descriptions, and accept-all policy as the oracle.
socket=$tmp/rustbgpd.sock
aliases=$tmp/protocol-aliases
mkdir -p "$tmp/runtime"
printf '%s\n' \
  'pb_as64496=198.51.100.2@master4' \
  'pb6_as64496=2001:db8:5100::2@master6' \
  'pb_as64497=198.51.100.4@master4' \
  'pb6_as64497=2001:db8:5100::4@master6' >"$aliases"
cat >"$tmp/rustbgpd.toml" <<CONF
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

[policy.definitions.accept-all]
default_action = "permit"

[[neighbors]]
address = "198.51.100.2"
remote_asn = 64496
description = "oracle client AS64496"
route_server_client = true
graceful_restart = false
hold_time = 240
families = ["ipv4_unicast"]
import_policy_chain = ["accept-all"]
export_policy_chain = ["accept-all"]

[[neighbors]]
address = "2001:db8:5100::2"
remote_asn = 64496
description = "oracle client AS64496 IPv6"
route_server_client = true
graceful_restart = false
hold_time = 240
families = ["ipv6_unicast"]
import_policy_chain = ["accept-all"]
export_policy_chain = ["accept-all"]

[[neighbors]]
address = "198.51.100.4"
remote_asn = 64497
description = "oracle client AS64497"
route_server_client = true
graceful_restart = false
hold_time = 240
families = ["ipv4_unicast"]
import_policy_chain = ["accept-all"]
export_policy_chain = ["accept-all"]

[[neighbors]]
address = "2001:db8:5100::4"
remote_asn = 64497
description = "oracle client AS64497 IPv6"
route_server_client = true
graceful_restart = false
hold_time = 240
families = ["ipv6_unicast"]
import_policy_chain = ["accept-all"]
export_policy_chain = ["accept-all"]
CONF

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
  --protocol-alias-file "$aliases" --max-routes 100 \
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
live_api=http://127.0.0.1:$port

# Both legs must hold every route from both announcers in both tables before
# the consumer reads them: 4 IPv4 (3 + 1) and 3 IPv6 (2 + 1).
table_size() {
  curl --silent --max-time 5 "$1/routes/table/$2" | python3 -c \
    'import json,sys; print(len(json.load(sys.stdin).get("routes", [])))' 2>/dev/null || echo -1
}
converged() {
  [ "$(table_size "$oracle_api" master4)" = 4 ] && [ "$(table_size "$oracle_api" master6)" = 3 ] \
    && [ "$(table_size "$live_api" master4)" = 4 ] && [ "$(table_size "$live_api" master6)" = 3 ]
}
for _ in $(seq 1 180); do
  if converged; then break; fi
  kill -0 "$daemon_pid" 2>/dev/null || { cat "$tmp/daemon.log" >&2; exit 1; }
  sleep 1
done
if ! converged; then
  echo "populated oracle leg did not converge: oracle master4=$(table_size "$oracle_api" master4) master6=$(table_size "$oracle_api" master6) live master4=$(table_size "$live_api" master4) master6=$(table_size "$live_api" master6)" >&2
  docker exec "$oracle" cat /tmp/birdseye.log >&2 || true
  docker logs "$announcer_a" >&2 || true
  tail -n 40 "$tmp/daemon.log" >&2
  exit 1
fi
# Let BIRD's route-change counters and both legs' session timers settle on one
# stable snapshot before reading.
sleep 3

run_consumer() {
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    --env IXP_MANAGER_ROOT=/upstreams/ixp-manager \
    --env BIRDSEYE_API="$1" \
    --volume "$root:/harness:ro" \
    --volume "$ixp_manager:/upstreams/ixp-manager:ro" \
    "$image" php /harness/oracle-consumer.php >"$2"
  [ -s "$2" ]
}
run_consumer "$oracle_api" "$capture_output/populated-oracle.raw.json"
run_consumer "$live_api" "$capture_output/populated-live.raw.json"
chmod 600 "$capture_output/populated-oracle.raw.json" "$capture_output/populated-live.raw.json"
