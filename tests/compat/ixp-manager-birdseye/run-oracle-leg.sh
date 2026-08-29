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
alice_source=${4:?Alice-LG checkout is required}
alice_image=${5:?Alice-LG image is required}
manrs_source=${6:?MANRS checkout is required}
manrs_image=${7:?MANRS image is required}
capture_output=${CAPTURE_OUTPUT:?capture output directory is required}
tmp=$(mktemp -d)
network=rustbgpd-ixp-oracle-$$
oracle=rustbgpd-ixp-oracle-$$
announcer_a=rustbgpd-ixp-announcer-as64496-$$
announcer_b=rustbgpd-ixp-announcer-as64497-$$
alice=rustbgpd-ixp-alice-$$
manrs=rustbgpd-ixp-manrs-$$
exabgp='ghcr.io/exa-networks/exabgp@sha256:5554ac053766e66ca3b99eb6b66e83e32113913729a184dcbaf0cc4abd2f4244'
daemon_pid=
adapter_pid=
dump_proof_logs() {
  [ ! -f "$tmp/daemon.log" ] || { echo '--- rustbgpd log ---' >&2; tail -n 80 "$tmp/daemon.log" >&2; }
  [ ! -f "$tmp/adapter.log" ] || { echo '--- adapter log ---' >&2; tail -n 80 "$tmp/adapter.log" >&2; }
  if docker inspect "$alice" >/dev/null 2>&1; then
    echo '--- Alice-LG log ---' >&2
    docker logs "$alice" >&2 || true
  fi
  if docker inspect "$manrs" >/dev/null 2>&1; then
    echo '--- MANRS log ---' >&2
    docker logs "$manrs" >&2 || true
  elif [ -f "$tmp/manrs.out" ]; then
    echo '--- MANRS output ---' >&2
    cat "$tmp/manrs.out" >&2
  fi
}
cleanup() {
  status=$?
  [ "$status" -eq 0 ] || dump_proof_logs
  [ -z "$adapter_pid" ] || kill "$adapter_pid" 2>/dev/null || true
  [ -z "$daemon_pid" ] || kill "$daemon_pid" 2>/dev/null || true
  docker rm --force "$manrs" "$alice" >/dev/null 2>&1 || true
  docker rm --force "$oracle" "$announcer_a" "$announcer_b" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

read_manifest() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
    "$root/contract.json" "$1"
}
alice_commit=$(read_manifest alice_lg_commit)
alice_version=$(read_manifest alice_lg_version)
manrs_commit=$(read_manifest manrs_commit)
[ "$(git -C "$alice_source" rev-parse HEAD)" = "$alice_commit" ]
[ "$(tr -d '\n' <"$alice_source/VERSION")" = "$alice_version" ]
[ "$(git -C "$manrs_source" rev-parse HEAD)" = "$manrs_commit" ]
[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$alice_image")" = "$alice_commit" ]
[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$alice_image")" = "$alice_version" ]
[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$manrs_image")" = "$manrs_commit" ]

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

container_running() {
  [ "$(docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null || true)" = true ]
}
topology_containers_running() {
  container_running "$oracle" \
    && container_running "$announcer_a" \
    && container_running "$announcer_b"
}

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
  kill -0 "$daemon_pid" 2>/dev/null && topology_containers_running || exit 1
  sleep 0.1
done
[ -S "$socket" ] || exit 1
NO_COLOR=1 "$repo/target/debug/birdwatcher-adapter" \
  --grpc-addr "unix://$socket" --listen 0.0.0.0:0 \
  --protocol-alias-file "$aliases" --max-routes 100 \
  >"$tmp/adapter.out" 2>"$tmp/adapter.log" &
adapter_pid=$!
port=
for _ in $(seq 1 120); do
  port=$(grep -o '0\.0\.0\.0:[0-9][0-9]*' "$tmp/adapter.log" | tail -1 | cut -d: -f2 || true)
  [ -z "$port" ] || break
  kill -0 "$daemon_pid" 2>/dev/null \
    && kill -0 "$adapter_pid" 2>/dev/null \
    && topology_containers_running || exit 1
  sleep 0.1
done
[ -n "$port" ] || exit 1
live_api=http://127.0.0.1:$port

sed "s/__ADAPTER_PORT__/$port/" "$root/alice.conf" >"$tmp/alice.conf"
docker run --detach --name "$alice" --network "$network" \
  --ip 198.51.100.5 \
  --volume "$tmp/alice.conf:/etc/alice-lg/alice.conf:ro" \
  "$alice_image" -config /etc/alice-lg/alice.conf >/dev/null
alice_api=http://198.51.100.5:7340/api/v1
alice_ready() {
  curl --fail --silent --max-time 2 "$alice_api/status" | python3 -c \
    'import json,sys; assert json.load(sys.stdin).get("version") == "6.2.0"' \
    >/dev/null 2>&1
}
alice_deadline=$(($(date +%s) + 115))
while [ "$(date +%s)" -lt "$alice_deadline" ]; do
  if alice_ready; then break; fi
  kill -0 "$daemon_pid" 2>/dev/null \
    && kill -0 "$adapter_pid" 2>/dev/null \
    && topology_containers_running \
    && container_running "$alice" || exit 1
  sleep 1
done
alice_ready || exit 1

# Both legs must hold every route from both announcers in both tables before
# the consumer reads them: 4 IPv4 (3 + 1) and 3 IPv6 (2 + 1).
table_size() {
  curl --silent --max-time 1 "$1/routes/table/$2" | python3 -c \
    'import json,sys; print(len(json.load(sys.stdin).get("routes", [])))' 2>/dev/null || echo -1
}
converged() {
  [ "$(table_size "$oracle_api" master4)" = 4 ] && [ "$(table_size "$oracle_api" master6)" = 3 ] \
    && [ "$(table_size "$live_api" master4)" = 4 ] && [ "$(table_size "$live_api" master6)" = 3 ]
}
convergence_deadline=$(($(date +%s) + 110))
while [ "$(date +%s)" -lt "$convergence_deadline" ]; do
  if converged; then break; fi
  kill -0 "$daemon_pid" 2>/dev/null \
    && kill -0 "$adapter_pid" 2>/dev/null \
    && topology_containers_running \
    && container_running "$alice" || exit 1
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

alice_proof='alice consumer proof: Alice-LG 6.2.0 read rs0 with 4 up neighbors, 7 accepted routes, 0 filtered routes, and the labeled split-horizon noexport route'
timeout 60s python3 "$root/alice-consumer.py" "$alice_api" >"$tmp/alice-consumer.out"
[ "$(grep -Fxc "$alice_proof" "$tmp/alice-consumer.out")" -eq 1 ]
cat "$tmp/alice-consumer.out" >&2

timeout 120s docker run --name "$manrs" --network "$network" \
  --volume "$root/manrs-roas.json:/proof/manrs-roas.json:ro" \
  "$manrs_image" --alice-url "$alice_api" \
  --alice-rs-group rustbgpd-contract /proof/manrs-roas.json \
  >"$tmp/manrs.out" 2>&1
python3 - "$tmp/manrs.out" <<'PY'
import sys

text = open(sys.argv[1], encoding="utf-8").read()
community = "Using BGP communities 65001:1000:4:* as expected RPKI invalid"
summary = "Processed 7 route entries, 5 ROAs, found 1 unexpected RPKI invalid entries"
if text.splitlines().count(community) != 1:
    raise SystemExit("MANRS proof omitted the Alice-derived RPKI community")
if text.splitlines().count(summary) != 1:
    raise SystemExit("MANRS proof summary drifted")
if sum(line.startswith("RPKI invalid:") for line in text.splitlines()) != 1:
    raise SystemExit("MANRS proof did not emit exactly one invalid stanza")
start = text.index("RPKI invalid:")
end = text.index(summary)
actual = text[start:end].strip()
expected = """RPKI invalid: prefix 203.0.113.0/24 from origin AS64520
Received from peer: 198.51.100.2 AS64496
AS path: 64496 64510 64520
Communities: 64496:100 64496:1:1 64496:1:2 64496:200
Source: Alice LG route server rs0 peer pb_as64496
ROAs found:
    Prefix 203.0.113.0/24, ASN 64496, max length 26"""
if actual != expected:
    raise SystemExit(f"MANRS invalid stanza drifted:\n{actual}")
lower = text.lower()
for marker in ("traceback", "decoder error", "decode error"):
    if marker in lower:
        raise SystemExit(f"MANRS output contains {marker!r}")
PY
echo 'MANRS proof: pinned validator traversed 7 Alice-LG received routes and found exactly one deliberate synthetic ROA mismatch' >&2

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

# Deterministic backend-failure journey, captured last so every journey above
# read a healthy backend: stop rustbgpd under the still-running adapter (its
# next gRPC call fails, HTTP 502) and BIRD under the still-running Bird's Eye
# (birdc fails, its own HTTP 503), then record one api/status probe per leg
# directly — the pinned consumer collapses every non-2xx to "". Nothing after
# this point reads either backend; teardown follows.
kill "$daemon_pid"
wait "$daemon_pid" 2>/dev/null || true
daemon_pid=
docker exec "$oracle" birdc -s /run/bird/bird.ctl down >/dev/null 2>&1 || true
docker exec "$oracle" sh -c \
  'for _ in $(seq 1 100); do [ ! -S /run/bird/bird.ctl ] && exit 0; sleep 0.1; done; exit 1'
probe_failure() {
  curl --silent --max-time 10 --header 'Accept: application/json' \
    --output "$2" --write-out '%{http_code}' "$1/status"
}
live_failure_status=$(probe_failure "$live_api" "$tmp/live-failure-body.json")
oracle_failure_status=$(probe_failure "$oracle_api" "$tmp/oracle-failure-body.json")
merge_backend_failure() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

path, status, body_path = sys.argv[1:4]
with open(path) as handle:
    document = json.load(handle)
with open(body_path) as handle:
    body = json.load(handle)
document["journeys"]["backend_failure"] = {
    "endpoint": "api/status",
    "response": json.dumps({"http_status": int(status), "body": body}),
}
with open(path, "w") as handle:
    json.dump(document, handle, indent=4)
    handle.write("\n")
PY
}
merge_backend_failure "$capture_output/populated-live.raw.json" \
  "$live_failure_status" "$tmp/live-failure-body.json"
merge_backend_failure "$capture_output/populated-oracle.raw.json" \
  "$oracle_failure_status" "$tmp/oracle-failure-body.json"
echo "backend failure journey: live adapter answered HTTP $live_failure_status, oracle Bird's Eye answered HTTP $oracle_failure_status" >&2
chmod 600 "$capture_output/populated-oracle.raw.json" "$capture_output/populated-live.raw.json"
