#!/usr/bin/env bash
# Local released-rustbgpd -> pinned-main trial; no external RR qualification.
# Deploy rr-upgrade-bmp-trial.clab.yml first. See rr-upgrade-bmp-trial.md.
set -euo pipefail

TOPO=rr-upgrade-bmp-trial
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MAIN=clab-${TOPO}-main
OLD=clab-${TOPO}-incumbent
SOURCE=clab-${TOPO}-originator
OBSERVER=clab-${TOPO}-observer
SINK=clab-${TOPO}-bmpsink
RUSTBGPD=$MAIN
INTEROP_TEST_OPERATOR_AUTH=1
CLEANUP=${CLEANUP:-1}
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

readonly MAIN_COMMIT=56cc5c4af5a607951915d175966de17241fca9a9
readonly OLD_COMMIT=54ed19b5af927f1c8e5064ecb1a497885c15d068
readonly ARCHIVE_SHA=9aa9fe9f84162085ee5eef13f5090981550f1f45a5f9c3b37347178cff990489
readonly PREFIX=198.51.100.0/24
ARTIFACT_DIR=${ARTIFACT_DIR:?set an empty owned receipt directory}
RELEASE_ARCHIVE=${RELEASE_ARCHIVE:?supply the original v0.75.0 linux-amd64 archive}
RR_MAIN_IMAGE=${RR_MAIN_IMAGE:?set the immutable pinned-main image ID}
RR_MAIN_IMAGE_ALIAS=${RR_MAIN_IMAGE_ALIAS:?set an owned retained image alias for containerlab}
CHECKER=$SCRIPT_DIR/check-rr-upgrade-bmp-trial.py
case "$RR_MAIN_IMAGE" in sha256:*) ;; *) echo 'immutable RR_MAIN_IMAGE required' >&2; exit 2 ;; esac
case "$RR_MAIN_IMAGE_ALIAS" in rustbgpd:rr-upgrade-*) ;; *) echo 'use an owned rustbgpd:rr-upgrade-* alias' >&2; exit 2 ;; esac
test "$(docker image inspect -f '{{.Id}}' "$RR_MAIN_IMAGE_ALIAS")" = "$RR_MAIN_IMAGE"
mkdir -p "$ARTIFACT_DIR"
test -z "$(ls -A "$ARTIFACT_DIR")"
ARTIFACT_DIR=$(cd "$ARTIFACT_DIR" && pwd)

retain_logs() {
    local status=$? cleanup_status=0 node
    trap - EXIT
    for node in "$MAIN" "$OLD" "$SOURCE" "$OBSERVER"; do
        docker cp "$node:/tmp/daemon.log" "$ARTIFACT_DIR/$node.log" 2>/dev/null || true
    done
    docker cp "$SINK:/tmp/sink.log" "$ARTIFACT_DIR/sink.log" 2>/dev/null || true
    printf '%s\n' "$status" > "$ARTIFACT_DIR/driver.exit"
    if [ "$CLEANUP" = 1 ]; then
        containerlab destroy -t "$SCRIPT_DIR/../$TOPO.clab.yml" --cleanup \
            > "$ARTIFACT_DIR/cleanup.log" 2>&1 || cleanup_status=$?
        printf '%s\n' "$cleanup_status" > "$ARTIFACT_DIR/cleanup.exit"
        if [ "$status" -eq 0 ]; then status=$cleanup_status; fi
    fi
    exit "$status"
}
trap retain_logs EXIT

log "Checking exact source, release archive, and existing peer binaries"
test "$(uname -m)" = x86_64
git diff --quiet "$MAIN_COMMIT" -- Cargo.toml Cargo.lock .cargo src crates proto bench benches examples tools
test -z "$(git ls-files --others --exclude-standard -- .cargo src crates proto bench benches examples tools)"
tree_id=$(bash scripts/source-id.sh)
for node in "$MAIN" "$OLD"; do
    test "$(docker inspect -f '{{.Image}}' "$node")" = "$RR_MAIN_IMAGE"
    test "$(docker exec "$node" cat /usr/local/share/rustbgpd/source-id)" = "$tree_id"
done
printf '%s  %s\n' "$ARCHIVE_SHA" "$RELEASE_ARCHIVE" | sha256sum --check --strict > "$ARTIFACT_DIR/release-archive-check.txt"
mkdir "$ARTIFACT_DIR/release"
tar -xzf "$RELEASE_ARCHIVE" -C "$ARTIFACT_DIR/release" rustbgpd
docker exec "$OLD" mkdir /opt/incumbent
docker cp "$ARTIFACT_DIR/release/rustbgpd" "$OLD:/opt/incumbent/rustbgpd"
docker cp "$MAIN:/usr/local/bin/rbgp" "$ARTIFACT_DIR/rbgp"
RBGP=$ARTIFACT_DIR/rbgp
test "$(docker exec "$OLD" /opt/incumbent/rustbgpd --version)" = 'rustbgpd 0.75.0'
for node in "$SOURCE" "$OBSERVER"; do
    test "$(docker exec "$node" gobgp --version)" = 'gobgp version 4.10.0'
    test "$(docker exec "$node" gobgpd --version)" = 'gobgpd version 4.10.0'
    test "$(docker exec "$node" sha256sum /usr/local/bin/gobgp | cut -d' ' -f1)" = 55eded2e53f5c597baab409f69d18729292a6e28084fd0ce2be9b5383a406f86
    test "$(docker exec "$node" sha256sum /usr/local/bin/gobgpd | cut -d' ' -f1)" = bea17d8561b776cb35820ce14601a617e26acb1efa687b9d949a1737ee2f670d
done
docker inspect "$MAIN" "$OLD" "$SOURCE" "$OBSERVER" "$SINK" > "$ARTIFACT_DIR/containers.json"
{
    printf 'main_commit=%s\nrelease_commit=%s\nmain_source_id=%s\n' "$MAIN_COMMIT" "$OLD_COMMIT" "$tree_id"
    docker exec "$MAIN" rustbgpd --version
    docker exec "$MAIN" sha256sum /usr/local/bin/rustbgpd /usr/local/bin/rbgp
    docker exec "$OLD" /opt/incumbent/rustbgpd --version
    docker exec "$OLD" sha256sum /opt/incumbent/rustbgpd
} > "$ARTIFACT_DIR/versions.txt"

main_ip=$(resolve_ip "$MAIN")
old_ip=$(resolve_ip "$OLD")
source_ip=$(resolve_ip "$SOURCE")
observer_ip=$(resolve_ip "$OBSERVER")
sink_ip=$(resolve_ip "$SINK")
for address in "$main_ip" "$old_ip" "$source_ip" "$observer_ip" "$sink_ip"; do test -n "$address"; done

rr_config() {
    local name=$1 identity=$2 cluster=$3 port=$4
    sed -e "s/RR_ID/$identity/g" -e "s/CLUSTER_ID/$cluster/g" \
        -e "s/SINK_ADDR/$sink_ip/g" -e "s/SINK_PORT/$port/g" \
        -e "s/ORIGINATOR_ADDR/$source_ip/g" -e "s/OBSERVER_ADDR/$observer_ip/g" \
        tests/interop/configs/rustbgpd-rr-upgrade-bmp.toml > "$ARTIFACT_DIR/$name.toml"
}
rr_config incumbent 192.0.2.10 192.0.2.1 11019
rr_config main-equal 192.0.2.11 192.0.2.1 11020
rr_config main-divergent 192.0.2.11 192.0.2.2 11020
for role in originator observer; do
    identity=192.0.2.20
    if [ "$role" = observer ]; then identity=192.0.2.30; fi
    sed -e "s/PEER_ID/$identity/g" -e "s/INCUMBENT_ADDR/$old_ip/g" -e "s/MAIN_ADDR/$main_ip/g" \
        tests/interop/configs/gobgp-rr-upgrade-bmp.toml > "$ARTIFACT_DIR/$role.toml"
    docker cp "$ARTIFACT_DIR/$role.toml" "clab-${TOPO}-$role:/tmp/config.toml"
done
docker cp "$ARTIFACT_DIR/incumbent.toml" "$OLD:/tmp/config.toml"
docker cp "$ARTIFACT_DIR/main-equal.toml" "$MAIN:/tmp/config.toml"
docker exec "$OLD" /opt/incumbent/rustbgpd --check --strict /tmp/config.toml > "$ARTIFACT_DIR/incumbent-config-check.log" 2>&1
docker exec "$MAIN" rustbgpd --check --strict /tmp/config.toml > "$ARTIFACT_DIR/main-config-check.log" 2>&1

sink_ready() { docker exec "$SINK" sh -c 'grep -q "listening on :11019" /tmp/sink.log && grep -q "listening on :11020" /tmp/sink.log'; }
collector_ready() {
    docker exec "$SINK" python3 -c '
import json, pathlib, sys
try:
    rows = [json.loads(line) for line in pathlib.Path("/tmp/bmp-raw-" + sys.argv[1] + ".jsonl").read_text().splitlines()]
    sys.exit(0 if any(row["conn"] == int(sys.argv[2]) and row["type"] == 4 for row in rows) else 1)
except (OSError, ValueError):
    sys.exit(1)
' "$1" "$2"
}
peer_ready() {
    local state
    state=$(docker exec "$1" gobgp neighbor "$2") || return 1
    grep -qi 'BGP state = ESTABLISHED' <<<"$state"
}
peer_down() { ! peer_ready "$1" "$2"; }
observer_ready() {
    local peer=$1 cluster=$2 output=$3
    docker exec "$OBSERVER" gobgp neighbor "$peer" adj-in -a ipv4 -j > "$output" &&
        python3 "$CHECKER" observer "$output" "$source_ip" "$cluster" > "$output.check.json"
}
start_rr() {
    RUSTBGPD=$1
    resolve_grpc_addr
    start_rustbgpd "echo \$\$ > /tmp/daemon.pid; exec $2 /tmp/config.toml >>/tmp/daemon.log 2>&1"
}

log "Starting both BMP collectors before any RR peer session"
docker exec "$SINK" sh -c 'test ! -e /tmp/bmp-raw-11019.jsonl && test ! -e /tmp/bmp-raw-11020.jsonl'
docker exec -d "$SINK" sh -c 'exec python3 /usr/local/bin/bmp-raw-sink.py >/tmp/sink.log 2>&1'
wait_until 10 1 sink_ready
start_rr "$OLD" /opt/incumbent/rustbgpd
start_rr "$MAIN" /usr/local/bin/rustbgpd
wait_until 30 1 collector_ready 11019 0
wait_until 30 1 collector_ready 11020 0
for node in "$SOURCE" "$OBSERVER"; do
    docker exec -d "$node" sh -c 'exec gobgpd -f /tmp/config.toml >/tmp/daemon.log 2>&1'
    wait_until 60 1 peer_ready "$node" "$old_ip"
    wait_until 60 1 peer_ready "$node" "$main_ip"
done
docker exec "$SOURCE" gobgp global rib add "$PREFIX" nexthop "$source_ip"

convert_phase() {
    local phase=$1 connection=$2 cluster=$3 generation=$4
    docker cp "$SINK:/tmp/bmp-raw-11019.jsonl" "$ARTIFACT_DIR/$phase/incumbent.jsonl" &&
    docker cp "$SINK:/tmp/bmp-raw-11020.jsonl" "$ARTIFACT_DIR/$phase/main.jsonl" &&
    python3 "$CHECKER" capture "$ARTIFACT_DIR/$phase/incumbent.jsonl" 0 "$observer_ip" "$ARTIFACT_DIR/$phase/incumbent.bmp" > "$ARTIFACT_DIR/$phase/incumbent-capture.json" &&
    python3 "$CHECKER" capture "$ARTIFACT_DIR/$phase/main.jsonl" "$connection" "$observer_ip" "$ARTIFACT_DIR/$phase/main.bmp" > "$ARTIFACT_DIR/$phase/main-capture.json" &&
    "$RBGP" diff snapshot from-bmp "$ARTIFACT_DIR/$phase/incumbent.bmp" --neighbor "$observer_ip" --generation "$generation" > "$ARTIFACT_DIR/$phase/incumbent.ndjson" &&
    "$RBGP" diff snapshot from-bmp "$ARTIFACT_DIR/$phase/main.bmp" --neighbor "$observer_ip" --generation "$generation" > "$ARTIFACT_DIR/$phase/main.ndjson" &&
    python3 "$CHECKER" snapshot "$ARTIFACT_DIR/$phase/incumbent.ndjson" "$observer_ip" "$source_ip" 192.0.2.1 > "$ARTIFACT_DIR/$phase/incumbent-snapshot.json" &&
    python3 "$CHECKER" snapshot "$ARTIFACT_DIR/$phase/main.ndjson" "$observer_ip" "$source_ip" "$cluster" > "$ARTIFACT_DIR/$phase/main-snapshot.json"
}
phase() {
    local name=$1 connection=$2 cluster=$3 generation=$4 expected=$5 status=0
    mkdir "$ARTIFACT_DIR/$name"
    wait_until 60 1 observer_ready "$old_ip" 192.0.2.1 "$ARTIFACT_DIR/$name/observer-incumbent.json"
    wait_until 60 1 observer_ready "$main_ip" "$cluster" "$ARTIFACT_DIR/$name/observer-main.json"
    docker exec "$OBSERVER" gobgp neighbor "$old_ip" -j > "$ARTIFACT_DIR/$name/observer-incumbent-session.json"
    docker exec "$OBSERVER" gobgp neighbor "$main_ip" -j > "$ARTIFACT_DIR/$name/observer-main-session.json"
    convert_phase "$name" "$connection" "$cluster" "$generation"
    "$RBGP" diff snapshots "$ARTIFACT_DIR/$name/incumbent.ndjson" "$ARTIFACT_DIR/$name/main.ndjson" --json > "$ARTIFACT_DIR/$name/diff.json" || status=$?
    printf '%s\n' "$status" > "$ARTIFACT_DIR/$name/diff.exit"
    test "$status" -eq "$expected"
    python3 "$CHECKER" report "$ARTIFACT_DIR/$name/diff.json" "$name" > "$ARTIFACT_DIR/$name/result.json"
}

phase equal 0 192.0.2.1 1 0
log "Changing only main's configured cluster ID and restarting its RR"
for node in "$SOURCE" "$OBSERVER"; do
    docker exec "$node" gobgp neighbor "$main_ip" disable
    wait_until 30 1 peer_down "$node" "$main_ip"
done
docker exec "$MAIN" sh -c 'kill -TERM "$(cat /tmp/daemon.pid)"'
main_stopped() { ! docker exec "$MAIN" sh -c 'kill -0 "$(cat /tmp/daemon.pid)" 2>/dev/null'; }
wait_until 30 1 main_stopped
docker cp "$ARTIFACT_DIR/main-divergent.toml" "$MAIN:/tmp/config.toml"
start_rr "$MAIN" /usr/local/bin/rustbgpd
wait_until 30 1 collector_ready 11020 1
for node in "$SOURCE" "$OBSERVER"; do docker exec "$node" gobgp neighbor "$main_ip" enable; done
wait_until 60 1 peer_ready "$SOURCE" "$main_ip"
wait_until 60 1 peer_ready "$OBSERVER" "$main_ip"
phase divergent 1 192.0.2.2 2 1
log "PASS: genuine RR upgrade equality and configured cluster-list divergence"
