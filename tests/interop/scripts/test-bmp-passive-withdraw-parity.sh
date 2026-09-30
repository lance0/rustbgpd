#!/usr/bin/env bash
# Run after deploying tests/interop/bmp-passive-withdraw-parity.clab.yml.
# Captures the actual BGP sends and raw BMPv3 receives for a bounded passive
# two-peer test. ARTIFACT_DIR names an owned output directory.
set -euo pipefail

TOPO=bmp-passive-withdraw-parity
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

PE1=clab-${TOPO}-gobgp-pe1
PE2=clab-${TOPO}-gobgp-pe2
SINK=clab-${TOPO}-bmpsink
CAP=bmp-passive-bgp-capture
CAP_CREATED=0
CHECKER="$SCRIPT_DIR/check-bmp-passive-withdraw-parity.py"
ARTIFACT_DIR=${ARTIFACT_DIR:?set ARTIFACT_DIR to an owned receipt directory}
mkdir -p "$ARTIFACT_DIR"

cleanup_capture() {
    if [ "$CAP_CREATED" -eq 1 ]; then
        docker rm -f "$CAP" >/dev/null 2>&1 || true
    fi
}
on_exit() {
    local status=$?
    cleanup_capture
    set +e  # Feed the original status to test-lib's cleanup handler.
    (exit "$status")
    _cleanup_on_exit
    exit "$status"
}
trap on_exit EXIT

if [ "${1:-}" = --self-test-cleanup ]; then
    CAP_CREATED=1
    case ${2:-} in
        success) exit 0 ;;
        failure) exit 7 ;;
        signal) kill -TERM "$$" ;;
        *) exit 2 ;;
    esac
fi
command -v tshark >/dev/null || { echo 'ERROR: host tshark is required' >&2; exit 1; }

peer_established() {
    docker exec "$1" gobgp neighbor "$2" 2>/dev/null | grep -qi 'establ'
}

peer_down() {
    ! peer_established "$1" "$2"
}

flap() {
    local container=$1 rr_addr=$2
    docker exec "$container" gobgp neighbor "$rr_addr" disable
    wait_until 30 1 peer_down "$container" "$rr_addr"
    docker exec "$container" gobgp neighbor "$rr_addr" enable
    wait_until 60 1 peer_established "$container" "$rr_addr"
}

log "Starting raw sink and BGP capture"
docker exec "$SINK" rm -f /tmp/bmp-raw-11019.jsonl
docker exec -d "$SINK" python3 /usr/local/bin/bmp-raw-sink.py
sleep 1
docker run -d --name "$CAP" --network "container:$RUSTBGPD" \
    --cap-add NET_RAW --cap-add NET_ADMIN bmpsink:m81 \
    tshark -i any -f 'tcp port 179' -w /tmp/bgp.pcapng >/dev/null
CAP_CREATED=1
wait_capture_ready "$CAP" /tmp/bgp.pcapng -

sink_ip=$(resolve_ip "$SINK")
test -n "$sink_ip"
docker exec "$RUSTBGPD" sh -c \
    "sed 's/SINK_ADDR/$sink_ip/' /etc/rustbgpd/config.toml > /tmp/config.toml"
resolve_grpc_addr
start_rustbgpd 'exec /usr/local/bin/rustbgpd /tmp/config.toml >/tmp/rustbgpd-bmp-passive.log 2>&1'
for peer in "$PE1" "$PE2"; do
    docker exec -d "$peer" sh -c \
        'exec gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
done
wait_until 60 1 peer_established "$PE1" 10.0.0.1
wait_until 60 1 peer_established "$PE2" 10.0.1.1

log "Three eight-prefix rounds per peer; two controlled flaps per peer"
for round in 1 2 3; do
    for idx in $(seq 1 8); do
        docker exec "$PE1" gobgp global rib add "198.18.164.$idx/32" nexthop 10.0.0.2
        docker exec "$PE2" gobgp global rib add "198.18.165.$idx/32" nexthop 10.0.1.2
    done
    sleep 1
    for idx in $(seq 1 8); do
        docker exec "$PE1" gobgp global rib del "198.18.164.$idx/32"
        docker exec "$PE2" gobgp global rib del "198.18.165.$idx/32"
    done
    sleep 1
    if [ "$round" -lt 3 ]; then
        flap "$PE1" 10.0.0.1
        flap "$PE2" 10.0.1.1
    fi
done

log "Freezing captures after BMP delivery settles"
sleep 5
docker kill --signal=INT "$CAP" >/dev/null
timeout 15 docker wait "$CAP" >/dev/null
docker cp "$CAP:/tmp/bgp.pcapng" "$ARTIFACT_DIR/bgp.pcapng"
docker cp "$SINK:/tmp/bmp-raw-11019.jsonl" "$ARTIFACT_DIR/bmp.jsonl"
docker cp "$RUSTBGPD:/tmp/rustbgpd-bmp-passive.log" "$ARTIFACT_DIR/rustbgpd.log"
tshark -r "$ARTIFACT_DIR/bgp.pcapng" \
    -Y 'bgp.type == 2 && bgp.withdrawn_prefix && (ip.src == 10.0.0.2 || ip.src == 10.0.1.2) && !tcp.analysis.retransmission' \
    -T fields -E separator=/t -E occurrence=a -E aggregator=, \
    -e ip.src -e bgp.withdrawn_prefix > "$ARTIFACT_DIR/bgp-withdrawals.tsv"

export_announces=$(tshark -r "$ARTIFACT_DIR/bgp.pcapng" \
    -Y 'bgp.type == 2 && bgp.nlri_prefix && (ip.src == 10.0.0.1 || ip.src == 10.0.1.1)' \
    -T fields -e bgp.nlri_prefix | wc -l)
test "$export_announces" -eq 0
python3 "$CHECKER" "$ARTIFACT_DIR/bgp-withdrawals.tsv" "$ARTIFACT_DIR/bmp.jsonl" \
    > "$ARTIFACT_DIR/result.json"

# Negative control on the actual capture: erase one BMP wire withdrawal.
python3 - "$ARTIFACT_DIR/bmp.jsonl" "$ARTIFACT_DIR/bmp-dropped.jsonl" <<'PY'
import json
import sys

dropped = False
with open(sys.argv[1], encoding="utf-8") as source, open(sys.argv[2], "w", encoding="utf-8") as target:
    for line in source:
        row = json.loads(line)
        raw = bytes.fromhex(row["hex"])
        if not dropped and row["type"] == 0 and int.from_bytes(raw[67:69], "big"):
            dropped = True
            continue
        target.write(line)
if not dropped:
    sys.exit("no BMP withdrawal available for negative control")
PY
if python3 "$CHECKER" "$ARTIFACT_DIR/bgp-withdrawals.tsv" \
    "$ARTIFACT_DIR/bmp-dropped.jsonl" > "$ARTIFACT_DIR/negative-control.log" 2>&1; then
    echo 'FAIL: dropped BMP withdrawal passed parity check' >&2
    exit 1
fi
grep -q 'withdrawal mismatch' "$ARTIFACT_DIR/negative-control.log"
rm "$ARTIFACT_DIR/bmp-dropped.jsonl"
printf 'empty_export_announcements=%s\n' "$export_announces" \
    > "$ARTIFACT_DIR/export-check.txt"
cat "$ARTIFACT_DIR/result.json"
cat "$ARTIFACT_DIR/negative-control.log"
