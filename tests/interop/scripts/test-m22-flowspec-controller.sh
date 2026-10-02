#!/usr/bin/env bash
# Run on a fresh M22 deployment, separately from test-m22-flowspec-frr.sh.
# Optional first argument: directory for JSON observations and result receipt.
TOPO="m22-flowspec-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"

OUTPUT="${1:-$(mktemp -d /tmp/m22-flowspec-controller.XXXXXXXX)/observations}"
if [ -e "$OUTPUT" ]; then
    echo "ERROR: observation directory already exists: $OUTPUT" >&2
    exit 1
fi
log "Controller observations: $OUTPUT"
resolve_grpc_addr
SOURCE="clab-${TOPO}-source"
SOURCE_GRPC_ADDR="$(resolve_ip "$SOURCE"):50051"
FRR="clab-${TOPO}-frr"
if rustbgpd_running; then
    echo "ERROR: controller qualification requires a fresh M22 deployment" >&2
    exit 1
fi
if docker exec "$SOURCE" sh -c 'grep -q rustbgpd /proc/*/comm 2>/dev/null'; then
    echo "ERROR: controller qualification requires a fresh source container" >&2
    exit 1
fi
docker cp tests/interop/configs/rustbgpd-m22-controller.toml "$RUSTBGPD:/tmp/controller.toml"
# Keep the existing IPv4 validation fixture unchanged; this run adds IPv6
# FlowSpec to the source and observer only inside its disposable containers.
docker exec "$SOURCE" sh -c 'sed "s/\"ipv4_flowspec\"/\"ipv4_flowspec\", \"ipv6_flowspec\"/" /etc/rustbgpd/config.toml > /tmp/controller.toml'
docker exec "$FRR" vtysh -c 'configure terminal' -c 'router bgp 65002' \
    -c 'address-family ipv6 flowspec' -c 'neighbor 10.0.0.1 activate'
start_rustbgpd '/usr/local/bin/rustbgpd /tmp/controller.toml > /tmp/controller.log 2>&1'
start_source() {
    local RUSTBGPD="$SOURCE" GRPC_ADDR="$SOURCE_GRPC_ADDR"
    start_rustbgpd '/usr/local/bin/rustbgpd /tmp/controller.toml > /tmp/controller.log 2>&1'
}
start_source
python3 "$SCRIPT_DIR/m22_flowspec_controller.py" \
    --grpc "$GRPC_ADDR" --source-grpc "$SOURCE_GRPC_ADDR" \
    --daemon "$RUSTBGPD" --frr "$FRR" \
    --output "$OUTPUT"
