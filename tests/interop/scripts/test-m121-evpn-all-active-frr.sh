#!/usr/bin/env bash
# M121: run fresh preference-DF cells and the explicit default-modulo hazard.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TOPO=m121-evpn-all-active-frr
CONTROLLER="clab-${TOPO}-controller"
COMPARE_HISTORICAL="${M121_COMPARE_HISTORICAL-0}"
case "$COMPARE_HISTORICAL" in
    0|1) ;;
    *) echo "M121_COMPARE_HISTORICAL must be 0 or 1" >&2; exit 2 ;;
esac
ARTIFACT_ROOT="${M121_ARTIFACT_DIR:-/tmp/m121}"
mkdir -p "$ARTIFACT_ROOT"
OUT=$(mktemp -d "$ARTIFACT_ROOT/attempt-XXXXXXXX")
finish() {
    local rc=$?
    trap - EXIT
    docker cp "$CONTROLLER:/receipt/." "$OUT/" || rc=1
    for node in a r controller; do
        docker logs "clab-${TOPO}-${node}" > "$OUT/container-${node}.log" 2>&1 || true
    done
    printf '%s\n' "$rc" > "$OUT/run.exit"
    exit "$rc"
}
trap finish EXIT
# shellcheck source=tests/interop/scripts/source-id-guard.sh
source "$SCRIPT_DIR/source-id-guard.sh"
check_lab_source_ids "$TOPO" "$CONTROLLER"
python3 - "$ROOT" "$OUT" "$TOPO" <<'META'
import sys
from pathlib import Path
root,out,topology=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
sys.path.insert(0,str(root/'tests/interop/scripts'))
from m121_all_active_frr import record_host_metadata
record_host_metadata(root,out,topology)
META
# Validate retained baseline identity before comparing any fresh packets.
python3 - "$ROOT" "$OUT" <<'PY'
import hashlib,json,sys
from pathlib import Path
root,out=map(Path,sys.argv[1:])
path=root/'docs/artifacts/interop/evpn-frr-peer-sync-20261011/result.json'
assert hashlib.sha256(path.read_bytes()).hexdigest()=='ae3f7cc6d24d384b45913bd55d4a60f13604a2c257ec811ed1beb50210b36d4f'
(out/'historical-baseline.json').write_bytes(path.read_bytes())
PY
pids=$(python3 - "$TOPO" <<'PY'
import json,subprocess,sys
print(json.dumps({n:int(subprocess.check_output(['docker','inspect','-f','{{.State.Pid}}',f'clab-{sys.argv[1]}-{n}'])) for n in ['a','r']}))
PY
)
docker exec "$CONTROLLER" mkdir -p /receipt
# Install only in the owned controller. No changes to the pinned FRR image.
timeout 240 docker exec -e DEBIAN_FRONTEND=noninteractive "$CONTROLLER" sh -ec \
    'apt-get update && apt-get install -y --no-install-recommends python3 tcpdump tshark procps util-linux' \
    > "$OUT/setup.log" 2>&1
M121_COMPARE_HISTORICAL="$COMPARE_HISTORICAL" M121_HOST_OUT="$OUT" FRR_PIDS="$pids" python3 "$SCRIPT_DIR/m121_all_active_frr.py" --host-run \
    > "$OUT/run.log" 2>&1
docker exec "$CONTROLLER" cat /receipt/result.json
