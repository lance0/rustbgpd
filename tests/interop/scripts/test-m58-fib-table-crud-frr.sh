#!/usr/bin/env bash
# M58 interop test — ADR-0061 FIB-table runtime CRUD.
#
# Exercises the runtime [[fib_tables]] CRUD surface end-to-end against a real
# FRR peer and a real kernel: SetFibTable (add + table-key move),
# DeleteFibTable, ListFibTables, and the persist-across-restart round-trip.
# Companion to M42, which covers the startup FIB path.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - containerlab deploy -t tests/interop/m58-fib-table-crud-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m58-fib-table-crud-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"

EDGE_ID=1000
EDGE_METRIC=200
CORE_ID=2000
CORE_METRIC=300
CORE_METRIC_MOVED=350
NEXT_HOP="10.0.0.2"
# Both prefixes are advertised by FRR and carry no pre-existing foreign route,
# so they install cleanly as daemon-owned in every configured table.
PREFIX_A="203.0.113.42/32"
PREFIX_B="203.0.113.99/32"

resolve_grpc_addr
start_rustbgpd
wait_frr_established "$FRR" "10.0.0.1" "rustbgpd ↔ FRR"

# ---- gRPC helpers -----------------------------------------------------------

grpc() {
    grpcurl_call "$@"
}

list_fib_tables() {
    grpc "$GRPC_ADDR" rustbgpd.v1.RibService/ListFibTables
}

set_fib_table() {
    local name=$1 table_id=$2 metric=$3
    grpc -d "{\"table\":{\"name\":\"${name}\",\"tableId\":${table_id},\"metric\":${metric},\"families\":[\"ipv4_unicast\"]}}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/SetFibTable
}

delete_fib_table() {
    local name=$1
    grpc -d "{\"name\":\"${name}\"}" "$GRPC_ADDR" rustbgpd.v1.RibService/DeleteFibTable
}

# Count configured tables ListFibTables currently reports.
fib_table_count() {
    list_fib_tables 2>/dev/null | jq -r '.tables | length' 2>/dev/null || echo "ERR"
}

# Does ListFibTables report a table with this name + table_id + metric?
fib_table_has() {
    local name=$1 table_id=$2 metric=$3
    list_fib_tables 2>/dev/null | jq -e --arg n "$name" --argjson t "$table_id" --argjson m "$metric" \
        '[.tables[]? | select(.name == $n and .tableId == $t and .metric == $m)] | length == 1' \
        >/dev/null 2>&1
}

# ---- kernel helpers (parameterized by table + metric) -----------------------

kernel_owned() {
    # owned (daemon-installed) route: proto bgp, given metric, via NEXT_HOP
    local prefix=$1 table_id=$2 metric=$3
    docker exec "$RUSTBGPD" ip route show table "$table_id" exact "$prefix" 2>/dev/null \
        | grep -q "via $NEXT_HOP" \
        && docker exec "$RUSTBGPD" ip route show table "$table_id" exact "$prefix" 2>/dev/null \
        | grep -q "proto bgp" \
        && docker exec "$RUSTBGPD" ip route show table "$table_id" exact "$prefix" 2>/dev/null \
        | grep -q "metric $metric"
}

kernel_absent() {
    local prefix=$1 table_id=$2
    ! docker exec "$RUSTBGPD" ip route show table "$table_id" exact "$prefix" 2>/dev/null | grep -q .
}

dump_state_on_failure() {
    echo "===== ListFibTables =====" >&2
    list_fib_tables | jq . >&2 || true
    echo "===== table $EDGE_ID =====" >&2
    docker exec "$RUSTBGPD" ip route show table "$EDGE_ID" >&2 || true
    echo "===== table $CORE_ID =====" >&2
    docker exec "$RUSTBGPD" ip route show table "$CORE_ID" >&2 || true
    echo "===== config.toml =====" >&2
    docker exec "$RUSTBGPD" cat /etc/rustbgpd/config.toml >&2 || true
    echo "===== rustbgpd.log tail =====" >&2
    docker exec "$RUSTBGPD" tail -40 /tmp/rustbgpd.log >&2 || true
}

wait_kernel_owned() {
    local prefix=$1 table_id=$2 metric=$3
    log "Waiting for $prefix owned in table $table_id metric $metric..."
    for i in $(seq 1 30); do
        if kernel_owned "$prefix" "$table_id" "$metric"; then
            ok "$prefix installed in table $table_id (metric $metric, via $NEXT_HOP) after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix did not install in table $table_id metric $metric"
    dump_state_on_failure
    return 1
}

wait_kernel_absent() {
    local prefix=$1 table_id=$2
    log "Waiting for $prefix to leave table $table_id..."
    for i in $(seq 1 30); do
        if kernel_absent "$prefix" "$table_id"; then
            ok "$prefix absent from table $table_id after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix remained in table $table_id"
    dump_state_on_failure
    return 1
}

assert_set_ack() {
    local label=$1 json=$2
    if printf '%s' "$json" | jq -e '.runtimeAvailable == true' >/dev/null 2>&1; then
        ok "$label acknowledged (runtime_available=true)"
    else
        fail "$label did not return runtime_available=true: $json"
        dump_state_on_failure
        exit 1
    fi
}

# ---- 1. Baseline: the startup `edge` table installs both prefixes -----------

log "=== 1. Baseline: startup table 'edge' ($EDGE_ID/$EDGE_METRIC) ==="
wait_kernel_owned "$PREFIX_A" "$EDGE_ID" "$EDGE_METRIC"
wait_kernel_owned "$PREFIX_B" "$EDGE_ID" "$EDGE_METRIC"
if fib_table_has "edge" "$EDGE_ID" "$EDGE_METRIC"; then
    ok "ListFibTables reports edge/$EDGE_ID/$EDGE_METRIC"
else
    fail "ListFibTables missing edge table"; dump_state_on_failure; exit 1
fi

# ---- 2. SetFibTable adds a second table at runtime --------------------------

log "=== 2. SetFibTable adds 'core' ($CORE_ID/$CORE_METRIC) at runtime ==="
set_resp=$(set_fib_table "core" "$CORE_ID" "$CORE_METRIC")
assert_set_ack "SetFibTable core" "$set_resp"
wait_kernel_owned "$PREFIX_A" "$CORE_ID" "$CORE_METRIC"
wait_kernel_owned "$PREFIX_B" "$CORE_ID" "$CORE_METRIC"
# The edge table must be untouched by the add.
if kernel_owned "$PREFIX_A" "$EDGE_ID" "$EDGE_METRIC"; then
    ok "edge table unaffected by adding core"
else
    fail "edge table lost $PREFIX_A after adding core"; dump_state_on_failure; exit 1
fi
if [ "$(fib_table_count)" = "2" ]; then
    ok "ListFibTables now reports 2 tables"
else
    fail "expected 2 tables after add, got $(fib_table_count)"; dump_state_on_failure; exit 1
fi

# ---- 3. SetFibTable metric change is a table-key move -----------------------

log "=== 3. SetFibTable 'core' metric $CORE_METRIC->$CORE_METRIC_MOVED (table-key move) ==="
move_resp=$(set_fib_table "core" "$CORE_ID" "$CORE_METRIC_MOVED")
assert_set_ack "SetFibTable core (metric move)" "$move_resp"
# New metric installs; old metric rows withdraw.
wait_kernel_owned "$PREFIX_A" "$CORE_ID" "$CORE_METRIC_MOVED"
wait_kernel_owned "$PREFIX_B" "$CORE_ID" "$CORE_METRIC_MOVED"
for prefix in "$PREFIX_A" "$PREFIX_B"; do
    if docker exec "$RUSTBGPD" ip route show table "$CORE_ID" exact "$prefix" 2>/dev/null | grep -q "metric $CORE_METRIC\b"; then
        fail "$prefix still present at old metric $CORE_METRIC after table-key move"
        dump_state_on_failure; exit 1
    fi
done
ok "table-key move withdrew old metric-$CORE_METRIC rows, installed metric-$CORE_METRIC_MOVED rows"

# ---- 4. Persistence: restart and confirm the post-CRUD set survives --------

log "=== 4. Restart rustbgpd; the runtime CRUD must have persisted to TOML ==="
# The config bind is read-write, and the daemon was started with --config, so
# SetFibTable persisted the new set. After a restart the daemon must come back
# with BOTH edge(1000/200) and core(2000/350).
if docker exec "$RUSTBGPD" grep -q "table_id = $CORE_ID" /etc/rustbgpd/config.toml; then
    ok "core table persisted into config.toml"
else
    fail "config.toml does not contain the runtime-added core table"; dump_state_on_failure; exit 1
fi
log "Stopping rustbgpd..."
docker exec "$RUSTBGPD" sh -c 'kill -TERM "$(pidof rustbgpd)"'
for i in $(seq 1 30); do
    docker exec "$RUSTBGPD" sh -c 'pidof rustbgpd >/dev/null 2>&1' || break
    sleep 1
done
start_rustbgpd
wait_frr_established "$FRR" "10.0.0.1" "rustbgpd ↔ FRR (after restart)"
wait_kernel_owned "$PREFIX_A" "$EDGE_ID" "$EDGE_METRIC"
wait_kernel_owned "$PREFIX_A" "$CORE_ID" "$CORE_METRIC_MOVED"
if [ "$(fib_table_count)" = "2" ]; then
    ok "post-restart ListFibTables reports both persisted tables"
else
    fail "expected 2 tables after restart, got $(fib_table_count)"; dump_state_on_failure; exit 1
fi

# ---- 5. DeleteFibTable withdraws only its rows ------------------------------

log "=== 5. DeleteFibTable 'core' withdraws its rows; edge untouched ==="
del_resp=$(delete_fib_table "core")
assert_set_ack "DeleteFibTable core" "$del_resp"
wait_kernel_absent "$PREFIX_A" "$CORE_ID"
wait_kernel_absent "$PREFIX_B" "$CORE_ID"
# edge table must still hold both prefixes.
wait_kernel_owned "$PREFIX_A" "$EDGE_ID" "$EDGE_METRIC"
wait_kernel_owned "$PREFIX_B" "$EDGE_ID" "$EDGE_METRIC"
if [ "$(fib_table_count)" = "1" ]; then
    ok "ListFibTables back to 1 table after delete"
else
    fail "expected 1 table after delete, got $(fib_table_count)"; dump_state_on_failure; exit 1
fi

# ---- 6. DeleteFibTable on a missing name is NOT_FOUND -----------------------

log "=== 6. DeleteFibTable on a missing name returns NOT_FOUND ==="
if delete_fib_table "does-not-exist" >/dev/null 2>&1; then
    fail "deleting a missing table unexpectedly succeeded"; dump_state_on_failure; exit 1
else
    ok "delete of missing table rejected as expected"
fi

print_summary
