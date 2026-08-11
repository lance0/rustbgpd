#!/usr/bin/env bash
# Fast unit proof for the shared M66/M67 VTEP route observation helpers.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
TOPO="test-vtep-route-oracles"
export TOPO

# test-lib runs preflight while sourced. These stubs satisfy only its external
# probes; every route observation below is supplied by an overridden vtep_ctl.
docker() { [ "${1:-}" = "inspect" ]; }
grpcurl() { :; }

# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"
sleep() { :; }

case_name=""
transient_counter="$(mktemp)"
trap 'rm -f "$transient_counter"' EXIT
printf '0\n' >"$transient_counter"

vtep_ctl() {
    case "$case_name" in
        exit42) printf '[]\n'; return 42 ;;
        malformed) printf '[\n' ;;
        object) printf '{"route":1}\n' ;;
        null) printf 'null\n' ;;
        scalar) printf '7\n' ;;
        nonobject) printf '[{"mac":"aa"}, 7]\n' ;;
        multiple) printf '[]\n[]\n' ;;
        empty) printf '[]\n' ;;
        routes) printf '[{"mac":"aa","up":true},{"mac":"bb","up":false}]\n' ;;
        transient)
            local seen
            seen=$(<"$transient_counter")
            printf '%s\n' "$((seen + 1))" >"$transient_counter"
            if [ "$seen" -eq 0 ]; then
                printf '[]\n'
                return 42
            fi
            printf '[]\n'
            ;;
        *) return 99 ;;
    esac
}

run_capture() {
    local stdout_file=$1 stderr_file=$2
    shift 2
    set +e
    "$@" >"$stdout_file" 2>"$stderr_file"
    CAPTURE_RC=$?
    set -e
}

expect_rc2_no_stdout() {
    local label=$1
    shift
    local out err
    out=$(mktemp)
    err=$(mktemp)
    run_capture "$out" "$err" "$@"
    if [ "$CAPTURE_RC" -ne 2 ] || [ -s "$out" ] || [ ! -s "$err" ]; then
        echo "$label: expected rc2, empty stdout, and diagnostic stderr" >&2
        rm -f "$out" "$err"
        exit 1
    fi
    rm -f "$out" "$err"
}

for case_name in exit42 malformed object null scalar nonobject multiple; do
    expect_rc2_no_stdout "$case_name routes" vtep_routes 2 192.0.2.1
    expect_rc2_no_stdout "$case_name count" vtep_route_count 2 192.0.2.1 true
done
case_name=exit42
expect_rc2_no_stdout "unusable at-least exhaustion" wait_vtep_routes_at_least 2 192.0.2.1 true 1 1
expect_rc2_no_stdout "unusable gone exhaustion" wait_vtep_routes_gone 2 192.0.2.1 true 1

case_name=routes
expect_rc2_no_stdout "invalid jq predicate" \
    vtep_route_count 2 192.0.2.1 '.mac =='

case_name=empty
[ "$(vtep_routes 2 192.0.2.1)" = '[]' ]
[ "$(vtep_route_count 2 192.0.2.1 true)" = 0 ]
[ "$(wait_vtep_routes_gone 2 192.0.2.1 true 1)" = 0 ]

case_name=routes
[ "$(vtep_route_count 2 192.0.2.1 '.up')" = 1 ]
[ "$(wait_vtep_routes_at_least 2 192.0.2.1 '.up' 1 1)" = 1 ]
out=$(mktemp)
err=$(mktemp)
run_capture "$out" "$err" wait_vtep_routes_gone 2 192.0.2.1 true 2
[ "$CAPTURE_RC" -eq 1 ] && [ "$(<"$out")" = 2 ] && [ ! -s "$err" ]
rm -f "$out" "$err"

case_name=transient
[ "$(wait_vtep_routes_gone 2 192.0.2.1 true 2)" = 0 ]
[ "$(<"$transient_counter")" -eq 2 ]

echo "shared VTEP route oracles: PASS"
