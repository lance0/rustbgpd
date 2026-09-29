#!/usr/bin/env bash
# Offline proof for the shared command-polling helper.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
TOPO=test-wait-helper
CLEANUP=0

# Satisfy source-time preflight without a daemon or containerlab deployment.
docker() { [ "${1:-}" = inspect ]; }
grpcurl() { :; }
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

delays=()
sleep() { delays+=("$1"); }
calls=0
succeeds_at=1
# shellcheck disable=SC2016 # Deliberately pass shell syntax as a literal argument.
literal_arg='$(exit 99); *'
predicate() {
    calls=$((calls + 1))
    # Argument boundaries and shell metacharacters must survive without eval.
    [ "$#" -eq 3 ] && [ "$1" = 'two words' ] && [ -z "$2" ] \
        && [ "$3" = "$literal_arg" ] || exit 1
    [ "$calls" -ge "$succeeds_at" ]
}

wait_until 3 2 predicate 'two words' '' "$literal_arg"
[ "$calls" -eq 1 ] && [ "${#delays[@]}" -eq 0 ]

calls=0
succeeds_at=3
wait_until 3 2 predicate 'two words' '' "$literal_arg"
[ "$calls" -eq 3 ] && [ "${delays[*]}" = '2 2' ]

calls=0
delays=()
succeeds_at=4
if wait_until 3 1 predicate 'two words' '' "$literal_arg"; then
    echo 'exhausted attempts were reported as success' >&2
    exit 1
fi
[ "$calls" -eq 3 ] && [ "${delays[*]}" = '1 1 1' ]

calls=0
delays=()
if wait_until 0 1 predicate 'two words' '' "$literal_arg"; then
    echo 'zero attempts were reported as success' >&2
    exit 1
fi
[ "$calls" -eq 0 ] && [ "${#delays[@]}" -eq 0 ]
[ "$(wait_until 1 1 printf '%s' 'predicate output')" = 'predicate output' ]

echo 'shared wait helper: PASS'
