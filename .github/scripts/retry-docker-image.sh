#!/usr/bin/env bash
set -euo pipefail

output=$(mktemp)
trap 'rm -f "$output"' EXIT

for attempt in 1 2 3; do
  if "$@" >"$output"; then
    cat "$output"
    exit 0
  else
    status=$?
    cat "$output" >&2
  fi
  if (( attempt < 3 )); then
    sleep "$((attempt * 5))"
  fi
done
exit "$status"
