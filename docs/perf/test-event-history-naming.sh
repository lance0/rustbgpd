#!/usr/bin/env bash
# Keep the event-history performance surface named after its behavior, not a
# private issue tracker that operators and contributors cannot inspect.
set -euo pipefail

for required_command in git grep rg; do
    command -v "$required_command" >/dev/null 2>&1 || {
        printf 'required command not found: %s\n' "$required_command" >&2
        exit 1
    }
done

ROOT=$(git rev-parse --show-toplevel)
mapfile -t files < <(
    git -C "$ROOT" ls-files -- \
        'crates/api/benches/event_history_producer.rs' \
        'docs/perf/*event-history*' \
        'docs/perf/bgperf-rustbgpd-ehm-wrapper.sh' \
        'docs/perf/artifacts/event-history-producer-2026-07/**'
)

((${#files[@]} > 0)) || {
    printf '%s\n' 'event-history naming guard found no tracked files' >&2
    exit 1
}

if bad_paths=$(printf '%s\n' "${files[@]}" | grep -Ei 'lan-?[0-9]{3}'); then
    printf '%s\n' 'private-ticket namespace found in event-history paths:' >&2
    printf '%s\n' "$bad_paths" >&2
    exit 1
fi

absolute_files=()
for file in "${files[@]}"; do
    absolute_files+=("$ROOT/$file")
done
if matches=$(rg -n -i 'lan-?[0-9]{3}' "${absolute_files[@]}"); then
    printf '%s\n' 'private-ticket namespace found in event-history content:' >&2
    printf '%s\n' "$matches" >&2
    exit 1
fi

printf '%s\n' 'event-history naming guard passed'
