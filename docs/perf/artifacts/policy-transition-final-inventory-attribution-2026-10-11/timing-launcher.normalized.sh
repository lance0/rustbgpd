#!/usr/bin/env bash
# PREPARED ONLY: separate timing admission is required.
set -euo pipefail
PREP=<PREPARATION>
OUT=<ARTIFACTS>
[[ ! -e $OUT/logs/abba-wrapper.log && ! -e $OUT/logs/abba-wrapper.exit ]]
exec >"$OUT/logs/abba-wrapper.log" 2>&1
rc=0
trap 'rc=$?; printf "%s\n" "$rc" >"$OUT/logs/abba-wrapper.exit"' EXIT
cp "$PREP/timing-invocation.sh" "$OUT/abba-invocation-as-run.sh"
cp "$PREP/timing-preparation.json" "$OUT/abba-preparation-manifest.json"
# Refuse optional shapes, quiet-test roots/spacing and inherited lock owners.
# The unchanged driver sets its own 600-second quiet timeout after admission.
overrides=$(compgen -e | rg '^(GEN_|RELOADSTALL_|RUSTBGPD_HOST_QUIET_|SOAK_NOFILE_SOFT$|RUSTBGPD_HOST_LOCK_FD$|RUSTBGPD_LIGHT_LOCK_FD$)' || true)
[[ -z $overrides ]] || { printf 'refusing inherited overrides: %s\n' "$overrides"; exit 2; }
# Small source/metadata hashes only; engine/daemon/CLI hashing stays post-lock.
sha256sum -c "$PREP/timing-invocation-sources.sha256"
bash "$PREP/driver.sh" abba
