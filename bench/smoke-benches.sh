#!/usr/bin/env bash
#
# Prove every criterion bench target still *executes*.
#
# Benches are outside the gate battery, so a bench that panics on its first
# iteration is indistinguishable from one nobody ran. `cargo bench --no-run`
# does not close that: an attribute fixture that a codec change made illegal
# compiles fine and only fails when the body runs. `cargo test --bench` puts
# criterion in `--test` mode — every benchmark body runs exactly once with no
# measurement, which is the cheapest thing that actually catches it.
#
# This is a smoke check, not a measurement. It reports pass/fail only; any
# timing it happens to produce is meaningless and is not reported.
#
# The target list comes from `cargo metadata`, so a bench target is covered the
# day it lands rather than when someone remembers to register it here. The two
# non-criterion harnesses are excluded by name; renaming one drops its
# exclusion and this script then fails loudly instead of skipping it silently.

set -euo pipefail

cd "$(dirname "$0")/.."

# Excluded — standalone measurement harnesses with their own CLIs rather than
# criterion, so they reject criterion's `--test` flag:
#
#   snapshot_allocation  needs a `timing|diagnostic` mode plus --commit and
#                        --output. CI smokes both modes separately through the
#                        harness's own `--smoke` bound.
#   route_paging         CSV receipt harness; one complete traversal per
#                        process, driven by --route-count/--output.
EXCLUDED=(snapshot_allocation route_paging)

mapfile -t targets < <(
  cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys

for package in json.load(sys.stdin)["packages"]:
    for target in package["targets"]:
        if "bench" in target["kind"]:
            features = ",".join(target.get("required-features") or [])
            print(package["name"], target["name"], features)
' | sort
)

if [ "${#targets[@]}" -eq 0 ]; then
  echo "no bench targets found — cargo metadata parse is broken" >&2
  exit 1
fi

status=0
for target in "${targets[@]}"; do
  read -r package name features <<<"$target"

  skip=
  for excluded in "${EXCLUDED[@]}"; do
    if [ "$name" = "$excluded" ]; then
      skip=1
      break
    fi
  done
  if [ -n "$skip" ]; then
    echo "skip  $package/$name (not a criterion harness)"
    continue
  fi

  feature_args=()
  if [ -n "$features" ]; then
    feature_args=(--features "$features")
  fi

  echo "smoke $package/$name ${features:+[$features]}"
  if ! cargo test -p "$package" --bench "$name" "${feature_args[@]}"; then
    echo "::error::bench target $package/$name failed to execute" >&2
    status=1
  fi
done

exit "$status"
