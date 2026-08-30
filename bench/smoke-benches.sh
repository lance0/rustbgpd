#!/usr/bin/env bash
#
# Exercise every bench target that is not already smoked by a dedicated CI
# step.
#
# Benches are outside the gate battery, so a bench that panics on its first
# iteration is indistinguishable from one nobody ran. `cargo bench --no-run`
# does not close that: an attribute fixture that a codec change made illegal
# compiles fine and only fails when the body runs. `cargo test --bench` runs
# every criterion benchmark body exactly once with no measurement, which is
# the cheapest thing that actually catches it. The two paging receipt harnesses
# are custom CLIs, so they use bounded multi-page fixtures below instead.
#
# This is a smoke check, not a measurement. It reports pass/fail only; any
# timing it happens to produce is meaningless and is not reported.
#
# The target list comes from `cargo metadata`, so a bench target is covered the
# day it lands rather than when someone remembers to register it here. Four
# custom harnesses with separate CI smoke steps are excluded by package/target
# key; renaming one drops its exclusion and this script then fails loudly
# instead of skipping it silently.

set -euo pipefail

cd "$(dirname "$0")/.."

locked_args=()
fail_fast=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --locked)
      locked_args=(--locked)
      ;;
    --fail-fast)
      fail_fast=1
      ;;
    *)
      echo "usage: $0 [--locked] [--fail-fast]" >&2
      exit 2
      ;;
  esac
  shift
done

# Standalone measurement harnesses have their own CLIs rather than criterion.
# They accept Cargo's libtest-compatible `--bench` marker; two have bounded
# invocations in this script:
#
#   route_paging         CSV receipt harness; one complete traversal per
#                        process, driven by --routes/--page-size/--scope.
#   dataplane_prefix_paging
#                        CSV-to-stdout receipt harness; one complete traversal
#                        per process, driven by prefix/path/index-mode flags.
#
# The remaining four are excluded here because CI executes their native smoke
# contracts separately:
#
#   snapshot_allocation  needs a `timing|diagnostic` mode plus --commit and
#                        --output. CI smokes both modes separately through the
#                        harness's own `--smoke` bound.
#   vpn_query_*          are one-cell timing/allocation executables. CI runs
#                        their exact 256-route smoke separately.
#   selection_deferral_release
#                        fixed-fleet receipt harness with its own CLI and
#                        bounded self-test, which CI runs separately.
EXCLUDED=(
  rustbgpd-mrt/snapshot_allocation
  rustbgpd-api/vpn_query_timing
  rustbgpd-api/vpn_query_allocation
  rustbgpd-rib/selection_deferral_release
)

mapfile -t targets < <(
  cargo metadata "${locked_args[@]}" --no-deps --format-version 1 | python3 -c '
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
  key="$package/$name"

  skip=
  for excluded in "${EXCLUDED[@]}"; do
    if [ "$key" = "$excluded" ]; then
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

  bench_args=()
  case "$key" in
    rustbgpd-rib/route_paging)
      # Grouped advertised routes exercise split horizon; 31 leaves a partial
      # eighth page after the filtered rows are removed.
      bench_args=(-- --routes 257 --page-size 31 --scope grouped-advertised --repetition 1)
      ;;
    rustbgpd-rib/dataplane_prefix_paging)
      # Cross the harness's 1,024-prefix page boundary and retain multipath.
      bench_args=(-- --prefixes 1025 --announcers 2 --max-paths 2 --mode eager --repetition 1)
      ;;
  esac

  echo "smoke $package/$name ${features:+[$features]}"
  if ! cargo test "${locked_args[@]}" -p "$package" --bench "$name" "${feature_args[@]}" "${bench_args[@]}"; then
    echo "::error::bench target $package/$name failed to execute" >&2
    if [ "$fail_fast" -eq 1 ]; then
      exit 1
    fi
    status=1
  fi
done

exit "$status"
