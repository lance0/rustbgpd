#!/usr/bin/env bash
# Final step of a job that runs several lab scenarios in turn.
#
# RESULTS holds one `LABEL=<run outcome>/<teardown outcome>` word per scenario,
# from `steps.<id>.outcome`. Prints every scenario's result and fails, naming
# them, when any scenario's run or teardown did not succeed. A skipped step
# counts as a failure: no scenario in a bundle is optional.
set -euo pipefail

failed=()
for entry in ${RESULTS:?RESULTS is empty}; do
  label=${entry%%=*}
  outcome=${entry#*=}
  echo "${label}: run/teardown ${outcome}"
  [ "$outcome" = "success/success" ] || failed+=("${label} (${outcome})")
done

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Bundled scenarios"
    echo ""
    echo "| scenario | run / teardown |"
    echo "|---|---|"
    for entry in $RESULTS; do echo "| ${entry%%=*} | ${entry#*=} |"; done
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "${#failed[@]}" -gt 0 ]; then
  echo "::error::bundled scenarios failed: ${failed[*]}"
  exit 1
fi
