#!/usr/bin/env bash
# Usage: assert-lab-torn-down.sh LABEL TOPOLOGY
#
# Run after each scenario in a job that runs several lab scenarios in turn.
# Destroys the scenario's topology again (idempotent), then fails if any
# containerlab container or clab-* network namespace survived. Leftovers are
# removed before failing, so the next scenario still deploys onto a clean host
# and the leak is reported against the scenario that caused it.
set -uo pipefail

label=$1
topology=$2

sudo containerlab destroy -t "$topology" --cleanup >/dev/null 2>&1 || true

# An inventory that cannot be read is not evidence of a clean host.
if ! containers=$(docker ps -aq --filter label=containerlab); then
  echo "::error::${label}: cannot list containerlab containers; teardown is unverified"
  exit 1
fi
if ! namespaces=$(ip netns list); then
  echo "::error::${label}: cannot list network namespaces; teardown is unverified"
  exit 1
fi
netns=$(awk '$1 ~ /^clab-/ { print $1 }' <<<"$namespaces")
if [ -z "$containers" ] && [ -z "$netns" ]; then
  echo "${label}: no containerlab containers or clab-* namespaces remain"
  exit 0
fi

docker ps -a --filter label=containerlab
echo "${netns}"
echo "::error::${label} left lab state behind after teardown; removing it before the next scenario"
[ -z "$containers" ] || xargs -r docker rm -f <<<"$containers" >/dev/null
for ns in $netns; do
  sudo ip netns delete "$ns" || true
done
exit 1
