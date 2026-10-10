#!/usr/bin/env bash
# Interleaved 3x3 legs: ABBAAB. Each leg takes and releases the host lock itself.
set -u
O=<bench-dir>
n=0
for arm in main fix fix main main fix; do
  n=$((n+1)); leg=$arm-$n
  $O/run-leg.sh $arm $leg; rc=$?
  echo "leg $leg rc=$rc"
  [ $rc = 3 ] && { echo "deadline stop"; exit 3; }
done
echo ab-done
