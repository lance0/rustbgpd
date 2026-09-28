#!/usr/bin/env bash
# Adapted for publication: absolute scratch, checkout, repository and home paths
# are replaced with SCRATCH, WORKTREES, REPO, BGPERF2 and HOME. Otherwise as run.
# bgperf2 single-run spot-check of the v0.73.0 image, rustbgpd only, one
# instance at a time with cleanup between shapes. Run under the bench lock.
# The first attempt failed at tester creation: the bgperf/bird:latest tag was
# missing. It was re-pointed inline (docker tag bgperf/bird:2.19.2
# bgperf/bird:latest) to the image the 2026-08-30 campaign used under both
# tags (sha256:e5e814ba...), and this script was run again.
L=${SCRATCH:?}/headline-v0730
cd ${BGPERF2:?} || exit 1
echo "load $(cut -d' ' -f1-3 /proc/loadavg) bgperf2 $(git rev-parse HEAD) image $(docker image inspect --format '{{.Id}}' bgperf/rustbgpd:v0.73.0-spot)"
docker run --rm --entrypoint rustbgpd bgperf/rustbgpd:v0.73.0-spot --version
for np in "10 1000" "2 10000" "2 100000"; do
  n=${np% *}; p=${np#* }
  ids=$(docker ps -aq --filter "name=bgperf"); [ -n "$ids" ] && docker rm -f $ids >/dev/null
  docker network rm bgperf2-br >/dev/null 2>&1
  echo "=== ${n}p x ${p}pfx start $(date -Is) load $(cut -d' ' -f1-3 /proc/loadavg)"
  .venv/bin/python bgperf2.py bench -t rustbgpd -i bgperf/rustbgpd:v0.73.0-spot -n "$n" -p "$p" > $L/bgperf2-${n}x${p}.log 2>&1
  echo "rc=$?"
  grep -E "elapsed: [0-9]|^total time|Max cpu|Max mem|^rustbgpd," $L/bgperf2-${n}x${p}.log | tail -8
done
ids=$(docker ps -aq --filter "name=bgperf"); [ -n "$ids" ] && docker rm -f $ids >/dev/null
docker network rm bgperf2-br >/dev/null 2>&1
echo SPOT_DONE
