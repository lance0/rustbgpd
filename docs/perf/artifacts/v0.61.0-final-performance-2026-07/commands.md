# Reproduction commands

Run from a clean checkout of the source commit on an otherwise idle Linux host.
The route-server driver performs its own quiet-host, governor, swap-I/O, port,
memory, file-descriptor, clean-tree, and source-stability checks.

```console
OUT=$RECEIPT_ROOT
REPO=$PWD LABEL=final-a-1000x400 OUTBASE=$OUT \
  PEERS=1000 TOTAL=400000 EXPLAIN=false RELOADS=0 CONTROL_SECS=30 \
  PROFILE=release docs/perf/run-explain-cache-variant.sh
REPO=$PWD LABEL=final-b-1000x400 OUTBASE=$OUT \
  PEERS=1000 TOTAL=400000 EXPLAIN=false RELOADS=0 CONTROL_SECS=30 \
  PROFILE=release docs/perf/run-explain-cache-variant.sh
REPO=$PWD LABEL=final-c-1000x400 OUTBASE=$OUT \
  PEERS=1000 TOTAL=400000 EXPLAIN=false RELOADS=0 CONTROL_SECS=30 \
  PROFILE=release docs/perf/run-explain-cache-variant.sh
```

The accepted Criterion archive was collected on logical CPU 8 after the host's
dedicated swap file had been cycled to zero use. The page counters were equal
before and after all three suites.

```console
taskset -c 8 cargo bench -p rustbgpd-rib --bench rib_ops -- \
  --save-baseline v0.61.0-final-99ee74ba
taskset -c 8 cargo bench -p rustbgpd-wire --bench codec -- \
  --save-baseline v0.61.0-final-99ee74ba
taskset -c 8 cargo bench -p rustbgpd-policy --bench policy_eval -- \
  --save-baseline v0.61.0-final-99ee74ba
```

Regenerate `criterion/results.tsv` from each saved baseline's
`estimates.json` and `sample.json`. Only the median point estimate, median 95%
confidence interval, sample count, and sampling mode are retained.

```console
python3 \
  docs/perf/artifacts/v0.61.0-final-performance-2026-07/criterion/derive_criterion.py \
  $SAVED_CRITERION_ROOT > $REGENERATED_RESULTS
cmp $REGENERATED_RESULTS \
  docs/perf/artifacts/v0.61.0-final-performance-2026-07/criterion/results.tsv
```

Verify the compact archive:

```console
python3 docs/perf/artifacts/v0.61.0-final-performance-2026-07/verify.py
```
