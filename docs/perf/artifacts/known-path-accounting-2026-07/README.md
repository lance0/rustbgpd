# Known-path accounting artifacts — July 2026

This directory is the bounded evidence for
[`known-path-accounting-2026-07.md`](../../known-path-accounting-2026-07.md).
`manifest.json` records the exact source, image, workload, admitted order,
rejected startup attempts, classifier hashes, and gate results.

The eight `*.csv` files are sanitized bgperf2 final rows. `scenario.yaml` and
`config.toml` are byte-identical across all admitted runs and show that Add-Path
was not configured. The sixteen BIRD logs are the actual admitted tester logs;
`bird-tester-scan.tsv` applies the pinned adapter rule (count `RMT`, excluding
`NEXT_HOP`) and records zero for every run. bgperf2's BIRD timeout field is
structurally zero and is retained only as raw schema, not claimed as independent
timeout evidence.

The raw DHAT JSON is not committed. The lossless sanitized derivatives retain
the allocation bytes and stack text required by the classifier, without raw
addresses or host paths. Reproduce the classified tables from the repository
root:

```text
python3 bench/scale/rebaseline/classify_dhat.py \
  --from-derivative docs/perf/artifacts/known-path-accounting-2026-07/baseline.dhat-derivative.tsv \
  --check docs/perf/artifacts/known-path-accounting-2026-07/baseline.memory.tsv
python3 bench/scale/rebaseline/classify_dhat.py \
  --from-derivative docs/perf/artifacts/known-path-accounting-2026-07/candidate.dhat-derivative.tsv \
  --check docs/perf/artifacts/known-path-accounting-2026-07/candidate.memory.tsv
```

Validate each bounded bgperf2 row and all artifact hashes:

```text
for receipt in docs/perf/artifacts/known-path-accounting-2026-07/*.csv; do
  python3 bench/scale/rebaseline/sanitize_bgperf_csv.py \
    --from-sanitized "$receipt" --check "$receipt"
done
(cd docs/perf/artifacts/known-path-accounting-2026-07 && sha256sum -c SHA256SUMS)
```

The locally retained raw measurement directory also contains daemon/monitor
logs, per-second RSS samples, full stdout, rejected collision attempts, and
the exact source archives. Those unbounded host-specific inputs are deliberately
not part of the public artifact.
