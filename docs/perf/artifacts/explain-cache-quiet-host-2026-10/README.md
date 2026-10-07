# Import-explain cache quiet-host artifacts (October 2026)

Compact public evidence for the [dated receipt](../../explain-cache-quiet-host-2026-10.md).
All ten cells are retained; none was retried or excluded.

| File | Contents |
| --- | --- |
| [`cells.csv`](cells.csv) | One row per cell in run order: shape, explain setting, daemon cgroup peak, swap/OOM readings, anonymous memory before the cgroup move, settled VmRSS, VmHWM, process-tree RSS median, jemalloc gauges, harness cgroup peak, convergence time, explain outcomes, preflight load and runner status |
| [`explain-answers.json`](explain-answers.json) | The exact JSON and exit status of both `rbgp policy explain --direction import` probes in every cell |
| [`recompute.py`](recompute.py) | Recomputes arm means, ranges and differences from `cells.csv` |
| [`comparison.json`](comparison.json) | Output of `recompute.py` |
| [`cgroup-cell-wrapper.sh`](cgroup-cell-wrapper.sh) | The per-cell wrapper that splits the scope into daemon and runner cgroups and records their peaks; byte-identical to the as-run copy |
| [`campaign.sh`](campaign.sh) | The campaign driver; private paths and the unit-name prefix were replaced, as recorded in `provenance.json` |
| [`provenance.json`](provenance.json) | Source, toolchain, binary hashes, host, runner inputs, run order, lock and scheduling arrangement, memory method and caveats |

From the repository root, reproduce the comparison:

```bash
python3 docs/perf/artifacts/explain-cache-quiet-host-2026-10/recompute.py > /tmp/explain-cache-comparison.json
diff -u docs/perf/artifacts/explain-cache-quiet-host-2026-10/comparison.json /tmp/explain-cache-comparison.json
```

The full per-cell runner directories, including RSS and cgroup sample streams,
metric scrapes, daemon logs and generated configurations, are retained outside
this repository. The generated scenario is reproducible from the measured tree
with `bench/scale/reloadstall/gen-scenario.py`, and the runner injects the
`[policy.explain]` block shown in the receipt.
