# TCP unsent-threshold 128 KiB screen extracts

Compact evidence for the [October 2026 128 KiB screen](../../tcp-unsent-threshold-128k-screen-2026-10.md).
All six predeclared native process legs and all 24 reload rows are retained.
The earlier 64 KiB screen remains in its separate artifact directory.

- `reloads-*.csv`: original header and four reload CSV log lines per leg,
  including the `reloadstall_csv_header` / `reloadstall_csv` marker column.
- `legs.json`: exact observed kernel peak bytes, observed trace CPU and duration,
  sampling quality, quiet samples, actual exits, cooldowns, and audited live
  socket readbacks. Cleanup success is inferred from successful runner/cell
  results and confirmed removal of original owned scopes/processes; there is no
  separate cleanup exit receipt. The anon/sock/file/kernel values come from the
  sample maximizing the larger bracketing `memory.current` read, without atomic
  attribution of kernel `memory.peak`.
- `cpu-brackets.csv`: daemon CPU and task-switch deltas from outer sample
  brackets enclosing each reload, plus preceding one-second controls. Requested
  durations and excess bracket milliseconds remain explicit. Approximate trigger
  alignment and bracket width limit attribution. Marked task-switch reliability
  does not identify asynchronous writer or kernel wakeups.
- `provenance.json`: frozen source, binaries, tools, workload, environment digest,
  lifecycle evidence, and caveats. Private environment values are omitted.
- `archived-raw-sha256.json`: identities of externally retained raw traces,
  logs, scenarios, before/after attestations, recorder timing/results, audits,
  preparation, parsers, and launchers. `leg-N/` is a logical archive label;
  preparation, parser, and build filenames use public aliases. The unpublished
  raw files are needed to independently audit their contents.
- `recompute.py` and `comparison.json`: arithmetic from published reload rows,
  exact peak bytes, and CPU extracts, including matched pairs, process-leg
  medians, and numeric gates. Explicit validation rejects missing/duplicate
  reloads, unexpected workload shape, and nonfinite arithmetic inputs even with
  Python optimization. It does not reconstruct CPU windows from full traces or
  resolve writer wakeups.
- `SHA256SUMS`: hashes of every other file in this compact artifact directory.

Raw files remain unchanged. Public metadata omits private absolute paths and
normalizes leg labels; original reload fields remain intact. Source/environment
equality, 700 unique live socket values per leg, original-process cleanup, exits,
and cooldowns were independently audited against raw evidence. Compact assertions
preserve that result without replacing the raw logs. Separate driver preparation
and functional-smoke attempts are outside the six-leg numeric comparison.

From the repository root:

```bash
(cd docs/perf/artifacts/tcp-unsent-threshold-128k-screen-2026-10 && sha256sum -c SHA256SUMS)
python3 docs/perf/artifacts/tcp-unsent-threshold-128k-screen-2026-10/recompute.py > /tmp/tcp-unsent-128k-comparison.json
diff -u docs/perf/artifacts/tcp-unsent-threshold-128k-screen-2026-10/comparison.json /tmp/tcp-unsent-128k-comparison.json
```

Pooled medians use 12 correlated reload values per arm; the independent count is
three process legs per arm. Memory medians use one observed kernel peak per leg.
CPU rates divide each outer-bracket CPU delta by its requested duration plus
recorded excess width before taking the median; they are separate from CPU totals.
The 131,072-byte candidate misses the original +2% completion gate despite meeting
the ≥100 MiB memory component. The resulting recommendation preserves existing
socket behavior and sizes containers from representative cgroup peaks plus headroom.
