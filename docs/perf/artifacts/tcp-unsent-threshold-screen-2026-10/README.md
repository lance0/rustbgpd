# TCP unsent-threshold screen extracts

Compact evidence for the [October 2026 screen](../../tcp-unsent-threshold-screen-2026-10.md).
All six legs and all 24 reload rows are retained; nothing is excluded.

- `reloads-*.csv`: the original header and four reload CSV log lines per leg,
  including their `reloadstall_csv_header` / `reloadstall_csv` marker column.
- `legs.json`: exact observed kernel peak bytes, observed trace CPU and duration,
  sampling quality, quiet samples, actual exits, cooldowns, and audited readback
  results. Cleanup success is inferred from successful runner/cell results and
  confirmed scope/process removal; there is no separate cleanup exit receipt. The anon/sock/file/kernel values come from the sample
  maximizing the larger bracketing `memory.current` read. They are not atomic
  attribution of the kernel's `memory.peak` value.
- `cpu-brackets.csv`: daemon CPU and task-switch deltas from outer sample
  brackets enclosing each reload, plus preceding one-second control brackets.
  Requested wall durations and excess bracket milliseconds remain explicit.
  Thread exit/read races make the marked task-switch windows unreliable; these
  counters do not identify asynchronous writer or kernel wakeups.
- `provenance.json`: frozen source, binaries, tools, workload, environment digest,
  execution conditions, and caveats. Private environment values are omitted.
- `archived-raw-sha256.json`: SHA-256 identities of externally retained raw
  traces, logs, scenario files, attestations, audits, preparation, parser, and
  build evidence. `leg-N/` is a logical archive label. Root preparation, parser,
  and build filenames use public aliases. Hashes identify the retained bytes;
  the unpublished raw files are required to independently audit their contents.
- `recompute.py` and `comparison.json`: arithmetic from the published reload
  rows, peak bytes, and CPU extracts, including matched pairs and both numeric
  gate components. The script validates shape and reload coverage. It does not
  regenerate CPU brackets from unpublished full traces or resolve writer wakes.
- `SHA256SUMS`: hashes of every other file in this compact artifact directory.

The raw archive was frozen before extraction. Public metadata omits private
absolute paths and normalizes leg labels; original reload fields remain intact.
Source/environment equality, readbacks, process cleanup, and exits were audited
against the raw evidence. Their compact assertions are not substitutes for raw
logs. Sampling covers approximately 128.1 seconds per leg; observed kernel peaks
are pre-stop observations, not guaranteed final lifetime maxima. Leg 1's recorder
pause and leg 4's unexplained low background CPU remain recorded in provenance.

From the repository root, verify the compact bytes and reproduce the comparison:

```bash
(cd docs/perf/artifacts/tcp-unsent-threshold-screen-2026-10 && sha256sum -c SHA256SUMS)
python3 docs/perf/artifacts/tcp-unsent-threshold-screen-2026-10/recompute.py > /tmp/tcp-unsent-comparison.json
diff -u docs/perf/artifacts/tcp-unsent-threshold-screen-2026-10/comparison.json /tmp/tcp-unsent-comparison.json
```

Medians pool 12 correlated reload values per arm; the independent sample count
is three legs per arm. Memory medians use one observed kernel peak per leg.
The 65,536-byte candidate misses the original +2% completion gate despite meeting
the ≥100 MiB memory-reduction component. The investigation remains open, with
128 KiB queued and unmeasured.
