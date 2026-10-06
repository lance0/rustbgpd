# Export-probe delta S2 screen extracts

Compact evidence for the [October 2026 S2 receipt](../../export-probe-delta-arcvec-2026-10.md).
All six process legs and all 24 native reload rows are retained; no row is excluded.

- `reloads-24.csv` preserves the native CSV fields and values, adding only leg
  and arm labels. Each leg has reloads 1–4, 700 sessions and zero parse errors.
- `candidate-paths-12.csv` preserves exact path counts, proof state, event
  timestamps, sealing/reconciliation microseconds and cumulative Validate
  milliseconds. Seal values of zero are timer-resolution observations.
- `legs.json` records native and wrapper exit maps, workload, source and binary
  identities, quiet samples, actual cooldowns, memory, sampling quality and
  cleanup. Native harness/cleanup/cell results come from the runner's status
  line; daemon and wrapper results come from their actual exit receipts.
  This campaign has no additional HTTP health probe; reload-row session and
  parse-error checks are its recorded protocol health evidence.
- `cpu-brackets.csv` records every reload's enclosing sample endpoints, CPU and
  task-switch deltas, leading/trailing uncertainty and thread-read race counts.
  It does not invent preceding control measurements or count writer wakeups.
- `provenance.json` binds each arm to its exact source/tree and executable
  producers, preserving the shared baseline harness and cached auxiliary
  producers. `FLAP_ROUNDS` is explicitly empty in the frozen wrapper; the
  native workload map omits that field. `COMPETITOR_GENERATION=historical` is
  native receipt vocabulary for this rustbgpd-only campaign, not a comparator
  result. Earlier failed candidates remain separately identified here.
- `archived-raw-sha256.json` identifies all 298 files in the externally retained
  raw archive. Paths are logical relative labels; original private locations
  are not published. Hashes identify bytes, but auditing unpublished contents
  still requires the archive. Compact assertions do not replace those records.
- `recompute.py`, `test_recompute.py` and `comparison.json` validate and reproduce
  compact S2 arithmetic: all nine endpoints, actual worst of 12 for maximum
  endpoints, all six process-leg medians, both 60 ms gain bars and both +2%
  comparisons. The reader rejects missing native maps, wrong workload/identity,
  coherent producer relabeling, missing or duplicate reloads, invalid numbers,
  shortened cooldowns and out-of-leg quiet samples. Native quiet timestamps have one-second truncation;
  legitimate same-second start rounding is accepted.
- `SHA256SUMS` hashes every other file in this compact directory.

Three launches per arm are independent repetitions; the four reloads within
each launch are correlated. `timing_bars_pass` is distinct from full raw-path
validity. The frozen full analyzer additionally verified producer receipts,
process ownership, trace bounds/counters and candidate event order/completeness.
It ran once after the final cooldown, exited zero and left empty stderr.

Memory medians use one observed peak per leg. RSS and VmHWM are approximate
proc observations; all raw VmHWM decreases remain in the archive. Kernel cgroup
charge differs from RSS, and observed pre-stop peaks are not guaranteed final
lifetime maxima. The retained memory.stat sample is near the largest sampled
current charge, not atomic attribution of the kernel peak. CPU across the
sampled lifetime is separate from reload-window CPU.

From the repository root, verify compact bytes and reproduce the arithmetic:

```bash
(cd docs/perf/artifacts/export-probe-delta-arcvec-2026-10 && sha256sum -c SHA256SUMS)
python3 docs/perf/artifacts/export-probe-delta-arcvec-2026-10/test_recompute.py
python3 docs/perf/artifacts/export-probe-delta-arcvec-2026-10/recompute.py > /tmp/export-probe-comparison.json
diff -u docs/perf/artifacts/export-probe-delta-arcvec-2026-10/comparison.json /tmp/export-probe-comparison.json
```

The raw archive was frozen before extraction. This compact bundle reproduces
the reported arithmetic; it does not regenerate path/CPU/memory extraction
from unpublished raw logs or qualify another workload.
