# Reload observer-tail extracts

Compact evidence for the [October 2026 diagnostic](../../reload-observer-tail-2026-10-06.md).
Both complete four-reload legs are retained: one clean control process and one
instrumented process, each with 700 observers. Reloads within a leg are correlated.

- `native-control.log` and `native-probe.log`: original observer gap, expected
  generation, clock bracket, and native aggregate records. The files omit
  unrelated log lines, including process identifiers.
- `observers-*.csv`: all 5,600 observer rows with first base/generation event,
  completion, and maximum-gap boundaries. Probe rows additionally contain
  release, consumer, accepted admission, and matched writer measurements.
  Observer indices identify peers within this experiment; peer addresses and
  writer thread identifiers are omitted.
- `matched-writers.csv`: the 2,800 matched writer byte intervals. Together with
  observer admission watermarks and chunk lengths these permit a fresh FIFO
  containment check; they do not include every additional sampled writer batch.
- `coverage-*.json`, `producer.json`, and `event-counts.json`: audited stage
  counts, one producer per probe reload, and lifetime/reload probe-event counts.
  `reload-N-inventory` replaces the distinct original allocation identity for
  reload N. One alias is shared by its release, consumer, admission, and producer
  records. Original numeric identities remain only in the raw archive.
- `summary-*.json` and `phase-and-rank-summary.json`: frozen initial analysis,
  sanitized only for identity. These use nearest-order-statistic quantiles and
  Spearman correlations with average ranks for ties.
- `tail-anatomy.png`: the existing probe distribution/association figure,
  rendered from the complete joined rows before the raw archive was frozen.
- `provenance.json`, `legs.json`, and `archived-raw-sha256.json`: source and binary
  hashes, workload, execution conditions, and identities of retained external
  raw evidence. Paths are logical archive labels. Hashes establish byte identity
  when those files are available; public extracts cannot authenticate unseen raw
  contents, source/build equality, or cleanup by themselves.
- `native-provenance.json`, `freezes.json`, and `builds.json`: native per-arm
  metadata, before/after execution identity maps, and separate build bindings.
  Freeze source maps retain the five locally instrumented files; the full
  tracked-source maps remain in the raw archive. Both execution freezes saw the
  probe worktree. The control binary was built separately from clean source;
  its build binding must not be inferred from the later execution worktree.
  Native binary paths are omitted; all retained source paths are repo-relative.
- `recompute.py`, `test_recompute.py`, and `recomputed.json`: a stdlib reader,
  malformed-evidence regressions, and freshly recomputed report arithmetic.
  The reader requires both native maps, exact workload/observer/stage coverage,
  ordered finite timestamps, FIFO containment, and complete artifact hashes.
- `SHA256SUMS`: hashes of every other file in this directory.

All millisecond timestamps are relative to the corresponding reload trigger.
Daemon wall timestamps were aligned using a monotonic/wall-clock bracket taken
by the observer process; `clock_uncertainty_us` is half that bracket width, not a
claim about every possible wall-clock error. Writer start to observer arrival
ends after receiver decoding and classification, so it includes receiver and
harness scheduling. It does not isolate kernel delivery. Writer elapsed includes
write-path setup; `busy_ns` measures wall time inside `Future::poll`, including
scheduler preemption, and is not CPU time. `Pending` is not a kernel wakeup
counter, and `send_buffer` is `SO_SNDBUF` capacity rather than occupancy.

The reader uses `sorted(values)[round((n-1)*p)]` for individual-observer quantiles,
matching the frozen analysis. Native per-reload aggregate medians use
`statistics.median` across four native values; the two estimators are deliberately
kept separate. The reader pins this dated workload and source/binary/raw hashes,
requires both arms' native/freeze/build maps, and checks their cross-bindings.
It validates the observer exports against native gap and
generation maps, then computes phase distributions and rank movement from the
exported join. It cannot recreate that join from unpublished full daemon logs or
prove absence of omitted raw events; strict original coverage and raw hashes
record that audit boundary.

From the repository root:

```bash
(cd docs/perf/artifacts/reload-observer-tail-2026-10-06 && sha256sum -c SHA256SUMS)
python3 docs/perf/artifacts/reload-observer-tail-2026-10-06/recompute.py > /tmp/reload-tail-recomputed.json
diff -u docs/perf/artifacts/reload-observer-tail-2026-10-06/recomputed.json /tmp/reload-tail-recomputed.json
python3 -m unittest discover -s docs/perf/artifacts/reload-observer-tail-2026-10-06 -p 'test_recompute.py'
```

The probe generated 229,470,514 daemon-log bytes, versus 8,179,071 for control,
including extensive initial-convergence logging. One fixed-order pair does not
qualify probe overhead, production tails, readiness, or a cross-daemon result.
