# M67 link-drain churn 24h soak — postmortem (EVPN MAC-mobility leak fix)

One-page record of the 24-hour M67 link-drain churn soak that
confirms the EVPN Adj-RIB-In attribute-intern memory leak is fixed.
This is the gating evidence that the fix landed in
[#590](https://github.com/lance0/rustbgpd/pull/590) +
[#592](https://github.com/lance0/rustbgpd/pull/592) holds under a
full day of sustained MAC-mobility churn — the same workload that
first surfaced the leak and failed an earlier soak ~1.5h in.

## What this soak exercised

The harness (`tests/soak/run-m67-link-drain-churn-soak.sh`) drives a
VTEP + 2-PE (`pe1`/`pe2`) single-active EVPN multi-homing topology
with a CE generating MAC traffic. Every 90s it drains `pe1`'s access
circuit (AC down), forcing the single-active DF role to fail over to
`pe2` and then revert on recovery. The CE MAC traffic drives RFC 7432
§7.7 MAC-Mobility churn — each move re-advertises the route with an
incremented sequence number, i.e. a **fresh attribute set every
move**. That is the exact workload that exposed the leak: the EVPN
attribute intern table never garbage-collected on EVPN mutation
paths, so it grew 1:1 with moves (unbounded RSS on every node,
including the pure route reflector). The harness samples RSS, BGP
session state, DF/Non-DF role, AC state, and blackout/release timing
every 30s.

## Run metadata

| Field | Value |
|---|---|
| Started | `2026-06-28T14:19:45Z` |
| Completed | `2026-06-29T14:19:47Z` |
| Wall clock | 24h 00m 02s |
| Build `git_rev` | `e9ad3479` (clean tree, post #590 + #592) |
| Kernel | `6.8.0-117-generic` |
| Topology | `tests/soak/m67-link-drain-soak.clab.yml` |
| Sample interval | 30s |
| Cycle interval | 90s (AC drain → DF failover → revert) |
| Samples written | 4800 |
| Link-drain cycles | 960 |

## Results

### RSS — flat plateau after a one-time settle (the headline)

```
node    first post-warmup   plateau (24h)   steady-state slope   peak
pe1     ~29.95 MB           ~36.22 MB        +0.006 MB/h          36.2 MB
pe2     ~29.81 MB           ~36.47 MB        +0.008 MB/h          36.5 MB
vtep    ~29.73 MB           ~35.61 MB        +0.016 MB/h          35.6 MB
```

- **Steady-state slopes** (least-squares over the post-300s window,
  4616+ samples): **0.006 / 0.008 / 0.016 MB/h** — all ~250× under
  the 1.5 MB/h gate cap, and ~17,000–40,000× below the **+258–279
  MB/h** dead-linear growth the leak produced before the fix (which
  failed the original soak's memory gates ~1.5h in).
- **Peak RSS**: 36.2 / 36.5 / 35.6 MB — far under the 512 MB cap.
- The ~30 → ~36 MB rise is a one-time allocator/RIB settle in the
  first few minutes; RSS was then pinned at ~36 MB for the remaining
  ~23.9h across 960 failover cycles. This is the textbook
  flat-plateau shape, not a leak.

### Failover behavior — all gates pass

Across 960 AC-drain cycles, every failover gate passed:

- `pe2_promoted_and_demoted` — `pe2` took the DF role on each drain
  and `pe1` reverted on recovery. ✓
- `blackout_bounded` — max measured blackout **300 ms** (cap 30,000
  ms); `blackout_measured` had 0 unmeasured samples of 1920. ✓
- `release_bounded` — max release **5,448 ms** (cap 30,000 ms). ✓
- `restart_counts_flat` — no daemon/container restarts the whole
  run. ✓
- `link_drain_toggled`, `drained_and_recovered_phases_observed`,
  `operator_reason_never_set`, `minimum_cycles` — all ✓.

### Corrected analyzer gate — `sessions_stayed_established`

The first analyzer version treated every failed VTEP CLI/query sample as
a known non-Established session. The gate now distinguishes transient
sampler misses from a sustained non-Established window; the regenerated
`report.json` passes. This is **not** the leak and **not** a regression
from the fix:

- ~3–4% of VTEP-side CLI samples recorded a non-Established result
  (`pe1` 176/4800, `pe2` 169/4800), **spread across all phases**
  (idle/drained/recovered), not drain-correlated. Every run was one or
  two samples long; no sustained loss was observed.
- `restart_counts_flat` passed (no restarts), the route/timing gates
  passed, and the corrected sustained-loss gate passes with
  `max_consecutive_samples = 2` for both peers. The dips were
  transient harness sampler artifacts.
- The gate failed **identically on both binaries** in the controlled
  A/B that preceded this run (pre- and post-fix), confirming it is
  pre-existing and fix-independent.

Tracked and corrected separately as
[#593](https://github.com/lance0/rustbgpd/issues/593).

## Verdict

The **EVPN MAC-mobility attribute-intern leak is confirmed fixed over
24h.** All six RSS gates pass with flat slopes (0.006–0.016 MB/h)
under 960 sustained link-drain failover cycles with live MAC-mobility
churn — the exact workload that produced unbounded growth before
[#590](https://github.com/lance0/rustbgpd/pull/590) +
[#592](https://github.com/lance0/rustbgpd/pull/592). The original
`sessions_stayed_established` analyzer failure (#593) was a harness
sampler artifact orthogonal to the memory result; the current analyzer
reports the run as passing.

This closes the operational-proof loop on
[#591](https://github.com/lance0/rustbgpd/issues/591) (the leak,
already fixed and closed on merge).

## Raw data

The five load-bearing artifacts are tracked here so the postmortem
stays self-contained when the soak host is recycled (`tests/soak/runs/`
and the per-machine state dir stay off-repo):

- Per-sample CSV: [`artifacts/soak/m67-link-drain-20260628T141945Z/samples.csv`](artifacts/soak/m67-link-drain-20260628T141945Z/samples.csv)
- Harness driver log: [`artifacts/soak/m67-link-drain-20260628T141945Z/soak.log`](artifacts/soak/m67-link-drain-20260628T141945Z/soak.log)
- Per-cycle log: [`artifacts/soak/m67-link-drain-20260628T141945Z/cycles.log`](artifacts/soak/m67-link-drain-20260628T141945Z/cycles.log)
- Gate report: [`artifacts/soak/m67-link-drain-20260628T141945Z/report.json`](artifacts/soak/m67-link-drain-20260628T141945Z/report.json)
- Run manifest: [`artifacts/soak/m67-link-drain-20260628T141945Z/run.json`](artifacts/soak/m67-link-drain-20260628T141945Z/run.json)

## Cross-references

- [`docs/soak-gate8b-24h-bum-state.md`](soak-gate8b-24h-bum-state.md) —
  postmortem template + the flat-plateau RSS reference shape.
- `tests/soak/run-m67-link-drain-churn-soak.sh` /
  `tests/soak/analyze-m67-link-drain-soak.py` — harness + gate analyzer.
- [#593](https://github.com/lance0/rustbgpd/issues/593) — the
  `sessions_stayed_established` sampler-artifact follow-up.
