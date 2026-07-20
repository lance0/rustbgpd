# Adj-RIB-Out family-gauge benchmark artifacts

This directory retains the exact unrounded Criterion estimates used by
`../../adj-rib-out-family-gauge-2026-07.md`.

- `primary.csv`: control/target means and 95% confidence bounds, plus
  Criterion's paired mean-change estimate and bounds.
- `paired.csv`: exact means and confidence bounds from three additional
  retained pairs at 256 and 1,000 peers. `delta_percent` is
  `(target_mean_ns / control_mean_ns - 1) * 100`.
- `pair4-host-preflight.tsv`: the shared-lock/governor/load/competing-process
  preflight for the full-duration target-then-control pair.
- `controls.csv`: retained 256-peer existing-fanout regression controls. The
  policy row reports the reverse-order pair with its interval algebraically
  oriented as target versus control.
- `metadata.txt`: revisions, fleet, measured boundary, and host/toolchain
  metadata. The public receipt deliberately uses `<BENCH_HOST>` instead of a
  developer-machine hostname.
- `rejected-attempts.md`: excluded-attempt audit trail.
- `SHA256SUMS`: integrity hashes for the retained files.

Criterion estimates are nanoseconds. The CSV means and bounds are copied
without rounding from each retained `estimates.json`; derived deltas retain 15
decimal places.
