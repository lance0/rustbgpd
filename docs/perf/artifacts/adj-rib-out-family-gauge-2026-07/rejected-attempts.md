# Rejected attempts

The retained CSV files exclude the following preflight-invalid work:

- An initial comparison that reused one Cargo target directory across control
  and target worktrees. It was aborted after the executable identity problem
  was detected; the retained primary run uses separate target directories.
- Two short target attempts during which a local inference server became
  CPU-active on the pinned core. They were rejected rather than averaged into
  favorable or unfavorable results. The clean pair-3 target was rerun and
  overwrote its invalid estimate directory before the retained values were
  copied.
- The first short `distribute_fanout/with_policy/256` regression-control pair
  reported a 3.44% target regression. It crossed the 3% ceiling and was not
  used to pass the gate. A full-duration reverse-order pair reported 1.72%
  with a +1.33% to +2.22% interval; that pair is retained in `controls.csv`.

No rejected estimate contributes to `primary.csv` or `paired.csv`.
