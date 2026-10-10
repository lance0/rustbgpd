### Added

- `just bench-converged-rejoin <out-dir> <base> <head>` measures the
  reloadstall converged-rejoin (GR helper) flapstorm, base against head at a
  low and a high K in alternating order, one fresh daemon per cell behind the
  quiet-host gate. Its shape and bars are written to `campaign.json` before
  the first cell, and `ACCEPTANCE` overrides the bars from a JSON file. The
  verdict is PASS, FAIL or INVALID, and any missing or malformed cell makes
  it INVALID. `SMOKE=1` runs a small pipeline check that applies every
  validity check but no performance bar, and `DRY_RUN=1` prints the plan.
  See
  [`bench/scale/reloadstall/README.md`](../bench/scale/reloadstall/README.md#converged-rejoin-ab-campaign).
