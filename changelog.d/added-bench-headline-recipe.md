### Added

- `just bench-headline <out-dir> <label>=<ref>...` runs the headline
  performance campaign in one command: it builds each arm from its own tree,
  checks that each daemon hashes the same at its ref, runs the IXP matrix S2
  and S3 legs, the IRR reload roots and the RR1000 campaigns with the arm
  order rotated each run, logs load, swap counters and CPU placement at every
  leg, resumes an interrupted campaign, and exits non-zero when a build or leg
  fails. `just bench-headline-summary` re-extracts the per-run
  `summary.csv` and the per-arm table from a campaign or a committed receipt
  bundle without running anything. See
  [`bench/scale/headline/run-campaign.sh`](../bench/scale/headline/run-campaign.sh).
