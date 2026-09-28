### Added

- `just bench-headline <out-dir> <label>=<ref> <label>=<ref>...` runs the
  headline performance campaign across two or more arms in one command: it
  builds each arm from its own tree, checks that each daemon hashes the same
  at its ref, runs the IXP matrix S2 and S3 legs, the IRR reload roots and the
  RR1000 campaigns with the arm order rotated each run, logs load, swap
  counters and CPU placement at every leg, resumes an interrupted campaign
  only with the shape it started with, and exits non-zero when a build or leg
  fails. `just bench-headline-summary <out-dir>` re-extracts the per-run
  `summary.csv`, including the daemon's own reload intervals, and the per-arm
  table without running anything; a committed receipt bundle also needs
  `--out <dir>`. See
  [`bench/scale/headline/run-campaign.sh`](../bench/scale/headline/run-campaign.sh).
