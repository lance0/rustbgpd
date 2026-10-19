# Competitive bgperf2 spot-check, 2026-10-19

This is a same-host comparator spot-check, not a campaign. It covers three of the
five fixed shapes (10 peers × 1,000 prefixes, 2 × 10,000 and 2 × 100,000), with
two repetitions per cell. All 24 runs exited 0 and reached the expected route count.

- **rustbgpd:** unreleased commit `0900224939ced8bb662aaed10c49d305837dc901`
  (after v0.78.0; it reports itself as 0.78.0). The image was built from a clean tree.
- **BIRD 2.19.3:** the like-for-like refresh of the BIRD 2.19.2 column in the
  v0.68.0 campaign.
- **BIRD 3.3.3:** a new comparator with no earlier bgperf2 counterpart.
- **GoBGP 4.10.0:** refreshes the GoBGP 4.8.0 column.
- **Testers and monitor:** BIRD 2.19.2 testers and a GoBGP 4.8.0 monitor, the
  same versions as the v0.68.0 campaign.
- **Harness:** bgperf2 revision `4a13f8d0c`, a local commit on the fork that pins
  the comparator builds to the upstream tag commits (BIRD 3.3.3 `2ed8b593`,
  BIRD 2.19.3 `5c6376d3`, GoBGP v4.10.0 `da824d99`). It is not published in the
  fork. The v0.68.0 campaign used `d0449574`.
- **Order:** repetition 1 ran rustbgpd, BIRD 3.3.3 and GoBGP for each shape;
  repetition 2 ran them in reverse. The BIRD 2.19.3 runs came last, repetition 1
  then 2.

`results.csv` holds the harness's single-row CSV output for each run, in
filename order, with a `source_run` column naming the run. `provenance.json`
records the harness revision and the target, tester and monitor image ids and
versions that the harness recorded for each run. Every run recorded the same
tester, monitor and harness. The host is the AMD Ryzen Threadripper 7970X
described in [the benchmark page](../../../benchmarks.md#2026-10-19-comparator-spot-check).

Two repetitions per cell are not enough to separate small differences from
run-to-run variation. The totals have 0.01 s resolution, and convergence is
whole seconds.
