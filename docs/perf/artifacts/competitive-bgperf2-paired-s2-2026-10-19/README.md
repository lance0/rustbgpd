# bgperf2 paired-read rerun and IXP S2 rerun, 2026-10-19

Two same-host measurements from one daytime quiet window on 2026-10-19, both
against unreleased rustbgpd commit `3e3fba0de8f1955c3b979ac3705827636dc886e4`
(after v0.78.0; it reports itself as 0.78.0), built from a clean tree.

## bgperf2 import comparison

Three of the five fixed shapes (10 peers × 1,000 prefixes, 2 × 10,000 and
2 × 100,000), with three repetitions per cell. All 36 runs exited 0 and reached
the expected route count.

- **Targets:** rustbgpd `3e3fba0de`, BIRD 2.19.3, BIRD 3.3.3 and GoBGP 4.10.0.
  The comparator images are the ones from the
  [morning spot-check](../competitive-bgperf2-spot-check-2026-10/README.md);
  `provenance.json` records every image id.
- **Testers and monitor:** BIRD 2.19.2 testers and a GoBGP 4.8.0 monitor, as in
  the v0.68.0 campaign and the morning spot-check.
- **Harness:** bgperf2 fork commit
  [`1a2648d`](https://github.com/lance0/bgperf2/commit/1a2648da73b4e89e2a6ad0ce00367ca8f665eb73),
  which adds target-read pairing. Each monitor sample is decided against the
  target read that started between half a poll before it and 50 ms after it,
  waiting for that read if it is still in flight. The rule is the same for every
  target. Earlier revisions decided each sample on whichever of two
  free-running polls had been dequeued first, so a target whose read finished
  a millisecond after the monitor's could lose a whole one-second tick.
- **Pairing per run:** `bgperf2-results.csv` adds the paired and unpaired
  sample counts and the start-offset range from each run's
  `instrument.target_read_pairing`. Every run paired every sample except
  GoBGP 4.10.0 at 10 × 1k in repetition 1 (8 unpaired).
- **Order:** repetitions 1 and 3 ran rustbgpd, BIRD 2.19.3, BIRD 3.3.3 and
  GoBGP for each shape; repetition 2 ran them in reverse.

## IXP S2 policy reload

Three fresh processes per daemon at 700 route-server members × 400,400 IPv4
prefixes, two reloads per process, 30 s control window, with the daemon order
alternated by repetition. OpenBGPD is 9.3, image
`openbgpd/openbgpd@sha256:8f4b44f25796beaecb72ab7f099a3914961ac444a9de094ffca6a4614e741412`,
the same pin as the v0.75.0 cross-daemon receipt. The `reloadstall` harness
was built from the same commit, with churners phased on a fixed grid. Each leg
checks the control window's merged churner write stream against a 31.25 ms
bound and is INVALID above it. All six legs were VALID, with churner write
gaps of 16.7–18.4 ms.

`s2-legs.csv` has one row per reload: the control-window gap quantiles, the
churner write gap, and the changed-observer `changed_maxgap` p50, p95 and
maximum.

## Files

- `bgperf2-results.csv`: the harness's single-row CSV output for each run,
  plus the pairing columns and a `source_run` column.
- `provenance.json`: the harness revision and the target, tester and monitor
  image ids and versions recorded for each run.
- `s2-legs.csv`: the S2 per-reload summary.
- `analysis.txt`: the queue's summary for both measurements, with local paths
  and internal tracker references replaced by placeholders and labels.

`SHA256SUMS` hashes each file. The host is the AMD Ryzen Threadripper 7970X
described in [the benchmark page](../../../benchmarks.md#2026-10-19-paired-read-rerun).
bgperf2 total time moves in roughly one-second steps, set by the monitor's poll
and stability wait, and convergence is whole seconds.
