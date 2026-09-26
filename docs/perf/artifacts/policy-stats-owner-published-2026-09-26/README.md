# Policy-stats reload cell: owner-published counter reads — 2026-09-26

> **Document class: HISTORICAL.** This receipt describes one bounded local cell at the revisions below.

This receipt records the isolated-cell qualification run for
[ADR-0136](../../../adr/0136-owner-published-counter-reads.md) on main
`292c32b39d1c9f8f056a472ed0c6d0a72658e87f` (2026-09-26 UTC), together with
the summaries of the same cell at the slice 0 baseline and at the slice 2 and
slice 3 development heads. It measures `GetPolicyStats` latency through
changed-policy reloads at one shape and placement. It is not a soak
qualification, a scale result beyond this shape, or a general operator deadline
guarantee.

## Setup

- **Harness:** `bench/scale/reloadstall/policy_stats_cell.{sh,py}`, as described
  in the [reloadstall README](../../../../bench/scale/reloadstall/README.md#policy-stats-reload-cell).
- **Shape:** 1,000 loopback eBGP route-server peers with 400 IPv4 prefixes each
  (400,000 total). Every peer changes export policy; 12 SIGHUP reloads in
  alternating directions, 15 s control window, 40 s quiesce.
- **Calls:** per reload, one `rbgp policy stats --direction both` and
  `rbgp neighbor` pair fired 0.50 s after the cohort hot-apply completes, and
  one quiescent `policy stats` probe 20 s after the reload completes. Nothing
  is retried.
- **Placement:** AMD Ryzen Threadripper 7970X. Daemon on CPUs 2–3 with two
  runtime workers, `reloadstall` on CPUs 4–5, probes and CPU sampler on
  CPUs 8–15. Every run below uses the same placement.
- **Build:** release `rustbgpd` and `rbgp` 0.72.0 at each source, Rust 1.98.1.
  Hashes are in [binary-hashes.txt](binary-hashes.txt). The qualification
  daemon binary is byte-identical to the slice 3 head's; the commits between
  them changed the CLI and documentation only.
- **Host:** load average 1.95 at start and no compiler processes. During the
  calls, foreign load on the daemon CPUs had a p95 of 0.02 cores and a
  maximum of 0.07.

## Criterion

The ADR's flat criterion: every call completes within the external 2 s
criterion with all 1,000 import and 1,000 export rows, at least six complete
pairs start in the −220 to 0 ms band before the RIB commit, and the in-band
maximum of the summed stage `elapsed_ms` stays within twice the quiescent
median plus 50 ms. Stage times are whole milliseconds, so 0 means under 1 ms.

## Results

| Run | Source | Verdict | In-band summed stage max | Limit | External CLI in-band min / p50 / max | Quiescent external p50 |
| --- | --- | --- | ---: | ---: | --- | ---: |
| Slice 0 baseline | `439cb3412` | FAIL | 469 ms | 52 ms | 223 / 458 / 487 ms | 10.3 ms |
| Slice 2 head (import roster) | `3af1c3292` | FAIL | 171 ms | 50 ms | 138 / 201 / 277 ms | 10.0 ms |
| Slice 3 head (export roster) | `904676ad5` | PASS | 0 ms | 50 ms | 57 / 138 / 239 ms | 9.8 ms |
| **Qualification, merged main** | **`292c32b39`** | **PASS** | **0 ms** | **50 ms** | **58 / 70 / 229 ms** | **10.2 ms** |

In every run all 12 pairs started in band, with no deadline misses, no calls
over 2 s and no invalid audit records, and every statistics reply carried
1,000 import and 1,000 export rows. Slice 0 failed only the flat criterion:
its export stage waited up to 256 ms for the RIB, its import stage up to
454 ms in peer-manager admission and collection, and its datasets stage up to
38 ms. Slice 2 removed the import
and dataset waits; its remaining 171 ms was the export stage. From slice 3 on,
every stage of every call took under 1 ms.

In the qualification run:

- Pairs started 93.5 to 80.8 ms before the RIB commit.
- The import stage read 1,000 of 1,000 publications with 0 yields in every
  call.
- All 12 reloads committed with no cohort exclusions and no remainder targets.
  SIGHUP to RIB commit had a p50 of 1,301 ms, and the RIB transition took
  581–589 ms.
- Each statistics reply reported one export counter-instance id across all
  1,000 rows, either the instance before the commit or the one after it,
  never a mix. The id advanced once per reload, from 2002 to 2013.
- Neighbor pair calls took 324–493 ms with 1,000 rows each. Stale neighbor
  rows per body were `[0,0,0,0,26,28,0,1,49,0,0,0]`; they are counted, not
  gated.

## Limits

The external CLI time still includes process start, runtime scheduling,
rendering and delivery, which ADR-0136 does not remove. Two runtime workers,
1,000 peers, one export-policy change per reload and a quiet host are one
shape; this cell says nothing about larger fleets, other placements or a
co-pinned generator. The next route-server flagship soak is the remaining
qualification step.

## Files

- [summary.json](summary.json) and [environment.json](environment.json): the
  qualification run's analyzer output (every call, commit offset, parsed audit
  line and verdict) and its source, binary hashes and placement.
- [probes.jsonl.gz](probes.jsonl.gz): every probe record with reply-body
  hashes. Reply bodies are not retained.
- [cpu.jsonl.gz](cpu.jsonl.gz): 1 s CPU samples of the pinned cores and their
  SMT siblings.
- [metrics-before.prom.gz](metrics-before.prom.gz) and
  [metrics-after.prom.gz](metrics-after.prom.gz): daemon metrics around the run.
- `slice0-`, `slice2-` and `slice3-` `summary.json` / `environment.json`: the
  earlier runs in the table.
- [binary-hashes.txt](binary-hashes.txt): source commit and executable hashes
  for every run.

Re-run the analyzer over a complete run directory with
`python3 bench/scale/reloadstall/policy_stats_cell.py analyze <run>`. The
daemon log and reply bodies stay outside the repository.
