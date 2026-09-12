# RIB summary reads during rollback — 2026-09-12

> **Document class: HISTORICAL.** One bounded local baseline/candidate pair at the revisions below.

Both runs completed an authoritative rollback with responsive operator reads.
The candidate served eight calls starting inside its frozen-summary interval
in 18.814–38.489 ms. The baseline also met the 2-second deadline: this pair
provides native branch and observation evidence, without reproducing a baseline
deadline failure or establishing a speedup.

## Shape and identity

Each daemon had 1,000 loopback route-server peers with 400 accepted base
IPv4 prefixes each. The unchanged `reloadstall` engine supplied 999 peers and
399,600 prefixes; a Python peer supplied the remaining 400, with IPv4 MP and
AS4 capabilities but no Route Refresh. Before and after the trigger, all
1,000 current sessions were Established. The engine's ordinary control churn
made the restore inventories 400,016 and 400,048 respectively.

Both used Rust/Cargo 1.98.1, release builds, and
`--features rustbgpd-rib/bench-internals`. Daemon CPUs were 2–3, engine/Python
peer CPUs 4–7, and probe CPUs 8–15. Harness scripts and both policy generations
were byte-identical; parsed configurations match after removing only the two
local runtime/socket paths. Full source, executable hashes, build commands,
normalization, and harness hashes are in [summary.json](summary.json).

- Baseline: `122c0f40de79b6a12c2a237dd280e6136aa9eea6` plus the four-line
  [trace-only marker patch](baseline-markers.patch), SHA-256
  `bf5d915c5bc84488e628f965cc92d597486e44d5ff439e9238a94633bba11f8a`.
- Candidate: clean `fcd9dc87f33e1a3654e38351b2b300e32bb91bec`.

## Observed branch and calls

During the engine's 900-second control window, the controller changed both
existing policy chains and sent one SIGHUP. Each run committed a 1,000-member
RIB cohort, then the daemon rejected the deferred import refresh because
that peer had not negotiated Route Refresh. Both executed a 1,000-member authoritative restore and recorded exactly
one `rejected_no_effect`, with zero complete, partial, ignored, or task-failure
deltas. This exercises rollback after commit, not rejection during preflight.

For 120 seconds, separate `neighbor` and `policy stats --direction both` CLI
streams waited 200 ms after each completion before their next call. Each stream
had at most one call in flight and a 5-second driver cap.

| Observation | Baseline | Candidate |
| --- | ---: | ---: |
| All-phase CLI calls | 1,098 | 1,106 |
| Failed calls / calls above 2 s | 0 / 0 | 0 / 0 |
| Neighbor calls starting inside measured restore/interior | 1; 960.575 ms | 4; 18.814–35.634 ms |
| Stats-both calls starting inside measured restore/interior | 1; 1,124.832 ms | 4; 21.272–38.489 ms |
| Whole restore elapsed | 1,106.767 ms | 1,114.594 ms |
| Restore process RSS samples | 466,616–699,752 KiB | 465,772–667,960 KiB |

The baseline had one additional stats call overlapping entry; the candidate had
one additional call of each operation overlapping entry. Those calls started
before the measured interior and are reported separately in the summary.

Candidate capture recorded 2,678 µs and retirement 689 µs for 1,000 peers,
1,000 policies, 1,000 terms, and one group. These elapsed scopes include
checkpoint/read service, not isolated allocation/free CPU. Its frozen-summary
interior lasted 1,111.194 ms. Baseline markers enclose readiness setup and
terminal cleanup; candidate markers sit inside those boundaries. Process RSS
was sampled every 100 ms, with no sample inside capture or retirement; it
cannot identify projection allocation bytes or guarantee a transient peak.

Seven expected rejection warning/error records occurred in each probe interval.
After the last probe, owned teardown produced channel/writer warnings:
11,821/918 for baseline and 11,406/921 for candidate. All owned children were
reaped and listening ports released. Earlier fixture and preflight failures
are excluded from this pair and retained locally.

## Evidence

The checksummed compressed files retain all per-call rows, selected branch and
phase records, before/after session inventories and outcome counters, and RSS
samples around each restore. The normalized configuration is retained too.
[summary.json](summary.json) maps each run to its measurements;
[original-raw-hashes.json](original-raw-hashes.json) identifies the full local
inputs. [SHA256SUMS](SHA256SUMS) covers the published files. Decode `.gz` files
as ordinary JSON, JSONL, or Prometheus text. No full daemon logs or local paths
are published.
