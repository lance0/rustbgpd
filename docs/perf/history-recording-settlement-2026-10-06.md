# Config-history recording and reload settlement (2026-10-06)

The predeclared settled-boundary performance criterion was **not met** in a
quiet six-process A/B at 400 BGP sessions and 184,000 generated prefixes.
The candidate preserves history behavior while decoding only the unique newest
record during writer deduplication. Its largest process-leg median was
566.3215 ms, above the baseline's smallest median of 548.4575 ms. Both the
process-leg ranges and raw reload ranges overlap.

| Trigger to settled | Baseline A | Candidate B |
| --- | ---: | ---: |
| Three process-leg medians, ms | 548.4575 / 564.5800 / 568.5955 | 546.8975 / 566.3215 / 549.9970 |
| Process-leg median range, ms | 548.4575–568.5955 | 546.8975–566.3215 |
| Median of three process-leg medians, ms | 564.5800 | 549.9970 |
| Twelve raw reloads: min–max, ms | 528.033–614.156 | 529.982–569.757 |

The 14.583 ms (2.58%) lower median of the three candidate legs is descriptive.
Three legs per arm do not establish statistical significance, a latency bound
or a settled-boundary gain. This result also does not establish that the
remaining gap is required durability work. All 24 reloads, including each
first reload, remain in the [compact evidence bundle](artifacts/history-recording-settlement-2026-10-06/README.md).

## Milestones, receiver observations and health

The `config reload complete` and `runtime config settlement settled`
milestones retain their existing positions. Each elapsed time is paired with
the same SIGHUP operation ID. The table below uses the median of three
process-leg medians for each metric; a gap median is computed from the four
per-reload gaps, not by subtracting the complete and settled medians.

| Observation | Baseline A | Candidate B |
| --- | ---: | ---: |
| Trigger to complete, ms | 508.5085 | 503.1970 |
| Complete to settled, ms | 54.9690 | 43.7805 |
| Receiver completion p50, s | 0.5558345 | 0.5483135 |
| Receiver completion p95, s | 0.5634675 | 0.5543505 |
| Receiver completion maximum, s | 0.5811795 | 0.5760025 |
| All-observer stall p95, ms | 423.2580 | 402.5065 |
| All-observer stall maximum, ms | 434.7030 | 419.5325 |

Every reload kept 400/400 sessions with zero parse errors and passed the
withdrawal checks. Each leg retained four matching settlement acknowledgements,
fresh history sequences 1–5, normal daemon teardown (`wait_exit=0`, `forced=0`)
and successful launcher, leg and harness exits. All six full 300-second
cooldowns completed, including the final one. Campaign, wrapper, recorder and
actual wait exits were zero. Postflight confirmed all 19 owned processes and
groups gone, six daemon cgroup scopes absent, reusable ports and the host lock
released.

The bundle retains every receiver field, including completion and
first-generation p50/p95/max, changed/all-observer stalls and RSS. Memory
readings cover **through harness completion** and remain **diagnostic only**;
they do not bound the full daemon lifetime. Whole-cgroup CPU is unavailable
because the unchanged cell does not capture `cpu.stat`.

## Writer behavior and regression evidence

After the existing cleanup and over-cap repair, the candidate compares the
highest two sequence numbers in the full sorted filename roster. It decodes
the newest record only when that sequence is unique. Duplicate highest
sequences continue to refuse deduplication and require a new record; older
duplicate sequences do not prevent deduplication of a unique newest record.
Operator history listing continues to decode all retained records.

The newest record is still opened and decoded twice, with content digests and
exact-object identity revalidated before deduplication. Filename chronology,
newer-format refusal, owner/type checks, retention, recovery, staging, rename
and every existing durability sync remain unchanged. The change introduces
no new setting or milestone.

All 58 focused history tests passed before and after two controlled failing
mutations. Restoring full-roster decoding broke the decode-open regression;
removing only the uniqueness guard broke both valid matching V2 and V3
duplicate-highest regressions. The restored source passed the full local gate,
normal commit hooks and a default-feature release build with Rust/Cargo/Clippy
1.99.0. Canonical history fixtures and full listing remain covered.

The counter regression starts with twenty retained records. The candidate
writer performs two decode opens, while a full twenty-record listing performs
twenty; restoring the previous writer produces twenty-one recording opens.
These are test counters. The daemon workload instead starts with one V2
startup record and appends sequences 2–5 across four reloads, without prefill
or extra warmup. Source inspection predicts writer decode opens of 2/3/4/5
for the baseline and 2/2/2/2 for the candidate. These are source-derived counts,
not measured CPU, syscall or daemon latency results. The first reload has the
same predicted count in both arms.

## Completed attribution diagnostic

A separate baseline control–trace–control diagnostic preceded the A/B. Each
process performed four reloads at the same 400-session/184,000-prefix shape
and a full 300-second cooldown. All workload, daemon cleanup and campaign
exits were zero, with 400 sessions and zero parse errors.

| Diagnostic leg | Complete to settled median, ms | Range, ms | Median receiver completion p50, s |
| --- | ---: | ---: | ---: |
| Untraced control before | 71.372 | 56.485–86.889 | 0.545210 |
| Selected-syscall trace | 68.4585 | 41.923–70.628 | 0.931986 |
| Untraced control after | 67.812 | 51.475–78.369 | 0.559058 |

The gap ranges overlap. Tracing increased receiver completion time relative
to both untraced controls. This diagnostic is attribution evidence and does
not enter the performance A/B pool.

| Traced reload | Complete to settled, ms | Successful selected sync/rename interval union, ms | Unassigned remainder, ms |
| --- | ---: | ---: | ---: |
| 1 | 41.923 | 3.162 | 38.761 |
| 2 | 66.438 | 11.224 | 55.214 |
| 3 | 70.628 | 6.184 | 64.444 |
| 4 | 70.479 | 4.812 | 65.667 |

The union counts overlapping intervals once and clips them to the paired
complete/settled window. Observed sync/rename coverage accounts for a small
part of each gap. The remainder stays unassigned; it does not establish
required durability cost, history-decoding cost, blocking-pool delay or
scheduler delay.

Source review found synchronous retained-record decoding between the
cleanup-directory sync and staged-file sync, including canonical JSON,
digest/manifest validation and TOML summaries. Writer deduplication uses only
the unique newest record's decoded content. This source mapping motivates the
candidate without assigning a measured duration to decoding.

## Predeclared method and provenance

Six fresh daemon process legs ran in A–B / B–A / A–B order: 01-A, 02-B,
03-B, 04-A, 05-A, 06-B. Each leg used 400 peers, 184,000 generated prefixes,
seed 61, 0% IRR policy changes, changing export communities, a 30-second
control and four SIGHUP reloads. Both arms consumed identical datasets and
renderer/harness bytes, with native loopback networking.

The independent observation is a fresh daemon process leg. Its primary
response is the median trigger-to-settled elapsed time across four correlated
reloads, giving three observations per arm. Before measurement, the criterion
was fixed as:

```text
max(candidate process-leg medians) < min(baseline process-leg medians)
```

That criterion is false. The raw-round ranges also overlap and are reported
separately. The campaign retained exclusive timing ownership, the original
two-sample quiet admission before every leg, exact daemon process identities,
native daemon-only cgroups with swap disabled, existing deadlines and the
100 GiB RSS abort. There was no trace pooling, optional success stop, retry
inside a campaign, row exclusion, prefill or new sampling instrumentation.

Two earlier attempts remain separately retained: a pre-workload freshness
rejection, then a baseline-only leg whose post-leg report compared the
filename's `source_sha256` against the distinct normalized-TOML `sha256`.
Both attempts exited 1. The corrected checker binds the filename to
`source_sha256` and independently verifies the normalized TOML digest; it
changes no workload, milestone or runtime code. A separately retained full
300-second cooldown followed the failed baseline leg. Neither attempt enters
the fresh completed six-leg pool, and no final-campaign row was excluded.

| Measured runtime | Commit | Tree |
| --- | --- | --- |
| Baseline A | `dcc9b6384d2f7931d4aa905b0cdc1e55efd790c4` | `adeb355e88708a3d7ef1c96a6cd173c3f366e9f4` |
| Candidate B | `6bbc0a1e1b44df7a9b325f95762ed2da8a81c432` | `0e8958dac582c6af8d6216de2a2a34ba228da4ab` |

These remain the measured runtime sources if later documentation changes the
branch head. Default-feature daemon SHA-256 values are
`4c98759f7623858f23543754d02bca43266e5da691c62a78d3dfbc2995ab9c2d` for A
and `8cb508568b4fc522053e9c6f225af7e0582ced7821b8f15db0a3af8495527ba8`
for B. The candidate daemon was freshly built. Its renderer and scale harness
are unchanged baseline-produced binaries, retained with their original
successful producer build logs; no candidate scale build is claimed.

The [bundle inventory](artifacts/history-recording-settlement-2026-10-06/README.md)
describes all rows, 30 history scalar records, controls, quiet/cooldown/exit
evidence, memory and exact component provenance. Full V2 envelopes and raw
logs remain outside the repository because encoded configuration paths occur
in their contents. The compact bundle can reproduce timing aggregates and
verify its own hashes; it cannot rerun full private validation.
