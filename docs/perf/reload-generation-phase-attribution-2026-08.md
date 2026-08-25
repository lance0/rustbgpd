# Reload-generation phase attribution (August 2026)

LAN-1165 asked why reloads 2–4 were slower than reload 1. Two fresh, sequential
full campaigns reproduced the curve and localized it, but did not establish the
internal mechanism. The decision is therefore **instrumentation only**.

The workload was identical in both roots: 320 members, 183,040 prefixes, seed
61, changed fraction 0.10, overlap 0, and four SIGHUP reloads. Both roots used
candidate `e5cd75b604a4988a57ffa7875694e82c4f964126`, descended from fetched
`origin/main` `3da4e43017d73a89a2a0c23a05fd5afd2b1374b2`. Checksums, provenance,
320/320 sessions, four rows, and zero decode errors/session loss all passed.

| Root | reload 1 total | later median | increase | RIB-transition share of delta |
|---|---:|---:|---:|---:|
| A | 478,614 µs | 1,787,955 µs | +273.57% | 98.87% |
| B | 462,544 µs | 1,819,660 µs | +293.40% | 99.42% |

Every record had 320 cohort targets, zero remainder targets, 320 deferred
refreshes, a committed outcome, and `authoritative_fallback=true`. That outer
flag is expected for per-client-best. The corresponding authoritative RIB batch
records had `n_fallback_members=0`, 320 shared members, and one destination
group. The repeated latency is therefore inside the synchronous batched
authoritative RIB transition, not a per-member degradation fallback.

This is localization, not a latency improvement and not a sufficient mechanism
for a fix. The next measurement must split
`apply_export_policy_replacements_synchronously` and
`apply_batched_group_transition` into non-overlapping subphases with
deterministic work counts, then reproduce the difference in deterministic
in-process RIB tests before any production change is considered.

The sealed rows and verification metadata are in
[`artifacts/reload-generation-phase-attribution-2026-08/`](artifacts/reload-generation-phase-attribution-2026-08/README.md).
