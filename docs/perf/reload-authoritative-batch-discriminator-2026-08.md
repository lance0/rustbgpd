# Authoritative reload-batch discriminator (August 2026)

Two fresh, sequential single-cell campaigns split the synchronous authoritative
RIB transition into exclusive phases and deterministic work counts. They
reproduce the later-reload asymmetry and narrow its location, but the frozen
two-root adjudicator returns `negative_result`: no phase has the required directional owned-counter witness.

## Receipt

Both roots used exact candidate `09c1a1342c86c118e34a62d30c53d1cf159b3ade` (tree
`f7e638f7bb6ba455aa72e83c855e5c00f698e1d7`) over fetched main
`9fc3286dcea4c8f1a5d371a782931a416e30a4b6`. The frozen shape was 320 members,
183,040 prefixes, four SIGHUP reloads, changed fraction 0.1, seed 61, and overlap 0.

| Root | Reload 1 total | Later median | Increase | Registration/membership share of delta |
|---|---:|---:|---:|---:|
| A | 476,553 µs | 1,772,219 µs | 271.88% | 101.53% |
| B | 467,851 µs | 1,791,971 µs | 283.02% | 99.40% |

Every reload retained 320/320 sessions, a committed shared outcome, 320 shared members,
zero fallback members, one destination cohort, zero dirty or pending residue, and zero parse errors.
Both 30-entry root checksum rosters passed; raw daemon logs re-extracted both phase CSVs byte-for-byte;
candidate, tree, tracked scripts, binaries, workload, environment, and dataset identities match; daemon identities are distinct and sequential.

## Boundary

`registration_membership_us` grows from 1,294 µs to a 1,316,790 µs later median in A
and from 1,333 µs to 1,317,455 µs in B. That stage installs the resolved policy chains
and computes destination membership. Its input and present-peer counts remain exactly
320 in every row, so the receipt does not prove which internal work increased. Other owned counters change only with the small generation-specific route inventory and do not explain the timing delta.

This is stage localization, not a mechanism, latency improvement, or
authorization to optimize. Any next tranche must add deterministic work counts
inside registration/membership and pass the same two-root gate; this receipt
does not license a speculative correction or an opportunistic rerun.

The exact rows, retained full-root adjudicator output, and sanitized verification record are
[`authoritative-batch-phases.csv`](artifacts/reload-authoritative-batch-discriminator-2026-08/authoritative-batch-phases.csv),
[`authoritative-pair.json`](artifacts/reload-authoritative-batch-discriminator-2026-08/authoritative-pair.json),
and [`verification.json`](artifacts/reload-authoritative-batch-discriminator-2026-08/verification.json).
Validate the checked publication without the raw roots with
`python3 bench/scale/irrreload/verify-receipt.py authoritative-publication --artifact-dir docs/perf/artifacts/reload-authoritative-batch-discriminator-2026-08`.
