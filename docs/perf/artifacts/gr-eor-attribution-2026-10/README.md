# GR EoR attribution inputs

These six one-line JSON files are the raw samples for the
[October 2026 receipt](../../gr-eor-attribution-2026-10.md). Nanosecond fields
are direct bench output; the receipt rounds them to milliseconds.

| File | Fixture | Instrumentation binary |
| --- | --- | --- |
| `dual.jsonl` | 1M IPv4 + 200k IPv6, one attribute set | Earlier four-mode binary |
| `pcb-group.jsonl` | Same routes, grouped per-client-best | Earlier four-mode binary |
| `pcb-fallback.jsonl` | Same routes, per-peer fallback | Earlier four-mode binary |
| `ipv4.jsonl` | 1M IPv4, one attribute set | Earlier four-mode binary |
| `dual-sets-1.jsonl` | 1M IPv4 + 200k IPv6, one attribute set | Final diversity-control binary |
| `dual-sets-148667.jsonl` | Same routes, 148,667 MED-distinct sets | Final diversity-control binary |

All rows report zero affected, changed and retained-stale routes and zero
outbound envelopes at every EoR; the final bench source asserts this tuple.
The final-binary rows also report a
requested set count equal to the interned set count; every row has capacity
at least as large as its interned count. `gr_complete` is 1 only after the
last family EoR. The two final-binary rows ran consecutively on core 36 at
2026-10-02 16:01 UTC, under the repository host lock and a separate benchmark
lock. Pre-run checks found no competing build, profiler, bench or daemon
process. The earlier four modes ran at 15:40–15:41 UTC under the same lock
order and process guard. The host had 64 logical CPUs and more than 100 GiB
available memory; a shared model scheduler was active. Neither campaign was
repeated. The process and load receipts remain outside this compact public
artifact; no sample was discarded or replaced.

Both binaries were built from base commit
`1531ca860cd91bf5a8f3c6a8e6d8ce313336c73d` with Rust/Cargo 1.99.0,
`Cargo.lock` SHA-256
`0b06f1bb7410c43e28619a0d3c9f7ab0810ea21804262d6f311db5b6e9bf1e79`,
the `bench-internals` feature and the optimized Cargo bench profile.
The earlier four-mode binary SHA-256 was
`71608bbd390962f5fab189d5749e5622ab1e6274423814cf0fb74e496ad0e071`;
its uncommitted source diff SHA-256 was
`217b1d5bd93333f5a74fd935d26c07d3daa4056fabc76bd76a71664154546893`.
The final diversity-control binary SHA-256 was
`cf574ef7fc52a00e8539141df0e4aa2346ec685033fcef16c42f273b844ba4bc`;
its code-only diff SHA-256 was
`527107b1c701ac00bcabb8edc75aa90d419c9f80b17d4b0983092c018560248a`.
The latter diff is the four Rust paths in the corresponding change, before
adding this documentation; its bench source file SHA-256 was
`e2981c92f5c3710887789002072ebe9055b005e25271f4e4a22217a37bebc15d`.
The prior instrumentation state is retained as measured data, but only the
final source state is proposed for merge.

Build and run commands are in the receipt. Each bench JSON line reports
`total_ns` for the production EoR dispatch and component timers for unicast
recompute/distribution, `gc_attr_intern()` including gauge sync, and the
exact `retained_stale_count()` call. A separate post-dispatch stale check runs
outside `total_ns`. Do not sum process wall time to infer EoR cost.
