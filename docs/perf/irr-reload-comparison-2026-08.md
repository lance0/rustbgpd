# IRR-scale reload comparison — rustbgpd vs BIRD vs OpenBGPD — 2026-08

What does the routine IRR filter refresh cost on a live route server —
in each daemon's own reload idiom, at a realistic policy scale? The
shape here is 320 members announcing 183,040 /24s, filtered by
per-member IRR lists totalling 3,218,965 prefix entries, reloaded four
times per cell while all 320 sessions stay up. rustbgpd reloads by
SIGHUP + `.rpol` swap, BIRD 3.3.1 by `birdc configure`, OpenBGPD 9.1 by
`bgpctl reload` — each at its operator-documented route-server
configuration, all through one harness and one receiver-side
instrument. Four fresh sealed artifact roots in counterbalanced
A/B/B/A order, all green, cross-checked by the campaign's independent
verifier. A standalone grouped-export control cell (never a comparison
row) prices rustbgpd's per-client path-hiding fan-out.

## Headline

| Cell (320 members × 183,040 routes, 3.2M filter entries, 4 reloads × 2 roots) | Completion p50 (reload 1; reloads 2–4) | Completion p95 (reloads 2–4) | Reload stall p50 (reload 1; reloads 2–4) | First new-generation route p50 | Process-tree RSS peak (root A / B) |
|---|---|---|---|---|---|
| rustbgpd (SIGHUP, per-client best) | 53.7–54.7 s; 67.2–69.4 s | 114.1–117.2 s | 285–305 ms; 8.1–9.2 s | 53.7–69.4 s (lands with completion) | 10,755 / 10,472 MiB |
| BIRD 3.3.1 (`birdc configure`) | 11.1–12.0 s (no reload-1 effect) | 12.1–13.2 s | 0.78–0.93 s (no reload-1 effect) | 1.39–1.65 s | 1,364 / 1,362 MiB |
| OpenBGPD 9.1 (`bgpctl reload`) | 51.1–69.9 s (no reload-1 effect) | 51.1–69.9 s (p95 ≈ p50 ≈ max) | 362–502 ms | 6.8–7.0 s | 1,408 / 1,119 MiB |

Every row: 320/320 sessions up at reload validation, zero parse
errors, zero stale-marker leaks. Reading the table honestly:

- **BIRD leads completion outright** (~11–12 s to full 320-observer
  re-advertisement). rustbgpd's per-client completion p95 in steady
  state is roughly **9–10× BIRD's** — the known generic UPDATE fan-out
  gap under per-client best-path, not a policy-compile cost.
- **OpenBGPD and per-client rustbgpd occupy the same completion class**
  (~51–70 s), with OpenBGPD delivering near-uniformly across observers
  (p95 ≈ max) and holding the smallest steady-state reload stall of the
  three.
- **rustbgpd's first reload after fresh convergence is systematically
  cheaper than later generation flips** (stall p50 ~0.3 s vs ~8–9 s;
  completion p50 ~54 s vs ~67–69 s), reproducibly in both comparison
  roots and both grouped repeats. This first-reload-cheap /
  later-reloads-costlier pattern is recorded as an **open item**; this
  receipt does not attribute a cause.
- **RSS**: rustbgpd per-client holds ~10.5 GiB process-tree peak
  against BIRD's ~1.4 GiB and OpenBGPD's ~1.1–1.4 GiB at this shape.
  The sampler sums a process tree (containers for BIRD/OpenBGPD), so
  close absolute differences are not exact allocator comparisons.

## Grouped-export control (standalone diagnostic — never a comparison row)

The same daemon, dataset, and reload mechanism with
`path_hiding false` (grouped export) instead of the comparison's
per-client best-path. Grouped rows exist to price the path-hiding
fan-out seam; they never enter the cross-daemon table or any
recommendation text.

| Repeat | Completion p50 (reload 1; reloads 2–4) | Completion p95 (reloads 2–4) | Stall p50 (reload 1; reloads 2–4) | First new-generation route p50 | RSS (row VmRSS; sampler peak) |
|---|---|---|---|---|---|
| A | 1.69 s; 4.32–4.35 s | 4.40–4.43 s | 171 ms; 2.76–2.85 s | 1.57 s; 4.16–4.20 s | 722→1,949 MiB; 2,046 MiB |
| B | 1.77 s; 4.38–4.45 s | 4.48–4.56 s | 156 ms; 2.75–2.85 s | 1.58 s; 4.22–4.26 s | 722→1,906 MiB; 1,991 MiB |

Grouped vs per-client, same daemon and dataset: steady-state
completion p50 **~4.4 s vs ~68 s (~15×)**, stall p50 ~2.8 s vs
~8–9 s (~3×), process-tree peak RSS **~2.0 GiB vs ~10.5 GiB (~5×)**.
In grouped mode rustbgpd's completion lands **below BIRD's completion
class** (~4.4 s vs ~11–12 s) — though BIRD still holds the lower RSS
(~1.4 GiB vs ~2.0 GiB). All 8 grouped reloads completed with sessions
up: the grouped-reload transition fix measured here survived full
scale under seal (8/8 clean).

The first-reload-cheap pattern reproduces in grouped mode too
(stall p50 ~0.16–0.17 s vs ~2.8 s) — the same open item as above.

## Metric definitions

- **Completion** (`completion_{p50,p95,max}_s`) — reload trigger until
  an observer holds every expected unique non-self base-table prefix
  re-advertised with the new generation marker community; duplicates
  never advance it; churn prefixes are excluded by range. Percentiles
  are across all 320 observers.
- **Reload stall** (`all_observer_maxgap_{p50,p95}_ms`) — per-observer
  maximum inter-UPDATE gap in the 120 s window after the reload
  trigger, wire-observable in the receiver stubs. The trigger
  timestamp precedes the reload command, so `birdc`/`bgpctl` cells
  include their control-channel round-trip (SIGHUP has none).
- **First new-generation route**
  (`changed_first_generation_update_{p50,p95,max}_ms`) — reload
  trigger to the first non-self base prefix carrying the expected new
  generation marker at that observer. Unmarked output, stale markers,
  churn space, duplicates, and the observer's own slice cannot start
  this clock. rustbgpd delivers new-generation output as a terminal
  burst after the policy swap, so this clock lands essentially with
  completion for rustbgpd (p50 53.7–69.4 s ≈ completion p50); BIRD and
  OpenBGPD begin emitting marked routes early and spread delivery.
- **Historical footnote — not comparable with earlier receipts**:
  before the harness revision in #1350, this column was named
  `changed_first_update_*` and measured the post-SIGHUP *leading
  stall* — trigger to the first UPDATE of **any** kind at the
  observer, including ambient churn traffic. Figures published from
  that era (including the July 2026 "first re-advertisement 14 ms
  p50" fix-verification figure) are that leading-stall metric and
  must not be compared against `changed_first_generation_update_*`
  values here.
- **RSS** — row-level `rss_before_mib`/`rss_after_mib` are
  `/proc/<pid>` VmRSS around each reload, available only for the bare
  rustbgpd cells (zero for container cells). Cross-daemon comparisons
  use only the 5 s-cadence process-tree sampler, whose per-cell peak
  is quoted above; it can double-count shared mappings.

## Method

- **Four fresh sealed roots** in counterbalanced order:
  comparison-A → grouped-A → grouped-B → comparison-B, each cell a
  fresh daemon/process identity, each root sealed with `COMPLETED`
  plus an exact `SHA256SUMS` roster and made read-only. 300 s
  cool-downs between roots and runner-internal 300 s cool-downs after
  every cell.
- **One harness, one instrument**: the
  [`bench/scale/irrreload/`](../../bench/scale/irrreload/README.md)
  campaign runner over the `bench/scale/reloadstall` receiver-side
  stubs — real BGP sessions over loopback TCP, receiver timestamps
  after full wire framing + decode, generation-marker completion
  tracking. Same dataset, addressing, churn, and completion semantics
  for every cell; the dataset is expressed in each daemon's native
  policy idiom, and each daemon reloads by its operator-documented
  mechanism at its documented route-server configuration. The full
  comparability protocol and its documented asymmetries (reload-
  semantic asymmetry, hygiene depth, bench plumbing) are in that
  README.
- **Quiet-host gates**: clean `HEAD` exactly at `origin/main`, passing
  preflight, exclusive host lock, retained load/swap sample pairs, and
  per-cell load gates, with the recurring bench schedule disabled for
  the window.
- **Independent verification**:
  `bench/scale/irrreload/verify-receipt.py campaigns` over the four
  roots returned `status: "pass"` — 24 comparison rows and 8
  grouped-control rows re-derived, root order, seals, process
  identities, per-root provenance fingerprints, and the common dataset
  digest all validated. Its output (`comparison.csv`,
  `grouped-control.csv`, `verification.json`) is committed beside this
  receipt.

## Full per-reload rows

All 24 comparison rows and 8 grouped-control rows, exactly as
re-derived by the verifier, are in
[`artifacts/irr-reload-comparison-2026-08/`](artifacts/irr-reload-comparison-2026-08/README.md)
(`comparison.csv`, `grouped-control.csv`). The headline ranges above
are min–max of the per-reload p50/p95 values across both roots; every
number in this document traces to a row in those CSVs.

## Honesty notes

- Loopback TCP on one host; one shape, two repeats per cell class in
  fixed counterbalanced order — not statistically independent trials.
- SIGHUP + `.rpol` swap re-parses only the policy files; `birdc
  configure` and `bgpctl reload` re-parse the entire config. These are
  each daemon's documented reload operation — not the same amount of
  work.
- BIRD's stall p50 is quoted from the all-observer gap column; its
  changed-cohort and all-observer gaps differ slightly (0.76–0.80 s vs
  0.78–0.93 s) even though every observer is changed at this shape.
  rustbgpd and OpenBGPD report identical values in both columns.
- Filter-list padding entries are all /24s; real IRR lists mix
  lengths. Constant across daemons and generations.
- The grouped-control cell is a seam diagnostic, not a competitor
  configuration for this comparison: the comparison's rustbgpd cell
  deliberately runs `per_client_best` path hiding, the documented
  route-server default posture measured throughout this receipt line.

## Provenance

- **Commit measured**: `f2a8b0275d22d431ec0b031cb8f58fcf28a95029` —
  clean, exactly `origin/main` at run time for all four roots
  (v0.63.0 plus the grouped export-policy transition fix #1469 and
  the BMP Loc-RIB dump boundary fix #1470).
- **Dataset digest** (identical across all six cells):
  `fad37b701fcd3f7f51884906f66052325f3f1e57a02528a039535ed08907c56b`
  (320 members, 183,040 prefixes, log-uniform 1,000–40,000-entry
  filter lists totalling 3,218,965 entries, seed 61; 36 of 320 filter
  lists change between generations, and the export marker swap changes
  output for all 320 observers).
- **Per-root provenance fingerprints** (schema-3, re-derived by the
  verifier):

  | Root | Fingerprint |
  |---|---|
  | comparison-A | `c7b88cd976e55ed4aa494d7242f9ee02c46ee1357b971861456892f035ac9845` |
  | grouped-A | `9950251fd4a485a72dbe2981d1332922398f3dd980b4fa0f74fab82a8267ce10` |
  | grouped-B | `aa0c604a1e5a5aacfeb14fef91482dbe813e88ab06953c2bff99f4da207694c9` |
  | comparison-B | `b787c4873465e7ba061794af9bb41090467d9f26e21127efbe6ab59451450954` |

- **Peer images**: `bird:3.3.1` (built from
  `tests/interop/Dockerfile.bird3`) and `openbgpd/openbgpd:9.1`.
- **Sealed evidence**: the four full roots (daemon logs, RSS streams,
  per-cell manifests, quiet samples, seals) are retained read-only in
  the campaign artifact archive, off-repo. Recognize the originals by
  their seal digests:

  | Root | `SHA256SUMS` seal digest | `COMPLETED` digest |
  |---|---|---|
  | comparison-A | `9dbe2ba6ad11e66fd38eaa5cd8d146aac2bf651d210ca8f13ff6fffd30dc71cb` | `e5f23ea08a37ee4b8a91a35048d54aeb92fc853dcabff410c9cb2484bb5a94c8` |
  | grouped-A | `3940098f75d12be95abd5f42e0230b344375c31a05e3d0580abebbe5f2bfef89` | `c889b54ddc072a0e4b3232201ddbdcf2557cabe10d57eeba463982d756c6ce32` |
  | grouped-B | `d0d8f3402e7fa8f4d6c65c078716c75a7f214daba12aa6628d163390a0a4cd2e` | `bea325f24897d5a309d9f905995c876806213244c194369aa85d9455744c53fb` |
  | comparison-B | `6426eed90127978f19d4d47a4ea5707f04ff23c64a647ee152f163d95f1b5541` | `06cf073c984696d396f06ed5af6a5349729a1241f53a677cd39ff8d0e6e3be0e` |

## Environment

| Field | Value |
|---|---|
| Hardware | AMD Ryzen Threadripper 7970X (32 cores), 125 GiB RAM |
| Kernel | Linux 6.17.0-35-generic x86_64 |
| Toolchain | rustc 1.97.0, cargo 1.97.0, Python 3.12.3, Docker 29.2.1 |
| Build | `--release`; quiet-host gates as above |

## Reproduction

The campaign runner, protocol, comparability notes, and verifier are
[`bench/scale/irrreload/`](../../bench/scale/irrreload/README.md).
This receipt reproduces with the four-root A/B/B/A invocation sequence
and the `verify-receipt.py campaigns` step documented there.
