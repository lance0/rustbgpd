# Import-decision explain cache opt-in memory receipt — 2026-07

This receipt answers one bounded question: what does the per-session
import-decision explain cache cost in resident memory, and what does making it
opt-in return to an operator who never asked for it? On this host and these
exact commits, a default 1,000-session route server gives back a *computed*
373.5 MiB of steady RSS, and the cache's configured worst case is a *computed*
2.44 MiB per saturated session.

This is a memory receipt for one configuration change, not a throughput claim
and not a competitor comparison. Every number below is a same-host loopback
measurement of the disclosed fleet shapes; nothing here forecasts a different
deployment.

**Measured commits:** `515659b191b7fde91a1a1c9f973e7c8ae3731086` (explain cache
opt-in) and its immediate parent `530badfef268bed9821f5a363a415b77bed6c47f`
(explain cache on by default). The two are one commit apart, so no other change
sits inside the comparison.

Every figure is labelled *measured*, *computed*, or *extrapolated* at the point
of use. Resident-set figures and DHAT figures are different quantities and are
never mixed: RSS is what the kernel reports resident for the daemon process
tree under jemalloc, DHAT bytes are what the program *allocated* in a separate
non-jemalloc instrumented build.

## Result

Fifteen accepted runs: eleven resident-memory runs across two fleet shapes,
plus four DHAT-instrumented runs at a third, smaller shape. Every row below is
*measured*. Steady RSS is the
median process-tree sample after cold convergence at 1 Hz; peak is the kernel's
`VmHWM` high-water mark for the daemon process, read from `/proc` after the
measured phase.

| Run | Commit | Fleet | `[policy.explain]` | Steady RSS (MiB) | Peak `VmHWM` (MiB) |
|---|---|---|---|---:|---:|
| R1a / R1b | `515659b1` | 1000 × 400 | omitted (now off) | 496.1 / 498.0 | 723.9 / 737.0 |
| R2a / R2b | `530badfe` | 1000 × 400 | omitted (then on) | 870.3 / 870.8 | 1112.2 / 1103.1 |
| R3a / R3b | `515659b1` | 1000 × 400 | `enabled = true` | 871.5 / 872.1 | 1102.9 / 1109.7 |
| R3c | `515659b1` | 1000 × 400 | `enabled = false` | 497.1 | 727.4 |
| R4a / R4b | `515659b1` | 100 × 5000 | `enabled = true` | 771.6 / 768.2 | 1069.7 / 1061.9 |
| R4c / R4d | `515659b1` | 100 × 5000 | `enabled = false` | 526.0 / 524.9 | 835.1 / 821.5 |

The headline is the R2→R1 pair, because it is the only comparison that
describes what actually changed for an operator who never wrote a
`[policy.explain]` block: the same config file, the same fleet, the default
flipped underneath it. Steady RSS 870.5 → 497.1 MiB, a *computed* difference of
**−373.5 MiB (−42.9%)**; peak `VmHWM` 1107.7 → 730.5 MiB.

## Why the saving is attributable to the flip and nothing else

Two cross-checks isolate the configuration change from every other difference
between the two commits.

- **Post-flip `enabled = true` reproduces pre-flip default-on.** R3a/R3b
  average 871.8 MiB against R2a/R2b's 870.5 MiB — a *computed* 1.3 MiB apart,
  well inside run-to-run spread. Turning the cache back on at the newer commit
  returns the daemon to the older commit's footprint, so the newer commit
  changed the default and not the cache.
- **Post-flip `enabled = false` reproduces omitted.** R3c's 497.1 MiB sits
  between R1a's 496.1 and R1b's 498.0. Writing the new default explicitly is
  indistinguishable from leaving the block out.

The three default-off runs at the same shape — 496.1, 498.0, 497.1 MiB — span a
*computed* **0.38%**. That is the control this receipt reads its differences
against, and it is two orders of magnitude below the effect.

Because the cross-checks hold, the same-binary, config-only difference is the
cleaner number for sizing: R3a/R3b against R3c is a *computed* **374.7 MiB** at
1,000 sessions × 400 routes.

## Cost per session, and where it stops growing

The cache is a per-session LRU capped at `DEFAULT_EXPLAIN_CACHE_SIZE` = 4,096
entries. The two fleet shapes bracket that ceiling: one sits well below it, the
other pins every session against it.

| Shape | Cache cost (MiB) | Per session | Cache state |
|---|---:|---:|---|
| 1000 × 400 | 374.7 (*computed*) | 383.7 KiB (*computed*) | 400 entries — below the ceiling |
| 100 × 5000 | 244.45 (*computed*) | 2.44 MiB (*computed*) | saturated at the 4,096 ceiling |

Solving the two shapes together gives a *computed* cost model of roughly
**154 KiB per session fixed plus 587 B per cached entry**. The fixed part is the
allocation the cache pays for existing at all; the variable part is what each
retained import decision costs.

A 1,000-session fleet whose sessions all saturate the ceiling would therefore
cost about **2.4 GiB** for the cache alone. That figure is *extrapolated* from
the 100-session shape and was **never measured at that fleet size** — no run in
this campaign combined 1,000 sessions with a saturated cache. It is a sizing
bound to design against, not a result.

## DHAT attribution

Two DHAT-instrumented runs at 20 sessions × 5,000 routes, both at
`515659b1`, differing only in `[policy.explain] enabled`, place the allocation
exactly where the RSS delta says it is. (Two earlier DHAT runs at the same
shape produced unclassifiable captures because the plain `release` profile
strips symbols; they are retained but carry no attribution. See
[`KNOWN_ISSUES.md`](../../KNOWN_ISSUES.md).)

DHAT reports **allocated** bytes live at the global heap maximum, from a
`release-prof` build without jemalloc. These numbers are not resident bytes and
are not comparable to the RSS table above; they answer *what allocated it*, not
*what it costs the machine*.

- With the cache enabled, the explain cache holds a *measured* **43,394,624
  allocated bytes**, of which the LRU entries themselves are **37,355,520 B**.
  At 456 B per `LruEntry`, that is a *computed* 81,920 entries — exactly
  20 sessions × 4,096, confirming every session sat at the ceiling.
- With the cache disabled, the explain cache allocates a *measured*
  **exactly zero bytes**.

That zero is only visible after netting out a classifier defect: the DHAT
classifier folds the unrelated `RejectedRouteStore` into the explain bucket,
identically in both runs (704,320 B). The per-row evidence is
[`dhat/explain-bucket-netting.tsv`](artifacts/explain-cache-opt-in-2026-07/dhat/explain-bucket-netting.tsv);
the defect and two others found alongside it are recorded in
[`KNOWN_ISSUES.md`](../../KNOWN_ISSUES.md).

## Method and fail-closed gates

The driver is
[`run-explain-cache-variant.sh`](run-explain-cache-variant.sh), derived from
`bench/scale/route-server-1000/run-receipt.sh` and keeping its preflight
gating, host lock, clean-tree refusal, and process-tree RSS sampler verbatim.
It adds the three axes this campaign varies and the shipped no-argument driver
fixes: which clean worktree is measured, the fleet shape, and the
`[policy.explain]` value injected after the generated `[policy]` block.

Before and after each build, a run requires one-minute load below 2, all 64 CPU
governors in `performance`, no competing build/daemon/benchmark process, no
swap I/O over a two-second sample, free ports, at least 16 GiB available
memory, and a file-descriptor limit of at least 4,096. It refuses a dirty
worktree, records the exact commit and tree, and fails if either moves during
the run. A run that does not reach cold convergence inside its cap, or whose
harness or RSS sampler exits non-zero, is not accepted.

One gate was deliberately loosened from the shipped driver: the RSS ceiling was
raised from 2 GiB to 4 GiB so that an unexpectedly large shape reports a number
instead of aborting mid-run. No run approached either bound.

## Limitations

- One host, one allocator configuration, loopback only. Absolute RSS is
  host-specific; the *ratio* between the paired runs is the durable result.
- The per-entry and fixed-cost split is solved from two fleet shapes, not
  measured directly at a third. Treat it as a sizing model.
- The 4,096-entry ceiling is the shipped default. A deployment that raises it
  moves every per-session figure here.
- The DHAT runs use a much smaller fleet (20 sessions) than the RSS runs and a
  different build profile. They establish attribution, not magnitude.
- No throughput, convergence, or policy-evaluation-latency claim is made. The
  cache exists to answer import-decision explain queries; this receipt prices
  it and does not measure what it buys.

## Reproduce and artifacts

On a dedicated Linux host with loopback addresses available, from a clean
worktree at the commit under test:

```console
REPO=$PWD LABEL=r1a-post-omit-1000x400 OUTBASE=/var/tmp/explain-cache \
    PEERS=1000 TOTAL=400000 EXPLAIN=omit \
    docs/perf/run-explain-cache-variant.sh
```

The [retained artifact set](artifacts/explain-cache-opt-in-2026-07/README.md)
holds the per-run index, the exact invocation of every run, sanitized configs
and policies, binary hashes, preflight admission rows, the compressed RSS
sample streams, the `/proc` high-water snapshots, the two DHAT derivatives, the
derived netting table, and checksums.
