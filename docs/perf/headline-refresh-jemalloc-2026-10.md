# Headline performance refresh on the jemalloc harness: main against a same-night control — 2026-10-03

This overnight campaign re-measured the headline route-server cells on two
trees on one host, with the `reloadstall` receiver harness linked against
jemalloc in both. It ran on 2026-10-03 from 02:45 to 05:24 local time. The
arms alternated in every cell, with three runs per cell per arm.

It is the first headline receipt whose receiver-bound completion times are
free of the harness allocator artefact described in
[Why earlier receiver-bound rows are not comparable](#why-earlier-receiver-bound-rows-are-not-comparable).

**The arms:**

- **Harness-fix control** (`370e211b9`): main at the commit that linked the
  `reloadstall` harness against jemalloc. It is v0.73.0 plus 93 commits.
- **Main** (`481e0187d`): the control plus 26 commits. They include these
  runtime changes:
  - prefix-retirement batching;
  - the graceful-restart End-of-RIB single pass;
  - value-only group-opener indexing;
  - `/metrics` rendered off the async workers;
  - IPv6 prefix hash mixing.

  The other commits are tests, documentation, benchmark and CI changes and one
  configuration diagnostic. The two arms' `reloadstall` sources are identical
  apart from its README.

**Main against the control:**

- **Faster:** the S2 daemon-logged RIB transition, 485–509 ms
  (median 490) against 561–604 ms (median 579). The ranges are separate.
- **Not in the reload clock.** The faster RIB transition does not show up in
  the reload clock. The S2 daemon-logged SIGHUP-to-reload-complete interval
  and the harness-observed S2 completion are flat:
  - in the same logged reload generation, the deferred refresh dispatch phase
    that follows the RIB transition grew from a median of 18 ms to 88 ms;
  - the generation total stayed at a median of 1,092 against 1,091 ms.
- **Within spread:**
  - S1 cold convergence and session establishment;
  - S3 withdraw, re-announce and first re-announcement;
  - the IRR 0% reload's harness completion and its daemon-logged intervals.
    Main's medians are lower, but the per-reload ranges overlap.
- **Lower on main:** S2 daemon VmHWM, by about 3%, and the IRR peak
  process-tree RSS sample. Both have three samples per arm.
- **Not attributed.** The headline cells do not isolate any single change,
  so no delta here is assigned to one of the changes listed above.

**Slow IRR roots:** none in either arm. All six roots had a completion
median of 1.10–1.15 s, against the 1.40 s slow-run threshold.

## Results

S1 comes from the convergence phase of all six S2 and S3 legs per arm. S2
values are per-reload p50s over three runs of four reloads (n = 12). S3 values
are per-round p50s over three runs of three rounds (n = 9). IRR values are
per-reload p50s over three roots of four reloads (n = 12).

| Cell | Control (`370e211b9`) | Main (`481e0187d`) | Main vs control |
|---|---:|---:|---|
| S1 sessions established (700), harness reading | 0.8 s (all legs) | 0.8 s (all legs) | Equal at the harness's 0.1 s resolution |
| S1 first-to-700th established, daemon log | 0.730–0.750 s (median 0.743) | 0.728–0.749 s (median 0.740) | Within spread |
| S1 cold convergence, 700 × 400,400 | 2.6–2.8 s (median 2.8) | 2.6–2.8 s (median 2.8) | Within spread |
| S2 policy-reload completion p50 | 1.10–1.20 s (median 1.13) | 1.12–1.17 s (median 1.155) | Within spread |
| S2 changed-observer reload stall p50 | 459–487 ms (median 469) | 457–490 ms (median 469) | Within spread |
| S3 withdraw p50 | 0.20–0.25 s (median 0.24) | 0.19–0.25 s (median 0.24) | Within spread |
| S3 re-announce p50 | 0.35–0.39 s (median 0.37) | 0.35–0.40 s (median 0.38) | Within spread |
| S3 first re-announcement p50 | 0.23–0.25 s (median 0.24) | 0.24 s (all rounds) | Within spread |
| IRR reload, 0% overlap, completion p50 | 1.118–1.167 s (median 1.143) | 1.088–1.142 s (median 1.108) | Median −35 ms; ranges overlap; within spread |
| IRR reload, 0% overlap, per-root completion median | 1.138–1.149 s | 1.097–1.120 s | Separate, but n = 3 per arm |
| IRR reload, 0% overlap, changed-observer gap p50 | 493–527 ms (median 512) | 474–572 ms (median 492) | Within spread |
| IRR roots with a completion median ≥ 1.40 s | 0 of 3 | 0 of 3 | — |

Every leg passed its runner's acceptance. `progress.txt` records 18 legs,
each with exit code 0:

- **IXP matrix:** 12 of 12 legs passed, with 700/700 sessions in every reload
  and flap round.
- **IRR reload:** 6 of 6 roots completed. Every row has 320/320 sessions and
  zero parse errors.
- **No leg is excluded.**

### Daemon-logged reload intervals

These come from the daemon's own JSON log, not from the harness. Each cell has
twelve reloads per arm.

| Cell | Interval | Control | Main |
|---|---|---:|---:|
| S2 | SIGHUP received → config source loaded | 5.7–7.4 ms (median 6.3) | 6.2–27.9 ms (median 7.1) |
| S2 | SIGHUP received → config reload complete | 1,091–1,186 ms (median 1,130) | 1,099–1,159 ms (median 1,134) |
| S2 | Logged `validate_ms` | 0 ms | 0 ms |
| S2 | RIB transition | 561–604 ms (median 579) | 485–509 ms (median 490) |
| S2 | Cohort pre-stage session apply | 459–532 ms (median 492) | 468–519 ms (median 505) |
| S2 | Deferred refresh dispatch (`deferred_refresh_dispatch_us`) | 16–34 ms (median 18) | 71–101 ms (median 88) |
| S2 | Reload generation total | 1,052–1,145 ms (median 1,092) | 1,053–1,116 ms (median 1,091) |
| IRR 0% | SIGHUP received → config source loaded | 253–265 ms (median 256) | 243–260 ms (median 253) |
| IRR 0% | SIGHUP received → config reload complete | 1,065–1,114 ms (median 1,090) | 1,029–1,084 ms (median 1,052) |
| IRR 0% | Logged `validate_ms` | 78–86 ms (median 82) | 76–85 ms (median 80.5) |
| IRR 0% | RIB transition | 465–494 ms (median 482) | 444–466 ms (median 454) |

- **S2: the saving stays inside the generation.**
  - The RIB transition ranges are separate, 89 ms apart at the median.
  - The deferred refresh dispatch phase grew by about 70 ms at the
    median, with separate ranges. The pre-stage session apply phase grew by
    about 13 ms at the median, with overlapping ranges.
  - So the generation total and the SIGHUP-to-complete interval did not move,
    and neither did the harness-observed completion.
  - This receipt does not show why the dispatch phase grew. It does not
    assign that to any one change either.
- **One slow config load on main.** One S2 reload took 27.9 ms from SIGHUP to
  config loaded; the other eleven took 6.2–8.5 ms. It did not move that
  reload's completion.
- **IRR: lower medians, overlapping ranges.**
  - The RIB transition median is 28 ms lower on main. The ranges meet at
    465–466 ms, and the difference is the size of the control's own spread.
  - The SIGHUP-to-complete median is 38 ms lower. The arms' spreads are 49 and
    55 ms.
  - Neither is a measured improvement at this n.

### Memory

| Cell | Measure | Control | Main |
|---|---|---:|---:|
| S2 | Settled process-tree RSS (last 5 s sample) | 364 / 365 / 366 MiB | 366 / 367 / 367 MiB |
| S2 | Peak process-tree RSS sample | 506–564 MiB | 475–526 MiB |
| S2 | Daemon VmHWM | 577–580 MiB | 560–564 MiB |
| S2 | Daemon cgroup memory peak | 937–1,192 MiB | 1,063–1,092 MiB |
| S3 | Settled process-tree RSS (last 5 s sample, noisy) | 364 / 366 / 371 MiB | 359 / 375 / 375 MiB |
| S3 | Harness post-flap RSS (after each round) | 405–454 MiB (median 426) | 399–442 MiB (median 430) |
| S3 | Daemon jemalloc allocated after each round | 321–333 MiB (median 328) | 319–329 MiB (median 327) |
| S3 | Daemon jemalloc resident after each round | 422–483 MiB (median 444) | 414–462 MiB (median 445) |
| S3 | Daemon VmHWM | 547–553 MiB | 551–576 MiB |
| IRR 0% | Peak process-tree RSS sample | 642–743 MiB | 625–637 MiB |

- **S2 VmHWM** is about 3% lower on main, with separate ranges over three runs
  per arm.
- **The IRR peak RSS sample** is lower on main, and its ranges are separate.
  It is a 5-second sample of the process tree over three roots per arm, and
  one control root at 743 MiB widens that arm's range.
- **Within spread:** every other memory reading.
- **The S2 cgroup peak counts every page the daemon's scope was charged,**
  file pages included, so it reads well above VmHWM. Its swap limit is zero,
  so no page is hidden in swap.
- **Swap was untouched.** The kernel's swap-in and swap-out counters did not
  change across the window.

## Why earlier receiver-bound rows are not comparable

Before this campaign, the `reloadstall` harness ran on glibc malloc. The
daemon has used jemalloc throughout.

- **The mechanism.** When the daemon delivered a coalesced post-reload burst,
  hundreds of stub readers reallocated their frame buffers and NLRI vectors at
  the same instant. Under glibc malloc those reallocations contended on the
  arena lock.
- **The shape it gave.** glibc assigns arenas to threads once per process, so
  the contention varied between process starts. Whole runs were slow or fast,
  with all four reloads alike. That is what produced the two slow v0.73.0 IRR
  roots in the
  [2026-09-28 v0.73.0 receipt](headline-refresh-v0730-2026-09.md#the-v0730-irr-result).
- **Even fast runs paid.** The contention added roughly 0.1 s to completion in
  fast runs too.
- **Diagnostic evidence, 2026-10-02.** Two sets of six IRR 0% roots ran on the
  same daemon tree, the parent of the harness fix:
  - **On the glibc harness,** per-root completion medians were 1.29–1.58 s.
    Two roots were slow. In the four roots sampled, the harness used 3–14
    core-seconds per reload while the daemon stayed under one core.
  - **On the jemalloc harness,** per-root medians were 1.205–1.224 s, none
    slow. The harness used about 1 core-second per reload.
- **The daemon's own reload clock was unaffected.** The contention was in the
  harness process. During delivery the daemon used under one core and waited
  on the receivers' TCP windows. Its logged SIGHUP-to-complete medians were
  1,139–1,152 ms per root on the glibc harness, slow and fast roots alike. The daemon-logged intervals in earlier
  receipts therefore stand. The [harness README](../../bench/scale/reloadstall/README.md#allocator)
  records the change.

**Which rows this touches.** The S2 completion and stall rows and the IRR
completion and gap rows were measured with the glibc harness, in this
receipt's predecessors and in the dated matrix and IRR receipts. They are not
directly comparable with this receipt's completion rows. Compare across that
boundary only with daemon-logged intervals, S1 cold convergence, or S3 flap
timings. The [2026-09-28 receipt](headline-refresh-v0730-2026-09.md#daemon-or-instrument)
showed the S3 flap timings to be daemon-side.

## What these cells cannot show

- **No cell isolates a single change,** so every delta in this receipt is
  unattributed. That includes the S2 RIB transition and the growth of the
  deferred refresh dispatch phase.
- **No released tree was measured.** Neither arm is a release, and this
  campaign has no v0.68.0, v0.72.0 or v0.73.0 arm. Any comparison with those
  releases is cross-date and is limited to the measures above that the
  harness allocator could not distort.
- **No comparator daemon was run,** so no cross-daemon ranking changes here.
- **Coverage is two cells.** RR1000, and IRR reload at 10% and 50% overlap,
  were not run.

## Method

### Builds

| Arm | Commit | Tree | Daemon SHA-256 (this build directory) |
|---|---|---|---|
| Control | `370e211b95ec3e4a7b07556146e31dd02f391ea6` | `cae43a47f9d597342c3ec0599a1ddbbfe23fbe36` | `f7b540cb49dd62ecab48f2462c6f773e65fab0e47f71ddecfb85208169e85d8e` |
| Main | `481e0187d873dd8e7715033224be0fe90cb7d4e2` | `dc90a0c052af909f56a2625515fcd22e72fa658b` | `7ef213c92b7c9b1a6fc6551ec76e18cb4dbc552422c68ef7044b93d445322e8b` |

- **The driver** is the in-repository campaign:
  `just bench-headline` with `CELLS=matrix,irr` and `RUNS=3`, running
  [`bench/scale/headline/run-campaign.sh`](../../bench/scale/headline/run-campaign.sh)
  from the main tree.
- **Local commits for the source gate.** Each arm ran from a local,
  never-published commit whose tree is the arm's tree and whose parent is
  `origin/main`. The IRR runner's source gate requires this, and provenance
  files name those commits. The tree hashes are the verifiable identity.
- **Same-directory check.** Before the first leg, each arm's daemon was rebuilt
  at the arm's real commit in the same directory, and the campaign requires
  the hash to match. It did for both arms.
- **Harnesses.** Each arm ran its own tree's runners and harnesses. Both link
  jemalloc. The two `reloadstall` binaries hash differently because a harness
  hash depends on its build directory and on the `rustbgpd-wire` crate it
  links. Their hashes are in `identity.tsv` and in each provenance file.
- **Toolchain.** rustc 1.99.0. The 2026-09-28 receipt used rustc 1.98.1.

### Host and order

- **Host.** One AMD Ryzen Threadripper 7970X host: 125 GiB RAM, no swap
  configured, Linux 7.0. The runners' quiet gate recorded the `performance`
  governor on all 64 CPUs before every cell.
- **CPU placement.** Nothing was pinned. The runners, harnesses and daemons
  ran across all 64 logical CPUs, as `placement.txt` records.
- **Load.** The one-minute load at leg boundaries was 1.00–1.32. The
  exception was the first leg's start, at 7.85 right after the builds. The
  runners' quiet gate (one-minute load below 2.0, two accepted samples)
  passed before every cell, including that one.
- **Order.** The campaign was strictly sequential:
  - matrix S2 then S3, three runs per arm, in the arm order control → main,
    main → control, control → main;
  - IRR at 0% overlap, three roots per arm, in the same rotation.

  The runners' 300-second cool-downs separated the cells.

### Shapes and extraction

- **Shapes.** These are the current receipts' canonical shapes:
  - **IXP matrix:** 700 members × 400,400 routes, four reloads and a 30-second
    control window. S3 has 50 flapping members and three rounds.
  - **IRR:** 320 members × 183,040 prefixes, seed 61, four reloads.
- **Extraction.** `summary.csv` and the per-arm ranges come from
  [`bench/scale/headline/summarize.py`](../../bench/scale/headline/summarize.py)
  (`just bench-headline-summary`). Re-running it on the campaign directory
  reproduced the campaign's files byte for byte. Run on this bundle, it
  reproduces every non-daemon row of `summary.csv`. The bundle has no daemon
  logs, so the daemon rows cannot be re-extracted from it.
- **Daemon-log intervals.** These are computed as in the 2026-09-28 receipt:
  - SIGHUP received to "config source loaded" and to "config reload
    complete";
  - `validate_ms` from "config source loaded";
  - `cohort_rib_transition_us` from "reload generation phase timing".

  `daemon-reload.csv` holds them per reload. A second pass with the 2026-09-28
  extractor matched all 192 daemon values in `summary.csv`.
  `generation-phase.csv` adds the pre-stage, deferred-dispatch and total
  fields from the same "reload generation phase timing" record.
- **Within spread.** A difference counts as a change only when the arms'
  ranges are separate. It also counts when the medians differ by more than
  each arm's own spread.

## Artifacts

The compact bundle is
[`artifacts/headline-refresh-jemalloc-2026-10`](artifacts/headline-refresh-jemalloc-2026-10/README.md).
It holds:

- each matrix leg's harness log, status, RSS samples, VmHWM, cgroup memory
  readout and provenance;
- each IRR root's rows, completion status, provenance, dataset digest and
  harness log;
- the campaign progress log, manifest, CPU placement and arm identities;
- `summary.csv`, `establishment-span.csv`, `daemon-reload.csv` and
  `generation-phase.csv`.

The full daemon logs, scenario configurations and metrics scrapes stay
outside the repository.
