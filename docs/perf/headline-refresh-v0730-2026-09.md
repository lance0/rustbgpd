# Headline performance refresh: v0.73.0 with v0.72.0 and v0.68.0 controls — 2026-09-28

This overnight campaign re-measured the headline route-server and
route-reflector cells on three release trees on one host: v0.73.0, v0.72.0 and
v0.68.0. It ran from 2026-09-27 22:31 to 2026-09-28 04:13 local time, and the
arms alternated in every cell, with at least three runs per cell per arm.

**v0.73.0 against the same-night v0.72.0 control:**

- **Faster:**
  - S1 cold convergence: 2.8–3.1 s against 3.6–4.0 s.
  - S3 member re-announce p50: 0.37–0.39 s against 0.50–0.55 s.
  - RR1000 first exact wire convergence: 305–330 ms against 332–356 ms.
  - RR1000 wire-point RSS: about 8% lower at the median.
- **Within spread:** S2 policy-reload completion.
- **Slower:**
  - IRR reload at 0% overlap, by about 9% at the median. Two of five v0.73.0
    roots ran markedly slower than the other three.
  - Session establishment, by about 0.08 s.
  - Settled S2 RSS, by about 4%.
  - S3 post-flap RSS, by about 16%.
- **Not attributed.** The headline cells do not isolate any single change, so
  none of these deltas is assigned to one.

**v0.68.0 against v0.72.0.** The earlier refresh found v0.72.0 slower than the
2026-08-30 v0.68.0 rows, and this campaign settles why:

- **Not host drift.** v0.68.0 reproduced its 2026-08-30 rows on this host,
  and v0.72.0 reproduced its 2026-09-26 rows. The slowdown sits between the
  two releases.
- **A cross-harness check separates daemon from instrument.** It ran the
  v0.68.0 daemon under the v0.72.0 harness:
  - **Cold convergence and flap re-announce:** the v0.72.0 slowdown is in the
    daemon.
  - **S2 reload completion:** about 0.11 s of the median gap comes from the
    newer harness, and the rest from the daemon.
  - **IRR reload:** the daemon's own log shows its reload processing slower
    by the same amount as the observed completion.
- **Not bisected.** v0.73.0 recovers the cold-convergence and flap cells but
  not the reload cells.

## Results

S1 comes from the convergence phase of all six S2 and S3 legs per arm. S2
reload values are per-reload p50s over three runs of four reloads. S3 flap
values are per-round p50s over three runs of three rounds. IRR values are
per-reload p50s over four reloads per root. RR1000 values are nine attempts
(three three-attempt campaigns) per arm. The v0.68.0 column is its main-block
runs 1–3; its interleaved cross-harness control runs (below) agree.

| Cell | v0.73.0 | v0.72.0 | v0.68.0 | v0.73.0 vs v0.72.0 |
|---|---:|---:|---:|---|
| S1 sessions established (700), harness reading | 0.8 s (all legs) | 0.7 s (all legs) | 0.7 s (all legs) | +0.1 s at the harness's 0.1 s resolution |
| S1 first-to-700th established, daemon log | 0.742–0.755 s (median 0.747) | 0.664–0.690 s (median 0.671) | 0.653–0.669 s (median 0.657) | +0.076 s median; consistent, unattributed |
| S1 cold convergence, 700 × 400,400 | 2.8–3.1 s (median 3.0) | 3.6–4.0 s (median 3.7) | 3.4–3.6 s (median 3.5) | −0.7 s median; no overlap |
| S2 policy-reload completion p50 | 1.38–1.69 s (median 1.47) | 1.37–1.74 s (median 1.52) | 1.20–1.52 s (median 1.32) | Within spread |
| S2 changed-observer reload stall p50 | 464–789 ms (median 587) | 463–657 ms (median 536) | 390–689 ms (median 495) | Median +51 ms; ranges overlap |
| S3 withdraw p50 | 0.23–0.34 s (median 0.28) | 0.25–0.45 s (median 0.32) | 0.21–0.46 s (median 0.36) | Within spread |
| S3 re-announce p50 | 0.37–0.39 s (median 0.38) | 0.50–0.55 s (median 0.51) | 0.36–0.40 s (median 0.38) | −25% median; no overlap |
| S3 first re-announcement p50 | 0.25–0.26 s | 0.31–0.33 s | 0.20–0.21 s | −0.08 s; no overlap |
| IRR reload, 0% overlap, completion p50 | 1.271–1.834 s (median 1.382) | 1.249–1.330 s (median 1.273) | 0.855–1.006 s (median 0.897) | Median +8.6%; two of five v0.73.0 roots at 1.49–1.83 s; unattributed |
| IRR reload, 0% overlap, changed-observer gap p50 | 530–729 ms (median 555) | 501–562 ms (median 515) | 402–468 ms (median 442) | Median +40 ms |
| RR1000 injection | 15–23 ms (median 17) | 31–42 ms (median 37) | 31–39 ms (median 35) | About half |
| RR1000 staged convergence | 284–310 ms (median 298) | 295–311 ms (median 304) | 294–317 ms (median 305) | Within spread |
| RR1000 first exact wire convergence | 305–330 ms (median 318) | 332–356 ms (median 341) | 322–349 ms (median 335) | −7% median |

Every cell passed its runner's acceptance:

- **IXP matrix:** 30 of 30 cells passed, with 700/700 sessions in every
  reload and flap round. That is 18 in the main block and 12 in the
  cross-harness block.
- **IRR reload:** 13 of 13 roots completed. Every row has 320/320 sessions
  and zero parse errors.
- **RR1000:** all 27 attempts passed the semantic verifier, with 1,000/1,000
  sessions.

### The v0.73.0 IRR result

- **Two populations.** Across five roots per arm, v0.72.0 was tight at
  1.249–1.330 s. v0.73.0 split in two:
  - three roots at 1.271–1.436 s;
  - two, the second and fifth, at 1.488–1.834 s.
- **Not host load.** The slow roots began at a one-minute load of 1.04 and
  1.24, like the others.
- **Not the reload itself.** The daemon's own log shows v0.73.0's reload
  processing at 1,092–1,133 ms (median 1,110), against 1,138–1,180 ms
  (median 1,149) for v0.72.0: 39 ms shorter. The extra time therefore falls
  after the reload commits, while the changed routes are distributed.
- **Unexplained.** No cell here isolates the cause.

### Memory

| Cell | Measure | v0.73.0 | v0.72.0 | v0.68.0 |
|---|---|---:|---:|---:|
| S2 | Settled process-tree RSS (last 5 s sample) | 398 / 398 / 398 MiB | 384 / 383 / 384 MiB | 372 / 372 / 374 MiB |
| S2 | Peak process-tree RSS sample | 472–495 MiB | 498–578 MiB | 416–444 MiB |
| S2 | Daemon VmHWM | 624–637 MiB | 610–617 MiB | not captured |
| S3 | Settled process-tree RSS (last 5 s sample, noisy) | 528 / 528 / 536 MiB | 602 / 503 / 528 MiB | 454 / 455 / 458 MiB |
| S3 | Harness post-flap RSS (after each round) | 426–492 MiB (median 476) | 400–418 MiB (median 410) | 380–421 MiB (median 404) |
| S3 | Daemon VmHWM | 581–606 MiB | 643–656 MiB | not captured |
| IRR 0% | Peak process-tree RSS sample | 645–661 MiB | 658–664 MiB | 627–637 MiB |
| RR1000 | Direct-process VmRSS at wire completion | 350,504–383,660 KiB (median 366,344) | 376,440–419,292 KiB (median 396,360) | 360,668–423,620 KiB (median 405,280) |

- **v0.73.0 against v0.72.0.** Settled S2 RSS is about 4% higher and S2 VmHWM
  about 3% higher. S3 VmHWM is about 9% lower. The S3 post-flap readings are
  about 16% higher at the median. The RR1000 wire-point RSS is about 8% lower.
  None of these is attributed.
- **S3 settled RSS is noisy.** Its last sample lands at an arbitrary point in
  the reconnect cycle. The harness's post-flap readings are the steadier S3
  measure.
- **No VmHWM for v0.68.0.** Its matrix runner predates the VmHWM capture, and
  the matrix runner has no cgroup memory peak for any arm.
- **Swap was untouched.** The kernel's swap-in and swap-out counters did not
  change across the window, so no VmHWM is under-reported by swapped pages.

## The v0.68.0 to v0.72.0 gap

The 2026-09-26 refresh found v0.72.0 slower on this host than the 2026-08-30
v0.68.0 rows, and could not say whether the releases or the host had changed.

### v0.68.0 reproduces its August rows

| Cell | v0.68.0, 2026-08-30 | v0.68.0, this campaign | v0.72.0, 2026-09-26 | v0.72.0, this campaign |
|---|---:|---:|---:|---:|
| S1 cold convergence | 3.4 s | 3.4–3.6 s | 3.6–4.0 s | 3.6–4.0 s |
| S2 completion p50 | 1.21–1.35 s | 1.20–1.52 s | 1.37–1.63 s | 1.37–1.74 s |
| S3 re-announce p50 | 0.36–0.39 s | 0.36–0.40 s | 0.48–0.55 s | 0.50–0.55 s |
| S3 first re-announcement p50 | 0.21 s | 0.20–0.21 s | 0.31–0.34 s | 0.31–0.33 s |
| IRR 0% completion p50 | 0.85–0.97 s | 0.86–1.01 s | 1.22–1.44 s | 1.25–1.33 s |
| RR1000 wire convergence | 318–341 ms | 322–349 ms | 332–351 ms | 332–356 ms |

- **Both builds reproduce their earlier rows.** The host's kernel and Rust
  patch release changed after August (Linux 6.17 to 7.0, rustc 1.98.0 to
  1.98.1), yet v0.68.0's rows came back. The gap is therefore between the
  releases, not on the host. RR1000 shows no gap: v0.68.0 and v0.72.0
  overlap there.
- **S2 and IRR carry a slightly wider v0.68.0 spread this time,** but the
  medians are in the August bands.

### Daemon or instrument

Each arm ran its own tree's harnesses, and the harness changed between
v0.68.0 and v0.72.0:

- **`reloadstall` gained about 2,200 lines**, including dual-stack, filtering
  and membership bookkeeping on its receive path.
- **The v0.72.0 matrix and IRR runners** make the harness poll the daemon's
  `/metrics` once a second during every SIGHUP reload, until the daemon
  reports the reload applied. The v0.68.0 runners do not.

To separate daemon from instrument, the campaign ran the v0.68.0 daemon under
the v0.72.0 matrix runner and harness. That block interleaved it three times
with the v0.68.0 own-harness arm, after the main block.

One interleaved v0.68.0 own-harness S2 leg is excluded (see
[Host and order](#host-and-order)). That arm's column below therefore covers
two S2 runs (eight reloads), three S3 runs and five S1 legs.

| Cell | v0.68.0 own harness (interleaved) | v0.68.0 daemon, v0.72.0 harness | v0.72.0 (main block) |
|---|---:|---:|---:|
| S1 cold convergence | 3.4–3.6 s (median 3.4) | 3.4–3.6 s (median 3.4) | 3.6–4.0 s (median 3.7) |
| S1 first-to-700th established, daemon log | 0.656–0.664 s | 0.658–0.661 s | 0.664–0.690 s |
| S2 completion p50 | 1.19–1.44 s (median 1.33) | 1.33–1.63 s (median 1.44) | 1.37–1.74 s (median 1.52) |
| S2 changed-observer stall p50 | 390–671 ms (median 562) | 420–786 ms (median 666) | 463–657 ms (median 536) |
| S2 daemon SIGHUP-to-reload-complete, daemon log | 901–995 ms (median 943) | 895–984 ms (median 944) | 1,128–1,220 ms (median 1,199) |
| S3 re-announce p50 | 0.36–0.40 s (median 0.37) | 0.35–0.39 s (median 0.37) | 0.50–0.55 s (median 0.51) |
| S3 first re-announcement p50 | 0.19–0.22 s | 0.18–0.22 s | 0.31–0.33 s |

- **S1 cold convergence and S3 re-announce: daemon.** The v0.68.0 daemon
  gives its own numbers under the newer harness. The v0.72.0 slowdowns are
  about +0.2–0.3 s cold convergence, +0.13 s re-announce and +0.12 s first
  re-announcement, and they are in the daemon.
- **S2 reload completion: both.**
  - **Harness:** the newer harness moves the v0.68.0 daemon's completion
    median from 1.33 to 1.44 s, and its stall median from 562 to 666 ms.
  - **Daemon:** its own log shows reload processing unchanged under the newer
    harness (944 against 943 ms, SIGHUP received to "config reload complete").
    The daemon-log interval for v0.72.0 is 1,199 ms, about 250 ms longer.
    - Most of that increase is the logged RIB transition phase: median
      349 ms for v0.68.0 against 581 ms for v0.72.0.
    - So the metrics polling does not slow the daemon's reload. Its cost is
      in the harness's own observation, and it is the same for every
      v0.72.0-era arm, v0.73.0 included.
- **IRR reload: daemon, from its own clock.** No cross-harness IRR root was
  run.
  - **The daemon's log** puts SIGHUP-to-reload-complete at 765–826 ms
    (median 787) for v0.68.0 and 1,138–1,180 ms (median 1,149) for v0.72.0.
  - **Two logged sub-phases grow:** configuration validation (median 27 to
    84 ms) and the RIB transition (median 407 to 489 ms).
  - **The size matches.** That is close to the whole 0.38 s median gap in
    observed completion.
  - **Polling is not the cause.** The S2 cross-harness result shows the
    metrics polling does not inflate these daemon-side intervals.

The harness-drift part of the S2 difference applies equally to v0.72.0 and
v0.73.0, so the v0.73.0 against v0.72.0 deltas above are unaffected by it.

## What these cells cannot show

- **The bounded distribution-window coalescing in v0.73.0** targets
  already-queued route messages to many members. Every matrix and IRR stub
  announces one uniform attribute set per member, and the cells do not
  isolate the messages-times-members term. The v0.73.0 gains in S1, S3 and
  RR1000 are consistent with that change, but no cell here attributes them to
  it.
- **No cell isolates a single change,** so every delta in this receipt is
  unattributed.

## Coverage

- **IRR reload at 10% and 50% overlap was not re-measured.**
  - **The runner.** It refuses an overlap above 0% for a rustbgpd-only
    campaign, so each such root must include a comparator daemon. At the
    comparator's reload times and the runner's cool-downs, three roots per arm
    at two overlaps would have added about six hours.
  - **The choice.** The window went to the cross-harness block instead.
  - **What stays.** The 10% and 50% rows remain the dated v0.68.0
    observations.
- **BIRD and OpenBGPD** were not run. Their matrix and IRR rows remain dated to
  their own receipts.
- **A bgperf2 spot-check** of v0.73.0 ran after the window. It is a
  single-run note in [Benchmarks](../benchmarks.md) and does not change the
  cross-stack median table.

## Method

### Builds

| Arm | Release commit | Release tree |
|---|---|---|
| v0.73.0 | `335676078965ae5a7d24273821dab12da79222d2` | `8a15d254039aa680371702c9deb5bf87bacedfb7` |
| v0.72.0 | `dcbac54420dc92d5b0218916b3568598cd154cd0` | `4ff22f7e882d5ade6057eacbe1e7da5613955838` |
| v0.68.0 | `d3e6c3571116261c47039b603ec64db14100ea0e` | `77600eafd878c19cccea0cca02efc42d94b4358a` |

- **v0.68.0 is the exact release tree.** The August rows were measured at
  `ba5717b4` (matrix, RR1000) and `451e3685` (IRR). Those trees differ from
  the release only in workflow checkout-depth lines and, for IRR, an AS_TRANS
  harness change above 1,023 peers.
- **Local commits for the source gate.** The IRR runner accepts a measured
  source only if it is current `origin/main` or a descendant of it, and all
  three tags are ancestors. So each arm ran from a local, never-published
  commit made with `git commit-tree <tag>^{tree} -p origin/main`.
  - Main did not move during the window, so no arm was re-parented.
  - Matrix and IRR provenance files name those local commits. The tree hashes
    above are the verifiable identity.
- **Build command.** Every arm used the IRR runner's command,
  `cargo build --release -p rustbgpd -p rustbgpctl -p rs-config-render`, for
  every cell. Building the three packages together changes the daemon's
  unified feature set, so the build command is part of the identity.
- **Daemon identity and build path.** A daemon's hash depends on the build
  directory: cargo's per-package metadata includes a path dependency's
  location, and that changes symbol names. The same tree built in two
  directories therefore gives different hashes, so the 2026-09-26 v0.72.0
  hash cannot be matched from another directory.
  - **Same directory, tag commit.** In each arm's build directory, checking
    out the tag commit itself and re-running the build recompiled nothing and
    left the daemon hash unchanged. No commit identity enters the build.
  - **Measured hashes (SHA-256):**
    - v0.73.0 `22cf7d4b…`
    - v0.72.0 `b7757f08…`
    - v0.68.0 `82fe1b79…`
- **Harnesses.** Each arm ran its own tree's runners and harnesses.
  - **v0.72.0 to v0.73.0.** `reloadstall` gained its failover and
    policy-stats cells, which the headline cells do not run. The shared RR1000
    instrument changed by a few lines.
  - **v0.68.0 to v0.72.0.** The drift is described in
    [Daemon or instrument](#daemon-or-instrument).
  - **The scenario generator** emits byte-identical configuration by default
    in all three trees.
- **Cross-harness arm.** A fourth checkout of the v0.72.0 tree held the
  v0.68.0 daemon binary (`82fe1b79…`) and the v0.72.0 `reloadstall` binary.
  It ran the v0.72.0 matrix runner, whose provenance records both hashes.

### Host and order

- **Host.** One AMD Ryzen Threadripper 7970X host: 125 GiB RAM, no swap
  configured, Linux 7.0, rustc 1.98.1. All CPU governors were set to
  `performance`.
- **CPU placement.** Nothing was pinned: the runners and harnesses ran across
  all 64 logical CPUs.
  - This matches what the runners do on their own, and what the 2026-09-26
    campaign's driver did.
  - That receipt's statement that its daemon and harness ran on cores 16–23
    and 24–39 does not match its own driver, which set no CPU affinity. This
    receipt records the placement actually used.
- **Background load.** A shared local inference service kept one core busy
  throughout. The benchmark and gate locks, and the quiet-window marker, were
  held for the whole window. No pushes to main ran, and no builds or test
  gates ran apart from one exception:
  - **One contaminated leg, excluded.** At about 03:27, during the v0.68.0
    own-harness S2 leg of the cross-harness block's third pair
    (03:24:29–03:32:08), another development lane's commit hooks ran
    `cargo fmt` and `cargo clippy` for a few seconds, without CPU pinning.
  - **How it is handled.** That leg, including its S1 reading, is excluded
    from the cross-harness comparison. Its files stay in the bundle as
    `matrix/matrix-v0680-r6-s2/` and in `summary.csv`.
  - **Scope.** The main block, which supplies every v0.73.0, v0.72.0 and
    v0.68.0 headline value, and every other leg ran before or after it.
  - **Quiet gate.** The runners' own quiet gates (one-minute load below 2.0
    before every matrix and IRR cell, two accepted samples) passed each time.
  - **RR1000 load readings.** The one-minute load recorded between RR1000
    campaigns reached 3.7–4.6. Those campaigns run back to back, and the load
    is their own. The RR1000 runner's load gate does not hold them apart.
  - **No bench-nightly job** was scheduled on the host during the window.
- **Order.** The campaign was strictly sequential. The main block ran:
  - matrix S2 then S3, three runs per arm;
  - IRR at 0% overlap, three roots per arm;
  - RR1000, three campaigns per arm.

  The arm order rotated each run (v0.73.0 → v0.72.0 → v0.68.0, then
  v0.72.0 → v0.68.0 → v0.73.0, then v0.68.0 → v0.73.0 → v0.72.0), with the
  runners' 300-second cool-downs. Two further blocks followed:
  - the cross-harness block, which alternated the cross-harness arm and the
    v0.68.0 own-harness arm three times;
  - two more IRR 0% roots each for v0.73.0 and v0.72.0, alternating
    (v0.73.0 first, then v0.72.0 first). They were added because the first
    three v0.73.0 roots disagreed with each other.

### Shapes and extraction

- **Shapes.** Each cell uses the current receipts' canonical shape:
  - **IXP matrix:** 700 members × 400,400 routes, four reloads, a 30-second
    control window. S3 has 50 flapping members.
  - **IRR:** 320 members × 183,040 prefixes, seed 61, four reloads.
  - **RR1000:** the fixed shape of `rrtransport rr1000`.
- **Matrix extraction.** Matrix values come from the labeled lines in each
  `reloadstall.log`, not from the CSV rows. The labels are `established`,
  `converged`, `reload N completion_s`, `reload N maxgap_ms` and
  `flap N withdraw_s/reannounce_s/first_reann_s`.
- **Daemon-log intervals.** These come from the daemon's JSON log: from
  "SIGHUP received" to "config reload complete". The `validate_ms` field comes
  from "config source loaded", and `cohort_rib_transition_us` from "reload
  generation phase timing". Their per-reload values are in
  `daemon-reload.csv`.

## Artifacts

The compact bundle is
[`artifacts/headline-refresh-v0730-2026-09`](artifacts/headline-refresh-v0730-2026-09/README.md).
It holds:

- logs, per-run status and provenance, RSS samples, IRR rows and RR1000 phase
  records;
- the campaign progress log;
- a machine-readable `summary.csv` of every value above;
- the derived `establishment-span.csv` and `daemon-reload.csv`;
- the campaign driver, as run, under `driver/`.

The full daemon logs stay outside the repository.
