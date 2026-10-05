# Cross-daemon refresh at v0.75.0: rustbgpd, OpenBGPD 9.3 and BIRD 3.3.2 on one night — 2026-10

This overnight campaign measured rustbgpd v0.75.0's daemon source against
OpenBGPD 9.3 on one host, with BIRD 3.3.2 added in the IRR reload roots. It
ran from 2026-10-04 21:37 to 2026-10-05 05:04 local time and covers the
comparison cells published on the IXP matrix and IRR reload receipts:

- **IXP matrix, 700 clients × 400,400 routes:** S1 cold convergence, S2
  policy reload and S3 flapstorm, three runs each for rustbgpd and OpenBGPD
  9.3, with the daemon order alternated. BIRD did not run in the matrix.
- **IRR reload, 320 members × 183,040 prefixes:** cross-daemon roots at 0%,
  10% and 50% received-view overlap, three roots per overlap, each measuring
  rustbgpd, BIRD 3.3.2 and OpenBGPD 9.3.

All 21 legs passed their runners' acceptance, and no leg is excluded.

**The measured commit.** The campaign built and measured `319d14e4b`
(`v0.74.0-11-g319d14e4b`). v0.75.0 is tagged at `54ed19b5a`, which contains
it. Between the two, the daemon sources differ only in version strings: the
workspace and internal crate versions in `Cargo.toml` and `Cargo.lock` move
from 0.74.0 to 0.75.0, and `src/`, `crates/` and `bench/` are identical. The
measured binary therefore reports `rustbgpd 0.74.0`. This receipt calls it
v0.75.0 on that basis.

**The same-night results:**

- **rustbgpd is ahead of OpenBGPD 9.3 on S1 cold convergence, S2
  completion, S3 withdraw and re-announce, and IRR completion,** with
  separate ranges in every case. It is also ahead of BIRD 3.3.2 on IRR
  completion and the IRR changed-observer gap, with separate ranges.
- **The S2 stall p50 is close.** rustbgpd's median per-reload stall p50 is
  177.3 ms against OpenBGPD's 197.8 ms, about 10% lower. The per-reload
  values overlap at the tails: rustbgpd's slowest reload, 196.33 ms, is above
  OpenBGPD's five fastest, 192.74–196.26 ms.
- **OpenBGPD 9.3 keeps the smaller S2 stall tail:** p95 198–267 ms against
  rustbgpd's 217–365 ms, and worst single observer 268 ms against 378 ms.
- **OpenBGPD 9.3 delivers the first re-announced route sooner** after a
  member flap: p50 0.10–0.17 s (median 0.13 s) against rustbgpd's
  0.16–0.17 s (median 0.17 s). It finishes the re-announce in
  17.55–18.06 s against 0.29–0.33 s.
- **OpenBGPD 9.3 has the shorter changed-observer gap at IRR 50% overlap,**
  377–517 ms p50 against 591–627 ms. At 0% and 10% the ranges overlap.
- **S2 reload peak memory is about even** by cgroup peak: rustbgpd's own
  scope read 914–1,068 MiB and OpenBGPD's container 991–1,005 MiB. rustbgpd
  settles at less than half of OpenBGPD's RSS at both matrix shapes.

## Results

S1 comes from the convergence phase of the six S2 and S3 legs per daemon. S2
values are per-reload p50s over three runs of four reloads (n = 12). S3
values are per-round p50s over three runs of three rounds (n = 9). IRR values
are per-reload p50s over three roots of four reloads (n = 12 per overlap).
Every range is the minimum and maximum across those values.

BIRD 3.3.2 did not run in the matrix this time. Its matrix rows remain those
of the [v0.74.0 receipt](cross-daemon-v0740-2026-10.md), measured
2026-10-03 to 2026-10-04 against rustbgpd v0.74.0. They are quoted under
each matrix table as dated context, not as a same-night comparison. BIRD
3.3.3 was released on 2026-10-01 and has not been measured.

### S1 — cold convergence

| Cell | rustbgpd v0.75.0 | OpenBGPD 9.3 |
|---|---:|---:|
| 700 sessions Established, harness reading | **0.8 s** (all legs) | 88.6–182.5 s |
| Full base table at every observer | **2.8 s** (all legs) | 325.2–417.8 s |

The harness reads both times at 0.1 s resolution. rustbgpd's own log puts
the first to 700th `session established` record 0.722–0.744 s apart.
BIRD 3.3.2, dated (v0.74.0 night): 15.2–17.8 s and 67.3–70.1 s.

### S2 — policy reload, 700 × 400,400

**Stall** is the largest gap between consecutive UPDATE arrivals at an
observer during its reload window. **Completion** is when the observer holds
every expected base prefix with the new policy's community. All 700
observers are changed observers in this cell.

| Cell | rustbgpd v0.75.0 | OpenBGPD 9.3 |
|---|---:|---:|
| Stall p50 | 157–196 ms (median 177.3) | 193–212 ms (median 197.8) |
| Stall p95 | 217–365 ms | **198–267 ms** |
| Stall, worst single observer | 378 ms | **268 ms** |
| Completion p50 | **0.75–0.91 s** | 201.90–208.04 s |
| Completion, worst observer | **0.97 s** | 208.06 s |

- **Stall p50 by run.** The per-run medians are 171.3, 178.2 and 177.1 ms
  for rustbgpd and 202.0, 198.4 and 194.6 ms for OpenBGPD. rustbgpd is
  lower in each run's median, but not in every reload, so neither daemon is
  ahead across the range.
- **Sessions.** Every reload kept 700/700 sessions.
- **BIRD 3.3.2, dated (v0.74.0 night):** stall p50 1,767–2,531 ms, worst
  observer 9,285 ms, completion p50 89.06–103.61 s, worst 118.20 s.

### S3 — flapstorm, 50 members down and up

| Cell | rustbgpd v0.75.0 | OpenBGPD 9.3 |
|---|---:|---:|
| Withdraw p50 | **0.20–0.26 s** | 8.45–9.71 s |
| Re-announce p50 | **0.29–0.33 s** | 17.55–18.06 s |
| First re-announcement p50 | 0.16–0.17 s (median 0.17) | **0.10–0.17 s** (median 0.13) |
| Re-announce, worst observer | **0.34 s** | 18.10 s |

- **The clocks.** The re-announce clock starts when the harness begins
  sending the re-announcements, after all 50 sessions are Established again.
  First re-announcement is the first re-announced route at each survivor;
  re-announce is when the survivor holds them all.
- **First re-announcement.** OpenBGPD's round values range from 0.10 to
  0.17 s, and rustbgpd's are 0.17 s in eight rounds and 0.16 s in one. The
  ranges touch only at OpenBGPD's slowest rounds; every rustbgpd round is
  above OpenBGPD's median of 0.13 s.
- **No reconnect pacing.** Every reconnect in every round needed zero
  transport retries, for both daemons.
- **BIRD 3.3.2, dated (v0.74.0 night):** withdraw p50 0.68–0.99 s,
  re-announce p50 3.27–4.06 s, first re-announcement p50 0.26–0.85 s.

### Memory, matrix shapes

Values are runs 1 / 2 / 3. Each row names its source:

- **cgroup peak** is `memory.peak` of a swap-fenced cgroup that holds only
  that daemon. For rustbgpd it is the daemon's own scope. For OpenBGPD it is
  its container, which also charges the `docker exec` reload clients. Both
  include resident anonymous memory, page cache and kernel socket buffers,
  so the two rows are the same kind of reading. Each was recorded only with
  a swap peak of zero.
- **VmHWM** is the kernel's resident high-water mark for the rustbgpd
  process over the whole cell. The harness has no equivalent for the
  containerised OpenBGPD processes.
- **Sampled RSS** comes from a sampler that records the daemon's process
  tree every 5 seconds: one process for rustbgpd and seven for OpenBGPD.
  Settled is the last sample. The peak sample is the largest sample, which
  misses transients shorter than the interval, so a reload peak depends on
  sampling phase.

| Cell | Source | rustbgpd v0.75.0 | OpenBGPD 9.3 |
|---|---|---:|---:|
| S2 peak | cgroup peak | 1,002.7 / 914.0 / 1,067.6 MiB | 1,005.3 / 991.4 / 990.6 MiB |
| S2 peak | VmHWM | 568.4 / 564.7 / 559.4 MiB | not recorded |
| S2 peak | 5 s sample | 530.6 / 533.5 / 533.2 MiB | 988.5 / 988.1 / 988.3 MiB |
| S2 settled | 5 s sample | **369.5 / 368.3 / 369.1 MiB** | 804.4 / 800.1 / 796.3 MiB |
| S3 peak | cgroup peak | **572.9 / 578.7 / 570.5 MiB** | 989.9 / 990.1 / 988.5 MiB |
| S3 peak | VmHWM | 569.9 / 577.9 / 563.5 MiB | not recorded |
| S3 peak | 5 s sample | 560.3 / 559.6 / 565.0 MiB | 987.7 / 988.5 / 987.9 MiB |
| S3 settled | 5 s sample | **384.3 / 376.4 / 376.0 MiB** | 823.4 / 825.7 / 836.4 MiB |

- **S2 peak is about even.** rustbgpd's cgroup peaks span 914–1,068 MiB
  and OpenBGPD's 991–1,005 MiB. The ranges overlap, and OpenBGPD's median
  is 11 MiB lower. The rustbgpd cgroup peak runs 349–508 MiB above its
  VmHWM in the same run. The cgroup also charges socket buffers, page cache
  and kernel memory, and the harness does not split that share out.
- **Settled and S3:** rustbgpd is lower in every run.
- **rustbgpd's own readings.** The scope's `memory.current` at the last
  sample read 364.8–365.3 MiB at S2 and 371.1–380.4 MiB at S3. After each
  flap round, the daemon's jemalloc allocated bytes read 322–328 MiB and
  resident bytes 418–457 MiB. The harness's per-round RSS reading is 0 for
  the containerised OpenBGPD, so it has no per-round row.
- **BIRD 3.3.2, dated (v0.74.0 night):** its peak and settled RSS samples
  were 407–414 MiB at S2 and 332–377 MiB at S3; its last sample was its
  largest in every leg. That night recorded no container cgroup peak.

### IRR reload, 320 × 183,040

| Overlap | rustbgpd v0.75.0 | BIRD 3.3.2 | OpenBGPD 9.3 |
|---:|---:|---:|---:|
| 0%, completion p50 | **0.584–0.611 s** | 12.926–13.709 s | 44.010–58.695 s |
| 10%, completion p50 | **0.632–0.657 s** | 13.269–14.633 s | 54.594–63.574 s |
| 50%, completion p50 | **0.768–0.801 s** | 13.601–14.810 s | 56.096–63.948 s |
| 0%, changed-observer gap p50 | 391–448 ms | 832–873 ms | 368–519 ms |
| 10%, changed-observer gap p50 | 420–517 ms | 841–900 ms | 364–532 ms |
| 50%, changed-observer gap p50 | 591–627 ms | 829–899 ms | **377–517 ms** |
| 0%, peak process-tree RSS sample | 622 / 635 / 636 MiB | 1,381 / 1,365 / 1,385 MiB | 1,294 / 1,277 / 1,326 MiB |
| 10%, peak process-tree RSS sample | 653 / 673 / 654 MiB | 1,394 / 1,376 / 1,373 MiB | 1,434 / 1,439 / 1,419 MiB |
| 50%, peak process-tree RSS sample | 718 / 709 / 735 MiB | 1,419 / 1,422 / 1,419 MiB | 1,496 / 1,310 / 1,277 MiB |

- **Acceptance.** Every row has 320/320 sessions and zero parse errors.
- **Received-view overlap.** The rustbgpd cell's pre-reload topology proof
  recorded 0, 18,304 and 91,520 overlapping member/prefix pairs at the three
  overlap points.
- **The gap at 50%.** OpenBGPD's changed-observer gap p50 is lower than
  rustbgpd's in every reload of every root. The gap does not reverse the
  completion result.
- **rustbgpd VmHWM.** The daemon's resident high-water mark per root was
  745.2 / 741.3 / 780.4 MiB at 0%, 763.0 / 833.6 / 760.7 MiB at 10% and
  866.2 / 869.8 / 905.1 MiB at 50%.
- **Memory.** The IRR runner records no cgroup peak for any daemon, and no
  VmHWM for BIRD or OpenBGPD. The RSS rows are raw 5 s process-tree samples,
  and no cross-daemon memory ranking is claimed from them.

### rustbgpd's own reload clock

These intervals come from rustbgpd's JSON log, not from the harness, one per
SIGHUP (n = 12 per cell).

| Cell | SIGHUP → config source loaded | SIGHUP → config reload complete | RIB transition |
|---|---:|---:|---:|
| S2 policy reload | 5.1–8.1 ms | 717.5–872.7 ms (median 772.3) | 206.9–239.7 ms |
| IRR 0% | 95.8–101.9 ms | 560.7–609.0 ms (median 578.6) | 375.6–398.9 ms |
| IRR 10% | 99.1–102.3 ms | 602.0–642.9 ms (median 622.2) | 422.5–440.4 ms |
| IRR 50% | 101.3–104.6 ms | 769.9–801.8 ms (median 786.8) | 591.1–621.5 ms |

## Against the v0.74.0 receipt

The [v0.74.0 receipt](cross-daemon-v0740-2026-10.md) ran the night before,
on the same host, harness and shapes. Comparing the two is cross-night
context only; the same-night OpenBGPD arm above is the fair comparison.

- **rustbgpd's S2 stall.** The stall p50 range moved from 347–395 ms to
  157–196 ms, and the daemon-logged RIB transition from 321.2–392.1 ms to
  206.9–239.7 ms. S2 completion p50 (0.83–0.90 s against 0.75–0.91 s),
  SIGHUP to reload complete (793.0–872.5 ms against 717.5–872.7 ms), S1, S3
  and the IRR cells overlap their v0.74.0 ranges.
- **What changed in between.** The runtime commits between v0.74.0 and the
  measured commit are a counting sort for the shared encoder's transition
  inventory, building the clean-transition inventory before the RIB fence,
  and idle-client eviction in the telemetry listener. Two runs on two nights
  cannot attribute the S2 movement to any one of them.
- **OpenBGPD 9.2 against 9.3.** OpenBGPD's matrix and IRR p50 ranges
  overlap between the two nights in every cell: S2 stall p50 195–203 ms on
  9.2 against 193–212 ms on 9.3, S3 re-announce p50 17.67–18.10 s against
  17.55–18.06 s, and IRR completion p50 43.884–63.240 s against
  44.010–63.948 s. Its S1 established time spread wider this night,
  88.6–182.5 s against 131.1–159.9 s.
- **BIRD 3.3.2 in the IRR roots.** The same image measured 12.412–15.191 s
  IRR completion p50 on the v0.74.0 night and 12.926–14.810 s on this one.

## What these cells cannot show

- **BIRD was not in the matrix.** The matrix legs measured OpenBGPD 9.3
  against rustbgpd only. BIRD's matrix rows are the v0.74.0 night's.
- **Newer comparator releases were not measured.** BIRD 3.3.3 was released
  on 2026-10-01 and GoBGP v4.10.0 on 2026-10-04. This campaign measured
  BIRD 3.3.2 in the IRR roots, and GoBGP is not part of these cells.
- **One fixed shape per cell on one host.** No cell covers IPv6, other policy
  distributions, larger fleets or live Internet tables.
- **No attribution.** The campaign measured one rustbgpd tree, so it cannot
  attribute any rustbgpd change.
- **RR1000 was not run.** Its current rows remain in the
  [2026-09-28 receipt](headline-refresh-v0730-2026-09.md).
- **IRR has no grouped control.** The roots ran the three comparison cells
  only, so the received-view delta was checked by the rustbgpd cell's
  topology proof, not against a grouped control.
- **No IRR cgroup peaks.** The IRR runner does not yet read cgroup peaks for
  any daemon, so the IRR memory rows rest on VmHWM for rustbgpd and on 5 s
  samples for all three.

## Method

### Builds and identities

| Item | Value |
|---|---|
| rustbgpd | commit `319d14e4b78e8baaa24d27d13099a3b296ca7c10` (`v0.74.0-11-g319d14e4b`), tree `e6a802074f2bfb3680c9e3d684f3c4a22ca002b9`, release build, daemon SHA-256 `a013a469897af4a05620e4261726598afccc4de7179569fbf4422bdddc9af561`; v0.75.0 (`54ed19b5a`) differs from it only in version strings |
| `reloadstall` harness | built from the same tree with the `scale` profile, jemalloc, SHA-256 `fe0f2d89857b2284a5f31680c2d93478d63effc09957252d7794cfa6b85e7423` |
| OpenBGPD | 9.3, image `openbgpd/openbgpd@sha256:8f4b44f25796beaecb72ab7f099a3914961ac444a9de094ffca6a4614e741412`, the `:9.3` index digest; `bgpd -V` reports `OpenBGPD 9.3` |
| BIRD | 3.3.2, image `bird:v3.3.2-m101` (`sha256:98e6c2c4ed934ab426cd8932c282ec163fb5f0be9e79cef7ff19f052b7786fc7`), built from the checksum-pinned `tests/interop/Dockerfile.bird-v332`, 8 threads |
| Toolchain | rustc 1.99.0 |
| Host | AMD Ryzen Threadripper 7970X, 125 GiB RAM, no swap configured, Linux 7.0.0-30-generic |

The runners recorded `COMPETITOR_GENERATION=current`, which pairs OpenBGPD
9.3 with BIRD 3.3.2. OpenBGPD 9.3 was tagged on 2026-09-29 and its image
published on 2026-09-30. Every leg's provenance names the measured commit
with a clean tree.

### Order and host

- **One leg at a time.** A queue ran 21 legs strictly in sequence. Each leg
  is one invocation of an existing runner, which takes the host lock, waits
  for its quiet gate (one-minute load below 2.0, two accepted samples) and
  cools down for 300 seconds after each cell.
- **Matrix order.** For S2 and then S3, runs 1 and 3 measured OpenBGPD then
  rustbgpd, and run 2 measured rustbgpd then OpenBGPD.
- **IRR root order.** Within every IRR root, the runner measures rustbgpd,
  then BIRD, then OpenBGPD, with a cool-down between cells. The three roots
  at 0%, then 10%, then 50% followed the matrix legs. The IRR order is
  therefore fixed, not rotated.
- **Load.** No leg waited for the host lock. The one-minute load at leg starts was 1.02–1.33,
  except 3.76 at the first leg, right after the build. Every cell passed the
  quiet gate before it started.

### Invocations

- **Matrix:** `bench/scale/matrix/run-matrix.sh <daemon>` with
  `N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4 CONTROL_SECS=30`, and
  `FLAPSTORM=50` for S3. The recipe form is
  `N_PEERS=700 just bench-ixp-matrix <daemon>`.
- **IRR:** `bench/scale/irrreload/run-irr-reload.sh rustbgpd-sighup bird
  openbgpd` with `OVERLAP_FRACTION` set to 0, 0.1 or 0.5 and the canonical
  shape: seed 61, lists of 1,000–40,000 prefixes, 10% changed members and
  four reloads. The recipe form is `just bench-irr-reload`.

### Verification and extraction

- **Matrix provenance.** `bench/scale/matrix/verify-provenance.py` with the
  `current` generation passed for all 12 legs.
- **IRR roots.** The IRR verifier's per-root check (`validate_root` in
  `bench/scale/irrreload/verify-receipt.py`, comparison kind) passed for all
  nine roots. It covers the canonical shape, dataset digest, competitor
  image identities, quiet-gate samples, process identities and the
  pre-reload topology proof. The verifier's `campaigns` command needs a
  grouped control, which this campaign did not run.
- **Main extraction.** [`bench/scale/headline/summarize.py`](../../bench/scale/headline/summarize.py),
  run on the raw queue directory, wrote `summary.csv`,
  `establishment-span.csv` and `report.md`. It produced every matrix figure
  above apart from the tails, every rustbgpd IRR figure, and every memory
  figure apart from the IRR RSS samples of BIRD and OpenBGPD. `report.md`
  defines each memory metric's source.
- **Supplementary extraction.** `summarize.py` reports p50s, and rustbgpd's
  IRR rows only. The v0.74.0 bundle's `extract-tails.py`, unchanged, wrote
  the p95 and maximum values from the same labelled `reloadstall.log`
  lines, each matrix leg's RSS samples, and the BIRD and OpenBGPD IRR rows
  from the verified `rows.csv` and RSS files. It wrote `matrix-tails.csv`
  and `irr-cells.csv`. Every BIRD and OpenBGPD IRR figure above comes from
  `irr-cells.csv`.

## Artifacts

The compact bundle is
[`artifacts/cross-daemon-v0750-2026-10`](artifacts/cross-daemon-v0750-2026-10/README.md).
It holds each leg's harness log, status, RSS samples and provenance, the
rustbgpd VmHWM and cgroup readouts, OpenBGPD's container cgroup readout,
each IRR root's rows, completion status, dataset digest and per-cell logs,
the campaign progress log and identity file, and the extracted CSVs. Daemon
logs, scenario configurations and metrics scrapes stay outside the
repository.
