# Cross-daemon refresh at v0.74.0: rustbgpd, BIRD 3.3.2 and OpenBGPD 9.2 on one night — 2026-10

This overnight campaign measured the v0.74.0 release tree against BIRD 3.3.2
and OpenBGPD 9.2 on one host. It ran from 2026-10-03 21:47 to 2026-10-04
06:36 local time. It covers the comparison cells published on the IXP matrix
and IRR reload receipts:

- **IXP matrix, 700 clients × 400,400 routes:** S1 cold convergence, S2
  policy reload and S3 flapstorm, three runs per daemon, with the daemon
  order rotated in a Latin square.
- **IRR reload, 320 members × 183,040 prefixes:** cross-daemon roots at 0%,
  10% and 50% received-view overlap, three roots per overlap.

All 27 legs passed their runners' acceptance, and no leg is excluded. It is
the first campaign since 2026-08-08 to run all three daemons through the IXP
matrix in one window. The older receipts are unchanged and stay as dated
records.

**The same-night results:**

- **rustbgpd is ahead on S1 cold convergence, S2 completion, S3 withdraw
  and re-announce, and IRR completion,** with separate ranges in every
  case.
- **OpenBGPD 9.2 has the smaller S2 reload stall,** 195–203 ms p50 against
  rustbgpd's 347–395 ms, and the smaller worst single observer, 237 ms
  against 563 ms.
- **OpenBGPD 9.2 has the shorter changed-observer gap at IRR 50% overlap,**
  378–445 ms p50 against 566–643 ms. At 0% and 10% the ranges overlap.
- **OpenBGPD 9.2 delivers the first re-announced route sooner** after a
  member flap, 0.09–0.16 s p50 against rustbgpd's 0.17 s. It finishes the
  re-announce in 17.67–18.10 s against 0.29–0.33 s.
- **BIRD 3.3.2 has the lower peak process-tree RSS sample** at both matrix
  shapes. Settled RSS is mixed at S3, and lower for rustbgpd at S2.

## Results

S1 comes from the convergence phase of the six S2 and S3 legs per daemon. S2
values are per-reload p50s over three runs of four reloads (n = 12). S3
values are per-round p50s over three runs of three rounds (n = 9). IRR values
are per-reload p50s over three roots of four reloads (n = 12 per overlap).
Every range is the minimum and maximum across those values.

### S1 — cold convergence

| Cell | rustbgpd v0.74.0 | BIRD 3.3.2 | OpenBGPD 9.2 |
|---|---:|---:|---:|
| 700 sessions Established, harness reading | **0.8 s** (all legs) | 15.2–17.8 s | 131.1–159.9 s |
| Full base table at every observer | **2.8–2.9 s** | 67.3–70.1 s | 368.6–406.3 s |

The harness reads both times at 0.1 s resolution. rustbgpd's own log puts
the first to 700th `session established` record 0.735–0.756 s apart.

### S2 — policy reload, 700 × 400,400

**Stall** is the largest gap between consecutive UPDATE arrivals at an
observer during its reload window. **Completion** is when the observer holds
every expected base prefix with the new policy's community. All 700
observers are changed observers in this cell.

| Cell | rustbgpd v0.74.0 | BIRD 3.3.2 | OpenBGPD 9.2 |
|---|---:|---:|---:|
| Stall p50 | 347–395 ms | 1,767–2,531 ms | **195–203 ms** |
| Stall p95 | 424–538 ms | 2,183–6,265 ms | **200–209 ms** |
| Stall, worst single observer | 563 ms | 9,285 ms | **237 ms** |
| Completion p50 | **0.83–0.90 s** | 89.06–103.61 s | 204.08–211.99 s |
| Completion, worst observer | **0.97 s** | 118.20 s | 212.00 s |

Every reload kept 700/700 sessions. The 2026-08-30 OpenBGPD 9.2 amendment
published no completion maximum; this receipt does.

### S3 — flapstorm, 50 members down and up

| Cell | rustbgpd v0.74.0 | BIRD 3.3.2 | OpenBGPD 9.2 |
|---|---:|---:|---:|
| Withdraw p50 | **0.24–0.25 s** | 0.68–0.99 s | 8.39–9.69 s |
| Re-announce p50 | **0.29–0.33 s** | 3.27–4.06 s | 17.67–18.10 s |
| First re-announcement p50 | 0.17 s (all rounds) | 0.26–0.85 s | **0.09–0.16 s** |
| Re-announce, worst observer | **0.34 s** | 5.34 s | 18.12 s |

- **The clocks.** The re-announce clock starts when the harness begins
  sending the re-announcements, after all 50 sessions are Established again.
  First re-announcement is the first re-announced route at each survivor;
  re-announce is when the survivor holds them all.
- **No reconnect pacing this time.** Every reconnect in every round needed
  zero transport retries, for all three daemons. The 2026-08-30 OpenBGPD 9.2
  amendment recorded IdleHold pacing in rounds two and three; it did not
  recur.

### Memory, matrix shapes

The sampler records the daemon's process-tree RSS every 5 seconds. Settled
is the last sample and peak is the largest. Values are runs 1 / 2 / 3.

| Cell | rustbgpd v0.74.0 | BIRD 3.3.2 | OpenBGPD 9.2 |
|---|---:|---:|---:|
| S2 settled RSS | **369 / 373 / 370 MiB** | 407 / 412 / 414 MiB | 794 / 794 / 793 MiB |
| S2 peak RSS sample | 541 / 541 / 540 MiB | **407 / 412 / 414 MiB** | 988 / 988 / 988 MiB |
| S3 settled RSS | 376 / 376 / 375 MiB | 377 / 332 / 373 MiB | 830 / 841 / 826 MiB |
| S3 peak RSS sample | 544 / 515 / 511 MiB | **377 / 332 / 373 MiB** | 987 / 988 / 989 MiB |

- **S2 settled:** rustbgpd is lower in every run. This is the first
  head-to-head measurement of this cell: the previously published BIRD
  figure was dated to 2026-08-08.
- **S3 settled is mixed.** Run by run, rustbgpd was 1 MiB lower in run 1,
  and BIRD was 44 MiB lower in run 2 and 3 MiB lower in run 3. Earlier
  receipts put the noise floor of a single settled sample at this shape at
  30–50 MiB.
- **Peak:** BIRD's highest sample is its last one, in every leg.
  rustbgpd's peak sample is 126–183 MiB above BIRD's in the same run.
- **rustbgpd's own readings.** Daemon VmHWM was 571–575 MiB at S2 and
  556–567 MiB at S3. After each flap round, the daemon's jemalloc allocated
  bytes read 320–333 MiB and resident bytes 427–470 MiB. The harness's
  per-round RSS reading is 0 for the containerised competitors, so they
  have no per-round row.
- **No memory ranking beyond these rows.** Daemon and container defaults
  differ. The sampler covers each daemon's process tree: one process for
  rustbgpd and BIRD, seven for OpenBGPD.

### IRR reload, 320 × 183,040

| Overlap | rustbgpd v0.74.0 | BIRD 3.3.2 | OpenBGPD 9.2 |
|---:|---:|---:|---:|
| 0%, completion p50 | **0.592–0.621 s** | 12.412–13.732 s | 43.884–58.416 s |
| 10%, completion p50 | **0.638–0.689 s** | 13.119–14.219 s | 53.595–62.446 s |
| 50%, completion p50 | **0.778–0.822 s** | 13.937–15.191 s | 55.329–63.240 s |
| 0%, changed-observer gap p50 | 389–427 ms | 818–908 ms | 368–463 ms |
| 10%, changed-observer gap p50 | 436–495 ms | 834–904 ms | 367–464 ms |
| 50%, changed-observer gap p50 | 566–643 ms | 822–878 ms | **378–445 ms** |
| 0%, peak process-tree RSS sample | 626 / 627 / 621 MiB | 1,382 / 1,403 / 1,381 MiB | 1,411 / 1,257 / 1,249 MiB |
| 10%, peak process-tree RSS sample | 659 / 654 / 652 MiB | 1,379 / 1,375 / 1,399 MiB | 1,290 / 1,402 / 1,358 MiB |
| 50%, peak process-tree RSS sample | 710 / 721 / 705 MiB | 1,414 / 1,414 / 1,417 MiB | 1,321 / 1,464 / 1,317 MiB |

- **Acceptance.** Every row has 320/320 sessions and zero parse errors.
- **Received-view overlap.** The rustbgpd cell's pre-reload topology proof
  recorded 0, 18,304 and 91,520 overlapping member/prefix pairs at the three
  overlap points.
- **The gap at 50%.** OpenBGPD's changed-observer gap p50 is lower than
  rustbgpd's in every root, as the v0.68.0 receipt also recorded. The gap
  does not reverse the completion result.
- **Memory.** These are raw process-tree samples, and no cross-daemon memory
  ranking is claimed because daemon and container defaults differ.

### rustbgpd's own reload clock

These intervals come from rustbgpd's JSON log, not from the harness, one per
SIGHUP (n = 12 per cell).

| Cell | SIGHUP → config source loaded | SIGHUP → config reload complete | RIB transition |
|---|---:|---:|---:|
| S2 policy reload | 5.6–7.5 ms | 793.0–872.5 ms (median 823.9) | 321.2–392.1 ms |
| IRR 0% | 96.5–102.1 ms | 533.8–562.0 ms (median 550.3) | 364.8–386.9 ms |
| IRR 10% | 97.9–100.7 ms | 583.3–614.5 ms (median 598.5) | 412.7–435.9 ms |
| IRR 50% | 98.9–107.8 ms | 764.3–807.0 ms (median 780.5) | 571.8–590.2 ms |

## Against the previously published rows

These are cross-date comparisons, given as context only. The same-night
competitor arms above are the fair comparison. This campaign does not show
which change moved any rustbgpd figure, and it claims no speedup from them.

- **The harness boundary.** The published v0.68.0 rows and the competitor
  rows from 2026-08-08 and 2026-08-30 were measured with the `reloadstall`
  receiver harness on glibc malloc. This campaign's harness links jemalloc.
  Their S2 completion and stall, and IRR completion and gap rows, are not
  directly comparable with this receipt's
  ([why](headline-refresh-jemalloc-2026-10.md#why-earlier-receiver-bound-rows-are-not-comparable)).
  S1, S3 and daemon-logged intervals are comparable across that boundary.
- **rustbgpd at v0.68.0,** measured 2026-08-30
  ([matrix](ixp-matrix-2026-07.md#v0680-source-equivalent-refresh--2026-08-30),
  [IRR](irr-reload-v0680-2026-08.md)): S1 0.7 s and 3.4 s; S3 withdraw p50
  0.30–0.43 s and re-announce p50 0.358–0.393 s; S2 completion p50
  1.209–1.350 s; IRR completion p50 0.852–1.085 s across the three overlaps.
- **rustbgpd's daemon-logged reload clock.** The
  [2026-09-28 receipt](headline-refresh-v0730-2026-09.md) measured v0.68.0
  at 886–987 ms SIGHUP to reload complete at S2, and 765–826 ms at IRR 0%.
  The [2026-10-03 receipt](headline-refresh-jemalloc-2026-10.md) measured
  main at `481e0187d` at 1,099–1,159 ms and 1,029–1,084 ms. v0.74.0 reads
  793.0–872.5 ms and 533.8–562.0 ms here.
- **BIRD,** measured 2026-08-08 at 3.3.1 in the matrix and 2026-08-30 at
  3.3.2 in the IRR receipt. The matrix now runs 3.3.2, so its BIRD rows also
  changed release.
- **OpenBGPD 9.2,** same image digest, measured 2026-08-30
  ([amendment](ixp-matrix-2026-07.md#openbgpd-92-comparator-refresh-2026-08-30)):
  established 83.6–105.7 s, base table 326.0–347.8 s, S2 stall p50
  0.213–0.238 s, S3 withdraw p50 8.22–9.55 s, S3 settled RSS 831/827 MiB.

## What these cells cannot show

- **OpenBGPD 9.3 was not measured.** OpenBGPD 9.3 was released on
  2026-09-30. This campaign measured 9.2, at the image digest the runners
  pin. A 9.3 re-measurement is planned separately.
- **One fixed shape per cell on one host.** No cell covers IPv6, other policy
  distributions, larger fleets or live Internet tables.
- **No attribution.** The campaign measured one rustbgpd tree, so it cannot
  attribute any rustbgpd change.
- **RR1000 was not run.** Its current rows remain in the
  [2026-09-28 receipt](headline-refresh-v0730-2026-09.md).
- **IRR has no grouped control.** The roots ran the three comparison cells
  only, so the received-view delta was checked by the rustbgpd cell's
  topology proof, not against a grouped control.

## Method

### Builds and identities

| Item | Value |
|---|---|
| rustbgpd | v0.74.0, commit `4d14851f77b064dd254f2319708dd91f281f9b0d`, tree `e5978429af576da29aaced1d4d04785c3d1ab6b1`, release build, daemon SHA-256 `6e9095a4bfebe3e96050089a76d1f73e907a57f29519bad58c229a1cafe3ef72` |
| `reloadstall` harness | built from the same tree with the `scale` profile, jemalloc, SHA-256 `c4e393397204e8ca3580c30b72e9f5fa16c6833d1d679194ec68290d3892e18a` |
| BIRD | 3.3.2, image `bird:v3.3.2-m101` (`sha256:98e6c2c4ed934ab426cd8932c282ec163fb5f0be9e79cef7ff19f052b7786fc7`), built from the checksum-pinned `tests/interop/Dockerfile.bird-v332`, 8 threads |
| OpenBGPD | 9.2, image `openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9` |
| Toolchain | rustc 1.99.0 |
| Host | AMD Ryzen Threadripper 7970X, 125 GiB RAM, no swap configured, Linux 7.0.0-30-generic |

The runners recorded `COMPETITOR_GENERATION=current`. BIRD 3.3.2 was the
latest 3.x release when the campaign started. Every leg's provenance names
the measured commit with a clean tree; no leg ran from a reparented commit.

### Order and host

- **One leg at a time.** A queue ran 27 legs strictly in sequence. Each leg
  is one invocation of an existing runner, which takes the host lock, waits
  for its quiet gate (one-minute load below 2.0, two accepted samples) and
  cools down for 300 seconds after each cell.
- **Matrix Latin square.** For S2 and then S3, run 1 measured rustbgpd →
  BIRD → OpenBGPD, run 2 BIRD → OpenBGPD → rustbgpd, and run 3 OpenBGPD →
  rustbgpd → BIRD.
- **IRR root order.** Within every IRR root, the runner measures rustbgpd,
  then BIRD, then OpenBGPD, with a cool-down between cells. The three roots
  at 0%, then 10%, then 50% followed the matrix legs. The IRR order is
  therefore fixed, not rotated.
- **Interleaved release checks.** The v0.74.0 release checks ran on this host
  under the same host lock, only between legs. Two legs waited 30 s and
  150 s for the lock. The one-minute load at leg starts was 1.01–2.74,
  except 4.34 at the first leg, right after the build. Every cell passed the
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
  `current` generation passed for all 18 legs.
- **IRR roots.** The IRR verifier's per-root check (`validate_root` in
  `bench/scale/irrreload/verify-receipt.py`, comparison kind) passed for all
  nine roots. It covers the canonical shape, dataset digest, competitor
  image identities, quiet-gate samples, process identities and the
  pre-reload topology proof. The verifier's `campaigns` command needs a
  grouped control, which this campaign did not run.
- **Main extraction.** [`bench/scale/headline/summarize.py`](../../bench/scale/headline/summarize.py)
  wrote `summary.csv`, `establishment-span.csv` and the per-daemon ranges.
  Its leg names are `matrix-<daemon>-r<N>-s<K>` and
  `irr-ov<F>-rustbgpd-r<N>`. It reads the rustbgpd rows of each IRR root.
- **Supplementary extraction.** `summarize.py` reports p50s and rustbgpd's
  IRR rows only. A short script in the bundle, `extract-tails.py`, writes
  the p95 and maximum values from the same labelled `reloadstall.log` lines,
  each matrix leg's RSS samples, and the BIRD and OpenBGPD IRR rows from the
  verified `rows.csv` and RSS files. It wrote `matrix-tails.csv` and
  `irr-cells.csv`.

## Artifacts

The compact bundle is
[`artifacts/cross-daemon-v0740-2026-10`](artifacts/cross-daemon-v0740-2026-10/README.md).
It holds each leg's harness log, status, RSS samples and provenance, the
rustbgpd VmHWM and cgroup readouts, each IRR root's rows, completion status,
dataset digest and per-cell logs, the campaign progress log and identity
file, and the extracted CSVs. Daemon logs, scenario configurations and
metrics scrapes stay outside the repository.
