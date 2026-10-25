# Cross-daemon refresh at v0.80.0: rustbgpd, OpenBGPD 9.3 and BIRD 3.3.3 on one night — 2026-10-25

> v0.80.1 fixes the S3 withdraw regression below; see the [v0.80.1 flap-storm addendum](cross-daemon-v0801-s3-2026-10.md).

One sequential overnight queue on 2026-10-25 (UTC) measured the v0.80.0 tag (`871d9d269`)
against OpenBGPD 9.3 on the IXP matrix and against OpenBGPD 9.3 and BIRD 3.3.3 in the IRR
reload roots. It also ran a Criterion A/B against v0.79.0, the in-repo rrharness flood rungs
and a bgperf2 spot-check. All 24 queue legs passed at their first attempt, and no leg is excluded.

- **rustbgpd is ahead of OpenBGPD 9.3 on S1, S2 completion and stall, S3 withdraw and
  re-announce, and IRR completion,** and ahead of BIRD 3.3.3 on IRR completion and gap, with
  separate ranges in every case. The S2 stall tail is now lower than OpenBGPD's as well; the
  stall harness changed after v0.75.0, so that cell is compared within this night only.
- **The S3 withdraw is a regression against v0.75.0:** p50 3.42–3.56 s, against 0.20–0.26 s.
  The daemon log shows why. In all nine rounds, the 50 sessions go down within 4.2–7.3 ms,
  but the RIB then deregisters the departed peers one at a time, 67.5–81.6 ms apart (round
  medians 68.5–71.4 ms), and the last lands 3.46–3.59 s after the flap. The change is not yet
  attributed to a commit; a fix is in progress. Re-announce and first re-announcement also slowed.
- **The losses:** OpenBGPD delivers the first re-announced route sooner after a member flap
  (p50 0.10–0.16 s against 0.25–0.42 s) and has the shorter changed-observer gap at IRR 50%
  overlap (365–448 against 589–623 ms).

## Bars, written before the run

| Bar | Result |
|---|---|
| Criterion: no shared id regresses beyond the same-SHA band + 5 points; multimodal ids per mode or hand-checked | **No regressions: 99 of 109 PASS.** 10 multimodal ids were not scored and are flagged for a closer look (below) |
| Matrix and cross-daemon: report the bands; a moved band is published as the new band; a losing cell is a loss | Reported below, with every moved band and loss |
| Failed runs retained, never rerun | No leg failed or was retried |
| No headline from a single bgperf2 run; RR headline never refreshed from rrharness | bgperf2 is a dated note only; the RR headline is unchanged |

The 10 unscored Criterion ids are `adj_rib_in_insert/100000`, `adj_rib_in_insert/500000`,
`attr_intern/typical_shared_arc/10000`, `loc_rib_recompute/1`, `loc_rib_recompute/2`,
`loc_rib_recompute/8`, `loc_rib_recompute_steady/withdraw_hit`, `nlri_encode/10`,
`nlri_encode/100` and `rib_pipeline/50000`. For each, the per-mode summarizer found modes it
could not split, a third mode, or too few samples in a mode to score. Where it could still
compare a mode, no delta exceeds the same-SHA band (the largest is +1.71% against a 1.76%
band). The summarizer's output, including its raw rollup line, is in the artifacts.

## Results

Ranges are min–max (median) over three runs. S2 reports per-reload p50s (n = 12), S3 per-round
p50s (n = 9) and IRR per-reload p50s (n = 12 per overlap). The v0.75.0 column is the
[v0.75.0 receipt](cross-daemon-v0750-2026-10.md), measured 2026-10-04 to 2026-10-05.

| Cell, 700 × 400,400 | rustbgpd v0.80.0 | OpenBGPD 9.3 | rustbgpd v0.75.0 |
|---|---:|---:|---:|
| S1 sessions Established | **0.8 s** | 126.2–209.9 s | 0.8 s |
| S1 full base table at every observer | **3.1–3.3 s** | 365.7–449.8 s | 2.8 s |
| S2 completion p50 | **0.84–0.96 s** (0.865) | 205.91–215.36 s | 0.75–0.91 s |
| S2 stall p50 | **35.4–51.8 ms** (42.5) | 193.1–251.9 ms (201.0) | 157–196 ms |
| S2 stall p95 / worst observer | **36.2–82.0 / 132.6 ms** | 199.8–291.0 / 291.6 ms | 217–365 / 378 ms |
| S2 SIGHUP → reload complete (daemon log) | 899.0–1,021.4 ms (928.9) | – | 717.5–872.7 ms |
| S3 withdraw p50 | **3.42–3.56 s** | 8.46–9.60 s | 0.20–0.26 s |
| S3 re-announce p50 / worst | **0.39–0.55 / 0.58 s** | 17.88–18.55 / 18.57 s | 0.29–0.33 / 0.34 s |
| S3 first re-announcement p50 | 0.25–0.42 s (0.25) | **0.10–0.16 s** (0.13) | 0.16–0.17 s |
| S2 cgroup peak, runs 1 / 2 / 3 | **583 / 616 / 609 MiB** | 1,003 / 989 / 989 MiB | 1,003 / 914 / 1,068 MiB |
| S2 settled, 5 s sample | **376 / 375 / 375 MiB** | 802 / 794 / 800 MiB | 370 / 368 / 369 MiB |
| S3 cgroup peak | **466 / 457 / 462 MiB** | 990 / 992 / 988 MiB | 573 / 579 / 571 MiB |
| S3 settled, 5 s sample | **406 / 396 / 410 MiB** | 847 / 830 / 825 MiB | 384 / 376 / 376 MiB |

| IRR, 320 × 183,040 | rustbgpd v0.80.0 | BIRD 3.3.3 | OpenBGPD 9.3 | rustbgpd v0.75.0 |
|---|---:|---:|---:|---:|
| 0% completion p50 | **0.598–0.657 s** | 12.884–13.788 s | 44.921–59.053 s | 0.584–0.611 s |
| 10% completion p50 | **0.650–0.673 s** | 12.905–14.703 s | 54.661–64.641 s | 0.632–0.657 s |
| 50% completion p50 | **0.819–0.853 s** | 13.476–15.858 s | 56.448–64.451 s | 0.768–0.801 s |
| 0% / 10% / 50% changed-observer gap p50 | 380–413 / 430–459 / 589–623 ms | 825–926 / 839–880 / 843–922 ms | 361–428 / 356–445 / **365–448** ms | 391–448 / 420–517 / 591–627 ms |
| 0% / 10% / 50% cgroup peak | 759–806 / 779–812 / 906–931 MiB | 1,378–1,596 / 1,484–1,597 / 1,478–1,576 MiB | 1,471–1,479 / 1,508–1,511 / 1,554–1,555 MiB | not recorded |

- **Acceptance.** Every IRR row has 320/320 sessions and zero parse errors; the topology proof
  recorded 0, 18,304 and 91,520 overlapping member/prefix pairs. Cgroup peaks are `memory.peak`
  of rustbgpd's swap-fenced scope or the competitor's container, which also charges its
  `docker exec` reload clients.
- **Moved bands.** S1, S2 SIGHUP to reload complete, every S3 latency, IRR 50% completion
  (about 6% slower, with separate ranges) and settled RSS at both matrix shapes are higher than
  at v0.75.0; S2 and IRR 0%/10% completion overlap. The daemon-logged S2 RIB transition fell
  from 206.9–239.7 ms to 59.2–80.1 ms, the same S2 shift as the
  [2026-10-11 quiet-host comparison](quiet-main-v075-s2-irr-2026-10-11.md).
- **The S2 stall is compared only within this night.** Since v0.75.0 the `reloadstall`
  churners stay phased, and a leg whose control-window churn stream has a gap above 31.25 ms
  is INVALID. The control-window stall fell from 70.5 to 19.3 ms on that change alone.

## In-repo rrharness rungs

`rrharness flood N 100000 20`, two runs per rung, against the in-repo table in the
[v0.64.0 refresh](ixp-matrix-2026-07.md#1000-client-rr-cell--in-repo-manager-direct-harness-1):

| Rung | cold staged (runs) | RSS converged | sustained fresh-100k blocks / 20 s | v0.64.0 |
|---|---|---|---|---|
| 256 | 0.230 / 0.230 s | 120 MiB | 82 / 82 | 0.396 / 0.418 s, 174 MiB, 50 |
| 512 | 0.329 / 0.304 s | 133 MiB | 73 / 71 | 0.656 / 0.674 s, 189 MiB, 36 |
| 1000 | 0.448 / 0.474 s | 157 MiB | 52 / 52 | 0.983 / 1.048 s, 213–214 MiB, 22 |

These manager-direct numbers are **not comparable** to the 1.82 s / 419 MiB transport-harness
headline in the [1000-peer scale receipt](scale-receipt-2026-07.md), which remains that
instrument's latest measurement. End-of-window RSS (3,192 MiB at 1000) is the harness process.

## Scope

- **One host, one night, fixed shapes:** no IPv6, other policy mixes, larger fleets or live
  tables. BIRD did not run in the matrix; its matrix rows remain BIRD 3.3.2 from the
  [v0.74.0 night](cross-daemon-v0740-2026-10.md). BIRD 3.4.0 and GoBGP are not measured.
- **The measured tree.** The IRR runner requires `origin/main` as an ancestor, so the IRR roots
  measured the v0.80.0 tree on a local commit parented on the next main commit, which adds only
  frozen v1-stable fixtures and a deployment-guide edit. Tree and binaries are identical
  (rustbgpd SHA-256 `a9bbbcea…`).
- **Order and host.** Matrix runs 1 and 3 measured OpenBGPD first and run 2 rustbgpd first; the
  IRR order is fixed (rustbgpd, BIRD, OpenBGPD). One-minute load at leg start was 1.02–2.13.
  The 10 s sampler shows no build processes and no containers beyond a constant baseline and
  the runner's own; the docker-events monitor recorded nothing. bgperf2's contention check
  found about one core in use outside the benchmark, mostly a resident inference server; the
  load floor of about 1.0 at leg starts is consistent with it running all night.
- **Pins.** OpenBGPD 9.3 `sha256:8f4b44f2…` (the `:9.3` tag has since been re-pushed), BIRD
  3.3.3 `sha256:fa47b7dc…`, rustc 1.99.1. The bgperf2 spot-check is a single rustbgpd run,
  recorded as a dated note in [benchmarks](../benchmarks.md).

## Method and artifacts

Matrix: `N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4 CONTROL_SECS=30 run-matrix.sh`, plus
`FLAPSTORM=50` for S3. IRR: `run-irr-reload.sh rustbgpd-sighup bird openbgpd` at overlap 0, 0.1
and 0.5 with the canonical seed-61 shape. `verify-provenance.py … current` passed for all 12
matrix legs and the IRR verifier's `validate_root(…, "comparison")` for all nine roots.
`summarize.py` and the unchanged v0.74.0 `extract-tails.py` wrote every figure. The bundle,
with gzipped rustbgpd daemon logs, is
[`artifacts/cross-daemon-v0800-2026-10`](artifacts/cross-daemon-v0800-2026-10/README.md).
