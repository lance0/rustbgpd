# Cross-daemon IXP matrix at v0.84.0: rustbgpd, BIRD 3.3.3 and OpenBGPD 9.3 on one host — 2026-11-22

One sequential campaign on 2026-11-22 (UTC) measured the v0.84.0 release preparation head (`5f5ca6a31`, whose tree is identical to the
v0.84.0 squash commit `8ac5f59ab`; the tag at `0d2c9027a` adds only documentation changes)
against BIRD 3.3.3 and OpenBGPD 9.3 on the IXP matrix: S1 cold start, S2 policy reload and S3
member flap at 700 route-server clients × 400,400 IPv4 routes, two runs per daemon with the
daemon order rotated. All 12 cells passed at their first attempt; none was excluded or rerun.
It is the first matrix measurement of BIRD 3.3.3.

- **rustbgpd is ahead of both incumbents on S1, S2 completion and stall, and S3 withdraw and
  re-announce,** with separate ranges in every case.
- **Moved rustbgpd bands against v0.80.0/v0.80.1:** S2 completion p50 is lower (0.77–0.83 s
  against 0.84–0.96 s) and so is the daemon's SIGHUP-to-complete interval. Cold convergence
  (3.9 s against 3.1–3.3 s), the S2 stall (p50 50.1–69.2 ms against 35.4–51.8 ms) and the S3
  withdraw (p50 0.37–0.40 s against v0.80.1's 0.24–0.30 s) are higher. Both runs agree on
  every moved band. None is attributed to a commit.
- **The losses:** OpenBGPD delivers the first re-announced route sooner after a member flap
  (p50 0.11–0.15 s against 0.26–0.28 s). BIRD has the lower peak process-tree RSS sample at both
  shapes and the lower settled RSS at S3.

## Results

Ranges are min–max (median) over two runs. S2 reports per-reload p50s (n = 8) and S3 per-round
p50s (n = 6); S1 pools the four S2 and S3 legs per daemon. The comparison columns are the
[v0.80.0 cross-daemon receipt](cross-daemon-v0800-2026-10.md) (rustbgpd v0.80.0 and OpenBGPD
9.3, 2026-10-25), its [v0.80.1 flap-storm addendum](cross-daemon-v0801-s3-2026-10.md) for
rustbgpd S3, and the [v0.74.0 cross-daemon receipt](cross-daemon-v0740-2026-10.md) for BIRD 3.3.2
(2026-10-03 to 2026-10-04).

| Cell, 700 × 400,400 | rustbgpd v0.84.0 | BIRD 3.3.3 | OpenBGPD 9.3 | rustbgpd v0.80.x | BIRD 3.3.2 | OpenBGPD 9.3, 2026-10-25 |
|---|---:|---:|---:|---:|---:|---:|
| S1 sessions Established | **0.8 s** | 15.3–18.3 s | 131.5–206.5 s | 0.8 s | 15.2–17.8 s | 126.2–209.9 s |
| S1 full base table at every observer | **3.9 s** | 68.2–71.4 s | 376.7–443.9 s | 3.1–3.3 s | 67.3–70.1 s | 365.7–449.8 s |
| S2 completion p50 | **0.77–0.83 s** (0.79) | 72.40–100.04 s (92.48) | 205.71–216.26 s (212.38) | 0.84–0.96 s | 89.06–103.61 s | 205.91–215.36 s |
| S2 completion, worst observer | **0.87 s** | 110.62 s | 216.28 s | – | 118.20 s | – |
| S2 stall p50 | **50.1–69.2 ms** (57.1) | 1,962–3,173 ms (2,138) | 192.3–209.7 ms (200.0) | 35.4–51.8 ms | 1,767–2,531 ms | 193.1–251.9 ms |
| S2 stall p95 / worst observer | **53.9–125.3 / 139.5 ms** | 3,107–8,562 / 11,307 ms | 199.8–250.9 / 251.9 ms | 36.2–82.0 / 132.6 ms | 2,183–6,265 / 9,285 ms | 199.8–291.0 / 291.6 ms |
| S2 SIGHUP → reload complete (daemon log) | 823.3–890.6 ms (850.0) | – | – | 899.0–1,021.4 ms | – | – |
| S3 withdraw p50 | **0.37–0.40 s** (0.38) | 0.73–0.97 s (0.81) | 8.51–9.84 s (9.13) | 0.24–0.30 s | 0.68–0.99 s | 8.46–9.60 s |
| S3 re-announce p50 / worst | **0.44–0.48 / 0.51 s** | 3.25–4.41 / 5.26 s | 17.90–18.61 / 18.64 s | 0.36–1.02 / 1.05 s | 3.27–4.06 / 5.34 s | 17.88–18.55 / 18.57 s |
| S3 first re-announcement p50 | 0.26–0.28 s (0.27) | 0.38–0.67 s (0.48) | **0.11–0.15 s** (0.13) | 0.24–0.90 s | 0.26–0.85 s | 0.10–0.16 s |

### Memory

Settled is the last 5-second process-tree RSS sample and peak sample is the largest. Cgroup
peak is `memory.peak` of rustbgpd's swap-fenced scope or the competitor's container, which also
charges its `docker exec` reload clients. Values are runs A / B, in MiB.

| Cell | rustbgpd v0.84.0 | BIRD 3.3.3 | OpenBGPD 9.3 | rustbgpd v0.80.x | OpenBGPD 9.3, 2026-10-25 |
|---|---:|---:|---:|---:|---:|
| S2 settled | **378 / 375** | 414 / 415 | 797 / 797 | 376 / 375 / 375 | 802 / 794 / 800 |
| S2 peak sample | 510 / 498 | **414 / 420** | 987 / 987 | – | – |
| S2 cgroup peak | **666 / 622** | 792 / 877 | 987 / 988 | 583 / 616 / 609 | 1,003 / 989 / 989 |
| S3 settled | 402 / 396 | **347 / 372** | 832 / 826 | 412 / 418 / 410 | 847 / 830 / 825 |
| S3 peak sample | 458 / 462 | **347 / 372** | 988 / 988 | – | – |
| S3 cgroup peak | 463 / 460 | 681 / 384 | 988 / 989 | 464 / 462 / 463 | 990 / 992 / 988 |

- **Acceptance.** Every reload and flap round kept 700/700 sessions, and the runner's provenance
  verifier passed for all 12 cells: clean tree at the measured commit, matching binary and image
  identities and workload inputs.
- **In-band.** Every OpenBGPD 9.3 row is inside or at the edge of its 2026-10-25 range. BIRD
  3.3.3's S1, S3 and memory rows sit with BIRD 3.3.2's; its S2 completion range is wider at the
  low end (72.40 s against 89.06 s) and its S2 stall tail is longer.
- **rustbgpd memory.** S2 settled RSS is unchanged; the S2 cgroup peak's upper edge rose from
  616 to 666 MiB. S3 cgroup peak is unchanged and S3 settled RSS is 8–22 MiB lower than at v0.80.1.
- **The S2 daemon RIB transition** read 83.6–89.1 ms, against 59.2–80.1 ms at v0.80.0.

## Scope

- **One host, one day, fixed shapes:** IPv4 only, one policy mix, no larger fleets or live
  tables. IRR reload, rrharness and bgperf2 were not run in this campaign; the IRR rows remain
  the [v0.80.0 receipt](cross-daemon-v0800-2026-10.md)'s.
- **Two runs, not three.** The v0.80.0 night ran three per daemon; ranges here have n = 8 (S2)
  and n = 6 (S3).
- **Changed inputs since v0.80.0.** rustc 1.100.0 (v0.80.0 used 1.99.1). The BIRD 3.3.3 image
  was rebuilt under its matrix tag from the same checksum-pinned source and Dockerfile; its
  image ID (`sha256:4362cdcb…`) differs from the v0.80.0 night's (`sha256:fa47b7dc…`), whose
  IRR roots used it. BIRD 3.3.2 is the previous matrix BIRD, so the BIRD comparison column also
  crosses a version. The OpenBGPD 9.3 image is the same digest.
- **Order and host.** Run A measured OpenBGPD, rustbgpd, BIRD; run B rustbgpd, BIRD, OpenBGPD;
  each run measured S2 before S3. One-minute load at leg start was 1.02–1.27. A 10 s sampler
  recorded no compiler, docker build, benchmark harness or foreign container during any leg; a
  resident inference server held the load floor near 1.0 throughout.

## Method and artifacts

Each cell was one `N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4 CONTROL_SECS=30 run-matrix.sh
<daemon>` invocation, plus `FLAPSTORM=50` for S3, with `COMPETITOR_GENERATION=current` and its
own artifact root; the runner holds the host lock, gates on a quiet host and cools down 300 s
after each cell. The release daemon was built with `cargo build --release --locked -p rustbgpd
-p rustbgpctl -p rs-config-render` and the harness with `cargo build --profile scale --locked
-p reloadstall`; rustbgpd SHA-256 `73685c58…`. [`summarize.py`](../../bench/scale/headline/summarize.py)
and the unchanged v0.74.0 `extract-tails.py` wrote every figure. The bundle, with gzipped
rustbgpd daemon logs, is
[`artifacts/ixp-matrix-2026-07/v0840-refresh-2026-11`](artifacts/ixp-matrix-2026-07/v0840-refresh-2026-11/README.md).
