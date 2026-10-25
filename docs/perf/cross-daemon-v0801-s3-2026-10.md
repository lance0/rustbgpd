# Flap-storm (S3) addendum at v0.80.1: the withdraw regression fixed — 2026-10-25

This addendum re-measures one cell of the
[v0.80.0 cross-daemon refresh](cross-daemon-v0800-2026-10.md): the IXP-700 member flap (S3),
whose withdraw p50 regressed to 3.42–3.56 s at v0.80.0. v0.80.1 ships the fix. On the same host
and shape, three rustbgpd runs on 2026-10-25 put the withdraw p50 at **0.25–0.30 s**, against
8.46–9.60 s for OpenBGPD 9.3 in the v0.80.0 queue. OpenBGPD still delivers the first
re-announced route sooner.

## Results

Ranges are min–max (median) of the per-round p50s over three runs of three flaps (n = 9).
The OpenBGPD 9.3 and v0.80.0 columns are the [v0.80.0 receipt](cross-daemon-v0800-2026-10.md),
measured in that receipt's overnight queue; the v0.75.0 column is the
[v0.75.0 receipt](cross-daemon-v0750-2026-10.md), measured 2026-10-04 to 2026-10-05.

| S3, 700 × 400,400, 50 flap | rustbgpd v0.80.1 | OpenBGPD 9.3 | rustbgpd v0.80.0 | rustbgpd v0.75.0 |
|---|---:|---:|---:|---:|
| Withdraw p50 | **0.25–0.30 s** (0.25) | 8.46–9.60 s (9.17) | 3.42–3.56 s (3.51) | 0.20–0.26 s |
| Re-announce p50 / worst | **0.38–1.17 / 1.20 s** (0.39) | 17.88–18.55 / 18.57 s (18.16) | 0.39–0.55 / 0.58 s (0.40) | 0.29–0.33 / 0.34 s |
| First re-announcement p50 | 0.24–1.04 s (0.25) | **0.10–0.16 s** (0.13) | 0.25–0.42 s (0.25) | 0.16–0.17 s |
| Cgroup peak, runs 1 / 2 / 3 | 463 / 466 / 461 MiB | 990 / 992 / 988 MiB | 466 / 457 / 462 MiB | 573 / 579 / 571 MiB |
| Settled, 5 s sample | 413 / 404 / 410 MiB | 847 / 830 / 825 MiB | 406 / 396 / 410 MiB | 384 / 376 / 376 MiB |

- **Per round.** Withdraw p50s were 0.26 / 0.26 / 0.25, 0.25 / 0.30 / 0.25 and
  0.25 / 0.25 / 0.25 s; eight of the nine are inside v0.75.0's 0.20–0.26 s band.
- **Two slower rounds stay in the band.** Run 2 flap 2 (withdraw 0.30 s, re-announce 1.17 s,
  first re-announcement 1.04 s) and run 3 flap 2 (re-announce 0.70 s, first 0.56 s). In all
  nine rounds the daemon log shows the 50 sessions down within 8 ms and the RIB clearing the last
  departed peer's registration 0.23–0.27 s after the flap, including those two; the extra time
  in those rounds accrued after the daemon's logged teardown, on the observer side.
- **The loss stands.** OpenBGPD's first re-announcement p50 (0.10–0.16 s) is below rustbgpd's
  0.24–1.04 s (median 0.25), as at v0.80.0.

## Source identity

The runner recorded HEAD `00cfdbb15` (v0.80.0's fixture-freeze commit, daemon source identical
to the v0.80.0 tag) with uncommitted changes. The retained diffstat names the same five files,
with the same line counts, as `00cfdbb15..1d04f65a0`, the fix's PR head. `git diff 1d04f65a0
2fb2cbf27 -- src crates` against the v0.80.1 release commit (`2fb2cbf27`) changes only
`#[cfg(test)]` code in `slice_timing.rs` and four RIB test modules, so the measured daemon
source is v0.80.1's; the binary reports `0.80.0` because the version bump came with the release
commit. rustbgpd SHA-256 `adc21809…`, rustc 1.99.1, harness sources unchanged since v0.80.0.

## Scope

- **S3 only.** S1, S2, IRR, Criterion, rrharness and bgperf2 stay as measured in the
  [v0.80.0 receipt](cross-daemon-v0800-2026-10.md); nothing else was re-run, and v0.80.1 changes
  no other daemon code. One shape: no BIRD, IPv6 or other fleet sizes.
- **Not one session.** OpenBGPD ran in the v0.80.0 overnight queue on the same host and inputs,
  not alongside these runs. One-minute load at leg start was 1.07–1.42, with no competitor
  daemons running and no swap configured.

## Method and artifacts

`N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4 CONTROL_SECS=30 FLAPSTORM=50 run-matrix.sh
rustbgpd`, three sequential runs, each three flaps. `verify-provenance.py … rustbgpd current`
passed for all three legs. [`summarize.py`](../../bench/scale/headline/summarize.py) wrote
the p50s and memory figures; the re-announce worst is the harness's per-round maximum in
`reloadstall.log`. The bundle, with gzipped daemon logs, is
[`artifacts/cross-daemon-v0801-s3-2026-10`](artifacts/cross-daemon-v0801-s3-2026-10/README.md).
