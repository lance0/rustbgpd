# Flap-storm (S3) addendum at v0.80.1: the withdraw regression fixed — 2026-10-25

This addendum re-measures one cell of the
[v0.80.0 cross-daemon refresh](cross-daemon-v0800-2026-10.md): the IXP-700 member flap (S3),
whose withdraw p50 regressed to 3.42–3.56 s at v0.80.0. v0.80.1 ships the fix. Three runs of
the v0.80.1 tag (`2fb2cbf27`) on the same host and shape, on 2026-10-25, put the withdraw p50 at
**0.24–0.30 s**, against 8.46–9.60 s for OpenBGPD 9.3 in the v0.80.0 queue. OpenBGPD still
delivers the first re-announced route sooner.

## Results

Ranges are min–max (median) of the per-round p50s over three runs of three flaps (n = 9).
The OpenBGPD 9.3 and v0.80.0 columns are the [v0.80.0 receipt](cross-daemon-v0800-2026-10.md),
measured in that receipt's overnight queue; the v0.75.0 column is the
[v0.75.0 receipt](cross-daemon-v0750-2026-10.md), measured 2026-10-04 to 2026-10-05.

| S3, 700 × 400,400, 50 flap | rustbgpd v0.80.1 | OpenBGPD 9.3 | rustbgpd v0.80.0 | rustbgpd v0.75.0 |
|---|---:|---:|---:|---:|
| Withdraw p50 | **0.24–0.30 s** (0.25) | 8.46–9.60 s (9.17) | 3.42–3.56 s (3.51) | 0.20–0.26 s |
| Re-announce p50 / worst | **0.36–1.02 / 1.05 s** (0.39) | 17.88–18.55 / 18.57 s (18.16) | 0.39–0.55 / 0.58 s (0.40) | 0.29–0.33 / 0.34 s |
| First re-announcement p50 | 0.24–0.90 s (0.25) | **0.10–0.16 s** (0.13) | 0.25–0.42 s (0.25) | 0.16–0.17 s |
| Cgroup peak, runs 1 / 2 / 3 | 464 / 462 / 463 MiB | 990 / 992 / 988 MiB | 466 / 457 / 462 MiB | 573 / 579 / 571 MiB |
| Settled, 5 s sample | 412 / 418 / 410 MiB | 847 / 830 / 825 MiB | 406 / 396 / 410 MiB | 384 / 376 / 376 MiB |

- **Per round, runs 1 / 2 / 3.** Withdraw p50 0.25 / 0.25 / 0.25, 0.24 / 0.26 / 0.26 and
  0.26 / 0.25 / 0.30 s; eight of the nine are inside v0.75.0's 0.20–0.26 s band. Re-announce
  p50 0.40 / 0.99 / 1.02, 0.39 / 0.39 / 0.38 and 0.39 / 0.67 / 0.36 s; first re-announcement
  0.25 / 0.86 / 0.90, 0.24 / 0.25 / 0.24 and 0.25 / 0.55 / 0.24 s. The three slower rounds
  (run 1 flaps 2 and 3, run 3 flap 2) are reported as measured and are not attributed.
- **Teardown in the daemon log.** In every round the 50 sessions were logged down within 9 ms
  of the flap, and the RIB logged clearing the last departed peer's registration 0.24–0.27 s
  after it.
- **The loss stands.** OpenBGPD's first re-announcement p50 (0.10–0.16 s) is below rustbgpd's
  0.24–0.90 s (median 0.25), as at v0.80.0.
- **Pre-release run.** A pre-release run on the fix commit, before the tag, measured withdraw
  p50 0.25–0.30 s on the same shape.

## Scope

- **S3 only.** S1, S2, IRR, Criterion, rrharness and bgperf2 stay as measured in the
  [v0.80.0 receipt](cross-daemon-v0800-2026-10.md); nothing else was re-run, and v0.80.1 changes
  no other daemon code. One shape: no BIRD, IPv6 or other fleet sizes.
- **Not one session.** OpenBGPD ran in the v0.80.0 overnight queue on the same host and inputs,
  not alongside these runs. These legs ran on CPUs 0-23,32-55 rather than the whole box. Load at
  leg start was 1.07–1.54, with no competitor daemons, builds or swap.

## Method and artifacts

A clean worktree at the v0.80.1 tag built `rustbgpd` and the `reloadstall` harness
(`cargo build --release --locked -p rustbgpd -p rustbgpctl -p rs-config-render`,
`cargo build --profile scale --locked -p reloadstall`); rustbgpd SHA-256 `32ab97e3…`, rustc
1.99.1. Each run was `N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4 CONTROL_SECS=30
FLAPSTORM=50 run-matrix.sh rustbgpd`, three sequential runs of three flaps; all three passed,
and none was retried. Provenance records commit `2fb2cbf27`, clean, and
`verify-provenance.py … rustbgpd current` passed for all three legs.
[`summarize.py`](../../bench/scale/headline/summarize.py) wrote the p50s and memory figures;
the re-announce worst is the harness's per-round maximum. The curated `comparison.json`, with
the gzipped daemon logs and per-leg files, is in
[`artifacts/cross-daemon-v0801-s3-2026-10`](artifacts/cross-daemon-v0801-s3-2026-10/README.md).
