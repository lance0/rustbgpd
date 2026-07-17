# IXP receipt matrix — campaign state

Cross-daemon reload-stall matrix (rustbgpd vs BIRD 3.3.1 vs OpenBGPD
9.1) through the shared `bench/scale/reloadstall` harness. Design and
fairness protocol: identical wire inputs, receiver-side measurement,
each incumbent at its documented strongest configuration, DNF published
with mechanism, pre-committed shapes. The final receipt lands at
`docs/perf/ixp-matrix-2026-07.md` with raw artifacts alongside.

## Done

- Tooling shipped: harness `reload_cmd` trigger + external-RSS mode +
  `--flapstorm`, `gen-bird-scenario.py` / `gen-obgpd-scenario.py`
  (config-parse verified in their containers), `run-matrix.sh`
  (resumable per-cell), `rss-sampler.sh` (process-tree).
- Images: `bird:3.3.1` built from `tests/interop/Dockerfile.bird3`;
  `openbgpd/openbgpd:9.1` pulled.
- **Scale ladder complete, 6/6 cells PASS** (2026-07-16, artifacts in
  `artifacts-rung1/` and `artifacts-rung2/`):

  | 200 × 115,000, 2 reloads | rustbgpd | BIRD 3.3.1 | OpenBGPD 9.1 |
  |---|---|---|---|
  | stall p50 | 109–128 ms | 984 ms (max 2.46 s) | 36–61 ms |
  | completion p50 | 0.29–0.31 s | 7.5–7.7 s | 15.2 s |
  | daemon RSS (tree) | ~432 MB | ~103 MB | ~284 MB |

  Rung 1 (20 × 20k): all three fast and healthy — validates sessions,
  NEXT_HOP glue, generation delivery, reload triggers, RSS sampling.
- **Shape decision: full 700 × 400,400 is GO** — OpenBGPD's RSS slope
  at rung 2 projects far under the 100 GiB cell-abort gate; the
  pre-committed 300 × 200k fallback stays unused unless run A's first
  OpenBGPD cell says otherwise.

## Threads decision (done)

BIRD sweep at 200 × 115k, 2 reloads: `threads 32` completes ~15%
faster (6.3–6.7 s vs 7.5–7.7 s p50) but stalls ~55% worse
(1.49–1.60 s vs 0.98 s p50). **Campaign runs use `threads 8`** — the
better configuration on the headline stall KPI (the
generous-to-competitor choice) and consistent with upstream guidance
to cap threads. Both raw runs preserved (`artifacts-rung2/bird`,
`artifacts-bird-threads32/`); the trade goes in the receipt's
config-disclosure section.

## Campaign runs A + B: COMPLETE (2026-07-17, 12/12 cells pass)

All four legs pass at head `40fd0a0c` (jemalloc-default binary +
rs_control opt-in fix): `artifacts-runA-s2`, `artifacts-runA-s3`
(flapstorm 50), `artifacts-runB-s2`, `artifacts-runB-s3`. rustbgpd
S2 stall p50 652/808 ms, completion p50 1.51/1.66 s, daemon RSS
~755-785 MB (the jemalloc default nearly halves the prior 1.3 GiB
glibc peak at this shape). Two anomalies preserved as `*-fail-*`
artifact siblings, both for the receipt's notes: (1) the initial
rustbgpd cells RSS-aborted >100 GiB because rs_control_communities
defaulted on for rs-clients and collapsed update-group sharing —
caught by this campaign, fixed same-night (#976, follow-up filed);
(2) openbgpd runB-s2 attempt 1 established 700 sessions but moved
zero prefixes for 120 s (RDE wedge, did not recur on rerun).

## Remaining (in order)

1. **Campaign run A** (overnight, box exclusively quiet): for each
   daemon × scenario S1/S2/S3 —
   `N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4 bash bench/scale/matrix/run-matrix.sh`
   (S1 = convergence phase of the same runs; S3 = harness
   `--flapstorm 50` mode; delete per-cell `status` files between
   distinct scenarios or point `ARTIFACTS` elsewhere per scenario).
2. **Campaign run B**: independent repetition, fresh daemon starts,
   same order — run-to-run spread goes in the receipt.
3. **S4 stretch** (export-only 600/700 split) for whichever incumbents
   survive per-peer filter generation without config explosion.
4. **Receipt write-up**: `docs/perf/ixp-matrix-2026-07.md` — one table
   per scenario with all three columns published (including losses),
   honesty-notes checklist (single host, loopback, config disclosure,
   daemon-side clocks advisory-only, per-daemon reload-semantic
   asymmetries), reproduction section; commit raw artifacts under
   `docs/perf/artifacts/ixp-matrix-2026-07/`; cross-link from
   `docs/RECEIPTS.md` and `docs/COMPARISON.md`.

## Run hygiene (learned the hard way)

Regenerate scenarios before every run (the harness overwrites the live
policy file); resolve daemon PIDs by exact comm name, not
`pgrep | head`; `pkill -x` only; wait for the listener before starting
stubs; nothing else on the box during timed cells.
