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

## Remaining (in order)

1. **BIRD threads spot-check** (~30 min): one 200 × 115k BIRD cell
   with `threads` uncapped vs the default 8 in
   `gen-bird-scenario.py`; keep whichever is faster and record the
   choice in the receipt's config-disclosure section.
2. **Campaign run A** (overnight, box exclusively quiet): for each
   daemon × scenario S1/S2/S3 —
   `N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4 bash bench/scale/matrix/run-matrix.sh`
   (S1 = convergence phase of the same runs; S3 = harness
   `--flapstorm 50` mode; delete per-cell `status` files between
   distinct scenarios or point `ARTIFACTS` elsewhere per scenario).
3. **Campaign run B**: independent repetition, fresh daemon starts,
   same order — run-to-run spread goes in the receipt.
4. **S4 stretch** (export-only 600/700 split) for whichever incumbents
   survive per-peer filter generation without config explosion.
5. **Receipt write-up**: `docs/perf/ixp-matrix-2026-07.md` — one table
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
