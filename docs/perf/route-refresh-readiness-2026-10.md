# Route-refresh replay readiness A/B — 2026-10-10

A daemon-level A/B of #3038, which serves readiness probes during a
ROUTE-REFRESH replay. It used the converged-rejoin cell: 700 route-server
peers, 400,400 IPv4 prefixes, one peer flapped per round under graceful-restart
helper, three rounds per cell. Measured on 2026-10-10 from 08:57 to 09:20 UTC
and published retroactively the same day from the retained cell data.

| Arm | Cells passing the harness | Readiness misses | Replay actor time, back-to-back refresh gap |
|---|---|---|---|
| base (`85224b2e4`) | 1 of 4 | 3 | 211–227 ms (cell medians 215–223) |
| fix (#3038) | 4 of 4 | 0 | 231–246 ms (cell medians 237–243) |

**What the A/B shows.** On base, a full-table replay holds the RIB actor for
about as long as the 200 ms readiness deadline. Three of four base cells
logged exactly one `readiness probe failed: RIB manager probe timed out
(200ms deadline)`. At that point the harness's `/readyz` sample returned
non-200 and the cell failed. With the fix, no cell missed a probe.

**What it costs.** Each replay took about 20 ms (~9%) longer, because the
replay's existing per-element checkpoints now run inside the readiness owner.

## Setup

- **Arms.** Base is `85224b2e4102682c186f4aa83e7d0b17a0a8e2e4`. The fix arm is
  #3038's working tree on that base. It was built about six minutes before
  being committed as `0a56c75cb` (merged as `1d0e4e155`), so its binary is
  identified by SHA-256 only, not by a commit hash. Both daemons were built with
  `cargo build --release --locked -p rustbgpd --bin rustbgpd`. The hashes are
  in [`provenance.json`](artifacts/route-refresh-readiness-2026-10/provenance.json).
- **Instrument.** Both arms used one `reloadstall` and one scenario generator,
  both from `591ac39d4`: `GEN_CONVERGED_REJOIN=1`, then
  `reloadstall 700 400400 … 0 30 --flapstorm 1 --flap-rounds 3 --converged-rejoin`.
  The per-cell procedure is [`cell.sh`](artifacts/route-refresh-readiness-2026-10/cell.sh).
  Each cell started a fresh daemon, pinned to CPUs 12–32 and 34–39, with the
  harness on 40–63.
- **Host.** One AMD Ryzen Threadripper 7970X Linux host. Every cell held the
  shared host lock and passed the canonical quiet-host gate.
- **Order.** The arms were partly interleaved: fix, fix, base, fix, base, fix,
  base, base.
- **Replay time.** The two surviving observers request a refresh back to back
  in every round. The gap between their `handling route refresh request` log
  events is the RIB actor time of one family replay. Gaps of 0.5 s or more are
  not back-to-back pairs and are excluded.

## Results

- **Harness verdicts.** The failing base cells exited with
  `FAIL: converged rejoin: metrics HTTP status is not 200`. base-k1-rep1 and
  base-k1-rep3 failed in round 1 before writing any row. base-k1-rep4 failed
  after round 1.
- **Readiness misses.** Each failing base cell has exactly one daemon
  readiness failure, and every passing cell has none
  ([`daemon-events.csv`](artifacts/route-refresh-readiness-2026-10/daemon-events.csv)).
- **Unchanged.**
  - Survivor maximum inter-UPDATE gap: 118.5–126.6 ms across all 16 completed
    rounds in both arms.
  - Harness rejoin time: about 0.145 s or about 0.18 s in both arms (bimodal).

## What this does not establish

- **No bound under other loads.** It shows no readiness bound for other
  table sizes, for many concurrent refreshes, or for replays of other
  families.
- **No measurement of coalescing.** Coalescing concurrent refreshes is
  separate work.
- **No release result.** At n = 4 cells per arm, it shows the failure and its
  removal on this shape. It is not a miss-rate estimate.
- **No in-crate figures.** #3038's description also reports an in-crate
  replay measurement. That came from a scratch test that is not in the
  repository, so it is not part of this receipt.

## Evidence

[`artifacts/route-refresh-readiness-2026-10/`](artifacts/route-refresh-readiness-2026-10/README.md)
holds each cell's `reloadstall.log`, quiet-host samples and exit codes, the
refresh and readiness events extracted from each daemon log, the cell script
and `provenance.json`. `python3 recompute.py` reproduces every number above.
