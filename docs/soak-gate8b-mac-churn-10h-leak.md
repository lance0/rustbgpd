# Gate 8b MAC-churn 10h soak — postmortem (MAC-mobility leak, DF-flip axis)

One-page record of a ~10-hour Gate 8b MAC-churn soak confirming the
EVPN attribute-intern table stays bounded under sustained bridge-FDB
churn plus RFC 7432 §15.1 MAC mobility across repeated DF flips, on
v0.45.0 HEAD. This complements the M67 link-drain receipt
(2026-06-28, [`docs/soak-m67-link-drain-24h-evpn-leak.md`](soak-m67-link-drain-24h-evpn-leak.md))
with the DF-flip + MAC-mobility-sequencing angle, and the M33
50k-route scale receipt run the same night. Stopped at ~10h on a
conclusive-flat signal — a leak-confirmation receipt.

## What this soak exercised

The harness (`tests/soak/run-gate8b-mac-churn-soak.sh`) drives the
2-PE shared-ESI topology (`tests/soak/gate8b-soak.clab.yml`). It
sustains bounded rotating-MAC FDB churn (batches of 16 every 5 s over
a 512-MAC pool, 25% of batches moving MACs between PEs) while flipping
the DF role every 600 s by SIGTERM-restarting `pe2`. Each MAC move
re-originates a Type 2 route with an incremented mobility sequence — a
fresh attribute set per move — exercising the intern-GC path under
churn. `pe1` stays up for the whole run (the clean leak signal);
`pe2` restarts on each flip.

## Run metadata

| Field | Value |
|---|---|
| Started | `2026-07-01T01:44:34Z` |
| Runtime | ~10.1 h (591 samples @ 60 s), stopped on conclusive-flat signal |
| Build `git_rev` | `c273118e` (v0.45.0 HEAD; the run manifest's `dirty` flag reflects untracked run-dir artifacts only — the binary is the c273118e image) |
| Kernel | `6.8.0-117-generic` |
| Topology | `tests/soak/gate8b-soak.clab.yml` |
| Flip interval | 600 s (SIGTERM-restart `pe2`) |
| Churn | batch 16 / 5 s, 512-MAC pool, 25% mobility |
| Sample interval | 60 s |

## Results

### RSS — flat on the always-up PE (the headline)

| node | steady-state slope | peak |
|---|---|---|
| `pe1` (always up) | **0.125 MB/h** | 34.9 MB |
| `pe2` (restarts each flip) | 0.148 MB/h | 33.5 MB |

- `pe1` is the leak signal (never restarts): slope **0.125 MB/h**,
  ~12× under the 1.5 MB/h cap and ~2 200× below the pre-fix
  +279 MB/h. RSS settled ~30 → ~35 MB in the first ~2h, then held
  flat.
- `pe2` sawtooths (fresh process each flip) and never trends up
  across restarts — no cross-flip accumulation.

### Churn + failover — all healthy

- ~59 DF flip cycles; `pe2` re-established after every flip (harness
  gate: fail if not re-established within 300 s — never fired).
- Churn: 26 560 FDB deletes + 26 048 MAC moves; adds plateaued at the
  256/PE pool target, as designed.
- ADR-0059 aliasing-ECMP drift-repair counters: 0 (no drift churn).
- 0 WARN / 0 FATAL / no topology-link loss in the driver log.

### Analyzer verdict

`analyze-gate8b-soak.py` → **`verdict: pass`**. pe1/pe2 memory slopes
0.125 / 0.148 MB/h (cap 1.5 MB/h), peaks 34.9 / 33.5 MB (cap 512 MB).

## Conclusion

**PASS.** The intern-GC path stays bounded under MAC-mobility churn
and repeated DF flips on v0.45.0 HEAD, adding the DF-flip +
mobility-sequencing axis to the M67 link-drain and M33 route-scale
receipts of the same fix.

## Raw data

Tracked here so the postmortem stays self-contained when the soak host
is recycled (`tests/soak/runs/` stays off-repo):

- [`artifacts/soak/gate8b-mac-churn-20260701T014434Z/samples.csv`](artifacts/soak/gate8b-mac-churn-20260701T014434Z/samples.csv)
- [`artifacts/soak/gate8b-mac-churn-20260701T014434Z/soak.log`](artifacts/soak/gate8b-mac-churn-20260701T014434Z/soak.log)
- [`artifacts/soak/gate8b-mac-churn-20260701T014434Z/flips.log`](artifacts/soak/gate8b-mac-churn-20260701T014434Z/flips.log)
- [`artifacts/soak/gate8b-mac-churn-20260701T014434Z/report.json`](artifacts/soak/gate8b-mac-churn-20260701T014434Z/report.json)
- [`artifacts/soak/gate8b-mac-churn-20260701T014434Z/run.json`](artifacts/soak/gate8b-mac-churn-20260701T014434Z/run.json)

The raw per-batch churn log stays off-repo (bulky); churn totals are
in `samples.csv`.

## Cross-references

- [`docs/soak-m67-link-drain-24h-evpn-leak.md`](soak-m67-link-drain-24h-evpn-leak.md) —
  the link-drain axis of the same fix.
- [`docs/soak-m33-evpn-scale-10h-leak.md`](soak-m33-evpn-scale-10h-leak.md) —
  the 50k-route scale axis, run the same night.
- [`docs/soak-gate8b-mac-churn-1h.md`](soak-gate8b-mac-churn-1h.md) —
  the 1h dry-run template.
- `tests/soak/run-gate8b-mac-churn-soak.sh` /
  `tests/soak/analyze-gate8b-soak.py` — harness + gate analyzer.
