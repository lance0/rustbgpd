# Gate 8b MAC-churn 24h soak — raw artifacts

Frozen snapshot of the five load-bearing files from the run that
landed [`docs/soak-gate8b-mac-churn-24h.md`](../../../soak-gate8b-mac-churn-24h.md).
This is the 24-hour MAC-churn evidence that, together with the M37
local-origination soak, gated the EVPN production-default flip.

| File | Bytes | Lines | What it is |
|---|---:|---:|---|
| `run.json` | 673 | 22 | Harness manifest: start time, git rev, image SHA, kernel, cadence, MAC pool, and topology path. |
| `samples.csv` | 220,082 | 1,391 | One row per ~60 s sample after warmup: RSS, DF state, BGP state, FDB/NHG counters, origination counters, and churn counters. |
| `flips.log` | 6,817 | 139 | Timestamped PE2 process-stop/start events emitted by the harness driver. |
| `churn.log` | 8,487,742 | 144,697 | Per-cycle MAC add/delete/move records from the bounded churn pool. |
| `soak.log` | 14,897 | 221 | Driver log: run banner, cycle bookkeeping, and completion record. |

The original run directory lived at
`tests/soak/runs/gate8b-mac-churn-20260515T214043Z/` (gitignored).
This checked-in copy is what the 24-hour postmortem cites.
