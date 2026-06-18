# Gate 8b MAC-churn 1h dry-run soak — raw artifacts

Frozen snapshot of the five load-bearing files from the dry run that
landed [`docs/soak-gate8b-mac-churn-1h.md`](../../../soak-gate8b-mac-churn-1h.md).
This run validated the process-restart flip mechanism and churn harness
before the 24-hour production-default gate.

| File | Bytes | Lines | What it is |
|---|---:|---:|---|
| `run.json` | 672 | 22 | Harness manifest: start time, git rev, image SHA, kernel, cadence, MAC pool, and topology path. |
| `samples.csv` | 9,136 | 57 | One row per ~60 s sample after warmup: RSS, DF state, BGP state, FDB/NHG counters, origination counters, and churn counters. |
| `flips.log` | 251 | 5 | Timestamped PE2 process-stop/start events emitted by the harness driver. |
| `churn.log` | 342,866 | 5,847 | Per-cycle MAC add/delete/move records from the bounded churn pool. |
| `soak.log` | 1,491 | 20 | Driver log: run banner, gate progress, and completion record. |

The original run directory lived at
`tests/soak/runs/gate8b-mac-churn-20260515T192034Z/` (gitignored).
This checked-in copy is what the dry-run postmortem cites.
