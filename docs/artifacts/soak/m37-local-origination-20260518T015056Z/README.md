# M37 local-origination MAC-churn 24h soak — raw artifacts

Frozen snapshot of the repo-suitable files from the run that landed
[`docs/soak-m37-local-origination-churn-24h.md`](../../../soak-m37-local-origination-churn-24h.md).
The large `churn.log` and `rustbgpd.log` stayed local to the soak host
and are intentionally not checked in.

| File | Bytes | Lines | What it is |
|---|---:|---:|---|
| `run.json` | 425 | 14 | Harness manifest: run id, git head, duration, cadence, MAC pool, containers, and topology path. |
| `samples.csv` | 131,314 | 1,438 | One row per ~60 s sample: rustbgpd RSS, local FDB count, FRR Type 2 count, BGP state, churn totals, origination counters, observation drops, and duplicate-MAC moves. |
| `consumer.log` | 3,185 | 35 | FRR consumer log excerpt captured by the harness. |
| `soak.log` | 902 | 12 | Driver log: run banner, completion record, and postmortem reminder. |

The original run directory lived at
`tests/soak/runs/m37-local-origination-20260518T015056Z/` (gitignored).
This checked-in copy is what the 24-hour postmortem cites.
