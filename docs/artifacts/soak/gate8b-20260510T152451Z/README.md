# Gate 8b 24h BUM-state soak — raw artifacts

Frozen snapshot of the four load-bearing files from the run that
landed [`docs/soak-gate8b-24h-bum-state.md`](../../../soak-gate8b-24h-bum-state.md).

| File | Bytes | What it is |
|---|---|---|
| `run.json` | ~504 | Harness manifest: start time, git rev, kernel, soak hours, sample / flip cadence. |
| `samples.csv` | ~80 KB | One row per minute: `ts_unix, elapsed_sec, pe1_rss_mb, pe2_rss_mb, pe1_df_role, pe2_df_role, pe1_df_changes, pe2_df_changes, pe1_bum_flags, pe2_bum_flags, pe2_running`. 1422 rows after the 120s warm-up. |
| `flips.log` | ~5.1 KB | Timestamped PE2 stop/start events emitted by the harness driver. 142 lines = 71 complete cycles. |
| `soak.log` | ~6.5 KB | Driver log: cycle bookkeeping, completion record. |

The original run directory lived on the cloudbox at
`tests/soak/runs/gate8b-20260510T152451Z/` (gitignored). This
checked-in copy is what the postmortem cites.
