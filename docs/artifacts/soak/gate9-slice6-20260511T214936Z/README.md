# Gate 9 slice 6 24h symmetric IRB soak — raw artifacts

Frozen snapshot of the four load-bearing files from the run that
landed [`docs/soaks/soak-gate9-slice6-24h-symmetric-irb.md`](../../../soaks/soak-gate9-slice6-24h-symmetric-irb.md).

| File | Bytes | What it is |
|---|---|---|
| `run.json` | ~614 | Harness manifest: start time, git rev, image SHA, kernel, soak hours, sample / churn cadence, warmup. |
| `samples.csv` | ~59 KB | One row per ~60 s sample: `ts_unix, elapsed_sec, pe1_rss_mb, pe2_rss_mb, pe1_installed_routes, pe1_observed_routes, bgp_established, tenant_present, churn_cycles`. 1407 rows after the 120 s warmup. |
| `churn.log` | ~83 KB | Timestamped `ip addr add` / `ip addr del` events emitted by the harness driver. 1407 lines = 703 full cycles + the trailing `del`. |
| `soak.log` | ~85 KB | Driver log: warmup banner, churn-cycle bookkeeping, completion record. Zero `error` / `warn` / `panic` / `fail` lines. |

The original run directory lived on the cloudbox at
`tests/soak/runs/gate9-slice6-20260511T214936Z/` (gitignored). This
checked-in copy is what the postmortem cites.

`pe1.log` was 0 bytes on cloudbox (rustbgpd's tracing output didn't
route there in this harness revision — see postmortem follow-up
#4). Not mirrored.
