# RPKI validation-refresh baseline compact artifacts (2026-10-03)

These files are the evidence for the
[RPKI validation-refresh baseline](../../rpki-validation-refresh-baseline-2026-10.md).
`python3 recompute.py` re-runs every per-cell validity check, rebuilds each
cell's row, requires the rows to equal `cells.json`, and checks the receipt's
medians and member-burden counts. It exits non-zero on any mismatch.

| Path | Contents |
|---|---|
| `cells/n{10,100,1000}-rep{1,2}/cell.env` | Cell parameters, idle and injection timestamps with daemon CPU ticks, the daemon-log line count before injection, and the harness and daemon exit codes |
| `cells/*/caches-{before,after}.json` | `rbgp --json rpki caches` before and after the delta: same RTR session, serial advanced by one, unchanged VRP counts |
| `cells/*/neighbors-{before,after}.tsv` | Address, state and flap count for all 700 members, extracted from `rbgp --json neighbor` |
| `cells/*/daemon-events.jsonl` | Every post-injection daemon log event for an RTR incremental update, an RTR full table, the RIB's RPKI re-validation and the validation-cache import refresh pass. The rest of the daemon log is not retained |
| `cells/*/refresh-counter-{before,after}.prom` | The `bgp_validation_import_refreshes_total` lines from the before and after metrics scrapes |
| `cells/*/poll.tsv` | Daemon CPU ticks and summed received-UPDATE counter, every 0.25 s |
| `cells/*/readyz.tsv` | `/readyz` status and latency, every 0.25 s |
| `cells/*/reloadstall.log` | Harness output, including one `route_refresh_accounting` row per member and family |
| `cells/*/stayrtr.log` | The RTR cache's log: the file change, the computed diff and the serial |
| `cells/*/quiet.tsv` | The two accepted quiet-host samples taken before the cell |
| `cells.json` | The per-cell rows the job's analysis wrote on 2026-10-03 |
| `fixtures/delta-*.counts` | Withdrawal and announcement counts per family for each delta fixture |
| `job.sh` | The job that built the binaries, generated the fixtures, ran the cells and wrote `cells.json`. Local paths are replaced with `<repo>`, `<worktree>`, `<queue-dir>`, `<queue-lock>` and `<out-dir>` |
| `job.log` | The job's timeline, with the same path replacements |
| `poll.py` | The CPU, UPDATE-counter and readiness poller |
| `provenance.json` | Source commit, toolchain, binary and fixture hashes, RTR cache image, shape, CPU placement and cell order |
| `recompute.py` | Recomputes and checks everything above |

Not retained: the binaries, the 35 MB VRP fixtures (regenerate them with
`bench/scale/rpki-cell/rpki_cell.py vrps` and `maxlen-delta` at the source
commit; `provenance.json` has their hashes), full daemon logs, full metrics
scrapes and the full neighbor JSON.
