# RFC 9324 local re-evaluation A/B: compact evidence (2026-10-13)

These files are the evidence for the
[RFC 9324 local re-evaluation A/B](../../rpki-local-revalidation-2026-10-13.md).
All 12 cells are retained. `python3 recompute.py` rebuilds the inputs the
summarizer reads from the extracts below and re-runs `summarize.py`. It
requires the output to equal `summary.txt` and the per-cell rows to equal
`cells.json`, and exits non-zero on any difference. Changing one retained
reject count in a daemon event, one in-window readiness status, or one
delta-peak reading makes it fail.

| Path | Contents |
|---|---|
| `cells/<arm>-n<N>-rep<r>/cell.env` | Arm, `local_revalidation` value, delta size, idle and injection timestamps with daemon CPU ticks, and the harness and daemon exit codes |
| `cells/*/caches-{before,after}.json` | `rbgp --json rpki caches` before and after the delta: same RTR session, serial advanced by one, unchanged VRP counts |
| `cells/*/neighbors-{before,after}.tsv` | Address, state, flap count and received and sent prefix counts for all 700 members, extracted from `rbgp --json neighbor` |
| `cells/*/daemon-events.jsonl` | Every post-injection daemon log event the summarizer reads: RTR incremental and full-table updates, the RIB's RPKI re-validation, the refresh pass (A), the local re-evaluation pass (B) and B's 700 per-session `RFC 9324 local import re-evaluation queued` events with their `retained` and `retained_rejects` fields. The rest of the daemon log is not retained |
| `cells/*/refresh-counter-{before,after}.prom` | The `bgp_validation_import_refreshes_total` lines from the before and after metrics scrapes |
| `cells/*/cgroup-{pre,post}.txt` | The daemon scope's steady `memory.current` after convergence, its `memory.peak` before injection, `memory.swap.max`, and the final current, lifetime peak and swap peak |
| `cells/*/cg-delta-peak.txt` | The scope's `memory.peak` from the start of the 10 s idle window to 60 s after injection, read before the view capture |
| `cells/*/cg-hold-peak.txt` | The same peak through the view capture and the rest of the hold |
| `cells/*/poll.tsv` | Daemon CPU ticks, summed received-UPDATE counter and scope `memory.current`, every 0.25 s |
| `cells/*/readyz.tsv` | `/readyz` status and latency, every 0.25 s |
| `cells/*/views.tsv`, `view-peers.txt` | Member-view digests (`rbgp rib advertised`, two members × two families) and the two members chosen |
| `cells/*/reloadstall.log` | Harness output, including one `route_refresh_accounting` row per member and family that received a ROUTE-REFRESH |
| `cells/*/stayrtr.log` | The RTR cache's log: the file change, the computed diff and the serial |
| `cells/*/vmhwm`, `vrp-gate.log` | The daemon's final `VmHWM` and `VmRSS`; the VRP count the daemon reported before the harness started |
| `cells/*/quiet.tsv` | The two accepted quiet-host samples taken before the cell |
| `schedule.txt` | The cell order |
| `summary.txt` | The summarizer's output |
| `cells.json` | The per-cell rows the summarizer wrote, less one field: a Python `hash()` of the prefix counts, which differs from process to process |
| `fixtures/share.json` | The VRP snapshot and RouteViews RIB sources and hashes, the measured Valid, Invalid and NotFound shares, per-peer Invalid shares, and the shares assigned to the scenario |
| `fixtures/import-rejected.txt` | The 1,574 Invalid route indexes, as `family index` |
| `fixtures/delta-*.counts`, `fixtures/SHA256SUMS` | Withdrawal and announcement counts for each delta, and the hashes of every fixture file |
| `real-fixture.py` | The fixture generator |
| `reloadstall-import-rejected.patch` | The local harness patch that excludes Invalid routes from each observer's convergence target |
| `job.sh`, `job.log` | The job that ran the cells, and its timeline |
| `poll.py`, `viewdigest.py` | The CPU, UPDATE-counter, memory and readiness poller, and the member-view digest |
| `summarize.py` | The summarizer, with the validity rules and bars B1–B4 |
| `provenance.txt` | Source commit and tree, toolchain, binary, script and fixture hashes, the VRP snapshot, the shares, the RTR cache image, CPU placement and the shape |
| `recompute.py` | Rebuilds the summarizer's inputs from the extracts and checks its output |

The published scripts and text files differ from those that ran only in
local paths and internal run labels. Paths are replaced with `<prep-dir>`,
`<worktree>`, `<out-dir>`, `<queue-dir>`, `<queue-lock>` and
`<route-views2-rib>`, and labels are reworded. `real-fixture.py` also takes
its hash-order seed from a `SEED` placeholder; the indexes it chose are in
`fixtures/import-rejected.txt`. `provenance.txt` lists the hashes of the
scripts as they ran.

Not retained: the binaries, the 36 MB VRP fixtures (`fixtures/SHA256SUMS` has
their hashes), the source VRP and RIB archives (`fixtures/share.json` has
their URLs and hashes), full daemon logs, full metrics scrapes, the full
neighbor JSON and the generated configurations.
