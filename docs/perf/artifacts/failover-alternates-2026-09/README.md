# Failover alternates cell artifacts

These files retain every run behind the [failover alternates receipt](../../failover-alternates-2026-09.md).

- [`rounds.csv`](rounds.csv): one row per flap round (cell, arm, run, round): alternate prefixes and sources, daemon CPU-seconds over the down pass, `distribute_flush` sum and count over the same window, withdraw-phase completion p50/max and re-announce completion p50/max.
- [`runs.csv`](runs.csv): per run, the mean and median of the three rounds' CPU-seconds and completion p50, the daemon's mixed-pass path counts, and harness/daemon exit codes.
- [`logs.tar.gz`](logs.tar.gz): per run, the complete harness output (`reloadstall.log`), the daemon's `bench: grouped mixed pass fanout paths` lines (`daemon-mixed-passes.jsonl`), and every daemon WARN/ERROR line (`daemon-warnings.jsonl`). Full daemon logs (about 6.7 MB each) are not published; their remaining lines are session establishment and INFO records.
- [`background-check.csv`](background-check.csv): one supplementary run per arm at F=0.75, k=16 with the later harness, which also records each CPU window's wall length and a churn-only daemon CPU rate sampled over 2 s before the close. Its harness output, mixed-pass lines and warnings are in `logs.tar.gz` under `background-check/`.
- [`host.json`](host.json): host and CPU placement.

The overlap allocations are omitted because `gen-failover-overlap.py` regenerates them exactly from the recorded arguments. Warnings are the daemon's expected active dials to the stubs' unreachable port 179 (`TCP connect failed`), writer failures on the flapped sessions, one startup RFC 8212 notice per run, zero to two `outbound channel full or closed during initial dump` dirty marks and zero to three deferred End-of-RIB notices per run from initial-table dumps (at startup or a flapped member's reconnect), and one `marking dirty for resync` at teardown after the last round of `p75-k1/main/run1`.

To inspect:

```bash
tar -xzf logs.tar.gz
grep -h '^flapstorm_failover_csv,' failover-alternates-2026-09/p75-k16/*/run*/reloadstall.log
```
