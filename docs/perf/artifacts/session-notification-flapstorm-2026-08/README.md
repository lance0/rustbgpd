# Session-notification flapstorm receipt

This one-host, one-run receipt exercised 700 sessions and 400,400 prefixes
across three rounds, closing and reconnecting 50 sessions per round. Initial
convergence excluded each observer's 572 owned prefixes and completed all
700 observers at exactly 399,828 prefixes. In every round all 650 survivors
completed the exact 28,600-prefix withdraw and reannounce targets; each round
ended at 700/700 sessions with zero parse errors. All ten checkpoints observed
the notification population drained to zero, with zero notification-send or
correctness errors. The daemon-lifetime cumulative high-water mark rose from
8 to 30 and did not decrease.

This receipt proves dequeue accounting only. Accounting is released when the
PeerManager dequeues a notification; handling occurs afterward. The
`session_notify` transport remains intentionally unbounded because collision
resolution performs synchronous `QueryState` work. The high-water value is a
daemon-lifetime cumulative observation, not a per-round peak, queue capacity,
latency or memory measurement, performance bound, or optimization claim.

The campaign ran at the pre-merge measurement commit
`cdc9966ffbca9a3f4902484e75c9bd703bdb1322` (tree
`51e56d5b1b19ee52fe6312cd89d4bef336f64ca8`). That branch commit is not an
ancestor of `main`; the reachable squash is
`9fc3286dcea4c8f1a5d371a782931a416e30a4b6`. The measured harness, scenario
generator, matrix runner, and lockfiles are byte-identical between those two
commits.

The run was captured at `2026-08-25T13:10:21Z` on an AMD Ryzen Threadripper
7970X 32-Core host running Linux 6.17.0-35-generic, rustc 1.98.0, and Cargo
1.98.0. This equivalent reproduction command normalizes `ARTIFACTS_DIR` to a
fresh generic path; the output-directory name is not measurement-relevant:

```sh
N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=0 CONTROL_SECS=30 FLAPSTORM=50 \
  ARTIFACTS_DIR=/tmp/session-notification-flapstorm-run \
  RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR=127.0.0.1:9179 \
  bash bench/scale/matrix/run-matrix.sh rustbgpd
```

`initial.csv` records exact initial convergence, `checkpoints.csv` records the
ten drained notification-accounting boundaries, and `flapstorm.csv` records
the three withdraw/reannounce rounds. `summary.json` preserves the
publication-time scan of the raw daemon and harness logs; those raw logs are
not retained. It also records campaign status, revision, and capture time.
