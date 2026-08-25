# LAN-1162 session-notification flapstorm receipt

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

`receipt.json` pins source, binary, environment, workload, host, and raw-root
provenance. `SHA256SUMS` seals the seven compact artifacts. The independent
verifier derives the compact CSV files from the retained raw harness log and
scans the raw daemon and harness logs before accepting the receipt.

The retained raw root is `/tmp/lan1162-b2-20260825T1305Z`: 10 files totaling
57,264,495 bytes, sealed by directory digest
`fdf81db0f657838a83df899a85f4ff94c9689b09f9135a6781ffe5fb946d0885`.
The exact campaign and verification commands are:

```sh
N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=0 CONTROL_SECS=30 FLAPSTORM=50 \
  ARTIFACTS_DIR=/tmp/lan1162-b2-20260825T1305Z \
  RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR=127.0.0.1:9179 \
  bash bench/scale/matrix/run-matrix.sh rustbgpd
python3 bench/scale/reloadstall/verify_session_notification_receipt.py \
  docs/perf/artifacts/lan-1162-session-notification-flapstorm
```
