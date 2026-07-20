# 1,000-peer route-server receipt

`run-receipt.sh` is the fixed-shape, rustbgpd-only evidence driver for
LAN-508. It does not compare daemons and makes no performance claim by itself.

The shape is deliberately not configurable:

- 1,000 real all-eBGP route-server clients, 400 routes each (400,000 total);
- every observer receives 399,600 routes (split horizon removes its own 400);
- four export-only policy swaps after a 30-second control window; and
- the harness's fixed 8 churners x 16 routes at 125 ms.

The driver refuses a dirty checkout, acquires the shared host lock, records the
exact commit and tree, builds the real daemon, CLI, and wire harness with
`--release --locked`, then repeats the idle-host check. Host admission is
bounded at 120 seconds and requires load below 2, all CPU governors set to
`performance`, no competing build/daemon/benchmark, no swap I/O over two
seconds, ports 1790/9179 free, at least 4,096 file descriptors, and at least 16
GiB `MemAvailable`. Lock contention exits 75.

Runtime gates are also fixed: cold convergence within 60 seconds, overall
completion within 600 seconds, daemon-tree RSS at most 2 GiB sampled each
second, and `/readyz` sampled every 100 ms with every response HTTP 200 in at
most 250 ms. Selected update-group and actor-poll metrics are scraped every
250 ms. The run is accepted only with four exact delivery rows, all sessions
up, no decode errors, one 1,000-member update group, no fallback peers, and at
least four `finalize` polls. An advertised-route explanation additionally
proves an actual prefix passes export policy through a non-null update group.

Run only on a quiet performance host, from the immutable commit to measure:

```text
bench/scale/route-server-1000/run-receipt.sh
```

Raw output is private and ignored under `target/route-server-1000/`. It includes
the preflight ledger, provenance, build logs and binary hashes, generated
scenario, daemon and harness logs, 100/250 ms probe streams, RSS, pre/post
metrics, advertised explanation, and checksums. Review and sanitize a bounded
subset before adding the separate evidence commit; never publish raw host or
path-bearing output.
