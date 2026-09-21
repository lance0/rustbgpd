# Controller injection and attribute collection

> **Document class: HISTORICAL.** This dated receipt describes one controlled local workload, not a throughput guarantee.

Unary controller updates preserve route visibility and reconciliation while deferred
attribute collection avoids a global-table sweep for every replacement or deletion.

## Workload and measurement boundaries

The baseline used release source `4f8b1712274d2d52b07bc014446eced2ed53f2b5`,
one receive-only BGP client and a typed Python gRPC client with one outstanding unary
request. Fresh daemons received 100, 10,000 or 100,000 IPv4 `/24` routes. Each cell
inserted the whole table, replaced every route's community, then deleted the table.
Shared-attribute cells used one community per generation; distinct cells used a
different community per prefix. The measured intern-table gauges confirmed one
versus exactly 100,000 entries at the largest shape.

RPC phases had a 180-second cap and individual calls had five-second deadlines.
After each phase the receiver checked the complete prefix/community inventory,
and `ListReceivedRoutes` with neighbor `0.0.0.0` checked every local route through
version-fenced pagination. Acknowledgement latency is distinct from wire completion;
the artifacts preserve both. Successful deletion leaves no local or received routes.

The host has a 32-core/64-thread AMD Threadripper 7970X. The daemon was pinned to
CPUs 4–11 and the controller/receiver to CPUs 12–13, which are disjoint physical
cores on this host. Background documentation and IDE check jobs were allowed and
recorded; their affinity was not changed. These are **nonexclusive-host** results,
not isolated latency measurements. Daemon CPU time comes from `/proc/PID/stat` at
the host's 10 ms accounting resolution; the 100-route cells establish correctness
rather than reliable CPU timing.

## Baseline

Each cell passed insert, replacement and deletion reconciliation. Every phase
produced exactly one UPDATE per requested prefix at the client, including when
attributes were shared. The 100,000-route listings used 100 pages after insertion
and replacement; deletion returned an empty terminal page.

| Routes | Attributes | Insert wall / CPU (s) | Replace wall / CPU (s) | Delete wall / CPU (s) |
| --- | --- | ---: | ---: | ---: |
| 10,000 | Shared | 1.719 / 0.84 | 1.466 / 0.82 | 1.339 / 0.76 |
| 10,000 | Distinct | 1.650 / 0.77 | 1.572 / 0.90 | 1.405 / 0.77 |
| 100,000 | Shared | 15.264 / 8.44 | 14.832 / 7.93 | 13.453 / 7.42 |
| 100,000 | Distinct | 15.327 / 8.43 | 30.484 / 23.41 | 22.647 / 15.96 |

The distinct table did not materially increase insertion CPU, but replacement
used 15.48 additional CPU seconds and deletion used 8.54 additional CPU seconds.
The baseline controller handlers synchronously swept the entire global attribute
table after every replacement or successful withdrawal. Session-learned unicast
updates already shared a bounded deferred collector.

The existing actor-work histogram does not time the complete injection handler or
its immediate collection calls. Its zero baseline samples must not be read as zero
actor work. The CPU comparison and the controlled collector change establish the
performance result; no total-actor-time claim is made.

## Controlled collector comparison

Measurements ran on 2026-09-20–21 UTC. The corrected binary was built from
`fde0cf10ca220278b586ccb7a2ff64af9ec12f3e` plus the
[recorded runtime patch](artifacts/controller-injection-2026-09/runtime.patch).
The intervening base commit changes documentation and a versioned configuration
fixture test, not production behavior. Only the two controller collection seams
changed in production. The same measured Python driver, receiver, affinity,
configuration, deadlines and single-client shape were used for the comparison.

| 100,000-route cell | Insert wall / CPU (s) | Replace wall / CPU (s) | Delete wall / CPU (s) |
| --- | ---: | ---: | ---: |
| Corrected, shared attributes | 15.450 / 8.52 | 15.302 / 8.31 | 13.670 / 7.70 |
| Corrected, distinct attributes | 15.516 / 8.53 | 15.441 / 8.33 | 13.442 / 7.03 |

All six corrected phases passed, with exactly 100,000 UPDATEs per phase and
complete route/community reconciliation. Distinct-attribute replacement CPU
fell from 23.41 to 8.33 seconds (64.4%); deletion fell from 15.96 to 7.03 seconds
(56.0%). Their wall times fell from 30.484 to 15.441 seconds and 22.647 to
13.442 seconds. The shared-attribute control and distinct insertion remained
broadly comparable. These are single-cell observations with recorded background
work, not statistical latency estimates or a general throughput promise.

After distinct replacement the corrected intern gauge was 101,696. Immediately
after deletion it was 3,392 although both the local and wire route inventories
were zero. These retained entries remain below the shared 4,096-displacement
bound; idle deadline reclamation is proved by the paused-time actor regression.
The measured driver did not wait for this final timer, so this receipt does not
claim a live zero-intern observation after idle expiry.

## Decision and checks

The correction reuses the existing collector: large-table sweeps occur after
4,096 displaced routes or a one-second actor deadline. Small tables still collect
immediately. Route installation, withdrawal, per-prefix distribution and reply
ordering are unchanged. Interned attributes can remain until the bound even after
the final route is gone; the intern-table gauge reports retained entries honestly.

Three large-table regressions verify the displacement bound, immediate replacement
and withdrawal visibility, idle deadline reclamation, and unchanged missing-route
errors. Restoring the original two production calls makes all three tests fail;
the corrected attribute suite passes all 26 tests.

No new reconciliation API is needed: the existing local-peer listing worked
through all measured phases. UPDATE packing remains one prefix per unary request
in this workload. A batch or coalescing API is a separate decision, not a prerequisite
for fixing repeated global collection.

The [artifacts and reproduction driver](artifacts/controller-injection-2026-09/README.md)
retain source/binary provenance, metrics, wire counts and reconciliation results.
