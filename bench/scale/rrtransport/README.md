# rrtransport

`rrtransport smoke` is a fixed-shape correctness harness for the real
route-reflector transport path. It starts a production `RibManager`, two
production transport sessions over TCP loopback, and the existing
`rustbgpd-evpn-load` peer handshake/decoder. Four synthetic ingress sources
inject exactly 100 unique IPv4 `/24` routes through `RibUpdate::RoutesReceived`.
Each target listener remains bound while its actual ephemeral address is given
to rustbgpd, then that exact socket is transferred into the peer handshake.

The smoke preloads the RIB before registering either target session, then
asserts one shared update group, exact staged Adj-RIB-Out counts, and exact
wire-side initial-dump prefix sets through each IPv4 End-of-RIB. It prints one
stable JSON receipt and a human summary. It is deliberately not a benchmark:
the shape is fixed and it makes no latency, throughput, RSS, or competitor
claim.

Run from the repository root:

```text
cargo run --manifest-path bench/scale/rrtransport/Cargo.toml --locked -- smoke
```

## Fixed scale instrument

`rrtransport rr1000 <output-dir>` is the measurement-only real-transport
instrument. Its shape is intentionally not configurable: 1,000 uniform
IPv4-unicast iBGP route-reflector clients, 100,000 distinct `/24` routes from
four sources, and a 12-worker Tokio runtime. Every listener is retained through
accept. All sessions establish against an empty RIB and drain exactly one empty
initial EoR before T0. The receipt reports injection-finished, exact staged
Adj-RIB-Out convergence, and exact decoded wire convergence separately.

Wire classification retains one expected table and a 100,000-bit bitmap per
client. It rejects missing or outside prefixes, duplicates, withdrawals,
decode failures, incomplete sessions, and more than one update group. It counts
decoded NLRI, not UPDATE messages. One aggregate 120-second deadline covers
setup, convergence, validation, and shutdown.

Wire completion is explicitly `first_exact_bitmap`: a peer completes when its
bitmap first covers the fixed expected prefix set with exact decoded-NLRI
cardinality. Duplicate, withdrawal, outside-set, decode-failure, and message
counters describe input observed through that boundary only. The instrument
does not claim a trailing quiet period, writer flush, refresh pass, teardown
marker, or absence of later UPDATEs.

Run the three-attempt campaign only through:

```text
bench/scale/rrtransport/run-receipt.sh /absolute/output/outside/the/repository
```

The runner requires 4,096 file descriptors, 16 GiB available RAM, performance
CPU governors, a quiet host, no competing BGP daemon, and a clean source tree.
It owns a host lock, enforces a 2 GiB whole-process RSS ceiling, a 300-second
per-run guard, and a 20-minute campaign guard.

Before starting the supervised target, the runner executes an explicitly
untimed grouped-commit correctness leg through the production RIB seam and
transport-session encoder. Its schema-2 receipt separates the one-dispatch
65000:100 seed from a fast wire-visible RPOL transition to 65000:200. The
transition records its native shared plan, exact probes, route-shell
materialization, and zero authoritative per-peer fallback. Concrete transport
snapshots plus common group-token and announce-vector identities prove the
shared envelope path. The full-shape leg runs once and its immutable receipt is
copied into each attempt.

Each measured target records direct-PID `VmRSS`/`VmHWM` and jemalloc allocated,
active, resident, and mapped bytes at established, staged, and wire
checkpoints. The runner's process-tree target sampler remains separately named
and reported. Receipts also retain per-peer evidence, logs, source/binary
provenance, verifier output, and checksums. Results are not comparable to the
historical unavailable scratch harness and must not be published as an A/B.

CI never runs the scale shape. It runs the original smoke, a 4×100 real-TCP
fixture through the same scale collector/verifier/RSS seams, and destructive
parser/mechanics fixtures.
