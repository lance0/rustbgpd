# outbound-prefix-limits

ADR-0113 outbound unicast prefix-maximum integration receipt.

## What it proves

`run-receipt.sh` starts a real rustbgpd and dials it with four real BGP stub
sessions (real OPEN/KEEPALIVE/UPDATE, encoded and decoded by `crates/wire`),
then answers one question: **do the configured outbound maxima actually bound
what leaves the encoder, on the shared update-group path as well as the
private one?**

It is a behavior receipt, not a timing one. There is no host-quiescence
preflight and no performance number is published from it.

The shape is fixed, not configurable, so a published row cannot describe a
different run than the driver performed:

| peer | role | maxima | distribution path |
|---|---|---|---|
| `127.9.0.1` | route source (originates the table) | -- | grouped |
| `127.9.0.2` | peer-group member, **inherits** both maxima | peer group | grouped |
| `127.9.0.3` | unlimited sibling in the same update group | -- | grouped |
| `127.9.0.4` | RFC 7947 per-client-best peer | neighbor | private |

- 12 IPv4 unicast `/24`s and 6 IPv6 unicast `/64`s, originated by the source.
- Starting maxima 8 IPv4 / 4 IPv6, so 4 IPv4 and 2 IPv6 prefixes must be
  withheld from both limited peers.
- Add-Path is not negotiated on any session. Add-Path *send* disqualifies
  update-group membership, so one session cannot exercise both the grouped
  fanout and RFC 7911 slot sharing; the latter stays a unit-level contract.

`127.9.0.3` is the non-vacuity sentinel: until the unlimited sibling holds all
18 prefixes, "the capped peer only received 8" would be indistinguishable from
"only 8 were ever distributed".

Phases: converge, assert the caps on the wire, SIGHUP a lowering below current
usage (must be rejected whole with wire state intact), SIGHUP a raise (the
withheld prefixes must arrive without touching the sibling).

## Backs

[`docs/perf/outbound-prefix-limits-2026-07.md`](../../../docs/perf/outbound-prefix-limits-2026-07.md).

## Build and run

The harness is a standalone crate (its own empty `[workspace]` table), not a
root-workspace member. CI compiles, formats, lints, and tests it explicitly.

```text
cd bench/scale/outbound-prefix-limits && cargo build --release
```

The driver takes no arguments, refuses a dirty checkout, and owns the whole
lifecycle (build, config generation, `rustbgpd --check`, daemon start, the
measured run, log gates, teardown):

```text
bench/scale/outbound-prefix-limits/run-receipt.sh
```

It binds BGP on `127.0.0.1:17900` and Prometheus on `127.0.0.1:19179`, and
keeps runtime state (the gRPC socket included) under a short `/tmp` path
because `sockaddr_un.sun_path` cannot hold a deep checkout path.

Raw output is private and ignored under `target/outbound-prefix-limits/`:
provenance, binary hashes, the three generated config generations, the daemon
log, per-phase Prometheus scrapes, `rbgp` neighbor / advertised-route /
update-group-comparison output, `summary.json`, and checksums. Never publish
path-bearing raw output; the receipt document carries the sanitized rows.

## Arg contract (harness binary)

The driver supplies these; they are not a stable interface:

```text
outboundlimits <daemon_port> <daemon_pid> <rbgp_bin> <grpc_addr> \
    <metrics_addr> <config_live> <config_lower> <config_raise> <out_dir>
```

Every assertion prints one `CHECK <name> <PASS|FAIL> <detail>` line. Exit 0 =
all checks passed, 1 = at least one failed, 2 = the run could not be performed
(session, tooling, or a fatal convergence failure). Phase gates after cold
convergence are non-fatal: one failure must not hide the rest of the picture.
