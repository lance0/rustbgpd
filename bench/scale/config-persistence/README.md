# config-persistence

Config persistence, history, rollback, and commit-confirm integration receipt.

## What it proves

`run-receipt.sh` deploys a writable config the way the quick-start now does —
a template copied into the daemon's own state volume — starts a real rustbgpd,
dials it with three real BGP stub sessions (real OPEN/KEEPALIVE/UPDATE,
encoded and decoded by `crates/wire`), and answers five questions:

1. **Persistence and restart recovery.** Does a mutation reach disk, the
   runtime, and the history, and is it still there after a restart?
2. **History and rollback.** Does history record each applied generation, and
   does `config rollback` restore a prior one in the runtime as well as on
   disk?
3. **Commit-confirm.** Does a confirmed transaction stick, an unconfirmed one
   auto-revert on its deadline, and a daemon SIGKILLed *inside* the
   confirmation window come back in a defined state rather than a torn one?
4. **Injected persistence rejection.** With the config directory sealed to
   `0o500`, does a refused mutation leave runtime config, session identity,
   flap state, cumulative counters, metric series, and wire state
   **unchanged** — not restored, unchanged?
5. **Agreement.** After each successful mutation, do the persisted file, the
   runtime snapshot, and the newest history record agree?

It is a behavior receipt, not a timing one. There is no host-quiescence
preflight and no performance number is published from it.

The shape is fixed, not configurable, so a published row cannot describe a
different run than the driver performed:

| stub | role |
|---|---|
| `127.9.2.1` | route source (originates the table) |
| `127.9.2.2` | subject — the session a rejected mutation must leave untouched |
| `127.9.2.3` | bystander — an unrelated session that must also be undisturbed |

- 6 IPv4 unicast `/24`s and 3 IPv6 unicast `/64`s, originated by the source.
  The table is small on purpose: this receipt measures config-plane behavior,
  and the routes exist only so the sessions carry wire history a rejected
  mutation could disturb.
- Six further neighbors (`127.9.2.11`..`127.9.2.16`) are added, rolled back,
  confirmed, timed out, killed mid-window, and refused. None is ever dialed.

Phase order is deliberate: everything needing the original, never interrupted
sessions runs **before** the first restart, so a restart-path failure cannot
silently weaken the rejected-mutation evidence.

The bystander is the non-vacuity sentinel for the rejection phase, and the
`uptime_seconds` / `messages_*` / `updates_sent` preconditions are the
non-vacuity sentinel for "untouched": at uptime 0 with no messages exchanged,
an untouched session and a freshly rebuilt one are indistinguishable.

## Backs

[`docs/perf/config-persistence-2026-07.md`](../../../docs/perf/config-persistence-2026-07.md).

## Build and run

The harness is a standalone crate (its own empty `[workspace]` table), not a
root-workspace member. CI compiles, formats, lints, and tests it explicitly;
the full run is not on the PR critical path.

```text
cd bench/scale/config-persistence && cargo build --release
```

The driver takes no arguments, refuses a dirty checkout, refuses to run as
root (uid 0 ignores the `0o500` seal, which would make the whole rejection
phase vacuous), and owns the deployment (build, template emission, the
template-to-writable copy, `rustbgpd --check`, the measured run, log gates,
teardown):

```text
bench/scale/config-persistence/run-receipt.sh
```

It binds BGP on `127.0.0.1:17910` and Prometheus on `127.0.0.1:19189`, and
keeps the deployment (config directory, runtime state directory, and the gRPC
socket) under a short `/tmp` path because `sockaddr_un.sun_path` cannot hold a
deep checkout path.

Unlike the sibling receipts, the **harness** owns the daemon process rather
than the shell: three of the five areas only exist across a restart.

Raw output is private and ignored under `target/config-persistence/`:
provenance, binary hashes, the config template, one log per daemon generation,
per-phase history/effective-config/Prometheus captures, the subject's before
and after neighbor JSON, `summary.json`, and checksums. Never publish
path-bearing raw output; the receipt document carries the sanitized rows.

## Arg contract (harness binary)

The driver supplies these; they are not a stable interface:

```text
configpersist <daemon_bin> <rbgp_bin> <config_path> <state_dir> \
    <bgp_port> <metrics_addr> <out_dir>
```

Every assertion prints one `CHECK <name> <PASS|FAIL> <detail>` line. Exit 0 =
all checks passed, 1 = at least one failed, 2 = the run could not be performed
(session, tooling, or a fatal convergence failure). Phase gates after cold
convergence are non-fatal: one failure must not hide the rest of the picture.
