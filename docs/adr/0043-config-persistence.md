# ADR-0043: Config Persistence and SIGHUP Reload

**Status:** Accepted
**Date:** 2026-03-05

## Context

rustbgpd's original design treated the config file as boot-time-only: gRPC
owned runtime state, and changes made via `AddNeighbor`/`DeleteNeighbor` were
lost on restart. This forced operators to manually keep the config file in sync
with runtime state — a friction point that GoBGP avoids by persisting gRPC
mutations.

Additionally, operators need a way to apply config file changes without a full
restart. SIGHUP-based reload is the standard Unix convention for this.

## Decision

### Config persistence via `ConfigPersister`

A dedicated `ConfigPersister` tokio task receives `ConfigMutation` messages
via a bounded `mpsc` channel and writes them to the config file:

- **`ConfigMutation::AddNeighbor`** — appends a new `[[neighbors]]` block
- **`ConfigMutation::DeleteNeighbor`** — removes the matching neighbor block

Write strategy: **atomic write** (write to temp file in same directory, then
`rename()`). This prevents partial writes on crash or power loss.

### Fail-fast on persistence unavailability

`AddNeighbor` and `DeleteNeighbor` gRPC handlers reserve channel capacity
**before** mutating runtime state. If the persistence channel is full or
closed, the RPC fails with `INTERNAL` rather than applying an unpersisted
change. This prevents runtime/disk config divergence.

### SIGHUP reload

The main `select!` loop listens for `SIGHUP` via `tokio::signal::unix::signal()`:

1. Re-read and parse the TOML config file
2. `diff_neighbors()` computes the delta between running neighbors and file
   state (added, removed, changed)
3. `ReconcilePeers` command sent to `PeerManager` with per-peer add/delete
   operations
4. Global config changes (ASN, router_id, listen_port, etc.) are logged as
   warnings — they require a full restart to take effect

### Error handling

- Per-peer reconciliation failures are reported with structured logging
  (peer address, error reason)
- The previous in-memory config snapshot is preserved when reconciliation is
  incomplete
- Partial success is allowed: some peers may be added/removed while others
  fail

### What is NOT persisted

- `EnableNeighbor`/`DisableNeighbor` state (administrative up/down is
  transient)
- Policy changes (policies are config-file-only today)
- Global config changes via `SetGlobal`

## Consequences

### Positive

- Config file stays in sync with runtime state across restarts
- Operators can edit the config file and `SIGHUP` to apply changes
- Atomic writes prevent corruption on crash
- Fail-fast prevents silent runtime/disk divergence

### Negative

- Config file format must remain stable enough for programmatic modification
- SIGHUP reload cannot change global parameters (ASN, router_id, listen_port)
- Concurrent gRPC mutations and SIGHUP reloads could race (mitigated by
  PeerManager serialization)

### Neutral

- `ConfigPersister` is a single writer — no concurrent file access issues
- TOML serialization uses the same `serde` derives as deserialization
