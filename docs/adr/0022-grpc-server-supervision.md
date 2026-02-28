# ADR-0022: gRPC server supervision — unexpected exit triggers shutdown

**Status:** Accepted
**Date:** 2026-02-28

## Context

The gRPC server was spawned as a detached `tokio::spawn` task. If it exited
unexpectedly (bind failure, panic, tonic internal error), the daemon would
continue running without its control plane — all 5 gRPC services silently
unavailable. This is inappropriate for an API-first daemon where the gRPC
API is the primary management interface.

Options considered:

1. **Restart the gRPC server on failure** — adds complexity (backoff,
   port rebind, state recovery). The gRPC server is stateless except for
   channel handles, but rebinding to the same port may fail if the socket
   is in TIME_WAIT.

2. **Treat gRPC exit as a shutdown trigger** — simple, correct for an
   API-first daemon. If the API is down, operators have no way to manage
   the daemon, so it should exit cleanly so a process supervisor can
   restart the entire process.

3. **Log and continue** — not appropriate for the primary management
   interface. Acceptable for the metrics server (read-only, supplementary)
   but not for the gRPC control plane.

## Decision

Keep the gRPC `JoinHandle` and add it to the main shutdown `select!` loop
(option 2). An unexpected gRPC server exit triggers the same coordinated
shutdown sequence as ctrl-c or the Shutdown RPC.

```rust
tokio::select! {
    result = tokio::signal::ctrl_c() => { ... }
    _ = &mut rpc_shutdown_rx => { ... }
    result = &mut grpc_handle => {
        error!(?result, "gRPC server exited unexpectedly");
        info!("initiating shutdown due to gRPC server failure");
    }
}
```

The normal shutdown path (Shutdown RPC) still works because it fires
`rpc_shutdown_rx` before the gRPC server exits — the select branch for
`rpc_shutdown_rx` wins the race.

## Consequences

**Positive:**
- API-first invariant upheld — daemon without API exits cleanly.
- Process supervisor (systemd, container runtime) can restart the daemon.
- No additional dependencies or complexity.
- Normal shutdown paths unchanged.

**Negative:**
- A transient gRPC failure causes full daemon restart. This is acceptable
  because gRPC failures are not expected in normal operation, and a full
  restart is a clean recovery path.
- The metrics server remains unsupervised (fire-and-forget). This is
  intentional — the metrics endpoint is supplementary and read-only.
