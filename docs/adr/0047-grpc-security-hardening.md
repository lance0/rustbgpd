# ADR-0047: gRPC Security Hardening

- **Status:** Accepted
- **Date:** 2026-03-06

## Context

The gRPC management API exposes privileged operations: peer lifecycle, route
injection, soft reset, MRT triggers, and daemon shutdown. Before this change,
the daemon defaulted to a loopback TCP listener (`127.0.0.1:50051`), which
is reachable by any process on the host regardless of user identity. This is
a weak default for a daemon that controls routing state.

Operators deploying in containers, multi-tenant hosts, or orchestrated
environments need stronger isolation without requiring an external proxy for
local-only access.

## Decision

### UDS-first default

When neither `[global.telemetry.grpc_tcp]` nor `[global.telemetry.grpc_uds]`
is present in the config, the daemon creates a Unix domain socket at
`<runtime_state_dir>/grpc.sock` with mode `0600`. This gives the OS a concrete
user/group permission boundary that loopback TCP cannot provide.

### TCP is opt-in

TCP gRPC listeners require an explicit `[global.telemetry.grpc_tcp]` config
block with `address`. Non-loopback TCP addresses produce a startup warning;
non-loopback TCP without bearer auth produces a stronger warning.

### Per-listener bearer-token auth

Each listener (UDS or TCP) can independently configure a `token_file` pointing
to a file containing a bearer token. The daemon reads the token at startup and
validates it on every RPC via an `AuthInterceptor` using constant-time
comparison. Tokens are not rotatable without a daemon restart.

### Multi-listener support

UDS and TCP listeners can run concurrently. Each gets its own interceptor
instance, so auth policies are independent per listener. A `JoinSet` supervises
all listeners; if any exits unexpectedly, all are shut down.

### CLI alignment

`rustbgpctl` defaults to `unix:///var/lib/rustbgpd/grpc.sock` and supports
`--token-file` / `RUSTBGPD_TOKEN_FILE` for bearer auth injection.

## Alternatives considered

### Native in-daemon mTLS

Would provide encryption and mutual authentication without a sidecar. Deferred
because: (1) certificate lifecycle management is complex, (2) most production
deployments already have a proxy/sidecar story, (3) UDS + bearer auth covers
the local and simple-remote cases well. Tracked in the roadmap.

### Single listener with TLS optional

Simpler config surface, but forces operators to choose between local UDS
convenience and remote TCP access. Multi-listener lets both coexist.

### Token rotation via SIGHUP

Re-reading token files on SIGHUP would allow rotation without restart. Deferred
because the current SIGHUP handler is scoped to neighbor reconciliation, and
token rotation is a low-frequency operation. Can be added later without breaking
changes.

## Consequences

- **Breaking change:** configs using `grpc_addr` must migrate to the new
  `grpc_tcp`/`grpc_uds` model.
- **Token files must exist at config-load time.** `validate_grpc_token_file()`
  reads the file during validation. Orchestrated deployments where secrets
  mount after config load must ensure the token file is available before the
  daemon starts.
- **UDS socket path must live in a daemon-owned directory.** The daemon removes
  stale sockets at bind time and cleans up on shutdown. Non-socket files at
  the path are refused at bind but may be removed during cleanup if they appear
  after shutdown.
- **No token rotation without restart.** Acceptable for initial release; tracked
  as a future improvement.

## References

- [SECURITY.md](../SECURITY.md) — deployment tiers and firewall guidance
- [CONFIGURATION.md](../CONFIGURATION.md) — `grpc_tcp`/`grpc_uds` reference
- [`examples/envoy-mtls/`](../../examples/envoy-mtls/) — mTLS sidecar example
