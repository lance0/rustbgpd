# Security Posture

## gRPC API

rustbgpd exposes a gRPC API for daemon control and route management.
**There is no built-in authentication, authorization, or TLS.**

### Default configuration

The default bind address is `127.0.0.1:50051` (loopback only). In this
configuration, only processes on the local machine can reach the API.
This is safe for single-host deployments.

### Non-loopback deployments

When `grpc_addr` is set to a non-loopback address (e.g., `0.0.0.0:50051`),
**all RPCs are accessible without authentication**, including privileged
control-plane operations:

- `Shutdown` — stops the daemon
- `AddNeighbor` / `DeleteNeighbor` — modifies the peer table
- `EnableNeighbor` / `DisableNeighbor` — controls session state
- `AddPath` / `DeletePath` — injects or withdraws routes

The daemon logs a warning at startup when bound to a non-loopback address.

**Recommendations for non-loopback deployments:**

- Use an mTLS termination proxy (e.g., Envoy, nginx) in front of the
  gRPC port
- Restrict access at the network level (firewall rules, security groups)
- Bind to a management-only interface rather than `0.0.0.0`

### Read-only endpoints

`GetGlobal`, `ListNeighbors`, `GetNeighborState`, `ListReceivedRoutes`,
`ListBestRoutes`, `ListAdvertisedRoutes`, `WatchRoutes`, `GetHealth`,
and `GetMetrics` are read-only but also unauthenticated.

## Metrics endpoint

The Prometheus `/metrics` HTTP endpoint (configured via `prometheus_addr`;
commonly `0.0.0.0:9179`) is
read-only and unauthenticated. It exposes operational counters and gauges
but no secrets. The same loopback-vs-non-loopback considerations apply.

## TCP MD5 and GTSM

Per-neighbor TCP MD5 authentication (RFC 2385) and GTSM / TTL security
(RFC 5082) are supported on Linux via `md5_password` and `ttl_security`
configuration fields. These are applied at the socket level before the
TCP handshake.

## Intentional gaps

- **No built-in TLS for gRPC** — use a proxy or sidecar for TLS termination
- **No TCP-AO** (RFC 5925) — deferred to post-v1
- **No config persistence** — gRPC mutations are not written back to TOML
- **No RPKI validation** — deferred to post-v1
