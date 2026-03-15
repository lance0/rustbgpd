# Security Posture

rustbgpd exposes a privileged gRPC management API for peer lifecycle, route
injection, soft reset, MRT triggers, and daemon shutdown. Treat that surface as
part of your management plane, not as a general-purpose service endpoint.

Today the daemon defaults to a Unix domain socket at
`/var/lib/rustbgpd/grpc.sock`. That local-only default is the safe baseline.
If you enable TCP gRPC access, you are responsible for putting network and
transport controls in front of it.

## Recommended deployment tiers

### Same-host administration

Preferred posture:

- Use the default Unix domain socket (UDS) for local-only access.
  Filesystem permissions give the OS a concrete user/group boundary that
  loopback TCP does not.
- If you need TCP for local tooling or container networking, configure
  `[global.telemetry.grpc_tcp]` on `127.0.0.1:50051` and access it locally via
  `rustbgpctl`, `grpcurl`, or SSH.
- Optional bearer-token auth can be enabled per listener with `token_file`, but
  same-host UDS access is still the preferred local posture.
- For occasional remote administration, tunnel to the local listener or socket
  rather than exposing raw management TCP on a routed interface.

### Remote administration

Preferred posture:

- Keep rustbgpd itself bound to loopback or a local UDS.
- Put an mTLS proxy or sidecar in front of it for remote access. Envoy is the
  recommended reference path; see [`examples/envoy-mtls/`](../examples/envoy-mtls/).
- If you need to expose monitoring directly, prefer a dedicated
  `access_mode = "read_only"` listener over exposing the mutating control
  surface.
- Restrict the exposed listener to a management VLAN/interface or a small set
  of management hosts.
- Even behind a proxy, treat the API as privileged. Read-only RPCs still reveal
  peer topology, route state, and policy results.

### Direct TCP on a non-loopback address

This is the least-preferred posture.

When `[global.telemetry.grpc_tcp]` is configured on a non-loopback address (for
example `0.0.0.0:50051`), the entire gRPC surface becomes reachable on that
interface.
That includes privileged RPCs such as:

- `Shutdown`
- `AddNeighbor` / `DeleteNeighbor`
- `EnableNeighbor` / `DisableNeighbor`
- `SoftResetIn`
- `AddPath` / `DeletePath`
- `AddFlowSpec` / `DeleteFlowSpec`
- `TriggerMrtDump`

The daemon logs a warning at startup when a gRPC TCP listener is bound to a
non-loopback address. It logs a stronger warning when that listener is also
unauthenticated. Use that posture only on a deliberately isolated management
network, and prefer an mTLS proxy in front of it.

## Firewall guidance

If you do expose the management API on TCP, firewall it to known management
hosts. Examples below assume the daemon or proxy is listening on `:50051`.
Adjust the port if your proxy terminates on a different frontend port.

### `iptables`

```bash
# Allow only the management subnet to reach gRPC.
iptables -A INPUT -p tcp -s 198.51.100.0/24 --dport 50051 -j ACCEPT
iptables -A INPUT -p tcp --dport 50051 -j DROP
```

### `nftables`

```nft
table inet filter {
  chain input {
    type filter hook input priority 0;

    tcp dport 50051 ip saddr 198.51.100.0/24 accept
    tcp dport 50051 drop
  }
}
```

These examples are intentionally minimal. Fold them into your existing
stateful-policy baseline rather than pasting them in isolation.

## Metrics endpoint

The Prometheus `/metrics` HTTP endpoint is read-only and unauthenticated. It
does not expose secrets, but it does expose operational detail. Apply the same
loopback-vs-management-network discipline to `prometheus_addr` that you apply
to gRPC.

## Looking glass endpoint

The optional birdwatcher-compatible looking glass HTTP server
(`[global.telemetry.looking_glass]`) is read-only and unauthenticated. It
exposes neighbor state, received routes, and peer addresses. Apply the same
network-level access controls as Prometheus. If not needed, omit the config
section entirely — no HTTP server is started.

## TCP MD5 and GTSM

Per-neighbor TCP MD5 authentication (RFC 2385) and GTSM / TTL security
(RFC 5082) are supported on Linux via `md5_password` and `ttl_security`.
These protect BGP transport sessions, not the gRPC management surface.

## Deferred hardening

The following security improvements are intentionally deferred and tracked in
the roadmap:

- Native gRPC mTLS inside the daemon
- Finer-grained gRPC authorization beyond "listener allowed / denied"

## Current gaps

- No native TLS termination in the daemon today; use a proxy or sidecar for
  remote encrypted access
- Authorization is listener-wide (`read_only` vs `read_write`), not per-RPC or
  per-role
- No TCP-AO (RFC 5925); TCP MD5 and GTSM are the supported session protections
