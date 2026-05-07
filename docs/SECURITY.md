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

- Configure native mTLS on the daemon's gRPC TCP listener. Set
  `tls_cert_file`, `tls_key_file`, and `tls_client_ca_file` on
  `[global.telemetry.grpc_tcp]` — all three are required together; a
  partial config is rejected at `Config::load`. The daemon presents
  the server certificate, requires every client to present a
  certificate signed by `tls_client_ca_file`, and rejects unverified
  clients at the TLS layer before any gRPC handler runs. There is
  no "TLS-without-mTLS" half-mode by design. PEM material is
  pre-flight-validated at load and `--check` time so a successful
  `--check` rules out cert-rotation surprises at startup.
- For multi-host fan-out, off-host TLS termination, or richer
  authorization fan-out, an Envoy / nginx mTLS sidecar in front of
  the daemon is still a valid pattern; see
  [`examples/envoy-mtls/`](../examples/envoy-mtls/) for a reference
  config. The native path is the default recommendation; the proxy
  path is the multi-tenant / multi-host fallback.
- If you need to expose monitoring directly, prefer a dedicated
  `access_mode = "read_only"` listener over exposing the mutating control
  surface.
- Restrict the exposed listener to a management VLAN/interface or a small set
  of management hosts.
- Even with mTLS in place, treat the API as privileged. Read-only RPCs still
  reveal peer topology, route state, and policy results.

> **Listener config is restart-required.** Adding, removing, or
> rotating `tls_cert_file` / `tls_key_file` / `tls_client_ca_file`
> takes effect only on a daemon restart, not on SIGHUP. SIGHUP
> reload pins the runtime listener config back to the live values
> and surfaces the drift in `rustbgpd --diff` until restart.

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
- `AddEvpnRoute` / `DeleteEvpnRoute`
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

## Linux EVPN VTEP — `CAP_NET_ADMIN` requirement

Running rustbgpd in **EVPN VTEP mode** on Linux (a non-empty
`[[evpn_instances]]` configuration) requires the daemon to hold
`CAP_NET_ADMIN` (or run as root) for two distinct kernel-facing
operations:

1. **Bridge FDB program / withdraw** (Gate 7b, ADR-0054 — v0.14.0).
   The `crates/evpn-linux` reconciler issues `RTM_NEWNEIGH` /
   `RTM_DELNEIGH` netlink messages to install remote-MAC entries
   into the kernel bridge FDB with `NTF_EXT_LEARNED`.
2. **`RTNLGRP_NEIGH` multicast subscription** (Gate 7b+1,
   ADR-0055 — v0.15.0). The originator's notify task calls
   `Socket::add_membership(RTNLGRP_NEIGH)` on the rtnetlink socket
   to receive unsolicited `RTM_NEWNEIGH` / `RTM_DELNEIGH` events
   for kernel-learned local MACs. This is a kernel-side privilege
   separate from gRPC management security.

If `CAP_NET_ADMIN` is not granted:

- `LinuxDataplane::connect()` may succeed but FDB program ops fail
  with `EPERM`/`EACCES` → `DataplaneError::PermissionDenied`. The
  reconcile actor's permanent-failure suppression then logs the
  failure and stops retrying that op.
- The notify task logs `could not subscribe to RTNLGRP_NEIGH;
  local-MAC observations will be silent` at WARN. Downward
  programming may still work; upward origination won't fire.

**RR-only deployments** (empty `[[evpn_instances]]`) need none of
this — no netlink socket is opened, no background reconciler or
originator is spawned, and the daemon runs at the same privilege
level as a pure control-plane speaker.

Recommended deployment posture for EVPN VTEPs:

```bash
# Grant the binary CAP_NET_ADMIN without running as root
setcap cap_net_admin=eip /usr/local/bin/rustbgpd
getcap /usr/local/bin/rustbgpd  # verify
```

Or under systemd:

```ini
[Service]
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true
```

This privilege scope is the minimum required for Linux EVPN VTEP
mode; do not grant `CAP_NET_RAW` or `CAP_SYS_ADMIN` — neither is
needed by rustbgpd.

## Deferred hardening

The following security improvements are intentionally deferred and tracked in
the roadmap:

- Finer-grained gRPC authorization beyond "listener allowed / denied"
- TCP-AO (RFC 5925) for BGP session protection (currently TCP MD5 and GTSM)

## Current gaps

- Authorization is listener-wide (`read_only` vs `read_write`), not per-RPC or
  per-role
- No TCP-AO (RFC 5925); TCP MD5 and GTSM are the supported session protections
- Cert rotation on the gRPC TLS listener requires a daemon restart (not SIGHUP)
