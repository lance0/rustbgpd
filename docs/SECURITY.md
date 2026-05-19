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
- `access_mode` is still a listener-level boundary, not per-client RBAC. The
  method-risk inventory in `docs/grpc-method-inventory.md` and
  `crates/api/src/authz.rs` is the ADR-0064 foundation for future
  per-method tiers (`read`, `sensitive_read`, `mutating`,
  `operator_only`). The runtime now emits audit-only `grpc_authz`
  decision logs and `bgp_grpc_authz_decisions_total`, but current
  enforcement is still the read-only/read-write listener split. The
  external-review packet in `docs/adr/0064-threat-model.md` summarizes
  the trust boundaries, abuse paths, evidence checklist, and residual
  risks for that migration.
- `[security.grpc.roles]` and listener `principal` labels can be staged now so
  audit records use stable operator-controlled identities on bearer-token TCP
  and UDS listeners. These roles are configuration-only until ADR-0064
  deny-by-tier enforcement lands.
- Peer-group read RPCs redact `md5_password` rather than echoing stored
  secret material; they expose only the non-secret `has_md5_password`
  presence flag. The write path preserves an omitted redacted MD5 value by
  default; clearing requires an explicit `has_md5_password=false`. Treat the
  remaining peer-group template, policy, and topology data as sensitive
  operational metadata.
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

## TCP-AO

TCP-AO (RFC 5925) is the intended successor to TCP MD5. rustbgpd now has
an internal Linux socket primitive and capability probe for TCP-AO
(ADR-0062), plus static-neighbor `tcp_ao` TOML parsing/validation and startup
runtime installation. Outbound active-open sockets install the key before
`connect()`, and the passive BGP listener installs configured peer keys before
`listen()`. Listener key-install failures abort startup rather than running a
partially protected listener; active-open key-install failures fail the
connection attempt and retry later without falling back to unauthenticated TCP.
Runtime deletion of configured TCP-AO neighbors is rejected because listener
MKTs are installed on the startup listener socket and are not deleted yet.
Static-neighbor protected interop is validated by M43 against BIRD 3.2.1:
matching keys establish and import a route, while a mismatched key withdraws
the route and does not re-establish within the fail-closed window. The
protected `kernel-dataplane` workflow includes M43 and runs it on kernels that
advertise `CONFIG_TCP_AO=y`; runners without TCP-AO support skip that topology
with a warning.
Dynamic-neighbor TCP-AO, runtime key rotation, multi-key rollover, and richer
accepted-socket inspection remain deferred.

## Linux EVPN VTEP — `CAP_NET_ADMIN` requirement

Running rustbgpd in **EVPN VTEP mode** on Linux (a non-empty
`[[evpn_instances]]` or `[[evpn_ip_vrfs]]` configuration) requires the
daemon to hold `CAP_NET_ADMIN` (or run as root) for the kernel-facing
operations the EVPN reconciler issues:

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
3. **IP-VRF / L3 VXLAN link + route dumps + multicast**
   (Gate 9 slice 6, ADR-0058 — v0.18.0). When `[[evpn_ip_vrfs]]`
   is non-empty, the reconcile actor issues `RTM_GETLINK` to
   populate the IP-VRF readiness probe and `RTM_GETROUTE` per
   IP-VRF `table_id` for the slice 6a kernel-route observer.
   The notify task additionally subscribes to
   `RTNLGRP_IPV4_ROUTE` + `RTNLGRP_IPV6_ROUTE` for sub-second
   tenant `ip addr del` withdraw. Slice 6 PR B mutates kernel
   state: `RTM_NEWROUTE` / `RTM_DELROUTE` to program L3 FIB
   entries inside the IP-VRF's `table_id`, plus `RTM_NEWNEIGH` /
   `RTM_DELNEIGH` and bridge FDB ops for the L3 neighbor +
   L3VXLAN FDB rows that resolve the remote Router MAC.
4. **FDB nexthop group programming** (ADR-0059, slices 1-4 on
   `main`). When a multi-homed Type 2 lands, the reconcile actor
   constructs an FDB nexthop group via the `nexthop_raw`
   raw-netlink primitive (`rtnetlink 0.21` exposes no nexthop
   API) and points an FDB row at it via `NDA_NH_ID`. Requires
   `CAP_NET_ADMIN` for the nexthop add/del + FDB write paths,
   plus a Linux kernel ≥ 5.8 for `NDA_NH_ID` support. The
   apply layer refuses to install on a VXLAN device with
   `learning on` per CVE-2025-39851's mainline fix.

If `CAP_NET_ADMIN` is not granted:

- `LinuxDataplane::connect()` may succeed but FDB program ops fail
  with `EPERM`/`EACCES` → `DataplaneError::PermissionDenied`. The
  reconcile actor's permanent-failure suppression then logs the
  failure and stops retrying that op.
- The notify task logs `could not subscribe to RTNLGRP_NEIGH;
  local-MAC observations will be silent` at WARN. Downward
  programming may still work; upward origination won't fire.

**RR-only deployments** (both `[[evpn_instances]]` and
`[[evpn_ip_vrfs]]` empty) need none of this — no netlink socket is
opened, no background reconciler or originator is spawned, and the
daemon runs at the same privilege level as a pure control-plane
speaker.

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

- ADR-0064 runtime enforcement for the checked gRPC method-tier matrix
  (`read`, `sensitive_read`, `mutating`, `operator_only`). Audit-only
  method-tier decision logs, metrics, staged principal/role config, and
  the `docs/adr/0064-threat-model.md` audit packet are present; mTLS
  certificate principal extraction, listener tier caps, deny-by-tier
  enforcement, and audit-log hardening remain deferred.
- TCP-AO (RFC 5925) dynamic-neighbor support, runtime key rotation,
  multi-key rollover, and accepted-socket inspection for BGP session
  protection

## Current gaps

- Authorization is still listener-wide at runtime (`read_only` vs
  `read_write`). ADR-0064 classifies every RPC and emits audit-only
  runtime decisions. Explicit non-mTLS listener principals and
  `[security.grpc.roles]` can be configured for audit identity, but
  per-RPC / per-role enforcement is not active yet.
- TCP-AO currently supports static-neighbor startup keys only; dynamic
  neighbors, live key rotation, and multi-key rollover remain follow-up work.
  Protected static-neighbor interop is covered by M43 against BIRD 3.2.1 on
  Linux with `CONFIG_TCP_AO=y`.
- Cert rotation on the gRPC TLS listener requires a daemon restart (not SIGHUP)
