# Security Posture

> For the end-to-end install + lifecycle walkthrough (systemd setup,
> Docker, containerlab quick-start), see [`deployment.md`](deployment.md).

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
  `rbgp`, `grpcurl`, or SSH.
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
- `access_mode` is a listener-level boundary; per-client RBAC is layered on top
  via the ADR-0064 per-method tiers (`read`, `sensitive_read`, `mutating`,
  `operator_only`) catalogued in `docs/grpc-method-inventory.md` and
  `crates/api/src/authz.rs`. The runtime emits `grpc_authz` decision logs and
  `bgp_grpc_authz_decisions_total`; listener `max_tier` caps are enforced, and
  `security.grpc.enforcement = "tier"` (the default since v0.24.0) enforces
  per-principal role ceilings. The external-review packet in
  `docs/adr/0064-threat-model.md` summarizes the trust boundaries, abuse paths,
  evidence checklist, and residual risks for that surface.
- `[security.grpc.roles]` and listener `principal` labels can be staged now so
  audit records use stable operator-controlled identities on bearer-token TCP
  and UDS listeners. Native mTLS listeners derive audit principals from the
  client certificate (`rustbgpd:` URI SAN, then email SAN, then Subject CN);
  unsafe or overlong cert values fall back to `mtls-unresolved` rather than
  entering structured logs verbatim.
  In legacy mode these roles are audit context only; in tier mode they
  authorize or deny calls by method tier.
- Listener `max_tier` caps are enforced now and should be used to bound remote
  TCP listeners to the smallest required method tier. `access_mode =
  "read_only"` remains a compatibility ceiling equivalent to
  `sensitive_read`.
- gRPC `grpc_authz` audit records are result-aware for forwarded calls and use
  bounded result labels such as `handler_ok`, `handler_invalid_argument`, and
  `listener_tier_denied`. Credential-bearing request summaries are masked:
  `DiffRuntimeConfigRequest.candidate_toml`,
  `PlanConfigTransactionRequest.candidate_toml`, and
  `ApplyConfigTransactionRequest.candidate_toml` are never logged verbatim, and
  `SetPeerGroup` records only MD5 state (`set_redacted`, `preserve`, or
  `clear`) rather than secret material. TCP-AO keys embedded in candidate TOML
  are covered by the same `candidate_toml=<redacted>` summary; transaction
  apply comments are recorded only as present/absent.
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

> **Listener shape is restart-required; credential bytes rotate live.** SIGHUP
> atomically reloads token and mTLS material behind unchanged configured paths.
> Existing TLS connections and admitted streams continue; new TLS connections
> and new bearer-authenticated RPCs use the new generation. Path, listener,
> auth-mode, principal, role, and access changes still require restart.

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

## Metrics and probe endpoint

The telemetry HTTP endpoint is read-only and unauthenticated. `/metrics`
exposes operational detail, `/readyz` exposes only core actor readiness, and
`/livez` exposes only process liveness. Apply the same
loopback-vs-management-network discipline to `prometheus_addr` that you apply
to gRPC.

## Looking glass adapter

The in-daemon looking glass HTTP server has been removed. The
birdwatcher-compatible REST surface is served by the external
`examples/birdwatcher-adapter` binary over the daemon's gRPC API. The
adapter is read-only and unauthenticated: it exposes neighbor state,
received routes, and peer addresses, so apply the same network-level
access controls as Prometheus.

## TCP MD5 and GTSM

Per-neighbor TCP MD5 authentication (RFC 2385) and GTSM / TTL security
(RFC 5082) are supported on Linux via `md5_password` and `ttl_security`.
These protect BGP transport sessions, not the gRPC management surface.

## TCP-AO

TCP-AO (RFC 5925) is the intended successor to TCP MD5. rustbgpd has an
internal Linux socket primitive and capability probe for TCP-AO (ADR-0062),
plus static-neighbor and direct dynamic-range `tcp_ao` TOML
parsing/validation and startup runtime installation. A selector may configure
an ordered keyring of one to 256 MKTs; the legacy singleton table remains
compatible. Outbound active-open sockets install the selected key before
`connect()` and then install every remaining key. The passive BGP listener
installs every configured peer key before `listen()`. Listener key-install
failures abort startup rather than running a partially protected listener;
active-open key-install failures fail the connection attempt and retry later
without falling back to unauthenticated TCP.
Runtime deletion of configured TCP-AO neighbors is rejected because listener
MKTs are installed on the startup listener socket and are not deleted yet.
Static-neighbor protected interop is validated by M43 against BIRD 3.3.1:
matching keys establish and import a route, a nonpreferred successor is added
with SIGHUP without flapping the session, and a mismatched preferred key
withdraws the route and does not re-establish within the fail-closed window. The
hosted `kernel-dataplane` workflow includes M43, and the current hosted
runner advertises `CONFIG_TCP_AO=y` and runs the topology. The workflow keeps a
warning-only skip guard for future runner kernels without TCP-AO support.
Dynamic prefix MKTs are installed before `listen()` without setting the
listener-wide `ao_required` bit. Protected accepted sockets are discarded
unless `TCP_AO_INFO` and `TCP_AO_GET_KEYS` confirm valid selection state, clean
authentication counters, and the complete configured keyring. Kernel-returned
MKT material is compared only inside zeroizing transport-local buffers and is
never logged or exported. Protected-owner CRUD and non-additive keyring reloads
remain restart-gated. Neighbor API/CLI queries refresh read-only TCP-AO KeyIDs,
redacted MKT inventory, and cumulative verification counters from the live
connected socket without exposing key material. Ordered keyrings are
supported. Static exact owners take precedence over dynamic longest-prefix
matches; accepted sockets must expose the owned union of all covering protected
selectors, while current and RNext selection must belong to the resolved owner.
If a child completed before an add-only listener flip, only the exact
immediately previous inventory may be reconciled forward; arbitrary subsets,
partial successor inventories, and older generations remain fail-closed.
The hosted queued-child receipt uses a dynamic `127.0.0.0/24` owner and proves
its successor is reconciled onto the accepted child with logical owner metadata,
unchanged Current/RNext, and authenticated traffic. Transport-owned TCP-AO key
and TCP-MD5 password allocations are redacted and zeroized when each runtime
clone is replaced or dropped. This does not claim erasure of the TOML parser,
configuration snapshots, API messages, kernel MKTs, allocator copies, or other
process memory outside the transport-owned allocations.
Overlapping TCP-AO owners require directionally disjoint SendID and RecvID sets;
TCP-AO/plaintext and TCP-AO/MD5 overlaps are rejected. Config validation and
transport binding enforce the same 4,096-MKT inspection ceiling independently
for each listener address family, preventing a valid configuration from
exceeding the fail-closed inspection path. SIGHUP can append a globally
preflighted non-preferred successor generation without changing Current/RNext;
selection, deprecation, deletion, protected-owner CRUD, and metrics exposure of
per-socket inspection remain deferred.

## Shutdown warm-checkpoint confidentiality

The optional shutdown warm checkpoint contains pre-policy Adj-RIB-In routing
data, peer identity, and digests of the effective configuration and resolved
import policies. Treat `<runtime_state_dir>/warm-bundle-v1` as sensitive
control-plane state: keep `runtime_state_dir` on local trusted storage, owned by
the daemon account, and do not expose or back it up as a public MRT feed.

Publication is descriptor-relative beneath an owner-verified directory that is
not group/world-writable. Bundle files are owner-only, symlink traversal is
rejected, content is size-bounded and hashed, and `manifest.json` is the atomic
commit point. A descriptor-relative post-commit sweep removes only canonical
superseded snapshot names and recognizable atomic temporary names; it preserves
the manifest's exact current snapshot and ignores unknown entries. Cleanup
failure is logged without invalidating the committed generation. Startup does
not load the checkpoint, so a stale or tampered
bundle cannot currently inject, select, install, or advertise a route. The GR
marker carries only an opaque checkpoint generation plus restart-deadline clock
metadata. Marker v3 includes the kernel boot ID and time-namespace
device/inode/offset, which can fingerprint a host or container clock domain;
keep it under the same owner-private `runtime_state_dir` protections. It never
contains key material, routes, or configuration. Checkpoint publication
failure retains a generationless restart marker, while unavailable clock
metadata degrades to a complete wall-only marker rather than publishing a
partial clock identity.

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

Or under systemd, install the shipped drop-in
[`examples/systemd/rustbgpd-dataplane.conf`](../examples/systemd/rustbgpd-dataplane.conf)
on top of the unprivileged base unit (see
[deployment.md](deployment.md#kernel-dataplane-opt-in-privilege-drop-in)):

```ini
[Service]
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
```

This privilege scope is the minimum required for Linux EVPN VTEP
mode; do not grant `CAP_NET_RAW` or `CAP_SYS_ADMIN` — neither is
needed by rustbgpd.

## Deferred hardening

The following security improvements are intentionally deferred and tracked in
the roadmap:

- A separate in-daemon durable audit sink for `grpc_authz` records (file /
  syslog with defined backpressure and failure semantics). The ADR-0064
  per-method tier matrix itself is fully enforced —
  `enforcement = "tier"` is the **default since v0.24.0**, with runtime
  decision logs/metrics, listener tier caps, mTLS certificate principal
  extraction (URI SAN → email SAN → Subject CN), per-principal role
  enforcement, and result-aware audit records with masked credential-bearing
  request summaries. Structured-log audit collection, retention, query
  examples, and resource-abuse guardrails are documented in
  [`docs/OPERATIONS.md`](OPERATIONS.md#grpc-authorization-audit-and-resource-guardrails);
  only the durable in-daemon sink remains deferred until file/syslog
  backpressure and failure semantics are designed.
- TCP-AO (RFC 5925) live key selection/deprecation/deletion and per-socket
  metrics for BGP session protection

## Current gaps

- Authorization defaults to per-principal tier enforcement
  (`security.grpc.enforcement = "tier"`, default since v0.24.0) layered on
  listener `access_mode` (`read_only` vs `read_write`) and `max_tier` caps.
  `enforcement = "legacy"` remains a supported opt-out. Configs that rely on the
  implicit UDS listener must declare `[global.telemetry.grpc_uds]` with a
  `principal` to run under tier enforcement.
- Per-principal request-rate and stream-count budgets are not implemented in
  the daemon. Use listener tier caps, role enforcement, management-network
  controls, client deadlines, and the documented `grpc_authz` / stream metrics
  to detect or constrain accepted-client abuse in v1.
- TCP-AO supports ordered static-neighbor and direct dynamic-prefix keyrings,
  plus add-only non-preferred successor installation on SIGHUP. Selection,
  deprecation, deletion, edits/reordering, and protected-owner CRUD require a
  restart.
  Protected static-neighbor interop is covered by M43 against BIRD 3.3.1 on
  Linux with `CONFIG_TCP_AO=y`.
- gRPC token and mTLS material behind unchanged paths rotate on SIGHUP as one
  all-listener generation. Alert on
  `bgp_grpc_credential_reloads_total{outcome="failure"}`; failures retain the
  last-known-good generation and logs never include secret bytes.
