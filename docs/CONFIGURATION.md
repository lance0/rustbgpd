# Configuration Reference

rustbgpd is configured via a single TOML file, passed as the first argument to the daemon:

```
rustbgpd /etc/rustbgpd/config.toml
```

The config file defines the initial boot state. At runtime, the gRPC API is the
source of truth -- peers can be added, removed, enabled, and disabled dynamically
without restarting the daemon. Neighbor add/delete mutations made via gRPC are
persisted back to the config file. Sending `SIGHUP` to the daemon triggers a
config reload with per-peer reconciliation. Starting with zero `[[neighbors]]` is valid when
all peers are managed via gRPC.

> **Reload behavior.** For a per-field table of which config keys hot-apply,
> which are restart-required, and which are rejected at parse time, see
> [`reload-matrix.md`](reload-matrix.md). This page documents *what* each
> field means; the matrix documents *when* a change takes effect.
>
> **Deploying it.** For the end-to-end install + lifecycle walkthrough
> (systemd setup, Docker, containerlab quick-start, upgrade, observability),
> see [`deployment.md`](deployment.md).

---

## `[global]`

Required. Defines the local BGP speaker identity.

| Field               | Type   | Required | Default              | Description                        |
|---------------------|--------|----------|----------------------|------------------------------------|
| `asn`               | u32    | yes      | --                   | Local autonomous system number     |
| `router_id`         | string | yes      | --                   | BGP router ID (must be valid IPv4) |
| `listen_port`       | u16    | yes      | --                   | TCP port to listen on (typically 179) |
| `dynamic_neighbor_limit` | u32 | no     | `100`                | Maximum number of auto-accepted dynamic peers (1--5000) |
| `worker_threads`    | usize  | no       | `min(cores, 8)`      | Tokio runtime worker threads. Unset caps to `min(CPU parallelism, 8)` to avoid over-provisioning the async runtime (one worker + stack reservation per core) on a high-core host for this I/O-bound daemon — reduces virtual-address reservation and scheduler footprint (RSS-neutral in benchmarks). `0` means unset. `RUSTBGPD_WORKER_THREADS` overrides. **Restart-required** (runtime built once at startup). |
| `runtime_state_dir` | string | no       | `"/var/lib/rustbgpd"` | Directory for daemon-owned runtime state (GR restart marker today) |
| `cluster_id`        | string | no       | --                    | Route reflector cluster ID (must be valid IPv4; enables RR mode) |
| `honor_graceful_shutdown` | bool | no  | `false`              | Enable RFC 8326 §4 receiver behavior on EBGP imports — see below |
| `honor_blackhole`   | bool   | no       | `false`              | Enable RFC 7999 receiver scoping on EBGP imports — see below |
| `install_blackhole_discard` | bool | no | `false`              | Install kernel blackhole routes for accepted RFC 7999 host routes — see below |
| `allow_blackhole_broad_prefixes` | bool | no | `false`           | Permit non-host BLACKHOLE discard installs when the FIB slice is enabled |
| `apply_bum_enforcement` | bool | no   | `true` (since v0.23.0) | Apply Gate 8b BUM-suppression filters to the kernel per-port `IFLA_BRPORT_*_FLOOD` triplet. Restart-required. Default flipped to `true` after the Gate 8b 24 h MAC-churn soak (2026-05-16) and the M37 local-origination 24 h MAC-churn soak (2026-05-19) both passed. Operators who need the prior observe-only posture must set `apply_bum_enforcement = false` explicitly |
| `multipath_relax`   | bool   | no       | `false`              | ADR-0066 multipath-relax: group unicast ECMP candidates by `AS_PATH` *length* instead of an exact `AS_PATH` match (FRR's `bgp bestpath as-path multipath-relax`). Best-path-wide; inert unless a `[[fib_tables]]` sets `maximum_paths`, `maximum_paths_ebgp`, or `maximum_paths_ibgp` above `1` |
| `link_bandwidth_weighted` | bool | no   | `false`              | ADR-0068 weighted multipath: weight unicast ECMP next-hops by their Link Bandwidth Extended Community (draft-ietf-idr-link-bandwidth, FRR's `bgp bestpath bandwidth`) when the whole equal-cost group carries one; otherwise equal-cost. Best-path-wide; inert unless a `[[fib_tables]]` sets `maximum_paths`, `maximum_paths_ebgp`, or `maximum_paths_ibgp` above `1` |

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
runtime_state_dir = "/var/lib/rustbgpd"
honor_graceful_shutdown = true
honor_blackhole = true
install_blackhole_discard = false
allow_blackhole_broad_prefixes = false
```

`runtime_state_dir` must be writable by the rustbgpd process. In containers or
non-root deployments, override the default to a mounted writable path (for
example `/var/lib/rustbgpd` on a volume, or `/data/rustbgpd`).

`dynamic_neighbor_limit` caps the number of active peers auto-created from
`[[dynamic_neighbors]]` ranges. When omitted, rustbgpd allows up to 100 dynamic
peers at a time.

### `honor_graceful_shutdown` — RFC 8326 receiver behavior

When `true`, rustbgpd appends an implicit chain-tail rule on every
EBGP peer's import chain:

```
match community = GRACEFUL_SHUTDOWN (65535:0) → permit, set local_pref = 0
```

Routes carrying the `GRACEFUL_SHUTDOWN` well-known community land in the RIB
with `LOCAL_PREF = 0`, demoting the path so any non-shutting peer's path is
preferred during best-path selection. The originating peer can then close the
session knowing that traffic has already shifted.

The implicit rule sits at the **end** of the resolved chain so it wins the
last-writer accumulation against any operator policy that also sets
`LOCAL_PREF`. Operator denies still short-circuit normally — denied routes
don't survive to the demotion step.

iBGP peers (`remote_asn == global.asn`) are exempt because `LOCAL_PREF` is
preserved within an AS; re-applying the demotion per iBGP hop would clobber
values set legitimately at the upstream EBGP edge. Confederation gating is
tracked in [`ROADMAP.md`](../ROADMAP.md) as a follow-up.

Off by default — the operator opt-in is deliberate, RFC 8326 §4 says receivers
SHOULD apply this, not MUST.

SIGHUP hot-applies this field. When the value flips, rustbgpd recomputes
runtime policies for every EBGP peer and forces a policy refresh so
already-Established sessions see (or stop seeing) the implicit chain-tail
rule without a daemon restart. iBGP peers are skipped — the rule never
applied to them in the first place.

Hot-apply is **best-effort with partial-apply semantics**: the daemon's
working config and the peer manager's current config both advance to the
new value even if the refresh fan-out fails for some peers (channel-full,
session wedged, etc.). The value reported by `rustbgpd --diff` and
`rustbgpd --check` therefore always matches what the daemon believes it is
running.
Peers that failed the immediate refresh retry on their next policy edit
through the same `pending_refresh` / `pending_export_apply` carry-forward
plumbing used elsewhere in the reload path; transient failures surface as
`warn!` log lines rather than aborting the whole reload.

The matching initiator-side toggle (`rbgp gshut`) is a runtime gRPC
operation, not a config field; see `docs/OPERATIONS.md` for the operator
workflow.

The `"GRACEFUL_SHUTDOWN"` alias is also accepted everywhere
`match_community` / `set_community_add` / `set_community_remove` parse
community values, so policies can refer to it by name without repeating
`65535:0`.

### `honor_blackhole` — RFC 7999 receiver scoping

When `true`, rustbgpd appends an implicit chain-tail rule on every
EBGP peer's import chain:

```
match community = BLACKHOLE (65535:666) → permit, add BLACKHOLE + NO_ADVERTISE
```

RFC 7999 deliberately requires an explicit operator directive before a router
discards traffic for tagged prefixes. This knob is that directive for the
control-plane scoping behavior rustbgpd can enforce today: it preserves the
`BLACKHOLE` marker and adds `NO_ADVERTISE` at the chain tail so a blackhole
request is not propagated to other peers unless the operator writes a more
specific policy. Earlier operator denies still short-circuit normally.

By default this does **not** install a kernel discard/null route. To turn
local RTBH enforcement on, set both:

```toml
[global]
honor_blackhole = true
install_blackhole_discard = true
```

The FIB path is conservative. It only considers accepted best routes that
still carry `BLACKHOLE` after import policy, only installs routes learned
from EBGP, and only installs IPv4 `/32` or IPv6 `/128` host routes unless
`allow_blackhole_broad_prefixes = true` is also set. Existing foreign kernel
routes for the same prefix are treated as install failures rather than
overwritten, so operator/static or other-daemon routes are preserved.

Rows that carry rustbgpd's own ownership marker (`proto bgp` + blackhole
type in the main table) are the exception: after an unclean restart the
first reconcile pass **adopts** them (ADR-0079), so a crash leftover keeps
discarding attack traffic instead of blocking re-installation as foreign. A
still-desired prefix re-claims its adopted row silently (status `adopted`);
rows no BGP route re-claims stay visible as `adopted_pending_reap` and are
removed after a 500 s deferral, which makes reaping while BGP is still
reconverging unlikely (the deferral is a time proxy for convergence, not a
convergence signal).
Note this marker is a userspace convention: an operator's manual
`ip route add blackhole ... proto bgp` is indistinguishable from daemon
state and will be adopted, and co-residency with another proto-bgp daemon
(e.g. FRR zebra, which claims the same marker) is unsupported.

`rbgp rib blackholes` shows the current discard status for every
BLACKHOLE-marked best route the daemon has observed: `installed`
(`installed` / `owned` / `adopted` / `adopted_pending_reap`), `rejected`
(`broad_prefix` / `not_ebgp`), or `failed` (`foreign_route_exists`,
`dump_failed`, `remove_failed`, `reap_failed`, or the kernel install
error). The same surface is available as JSON with
`rbgp -j rib blackholes`. Adoption and reaping are counted by
`bgp_blackhole_discard_adopted_total` and
`bgp_blackhole_discard_reaped_total`.
If the reconciler cannot start at all (for example netlink setup failure, or
requesting FIB install on a non-Linux build), the status list is empty and
`bgp_blackhole_discard_kernel_failures_total{action="setup"}` or
`{action="unsupported_platform"}` carries the failure signal.

SIGHUP hot-applies this field with the same best-effort partial-apply
semantics as `honor_graceful_shutdown`: rustbgpd recomputes runtime policies
for EBGP peers, advances the live snapshot, and retries transient per-peer
refresh failures through the existing pending-refresh path.

`install_blackhole_discard`, `allow_blackhole_broad_prefixes`, and the
`honor_blackhole` component of an enabled or requested FIB-discard spawn gate
are startup-only in this slice because the kernel-discard reconciler is
spawned once at daemon boot. A SIGHUP that edits those fields logs an error
and pins the live config snapshot back until restart. When FIB discard is not
configured, `honor_blackhole` remains hot-applied through the peer manager.

The `"BLACKHOLE"` alias is accepted everywhere `match_community`,
`set_community_add`, and `set_community_remove` parse community values, so
policies can refer to it by name without repeating `65535:666`.

---

## `[global.telemetry]`

Required. Configures observability and management endpoints.

| Field             | Type   | Required | Default | Description                        |
|-------------------|--------|----------|---------|------------------------------------|
| `prometheus_addr` | string | no       | --      | `host:port` for Prometheus metrics and HTTP `/livez` / `/readyz` probes (omit to disable) |
| `log_format`      | string | yes      | --      | Log output format (`"json"`)       |

`prometheus_addr`, when present, must be a valid `ip:port` socket address. The
same listener serves `/metrics`, `/livez`, and `/readyz`.

### `[global.telemetry.looking_glass]`

Optional birdwatcher-compatible HTTP server for looking glass frontends
(Alice-LG, etc.).

| Field  | Type   | Required | Description                              |
|--------|--------|----------|------------------------------------------|
| `addr` | string | yes      | `host:port` for the looking glass server |

When configured, rustbgpd starts an HTTP server exposing birdwatcher-compatible
endpoints (`/status`, `/protocols/bgp`, `/routes/protocol/{id}`,
`/routes/peer/{peer}`). Omit the section entirely to disable.

```toml
[global.telemetry.looking_glass]
addr = "0.0.0.0:8080"
```

gRPC listeners are configured with optional subtables:

### `[global.telemetry.grpc_uds]`

Preferred local-only gRPC transport. If neither `grpc_uds` nor `grpc_tcp` is
configured, rustbgpd enables this listener by default at
`<runtime_state_dir>/grpc.sock`.

| Field        | Type   | Required | Default | Description |
|--------------|--------|----------|---------|-------------|
| `enabled`    | bool   | no       | `true`  | Enable this listener when the table is present |
| `path`       | string | no       | `<runtime_state_dir>/grpc.sock` | Absolute Unix socket path |
| `mode`       | u32    | no       | `0o600` | Filesystem mode applied to the socket after bind |
| `access_mode` | string | no      | `"read_write"` | Listener authorization mode: `"read_write"` or `"read_only"` |
| `max_tier`   | string | no       | implied by `access_mode` | ADR-0064 per-method listener cap: `read`, `sensitive_read`, `mutating`, or `operator_only` |
| `token_file` | string | no       | --      | Optional bearer token file for listener auth |
| `principal`  | string | no       | --      | Stable ADR-0064 audit principal label for this UDS listener |

### `[global.telemetry.grpc_tcp]`

Optional TCP gRPC listener. Use this only when you need remote access or
container/network exposure.

| Field        | Type   | Required | Default | Description |
|--------------|--------|----------|---------|-------------|
| `enabled`    | bool   | no       | `true`  | Enable this listener when the table is present |
| `address`    | string | yes*     | --      | `host:port` bind address (`required when enabled = true`) |
| `access_mode` | string | no      | `"read_write"` | Listener authorization mode: `"read_write"` or `"read_only"` |
| `max_tier`   | string | no       | implied by `access_mode` | ADR-0064 per-method listener cap: `read`, `sensitive_read`, `mutating`, or `operator_only` |
| `token_file` | string | no       | --      | Optional bearer token file for listener auth |
| `principal`  | string | no       | --      | Stable ADR-0064 audit principal label for non-mTLS bearer-token listeners |
| `tls_cert_file` | string | no   | --      | PEM-encoded server certificate (mTLS — requires the two siblings below) |
| `tls_key_file`  | string | no   | --      | PEM-encoded server private key |
| `tls_client_ca_file` | string | no | --   | PEM-encoded CA bundle that must sign every client certificate |

**Native gRPC mTLS.** Setting any of `tls_cert_file` / `tls_key_file` /
`tls_client_ca_file` requires *all three* together; a partial config is
rejected at `Config::load`. There is no "TLS-without-mTLS" half-mode by
design. When enabled, the daemon presents the server certificate, requires
every client to present a certificate signed by `tls_client_ca_file`, and
rejects unverified clients at the TLS layer before any gRPC handler runs.
PEM material is pre-flight-validated at config load and `--check` time so a
successful `--check` rules out cert-rotation surprises at startup. Listener
config (including any TLS field) is **restart-required** — SIGHUP reload
pins the runtime listener back to the live values and surfaces the drift
in `rustbgpd --diff` until the daemon is restarted.

Native gNMI / OpenConfig telemetry (`gnmi.gNMI`) is registered on TCP only when
this native mTLS config is present. Plaintext or bearer-token-only TCP listeners
serve the native `rustbgpd.v1` API but intentionally do not expose network gNMI;
the UDS listener may serve gNMI as a local-only extension. See
[GNMI.md](GNMI.md) for the supported OpenConfig path subset and `gnmic`
examples.

If either listener subtable is present, at least one gRPC listener must remain
enabled after applying `enabled = false`.

`access_mode = "read_only"` permits query and watch RPCs but rejects mutating
RPCs such as neighbor add/delete, route injection, policy changes, peer-group
changes, shutdown, and MRT trigger requests with `PERMISSION_DENIED`. This is
intended for monitoring or dashboard listeners that should not expose control
plane writes.

**ADR-0064 listener tier caps:** `max_tier` is a per-listener ceiling based on
the checked gRPC method-tier matrix. Calls whose method tier is higher than the
effective listener cap return `PERMISSION_DENIED` before the handler runs, after
bearer-token listeners first authenticate the request so missing or invalid
tokens still return `UNAUTHENTICATED` without exposing tier-cap details. The
field is backwards-compatible with `access_mode`: omitting `max_tier` preserves
the existing `access_mode` behavior, `read_only` implies `sensitive_read`, and
`read_write` implies `operator_only`. When both fields are set, the effective
cap is the stricter of the two, so `access_mode = "read_only"` cannot be
weakened by `max_tier = "operator_only"`.

**Token file lifecycle:** When `token_file` is configured, the file must exist
and contain a non-empty token at daemon startup. The token is read once during
config validation and kept in memory for the daemon's lifetime. Token rotation
requires a daemon restart. In orchestrated environments where secrets are
mounted after config files, ensure the token file is available before starting
the daemon.

**ADR-0064 audit principals:** `principal` gives the audit-only
`grpc_authz` log line a stable operator-controlled identity. On UDS listeners
it labels the listener identity established by filesystem permissions and/or
the optional token. On TCP listeners it is accepted only when `token_file` is
configured and native mTLS is not configured. Native mTLS listeners derive the
audit principal from the peer certificate in ADR-0064 order: first `rustbgpd:`
URI SAN, then email SAN, then Subject CN. If a validated client certificate has
none of those fields, or if the selected value is too long or contains embedded
control characters, the request remains allowed in legacy mode and the audit
principal falls back to `mtls-unresolved`.

### `[security.grpc]`

ADR-0064 per-method authorization defaults to `"tier"` since v0.24.0. Tier
mode enforces `[security.grpc.roles]` for the authenticated principal before
the handler runs, in addition to listener `max_tier` caps; upgrading without a
`[security.grpc.roles]` block fails validation at startup. Legacy mode
(`enforcement = "legacy"`) remains a supported opt-out that preserves the prior
listener-wide behavior.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enforcement` | string | no | `"tier"` | ADR-0064 enforcement mode (default since v0.24.0). `"tier"` enables per-principal role enforcement in addition to listener `max_tier` caps. `"legacy"` is the opt-out that preserves prior listener `access_mode` behavior |

`[security.grpc.roles]` maps an authenticated principal string to one of the
built-in roles:

| Role | Max tier in `enforcement = "tier"` |
|------|------------------------------------|
| `observer` | `sensitive_read` |
| `automation` | `mutating` |
| `operator` | `operator_only` |

When `enforcement = "tier"` is configured:

- `[security.grpc.roles]` must contain at least one principal mapping.
- Bearer-token TCP listeners must set both `token_file` and an explicit
  `principal`; the token value itself is never used as an identity. That
  principal must have a matching `[security.grpc.roles]` entry.
- UDS listeners must set an explicit `principal`; filesystem permissions
  authenticate access but do not identify the client role. That principal must
  have a matching `[security.grpc.roles]` entry.
- Native mTLS TCP listeners derive the principal from the verified client
  certificate and do not set `grpc_tcp.principal`.
- Unauthenticated TCP listeners are rejected at config load.
- Requests from principals absent from `[security.grpc.roles]` fail closed with
  `PERMISSION_DENIED`.

**Default changed to `tier` in v0.24.0.** Upgrading an existing
deployment without staging the migration first will fail validation
at startup; the error message points at this section and at the
`enforcement = "legacy"` escape hatch. Already-staged operators see
no behavior change.

The safe migration sequence (run against a pre-upgrade daemon if
possible):

1. Add `[security.grpc.roles]` entries for every expected gRPC principal.
2. Set an explicit `principal` on each UDS listener and each bearer-token TCP
   listener. The implicit default UDS listener has no principal identity, so
   tier-ready configs must declare `[global.telemetry.grpc_uds]` explicitly.
3. For remote TCP, prefer native mTLS so the principal is derived from the
   client certificate; otherwise use `token_file` plus a non-secret
   `principal` label.
4. Set `enforcement = "legacy"` while staging labels and roles, then run
   `rustbgpd --check` against the candidate TOML.
5. Remove the explicit `enforcement = "legacy"` (or change it to
   `"tier"`) and monitor `grpc_authz` logs/metrics for
   `principal_unmapped` and `role_tier_denied`.
6. If you need to preserve the pre-v0.24.0 behavior indefinitely, set
   `enforcement = "legacy"` explicitly and keep it there.

```toml
# The v0.24.0 default — equivalent to omitting [security.grpc]
# entirely on a tier-ready config.
[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"observer-readonly" = "observer"
"automation.example" = "automation"
"operator.example" = "operator"
```

```toml
# Pre-v0.24.0 behavior. Explicit opt-out preserved indefinitely.
[security.grpc]
enforcement = "legacy"
```

```toml
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/grpc.sock"
mode = 0o660
access_mode = "read_write"
principal = "local-admin"

[global.telemetry.grpc_tcp]
address = "127.0.0.1:50051"
access_mode = "read_only"
max_tier = "sensitive_read"
# token_file = "/etc/rustbgpd/grpc.token"
# principal = "observer-readonly"
```

---

## `[[neighbors]]`

Optional, repeatable. Each entry defines one BGP peer. Omit entirely for a
dynamic-only deployment where peers are added at runtime via gRPC.

| Field                  | Type     | Required | Default | Description                                      |
|------------------------|----------|----------|---------|--------------------------------------------------|
| `address`              | string   | yes      | --      | Peer IP address (IPv4 or IPv6)                   |
| `interface`            | string   | IPv6 link-local only | -- | Interface name for `fe80::/10` / unnumbered peers |
| `remote_asn`           | u32      | yes      | --      | Peer's autonomous system number                  |
| `description`          | string   | no       | --      | Human-readable label (used in logs; defaults to address if absent) |
| `peer_group`           | string   | no       | --      | Named peer-group to inherit transport and policy defaults from      |
| `hold_time`            | u16      | no       | 90      | BGP hold timer in seconds (0 or >= 3)            |
| `max_prefixes`         | u32      | no       | --      | Maximum prefixes accepted before session teardown |
| `md5_password`         | string   | no       | --      | TCP MD5 authentication password (RFC 2385, Linux only) |
| `tcp_ao`               | table    | no       | --      | TCP-AO key for static neighbors (RFC 5925; Linux startup sockets, restart-required edits) |
| `bfd`                  | table    | no       | --      | Single-hop BFD attachment referencing a `[[bfd_profiles]]` entry (RFC 5880/5881/5882; static neighbors only, restart-required edits) |
| `ttl_security`         | bool     | no       | false   | Enable GTSM / TTL security (RFC 5082, Linux only) |
| `families`             | [string] | no       | (auto)  | Address families to negotiate (see below)        |
| `graceful_restart`     | bool     | no       | true    | Enable Graceful Restart receiving speaker (RFC 4724) |
| `gr_restart_time`      | u16      | no       | 120     | Restart time advertised in GR capability (seconds, 1--4095) |
| `gr_stale_routes_time` | u64      | no       | 360     | Time to retain stale routes after peer reconnects (seconds, 1--3600) |
| `route_server_client`  | bool     | no       | false   | Transparent route-server mode for eBGP peers (see below) |
| `role`                 | string   | no       | --      | Local BGP Role for RFC 9234 route-leak protection: `"provider"`, `"rs"`, `"rs-client"`, `"customer"`, or `"peer"` (eBGP only) |
| `strict_role`          | bool     | no       | false   | Require the peer to advertise a compatible BGP Role capability; only valid when `role` is set |
| `prefix_orf_receive`   | bool     | no       | false   | Advertise receive-side Address-Prefix ORF (RFC 5291/5292); peer-pushed prefix filters constrain outbound advertisements |
| `disable_ipv4_unicast` | bool     | no       | false   | True IPv6-only peering: never negotiate IPv4 unicast on this session (suppresses the RFC 4760 §8 implicit-IPv4 fallback; see below) |
| `remove_private_as`   | string   | no       | --      | Remove private ASNs from AS_PATH: `"remove"`, `"all"`, or `"replace"` (eBGP only) |
| `route_reflector_client` | bool   | no       | false   | Mark this iBGP peer as a route reflector client (RFC 4456) |
| `local_ipv6_nexthop`   | string   | no       | --      | Override IPv6 next-hop for eBGP exports (must be valid non-link-local IPv6) |
| `import_policy_chain`  | [string] | no       | --      | Named policy chain for import (mutually exclusive with inline import_policy) |
| `export_policy_chain`  | [string] | no       | --      | Named policy chain for export (mutually exclusive with inline export_policy) |
| `llgr_stale_time`      | u32      | no       | 0       | LLGR stale time in seconds (0 = disabled, max 16777215; RFC 9494)    |
| `add_path`             | table    | no       | --      | Add-Path (RFC 7911) config table (see below)                         |
| `log_level`            | string   | no       | --      | Override log level for this peer: `"error"`, `"warn"`, `"info"`, `"debug"`, or `"trace"` |

IPv6 link-local neighbors (`fe80::/10`) must set `interface`, because a
link-local address is not globally unique (RFC 4007). Numbered IPv4 / IPv6
neighbors must not set `interface`. Duplicate numbered peers are rejected by
address. In this release each link-local address must also be unique across
neighbors: the same link-local address may not be bound to more than one
interface, because the RIB still keys peers by address. Scoped multi-interface
link-local peering is deferred (see ADR-0069).

```toml
[[neighbors]]
address = "fe80::5054:ff:fe00:1"
interface = "eth1"
remote_asn = 65101
families = ["ipv4_unicast"]
```

TCP-AO (RFC 5925) `tcp_ao` is accepted for static `[[neighbors]]` only. On
Linux, rustbgpd installs the configured key on outbound active-open sockets
before `connect()` and on the passive BGP listener before `listen()` when the
peer address family matches the configured listener socket. If a configured
TCP-AO listener key cannot be installed, startup fails closed instead of
running a partially protected listener. Active-open key installation failures
fail that session connect attempt and retry later; they do not fall back to an
unauthenticated session. `rbgp global` / `GlobalService.GetGlobal` expose
the host capability probe so operators can verify kernel support before
enabling the field.

Active-open sockets install the key as both Linux `current_key` and `rnext_key`
so the initial SYN is signed. Listener sockets install the per-peer MKT without
`current_key` / `rnext_key`; Linux rejects those flags on listening sockets.
rustbgpd does not set the socket-wide `ao_required` bit because a shared BGP
listener may also serve non-TCP-AO neighbors.

Linux TCP-AO Master Key Tuples are socket state, so `tcp_ao` additions,
removals, and key changes are restart-required. On SIGHUP, rustbgpd pins the
live neighbor back to the startup snapshot, reports `[[neighbors]].tcp_ao` as
restart-required in `--diff` / config-diff JSON, pins peer-group and policy
dependencies referenced by the pinned TCP-AO neighbors and restart-required
global fields that affect neighbor validation to the live snapshot for that
reload, and leaves the edited TOML as the desired config for the next daemon
restart. Runtime deletion of a configured TCP-AO neighbor is also rejected
until listener MKT deletion / key rotation support lands.

`tcp_ao` is mutually exclusive with `md5_password`, including an inherited
peer-group MD5 password. It is not available in `[peer_groups.*]` because
dynamic-neighbor TCP-AO needs a separate wildcard-MKT design. Example:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
tcp_ao = {
  key = "secret",
  send_id = 1,
  recv_id = 1,
  algorithm = "hmac(sha256)",
  preferred = true,
  deprecated = false,
}
```

Allowed `algorithm` values are `"hmac(sha1)"`, `"hmac(sha256)"`, and
`"cmac(aes128)"`. `key` must be 1--80 bytes. `send_id` and `recv_id` are
TCP-AO KeyIDs (`0..=255`). `preferred` and `deprecated` are parsed as
rollover metadata for future multi-key support; with the current single-key
runtime, active-open sockets install the configured key as the initial current
/ receive-next key, while listener MKTs are installed without current /
receive-next flags. `preferred` and `deprecated` cannot both be true.

### BFD (RFC 5880 / 5881 / 5882)

Single-hop asynchronous BFD (ADR-0067) gives sub-second peer-failure detection
and, via RFC 5882, tears the BGP session down on a BFD-down event before the
hold timer expires. Timers live in named profiles; neighbors (or peer groups)
attach to a profile.

```toml
# A named timing profile. Intervals are milliseconds.
[[bfd_profiles]]
name = "fast"
min_tx_interval = 300   # default 300, floor 100
min_rx_interval = 300   # default 300, floor 100
multiplier = 3          # default 3, min 2 (detection ≈ interval × multiplier)

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
# Attach BFD. `strict` is optional (default false).
bfd = { profile = "fast" }

# Peer groups can carry a default; a neighbor can override it off:
[peer_groups.edge]
bfd = { profile = "fast" }

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "edge"
bfd = { profile = "fast", enabled = false }   # opt this neighbor out
```

`[neighbors.bfd]` / `[peer_groups.<name>.bfd]` fields:

| Field     | Type   | Default | Description                                                       |
|-----------|--------|---------|-------------------------------------------------------------------|
| `profile` | string | --      | Name of a `[[bfd_profiles]]` entry (must exist)                   |
| `enabled` | bool   | true    | Set `false` to disable BFD (e.g. override an inherited group block) |
| `strict`  | bool   | false   | RFC 5882 strict mode: withhold BGP establishment until BFD is Up   |

In **non-strict** mode (default) BGP establishes normally and a later BFD-down
tears it down faster than the hold timer; recovery re-establishes. In **strict**
mode the BGP session is withheld (on both the active-open and inbound paths)
until BFD first reaches Up.

A **remote `AdminDown`** — the peer *administratively disabling* BFD — is treated
per RFC 5882 §4.1 as administrative, not a liveness failure: the BGP adjacency is
**allowed in both modes**. An established session stays up; a withheld strict
session is released. (BGP keeps its own hold-timer liveness; BFD is simply not in
use while the peer has it administratively down. Our local BFD session state
stays `Down` in this case — the remote-AdminDown cause is tracked separately — so
`GetBfdSessions` still shows `Down`; only the BGP coupling treats it as
permitting BGP.) Genuine failures — a detection timeout or a remote-signaled
`Down` — still tear BGP down (non-strict) or keep it withheld (strict). A *local*
operator disable/delete of the neighbor stops BGP through the normal lifecycle,
not this path.

BFD is **static-neighbors only** in v1 — a `[[dynamic_neighbors]]` range whose
peer group enables BFD is rejected at config time. v1 covers IPv4 + IPv6
**global** addresses. BFD on IPv6 link-local / unnumbered peers is still
deferred even though the BGP neighbor itself can be interface scoped. Like
TCP-AO, BFD edits are **restart-required**: on SIGHUP rustbgpd pins
`[[bfd_profiles]]` and neighbor / peer-group `bfd` back to the live snapshot and
reports them as restart-required in `--diff`. Inspect sessions with
`rbgp bfd` / `BfdService.GetBfdSessions` (see [API.md](API.md)).

### Address families

The `families` field controls which AFI/SAFI combinations are negotiated with
the peer via MP-BGP capabilities. Supported values:

- `"ipv4_unicast"` — IPv4 Unicast (AFI 1, SAFI 1)
- `"ipv6_unicast"` — IPv6 Unicast (AFI 2, SAFI 1)
- `"ipv4_flowspec"` — IPv4 FlowSpec (AFI 1, SAFI 133, RFC 8955)
- `"ipv6_flowspec"` — IPv6 FlowSpec (AFI 2, SAFI 133, RFC 8956)
- `"l2vpn_evpn"` — L2VPN EVPN (AFI 25, SAFI 70, RFC 7432). Two
  deployment modes share the family:
  - **RR mode (Phase 1):** the daemon reflects all five RFC 7432
    route types between iBGP-speaking VTEPs configured as
    `route_reflector_client = true`, with no local EVI state. Empty
    `[[evpn_instances]]` selects this mode.
  - **Bidirectional VTEP mode (Phase 2 — Gates 7a / 7b / 7b+1 / 7b+2 / 7c / 8 / 8b):**
    populating `[[evpn_instances]]` (see § *EVPN VTEP instances*
    below) makes the daemon program remote-MAC FDB entries from
    received Type 2 routes (downward), originate local MAC-only and
    MAC+IP Type 2 routes plus one Type 3 IMET per L2VNI (upward),
    and optionally run Gate 8/8b multi-homing enforcement when
    `[[ethernet_segments]]` and `apply_bum_enforcement` are
    configured. Linux-only; requires `CAP_NET_ADMIN` for the
    rtnetlink subscription and FDB program path.
  See [docs/USE_CASES.md](USE_CASES.md) § "VXLAN-EVPN DC Fabric"
  for a worked example and `examples/rr-evpn-fabric/config.toml`
  for a copy-paste-ready starting point.

**Defaults:** If `families` is omitted, the default depends on the neighbor
address type:

- IPv4 neighbor address → `["ipv4_unicast"]`
- IPv6 neighbor address → `["ipv4_unicast", "ipv6_unicast"]`

### IPv6-only peering (`disable_ipv4_unicast`)

Per RFC 4760 §8, IPv4 unicast is implicitly available on a BGP session
whenever it is not explicitly negotiated away — even a `families =
["ipv6_unicast"]` neighbor still ends up with IPv4 unicast negotiated.
That default is correct for backward compatibility but wrong for an
IPv6-only fabric (including ADR-0069 link-local unnumbered peering)
where the peer genuinely refuses IPv4 unicast.

Set `disable_ipv4_unicast = true` on a neighbor or peer group to make
the session truly IPv6-only:

- IPv4 unicast is excluded from the MultiProtocol capability rustbgpd
  advertises in OPEN (and from every family-derived capability: GR,
  LLGR, Add-Path, ORF, extended next-hop), regardless of what
  `families` resolves to.
- The RFC 4760 §8 implicit-IPv4 fallback is suppressed during
  negotiation — IPv4 unicast is never added behind the operator's back.
- If the resulting family intersection with the peer is empty (for
  example the peer advertises only IPv4 unicast, or sends no
  MultiProtocol capability at all), rustbgpd rejects the session with
  NOTIFICATION OPEN error / Unsupported Capability (2/7) — the same
  behavior FRR exhibits when configured AFI/SAFIs do not overlap.

```toml
[[neighbors]]
address = "fd00:64::2"
remote_asn = 65002
families = ["ipv6_unicast"]
disable_ipv4_unicast = true
```

Config validation rejects `disable_ipv4_unicast = true` when the
neighbor's effective `families` resolve to `ipv4_unicast` only — that
combination could never negotiate anything. The knob is off by default;
existing configs behave identically. It controls capability negotiation
only: RFC 8950 extended-next-hop and unnumbered peering are unaffected.

### Peer groups

Peer groups are reusable neighbor templates defined at the top level under
`[peer_groups.<name>]`. A neighbor can reference one with `peer_group = "..."`.
Explicit neighbor settings win over peer-group settings. Peer-group definitions
can also be managed at runtime through the gRPC `PeerGroupService`; successful
mutations persist back to TOML.

```toml
[peer_groups.rs-clients]
hold_time = 90
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true
export_policy_chain = ["tag-ixp"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "rs-clients"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "rs-clients"
hold_time = 45  # neighbor override beats peer-group default
```

Peer-group fields mirror inheritable neighbor settings: timers, families,
GR/LLGR, Add-Path, route-server / RR flags, BGP Role / strict-role defaults,
receive-side Prefix ORF, private-AS handling, MD5/GTSM,
`local_ipv6_nexthop`, `log_level`, and import/export inline policy or named
chains. TCP-AO is intentionally not inherited through peer groups because
dynamic-neighbor TCP-AO needs a separate wildcard-MKT design.

```toml
# IPv4 peer with dual-stack
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "upstream-provider"
hold_time = 90
max_prefixes = 10000
md5_password = "s3cret"
ttl_security = true
families = ["ipv4_unicast", "ipv6_unicast"]

# IPv6 peer (defaults to dual-stack)
[[neighbors]]
address = "fd00::2"
remote_asn = 65003
description = "ipv6-peer"
```

**Extended Next Hop (RFC 8950):** When both `"ipv4_unicast"` and
`"ipv6_unicast"` are configured for a neighbor, rustbgpd automatically
advertises the Extended Next Hop capability. If negotiated, IPv4 unicast
routes may be exchanged via `MP_REACH_NLRI` / `MP_UNREACH_NLRI` using an
IPv6 next hop. For eBGP exports, `local_ipv6_nexthop` (if configured) is
used as the IPv6 self next-hop; otherwise the local IPv6 socket address is
used when available.

---

## `[[dynamic_neighbors]]`

Optional, repeatable. Defines prefix ranges for auto-accepting inbound BGP
connections. When an inbound TCP connection arrives from an address inside the
configured prefix, rustbgpd creates an ephemeral peer using the referenced peer
group.

Dynamic peers:

- inherit transport and policy defaults from the referenced peer group
- never initiate outbound TCP connections
- the ephemeral peer entry is not written back to `[[neighbors]]` (the *range*,
  however, is persisted to `[[dynamic_neighbors]]` when added at runtime with the
  daemon started under `--config` — see "Runtime management" below)
- the ephemeral peer is removed automatically when its session returns to Idle
  (the range itself persists)
- count against `global.dynamic_neighbor_limit`

| Field         | Type   | Required | Default | Description |
|---------------|--------|----------|---------|-------------|
| `prefix`      | string | yes      | --      | IPv4 or IPv6 prefix range in CIDR notation |
| `peer_group`  | string | yes      | --      | Peer group whose settings dynamic peers inherit |
| `remote_asn`  | u32    | no       | `0`     | Expected remote ASN. `0` means accept any ASN from the peer's OPEN |
| `description` | string | no       | --      | Optional description applied to accepted dynamic peers |

When `remote_asn = 0`, the accepted peer keeps the configured range as
accept-any, but the ephemeral peer's session state uses the ASN learned from the
peer's OPEN. Peer snapshots, gRPC state, BMP peer state, and RIB peer-up
metadata therefore report the learned ASN rather than the sentinel `0`.

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
dynamic_neighbor_limit = 500

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-members]
hold_time = 90
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
remote_asn = 0
description = "IXP auto-accept"

[[dynamic_neighbors]]
prefix = "2001:db8::/32"
peer_group = "ix-members"
```

Validation rules:

- `peer_group` must reference an existing `[peer_groups.<name>]`
- `prefix` must be valid CIDR with a family-appropriate prefix length
- static `[[neighbors]]` cannot use `remote_asn = 0`; that sentinel is reserved for `[[dynamic_neighbors]]`
- two ranges covering the **identical** effective prefix (same masked network
  and length) are rejected; overlapping ranges of *different* lengths are
  allowed and resolve by longest-prefix-match at accept time

### Runtime management (gRPC / `rbgp`)

Ranges can be added and removed at runtime without a restart, in addition to
the static TOML form above:

```sh
rbgp dynamic-neighbor list
rbgp dynamic-neighbor add 10.0.0.0/24 --peer-group ix-members [--asn 65010] [--description "..."]
rbgp dynamic-neighbor delete 10.0.0.0/24
```

- Backed by `NeighborService` (`AddDynamicNeighbor` / `DeleteDynamicNeighbor` /
  `ListDynamicNeighbors`); add/delete are tier `mutating`.
- When the daemon was started with `--config`, runtime changes reserve config
  persistence capacity before mutating and then wait for the atomic TOML write
  to be acknowledged after the peer manager accepts the change. Runtime
  dynamic-neighbor CRUD is serialized with SIGHUP reload, so a reload sees
  either the pre-mutation TOML or the committed post-mutation TOML. If the write
  is rejected after the runtime mutation, the matcher is rolled back and the RPC
  reports failure. Without `--config`, changes are in-memory only.
- **Delete stops *future* accepts only.** Already-established dynamic peers from
  a removed range keep running and drain naturally when they next return to
  Idle; delete never tears down a live session.
- Add is rejected for an unknown or BFD-enabled peer group, an invalid prefix,
  or a duplicate effective prefix. Delete matches by effective prefix, so a
  host-bit variant of the same network (e.g. `10.0.0.7/24`) removes the
  `10.0.0.0/24` range.

Operational note:

- disabling a dynamic peer keeps the peer entry in memory but prevents reconnect

### Graceful Restart (RFC 4724)

Graceful Restart is enabled by default. rustbgpd implements:

- **Helper mode (receiving speaker):** when a peer with GR capability
  restarts, its routes are preserved as stale during the restart window
  instead of being immediately withdrawn. End-of-RIB markers from the peer
  clear stale flags per address family; if the timer expires before all
  End-of-RIB markers arrive, remaining stale routes are swept.
- **Minimal restarting-speaker mode:** after a coordinated daemon restart,
  rustbgpd can temporarily advertise `restart_state = true` to static peers
  restored from config, using a marker file under `runtime_state_dir`.
  This helps peers retain our routes while we reconnect, but
  `forwarding_preserved` remains false because rustbgpd does not persist
  route/FIB ownership across restart or verify that forwarding state survived.
  ADR-0061 FIB programming is opt-in and scoped; crash-left rows are preserved
  as foreign rather than adopted.

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
graceful_restart = true      # default: true
gr_restart_time = 120        # seconds, advertised in GR capability (max 4095)
gr_stale_routes_time = 360   # seconds, how long to wait for EoR after reconnect (max 3600)
```

To disable GR for a specific peer:

```toml
[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
graceful_restart = false
```

**Implementation note:** restarting-speaker mode is deliberately minimal and
honest. The daemon may advertise `R=1` after a planned restart, but it does
not claim forwarding-state preservation (`forwarding_preserved = false`) and
does not persist route state across restarts.
See [ADR-0024](adr/0024-graceful-restart.md).

### Long-Lived Graceful Restart (RFC 9494)

LLGR extends Graceful Restart with a second stale-timer phase. When the GR
timer expires, routes for LLGR-negotiated families are promoted to LLGR-stale
(with the `LLGR_STALE` well-known community added) instead of being purged.
Routes carrying `NO_LLGR` are purged at the GR-to-LLGR transition.

The effective LLGR stale time is `min(local llgr_stale_time, peer's per-family minimum)`.

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
graceful_restart = true
llgr_stale_time = 3600    # seconds (0 = disabled, max 16777215)
```

To disable LLGR for a specific peer, set `llgr_stale_time = 0` (the default).

Best-path selection uses three-tier stale ranking: fresh > GR-stale > LLGR-stale,
applied at step 0 (before LOCAL_PREF). LLGR-stale routes are least preferred but
still participate in best-path selection until the LLGR timer expires.

See [ADR-0024](adr/0024-graceful-restart.md) for the two-phase timer design.

### Add-Path (RFC 7911)

Add-Path allows accepting and advertising multiple paths per prefix.
Configure it per-neighbor with the `[neighbors.add_path]` table:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[neighbors.add_path]
receive = true    # accept multiple paths per prefix from this peer
send = true       # advertise multiple paths per prefix to this peer
send_max = 4      # limit to top 4 candidates (omit for unlimited)
```

| Field      | Type    | Required | Default | Description                                |
|------------|---------|----------|---------|--------------------------------------------|
| `receive`  | bool    | no       | false   | Accept multiple paths per prefix from peer  |
| `send`     | bool    | no       | false   | Advertise multiple paths per prefix to peer |
| `send_max` | integer | no       | —       | Max paths per prefix (omit for unlimited)   |

When `receive` is true, the Add-Path capability (code 69) is advertised in
OPEN with `Receive` mode. When `send` is true, `Send` mode is advertised.
If both are enabled, `Both` is advertised.

**Multi-path send (route server mode):** When `send = true`, the RIB
distributes multiple candidate paths per prefix to this peer, sorted by
best-path preference. Paths are assigned rank-based path IDs (best=1,
second=2, etc.). Split horizon, iBGP suppression, and per-candidate export
policy are evaluated for each path.

Both IPv4 and IPv6 unicast are supported. See [ADR-0033](adr/0033-add-path.md).

### Transparent Route Server Mode

For IX route-server clients, you can make eBGP export transparent by setting
`route_server_client = true` on the neighbor:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true
```

When enabled:

- outbound **unicast** advertisements to that peer preserve the original next
  hop by default
- outbound **unicast** advertisements skip the automatic local-AS prepend
  normally applied on eBGP export
- outbound **FlowSpec** advertisements skip the automatic local-AS prepend
- explicit export-policy next-hop rewrites (`set_next_hop`) still win for
  unicast
- `LOCAL_PREF` is still stripped, because the peer is still eBGP

This applies to:

- classic IPv4 unicast (`NEXT_HOP`)
- IPv4 unicast over IPv6 next hop (RFC 8950)
- IPv6 unicast (`MP_REACH_NLRI`)
- IPv4 and IPv6 FlowSpec export (`AS_PATH` transparency only; FlowSpec has no
  wire-level `NEXT_HOP`)

`route_server_client` is only valid for eBGP neighbors. Config validation
rejects it on iBGP peers.

### Receive-side Prefix ORF (RFC 5291/5292)

Set `prefix_orf_receive = true` on a neighbor or peer group to advertise that
rustbgpd can receive Address-Prefix ORF entries from that peer. When negotiated,
rustbgpd applies the peer-pushed prefix filter before export policy for that
peer. This is route-server oriented: a client can suppress routes it does not
want to receive without the server pre-configuring a dedicated export policy for
that client.

For an ORF-negotiated family, rustbgpd gates the initial table dump until the
peer sends its first ROUTE-REFRESH for that family, then floods the filtered
view. ORF entries use prefix-list semantics: sequence order, first match wins,
implicit deny on a non-empty list, and permit-all when the list is empty or
removed. `DEFER` installs the filter state but waits for a later immediate or
plain ROUTE-REFRESH to sweep advertisements and withdrawals.

rustbgpd implements the receive side only: it does not send ORF entries to its
own upstreams. The knob is static TOML state, inherited through peer groups, and
is off by default.

### BGP Roles and Only-to-Customer (RFC 9234)

Static eBGP neighbors can advertise a local BGP Role and apply the RFC 9234
Only-to-Customer (OTC) route-leak procedures for IPv4/IPv6 unicast:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
role = "provider"
strict_role = true
```

Valid role values are `"provider"`, `"rs"`, `"rs-client"`, `"customer"`, and
`"peer"`. The longer aliases `"route_server"` and `"route_server_client"` are
also accepted. When `role` is configured, rustbgpd advertises the BGP Role
capability and applies OTC rules based on the local role even if the peer does
not advertise a Role. `strict_role = true` changes that compatibility behavior:
the peer must advertise a compatible Role or the OPEN is rejected with Role
Mismatch (NOTIFICATION 2/11).

OTC handling is scoped to unicast. FlowSpec and EVPN route attributes are not
modified by the v1 implementation. Existing OTC attributes are preserved;
rustbgpd only adds OTC when RFC 9234 requires it and the attribute is absent.
Malformed OTC length is handled as treat-as-withdraw for unicast announcements:
withdrawals in the same UPDATE still apply and the BGP session stays up.
`rbgp neighbor <addr>` and `NeighborService.GetNeighborState` report the
configured local role, any remote role advertised in OPEN, whether the role was
mutually negotiated, and the running `otc_routes_blocked` count.

`role` is eBGP-only and `strict_role` requires `role`. Config reload applies a
role change by reconfiguring the affected peer session; dynamic in-place role
flips without a session restart are deferred in ADR-0071.

### Private AS Removal

Strip private ASNs (64512–65534, 4200000000–4294967294) from AS_PATH
before eBGP advertisement:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
remove_private_as = "all"
```

Three modes are available:

- **`"remove"`** — remove private ASNs only if *every* ASN in the path is private (safe default)
- **`"all"`** — unconditionally remove all private ASNs from every segment; drop empty segments
- **`"replace"`** — replace each private ASN with the local ASN

`remove_private_as` is only valid for eBGP neighbors. Config validation
rejects it on iBGP peers. Route server client peers skip private AS
removal (they already skip AS_PATH manipulation).

See [ADR-0045](adr/0045-private-as-removal.md).

### FlowSpec (RFC 8955)

FlowSpec distributes traffic filtering rules via BGP. Enable it by adding
FlowSpec families to the `families` list:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
families = ["ipv4_unicast", "ipv6_unicast", "ipv4_flowspec", "ipv6_flowspec"]
```

FlowSpec rules have no next-hop (NH length = 0 in MP_REACH_NLRI). Traffic
actions (rate-limit, redirect, DSCP mark) are encoded as extended communities
per RFC 8955 section 7.

FlowSpec routes are injected and queried via the gRPC API:

- `InjectionService/AddFlowSpec` — inject a FlowSpec rule with match components and actions
- `InjectionService/DeleteFlowSpec` — withdraw a FlowSpec rule
- `RibService/ListFlowSpecRoutes` — query the FlowSpec Loc-RIB

FlowSpec routes pass through the same policy engine as unicast routes:
import/export policy, iBGP split-horizon, and route reflector rules all
apply. See [ADR-0035](adr/0035-flowspec.md).

### Per-neighbor policy

Each neighbor can carry its own import and export policy. These are
defined as nested arrays of tables within the `[[neighbors]]` entry.

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[neighbors.import_policy]]
prefix = "10.0.0.0/8"
ge = 24
le = 32
action = "deny"

[[neighbors.import_policy]]
prefix = "0.0.0.0/0"
le = 24
action = "permit"
set_local_pref = 200

[[neighbors.export_policy]]
prefix = "192.168.0.0/16"
action = "permit"
set_as_path_prepend = { asn = 65001, count = 2 }
```

See the [Policy entries](#policy-entries) section below for field details.

### Route Reflector (RFC 4456)

rustbgpd can act as a route reflector, relaxing the iBGP full-mesh requirement.
When `cluster_id` is set and at least one neighbor has `route_reflector_client = true`,
iBGP-learned routes from clients are reflected to all iBGP peers, while routes
from non-clients go to clients only.

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
cluster_id = "10.0.0.1"    # enables route reflector mode

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
route_reflector_client = true    # this peer is a RR client

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65001
# non-client -- receives reflected client routes only
```

See [ADR-0029](adr/0029-route-reflector.md) for reflection rules and
ORIGINATOR_ID/CLUSTER_LIST handling.

---

## `[rpki]`

Optional. Configures RPKI origin validation via a persistent RTR client (RFC 8210).
rustbgpd connects to one or more RPKI cache validators and uses their VRP
(Validated ROA Payload) data to classify routes as Valid, Invalid, or NotFound.
The RTR session stays connected after `EndOfData`, uses `SerialNotify` for
immediate refreshes when the cache sends them, falls back to periodic serial
polling at `refresh_interval`, and expires cached VRPs if no fresh `EndOfData`
arrives before the effective expiry timer.

### Prerequisites

You need a running RPKI validator that speaks RTR:

| Validator | Default RTR Port | Notes |
|-----------|:----------------:|-------|
| [Routinator](https://nlnetlabs.nl/projects/routinator/) | 3323 | Rust, recommended |
| [rpki-client](https://www.rpki-client.org/) | 8282 | OpenBSD origin |
| [FORT](https://fortproject.net/) | 8323 | C, lightweight |
| [OctoRPKI](https://github.com/cloudflare/cfrpki) | 8282 | Go, Cloudflare |

### Basic setup

```toml
[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"
```

### Multiple cache servers (redundancy)

For production, connect to 2+ caches. VRPs are merged (union) across all
connected caches:

```toml
[rpki]
[[rpki.cache_servers]]
address = "rpki1.example.com:3323"

[[rpki.cache_servers]]
address = "rpki2.example.com:3323"
```

### Cache server options

| Field | Type | Required | Default | Description |
|-------|------|:--------:|:-------:|-------------|
| `address` | string | yes | -- | Cache server `host:port` |
| `refresh_interval` | u64 | no | 3600 | Seconds between Serial Queries |
| `retry_interval` | u64 | no | 600 | Seconds before reconnect on failure |
| `expire_interval` | u64 | no | 7200 | Seconds before discarding stale VRPs |

### Validation states

Every route receives a validation state based on RPKI data:

| State | Meaning | Best-path effect |
|-------|---------|------------------|
| **Valid** | Origin AS matches a VRP covering the prefix | Preferred |
| **NotFound** | No VRP covers the prefix | Neutral (default) |
| **Invalid** | VRP covers the prefix but origin AS doesn't match, or the route exceeds the VRP `maxLength` | Deprioritized |

### Policy integration

Use `match_rpki_validation` in import or export policy statements to filter
routes by RPKI state. Import validation evaluates against the current VRP
snapshot at ingress time. Later VRP/ASPA cache updates trigger inbound Route
Refresh for established peers whose resolved import policy matches validation
state, so previously denied routes can be reconsidered against the fresh
snapshot. Peers that are not established evaluate against the fresh snapshot
when they next receive routes.

Drop RPKI-invalid routes (recommended):

```toml
[[policy.export]]
match_rpki_validation = "invalid"
action = "deny"
```

Prefer valid routes with higher LOCAL_PREF:

```toml
[[policy.export]]
match_rpki_validation = "valid"
action = "permit"
set_local_pref = 200

[[policy.export]]
match_rpki_validation = "not_found"
action = "permit"
set_local_pref = 100
```

### Monitoring

Prometheus metrics exposed at the configured metrics endpoint:

| Metric | Description |
|--------|-------------|
| `bgp_rpki_vrp_count{af="ipv4\|ipv6"}` | Current VRP entries by address family |

See [ADR-0034](adr/0034-rpki-origin-validation.md) for design details.

---

## `[policy]`

Optional. Defines global import and export policy that applies to all neighbors
that do not declare their own per-neighbor policy.

### Inline policy (original syntax)

```toml
[[policy.import]]
prefix = "10.0.0.0/8"
ge = 8
le = 24
action = "permit"
set_local_pref = 150

[[policy.import]]
prefix = "0.0.0.0/0"
action = "deny"

[[policy.export]]
prefix = "172.16.0.0/12"
action = "deny"
```

### Named policy definitions

Named policies are reusable policy blocks defined under `[policy.definitions]`.
Each has a name, optional `default_action` (default: `"permit"`), and a list of
statements. The same named definitions and chain attachments can also be
managed at runtime through the gRPC `PolicyService`; successful mutations are
persisted back to TOML.

```toml
[policy.definitions.reject-bogons]
default_action = "deny"
[[policy.definitions.reject-bogons.statements]]
action = "permit"
prefix = "0.0.0.0/0"
ge = 8
le = 24

[policy.definitions.set-lp-customer]
[[policy.definitions.set-lp-customer.statements]]
action = "permit"
set_local_pref = 150

[policy.definitions.tag-ixp]
[[policy.definitions.tag-ixp.statements]]
action = "permit"
set_community_add = ["LC:65001:1:100"]
set_next_hop = "self"
```

| Field            | Type   | Required | Default    | Description                             |
|------------------|--------|----------|------------|-----------------------------------------|
| `default_action` | string | no       | `"permit"` | Action when no statement matches (`"permit"` or `"deny"`) |
| `statements`     | array  | no       | `[]`       | Policy statements (same schema as inline entries) |

### Neighbor sets

Neighbor sets are reusable peer identity groups for policy matching. They live
under `[policy.neighbor_sets.<name>]` and can match by exact neighbor address,
remote ASN, and/or peer-group name. A policy statement references one with
`match_neighbor_set = "..."`. Neighbor sets are also manageable at runtime via
the gRPC `PolicyService`.

```toml
[policy.neighbor_sets.ixp-clients]
addresses = ["10.0.0.2", "10.0.0.3"]
remote_asns = [65002, 65003]
peer_groups = ["rs-clients"]
```

### Policy chains

Policy chains reference named definitions by name, evaluated in order with
GoBGP-style semantics:

- **Permit** — accumulate route modifications, continue to next policy
- **Deny** — reject immediately, stop the chain
- **After all policies** — implicit permit with all accumulated modifications

Global chains:

```toml
[policy]
import_chain = ["reject-bogons", "set-lp-customer"]
export_chain = ["tag-ixp"]
```

Per-neighbor chains (override global):

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
import_policy_chain = ["reject-bogons", "set-lp-customer"]
export_policy_chain = ["tag-ixp"]
```

When multiple policies in a chain both set a scalar value (e.g. `set_local_pref`),
the later policy wins. List values (community add/remove) accumulate across the
chain.

**Mutual exclusion:** Inline policy and policy chain cannot both be set for the
same direction on the same neighbor. This is a config validation error.

### Import-decision explain (`[policy.explain]`)

Optional. Controls the per-session import-decision cache that backs
`PolicyService.ExplainImportPolicy` and `rbgp policy explain`
(ADR-0073). Every import evaluation — permit **and** deny — is recorded
at the transport eval site keyed by `(AFI, SAFI, prefix, path_id)`, so a
prefix that was denied and never reached the RIB stays explainable.

```toml
[policy.explain]
enabled = true
cache_size = 4096
```

| Field        | Type    | Required | Default | Description |
|--------------|---------|----------|---------|-------------|
| `enabled`    | bool    | no       | `true`  | Gates the cache write-path. When `false`, the inbound UPDATE path skips the compact decision/context snapshot entirely (one boolean check, nothing stored) and explain queries answer `not_seen`. Set `false` on perf-sensitive full-table peers. |
| `cache_size` | integer | no       | `4096`  | Per-peer LRU capacity, one entry per `(AFI, SAFI, prefix, path_id)`. The 4096 default suits fabric / partial-table peers; raise it for full-table peers. |

This is **diagnostic state only** — it never affects which routes are
accepted. Scope is IPv4 / IPv6 unicast. The cache resets on peer session
reset and is **not durable across restart** (for durable history use the
event-history outbox, ADR-0072). Both fields are **restart-required
per-peer** on reload; see [`reload-matrix.md`](reload-matrix.md) and the
"Explain an import decision" runbook in [`OPERATIONS.md`](OPERATIONS.md).

---

## Policy entries

Both global (`[[policy.import]]` / `[[policy.export]]`) and per-neighbor
(`[[neighbors.import_policy]]` / `[[neighbors.export_policy]]`) entries share
the same schema.

### Match conditions

Each entry must have at least one match condition. Multiple conditions on the
same entry are ANDed.

| Field                    | Type     | Required | Description                                           |
|--------------------------|----------|----------|-------------------------------------------------------|
| `prefix`                 | string   | no*      | Network prefix in CIDR notation (IPv4 or IPv6)        |
| `ge`                     | u8       | no       | Minimum prefix length to match (inclusive)            |
| `le`                     | u8       | no       | Maximum prefix length to match (inclusive)            |
| `match_community`        | [string] | no*      | Community match criteria (see below). OR within list. |
| `match_as_path`          | string   | no*      | AS_PATH regex (Cisco/Quagga style, `_` = boundary)    |
| `match_neighbor_set`     | string   | no*      | Named neighbor set matched against the evaluation peer |
| `match_route_type`       | string   | no*      | Route source type: `"local"`, `"internal"`, `"external"` |
| `match_as_path_length_ge`| u32      | no*      | Minimum AS_PATH length to match (inclusive)           |
| `match_as_path_length_le`| u32      | no*      | Maximum AS_PATH length to match (inclusive)           |
| `match_local_pref_ge`    | u32      | no*      | Minimum `LOCAL_PREF` to match (inclusive)             |
| `match_local_pref_le`    | u32      | no*      | Maximum `LOCAL_PREF` to match (inclusive)             |
| `match_med_ge`           | u32      | no*      | Minimum MED to match (inclusive)                      |
| `match_med_le`           | u32      | no*      | Maximum MED to match (inclusive)                      |
| `match_next_hop`         | string   | no*      | Exact next-hop IP address to match (unicast only)     |
| `match_rpki_validation`  | string   | no*      | RPKI state: `"valid"`, `"invalid"`, or `"not_found"` |
| `match_aspa_validation`  | string   | no*      | ASPA state: `"valid"`, `"invalid"`, or `"unknown"` |
| `action`                 | string   | yes      | `"permit"` or `"deny"`                                |

*At least one of `prefix`, `match_community`, `match_as_path`,
`match_neighbor_set`, `match_route_type`, `match_as_path_length_ge`,
`match_as_path_length_le`, `match_local_pref_ge`, `match_local_pref_le`,
`match_med_ge`, `match_med_le`, `match_next_hop`, or
`match_rpki_validation` / `match_aspa_validation` is required.

### Route modifications (set actions)

These fields modify matching routes. Only valid with `action = "permit"`.

| Field                  | Type        | Description                                        |
|------------------------|-------------|----------------------------------------------------|
| `set_local_pref`       | u32         | Set LOCAL_PREF on matching routes                  |
| `set_med`              | u32         | Set MED on matching routes                         |
| `set_next_hop`         | string      | `"self"` or an IP address                          |
| `set_community_add`    | [string]    | Communities to add (standard, EC, or LC format)    |
| `set_community_remove` | [string]    | Communities to remove                              |
| `set_as_path_prepend`  | table       | `{ asn = 65001, count = 3 }` (count 1-10)         |

### Community formats

The `match_community`, `set_community_add`, and `set_community_remove` fields
accept these formats:

| Format | Example | Type |
|--------|---------|------|
| `ASN:VALUE` | `"65001:100"` | Standard community |
| Well-known name | `"NO_EXPORT"`, `"NO_ADVERTISE"`, `"NO_EXPORT_SUBCONFED"`, `"BLACKHOLE"`, `"GRACEFUL_SHUTDOWN"` | Standard community |
| `RT:ASN:VALUE` | `"RT:65001:100"` | Extended community (route target) |
| `RO:ASN:VALUE` | `"RO:65001:200"` | Extended community (route origin) |
| `LC:G:L1:L2` | `"LC:65001:100:200"` | Large community (RFC 8092) |

### AS_PATH regex

The `match_as_path` field accepts regular expressions with the Cisco/Quagga `_`
boundary convention. `_` expands to `(?:^| |$|[{}])` before compilation, matching
the start of the string, a space between ASNs, the end of the string, or
`AS_SET` delimiters (`{`/`}`).

| Pattern | Matches |
|---------|---------|
| `^65100_` | AS_PATH starting with 65100 |
| `_65200$` | AS_PATH ending with 65200 |
| `_65300_` | AS_PATH containing 65300 |
| `^65100$` | AS_PATH that is exactly 65100 |

Entries are evaluated in order. The first matching entry wins. If no entry
matches, the default action is **permit**.

### AS_PATH length matching

Use `match_as_path_length_ge` / `match_as_path_length_le` to match routes by
inclusive AS_PATH length. Either field may be used independently or together
as a range. `AS_SET` counts as 1 per RFC 4271.

```toml
[[policy.import]]
match_as_path_length_ge = 3
match_as_path_length_le = 8
action = "deny"
```

### Neighbor-set, route-type, next-hop, and MED / `LOCAL_PREF` matching

`match_neighbor_set` evaluates against the peer currently being evaluated by
policy:

- import policy: the source peer that sent the route
- export policy: the destination peer receiving the route

`match_route_type` distinguishes:

- `"external"` — learned from an eBGP peer
- `"internal"` — learned from an iBGP peer
- `"local"` — locally injected or originated

`match_local_pref_*` and `match_med_*` are inclusive comparisons. When the
route does not carry the attribute on the wire (typical for `LOCAL_PREF` on
eBGP-received routes), the engine substitutes the RFC 4271 implicit defaults
— 100 for `LOCAL_PREF` (§5.1.5), 0 for `MED` (§5.1.4) — and matches against
those. A single policy `match_local_pref_ge = 100` therefore reads
identically against iBGP routes (LP attribute on the wire) and eBGP routes
(no LP on the wire). Matches FRR / BIRD / GoBGP convention. To match only
routes with an explicit attribute, pair the numeric match with
`match_route_type = "internal"` (LP) or a more specific filter.

`match_next_hop` is exact IP equality against the route's resolved next hop.
It applies to unicast routes. FlowSpec routes do not expose a policy-matchable
next hop because FlowSpec `MP_REACH_NLRI` carries NH length 0.

```toml
[[policy.export]]
match_neighbor_set = "ixp-clients"
match_route_type = "external"
match_next_hop = "2001:db8::1"
match_local_pref_ge = 200
match_med_le = 50
action = "permit"
set_community_add = ["65001:100"]
```

### Prefix length matching

Without `ge`/`le`, only exact prefix-length matches count. With them, a route
matches if its prefix falls within the given network *and* its mask length is
within `[ge, le]`.

Example -- deny all specifics of 10.0.0.0/8 longer than /24:

```toml
[[policy.import]]
prefix = "10.0.0.0/8"
ge = 25
le = 32
action = "deny"
```

---

## Policy resolution order

For each neighbor, import and export policies are resolved independently:

1. If the neighbor has a per-neighbor **policy chain** (`import_policy_chain` /
   `export_policy_chain`), that chain is used.
2. If the neighbor has per-neighbor **inline policy** (`[[neighbors.import_policy]]`
   or `[[neighbors.export_policy]]`), those are wrapped in a single-element chain.
3. Otherwise, the global **chain** (`import_chain` / `export_chain`) is used.
4. Otherwise, the global **inline policy** (`[[policy.import]]` / `[[policy.export]]`)
   is wrapped in a single-element chain.
5. If none of the above exist, all routes are permitted (no filtering).

Per-neighbor policy completely replaces the global policy for that direction --
the two are never merged. Inline and chain on the same neighbor/direction is a
config error.

---

## Complete example

A realistic configuration with three peers, policy actions, and community matching:

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

# gRPC defaults to a UDS at <runtime_state_dir>/grpc.sock when no listener
# is configured. Uncomment below to add a TCP listener (UDS stays active
# unless explicitly disabled with [global.telemetry.grpc_uds] enabled = false).
# [global.telemetry.grpc_tcp]
# address = "127.0.0.1:50051"
# token_file = "/etc/rustbgpd/grpc.token"

# Global import policy: deny default route and RFC 1918, permit up to /24
[[policy.import]]
prefix = "0.0.0.0/0"
action = "deny"

[[policy.import]]
prefix = "10.0.0.0/8"
le = 32
action = "deny"

[[policy.import]]
prefix = "172.16.0.0/12"
le = 32
action = "deny"

[[policy.import]]
prefix = "192.168.0.0/16"
le = 32
action = "deny"

# Prefer routes from AS 65100
[[policy.import]]
match_as_path = "^65100_"
action = "permit"
set_local_pref = 200

[[policy.import]]
prefix = "0.0.0.0/0"
le = 24
action = "permit"

# Upstream provider -- uses global import policy, custom export with prepend
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "upstream-provider"
hold_time = 90
max_prefixes = 50000

[[neighbors.export_policy]]
prefix = "192.168.1.0/24"
action = "permit"
set_as_path_prepend = { asn = 65001, count = 2 }

[[neighbors.export_policy]]
prefix = "192.168.2.0/24"
action = "permit"

[[neighbors.export_policy]]
prefix = "0.0.0.0/0"
le = 32
action = "deny"

# IXP route server -- tag routes with large community, next-hop self
[[neighbors]]
address = "10.0.1.2"
remote_asn = 65100
description = "ixp-rs1"
hold_time = 90

[[neighbors.export_policy]]
action = "permit"
prefix = "0.0.0.0/0"
le = 24
set_next_hop = "self"
set_community_add = ["LC:65001:1:100"]

# eBGP peer with MD5 auth -- per-peer import to reject specifics
[[neighbors]]
address = "10.0.2.2"
remote_asn = 65200
description = "peer-secure"
hold_time = 180
md5_password = "s3cret"
ttl_security = true
max_prefixes = 10000

[[neighbors.import_policy]]
prefix = "10.0.0.0/8"
ge = 25
le = 32
action = "deny"

[[neighbors.import_policy]]
prefix = "0.0.0.0/0"
le = 24
action = "permit"
set_med = 50
```

---

## `[bmp]`

Optional. Configures BMP (BGP Monitoring Protocol, RFC 7854) export to external
collectors. rustbgpd acts as a BMP client, initiating TCP connections to each
configured collector and streaming BGP state changes (peer up/down, route
monitoring) as BMP messages.

```toml
[bmp]
sys_name = "rustbgpd"          # optional, default "rustbgpd"
sys_descr = "my bgp speaker"   # optional, default "rustbgpd <version>"

[[bmp.collectors]]
address = "10.0.0.100:11019"
reconnect_interval = 30        # seconds, default 30

[[bmp.collectors]]
address = "10.0.0.101:11019"
```

### BMP section fields

| Field       | Type   | Required | Default      | Description                          |
|-------------|--------|----------|--------------|--------------------------------------|
| `sys_name`  | string | no       | `"rustbgpd"` | System name in BMP Initiation message |
| `sys_descr` | string | no       | version string | System description in BMP Initiation message |
| `collectors`| array  | no       | `[]`         | List of BMP collector endpoints       |

### Collector fields

| Field                | Type   | Required | Default | Description                          |
|----------------------|--------|----------|---------|--------------------------------------|
| `address`            | string | yes      | --      | Collector `host:port` socket address  |
| `reconnect_interval` | u64   | no       | 30      | Seconds between reconnect attempts    |

### What is streamed

BMP messages sent to collectors:

| Message | When |
|---------|------|
| **Initiation** (Type 4) | On TCP connect to collector |
| **Peer Up** (Type 3) | BGP session reaches Established (includes raw OPEN PDUs) |
| **Peer Down** (Type 2) | BGP session leaves Established |
| **Route Monitoring** (Type 0) | Inbound UPDATE received (pre-policy, raw PDU) |
| **Stats Report** (Type 1) | Periodic per-peer export every 60s (Adj-RIB-In route count, type 7) |
| **Termination** (Type 5) | On coordinated daemon shutdown (and on client channel shutdown) |

Route Monitoring messages carry the original raw BGP UPDATE PDU bytes
(including the 19-byte BGP header), enabling collectors to decode the full
UPDATE without loss.

When BMP is not configured, overhead remains minimal: raw frame capture uses
`Bytes` refcount clones (no message-data copy).

---

## `[mrt]`

Optional. Configures periodic MRT TABLE_DUMP_V2 (RFC 6396) RIB snapshots for
offline analysis and archival. Dumps can also be triggered on demand via the
gRPC `TriggerMrtDump` RPC or the `rbgp mrt-dump` CLI command.

```toml
[mrt]
output_dir = "/var/lib/rustbgpd/mrt"
dump_interval = 7200        # seconds between periodic dumps (default 7200)
compress = true             # gzip output files (default false)
file_prefix = "rib"         # filename prefix (default "rib")
```

### MRT section fields

| Field           | Type    | Required | Default  | Description                              |
|-----------------|---------|----------|----------|------------------------------------------|
| `output_dir`    | string  | yes      | --       | Directory for MRT dump files (must exist and be writable) |
| `dump_interval` | u64     | no       | 7200     | Seconds between periodic dumps (must be > 0) |
| `compress`      | bool    | no       | false    | Compress output files with gzip           |
| `file_prefix`   | string  | no       | `"rib"`  | Filename prefix for dump files            |

### Output files

Dump files are written atomically (temp file + rename) with collision-resistant
names:

```
{file_prefix}.{YYYYMMDD.HHMMSS}.{nanoseconds}.mrt[.gz]
```

For example: `rib.20260305.143022.123456789.mrt.gz`

### What is dumped

Each dump contains a complete `TABLE_DUMP_V2` snapshot:

| Record | Contents |
|--------|----------|
| `PEER_INDEX_TABLE` (subtype 1) | All known peers with ASN and BGP ID |
| `RIB_IPV4_UNICAST` (subtype 2) | IPv4 routes from Adj-RIB-In per peer |
| `RIB_IPV6_UNICAST` (subtype 4) | IPv6 routes from Adj-RIB-In per peer |
| `RIB_IPV4_UNICAST_ADDPATH` (subtype 8) | IPv4 routes with path IDs (RFC 8050) |
| `RIB_IPV6_UNICAST_ADDPATH` (subtype 9) | IPv6 routes with path IDs (RFC 8050) |

Routes are sourced from Adj-RIB-In (not Loc-RIB) to avoid duplicate entries
for the best-path winner. Next-hop attributes are synthesized per the MP-BGP
architecture (IPv4 `NEXT_HOP`, IPv6 `MP_REACH_NLRI`, RFC 8950
IPv4-with-IPv6-NH `MP_REACH_NLRI`).

Peer metadata is retained during Graceful Restart and LLGR transitions, so
dumps taken during a peer restart window still include correct peer entries.

When MRT is not configured, no timer or manager task is spawned — zero
overhead.

See [ADR-0044](adr/0044-mrt-dump-export.md) for design details.

---

## `[[fib_tables]]`

Optional, repeatable. Declares ordinary Linux route tables that the
ADR-0061 general unicast FIB runtime may program. Empty by default —
route-server, route-reflector, and looking-glass deployments leave it
empty and remain control-plane-only.

```toml
[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
families = ["ipv4_unicast", "ipv6_unicast"]
allowed_peer_groups = ["transit"]
allowed_neighbors = ["198.51.100.2"]
max_routes = 1000
```

When at least one table is configured on Linux, rustbgpd starts a
level-triggered reconciler that projects Loc-RIB best routes into the
declared tables only. The actor preserves foreign kernel rows, writes
routes as `RTPROT_BGP` with the configured table and metric, drains
daemon-owned rows on coordinated shutdown, and publishes per-route
status through `RibService.ListFibRoutes` and
`rbgp rib fib`. The actor also writes a crash-recovery owned-state
file at `<runtime_state_dir>/fib-owned.json` so an ungraceful process
restart can recover routes the previous rustbgpd instance installed.

Peer and route-count guardrails are enforced before any kernel apply.
If `allowed_peer_groups` or `allowed_neighbors` is non-empty, a best
route is eligible when its source peer matches either allow-list. If
`max_routes` is set and the eligible route count for that table exceeds
the cap, the table freezes for that pass: already-owned rows stay in
place, no new growth or replacements are emitted, and over-cap candidates
that are not already owned are reported as `route_limit_exceeded`. The
rejected status list is sampled for very large over-cap tables so the cap
does not produce an unbounded API payload.
`allowed_neighbors` entries are not required to appear in `[[neighbors]]`;
this keeps the knob usable for dynamic-neighbor ranges and staged peers.

`RTPROT_BGP` is not treated as ownership proof by itself. A route that
already exists in a configured table before this daemon instance owns it
is reported as `foreign_route_exists`, even if its protocol is BGP. Crash
recovery uses the persisted owned-state file, the unchanged `[[fib_tables]]`
declaration, and an exact live-kernel value match; if any of those checks
fail, the row stays foreign. Unsupported or config-stale state files are
quarantined as `fib-owned.json.stale`. This conservative rule avoids
replacing or deleting FRR/BIRD routes in the same table and metric.
If another writer changes a row while rustbgpd owns it, the next reconcile
reports `owned_route_drifted`, releases ownership, and preserves the live
kernel row.

### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | -- | Operator-facing table name used in status output. Must be unique and match rustbgpd's identifier rules |
| `table_id` | u32 | yes | -- | Linux route table id. Must be unique and cannot be `0`, `252`, `253`, `254`, or `255` |
| `metric` | u32 | yes | -- | Kernel route metric / priority. Part of the daemon-owned route identity |
| `families` | string[] | no | `["ipv4_unicast", "ipv6_unicast"]` | Address families eligible for install. Only IPv4 and IPv6 unicast are accepted |
| `allowed_peer_groups` | string[] | no | `[]` | Optional source peer-group allow-list. Entries must reference existing `[peer_groups.NAME]` blocks |
| `allowed_neighbors` | string[] | no | `[]` | Optional source neighbor-address allow-list. Entries must parse as IPv4 or IPv6 addresses |
| `max_routes` | u32 | no | unset | Optional hard cap. `0` is rejected; exceeding the cap freezes existing owned rows and suppresses growth for that table |
| `maximum_paths` | u32 | no | `1` | Unicast multipath/ECMP: install up to N equal-cost next-hops per prefix as a kernel `RTA_MULTIPATH` route (ADR-0066). `1` (or unset) = single next-hop, today's behavior. Validated `>= 1`, capped at 256 |
| `maximum_paths_ebgp` | u32 | no | unset | Per-class ECMP cap for **eBGP** groups (FRR's `maximum-paths`). Overrides `maximum_paths` for eBGP best routes; falls back to `maximum_paths` then `1`. Validated `>= 1`, capped at 256 |
| `maximum_paths_ibgp` | u32 | no | unset | Per-class ECMP cap for **iBGP** groups (FRR's `maximum-paths ibgp`). Overrides `maximum_paths` for iBGP best routes; falls back to `maximum_paths` then `1`. Validated `>= 1`, capped at 256 |

**SIGHUP hot-reload** (when the FIB runtime is running): edits to
`[[fib_tables]]` — adding or removing a table, or changing a table's
`allowed_neighbors`, `allowed_peer_groups`, `max_routes`, ECMP caps, or
`families` — are applied to the running reconciler on SIGHUP **without a
restart**, provided at least one table was present at startup (so the
reconciler actor is alive). The reconciler swaps to the new desired set and
reconciles: added tables back-fill from the current best routes, removed
tables have their owned kernel rows withdrawn, and unaffected rows don't flap.
The in-memory config snapshot advances only **after** the reconciler
acknowledges the new set, so a missed apply never leaves the snapshot ahead of
the kernel.

**Restart still required to *start* the FIB subsystem from an empty config**:
if no `[[fib_tables]]` were present at startup the reconciler was never spawned,
so adding the first table needs a restart (SIGHUP logs this and leaves the
runtime unchanged). Deleting all tables at runtime is fine — the actor stays
alive but idle, and re-adding a table later hot-applies.

**gRPC / CLI runtime CRUD** (same lifecycle rules as SIGHUP): `RibService`
exposes `SetFibTable` (create-or-replace by name — the request carries the full
table definition, not a patch), `DeleteFibTable`, and `ListFibTables`, surfaced
as `rbgp fib-table {list,set,delete}`. A `set` that changes `table_id` or
`metric` for an existing name is a table-key move: the old kernel rows withdraw
and the new table back-fills. The candidate is validated against the live config
(reserved/duplicate ids, families, ECMP caps, peer-group references) before it
reaches the reconciler, applied through the same hot-reload path, and persisted
to the TOML config (atomic write) **only after** the reconciler acknowledges the
exact accepted set — and runtime CRUD is serialized with SIGHUP reloads through
one coordinator lock, so runtime and on-disk config cannot drift. The mutating
RPCs require the reconciler to be running (return `FAILED_PRECONDITION`
otherwise) and are tier `mutating`; `ListFibTables` is `sensitive_read` and also
reports whether the reconciler is running.

**Config transactions** (ADR-0076): `ConfigService.PlanConfigTransaction` can
validate a complete candidate TOML and return an optimistic runtime snapshot
token; `ApplyConfigTransaction` commits one pure runtime family at a time:
full-set `[[fib_tables]]`, full-set `[[dynamic_neighbors]]`, static
`[[neighbors]]` add/delete/modify, catalog-only
policy/neighbor-set/peer-group/global-chain changes, or pure live policy-chain
impact for static neighbors and accepted dynamic peers. Peer-group/session
reshape impact is also committable — for example a peer-group `hold_time` edit
or a static neighbor peer-group reassignment that requires the affected
sessions to be rebuilt. Static members are reconfigured in place with captured
prior configs; live dynamic sessions accepted by an affected
`[[dynamic_neighbors]]` range are gracefully reset after persist and re-accept
under the committed config on reconnect (ADR-0086). The apply path re-checks
the token under the shared runtime-config coordinator, rejects mixed or
unsupported candidates without mutation, applies live runtime state when the
family has one, persists the exact accepted candidate with an acknowledgement,
and rolls runtime state back if apply or persistence fails. Live policy-chain
impact uses Route Refresh to re-evaluate already-received routes, so every
impacted Established peer must have negotiated Route Refresh or the transaction
is rejected and rolled back. Dynamic-range peer-group reassignments and mixed
policy/session effective-impact candidates remain rejected until dedicated
executors exist.
Like SIGHUP and FIB CRUD, FIB transaction apply requires the FIB reconciler to
already be running: a daemon that started with no `[[fib_tables]]` still needs a
restart to enable the subsystem.
Operators can drive the workflow through `rbgp config plan --from-file`
and `rbgp config apply --from-file --expected-runtime-snapshot-token`;
`--json` returns the same status, section, and token fields for automation.
For safe deploys, `ApplyConfigTransaction` also supports a confirmed-commit
mode: add `--confirm-id <id>` (and optionally `--confirm-timeout <seconds>`) to
the normal apply invocation — `rbgp config apply --from-file <config.toml>
--expected-runtime-snapshot-token <token> --confirm-id <id> --confirm-timeout
<seconds>` — or set the matching gRPC fields directly. The confirm flags are
additions; `--from-file` and `--expected-runtime-snapshot-token` are still
required. The timeout defaults to 600 seconds
and is capped at 86400. The change applies immediately, then remains pending
until `rbgp config confirm <id>` (or `ConfirmConfigTransaction`) makes it
permanent. `rbgp config abort <id>` rolls it back immediately, and an
expired timer automatically re-applies the pre-commit runtime snapshot through
the same transaction executor. While a confirmed transaction is applying or
pending, persisted runtime config mutators such as static/dynamic neighbor CRUD,
policy/peer-group CRUD, FIB-table CRUD, and another config transaction are
rejected with `FAILED_PRECONDITION`; SIGHUP reload is skipped and logged until
the transaction is confirmed, aborted, or auto-reverted. Use
`rbgp config status` to inspect the redacted pending or last
confirmed-transaction state. If abort or timer rollback fails, status records
the failed lifecycle result and clears the pending fence so operators can apply
a corrective transaction instead of leaving runtime config mutations blocked
indefinitely.

Confirm handles are operator-chosen correlation IDs. They must be non-empty, at
most 128 characters, and free of control characters; the CLI validates those
constraints before reading the candidate file or calling the daemon.

```console
$ rbgp fib-table set edge --table-id 1000 --metric 200 \
    --families ipv4_unicast,ipv6_unicast --max-routes 50000
$ rbgp fib-table list
$ rbgp fib-table delete edge
```

---

## `[[evpn_instances]]`

Optional, repeatable. Declares the local L2VNI / EVPN-instance tenants
this VTEP serves (Gate 7a foundation, ADR-0052 + ADR-0055). Empty by
default — RR-only deployments leave it empty.

> rustbgpd is observe-only for kernel netdevs: you provision the bridge
> and VXLAN port yourself, and the daemon probes them (ADR-0054 §4). See
> [docs/evpn-vtep-setup.md](evpn-vtep-setup.md) for the `ip link` recipe;
> the `bridge` / `local_vtep_ip` fields below must match. ADR-0088 keeps
> rustbgpd-managed bridge / VXLAN / VRF creation fail-closed until explicit
> ownership exists; ADR-0089 enables the first VLAN-aware bridge programming
> target through a local bridge-VLAN / VNI binding while keeping EVPN
> Ethernet Tag ID at `0`.

```toml
[[evpn_instances]]
vni = 100
rd = "10.0.0.1:100"
route_targets = ["65000:100"]
auto_derive_route_target = false        # derive RFC 8365 VXLAN RT from [global].asn + VNI when true
local_vtep_ip = "10.0.0.1"
bridge = "br100"                       # Linux bridge name (optional — RR-only deployments omit)
bridge_vlan = 100                      # local Linux VLAN selector for ADR-0089 VLAN-aware bridge attribution
advertise_svi_mac = false              # originate Type 2 for the bridge's own MAC (RFC 9135 §6.1)
sticky_macs = ["aa:bb:cc:dd:ee:01"]    # MACs to originate with RFC 7432 §15.4 sticky bit (ADR-0056)
ip_vrf = "vrf1"                        # link this L2VNI to a declared [[evpn_ip_vrfs]] entry (Gate 9 / ADR-0058)
apply_aliasing_ecmp = true             # program FDB nexthop groups for multi-homed Type 2 (ADR-0059)
duplicate_mac_detection = { action = "detect", window_seconds = 180, threshold = 5, recovery_seconds = 540 }
```

### Fields

| Field                 | Type     | Required | Default | Description |
|-----------------------|----------|----------|---------|-------------|
| `vni`                 | u32      | yes      | --      | 24-bit VNI (RFC 8365 §5) |
| `rd`                  | string   | yes      | --      | Route Distinguisher in RFC 4364 form (`asn:value`, `ipv4:value`, or 4-octet AS variants) |
| `route_targets`       | string[] | yes*     | `[]`    | One or more EVPN Route Targets in the same encodings. Required unless `auto_derive_route_target = true` |
| `auto_derive_route_target` | bool | no | `false` | Append the RFC 8365 §5.1.2.1 VXLAN auto-derived Route Target using `[global].asn` and `vni` (`2-octet AS only`) |
| `local_vtep_ip`       | string   | yes      | --      | Source IP for VXLAN encap on this VTEP |
| `bridge`              | string   | no       | --      | Linux bridge name for kernel reconciliation. Omit for RR-only deployments. Without `bridge_vlan`, a `Ready` L2VNI requires a non-VLAN-aware bridge with exactly one VXLAN port carrying `nolearning`; with `bridge_vlan`, it requires a traditional `vlan_filtering=1` bridge whose matching VXLAN member carries the configured VLAN |
| `bridge_vlan`         | u32      | no       | --      | Local Linux bridge VLAN selector (`1..=4094`) for ADR-0089 VLAN-aware bridge attribution. Valid only with `bridge`; this is **not** an EVPN Ethernet Tag, EVPN routes still use Ethernet Tag ID `0`, and FDB writes plus AF_BRIDGE local-MAC observations for this instance are scoped with `NDA_VLAN` |
| `advertise_svi_mac`   | bool     | no       | `false` | Originate a Type 2 route for the bridge's own MAC (RFC 9135 §6.1) when the instance has a Ready bridge report |
| `sticky_macs`         | string[] | no       | `[]`    | MAC addresses to originate with the RFC 7432 §15.4 sticky bit; SVI MAC origination honors the same list (ADR-0056) |
| `ip_vrf`              | string   | no       | --      | Name of an `[[evpn_ip_vrfs]]` entry to link this L2VNI to (Gate 9 IRB binding) |
| `apply_aliasing_ecmp` | bool     | no       | `true`  | Program ADR-0059 FDB nexthop groups for multi-homed Type 2 routes (aliasing-ECMP via `NDA_NH_ID` + `NHA_FDB`). Flip to `false` to roll this L2VNI back to single-dst FDB rows at the primary VTEP. Single-homed Type 2 entries are unaffected |
| `duplicate_mac_detection` | table | no | `{ action = "detect", window_seconds = 180, threshold = 5, recovery_seconds = 540 }` | RFC 7432 §15.1 duplicate-MAC M/N detector. `action = "detect"` records threshold crossings only; `action = "suppress_local"` additionally withdraws/suppresses locally-originated Type 2 MAC-only and MAC+IP routes for the offending `(VNI, MAC)` until `recovery_seconds` elapses |

### Validation

- The combined table enforces uniqueness on both `vni` and `rd` —
  duplicates on either column reject config load.
- `bridge` (when set) must reference a Linux bridge created out of
  band; rustbgpd does not create/delete netdevs (ADR-0054 §4 and
  ADR-0088).
- `bridge_vlan` (when set) must be in `1..=4094` and requires
  `bridge`. At runtime it selects the ADR-0089 VLAN-aware path: the
  observed bridge must have `vlan_filtering=1`, the configured VLAN
  present on the bridge, and exactly one matching VXLAN target. A
  target can be either a fixed-VNI VXLAN member carrying the VLAN, or
  a collect-metadata / SVD VXLAN member whose VLAN tunnel mapping ties
  that VLAN to the instance VNI. Without `bridge_vlan`, a
  `vlan_filtering=1` bridge remains `NotReady`.
- `advertise_svi_mac = true` is inert until the instance has a Ready
  bridge report with a bridge MAC; configs without `bridge` are accepted
  but originate nothing.
- `route_targets` may be omitted or empty only when
  `auto_derive_route_target = true`; otherwise at least one explicit RT is
  required.
- `auto_derive_route_target = true` requires `[global].asn <= 65535`. RFC
  8365 §5.1.2.1 does not define an auto-derived VXLAN RT for 4-octet ASNs,
  so those deployments must configure `route_targets` manually.
- `ip_vrf` (when set) must name an `[[evpn_ip_vrfs]]` entry declared
  in the same config.
- `duplicate_mac_detection.window_seconds`, `threshold`, and
  `recovery_seconds` must all be greater than zero.
- `duplicate_mac_detection.recovery_seconds` must be no greater than
  31,536,000 seconds (365 days).
- Same VNI must not appear in multiple `[[ethernet_segments]]`
  `member_vnis` lists until per-port learned disambiguation is plumbed.

The auto-derived RT form depends on the VNI's scope:

- **L2VNI / MAC-VRF** (`[[evpn_instances]]`): the RFC 8365 §5.1.2.1 *opaque*
  2-octet-AS RT with local-admin value `0x10000000 | vni`. For example
  `[global].asn = 65000`, `vni = 100` → `65000:268435556`.
- **L3VNI / IP-VRF** (`[[evpn_ip_vrfs]]`): a plain `AS:VNI` 2-octet-AS RT.
  For example `[global].asn = 65000`, `vni = 100` → `65000:100`.

Explicit `route_targets` are preserved; when auto-derive is also enabled the
derived RT is appended and duplicates are deduped during config resolution.

**Cross-vendor interop.** The two forms exist because that is what FRR (and
Cumulus/NVIDIA) actually put on the wire:

- For the **L3VNI / IP-VRF** RT, FRR's tenant-VRF auto-RT is `AS:VNI`
  regardless of any knob, so rustbgpd's `AS:VNI` form imports against a
  default FRR L3VNI peer with no extra configuration. (Validated by the
  M39b interop smoke.)
- For the **L2VNI / MAC-VRF** RT, rustbgpd uses the RFC 8365 opaque form,
  which matches FRR **only** when FRR is configured with `autort
  rfc8365-compatible` (under `address-family l2vpn evpn`). FRR's *default*
  L2VNI autort is `AS:VNI`, which would not match. rustbgpd-to-rustbgpd
  fabrics always agree. When peering an L2VNI with a vendor whose auto-RT
  form you are unsure of, configure `route_targets` explicitly on both ends.

### Duplicate-MAC Detection And Local Suppression

RFC 7432 §15.1 describes duplicate-MAC detection as `N` mobility
events within `M` seconds, with defaults `N = 5` and `M = 180s`.
rustbgpd applies that window per `(VNI, MAC)` inside the local
originator.

Default behavior is detection-only:

```toml
duplicate_mac_detection = { action = "detect" }
```

With `action = "suppress_local"`, crossing the threshold withdraws any
locally-originated Type 2 routes for that MAC on this VNI (MAC-only and
MAC+IP), suppresses future local originations while the quarantine is
active, and automatically retries after `recovery_seconds`:

```toml
duplicate_mac_detection = { action = "suppress_local", window_seconds = 180, threshold = 5, recovery_seconds = 540 }
```

This first action slice is intentionally local-origin scoped. The EVPN
Loc-RIB, route-reflector behavior, `ListEvpnRoutes`, and receive-side
dataplane projection remain visible/unchanged; full remote-route
processing suppression and dataplane loop-protection are tracked as
follow-up work.

### Aliasing-ECMP off-switch behavior

`apply_aliasing_ecmp = false` routes multi-homed Type 2 entries on the
target L2VNI through the single-dst FDB path (primary VTEP only, no
kernel-side ECMP); other L2VNIs in the same daemon are unaffected.

**Runtime mutation and reload behavior**: ADR-0063's coordinator
live-commits supported `[[evpn_instances]]` changes through both
`EvpnService.ApplyEvpnRuntime` and SIGHUP reload. A redefine, including
field flips such as `bridge_vlan` or `apply_aliasing_ecmp`, re-derives per-VNI dataplane
state via the `FdbNhg → SingleDst` transition. Supported shapes include
single L2VNI/IP-VRF/Ethernet-Segment add/delete/redefine, additive
build-up, atomic tenant teardown, `ip_vrf` relink, and L2VNI-only
add/delete/redefine compositions. L3VNI/device/table IP-VRF identity
changes are restart-required by design, and ES/IP-VRF row mixed edits
outside the L2VNI-only composer fail closed — split those changes into
supported requests (<https://github.com/lance0/rustbgpd/issues/268>).

**Restart edge case**: if you flip `apply_aliasing_ecmp = false` and
restart the daemon while tagged FDB nexthop groups from the prior run
are still in the kernel, the orphaned tagged FDB rows remain bound to
the stale `nh_id` until the next periodic drift cycle cleans them up
(≤ 60 s, ADR-0059 slice 3.5 PR 2).

---

## `[[ethernet_segments]]`

Optional, repeatable. Declares local Ethernet Segments for active-active
multi-homing (Gate 8 + 8b, RFC 7432 §8 + RFC 8584 + ADR-0057). Empty by
default — single-homed VTEPs leave it empty.

```toml
[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"          # 10-byte ESI (Type 0 here; Types 1–5 also accepted)
member_vnis = [100, 200]                       # L2VNIs this ES is reachable on
df_preference = 32768                          # RFC 9785 preference; default/HRW require this default
df_algorithm = "default-modulo"                # default-modulo, highest-random-weight, highest-preference, or lowest-preference
redundancy_mode = "all-active"                 # "all-active" or "single-active"
originator_ip = "10.0.0.1"                     # source IP used for Type 1/4 origination
```

### Fields

| Field           | Type     | Required | Default       | Description |
|-----------------|----------|----------|---------------|-------------|
| `esi`           | string   | yes      | --            | 10-byte non-zero ESI in colon-separated hex (RFC 7432 §5). The all-zero Type 0 single-homed sentinel is rejected; non-zero Type 0 and Types 1–5 are accepted. |
| `member_vnis`   | u32[]    | yes      | --            | L2VNIs this segment is reachable on. Each must match a configured `[[evpn_instances]].vni` |
| `df_preference` | u32      | no       | `32768`       | RFC 9785 preference value for `"highest-preference"` / `"lowest-preference"` (`0..=65535`). Default-modulo and HRW ignore preference, so only the default is accepted for those algorithms |
| `df_algorithm`  | string   | no       | `"default-modulo"` | `"default-modulo"` (RFC 7432 §8.5 service carving), `"highest-random-weight"` (RFC 8584 §3.2), `"highest-preference"` or `"lowest-preference"` (RFC 9785) |
| `df_dont_preempt` | bool   | no       | `false`       | RFC 9785 Don't-Preempt (non-revertive): when `true`, advertise DP=1 in the Type 4 DF Election extcomm. Only valid with `"highest-preference"` / `"lowest-preference"` — rejected for default-modulo / HRW. Origination + parse only today: the DP bit is not yet an election input (stateful non-revertive election is deferred), so a peer's DP=1 does not currently change which PE rustbgpd elects. |
| `redundancy_mode` | string | no       | `"all-active"` | `"all-active"` sets the ESI Label extcomm Single-Active flag to 0 and allows receiver-side aliasing ECMP. `"single-active"` sets the flag to 1, suppresses all-active aliasing ECMP for remote single-active ES reachability, and enables the receive-side backup-path pre-install path from ADR-0083 |
| `originator_ip` | string   | yes      | --            | Source IP carried in Type 1/4 origination. Usually equals a member VNI's `local_vtep_ip` |

### What gets originated

When `[[ethernet_segments]]` is non-empty and the EVPN reconcile actor
is running, each segment originates:

- **Type 4 (ES route)** — one per `[[ethernet_segments]]` block, with
  ES-Import Route Target derived from the ESI per RFC 7432 §7.6.
- **Type 1 EAD-per-ES** — one per ES with `ethernet_tag = MAX_ET` and
  the ESI label (assigned by `EsiLabelAllocator`, ADR-0057 §6) in the
  ESI Label extended community.
- **Type 1 EAD-per-EVI** — one per `(ES, member_vni)` pair, with
  `ethernet_tag = 0` (RFC 7432 §6.1 VLAN-based service) and the member
  VNI in the route's label field (RFC 8365 §5.1.3). The per-VNI RD
  keeps the routes distinct.

The DF election runs on the union of locally configured ES and
remote Type 4 routes for the same ESI; the elected DF role drives
Type 2 origination ESI tagging and the optional BUM-suppression
filter (see `apply_bum_enforcement` in `[global]`).

SIGHUP reload and `EvpnService.ApplyEvpnRuntime` can live-commit a single
Ethernet Segment add, delete, or redefine when the segment actor exists,
additive build-up, and dropping an Ethernet Segment (delete or member-shrink)
as part of an atomic tenant teardown alongside its member L2VNI. Generic mixed
add/delete/redefine edits still fail closed.

---

## `[[evpn_ip_vrfs]]`

Optional, repeatable. Declares the local IP-VRF / L3VNI tenants this VTEP
serves under the RFC 9136 §4.4.2 symmetric Interface-less IRB model
(Gate 9, ADR-0058). Empty by default — L2-only VTEPs and RR-only
deployments leave it empty.

> rustbgpd is observe-only for kernel netdevs: you provision the VRF and
> L3 VXLAN devices yourself, and the daemon probes them against the seven
> ADR-0058 §3 predicates. See [docs/evpn-vtep-setup.md](evpn-vtep-setup.md)
> for the `ip link` recipe the fields below must match.

The daemon parses and validates this block, builds an `IpVrfTable`,
runs the per-pass `IpVrfStatus` readiness probe (the seven ADR-0058
§3 predicates), originates Type 5 routes from observed local
forwarding routes when the IP-VRF is `Ready`, imports remote Type 5
routes through the transactional `L3OwnedState` model, and programs
kernel routes + L3 neighbor + L3VXLAN FDB rows atomically with
four-phase apply ordering (route-remove → resolution-add → route-add
→ resolution-remove) and Router MAC conflict detection. Operators
read readiness, originated-route count, and installed-route count
via `rbgp evpn vrfs [NAME]` and the `EvpnService.ListIpVrfs` /
`EvpnService.GetIpVrf` gRPC RPCs. Sub-second tenant withdraw is
driven by `RTNLGRP_IPV4_ROUTE` / `RTNLGRP_IPV6_ROUTE` multicast.

```toml
[[evpn_ip_vrfs]]
name = "tenant-blue"               # operator-facing handle
vni = 5000                         # L3VNI (1..=16_777_215)
rd = "65000:5000"                  # Route Distinguisher
route_targets = ["65000:5000"]     # bidirectional RTs (non-empty)
auto_derive_route_target = false   # derive AS:VNI RT from [global].asn + L3VNI when true (FRR-compatible)
local_vtep_ip = "10.0.0.1"         # VXLAN source IP for outbound Type 5
router_mac = "02:00:00:00:00:01"   # Router MAC ext-community value
vrf_device = "vrf-blue"            # Linux VRF device (observe-only)
l3vxlan_device = "vni5000"         # Linux L3 VXLAN device (observe-only)
table_id = 5000                    # VRF route table id
overlay_index_mode = "interface_less" # "interface_less", "gateway_ip", or "esi" (ADR-0087)
# overlay_index_esi = "00:00:00:00:00:00:00:00:00:01" # required when mode = "esi"
# overlay_index_mac = "02:aa:bb:cc:dd:ee"             # required when mode = "esi"
# overlay_index_l2vni = 100                            # required for ESI mode only when multiple L2VNIs link here

# An `[[evpn_instances]]` entry binds to this IP-VRF by name.
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"             # optional — empty means L2-only
```

### IP-VRF fields

| Field            | Type      | Required | Default | Description |
|------------------|-----------|----------|---------|-------------|
| `name`           | string    | yes      | --      | Operator handle; `^[a-zA-Z][a-zA-Z0-9_-]*$`, unique across `[[evpn_ip_vrfs]]` |
| `vni`            | u32       | yes      | --      | L3VNI in `1..=16_777_215`; must not collide with any `[[evpn_instances]]` VNI |
| `rd`             | string    | yes      | --      | Route Distinguisher (`asn:value` or `ipv4:value`) |
| `route_targets`  | [string]  | yes*     | `[]`    | Bidirectional RTs applied to import and export. Required unless `auto_derive_route_target = true` |
| `auto_derive_route_target` | bool | no | `false` | Append the auto-derived L3VNI RT as plain `AS:VNI` from `[global].asn` and the L3VNI — matches FRR's default tenant-VRF auto-RT (`2-octet AS only`) |
| `local_vtep_ip`  | string    | yes      | --      | Unicast VTEP source IP for outbound Type 5 `NEXT_HOP` |
| `router_mac`     | string    | yes      | --      | Unicast non-zero MAC (`aa:bb:cc:dd:ee:ff`) advertised via the RFC 9135 §4.2 / RFC 9136 Router MAC extended community |
| `vrf_device`     | string    | yes      | --      | Linux VRF device name (operator-managed, observe-only) |
| `l3vxlan_device` | string    | yes      | --      | Linux L3 VXLAN device name (operator-managed, observe-only) |
| `table_id`       | u32       | yes      | --      | VRF route table id (> 0); cross-checked against `vrf_device`'s `IFLA_VRF_TABLE` |
| `overlay_index_mode` | string | no      | `"interface_less"` | Outbound Type 5 overlay-index shape (ADR-0087). `"interface_less"` (RFC 9136 §4.4.2) keeps the Gateway Address zero + Router's MAC extcomm. `"gateway_ip"` (RFC 9136 §4.1/§4.2) originates a route whose kernel via lands on a connected subnet of this VRF with that via in the Gateway Address and no Router's MAC extcomm; routes without an eligible via fall back to interface-less. `"esi"` (RFC 9136 §4.3) originates with a configured non-zero ESI, zero Gateway Address, and `overlay_index_mac` as the Router MAC extcomm. `"gateway_ip"` and `"esi"` require at least one `ip_vrf`-linked L2VNI |
| `overlay_index_esi` | string | `esi` only | -- | Non-zero ESI (`xx:xx:xx:xx:xx:xx:xx:xx:xx:xx`) used as the Type 5 overlay index when `overlay_index_mode = "esi"`; must match a configured `[[ethernet_segments]].esi` |
| `overlay_index_mac` | string | `esi` only | -- | Unicast non-zero virtual/transit MAC advertised as the Router MAC extcomm when `overlay_index_mode = "esi"` |
| `overlay_index_l2vni` | u32 | conditional | -- | L2VNI disambiguator for `overlay_index_mode = "esi"` when multiple `[[evpn_instances]]` entries link to this IP-VRF; the selected L2VNI must be linked to this IP-VRF and be a member of `overlay_index_esi` |

### L2VNI binding

`[[evpn_instances]].ip_vrf` is an optional string that names an
`[[evpn_ip_vrfs]]` entry. Empty / unset leaves that L2VNI as
bridging-only. Validation rejects a name that does not resolve to any
declared IP-VRF.

### Readiness predicates

The reconcile actor maps each IP-VRF against its kernel snapshot every
pass. ADR-0058 §3 defines seven predicates that must all hold for the
IP-VRF to be `Ready`:

1. `vrf_device` exists and is administratively UP.
2. `vrf_device`'s `IFLA_VRF_TABLE` equals `table_id`.
3. `l3vxlan_device` exists and is administratively UP.
4. `l3vxlan_device`'s `IFLA_VXLAN_ID` equals the configured L3VNI.
5. `l3vxlan_device`'s `IFLA_VXLAN_LOCAL` (or `IFLA_VXLAN_LOCAL6`) equals
   `local_vtep_ip`.
6. `l3vxlan_device`'s `IFLA_MASTER` points to `vrf_device`.
7. `l3vxlan_device`'s link-layer address equals the configured
   `router_mac`.

`NotReady` results enumerate every failing predicate; the actor logs
the transition once per state change rather than every pass.

### Validation rules (Gate 9 foundation)

- `name` matches `^[a-zA-Z][a-zA-Z0-9_-]*$` and is unique across `[[evpn_ip_vrfs]]`.
- `vni` is in `1..=16_777_215` and does not collide with any `[[evpn_instances]]` VNI.
- `rd` parses as `asn:value` or `ipv4:value`.
- `route_targets` is non-empty and every entry parses unless
  `auto_derive_route_target = true`.
- `auto_derive_route_target = true` requires `[global].asn <= 65535`; 4-octet
  ASNs must configure `route_targets` manually.
- `local_vtep_ip` is a valid unicast IP (rejects unspecified / multicast / loopback).
- `router_mac` is a unicast non-zero MAC.
- `vrf_device` and `l3vxlan_device` are non-blank.
- `table_id` is `> 0`.
- `overlay_index_mode` is `"interface_less"` (default), `"gateway_ip"`, or
  `"esi"`. `"gateway_ip"` is rejected at load unless at least one
  `[[evpn_instances]]` links to this IP-VRF via `ip_vrf` — the GW-IP
  receive side scopes its recursive Type 2 lookup to the linked
  L2VNIs, so a `gateway_ip` VRF with no L2VNI link could never
  originate a resolvable route (ADR-0087). `"esi"` also requires at least one
  linked L2VNI plus `overlay_index_esi` and `overlay_index_mac`.
- `overlay_index_esi`, `overlay_index_mac`, and `overlay_index_l2vni` are valid
  only when `overlay_index_mode = "esi"`. The ESI must be non-zero and match a
  configured `[[ethernet_segments]].esi`; the MAC must be unicast and non-zero.
  If exactly one L2VNI links to the IP-VRF, that L2VNI is selected
  automatically. If multiple L2VNIs link to the IP-VRF, `overlay_index_l2vni`
  is required and must both link to the IP-VRF and appear in the selected
  Ethernet Segment's `member_vnis`.
- Every `[[evpn_instances]].ip_vrf` resolves to a declared IP-VRF.
- `[[evpn_ip_vrfs]]` follows the ADR-0063 coordinator lifecycle.
  SIGHUP and `EvpnService.ApplyEvpnRuntime` can live-commit a single
  IP-VRF add, standalone delete, or redefine with unchanged
  L3VNI/device/table identity, and an atomic tenant teardown that drops a
  linked IP-VRF together with its L2VNI (and any Ethernet Segment) in one
  pass. `ip_vrf` relink and L2VNI-only add/delete/redefine compositions
  commit live; L3VNI/device/table IP-VRF identity changes and ES/IP-VRF
  row mixed edits remain fail-closed
  [#268](https://github.com/lance0/rustbgpd/issues/268) shapes.

### GW-IP overlay-index origination (`overlay_index_mode = "gateway_ip"`)

By default (`"interface_less"`) every originated Type 5 carries
Gateway Address zero and the Router's MAC extended community —
receivers reach the prefix's VTEP and resolve the inner MAC from that
extcomm (RFC 9136 §4.4.2). With `"gateway_ip"` (RFC 9136 §4.1/§4.2,
ADR-0087), a kernel route whose via (`ip route add <prefix> via <gw>`)
lands inside a connected subnet of the VRF is originated with that via
in the Gateway Address and **no** Router's MAC extcomm; receivers
resolve the gateway recursively through its Type 2 MAC/IP route and
forward straight to wherever the gateway host lives. When the gateway
host moves, its Type 2 alone re-converges every prefix that points at
it.

- The via must land on a `Connected` (kernel) prefix of the same VRF
  with prefix length > 0 and be a usable gateway host. Ordinary IPv4
  subnet network and directed-broadcast addresses fall back to the
  interface-less shape; `/31` point-to-point endpoints and `/32` host
  routes are eligible. An off-subnet via (no Type 2 will ever name it)
  falls back too, as does a route with no via.
- The companion Type 2 is a dependency, not a precondition: rustbgpd
  originates the Type 5 immediately, and receivers hold it unresolved
  (surfaced via the `unresolved_overlay_index_gateway` drop counter)
  until the Type 2 arrives. The L3VNI stays in the label slot in both
  modes (deviating from the RFC 9136 §3.1 SHOULD-zero — our own
  receive side and FRR both keep it).
- A via change re-originates in place (same route key, new Gateway
  Address) — one UPDATE, no withdraw/announce pulse.

### ESI overlay-index origination (`overlay_index_mode = "esi"`)

With `"esi"` (RFC 9136 §4.3), every locally originated Type 5 for that
IP-VRF carries:

- the configured non-zero `overlay_index_esi` as the Type 5 ESI;
- Gateway Address zero, so the route carries exactly one overlay index;
- the IP-VRF's L3VNI in the label slot, matching the shipped
  interface-less and GW-IP shapes;
- Router MAC extcomm set to `overlay_index_mac`, which names the virtual
  appliance / transit-switch MAC rather than the PE/NVE `router_mac`.

This mode is for locally attached multi-homed gateway designs where receivers
resolve the ESI through Ethernet A-D state. rustbgpd also ships bounded
receive-side ESI protected recursion: a non-zero-ESI Type 5 imports through
scoped EAD-per-EVI state when the candidate set is either exactly one
single-active remote VTEP or a valid two-or-more-member all-active target set.
Unsupported, ambiguous, mixed-signal, or incomplete ESI recursion still drops
fail-closed through bounded remote-prefix drop reasons. Existing receive-side
GW-IP protected recursion is unchanged.

See [ADR-0058](adr/0058-evpn-gate-9-irb-l3vni.md) and
[ADR-0087](adr/0087-evpn-type5-gateway-ip-overlay-index-origination.md)
for the design rationale.

---

## `[managed_netdevs]`

ADR-0091 managed EVPN netdevs are opt-in and class-scoped. The first
tranche accepts only bridge rows, derives the durable Linux altname
ownership stamp, and reports status through
`EvpnService.ListManagedNetdevs` / `rbgp evpn managed-netdevs`. It
does **not** create, adopt, or delete links yet; bridge lifecycle
execution lands in the next ADR-0091 slice.

Any `[managed_netdevs]` add/remove/change is restart-required in this
tranche for SIGHUP, config transactions, gNMI Set, and
`EvpnService.ApplyEvpnRuntime`.

```toml
[managed_netdevs]
owner_token = "leaf-1"             # ASCII letters/digits/_/./-, <= 63 bytes

[[managed_netdevs.bridges]]
name = "br100"                     # Linux ifname, <= 15 bytes
vlan_filtering = true              # protected bridge attribute
```

The derived bridge stamp is:

```text
rustbgpd:bridge:<owner_token>:<bridge_name>
```

Validation rejects bridge rows without `owner_token`, duplicate bridge
names, invalid Linux-style bridge names (`.`, `..`, spaces, or names
over 15 bytes), invalid owner tokens, and derived stamps longer than
Linux's 127-byte altname limit. Unknown future rows such as
`[[managed_netdevs.vxlans]]` and `[[managed_netdevs.vrfs]]` are rejected
until those classes ship.

Status states:

| State | Meaning |
|-------|---------|
| `desired-absent` | Configured bridge is not present in the kernel snapshot |
| `foreign-present` | Same-name bridge exists without the expected rustbgpd ownership stamp |
| `owned-unsafe` | Bridge carries a rustbgpd stamp that is not the expected one, or a protected attribute such as `vlan_filtering` does not match config |
| `owned-safe` | Expected stamp and protected attributes match |
| `orphaned` | A rustbgpd-stamped bridge exists with no desired config row |
| `unknown` | No dataplane status snapshot has been published yet, or the link dump failed |

---

## `[event_history]`

Durable event-history outbox (ADR-0072). A daemon-local SQLite WAL
store that survives daemon restart with a monotonic `event_id`
cursor. External collectors bridge to their own bus (Kafka, NATS,
Vector, journald, custom) over the existing gRPC event-stream
RPCs; rustbgpd itself does not try to be an event bus.

**Opt-in — default off as of v0.32.0.** The outbox is disabled by
default; operators who want restart-safe event replay set
`enabled = true` and restart. It is off by default because v0.32.0
benchmarking measured a material always-on cost (~62 MB RSS and roughly
double the peak CPU at 2p/100k); a routing daemon should be lean by
default. While disabled, `SubscribeFromEvent` and gNMI `Subscribe
ON_CHANGE` return `FAILED_PRECONDITION`; the live `WatchEvents` /
`WatchRoutes` / `List*Events` surfaces are unaffected. When enabled, the
outbox is bounded by a hard `max_events` count cap plus a `max_bytes`
retention trigger. SQLite reuses freed pages after DELETE and does not
guarantee that the main database file immediately shrinks without a
future compaction pass, so `max_bytes` is an operational target rather
than a strict filesystem ceiling in v1.

All fields are restart-required; see
[reload-matrix.md](reload-matrix.md#event_history-adr-0072) for
the per-field classification.

```toml
[event_history]
enabled = false                 # default (v0.32.0); set true for durable event replay
required = false                # if true, daemon fails to start when DB unrecoverable
path = ""                       # relative to runtime_state_dir; "" = events.db
max_events = 100_000            # hard count cap
max_bytes = 256_000_000         # byte retention target (events.db + WAL)
synchronous = "full"            # full = fsync per commit; normal trades crash window for throughput
overflow = "drop"               # v1 only supports "drop"; "block" reserved for a future ADR
queue_capacity = 4096           # per-producer mpsc capacity
batch_size = 1024               # batch-commit size threshold
batch_interval_ms = 50          # batch-commit time threshold
```

### Recovery and degraded health

When the events DB fails to open or is corrupted:

- The bad file is renamed to `events.db.stale` (matches the
  `*.json.stale` convention from `fib-owned.json`).
- The allocator anchor is recovered via authoritative DB metadata:
  primary DB metadata, then quarantine fallback. `events.last_id` is
  written as a diagnostic hint, but it may lag committed events and is
  not used to resume allocation in v1.
- If both authoritative sources fail AND prior allocation evidence
  exists (`events.db.stale` or `events.last_id`), EHM enters
  pass-through (`required = false`) or refuses to start
  (`required = true`). The allocator never restarts at 1 silently.
- `bgp_event_outbox_degraded` flips to `1` and does not auto-
  clear in v1; operator restarts to clear.

### Best-effort under overload

On a full producer queue, EHM drops the event, increments
`bgp_event_outbox_dropped_total{category, reason="queue_full"}`,
and flips the degraded flag. Drops are **observable but lie
outside the committed cursor sequence by design**. The outbox is
not a compliance-grade audit log; operators wanting that should
treat it as a transport to their external bus, which is the
system of record.

### External-bus integration

The documented pattern is `SubscribeFromEvent(from_event_id)` —
a server-side replay-then-live join over the durable outbox.
Cursor semantics on `from_event_id`:

- absent ⇒ live-only (no replay), like `WatchEvents`.
- `0` ⇒ replay everything retained, then live (fresh-collector
  case).
- `N > 0` ⇒ replay events with `event_id > N`, then live (the
  normal reconnect case).

When the requested cursor is older than the retention floor,
the server emits a leading `StreamLagEvent` with the missed
count over the global committed stream (not the filtered
subset) and then resumes replay from the earliest retained
event. The `bgp_event_outbox_cursor_gap_total` counter
tracks how often that fires — alert on non-zero to know your
retention is undersized for the collector reconnect SLA.

The CLI `rbgp events watch --from-event-id <N>` drives
the same RPC and is mutually exclusive with `--backfill`
(`--backfill` replays the daemon's process-local route ring,
which resets on restart; `--from-event-id` replays the
durable outbox, which survives restart).

`examples/event-bridge/` is the reference workspace binary
that streams `BgpEvent` as JSON-lines to stdout. Operators
copy it and replace the stdout writer with their Kafka /
NATS / Vector / journald sink, then persist
`last_seen_event_id` after their downstream sink confirms
durable receipt. See `OPERATIONS.md` "Durable Event Cursor"
for the alert + sizing playbook.

When `enabled = false`, when EHM failed to start with
`required = false`, or when EHM dropped into pass-through
mode at runtime, `SubscribeFromEvent` returns
`FAILED_PRECONDITION`. The legacy `WatchEvents`,
`WatchRoutes`, and `List*Events` surfaces are byte-identical
to pre-ADR-0072 behavior in all three cases — they're
backed by the existing in-memory rings.

**Producer set:** route, EVPN, session-lifecycle,
session-notification, policy, dataplane, and BFD. Dataplane
summary rollups and per-route FIB apply outcomes stay available
live through `WatchEvents`, and are also replayable through
`SubscribeFromEvent` when event history is enabled.

## Config Persistence

Neighbor mutations made through the gRPC API (`AddNeighbor`, `DeleteNeighbor`)
reserve config-persistence queue capacity before mutating runtime state, then
wait for the atomic config-file write (temp file + rename) to be acknowledged
after the peer manager accepts the change. Static-neighbor and dynamic-neighbor
runtime CRUD share the runtime-config coordinator lock with SIGHUP, so reload
sees either the pre-mutation TOML or the committed post-mutation TOML. If the
write is rejected after runtime apply, the accepted runtime mutation is rolled
back and the RPC reports failure.

### SIGHUP Reload

Sending `SIGHUP` to the rustbgpd process triggers a four-bucket config
reload, applied in dependency order:

1. **Definitions and hot-applied global flags** — neighbor sets, named
   policies, peer groups, global import / export chains,
   `honor_graceful_shutdown`, and control-plane-only
   `honor_blackhole`. Each bucket diffs against the running config and
   fires a single-shot command at the peer manager that goes through the
   same `apply_policy_change` / `apply_peer_group_change` paths the
   gRPC API uses. Hot-applied policy chains land at every affected
   peer's session task without tearing the BGP session.
2. **`[[neighbors]]` reconcile** — adds, deletes, and changes flow
   through `diff_neighbors()` + a single `ReconcilePeers` command with
   add/delete/change deltas.
3. **Deletes of obsolete definitions** in reverse-dependency order —
   so transient `still referenced` rejections don't fire while a
   peer group is being deleted before the chain that named it.
4. **Automatic Route Refresh on import-policy hot-apply** — when a
   peer's effective import chain changes,
   `PeerManager::update_runtime_policies` issues `soft_reset_in`
   (gated on Established) so routes already in `AdjRibIn` get
   re-evaluated. Operators do not need to follow up with a manual
   `softreset` after a chain swap.

Reload halts at the first step failure and returns a partial-state
snapshot, so the daemon's in-memory config tracks what the peer
manager actually applied (operator fixes the failing TOML and
reloads again to converge against the half-applied state). The
neighbor-reconcile step returns `None` on partial failure because
live state is genuinely ambiguous after a delete-then-readd partial;
earlier reload steps still land at the manager and remain in effect.

Inline `policy.import` / `policy.export` (the legacy global-fallback
statements), `[global]` ASN/router-id/families,
`[global.telemetry.grpc_*]` listener config, `[rpki]`, `[bmp]`,
`[mrt]`, and `apply_bum_enforcement` are
**restart-required** — they're surfaced under "Restart-required" in
`rustbgpd --diff` and logged at reload time with a one-line migration
hint to named definitions plus `import_chain` / `export_chain` where
applicable. EVPN tables (`[[evpn_instances]]`, `[[ethernet_segments]]`,
and `[[evpn_ip_vrfs]]`) are coordinator-gated instead: SIGHUP and the
whole-model `EvpnService.ApplyEvpnRuntime` RPC validate a full candidate,
converge the daemon actors in order, and advance the committed runtime
snapshot only after the actors accept the change. Supported live shapes
include single L2VNI/IP-VRF/Ethernet-Segment add/delete/redefine,
additive build-up, atomic tenant teardown, `ip_vrf` relink, and
L2VNI-only add/delete/redefine compositions. Unsupported mixed edits,
missing actors, actor convergence failure, or restart-only IP-VRF
identity changes pin back to the committed runtime model and keep the
drift visible. The ADR-0061 `[[fib_tables]]` table is another
reload-applied surface: when the FIB reconciler is running it
**hot-applies** table edits on SIGHUP (see the `[[fib_tables]]` section),
advancing the snapshot only after the actor acks the new set; only *starting*
the FIB subsystem from an empty config still requires a restart. Runtime EVPN
mutation does not expose direct `AddEvpnInstance` / `DeleteEvpnInstance`
RPCs; unsupported shapes are tracked in
<https://github.com/lance0/rustbgpd/issues/268>.

Reload failures are reported per-step with structured logging
(bucket / target / error). The previous in-memory config snapshot
is preserved up to the point of failure.

---

## Validation rules

The following checks run at startup. Any failure prevents the daemon from
starting:

| Rule | Error |
|------|-------|
| `router_id` must be a valid IPv4 address | `invalid router_id` |
| Each `address` in `[[neighbors]]` must be a valid IP address (IPv4 or IPv6) | `invalid neighbor address` |
| IPv6 link-local `[[neighbors]]` must set `interface`; numbered neighbors must not | `invalid neighbor config` |
| `[[neighbors]]` identity must be unique by address for numbered peers and by `(address, interface)` for IPv6 link-local peers | `duplicate neighbor address/interface` |
| An IPv6 link-local address may not be bound to more than one interface in this release (the RIB keys peers by address; deferred per ADR-0069) | `not supported in this release` |
| `prometheus_addr` must be a valid `ip:port` | `invalid prometheus_addr` |
| `grpc_tcp.address` must be a valid `ip:port` when `grpc_tcp` is enabled | `invalid gRPC config` |
| `grpc_uds.path` must be absolute when configured | `invalid gRPC config` |
| `grpc_uds.mode` must be <= `0o777` | `invalid gRPC config` |
| `grpc_*.access_mode` must be `read_only` or `read_write` | `invalid gRPC config` |
| `grpc_*.max_tier` must be `read`, `sensitive_read`, `mutating`, or `operator_only` | TOML parse error |
| `grpc_*.token_file` must exist, be readable, and contain a non-empty token when configured | `invalid gRPC config` |
| `grpc_*.principal` must not be empty when configured | `invalid gRPC config` |
| `grpc_tcp.principal` requires `grpc_tcp.token_file` and is rejected on mTLS listeners because mTLS principals are derived from client certificates | `invalid gRPC config` |
| `security.grpc.enforcement = "tier"` requires at least one role mapping and every enabled listener must have mTLS or an explicit principal | `invalid gRPC config` |
| `[security.grpc.roles]` principal keys must not be empty; role values must be `observer`, `automation`, or `operator` | `invalid gRPC config` / TOML parse error |
| If `grpc_tcp`/`grpc_uds` tables are present, at least one listener must be enabled | `invalid gRPC config` |
| `hold_time` must be 0 (disabled) or >= 3 seconds | `invalid hold_time` |
| `families` entries must be `"ipv4_unicast"`, `"ipv6_unicast"`, `"ipv4_flowspec"`, or `"ipv6_flowspec"` | `unsupported address family` |
| `gr_restart_time` must be <= 4095 | `gr_restart_time exceeds 4095` |
| `gr_restart_time` must be > 0 when `graceful_restart` is enabled | `gr_restart_time must be > 0` |
| `gr_stale_routes_time` must be > 0 and <= 3600 | `invalid gr_stale_routes_time` |
| Policy prefix length must not exceed AFI max (32 for IPv4, 128 for IPv6) | `invalid prefix length` |
| Policy entry must have at least one match condition (`prefix`, `match_community`, `match_as_path`, `match_as_path_length_ge`, `match_as_path_length_le`, `match_rpki_validation`, or `match_aspa_validation`) | `must have at least one match condition` |
| Import `match_rpki_validation`/`match_aspa_validation` evaluates against the current snapshot — routes arriving before the first VRP/ASPA table loads see `not_found`/`unknown`; later cache updates trigger inbound Route Refresh for established peers whose import policy depends on validation state | *(informational — no error)* |
| `match_as_path_length_ge` must not exceed `match_as_path_length_le` | `match_as_path_length_ge (...) exceeds match_as_path_length_le (...)` |
| `set_*` fields cannot be used with `action = "deny"` | `set_* fields cannot be used with action = "deny"` |
| `set_as_path_prepend.count` must be 1--10 | `count must be 1-10` |
| `match_as_path` must be a valid regex | `invalid regex` |
| RT/RO extended community ASN must be <= 65535 (2-octet AS sub-type) | `ASN exceeds 65535` |
| RPKI `refresh_interval`, `retry_interval`, `expire_interval` must be > 0 | `must be > 0` |
| RPKI `expire_interval` must be >= `refresh_interval` | `expire_interval must be >= refresh_interval` |
| Named policy referenced in chain must exist in `[policy.definitions]` | `undefined policy` |
| Inline policy and policy chain cannot both be set for the same neighbor/direction | `mutually exclusive` |
| `route_server_client` is only valid on eBGP neighbors | `invalid route_server_client` |
| `disable_ipv4_unicast = true` requires at least one non-`ipv4_unicast` effective family | `invalid neighbor config` |
| `role` is only valid on eBGP neighbors; `strict_role = true` requires `role` | `invalid neighbor config` |
| `remove_private_as` must be `"remove"`, `"all"`, or `"replace"` (eBGP only) | `invalid remove_private_as` |
| MRT `output_dir` must not be empty | `output_dir must not be empty` |
| MRT `dump_interval` must be > 0 | `dump_interval must be > 0` |
| BMP collector `address` must be a valid `ip:port` | `invalid BMP collector address` |
| BMP collector `reconnect_interval` must be > 0 | `reconnect_interval must be > 0` |
| `cluster_id` must be a valid IPv4 address | `invalid cluster_id` |
| `runtime_state_dir` must not be empty | `runtime_state_dir must not be empty` |
| `[[fib_tables]].name` must be unique and match the identifier rule | `duplicate fib table name` / `invalid fib table name` |
| `[[fib_tables]].table_id` must be unique and must not be `0`, `252`, `253`, `254`, or `255` | `duplicate fib table_id` / `reserved fib table_id` |
| `[[fib_tables]].families` must be non-empty, contain no duplicates, and contain only `ipv4_unicast` / `ipv6_unicast` | `fib table families must not be empty` / `duplicate fib table family` / `unsupported fib table family` |
| `[[fib_tables]].allowed_peer_groups` entries must reference existing peer groups and contain no duplicates | `undefined peer_group` / `duplicate allowed_peer_groups` |
| `[[fib_tables]].allowed_neighbors` entries must parse as IP addresses and contain no duplicates | `invalid allowed_neighbors` / `duplicate allowed_neighbors` |
| `[[fib_tables]].max_routes` must be omitted or greater than zero | `max_routes must be greater than zero` |
| `llgr_stale_time` must be <= 16777215 (24-bit) | `llgr_stale_time exceeds maximum` |
| `route_reflector_client` requires iBGP (local ASN == remote ASN) | `route_reflector_client requires iBGP` |
| `local_ipv6_nexthop` must be a valid non-link-local, non-loopback, non-multicast IPv6 address | `invalid local_ipv6_nexthop` |
| `ge` must be >= prefix length and <= AFI max (32 for IPv4, 128 for IPv6) | `invalid ge` |
| `le` must be <= AFI max | `invalid le` |
| `ge` must be <= `le` when both are set | `ge must be <= le` |
| Config file must be valid TOML | `failed to parse TOML` |

### Defaults applied at runtime

| Field | Default value |
|-------|---------------|
| `hold_time` | 90 seconds |
| `connect_retry_secs` | 5 seconds (not configurable) |
| gRPC listener | UDS at `<runtime_state_dir>/grpc.sock` with mode `0o600` |
| `ttl_security` | `false` |
| `families` | `["ipv4_unicast"]` for IPv4 peers; `["ipv4_unicast", "ipv6_unicast"]` for IPv6 peers |
| `graceful_restart` | `true` |
| `gr_restart_time` | 120 seconds |
| `gr_stale_routes_time` | 360 seconds |
| `llgr_stale_time` | 0 (disabled) |
| `description` | peer address used as label |
| `route_server_client` | `false` |
| `prefix_orf_receive` | `false` |
| `disable_ipv4_unicast` | `false` |
| `role` / `strict_role` | disabled / `false` |
| `remove_private_as` | disabled (absent) |
| Policy default action | permit (when no entry matches) |
