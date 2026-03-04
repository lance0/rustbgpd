# Configuration Reference

rustbgpd is configured via a single TOML file, passed as the first argument to the daemon:

```
rustbgpd /etc/rustbgpd/config.toml
```

The config file defines the initial boot state. At runtime, the gRPC API is the
source of truth -- peers can be added, removed, enabled, and disabled dynamically
without restarting the daemon. Starting with zero `[[neighbors]]` is valid when
all peers are managed via gRPC.

---

## `[global]`

Required. Defines the local BGP speaker identity.

| Field               | Type   | Required | Default              | Description                        |
|---------------------|--------|----------|----------------------|------------------------------------|
| `asn`               | u32    | yes      | --                   | Local autonomous system number     |
| `router_id`         | string | yes      | --                   | BGP router ID (must be valid IPv4) |
| `listen_port`       | u16    | yes      | --                   | TCP port to listen on (typically 179) |
| `runtime_state_dir` | string | no       | `"/var/lib/rustbgpd"` | Directory for daemon-owned runtime state (GR restart marker today) |

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
runtime_state_dir = "/var/lib/rustbgpd"
```

`runtime_state_dir` must be writable by the rustbgpd process. In containers or
non-root deployments, override the default to a mounted writable path (for
example `/var/lib/rustbgpd` on a volume, or `/data/rustbgpd`).

---

## `[global.telemetry]`

Required. Configures observability and management endpoints.

| Field             | Type   | Required | Default             | Description                          |
|-------------------|--------|----------|---------------------|--------------------------------------|
| `prometheus_addr` | string | yes      | --                  | `host:port` for Prometheus metrics   |
| `log_format`      | string | yes      | --                  | Log output format (`"json"`)         |
| `grpc_addr`       | string | no       | `"127.0.0.1:50051"` | `host:port` for the gRPC API server |

Both `prometheus_addr` and `grpc_addr` must be valid `ip:port` socket addresses.
Use `0.0.0.0` as the host to bind on all interfaces (necessary when gRPC or
metrics must be reachable from outside the host, e.g. in containers).

```toml
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
grpc_addr = "0.0.0.0:50051"
```

---

## `[[neighbors]]`

Optional, repeatable. Each entry defines one BGP peer. Omit entirely for a
dynamic-only deployment where peers are added at runtime via gRPC.

| Field                  | Type     | Required | Default | Description                                      |
|------------------------|----------|----------|---------|--------------------------------------------------|
| `address`              | string   | yes      | --      | Peer IP address (IPv4 or IPv6)                   |
| `remote_asn`           | u32      | yes      | --      | Peer's autonomous system number                  |
| `description`          | string   | no       | --      | Human-readable label (used in logs; defaults to address if absent) |
| `hold_time`            | u16      | no       | 90      | BGP hold timer in seconds (0 or >= 3)            |
| `max_prefixes`         | u32      | no       | --      | Maximum prefixes accepted before session teardown |
| `md5_password`         | string   | no       | --      | TCP MD5 authentication password (RFC 2385, Linux only) |
| `ttl_security`         | bool     | no       | false   | Enable GTSM / TTL security (RFC 5082, Linux only) |
| `families`             | [string] | no       | (auto)  | Address families to negotiate (see below)        |
| `graceful_restart`     | bool     | no       | true    | Enable Graceful Restart receiving speaker (RFC 4724) |
| `gr_restart_time`      | u16      | no       | 120     | Restart time advertised in GR capability (seconds, 1--4095) |
| `gr_stale_routes_time` | u64      | no       | 360     | Time to retain stale routes after peer reconnects (seconds, 1--3600) |
| `route_server_client`  | bool     | no       | false   | Transparent route-server mode for eBGP unicast peers (see below) |
| `add_path`             | table    | no       | --      | Add-Path (RFC 7911) config table (see below)                         |

### Address families

The `families` field controls which AFI/SAFI combinations are negotiated with
the peer via MP-BGP capabilities. Supported values:

- `"ipv4_unicast"` — IPv4 Unicast (AFI 1, SAFI 1)
- `"ipv6_unicast"` — IPv6 Unicast (AFI 2, SAFI 1)
- `"ipv4_flowspec"` — IPv4 FlowSpec (AFI 1, SAFI 133, RFC 8955)
- `"ipv6_flowspec"` — IPv6 FlowSpec (AFI 2, SAFI 133, RFC 8956)

**Defaults:** If `families` is omitted, the default depends on the neighbor
address type:

- IPv4 neighbor address → `["ipv4_unicast"]`
- IPv6 neighbor address → `["ipv4_unicast", "ipv6_unicast"]`

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
  `forwarding_preserved` remains false because rustbgpd does not yet own or
  verify the FIB.

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
See [ADR-0024](docs/adr/0024-graceful-restart.md).

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

Both IPv4 and IPv6 unicast are supported. See [ADR-0033](docs/adr/0033-add-path.md).

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

When enabled, outbound **unicast** advertisements to that peer:

- preserve the original next hop by default
- skip the automatic local-AS prepend normally applied on eBGP export
- still strip `LOCAL_PREF` (the peer is still eBGP)
- still honor explicit export-policy next-hop rewrites (`set_next_hop`)

This applies to:

- classic IPv4 unicast (`NEXT_HOP`)
- IPv4 unicast over IPv6 next hop (RFC 8950)
- IPv6 unicast (`MP_REACH_NLRI`)

`route_server_client` is only valid for eBGP neighbors. Config validation
rejects it on iBGP peers.

**Current scope:** transparent route-server behavior is implemented for
unicast only. FlowSpec still uses the standard eBGP automatic AS_PATH prepend
behavior and does not yet have a transparent mode.

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
apply. See [ADR-0035](docs/adr/0035-flowspec.md).

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

See [ADR-0029](docs/adr/0029-route-reflector.md) for reflection rules and
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
| **Invalid** | VRP covers the prefix but origin AS doesn't match | Deprioritized |

### Policy integration

Use `match_rpki_validation` in policy statements to filter routes by RPKI state.

Drop RPKI-invalid routes (recommended):

```toml
[[policy.import]]
match_rpki_validation = "invalid"
action = "deny"
```

Prefer valid routes with higher LOCAL_PREF:

```toml
[[policy.import]]
match_rpki_validation = "valid"
action = "permit"
set_local_pref = 200

[[policy.import]]
match_rpki_validation = "not_found"
action = "permit"
set_local_pref = 100
```

### Monitoring

Prometheus metrics exposed at the configured metrics endpoint:

| Metric | Description |
|--------|-------------|
| `bgp_rpki_vrp_count{af="ipv4\|ipv6"}` | Current VRP entries by address family |

See [ADR-0034](docs/adr/0034-rpki-origin-validation.md) for design details.

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
statements.

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

---

## Policy entries

Both global (`[[policy.import]]` / `[[policy.export]]`) and per-neighbor
(`[[neighbors.import_policy]]` / `[[neighbors.export_policy]]`) entries share
the same schema.

### Match conditions

Each entry must have at least one match condition. Multiple conditions on the
same entry are ANDed.

| Field             | Type     | Required | Description                                           |
|-------------------|----------|----------|-------------------------------------------------------|
| `prefix`          | string   | no*      | Network prefix in CIDR notation (IPv4 or IPv6)        |
| `ge`              | u8       | no       | Minimum prefix length to match (inclusive)             |
| `le`              | u8       | no       | Maximum prefix length to match (inclusive)             |
| `match_community` | [string] | no*      | Community match criteria (see below). OR within list.  |
| `match_as_path`   | string   | no*      | AS_PATH regex (Cisco/Quagga style, `_` = boundary)    |
| `match_rpki_validation` | string | no* | RPKI state: `"valid"`, `"invalid"`, or `"not_found"` |
| `action`          | string   | yes      | `"permit"` or `"deny"`                                |

*At least one of `prefix`, `match_community`, `match_as_path`, or `match_rpki_validation` is required.

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
| Well-known name | `"NO_EXPORT"`, `"NO_ADVERTISE"`, `"NO_EXPORT_SUBCONFED"` | Standard community |
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
grpc_addr = "0.0.0.0:50051"

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

## Validation rules

The following checks run at startup. Any failure prevents the daemon from
starting:

| Rule | Error |
|------|-------|
| `router_id` must be a valid IPv4 address | `invalid router_id` |
| Each `address` in `[[neighbors]]` must be a valid IP address (IPv4 or IPv6) | `invalid neighbor address` |
| `prometheus_addr` must be a valid `ip:port` | `invalid prometheus_addr` |
| `grpc_addr` must be a valid `ip:port` | `invalid grpc_addr` |
| `hold_time` must be 0 (disabled) or >= 3 seconds | `invalid hold_time` |
| `families` entries must be `"ipv4_unicast"`, `"ipv6_unicast"`, `"ipv4_flowspec"`, or `"ipv6_flowspec"` | `unsupported address family` |
| `gr_restart_time` must be <= 4095 | `gr_restart_time exceeds 4095` |
| `gr_restart_time` must be > 0 when `graceful_restart` is enabled | `gr_restart_time must be > 0` |
| `gr_stale_routes_time` must be > 0 and <= 3600 | `invalid gr_stale_routes_time` |
| Policy prefix length must not exceed AFI max (32 for IPv4, 128 for IPv6) | `invalid prefix length` |
| Policy entry must have at least one match condition (`prefix`, `match_community`, `match_as_path`, or `match_rpki_validation`) | `must have at least one match condition` |
| `set_*` fields cannot be used with `action = "deny"` | `set_* fields cannot be used with action = "deny"` |
| `set_as_path_prepend.count` must be 1--10 | `count must be 1-10` |
| `match_as_path` must be a valid regex | `invalid regex` |
| RT/RO extended community ASN must be <= 65535 (2-octet AS sub-type) | `ASN exceeds 65535` |
| RPKI `refresh_interval`, `retry_interval`, `expire_interval` must be > 0 | `must be > 0` |
| RPKI `expire_interval` must be >= `refresh_interval` | `expire_interval must be >= refresh_interval` |
| Named policy referenced in chain must exist in `[policy.definitions]` | `undefined policy` |
| Inline policy and policy chain cannot both be set for the same neighbor/direction | `mutually exclusive` |
| `route_server_client` is only valid on eBGP neighbors | `invalid route_server_client` |
| Config file must be valid TOML | `failed to parse TOML` |

### Defaults applied at runtime

| Field | Default value |
|-------|---------------|
| `hold_time` | 90 seconds |
| `connect_retry_secs` | 30 seconds (not configurable) |
| `grpc_addr` | `127.0.0.1:50051` |
| `ttl_security` | `false` |
| `families` | `["ipv4_unicast"]` for IPv4 peers; `["ipv4_unicast", "ipv6_unicast"]` for IPv6 peers |
| `graceful_restart` | `true` |
| `gr_restart_time` | 120 seconds |
| `gr_stale_routes_time` | 360 seconds |
| `description` | peer address used as label |
| `route_server_client` | `false` |
| Policy default action | permit (when no entry matches) |
