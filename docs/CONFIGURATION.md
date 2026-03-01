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

| Field         | Type   | Required | Default | Description                        |
|---------------|--------|----------|---------|------------------------------------|
| `asn`         | u32    | yes      | --      | Local autonomous system number     |
| `router_id`   | string | yes      | --      | BGP router ID (must be valid IPv4) |
| `listen_port` | u16    | yes      | --      | TCP port to listen on (typically 179) |

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
```

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

| Field             | Type     | Required | Default | Description                                      |
|-------------------|----------|----------|---------|--------------------------------------------------|
| `address`         | string   | yes      | --      | Peer IP address (IPv4 or IPv6)                   |
| `remote_asn`      | u32      | yes      | --      | Peer's autonomous system number                  |
| `description`     | string   | no       | --      | Human-readable label (used in logs; defaults to address if absent) |
| `hold_time`       | u16      | no       | 90      | BGP hold timer in seconds (0 or >= 3)            |
| `max_prefixes`    | u32      | no       | --      | Maximum prefixes accepted before session teardown |
| `md5_password`    | string   | no       | --      | TCP MD5 authentication password (RFC 2385, Linux only) |
| `ttl_security`    | bool     | no       | false   | Enable GTSM / TTL security (RFC 5082, Linux only) |
| `families`        | [string] | no       | (auto)  | Address families to negotiate (see below)        |

### Address families

The `families` field controls which AFI/SAFI combinations are negotiated with
the peer via MP-BGP capabilities. Supported values:

- `"ipv4_unicast"` — IPv4 Unicast (AFI 1, SAFI 1)
- `"ipv6_unicast"` — IPv6 Unicast (AFI 2, SAFI 1)

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

### Per-neighbor policy

Each neighbor can carry its own import and export prefix-list policy. These are
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

[[neighbors.export_policy]]
prefix = "192.168.0.0/16"
action = "permit"
```

See the [Policy entries](#policy-entries) section below for field details.

---

## `[policy]`

Optional. Defines global import and export prefix-list policy that applies to
all neighbors that do not declare their own per-neighbor policy.

```toml
[[policy.import]]
prefix = "10.0.0.0/8"
ge = 8
le = 24
action = "permit"

[[policy.import]]
prefix = "0.0.0.0/0"
action = "deny"

[[policy.export]]
prefix = "172.16.0.0/12"
action = "deny"
```

---

## Policy entries

Both global (`[[policy.import]]` / `[[policy.export]]`) and per-neighbor
(`[[neighbors.import_policy]]` / `[[neighbors.export_policy]]`) entries share
the same schema:

| Field    | Type   | Required | Description                                           |
|----------|--------|----------|-------------------------------------------------------|
| `prefix` | string | yes      | Network prefix in CIDR notation (IPv4 or IPv6, e.g. `"10.0.0.0/8"` or `"2001:db8::/32"`) |
| `ge`     | u8     | no       | Minimum prefix length to match (inclusive)            |
| `le`     | u8     | no       | Maximum prefix length to match (inclusive)            |
| `action` | string | yes      | `"permit"` or `"deny"`                                |

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

1. If the neighbor has per-neighbor policy entries (`[[neighbors.import_policy]]`
   or `[[neighbors.export_policy]]`), those are used.
2. Otherwise, the corresponding global policy (`[[policy.import]]` or
   `[[policy.export]]`) is used.
3. If neither exists, all routes are permitted (no filtering).

Per-neighbor policy completely replaces the global policy for that direction --
the two are never merged.

---

## Complete example

A realistic configuration with three peers and mixed policy:

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

[[policy.import]]
prefix = "0.0.0.0/0"
le = 24
action = "permit"

# Upstream provider -- uses global import policy, custom export
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "upstream-provider"
hold_time = 90
max_prefixes = 50000

[[neighbors.export_policy]]
prefix = "192.168.1.0/24"
action = "permit"

[[neighbors.export_policy]]
prefix = "192.168.2.0/24"
action = "permit"

[[neighbors.export_policy]]
prefix = "0.0.0.0/0"
le = 32
action = "deny"

# IXP route server -- no policy filtering
[[neighbors]]
address = "10.0.1.2"
remote_asn = 65100
description = "ixp-rs1"
hold_time = 90

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
| `families` entries must be `"ipv4_unicast"` or `"ipv6_unicast"` | `unsupported address family` |
| Policy prefix length must not exceed AFI max (32 for IPv4, 128 for IPv6) | `invalid prefix length` |
| Config file must be valid TOML | `failed to parse TOML` |

### Defaults applied at runtime

| Field | Default value |
|-------|---------------|
| `hold_time` | 90 seconds |
| `connect_retry_secs` | 30 seconds (not configurable) |
| `grpc_addr` | `127.0.0.1:50051` |
| `ttl_security` | `false` |
| `families` | `["ipv4_unicast"]` for IPv4 peers; `["ipv4_unicast", "ipv6_unicast"]` for IPv6 peers |
| `description` | peer address used as label |
| Policy default action | permit (when no entry matches) |
