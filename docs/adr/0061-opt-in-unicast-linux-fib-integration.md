# ADR-0061: Opt-in unicast Linux FIB integration

**Status:** Accepted
**Date:** 2026-05-14

## Context

rustbgpd computes IPv4 and IPv6 unicast best paths, reflects routes,
exports BMP / MRT / gRPC state, and now owns several specialized Linux
kernel paths:

- EVPN L2 FDB programming and BUM enforcement (`crates/evpn-linux`,
  ADR-0054 / ADR-0057 / ADR-0059).
- EVPN symmetric-IRB Type 5 import into an IP-VRF table (ADR-0058).
- RFC 7999 BLACKHOLE discard routes (`src/blackhole.rs`, ADR-0060).

It still does not program ordinary unicast Loc-RIB best paths into the
kernel. Closing that gap changes rustbgpd's product shape: it becomes
usable as an edge router in addition to route-server / control-plane /
EVPN roles.

That blast radius is larger than BLACKHOLE and less tenant-scoped than
EVPN L3VNI. The feature needs its own opt-in boundary, ownership model,
table-selection rules, and failure visibility before any kernel writes
land.

## Decision

### 1. General unicast FIB install is explicit opt-in

The default remains control-plane-only. Route reflectors, route
servers, and looking-glass deployments do not spawn a general FIB actor
and do not mutate the ordinary Linux routing table unless the operator
declares an explicit FIB table block.

The first schema slice adds:

```toml
[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
families = ["ipv4_unicast", "ipv6_unicast"]
```

The block is config-only in this ADR's first slice. It reserves the
operator contract without programming routes yet.

### 2. Table selection is explicit and non-reserved

rustbgpd will not silently write to the `main` table. Each table the
future actor may write to must be named in `[[fib_tables]]`.

Reserved Linux table IDs are rejected:

- `0` (`RT_TABLE_UNSPEC`)
- `252` (`RT_TABLE_COMPAT`)
- `253` (`RT_TABLE_DEFAULT`)
- `254` (`RT_TABLE_MAIN`)
- `255` (`RT_TABLE_LOCAL`)

Operators that want main-table programming can get a dedicated,
separately reviewed opt-in later. The first tranche uses non-reserved
tables to make coexistence with FRR, BIRD, static routes, and host
networking safer.

### 3. Metric is explicit

Each `[[fib_tables]]` entry requires `metric`. The metric becomes part
of the future owned-route identity and coexistence story; defaulting it
would hide an operationally important choice.

### 4. Families are unicast-only

`families` defaults to `["ipv4_unicast", "ipv6_unicast"]` when a
`[[fib_tables]]` block exists. Other families are rejected.

FlowSpec, EVPN, VPNv4/v6, and labeled-unicast are not part of the
ordinary FIB contract.

### 5. Initial route set is single-best

The first runtime slice should consume `RibUpdate::SubscribeRouteEvents`
as a wakeup and `RibUpdate::QueryBestRoutes` as the level-triggered
snapshot, matching `src/blackhole.rs`.

The existing unicast `RouteEvent` does not carry a full route, and the
Loc-RIB exposes one best route per prefix. ECMP therefore remains a
follow-up that needs a deliberate RIB query/view for install candidates.

### 6. Kernel route shape

The future Linux route apply path should start with ordinary rtnetlink
route messages:

- `RTM_NEWROUTE` / `RTM_DELROUTE`
- `RTN_UNICAST`
- configured `RTA_TABLE`
- configured `RTA_PRIORITY` / metric
- `RTPROT_BGP`
- gateway from the selected best route's next hop
- optional output interface only when the config grows one

Do not inherit `RTNH_F_ONLINK` from EVPN Gate 9. L3VXLAN needs `onlink`
because the next-hop is intentionally not reachable through that device.
Ordinary unicast should let the kernel validate reachability unless a
future config knob explicitly changes that behavior.

### 7. Ownership and foreign routes

The actor must own only rows it installed. It must preserve foreign
kernel routes by default.

Before any `replace`, the actor must prove the existing kernel row is
daemon-owned and matches the configured table/metric/protocol identity.
An existing static route, kernel connected route, FRR/BIRD route, or
operator route for the same prefix/table is a reported conflict, not a
silent overwrite.

The EVPN L3 owned-state model is the template: track route *values*, not
only route keys, so next-hop/metric/table drift emits a correction and
foreign drift is observable.

### 8. Reload and shutdown

Until a runtime swap surface exists, `[[fib_tables]]` edits are
restart-required and surfaced through config diff. A future hot-reload
slice may use a `watch<Arc<FibIntent>>` style actor, but the ADR does
not assume it.

Shutdown drains only daemon-owned rows with a bounded timeout. Missing
rows on delete (`ENOENT` / `ESRCH`) satisfy the post-condition and must
not wedge convergence.

### 9. Observability is required before default recommendations change

The first runtime slice must expose status via gRPC / CLI / Prometheus
before README language changes from "not the best fit" to "supported
edge-router role." At minimum, operators need installed / rejected /
failed counts and per-route reasons such as foreign conflict, kernel
apply error, unresolved next-hop, or unsupported family.

## Consequences

Positive:

- The default route-server / RR posture is preserved.
- The config makes table and metric choices explicit before kernel
  writes exist.
- The first implementation can be reviewed and tested without a
  privileged runner.
- The design reuses proven local patterns: route-event wakeups,
  periodic full reconcile, owned-state diffs, foreign preservation, and
  bounded drains.

Negative:

- No main-table programming in the first tranche, even for operators who
  already want it.
- ECMP is not part of the first runtime slice.
- `[[fib_tables]]` is restart-required until a hot-swap actor exists.

Neutral:

- `RTPROT_BGP` is an initial marker, not ownership proof by itself.
  Ownership is the full configured table/metric/protocol/route value plus
  daemon-owned state.
- Graceful Restart `forwarding_preserved=true` remains out of scope.
  Programming a FIB is not enough; preserved forwarding needs crash and
  restart semantics.

## What we rejected

- **Implicit main-table takeover.** Too much blast radius for a project
  whose default role is still control-plane / route-server.
- **Reusing `crates/evpn-linux` directly.** EVPN carries VNI, MAC,
  Router MAC, VXLAN, and ESI assumptions. General unicast needs its own
  boundary, though it should copy the reconciliation discipline.
- **Overwriting foreign routes by default.** Convenient, but unsafe on a
  host that may also run static routes, FRR, BIRD, NetworkManager, or
  systemd-networkd.
- **ECMP in slice one.** The netlink crate can encode `RTA_MULTIPATH`,
  but rustbgpd needs a deliberate RIB install-candidate view first.
- **Treating FIB install as export policy.** Adj-RIB-Out answers "what
  would I send to a peer"; kernel install is local operator intent and
  must have its own policy/config surface.

## Cross-references

- `src/blackhole.rs` — existing unicast kernel actor pattern.
- `crates/rib/src/update.rs` — `QueryBestRoutes` and
  `SubscribeRouteEvents`.
- `crates/rib/src/event.rs` — unicast route event shape.
- `crates/evpn-linux/src/l3_diff.rs` — value-aware owned-state diff
  pattern.
- `crates/evpn-linux/src/linux/l3.rs` — existing rtnetlink route apply
  helper for EVPN IP-VRF tables.
- ADR-0054 — EVPN Linux dataplane boundary.
- ADR-0058 — EVPN Gate 9 L3VNI / Type 5 FIB programming.
- ADR-0060 — RFC 7999 BLACKHOLE receiver and discard routes.
