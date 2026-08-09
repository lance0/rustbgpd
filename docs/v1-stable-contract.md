# Narrow v1 route-server / route-reflector contract

rustbgpd remains a public-alpha project overall. This document defines a much
narrower compatibility promise for deployments that use rustbgpd as an IPv4 /
IPv6 unicast route server or route reflector. It does not make every protocol,
configuration key, RPC, CLI command, or Linux dataplane role stable.

The machine-readable source of truth is
[`v1-stable-surface.json`](v1-stable-surface.json). CI checks its config fields
against the generated JSON Schema, its RPC and top-level request/response
signatures against the protobuf, its RPC membership against the authorization
inventory, its CLI paths against the Clap tree, and its consecutive-release
upgrade receipt. A surface absent from that file is outside the v1 promise.
[ADR-0125](adr/0125-v1-stability-contract.md) defines the accepted evidence bar
for turning this narrow promise into a v1.0 tag; acceptance schedules no tag
and freezes nothing beyond the inventory until that evidence is complete.

## Role matrix

| Classification | Role / family | Supported boundary |
|---|---|---|
| **Stable** | `route-server-unicast` — IPv4/IPv6 unicast route server | Control-plane route-server operation, RFC 7947 transparency, Add-Path and proven per-client-best path-hiding mitigation, RPKI/ASPA policy, Roles/OTC, policy explain/test/stats, and the inventoried management/observability surfaces. |
| **Stable** | `route-reflector-unicast` — IPv4/IPv6 unicast route reflector | Control-plane reflection, Add-Path where negotiated, ORR where configured, policy, and the inventoried management/observability surfaces. |
| **Scoped RR-only** | `route-reflector-bgp-ls` — BGP-LS / BGP-LS VPN | Receive, reflect, query, and ORR topology input. No local topology origination or general link-state controller promise. |
| **Scoped RR-only** | `route-reflector-l3vpn` — VPNv4/VPNv6 | Route reflection and controller-feed use only. No PE VRF import, CE attachment, MPLS forwarding, or dataplane programming promise. |
| **Scoped RR-only** | `route-reflector-labeled-unicast` — IPv4/IPv6 labeled-unicast | Receive, reflect, and query. Labels are not installed in a forwarding plane. |
| **Scoped RR-only** | `route-reflector-rtc` — RT-Constrain | Receive, reflect, query, and VPN export membership within the RR boundary. |
| **Alpha** | `evpn` — EVPN RR, VTEP, IRB, multi-homing | Functional and interop-tested slices exist, but EVPN remains outside this v1 compatibility promise, including RR-only EVPN. |
| **Alpha** | `linux-dataplane` — Linux FIB and managed netdev roles | Opt-in and tested, but not part of the control-plane RS/RR v1 contract. |
| **Experimental** | `paths-limit` — Paths-Limit | Draft capability; semantics and wire assignments are not stable. |

FlowSpec, BFD, gNMI, TCP-AO runtime lifecycle, BGP unnumbered, and other
unlisted features continue to follow the project-wide alpha posture even when
individual slices are interoperable. In particular, “shipped” or “tested” does
not automatically mean “v1 stable.”

## Stable surfaces

The inventory pins individual config fields rather than whole structs. This is
intentional: for example, core `Neighbor` route-server and route-reflector
fields are stable while `Neighbor.tcp_ao`, `Neighbor.bfd`, and
`Neighbor.interface` remain outside v1. The same rule applies to RPCs: the
inventory pins the native gRPC method name, request type, response type, and
streaming mode. Each stable config definition's digest covers the selected
property schemas, its complete (order-independent) required-field set, and its
unknown-field policy. Unselected optional sibling properties and descriptive
prose remain outside that digest, so additive optional siblings stay possible.
The ten contextual defaults scoped by this contract update
are pinned separately under `config.effective_defaults`. Their named resolver
test loads real TOML and checks omission, peer-group inheritance, derived
values, direct overrides, address-dependent family synthesis, and conditional
route-reflector behavior. This is a deliberately scoped guard, not an exhaustive
catalog of every config omission behavior. Eight values remain description-only
in the JSON Schema. `Global.dynamic_neighbor_limit = null` and
`Neighbor.families = []` are pinned separately as serialization/schema
representations of omission; they are not the runtime defaults of 100 and the
address- and inheritance-dependent family set. The Python release checker pins
the exact inventory, those two representation values, the daemon's shared
dynamic-neighbor-limit accessor, and linkage to a live, non-ignored Rust test;
the focused Cargo test executes that test and detects runtime resolver changes.
Nested protobuf evolution follows the compatibility rules below. The
message-graph digest is a review tripwire, not an implicit promotion:
experimental fields such as Paths-Limit are explicitly excluded in the
inventory and may evolve under their experimental contract after review. The
new update-group impact projection and alpha EVPN/BFD/dataplane event payloads
are excluded the same way even though they are reachable through otherwise
stable transaction or event envelopes.

The stable CLI set is also explicit. For an inventoried command, the v1 promise
covers only its command path and command name. Flags, positional arguments,
defaults, exit behavior, and human-readable output remain outside v1 unless a
separate inventory entry explicitly pins them. The versioned machine formats
currently include `rbgp-ribdiff/1` and `rbgp-ribsnap/1`. The ribdiff report may
gain additive fields, but removing or reinterpreting existing fields is not
compatible. The ribsnap parser is intentionally closed and rejects unknown
fields; changing its record schema requires a new format version rather than an
in-place additive change. Each format inventory names the CLI paths that expose
it. Every pinned ribsnap golden is also linked to the exact BIRD, FRR, GoBGP,
MRT, or BMP producer test that creates it; the executable floor checks every
record in those real goldens and then passes each complete artifact through the
fail-closed parser. The neighbor-detail JSON and support-bundle manifest v2 pin
required and optional key/type floors, including promised nested object shapes,
in their serializer contract tests while allowing additive fields.

Prometheus metrics and structured event payloads used by the stable roles are
covered by semantic rules rather than a promise that no new metric, event kind,
or optional field will appear. Consumers must ignore unknown additive fields
and series.

## Compatibility rules

- **Protobuf:** stable RPC names, streaming modes, top-level request/response
  types, existing field numbers/types, and enum numeric values do not change in
  v1. Additive optional fields and new RPCs are allowed. Removed field numbers
  and names stay reserved.
- **Config:** a stable field may gain optional siblings with documented safe
  defaults. Removing, renaming, changing the type, changing the effective
  default, changing required-field membership, or changing whether unknown
  fields are accepted is breaking.
- **rpol:** grammar additions must keep existing v1 programs parseable and
  preserve the golden decision corpus. A change to an existing program's
  accept/reject result or emitted modifications is breaking even if it still
  parses.
- **Metrics:** stable names and metric types remain; existing label names and
  meanings are not removed or reinterpreted. New bounded labels and metrics
  are additive.
- **Events / JSON:** existing event kinds and fields retain their meaning. New
  optional fields and event kinds are additive. Consumers must ignore unknown
  fields.

Breaking changes to the inventoried surface require a new contract major, a
CHANGELOG entry, a migration guide, and a consecutive-release fixture accepted
by the new release. Once v1.0 is tagged, an inventoried surface deprecated in 1.x
remains functional for the rest of 1.x and is removable no earlier than 2.0.
Migration compatibility covers the current and immediately previous minor
release. Security fixes support the latest 1.x release; that is a separate
promise and does not extend migration compatibility into security support.

## Mutation and reload model

The canonical live-mutation path is:

1. `PlanConfigTransaction` against the current runtime snapshot token.
2. `ApplyConfigTransaction` with that token.
3. For commit-confirmed changes, `ConfirmConfigTransaction` or
   `AbortConfigTransaction` before the deadline.

`rbgp config plan/apply/confirm/abort/status` is the operator CLI for this
lifecycle. Mutation-specific RPCs may remain for focused automation, but they
do not bypass validation, persistence, or the daemon's single-writer planning
boundary.

Unary `PlanConfigTransaction` / `ApplyConfigTransaction` is the permanent
small-candidate path and remains in the frozen inventory. Streaming Plan/Apply,
`ListConfigHistory`, and `RollbackConfigTransaction` remain outside the initial
v1 inventory; production use does not promote them implicitly. Each may be
added deliberately in a later 1.x minor through the inventory review.

SIGHUP remains the file-driven compatibility/reconcile path. It uses the same
planner for supported changes, but it is not a general atomic compound-mutation
API: the reload matrix decides which changes hot-apply, reset sessions, require
restart, or are rejected. Operators that need snapshot fencing and
commit-confirmed rollback must use the transaction path.

## Upgrade receipt

The first pinned exercise archives the complete v0.50.0 route-server example
(`config.toml` plus its referenced `hygiene.rpol`) under
`tests/fixtures/v1-stable/v0.50.0/`. The checker verifies every immutable byte
digest against the v0.50.0 git tag, and a dedicated current-parser test loads,
compiles, and validates that archived fixture under v0.51.0/current code. A
version-bump PR therefore does not require the not-yet-created target tag;
historical exercises require both release tags. The
inventory records the source/target releases, file and semantic TOML digests,
validation test, and result. The latest exercise must end at the workspace
release-line anchor (`vMAJOR.MINOR.0`); the exact workspace patch remains
recorded separately in `baseline_release`. Exercises form one contiguous chain
of adjacent minor release lines from the canonical `v0.50.0` history origin,
with an explicit transition into a new major. Future stable-surface migrations
add a new consecutive-release fixture rather than overwriting this receipt.

A deliberate release-numbering milestone jump — a target line more than one
step ahead, where the skipped intermediate lines never exist — may be recorded
by annotating that single exercise with `"milestone_jump": true` and a
non-empty `"jump_rationale"` string. The annotated exercise must still advance
to a later release line, keep the chain contiguous, and end at the workspace
anchor. An unannotated gap remains an error, and the annotation is rejected on
an exercise that is actually between consecutive release lines.

The v0.51.0 route-server example is staged byte-for-byte under
`tests/fixtures/v1-stable/v0.51.0/` and exercised by the current parser. The
v0.60.0 release records that fixture as the accepted v0.51.0-to-v0.60.0
milestone-jump upgrade exercise, extending the inventory's accepted release
chain to the v0.60.0 anchor. The v0.60.0 route-server example is likewise
archived under `tests/fixtures/v1-stable/v0.60.0/`; the v0.61.0 release records
it as the accepted consecutive v0.60.0-to-v0.61.0 exercise and proves it with
the current parser. The v0.61.0 route-server example continues the chain under
`tests/fixtures/v1-stable/v0.61.0/` as the accepted consecutive
v0.61.0-to-v0.62.0 exercise, proven the same way. The v0.62.0 route-server
example continues the chain under `tests/fixtures/v1-stable/v0.62.0/` as the
accepted consecutive v0.62.0-to-v0.63.0 exercise, proven the same way. The
v0.63.0 route-server example continues the chain under
`tests/fixtures/v1-stable/v0.63.0/` as the accepted consecutive
v0.63.0-to-v0.64.0 exercise, proven the same way.

## Release gate

Run:

```bash
python3 scripts/check-v1-stable-surface.py
cargo test -p rustbgpctl v1_stable_cli_command_inventory_matches_clap_tree
cargo test -p rustbgpd v1_stable_v0_50_route_server_fixture_parses
cargo test -p rustbgpd v1_stable_v0_51_route_server_fixture_parses
cargo test -p rustbgpd v1_stable_v0_60_route_server_fixture_parses
cargo test -p rustbgpd v1_stable_v0_61_route_server_fixture_parses
cargo test -p rustbgpd v1_stable_v0_62_route_server_fixture_parses
cargo test -p rustbgpd v1_stable_v0_63_route_server_fixture_parses
cargo test -p rustbgpd v1_stable_effective_defaults_match_runtime_resolution
```

Updating a digest is not a mechanical fix. Review the compatibility policy,
classify the change as additive or breaking, and add the required deprecation
or migration evidence first.
