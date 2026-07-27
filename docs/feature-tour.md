# Feature tour

The full-depth version of the README's highlights: what each headline
feature actually contains, with the receipts and reference pages behind
it. If you want the one-screen version, read the
[README](../README.md); if you want the design rationale, read
[DESIGN.md](DESIGN.md) and the [ADRs](adr/).

## API-first control plane

Full gRPC control surface across twelve services (eleven native
`rustbgpd.v1` services plus the OpenConfig `gnmi.gNMI` service) and a
thin CLI (`rbgp`) with colored tables, dynamic column alignment, and
human-readable uptimes. Dynamic peer management, dynamic-neighbor and
FIB-table CRUD, route injection, policy CRUD, peer groups, BFD
inspection, EVPN
instance queries, streaming events, and daemon control without
restarts. Service-by-service reference: [API.md](API.md); CLI command
map: [`crates/cli/README.md`](../crates/cli/README.md).

## Native route explainability

Answers "why is this route (not) here?" from the live RIB in one
command: best-path explain with decisive-comparison attribution, export
explain that dry-runs the real per-peer gate ladder, a retained
rejected-route view with machine-readable reasons, and opt-in
import-decision explain (`[policy.explain] enabled = true`, which
retains a decision cache per session) — where incumbents need an
external looking-glass stack for less. Catalog of every explain
surface: [explain.md](explain.md).

## Dual-stack and modern protocol support

MP-BGP, Add-Path, Extended Next Hop, Extended Messages, GR/LLGR/
Notification GR, Route Refresh/Enhanced Route Refresh, receive-side
Prefix ORF, FlowSpec, Route Reflector, large and extended communities.
Per-RFC conformance notes: [RFC_NOTES.md](RFC_NOTES.md).

## Typed, compiled policy language (`.rpol`)

Named prefix/community sets compiled to indexed matchers, parameterized
policies, policy composition, and in-language unit tests
(`rbgp policy check`); candidate policies dry-run read-only against the
live RIB (`rbgp policy test`), decisions explain themselves per term
(`rbgp policy explain`), and installed chains expose live per-term hit
counters (`rbgp policy stats`). Mixes freely with the existing TOML
policy chains; FRR route-map parity proven route-for-route in interop
(M80). Designed under ADR-0096. Full language reference:
[rpol-language.md](rpol-language.md).

## Full BMP monitoring trio

RFC 7854/8671/9069 (ADR-0097): per-collector selectable Adj-RIB-In
(pre-policy), Adj-RIB-Out (post-policy, byte-exact wire PDUs), and
Loc-RIB views on one exporter. Loc-RIB collectors get a chunked table
dump + End-of-RIB when they connect; Adj-RIB-In/Out are live streams by
design. Optional per-collector BMPv4 TLV framing plus the Path Marking
TLV (draft-ietf-grow-bmp-tlv / draft-ietf-grow-bmp-path-marking-tlv,
pre-IANA — code points may renumber; default stays BMP v3). Validated
against pmacct, gobmp, and tshark at once (M81).

## Operational visibility

Prometheus metrics, gNMI / OpenConfig BGP telemetry (`Capabilities` /
`Get` / `Subscribe`, RFC 7951 JSON over mTLS) plus a transaction-backed
`Set` subset for static numbered-neighbor config, BMP export to
collectors (all three RIB views), MRT TABLE_DUMP_V2 snapshots, a
Birdwatcher-shaped status/peer/accepted/filtered/noexport REST subset
via the external `examples/birdwatcher-adapter`, structured JSON logging, and
per-peer counters. The explain surfaces have their own catalog:
[explain.md](explain.md). gNMI operator guide: [GNMI.md](GNMI.md);
Grafana dashboard: [GRAFANA.md](GRAFANA.md).

## Update-group fanout

Peers whose staged output is provably identical automatically share one
outbound staging pass and one Arc-shared announce payload (ADR-0098,
ADR-0099); measured ~28x faster 100k-route convergence at 256 uniform
RR clients (15.1 s to 0.54 s), and 1.8 s wire-measured convergence /
419 MiB process RSS at 1,000 uniform RR clients x 100k routes
([scale receipt](perf/scale-receipt-2026-07.md)), with a structural
per-peer fallback (no knob) and a differential oracle pinning identical
wire behavior. v2 extends the sharing to VPNv4/VPNv6 with the RFC 4684
RT filter applied per member at emit: 1,000 clients x 100k VPNv4
converge in 12.6 s / 625 MiB uniform and 3.9 s / 636 MiB with
heterogeneous ~10% RT memberships (vs ~73 s / ~31 GiB and
~12.5 s / ~5.7 GiB extrapolated per-peer), and a member's RT-membership
flip at 100k staged routes hits the wire in ~15 ms with zero policy
evaluations.

## Route-reflector families beyond unicast

BGP-LS receive/reflection/API export (RFC 9552), VPNv4/VPNv6 L3VPN
route-reflection (RFC 4364 / RFC 4659, SAFI 128 — RR/controller-feed
with RD, MPLS label stack, next-hop, and Route Targets preserved
verbatim; no VRF import or MPLS FIB), RT-Constrain (RFC 4684, SAFI 132
— strict per-peer VPN reflection filtering), and IPv4/IPv6
labeled-unicast route-reflection (RFC 8277, SAFI 4 — label stack and
next-hop preserved verbatim) have shipped under ADR-0077, and
**Optimal Route Reflection (RFC 9107, ADR-0095)** computes per-client
best paths via SPF over the BGP-LS-sourced topology — a capability no
other open-source BGP daemon ships. Future BGP-LS local topology
production stays scoped by
[ADR-0077](adr/0077-mpls-vpn-bgpls-address-family-boundary.md): those
families must land as typed route-family slices or unreachable
substrate, not as unicast `Prefix` shortcuts or MPLS dataplane creep.

## Reusable wire codec and FSM

`rustbgpd-wire` has zero internal dependencies and `rustbgpd-fsm`
depends only on `wire`; both are published as daemon-independent crates
for Rust BGP tooling that does not need the full router. See
[EMBEDDING.md](EMBEDDING.md).
