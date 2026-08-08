# IXP route-server evaluation matrix

One page for an exchange evaluating rustbgpd as a route server: the
capabilities IXP evaluations actually score, each with its current
status and a link to the config, cookbook, ADR, or measurement receipt
that backs it. Statuses are deliberately conservative — an "In
progress" row says exactly what is missing, and where an incumbent
currently does better, the row links the comparison rather than
omitting it. To evaluate against live members with zero blast radius,
start with the
[route-server shadow pilot](cookbook/route-server-shadow-pilot.md).

| # | Capability | Status | What exists | Evidence |
|---|------------|--------|-------------|----------|
| 1 | Config generation (arouteserver pipeline) | Yes | Keep your `general.yml` / `clients.yml` and refresh cadence: `arouteserver template-context` → in-repo `rs-config-render` → fail-stale render → `--check --strict` validated reload, proven end to end against the pinned official arouteserver image. Upstream arouteserver has no rustbgpd target — the render step is maintained here, not there. | [IXP filter pipeline](cookbook/ixp-filter-pipeline.md) · [`tools/rs-config-render/`](../tools/rs-config-render/README.md) · [ADR-0110](adr/0110-irr-peeringdb-filtering-pipeline.md) |
| 2 | RFC 7947/7948 route-server semantics | Yes | Byte-level transparent redistribution (verified on the wire against BIRD/GoBGP/FRR), both §2.3.2 path-hiding mitigations (Add-Path and per-client best-path), RFC 7948 §4.8 next-hop ownership rejection. | [Route-server cookbook](cookbook/route-server.md) · [ADR-0101](adr/0101-route-server-profile.md) · [ADR-0107](adr/0107-route-server-next-hop-ownership.md) · M83/M19 in [RECEIPTS.md](RECEIPTS.md) |
| 3 | BGP communities | Yes | Standard, extended, and large communities in matching and actions across TOML and `.rpol` policy; RFC 7947 §2.3.2 / RFC 8195 control communities (per-target announce / no-announce / prepend, scrubbed on egress, transparency preserved for non-participating sessions). Extended-community control forms are deliberately not implemented. | [RFC notes](RFC_NOTES.md#rfc-7947-232--rfc-8195--route-server-control-communities) · [control-community matrix](cookbook/route-server.md#member-set-control-communities-rfc-7947-232--rfc-8195) |
| 4 | RPKI: invalid = reject | Yes | RTR client with multi-cache union, RFC 6811 validation with `maxLength` enforced in the Invalid determination, invalid = reject at import in one deny statement; later VRP updates trigger inbound Route Refresh so verdicts track the cache. | [`[rpki]` reference](CONFIGURATION.md#rpki) · reject-at-import lab (M83) in [RECEIPTS.md](RECEIPTS.md) · rendered hygiene chain in the [pipeline](cookbook/ixp-filter-pipeline.md) |
| 5 | IRR-based filtering | Yes | Per-member IRR prefix/origin sets (bgpq4-expanded, from arouteserver's resolved data model) rendered into trie-backed `.rpol` sets, refreshed on your existing cadence, fail-stale on any implausible or broken IRR answer. The daemon has no native IRRd/bgpq4 client — ingest rides arouteserver's. | [IXP filter pipeline](cookbook/ixp-filter-pipeline.md) · [ADR-0110](adr/0110-irr-peeringdb-filtering-pipeline.md) |
| 6 | Looking glass incl. filtered routes | Yes | Alice-LG through the birdwatcher adapter: status, peer, and accepted views, a filtered-route view served from the daemon's reject-retention store (with machine-readable reject-reason communities), and a noexport view from a live export dry run. Coverage is IPv4/IPv6 unicast single-table only. | [birdwatcher adapter](../examples/birdwatcher-adapter/README.md) · [Alice-LG wiring](cookbook/ixp-filter-pipeline.md#6-looking-glass-alice-lg-via-the-birdwatcher-adapter) |
| 7 | Reload at IRR scale | Yes | Four fresh sealed roots compare rustbgpd, BIRD 3.3.1, and OpenBGPD 9.1 at 320 members × 183,040 routes with 3,218,965 IRR filter entries. The receipt publishes the real losses — BIRD leads completion and rustbgpd uses substantially more memory — alongside the grouped-control result and the later grouped per-client-best improvement. | [IRR reload comparison](perf/irr-reload-comparison-2026-08.md) · [grouped per-client-best receipt](perf/irr-reload-grouped-per-client-best-2026-08.md) |
| 8 | Paired-RS operations | Yes | Runbook for two independent route servers: why members peer with both, staggered config updates, inter-RS consistency checked with `rbgp diff advertised`, and the maintenance-window drain flow (RFC 8326). | [Paired route servers](cookbook/paired-route-servers.md) |
| 9 | MANRS documentation | Yes | MANRS IXP Programme Action 1 mapped requirement-by-requirement to validated config fragments and the surfaces that make each control member-verifiable. | [MANRS IXP Action 1](cookbook/manrs-ixp-action1.md) |

Related evaluation material: the broader daemon
[feature comparison](COMPARISON.md), the
[reload classification of every config field](reload-matrix.md), the
[receipt index](RECEIPTS.md) behind every wire-behavior and performance
claim, and the [migration notes](cookbook/route-server-migration.md)
for mapping an existing BIRD / OpenBGPD / ARouteServer deployment.
