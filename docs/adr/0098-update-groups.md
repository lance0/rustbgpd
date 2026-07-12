# ADR-0098: RIB-level update groups — shared outbound staging

**Status:** Accepted — shipped across #674 (fingerprint registry, shadow
mode), #676 (group staging + source-flip fanout + lifecycle), and the
cold-path/payload slice (route-refresh replay, `Arc` announce payload,
FxHash outbound caches). Extended to VPNv4/VPNv6 with per-member RT
filtering by [ADR-0099](0099-update-groups-v2.md).
**Date:** 2026-07-03

## Context

The 2026-07-03 CPU measurement pass (rrharness: the real `RibManager` +
real transport `PeerSession`s over loopback TCP, pprof-sampled) showed
RR fanout convergence dominated by per-peer outbound staging:
**staging + AdjRibOut = 82.8% of RR CPU at 256 uniform clients**, with a
single-shot 100k-route convergence of 15.1 s at 256 peers (~59 s
extrapolated at 1000). The cost was structural: the export tail
(split-horizon, RFC 4456 suppression, family/LLGR gates, policy eval,
equality diff, AdjRibOut insert) ran once per (peer × prefix), and the
per-peer AdjRibOut stored a full `Route` per (peer × prefix) — the dhat
structural memory ceiling at scale.

BIRD/FRR solve this with update groups that share **encoded packets**,
which forces the group key to include every negotiated encode option.
rustbgpd's layering is different — all per-peer wire preparation
(NEXT_HOP rewrite, ORIGINATOR_ID/CLUSTER_LIST, GShut, LLGR §4.6, encode
options) lives in transport's per-session `prepare_outbound_attributes`,
not in RIB staging — so rustbgpd can share **staged routes**, one layer
up, with a key built only from RIB-staging inputs.

## Decisions

1. **Group key = RIB-staging inputs only; content-equality, never Arc
   identity.** The fingerprint is (export-chain *content* via
   `PolicyChain: PartialEq`, `target_is_ebgp`, `target_is_rr_client`,
   sendable unicast family set, advertised LLGR family set). A SIGHUP
   rpol overlay or ADR-0076 txn that reinstalls a content-identical
   chain is key-stable: no regroup, no resync, nothing emitted. Chains
   that match on peer context (`requires_peer_context()`, mirroring
   `requires_as_path_string`) disqualify the peer instead of entering
   the key.

2. **Structural fallback, no config knob.** Peers hitting a v1
   disqualifier — peer-context policy, Add-Path send, ORR vantage
   (ADR-0095 Decision 5), ORF-receive — keep today's per-peer path
   wholesale. Grouping is decidable per peer; correctness never depends
   on it. The ungrouped reason is operator-visible (`rbgp neighbor
   show`, `bgp_update_group_fallback_peers`).

3. **One body serves both paths.** The shared group pass reuses
   `distribute_single_best_prefix` parameterized by `ExportTarget::Peer`
   vs `ExportTarget::Group` — never copied. The per-peer path is the
   group path's correctness oracle forever: a differential test suite
   drives identical scenarios through grouped vs forced-ungrouped
   managers and asserts identical per-peer streams (including RFC 2918
   refresh, GShut forced refresh, joins, leaves, regroups).

4. **Group-owned table, O(1) members, derived per-member views.** Each
   group owns ONE staged table (`GroupRibOut`, the unicast `AdjRibOut`
   substrate, source peer preserved). A member's advertised set is
   `group table − own-sourced entries` — **no per-peer unicast
   Adj-RIB-Out storage exists for grouped members**. Per-member updates
   derive from the shared delta by the source-flip matrix, decided from
   `(member == new source, member == old source)` alone; split horizon
   is applied at member emit, not in the key. Non-unicast families ride
   the existing per-peer path in the same `OutboundRouteUpdate`.

5. **Cold paths replay the table instead of re-staging.** Join / initial
   dump / RFC 2918 route-refresh response / GShut force-refresh replay
   the group table (family-filtered, own-source-excluded) with no policy
   re-evaluation; export counters replay from staged residue as integer
   adds (`totals − own-sourced`). Queries (advertised routes/count, BMP
   stat-17 family counts, adj-rib-out gauges) synthesize the same way,
   O(1) via per-source counts.

6. **Shared `Arc` announce payload with exception fallback.**
   `OutboundRouteUpdate.announce` is `Arc<[Route]>` (and
   `next_hop_override` `Arc<[Option<NextHopAction>]>`): the group pass
   pre-builds ONE announce vector and every in-sync member whose matrix
   output equals it (any member that is neither the new nor the
   displaced source of any delta — the overwhelming majority) enqueues
   an Arc clone. Exception members fall back to the per-member matrix
   walk. This removes the last per-member O(prefixes) cost from the
   manager task: at 1000 × 100k the old shape cloned 100 M `Route`
   shells.

7. **FxHash on the transport outbound caches.** The flamegraph's top
   prepare+encode line was SipHash over `PreparedAttrCacheKey` /
   `AttrGroupKey`. Both maps are per-`send_route_update`-batch and keyed
   by route data of configured peers under enforced `max_prefixes` —
   the same bounded-HashDoS tradeoff as the #308 route maps (rationale
   block in `rib::adj_rib_in`, mirrored at the top of
   `transport::session::outbound`).

8. **Exact exportability is a per-member precommit overlay, not a group-key
   input.** One immutable session encoder snapshot is attached to each
   route-bearing envelope. After shared staging, every candidate is probed in
   its final one-route wire form before that member's Adj-RIB-Out projection is
   committed. A sparse `(peer, route identity)` rejection overlay subtracts
   unexportable routes from grouped advertised queries and BMP counts without
   splitting otherwise-identical 4096-byte and Extended Message peers into
   separate groups. A newly rejected prior advertisement is withdrawn;
   recompute/resync retries it, while a source withdrawal simply retires an
   identity that was never advertised. The transport Cease/8 path remains the
   defense for a missing/mismatched snapshot or a live-encoder invariant
   breach.

## As-built deviations from the design report

- **Dirty resync is state-equivalent, not stream-equivalent.** A grouped
  member keeps no per-peer advertised record, so its resync deliberately
  over-emits: full-table announce + withdraw of `tombstones ∖
  still-retained` (spurious withdraws are RFC 4271 no-ops — the safe
  direction). The oracle compares folded final state for this scenario.
- **Advertised = intended state for grouped members.** The group table
  advances at staging time (before the per-member channel send), so a
  grouped member's synthesized "advertised" view is the intended state,
  healing via the dirty resync — vs the per-peer path's
  commit-after-send discipline. Three lifecycle tests pin the per-peer
  discipline unchanged.
- **Counter semantics.** Per-peer export-policy counters are replayed
  from group verdicts as aggregated integer adds rather than recorded
  per (prefix × peer); joins and refreshes reconstruct from per-entry
  policy-label residue (refresh family-scoped). Totals match the
  per-peer path; per-(prefix × peer) prometheus lookups disappear for
  grouped members.
- **`pending_extra_withdraws`.** A dirty member that regroups carries
  the old group's tombstones as extra (over-)withdraws into the
  destination resync — a case the design's lifecycle sketch glossed.
- **Per-member exportability overlay.** The group table remains the shared
  post-policy intent. Each member's advertised projection subtracts its sparse
  exact-export rejection set, including on queries, BMP stat 17, dirty resync,
  and regroup. This keeps group identity independent of negotiated wire size
  while preserving commit-after-exact-probe semantics per peer.

## Consequences

- rrharness flood (100k routes × 256 uniform RR clients, same host):
  single-shot convergence **15.1 s → 1.41 s (slice 2) → 0.54 s
  (slices 3+4, ~28×)**; sustained flood 14 → 28 blocks per ~20 s
  (~0.73 s per 100k round). Bucket shares: staging+AdjRibOut 82.8% →
  30.5%, prepare+encode 61.5% → 32.3% (the SipHash line is gone),
  writer+syscall 2.9% → 21.8% — the pipeline is now substantially
  wire-bound, which is where a reflector should spend its cycles.
- Per-peer unicast AdjRibOut memory for grouped members goes from
  O(peers × prefixes) full `Route`s + tries to one table per group +
  O(1) per member.
- Two live implementations of export semantics remain the standing risk
  (design risk 1); the parameterized-body rule plus the differential
  oracle are the mitigation, and any new export-tail feature must
  either land in the shared body or disqualify.
- Observability: `bgp_update_groups`, `bgp_update_group_members{group}`,
  `bgp_update_group_regroups_total`, `bgp_update_group_fallback_peers`;
  per-peer membership/reason via `NeighborState.update_group`. Exact-export
  failures add `bgp_exact_export_rejections_total{peer,family,reason}`; labels
  are bounded, and peer series are reaped when configuration deletes the peer.
