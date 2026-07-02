# ADR-0095: Optimal Route Reflection via BGP-LS-sourced SPF (RFC 9107)

**Status:** Accepted — shipped across #628 (typed BGP-LS topology accessors),
#629 (topology graph + SPF engine + `rbgp topology`), #630 (`orr_vantage`
config + vantage registry + cached SPF), #631 (per-vantage best selection),
with the M76 divergent-best interop receipt.
**Date:** 2026-07-02

## Context

A route reflector runs one best-path selection from its own position and
reflects that single answer to every client. Clients far from the RR get
exits that are optimal for the RR, not for them — the classic RR
sub-optimality RFC 9107 exists to fix. ORR re-runs exactly one step of the
RFC 4271 decision process — the interior-cost-to-NEXT_HOP tiebreak — from a
configured **IGP location** ("vantage"): a node in the topology identified
by one of its IP addresses.

RFC 9107 §3.1 admits two topology sources: a link-state IGP (rustbgpd runs
none and will not) or **BGP-LS** — which rustbgpd receives, stores, and
reflects since the ADR-0077 arc. That made ORR implementable here without an
IGP: the RR's clients' IGP feeds BGP-LS (directly or via the fabric's
existing BGP-LS producers), and the RR runs SPF over that feed. No
open-source BGP daemon ships ORR (FRR's request has been open since 2018;
BIRD/GoBGP/OpenBGPd lack it); only commercial routers do.

## Decisions

1. **Node identity is the canonical descriptor byte string** — protocol-id +
   identifier + the raw TLV-256/257 node-descriptor container value bytes
   (`BgpLsNodeKey`). Link endpoints intern to nodes by byte equality; no
   per-protocol IGP Router-ID interpretation is needed for graph
   construction (RFC 9552's mandatory ascending TLV order, already enforced
   by the decoder, makes byte equality sound). Router-ID parsing is
   display-only (CLI).

2. **The BGP-LS Attribute (path attribute 29) is never typed.** It stays
   `PathAttribute::Unknown(RawAttribute)` end-to-end so reflection re-encodes
   it verbatim (the fidelity M73 pins). The topology builder parses the raw
   bytes lazily and locally: IGP Metric (TLV 1095, 1/2/3-byte forms) as link
   cost — a link without it contributes no edge; Prefix Metric (TLV 1155)
   for reachability cost; TE Default Metric (1092) parsed but unused;
   Multi-Topology deferred.

3. **Next-hop resolution**: exact match on link interface/neighbor addresses
   (TLVs 259–262) wins outright — an unreachable owner is a real
   unknown-cost answer, not a fall-through; otherwise longest-prefix match
   over Topology Prefix NLRIs (min over advertisers of SPF distance +
   prefix metric); otherwise unknown. Unknown cost is **least preferred**
   per RFC 9107's mandate for unresolvable metrics.

4. **Per-vantage bests are computed at distribution time — shadow
   per-vantage Loc-RIBs were considered and rejected.** The Loc-RIB keeps
   its single-best-per-prefix invariant. For a peer bound to a resolved
   vantage, the per-target candidate set (all Adj-RIB-Ins, split-horizon and
   RFC 4456 suppression applied per target, exactly the Add-Path multipath
   collector) is ranked by the standard decision chain with one added step —
   RFC 4271's interior-cost slot (after eBGP/iBGP, before CLUSTER_LIST) —
   using the vantage's SPF cost. Shadow RIBs would multiply memory by the
   vantage count and add an invalidation protocol; distribution-time
   selection costs CPU only when topology or candidates change and only for
   ORR peers.

5. **No per-(vantage, prefix) winner memo — it would be unsound.** The
   candidate set is per-target-peer (split horizon and reflection
   suppression drop different routes for different targets), so a memoized
   winner could be a route the next target must never receive. The sound
   cache is the per-SPF next-hop-cost LRU. Similarly, because ORR peers
   select from candidates rather than the Loc-RIB best, a candidate change
   that leaves the Loc-RIB best untouched can still flip a vantage best —
   ORR peers therefore stage every affected prefix (the Add-Path staging
   parallel).

6. **SPF is a hand-rolled binary-heap Dijkstra** (no graph dependency), one
   run per **distinct** vantage, cached on the RibManager and rebuilt at
   every BGP-LS mutation seam through the single `recompute_bgpls_keys`
   chokepoint (receive, Enhanced-Refresh sweep, GR sweep in the
   recompute-then-GC order, peer teardown). Change detection uses a
   canonical key-addressed SPF signature — raw distance vectors are
   unstable across interning orders. Changed vantages dirty their bound
   peers; the Adj-RIB-Out equality machinery emits the minimal delta. With
   no vantages configured the engine early-outs: zero steady-state cost.

7. **Vantage config** (`orr_vantage = "<ip>"`, neighbor + peer-group with
   standard inheritance) requires an iBGP route-reflector client; an
   unresolved vantage falls back silently to the standard best (surfaced by
   `rbgp orr` and a transition log, never a session error). Unicast v4+v6
   only in v1.

## Deferred (with un-defer triggers)

- **Backup IGP locations** (RFC 9107 SHOULD) — when an operator asks for
  vantage redundancy.
- **Inter-RR Add-Path** (required by RFC 9107 only for multi-cluster
  deployments) — when a second-RR topology lands.
- **VPN-ORR** (vantage ranking for SAFI 128) — **shipped**: an ORR
  client's VPNv4/VPNv6 routes are ranked with its vantage's interior
  cost to each candidate's next-hop, exactly like unicast
  (`vpn_tiebreak_orr`, same slot in the chain; the RFC 4684 RTC gate
  applies to the vantage winner).
- **TE / Multi-Topology metrics** — operator demand.
- **RFC 9107 §3.2 per-policy multiple Decision Processes** — policy
  divergence below step (e) is out of scope until a concrete case appears.

## Consequences

rustbgpd is the first open-source BGP daemon with working ORR. The cost is
a derived-state engine (topology + SPF) between BGP-LS ingest and unicast
emission — bounded by the early-out, the distinct-vantage dedup, and the
per-SPF LRU — and a second best-path entry point (`best_path_cmp_orr`)
pinned to the legacy chain by a property-test oracle. M76 proves live
divergence: two GoBGP clients of one RR receive different bests for the
same prefix, flip correctly on a topology metric change, and collapse to
the identical standard best when the topology is withdrawn.
