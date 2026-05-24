# ADR-0066: Unicast multipath / ECMP FIB install

**Status:** Accepted — supersedes ADR-0061's ECMP deferral.
**Date:** 2026-05-24

## Context

ADR-0061 shipped the general unicast Linux FIB: configured `[[fib_tables]]`
receive the Loc-RIB best route, one next-hop per prefix. It explicitly deferred
ECMP, naming the prerequisite:

> Loc-RIB exposes one best route per prefix. ECMP therefore remains a follow-up
> that needs a deliberate RIB query/view for install candidates.

FRR, BIRD, GoBGP, and Cisco all expose classic `maximum-paths`-style forwarding
load-balancing: select N equal-cost BGP paths for a prefix and install them as a
kernel multipath route. rustbgpd's `COMPARISON.md` marked Multipath/ECMP as
**Partial** — Add-Path multi-path *send* and EVPN aliasing ECMP (ADR-0059 FDB
nexthop groups) ship, but unicast forwarding ECMP did not. This ADR closes that
gap.

## Decision

Install up to N equal-cost BGP paths per prefix as a kernel `RTA_MULTIPATH`
route, **opt-in per table** via `[[fib_tables]].maximum_paths` (unset / `1` ==
today's single-next-hop behavior). Both eBGP and iBGP paths are eligible, but a
multipath group is **homogeneous** — it never mixes classes.

### Install-candidate view (the ADR-0061 prerequisite)

A new RIB query, `RibUpdate::QueryFibInstallCandidates { max_paths }`, returns
one `FibInstallCandidate` per Loc-RIB best route: the best route plus its
equal-cost next-hop set. For each best route the manager re-scans the per-peer
Adj-RIB-In for siblings of that prefix and keeps those that are
`multipath_equal` to the best. The set is ordered best-first (index 0 is the
best route's next-hop), then by `(next_hop, peer, path_id)`, deduplicated by
next-hop, and capped at `max_paths`. `QueryBestRoutes` is untouched — other
consumers still get exactly one best route per prefix.

The candidate type carries provenance (`FibInstallNextHop { next_hop,
link_local_next_hop, peer, path_id }`), not a bare `IpAddr`, so IPv6 link-local
forwarding and future recursive next-hop resolution need no RIB→FIB contract
change.

### `multipath_equal`

Two routes group iff they are equal on every decision step *above* the
next-hop-distinguishing tiebreakers: stale tier, RPKI preference, ASPA
preference, `LOCAL_PREF`, **full `AS_PATH` equality**, `ORIGIN`, `MED`, **and
the same eBGP/iBGP class**. The later steps (`CLUSTER_LIST`, `ORIGINATOR_ID`,
peer address) are intentionally *not* compared — those are exactly what
distinguishes the co-equal paths we want to bundle. Locally-originated routes
(`RouteOrigin::Local`) never group.

**Exact `AS_PATH` for v1** — the conservative choice, matching FRR's default. A
future `multipath-relax` knob that loosens to `AS_PATH`-length-only equality is
an explicit follow-up, not implied here.

### iBGP multipath semantics

`best_path_cmp` has **no IGP-metric step** — rustbgpd has no recursive next-hop
resolution, so it cannot compare resolved IGP cost. iBGP equal-cost is therefore
defined purely over the BGP decision chain. If IGP resolution is ever added, an
equal-resolved-cost clause becomes the natural extension point.

### Kernel encoding

`netlink-packet-route` 0.30 exposes `RouteAttribute::MultiPath(Vec<RouteNextHop>)`
natively — no hand-rolled `RTA_MULTIPATH`. A single next-hop emits a plain
`RTA_GATEWAY` (byte-for-byte today's shape); two or more emit `MultiPath` with
equal-weight (`hops = 0`), gateway-only next-hops (the kernel resolves each
output interface from the gateway's connected route). On read, both forms
**canonicalize** to a sorted/deduped next-hop set, so `Gateway(x)` and a
one-element `MultiPath([x])` compare equal and the reconcile diff never flaps
when the kernel echoes a different-but-equivalent representation than we emitted.

### Owned-state migration

The crash-restart owned-state envelope moves v1 → v2: it persists the `next_hops`
set, and on load it accepts both v2 and the v1 scalar `next_hop` (upgraded to a
one-element set). A version newer than this build still quarantines; v1 is never
hard-rejected, because rejecting it would orphan crash-restart state into a
foreign-route storm. `maximum_paths` joins the persisted table signature, so
changing it forces a clean re-projection.

### Config

`[[fib_tables]].maximum_paths: Option<u32>` (validated `>= 1`, capped at 256).
It is orthogonal to `max_routes` — `max_routes` caps the number of prefixes
(rows); `maximum_paths` caps the next-hops per row. The single knob applies to
both homogeneous eBGP and iBGP groups; per-class `maximum_paths_ebgp` /
`maximum_paths_ibgp` (FRR parity) can be added later without a breaking change.
The reconciler queries the RIB at the widest configured `maximum_paths` and
re-caps per table, so a default config never pays for sibling gathering: when
that width is `1` (no table opts into ECMP), the install-candidate handler
short-circuits — it returns each Loc-RIB best directly, with no Adj-RIB-In
sibling scan or sort.

## Consequences

- Operators get classic forwarding load-balancing, opt-in and off by default.
- M42's behavior is unchanged: a single best path still emits `RTA_GATEWAY`,
  never `MultiPath`. Tests assert the **semantic shape** (single gateway, no
  multipath) rather than byte-identical netlink internals.
- The Adj-RIB-In re-scan in the install-candidate query has a known cost
  proportional to siblings per prefix; it only runs when a table sets
  `maximum_paths > 1`.
- Validation: projection / canonicalization / owned-state unit tests; kernel
  encode→parse round-trip tests; a privileged netns test (install, failover to a
  single survivor, widen back, withdraw); and **M50** containerlab interop —
  two equal-cost eBGP paths from FRR install a two-way kernel ECMP route that
  fails over and recovers.

## Alternatives considered

- **`AS_PATH`-length-only equality (multipath-relax) in v1** — rejected as the
  default; it silently bundles paths through different transit ASes. Deferred to
  an explicit opt-in knob.
- **Mixed eBGP/iBGP groups** — rejected; the classes have different
  forwarding/trust semantics and FRR keeps them separate too.
- **Hand-rolled `RTA_MULTIPATH`** — unnecessary; the pinned netlink crate
  exposes the native variant.
