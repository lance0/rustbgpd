# ADR-0068: Weighted (unequal-cost) multipath via Link Bandwidth

**Status:** Accepted — extends ADR-0066's equal-weight ECMP.
**Date:** 2026-05-24

## Context

ADR-0066 installs up to N equal-cost BGP paths as a kernel `RTA_MULTIPATH`
route, every next-hop emitted with `hops = 0` (equal weight). It named the gap
bluntly:

> **Equal-weight only.** ECMP next-hops are emitted with `hops = 0` (equal
> weight). Unequal-cost / weighted multipath … is not supported; it is future
> work.

draft-ietf-idr-link-bandwidth defines a **Link Bandwidth Extended Community**
(non-transitive two-octet-AS-specific, type `0x40` subtype `0x04`) carrying a
path's link bandwidth as an IEEE-754 bytes/second value. FRR's
`bgp bestpath bandwidth` weights ECMP next-hops in proportion to it, so a
40G link draws ~4× the traffic of a 10G link in the same bundle. The wire
parse landed already (`ExtendedCommunity::as_link_bandwidth` /
`Route::link_bandwidth`); this ADR wires it into the FIB.

## Decision

Weight the next-hops of an equal-cost multipath group in proportion to each
path's advertised Link Bandwidth, **opt-in globally** via
`[global].link_bandwidth_weighted` (default `false`), parallel to
`multipath_relax`. It is inert unless a `[[fib_tables]]` sets
`maximum_paths > 1` *and* the grouped paths carry the community — when off, or
when bandwidth is absent, every next-hop keeps weight 1 and the kernel route is
**byte-for-byte ADR-0066's equal-weight shape**.

### Weight is an integer, computed in the RIB

The weight is computed once in `handle_query_fib_install_candidates` — the same
single widest-width query site where `multipath_relax` lives — and stored as
`FibInstallNextHop.weight: u16` (the kernel weight, `1..=256`).

It is **deliberately an integer, not the raw `f32` bandwidth.** `FibRouteTarget`
equality drives the reconcile diff; an `f32` is neither `Eq` nor `Ord` and would
poison the canonical sort/dedup and the owned-vs-kernel comparison. An integer
weight keeps the FIB target totally ordered and lets the kernel round-trip be
exact (see below).

### Normalization (all-or-nothing per group)

For each equal-cost group, after it is deduped and capped:

- If weighting is **enabled** and **every** next-hop in the set carries a
  **finite, positive** bandwidth: `weight_i = round(256 × bw_i / max_bw)`,
  clamped to `[1, 256]`, where `max_bw` is the largest bandwidth in the set. The
  highest-bandwidth next-hop gets 256; the rest scale proportionally.
- Otherwise: every next-hop gets weight `1` (equal cost).

The **all-or-nothing** rule (one path missing the community ⇒ the whole group
reverts to equal weight) is deterministic and avoids inventing a default
bandwidth for a path that never advertised one — a conservative reading of the
draft, akin to FRR's `skip-missing`. It is documented as a limitation, not a
silent guess.

### Why global, not per-table

Weights are computed at the single widest-`maximum_paths` RIB query (exactly as
`multipath_relax` must be), then per-table projection re-caps to a subset. The
subset carries the already-computed integer weights unchanged. Because the
kernel distributes traffic by the **ratio** between `rtnh_hops` values, ratios
survive subsetting even when the max-bandwidth member is capped out. Per-table
weighting would require re-normalizing inside each table, which the single-query
grouping cannot express (re-cap changes membership, not the normalization base).

### Kernel encoding and the weight round-trip

Linux `struct rtnexthop.rtnh_hops` encodes **weight minus one**. So each
multipath next-hop emits `RouteNextHop.hops = weight − 1`:

- weight 1 → `hops = 0` — ADR-0066's equal-weight shape, unchanged.
- weight 256 → `hops = 255`.

A single next-hop still emits a plain `RTA_GATEWAY` (no weight — one path takes
all traffic). On read, `hops` decodes back to `weight = hops + 1`, so a dumped
route reconstructs the **exact** weight it was programmed with. The reconcile
diff is therefore weight-stable: an unchanged set never flaps, and a pure
bandwidth change (same next-hop set, new weights) is detected and reprogrammed
as a `Replace`.

**Singleton normalization.** The canonical `FibRouteTarget` forces a lone
next-hop's weight to 1, because a single path carries all traffic regardless of
weight and the kernel stores it weightless (`RTA_GATEWAY`). Without this, a
weighted group reduced to one next-hop by a per-table `maximum_paths` cap (or a
lone best) would hold a non-1 weight in owned state while the dumped route reads
back 1 — a permanent diff. Normalizing the singleton keeps the round-trip exact.

### Owned-state migration v2 → v3

The crash-restart owned-state envelope moves v2 → v3: it persists per-next-hop
weights alongside the next-hop set. A v2 file (no weights) loads as all-weight-1;
if weighting is enabled, the first reconcile after upgrade reprograms the
affected routes once to pick up real weights. (v1's scalar still upgrades per
ADR-0066.) Persisting the weights keeps a crash-restart from briefly flattening
weighted routes to equal-cost before the RIB re-syncs.

### Config

`[global].link_bandwidth_weighted: bool` (default `false`). Global because the
weight is computed at the single widest-width query (see above). Orthogonal to
`maximum_paths` (the per-table width) and `multipath_relax` (the grouping
relaxation) — the three compose: relax decides *which* paths group, the
per-class `maximum_paths` caps *how many*, and this knob decides *how the
survivors are weighted*.

## Consequences

- Operators get unequal-cost load balancing proportional to advertised link
  bandwidth, opt-in and off by default. With it off (or no community present),
  the kernel route is byte-for-byte ADR-0066.
- **8-bit weight resolution.** `rtnh_hops` is a `u8`, so ratios quantize to
  `[1, 256]`; bandwidth ratios beyond 256:1 saturate at the high end.
- **All-or-nothing fallback.** A single path in a group missing the community
  disables weighting for that whole prefix. Mixed-bandwidth bundles are an
  explicit non-goal for v1.
- **Unequal weight, not unequal cost.** Only paths that are already equal-cost
  per `best_path_cmp` (ADR-0066's `multipath_equal`) are weighted among
  themselves. There is still no IGP-metric / recursive-resolution step, so this
  is not unequal-*cost* routing in the FRR/IGP sense.
- Validation: RIB weight-normalization unit tests (proportional, all-present vs
  mixed → equal, non-finite/zero guards); projection carries weights through to
  `FibRouteTarget`; kernel encode `hops = weight − 1` + decode round-trip;
  reconcile reprograms on a weight change and does not flap on an unchanged set;
  a privileged netns weighted-install test.

## Alternatives considered

- **Store the raw `f32` bandwidth on the FIB target** — rejected: breaks `Eq` /
  `Ord` on `FibRouteTarget`, which the reconcile diff and owned-state canonical
  form depend on. An integer weight computed in the RIB is diff-stable and
  round-trips exactly through `rtnh_hops`.
- **Default weight for a missing community** — rejected for v1 in favor of the
  all-or-nothing equal-cost fallback; inventing a bandwidth silently mis-weights
  a bundle.
- **Per-table weighting** — rejected; the single widest-width query cannot
  re-normalize per table, and ratios already survive the per-table re-cap.
- **Compute weights at projection/encode time** — rejected; the RIB
  install-candidate handler already groups equal-cost paths and hosts
  `multipath_relax`. Centralizing the weight there keeps one code path and one
  place to reason about the equal-cost set.
