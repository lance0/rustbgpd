# ADR-0101: IXP route-server profile — per-client best-path (RFC 7947 §2.3.2)

**Status:** Accepted — per-client best-path shipped in #696; explain arm,
profile polish, and this record in the follow-up slice. The M83
multi-stack interop receipt (BIRD 2 + GoBGP + FRR + RTR, 46 assertions,
hosted CI) closed the proof ladder: transparency byte-pinned via tshark,
and the §2.3 contrast observed live on real stacks — the single-best
member gets nothing, the same member gets the runner-up after a
`per_client_best` flip, the Add-Path member gets both. M83 also caught
the knob dropped at the `PeerManager::build_transport_config` seam
(every configured peer silently single-best despite #696's RIB/CLI
layers testing green) — fixed in the M83 change with a unit pin.
**Date:** 2026-07-03

## Context

The ROADMAP's route-server item named one load-bearing gap versus
BIRD/OpenBGPd at an IXP: **RFC 7948 path-hiding mitigation for members
that cannot do Add-Path**. A design pass over main verified that the
transparency core of RFC 7947 §2.2 had already shipped in ADR-0039
(`route_server_client`, FRR interop receipt M19) — at the transport seam
(`crates/transport/src/session/outbound.rs`, `prepare_outbound_attributes`):

| Attribute | RFC 7947 §2.2 | rustbgpd |
|---|---|---|
| AS_PATH no self-prepend | SHOULD NOT | prepend arm gated `is_ebgp && !route_server_client`, replicated in every per-family variant |
| NEXT_HOP unmodified | MUST | next-hop-self gated the same way; explicit policy `NextHopAction` remains ADR-0039's documented escape hatch; RFC 8950 covered |
| MED propagated | SHOULD | by pass-through — no MED arm exists in the attribute prep |
| Communities untouched | SHOULD NOT modify | catch-all pass-through (standard, large, extended) |
| LOCAL_PREF | n/a (eBGP) | stripped |

Dynamic peers can set `route_server_client` and `local_role` via gRPC
(closing ADR-0039's recorded negative); `local_role = "route_server"`
attaches OTC (RFC 9234) at the same seam — confirmed by test, not new
code. The "profile" is therefore what ADR-0039 chose: a per-neighbor /
per-peer-group flag plus a curated example (`examples/route-server/`),
**not** a new config mechanism — a peer group with
`route_server_client = true` IS the profile, matching how BIRD/OpenBGPd
operators and arouteserver think.

What the incumbents do about path hiding: BIRD offers `secondary`
(first filter-accepted route from the sorted table; arouteserver
defaults it on); OpenBGPd offers `rde evaluate all` (arouteserver does
NOT default it on, citing documented stability bugs — spurious 2nd-best
withdrawals/re-announcements, openbgpd-portable#21); Add-Path per
RFC 7948 is the alternative both support. rustbgpd already shipped
Add-Path send, so mitigation (b) existed; the gap was (a).

## Decisions

1. **Per-client best-path as an opt-in per-neighbor/per-group knob
   (`per_client_best`, requires `route_server_client`), with Add-Path
   remaining the recommended mitigation where members support it.** A
   negotiated capability outranks the fallback: families with Add-Path
   send negotiated use Add-Path, per family, no error. Opt-in — not
   default-on — until the churn class (the OpenBGPd bug family) has
   soak history; arouteserver defaults it on for BIRD but off for
   OpenBGPd for exactly this reason. Earn the default.

2. **Distribution-time selection through the existing multipath body —
   no per-client Loc-RIBs.** `distribute_multipath_prefix` already did
   filtered-best-N (collect per-target candidates, sort by
   `best_path_cmp`, take the first `send_max` export-policy-permitted);
   per-client best is that body with `send_max = 1` plus
   `stage_path_id_zero` — the winner stages at `path_id 0` so
   Adj-RIB-Out, BMP RIB-Out, and `ListAdvertisedRoutes` present the
   single-best shape and the filtered-best flip is an implicit replace.
   The wire is already path-id-free (Add-Path not negotiated). The
   shadow-table alternative (BIRD's multi-table model) is **rejected
   permanently**: memory multiplies by client count, and the
   distribution-time pattern was already proven twice (Add-Path send,
   ORR — ADR-0095 Decision 4's reasoning transfers verbatim). ORR and
   per-client-best are mutually exclusive by validation (vantage ⇒ iBGP
   RR client; per_client_best ⇒ eBGP RS client), pinned by debug_assert.

3. **Per-client-best peers disqualify from update groups
   (ADR-0098 Decision 2 structural fallback).** The member sourcing the
   Loc-RIB best receives the runner-up, so no shared staged winner
   exists — same shape as the Add-Path and ORR disqualifiers. Reason
   string `per_client_best` on `NeighborState.update_group`, counted by
   `bgp_update_group_fallback_peers`. The grouping claims verified
   during design: transparent RS clients sharing a chain with plain
   eBGP peers grouping legally is TRUE by construction
   (`route_server_client` acts in transport, below the staging
   boundary; it is not in `GroupKey` and does not need to be), pinned
   by a mixed-group differential test. "Distinct chains → distinct
   groups keeps heterogeneous member policy fast" is TRUE with an
   honest asterisk: arouteserver-style community steering
   ("do-not-announce-to-AS-X") written as per-member literal chains
   makes every chain distinct → groups of one → per-peer cost. rpol has
   no peer-parameterized community matcher, and adding one would trip
   `requires_peer_context` and disqualify anyway. The scalable answer
   is the ADR-0099 Decision-2 pattern — steering as a per-member
   **emit-time filter** `pass_m(route)` = f(route communities, member
   ASN), presence bit in the key, exactly like the VPN RT filter, which
   keeps the whole steering fleet in one group — **deferred to v2**
   with this sketch recorded; un-defer trigger: a real >100-member
   deployment where steering chains measurably shatter grouping.

4. **RPKI/ASPA enforcement stays in policy — no hard-coded RS gate.**
   Validation state is computed at import; enforcement is rpol/TOML
   matchers (`rpki invalid`, `aspa invalid`) in the import chain, which
   composes with explain (the deny term is named in the trace,
   answering "why isn't my prefix at the IXP?") and matches
   arouteserver's reject-or-tag configurability. Reject-AS_SET needed
   zero code: AS_SETs render as `{...}` in the AS_PATH string, so an
   rpol `route.as-path matches "\\{"` term works (the `_` boundary
   expansion already includes `[{}]`); it ships in the example's
   `hygiene.rpol` with in-language tests.

5. **Explain dry-runs the live filtered-best walk — the #690
   truthfulness principle.** `ExplainAdvertisedRoute` for a
   per-client-best peer ranks the exact candidate set live staging
   walks (`multipath_candidates`, shared collector: split horizon,
   RFC 4456 reflection, per-candidate LLGR) with the Loc-RIB comparator
   and records one verdict per denied candidate — "candidate k of N
   denied by export policy `<chain:term>`; candidate k+1 advertised".
   This fixes the slice-1 known gap where a per-client-best peer's
   explain dry-ran the single-best body and could report "denied" while
   live sent the runner-up. Grouped transparent members need nothing:
   grouped-vs-ungrouped verdict equality is already test-pinned, and
   transparency is transport-side, below explain's remit (explain
   describes what is staged; M83 verifies the bytes). `rbgp neighbor
   show` names the distribution mode
   (single-best / add-path / orr / per-client-best).

## Consequences

- The §2.3 scenario both ways is test-pinned: without the knob the
  member whose chain denies the best gets nothing (documented path
  hiding); with it, the runner-up — including the source member of the
  best. The OpenBGPd `rde evaluate all` bug class is pinned negative:
  candidate churn that doesn't flip the filtered best emits nothing;
  a filtered-best flip is announce-only implicit replace; content-equal
  policy reload emits nothing.
- Honest costs, documented: per-client-best peers are ungrouped (an
  all-members-enabled IXP pays per-peer staging again — recommend
  Add-Path first; the planned 1000-peer RS scale receipt should run the
  realistic mix), and each such peer pays O(candidates) export-policy
  evaluations per changed prefix — the same cost BIRD pays in filter
  runs.
- Three per-target selection modes now flow through
  `distribute_multipath_prefix` (Add-Path, per-client-best; ORR via its
  comparator-swapped sibling). The mode-agreement and differential
  tests are the drift guard; any new export-tail feature must land in
  the shared body or disqualify (the ADR-0098 Decision-3 rule extends
  to modes).
- Deferral register: per-client Loc-RIBs — rejected permanently;
  community-steering emit-time filter — v2, sketch in Decision 3;
  peer-parameterized policy matchers — rejected (superseded by the v2
  filter); default-on mitigation — deferred pending soak history;
  RFC 8097 validation-state extended-community tagging on import —
  **delivered** (the deferred small slice landed: `OV_VALID` /
  `OV_NOT_FOUND` / `OV_INVALID` well-known extended-community names in
  TOML and `.rpol` match/add/remove positions, exact-wire-value
  semantics, RFC 8097 encoding pinned by wire tests; the RS example's
  `hygiene.rpol` tags RPKI outcomes on import). ARouteServer target — deferred
  per ROADMAP until a pilot is credible; noted: arouteserver supports
  only BIRD and OpenBGPD (7.5+) today, adding a target is a Jinja2
  contribution on their side, and after this arc rustbgpd covers the
  generated-config essentials except RTT-based
  communities (no RTT source — likely permanent-reject); the RFC 8097
  tagging gap has since been closed (see above).
