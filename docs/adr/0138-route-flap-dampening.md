# ADR-0138: Route flap dampening

**Status:** Proposed (deferred — not scheduled; implementation NO-GO, demand-gated; see [Reopen conditions](#reopen-conditions))
**Date:** 2026-10-08

## Context

Route flap dampening (RFC 2439) keeps a decaying penalty for each received
path. Penalties are added when the path is withdrawn or changed. When the
penalty crosses a suppress threshold, the path stops taking part in route
selection. It is used again once the penalty decays below a reuse threshold.
The roadmap lists it under "Maybe". This record decides whether rustbgpd
implements it now, records the design an implementation would follow, and
states when the question should be reopened.

### Primary sources

**RFC 2439** defines the mechanism:

- **Figure of merit and decay (§2.3, §4.3).** Each path has a figure of merit
  that decays exponentially with a configured half-life. The RFC precomputes
  decay arrays so that one decay step is "an array bound check, an array
  lookup and a single multiply". The RFC unit is 1 per withdrawal. The
  familiar 1000-per-flap figures are vendor scaling (RFC 7196 §3, Table 1).
- **Parameters (§4.2).** A cutoff (suppress) threshold, a reuse threshold, a
  maximum hold-down time (T-hold), and separate half-lives for reachable and
  unreachable paths. The thresholds bound a **ceiling** (§4.5): the penalty is
  clipped at `reuse × 2^(T-hold / half-life)`, so a path at the ceiling decays
  to reuse in exactly T-hold. The printed formula in §4.5 is garbled; this is
  its intent.
- **What is a flap (§4.8).** A withdrawal adds a penalty (§4.8.2). A
  re-advertisement after a withdrawal only decays the penalty and adds none
  (§4.8.3). A replacement with different attributes is treated "as if an
  unreachable were received" (§4.8.4). §5: "Penalties for instability should
  only be applied when a route is removed or replaced and not when a route is
  added."
- **Suppressed paths (§4.4.2, §2.2).** A suppressed path is not used, neither
  installed nor advertised, until it is reused. The RFC prefers suppressing
  acceptance over suppressing only redistribution.
- **Reuse lists (§4.6–§4.8.7).** A circular array of list heads, processed
  once per reuse interval. "Reasonable defaults might be 30 seconds and 64 list
  heads" (§4.3).
- **History reclaim (§4.3, §4.8.1).** State is freed once the penalty decays
  to nothing.
- **Peer loss (§4.8.5).** An implementation may mark every path from a lost
  peer as unstable, or mark the session instead. Marking the session "will save
  considerable memory".
- **eBGP only (§4, §5).** "Route damping should never be applied on IBGP
  learned routes… Implementations should disallow configuration of route
  damping on IBGP peers." Applying it to iBGP-learned routes "can result in
  routing loops" (§4).
- **Operations (§5).** Operators should publish their parameters and be able
  to clear dampening state manually.

**RFC 7196** (Standards Track) records that the common vendor defaults are
too aggressive:

| Parameter | Cisco | Juniper |
|-----------|-------|---------|
| Withdrawal penalty | 1000 | 1000 |
| Re-advertisement penalty | 0 | 1000 |
| Attribute-change penalty | 500 | 500 |
| Suppress threshold | 2000 | 3000 |
| Half-life | 15 min | 15 min |
| Reuse threshold | 750 | 750 |
| Max suppress time | 60 min | 60 min |

§4 shows that a suppress threshold of 6000 still removes 19% of updates and
dampens 90% fewer prefixes than 2000. §6 recommends: the implementation's
maximum penalty "MUST be raised to at least 50,000"; operators "SHOULD
configure the Suppress Threshold to no less than 6,000"; existing
implementations "SHOULD NOT change their default values"; and an
implementation "MAY have a test mode" that calculates penalties without
dampening. §7 notes that induced flapping can get a victim's prefixes
suppressed.

**RIPE-580** (January 2013) obsoletes RIPE-378. RIPE-378 had said that
dampening in ISP networks is "NOT recommended". RIPE-580 instead recommends
dampening with raised parameters: vendors should raise the maximum suppress
threshold to 50,000, and operators should configure a suppress threshold of at
least 6,000. Its table pairs 6000 with 2.1% of prefixes suppressed and a 19%
churn reduction. It contains no route-server or IXP guidance.

**Route servers and IXPs.** RFC 7947 and RFC 7948 do not mention
dampening. The two common IXP route-server configuration generators,
arouteserver v1.27.0 and the IXP Manager route-server templates, contain no
dampening configuration. BIRD, the most common route-server daemon, does not
implement it (below). No published Euro-IX or IXP guidance was found that
recommends dampening on a route server, or that forbids it. In practice the
IXP ecosystem does not use it.

### Reference implementations

Pinned interop versions: FRR 10.7.1 (`frr-10.7.1`,
`f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1`), BIRD 2.19.2 (`v2.19.2`,
`1d201ed0360c749dfe3d3b3b079329e7148159cd`) and 3.3.3 (`v3.3.3`,
`2ed8b59333bed0f328c6804b70c09412b2f608d4`), GoBGP v4.10.0
(`da824d99912e02124b53741245ee4186c381adcc`).

**BIRD has no dampening.** Neither release tree contains a dampening
implementation, configuration keyword, or filter primitive for per-prefix
flap history. The only mention is the "Future work" list in the user guide
("Route aggregation and flap dampening";
[v2.19.2](https://gitlab.nic.cz/labs/bird/-/blob/v2.19.2/doc/bird.sgml#L7275),
[v3.3.3](https://gitlab.nic.cz/labs/bird/-/blob/v3.3.3/doc/bird.sgml#L7372)).

**GoBGP v4.10.0 accepts a flag and does nothing with it.** A
`route-flap-damping` boolean exists on neighbor and peer-group config and
state
([config](https://github.com/osrg/gobgp/blob/v4.10.0/pkg/config/oc/bgp_configs.go#L1943-L1946),
[protobuf](https://github.com/osrg/gobgp/blob/v4.10.0/proto/api/gobgp.proto#L768)).
It is copied between the API and the config, and no table, peer, or path code
reads it. There are no dampening parameters.

**FRR 10.7.1 implements RFC 2439** in
[`bgpd/bgp_damp.c`](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_damp.c):

| Question | FRR 10.7.1 behavior |
|----------|---------------------|
| Defaults | Half-life 15 min, reuse 750, suppress 2000, max suppress 4 × half-life = 60 min. Decay granularity 5 s, reuse-list tick 10 s, 256 reuse lists ([constants](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_damp.h#L108-L121), [max-suppress default](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_route.c#L18490-L18503)). |
| Penalties | Withdrawal +1000, attribute change +500, re-announcement after withdrawal +0, decay only ([penalty](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_damp.c#L285-L291), [update](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_damp.c#L325-L365)). Attribute change means any change of the attribute set. One decay rate; there is no separate unreachable half-life. |
| Ceiling | `reuse × 2^(max / half-life)`, so 12000 at the defaults, below RFC 7196's 50,000 ([setup](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_damp.c#L404-L408)). Nothing checks that suppress ≤ ceiling, so a configuration such as suppress 15000 with the default timers never suppresses anything. The only check is suppress ≥ reuse. |
| Scope | Per AFI/SAFI on the instance (`bgp dampening`), and per neighbor or peer group (`neighbor X dampening`), each with its own parameters. Precedence is peer, then peer group, then instance ([lookup](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_damp.c#L73-L88)). No route-map or prefix-scoped parameter sets. Unicast, multicast and labeled-unicast only. The user guide calls the commands "not recommended nowadays" ([doc](https://github.com/FRRouting/frr/blob/frr-10.7.1/doc/user/bgp.rst#L648-L669)). |
| iBGP | Every hook is gated on `peer->sort == BGP_PEER_EBGP` ([withdraw hook](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_route.c#L5424-L5428)). Configuration on an iBGP peer is accepted and silently has no effect. |
| Identity | State hangs off each received path, keyed by peer and received Add-Path ID. |
| Reclaim | A reused path's state is freed when its penalty falls to reuse / 2 ([reuse tick](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_damp.c#L210-L222)). A withdrawn path that was never suppressed is kept as a HISTORY path on a list the timer never scans, so its state stays until the path is announced again, cleared, or dampening is turned off. |
| Session reset | `bgp_rib_remove` removes paths "without taking damping into consideration (eg, because the session went down)" ([peer down](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_route.c#L5382-L5398)). A session reset adds no penalty. From code reading: the state of paths that are announced at the time is freed, but HISTORY paths survive the reset and keep their penalty. |
| Reconfiguration | Disabling dampening, or changing its parameters, frees all history. |
| Display | `show bgp … dampening dampened-paths | flap-statistics | parameters [json]`, plus per-neighbor `flap-statistics` and `dampened-routes`. A path line shows "penalty N, flapped N times in T, reuse in T". The per-path display checks only the instance flag, so peer-only dampening is not shown there. |
| Clearing | `clear ip bgp dampening [prefix]`, IPv4 unicast only. At 10.7.1 the per-prefix form is a no-op (fixed after the tag). From code reading, the whole-table form also frees the reuse arrays while leaving dampening enabled. Neither is used in the interop proof below. |
| Memory | `struct bgp_damp_info` is 80 bytes on x86-64, in addition to the retained path. |

### Constraints from this codebase

- **Adj-RIB-In is post-policy only.** Import policy runs in the session task
  before `RibUpdate::RoutesReceived`, and no pre-policy copy is kept (ADR-0076).
  A new announcement that import policy denies, replacing one it accepted,
  reaches the RIB as a withdrawal (`crates/transport/src/session/inbound.rs`).
  So does an RFC 7606 treat-as-withdraw.
- **Path identity.** Each source peer has one `AdjRibIn`
  (`RibManager.ribs`, keyed by peer address). Unicast paths are keyed by
  `(Prefix, path_id)`, with `path_id = 0` without Add-Path
  (`crates/rib/src/adj_rib_in.rs`). Locally injected routes use the
  `LOCAL_PEER` sentinel.
- **One apply point.** `process_announce_chunk` and `process_withdraw_chunk`
  (`crates/rib/src/manager/distribution/unicast.rs`) apply every received
  unicast change. `AdjRibIn::insert` overwrites without comparing, and
  `withdraw` reports whether the path existed. Today the RIB cannot tell an
  attribute change from an identical re-announcement, but attribute interning
  makes that cheap: after `AttrInternTable::intern`, equal attribute sets share
  one `Arc`, and `routes_equal` (`crates/rib/src/manager/helpers.rs`) adds the
  next-hop fields.
- **About ten selection call sites.** Loc-RIB recompute, the announce fast
  path, distribution's ORR and multipath candidates, BMP runner-up, and the
  explain paths each gather candidates from Adj-RIB-In
  (`crates/rib/src/manager/distribution/mod.rs`, `loc_rib.rs`, `queries.rs`).
  The only pre-ranking filter today is SRv6 eligibility. Stale, LLGR, RPKI and
  ASPA state lower a path's rank rather than removing it.
- **Peer down drops the whole `AdjRibIn`** (`clear_peer_adj_rib_in` in
  `crates/rib/src/manager/peer_lifecycle.rs`). GR keeps it and marks it
  stale; a re-received route clears stale through an ordinary insert. LLGR
  promotion edits attributes in place, outside the announce path.
- **Enhanced route refresh has a window.** `refresh_in_progress` holds a peer's
  families between BoRR and EoRR (`crates/rib/src/manager/route_refresh.rs`).
  A plain RFC 2918 refresh has no window.
- **Max-prefix is counted in the session task**, on accepted (post-policy) and
  received (pre-policy) routes. The RIB does not count it.
- **RIB actor timers.** `RibManager::run` keeps one pinned `sleep` per timer
  class. `DeadlineMap` caches its minimum but rescans the whole map when that
  entry is invalidated, which suits hundreds of entries, not a full table.
  ADR-0137's settle timer is one more such class.
- **BMP.** Adj-RIB-In route monitoring and statistics are emitted from the
  session task, so they do not depend on RIB state. Loc-RIB monitoring follows
  selection. `loc_rib_path_status` deliberately never sets the Path Marking
  "Suppressed" bit (`crates/rib/src/bmp_sync.rs`).

## Decision

rustbgpd does not implement route flap dampening now. The record is parked:
the design below is kept so that a later implementation starts from settled
answers, and no implementation is scheduled.

- rustbgpd's stable roles are route server and route reflector (see the
  [stability guide](../reference/stability.md)). The design itself excludes
  iBGP sessions and route-reflector clients, as RFC 2439 §5 requires, so the
  route-reflector role gains nothing from it.
- The IXP route-server ecosystem does not use dampening. arouteserver and the
  IXP Manager route-server templates offer no dampening configuration, and
  RFC 7947 and RFC 7948 do not mention it.
- Among the pinned peers, BIRD has no implementation, and GoBGP's
  `route-flap-damping` flag is read by nothing. FRR implements it, but
  documents its commands as "not recommended nowadays".
- The remaining users are therefore eBGP edge and transit speakers, which are
  outside the core roles. An alpha RIB-actor feature with its own timer
  class, held-route store, RPCs and interop leg is not justified for them
  without a deployment that asks for it.

The roadmap keeps the entry, marked as deferred, with a link to this record.

## Reopen conditions

Reopen this record when either of these holds:

- a named eBGP edge deployment asks for dampening;
- route-server or route-reflector operators ask for it.

A reopened implementation follows the design below, with the
[resolved design questions](#resolved-design-questions) as its defaults, and
stops at any of the [no-go conditions](#no-go-conditions-if-reopened).

## Design if reopened

The numbered sections are the design defaults for a reopened implementation.
They are referred to as Design 1 to Design 13.

### 1. Scope

Dampen **IPv4 and IPv6 unicast paths received from eBGP peers**, opt-in and
**off by default**, as an **alpha** feature. The intended use is an edge or
transit eBGP speaker that wants to shed churn from unstable upstream paths.

Dampening never applies to:

- route-server clients (Design 2 and Design 5);
- iBGP sessions, route-reflector clients and locally injected routes
  (Design 6);
- families other than unicast: labeled unicast, VPN, EVPN, FlowSpec, BGP-LS
  and RTC.

### 2. Configuration

One global parameter set, and per-neighbor and per-peer-group enablement:

```toml
[policy.route_flap_dampening]
# Enable for every eBGP neighbor that does not set its own value.
apply_to_ebgp = false
half_life = 900          # seconds
reuse = 750
suppress = 6000
max_suppress_time = 3600 # seconds
mode = "suppress"        # or "observe"

[peer_groups.transit]
route_flap_dampening = true

[[neighbors]]
address = "203.0.113.2"
remote_asn = 64502
route_flap_dampening = false   # overrides the group and the global default
```

| Field | Type | Default | Range and meaning |
|-------|------|---------|-------------------|
| `apply_to_ebgp` | bool | `false` | Global default enablement for eBGP neighbors. |
| `half_life` | integer seconds | `900` | 60–2700, the time for a penalty to halve. FRR allows 1–45 minutes. |
| `reuse` | integer | `750` | 1–49999. A suppressed path is used again when its penalty falls below this. |
| `suppress` | integer | `6000` | Greater than `reuse`, at most 50000. A path is suppressed when its penalty reaches this. |
| `max_suppress_time` | integer seconds | `3600` | At least `half_life`, at most 4 hours. Sets the ceiling `reuse × 2^(max_suppress_time / half_life)`, which bounds how long a path that stops flapping stays suppressed. |
| `mode` | `"suppress"` \| `"observe"` | `"suppress"` | `observe` is the RFC 7196 §6 test mode (Design 8). |
| `Neighbor.route_flap_dampening`, `PeerGroupConfig.route_flap_dampening` | optional bool | unset | Neighbor, then peer group, then `apply_to_ebgp`. |

The defaults are the RFC 7196 / RIPE-580 parameter set: the vendor defaults
for half-life, reuse and max suppress, with suppress raised to 6000. With these
values the ceiling is 12000. rustbgpd has no installed base of dampening
users, so the RFC 7196 advice that existing implementations keep their old
defaults does not apply.

**Validation.** Load-time validation rejects:

- an out-of-range field, or `suppress ≤ reuse`;
- `suppress` greater than the ceiling. FRR accepts this, and the result never
  suppresses anything. The error names the smallest `max_suppress_time` that
  would make the configuration valid;
- a ceiling above 1,000,000. The penalty is then always representable as a
  32-bit value. The bound still sits far above RFC 7196 §6's floor: "The
  internal constant for the maximum penalty value MUST be raised to at least
  50,000". rustbgpd has no internal maximum below the computed ceiling;
- an explicit `route_flap_dampening = true` on a neighbor whose `remote_asn`
  equals the local ASN (RFC 2439 §5: "Implementations should disallow
  configuration of route damping on IBGP peers");
- an explicit `route_flap_dampening = true` on a neighbor with
  `route_server_client = true` (Design 5).

An inherited setting does not apply to an iBGP session or a route-server
client. That is not an error, because a peer group may mix session types, and
`apply_to_ebgp` is global. The dampening view reports such a peer as "not
applied: iBGP" or "not applied: route-server client" (Design 9).

Penalty amounts are fixed: 1000 per withdrawal, 500 per attribute change, 0
per re-announcement (Design 3). They are not configuration. Per-neighbor
parameter sets, as FRR offers, are deferred until an operator names a need.
The same applies to per-family enablement.

**Classification.**

- `route_flap_dampening` on a peer group is a **config-file-only** field.
  `PeerGroupDefinition` does not carry it, so `copy_peer_group_file_only_fields`
  classifies it and `SetPeerGroup` preserves it. A sequential reload that
  changes it on a group is rejected, like the other file-only group fields.
- gRPC neighbor mutations that do not carry the neighbor field preserve it,
  as ADR-0137 does for its attachments.
- Both fields and the `[policy.route_flap_dampening]` block are **live** on
  the generation route. The resolved per-peer enablement and the parameters
  reach the RIB as one **staged** install, which takes effect only when the
  generation activates it after its last fallible step (Design 10). This
  differs from ADR-0137, whose gate takes effect at the install
  acknowledgement. The reload-matrix tables and the `RELOAD_MATRIX_*_FIELDS`
  drift lists gain the rows.

### 3. What counts as a flap

Dampening state exists only for a path that has flapped. A first
announcement allocates nothing. For an enabled peer:

| Received event for `(peer, prefix, path_id)` | Penalty | Effect |
|----------------------------------------------|---------|--------|
| Announcement, no existing path, no history | 0 | Ordinary insert; no state. |
| Announcement, no existing path, history present (re-announcement after withdrawal) | 0 | Decay the penalty, then apply the threshold check below. |
| Announcement replacing a GR-stale or LLGR-stale path | 0 | Stale-to-fresh replay: the stale flags are cleared, and the threshold check runs if history exists. Attributes are not compared. |
| Announcement equal to a fresh existing path (`routes_equal` after interning) | 0 | No state change. Covers duplicates, and refresh replay of an unchanged route. |
| Announcement that differs from a fresh existing path | +500 | Attribute change. |
| Withdrawal of an existing path | +1000 | Withdrawal. |
| Withdrawal of an unknown path | 0 | Nothing. |

Penalties are added to the decayed value and clipped at the ceiling.

**GR and LLGR replay is never a flap.** A path is stale when the RIB's own
`is_stale` or `is_llgr_stale` flag is set. An `LLGR_STALE` community that a
peer sends on a path does not make it stale for this rule. An announcement
that replaces a stale path is a replay, not a change, and it is never
compared, for two reasons:

- LLGR promotion edits the stored path in place. It adds the `LLGR_STALE`
  community and re-interns the attributes (`promote_to_llgr_stale` in
  `crates/rib/src/adj_rib_in.rs`). An attribute comparison against that copy
  would charge every replayed path an attribute-change penalty.
- A plain GR replay may differ from the stale copy because the peer's own
  state changed across its restart. That is not instability observed by this
  speaker.

The consequence is accepted: a peer that changes a path's attributes across
a restart escapes one 500 penalty for that path.

**Threshold check.** A path that is not suppressed becomes suppressed when its
penalty reaches `suppress`. A suppressed path is used again when its penalty
falls below `reuse`. A withdrawal of a suppressed path keeps its history, and
it stays suppressed if it is announced again while above `reuse`.

**Attribute change** means any difference in the interned attribute set or in
the next-hop fields. This follows FRR (the interop oracle) and RFC 7196's
vendor table, not RFC 2439 §4.4.3's suggestion of an AS-path-only tuple.

**The RIB sees post-policy input.** A new announcement that import policy now
denies arrives as a withdrawal and is penalized as one. That is the peer
changing its route. A local policy change replayed through an inbound
refresh is not the peer's instability:

- Within an enhanced route refresh window (BoRR to EoRR, per family), changes
  update the stored path and run the threshold check, but add no penalty.
- A plain RFC 2918 refresh has no window, and changes it replays are
  penalized. The bound is one attribute-change or withdrawal penalty per
  path per replay. At the default thresholds that is at most 1000 of the 6000
  needed to suppress, so a single policy change cannot suppress a stable path
  by itself. This bounded false penalty is accepted. The alternative, a
  time-bounded exemption window after locally requested refreshes, would also
  let a genuinely flapping path escape penalties. The documentation states
  the bound.

**Session events add no penalty.** A session reset, GR or LLGR stale sweep,
max-prefix teardown, or a peer's removal from configuration never adds a
penalty. This follows FRR. A reset is a session fault rather than path
instability, and per-path penalties for one reset would suppress a full table
at once. RFC 2439 §4.8.5 allows either choice.

### 4. Where state lives, and how a suppressed path leaves selection

The RIB actor gains one `Dampening` owner, separate from `AdjRibIn`:

- `history`: per peer identity, a map from `(Prefix, path_id)` to a small
  state record: penalty, last-update time, flap count, first-flap time,
  suppressed flag, scheduled tick, and an optional held route.
- `wheel`: the reuse schedule (Design 7).

**A suppressed path is held outside `AdjRibIn`.** On suppression, the path's
`Route` moves from `AdjRibIn` into its history record, and its prefix enters
the ordinary affected set, so the same selection pass that handles the
triggering UPDATE removes it. While suppressed, later announcements replace
the held route, and withdrawals drop it. On reuse, the held route is applied
through the same path as an announcement, including the RPKI and ASPA checks
that `process_announce_chunk` runs before insert, and selection runs for its
prefix.

This follows RFC 2439 §4.4.2: a suppressed path "is not used". It also means
none of the selection call sites change. Loc-RIB, distribution, Add-Path,
ORR, per-client best path, multipath, conditional-advertisement conditions
(ADR-0137) and MRT dumps already read only `AdjRibIn`, so a held path is
excluded from all of them. A selection-time filter was rejected, because it
would need the same check at about ten call sites, and one missed site would
be a silent leak. The cost is that operator views must read the held routes
explicitly (Design 9).

**History is keyed by peer identity, not by address.** The identity is the
pair of the RIB's peer key (the address that keys `AdjRibIn`) and the
session's remote ASN. For a static neighbor the remote ASN is the configured
`remote_asn`. For a dynamic neighbor it is the ASN the peer sent in its OPEN,
which also covers an accept-any range (`remote_asn = 0`). History does not
carry across an identity change:

- A static neighbor's `remote_asn` edit is a delete and add of the neighbor
  identity (`config_field_impact` in `src/config/mod.rs`). The edit drops the
  old identity's history when it is activated, so the replacement starts
  empty.
- A dynamic peer that reconnects from the same address with a different
  ASN is a different identity. It gets no history from the earlier peer, and
  the earlier history is reclaimed by decay.

**History outlives the session.** It is not dropped when the peer's
`AdjRibIn` is. A peer that resets its session under the same identity
therefore cannot clear its penalties, and a flapping path announced after
reconnect is suppressed again if it is still above `reuse`. This includes a
dynamic peer whose session ends and returns: its history remains until it
decays. Held routes are dropped when the session ends, with or without GR. A
held route is not in use, so dropping it changes no selection, and the peer
announces it again after the restart. History is removed when:

- its penalty decays below `reuse / 2` (FRR's reclaim point; Design 7);
- its identity is removed: a static neighbor is removed or its `remote_asn`
  changes, or a dynamic peer's range is removed;
- dampening is disabled for the identity, or the parameters change (Design 10);
- an operator clears it (Design 9).

**Add-Path.** Identity includes the received `path_id`, so each path of a
prefix is dampened on its own, as in FRR. A sender may renumber its path IDs
after a session reset, and history then follows the number, not the path.
This is accepted and documented.

**Memory (modeled, not measured).**

- A history entry is a `(Prefix, u32)` key of about 24 bytes plus a record of
  about 32 bytes. The record holds a 32-bit penalty, four 32-bit times and
  counts, a flags byte, and an `Option<Box<Route>>` for the held route. With
  hash-table control bytes and load factor, that is roughly 65 bytes.
- A wheel entry is a peer, prefix and path ID of about 40 bytes. Lazy
  rescheduling (Design 7) can leave about one stale entry per live entry.
- Worst case at 1M paths, every path with history: about 100–145 MiB.
- Held routes move out of the `AdjRibIn` slab rather than being copied, so the
  only added cost per held route is its box.
- Stable paths cost nothing. In practice only paths that flapped within the
  last `max_suppress_time + half_life` have history. RIPE-580's measurements
  suggest that is a small fraction of a full table.
- A peer with dampening disabled pays one boolean check per received chunk.
  An enabled peer pays one `AdjRibIn` lookup per announcement, for the
  equality check, and one history lookup when history exists.

The slice 5 receipt measures these figures; until then they are estimates.

### 5. Route servers: refused for clients, per source otherwise

Dampening never applies to a `route_server_client` neighbor. An explicit
setting is a load error, and an inherited one does not apply (Design 2). A
suppressed path hides a member's announcement from every client of the route
server, and the IXP ecosystem does not dampen. Refusing it outright is
simpler than documenting a discouraged mode.

For any other eBGP peer on the same daemon, Adj-RIB-In is per source peer, so
dampening is per source by construction. A suppressed path is absent for every
client at once. With `per_client_best`, a client whose best path would have
been the suppressed one falls through to its next permitted candidate,
because the held path is not a candidate. There is no per-client dampening
state, and none is planned. A per-client copy would multiply memory by the
number of clients and would let one client's export policy change another's
suppression.

Per-source scope also bounds the RFC 7196 §7 concern: a peer can only add
penalties to paths that it announced itself.

### 6. iBGP, route-reflector clients and local routes

Dampening applies only to paths whose `RouteOrigin` is `Ebgp`. iBGP paths,
including those from route-reflector clients, are never penalized, held or
recorded. RFC 2439 §4 and §5 forbid it, and FRR gates every hook on eBGP.
Dampening iBGP paths inside an AS can produce inconsistent selection between
speakers, and on a reflector it would hide a client's path from every other
client. Locally injected routes (`LOCAL_PEER`) are never dampened.
rustbgpd has no confederation support, so the confederation case does not
arise.

### 7. Decay and reuse scheduling on the RIB actor

**No per-path timers, and no decay arrays.** The penalty is stored with its
last-update time and decayed in closed form when the path is next touched:
`p(t) = p0 × 2^(−(t − t0) / half_life)`. The RFC's precomputed arrays avoided
floating-point exponentiation on 1998 hardware. One `exp2` per touch is
cheaper than keeping the arrays.

**One schedule.** Every history entry has exactly one due time:

- For a suppressed path, its reuse time, `t0 + half_life × log2(p0 / reuse)`.
  The ceiling caps this at `max_suppress_time` after the last penalty, which
  is how RFC 2439 enforces T-hold.
- For any other entry, its reclaim time,
  `t0 + half_life × log2(p0 / (reuse / 2))`.

Due times are rounded up to a 10-second tick, FRR's reuse granularity. The
wheel is a `BTreeMap<tick, Vec<key>>`. Its horizon is at most
`max_suppress_time + half_life`, which is 75 minutes and 450 ticks at the
defaults. A new penalty does not remove the old wheel entry. Instead the
record stores its current tick, and an entry whose record has moved is
skipped. This avoids a search inside a tick's vector, and it bounds stale
entries to the penalty events within one horizon.

**One timer class.** The RIB actor adds one pinned `dampening_sleep`, armed
for the earliest non-empty tick and disarmed when the wheel is empty. A
daemon with dampening off never arms it.

**Bounded work per tick.** A tick processes at most a fixed number of due
entries, initially 4096. For each one it re-decays, then either reuses the
path, reclaims the record, or reschedules it (a path that was penalized again
since). Reused prefixes join one affected set and go through one ordinary
selection and distribution pass. A tick with more due entries than the budget
leaves the rest for the next loop iteration, re-armed at the existing
resync-backlog interval. Queued UPDATEs are drained first, as the GR and
refresh arms already do. The tick's own work is therefore bounded by the
budget, and the distribution work for each reused prefix is the ordinary
per-prefix cost. A mass reuse, for example after a long upstream event,
spreads across iterations instead of stalling the actor. Slice 5 measures the
per-tick cost at the budget.

### 8. Observe mode

`mode = "observe"` runs all of the penalty and threshold logic and all of the
reporting, but never moves a path out of `AdjRibIn`. The dampening view and
the metrics report what would be suppressed and when it would be reused. This
is RFC 7196 §6's "calculate but do not damp" test mode. It is the documented
first step for any deployment.
Switching between modes is a parameter change (Design 10).

### 9. Operator surfaces

**Explain.** `rbgp rib --prefix P --explain` (`ExplainBestPath`) lists each
held path as a candidate with `vs_best_reason` code `dampening_suppressed`,
following the SRv6-ineligible precedent. The detail is, for example,
`suppressed by route flap dampening: penalty 6420, 4 flaps since
2026-10-08T12:00:00Z, reuse in 1830s`. Such a candidate takes no part in
runner-up selection or multipath. In observe mode, the path stays an ordinary
candidate, and the detail on its row notes `would be suppressed (observe)`.
`rbgp rib --prefix P advertised PEER --explain` needs no new step, because a
suppressed path never reaches export. `rbgp rib received PEER` continues to
list `AdjRibIn` only, so held paths are absent there, and the stable
`ListReceivedRoutes` message graph is unchanged. The dampening view and
explain cover held paths.

**Dampening view and clear.**

- `RibService.ListDampenedPaths` lists history entries, optionally filtered by
  peer, prefix and "suppressed only". Each entry reports peer, prefix, path
  ID, current decayed penalty, flap count, first-flap time, suppressed flag,
  reuse or reclaim time, and the held route's attributes. A summary reports
  the parameters, the mode, and the per-peer applied state, including "not
  applied: iBGP" and "not applied: route-server client".
- `RibService.ClearDampening` clears history by peer, by prefix, or entirely.
  Held paths in the scope are reused through the bounded tick, so a full
  clear does not stall the actor.
- The CLI is `rbgp rib dampening [--peer P] [--prefix X] [--suppressed]` and
  `rbgp rib dampening clear [--peer P] [--prefix X] [--all]`.
- Authorization tiers: `ListDampenedPaths` is **SensitiveRead**, the tier of
  `ListReceivedRoutes`, because it exposes received attributes.
  `ClearDampening` is **Mutating**, following
  `ClearDuplicateMacQuarantine`: a restorative clear of locally held state.
  It can only make paths usable again, never suppress them.

**Metrics.** No per-prefix labels:

| Metric | Type | Labels |
|--------|------|--------|
| `bgp_dampening_history_paths` | gauge | `peer`, `afi_safi` |
| `bgp_dampening_suppressed_paths` | gauge | `peer`, `afi_safi` |
| `bgp_dampening_penalties_total` | counter | `peer`, `afi_safi`, `cause` = `withdrawal` \| `attribute_change` |
| `bgp_dampening_suppressions_total` | counter | `peer`, `afi_safi` |
| `bgp_dampening_reuses_total` | counter | `peer`, `afi_safi`, `cause` = `decay` \| `clear` |
| `bgp_dampening_tick_backlog` | gauge | none |

Series exist only for peers with dampening applied, at two families each, and
are reaped with the peer. The peer-labeled families join the
`PEER_LABELED_FAMILIES` reaping lists. Observe mode uses the same series, so
`suppressed_paths` reads as "would be suppressed".

**Logs.** No per-path `info` logs, because a flapping table would flood them.
Suppression and reuse log at `debug`. A peer whose suppressed count crosses
from zero to nonzero, or back, logs one `info` event.

**BMP.** Adj-RIB-In monitoring is emitted before the RIB and is unchanged.
Loc-RIB monitoring follows selection, so a suppressed best path appears as an
ordinary Loc-RIB withdrawal. The Path Marking "Suppressed" bit stays unset,
because a suppressed path is not in the Loc-RIB that path marking describes.

### 10. Reload, parameter changes and clearing

- Enabling dampening for a peer starts with empty history.
- Disabling dampening for a peer, changing any global parameter, or changing
  `mode` **clears** the affected scope: history is dropped, and held paths
  are reused through the bounded tick. FRR does the same. Rescheduling
  existing penalties under new thresholds would give a mixed result that no
  operator could reason about, and the change is operator-initiated.
- A reload with identical dampening content changes nothing.

**A generation stages; it does not apply.** Restoring captured state cannot
undo wire effects. Suppose the install took effect when the RIB acknowledged
it. Clearing a scope would queue its held paths for reuse, and a bounded tick
could insert and distribute them before a later generation step failed.
Compensation could suppress them again, but it could not retract the
announcement. The same is true in the other direction: a newly enabled peer
could have paths suppressed and withdrawn downstream by a generation that
then fails. So:

- The RIB acknowledges the install by storing it as **staged**. The running
  parameters, enablement, history, held routes and wheel are unchanged, and
  received UPDATEs continue under the running configuration.
- The generation sends **activation** as its last step, after every fallible
  step has succeeded. Activation is the commit point for dampening. It swaps
  the staged install in and only then performs the clears and releases above.
  Released paths go through the bounded tick as usual.
- A generation that fails before activation **discards** the staged install.
  Nothing was applied, so there is no capture to restore and no wire effect to
  undo.
- An activation that the RIB does not acknowledge leaves the generation
  ambiguous, and the settlement contract recovery-fences the daemon, as for
  ADR-0137's re-observation. Until activation, the prior configuration
  stays in force.

`ClearDampening` (Design 9) is not part of a generation. It applies
immediately.

### 11. Interactions summary

| Event | Effect on dampening |
|-------|---------------------|
| GR or LLGR session end | Held routes dropped, history kept. Only fresh paths are in `AdjRibIn` to be marked stale, because suppressed paths are held outside it. |
| LLGR promotion | The local `LLGR_STALE` edit happens outside the announce path and is not a flap. |
| Replay after restart | Replacing a stale path adds no penalty (Design 3). A replayed path with no stale copy but with history, such as a held path dropped at session end, follows the re-announcement rule: no penalty, and the threshold check runs. If the path is still above `reuse` it is held again. |
| GR or LLGR stale sweep | Removing a path that was not replayed adds no penalty, and so does removing a `NO_LLGR` path at LLGR entry. The sweep reads only `AdjRibIn`. No held route can be stale, because held routes were dropped at session end, so no held path is left behind. |
| Wheel reuse during the stale period | The record has no held route, so reuse clears the suppressed flag and reschedules reclaim. Nothing is inserted. |
| Enhanced route refresh | No penalties between BoRR and EoRR for the family. The BoRR snapshot also covers held paths of that family. A held path not re-announced by EoRR is dropped with no penalty, like an unrefreshed `AdjRibIn` path, so the peer's implicit withdrawal is not lost. |
| Plain route refresh | Ordinary rules; bounded as described in Design 3. |
| Session reset | No penalty; held routes dropped; history kept. |
| Max-prefix | Counted in the session task over accepted routes, so held routes still count, since the peer did announce them. A max-prefix teardown is a session reset. |
| Neighbor removed, or `remote_asn` changed | History for the old identity dropped at activation; a replacement identity starts empty. |
| Dynamic peer reconnects | Same address and ASN: history kept. Different ASN: new identity, no history carried. |
| Import policy change | A deny now arrives as a withdrawal; a replay after refresh follows the refresh rows. |
| RPKI/ASPA revalidation | Held routes are not revalidated while held. They are validated when reused, through the announce path. |

### 12. Stability boundary

The feature is **alpha** and outside the v1 inventory:

- The new config fields are optional siblings that the stable digests do not
  select. The JSON Schema gains them, and the inventory hashes do not change.
- `ListDampenedPaths` and `ClearDampening` are listed in
  `explicitly_outside_v1`.
- `dampening_suppressed` is an additive `vs_best_reason` string value, which
  the v1 contract treats as compatible.
- The metrics and CLI subcommands are new and alpha.
- The inventory's `features[]` list gains `route-flap-dampening` as `alpha`.
- Behavior for every configuration that omits the feature is unchanged.

### 13. Non-goals

- Dampening on iBGP sessions, route-reflector clients, or locally injected
  routes, and any default-on behavior.
- Families other than IPv4 and IPv6 unicast.
- Per-client (export-side) dampening.
- Per-neighbor parameter sets, per-family enablement, separate reachable and
  unreachable half-lives (RFC 2439 §4.2), and policy-selected parameter sets
  (RFC 2439 §4.1). Each waits for a named need.
- Persisting history across a daemon restart.
- Penalizing session resets (RFC 2439 §4.8.5's per-session marking).

## Implementation slices (if reopened)

Each slice is a separate PR. Tests go through the real RIB path wherever the
slice changes behavior, and each regression is shown red with its mechanism
removed.

1. **Config, validation and install.** Add the fields, the JSON Schema
   update, every validation case above (including suppress above the ceiling
   and explicit iBGP or route-server-client enablement), the peer-group
   file-only classification and
   its sequential-reload rejection, gRPC neighbor-mutation preservation,
   reload-matrix rows and drift lists, and the staged RIB install with
   activation and discard. The install has no runtime effect yet.
   *Acceptance:* each rejected case fails with a message naming the field; a
   `SetPeerGroup` edit of an unrelated field preserves the group's setting; an
   identical reload produces no install change.
2. **Penalty engine.** Add a pure module: decay in closed form, penalties,
   ceiling clip, threshold transitions, reuse and reclaim times, and the
   wheel with lazy rescheduling and the per-tick budget. Use controlled time;
   no RIB wiring yet.
   *Acceptance:* decay agrees with the closed form to within 1 penalty unit;
   a path at the ceiling reuses at `max_suppress_time`, give or take one tick;
   reclaim happens below `reuse / 2`; a tick never processes more than the
   budget; a rescheduled entry is processed once.
3. **RIB integration.** Wire the hooks into the announce and withdraw chunks,
   using the equality check after interning. Add the held-route store,
   suppression into the affected set, reuse through the announce path
   (including RPKI and ASPA), `dampening_sleep` in the run loop, and handling
   for session end and GR (drop held routes, keep history). Add stale replay
   handling, history keyed by peer identity, the enhanced refresh exemption
   and held-path coverage, observe mode, and clear on disable or parameter
   change at activation.
   *Acceptance, through the real RIB with a downstream peer:*
   - Flap, suppress, decay and reuse produce exact withdrawals and
     re-announcements downstream.
   - Identical re-announcements add nothing. GR replay and LLGR replay over
     promoted paths add nothing, including a replay whose attributes differ
     from the stale copy.
   - A stale sweep after a restart that does not replay a path leaves no held
     path and adds no penalty. An unrefreshed held path is dropped at EoRR.
   - A `remote_asn` edit starts the replacement with empty history. A dynamic
     peer reconnecting with a different ASN inherits nothing, and with the
     same ASN keeps its history.
   - An iBGP or RR-client path is never dampened.
   - Add-Path paths are dampened independently.
   - `per_client_best` falls through to the next candidate.
   - A session reset keeps history, and a re-announced path above `reuse`
     stays suppressed.
   - Observe mode changes no selection.
   - A generation that fails after the staged install, but before
     activation, has no wire effect. No suppressed path is announced, and no
     path is newly suppressed or withdrawn. Prove this by failing a later
     generation step in the test.
   - A disabled peer allocates no state.
4. **Operator surface.** Add the explain code, the RPCs and authz entries, the
   CLI, metrics and reaping, logs, the stable-surface inventory entries,
   configuration and operations reference pages that state the route-server
   refusal, and a changelog fragment.
   *Acceptance:* the authz tier tests and the generated method inventory are
   updated; `check-v1-stable-surface` passes, with the RPCs listed as outside
   v1; explain shows `dampening_suppressed` with penalty and reuse time.
5. **Proof and measurement.**
   - *FRR interop leg.* `frr-src` flaps one prefix, announcing and
     withdrawing it with `network` / `no network`, toward both rustbgpd and
     `frr-ref`. `frr-ref` runs instance-level `bgp dampening` with the same
     parameters, scaled for a lab run: half-life 60 s, reuse 750, suppress
     2000, max suppress 240 s. A downstream `frr-obs` peers with rustbgpd.
     The leg asserts that rustbgpd and `frr-ref` suppress on the same flap,
     that their reported penalties agree within one FRR decay quantum, and
     that both reuse within one FRR reuse tick of each other. It also asserts
     that `frr-obs` loses and regains the prefix accordingly. Read FRR
     through `show bgp ipv4 unicast dampening dampened-paths json` and
     `flap-statistics json` with `vtysh.conf` bound. Avoid FRR's `clear`
     commands, which are defective at 10.7.1. Deploy fresh for each run.
   - *Receipt.* Measure the ingest benchmark with dampening off against main,
     and with dampening on and a flapping fraction against off. Measure the
     cost of one tick at the budget, and the resident memory of history at a
     stated path count, under the memory measurement protocol.
   *Acceptance:* with dampening off, ingest is within the noise floor of main;
   the per-tick cost and memory are recorded in a dated receipt, and the
   modeled figures in Design 4 are corrected if they differ.

## No-go conditions if reopened

- **Any cost when off.** If slice 5 shows an ingest regression beyond noise
  with dampening disabled, the hook placement is wrong. Do not ship until
  it is fixed.
- **Leakage through a held path.** If any reader of `AdjRibIn` turns out to
  need held paths for correctness, the hold-outside model is unsound. One
  example would be a reader whose withdrawal bookkeeping depends on the path
  still being present. The model must then be replaced with a selection-time
  filter at every call site before shipping, not patched per reader.

## Resolved design questions

These were open when the record was proposed. They are settled as the
defaults for a reopened implementation:

1. **Route-server posture.** Dampening is refused on `route_server_client`
   neighbors outright (Design 2 and Design 5). Supporting it while
   discouraging it, with observe mode first, was rejected.
2. **`rbgp rib received` and held paths.** Held paths stay out of
   `rbgp rib received`, so the stable `ListReceivedRoutes` message graph is
   unchanged. The dampening view and explain already cover them (Design 9).
3. **Plain refresh penalties.** The bounded false penalty from an RFC 2918
   refresh replay after a local policy change is accepted. It is at most 1000
   of the 6000 suppress threshold. An exemption window was rejected, because a
   flapping path could exploit it (Design 3).

## Consequences

- No runtime code, configuration, RPC or metric ships. rustbgpd still has no
  route flap dampening, and operators who need it on an eBGP edge use another
  speaker at that edge.
- The roadmap entry stays, marked as deferred, and links this record. A
  request that meets a reopen condition starts from the design above rather
  than from a new survey.

If the record is reopened and implemented as designed:

- Edge and transit operators get RFC 2439 dampening with the RFC 7196 /
  RIPE-580 parameter set, an RFC 7196 observe mode, and validation that
  refuses configurations that can never suppress.
- Selection, distribution and every Adj-RIB-In reader remain unchanged. A
  suppressed path is simply absent from `AdjRibIn`, and only the views and
  explain read the held store.
- History survives session resets, so resetting a session is not a way to
  escape suppression. It is lost on daemon restart.
- The RIB actor gains one timer class with bounded work per tick. A daemon
  with dampening off pays one boolean check per received chunk.
- Migrating from FRR is close but not exact:
  - there are no per-neighbor parameter sets;
  - the suppress default is 6000 instead of 2000;
  - iBGP and route-server-client enablement is an error instead of a no-op;
  - changing parameters clears history, as it does in FRR.

## References

- [RFC 2439](https://www.rfc-editor.org/rfc/rfc2439), BGP Route Flap Damping
- [RFC 7196](https://www.rfc-editor.org/rfc/rfc7196), Making Route Flap Damping Usable
- [RIPE-580](https://www.ripe.net/publications/docs/ripe-580/), RIPE Routing Working Group Recommendations on Route-flap Damping
- [RFC 7947](https://www.rfc-editor.org/rfc/rfc7947) and [RFC 7948](https://www.rfc-editor.org/rfc/rfc7948), Internet Exchange BGP Route Server and its operations
- [FRR 10.7.1 `bgp_damp.c`](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_damp.c)
- [ADR-0076](0076-config-transaction-model.md), the config transaction model
- [ADR-0137](0137-conditional-advertisement.md), conditional advertisement
- [ADR-0128](0128-route-server-next-hop-translation.md), a demand-gated route-server design precedent
