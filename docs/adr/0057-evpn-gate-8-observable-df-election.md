# ADR-0057: EVPN Gate 8 — observable DF election without forwarding enforcement

**Status:** Accepted
**Date:** 2026-05-09

## Context

EVPN multihoming as RFC 7432 envisions it has three load-bearing
pieces:

1. **Ethernet Segment identity** — every PE that attaches to a shared
   CE advertises the same 10-byte ESI via a Type 4 ES route, and a
   matching Type 1 EAD-per-ES + per-EVI announcement family.
2. **Designated Forwarder election** — the PEs in the segment agree
   on which one carries BUM traffic toward the segment for a given
   `(ES, VNI)` slot. RFC 7432 §8.5 specifies the default service
   carving algorithm; RFC 8584 §3 layers algorithm negotiation on top
   so PEs that disagree on algorithm fall back to `DefaultModulo`
   (algorithm-id 0).
3. **Split-horizon enforcement** — the elected DF forwards segment
   BUM toward the CE; non-DF PEs drop. The wire-side mechanism is the
   ESI Label extcomm (RFC 7432 §7.5) carried on the EAD-per-ES route,
   matched against the inner label of incoming VXLAN/MPLS frames.

The asymmetry that bit BIRD and even early GoBGP releases is that
piece 1 and piece 2 are both **observable** on the wire — peers can
see ESIs, can see your DF preference, can compute who wins —
*independent* of piece 3, which is forwarding enforcement. The
control-plane half is useful on its own: looking-glass operators can
watch DF flips, alerting can fire on stuck-non-DF, peers can validate
that the local PE participates in the segment, and the resulting
state machines are exactly the same ones you need at Gate 8b.

Gate 8 originally shipped pieces 1 and 2 only. Gate 8b follow-ups now
ship opt-in forwarding enforcement and the related receive-side
projection/filtering pieces; this ADR records the original carve-out so
the split is understandable historically.

## Decision

### Scope: control-plane election + Type 1/4 origination + observability

The Gate 8 surface is:

- **Domain types** in `crates/evpn/src/segment.rs`: `EthernetSegment`,
  `DfAlgorithm` (`DefaultModulo`, `HighestRandomWeight`,
  `HighestPreference`, `LowestPreference`), `DfRole`. The runtime config is parsed from
  `[[ethernet_segments]]` in `Config::resolve_ethernet_segments`;
  Gate 8 config accepts `DefaultModulo` with the default preference
  `32768`; the HRW follow-up additionally accepts
  `HighestRandomWeight`; the RFC 9785 follow-up accepts
  `HighestPreference` and `LowestPreference` with an explicit
  `df_preference` in the `0..=65535` range. Local Don't-Preempt
  origination shipped (`df_dont_preempt`, preference algorithms only —
  the Type 4 DF Election extcomm carries DP=1); remote Don't-Preempt is
  decoded and used as a tie-breaker for preference-DF election. Proactive
  non-revertive failover (single-active backup-path pre-install) remains
  deferred.
- **Pure DF election state machine** in
  `crates/evpn/src/df_election.rs`: `DfElection::run` takes the
  candidate set + the local PE's originator IP and returns
  `BTreeMap<EvpnInstanceId, DfRole>`. RFC 7432 §8.5 service carving
  (sort candidates by originator IP ascending; the candidate at slot
  `vni mod n` is the DF). RFC 8584 §3.2 Highest Random Weight
  selects the PE with the highest `Wrand(V, ESI, PE-IP)`, computed
  byte-for-byte per the RFC: `D(V,Es)` is a 31-bit CRC-32 (IEEE,
  MSB discarded) of the 4-octet Ethernet Tag + 10-octet ESI, fed
  through the `(1103515245·x + 12345) mod 2^31` LCG, with the
  numerically lowest PE IP as the equal-weight tie-break. A
  known-answer unit test pins the digest + weight against an
  independent computation. The IPv4 weight is cross-vendor exact
  (the interoperable VXLAN-underlay case); IPv6 `Si` has no
  standardized 128→32-bit reduction, so it uses the address's
  low-order 31 bits (the LCG already reduces `mod 2^31`) —
  deterministic and self-consistent across rustbgpd PEs but not
  cross-vendor guaranteed. The M46 rustbgpd×2 smoke exercises the
  config → DF Election extcomm → unanimous-HRW negotiation → election
  → failover path over real BGP (using a VNI where the HRW winner
  differs from the modulo winner, so it positively proves HRW is in
  effect); a true cross-vendor HRW smoke is not possible because FRR
  implements RFC 9785 preference-DF, not HRW, so the known-answer test
  is the cross-vendor conformance guarantee. RFC 8584 algorithm
  negotiation falls back to default service carving when candidates
  disagree or omit the DF Election Extended Community. RFC 9785
  Highest-/Lowest-Preference election selects the configured
  preference order, then Don't-Preempt, then the numerically lowest PE
  IP as tie-breakers; mixed algorithms likewise fall back to default
  service carving.
- **Three Type 1/4 originator state machines** in
  `crates/evpn/src/origination_es.rs`: `LocalEsOriginator` (Type 4
  ES), `LocalEadPerEsOriginator` (Type 1 EAD-per-ES with MAX_ET
  marker), `LocalEadPerEviOriginator` (Type 1 EAD-per-EVI, role-aware
  via `on_vni_role_changed`). All three follow the deterministic
  `(state, event) → action` pattern from `LocalMacOriginator`
  (Gate 7b+1) — no I/O, no time, callable from a unit test.
- **Daemon orchestrator** in `src/evpn_segment.rs`: one tokio task
  per `[[ethernet_segments]]` block, subscribed to the EVPN
  best-path broadcast (Gate 7c). On every Type 4 event for a tracked
  ESI, re-gather candidates from the RIB, run the election, fire
  per-VNI `on_vni_role_changed` for any flipped slot, update the
  Prometheus surface.
- **Observable Prometheus surface**: `evpn_df_role{esi,vni,role}`
  gauge (PromQL `evpn_df_role{role="df"} == 1` finds active DFs)
  and `evpn_df_role_changes_total{esi,vni}` counter for spotting
  flap loops.

### Out of scope at Gate 8 (Gate 8b status)

- **ES-Import RT extcomm (RFC 7432 §7.6) origination — closed in
  the Gate 8b prep follow-up.** The Type 4 ES route now carries an
  auto-derived ES-Import RT (high-order 6 octets of the ESI Value
  per §7.6), so peers that filter Type 4 imports on this RT can
  correlate the segment without preconfiguration. The remaining
  Gate 8b work is the *import-side* application of the RT in the
  daemon's own RIB filter — Gate 8 still imports Type 4 via the
  user-configured RTs only.
- **ESI Label extcomm (RFC 7432 §7.5) origination — closed in the
  Gate 8b prep follow-up.** The Type 1 EAD-per-ES route now carries
  the ESI Label extcomm with an allocated per-ESI label and
  a configured `single_active` flag (`false` for all-active, `true`
  for single-active). Gate 8b also adds the load-bearing half:
  opt-in dataplane filtering that suppresses segment BUM on non-DF
  receivers.
- **Aliasing / backup paths (RFC 7432 §14) — closed end-to-end.**
  Projection resolves Type 1 EAD-per-EVI alternatives into
  `RemoteMacEntry::alias_vtep_ips`; the kernel-side ECMP /
  multi-destination programming subsequently shipped under
  [ADR-0059](0059-evpn-aliasing-fdb-nexthop-groups.md) (FDB
  nexthop groups via `NDA_NH_ID` / `NHA_FDB`, slices 1-4,
  M40 protected self-hosted smoke against FRR EVPN-MH 10.3.1) for
  all-active ES reachability. Receiver-side aliasing suppresses
  those ECMP alternatives when the remote EAD-per-ES advertises the
  Single-Active flag. Proactive backup-path programming for
  single-active remains a follow-up.
- **Mass withdraw — receive-side filter closed in Gate 8b.** The
  dataplane supervisor snapshots EAD-per-ES reachability and drops
  non-zero-ESI Type 2 routes whose `(origin VTEP next-hop, ESI)` is
  not active. Event-driven AS_PATH-change heuristics remain optional
  future optimization, not the RFC base path.
- **DF-role-aware MAC origination — closed in Gate 8b.** Local Type 2
  routes for VNIs in configured Ethernet Segments now carry the
  segment ESI. Config rejects one VNI shared across multiple local
  ESIs until learned-port disambiguation is plumbed.

### Rejected: ship Gate 8 with split-horizon enforcement

> **Follow-up (ADR-0065):** what later shipped as Gate 8b is *role-based*
> DF/non-DF BUM-port suppression, not source-conditioned VXLAN local-bias
> split-horizon. ADR-0065's netns spike confirmed true local-bias is not
> achievable with stateless `tc` on the standard bridged-VXLAN softswitch
> (the overlay source isn't visible to `tc-flower` at the VXLAN ingress
> hook — the FRR #15400 failure mode) and is ASIC/offload-dependent. It
> remains the open all-active correctness gate.

The temptation was to bundle observation + enforcement in one gate
and call it "EVPN multihoming, complete." Three reasons against:

1. **Dataplane reach.** rustbgpd's Linux dataplane crate (ADR-0054)
   doesn't currently program ESI-label-aware filters; the Linux
   side would need an MPLS-in-UDP or VXLAN-with-ESI-label inner
   match path that doesn't exist yet. Gate 8b's scope is half
   wire-codec, half dataplane.
2. **Interop blast radius.** A non-DF PE that *advertises* it's a
   non-DF (via DF election extcomm) but *doesn't actually drop* on
   the dataplane is a strictly better wire-citizen than a PE that
   drops without telling peers. The control-plane half tested in
   isolation surfaces protocol bugs without risking real BUM black
   holes during interop runs.
3. **Reviewability.** Splitting at the observation/enforcement seam
   keeps each PR shippable. The Gate 8 PR is large enough as a
   pure control-plane addition; bundling the dataplane filter
   would push it past comfortable review size.

### Rejected: skip observation, ship full enforcement first

Equivalent argument in reverse: the election state machine is the
hardest part of Gate 8 (RFC 8584 negotiation, service carving,
deterministic ordering, idempotent re-emission), and shipping it
under observation means the field bug surface is one Prometheus
counter rather than a production-traffic black hole. Standard
"control plane first, enforcement second" cadence — same shape as
how route refresh, RPKI, and BMP all landed.

## Consequences

### Positive

- **Unblocks Gate 8b.** Election + Type 1/4 origination is the
  prerequisite for split-horizon, aliasing, and mass-withdraw work.
  Gate 8b can focus entirely on dataplane filtering + the ESI Label
  extcomm allocator without re-solving control-plane carving.
- **Useful in single-DF deployments.** Operators running 1 PE per
  segment (the simple case) get the full Gate 8 wire shape — peers
  see the segment, see the local PE as DF — without ever needing
  enforcement. Detection-only is a valid soak phase for anyone
  considering true multihoming.
- **Observable now.** Looking glass and alerting can rely on
  `evpn_df_role` immediately. Operators can validate election
  behavior in production traffic without dataplane risk.

### Negative / risks

- **Split-horizon black hole window — mitigated by Gate 8b
  enforcement.** A Gate 8-only two-PE multihoming setup duplicates
  BUM toward the CE. Gate 8b adds the kernel primitive behind
  `apply_bum_enforcement`, which defaults to `true` since v0.23.0
  after the Gate 8b 24 h MAC-churn soak (2026-05-16) and the M37
  local-origination 24 h MAC-churn soak (2026-05-19) both passed.
  Single-homed deployments and route-reflector deployments are
  unaffected.
- **Interop with strict ES-Import RT importers — closed in the
  Gate 8b prep follow-up.** Type 4 ES routes now carry the
  auto-derived ES-Import RT extcomm (high-order 6 octets of the
  ESI Value), so peers that filter on ES-Import RT now see the
  segment without operator preconfiguration.
- **Wire crate stays at 0.9.0.** Gate 8 reuses the existing Type 1/4
  encoders/decoders from `rustbgpd-wire`. No wire bump.

## Verification

- `crates/evpn/src/segment.rs` unit tests — domain construction,
  algorithm-id round-trip, role string formatting (6 tests).
- `crates/evpn/src/df_election.rs` unit tests — service carving
  determinism, algorithm negotiation floor, empty-candidate
  rejection, duplicate-originator rejection (17 tests).
- `crates/evpn/src/origination_es.rs` unit tests — startup,
  shutdown, EAD-per-EVI per-VNI state tracking (note: in Gate 8
  the EAD-per-EVI wire shape is role-independent per RFC 7432 §14,
  so role flips on an already-advertising VNI emit no wire
  actions; the per-VNI role state is still tracked for Gate 8b
  aliasing) (19 tests).
- `src/evpn_segment.rs` orchestrator tests — extcomm decode,
  candidate gathering, role-flip propagation (5 tests).
- M38 interop topology in `tests/interop/topologies/m38-evpn-df/`
  drives a 2-PE rustbgpd ⟷ FRR segment, asserts both PEs see each
  other's Type 4 + EAD-per-ES, asserts the elected DF flips when
  the lower-IP PE drops the segment.

## References

- RFC 7432 §7.5 (ESI Label extcomm), §7.6 (ES-Import RT), §8.5
  (default service carving), §8.6 (mass withdraw), §14 (aliasing),
  §15.4 (MAC mobility)
- RFC 8584 §3 (DF algorithm negotiation), §3.1 (DF election extcomm)
- ADR-0054 — Linux dataplane boundary (informs Gate 8b enforcement
  reach)
- ADR-0055 — Local-MAC origination boundary (Gate 8 reuses the same
  pure-state-machine pattern)
- `docs/evpn-enablement.md` — multihoming gate matrix
