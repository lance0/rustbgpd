# ADR-0097: BMP monitoring — the trio, BMPv4 framing, and path marking

**Status:** Accepted — shipped across #660 (RFC 8671 Adj-RIB-Out), #662
(RFC 9069 Loc-RIB + collector-connect table sync), #663 (BMPv4 TLV
framing), #664 (Path Marking TLV), with the M81 three-collector interop
receipt (#665).
**Date:** 2026-07-03

## Context

rustbgpd has exported BMP since ADR-0041: RFC 7854 pre-policy Adj-RIB-In
Route Monitoring, per-collector TCP clients with reconnect/backoff,
PeerUp replay, periodic stats, coordinated Termination — a lossy
try_send channel with drop counters, by design, because monitoring must
never backpressure the control plane.

The July 2026 research pass (ROADMAP "Next") found BMP depth to be the
open, niche-defining gap: **no open-source daemon ships the full
monitoring trio** — RFC 7854 (Adj-RIB-In) + RFC 8671 (Adj-RIB-Out) +
RFC 9069 (Loc-RIB). FRR and GoBGP stop at Loc-RIB, BIRD's BMP is
experimental, OpenBGPd has none. Per-client Adj-RIB-Out monitoring is
the observability twin of ORR (ADR-0095): *prove what the RR actually
sent each client*. On top of that, the BMPv4 TLV framework
(draft-ietf-grow-bmp-tlv) and the path-marking / route-event-logging
drafts had no router-side implementation anywhere, while rustbgpd
already computed per-path `BestPathReason` — making path marking mostly
a serialization problem.

This ADR records the decisions of that arc as shipped.

## Decisions

1. **The rib-out tap is the transport's outbound byte funnel; the
   loc-rib tap is the RIB's recompute commit points.** Two views, two
   honesty requirements, two seams:

   - *Adj-RIB-Out post-policy* taps `enqueue_bulk`
     (`crates/transport/src/session/io.rs`) — the single choke point
     every family's announces, withdraws, and EoRs pass through as
     already-encoded bytes. The BMP Route Monitoring message wraps the
     **exact PDU sent on the wire** (a `Bytes` refcount clone, zero
     re-encode), *after* transport stamping (ORIGINATOR_ID/CLUSTER_LIST,
     GShut, LLGR §4.6 stripping) — byte-exactness is what RFC 8671 is
     for, and it is test-pinned for VPN and EVPN. O-flag semantics
     verified against the RFC: O=0x10 on RM, L=post-policy under O=1,
     peer identity stays the remote peer's, PeerUp/Down/Stats remain
     O=0. Stats 15/17 come from one batched AdjRibOut query per stats
     tick; unavailable counts are omitted, never a false zero.
   - *Loc-RIB* is synthesized at the `recompute_best` commit seams in
     `crates/rib/src/manager/distribution/mod.rs` — the same seams the
     durable event system observes. Loc-RIB routes were stripped of
     their MP_REACH at decode, so `crates/rib/src/bmp_sync.rs` rebuilds
     UPDATE PDUs (the MRT exporter's attribute-synthesis pattern).
     The emulated instance peer follows RFC 9069 §5.2.1: peer type 3,
     peer flags **forced to zero** (its own registry — never V, even
     for v6), a fabricated sent-OPEN advertising exactly the capability
     set streamed, VRF/Table Name `"global"`, peer-down reason 6,
     stats 8/10. V1 synthesis scope is IPv4/IPv6 unicast + VPNv4/v6
     (`LOC_RIB_FAMILIES`); other families land additively and are
     deliberately absent from the fabricated OPEN so collectors are
     never promised streams that don't arrive.

   Per-collector `monitor = ["rib_in_pre", "rib_out_post", "loc_rib"]`
   selects views (default `["rib_in_pre"]` — pre-existing behavior
   unchanged), and a session-side gate keeps the BMP channel single-load
   when nobody subscribes to rib-out.

2. **Collector-connect table sync is a chunked, non-blocking dump.**
   RFC 7854's known gap: a collector that connects mid-life has no way
   to learn the current table. On connect (and every reconnect), after
   PeerUp replay and the loc-rib PeerUp, the RIB streams a Loc-RIB dump
   in 256-message chunks (`BMP_DUMP_CHUNK_SIZE`) to a **spawned
   forwarder task** that drains into the collector's bounded channel
   under a per-message send timeout — the RIB task and the BMP manager
   loop never await a slow collector; a stalled collector aborts its own
   dump (the next reconnect starts a fresh one). The dump ends with one
   End-of-RIB per synthesized family, then live monitoring continues.
   Dump/live overlap is the standard BMP initial-sync race — a route
   that changes mid-dump may appear twice — accepted as every collector
   already handles it; ordering (dump → EoR → live per collector) is
   test-pinned.

3. **Rib-out table dumps were rejected.** AdjRibOut stores routes
   *pre*-transport-stamping — ORIGINATOR_ID/CLUSTER_LIST, GShut, and
   LLGR stripping apply session-side at encode. A dump synthesized from
   AdjRibOut would not be byte-faithful to what the wire carried, which
   is the one property the rib-out view exists to provide. Rib-out is
   therefore live-only (like rib-in), and the post-policy Loc-RIB dump
   covers what dump consumers want from an RR.

4. **BMPv4 is a per-collector framing decision at fan-out, not an
   internal representation.** Internal `BmpEvent`s stay
   version-agnostic; the manager frames per collector at fan-out with a
   two-slot per-version memo, so an event is encoded at most once per
   BMP version in use — v3-only fleets do zero extra work. The PeerUp
   replay cache stores both encodings; the dump forwarder frames at its
   collector's version. Per-collector `version = 3 | 4`, **default 3**,
   and v3 output is byte-identical to prior releases, pinned by
   golden-bytes tests. Under `version = 4` (draft-ietf-grow-bmp-tlv-20):
   common-header version 4 everywhere, Route Monitoring wraps the UPDATE
   in the mandatory BGP Message TLV (type 7, index 0), Stats Reports
   wrap in the Stats TLV (code 1); message types that already provision
   TLV data in v3 (Peer Up/Down, Initiation, Termination) change only
   their version byte.

   **Pre-IANA posture:** every draft code point lives in ONE module —
   `crates/bmp/src/tlv.rs` — with section citations, so a renumber at
   RFC publication is a single-file change. The known collision is
   annotated there: path-marking-05 self-assigns RM TLV type 5 against
   an older base-draft registry, but tlv-20 §9 has since taken 5 for the
   VRF/Table Name TLV. rustbgpd never emits the VRF/Table Name RM TLV,
   so its own v4 output is self-consistent; a renumber is expected.
   (tlv-20's Appendix A wire example contradicts its own normative
   §5.2.1 on the Group TLV type; we follow the normative text.)

5. **Path marking is scoped to what the daemon can honestly attest.**
   The Path Marking TLV (draft-ietf-grow-bmp-path-marking-tlv-05) is an
   RM TLV, so it is v4-gated by construction — v3 output is byte-
   identical with or without a status payload (regression-pinned).
   Three honesty boundaries, all deliberate:

   - **Loc-RIB stream only.** rib-in-pre taps fire at receive time,
     before best-path selection — any Best/Non-selected mark there would
     be a guess. rib-out-post mirrors per-peer *staged output* (ORR and
     Add-Path variants), not the local decision process.
   - **Bits limited to Best + Stale.** Best because a Loc-RIB route is
     the decision winner by definition; Stale (0x400) from the GR/LLGR
     stale machinery. Primary/Backup/Non-installed/Filtered/Suppressed
     are FIB, policy-drop, and damping concepts a route reflector
     without a forwarding plane cannot attest to — never set rather
     than fabricated.
   - **The Reason Code is re-derived, not cached, and omitted when
     unmappable.** On live unicast announces the reason is computed at
     the `recompute_best` emit as best-vs-runner-up through the existing
     `best_path_cmp_with_reason` explain ladder, scanning the identical
     candidate expression the recompute itself used — so the reason is
     consistent with the actual decision. A sole candidate carries no
     reason (nothing was compared). Decisive steps with no registered
     draft code (stale/RPKI/ASPA preference, cluster-list length, EVPN
     MAC mobility) are omitted rather than mislabeled
     (`path_marking_reason_code` in `bmp_sync.rs`). VPN announces and
     dump entries carry status bits only.

   Perf note on record (#664): the runner-up scan is one extra
   O(candidates) pass per best-changed prefix when BMP is enabled, paid
   even for v3-only fleets that can't carry the result; if the
   1000-peer scale profile indicts it, the fix is an any-v4-collector
   flag plumbed to the RIB manager.

6. **REL (draft-ietf-grow-bmp-rel, Route Event Logging) was deferred.**
   Zero collectors decode it today; shipping an egress format nobody can
   consume is receipt-less work. The inputs it needs (policy discard
   reasons, RPKI/ASPA validation failures) already exist, so it stays a
   serialization slice whenever the collector ecosystem catches up.

7. **The M81 receipt scope was shaped by oracle reality, validated
   before assertions were written.** A Phase-0 pass established what
   each collector can honestly decode (matrix in the header of
   `tests/interop/scripts/test-m81-bmp-trio-gobgp.sh`): pmacct pmbmpd
   bleeding-edge implements pre-tlv-20 RM code points under a comment
   claiming tlv-20 and discards every tlv-20 RM, and reads the 2-byte
   TLV index through a dereferenced `char*` (docs/upstream-findings.md
   findings 5–6); gobmp hard-rejects version ≠ 3; released Wireshark
   dissects the v4 version byte, per-peer headers, and generic TLV
   headers but maps RM TLV *values* per older drafts. So pmacct + gobmp
   serve as independent **v3 semantic oracles** across all three RM
   streams, while tlv-20 code points and the entire Path Marking payload
   are asserted at **raw byte offsets against the drafts' wire
   figures**, with the v3 byte-stream as the cross-reference (RM PDU
   sets byte-equal across v3/v4 framings). 50/50 assertions; no
   assertion rests on an oracle that Phase 0 showed cannot decode it.
   No product bugs found — every oracle agreed with rustbgpd everywhere
   it could decode.

## Relationship to the event history (ADR-0072)

BMP and the durable event outbox observe the same internal seams (the
loc-rib tap fires at the recompute commit points the event system
already watches) but serve different consumers: BMP is **standards
egress** — raw PDUs in the format the monitoring ecosystem (pmacct,
OpenBMP, gobmp→Kafka) already ingests, lossy by design, no replay
semantics beyond the connect-time dump; the event history is **typed,
queryable, and replayable** (durable monotonic cursor across restarts).
Complementary, one observation layer, two egress formats.

## Deferred (with un-defer triggers)

- **REL** (Decision 6) — a collector that decodes it.
- **BMPv4 optional TLVs**: Timestamp, Sequence Number, Extended Flags,
  Stateless Parsing — collector demand; the indexed-TLV encode
  infrastructure is already in place.
- **Path Marking Statistics** (path-marking-05 §4) — its stat type
  codes are unassigned TBDs in the draft.
- **Nonselected / Add-Path marking** — needs a decision-aware rib-in
  seam that does not exist; today's rib-in tap is pre-decision by
  design (Decision 5).
- **Per-NLRI TLV indexes > 0 and Group TLVs on emit** — rustbgpd
  synthesizes single-NLRI UPDATEs for loc-rib, so index 0 suffices
  (the Group TLV encoder shipped in #663 for when that changes).
- **Reason codes on VPN announces and dump entries** — bits-only today
  (Decision 5).
- **Rib-out dumps** — rejected, not deferred, unless AdjRibOut ever
  moves post-transport-stamping (Decision 3).
- **Stale-bit lab assertion** — the derivation is unit-tested; a live
  GR-window pin in an M-series lab rides the next GR-touching receipt
  (the GR machinery itself is receipted in M77/M79).

## Consequences

rustbgpd is the first open-source BGP daemon shipping the full BMP
monitoring trio — rib-in-pre, rib-out-post, and loc-rib on one exporter,
per-collector selectable — plus the first router-side BMPv4 TLV framing
and Path Marking implementation anywhere (pre-IANA, default-off behind
`version = 3`). The costs: a second encode path per BMP version at
fan-out (bounded by the two-slot memo), the loc-rib PDU synthesis and
reason re-derivation on best-change (bounded by the perf note in
Decision 5), and a standing draft-tracking obligation concentrated in
one code-point module. The M81 receipt also seeded the collector
ecosystem's tlv-20 catch-up with two concrete pmacct findings.
