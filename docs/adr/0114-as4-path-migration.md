# ADR-0114: RFC 6793 AS4 path migration across legacy peers

**Status:** Accepted
**Date:** 2026-07-21

## Context

[RFC 6793](https://www.rfc-editor.org/rfc/rfc6793.html) lets a BGP speaker
that supports four-octet ASNs exchange routes with a speaker that does not.
The ordinary `AS_PATH` remains the path-selection attribute. Across a legacy
session it carries two-octet ASNs and substitutes `AS_TRANS` (23456) for every
non-mappable ASN. The optional-transitive `AS4_PATH` carries the four-octet
path needed to recover the logical path. `AGGREGATOR` and `AS4_AGGREGATOR`
form the corresponding pair for aggregation metadata.

This is not merely a wire-compatibility detail. RFC 6793 requires the
reconstructed path to be used for AS-loop detection. In rustbgpd the same
typed `AsPath` also feeds origin-AS and AS-path policy, path length, best-path
selection, ASPA validation, import rejection context, RIB state, reflection,
and operator explain output. A route server or route reflector that retains
only `AS_TRANS` can therefore apply policy to the wrong origin, miss a loop,
select a different route, and propagate a path whose four-octet identity has
been lost. Transparent third-party path preservation is core RR/IX behavior,
not forwarding-plane or PE scope.

Before this decision, rustbgpd implemented only part of the transition:

- OPEN advertises capability 65 and uses `AS_TRANS` in the two-octet My AS
  field when the configured local ASN is not mappable;
- negotiation records whether the peer advertised the four-octet-AS
  capability;
- `AS_PATH` is decoded with two- or four-octet elements according to that
  result; and
- outbound encoding toward a legacy peer replaces each non-mappable ASN with
  `AS_TRANS`.

At decision time, the remaining behavior was internally inconsistent:

- outbound encoding does not generate the compensating `AS4_PATH`;
- `AS4_PATH` and `AS4_AGGREGATOR` decode as opaque `RawAttribute` values;
- the raw AS4 attribute may be propagated with the Partial bit, but it is not
  reconciled with the typed `AS_PATH` used by any semantic consumer;
- migration attributes learned from a legacy peer can be carried onward to a
  four-octet-capable peer even though RFC 6793 forbids them between capable
  speakers; and
- exact-export probing measures the same encoder, so adding AS4 bytes only in
  a later send step would let Adj-RIB-Out commit a route that the final encoder
  rejects at the peer's negotiated message ceiling.

The revised attribute decoder already applies
[RFC 9774](https://www.rfc-editor.org/rfc/rfc9774.html) before duplicate
discard: `AS_SET` or `AS_CONFED_SET` in either `AS_PATH` or raw `AS4_PATH`
causes treat-as-withdraw. That is newer and stronger than RFC 6793's original
handling and must not be weakened. [RFC 7606](https://www.rfc-editor.org/rfc/rfc7606.html)
explicitly leaves the error handling defined for attributes 17 and 18 in
place: ordinary malformed `AS4_PATH` and `AS4_AGGREGATOR` use attribute
discard, while a conflicting Optional/Transitive flag combination remains
the stronger treat-as-withdraw action under RFC 7606.

Four-octet-AS capability support is ubiquitous, so this was not a high-volume
feature request. However, the daemon negotiated legacy sessions and then
silently offered incomplete semantics. The choices were to complete the
vertical slice, reject legacy negotiation, or keep a correctness trap.

## Options

### A. Normalize on ingress and project on egress

Decode the migration pair at the session boundary, construct one canonical
logical path and aggregator, and generate target-specific AS4 attributes only
while encoding for a legacy peer.

- **For:** every semantic consumer sees one lossless truth; NEW-to-NEW output
  remains clean; the exact-export probe and live encoder can stay identical;
  and the implementation follows the shape used by mature speakers.
- **Against:** the wire layer must parse attributes 17 and 18 together, add a
  canonical aggregator representation, and cover subtle reconstruction and
  error cases. It is larger than an encoder-only patch.

### B. Add only outbound `AS4_PATH`

Generate a compensating attribute when a non-mappable path is sent to a
legacy peer, leaving inbound attributes opaque.

- **For:** small and fixes one visible packet-capture defect.
- **Against:** loop detection, policy, ASPA, best path, and reflection still
  consume the lossy path. It creates the appearance of RFC 6793 support while
  preserving the more dangerous half of the bug.

### C. Reject peers without the four-octet capability

Fail session negotiation instead of accepting a representation rustbgpd does
not completely understand.

- **For:** small, explicit, and fail-closed.
- **Against:** removes compatibility already represented in configuration,
  negotiation, tests, and the CLI. It prevents a route server from serving a
  deliberately legacy member even though a bounded standards-compliant
  solution exists.

### D. Keep the current partial behavior

- **For:** no engineering cost for a rare deployment shape.
- **Against:** silent path corruption is worse than an explicit unsupported
  session and is especially inappropriate for a transparent route server.

## Decision

Choose **Option A** as one indivisible implementation tranche. It landed with
the complete ingress, egress, exact-export, error-handling, snapshot, and
real-session proof below. Option B was not merged independently.

This work is worthwhile as correctness hardening for an already-negotiated
mode, but it is not a release blocker and does not justify unrelated protocol
surface. No new address family, confederation support, aggregation feature,
policy language, or public configuration knob is authorized.

### One canonical semantic truth

The daemon continues to store one four-octet logical `AsPath` in route
attributes. `AS4_PATH` is a wire migration shadow, never a second policy- or
best-path-visible path. Inbound normalization must finish before mandatory
attribute validation, AS-loop and first-AS checks, import policy, RPKI/ASPA,
RIB insertion, best path, rejection/explain recording, semantic MRT/API/RIB
snapshots, Loc-RIB BMP synthesis, or reflection can observe the route.

RFC 7854 pre-policy Adj-RIB-In BMP is the deliberate exception. That tap runs
on the received UPDATE PDU before semantic decoding and must retain the exact
ordinary type 2/7 and migration type 17/18 wire attributes. Normalization must
not move the tap or replace its raw bytes. Post-policy and Loc-RIB views observe
the canonical route instead.

The normalization result contains:

- one typed canonical `AS_PATH`, with the RFC 6793 reconstruction applied when
  applicable;
- at most one typed canonical aggregator containing a `u32` ASN, router ID,
  and the selected source attribute's Partial provenance; and
- no raw type 17 or 18 attribute that could be emitted a second time.

The migration parser may use an internal sidecar while processing one UPDATE,
but that sidecar must not enter Loc-RIB, Adj-RIB-In, Adj-RIB-Out, an update
group, policy input, or a public route model. Adding `As4Path` as a competing
long-lived `PathAttribute` variant is rejected.

### Inbound ordering and error contract

The revised decoder must recognize type 17 as Optional+Transitive with
four-octet ASNs and type 18 as Optional+Transitive with exactly eight value
octets. The current ordering remains load-bearing:

1. inspect raw `AS_PATH` and `AS4_PATH` segment framing for RFC 9774-forbidden
   `AS_SET` and `AS_CONFED_SET` before duplicate handling;
2. retain treat-as-withdraw if either forbidden set is found, even in a later
   duplicate or an attribute that would otherwise be discarded;
3. apply the existing first-wins duplicate rule and attribute-discard later
   duplicate AS4 attributes;
4. validate known flags and framing; a flag conflict is treat-as-withdraw,
   while an otherwise malformed type 17 or 18 is attribute-discard; and
5. normalize the surviving pair, then run the existing UPDATE semantic
   validation and import pipeline against the canonical attributes.

An attribute-discard result removes only the malformed migration attribute;
the UPDATE continues using a valid ordinary `AS_PATH` and, where present, the
ordinary aggregator. The existing bounded malformed-update metric and local
diagnostic record the disposition and type code. No per-prefix event or
unbounded raw-byte label is added.

For type 17, "malformed" includes every RFC 6793 section 6 framing case: an
attribute value shorter than six octets, a value length that is not a multiple
of two, an unknown path-segment type, a zero segment count, or a segment whose
declared count is inconsistent with the remaining attribute length. Each case
is attribute-discard unless the earlier raw RFC 9774 inspection found a
forbidden set, whose stronger treat-as-withdraw action still wins. This matrix
must be implemented explicitly; reusing the current permissive ordinary-path
decoder without these checks is not conformant.

RFC 6793 forbids `AS_CONFED_SEQUENCE` and `AS_CONFED_SET` in `AS4_PATH`.
RFC 9774 already makes `AS_CONFED_SET` treat-as-withdraw. If an otherwise
well-framed type 17 contains `AS_CONFED_SEQUENCE`, the parser removes that
segment, adjusts the working path, logs the condition, and continues as RFC
6793 requires. This narrow skip does not add confederation segments to the
canonical model. An ordinary `AS_PATH` containing unsupported confederation
segments keeps its current error behavior; general confederation support is
out of scope.

When the peer did negotiate the four-octet capability, the ordinary
`AS_PATH` and `AGGREGATOR` already use four-octet ASNs. After the RFC 9774 raw
inspection, any type 17 or 18 is discarded and logged, and no reconstruction
occurs. Those attributes must not survive for later propagation.

### Legacy-peer reconstruction

For a peer that did not negotiate the four-octet capability, a valid surviving
`AS4_PATH` is reconciled with the two-octet `AS_PATH` exactly as RFC 6793
section 4.2.3 specifies:

1. Count ASNs in both paths using the route-selection counting rule from RFC
   4271 section 9.1.2.2: an `AS_SEQUENCE` contributes its number of ASNs and an
   `AS_SET` contributes one. Under rustbgpd's default RFC 9774 posture, a set
   has already caused treat-as-withdraw, but the reconstruction helper must
   implement the RFC count rather than a flattened-vector shortcut.
2. If the ordinary path count is less than the AS4 path count, ignore
   `AS4_PATH` and keep the ordinary path. Do not truncate the AS4 value to make
   it fit.
3. Otherwise, take the required count and segment structure from the leading
   part of the ordinary path and prepend it to `AS4_PATH`, so the reconstructed
   path has the same route-selection count as the ordinary path.
4. Replace the ordinary typed path with that result before any semantic
   consumer runs.

The helper must preserve segment boundaries where the RFC requires them and
must handle a boundary that splits an `AS_SEQUENCE`; concatenating two
sequence fragments is allowed only when it preserves the same logical path.
It must not reconstruct by replacing every `AS_TRANS` position independently:
OLD speakers prepend real two-octet ASNs only to `AS_PATH`, so positional
substitution is not the RFC algorithm.

### Aggregator decision matrix

`AGGREGATOR` becomes a typed canonical attribute rather than remaining opaque.
Migration handling covers type 18 in the same tranche as type 17:

| Received from legacy peer | Canonical result | AS4 path handling |
|---|---|---|
| `AGGREGATOR` only | Its two-octet ASN and router ID | Reconstruct if type 17 exists |
| Both, ordinary ASN is not `AS_TRANS` | Ordinary aggregator | Ignore type 18 and type 17 |
| Both, ordinary ASN is `AS_TRANS` | Type 18 ASN and router ID | Reconstruct from type 17 |
| `AS4_AGGREGATOR` only | Type 18 ASN and router ID | Reconstruct if type 17 exists |
| Neither | No aggregator | Reconstruct if type 17 exists |

The both-present rows are normative RFC 6793 behavior. The lone type 18 row is
an explicit interoperability decision for an underspecified input: retain its
informational value rather than propagate an opaque migration attribute or
discard a valid aggregator. It matches
[FRR's established behavior](https://github.com/FRRouting/frr/blob/198183c1981411eb227cf7d7471a4d29a11c1c11/bgpd/bgp_attr.c#L2627-L2636)
and does not let type 18 suppress reconstruction without the ordinary
non-`AS_TRANS` signal.

Partial provenance on a received optional-transitive aggregator is retained
in the canonical value and on a later optional-transitive projection. A
locally generated complete value does not acquire Partial merely because the
old raw-storage path used to mark all unknown optional-transitive attributes.

### Target-specific egress projection

The canonical route and update-group identity remain capability-independent.
Projection happens in the authoritative session export encoder after export
policy, route-server transparency changes, private-AS removal, and other
per-target AS-path transformations have produced the final logical path.

For a four-octet-capable target:

- encode the canonical path as the ordinary four-octet `AS_PATH`;
- encode a canonical aggregator as the ordinary eight-octet `AGGREGATOR`; and
- emit neither type 17 nor type 18.

For a legacy target:

- encode the final path as a two-octet `AS_PATH`, mapping every non-mappable
  ASN to `AS_TRANS`;
- if every ASN is mappable, emit no `AS4_PATH`;
- otherwise, emit the complete final logical path as a four-octet
  Optional+Transitive `AS4_PATH`, excluding unsupported confederation segments;
- encode a mappable canonical aggregator as the six-octet `AGGREGATOR` only;
  and
- encode a non-mappable canonical aggregator as six-octet `AGGREGATOR` with
  `AS_TRANS` plus an eight-octet `AS4_AGGREGATOR` carrying the true ASN and
  the same router ID.

No path reaching this projector may contain an RFC 9774-forbidden set. If an
internal injection path violates that invariant, exact-export rejects the
candidate rather than manufacturing an `AS4_PATH` containing `AS_SET` or
`AS_CONFED_SET`. This is a boundary assertion, not confederation support.

The generated migration attributes are derived values. Existing raw type 17
or 18 attributes are removed during ingress normalization, so projection can
never emit both a stale received shadow and a newly generated one.

The same authoritative builder must serve live sending, `encoded_len`, and
exact-export precommit. AS4 bytes are included before comparing against the
4,096- or 65,535-octet negotiated maximum and before Adj-RIB-Out advances.
Update-group probe reuse remains valid only between profiles that produce the
same target-specific wire representation; the existing four-octet-capability
profile discriminator must remain part of that proof. No post-commit fallback
may silently omit AS4_PATH to fit a message.

Path attributes are shared by every route-bearing UPDATE family, so this
projection applies through the existing common encoder to all already
supported families. The implementation must not wire only IPv4-unicast while
leaving MP_REACH routes lossy, and it must not add a new family.

### Public compatibility and observability

No TOML, gRPC, CLI, or route-policy schema change is required. Existing
neighbor output already reports whether four-octet-AS capability was
negotiated. Policy and route APIs continue to expose the canonical logical
path, now corrected for legacy ingress; they do not expose migration-shadow
attributes as policy inputs. The current gRPC `Route` and CLI route summaries
do not expose an aggregator, and they intentionally continue to omit it in this
tranche; adding that public field is a separate compatibility decision.

The non-exhaustive Rust `PathAttribute` model gains a typed aggregator. Every
full-attribute serializer that rebuilds a route from canonical state, including
MRT, Loc-RIB BMP, and ribsnap, must be audited so the selected canonical
aggregator is re-encoded rather than silently dropped. RFC 7854 pre-policy BMP
continues to carry the original raw type 7/18 bytes as specified above. A raw
type 7/18 pair may therefore normalize to one logical type 7 in a synthesized
four-octet record; that intentional content correction is not byte-for-byte
raw capture and must be covered by fixtures.

ASN4-to-ASN4 output without an aggregator or illegal raw types 17/18 remains
byte-for-byte unchanged. Recognizing `AGGREGATOR` can remove the artificial
Partial bit that the current opaque-attribute encoder adds; this is an
intentional wire correction and must be called out in implementation review.
Legacy paths containing only mappable ASNs remain byte-for-byte unchanged and
gain no empty or redundant AS4 attribute. Unknown optional-transitive
attributes of every other type retain the existing raw pass-through and
Partial behavior.

Logs and the existing malformed-update counter cover discarded or illegal
migration attributes. A successful ordinary reconstruction does not log per
route. If operators later need aggregate legacy-use visibility, a bounded
peer/session counter is a separate observability change, not a reason to grow
this protocol tranche.

### Implementation sequence and stop conditions

The implementation was reviewed in this order and merged as one capability:

1. add internal parsers and canonical aggregator representation with the
   RFC 7606/9774 disposition matrix;
2. normalize type 2/17 and type 7/18 pairs before semantic consumers;
3. project the canonical pair in the shared target-specific encoder;
4. prove exact-export sizing and update-group profile separation; and
5. add real-session interop and user-facing RFC notes.

Stop and return to design rather than merge if any of these occurs:

- only ingress or only egress is ready;
- raw and reconstructed paths remain independently semantic;
- type 18 or exact-export sizing is deferred;
- RFC 9774 handling is weakened or made configurable in this tranche;
- the diff expands into confederations, route aggregation, a new address
  family, a policy feature, or a public configuration/API redesign; or
- the real-session fixture cannot demonstrate both wire preservation and a
  semantic inbound effect.

## Load-bearing validation

The implementation's unit, integration, serializer, and M94 interop checks
are organized around these production breaks. Each executable test names the
deletion or mutation that must make it red; the implementation receipt records
the corresponding mutation runs.

| Proof | Required assertion | Revert or mutation that must make it red |
|---|---|---|
| Legacy outbound exact wire | A final logical path containing `4200000001` decodes from two-octet `AS_PATH` plus `AS4_PATH` to the exact original sequence | Remove generated type 17; the decoded path contains only `AS_TRANS` |
| Mappable-only output | A legacy target receives ordinary `AS_PATH` and no type 17 | Emit AS4_PATH unconditionally; the attribute inventory assertion fails |
| Inbound semantic path | A legacy UPDATE whose AS4 suffix contains the local ASN is rejected as an AS loop, or an origin-AS policy/best-path fixture changes outcome only after reconstruction | Bypass normalization; the lossy ordinary path is accepted or selected |
| Count and boundary vectors | Shorter, equal, and longer AS4 counts plus a split `AS_SEQUENCE` produce the RFC 6793 results | Replace the count algorithm with positional `AS_TRANS` substitution or flatten incorrectly |
| Aggregator matrix | Every table row above yields the specified canonical aggregator and path decision | Ignore type 7's non-`AS_TRANS` suppression rule or omit lone-type-18 handling |
| Pre-policy BMP wire preservation | A legacy inbound UPDATE's pre-policy BMP PDU is byte-equal, including its original type 2/7/17/18 attributes, while policy and Loc-RIB see the reconstructed path | Move BMP emission after normalization or feed it the canonical attribute vector |
| Malformed attribute discard | Separate vectors for a value shorter than six octets, odd value length, unknown segment type, zero segment count, and inconsistent declared segment length discard type 17 while valid reachable NLRI continues with ordinary `AS_PATH` | Reuse the permissive ordinary-path decoder or route AS4 parse failures through default treat-as-withdraw |
| AS4 confederation sequence | A well-framed type 17 containing `AS_CONFED_SEQUENCE` drops that segment and continues with the remaining path | Reject the UPDATE, discard all of type 17, or retain the confederation segment |
| RFC 9774 strongest action | A forbidden set in type 17, including a later duplicate, is treat-as-withdraw | Move raw set inspection after duplicate discard or downgrade it to attribute-discard |
| NEW-to-NEW suppression | Types 17/18 received from a capable peer never enter canonical attributes or later output | Preserve either raw migration attribute |
| Exact-export ceiling | A route whose compensating type 17 crosses the peer maximum is rejected before Adj-RIB-Out commit | Measure only the two-octet AS_PATH or add AS4_PATH after the probe |
| Common-family encoder | IPv4-unicast and one MP_REACH family both preserve the same non-mappable logical path | Add AS4 projection only to the IPv4-body builder |

Pure codec vectors are necessary but not sufficient. M94 runs a digest-pinned
real **ExaBGP 5.0.9** process with `asn4 disable;` as the OLD source. A bounded,
byte-transparent Python relay independently decodes the ExaBGP-to-rustbgpd
wire while forwarding it unchanged; a separate independent Python OLD speaker
receives and decodes rustbgpd's egress. ExaBGP is deliberately not used as the
receiving oracle because version 5.0.9 rejects its own valid legacy AS4 output.

The 13/13 live receipt proves both rustbgpd sessions negotiate without ASN4.
ExaBGP sends type 2 `[65010, 23456]`, type 17
`[65010, 4200000194]`, type 7 `23456:10.94.0.2`, and type 18
`4200000294:10.94.0.2`; the accepted route becomes the canonical path
`[65010, 4200000194]`. A second route's type 2 `[65010, 23456]` and type 17
`[65010, 4200000094]` reconstruct the high local ASN and trigger AS-path-loop
rejection. rustbgpd emits the same exact accepted-route path and aggregator
pairs to the independent OLD sink. The source withdrawal reaches the sink and
removes the received route while both sessions remain Established. The image
digest, relay bounds, and decoder live in the checked-in containerlab fixture;
a hand-built wire-crate packet alone would not satisfy this gate.

## Consequences

- Legacy sessions become semantically honest instead of merely encodable.
- Every downstream consumer benefits from one ingress fix, with no parallel
  AS4-aware policy or RIB path.
- Target-specific encoding grows by one derived attribute only when the route
  actually contains a non-mappable ASN; ordinary modern fanout is unchanged.
- The wire model gains typed aggregator semantics even though rustbgpd does
  not originate aggregates. That cost is required to avoid an incomplete RFC
  6793 slice, but it does not authorize route-aggregation behavior.
- A route learned through a legacy peer may change policy, validation, or best
  path because the daemon now sees its real ASNs. That shipped correctness
  change is called out in the release notes.

## References

- [RFC 6793 — BGP Support for Four-Octet Autonomous System Number Space](https://www.rfc-editor.org/rfc/rfc6793.html)
- [RFC 7606 — Revised Error Handling for BGP UPDATE Messages](https://www.rfc-editor.org/rfc/rfc7606.html)
- [RFC 9774 — Deprecation of AS_SET and AS_CONFED_SET](https://www.rfc-editor.org/rfc/rfc9774.html)
- [ExaBGP 5.0.9 `asn4 disable` example](https://github.com/Exa-Networks/exabgp/blob/5.0.9/etc/exabgp/conf-no-asn4.conf)
- [ExaBGP 5.0.9 configuration manual](https://github.com/Exa-Networks/exabgp/blob/5.0.9/doc/man/exabgp.conf.5)
