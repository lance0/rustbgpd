# Changelog

This changelog covers the independently published `rustbgpd-wire` crate. Daemon
and workspace changes remain in the repository-level `CHANGELOG.md`.

## Unreleased

- **Additive typed Partial preservation:** Added
  `PathAttribute::CommunitiesPartial`, `ExtendedCommunitiesPartial`,
  `PmsiTunnelPartial`, and `LargeCommunitiesPartial` while retaining every
  canonical tuple variant. Valid Partial-bearing values now remain typed and
  re-emit with Partial across compact and Extended Length framing; malformed
  recognized values remain RFC 7606 treat-as-withdraw. PMSI decoding now
  enforces the assigned, experimental, composite, and identifier-length
  boundaries from the IANA registry, RFC 6514, and RFC 8317.
- **Additive typed OTC correction:** Preserved
  `PathAttribute::OnlyToCustomer(u32)` for canonical/local OTC and added
  `PathAttribute::OnlyToCustomerPartial(u32)` for valid received OTC carrying
  Partial. Extended Length and reserved low flag bits are accepted and
  canonically emitted; malformed flags or lengths are legacy UPDATE attribute
  errors and revised RFC 7606 treat-as-withdraw records instead of opaque
  attributes.
- **Optional Tokio framing:** Added the default-off `tokio-codec` feature and
  the `BgpCodec` / `BgpCodecError` API. The adapter keeps separate inbound and
  outbound RFC 8654 ceilings, preserves incomplete input, isolates malformed
  complete frames, and encodes transactionally. A feature-gated example shows
  direct use with `tokio_util::codec`.
- **Additive notification API:** Added `cease_subcode::BFD_DOWN` and the
  corresponding `description` result for the RFC 9384 BFD Down Cease subcode.
- **Decode and encode behavior:** Unknown optional non-transitive path
  attributes are now ignored by both strict and revised decoders and by the
  defensive encoder. Unknown optional transitive attributes remain preserved
  for propagation with the Partial bit.
- **Adoption example:** Added a standalone captured-UPDATE decoder using the
  crate's public framing and parsed-update APIs.

## 0.17.2 - 2026-08-23

- **Additive API with decode-classification changes:** Added the
  `PathAttribute::AtomicAggregate` variant to the existing non-exhaustive enum.
  A valid zero-length ATOMIC_AGGREGATE now decodes to that variant instead of
  `Unknown`, so it no longer triggers unrecognized-well-known
  treat-as-withdraw validation. A non-zero-length value is now an attribute
  length error; the legacy strict decoder rejects the record while the revised
  path applies attribute-discard.
- Replaced attribute-decoder `unreachable!` guards with the typed
  `DecodeError`s already used by their surrounding validation. Existing
  rejected inputs remain rejected and no public signature was removed.

## 0.17.1 - 2026-08-19

- **Documentation and test-only patch:** Corrected RFC citations in rustdoc,
  the README, and test assertions and added a malformed-input fuzz seed. Public
  API, wire format, and decoder and encoder behavior are unchanged from 0.17.0.

## 0.17.0 - 2026-08-08

- **Breaking API:** `encode_evpn_nlri` now returns
  `Result<(), EncodeError>` instead of `()`. Direct callers must handle or
  propagate the result and discard the output buffer after an error.
- Invalid EVPN Type 5 gateway/prefix family combinations and invalid EAD
  ethernet-tag shapes now return `EncodeError::ValueOutOfRange` instead of
  silently emitting substitute bytes that could decode as a different route.

## 0.16.2 - 2026-08-04

- **Documentation-only patch:** Updated the ASPA verification draft citation
  and clarified its first-AS precondition. Public API and wire behavior are
  unchanged from 0.16.1.

## 0.16.1 - 2026-07-30

- **No library API or behavior change:** Corrected rustdoc and README
  descriptions of RFC 7606 retained attributes and added benchmark coverage.
  Public API and decoder and encoder behavior are unchanged from 0.16.0.

## 0.16.0 - 2026-07-27

- **Additive API with decode-acceptance changes:** Added RFC 6793 AS4
  normalization, RFC 9072 extended OPEN parameters, RFC 9774 prohibited-set
  handling, typed AGGREGATOR decoding, and an exact unknown-RD text fallback.
  No existing public item was removed or changed incompatibly.
- Binary decode acceptance or classification changed in six places:
  unsupported OPEN Optional Parameter types now error; BGP-LS attribute flags
  and TLV framing are enforced; AGGREGATOR is typed instead of `Unknown`; OPEN
  and KEEPALIVE remain capped at 4096 bytes even after Extended Messages
  negotiation; AS_SET and AS_CONFED_SET are rejected with treat-as-withdraw;
  and Link Bandwidth matching accepts only its exact registered types.
- Duplicate Large Communities now retain only the first occurrence. The text
  parser separately accepts the exact 16-hex-digit `RouteDistinguisher`
  fallback for an unknown RD type.

## 0.15.0 - 2026-07-18

- **Breaking API:** Marked the public enums that track extensible protocol
  registries `#[non_exhaustive]`; downstream matches on them must add a wildcard
  arm. `Capability` also gained `PathsLimit`, and constructible `UpdateError`
  gained its public `disposition` field.
- Added RFC 7606 revised UPDATE parsing through `parse_revised`, including
  per-attribute `ErrorDisposition` values and recoverable malformed-attribute
  evidence. Future additions to the non-exhaustive registry enums are no
  longer compile-time breaking changes.

## 0.14.1 - 2026-07-11

- **Additive API:** Added `AsPath::asns` and per-message `encode_with_limit`
  methods for NOTIFICATION and ROUTE-REFRESH. The existing
  `encode_message_with_limit` now applies the caller's ceiling to those message
  types. No public item was removed or changed incompatibly, and the default
  4096-byte encoding ceiling is unchanged.

## 0.14.0 - 2026-07-06

- **Breaking API:** Added public VPNv4/VPNv6, RT-Constrain, and labeled-unicast
  fields to `MpReachNlri` / `MpUnreachNlri`, plus
  `ParsedUpdate::bgpls_nlri_discarded`. External struct literals must supply the
  new fields.
- Added exhaustive `Safi` variants for labeled-unicast, MPLS VPN, and
  RT-Constrain and `NotificationCode::SendHoldTimerExpired`; downstream matches
  must add arms. The release also added typed BGP-LS topology accessors and
  Origin Validation State community constants.

## 0.13.0 - 2026-06-30

- **Breaking API:** Added `Afi::BgpLs`, `Safi::BgpLs`, and `Safi::BgpLsVpn` to
  exhaustive enums and public BGP-LS fields to `MpReachNlri` /
  `MpUnreachNlri`. Downstream matches and struct literals must be updated.
- Integrated the existing BGP-LS codec into structured `MP_REACH_NLRI` /
  `MP_UNREACH_NLRI` dispatch and made their encoding fallible for oversized
  FlowSpec rule vectors. `UpdateMessage::try_build` provides the fallible build
  path.

## 0.12.0 - 2026-06-17

- **Additive API:** Added standalone BGP-LS and VPNv4/VPNv6 labeled-NLRI codec
  substrates, round-trip helpers, fuzz coverage, and unsupported-family
  dispatch guards. The daemon did not yet negotiate or store those families.

## 0.11.0 - 2026-06-04

- **Breaking API:** Added RFC 5291/5292 ORF types and
  `Capability::OutboundRouteFilter`. `RouteRefreshMessage` gained the public
  `orf: Option<OrfPayload>` field and no longer implements `Copy`; callers using
  struct literals, exhaustive capability matches, or copy semantics must
  update.

## 0.10.0 - 2026-05-27

- **Breaking API:** Added `Capability::Role(BgpRole)` and
  `PathAttribute::OnlyToCustomer(u32)` to exhaustive enums for RFC 9234. Code
  matching either enum exhaustively must add arms. `BgpRole` itself is a new
  public type.

## 0.9.4 - 2026-05-25

- **Additive API and parser acceptance:** Added Link Bandwidth Extended
  Community decode and construction plus `UpdateValidationOptions` and
  `validate_update_attributes_with_options` for optional link-local-primary
  IPv4 `MP_REACH_NLRI` acceptance on unnumbered sessions.

## 0.9.3 - 2026-05-24

- **Additive API:** Added the typed RFC 8584 / RFC 9785 DF Election Extended
  Community and its decode and construction helpers. Existing public items are
  unchanged.

## 0.9.2 - 2026-05-21

- **Breaking API despite the patch version:** The public
  `encode_flowspec_nlri` function was replaced by
  `try_encode_flowspec_nlri`, which returns `Result<(), EncodeError>` and leaves
  its destination unchanged on failure. Direct callers must rename the call
  and handle or propagate the result.
- Added `FlowSpecRule::encoded_len`, `FlowSpecRule::validate_encoded_len`, and
  `MAX_FLOWSPEC_NLRI_RULE_LEN` so callers can reject rules above the 4095-byte
  wire limit before encoding.

## 0.9.1 - 2026-05-14

- **Additive API:** Added the RFC 1997 `NO_EXPORT`, `NO_ADVERTISE`, and
  `NO_EXPORT_SUBCONFED` community constants and the RFC 7999 `BLACKHOLE`
  constant. No signature or struct changed.

## 0.9.0 - 2026-05-07

- **Breaking API:** Added `PathAttribute::PmsiTunnel(PmsiTunnel)` to the then
  exhaustive `PathAttribute` enum. Downstream matches must add an arm.
- Added typed PMSI Tunnel values and the EVPN-VXLAN ingress-replication wire
  form, including `PmsiTunnel`, `PmsiTunnelType`, and
  `PmsiTunnelIdentifier`.

## 0.8.5 - 2026-05-04

- **Additive API:** Added the RFC 8326 `COMMUNITY_GRACEFUL_SHUTDOWN` well-known
  community constant. Existing public items are unchanged.

## 0.8.4 - 2026-05-01

- **Additive API:** Added `RouteDistinguisher::from_str` for the three RFC 4364
  structured textual encodings and the public `RouteDistinguisherParseError`
  type, with round-trip and fuzz coverage.

## 0.8.3 - 2026-05-01

- **Decode-acceptance correction:** IPv6 `MP_REACH_NLRI` 32-byte next hops now
  require the second segment to be in `fe80::/10`. The change rejects malformed
  input that 0.8.2 accepted; no public API changed.

## 0.8.2 - 2026-05-01

- **Decode-acceptance correction:** FlowSpec `MP_REACH_NLRI` no longer applies
  the unicast NEXT_HOP semantic check when that attribute is irrelevant. Valid
  FlowSpec input that 0.8.1 rejected is accepted; no public API changed.

## 0.8.1 - 2026-04-29

- **Documentation-only patch:** Refreshed the README's supported-RFC and key
  type lists for the published EVPN surface. Source and public API are unchanged
  from 0.8.0.

## 0.8.0 - 2026-04-29

- **Breaking API:** Added the public
  `MpReachNlri::link_local_next_hop: Option<Ipv6Addr>` field so 32-byte IPv6
  next hops round-trip without losing their link-local segment. External struct
  literals must supply the new field.

## 0.7.0 - 2026-04-26

- **Breaking API:** Added public `evpn_announced` / `evpn_withdrawn` fields to
  `MpReachNlri` / `MpUnreachNlri` and the `Afi::L2Vpn` and `Safi::Evpn`
  variants to exhaustive enums. External struct literals and exhaustive
  matches must be updated.
- Added the typed EVPN NLRI codec for route types 1-5, EVPN extended-community
  helpers, and EVPN decode and encode fuzz targets.

## 0.6.0 - 2026-03-14

- **Additive API:** Added the routing-domain `AspaValidation` enum with
  `Display`, `FromStr`, `Default`, `Hash`, and equality implementations.

## 0.5.0 - 2026-03-12

- Initial independent crate release of the BGP message codec, covering OPEN,
  UPDATE, KEEPALIVE, NOTIFICATION, and ROUTE-REFRESH with MP-BGP, FlowSpec,
  Add-Path, Extended Messages, Graceful Restart, and LLGR extensions.
- Established structured decode and encode errors, unknown-attribute
  preservation, property tests, and fuzz targets for message, UPDATE, and
  FlowSpec decoding.
