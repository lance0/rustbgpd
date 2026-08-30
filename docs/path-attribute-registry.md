# BGP path-attribute registry audit

This is an offline audit baseline, not a claim that every registered attribute is
implemented. It keeps registry data, protocol requirements, observed behavior,
and executable evidence distinct so a registry update cannot silently become a
codec claim.

## Provenance and refresh

- Registry: [IANA BGP Path Attributes](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2)
- CSV: `https://www.iana.org/assignments/bgp-parameters/bgp-parameters-2.csv`
- Registry snapshot: 2026-08-18 (live-verified 2026-08-23)
- SHA-256: `691f147f5c9ef9dbde82febe339f5691a1bfc4d83f63e3ed0d224676ebe68886`
- Normative anchors: [RFC 4271 §§4.3, 5](https://www.rfc-editor.org/rfc/rfc4271), [RFC 7606 §§2, 3, 5.2, 7.1-7.10, 7.16](https://www.rfc-editor.org/rfc/rfc7606), [RFC 9012 §§2, 13](https://www.rfc-editor.org/rfc/rfc9012), [RFC 6368 §5](https://www.rfc-editor.org/rfc/rfc6368), [RFC 9234 §§5](https://www.rfc-editor.org/rfc/rfc9234), [RFC 7311](https://www.rfc-editor.org/rfc/rfc7311), [RFC 9552](https://www.rfc-editor.org/rfc/rfc9552), and [RFC 8669 §3](https://www.rfc-editor.org/rfc/rfc8669).

Manual live comparison (never run by normal CI): download the CSV with
`curl -fsSL https://www.iana.org/assignments/bgp-parameters/bgp-parameters-2.csv -o /tmp/bgp-parameters-2.csv`, run
`sha256sum /tmp/bgp-parameters-2.csv`, then compare its `Value` and `Code`
columns with the census below, expanding every range. A digest change requires
human review before changing either the census or an observed-behavior claim.

## Complete IANA census

`pending follow-up audit` means this tranche makes no normative or implementation
claim for that row. The offline test expands the ranges and requires every
octet from 0 through 255 to appear exactly once with no blank cell.

<!-- registry-census:start -->
| Code | IANA assignment | Normative requirement | Observed-current behavior | Evidence |
|---|---|---|---|---|
| 0 | Reserved | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 1 | ORIGIN | well-known mandatory; flags `0x40`; RFC 4271 §5.1.1; RFC 7606 §7.1 | typed round-trip; malformed is treat-as-withdraw | core matrix below |
| 2 | AS_PATH | well-known mandatory; flags `0x40`; RFC 4271 §5.1.2; RFC 7606 §7.2 | typed round-trip; malformed is treat-as-withdraw | core matrix below |
| 3 | NEXT_HOP | well-known mandatory; flags `0x40`; RFC 4271 §5.1.3; RFC 7606 §7.3 | typed round-trip; malformed is treat-as-withdraw | core matrix below |
| 4 | MULTI_EXIT_DISC | optional non-transitive; flags `0x80`; RFC 4271 §5.1.4; RFC 7606 §7.4 | typed round-trip; malformed is treat-as-withdraw | core matrix below |
| 5 | LOCAL_PREF | well-known discretionary; flags `0x40`; RFC 4271 §5.1.5; RFC 7606 §7.5 | typed round-trip; malformed is discard on eBGP and treat-as-withdraw on iBGP | core matrix below |
| 6 | ATOMIC_AGGREGATE | well-known discretionary; flags `0x40`; RFC 4271 §5.1.6; RFC 7606 §7.6 | typed round-trip; bad length is attribute-discard | core matrix below |
| 7 | AGGREGATOR | optional transitive; flags `0xc0`; RFC 4271 §5.1.7; RFC 7606 §7.7 | typed round-trip; bad length is attribute-discard | core matrix below |
| 8 | COMMUNITIES | optional transitive; flags `0xc0`; values are four-octet communities; RFC 1997 / RFC 7606 §7.8 | typed canonical + Partial round-trip; Extended Length and reserved low bits canonicalize; malformed length is treat-as-withdraw | core matrix and typed-Partial matrix |
| 9 | ORIGINATOR_ID | optional non-transitive; flags `0x80`; RFC 7606 §7.9 | typed round-trip; malformed is discard on eBGP and treat-as-withdraw on iBGP | core matrix below |
| 10 | CLUSTER_LIST | optional non-transitive; flags `0x80`; RFC 7606 §7.10 | typed round-trip; malformed is discard on eBGP and treat-as-withdraw on iBGP | core matrix below |
| 11 | DPA (deprecated) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 12 | ADVERTISER (historic) (deprecated) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 13 | RCID_PATH / CLUSTER_ID (Historic) (deprecated) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 14 | MP_REACH_NLRI | optional non-transitive; flags `0x80`; RFC 4760 §3; RFC 7606 §§5.3, 7.11 | typed per-family decode/encode; structural, flag, or embedded-NLRI failure and duplicate attributes are session-reset | wire framing matrix and transport reset proof |
| 15 | MP_UNREACH_NLRI | optional non-transitive; flags `0x80`; RFC 4760 §4; RFC 7606 §§5.3, 7.11 | typed per-family decode/encode; structural, flag, or embedded-NLRI failure and duplicate attributes are session-reset; empty NLRI is MP End-of-RIB only for a negotiated family other than IPv4 unicast | wire framing matrix and transport reset proof |
| 16 | EXTENDED COMMUNITIES | optional transitive; flags `0xc0`; values are eight-octet communities; RFC 4360 / RFC 7606 §7.14 | typed canonical + Partial round-trip; Extended Length and reserved low bits canonicalize; malformed length is treat-as-withdraw | typed-Partial matrix |
| 17 | AS4_PATH | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 18 | AS4_AGGREGATOR | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 19 | SAFI Specific Attribute (SSA) (deprecated) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 20 | Connector Attribute (deprecated) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 21 | AS_PATHLIMIT (deprecated) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 22 | PMSI_TUNNEL | optional transitive; flags `0xc0`; RFC 6514 §5 / RFC 7385 | typed canonical + Partial round-trip; Extended Length and reserved low bits canonicalize; malformed tunnel type or identifier is treat-as-withdraw | typed-Partial and PMSI tunnel-type matrices |
| 23 | Tunnel Encapsulation | optional transitive; flags `0xc0`; RFC 9012 | opaque retention with exact Tunnel TLV and variable-width sub-TLV framing; malformed framing or class is treat-as-withdraw | assigned class and framing matrices below |
| 24 | Traffic Engineering | optional non-transitive; flags `0x80`; RFC 5543 §3 / RFC 7606 §7.13 | payload semantics unsupported; correct class ignored and never emitted; class or Partial conflict is treat-as-withdraw | assigned-class matrix below |
| 25 | IPv6 Address Specific Extended Community | optional transitive; flags `0xc0`; values are non-empty multiples of 20 octets; RFC 5701 §2 / RFC 7606 §7.15 | opaque retention with Partial on egress; zero or non-multiple-of-20 length and class conflicts are treat-as-withdraw | assigned-class and IPv6-community length matrices below |
| 26 | AIGP | optional non-transitive; flags `0x80`; RFC 7311 §3 | payload semantics unsupported; correct class ignored; Transitive-set conflicts are attribute-discard, other class conflicts are treat-as-withdraw | assigned-class matrix below |
| 27 | PE Distinguisher Labels | optional transitive; flags `0xc0`; RFC 6514 | payload semantics unsupported; correct class retained opaque and emitted with Partial; wrong class is treat-as-withdraw | assigned-class matrix below |
| 28 | BGP Entropy Label Capability Attribute (deprecated) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 29 | BGP-LS Attribute | optional non-transitive; flags `0x80`; RFC 9552 §5.3 | recognized opaque attribute survives byte-for-byte; `0xc0` is malformed | enriched fence test |
| 30 | Deprecated | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 31 | Deprecated | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 32 | LARGE_COMMUNITY | optional transitive; flags `0xc0`; values are twelve-octet communities; RFC 8092 §6 | typed canonical + Partial round-trip; duplicate values normalize first-seen; malformed length is treat-as-withdraw | typed-Partial matrix |
| 33 | BGPsec_Path | optional non-transitive; flags `0x80`; RFC 8205 | payload semantics unsupported; correct class ignored; wrong class is treat-as-withdraw | assigned-class matrix below |
| 34 | BGP Community Container Attribute (temporary assignment in the live IANA registry) | optional transitive; flags `0xc0`; draft-ietf-idr-wide-bgp-communities-11 (work in progress) | opaque retention with Partial on egress; bounded container, Type 1 subtype, atom, and prefix framing; wrong class, malformed framing, or a duplicate attribute is treat-as-withdraw | Community Container framing matrix below; this is not a stable standards-support claim |
| 35 | Only to Customer (OTC) | optional transitive; flags `0xc0`; exactly one four-octet ASN; RFC 9234 §5 | typed ASN + Partial round-trip; Extended Length and reserved low bits canonicalize; wrong class or length is treat-as-withdraw | OTC codec and transport matrices |
| 36 | BGP Domain Path (D-PATH) | optional transitive; flags `0xc0`; draft-ietf-bess-evpn-ipvpn-interworking-18 | opaque retention with bounded domain-segment framing; malformed is treat-as-withdraw | assigned framing matrix below |
| 37 | SFP attribute | optional transitive; flags `0xc0`; RFC 9015 §3.2.1 | opaque retention with TLV, Hop, and Hop sub-TLV framing; malformed is treat-as-withdraw | assigned framing matrix below |
| 38 | BFD Discriminator | optional transitive; flags `0xc0`; RFC 9026 §3.1.6 | opaque retention with base and Source-IP TLV framing; malformed is attribute-discard | assigned framing matrix below |
| 39 | Next Hop Dependent Characteristic (NHC) | optional transitive; flags `0xc0`; draft-ietf-idr-nhc-07 | opaque retention with next-hop and characteristic-TLV framing; malformed or empty characteristics is attribute-discard | assigned framing matrix below |
| 40 | BGP Prefix-SID | optional transitive; flags `0xc0`; RFC 8669 §§3, 6 | opaque retention with complete TLV framing and known-length checks; malformed is attribute-discard | assigned framing matrix below |
| 41 | BIER | optional transitive; flags `0xc0`; RFC 9793 §§3-4 | opaque retention with exact TLV/sub-TLV length-boundary framing; boundary failure is attribute-discard | assigned framing matrix below |
| 42 | Edge Metadata Path Attribute (TEMPORARY - registered 2025-04-23, extension registered 2026-04-03, expires 2027-04-23) | optional non-transitive; flags `0x80`; draft-ietf-idr-5g-edge-service-metadata-27 | payload unsupported; correct class ignored and never emitted; every class or Partial conflict is treat-as-withdraw | assigned framing matrix below |
| 43-127 | Unassigned | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 128 | ATTR_SET | optional transitive; flags `0xc0`; RFC 6368 / RFC 7606 §7.16 | opaque retention with Origin AS and embedded attribute framing; embedded MP attributes, malformed framing, or wrong class are treat-as-withdraw | assigned class and framing matrices below |
| 129 | Deprecated | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 130-240 | Unassigned | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 241 | Deprecated | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 242 | Deprecated | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 243 | Deprecated | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 244-254 | Unassigned | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 255 | Reserved for development | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
<!-- registry-census:end -->

## Executable RFC 7606 core matrix

Hex values are attribute payloads; the test builds the header. `empty` means a
zero-length payload. Each valid row must decode to one typed attribute and
re-encode byte-for-byte. A changed Optional/Transitive flag pair must be
treat-as-withdraw. The malformed payload must produce the exact neighbor-class
disposition shown.

<!-- core-behavior:start -->
| Code | Flags | Valid value | Malformed value | eBGP disposition | iBGP disposition |
|---|---|---|---|---|---|
| 1 | 40 | 00 | 03 | treat-as-withdraw | treat-as-withdraw |
| 2 | 40 | 02010000fde9 | 02020000fde9 | treat-as-withdraw | treat-as-withdraw |
| 3 | 40 | c0000201 | c00002 | treat-as-withdraw | treat-as-withdraw |
| 4 | 80 | 00000064 | 000000 | treat-as-withdraw | treat-as-withdraw |
| 5 | 40 | 00000064 | 000000 | attribute-discard | treat-as-withdraw |
| 6 | 40 | empty | 00 | attribute-discard | attribute-discard |
| 7 | c0 | 0000fde9c0000201 | 0000fde9c00002 | attribute-discard | attribute-discard |
| 8 | c0 | fde80001 | fde800 | treat-as-withdraw | treat-as-withdraw |
| 9 | 80 | c0000201 | c00002 | attribute-discard | treat-as-withdraw |
| 10 | 80 | c0000201 | c00002 | attribute-discard | treat-as-withdraw |
<!-- core-behavior:end -->

## M100 released-receiver Partial-flag differential

M100 freezes one version-scoped receiver observation across rustbgpd 0.67.0,
BIRD 2.19.2, OpenBGPD 9.2, and FRR 10.3.1. Each cell receives the exact
attribute bytes shown below with flags `0xa0`; a separate observer session
reconstructs candidate and survivor state. This is a proof-only comparison of
the named releases, not a change to rustbgpd policy, configuration, defaults,
or the current-main core-behavior matrix above.

| Attribute | Exact attribute bytes | rustbgpd 0.67.0 | BIRD 2.19.2 | OpenBGPD 9.2 | FRR 10.3.1 |
|---|---|---|---|---|---|
| MED (4), value 100 | `a0040400000064` | accepted | accepted | reset | treat-as-withdraw |
| ORIGINATOR_ID (9) | `a00904c0000209` | accepted; attribute not forwarded to observer | accepted; attribute not forwarded to observer | reset | treat-as-withdraw |
| CLUSTER_LIST (10) | `a00a04c000020a` | accepted; attribute not forwarded to observer | accepted; attribute not forwarded to observer | reset | treat-as-withdraw |
| MP_REACH (14) | `a00e0d000101040a69000a0018c63364` | reset | accepted | reset | reset |
| MP_UNREACH (15) | `a00f0700010118c63364` | reset | same-session candidate withdrawal | reset | reset |

`accepted` means the source session stays in the same epoch and both candidate
and survivor remain visible through the observer; MED is additionally pinned at
100. The two same-session withdrawal labels both mean the candidate disappears,
the survivor remains, and no notification, close, or re-establishment occurs.
`reset` requires one ordered UPDATE `3/4` notification carrying the exact
attribute bytes, one close, and one re-establishment at the next source epoch;
both routes are absent across that boundary. The hosted job also rejects altered
flags, inverted expected outcomes, malformed command output, incomplete UPDATE
attribute bounds, missing route reconstruction, and duplicate or missing rows.

## Assigned class fence

This matrix audits only the registered Optional/Transitive class; bounded
payload framing is documented separately below. It does not claim semantic
validation, policy support, or feature negotiation. "Wrong O" toggles
Optional, "wrong T" toggles Transitive, and "both" toggles both bits from the
canonical class.

| Codes | Class | Correct-class retention and egress | Wrong O | Wrong T | Both wrong | Legacy decoder |
|---|---|---|---|---|---|---|
| 23, 25, 27, 34, 36-41, 128 | optional transitive (`0xc0`) | opaque retention; Partial set on egress; input Partial and Extended Length preserved | treat-as-withdraw | treat-as-withdraw | treat-as-withdraw | `ATTRIBUTE_FLAGS_ERROR` for every conflict |
| 26 | optional non-transitive (`0x80`) | ignored; no retention or egress | treat-as-withdraw | attribute-discard | attribute-discard | `ATTRIBUTE_FLAGS_ERROR` for every conflict |
| 24, 33, 42 | optional non-transitive (`0x80`) | ignored; no retention or egress; Partial rejected | treat-as-withdraw | treat-as-withdraw | treat-as-withdraw | `ATTRIBUTE_FLAGS_ERROR` for every conflict |

## IPv6 Address Specific Extended Community length matrix

The type-25 payload remains opaque: only the RFC 5701/RFC 7606 cardinality
boundary is enforced, and unrecognized community types or sub-types are not
errors.

| Payload length | Result |
|---|---|
| 20, 40, ... | retained opaquely and propagated with Partial |
| 0 or any non-multiple of 20 | Attribute Length Error; revised treat-as-withdraw |

## Community Container framing matrix

Type 34 remains an unsupported opaque attribute under a temporary live IANA
assignment and a work-in-progress draft. The checks below validate only bounded
framing; they do not expose a typed model or claim stable standards support.

| Layer | Accepted boundary | Rejected boundary |
|---|---|---|
| Container stream | one or more exact six-octet-header containers; unknown types opaque | truncated header, total length below six, overrun, or trailing bytes |
| Type 1 | twelve-octet fixed body followed by uniquely typed subtype TLVs; repeated Type 1 containers allowed | short fixed body, subtype framing error, or repeated subtype within one Type 1 |
| Known subtypes 1-3 | empty or an exact atom stream; unknown subtypes opaque | atom framing error or reserved atom type 0/255 |
| Atom values | types 1/4/5/6/7: positive multiples of four; types 2/3: complete IPv4/IPv6 prefix sequences; type 8 and types 9-254 opaque | fixed-width mismatch, prefix length above 32/128, or truncated prefix octets |

## Assigned framing matrix (23, 36-42, 128)

These checks are syntax-only. They do not implement route-family applicability,
stateful lookup, policy, or attribute semantics. Unknown types and their values
remain opaque.

<!-- assigned-framing:start -->
| Code | Registered class | Bounded structural fence | Revised malformed action |
|---|---|---|---|
| 23 | optional transitive; flags `0xc0` | one or more exact two-octet-type/two-octet-length Tunnel TLVs; each body is an exact sub-TLV stream with one-octet lengths for types 0-127 and two-octet lengths for types 128-255; values remain opaque | treat-as-withdraw |
| 36 | optional transitive; flags `0xc0` | non-empty sequence of nonzero-count domain segments, each exactly `1 + 7*n` octets | treat-as-withdraw |
| 37 | optional transitive; flags `0xc0` | exact one-octet-type/two-octet-length TLVs, at least one Hop TLV, and at least one exactly framed sub-TLV after every Hop service index | treat-as-withdraw |
| 38 | optional transitive; flags `0xc0` | five-octet base, exact one-octet-type/length optional TLVs, and a Source IP TLV of length 4 or 16 | attribute-discard |
| 39 | optional transitive; flags `0xc0` | AFI/SAFI/next-hop-length boundary followed by one or more exact two-octet-type/two-octet-length characteristic TLVs | attribute-discard |
| 40 | optional transitive; flags `0xc0` | exact one-octet-type/two-octet-length TLVs; Label-Index length 7; Originator SRGB length `2 + nonzero*6` | attribute-discard |
| 41 | optional transitive; flags `0xc0` | non-empty exact two-octet-type/length TLV stream; known containers consume nested length framing only when their four-octet fixed prefix is present; semantic field shapes remain opaque | attribute-discard |
| 42 | optional non-transitive; flags `0x80` | no payload validation; exact registered class is dropped before value decoding | class conflict is treat-as-withdraw |
| 128 | optional transitive; flags `0xc0` | four-octet Origin AS followed by an exact embedded path-attribute stream using each inner Extended Length bit; embedded MP_REACH_NLRI and MP_UNREACH_NLRI are rejected; inner values remain opaque | treat-as-withdraw |
<!-- assigned-framing:end -->

## PMSI tunnel-type matrix

PMSI Tunnel values use RFC 6514 base type and identifier semantics, the RFC
7385/IANA registry boundary, and RFC 8317 composite tunnel-type semantics.
Assigned types without a dedicated enum variant and experimental values remain
typed through opaque `PmsiTunnelType::Other` state; this is distinct from
accepting an unassigned value.

| Wire value | Result |
|---|---|
| `0x00`-`0x08`, `0x0a`-`0x0d`, `0xff` | accepted assigned type; type 0 requires an empty identifier and type 6 requires exactly 4 or 16 identifier octets |
| `0x7b`-`0x7e`, `0xfb`-`0xfe` | accepted experimental type with opaque identifier |
| `0x80`-`0xfa` | accepted only when the low seven bits name an assigned base other than 0 or 6 |
| `0x09`, `0x0e`-`0x7a`, `0x7f`, invalid composite | malformed field; revised decoding omits the attribute and records treat-as-withdraw |

For a valid RFC 8317 composite, decoding checks only the generic 3-octet
receiver-label prefix framing; it does not interpret the underlying transmit
identifier semantics.

The enriched fence tests separately prove all six rows' outcomes, BGP-LS
opaque behavior, typed PMSI behavior and wrong-class handling, and unchanged
synthetic unassigned handling. Everything outside this executable slice remains
explicitly `pending follow-up audit`.
