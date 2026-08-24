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
- Normative anchors: [RFC 4271 §§4.3, 5](https://www.rfc-editor.org/rfc/rfc4271), [RFC 7606 §§2, 3, 5.2, 7.1-7.10](https://www.rfc-editor.org/rfc/rfc7606), [RFC 9234 §§5](https://www.rfc-editor.org/rfc/rfc9234), [RFC 7311](https://www.rfc-editor.org/rfc/rfc7311), [RFC 9552](https://www.rfc-editor.org/rfc/rfc9552), and [RFC 8669 §3](https://www.rfc-editor.org/rfc/rfc8669).

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
| 14 | MP_REACH_NLRI | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 15 | MP_UNREACH_NLRI | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 16 | EXTENDED COMMUNITIES | optional transitive; flags `0xc0`; values are eight-octet communities; RFC 4360 / RFC 7606 §7.14 | typed canonical + Partial round-trip; Extended Length and reserved low bits canonicalize; malformed length is treat-as-withdraw | typed-Partial matrix |
| 17 | AS4_PATH | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 18 | AS4_AGGREGATOR | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 19 | SAFI Specific Attribute (SSA) (deprecated) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 20 | Connector Attribute (deprecated) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 21 | AS_PATHLIMIT (deprecated) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 22 | PMSI_TUNNEL | optional transitive; flags `0xc0`; RFC 6514 §5 / RFC 7385 | typed canonical + Partial round-trip; Extended Length and reserved low bits canonicalize; malformed tunnel type or identifier is treat-as-withdraw | typed-Partial and PMSI tunnel-type matrices |
| 23 | Tunnel Encapsulation | optional transitive; flags `0xc0`; RFC 9012 | payload semantics unsupported; correct class retained opaque and emitted with Partial; wrong class is treat-as-withdraw | assigned-class matrix below |
| 24 | Traffic Engineering | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 25 | IPv6 Address Specific Extended Community | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 26 | AIGP | optional non-transitive; flags `0x80`; RFC 7311 §3 | payload semantics unsupported; correct class ignored; Transitive-set conflicts are attribute-discard, other class conflicts are treat-as-withdraw | assigned-class matrix below |
| 27 | PE Distinguisher Labels | optional transitive; flags `0xc0`; RFC 6514 | payload semantics unsupported; correct class retained opaque and emitted with Partial; wrong class is treat-as-withdraw | assigned-class matrix below |
| 28 | BGP Entropy Label Capability Attribute (deprecated) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 29 | BGP-LS Attribute | optional non-transitive; flags `0x80`; RFC 9552 §5.3 | recognized opaque attribute survives byte-for-byte; `0xc0` is malformed | enriched fence test |
| 30 | Deprecated | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 31 | Deprecated | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 32 | LARGE_COMMUNITY | optional transitive; flags `0xc0`; values are twelve-octet communities; RFC 8092 §6 | typed canonical + Partial round-trip; duplicate values normalize first-seen; malformed length is treat-as-withdraw | typed-Partial matrix |
| 33 | BGPsec_Path | optional non-transitive; flags `0x80`; RFC 8205 | payload semantics unsupported; correct class ignored; wrong class is treat-as-withdraw | assigned-class matrix below |
| 34 | BGP Community Container Attribute (TEMPORARY - registered 2017-07-28, extension registered 2024-08-22, expires 2025-07-28) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 35 | Only to Customer (OTC) | optional transitive; flags `0xc0`; exactly one four-octet ASN; RFC 9234 §5 | typed ASN + Partial round-trip; Extended Length and reserved low bits canonicalize; wrong class or length is treat-as-withdraw | OTC codec and transport matrices |
| 36 | BGP Domain Path (D-PATH) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 37 | SFP attribute | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 38 | BFD Discriminator | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 39 | Next Hop Dependent Characteristic (NHC) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 40 | BGP Prefix-SID | optional transitive; flags `0xc0`; RFC 8669 §3 | payload semantics unsupported; correct class retained opaque and emitted with Partial; wrong class is treat-as-withdraw | assigned-class matrix below |
| 41 | BIER | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 42 | Edge Metadata Path Attribute (TEMPORARY - registered 2025-04-23, extension registered 2026-04-03, expires 2027-04-23) | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 43-127 | Unassigned | pending follow-up audit | pending follow-up audit | IANA CSV digest above |
| 128 | ATTR_SET | optional transitive; flags `0xc0`; RFC 6368 | payload semantics unsupported; correct class retained opaque and emitted with Partial; wrong class is treat-as-withdraw | assigned-class matrix below |
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

## Assigned class fence

This matrix audits only the registered Optional/Transitive class. It does not
claim payload parsing, semantic validation, policy support, or feature
negotiation. "Wrong O" toggles Optional, "wrong T" toggles Transitive, and
"both" toggles both bits from the canonical class.

| Codes | Class | Correct-class retention and egress | Wrong O | Wrong T | Both wrong | Legacy decoder |
|---|---|---|---|---|---|---|
| 23, 27, 40, 128 | optional transitive (`0xc0`) | opaque retention; Partial set on egress; input Partial and Extended Length preserved | treat-as-withdraw | treat-as-withdraw | treat-as-withdraw | `ATTRIBUTE_FLAGS_ERROR` for every conflict |
| 26 | optional non-transitive (`0x80`) | ignored; no retention or egress | treat-as-withdraw | attribute-discard | attribute-discard | `ATTRIBUTE_FLAGS_ERROR` for every conflict |
| 33 | optional non-transitive (`0x80`) | ignored; no retention or egress | treat-as-withdraw | treat-as-withdraw | treat-as-withdraw | `ATTRIBUTE_FLAGS_ERROR` for every conflict |

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
