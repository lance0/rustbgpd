use rustbgpd_wire::attribute::{
    decode_path_attributes, decode_path_attributes_revised, encode_path_attributes,
};
use rustbgpd_wire::notification::update_subcode;
use rustbgpd_wire::validate::validate_update_attributes;
use rustbgpd_wire::{DecodeError, ErrorDisposition, PathAttribute};

const DOC: &str = include_str!("../../../docs/path-attribute-registry.md");

fn section(start: &str, end: &str) -> &'static str {
    DOC.split_once(start)
        .unwrap_or_else(|| panic!("missing {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing {end}"))
        .0
}

fn rows(section: &str, columns: usize) -> Vec<Vec<&str>> {
    section
        .lines()
        .filter(|line| line.starts_with('|'))
        .skip(2)
        .map(|line| {
            let cells: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
            assert_eq!(cells.len(), columns, "bad Markdown row: {line}");
            assert!(
                cells.iter().all(|cell| !cell.is_empty()),
                "blank audited cell: {line}"
            );
            cells
        })
        .collect()
}

fn hex(value: &str) -> Vec<u8> {
    if value == "empty" {
        return Vec::new();
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "odd hex value {value}");
    pairs
        .iter()
        .map(|pair| {
            let digits = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(digits, 16).unwrap()
        })
        .collect()
}

fn attribute(flags: u8, code: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![flags, code, u8::try_from(value.len()).unwrap()];
    bytes.extend_from_slice(value);
    bytes
}

fn extended_attribute(flags: u8, code: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![flags | 0x10, code];
    bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn community_tlv(kind: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn community_container(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = kind.to_be_bytes().to_vec();
    bytes.extend([0x5a, 0xa5]);
    bytes.extend_from_slice(&u16::try_from(body.len() + 6).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn community_type_one(subtypes: &[u8]) -> Vec<u8> {
    let mut body = vec![0; 12];
    body.extend_from_slice(subtypes);
    community_container(1, &body)
}

fn tunnel_sub_tlv(kind: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind];
    if kind < 128 {
        bytes.push(u8::try_from(value.len()).unwrap());
    } else {
        bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    }
    bytes.extend_from_slice(value);
    bytes
}

fn tunnel_tlv(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = kind.to_be_bytes().to_vec();
    bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn attr_set(origin_as: u32, embedded: &[u8]) -> Vec<u8> {
    let mut bytes = origin_as.to_be_bytes().to_vec();
    bytes.extend_from_slice(embedded);
    bytes
}

fn assert_opaque_round_trip(code: u8, value: &[u8]) {
    let input = attribute(0xe0, code, value);
    let strict = decode_path_attributes(&input, true, &[]).unwrap();
    let revised = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
    assert!(revised.malformed.is_empty());
    assert!(matches!(
        strict.as_slice(),
        [PathAttribute::Unknown(raw)]
            if raw.type_code == code && raw.data.as_ref() == value
    ));
    let mut emitted = Vec::new();
    encode_path_attributes(&revised.attributes, &mut emitted, true, false).unwrap();
    assert_eq!(emitted, input);
}

fn assert_length_error_treat_as_withdraw(code: u8, value: &[u8]) {
    let input = attribute(0xc0, code, value);
    assert!(matches!(
        decode_path_attributes(&input, true, &[]),
        Err(DecodeError::UpdateAttributeError { subcode, data, .. })
            if subcode == update_subcode::ATTRIBUTE_LENGTH_ERROR && data == input
    ));
    let revised = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
    assert!(revised.attributes.is_empty());
    assert_eq!(revised.malformed.len(), 1);
    assert_eq!(revised.malformed[0].type_code, code);
    assert_eq!(
        revised.malformed[0].disposition,
        ErrorDisposition::TreatAsWithdraw
    );
}

fn assigned_value(code: u8) -> Vec<u8> {
    match code {
        23 => tunnel_tlv(1, &[]),
        25 => (0_u8..20).collect(),
        34 => community_container(2, &[]),
        36 => vec![1, 0, 0, 0, 0, 0, 0, 0],
        37 => vec![2, 0, 4, 1, 99, 0, 0],
        38 => vec![1, 0, 0, 0, 1, 1, 4, 192, 0, 2, 1],
        39 => vec![0, 1, 1, 4, 192, 0, 2, 1, 0, 1, 0, 0],
        40 => vec![99, 0, 0],
        41 => vec![0, 1, 0, 12, 0, 0, 0, 0, 0, 4, 0, 4, 192, 0, 2, 1],
        42 => vec![0xaa],
        _ => vec![0xde, 0xad, 0xbe, 0xef],
    }
}

fn assigned_malformed(code: u8) -> Option<(Vec<u8>, ErrorDisposition)> {
    match code {
        23 => Some((Vec::new(), ErrorDisposition::TreatAsWithdraw)),
        36 => Some((vec![0; 8], ErrorDisposition::TreatAsWithdraw)),
        37 => Some((vec![2, 0, 1, 1], ErrorDisposition::TreatAsWithdraw)),
        38 => Some((vec![1, 0, 0, 0, 1], ErrorDisposition::AttributeDiscard)),
        39 => Some((
            vec![0, 1, 1, 4, 192, 0, 2, 1],
            ErrorDisposition::AttributeDiscard,
        )),
        40 => Some((vec![1, 0, 6, 0], ErrorDisposition::AttributeDiscard)),
        41 => Some((
            vec![0, 1, 0, 8, 0, 0, 0, 0, 0, 2, 0, 1],
            ErrorDisposition::AttributeDiscard,
        )),
        128 => Some((vec![0; 3], ErrorDisposition::TreatAsWithdraw)),
        _ => None,
    }
}

fn assigned_payload_contract(code: u8) -> &'static str {
    match code {
        23 => {
            "one or more exact two-octet-type/two-octet-length Tunnel TLVs; each body is an exact sub-TLV stream with one-octet lengths for types 0-127 and two-octet lengths for types 128-255; values remain opaque"
        }
        36 => "non-empty sequence of nonzero-count domain segments, each exactly `1 + 7*n` octets",
        37 => {
            "exact one-octet-type/two-octet-length TLVs, at least one Hop TLV, and at least one exactly framed sub-TLV after every Hop service index"
        }
        38 => {
            "five-octet base, exact one-octet-type/length optional TLVs, and a Source IP TLV of length 4 or 16"
        }
        39 => {
            "AFI/SAFI/next-hop-length boundary followed by one or more exact two-octet-type/two-octet-length characteristic TLVs"
        }
        40 => {
            "exact one-octet-type/two-octet-length TLVs; Label-Index length 7; Originator SRGB length `2 + nonzero*6`"
        }
        41 => {
            "non-empty exact two-octet-type/length TLV stream; known containers consume nested length framing only when their four-octet fixed prefix is present; semantic field shapes remain opaque"
        }
        42 => "no payload validation; exact registered class is dropped before value decoding",
        128 => {
            "four-octet Origin AS followed by an exact embedded path-attribute stream using each inner Extended Length bit; embedded MP_REACH_NLRI and MP_UNREACH_NLRI are rejected; inner values remain opaque"
        }
        _ => panic!("no assigned framing contract for code {code}"),
    }
}

fn disposition(value: &str) -> ErrorDisposition {
    match value {
        "attribute-discard" => ErrorDisposition::AttributeDiscard,
        "treat-as-withdraw" => ErrorDisposition::TreatAsWithdraw,
        other => panic!("unknown disposition {other}"),
    }
}

#[test]
fn census_covers_every_code_exactly_once() {
    assert!(DOC.contains("691f147f5c9ef9dbde82febe339f5691a1bfc4d83f63e3ed0d224676ebe68886"));
    assert!(DOC.contains("https://www.iana.org/assignments/bgp-parameters/bgp-parameters-2.csv"));

    let mut coverage = [0_u16; 256];
    for row in rows(
        section(
            "<!-- registry-census:start -->",
            "<!-- registry-census:end -->",
        ),
        5,
    ) {
        let (start, end) = row[0].split_once('-').unwrap_or((row[0], row[0]));
        let start: u8 = start.parse().unwrap();
        let end: u8 = end.parse().unwrap();
        assert!(start <= end, "reversed census range {}", row[0]);
        for code in start..=end {
            coverage[usize::from(code)] += 1;
        }
    }
    assert!(
        coverage.iter().all(|count| *count == 1),
        "census coverage must be exactly one per code: {coverage:?}"
    );
}

#[test]
fn otc_registry_claim_is_typed_partial_preserving_and_revised_safe() {
    let census = rows(
        section(
            "<!-- registry-census:start -->",
            "<!-- registry-census:end -->",
        ),
        5,
    );
    let row = census
        .iter()
        .find(|row| row[0] == "35")
        .expect("OTC registry row");
    assert!(row[2].contains("flags `0xc0`"));
    assert!(row[2].contains("four-octet ASN"));
    assert!(row[3].contains("typed ASN + Partial"));
    assert!(row[3].contains("treat-as-withdraw"));

    let value = 65_001_u32.to_be_bytes();
    for input in [
        attribute(0xc0, 35, &value),
        extended_attribute(0xe0, 35, &value),
    ] {
        let decoded = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
        assert!(decoded.malformed.is_empty());
        let [otc] = decoded.attributes.as_slice() else {
            panic!("OTC must remain typed");
        };
        let (asn, partial) = match otc {
            PathAttribute::OnlyToCustomer(asn) => (*asn, false),
            PathAttribute::OnlyToCustomerPartial(asn) => (*asn, true),
            other => panic!("expected typed OTC, got {other:?}"),
        };
        assert_eq!(asn, 65_001);
        assert_eq!(partial, input[0] & 0x20 != 0);
        let mut emitted = Vec::new();
        encode_path_attributes(&decoded.attributes, &mut emitted, true, false).unwrap();
        assert_eq!(
            emitted,
            attribute(if partial { 0xe0 } else { 0xc0 }, 35, &value)
        );
    }

    for (flags, value, subcode) in [
        (0xc0, &[0, 0, 1][..], update_subcode::ATTRIBUTE_LENGTH_ERROR),
        (
            0x80,
            &[0, 0, 0, 1][..],
            update_subcode::ATTRIBUTE_FLAGS_ERROR,
        ),
        // Wrong class takes priority over the simultaneous bad length.
        (0x00, &[0, 0, 1][..], update_subcode::ATTRIBUTE_FLAGS_ERROR),
    ] {
        let input = attribute(flags, 35, value);
        let legacy = decode_path_attributes(&input, true, &[]).unwrap_err();
        assert!(matches!(
            legacy,
            DecodeError::UpdateAttributeError {
                subcode: actual,
                ref data,
                ..
            } if actual == subcode && data == &input
        ));
        let revised = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
        assert!(revised.attributes.is_empty());
        assert_eq!(revised.malformed.len(), 1);
        assert_eq!(
            revised.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
    }
}

#[test]
fn recognized_optional_transitive_rows_are_typed_partial_preserving() {
    let census = rows(
        section(
            "<!-- registry-census:start -->",
            "<!-- registry-census:end -->",
        ),
        5,
    );
    for code in [8_u8, 16, 22, 32] {
        let row = census
            .iter()
            .find(|row| row[0] == code.to_string())
            .unwrap_or_else(|| panic!("missing registry row {code}"));
        assert!(row[2].contains("flags `0xc0`"), "row {code}");
        assert!(row[3].contains("typed canonical + Partial"), "row {code}");
        assert!(row[3].contains("treat-as-withdraw"), "row {code}");
    }

    for (code, value) in [
        (8_u8, 65_000_u32.to_be_bytes().to_vec()),
        (16, 0x0002_FDE8_0000_0064_u64.to_be_bytes().to_vec()),
        (22, vec![0, 0, 0, 0, 0]),
        (
            32,
            [65_000_u32, 1, 100]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect(),
        ),
    ] {
        for flags in [0xc0, 0xe0] {
            let input = attribute(flags, code, &value);
            let decoded = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
            assert!(decoded.malformed.is_empty(), "row {code}, flags {flags:#x}");
            let [typed] = decoded.attributes.as_slice() else {
                panic!("row {code} must decode to one typed attribute");
            };
            assert_eq!(typed.type_code(), code);
            assert_eq!(typed.flags() & 0x20, flags & 0x20);
            assert!(!matches!(typed, PathAttribute::Unknown(_)));
            let mut emitted = Vec::new();
            encode_path_attributes(&decoded.attributes, &mut emitted, true, false).unwrap();
            assert_eq!(emitted, input);
        }
    }
}

#[test]
fn core_matrix_proves_flags_roundtrip_and_malformed_dispositions() {
    let matrix = rows(
        section("<!-- core-behavior:start -->", "<!-- core-behavior:end -->"),
        6,
    );
    assert_eq!(matrix.len(), 10);

    for (index, row) in matrix.iter().enumerate() {
        let code: u8 = row[0].parse().unwrap();
        assert_eq!(code, u8::try_from(index + 1).unwrap());
        let flags = u8::from_str_radix(row[1], 16).unwrap();
        let valid = attribute(flags, code, &hex(row[2]));
        let decoded = decode_path_attributes_revised(&valid, true, false, &[]).unwrap();
        assert!(
            decoded.malformed.is_empty(),
            "valid type {code}: {decoded:?}"
        );
        let [decoded_attr] = decoded.attributes.as_slice() else {
            panic!("type {code} did not decode to exactly one attribute");
        };
        assert_eq!(decoded_attr.type_code(), code);
        assert_eq!(decoded_attr.flags(), flags);
        assert!(!matches!(decoded_attr, PathAttribute::Unknown(_)));
        let mut reencoded = Vec::new();
        encode_path_attributes(&decoded.attributes, &mut reencoded, true, false).unwrap();
        assert_eq!(reencoded, valid, "type {code} round-trip drift");

        let wrong_flags = flags ^ 0x80;
        let rejected = decode_path_attributes_revised(
            &attribute(wrong_flags, code, &hex(row[2])),
            true,
            false,
            &[],
        )
        .unwrap();
        assert!(rejected.attributes.is_empty());
        assert_eq!(rejected.malformed.len(), 1);
        assert_eq!(
            rejected.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw,
            "type {code} accepted wrong flags {wrong_flags:#04x}"
        );

        for (is_ibgp, expected) in [(false, row[4]), (true, row[5])] {
            let malformed = decode_path_attributes_revised(
                &attribute(flags, code, &hex(row[3])),
                true,
                is_ibgp,
                &[],
            )
            .unwrap();
            assert!(malformed.attributes.is_empty());
            assert_eq!(malformed.malformed.len(), 1);
            assert_eq!(malformed.malformed[0].type_code, code);
            assert_eq!(
                malformed.malformed[0].disposition,
                disposition(expected),
                "type {code}, is_ibgp={is_ibgp}"
            );
        }
    }
}

#[test]
fn assigned_and_unknown_behavior_fences_are_explicit() {
    let bgpls = attribute(0x80, 29, &[0x04, 0x47, 0, 1, 7]);
    let decoded = decode_path_attributes_revised(&bgpls, true, false, &[]).unwrap();
    let [PathAttribute::Unknown(raw)] = decoded.attributes.as_slice() else {
        panic!("BGP-LS must remain recognized opaque data");
    };
    assert_eq!(
        (raw.flags, raw.type_code, raw.data.as_ref()),
        (0x80, 29, &[0x04, 0x47, 0, 1, 7][..])
    );
    let mut emitted = Vec::new();
    encode_path_attributes(&decoded.attributes, &mut emitted, true, false).unwrap();
    assert_eq!(emitted, bgpls);
    let wrong_bgpls = decode_path_attributes_revised(
        &attribute(0xc0, 29, &[0x04, 0x47, 0, 1, 7]),
        true,
        false,
        &[],
    )
    .unwrap();
    assert_eq!(wrong_bgpls.malformed.len(), 1);
    assert_eq!(
        wrong_bgpls.malformed[0].disposition,
        ErrorDisposition::TreatAsWithdraw
    );

    let aigp = decode_path_attributes_revised(&attribute(0x80, 26, &[1, 0, 11]), true, false, &[])
        .unwrap();
    assert!(aigp.attributes.is_empty() && aigp.malformed.is_empty());

    let prefix_sid_value = assigned_value(40);
    let prefix_sid = attribute(0xc0, 40, &prefix_sid_value);
    let decoded = decode_path_attributes_revised(&prefix_sid, true, false, &[]).unwrap();
    assert!(
        matches!(&decoded.attributes[..], [PathAttribute::Unknown(raw)] if raw.type_code == 40)
    );
    let mut emitted = Vec::new();
    encode_path_attributes(&decoded.attributes, &mut emitted, true, false).unwrap();
    assert_eq!(emitted, attribute(0xe0, 40, &prefix_sid_value));

    let unknown =
        decode_path_attributes_revised(&attribute(0x40, 200, &[0xaa]), true, false, &[]).unwrap();
    let error = validate_update_attributes(&unknown.attributes, false, false, true).unwrap_err();
    assert_eq!(error.disposition, ErrorDisposition::TreatAsWithdraw);
}

#[test]
fn tunnel_encapsulation_enforces_tlv_and_sub_tlv_framing_only() {
    let one_tlv = tunnel_tlv(65_000, &tunnel_sub_tlv(127, &[0xaa, 0xbb]));
    let two_tlvs = [
        tunnel_tlv(1, &tunnel_sub_tlv(128, &[0xcc])),
        tunnel_tlv(65_001, &[]),
    ]
    .concat();
    let width_boundary = tunnel_tlv(
        2,
        &[tunnel_sub_tlv(127, &[0x7f]), tunnel_sub_tlv(128, &[0x80])].concat(),
    );
    for value in [one_tlv, two_tlvs, width_boundary, tunnel_tlv(3, &[])] {
        assert_opaque_round_trip(23, &value);
    }

    let malformed = [
        Vec::new(),
        vec![0],
        vec![0, 1],
        vec![0, 1, 0],
        vec![0, 1, 0, 1],
        tunnel_tlv(1, &[127]),
        tunnel_tlv(1, &[128]),
        tunnel_tlv(1, &[128, 0]),
        tunnel_tlv(1, &[127, 1]),
        tunnel_tlv(1, &[128, 0, 1]),
    ];
    for value in malformed {
        assert_length_error_treat_as_withdraw(23, &value);
    }
}

#[test]
fn attr_set_enforces_embedded_attribute_framing_without_recursive_decode() {
    let origin_only = attr_set(65_000, &[]);
    assert_opaque_round_trip(128, &origin_only);

    let embedded = [
        attribute(0x40, 1, &[0xff]),
        extended_attribute(0x80, 200, &[0xde, 0xad, 0xbe, 0xef]),
    ]
    .concat();
    assert_opaque_round_trip(128, &attr_set(65_001, &embedded));

    // The nested value would fail if interpreted as another ATTR_SET because
    // it is shorter than an Origin AS. This tranche treats it as opaque.
    let nested = attribute(0xc0, 128, &[0xc0, 14, 0]);
    assert_opaque_round_trip(128, &attr_set(65_002, &nested));

    let origin = 65_003_u32.to_be_bytes();
    let malformed = [
        Vec::new(),
        vec![0],
        vec![0, 0],
        vec![0, 0, 0],
        [origin.as_slice(), &[0x40]].concat(),
        [origin.as_slice(), &[0x40, 1]].concat(),
        [origin.as_slice(), &[0x50, 1]].concat(),
        [origin.as_slice(), &[0x50, 1, 0]].concat(),
        [origin.as_slice(), &[0x40, 1, 1]].concat(),
        [origin.as_slice(), &[0x50, 1, 0, 1]].concat(),
        [origin.as_slice(), &[0x80, 14, 0]].concat(),
        [origin.as_slice(), &[0x80, 15, 0]].concat(),
    ];
    for value in malformed {
        assert_length_error_treat_as_withdraw(128, &value);
    }
}

#[test]
fn bgpsec_path_remains_ignored_without_payload_parsing_or_egress() {
    for value in [&[][..], &[0xff][..], &[0x80, 0, 1][..]] {
        let input = attribute(0x80, 33, value);
        assert!(
            decode_path_attributes(&input, true, &[])
                .unwrap()
                .is_empty()
        );
        let revised = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
        assert!(revised.attributes.is_empty());
        assert!(revised.malformed.is_empty());
    }

    let mut emitted = Vec::new();
    encode_path_attributes(
        &[PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
            flags: 0x80,
            type_code: 33,
            data: bytes::Bytes::from_static(&[0xde, 0xad]),
        })],
        &mut emitted,
        true,
        false,
    )
    .unwrap();
    assert!(emitted.is_empty());
}

#[test]
fn assigned_unsupported_class_matrix_is_fail_closed_without_semantic_support() {
    #[derive(Clone, Copy)]
    struct Case {
        code: u8,
        canonical: u8,
        transitive_conflict: ErrorDisposition,
    }

    let cases = [
        Case {
            code: 23,
            canonical: 0xc0,
            transitive_conflict: ErrorDisposition::TreatAsWithdraw,
        },
        Case {
            code: 24,
            canonical: 0x80,
            transitive_conflict: ErrorDisposition::TreatAsWithdraw,
        },
        Case {
            code: 25,
            canonical: 0xc0,
            transitive_conflict: ErrorDisposition::TreatAsWithdraw,
        },
        Case {
            code: 26,
            canonical: 0x80,
            transitive_conflict: ErrorDisposition::AttributeDiscard,
        },
        Case {
            code: 27,
            canonical: 0xc0,
            transitive_conflict: ErrorDisposition::TreatAsWithdraw,
        },
        Case {
            code: 33,
            canonical: 0x80,
            transitive_conflict: ErrorDisposition::TreatAsWithdraw,
        },
        Case {
            code: 34,
            canonical: 0xc0,
            transitive_conflict: ErrorDisposition::TreatAsWithdraw,
        },
        Case {
            code: 40,
            canonical: 0xc0,
            transitive_conflict: ErrorDisposition::TreatAsWithdraw,
        },
        Case {
            code: 128,
            canonical: 0xc0,
            transitive_conflict: ErrorDisposition::TreatAsWithdraw,
        },
    ];
    for case in cases {
        let value = assigned_value(case.code);
        let canonical = attribute(case.canonical, case.code, &value);
        let decoded = decode_path_attributes_revised(&canonical, true, false, &[]).unwrap();
        assert!(decoded.malformed.is_empty(), "canonical type {}", case.code);
        if case.canonical == 0x80 {
            assert!(
                decoded.attributes.is_empty(),
                "ONT type {} retained",
                case.code
            );
        } else {
            let [PathAttribute::Unknown(raw)] = decoded.attributes.as_slice() else {
                panic!("OT type {} must remain opaque", case.code);
            };
            assert_eq!(raw.data.as_ref(), value);
            let mut emitted = Vec::new();
            encode_path_attributes(&decoded.attributes, &mut emitted, true, false).unwrap();
            assert_eq!(emitted, attribute(0xe0, case.code, &value));
        }

        for (label, flags, expected) in [
            (
                "wrong Optional",
                case.canonical ^ 0x80,
                ErrorDisposition::TreatAsWithdraw,
            ),
            (
                "wrong Transitive",
                case.canonical ^ 0x40,
                case.transitive_conflict,
            ),
            (
                "both wrong",
                case.canonical ^ 0xc0,
                if case.code == 26 {
                    ErrorDisposition::AttributeDiscard
                } else {
                    ErrorDisposition::TreatAsWithdraw
                },
            ),
        ] {
            let bytes = attribute(flags, case.code, &value);
            let revised = decode_path_attributes_revised(&bytes, true, false, &[]).unwrap();
            assert!(
                revised.attributes.is_empty(),
                "type {} {label} retained",
                case.code
            );
            assert_eq!(revised.malformed.len(), 1, "type {} {label}", case.code);
            assert_eq!(
                revised.malformed[0].disposition, expected,
                "type {} {label}",
                case.code
            );

            let legacy = decode_path_attributes(&bytes, true, &[]).unwrap_err();
            assert!(
                matches!(legacy, rustbgpd_wire::DecodeError::UpdateAttributeError { subcode, .. }
                    if subcode == update_subcode::ATTRIBUTE_FLAGS_ERROR),
                "type {} {label}: {legacy:?}",
                case.code
            );
        }
    }
}

#[test]
fn assigned_unsupported_opaque_flags_and_neighboring_fences_stay_orthogonal() {
    for code in [23, 25, 27, 34, 40, 128] {
        let value = assigned_value(code);
        for flags in [0xe0, 0xf0] {
            let input = if flags == 0xf0 {
                extended_attribute(flags, code, &value)
            } else {
                attribute(flags, code, &value)
            };
            let decoded = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
            let [PathAttribute::Unknown(raw)] = decoded.attributes.as_slice() else {
                panic!("type {code} did not remain opaque");
            };
            assert_eq!((raw.flags, raw.data.as_ref()), (flags, &value[..]));
            let mut emitted = Vec::new();
            encode_path_attributes(&decoded.attributes, &mut emitted, true, false).unwrap();
            assert_eq!(emitted, input, "type {code} flag preservation");
        }
    }

    let unassigned = attribute(0xc0, 200, &[0x55]);
    let decoded = decode_path_attributes_revised(&unassigned, true, false, &[]).unwrap();
    assert!(matches!(&decoded.attributes[..], [PathAttribute::Unknown(raw)] if raw.flags == 0xc0));

    let pmsi =
        decode_path_attributes_revised(&attribute(0xc0, 22, &[0; 5]), true, false, &[]).unwrap();
    assert!(matches!(
        pmsi.attributes.as_slice(),
        [PathAttribute::PmsiTunnel(_)]
    ));
    assert!(pmsi.malformed.is_empty());

    let wrong_pmsi =
        decode_path_attributes_revised(&attribute(0x80, 22, &[]), true, false, &[]).unwrap();
    assert_eq!(wrong_pmsi.malformed.len(), 1);
    assert_eq!(
        wrong_pmsi.malformed[0].disposition,
        ErrorDisposition::TreatAsWithdraw
    );

    let traffic_engineering = rustbgpd_wire::RawAttribute {
        flags: 0x80,
        type_code: 24,
        data: bytes::Bytes::from_static(&[0xaa]),
    };
    let mut defensive = Vec::new();
    encode_path_attributes(
        &[PathAttribute::Unknown(traffic_engineering)],
        &mut defensive,
        true,
        false,
    )
    .unwrap();
    assert!(
        defensive.is_empty(),
        "assigned optional non-transitive type 24 must never egress"
    );
}

#[test]
fn community_container_accepts_bounded_opaque_and_known_atom_streams() {
    let mut atoms = Vec::new();
    for kind in [1_u8, 4, 5, 6, 7] {
        atoms.extend(community_tlv(kind, &[0, 0, 0, kind]));
    }
    atoms.extend(community_tlv(2, &[]));
    atoms.extend(community_tlv(
        2,
        &[0, 17, 10, 0, 0, 24, 192, 0, 2, 32, 203, 0, 113, 9],
    ));
    let mut ipv6 = vec![0, 64];
    ipv6.extend([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 1]);
    ipv6.push(65);
    ipv6.extend([0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0]);
    ipv6.push(128);
    ipv6.extend([0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6]);
    atoms.extend(community_tlv(3, &[]));
    atoms.extend(community_tlv(3, &ipv6));
    atoms.extend(community_tlv(8, &[0, 0xff, 0x80]));
    atoms.extend(community_tlv(9, &[]));
    atoms.extend(community_tlv(254, &[0xff]));

    let mut empty_known = Vec::new();
    for kind in 1_u8..=3 {
        empty_known.extend(community_tlv(kind, &[]));
    }
    empty_known.extend(community_tlv(255, &[0, 1]));
    let mut value = community_type_one(&empty_known);
    value.extend(community_container(65000, &[0, 1, 2]));
    value.extend(community_type_one(&community_tlv(1, &atoms)));

    for flags in [0xc0, 0xe0] {
        let input = attribute(flags, 34, &value);
        let strict = decode_path_attributes(&input, true, &[]).unwrap();
        let [PathAttribute::Unknown(raw)] = strict.as_slice() else {
            panic!("type 34 must remain opaque");
        };
        assert_eq!((raw.flags, raw.data.as_ref()), (flags, &value[..]));
        let mut emitted = Vec::new();
        encode_path_attributes(&strict, &mut emitted, true, false).unwrap();
        assert_eq!(emitted[0], flags | 0x20);
        assert_eq!(&emitted[3..], value.as_slice());
    }
}

#[test]
fn community_container_rejects_every_framing_boundary_and_duplicate() {
    let mut invalid = vec![Vec::new()];
    invalid.extend((1_usize..6).map(|length| vec![0; length]));
    invalid.extend([
        vec![0, 2, 0, 0, 0, 0],
        vec![0, 2, 0, 0, 0, 5],
        vec![0, 2, 0, 0, 0, 7],
        [community_container(2, &[]), vec![0]].concat(),
        community_container(1, &[0; 11]),
    ]);
    for subtype in [vec![1], vec![1, 0], vec![1, 0, 1]] {
        invalid.push(community_type_one(&subtype));
    }
    invalid.push(community_type_one(
        &[community_tlv(1, &[]), community_tlv(1, &[])].concat(),
    ));
    for atom in [
        vec![1],
        vec![1, 0],
        vec![1, 0, 1],
        community_tlv(0, &[]),
        community_tlv(255, &[]),
    ] {
        invalid.push(community_type_one(&community_tlv(1, &atom)));
    }
    for kind in [1_u8, 4, 5, 6, 7] {
        for body in [&[][..], &[0; 5][..]] {
            invalid.push(community_type_one(&community_tlv(
                1,
                &community_tlv(kind, body),
            )));
        }
    }
    for (kind, prefixes) in [
        (2_u8, vec![33]),
        (2, vec![32, 192, 0, 2]),
        (2, vec![0, 24, 192, 0]),
        (3, vec![129]),
        (3, vec![128; 16]),
    ] {
        invalid.push(community_type_one(&community_tlv(
            1,
            &community_tlv(kind, &prefixes),
        )));
    }

    for value in invalid {
        let input = attribute(0xc0, 34, &value);
        assert!(matches!(
            decode_path_attributes(&input, true, &[]),
            Err(DecodeError::UpdateAttributeError { subcode, data, .. })
                if subcode == update_subcode::ATTRIBUTE_LENGTH_ERROR && data == input
        ));
        let revised = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
        assert!(revised.attributes.is_empty());
        assert_eq!(revised.malformed.len(), 1);
        assert_eq!(
            revised.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
    }

    let values = [community_container(2, &[]), community_container(3, &[1])];
    for (first, second) in [(&values[0], &values[1]), (&values[1], &values[0])] {
        let bytes = [attribute(0xc0, 34, first), attribute(0xc0, 34, second)].concat();
        assert!(matches!(
            decode_path_attributes(&bytes, true, &[]),
            Err(DecodeError::UpdateAttributeError { subcode, .. })
                if subcode == update_subcode::MALFORMED_ATTRIBUTE_LIST
        ));
        let revised = decode_path_attributes_revised(&bytes, true, false, &[]).unwrap();
        assert_eq!(revised.attributes.len(), 1);
        assert_eq!(revised.malformed.len(), 1);
        assert_eq!(
            revised.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
        assert!(matches!(
            &revised.attributes[0],
            PathAttribute::Unknown(raw) if raw.data.as_ref() == first.as_slice()
        ));
    }
}

#[test]
fn ipv6_specific_extended_community_enforces_length_and_opaque_propagation() {
    for length in [20_usize, 40] {
        let value: Vec<u8> = (0..length)
            .map(|octet| u8::try_from(octet).unwrap())
            .collect();
        for (flags, extended) in [(0xc0, false), (0xe0, false), (0xc0, true), (0xe0, true)] {
            let input = if extended {
                extended_attribute(flags, 25, &value)
            } else {
                attribute(flags, 25, &value)
            };
            let strict = decode_path_attributes(&input, true, &[]).unwrap();
            let revised = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
            assert!(revised.malformed.is_empty());
            let [PathAttribute::Unknown(raw)] = strict.as_slice() else {
                panic!("type 25 must remain opaque");
            };
            assert_eq!(raw.data.as_ref(), value);
            let mut emitted = Vec::new();
            encode_path_attributes(&revised.attributes, &mut emitted, true, false).unwrap();
            let mut expected = input;
            expected[0] |= 0x20;
            assert_eq!(emitted, expected);
        }
    }

    for length in [0_usize, 19, 21, 39] {
        let input = attribute(0xc0, 25, &vec![0; length]);
        assert!(matches!(
            decode_path_attributes(&input, true, &[]),
            Err(DecodeError::UpdateAttributeError { subcode, .. })
                if subcode == update_subcode::ATTRIBUTE_LENGTH_ERROR
        ));
        let revised = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
        assert!(revised.attributes.is_empty());
        assert_eq!(revised.malformed.len(), 1);
        assert_eq!(
            revised.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
    }
}

#[test]
fn assigned_rows_36_through_42_enforce_class_framing_and_disposition() {
    for code in 36_u8..=42 {
        let canonical = if code == 42 { 0x80 } else { 0xc0 };
        let value = assigned_value(code);
        let flag_inputs: &[u8] = if code == 42 { &[0x80] } else { &[0xc0, 0xe0] };
        for (&input_flags, extended) in flag_inputs
            .iter()
            .flat_map(|flags| [(flags, false), (flags, true)])
        {
            let input = if extended {
                extended_attribute(input_flags, code, &value)
            } else {
                attribute(input_flags, code, &value)
            };
            let strict = decode_path_attributes(&input, true, &[]).unwrap();
            let revised = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
            assert!(revised.malformed.is_empty(), "canonical type {code}");
            if code == 42 {
                assert!(strict.is_empty() && revised.attributes.is_empty());
            } else {
                let [PathAttribute::Unknown(raw)] = strict.as_slice() else {
                    panic!("type {code} must remain opaque");
                };
                assert_eq!(raw.data.as_ref(), value);
                assert_eq!(raw.flags, input[0]);
                let mut emitted = Vec::new();
                encode_path_attributes(&revised.attributes, &mut emitted, true, false).unwrap();
                let mut expected = input.clone();
                expected[0] |= 0x20;
                assert_eq!(emitted, expected, "type {code} exact opaque egress");
            }
        }

        for flags in [canonical ^ 0x80, canonical ^ 0x40, canonical ^ 0xc0] {
            let input = attribute(flags, code, &value);
            let error = decode_path_attributes(&input, true, &[]).unwrap_err();
            assert!(
                matches!(error, DecodeError::UpdateAttributeError { subcode, .. }
                if subcode == update_subcode::ATTRIBUTE_FLAGS_ERROR)
            );
            let revised = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
            assert!(revised.attributes.is_empty());
            assert_eq!(revised.malformed.len(), 1);
            assert_eq!(
                revised.malformed[0].disposition,
                ErrorDisposition::TreatAsWithdraw,
                "wrong class type {code} flags {flags:#x}"
            );
        }
    }

    for code in [24_u8, 26, 33, 42] {
        let partial = attribute(0xa0, code, &assigned_value(code));
        assert!(matches!(
            decode_path_attributes(&partial, true, &[]),
            Err(DecodeError::UpdateAttributeError { subcode, .. })
                if subcode == update_subcode::ATTRIBUTE_FLAGS_ERROR
        ));
        let revised = decode_path_attributes_revised(&partial, true, false, &[]).unwrap();
        assert_eq!(revised.malformed.len(), 1, "type {code}");
        assert_eq!(
            revised.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw,
            "type {code}"
        );
    }
    let mut defensive = Vec::new();
    encode_path_attributes(
        &[PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
            flags: 0xe0,
            type_code: 42,
            data: bytes::Bytes::from_static(&[0xaa]),
        })],
        &mut defensive,
        true,
        false,
    )
    .unwrap();
    assert!(defensive.is_empty(), "type 42 must never egress");

    let wrong_class_and_payload = attribute(0x80, 38, &[1]);
    assert!(matches!(
        decode_path_attributes(&wrong_class_and_payload, true, &[]),
        Err(DecodeError::UpdateAttributeError { subcode, .. })
            if subcode == update_subcode::ATTRIBUTE_FLAGS_ERROR
    ));
    let revised =
        decode_path_attributes_revised(&wrong_class_and_payload, true, false, &[]).unwrap();
    assert_eq!(revised.malformed.len(), 1);
    assert_eq!(
        revised.malformed[0].disposition,
        ErrorDisposition::TreatAsWithdraw
    );

    for code in 36_u8..=41 {
        let (value, expected) = assigned_malformed(code).unwrap();
        let input = attribute(0xc0, code, &value);
        assert!(matches!(
            decode_path_attributes(&input, true, &[]),
            Err(DecodeError::UpdateAttributeError { subcode, .. })
                if subcode == update_subcode::ATTRIBUTE_LENGTH_ERROR
        ));
        let revised = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
        assert!(revised.attributes.is_empty());
        assert_eq!(revised.malformed.len(), 1);
        assert_eq!(revised.malformed[0].disposition, expected, "type {code}");
    }

    for (code, value) in [
        (38_u8, vec![1, 0, 0, 0, 1, 2, 4, 192, 0, 2, 1]),
        (38, vec![1, 0, 0, 0, 1, 1, 3, 192, 0, 2]),
        (40, vec![1, 0, 6, 0, 0, 0, 0, 0, 0]),
        (40, vec![3, 0, 7, 0, 0, 0, 0, 0, 0, 0]),
    ] {
        let revised =
            decode_path_attributes_revised(&attribute(0xc0, code, &value), true, false, &[])
                .unwrap();
        assert!(revised.attributes.is_empty());
        assert_eq!(revised.malformed.len(), 1);
        assert_eq!(
            revised.malformed[0].disposition,
            ErrorDisposition::AttributeDiscard
        );
    }

    let unknown_mode_without_source = [99, 0, 0, 0, 1, 2, 4, 0, 0, 0, 0];
    let revised = decode_path_attributes_revised(
        &attribute(0xc0, 38, &unknown_mode_without_source),
        true,
        false,
        &[],
    )
    .unwrap();
    assert!(revised.attributes.is_empty());
    assert_eq!(revised.malformed.len(), 1);
    assert_eq!(
        revised.malformed[0].disposition,
        ErrorDisposition::AttributeDiscard
    );
    let unknown_mode_with_source = [99, 0, 0, 0, 1, 1, 4, 192, 0, 2, 1];
    let decoded = decode_path_attributes_revised(
        &attribute(0xc0, 38, &unknown_mode_with_source),
        true,
        false,
        &[],
    )
    .unwrap();
    assert!(decoded.malformed.is_empty());
    assert!(
        matches!(decoded.attributes.as_slice(), [PathAttribute::Unknown(raw)] if raw.type_code == 38)
    );

    let semantically_invalid_bier = vec![
        0, 1, 0, 1, 0xaa, // known BIER TLV without its fixed prefix
        0, 4, 0, 1, 0xbb, // known nexthop with a semantic-invalid length
        0, 99, 0, 1, 0xcc, // unknown TLV preserved
    ];
    let input = attribute(0xc0, 41, &semantically_invalid_bier);
    let decoded = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
    assert!(decoded.malformed.is_empty());
    let mut emitted = Vec::new();
    encode_path_attributes(&decoded.attributes, &mut emitted, true, false).unwrap();
    let mut expected = input;
    expected[0] |= 0x20;
    assert_eq!(emitted, expected);
    let empty = attribute(0xc0, 41, &[]);
    assert!(matches!(
        decode_path_attributes(&empty, true, &[]),
        Err(DecodeError::UpdateAttributeError { subcode, .. })
            if subcode == update_subcode::ATTRIBUTE_LENGTH_ERROR
    ));
    let empty = decode_path_attributes_revised(&empty, true, false, &[]).unwrap();
    assert!(empty.attributes.is_empty());
    assert_eq!(empty.malformed.len(), 1);
    assert_eq!(
        empty.malformed[0].disposition,
        ErrorDisposition::AttributeDiscard
    );

    let unknown_value = [0, 99, 0, 0];
    let unknown_input = attribute(0xc0, 41, &unknown_value);
    let unknown = decode_path_attributes_revised(&unknown_input, true, false, &[]).unwrap();
    assert!(unknown.malformed.is_empty());
    assert!(
        matches!(unknown.attributes.as_slice(), [PathAttribute::Unknown(raw)] if raw.data.as_ref() == unknown_value)
    );
    let mut emitted = Vec::new();
    encode_path_attributes(&unknown.attributes, &mut emitted, true, false).unwrap();
    let mut expected = unknown_input;
    expected[0] |= 0x20;
    assert_eq!(emitted, expected);
}

#[test]
fn assigned_framing_documentation_matches_executable_cases() {
    let framing = rows(
        section(
            "<!-- assigned-framing:start -->",
            "<!-- assigned-framing:end -->",
        ),
        4,
    );
    let codes = [23_u8, 36, 37, 38, 39, 40, 41, 42, 128];
    assert_eq!(framing.len(), codes.len());
    for (row, code) in framing.iter().zip(codes) {
        assert_eq!(row[0], code.to_string());
        let canonical = if code == 42 { 0x80 } else { 0xc0 };
        assert!(row[1].contains(&format!("flags `{canonical:#04x}`")));
        assert_eq!(
            row[2],
            assigned_payload_contract(code),
            "payload contract drift for row {code}"
        );
        let expected = if matches!(code, 38..=41) {
            "attribute-discard"
        } else {
            "treat-as-withdraw"
        };
        assert!(row[3].contains(expected), "row {code}");

        let decoded = decode_path_attributes_revised(
            &attribute(canonical, code, &assigned_value(code)),
            true,
            false,
            &[],
        )
        .unwrap();
        assert!(decoded.malformed.is_empty(), "documented valid row {code}");

        if let Some((malformed, expected_disposition)) = assigned_malformed(code) {
            let decoded = decode_path_attributes_revised(
                &attribute(canonical, code, &malformed),
                true,
                false,
                &[],
            )
            .unwrap();
            assert_eq!(decoded.malformed.len(), 1);
            assert_eq!(decoded.malformed[0].disposition, expected_disposition);
        } else {
            let decoded = decode_path_attributes_revised(
                &attribute(0xc0, code, &assigned_value(code)),
                true,
                false,
                &[],
            )
            .unwrap();
            assert_eq!(decoded.malformed.len(), 1);
            assert_eq!(
                decoded.malformed[0].disposition,
                ErrorDisposition::TreatAsWithdraw
            );
        }
    }
}

#[test]
fn deeply_nested_bier_framing_is_bounded_and_non_recursive() {
    let mut nested = vec![0, 4, 0, 4, 192, 0, 2, 1];
    for _ in 0..2_000 {
        let mut container = vec![0, 2];
        container.extend_from_slice(&u16::try_from(4 + nested.len()).unwrap().to_be_bytes());
        container.extend_from_slice(&[0; 4]);
        container.extend_from_slice(&nested);
        nested = container;
    }
    let mut value = vec![0, 1];
    value.extend_from_slice(&u16::try_from(4 + nested.len()).unwrap().to_be_bytes());
    value.extend_from_slice(&[0; 4]);
    value.extend_from_slice(&nested);
    let input = extended_attribute(0xc0, 41, &value);
    let decoded = decode_path_attributes_revised(&input, true, false, &[]).unwrap();
    assert!(decoded.malformed.is_empty());
    assert!(
        matches!(decoded.attributes.as_slice(), [PathAttribute::Unknown(raw)] if raw.type_code == 41)
    );
}
