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

    let prefix_sid = attribute(0xc0, 40, &[1, 0, 0]);
    let decoded = decode_path_attributes_revised(&prefix_sid, true, false, &[]).unwrap();
    assert!(
        matches!(&decoded.attributes[..], [PathAttribute::Unknown(raw)] if raw.type_code == 40)
    );
    let mut emitted = Vec::new();
    encode_path_attributes(&decoded.attributes, &mut emitted, true, false).unwrap();
    assert_eq!(emitted, attribute(0xe0, 40, &[1, 0, 0]));

    let unknown =
        decode_path_attributes_revised(&attribute(0x40, 200, &[0xaa]), true, false, &[]).unwrap();
    let error = validate_update_attributes(&unknown.attributes, false, false, true).unwrap_err();
    assert_eq!(error.disposition, ErrorDisposition::TreatAsWithdraw);
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
    let value = [0xde, 0xad, 0xbe, 0xef];

    for case in cases {
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
    let value = [0xaa, 0xbb, 0xcc];
    for code in [23, 27, 40, 128] {
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
}
