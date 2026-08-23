use rustbgpd_wire::attribute::{decode_path_attributes_revised, encode_path_attributes};
use rustbgpd_wire::validate::validate_update_attributes;
use rustbgpd_wire::{ErrorDisposition, PathAttribute};

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

    let mut coverage = [0_u8; 256];
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
