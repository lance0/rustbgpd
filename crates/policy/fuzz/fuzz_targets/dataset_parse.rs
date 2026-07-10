#![no_main]
//! Fuzz the external-dataset file parser (LAN-305): the operator-fed
//! snapshot format (one entry per line, `#` comments) parsed as each
//! of the three dataset kinds. Reuses the rpol literal parsers, so
//! this also stresses those on line-shaped input. Must return
//! `Err(String)`, never panic, abort, or hang.

use libfuzzer_sys::fuzz_target;
use rustbgpd_policy::datasets::DatasetKind;
use rustbgpd_policy::rpol::parse_dataset_text;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for kind in [DatasetKind::Prefix, DatasetKind::Asn, DatasetKind::Community] {
        let _ = parse_dataset_text(text, kind);
    }
});
