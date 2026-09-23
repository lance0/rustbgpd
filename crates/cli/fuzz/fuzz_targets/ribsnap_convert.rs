#![no_main]
//! Drive the `rbgp diff snapshot from-mrt` and `from-bmp` conversions on
//! arbitrary capture bytes. Both adapters promise to refuse malformed input
//! (exit 2, nothing on stdout): each conversion must return, never panic,
//! and a produced snapshot must end in a trailer that counts its routes.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use libfuzzer_sys::fuzz_target;
use rustbgpctl::{ribsnap, ribsnap_bmp};

fn assert_counted(snapshot: &str) {
    let lines: Vec<&str> = snapshot.lines().collect();
    let trailer: serde_json::Value =
        serde_json::from_str(lines.last().expect("snapshot has lines")).expect("trailer is JSON");
    assert_eq!(
        trailer["record"], "trailer",
        "snapshot does not end in a trailer"
    );
    assert_eq!(
        trailer["routes"],
        lines.len() - 2,
        "trailer count differs from route records"
    );
}

fuzz_target!(|data: &[u8]| {
    // Bound campaign work to one extended-message-sized capture, the same
    // ceiling as the MRT reader campaign.
    if data.len() > 65_536 {
        return;
    }
    let file = Path::new("fuzz-input");

    let mrt = ribsnap::FromMrtOpts {
        file,
        view: "adj-rib-out-capture",
        peer: "192.0.2.1",
        peer_asn: 64_500,
        source: None,
        generation: 0,
    };
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    if let Ok(snapshot) = ribsnap::convert(&mrt, peer, data) {
        assert_counted(&snapshot);
    }

    let bmp = ribsnap_bmp::FromBmpOpts {
        file,
        peers: &[],
        source: None,
        generation: 0,
    };
    if let Ok((snapshot, _notes)) = ribsnap_bmp::convert(&bmp, &BTreeSet::new(), data) {
        assert_counted(&snapshot);
    }
});
