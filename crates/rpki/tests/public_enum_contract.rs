//! Downstream construction and matching contracts for the public RPKI enums.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

use rustbgpd_rpki::VrpUpdate;
use rustbgpd_rpki::aspa::ProviderAuth;
use rustbgpd_rpki::rtr_client::RtrError;
use rustbgpd_rpki::rtr_codec::{RtrDecodeError, RtrEncodeError, RtrPdu};

#[test]
fn public_enum_construction_and_closed_application_matches() {
    let pdu = RtrPdu::SerialQuery {
        session_id: 7,
        serial: 42,
    };
    match &pdu {
        RtrPdu::SerialQuery { session_id, serial } => {
            assert_eq!((*session_id, *serial), (7, 42));
        }
        other => panic!("unexpected PDU: {other:?}"),
    }
    let mut bytes = Vec::new();
    pdu.encode(&mut bytes).unwrap();
    assert_eq!(RtrPdu::decode(&bytes).unwrap(), (pdu, bytes.len()));
    let mut reset_bytes = Vec::new();
    RtrPdu::ResetQuery.encode(&mut reset_bytes).unwrap();
    assert_eq!(
        RtrPdu::decode(&reset_bytes).unwrap(),
        (RtrPdu::ResetQuery, reset_bytes.len())
    );

    match RtrDecodeError::InvalidVersion(3) {
        RtrDecodeError::InvalidVersion(version) => assert_eq!(version, 3),
        other => panic!("unexpected decode error: {other:?}"),
    }
    match (RtrEncodeError::LengthOverflow {
        field: "error text",
        len: usize::MAX,
    }) {
        RtrEncodeError::LengthOverflow { field, len } => {
            assert_eq!(field, "error text");
            assert_eq!(len, usize::MAX);
        }
        other => panic!("unexpected encode error: {other:?}"),
    }
    match (RtrError::VersionMismatch {
        expected: 2,
        got: 1,
    }) {
        RtrError::VersionMismatch { expected, got } => {
            assert_eq!((expected, got), (2, 1));
        }
        other => panic!("unexpected client error: {other:?}"),
    }

    for (auth, expected) in [
        (ProviderAuth::ProviderPlus, "provider"),
        (ProviderAuth::NotProviderPlus, "non-provider"),
        (ProviderAuth::NoAttestation, "no attestation"),
    ] {
        let actual = match auth {
            ProviderAuth::ProviderPlus => "provider",
            ProviderAuth::NotProviderPlus => "non-provider",
            ProviderAuth::NoAttestation => "no attestation",
        };
        assert_eq!(actual, expected);
    }

    let server = "127.0.0.1:3323".parse().unwrap();
    let update = VrpUpdate::ServerDown { server };
    let observed_server = match update {
        VrpUpdate::FullTable { server, .. }
        | VrpUpdate::IncrementalUpdate { server, .. }
        | VrpUpdate::ServerDown { server } => server,
    };
    assert_eq!(observed_server, server);
}
