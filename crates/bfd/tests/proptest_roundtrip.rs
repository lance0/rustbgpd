//! Property test: any control packet this crate would emit survives an
//! encode → decode round-trip unchanged.

use proptest::prelude::*;
use rustbgpd_bfd::{ControlPacket, Diagnostic, SessionState};

fn arb_state() -> impl Strategy<Value = SessionState> {
    prop_oneof![
        Just(SessionState::AdminDown),
        Just(SessionState::Down),
        Just(SessionState::Init),
        Just(SessionState::Up),
    ]
}

fn arb_diag() -> impl Strategy<Value = Diagnostic> {
    (0u8..=31).prop_map(Diagnostic::from_wire)
}

proptest! {
    #[test]
    fn encode_decode_roundtrip(
        diagnostic in arb_diag(),
        state in arb_state(),
        poll in any::<bool>(),
        final_bit in any::<bool>(),
        control_plane_independent in any::<bool>(),
        demand in any::<bool>(),
        // Valid emitted packets: never multipoint, never auth, non-zero
        // detect-mult and my-discriminator (the decode "MUST discard" rules).
        detect_mult in 1u8..=255,
        my_discriminator in 1u32..=u32::MAX,
        your_discriminator in any::<u32>(),
        desired_min_tx_interval in any::<u32>(),
        required_min_rx_interval in any::<u32>(),
        required_min_echo_rx_interval in any::<u32>(),
    ) {
        let pkt = ControlPacket {
            diagnostic,
            state,
            poll,
            final_bit,
            control_plane_independent,
            auth_present: false,
            demand,
            multipoint: false,
            detect_mult,
            my_discriminator,
            your_discriminator,
            desired_min_tx_interval,
            required_min_rx_interval,
            required_min_echo_rx_interval,
        };
        let decoded = ControlPacket::decode(&pkt.encode()).expect("valid packet decodes");
        prop_assert_eq!(decoded, pkt);
    }

    /// Decoding never panics, whatever the input bytes.
    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let _ = ControlPacket::decode(&bytes);
    }
}
