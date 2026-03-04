use std::net::Ipv4Addr;

use bytes::Bytes;
use proptest::prelude::*;

use rustbgpd_wire::{
    Afi, Capability, DecodeError, NotificationMessage, OpenMessage, Safi,
    notification::NotificationCode,
};

use rustbgpd_fsm::{Event, PeerConfig, Session, SessionState};

fn test_config() -> PeerConfig {
    PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
    }
}

/// Generate an arbitrary Event.
fn arb_event() -> impl Strategy<Value = Event> {
    prop_oneof![
        Just(Event::ManualStart),
        Just(Event::ManualStop { reason: None }),
        Just(Event::ConnectRetryTimerExpires),
        Just(Event::HoldTimerExpires),
        Just(Event::KeepaliveTimerExpires),
        Just(Event::TcpConnectionConfirmed),
        Just(Event::TcpConnectionAcknowledged),
        Just(Event::TcpConnectionFails),
        Just(Event::KeepaliveReceived),
        // OPEN with varying parameters
        (1u16..=65535u16, 0u16..=300u16, 1u32..=u32::MAX).prop_map(|(my_as, ht, id)| {
            Event::OpenReceived(OpenMessage {
                version: 4,
                my_as,
                hold_time: ht,
                bgp_identifier: Ipv4Addr::from(id),
                capabilities: vec![Capability::FourOctetAs {
                    asn: u32::from(my_as),
                }],
            })
        }),
        // NOTIFICATION
        Just(Event::NotificationReceived(NotificationMessage::new(
            NotificationCode::Cease,
            0,
            Bytes::new(),
        ))),
        // UPDATE
        Just(Event::UpdateReceived),
        // UPDATE validation error
        Just(Event::UpdateValidationError(NotificationMessage::new(
            NotificationCode::UpdateMessage,
            3,
            Bytes::new(),
        ))),
        // DecodeError
        Just(Event::DecodeError(DecodeError::InvalidMarker)),
    ]
}

// The FSM must never panic, regardless of event sequence.
proptest! {
    #[test]
    fn handle_event_never_panics(events in prop::collection::vec(arb_event(), 1..50)) {
        let mut session = Session::new(test_config());
        for event in events {
            let _actions = session.handle_event(event);
        }
        // If we got here without panicking, the test passes.
    }

    #[test]
    fn state_is_always_valid(events in prop::collection::vec(arb_event(), 1..50)) {
        let mut session = Session::new(test_config());
        for event in events {
            session.handle_event(event);
            // State should always be one of the 6 valid states
            let state = session.state();
            assert!(matches!(
                state,
                SessionState::Idle
                    | SessionState::Connect
                    | SessionState::Active
                    | SessionState::OpenSent
                    | SessionState::OpenConfirm
                    | SessionState::Established
            ));
        }
    }
}
