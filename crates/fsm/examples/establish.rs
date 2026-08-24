use std::net::Ipv4Addr;

use rustbgpd_fsm::{Event, PeerConfig, Session, SessionState};
use rustbgpd_wire::{Afi, Capability, OpenMessage, Safi};

fn drive(session: &mut Session, event: Event) {
    let event_name = event.name();
    let actions = session.handle_event(event);

    println!("{event_name} -> {:?}", session.state());
    for action in actions {
        println!("  {action:?}");
    }
}

fn main() {
    let mut config = PeerConfig::new(65_001, 65_002, Ipv4Addr::new(10, 0, 0, 1));
    config.hold_time = 90;
    config.families = vec![(Afi::Ipv4, Safi::Unicast)];

    let peer_open = OpenMessage {
        version: 4,
        my_as: 65_002,
        hold_time: 180,
        bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: 65_002 },
        ],
    };

    let mut session = Session::new(config);
    println!("initial state: {:?}", session.state());
    assert_eq!(session.state(), SessionState::Idle);

    drive(&mut session, Event::ManualStart);
    assert_eq!(session.state(), SessionState::Connect);

    drive(&mut session, Event::TcpConnectionConfirmed);
    assert_eq!(session.state(), SessionState::OpenSent);

    drive(&mut session, Event::OpenReceived(peer_open));
    assert_eq!(session.state(), SessionState::OpenConfirm);

    drive(&mut session, Event::KeepaliveReceived);
    assert_eq!(session.state(), SessionState::Established);

    let negotiated = session
        .negotiated()
        .expect("an established session has negotiated parameters");
    assert_eq!(negotiated.peer_asn, 65_002);
    assert_eq!(negotiated.peer_router_id, Ipv4Addr::new(10, 0, 0, 2));
    assert_eq!(negotiated.hold_time, 90);
    assert_eq!(
        negotiated.negotiated_families,
        vec![(Afi::Ipv4, Safi::Unicast)]
    );

    println!("negotiated: {negotiated:?}");
}
