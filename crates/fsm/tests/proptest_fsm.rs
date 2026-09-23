use std::net::Ipv4Addr;

use bytes::Bytes;
use proptest::prelude::*;

use rustbgpd_wire::{
    Afi, BgpRole, Capability, DecodeError, NotificationMessage, OpenMessage, Safi,
    notification::NotificationCode,
};

use rustbgpd_fsm::negotiation::validate_open;
use rustbgpd_fsm::{Action, Event, PeerConfig, Session, SessionState};

fn test_config() -> PeerConfig {
    let mut config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    config.connect_retry_secs = 30;
    config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    config.gr_restart_time = 120;
    config
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

/// Local configurations that exercise distinct negotiation branches: plain
/// IPv4 eBGP, multi-family with every optional capability, a strict-role
/// IPv6-only route server, and iBGP with VPN/EVPN/BGP-LS families.
fn negotiation_configs() -> Vec<PeerConfig> {
    let plain = test_config();

    let mut rich = test_config();
    rich.families = vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv6, Safi::Unicast),
        (Afi::Ipv4, Safi::LabeledUnicast),
        (Afi::Ipv4, Safi::FlowSpec),
    ];
    rich.min_hold_time = Some(9);
    rich.graceful_restart = true;
    rich.llgr_stale_time = 3600;
    rich.add_path_receive = true;
    rich.add_path_send = true;
    rich.add_path_send_max = 4;
    rich.paths_limit_receive_max = 8;
    rich.prefix_orf_receive = true;
    rich.local_role = Some(BgpRole::Provider);

    let mut v6_rs = test_config();
    v6_rs.families = vec![(Afi::Ipv6, Safi::Unicast)];
    v6_rs.required_families = vec![(Afi::Ipv6, Safi::Unicast)];
    v6_rs.disable_ipv4_unicast = true;
    v6_rs.local_role = Some(BgpRole::RouteServer);
    v6_rs.strict_role = true;

    let mut ibgp = PeerConfig::new(65002, 65002, Ipv4Addr::new(10, 0, 0, 1));
    ibgp.families = vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::L2Vpn, Safi::Evpn),
        (Afi::BgpLs, Safi::BgpLs),
        (Afi::Ipv4, Safi::RtConstrain),
    ];
    ibgp.required_families = vec![(Afi::L2Vpn, Safi::Evpn)];
    ibgp.graceful_restart = true;
    ibgp.add_path_receive = true;

    vec![plain, rich, v6_rs, ibgp]
}

/// One capability TLV. AFI/SAFI, ASN, and mode fields are biased toward
/// values the configs above negotiate so decoded OPENs get past peer-ASN
/// validation and into family, Add-Path, GR, and Role negotiation.
fn arb_capability_tlv() -> impl Strategy<Value = Vec<u8>> {
    fn tlv(code: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![code, u8::try_from(body.len()).unwrap_or(u8::MAX)];
        out.extend_from_slice(body);
        out
    }
    let family = (
        prop_oneof![Just(1u16), Just(2), Just(25), Just(16_388), any::<u16>()],
        prop_oneof![
            Just(1u8),
            Just(4),
            Just(70),
            Just(71),
            Just(128),
            Just(132),
            Just(133),
            any::<u8>()
        ],
    )
        .prop_map(|(afi, safi)| {
            let [hi, lo] = afi.to_be_bytes();
            [hi, lo, safi]
        })
        .boxed();
    let entries = |extra: BoxedStrategy<Vec<u8>>| {
        prop::collection::vec((family.clone(), extra), 0..4).prop_map(|rows| {
            rows.into_iter()
                .flat_map(|([hi, lo, safi], extra)| {
                    let mut row = vec![hi, lo, safi];
                    row.extend(extra);
                    row
                })
                .collect::<Vec<u8>>()
        })
    };
    prop_oneof![
        family
            .clone()
            .prop_map(|[hi, lo, safi]| tlv(1, &[hi, lo, 0, safi])),
        prop_oneof![Just(65_002u32), Just(65_001), any::<u32>()]
            .prop_map(|asn| tlv(65, &asn.to_be_bytes())),
        entries((0u8..=4).prop_map(|mode| vec![mode]).boxed()).prop_map(|b| tlv(69, &b)),
        (
            any::<[u8; 2]>(),
            entries(any::<u8>().prop_map(|f| vec![f]).boxed())
        )
            .prop_map(|(head, b)| tlv(64, &[head.as_slice(), &b].concat())),
        entries(any::<[u8; 4]>().prop_map(|f| f.to_vec()).boxed()).prop_map(|b| tlv(71, &b)),
        (0u8..=6).prop_map(|role| tlv(9, &[role])),
        prop::collection::vec(
            (
                family.clone(),
                prop_oneof![Just(1u16), Just(2), any::<u16>()]
            ),
            0..3
        )
        .prop_map(|rows| {
            let body: Vec<u8> = rows
                .into_iter()
                .flat_map(|([hi, lo, safi], nh)| {
                    let [nh_hi, nh_lo] = nh.to_be_bytes();
                    [hi, lo, 0, safi, nh_hi, nh_lo]
                })
                .collect();
            tlv(5, &body)
        }),
        entries(any::<[u8; 2]>().prop_map(|l| l.to_vec()).boxed()).prop_map(|b| tlv(76, &b)),
        (
            family.clone(),
            prop::collection::vec((any::<u8>(), 0u8..=4), 0..3)
        )
            .prop_map(|([hi, lo, safi], orfs)| {
                let mut body = vec![hi, lo, 0, safi, u8::try_from(orfs.len()).unwrap_or(0)];
                body.extend(orfs.into_iter().flat_map(|(kind, mode)| [kind, mode]));
                tlv(3, &body)
            }),
        prop::sample::select(vec![2u8, 6, 70]).prop_map(|code| tlv(code, &[])),
        (any::<u8>(), prop::collection::vec(any::<u8>(), 0..12))
            .prop_map(|(code, body)| tlv(code, &body)),
    ]
}

/// An OPEN body (header already consumed, as the session path decodes it):
/// mostly structured capability parameters, some unstructured bytes.
fn arb_open_body() -> impl Strategy<Value = Vec<u8>> {
    let param = prop_oneof![
        4 => prop::collection::vec(arb_capability_tlv(), 0..6).prop_map(|caps| {
            let caps = caps.concat();
            let mut param = vec![2, u8::try_from(caps.len()).unwrap_or(u8::MAX)];
            param.extend(caps);
            param
        }),
        1 => (any::<u8>(), prop::collection::vec(any::<u8>(), 0..8)).prop_map(|(kind, body)| {
            let mut param = vec![kind, u8::try_from(body.len()).unwrap_or(u8::MAX)];
            param.extend(body);
            param
        }),
    ];
    // A coherent peer: expected ASN, a subset of the configured families,
    // optional Role and Add-Path over those families, and some arbitrary
    // extra capabilities.
    let coherent = (
        prop::sample::subsequence(
            vec![
                (1u16, 1u8),
                (2, 1),
                (1, 4),
                (1, 133),
                (1, 128),
                (25, 70),
                (16_388, 71),
                (1, 132),
            ],
            0..=8,
        ),
        prop::option::of(0u8..=5),
        prop::option::of(1u8..=3),
        prop::collection::vec(arb_capability_tlv(), 0..4),
        prop_oneof![Just(0u16), Just(90), 3u16..20],
        1u32..,
    )
        .prop_map(|(families, role, add_path, extra, hold, id)| {
            let mut caps: Vec<u8> = [65, 4].into_iter().chain(65_002u32.to_be_bytes()).collect();
            for &(afi, safi) in &families {
                let [hi, lo] = afi.to_be_bytes();
                caps.extend([1, 4, hi, lo, 0, safi]);
            }
            if let Some(mode) = add_path {
                caps.extend([69, u8::try_from(families.len() * 4).unwrap_or(u8::MAX)]);
                for &(afi, safi) in &families {
                    let [hi, lo] = afi.to_be_bytes();
                    caps.extend([hi, lo, safi, mode]);
                }
            }
            if let Some(role) = role {
                caps.extend([9, 1, role]);
            }
            caps.extend(extra.concat());
            let mut body = vec![4];
            body.extend(65_002u16.to_be_bytes());
            body.extend(hold.to_be_bytes());
            body.extend(id.to_be_bytes());
            body.push(u8::try_from(caps.len() + 2).unwrap_or(u8::MAX));
            body.extend([2, u8::try_from(caps.len()).unwrap_or(u8::MAX)]);
            body.extend(caps);
            body
        });
    prop_oneof![
        1 => prop::collection::vec(any::<u8>(), 0..64),
        3 => coherent,
        4 => (
            prop_oneof![Just(65_002u16), Just(23_456), Just(65_001), any::<u16>()],
            prop_oneof![Just(0u16), Just(90), 0u16..10, any::<u16>()],
            prop_oneof![Just(0u32), any::<u32>()],
            prop::collection::vec(param, 0..4),
        )
            .prop_map(|(my_as, hold, id, params)| {
                let params = params.concat();
                let mut body = vec![4];
                body.extend(my_as.to_be_bytes());
                body.extend(hold.to_be_bytes());
                body.extend(id.to_be_bytes());
                body.push(u8::try_from(params.len()).unwrap_or(u8::MAX));
                body.extend(params);
                body
            }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    // Every decodable peer OPEN, under every local config, either
    // negotiates a session or yields exactly one NOTIFICATION; the session
    // path agrees with a direct `validate_open` call.
    #[test]
    fn decoded_open_negotiates_or_notifies(body in arb_open_body()) {
        let Ok(open) = OpenMessage::decode(&mut Bytes::from(body.clone()), body.len()) else {
            return Ok(());
        };
        for config in negotiation_configs() {
            let direct = validate_open(&open, &config);
            let mut session = Session::new(config.clone());
            session.handle_event(Event::ManualStart);
            session.handle_event(Event::TcpConnectionConfirmed);
            prop_assert_eq!(session.state(), SessionState::OpenSent);
            let actions = session.handle_event(Event::OpenReceived(open.clone()));
            let notifications: Vec<_> = actions
                .iter()
                .filter_map(|action| match action {
                    Action::SendNotification(n) => Some(n),
                    _ => None,
                })
                .collect();
            match direct {
                Ok(negotiated) => {
                    prop_assert_eq!(session.state(), SessionState::OpenConfirm);
                    prop_assert!(notifications.is_empty());
                    prop_assert!(actions.iter().any(|a| matches!(a, Action::SendKeepalive)));
                    prop_assert_eq!(session.negotiated(), Some(&negotiated));
                    for family in &negotiated.negotiated_families {
                        prop_assert!(
                            config.families.contains(family),
                            "negotiated {:?} outside configured {:?}",
                            family,
                            config.families
                        );
                    }
                }
                Err(notification) => {
                    prop_assert_eq!(session.state(), SessionState::Idle);
                    prop_assert_eq!(notifications, vec![&notification]);
                    prop_assert!(session.negotiated().is_none());
                }
            }
        }
    }
}
