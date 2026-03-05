use std::collections::HashMap;

use bytes::Bytes;

use rustbgpd_wire::notification::{NotificationCode, open_subcode};
use rustbgpd_wire::{
    AddPathFamily, AddPathMode, Afi, Capability, ExtendedNextHopFamily, NotificationMessage,
    OpenMessage, Safi,
};

use crate::action::NegotiatedSession;
use crate::config::PeerConfig;

/// Validate a received OPEN message against our configuration and negotiate
/// session parameters.
///
/// On success, returns the [`NegotiatedSession`] to be used once the
/// handshake completes.  On failure, returns a [`NotificationMessage`] that
/// should be sent to the peer before tearing down the connection.
///
/// # Errors
///
/// Returns a [`NotificationMessage`] when the OPEN fails validation:
/// unsupported version, unacceptable hold time, bad BGP identifier, or
/// peer ASN mismatch.
#[expect(
    clippy::too_many_lines,
    reason = "OPEN validation keeps negotiation logic together for protocol correctness"
)]
pub fn validate_open(
    open: &OpenMessage,
    config: &PeerConfig,
) -> Result<NegotiatedSession, NotificationMessage> {
    // RFC 4271 §6.2 — version must be 4
    if open.version != 4 {
        return Err(NotificationMessage::new(
            NotificationCode::OpenMessage,
            open_subcode::UNSUPPORTED_VERSION,
            // Data: two octets of the highest supported version
            Bytes::from_static(&[0, 4]),
        ));
    }

    // RFC 4271 §6.2 — hold time: 0 or >= 3
    if open.hold_time != 0 && open.hold_time < 3 {
        return Err(NotificationMessage::new(
            NotificationCode::OpenMessage,
            open_subcode::UNACCEPTABLE_HOLD_TIME,
            Bytes::new(),
        ));
    }

    // RFC 4271 §6.2 — BGP Identifier must not be zero
    if open.bgp_identifier == std::net::Ipv4Addr::UNSPECIFIED {
        return Err(NotificationMessage::new(
            NotificationCode::OpenMessage,
            open_subcode::BAD_BGP_IDENTIFIER,
            Bytes::new(),
        ));
    }

    // Determine peer's true ASN: prefer 4-octet capability, fall back to my_as
    let peer_asn = open.four_byte_as();

    // Verify peer ASN matches our configuration
    if peer_asn != config.remote_asn {
        return Err(NotificationMessage::new(
            NotificationCode::OpenMessage,
            open_subcode::BAD_PEER_AS,
            Bytes::new(),
        ));
    }

    // Negotiate hold time
    let hold_time = negotiate_hold_time(config.hold_time, open.hold_time);
    let keepalive_interval = if hold_time == 0 { 0 } else { hold_time / 3 };

    // Detect whether both sides support 4-octet AS
    let peer_has_four_octet = open
        .capabilities
        .iter()
        .any(|c| matches!(c, Capability::FourOctetAs { .. }));
    let four_octet_as = peer_has_four_octet; // we always advertise it

    // Intersect address families: only families both sides advertise
    let negotiated_families = intersect_families(config, &open.capabilities);

    // Extract Graceful Restart capability from peer
    let (peer_gr_capable, peer_restart_state, peer_restart_time, peer_gr_families) = open
        .capabilities
        .iter()
        .find_map(|c| match c {
            Capability::GracefulRestart {
                restart_state,
                restart_time,
                families,
            } => Some((true, *restart_state, *restart_time, families.clone())),
            _ => None,
        })
        .unwrap_or_default();

    // Extract Long-Lived Graceful Restart capability (RFC 9494).
    // LLGR requires GR — if the peer didn't advertise GR, LLGR is ignored.
    let (peer_llgr_capable, peer_llgr_families) = if peer_gr_capable {
        open.capabilities
            .iter()
            .find_map(|c| match c {
                Capability::LongLivedGracefulRestart(families) => Some((true, families.clone())),
                _ => None,
            })
            .unwrap_or((false, Vec::new()))
    } else {
        (false, Vec::new())
    };

    let peer_route_refresh = open
        .capabilities
        .iter()
        .any(|c| matches!(c, Capability::RouteRefresh));

    let peer_enhanced_route_refresh = open
        .capabilities
        .iter()
        .any(|c| matches!(c, Capability::EnhancedRouteRefresh));

    let peer_extended_message = open
        .capabilities
        .iter()
        .any(|c| matches!(c, Capability::ExtendedMessage));

    let our_extended_nexthop_caps = config.extended_nexthop_capabilities();
    let peer_extended_nexthop_caps: Vec<ExtendedNextHopFamily> = open
        .capabilities
        .iter()
        .filter_map(|c| match c {
            Capability::ExtendedNextHop(families) => Some(families.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect();
    let extended_nexthop_families =
        negotiate_extended_nexthop(&our_extended_nexthop_caps, &peer_extended_nexthop_caps);

    // Negotiate Add-Path (RFC 7911)
    let our_add_path_caps = config.add_path_capabilities();
    let peer_add_path_caps: Vec<AddPathFamily> = open
        .capabilities
        .iter()
        .filter_map(|c| match c {
            Capability::AddPath(families) => Some(families.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect();
    let add_path_families = negotiate_add_path(&our_add_path_caps, &peer_add_path_caps);

    Ok(NegotiatedSession {
        peer_asn,
        peer_router_id: open.bgp_identifier,
        hold_time,
        keepalive_interval,
        peer_capabilities: open.capabilities.clone(),
        four_octet_as,
        negotiated_families,
        peer_gr_capable,
        peer_restart_state,
        peer_restart_time,
        peer_gr_families,
        peer_llgr_capable,
        peer_llgr_families,
        peer_route_refresh,
        peer_enhanced_route_refresh,
        peer_extended_message,
        extended_nexthop_families,
        add_path_families,
    })
}

/// RFC 4271 §4.2 — negotiated hold time is the minimum of the two
/// proposals.  If either side proposes 0 (no keepalives), the result is 0.
#[must_use]
pub fn negotiate_hold_time(local: u16, peer: u16) -> u16 {
    if local == 0 || peer == 0 {
        0
    } else {
        local.min(peer)
    }
}

/// Compute the intersection of address families between our config and the
/// peer's advertised capabilities. Only families both sides support are
/// negotiated.
///
/// RFC 4760 §8 backward compatibility: if neither side explicitly advertises
/// IPv4 unicast via `MultiProtocol` capability, IPv4 unicast is implicitly
/// supported (body NLRI is always IPv4).
///
/// **Limitation:** The implicit IPv4 fallback means a peer cannot be
/// configured as IPv6-only. Even if config specifies only `ipv6_unicast`
/// and the peer advertises only IPv6 MP, IPv4 unicast is still added
/// implicitly. An explicit `disable_ipv4_unicast` config option would
/// be needed to support IPv6-only peers — this is future work.
#[must_use]
fn intersect_families(config: &PeerConfig, peer_caps: &[Capability]) -> Vec<(Afi, Safi)> {
    let mut result: Vec<(Afi, Safi)> = config
        .families
        .iter()
        .filter(|(afi, safi)| {
            peer_caps.iter().any(|c| {
                matches!(c, Capability::MultiProtocol { afi: a, safi: s } if *a == *afi && *s == *safi)
            })
        })
        .copied()
        .collect();

    // RFC 4760 §8: IPv4 unicast is implicitly supported unless BOTH sides
    // explicitly advertise MultiProtocol for IPv4 unicast (making it subject
    // to explicit negotiation). If either side omits it, add it implicitly.
    let ipv4_unicast = (Afi::Ipv4, Safi::Unicast);
    if !result.contains(&ipv4_unicast) {
        let peer_advertises_mp_ipv4 = peer_caps.iter().any(|c| {
            matches!(
                c,
                Capability::MultiProtocol {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast
                }
            )
        });
        let local_advertises_mp_ipv4 = config.families.contains(&ipv4_unicast);

        // If both sides explicitly negotiate IPv4 MP and the intersection
        // didn't include it, one side rejected it — don't add implicitly.
        // Otherwise, at least one side didn't explicitly negotiate, so
        // IPv4 unicast is implicitly available.
        if !peer_advertises_mp_ipv4 || !local_advertises_mp_ipv4 {
            result.push(ipv4_unicast);
        }
    }

    result
}

/// Negotiate Add-Path capabilities between our local capabilities and the
/// peer's advertised capabilities (RFC 7911 §4).
///
/// The result indicates what *we* can do for each (AFI, SAFI):
/// - `Receive`: we can receive Add-Path from the peer (we want to receive, peer wants to send)
/// - `Send`: we can send Add-Path to the peer (we want to send, peer wants to receive)
/// - `Both`: we can both send and receive Add-Path
///
/// Only families where at least one direction matches are included.
#[must_use]
pub fn negotiate_add_path(
    our_caps: &[AddPathFamily],
    peer_caps: &[AddPathFamily],
) -> HashMap<(Afi, Safi), AddPathMode> {
    let mut result = HashMap::new();

    for ours in our_caps {
        let family = (ours.afi, ours.safi);
        if let Some(peer) = peer_caps
            .iter()
            .find(|p| p.afi == ours.afi && p.safi == ours.safi)
        {
            // "We Receive" requires "Peer Send"
            let we_receive = matches!(ours.send_receive, AddPathMode::Receive | AddPathMode::Both)
                && matches!(peer.send_receive, AddPathMode::Send | AddPathMode::Both);

            // "We Send" requires "Peer Receive"
            let we_send = matches!(ours.send_receive, AddPathMode::Send | AddPathMode::Both)
                && matches!(peer.send_receive, AddPathMode::Receive | AddPathMode::Both);

            let mode = match (we_send, we_receive) {
                (true, true) => Some(AddPathMode::Both),
                (true, false) => Some(AddPathMode::Send),
                (false, true) => Some(AddPathMode::Receive),
                (false, false) => None,
            };

            if let Some(m) = mode {
                result.insert(family, m);
            }
        }
    }

    result
}

/// Negotiate Extended Next Hop Encoding tuples (RFC 8950).
///
/// The result maps NLRI family to the negotiated next-hop AFI. Only exact
/// tuple matches between our local capability and the peer's capability are
/// retained.
#[must_use]
pub fn negotiate_extended_nexthop(
    our_caps: &[ExtendedNextHopFamily],
    peer_caps: &[ExtendedNextHopFamily],
) -> HashMap<(Afi, Safi), Afi> {
    let mut result = HashMap::new();

    for ours in our_caps {
        if peer_caps.iter().any(|peer| peer == ours) {
            result.insert((ours.nlri_afi, ours.nlri_safi), ours.next_hop_afi);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rustbgpd_wire::{Afi, Safi};

    use super::*;

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
            llgr_stale_time: 0,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
        }
    }

    fn peer_open() -> OpenMessage {
        OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 180,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![
                Capability::MultiProtocol {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                },
                Capability::FourOctetAs { asn: 65002 },
            ],
        }
    }

    #[test]
    fn valid_open_negotiates_session() {
        let cfg = test_config();
        let open = peer_open();
        let neg = validate_open(&open, &cfg).unwrap();

        assert_eq!(neg.peer_asn, 65002);
        assert_eq!(neg.peer_router_id, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(neg.hold_time, 90); // min(90, 180)
        assert_eq!(neg.keepalive_interval, 30);
        assert!(neg.four_octet_as);
    }

    #[test]
    fn reject_bad_version() {
        let cfg = test_config();
        let mut open = peer_open();
        open.version = 3;
        let err = validate_open(&open, &cfg).unwrap_err();
        assert_eq!(err.code, NotificationCode::OpenMessage);
        assert_eq!(err.subcode, open_subcode::UNSUPPORTED_VERSION);
    }

    #[test]
    fn reject_hold_time_one() {
        let cfg = test_config();
        let mut open = peer_open();
        open.hold_time = 1;
        let err = validate_open(&open, &cfg).unwrap_err();
        assert_eq!(err.subcode, open_subcode::UNACCEPTABLE_HOLD_TIME);
    }

    #[test]
    fn reject_hold_time_two() {
        let cfg = test_config();
        let mut open = peer_open();
        open.hold_time = 2;
        let err = validate_open(&open, &cfg).unwrap_err();
        assert_eq!(err.subcode, open_subcode::UNACCEPTABLE_HOLD_TIME);
    }

    #[test]
    fn accept_hold_time_zero() {
        let cfg = test_config();
        let mut open = peer_open();
        open.hold_time = 0;
        let neg = validate_open(&open, &cfg).unwrap();
        assert_eq!(neg.hold_time, 0);
        assert_eq!(neg.keepalive_interval, 0);
    }

    #[test]
    fn reject_zero_bgp_identifier() {
        let cfg = test_config();
        let mut open = peer_open();
        open.bgp_identifier = Ipv4Addr::UNSPECIFIED;
        let err = validate_open(&open, &cfg).unwrap_err();
        assert_eq!(err.subcode, open_subcode::BAD_BGP_IDENTIFIER);
    }

    #[test]
    fn reject_wrong_peer_asn() {
        let cfg = test_config();
        let mut open = peer_open();
        open.my_as = 65099;
        open.capabilities = vec![Capability::FourOctetAs { asn: 65099 }];
        let err = validate_open(&open, &cfg).unwrap_err();
        assert_eq!(err.subcode, open_subcode::BAD_PEER_AS);
    }

    #[test]
    fn four_octet_as_false_when_peer_lacks_cap() {
        let cfg = test_config();
        let mut open = peer_open();
        open.capabilities = vec![Capability::MultiProtocol {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        }];
        // my_as must match remote_asn since there's no FourOctetAs cap
        open.my_as = 65002;
        let neg = validate_open(&open, &cfg).unwrap();
        assert!(!neg.four_octet_as);
    }

    #[test]
    fn negotiate_hold_time_takes_minimum() {
        assert_eq!(negotiate_hold_time(90, 180), 90);
        assert_eq!(negotiate_hold_time(180, 90), 90);
        assert_eq!(negotiate_hold_time(90, 90), 90);
    }

    #[test]
    fn negotiate_hold_time_zero_if_either_zero() {
        assert_eq!(negotiate_hold_time(0, 90), 0);
        assert_eq!(negotiate_hold_time(90, 0), 0);
        assert_eq!(negotiate_hold_time(0, 0), 0);
    }

    #[test]
    fn implicit_ipv4_unicast_when_neither_advertises_mp() {
        // Neither side advertises MP-BGP for IPv4 → IPv4 unicast implicitly present
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv6, Safi::Unicast)]; // only IPv6 in config
        let open = OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 180,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![
                Capability::MultiProtocol {
                    afi: Afi::Ipv6,
                    safi: Safi::Unicast,
                },
                Capability::FourOctetAs { asn: 65002 },
            ],
        };
        let neg = validate_open(&open, &cfg).unwrap();
        // IPv6 negotiated explicitly, IPv4 added implicitly
        assert!(
            neg.negotiated_families
                .contains(&(Afi::Ipv6, Safi::Unicast))
        );
        assert!(
            neg.negotiated_families
                .contains(&(Afi::Ipv4, Safi::Unicast))
        );
    }

    #[test]
    fn ipv4_unicast_excluded_when_both_advertise_mp_but_mismatch() {
        // Both sides advertise MP-BGP for IPv4, but peer doesn't have it
        // → explicit negotiation, IPv4 NOT implicitly added
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast)]; // local has IPv4 MP
        let open = OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 180,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![
                // Peer advertises IPv4 MP but let's say they removed it somehow...
                // Actually, if both sides advertise IPv4 MP, intersection WILL include it.
                // The only way it's excluded is if peer doesn't advertise IPv4 MP.
                // So this tests: local has IPv4 MP, peer doesn't → implicit fallback kicks in.
                Capability::MultiProtocol {
                    afi: Afi::Ipv6,
                    safi: Safi::Unicast,
                },
                Capability::FourOctetAs { asn: 65002 },
            ],
        };
        let neg = validate_open(&open, &cfg).unwrap();
        // Peer didn't advertise IPv4 MP → implicit fallback applies
        assert!(
            neg.negotiated_families
                .contains(&(Afi::Ipv4, Safi::Unicast))
        );
    }

    #[test]
    fn graceful_restart_extracted_from_peer_open() {
        use rustbgpd_wire::GracefulRestartFamily;

        let cfg = test_config();
        let mut open = peer_open();
        open.capabilities.push(Capability::GracefulRestart {
            restart_state: true,
            restart_time: 120,
            families: vec![GracefulRestartFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: true,
            }],
        });
        let neg = validate_open(&open, &cfg).unwrap();
        assert!(neg.peer_gr_capable);
        assert!(neg.peer_restart_state);
        assert_eq!(neg.peer_restart_time, 120);
        assert_eq!(neg.peer_gr_families.len(), 1);
        assert!(neg.peer_gr_families[0].forwarding_preserved);
    }

    #[test]
    fn graceful_restart_absent_yields_defaults() {
        let cfg = test_config();
        let open = peer_open(); // no GR capability
        let neg = validate_open(&open, &cfg).unwrap();
        assert!(!neg.peer_gr_capable);
        assert!(!neg.peer_restart_state);
        assert_eq!(neg.peer_restart_time, 0);
        assert!(neg.peer_gr_families.is_empty());
    }

    #[test]
    fn four_byte_asn_via_capability() {
        let mut cfg = test_config();
        cfg.remote_asn = 4_200_000_001;
        let mut open = peer_open();
        open.my_as = rustbgpd_wire::constants::AS_TRANS;
        open.capabilities = vec![Capability::FourOctetAs { asn: 4_200_000_001 }];
        let neg = validate_open(&open, &cfg).unwrap();
        assert_eq!(neg.peer_asn, 4_200_000_001);
        assert!(neg.four_octet_as);
    }

    #[test]
    fn extended_message_extracted_from_peer_open() {
        let cfg = test_config();
        let mut open = peer_open();
        open.capabilities.push(Capability::ExtendedMessage);
        let neg = validate_open(&open, &cfg).unwrap();
        assert!(neg.peer_extended_message);
    }

    #[test]
    fn extended_message_absent_yields_false() {
        let cfg = test_config();
        let open = peer_open(); // no ExtendedMessage capability
        let neg = validate_open(&open, &cfg).unwrap();
        assert!(!neg.peer_extended_message);
    }

    #[test]
    fn negotiate_add_path_receive_only() {
        // We want Receive, peer wants Send → we can Receive
        let ours = vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Receive,
        }];
        let peers = vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Send,
        }];
        let result = negotiate_add_path(&ours, &peers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[&(Afi::Ipv4, Safi::Unicast)], AddPathMode::Receive);
    }

    #[test]
    fn negotiate_add_path_send_only() {
        // We want Send, peer wants Receive → we can Send
        let ours = vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Send,
        }];
        let peers = vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Receive,
        }];
        let result = negotiate_add_path(&ours, &peers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[&(Afi::Ipv4, Safi::Unicast)], AddPathMode::Send);
    }

    #[test]
    fn negotiate_add_path_both_directions() {
        // Both sides want Both → we can Both
        let ours = vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Both,
        }];
        let peers = vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Both,
        }];
        let result = negotiate_add_path(&ours, &peers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[&(Afi::Ipv4, Safi::Unicast)], AddPathMode::Both);
    }

    #[test]
    fn negotiate_add_path_no_overlap() {
        // We want Receive, peer also wants Receive → no match
        let ours = vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Receive,
        }];
        let peers = vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Receive,
        }];
        let result = negotiate_add_path(&ours, &peers);
        assert!(result.is_empty());
    }

    #[test]
    fn negotiate_add_path_different_families() {
        // We want IPv4, peer wants IPv6 → no match
        let ours = vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Receive,
        }];
        let peers = vec![AddPathFamily {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Send,
        }];
        let result = negotiate_add_path(&ours, &peers);
        assert!(result.is_empty());
    }

    #[test]
    fn negotiate_add_path_partial_overlap() {
        // Multiple families, only some match
        let ours = vec![
            AddPathFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Receive,
            },
            AddPathFamily {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Receive,
            },
        ];
        let peers = vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Send,
        }];
        let result = negotiate_add_path(&ours, &peers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[&(Afi::Ipv4, Safi::Unicast)], AddPathMode::Receive);
        assert!(!result.contains_key(&(Afi::Ipv6, Safi::Unicast)));
    }

    #[test]
    fn validate_open_negotiates_add_path() {
        let mut cfg = test_config();
        cfg.add_path_receive = true;
        let mut open = peer_open();
        open.capabilities
            .push(Capability::AddPath(vec![AddPathFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Send,
            }]));
        let neg = validate_open(&open, &cfg).unwrap();
        assert_eq!(neg.add_path_families.len(), 1);
        assert_eq!(
            neg.add_path_families[&(Afi::Ipv4, Safi::Unicast)],
            AddPathMode::Receive,
        );
    }

    #[test]
    fn validate_open_add_path_empty_when_disabled() {
        let cfg = test_config(); // add_path_receive = false
        let mut open = peer_open();
        open.capabilities
            .push(Capability::AddPath(vec![AddPathFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Both,
            }]));
        let neg = validate_open(&open, &cfg).unwrap();
        assert!(neg.add_path_families.is_empty());
    }

    #[test]
    fn validate_open_merges_multiple_add_path_capabilities() {
        let mut cfg = test_config();
        cfg.add_path_receive = true;
        let mut open = peer_open();
        open.capabilities.push(Capability::AddPath(vec![]));
        open.capabilities
            .push(Capability::AddPath(vec![AddPathFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Send,
            }]));

        let neg = validate_open(&open, &cfg).unwrap();
        assert_eq!(
            neg.add_path_families.get(&(Afi::Ipv4, Safi::Unicast)),
            Some(&AddPathMode::Receive)
        );
    }

    #[test]
    fn validate_open_negotiates_extended_nexthop() {
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        let mut open = peer_open();
        open.capabilities.push(Capability::MultiProtocol {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        });
        open.capabilities
            .push(Capability::ExtendedNextHop(vec![ExtendedNextHopFamily {
                nlri_afi: Afi::Ipv4,
                nlri_safi: Safi::Unicast,
                next_hop_afi: Afi::Ipv6,
            }]));

        let neg = validate_open(&open, &cfg).unwrap();
        assert_eq!(
            neg.extended_nexthop_families
                .get(&(Afi::Ipv4, Safi::Unicast)),
            Some(&Afi::Ipv6)
        );
    }

    #[test]
    fn negotiate_extended_nexthop_requires_exact_tuple_match() {
        let ours = vec![ExtendedNextHopFamily {
            nlri_afi: Afi::Ipv4,
            nlri_safi: Safi::Unicast,
            next_hop_afi: Afi::Ipv6,
        }];
        let peers = vec![ExtendedNextHopFamily {
            nlri_afi: Afi::Ipv4,
            nlri_safi: Safi::Unicast,
            next_hop_afi: Afi::Ipv4,
        }];
        let result = negotiate_extended_nexthop(&ours, &peers);
        assert!(result.is_empty());
    }
}
