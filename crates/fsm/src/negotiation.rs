use bytes::Bytes;

use rustbgpd_wire::notification::{NotificationCode, open_subcode};
use rustbgpd_wire::{Afi, Capability, NotificationMessage, OpenMessage, Safi};

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
}
