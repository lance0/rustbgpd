//! OPEN message validation and capability negotiation (RFC 4271 section 6.2).

use std::collections::HashMap;

use bytes::Bytes;

use rustbgpd_wire::notification::{NotificationCode, open_subcode};
use rustbgpd_wire::{
    AddPathFamily, AddPathMode, Afi, BgpRole, Capability, ExtendedNextHopFamily,
    NotificationMessage, OpenMessage, OrfCapEntry, OrfType, Safi,
};

use crate::action::NegotiatedSession;
use crate::config::{PeerConfig, graceful_restart_preserves_family};

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
/// unsupported version, unacceptable hold time, bad BGP identifier,
/// peer ASN mismatch, or an empty negotiated family intersection
/// (reachable only with `disable_ipv4_unicast`; OPEN error /
/// Unsupported Capability, matching FRR).
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

    // Verify peer ASN matches our configuration.
    // remote_asn == 0 is the dynamic-neighbor sentinel: accept any ASN from OPEN.
    if config.remote_asn != 0 && peer_asn != config.remote_asn {
        return Err(NotificationMessage::new(
            NotificationCode::OpenMessage,
            open_subcode::BAD_PEER_AS,
            Bytes::new(),
        ));
    }

    let remote_role = validate_role_capability(open, config)?;

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

    // No common address family: nothing could ever be exchanged on this
    // session. Reject with OPEN error / Unsupported Capability, matching
    // FRR's "Configured AFI/SAFIs do not overlap with received MP
    // capabilities" behavior. Without `disable_ipv4_unicast` this is
    // unreachable — the RFC 4760 §8 implicit-IPv4 fallback guarantees a
    // non-empty intersection. Per RFC 5492 §5 the Data field lists the
    // capabilities that caused the rejection — the MultiProtocol
    // capabilities this speaker required and the peer did not offer.
    if negotiated_families.is_empty() {
        let mut data = bytes::BytesMut::new();
        for (afi, safi) in config.effective_families() {
            // Encoding a MultiProtocol capability into a fresh buffer
            // cannot fail; skip rather than mask the NOTIFICATION if it
            // ever does.
            let _ = (Capability::MultiProtocol { afi, safi }).encode(&mut data);
        }
        return Err(NotificationMessage::new(
            NotificationCode::OpenMessage,
            open_subcode::UNSUPPORTED_CAPABILITY,
            data.freeze(),
        ));
    }

    // Extract Graceful Restart capability from peer
    let (
        mut peer_gr_capable,
        peer_restart_state,
        peer_notification,
        peer_restart_time,
        peer_gr_families,
    ) = open
        .capabilities
        .iter()
        // RFC 4724 section 3 requires duplicate instances to be ignored
        // except for the last one carried in the OPEN.
        .rev()
        .find_map(|c| match c {
            Capability::GracefulRestart {
                restart_state,
                notification,
                restart_time,
                families,
            } => Some((
                true,
                *restart_state,
                *notification,
                *restart_time,
                families.clone(),
            )),
            _ => None,
        })
        .unwrap_or_default();
    let peer_gr_families: Vec<_> = peer_gr_families
        .into_iter()
        .filter(|family| {
            let key = (family.afi, family.safi);
            negotiated_families.contains(&key) && graceful_restart_preserves_family(key)
        })
        .collect();
    peer_gr_capable = peer_gr_capable && !peer_gr_families.is_empty();

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
    let peer_llgr_families: Vec<_> = peer_llgr_families
        .into_iter()
        .filter(|family| {
            let key = (family.afi, family.safi);
            negotiated_families.contains(&key) && graceful_restart_preserves_family(key)
        })
        .collect();
    let peer_llgr_capable = peer_llgr_capable && !peer_llgr_families.is_empty();

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
    let peer_paths_limits: HashMap<(Afi, Safi), u16> = open
        .capabilities
        .iter()
        .filter_map(|cap| match cap {
            Capability::PathsLimit(families) => Some(families.as_slice()),
            _ => None,
        })
        .flatten()
        .filter(|entry| entry.receive_limit != 0)
        .fold(HashMap::new(), |mut limits, entry| {
            limits
                .entry((entry.afi, entry.safi))
                .or_insert(entry.receive_limit);
            limits
        });
    let configured_send_max = if config.add_path_send_max == 0 {
        u32::MAX
    } else {
        config.add_path_send_max
    };
    let effective_add_path_send_limits = add_path_families
        .iter()
        .filter(|(_, mode)| matches!(mode, AddPathMode::Send | AddPathMode::Both))
        .map(|(family, _)| {
            let effective = peer_paths_limits
                .get(family)
                .map_or(configured_send_max, |limit| {
                    configured_send_max.min(u32::from(*limit))
                });
            (*family, effective)
        })
        .collect();

    // Negotiate Outbound Route Filtering receive (RFC 5291). We advertise the
    // Receive role for Address-Prefix ORF (type 64); ORF-receive is active for
    // a family only if the peer advertised the Send (or Both) role for it.
    let our_orf_caps = config.orf_capabilities();
    let peer_orf_caps: Vec<OrfCapEntry> = open
        .capabilities
        .iter()
        .filter_map(|c| match c {
            Capability::OutboundRouteFilter(entries) => Some(entries.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    let negotiated_orf_recv = negotiate_orf_receive(&our_orf_caps, &peer_orf_caps);

    Ok(NegotiatedSession {
        peer_asn,
        peer_router_id: open.bgp_identifier,
        hold_time,
        keepalive_interval,
        peer_capabilities: open.capabilities.clone(),
        local_role: config.local_role,
        remote_role,
        role_negotiated: config.local_role.is_some() && remote_role.is_some(),
        four_octet_as,
        negotiated_families,
        peer_gr_capable,
        peer_restart_state,
        peer_restart_time,
        peer_gr_families,
        peer_notification_gr: peer_gr_capable && peer_notification && config.graceful_restart,
        peer_llgr_capable,
        peer_llgr_families,
        peer_route_refresh,
        peer_enhanced_route_refresh,
        peer_extended_message,
        extended_nexthop_families,
        add_path_families,
        peer_paths_limits,
        effective_add_path_send_limits,
        negotiated_orf_recv,
    })
}

/// Compute the (AFI,SAFI) families where rustbgpd will receive Address-Prefix
/// ORF entries from the peer (RFC 5291 §4 capability intersection): we
/// advertised the Receive role for ORF-Type 64 and the peer advertised the
/// Send (or Both) role for the same family. Only the standard type 64 is
/// considered — rustbgpd never advertises the legacy type 128.
fn negotiate_orf_receive(ours: &[OrfCapEntry], peer: &[OrfCapEntry]) -> Vec<(Afi, Safi)> {
    ours.iter()
        .filter(|our| {
            our.orf_types
                .iter()
                .any(|t| t.orf_type == OrfType::AddressPrefix && t.send_receive.can_receive())
        })
        .filter(|our| {
            peer.iter().any(|p| {
                p.afi == our.afi
                    && p.safi == our.safi
                    && p.orf_types
                        .iter()
                        .any(|t| t.orf_type == OrfType::AddressPrefix && t.send_receive.can_send())
            })
        })
        .map(|e| (e.afi, e.safi))
        .collect()
}

fn validate_role_capability(
    open: &OpenMessage,
    config: &PeerConfig,
) -> Result<Option<BgpRole>, NotificationMessage> {
    let mut remote_role: Option<BgpRole> = None;
    for capability in &open.capabilities {
        let Capability::Role { role } = capability else {
            continue;
        };
        if let Some(existing) = remote_role
            && existing != *role
        {
            return Err(role_mismatch_notification());
        }
        remote_role = Some(*role);
    }

    let Some(local_role) = config.local_role else {
        return Ok(remote_role);
    };

    let Some(remote_role) = remote_role else {
        if config.strict_role {
            return Err(role_mismatch_notification());
        }
        return Ok(None);
    };

    if !roles_compatible(local_role, remote_role) {
        return Err(role_mismatch_notification());
    }

    Ok(Some(remote_role))
}

const fn roles_compatible(local: BgpRole, remote: BgpRole) -> bool {
    matches!(
        (local, remote),
        (BgpRole::Provider, BgpRole::Customer)
            | (BgpRole::Customer, BgpRole::Provider)
            | (BgpRole::RouteServer, BgpRole::RouteServerClient)
            | (BgpRole::RouteServerClient, BgpRole::RouteServer)
            | (BgpRole::Peer, BgpRole::Peer)
    )
}

fn role_mismatch_notification() -> NotificationMessage {
    NotificationMessage::new(
        NotificationCode::OpenMessage,
        open_subcode::ROLE_MISMATCH,
        Bytes::new(),
    )
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
/// RFC 4760 §8 backward compatibility: IPv4 unicast is implicit only for a
/// **capability-less legacy peer** (one that advertised no `MultiProtocol`
/// capability at all), and only when the local family set includes it. A
/// peer that advertised any explicit MP set has stated its complete family
/// list — nothing is added behind its back.
///
/// **IPv6-only peering:** when the peer is configured with
/// `disable_ipv4_unicast`, the implicit IPv4 fallback is suppressed and
/// IPv4 unicast is excluded from the local family set entirely — only
/// explicitly negotiated non-IPv4-unicast families survive. The caller
/// rejects an empty intersection with OPEN error / Unsupported Capability.
#[must_use]
fn intersect_families(config: &PeerConfig, peer_caps: &[Capability]) -> Vec<(Afi, Safi)> {
    let local_families = config.effective_families();
    let mut result: Vec<(Afi, Safi)> = local_families
        .iter()
        .filter(|(afi, safi)| {
            peer_caps.iter().any(|c| {
                matches!(c, Capability::MultiProtocol { afi: a, safi: s } if *a == *afi && *s == *safi)
            })
        })
        .copied()
        .collect();

    // IPv6-only peering: never treat IPv4 unicast as implicitly available
    // for this peer (the operator asserted the session must not carry it).
    if config.disable_ipv4_unicast {
        return result;
    }

    // RFC 4760 §8's implicit-IPv4 rule is backward compatibility for
    // capability-less legacy speakers, NOT a floor under explicit MP
    // negotiation. A peer that advertised ANY MultiProtocol capability has
    // stated its complete family set — adding IPv4 unicast behind its back
    // leaks classic-NLRI UPDATEs onto (e.g.) a linkstate-only or VPN-only
    // session, which compliant peers treat as a fatal
    // family-not-negotiated error (GoBGP hard-resets in a permanent flap
    // loop; found live by the M76 lab). Likewise, never add a family the
    // LOCAL config excludes: we must not send what we never advertised in
    // our own OPEN. GoBGP/FRR/BIRD all implement these semantics.
    let ipv4_unicast = (Afi::Ipv4, Safi::Unicast);
    if !result.contains(&ipv4_unicast) {
        let peer_advertised_any_mp = peer_caps
            .iter()
            .any(|c| matches!(c, Capability::MultiProtocol { .. }));
        let local_advertises_mp_ipv4 = local_families.contains(&ipv4_unicast);

        if !peer_advertised_any_mp && local_advertises_mp_ipv4 {
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

    use rustbgpd_wire::{Afi, GracefulRestartFamily, LlgrFamily, Safi};

    use super::*;

    fn test_config() -> PeerConfig {
        PeerConfig {
            local_asn: 65001,
            remote_asn: 65002,
            local_router_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            send_hold_time: crate::config::default_send_hold_time(90),
            connect_retry_secs: 30,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
            graceful_restart: false,
            gr_restart_time: 120,
            llgr_stale_time: 0,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
            paths_limit_receive_max: 0,
            local_role: None,
            strict_role: false,
            prefix_orf_receive: false,
            disable_ipv4_unicast: false,
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
    fn remote_asn_zero_accepts_any_peer_asn() {
        let mut cfg = test_config();
        cfg.remote_asn = 0; // dynamic-neighbor sentinel
        let mut open = peer_open();
        open.my_as = 65099;
        open.capabilities = vec![Capability::FourOctetAs { asn: 65099 }];
        let neg = validate_open(&open, &cfg).unwrap();
        assert_eq!(neg.peer_asn, 65099);
    }

    #[test]
    fn role_capability_negotiates_compatible_pair() {
        let mut cfg = test_config();
        cfg.local_role = Some(BgpRole::Provider);
        let mut open = peer_open();
        open.capabilities.push(Capability::Role {
            role: BgpRole::Customer,
        });

        let neg = validate_open(&open, &cfg).unwrap();

        assert_eq!(neg.local_role, Some(BgpRole::Provider));
        assert_eq!(neg.remote_role, Some(BgpRole::Customer));
        assert!(neg.role_negotiated);
    }

    #[test]
    fn role_capability_missing_remote_is_allowed_when_not_strict() {
        let mut cfg = test_config();
        cfg.local_role = Some(BgpRole::Provider);
        cfg.strict_role = false;

        let neg = validate_open(&peer_open(), &cfg).unwrap();

        assert_eq!(neg.local_role, Some(BgpRole::Provider));
        assert_eq!(neg.remote_role, None);
        assert!(!neg.role_negotiated);
    }

    #[test]
    fn role_capability_missing_remote_rejected_when_strict() {
        let mut cfg = test_config();
        cfg.local_role = Some(BgpRole::Provider);
        cfg.strict_role = true;

        let err = validate_open(&peer_open(), &cfg).unwrap_err();

        assert_eq!(err.code, NotificationCode::OpenMessage);
        assert_eq!(err.subcode, open_subcode::ROLE_MISMATCH);
    }

    #[test]
    fn role_capability_mismatch_rejected() {
        let mut cfg = test_config();
        cfg.local_role = Some(BgpRole::Provider);
        let mut open = peer_open();
        open.capabilities.push(Capability::Role {
            role: BgpRole::Peer,
        });

        let err = validate_open(&open, &cfg).unwrap_err();

        assert_eq!(err.code, NotificationCode::OpenMessage);
        assert_eq!(err.subcode, open_subcode::ROLE_MISMATCH);
    }

    #[test]
    fn role_capability_duplicate_identical_coalesces() {
        let mut cfg = test_config();
        cfg.local_role = Some(BgpRole::RouteServer);
        let mut open = peer_open();
        open.capabilities.push(Capability::Role {
            role: BgpRole::RouteServerClient,
        });
        open.capabilities.push(Capability::Role {
            role: BgpRole::RouteServerClient,
        });

        let neg = validate_open(&open, &cfg).unwrap();

        assert_eq!(neg.remote_role, Some(BgpRole::RouteServerClient));
        assert!(neg.role_negotiated);
    }

    #[test]
    fn role_capability_duplicate_conflicting_rejected() {
        let mut cfg = test_config();
        cfg.local_role = Some(BgpRole::Provider);
        let mut open = peer_open();
        open.capabilities.push(Capability::Role {
            role: BgpRole::Customer,
        });
        open.capabilities.push(Capability::Role {
            role: BgpRole::Peer,
        });

        let err = validate_open(&open, &cfg).unwrap_err();

        assert_eq!(err.code, NotificationCode::OpenMessage);
        assert_eq!(err.subcode, open_subcode::ROLE_MISMATCH);
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
    fn no_implicit_ipv4_when_peer_advertises_explicit_mp_set() {
        // M76 regression: a peer that advertised ANY MultiProtocol
        // capability has stated its complete family set. Both sides here
        // are IPv6-only — silently adding IPv4 unicast used to leak
        // classic-NLRI UPDATEs onto the session (GoBGP hard-resets with
        // "family not available"). The session must be genuinely IPv6-only.
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
        assert_eq!(neg.negotiated_families, vec![(Afi::Ipv6, Safi::Unicast)]);
    }

    #[test]
    fn explicit_mp_mismatch_with_no_common_family_is_rejected() {
        // Local is IPv4-only; the peer's explicit MP set is IPv6-only.
        // The peer REFUSED IPv4 by omitting it from its explicit set, so
        // the intersection is empty and the OPEN is rejected (Unsupported
        // Capability) — matching how compliant stacks treat a genuinely
        // family-incompatible pair. (Previously the implicit-IPv4 fallback
        // masked this and sent IPv4 the peer never negotiated.)
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast)]; // local has IPv4 MP
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
        assert!(validate_open(&open, &cfg).is_err());
    }

    #[test]
    fn disable_ipv4_unicast_suppresses_implicit_fallback() {
        // Config: IPv6 only + flag. Peer: IPv6 MP only. Without the flag the
        // RFC 4760 §8 fallback would add IPv4 unicast (see
        // implicit_ipv4_unicast_when_neither_advertises_mp); with it the
        // session is genuinely IPv6-only.
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv6, Safi::Unicast)];
        cfg.disable_ipv4_unicast = true;
        let mut open = peer_open();
        open.capabilities = vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: 65002 },
        ];
        let neg = validate_open(&open, &cfg).unwrap();
        assert_eq!(neg.negotiated_families, vec![(Afi::Ipv6, Safi::Unicast)]);
    }

    #[test]
    fn disable_ipv4_unicast_excludes_ipv4_even_when_both_advertise_it() {
        // Dual-family config + flag, peer advertises both MP families:
        // IPv4 unicast must not survive the intersection — the flag wins
        // over the configured/inherited family list.
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        cfg.disable_ipv4_unicast = true;
        let mut open = peer_open(); // already advertises IPv4 MP
        open.capabilities.push(Capability::MultiProtocol {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        });
        let neg = validate_open(&open, &cfg).unwrap();
        assert_eq!(neg.negotiated_families, vec![(Afi::Ipv6, Safi::Unicast)]);
    }

    #[test]
    fn disable_ipv4_unicast_rejects_ipv4_only_peer() {
        // Peer explicitly advertises ONLY IPv4 unicast MP: the intersection
        // is empty → OPEN error / Unsupported Capability (FRR parity:
        // "Configured AFI/SAFIs do not overlap with received MP
        // capabilities").
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv6, Safi::Unicast)];
        cfg.disable_ipv4_unicast = true;
        let open = peer_open(); // advertises IPv4 unicast MP only
        let err = validate_open(&open, &cfg).unwrap_err();
        assert_eq!(err.code, NotificationCode::OpenMessage);
        assert_eq!(err.subcode, open_subcode::UNSUPPORTED_CAPABILITY);
        // RFC 5492 §5: the Data field carries the MultiProtocol
        // capabilities this speaker required and the peer did not offer.
        let mut buf = err.data.clone();
        let listed = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            listed,
            Capability::MultiProtocol {
                afi: Afi::Ipv6,
                safi: Safi::Unicast
            }
        );
        assert!(buf.is_empty(), "exactly one required family expected");
    }

    #[test]
    fn disable_ipv4_unicast_rejects_peer_without_any_mp_capability() {
        // A legacy peer sending no MP capability at all is implicitly
        // IPv4-unicast-only (RFC 4760 §8); with the fallback suppressed the
        // intersection is empty → same OPEN error / Unsupported Capability.
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv6, Safi::Unicast)];
        cfg.disable_ipv4_unicast = true;
        let mut open = peer_open();
        open.capabilities = vec![Capability::FourOctetAs { asn: 65002 }];
        let err = validate_open(&open, &cfg).unwrap_err();
        assert_eq!(err.code, NotificationCode::OpenMessage);
        assert_eq!(err.subcode, open_subcode::UNSUPPORTED_CAPABILITY);
    }

    #[test]
    fn legacy_peer_with_ipv4_in_local_families_gets_implicit_ipv4() {
        // RFC 4760 §8 survives for its actual purpose: a capability-less
        // legacy peer implies IPv4 unicast — when the local family set
        // includes it.
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        let mut open = peer_open();
        open.capabilities = vec![Capability::FourOctetAs { asn: 65002 }];
        let neg = validate_open(&open, &cfg).unwrap();
        assert_eq!(neg.negotiated_families, vec![(Afi::Ipv4, Safi::Unicast)]);
    }

    #[test]
    fn legacy_peer_rejected_when_local_families_exclude_ipv4() {
        // A capability-less legacy peer can only do IPv4 unicast; if the
        // local config excludes it (IPv6-only), there is no common family
        // and the OPEN is rejected — the old behavior silently negotiated
        // IPv4 against the operator's configured family set.
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv6, Safi::Unicast)];
        let mut open = peer_open();
        open.capabilities = vec![Capability::FourOctetAs { asn: 65002 }];
        assert!(validate_open(&open, &cfg).is_err());
    }

    #[test]
    fn graceful_restart_extracted_from_peer_open() {
        let mut cfg = test_config();
        cfg.graceful_restart = true;
        let mut open = peer_open();
        open.capabilities.push(Capability::GracefulRestart {
            restart_state: true,
            notification: true,
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
        assert!(neg.peer_notification_gr);
        assert_eq!(neg.peer_restart_time, 120);
        assert_eq!(neg.peer_gr_families.len(), 1);
        assert!(neg.peer_gr_families[0].forwarding_preserved);
    }

    /// Load-bearing RFC 4724 section 3 proof: selecting the first duplicate
    /// Graceful Restart capability instead of the last changes every asserted
    /// restart flag, timer, and family-forwarding value to the first fixture.
    #[test]
    fn duplicate_graceful_restart_capability_uses_last_instance() {
        let mut cfg = test_config();
        cfg.graceful_restart = true;
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        let first = Capability::GracefulRestart {
            restart_state: false,
            notification: false,
            restart_time: 30,
            families: vec![GracefulRestartFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: false,
            }],
        };
        let last = Capability::GracefulRestart {
            restart_state: true,
            notification: true,
            restart_time: 240,
            families: vec![GracefulRestartFamily {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                forwarding_preserved: true,
            }],
        };
        let mut open = peer_open();
        open.capabilities.push(Capability::MultiProtocol {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        });
        open.capabilities.extend([first, last]);

        let neg = validate_open(&open, &cfg).unwrap();
        assert!(neg.peer_gr_capable);
        assert!(neg.peer_restart_state);
        assert!(neg.peer_notification_gr);
        assert_eq!(neg.peer_restart_time, 240);
        assert_eq!(
            neg.peer_gr_families,
            vec![GracefulRestartFamily {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                forwarding_preserved: true,
            }]
        );
    }

    #[test]
    fn graceful_restart_keeps_bgpls_from_peer_open() {
        // BGP-LS has a wired GR/LLGR stale lifecycle, so a negotiated
        // (BgpLs, BgpLs) family survives the GR and LLGR capability filters.
        let mut cfg = test_config();
        cfg.graceful_restart = true;
        cfg.llgr_stale_time = 3600;
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::BgpLs, Safi::BgpLs)];

        let mut open = peer_open();
        open.capabilities.push(Capability::MultiProtocol {
            afi: Afi::BgpLs,
            safi: Safi::BgpLs,
        });
        open.capabilities.push(Capability::GracefulRestart {
            restart_state: false,
            notification: true,
            restart_time: 120,
            families: vec![
                GracefulRestartFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    forwarding_preserved: true,
                },
                GracefulRestartFamily {
                    afi: Afi::BgpLs,
                    safi: Safi::BgpLs,
                    forwarding_preserved: true,
                },
            ],
        });
        open.capabilities
            .push(Capability::LongLivedGracefulRestart(vec![
                LlgrFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    forwarding_preserved: true,
                    stale_time: 3600,
                },
                LlgrFamily {
                    afi: Afi::BgpLs,
                    safi: Safi::BgpLs,
                    forwarding_preserved: true,
                    stale_time: 3600,
                },
            ]));

        let neg = validate_open(&open, &cfg).unwrap();
        assert!(neg.peer_gr_capable);
        let gr_families: Vec<(Afi, Safi)> = neg
            .peer_gr_families
            .iter()
            .map(|f| (f.afi, f.safi))
            .collect();
        assert_eq!(
            gr_families,
            vec![(Afi::Ipv4, Safi::Unicast), (Afi::BgpLs, Safi::BgpLs)]
        );
        assert!(neg.peer_llgr_capable);
        let llgr_families: Vec<(Afi, Safi)> = neg
            .peer_llgr_families
            .iter()
            .map(|f| (f.afi, f.safi))
            .collect();
        assert_eq!(
            llgr_families,
            vec![(Afi::Ipv4, Safi::Unicast), (Afi::BgpLs, Safi::BgpLs)]
        );
    }

    #[test]
    fn graceful_restart_keeps_vpn_and_rtc_from_peer_open() {
        // VPNv4/VPNv6 (SAFI 128) and RT-Constrain (SAFI 132) are in the GR
        // preservation allowlist: negotiated tuples survive the capability
        // filter, while a non-negotiated tuple (VPNv6 here) is still dropped.
        let mut cfg = test_config();
        cfg.graceful_restart = true;
        cfg.families = vec![
            (Afi::Ipv4, Safi::MplsVpn),
            (Afi::Ipv4, Safi::RtConstrain),
            (Afi::Ipv4, Safi::Unicast),
        ];

        let mut open = peer_open();
        open.capabilities.push(Capability::MultiProtocol {
            afi: Afi::Ipv4,
            safi: Safi::MplsVpn,
        });
        open.capabilities.push(Capability::MultiProtocol {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
        });
        open.capabilities.push(Capability::GracefulRestart {
            restart_state: false,
            notification: true,
            restart_time: 120,
            families: vec![
                GracefulRestartFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::MplsVpn,
                    forwarding_preserved: true,
                },
                GracefulRestartFamily {
                    afi: Afi::Ipv6,
                    safi: Safi::MplsVpn,
                    forwarding_preserved: true,
                },
                GracefulRestartFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::RtConstrain,
                    forwarding_preserved: true,
                },
            ],
        });

        let neg = validate_open(&open, &cfg).unwrap();
        assert!(neg.peer_gr_capable);
        let gr_families: Vec<(Afi, Safi)> = neg
            .peer_gr_families
            .iter()
            .map(|f| (f.afi, f.safi))
            .collect();
        assert_eq!(
            gr_families,
            vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::Ipv4, Safi::RtConstrain)],
            "negotiated VPN/RTC tuples must survive; non-negotiated VPNv6 must not"
        );
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
    fn paths_limit_caps_only_matching_add_path_send_family() {
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        cfg.add_path_send = true;
        cfg.add_path_send_max = 8;
        let mut open = peer_open();
        open.capabilities.push(Capability::AddPath(vec![
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
        ]));
        open.capabilities.push(Capability::PathsLimit(vec![
            rustbgpd_wire::PathsLimitFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                receive_limit: 3,
            },
            rustbgpd_wire::PathsLimitFamily {
                afi: Afi::Ipv6,
                safi: Safi::MplsVpn,
                receive_limit: 1,
            },
        ]));

        let neg = validate_open(&open, &cfg).unwrap();
        assert_eq!(neg.peer_paths_limits[&(Afi::Ipv4, Safi::Unicast)], 3);
        assert_eq!(
            neg.effective_add_path_send_limits[&(Afi::Ipv4, Safi::Unicast)],
            3
        );
        assert_eq!(
            neg.effective_add_path_send_limits[&(Afi::Ipv6, Safi::Unicast)],
            8
        );
        assert!(
            !neg.effective_add_path_send_limits
                .contains_key(&(Afi::Ipv6, Safi::MplsVpn))
        );
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
    fn negotiate_add_path_vpn_families_both_directions() {
        // VPNv4/VPNv6 (SAFI 128) negotiate Add-Path exactly like unicast
        // (RFC 9107 requires it between RRs for multi-cluster ORR).
        let ours = vec![
            AddPathFamily {
                afi: Afi::Ipv4,
                safi: Safi::MplsVpn,
                send_receive: AddPathMode::Both,
            },
            AddPathFamily {
                afi: Afi::Ipv6,
                safi: Safi::MplsVpn,
                send_receive: AddPathMode::Both,
            },
        ];
        let peers = ours.clone();
        let result = negotiate_add_path(&ours, &peers);
        assert_eq!(result.len(), 2);
        assert_eq!(result[&(Afi::Ipv4, Safi::MplsVpn)], AddPathMode::Both);
        assert_eq!(result[&(Afi::Ipv6, Safi::MplsVpn)], AddPathMode::Both);
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

    use rustbgpd_wire::{OrfCapType, OrfSendReceive};

    fn orf_cap(send_receive: OrfSendReceive, orf_type: OrfType) -> Capability {
        Capability::OutboundRouteFilter(vec![OrfCapEntry {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            orf_types: vec![OrfCapType {
                orf_type,
                send_receive,
            }],
        }])
    }

    #[test]
    fn validate_open_negotiates_orf_receive_when_peer_sends() {
        let mut cfg = test_config();
        cfg.prefix_orf_receive = true;
        let mut open = peer_open();
        open.capabilities
            .push(orf_cap(OrfSendReceive::Send, OrfType::AddressPrefix));
        let neg = validate_open(&open, &cfg).unwrap();
        assert_eq!(neg.negotiated_orf_recv, vec![(Afi::Ipv4, Safi::Unicast)]);
    }

    #[test]
    fn validate_open_no_orf_when_peer_only_receives() {
        // Intersection requires the peer to advertise Send; Receive alone fails.
        let mut cfg = test_config();
        cfg.prefix_orf_receive = true;
        let mut open = peer_open();
        open.capabilities
            .push(orf_cap(OrfSendReceive::Receive, OrfType::AddressPrefix));
        let neg = validate_open(&open, &cfg).unwrap();
        assert!(neg.negotiated_orf_recv.is_empty());
    }

    #[test]
    fn validate_open_no_orf_when_local_disabled() {
        let cfg = test_config(); // prefix_orf_receive = false
        let mut open = peer_open();
        open.capabilities
            .push(orf_cap(OrfSendReceive::Both, OrfType::AddressPrefix));
        let neg = validate_open(&open, &cfg).unwrap();
        assert!(neg.negotiated_orf_recv.is_empty());
    }

    #[test]
    fn validate_open_no_orf_for_legacy_type_128() {
        // rustbgpd advertises only type 64; a peer offering Send for the legacy
        // type 128 does not intersect, so ORF stays un-negotiated.
        let mut cfg = test_config();
        cfg.prefix_orf_receive = true;
        let mut open = peer_open();
        open.capabilities
            .push(orf_cap(OrfSendReceive::Send, OrfType::AddressPrefixLegacy));
        let neg = validate_open(&open, &cfg).unwrap();
        assert!(neg.negotiated_orf_recv.is_empty());
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
