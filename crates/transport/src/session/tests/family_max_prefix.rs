//! Non-unicast per-family max-prefix bounds (`max_prefixes_<family>`).

use super::max_prefix::{counter_value, mode_config, notifying_session};
use super::*;
use crate::config::{MaxPrefixAction, PrefixLimitFamily};
use rustbgpd_wire::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, LabeledNlri, LabeledNlriEntry,
    MacAddress, MplsLabel, RtcNlri, VpnNlriEntry,
};

fn family_next_hop(family: PrefixLimitFamily) -> IpAddr {
    match family.afi_safi() {
        (_, Safi::FlowSpec) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        (Afi::Ipv6, _) => IpAddr::V6("2001:db8::2".parse().unwrap()),
        _ => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
    }
}

fn family_vpn_nlri(afi: Afi, index: u8, labels: bool) -> VpnNlri {
    VpnNlri {
        labels: if labels {
            vec![MplsLabelEntry::try_new(100, 0, true).unwrap()]
        } else {
            vec![]
        },
        route_distinguisher: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 7]),
        prefix: match afi {
            Afi::Ipv6 => {
                VpnPrefix::v6(format!("2001:db8:{index:x}::").parse().unwrap(), 64).unwrap()
            }
            _ => VpnPrefix::v4(Ipv4Addr::new(10, index, 0, 0), 24).unwrap(),
        },
    }
}

fn family_labeled_nlri(afi: Afi, index: u8, labels: bool) -> LabeledNlri {
    LabeledNlri {
        labels: if labels {
            vec![MplsLabelEntry::try_new(200, 0, true).unwrap()]
        } else {
            vec![]
        },
        prefix: match afi {
            Afi::Ipv6 => Prefix::V6(v6_prefix(u16::from(index))),
            _ => Prefix::V4(v4_prefix(index)),
        },
    }
}

fn family_evpn_route(index: u8) -> EvpnRoute {
    EvpnRoute::MacIp(EvpnMacIp {
        rd: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(100),
        mac: MacAddress([0x02, 0x00, 0x00, 0xaa, 0xbb, index]),
        ip: None,
        label1: MplsLabel::new(10_000),
        label2: None,
    })
}

fn family_flowspec_rule(index: u8) -> FlowSpecRule {
    FlowSpecRule {
        components: vec![FlowSpecComponent::IpProtocol(vec![NumericMatch {
            end_of_list: true,
            and_bit: false,
            lt: false,
            gt: false,
            eq: true,
            value: u64::from(index),
        }])],
    }
}

fn family_rtc_nlri(index: u8) -> RtcNlri {
    RtcNlri::new(65002, 0x0002_fdea_0000_0000 | u64::from(index), 96).unwrap()
}

/// One UPDATE announcing and withdrawing `(index, path_id)` routes of one
/// family.
fn family_update(
    family: PrefixLimitFamily,
    announce: &[(u8, u32)],
    withdraw: &[(u8, u32)],
    add_path: bool,
) -> UpdateMessage {
    let (afi, safi) = family.afi_safi();
    let mut reach = empty_nonunicast_reach(afi, safi, family_next_hop(family));
    let mut unreach = empty_nonunicast_unreach(afi, safi);
    for &(index, path_id) in announce {
        match safi {
            Safi::MplsVpn => reach.vpn_announced.push(VpnNlriEntry {
                path_id,
                nlri: family_vpn_nlri(afi, index, true),
            }),
            Safi::LabeledUnicast => reach.labeled_announced.push(LabeledNlriEntry {
                path_id,
                nlri: family_labeled_nlri(afi, index, true),
            }),
            Safi::Evpn => reach.evpn_announced.push(family_evpn_route(index)),
            Safi::FlowSpec => reach.flowspec_announced.push(family_flowspec_rule(index)),
            Safi::RtConstrain => reach.rtc_announced.push(family_rtc_nlri(index)),
            _ => unreachable!("fixture covers the bounded families"),
        }
    }
    for &(index, path_id) in withdraw {
        match safi {
            Safi::MplsVpn => unreach.vpn_withdrawn.push(VpnNlriEntry {
                path_id,
                nlri: family_vpn_nlri(afi, index, false),
            }),
            Safi::LabeledUnicast => unreach.labeled_withdrawn.push(LabeledNlriEntry {
                path_id,
                nlri: family_labeled_nlri(afi, index, false),
            }),
            Safi::Evpn => unreach.evpn_withdrawn.push(family_evpn_route(index)),
            Safi::FlowSpec => unreach.flowspec_withdrawn.push(family_flowspec_rule(index)),
            Safi::RtConstrain => unreach.rtc_withdrawn.push(family_rtc_nlri(index)),
            _ => unreachable!("fixture covers the bounded families"),
        }
    }
    let mut attrs = nonunicast_accepted_attrs();
    if !announce.is_empty() {
        attrs.push(PathAttribute::MpReachNlri(Box::new(reach)));
    }
    if !withdraw.is_empty() {
        attrs.push(PathAttribute::MpUnreachNlri(Box::new(unreach)));
    }
    UpdateMessage::build(&[], &[], &attrs, true, add_path, Ipv4UnicastMode::Body)
}

fn announce(family: PrefixLimitFamily, indexes: &[u8]) -> UpdateMessage {
    let routes: Vec<_> = indexes.iter().map(|&index| (index, 0)).collect();
    family_update(family, &routes, &[], false)
}

/// Negotiate exactly `family` (with route refresh, optionally Add-Path).
fn install_family_session(session: &mut PeerSession, family: PrefixLimitFamily, add_path: bool) {
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![family.afi_safi()];
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = true;
    if add_path {
        negotiated
            .add_path_families
            .insert(family.afi_safi(), AddPathMode::Both);
    }
    install_test_negotiated_session(session, negotiated);
}

fn family_config(
    family: PrefixLimitFamily,
    bound: u32,
    action: MaxPrefixAction,
) -> TransportConfig {
    let mut config = mode_config(action);
    config.max_prefixes_family.0[family as usize] = Some(bound);
    config
}

/// Announced non-unicast routes the RIB received, across every family
/// delivery shape.
fn drain_delivered_announcements(rib_rx: &mut mpsc::Receiver<RibUpdate>) -> usize {
    let mut delivered = 0;
    while let Ok(update) = rib_rx.try_recv() {
        delivered += match update {
            RibUpdate::RoutesReceived {
                flowspec_announced,
                evpn_announced,
                ..
            } => flowspec_announced.len() + evpn_announced.len(),
            RibUpdate::VpnRoutesReceived { announced, .. } => announced.len(),
            RibUpdate::LabeledRoutesReceived { announced, .. } => announced.len(),
            RibUpdate::RtcRoutesReceived { announced, .. } => announced.len(),
            _ => 0,
        };
    }
    delivered
}

fn family_usage(session: &PeerSession, family: PrefixLimitFamily) -> usize {
    session
        .max_prefix_scope_usage(MaxPrefixScope::Family(family))
        .0
}

/// Mutant: dropping the per-family check keeps every session up past its
/// bound; counting a family into another family's bound, or encoding the wrong
/// AFI/SAFI/bound, corrupts the RFC 4486 Cease data; skipping the per-family
/// counter reset leaves usage after teardown.
#[tokio::test]
async fn family_limit_shutdown_sends_cease_with_family_afi_safi_and_bound() {
    for family in PrefixLimitFamily::ALL {
        let config = family_config(family, 2, MaxPrefixAction::Shutdown);
        let (mut session, mut rib_rx, mut notify_rx, mut server) = notifying_session(config).await;
        install_family_session(&mut session, family, false);

        session.process_update(announce(family, &[1, 2])).await;
        assert!(session.read_half.is_some(), "{family:?} at its bound");
        assert_eq!(family_usage(&session, family), 2, "{family:?}");
        assert_eq!(drain_delivered_announcements(&mut rib_rx), 2, "{family:?}");

        session.process_update(announce(family, &[3])).await;
        assert!(session.read_half.is_none(), "{family:?} over its bound");
        let (afi, safi) = family.afi_safi();
        assert!(
            matches!(
                notify_rx.try_recv(),
                Ok(SessionNotification::MaxPrefixExceeded {
                    count: 3,
                    bound: 2,
                    family: Some(tripped),
                    received: false,
                    path_limit: false,
                    ..
                }) if tripped == (afi, safi)
            ),
            "{family:?}: the manager latch names the family"
        );
        let notif = read_until_notification(&mut server).await;
        assert_eq!(notif.code, NotificationCode::Cease, "{family:?}");
        assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES, "{family:?}");
        assert_eq!(
            notif.data.as_ref(),
            max_prefix_cease_data(afi, safi, 2).as_slice(),
            "{family:?}: Cease/1 data carries AFI, SAFI, and the bound"
        );
        assert_eq!(family_usage(&session, family), 0, "{family:?} reset");
    }
}

/// Mutant: charging every family to one counter trips a family whose own
/// bound was never reached.
#[tokio::test]
async fn family_limits_do_not_share_budget_across_families() {
    // VPNv4 and VPNv6 share `known_vpn`; FlowSpec v4/v6 share
    // `known_flowspec`; labeled v4/v6 share `known_labeled`.
    for (bounded, other) in [
        (PrefixLimitFamily::L3vpnIpv4, PrefixLimitFamily::L3vpnIpv6),
        (
            PrefixLimitFamily::Ipv4LabeledUnicast,
            PrefixLimitFamily::Ipv6LabeledUnicast,
        ),
        (
            PrefixLimitFamily::Ipv6Flowspec,
            PrefixLimitFamily::Ipv4Flowspec,
        ),
    ] {
        let config = family_config(bounded, 1, MaxPrefixAction::Shutdown);
        let (mut session, _rib_rx, _notify_rx, _server) = notifying_session(config).await;
        let mut negotiated = negotiated_session(65002, false);
        negotiated.negotiated_families = vec![bounded.afi_safi(), other.afi_safi()];
        install_test_negotiated_session(&mut session, negotiated);

        session.process_update(announce(other, &[1, 2, 3])).await;
        session.process_update(announce(bounded, &[1])).await;
        assert!(
            session.read_half.is_some(),
            "{other:?} must not use {bounded:?}"
        );
        assert_eq!(family_usage(&session, bounded), 1);
        assert_eq!(family_usage(&session, other), 3);
        assert_eq!(
            session.known_prefix_count(),
            4,
            "aggregate still counts all"
        );
    }
}

/// Mutant: tearing down under `warning`, or dropping the per-scope latch,
/// breaks the alive/once assertions; a missing family scope label leaves the
/// counter absent.
#[tokio::test]
async fn family_limit_warning_reports_once_and_keeps_accepting() {
    for family in PrefixLimitFamily::ALL {
        let config = family_config(family, 2, MaxPrefixAction::Warning);
        let (mut session, mut rib_rx, mut notify_rx, _server) = notifying_session(config).await;
        install_family_session(&mut session, family, false);

        session.process_update(announce(family, &[1])).await;
        assert!(notify_rx.try_recv().is_err(), "{family:?} below the bound");
        session.process_update(announce(family, &[2, 3])).await;
        assert!(
            session.read_half.is_some(),
            "{family:?} warning never tears down"
        );
        assert_eq!(
            family_usage(&session, family),
            3,
            "{family:?} keeps accepting"
        );
        assert_eq!(drain_delivered_announcements(&mut rib_rx), 3, "{family:?}");
        assert!(
            matches!(
                notify_rx.try_recv(),
                Ok(SessionNotification::MaxPrefixWarning { scope, usage: 3, bound: 2, .. })
                    if scope == family.label()
            ),
            "{family:?}"
        );
        session.process_update(announce(family, &[4])).await;
        assert!(
            notify_rx.try_recv().is_err(),
            "{family:?} warns once per crossing"
        );
        assert_eq!(
            counter_value(
                &session.metrics,
                "bgp_max_prefix_warning_total",
                &session.peer_label,
                family.label()
            ),
            Some(1.0),
            "{family:?}"
        );
    }
}

/// Mutant: skipping the family admission seam installs the over-limit route
/// (usage 3, delivered to the RIB); blocking already-accepted identities drops
/// the attribute change; never ending the episode sends no ROUTE-REFRESH.
#[tokio::test]
async fn family_limit_block_withholds_net_new_routes_without_reset() {
    for family in PrefixLimitFamily::ALL {
        let config = family_config(family, 2, MaxPrefixAction::Block);
        let (mut session, mut rib_rx, mut notify_rx, mut server) = notifying_session(config).await;
        install_family_session(&mut session, family, false);
        let scope = MaxPrefixScope::Family(family);

        session.process_update(announce(family, &[1, 2])).await;
        assert_eq!(drain_delivered_announcements(&mut rib_rx), 2, "{family:?}");

        // Net-new third route is withheld; an attribute refresh of an
        // accepted route in the same UPDATE still passes.
        session.process_update(announce(family, &[1, 3])).await;
        assert_eq!(family_usage(&session, family), 2, "{family:?} withheld");
        assert_eq!(
            drain_delivered_announcements(&mut rib_rx),
            1,
            "{family:?}: only the accepted identity reaches the RIB"
        );
        assert!(session.read_half.is_some(), "{family:?} block never resets");
        assert!(
            notify_rx.try_recv().is_err(),
            "{family:?} block never latches"
        );
        assert!(session.max_prefix_scope_blocking(scope), "{family:?}");
        assert_max_prefix_gauge(
            &session,
            "bgp_max_prefix_blocking",
            family.label(),
            Some(1.0),
        );
        assert_eq!(
            counter_value(
                &session.metrics,
                "bgp_max_prefix_blocked_total",
                &session.peer_label,
                family.label()
            ),
            Some(1.0),
            "{family:?}"
        );

        // A withdrawal frees the slot: the episode ends with one refresh for
        // this family and the replayed route is admitted.
        session
            .process_update(family_update(family, &[], &[(1, 0)], false))
            .await;
        assert!(!session.max_prefix_scope_blocking(scope), "{family:?}");
        let refresh = loop {
            if let Message::RouteRefresh(rr) = read_single_bgp_message(&mut server).await {
                break rr;
            }
        };
        let (afi, safi) = family.afi_safi();
        assert_eq!(
            (refresh.afi_raw, refresh.safi_raw),
            (afi as u16, safi as u8),
            "{family:?}"
        );
        session.process_update(announce(family, &[3])).await;
        assert_eq!(
            family_usage(&session, family),
            2,
            "{family:?} replay admitted"
        );
        assert_eq!(drain_delivered_announcements(&mut rib_rx), 1, "{family:?}");
    }
}

/// Mutant: counting Add-Path paths (the aggregate's VPN/labeled rule) trips
/// the bound on the second path of one route and blocks it under `block`;
/// dropping the identity refcount releases the slot on the first withdrawal.
#[tokio::test]
async fn family_limit_counts_unique_routes_under_add_path() {
    for family in [
        PrefixLimitFamily::L3vpnIpv4,
        PrefixLimitFamily::L3vpnIpv6,
        PrefixLimitFamily::Ipv4LabeledUnicast,
        PrefixLimitFamily::Ipv6LabeledUnicast,
    ] {
        for action in [MaxPrefixAction::Shutdown, MaxPrefixAction::Block] {
            let config = family_config(family, 1, action);
            let (mut session, mut rib_rx, _notify_rx, _server) = notifying_session(config).await;
            install_family_session(&mut session, family, true);

            session
                .process_update(family_update(family, &[(1, 11), (1, 22)], &[], true))
                .await;
            assert!(session.read_half.is_some(), "{family:?} {action:?}");
            assert_eq!(family_usage(&session, family), 1, "{family:?} {action:?}");
            assert_eq!(session.known_prefix_count(), 2, "aggregate counts paths");
            assert_eq!(drain_delivered_announcements(&mut rib_rx), 2);

            session
                .process_update(family_update(family, &[], &[(1, 11)], true))
                .await;
            assert_eq!(
                family_usage(&session, family),
                1,
                "{family:?} one path left"
            );
            session
                .process_update(family_update(family, &[], &[(1, 22)], true))
                .await;
            assert_eq!(
                family_usage(&session, family),
                0,
                "{family:?} last path gone"
            );
        }
    }
}

/// Mutant: skipping the family bounds in the runtime-apply enforcement keeps
/// a quiet session above a lowered bound; leaving the removed bound's series
/// publishes a stale limit.
#[tokio::test]
async fn runtime_family_limit_lowering_enforces_and_removal_drops_series() {
    let family = PrefixLimitFamily::L2vpnEvpn;
    let config = family_config(family, 10, MaxPrefixAction::Shutdown);
    let (mut session, _rib_rx, _notify_rx, mut server) = notifying_session(config).await;
    install_family_session(&mut session, family, false);
    session.process_update(announce(family, &[1, 2, 3])).await;
    assert_max_prefix_gauge(&session, "bgp_max_prefix_limit", "l2vpn_evpn", Some(10.0));
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "l2vpn_evpn", Some(3.0));

    let update = |session: &PeerSession, limit: Option<u32>| {
        let mut limits = session.config.max_prefixes_family;
        limits.0[family as usize] = limit;
        crate::handle::PeerRuntimeConfigUpdate {
            max_prefixes: None,
            max_prefixes_ipv4: None,
            max_prefixes_ipv6: None,
            max_prefixes_received_ipv4: None,
            max_prefixes_received_ipv6: None,
            max_prefixes_family: limits,
            max_prefix_action: session.config.max_prefix_action,
            max_prefix_warning_percent: None,
            gr_stale_routes_time: session.config.gr_stale_routes_time,
            gr_peer_restart_time_max: session.config.gr_peer_restart_time_max,
            local_ipv6_nexthop: session.config.local_ipv6_nexthop,
            remove_private_as: session.config.remove_private_as,
        }
    };

    let (reply, _done) = oneshot::channel();
    let config = Box::new(update(&session, None));
    assert_eq!(
        session
            .handle_command(PeerCommand::UpdateRuntimeConfig { config, reply })
            .await,
        ControlFlow::Continue(())
    );
    assert_max_prefix_gauge(&session, "bgp_max_prefix_limit", "l2vpn_evpn", None);
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "l2vpn_evpn", None);

    let (reply, _done) = oneshot::channel();
    let config = Box::new(update(&session, Some(2)));
    assert_eq!(
        session
            .handle_command(PeerCommand::UpdateRuntimeConfig { config, reply })
            .await,
        ControlFlow::Continue(())
    );
    assert!(
        session.read_half.is_none(),
        "lowering below the count enforces on apply"
    );
    let notif = read_until_notification(&mut server).await;
    assert_eq!(
        notif.data.as_ref(),
        max_prefix_cease_data(Afi::L2Vpn, Safi::Evpn, 2).as_slice()
    );
}

/// Mutant: sweeping `known_vpn` directly at `EoRR` (bypassing the per-family
/// counter) leaves VPN-IPv4 usage at 2 and trips the bound on the next route.
#[tokio::test]
async fn eorr_reconciles_family_accounting_before_later_check() {
    let family = PrefixLimitFamily::L3vpnIpv4;
    let config = family_config(family, 2, MaxPrefixAction::Shutdown);
    let (mut session, _rib_rx, _notify_rx, _server) = notifying_session(config).await;
    install_family_session(&mut session, family, false);

    session.process_update(announce(family, &[1, 2])).await;
    session.begin_refresh_accounting(Afi::Ipv4, Safi::MplsVpn);
    session.process_update(announce(family, &[1])).await;
    session.end_refresh_accounting(Afi::Ipv4, Safi::MplsVpn);
    assert_eq!(family_usage(&session, family), 1, "omitted route swept");
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", family.label(), Some(1.0));

    session.process_update(announce(family, &[3])).await;
    assert!(
        session.read_half.is_some(),
        "the swept slot is free: two routes fit a bound of two"
    );
    assert_eq!(family_usage(&session, family), 2);
}

/// Mutant: sending bare Cease/1 under the negotiated N-bit lets the peer keep
/// the over-limit routes as stale; dropping the encapsulated RFC 4486 data
/// loses the family that tripped.
#[tokio::test]
async fn family_limit_under_notification_gr_sends_hard_reset_wrapping_cease_data() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 1;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::L2Vpn, Safi::Evpn)];
    peer_config.graceful_restart = true;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.max_prefixes_family.0[PrefixLimitFamily::L2vpnEvpn as usize] = Some(1);
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let mut session = PeerSession::new_with_identity_and_lifecycle(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::primary(81),
    );
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    let mut open = notification_gr_open(false);
    open.capabilities.push(Capability::MultiProtocol {
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    });
    session.drive_fsm(Event::OpenReceived(open)).await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    let negotiated = session.negotiated.as_ref().unwrap();
    assert!(negotiated.peer_notification_gr);
    assert!(
        negotiated
            .negotiated_families
            .contains(&(Afi::L2Vpn, Safi::Evpn))
    );
    while rib_rx.try_recv().is_ok() {}

    let family = PrefixLimitFamily::L2vpnEvpn;
    session.process_update(announce(family, &[1])).await;
    assert!(session.read_half.is_some(), "at the bound");
    session.process_update(announce(family, &[2])).await;

    let notification = read_until_notification(&mut server).await;
    assert_eq!(notification.code, NotificationCode::Cease);
    assert_eq!(notification.subcode, cease_subcode::HARD_RESET);
    // Cease (6), Maximum Number of Prefixes Reached (1), AFI 25, SAFI 70,
    // bound 1.
    assert_eq!(
        notification.data.as_ref(),
        [6, 1, 0x00, 0x19, 0x46, 0x00, 0x00, 0x00, 0x01].as_slice()
    );
    let mut down = None;
    while let Ok(update) = rib_rx.try_recv() {
        if matches!(
            update,
            RibUpdate::PeerDown { .. } | RibUpdate::PeerGracefulRestart { .. }
        ) {
            down = Some(update);
        }
    }
    assert!(
        matches!(down, Some(RibUpdate::PeerDown { .. })),
        "Hard Reset must not retain the over-limit routes through GR"
    );
}

/// Mutant: leaving RFC 7606 treat-as-withdraw outside the family accounting
/// keeps EVPN usage at the bound, so the block episode never ends and the
/// family is never refreshed.
#[tokio::test]
async fn evpn_treat_as_withdraw_releases_family_slots_and_ends_block() {
    let family = PrefixLimitFamily::L2vpnEvpn;
    let config = family_config(family, 2, MaxPrefixAction::Block);
    let (mut session, mut rib_rx, _notify_rx, mut server) = notifying_session(config).await;
    install_family_session(&mut session, family, false);
    let scope = MaxPrefixScope::Family(family);
    let good = make_smet_route(0xf2).route;
    let sibling = EvpnRoute::Imet(rustbgpd_wire::EvpnImet {
        rd: "65000:100".parse().unwrap(),
        ethernet_tag: EthernetTagId(100),
        originator_ip: "192.0.2.10".parse().unwrap(),
    });

    session
        .process_update(smet_update(vec![good, sibling.clone()]))
        .await;
    assert_eq!(family_usage(&session, family), 2);
    session.process_update(announce(family, &[3])).await;
    assert!(
        session.max_prefix_scope_blocking(scope),
        "third route withheld"
    );
    rfc7606_drain(&mut rib_rx);

    // IPv6 (S,G) flags 0xf1 are invalid: the whole UPDATE is treated as a
    // withdrawal of both previously accepted keys.
    session
        .process_update(smet_update(vec![make_smet_route(0xf1).route, sibling]))
        .await;
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_eq!(family_usage(&session, family), 0, "both slots released");
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "l2vpn_evpn", Some(0.0));
    assert!(!session.max_prefix_scope_blocking(scope), "episode ended");
    let refresh = loop {
        if let Message::RouteRefresh(rr) = read_single_bgp_message(&mut server).await {
            break rr;
        }
    };
    assert_eq!(
        (refresh.afi_raw, refresh.safi_raw),
        (Afi::L2Vpn as u16, Safi::Evpn as u8)
    );
}
