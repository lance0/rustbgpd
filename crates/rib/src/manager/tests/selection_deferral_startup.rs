use super::*;
use crate::update::{ExactExportKey, OutboundRouteUpdate};

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 4);
const SOURCE_SESSION: u64 = 14;
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const EVPN: (Afi, Safi) = (Afi::L2Vpn, Safi::Evpn);
const RTC: (Afi, Safi) = (Afi::Ipv4, Safi::RtConstrain);

#[derive(Clone, Copy, Debug)]
enum Family {
    FlowSpec(Afi),
    Evpn,
    Vpn(Afi),
    Labeled(Afi),
    BgpLs,
    Rtc,
}

impl Family {
    fn afi_safi(self) -> (Afi, Safi) {
        match self {
            Self::FlowSpec(afi) => (afi, Safi::FlowSpec),
            Self::Evpn => EVPN,
            Self::Vpn(afi) => (afi, Safi::MplsVpn),
            Self::Labeled(afi) => (afi, Safi::LabeledUnicast),
            Self::BgpLs => (Afi::BgpLs, Safi::BgpLs),
            Self::Rtc => RTC,
        }
    }

    fn receive(self, manager: &mut RibManager) -> ExactExportKey {
        let peer = peer_v4(SOURCE);
        let (update, key) = match self {
            Self::FlowSpec(afi) => {
                let mut route = make_flowspec_route(SOURCE);
                if afi == Afi::Ipv6 {
                    route.afi = afi;
                    route.rule.components =
                        vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
                            rustbgpd_wire::FlowSpecPrefix::V6(rustbgpd_wire::Ipv6PrefixOffset {
                                prefix: Ipv6Prefix::new("2001:db8:44::".parse().unwrap(), 64),
                                offset: 0,
                            }),
                        )];
                }
                let key = ExactExportKey::FlowSpec(route.selection_key());
                (received(Vec::new(), vec![route]), key)
            }
            Self::Evpn => {
                let route = make_evpn_imet(SOURCE, 44);
                let key = ExactExportKey::Evpn(route.key());
                (received(vec![route], Vec::new()), key)
            }
            Self::Vpn(afi) => {
                let mut route = make_vpn_rib_route(SOURCE, 44, 100, 100);
                if afi == Afi::Ipv6 {
                    route.nlri.prefix =
                        VpnPrefix::v6("2001:db8:44::".parse().unwrap(), 64).unwrap();
                    route.next_hop = "2001:db8::4".parse().unwrap();
                }
                let key = ExactExportKey::Vpn(route.key());
                (
                    RibUpdate::VpnRoutesReceived {
                        peer,
                        session_id: SOURCE_SESSION,
                        announced: vec![route],
                        withdrawn: vec![],
                    },
                    key,
                )
            }
            Self::Labeled(afi) => {
                let mut route = make_labeled_rib_route(SOURCE, 44, 100, 100);
                if afi == Afi::Ipv6 {
                    route.nlri.prefix =
                        Prefix::V6(Ipv6Prefix::new("2001:db8:44::".parse().unwrap(), 64));
                    route.next_hop = "2001:db8::4".parse().unwrap();
                }
                let key = ExactExportKey::Labeled(route.key());
                (
                    RibUpdate::LabeledRoutesReceived {
                        peer,
                        session_id: SOURCE_SESSION,
                        announced: vec![route],
                        withdrawn: vec![],
                    },
                    key,
                )
            }
            Self::BgpLs => {
                let route = make_bgpls_route(SOURCE, 44, 100);
                let key = ExactExportKey::BgpLs(route.key());
                (
                    RibUpdate::BgpLsRoutesReceived {
                        peer,
                        session_id: SOURCE_SESSION,
                        announced: vec![route],
                        withdrawn: vec![],
                    },
                    key,
                )
            }
            Self::Rtc => {
                let route = make_rtc_rib_route(SOURCE, 44, 100);
                let key = ExactExportKey::Rtc(route.key());
                (
                    RibUpdate::RtcRoutesReceived {
                        peer,
                        session_id: SOURCE_SESSION,
                        announced: vec![route],
                        withdrawn: vec![],
                    },
                    key,
                )
            }
        };
        manager.handle_update(update);
        drain_route_chunks(manager);
        key
    }
}

fn received(
    evpn_announced: Vec<EvpnRibRoute>,
    flowspec_announced: Vec<FlowSpecRoute>,
) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: SOURCE_SESSION,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced,
        flowspec_withdrawn: vec![],
        evpn_announced,
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

fn connect(
    manager: &mut RibManager,
    address: Ipv4Addr,
    session_id: u64,
    families: &[(Afi, Safi)],
    waiter: bool,
    private: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    let export_policy = private.then(|| {
        let mut chain =
            deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))]);
        let entry = &mut chain.policies[0].policy.entries[0];
        entry.prefix = None;
        entry.match_neighbor_set = Some(rustbgpd_policy::NeighborSetMatch {
            addresses: vec![],
            remote_asns: vec![u32::MAX],
            peer_groups: vec![],
        });
        rustbgpd_policy::PolicyChain::from_named(chain.policies)
    });
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: if waiter { families.to_vec() } else { vec![] },
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: address,
        outbound_tx,
        export_policy,
        sendable_families: families.to_vec(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

fn drain(rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<OutboundRouteUpdate> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

fn announced(update: &OutboundRouteUpdate) -> Vec<ExactExportKey> {
    update
        .flowspec_announce
        .iter()
        .map(|route| ExactExportKey::FlowSpec(route.selection_key()))
        .chain(
            update
                .evpn_announce
                .iter()
                .map(|route| ExactExportKey::Evpn(route.key())),
        )
        .chain(
            update
                .vpn_announce
                .iter()
                .map(|route| ExactExportKey::Vpn(route.key())),
        )
        .chain(
            update
                .labeled_announce
                .iter()
                .map(|route| ExactExportKey::Labeled(route.key())),
        )
        .chain(
            update
                .bgpls_announce
                .iter()
                .map(|route| ExactExportKey::BgpLs(route.key())),
        )
        .chain(
            update
                .rtc_announce
                .iter()
                .map(|route| ExactExportKey::Rtc(route.key())),
        )
        .collect()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one startup transcript pins identical late-join completion rules for every typed family"
)]
fn dormant_typed_selection_replays_unchanged_rows_before_late_initial_eor() {
    for family in [
        Family::FlowSpec(Afi::Ipv4),
        Family::FlowSpec(Afi::Ipv6),
        Family::Evpn,
        Family::Vpn(Afi::Ipv4),
        Family::Vpn(Afi::Ipv6),
        Family::Labeled(Afi::Ipv4),
        Family::Labeled(Afi::Ipv6),
        Family::BgpLs,
        Family::Rtc,
    ] {
        for private in [false, true] {
            let afi_safi = family.afi_safi();
            let (_tx, rx) = mpsc::channel(8);
            let mut manager = RibManager::new(
                rx,
                dummy_query_rx(),
                None,
                Some(Ipv4Addr::new(10, 255, 0, 254)),
                BgpMetrics::new(),
            )
            .with_selection_deferral(SelectionDeferralConfig {
                timeout: Duration::from_secs(60),
                waiters: vec![SelectionDeferralWaiterConfig {
                    peer: peer_v4(WAITER),
                    families: vec![afi_safi],
                }],
            });
            let observer = Ipv4Addr::new(192, 0, 2, 5);
            let mut old_rx = connect(&mut manager, observer, 15, &[afi_safi], false, private);
            let initial = drain(&mut old_rx);
            assert_eq!(
                initial
                    .iter()
                    .filter(|update| update.end_of_rib.contains(&afi_safi))
                    .count(),
                1,
                "{family:?}, private={private}"
            );
            let mut expected: HashSet<_> = initial.iter().flat_map(announced).collect();
            let _source_rx = connect(
                &mut manager,
                SOURCE,
                SOURCE_SESSION,
                &[afi_safi],
                false,
                false,
            );
            let received_key = family.receive(&mut manager);
            let updates = drain(&mut old_rx);
            let received_keys: Vec<_> = updates.iter().flat_map(announced).collect();
            assert_eq!(
                received_keys,
                vec![received_key.clone()],
                "{family:?}, private={private}"
            );
            expected.extend(received_keys);
            assert_eq!(
                expected.len(),
                if matches!(family, Family::Rtc) { 2 } else { 1 }
            );
            assert!(!manager.selection_deferred(afi_safi));

            let _waiter_rx = connect(&mut manager, WAITER, 11, &[afi_safi], true, false);
            assert!(manager.selection_deferred(afi_safi));
            let late = Ipv4Addr::new(192, 0, 2, 6);
            let mut late_rx = connect(&mut manager, late, 16, &[afi_safi], false, private);
            assert!(
                drain(&mut late_rx).is_empty(),
                "the late initial table must wait: {family:?}, private={private}"
            );
            if matches!(family, Family::Evpn) {
                assert!(
                    manager.evpn_grouped_member_of(peer_v4(late)).is_none(),
                    "exercise production's private EVPN path"
                );
            }
            if matches!(family, Family::Vpn(_)) {
                assert_eq!(manager.grouped_member_of(peer_v4(late)).is_some(), !private);
            }
            drain(&mut old_rx);
            manager.handle_update(RibUpdate::EndOfRib {
                peer: peer_v4(WAITER),
                session_id: 11,
                afi: afi_safi.0,
                safi: afi_safi.1,
            });
            assert!(!manager.selection_convergence_held(afi_safi));
            let mut delivered = HashSet::new();
            let mut eors = 0;
            for update in drain(&mut late_rx) {
                for key in announced(&update) {
                    assert!(
                        delivered.insert(key),
                        "duplicate late announcement: {family:?}, private={private}"
                    );
                }
                if update.end_of_rib.contains(&afi_safi) {
                    eors += 1;
                    assert_eq!(
                        delivered, expected,
                        "EoR overtook frozen rows: {family:?}, private={private}"
                    );
                }
                assert!(
                    update.flowspec_withdraw.is_empty()
                        && update.evpn_withdraw.is_empty()
                        && update.vpn_withdraw.is_empty()
                        && update.labeled_withdraw.is_empty()
                        && update.bgpls_withdraw.is_empty()
                        && update.rtc_withdraw.is_empty()
                );
            }
            assert_eq!(delivered, expected, "{family:?}, private={private}");
            assert_eq!(eors, 1, "{family:?}, private={private}");
            assert!(
                drain(&mut old_rx).iter().all(|update| {
                    !update.end_of_rib.contains(&afi_safi) && announced(update).is_empty()
                }),
                "the older session already received its unchanged table and initial EoR"
            );
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one startup and RTC transcript checks the old advertised row and late initial marker together"
)]
fn dormant_private_evpn_membership_change_is_reconciled_at_selection_release() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 255, 0, 254)),
        BgpMetrics::new(),
    )
    .with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer_v4(WAITER),
            families: vec![EVPN],
        }],
    });
    let observer = Ipv4Addr::new(192, 0, 2, 5);
    let mut observer_rx = connect(&mut manager, observer, 15, &[EVPN, RTC], false, false);
    let membership = make_rtc_rib_route(observer, 100, 100);
    let membership_key = membership.key();
    manager.handle_update(RibUpdate::RtcRoutesReceived {
        peer: peer_v4(observer),
        session_id: 15,
        announced: vec![membership],
        withdrawn: vec![],
    });
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(observer),
        session_id: 15,
        afi: RTC.0,
        safi: RTC.1,
    });
    assert_eq!(
        drain(&mut observer_rx)
            .iter()
            .filter(|update| update.end_of_rib.contains(&EVPN))
            .count(),
        1
    );
    let _source_rx = connect(&mut manager, SOURCE, SOURCE_SESSION, &[EVPN], false, false);
    let mut route = make_evpn_imet(SOURCE, 100);
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.push(PathAttribute::ExtendedCommunities(vec![rt(100)]));
    });
    let key = route.key();
    manager.handle_update(received(vec![route], Vec::new()));
    drain_route_chunks(&mut manager);
    assert_eq!(
        drain(&mut observer_rx)
            .iter()
            .flat_map(|update| update.evpn_announce.iter().map(EvpnRibRoute::key))
            .collect::<Vec<_>>(),
        vec![key]
    );
    assert_eq!(manager.adj_ribs_out[&peer_v4(observer)].evpn_len(), 1);
    assert!(manager.evpn_grouped_member_of(peer_v4(observer)).is_none());

    let _waiter_rx = connect(&mut manager, WAITER, 11, &[EVPN], true, false);
    let late = Ipv4Addr::new(192, 0, 2, 6);
    let mut late_rx = connect(&mut manager, late, 16, &[EVPN], false, false);
    assert!(drain(&mut late_rx).is_empty());
    manager.handle_update(RibUpdate::RtcRoutesReceived {
        peer: peer_v4(observer),
        session_id: 15,
        announced: vec![],
        withdrawn: vec![membership_key],
    });
    assert!(manager.selection_deferred(EVPN));
    assert!(
        drain(&mut observer_rx).is_empty(),
        "the existing advertised row remains frozen during the hold"
    );
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 11,
        afi: EVPN.0,
        safi: EVPN.1,
    });
    let old_updates = drain(&mut observer_rx);
    assert_eq!(
        old_updates
            .iter()
            .flat_map(|update| update.evpn_withdraw.iter().copied())
            .collect::<Vec<_>>(),
        vec![key]
    );
    assert!(
        old_updates
            .iter()
            .all(|update| update.evpn_announce.is_empty() && !update.end_of_rib.contains(&EVPN))
    );
    assert_eq!(manager.adj_ribs_out[&peer_v4(observer)].evpn_len(), 0);
    let mut late_keys = Vec::new();
    let mut eors = 0;
    for update in drain(&mut late_rx) {
        late_keys.extend(update.evpn_announce.iter().map(EvpnRibRoute::key));
        if update.end_of_rib.contains(&EVPN) {
            eors += 1;
            assert_eq!(
                late_keys,
                vec![key],
                "the unchanged row precedes the late peer's EoR"
            );
        }
        assert_eq!(update.evpn_withdraw, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
    }
    assert_eq!(late_keys, vec![key]);
    assert_eq!(eors, 1);
}
