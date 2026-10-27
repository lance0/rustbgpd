use std::mem::size_of;
use std::sync::Mutex;

use super::*;
use crate::manager::selection_deferral::{
    SelectionDeferralReleaseReason, SelectionDeferralTransition,
};

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const UNICAST: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);

#[derive(Clone, Copy, Debug)]
enum Recorder {
    Unicast,
    FlowSpec,
    Evpn,
    Vpn,
    Labeled,
    BgpLs,
    Rtc,
}

impl Recorder {
    fn family(self) -> (Afi, Safi) {
        match self {
            Self::Unicast => UNICAST,
            Self::FlowSpec => (Afi::Ipv4, Safi::FlowSpec),
            Self::Evpn => (Afi::L2Vpn, Safi::Evpn),
            Self::Vpn => (Afi::Ipv4, Safi::MplsVpn),
            Self::Labeled => (Afi::Ipv4, Safi::LabeledUnicast),
            Self::BgpLs => (Afi::BgpLs, Safi::BgpLs),
            Self::Rtc => (Afi::Ipv4, Safi::RtConstrain),
        }
    }

    fn stage(self) -> &'static str {
        match self {
            Self::Unicast => "selection_record_unicast",
            Self::FlowSpec => "selection_record_flowspec",
            Self::Evpn => "selection_record_evpn",
            Self::Vpn => "selection_record_vpn",
            Self::Labeled => "selection_record_labeled",
            Self::BgpLs => "selection_record_bgpls",
            Self::Rtc => "selection_record_rtc",
        }
    }

    fn has_sibling_family(self) -> bool {
        !matches!(self, Self::Evpn | Self::Rtc)
    }

    fn record(self, manager: &mut RibManager, index: u32) {
        match self {
            Self::Unicast => {
                manager.record_deferred_unicast(&HashSet::from([recording_prefix(index, false)]));
            }
            Self::FlowSpec => manager.record_deferred_flowspec(&HashSet::from([
                recording_flowspec(index, false).selection_key(),
            ])),
            Self::Evpn => {
                manager.record_deferred_evpn(&HashSet::from([make_evpn_imet(SOURCE, index).key()]));
            }
            Self::Vpn => {
                manager.record_deferred_vpn(&HashSet::from([recording_vpn(index, false).key()]));
            }
            Self::Labeled => manager
                .record_deferred_labeled(&HashSet::from([recording_labeled(index, false).key()])),
            Self::BgpLs => {
                manager
                    .record_deferred_bgpls(&HashSet::from([recording_bgpls(index, false).key()]));
            }
            Self::Rtc => manager.record_deferred_rtc(&HashSet::from([make_rtc_rib_route(
                SOURCE,
                u16::try_from(index).unwrap(),
                100,
            )
            .key()])),
        }
    }

    fn receive(self, manager: &mut RibManager, include_sibling: bool) {
        let peer = peer_v4(SOURCE);
        let sibling_count = if include_sibling && self.has_sibling_family() {
            3
        } else {
            0
        };
        let inputs: Vec<_> = (0..4)
            .map(|index| (index, false))
            .chain((4..4 + sibling_count).map(|index| (index, true)))
            .collect();
        let update = match self {
            Self::Unicast => recording_received(
                inputs
                    .iter()
                    .map(|&(index, sibling)| recording_unicast(index, sibling))
                    .collect(),
                Vec::new(),
                Vec::new(),
            ),
            Self::FlowSpec => recording_received(
                Vec::new(),
                inputs
                    .iter()
                    .map(|&(index, sibling)| recording_flowspec(index, sibling))
                    .collect(),
                Vec::new(),
            ),
            Self::Evpn => recording_received(
                Vec::new(),
                Vec::new(),
                inputs
                    .iter()
                    .map(|&(index, _)| make_evpn_imet(SOURCE, index))
                    .collect(),
            ),
            Self::Vpn => RibUpdate::VpnRoutesReceived {
                peer,
                session_id: 0,
                announced: inputs
                    .iter()
                    .map(|&(index, sibling)| recording_vpn(index, sibling))
                    .collect(),
                withdrawn: Vec::new(),
            },
            Self::Labeled => RibUpdate::LabeledRoutesReceived {
                peer,
                session_id: 0,
                announced: inputs
                    .iter()
                    .map(|&(index, sibling)| recording_labeled(index, sibling))
                    .collect(),
                withdrawn: Vec::new(),
            },
            Self::BgpLs => RibUpdate::BgpLsRoutesReceived {
                peer,
                session_id: 0,
                announced: inputs
                    .iter()
                    .map(|&(index, sibling)| recording_bgpls(index, sibling))
                    .collect(),
                withdrawn: Vec::new(),
            },
            Self::Rtc => RibUpdate::RtcRoutesReceived {
                peer,
                session_id: 0,
                announced: inputs
                    .iter()
                    .map(|&(index, _)| {
                        make_rtc_rib_route(SOURCE, u16::try_from(index).unwrap(), 100)
                    })
                    .collect(),
                withdrawn: Vec::new(),
            },
        };
        manager.handle_update(update);
        drain_route_chunks(manager);
    }
}

fn recording_received(
    announced: Vec<Route>,
    flowspec_announced: Vec<FlowSpecRoute>,
    evpn_announced: Vec<EvpnRibRoute>,
) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced,
        withdrawn: Vec::new(),
        flowspec_announced,
        flowspec_withdrawn: Vec::new(),
        evpn_announced,
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    }
}

fn recording_prefix(index: u32, sibling: bool) -> Prefix {
    if sibling {
        Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::from((0x2001_0db8_u128 << 96) | u128::from(index)),
            128,
        ))
    } else {
        make_indexed_route(index, SOURCE).prefix
    }
}

fn recording_flowspec(index: u32, sibling: bool) -> FlowSpecRoute {
    let mut route = make_flowspec_route(SOURCE);
    let prefix = match recording_prefix(index, sibling) {
        Prefix::V4(prefix) => rustbgpd_wire::FlowSpecPrefix::V4(prefix),
        Prefix::V6(prefix) => {
            route.afi = Afi::Ipv6;
            rustbgpd_wire::FlowSpecPrefix::V6(rustbgpd_wire::Ipv6PrefixOffset { prefix, offset: 0 })
        }
    };
    route.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(prefix)];
    route
}

fn recording_unicast(index: u32, sibling: bool) -> Route {
    let mut route = match recording_prefix(index, sibling) {
        Prefix::V4(prefix) => make_route(prefix, SOURCE),
        Prefix::V6(prefix) => make_v6_route(prefix, Ipv6Addr::LOCALHOST),
    };
    set_peer(&mut route, peer_v4(SOURCE));
    route
}

fn recording_vpn(index: u32, sibling: bool) -> VpnRibRoute {
    let mut route = make_vpn_rib_route(SOURCE, 0, 100, 100);
    route.nlri.prefix = match recording_prefix(index, sibling) {
        Prefix::V4(prefix) => VpnPrefix::v4(prefix.addr, prefix.len).unwrap(),
        Prefix::V6(prefix) => {
            route.next_hop = IpAddr::V6(Ipv6Addr::LOCALHOST);
            VpnPrefix::v6(prefix.addr, prefix.len).unwrap()
        }
    };
    route
}

fn recording_labeled(index: u32, sibling: bool) -> crate::route::LabeledRibRoute {
    let mut route = make_labeled_rib_route(SOURCE, 0, 100, 100);
    route.nlri.prefix = recording_prefix(index, sibling);
    if sibling {
        route.next_hop = IpAddr::V6(Ipv6Addr::LOCALHOST);
    }
    route
}

fn recording_bgpls(index: u32, sibling: bool) -> BgpLsRibRoute {
    let mut route = make_bgpls_route(SOURCE, 0, 100);
    route.nlri.payload = index.to_be_bytes().to_vec().into();
    if sibling {
        route.family = BgpLsFamily::LinkStateVpn;
        route.nlri.route_distinguisher = Some([0, 0, 0, 0, 0, 0, 0, 1]);
    }
    route
}

fn recording_manager(families: Vec<(Afi, Safi)>) -> RibManager {
    let held_families = families.clone();
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_mins(1),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(SOURCE),
                families,
            }],
        });
    super::arm_selection_waiter(&mut manager, peer_v4(SOURCE), &held_families);
    for (octet, is_stale, is_llgr_stale) in [(253, true, false), (254, false, true)] {
        let mut route = make_route(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, octet), 32), SOURCE);
        route.is_stale = is_stale;
        route.is_llgr_stale = is_llgr_stale;
        let prefix = route.prefix;
        manager
            .ribs
            .entry(peer_v4(SOURCE))
            .or_insert_with(|| AdjRibIn::new(peer_v4(SOURCE)))
            .insert(route.clone());
        manager.register_unicast_announcer(peer_v4(SOURCE), prefix);
        assert!(manager.loc_rib.recompute(prefix, std::iter::once(&route)));
    }
    manager
}

fn route_counts(manager: &RibManager) -> [usize; 7] {
    let rib = &manager.ribs[&peer_v4(SOURCE)];
    [
        rib.len(),
        rib.flowspec_len(),
        rib.evpn_len(),
        rib.vpn_len(),
        rib.labeled_len(),
        rib.bgpls_len(),
        rib.rtc_len(),
    ]
}

fn assert_original_stale_counts(manager: &RibManager) {
    let rib = &manager.ribs[&peer_v4(SOURCE)];
    let expected = vec![(
        UNICAST,
        crate::adj_rib_in::StaleRouteCounts {
            stale: 1,
            llgr_stale: 1,
        },
    )];
    assert_eq!(rib.maintained_stale_route_counts(), expected);
    assert_eq!(rib.scanned_stale_route_counts(), expected);
    assert_eq!(rib.retained_stale_count(), 2);
}

/// Observe only the actual caller's owner. No readiness owner is installed
/// by this fixture: the first named callback must answer before the next.
fn observe_recording(
    manager: &mut RibManager,
    expected_stage: &'static str,
    work: impl FnOnce(&mut RibManager),
) -> Vec<usize> {
    let (tx, rx) = mpsc::channel(1);
    let (query_tx, query_rx) = mpsc::channel(1);
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    let (summary_tx, summary_rx) = mpsc::channel(1);
    manager.rx = rx;
    manager.query_rx = query_rx;
    manager.readiness_rx = Some(readiness_rx);
    manager.summary_rx = Some(summary_rx);
    manager.flush_poll_budget = Duration::ZERO;
    let (reply, mutation) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    let (reply, general) = oneshot::channel();
    query_tx
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();
    let (reply, summary) = oneshot::channel();
    summary_tx
        .try_send(crate::RibSummaryQuery::NeighborRibSnapshots {
            peers: Vec::new(),
            comparison: None,
            reply,
            include_retained: false,
        })
        .unwrap();
    let pending = Arc::new(Mutex::new(
        None::<oneshot::Receiver<Result<usize, crate::RibReadinessError>>>,
    ));
    let observed = Arc::new(Mutex::new(Vec::new()));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let pending = Arc::clone(&pending);
        let observed = Arc::clone(&observed);
        let mutation = Mutex::new(mutation);
        let general = Mutex::new(general);
        let summary = Mutex::new(summary);
        move |stage| {
            if stage != expected_stage {
                return;
            }
            assert!(matches!(
                mutation.lock().unwrap().try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                general.lock().unwrap().try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                summary.lock().unwrap().try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            if let Some(mut response) = pending.lock().unwrap().take() {
                observed.lock().unwrap().push(
                    response
                        .try_recv()
                        .expect("the preceding input checkpoint must answer readiness")
                        .unwrap(),
                );
            }
            let (reply, response) = oneshot::channel();
            readiness_tx
                .try_send(crate::RibReadinessQuery::LocRibCount {
                    reply,
                    enqueued: std::time::Instant::now(),
                })
                .unwrap();
            *pending.lock().unwrap() = Some(response);
        }
    }));
    work(manager);
    manager.replacement_readiness_test_hook = None;
    let mut response = pending
        .lock()
        .unwrap()
        .take()
        .expect("the production caller must visit the named ledger checkpoint");
    observed.lock().unwrap().push(
        response
            .try_recv()
            .expect("the final input checkpoint must answer before owner completion")
            .unwrap(),
    );
    Arc::try_unwrap(observed).unwrap().into_inner().unwrap()
}

fn actual_receive_records_with_readiness(recorder: Recorder) {
    for (include_sibling, overflow) in [(false, false), (true, false), (false, true)] {
        if include_sibling && !recorder.has_sibling_family() {
            continue;
        }
        let mut manager = recording_manager(vec![recorder.family()]);
        if overflow {
            manager.set_deferred_selection_limits_for_test(0, usize::MAX);
        }
        let observed = observe_recording(&mut manager, recorder.stage(), |manager| {
            recorder.receive(manager, include_sibling);
        });
        let extra = usize::from(include_sibling && recorder.has_sibling_family()) * 3;
        let mut expected_counts = [2, 0, 0, 0, 0, 0, 0];
        let index = match recorder {
            Recorder::Unicast => 0,
            Recorder::FlowSpec => 1,
            Recorder::Evpn => 2,
            Recorder::Vpn => 3,
            Recorder::Labeled => 4,
            Recorder::BgpLs => 5,
            Recorder::Rtc => 6,
        };
        expected_counts[index] += 4 + extra;
        assert_eq!(route_counts(&manager), expected_counts, "{recorder:?}");
        assert_original_stale_counts(&manager);
        assert_eq!(
            manager
                .deferred_selection_storage_shape_for_test(recorder.family())
                .0,
            if overflow { 0 } else { 4 },
            "only the gated family is retained"
        );
        assert_eq!(
            manager
                .deferred_selection_ledger_state_for_test(recorder.family())
                .1,
            overflow
        );
        let expected = if matches!(recorder, Recorder::Unicast) {
            // Announce and full recompute see the input before selection;
            // distribution sees changed and affected keys afterwards.
            [vec![2; 4 + 2 * extra], vec![2 + extra; 4 + 2 * extra]].concat()
        } else {
            vec![2; 4 + extra]
        };
        assert_eq!(
            observed, expected,
            "{recorder:?}, sibling={include_sibling}, overflow={overflow}"
        );
        assert_eq!(
            manager.loc_rib.len(),
            2 + usize::from(matches!(recorder, Recorder::Unicast)) * extra
        );
    }
}

#[test]
fn actual_unicast_receive_records_with_interior_readiness() {
    actual_receive_records_with_readiness(Recorder::Unicast);
}

#[test]
fn actual_flowspec_receive_records_with_interior_readiness() {
    actual_receive_records_with_readiness(Recorder::FlowSpec);
}

#[test]
fn actual_evpn_receive_records_with_interior_readiness() {
    actual_receive_records_with_readiness(Recorder::Evpn);
}

#[test]
fn actual_vpn_receive_records_with_interior_readiness() {
    actual_receive_records_with_readiness(Recorder::Vpn);
}

#[test]
fn actual_labeled_receive_records_with_interior_readiness() {
    actual_receive_records_with_readiness(Recorder::Labeled);
}

#[test]
fn actual_bgpls_receive_records_with_interior_readiness() {
    actual_receive_records_with_readiness(Recorder::BgpLs);
}

#[test]
fn actual_rtc_receive_records_with_interior_readiness() {
    actual_receive_records_with_readiness(Recorder::Rtc);
}

fn recorder_growth_is_bounded(recorder: Recorder) {
    let mut manager = recording_manager(vec![recorder.family()]);
    crate::fast_hash::assert_growth_bounded(
        recorder.stage(),
        &mut manager,
        |manager, index| recorder.record(manager, index),
        |manager| {
            manager
                .deferred_selection_storage_shape_for_test(recorder.family())
                .1
        },
    );
    let retained = manager.deferred_selection_ledger_state_for_test(recorder.family());
    let shape = manager.deferred_selection_storage_shape_for_test(recorder.family());
    assert_eq!(shape.0, crate::fast_hash::SHARD_SPLIT_AT * 2);
    assert!(!retained.1);
    assert!(retained.0 > 0);
    for index in [0, 1, 16_383, 16_384, 32_767] {
        recorder.record(&mut manager, index);
    }
    assert_eq!(
        manager.deferred_selection_storage_shape_for_test(recorder.family()),
        shape,
        "duplicates do not grow storage"
    );
    assert_eq!(
        manager.deferred_selection_ledger_state_for_test(recorder.family()),
        retained,
        "duplicates consume no identity or logical-byte budget"
    );
    assert_eq!(route_counts(&manager), [2, 0, 0, 0, 0, 0, 0]);
    assert_eq!(manager.loc_rib.len(), 2);
    assert_original_stale_counts(&manager);
}

#[test]
fn unicast_selection_recorder_growth_is_bounded() {
    recorder_growth_is_bounded(Recorder::Unicast);
}

#[test]
fn flowspec_selection_recorder_growth_is_bounded() {
    recorder_growth_is_bounded(Recorder::FlowSpec);
}

#[test]
fn evpn_selection_recorder_growth_is_bounded() {
    recorder_growth_is_bounded(Recorder::Evpn);
}

#[test]
fn vpn_selection_recorder_growth_is_bounded() {
    recorder_growth_is_bounded(Recorder::Vpn);
}

#[test]
fn labeled_selection_recorder_growth_is_bounded() {
    recorder_growth_is_bounded(Recorder::Labeled);
}

#[test]
fn bgpls_selection_recorder_growth_is_bounded() {
    recorder_growth_is_bounded(Recorder::BgpLs);
}

#[test]
fn rtc_selection_recorder_growth_is_bounded() {
    recorder_growth_is_bounded(Recorder::Rtc);
}

fn release_recorded_family(manager: &mut RibManager, family: (Afi, Safi)) {
    manager.apply_selection_deferral_transitions(
        [SelectionDeferralTransition::Release {
            family,
            already_staged: false,
            release_reason: SelectionDeferralReleaseReason::AllEndOfRib,
        }],
        "test recorded-family release",
    );
}

fn overflow_remains_sticky_after_other_family_release(identity_limit: bool) {
    let families = vec![UNICAST, Recorder::Evpn.family(), Recorder::BgpLs.family()];
    let mut manager = recording_manager(families);
    Recorder::Unicast.record(&mut manager, 0);
    Recorder::Evpn.record(&mut manager, 0);
    Recorder::BgpLs.record(&mut manager, 0);
    let prefix_bytes = size_of::<Prefix>();
    let evpn_bytes = size_of::<rustbgpd_wire::EvpnRouteKey>();
    let bgpls_bytes = size_of::<BgpLsRouteKey>() + 4;
    let total = prefix_bytes + evpn_bytes + bgpls_bytes;
    assert_eq!(
        manager.deferred_selection_ledger_state_for_test(UNICAST),
        (total, false)
    );
    manager.set_deferred_selection_limits_for_test(
        if identity_limit { 3 } else { 1_000_000 },
        if identity_limit { usize::MAX } else { total },
    );
    Recorder::Unicast.record(&mut manager, 0);
    assert_eq!(
        manager.deferred_selection_ledger_state_for_test(UNICAST),
        (total, false)
    );
    Recorder::Unicast.record(&mut manager, 1);
    assert_eq!(
        manager.deferred_selection_ledger_state_for_test(UNICAST),
        (total, true)
    );
    release_recorded_family(&mut manager, Recorder::BgpLs.family());
    let remaining = prefix_bytes + evpn_bytes;
    assert_eq!(
        manager.deferred_selection_ledger_state_for_test(UNICAST),
        (remaining, true)
    );
    assert_eq!(
        manager
            .deferred_selection_storage_shape_for_test(Recorder::BgpLs.family())
            .0,
        0
    );
    Recorder::Unicast.record(&mut manager, 1);
    assert_eq!(
        manager.deferred_selection_storage_shape_for_test(UNICAST).0,
        1
    );
    assert_eq!(
        manager.deferred_selection_ledger_state_for_test(UNICAST),
        (remaining, true)
    );
    release_recorded_family(&mut manager, UNICAST);
    assert_eq!(
        manager.deferred_selection_storage_shape_for_test(UNICAST).0,
        0
    );
    assert_eq!(
        manager.deferred_selection_ledger_state_for_test(UNICAST),
        (evpn_bytes, false)
    );
    assert_eq!(
        manager
            .deferred_selection_storage_shape_for_test(Recorder::Evpn.family())
            .0,
        1
    );
    assert!(manager.selection_deferred(Recorder::Evpn.family()));
    assert_eq!(route_counts(&manager), [2, 0, 0, 0, 0, 0, 0]);
    assert_eq!(manager.loc_rib.len(), 2);
    assert_original_stale_counts(&manager);
}

#[test]
fn selection_recording_identity_overflow_is_sticky_across_family_release() {
    overflow_remains_sticky_after_other_family_release(true);
}

#[test]
fn selection_recording_logical_bytes_overflow_is_sticky_across_family_release() {
    overflow_remains_sticky_after_other_family_release(false);
}

fn actual_release_retires_ledger_with_readiness(recorder: Recorder) {
    let mut manager = recording_manager(vec![recorder.family(), UNICAST]);
    Recorder::Unicast.record(&mut manager, 0);
    let count = crate::fast_hash::SHARD_SPLIT_AT + 1;
    for index in 0..u32::try_from(count).unwrap() {
        recorder.record(&mut manager, index);
    }
    manager.set_deferred_selection_limits_for_test(count + 1, usize::MAX);
    recorder.record(&mut manager, u32::try_from(count).unwrap());
    assert!(
        manager
            .deferred_selection_ledger_state_for_test(recorder.family())
            .1
    );
    assert!(manager.replacement_readiness.is_none());
    let observed = observe_recording(&mut manager, "selection_ledger_retirement", |manager| {
        release_recorded_family(manager, recorder.family());
    });
    assert_eq!(
        observed.len(),
        count + 2 * crate::fast_hash::SHARDS + 2,
        "every retained key, shard table and outer box retirement must checkpoint"
    );
    assert!(observed.iter().all(|&count| count == 2));
    assert_eq!(
        manager.deferred_selection_storage_shape_for_test(recorder.family()),
        (0, 0)
    );
    assert_eq!(
        manager.deferred_selection_ledger_state_for_test(recorder.family()),
        (size_of::<Prefix>(), false)
    );
    assert_eq!(
        manager.deferred_selection_storage_shape_for_test(UNICAST).0,
        1
    );
    assert!(manager.selection_deferred(UNICAST));
    assert!(!manager.selection_deferred(recorder.family()));
    assert_eq!(route_counts(&manager), [2, 0, 0, 0, 0, 0, 0]);
    assert_eq!(manager.loc_rib.len(), 2);
    assert_original_stale_counts(&manager);
}

#[test]
fn actual_evpn_release_retires_selection_ledger_with_interior_readiness() {
    actual_release_retires_ledger_with_readiness(Recorder::Evpn);
}

#[test]
fn actual_rtc_release_retires_selection_ledger_with_interior_readiness() {
    actual_release_retires_ledger_with_readiness(Recorder::Rtc);
}
