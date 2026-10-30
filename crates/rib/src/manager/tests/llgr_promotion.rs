use super::*;
use std::sync::Mutex;

const FAMILIES: [(Afi, Safi); 7] = [
    (Afi::Ipv4, Safi::Unicast),
    (Afi::Ipv4, Safi::FlowSpec),
    (Afi::L2Vpn, Safi::Evpn),
    (Afi::BgpLs, Safi::BgpLs),
    (Afi::Ipv4, Safi::MplsVpn),
    (Afi::Ipv4, Safi::LabeledUnicast),
    (Afi::Ipv4, Safi::RtConstrain),
];

fn sibling(family: (Afi, Safi)) -> Option<(Afi, Safi)> {
    match family {
        (Afi::Ipv4, Safi::Unicast | Safi::FlowSpec | Safi::MplsVpn | Safi::LabeledUnicast) => {
            Some((Afi::Ipv6, family.1))
        }
        (Afi::BgpLs, Safi::BgpLs) => Some((Afi::BgpLs, Safi::BgpLsVpn)),
        _ => None,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture sends the same retention cases through all seven real receive paths"
)]
fn announce_case(manager: &mut RibManager, family: (Afi, Safi), index: u8, other_family: bool) {
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = peer_v4(addr);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, index, 0), 24);
    let v6 = Ipv6Prefix::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, u16::from(index), 0),
        112,
    );
    let attrs = match index {
        1 => vec![PathAttribute::Communities(vec![
            rustbgpd_wire::COMMUNITY_NO_LLGR,
        ])],
        2 => vec![PathAttribute::CommunitiesPartial(vec![
            rustbgpd_wire::COMMUNITY_LLGR_STALE,
        ])],
        4 => vec![PathAttribute::Communities(vec![
            rustbgpd_wire::COMMUNITY_LLGR_STALE,
        ])],
        _ => Vec::new(),
    };
    let stale = other_family || index < 3;
    let llgr = !other_family && index == 4;
    let mut unicast = Vec::new();
    let mut flowspec = Vec::new();
    let mut evpn = Vec::new();
    let update = match family.1 {
        Safi::Unicast => {
            let mut route = make_route(prefix, addr);
            if other_family {
                route.prefix = Prefix::V6(v6);
            }
            route.attributes = AttrSet::new(attrs);
            route.is_stale = stale;
            route.is_llgr_stale = llgr;
            unicast.push(route);
            None
        }
        Safi::FlowSpec => {
            let mut route = make_flowspec_route(addr);
            let destination = if other_family {
                route.afi = Afi::Ipv6;
                rustbgpd_wire::FlowSpecPrefix::V6(rustbgpd_wire::Ipv6PrefixOffset {
                    prefix: v6,
                    offset: 0,
                })
            } else {
                rustbgpd_wire::FlowSpecPrefix::V4(prefix)
            };
            route.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
                destination,
            )];
            route.attributes = attrs;
            route.is_stale = stale;
            route.is_llgr_stale = llgr;
            flowspec.push(route);
            None
        }
        Safi::Evpn => {
            let mut route = make_evpn_imet(addr, u32::from(index));
            route.attributes = AttrSet::new(attrs);
            route.is_stale = stale;
            route.is_llgr_stale = llgr;
            evpn.push(route);
            None
        }
        Safi::BgpLs => {
            let mut route = make_bgpls_route(addr, index, 100);
            if other_family {
                route.family = BgpLsFamily::LinkStateVpn;
                route.nlri.route_distinguisher = Some([0, 0, 0xfd, 0xe8, 0, 0, 0, 1]);
            }
            route.attributes = AttrSet::new(attrs);
            route.is_stale = stale;
            route.is_llgr_stale = llgr;
            Some(RibUpdate::BgpLsRoutesReceived {
                session_id: 0,
                peer,
                announced: vec![route],
                withdrawn: Vec::new(),
            })
        }
        Safi::MplsVpn => {
            let mut route = make_vpn_rib_route(addr, index, 100, 100);
            if other_family {
                route.nlri.prefix = VpnPrefix::v6(v6.addr, v6.len).unwrap();
            }
            route.attributes = AttrSet::new(attrs);
            route.is_stale = stale;
            route.is_llgr_stale = llgr;
            Some(RibUpdate::VpnRoutesReceived {
                session_id: 0,
                peer,
                announced: vec![route],
                withdrawn: Vec::new(),
            })
        }
        Safi::LabeledUnicast => {
            let mut route = make_labeled_rib_route(addr, index, 100, 100);
            if other_family {
                route.nlri.prefix = Prefix::V6(v6);
            }
            route.attributes = AttrSet::new(attrs);
            route.is_stale = stale;
            route.is_llgr_stale = llgr;
            Some(RibUpdate::LabeledRoutesReceived {
                session_id: 0,
                peer,
                announced: vec![route],
                withdrawn: Vec::new(),
            })
        }
        Safi::RtConstrain => {
            let mut route = make_rtc_rib_route(addr, u16::from(index), 100);
            route.attributes = AttrSet::new(attrs);
            route.is_stale = stale;
            route.is_llgr_stale = llgr;
            Some(RibUpdate::RtcRoutesReceived {
                session_id: 0,
                peer,
                announced: vec![route],
                withdrawn: Vec::new(),
            })
        }
        _ => unreachable!("fixture family"),
    };
    manager.handle_update(update.unwrap_or(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: unicast,
        withdrawn: Vec::new(),
        flowspec_announced: flowspec,
        flowspec_withdrawn: Vec::new(),
        evpn_announced: evpn,
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    }));
    drain_route_chunks(manager);
}

fn retention_rows(rib: &AdjRibIn, family: (Afi, Safi)) -> Vec<(bool, bool, bool, bool)> {
    macro_rules! rows {
        ($routes:expr) => {
            $routes
                .map(|route| {
                    (
                        route.is_stale,
                        route.is_llgr_stale,
                        route.attributes.iter().any(|attr| {
                            attr.communities().is_some_and(|values| {
                                values.contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
                            })
                        }),
                        route.attributes.iter().any(|attr| {
                            attr.communities().is_some_and(|values| {
                                values.contains(&rustbgpd_wire::COMMUNITY_NO_LLGR)
                            })
                        }),
                    )
                })
                .collect::<Vec<_>>()
        };
    }
    let mut rows = match family.1 {
        Safi::Unicast => rows!(
            rib.iter()
                .filter(|route| super::super::helpers::prefix_family(&route.prefix) == family)
        ),
        Safi::FlowSpec => rows!(rib.iter_flowspec().filter(|route| route.afi == family.0)),
        Safi::Evpn => rows!(rib.iter_evpn()),
        Safi::BgpLs | Safi::BgpLsVpn => rows!(
            rib.iter_bgpls()
                .filter(|route| route.family.to_afi_safi() == family)
        ),
        Safi::MplsVpn => rows!(rib.iter_vpn().filter(|route| route.afi_safi() == family)),
        Safi::LabeledUnicast => rows!(
            rib.iter_labeled()
                .filter(|route| route.afi_safi() == family)
        ),
        Safi::RtConstrain => rows!(rib.iter_rtc()),
        _ => unreachable!("fixture family"),
    };
    rows.sort_unstable();
    rows
}

#[expect(
    clippy::too_many_lines,
    reason = "the actual timer caller proves interior replies, changing counts, fenced lanes and exact family retention together"
)]
fn run_timer_case(family: (Afi, Safi), excluded: u8, promote: bool) -> usize {
    let (tx, rx) = mpsc::channel(1);
    let (query_tx, query_rx) = mpsc::channel(1);
    let (summary_tx, summary_rx) = mpsc::channel(1);
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new())
        .with_readiness_queries(readiness_rx)
        .with_summary_queries(summary_rx);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));
    for index in 0..5 + excluded {
        announce_case(&mut manager, family, index, false);
    }
    if sibling(family).is_some() {
        announce_case(&mut manager, family, 100, true);
    }
    let initial_count = manager.loc_rib.len();
    let removed = if promote { 1 } else { 3 };
    let final_count = if family.1 == Safi::Unicast {
        initial_count - removed
    } else {
        initial_count
    };
    let original_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    manager
        .llgr_stale_deadlines
        .insert((peer, family.0, family.1), original_deadline);
    manager
        .llgr_peers
        .insert(peer, [family].into_iter().collect());
    let configured = if promote {
        family
    } else if family == FAMILIES[0] {
        FAMILIES[1]
    } else {
        FAMILIES[0]
    };
    manager.llgr_peer_config.insert(
        peer,
        super::super::helpers::LlgrPeerConfig {
            peer_llgr_capable: true,
            peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
                afi: configured.0,
                safi: configured.1,
                forwarding_preserved: false,
                stale_time: 3600,
            }],
            local_llgr_stale_time: 3600,
            stale_routes_time: 360,
        },
    );
    manager
        .gr_peers
        .insert(peer, [family].into_iter().collect());
    manager
        .gr_stale_deadlines
        .insert(peer, tokio::time::Instant::now());
    let orphans: Vec<_> = (0..32)
        .map(|med| {
            let mut attrs = AttrSet::new(vec![PathAttribute::Med(med)]);
            manager.attr_intern.intern(&mut attrs);
            Arc::downgrade(&attrs)
        })
        .collect();
    let (reply, general) = oneshot::channel();
    query_tx
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();
    let general = Arc::new(Mutex::new(general));
    let (reply, mutation) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    let mutation = Arc::new(Mutex::new(mutation));
    let (reply, summary) = oneshot::channel();
    summary_tx
        .try_send(crate::RibSummaryQuery::NeighborRibSnapshots {
            peers: vec![peer],
            comparison: None,
            include_retained: true,
            reply,
        })
        .unwrap();
    let summary = Arc::new(Mutex::new(summary));
    let pending = Arc::new(Mutex::new(
        None::<(
            &'static str,
            oneshot::Receiver<Result<usize, crate::RibReadinessError>>,
        )>,
    ));
    let observations = Arc::new(Mutex::new(Vec::new()));
    manager.flush_poll_budget = Duration::ZERO;
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let pending = Arc::clone(&pending);
        let observations = Arc::clone(&observations);
        let general = Arc::clone(&general);
        let mutation = Arc::clone(&mutation);
        let summary = Arc::clone(&summary);
        move |stage| {
            assert!(matches!(
                general.lock().unwrap().try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                mutation.lock().unwrap().try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                summary.lock().unwrap().try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            if let Some((previous, mut reply)) = pending.lock().unwrap().take() {
                observations.lock().unwrap().push((
                    previous,
                    reply
                        .try_recv()
                        .expect("preceding interior checkpoint must answer readiness")
                        .unwrap(),
                ));
            }
            let (reply, response) = oneshot::channel();
            readiness_tx
                .try_send(crate::RibReadinessQuery::LocRibCount {
                    reply,
                    enqueued: Instant::now(),
                })
                .unwrap();
            *pending.lock().unwrap() = Some((stage, response));
        }
    }));
    manager.sweep_gr_stale(peer);
    manager.replacement_readiness_test_hook = None;
    let (stage, mut reply) = pending
        .lock()
        .unwrap()
        .take()
        .expect("actual caller installed an owner");
    observations
        .lock()
        .unwrap()
        .push((stage, reply.try_recv().unwrap().unwrap()));
    let observations = observations.lock().unwrap();
    let walked = if promote {
        "llgr_promotion"
    } else {
        "llgr_purge"
    };
    for stage in [walked, "llgr_inventory", "llgr_intern_cleanup"] {
        assert!(
            observations
                .iter()
                .filter(|(seen, _)| *seen == stage)
                .count()
                >= 2,
            "{family:?}: no interior {stage} service"
        );
    }
    assert!(
        observations
            .iter()
            .all(|(_, count)| (final_count..=initial_count).contains(count))
    );
    assert_eq!(observations.last().unwrap().1, final_count);
    assert_eq!(manager.loc_rib.len(), final_count);
    if family.1 == Safi::Unicast {
        let counts: Vec<_> = observations
            .iter()
            .filter_map(|(stage, count)| (*stage == "selection_recompute").then_some(*count))
            .collect();
        assert_eq!(counts.len(), 3);
        assert_eq!(counts.last(), Some(&final_count));
        if !promote {
            assert_eq!(
                counts,
                (1..=removed)
                    .map(|removed| initial_count - removed)
                    .collect::<Vec<_>>(),
                "every completed unicast withdrawal publishes its exact count"
            );
        }
    }
    let mut expected = vec![(false, false, false, false); 1 + usize::from(excluded)];
    expected.extend(std::iter::repeat_n(
        (false, true, true, false),
        if promote { 3 } else { 1 },
    ));
    assert_eq!(retention_rows(&manager.ribs[&peer], family), expected);
    if let Some(sibling) = sibling(family) {
        assert_eq!(
            retention_rows(&manager.ribs[&peer], sibling),
            [(true, false, false, false)]
        );
    }
    let retained = manager.ribs[&peer]
        .stale_route_counts()
        .find(|(seen, _)| *seen == family)
        .unwrap()
        .1;
    assert_eq!(retained.stale, 0);
    assert_eq!(retained.llgr_stale, if promote { 3 } else { 1 });
    assert_eq!(
        manager.llgr_stale_deadlines[&(peer, family.0, family.1)],
        original_deadline
    );
    assert!(!manager.gr_stale_deadlines.contains_key(&peer));
    assert!(
        orphans.iter().all(|attrs| attrs.upgrade().is_none()),
        "{family:?}: unreachable intern entries survived cleanup"
    );
    assert_eq!(manager.primary_backlog(), 1);
    assert!(matches!(
        summary.lock().unwrap().try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    manager.drain_queries(1);
    assert_eq!(general.lock().unwrap().try_recv().unwrap(), final_count);
    assert!(matches!(
        mutation.lock().unwrap().try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(
        manager.ribs[&peer].maintained_stale_route_counts(),
        manager.ribs[&peer].scanned_stale_route_counts()
    );
    if promote && excluded == 0 {
        manager.handle_update(gr_with_llgr(peer, 120, vec![family], vec![family], 3600));
        manager.sweep_gr_stale(peer);
        assert_eq!(
            retention_rows(&manager.ribs[&peer], family),
            [(false, true, true, false); 4],
            "another restart preserves the previous LLGR rows and promotes the fresh row"
        );
        assert_eq!(
            manager.llgr_stale_deadlines[&(peer, family.0, family.1)],
            original_deadline,
            "another restart must not restart the original LLGR stale timer"
        );
    }
    observations
        .iter()
        .filter(|(stage, _)| *stage == walked)
        .count()
}

#[test]
fn llgr_timer_promotion_services_all_family_writers_and_excluded_routes() {
    for family in FAMILIES {
        let baseline = run_timer_case(family, 0, true);
        let excluded = run_timer_case(family, 8, true);
        assert!(
            excluded >= baseline + 16,
            "{family:?}: both promotion scans must checkpoint excluded rows"
        );
    }
}

#[test]
fn llgr_timer_nonnegotiated_purge_services_all_family_writers() {
    for family in FAMILIES {
        let baseline = run_timer_case(family, 0, false);
        let excluded = run_timer_case(family, 8, false);
        assert!(
            excluded >= baseline + 8,
            "{family:?}: purge must checkpoint excluded rows"
        );
    }
}

const BGPLS: (Afi, Safi) = (Afi::BgpLs, Safi::BgpLs);
const ORR_STAGES: [&str; 7] = [
    "orr_scan",
    "orr_build",
    "orr_compare",
    "orr_vantages",
    "orr_spf",
    "orr_signature",
    "orr_retire",
];

fn orr_vantage() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2))
}

/// A bidirectional chain of `nodes` with one prefix per node; node 1 owns
/// the vantage's interface address.
fn chain_topology(peer: Ipv4Addr, nodes: u8) -> Vec<crate::route::BgpLsRibRoute> {
    use crate::orr::fixtures::{link_route, prefix_route, v4_interface, v4_neighbor};
    let mut routes = Vec::new();
    for node in 1..=nodes {
        routes.push(prefix_route(
            peer,
            node,
            Ipv4Addr::new(172, 16, node, 0),
            24,
            Some(1),
        ));
        if node < nodes {
            for (local, remote) in [(node, node + 1), (node + 1, node)] {
                routes.push(link_route(
                    peer,
                    local,
                    remote,
                    Some(1),
                    &[
                        v4_interface(Ipv4Addr::new(10, 0, local, remote)),
                        v4_neighbor(Ipv4Addr::new(10, 0, remote, local)),
                    ],
                ));
            }
        }
    }
    routes
}

/// Drive the actual GR-timer caller into LLGR with ORR configured. One BGP-LS
/// feeder restarts; a steady feeder advertises the same topology, so the
/// rebuild still scans, compares, runs SPF and retires a full topology after
/// a purge. Returns how many queued readiness queries each stage answered,
/// and the capacity growth of every ORR rebuild destination.
fn run_orr_llgr_case(
    nodes: u8,
    promote: bool,
    empty_peers: usize,
) -> (
    BTreeMap<&'static str, usize>,
    crate::orr::rebuild_growth::Growth,
) {
    let (mut manager, readiness_tx) = readiness_manager();
    let restarting = Ipv4Addr::new(10, 9, 9, 1);
    let steady = Ipv4Addr::new(10, 9, 9, 2);
    manager
        .peer_orr_vantage
        .insert(peer_v4(Ipv4Addr::new(10, 0, 0, 2)), orr_vantage());
    for feed in [restarting, steady] {
        let peer = peer_v4(feed);
        manager.ribs.insert(peer, AdjRibIn::new(peer));
        manager.handle_update(RibUpdate::BgpLsRoutesReceived {
            session_id: 0,
            peer,
            announced: chain_topology(feed, nodes),
            withdrawn: Vec::new(),
        });
        drain_route_chunks(&mut manager);
    }
    assert_eq!(manager.orr.resolved.get(&orr_vantage()), Some(&true));
    let peer = peer_v4(restarting);
    let routes = manager.ribs[&peer].bgpls_len();
    let unicast = (Afi::Ipv4, Safi::Unicast);
    let llgr = if promote { BGPLS } else { unicast };
    manager.handle_update(gr_with_llgr(
        peer,
        120,
        vec![BGPLS, unicast],
        vec![llgr],
        3600,
    ));

    for index in 0..empty_peers {
        let empty = peer_v4(Ipv4Addr::new(
            10,
            8,
            u8::try_from(index / 256).unwrap(),
            u8::try_from(index % 256).unwrap(),
        ));
        manager.ribs.insert(empty, AdjRibIn::new(empty));
    }

    crate::orr::rebuild_growth::take();
    let answered = sweep_gr_stale_with_readiness_probe(&mut manager, readiness_tx, peer);
    let growth = crate::orr::rebuild_growth::take();

    let retained: Vec<_> = manager.ribs[&peer]
        .iter_bgpls()
        .map(|route| (route.is_stale, route.is_llgr_stale))
        .collect();
    if promote {
        assert_eq!(retained, vec![(false, true); routes]);
    } else {
        assert!(retained.is_empty(), "non-LLGR BGP-LS must purge");
    }
    assert_eq!(manager.orr.resolved.get(&orr_vantage()), Some(&true));
    assert_eq!(manager.orr.topology.node_count(), usize::from(nodes));
    assert_eq!(
        manager.orr.topology.link_count(),
        2 * usize::from(nodes - 1)
    );
    (answered, growth)
}

/// Run the actual GR-timer caller while every readiness checkpoint queues a
/// query that the next checkpoint must find already answered. Returns how
/// many queries each stage answered.
fn sweep_gr_stale_with_readiness_probe(
    manager: &mut RibManager,
    readiness_tx: mpsc::Sender<crate::RibReadinessQuery>,
    peer: PeerId,
) -> BTreeMap<&'static str, usize> {
    run_with_readiness_probe(manager, readiness_tx, |manager| {
        manager.sweep_gr_stale(peer);
    })
}

/// Stage key recording whether a query queued before `work` was answered
/// by the time `work` returned.
const PRE_QUEUED: &str = "pre_queued_answered_inside";

/// Run actual-caller `work` while every readiness checkpoint queues a query
/// that the next checkpoint must find already answered. A query is also
/// queued before `work`; `PRE_QUEUED` counts it when `work` answered it.
/// Returns how many queries each stage answered.
fn run_with_readiness_probe(
    manager: &mut RibManager,
    readiness_tx: mpsc::Sender<crate::RibReadinessQuery>,
    work: impl FnOnce(&mut RibManager),
) -> BTreeMap<&'static str, usize> {
    let (reply, mut pre_queued) = oneshot::channel();
    readiness_tx
        .try_send(crate::RibReadinessQuery::LocRibCount {
            reply,
            enqueued: Instant::now(),
        })
        .unwrap();
    let pending = Arc::new(Mutex::new(
        None::<(
            &'static str,
            oneshot::Receiver<Result<usize, crate::RibReadinessError>>,
        )>,
    ));
    let answered = Arc::new(Mutex::new(BTreeMap::<&'static str, usize>::new()));
    manager.flush_poll_budget = Duration::ZERO;
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let pending = Arc::clone(&pending);
        let answered = Arc::clone(&answered);
        move |stage| {
            if let Some((previous, mut reply)) = pending.lock().unwrap().take() {
                reply
                    .try_recv()
                    .unwrap_or_else(|error| {
                        panic!("{previous}: queued readiness query not answered inside: {error}")
                    })
                    .unwrap();
                *answered.lock().unwrap().entry(previous).or_default() += 1;
            }
            let (reply, response) = oneshot::channel();
            readiness_tx
                .try_send(crate::RibReadinessQuery::LocRibCount {
                    reply,
                    enqueued: Instant::now(),
                })
                .unwrap();
            *pending.lock().unwrap() = Some((stage, response));
        }
    }));
    work(manager);
    manager.replacement_readiness_test_hook = None;
    let mut answered = answered.lock().unwrap().clone();
    if pre_queued.try_recv().is_ok() {
        answered.insert(PRE_QUEUED, 1);
    }
    answered
}

fn readiness_manager() -> (RibManager, mpsc::Sender<crate::RibReadinessQuery>) {
    let (_tx, rx) = mpsc::channel(1);
    // One query queued before the work plus one outstanding per checkpoint.
    let (readiness_tx, readiness_rx) = mpsc::channel(2);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_readiness_queries(readiness_rx);
    (manager, readiness_tx)
}

/// LLGR promotion and non-LLGR purge of a mostly withdrawn unicast slab:
/// the walk services readiness between vacant slots, so the walked stage
/// gains at least one answered query per vacancy (two promotion passes,
/// one purge pass) over a dense table holding the same routes.
fn run_sparse_unicast_case(total: u16, kept: u16, promote: bool) -> usize {
    let (mut manager, readiness_tx) = readiness_manager();
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = peer_v4(addr);
    let mut rib = AdjRibIn::new(peer);
    let prefix = |index: u16| {
        let [high, low] = index.to_be_bytes();
        Ipv4Prefix::new(Ipv4Addr::new(203, high, low, 0), 24)
    };
    for index in 0..total {
        rib.insert(make_route(prefix(index), addr));
    }
    for index in 0..total - kept {
        assert!(rib.withdraw(&Prefix::V4(prefix(index)), 0));
    }
    assert_eq!(rib.len(), usize::from(kept));
    manager.ribs.insert(peer, rib);
    let unicast = (Afi::Ipv4, Safi::Unicast);
    let flowspec = (Afi::Ipv4, Safi::FlowSpec);
    let llgr = if promote { unicast } else { flowspec };
    manager.handle_update(gr_with_llgr(
        peer,
        120,
        vec![unicast, flowspec],
        vec![llgr],
        3600,
    ));
    let answered = sweep_gr_stale_with_readiness_probe(&mut manager, readiness_tx, peer);
    let retained: Vec<_> = manager.ribs[&peer]
        .iter()
        .map(|route| (route.is_stale, route.is_llgr_stale))
        .collect();
    if promote {
        assert_eq!(retained, vec![(false, true); usize::from(kept)]);
    } else {
        assert!(retained.is_empty(), "non-LLGR unicast must purge");
    }
    assert_eq!(
        manager.ribs[&peer].maintained_stale_route_counts(),
        manager.ribs[&peer].scanned_stale_route_counts()
    );
    let walked = if promote {
        "llgr_promotion"
    } else {
        "llgr_purge"
    };
    answered.get(walked).copied().unwrap_or(0)
}

#[test]
fn llgr_sparse_unicast_slab_services_readiness_between_vacant_slots() {
    // (promote, passes, dense, sparse) for the promotion and purge walks.
    let walks: Vec<_> = [(true, 2), (false, 1)]
        .into_iter()
        .map(|(promote, passes)| {
            (
                promote,
                passes,
                run_sparse_unicast_case(8, 8, promote),
                run_sparse_unicast_case(2048, 8, promote),
            )
        })
        .collect();
    assert!(
        walks
            .iter()
            .all(|&(_, passes, dense, sparse)| sparse >= dense + passes * 2040),
        "each pass over 2040 vacant slots must answer once per slot: {walks:?}"
    );
}

/// A topology page read without vantages caches a graph; the GR timer's
/// LLGR entry must retire it under the readiness owner, not drop it whole
/// while advancing page versions before the owner opens.
#[test]
fn llgr_timer_retires_cached_orr_page_topology_under_readiness() {
    let (mut manager, readiness_tx) = readiness_manager();
    let feed = Ipv4Addr::new(10, 9, 9, 1);
    let peer = peer_v4(feed);
    manager.ribs.insert(peer, AdjRibIn::new(peer));
    manager.handle_update(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: chain_topology(feed, 32),
        withdrawn: Vec::new(),
    });
    drain_route_chunks(&mut manager);
    manager.handle_update(gr_with_llgr(peer, 120, vec![BGPLS], vec![BGPLS], 3600));
    // An operator walks the retained topology while the peer is restarting.
    let (reply, mut page) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryOrrTopologyLinksPage {
        after: None,
        expected_version: None,
        page_size: 1000,
        reply,
    });
    let links = page.try_recv().unwrap().unwrap().total;
    assert_eq!(links, 62);
    assert!(
        manager.orr_page_topology.is_some(),
        "the read cached a graph"
    );

    let answered = sweep_gr_stale_with_readiness_probe(&mut manager, readiness_tx, peer);
    assert!(manager.orr_page_topology.is_none());
    let retired = answered.get("llgr_orr_page_retire").copied().unwrap_or(0);
    assert!(
        u64::try_from(retired).unwrap() >= 2 * links,
        "cached graph of {links} links retired with {retired} answered queries: {answered:?}"
    );
}

/// The ORR scan yields once per Adj-RIB-In, including peers that hold no
/// BGP-LS routes: each empty table adds a sizing and a traversal boundary.
#[test]
fn llgr_orr_scan_services_readiness_across_empty_bgpls_peers() {
    let (without, _) = run_orr_llgr_case(8, true, 0);
    let (with, _) = run_orr_llgr_case(8, true, 512);
    let scans = |answered: &BTreeMap<&str, usize>| answered.get("orr_scan").copied().unwrap_or(0);
    assert!(
        scans(&with) >= scans(&without) + 2 * 512,
        "512 empty peers answered {} vs {} orr_scan queries",
        scans(&with),
        scans(&without)
    );
}

/// BGP-LS LLGR promotion and purge reached from the GR timer rebuild ORR
/// under the readiness owner; a readiness query queued during every ORR
/// unit is answered inside that unit, not after the rebuild.
#[test]
fn llgr_bgpls_orr_rebuild_answers_readiness_inside_every_unit() {
    for promote in [true, false] {
        let (answered, _) = run_orr_llgr_case(8, promote, 0);
        for stage in ORR_STAGES {
            assert!(
                answered.get(stage).copied().unwrap_or(0) >= 2,
                "promote={promote}: no interior {stage} service: {answered:?}"
            );
        }
    }
}

/// Growth control per unit: as the BGP-LS inventory quadruples, every
/// inventory-sized ORR unit adds interior checkpoints at least in step with
/// the added nodes, the vantage unit stays independent of inventory, and no
/// reserved rebuild destination grows inside a checkpoint slice.
#[test]
fn llgr_bgpls_orr_rebuild_work_between_checkpoints_stays_bounded() {
    for promote in [true, false] {
        let (small, small_growth) = run_orr_llgr_case(16, promote, 0);
        let (large, large_growth) = run_orr_llgr_case(64, promote, 0);
        for stage in ORR_STAGES {
            let small = small.get(stage).copied().unwrap_or(0);
            let large = large.get(stage).copied().unwrap_or(0);
            if stage == "orr_vantages" {
                assert!(
                    small >= 2,
                    "promote={promote}: {stage} has no interior service"
                );
                assert_eq!(
                    small, large,
                    "promote={promote}: vantage work must not scale with BGP-LS inventory"
                );
            } else {
                assert!(
                    large >= small + 48,
                    "promote={promote}: {stage} checkpoints {small} -> {large} \
                     do not grow with 48 added nodes"
                );
            }
        }
        for (nodes, growth) in [(16, &small_growth), (64, &large_growth)] {
            let mut failures = Vec::new();
            for destination in [
                "orr_build_order",
                "orr_build_seen",
                "orr_build_node_keys",
                "orr_build_node_ix",
                "orr_build_links",
                "orr_build_addr_index",
                "orr_build_adjacency",
                "orr_prefix_signature",
                "orr_vantages",
                "orr_spf_dist",
                "orr_spf_heap",
                "orr_spf_signature",
                "orr_changed",
                "orr_spf_results",
                "orr_resolved",
                "orr_signatures",
            ] {
                let (fills, largest) = growth.get(destination).copied().unwrap_or_default();
                if fills == 0 || largest != 0 {
                    failures.push((destination, fills, largest));
                }
            }
            assert!(
                failures.is_empty(),
                "promote={promote}, nodes={nodes}: (destination, fills, growth inside one \
                 checkpoint slice) must be filled without growth: {failures:?}"
            );
        }
    }
}

const EXPIRY_UNITS: [&str; 3] = [
    "llgr_expiry_purge",
    "llgr_expiry_inventory",
    "llgr_intern_cleanup",
];

/// Make the peer's LLGR deadline for `family` due now, and keep a later
/// deadline on another tuple so expiry stays non-terminal: departed-peer
/// teardown has its own owner and must not stand in for this one.
fn make_llgr_expiry_due(manager: &mut RibManager, peer: PeerId, family: (Afi, Safi)) {
    let now = tokio::time::Instant::now();
    manager
        .llgr_stale_deadlines
        .insert((peer, family.0, family.1), now);
    manager.llgr_stale_deadlines.insert(
        (peer, Afi::Ipv6, Safi::Unicast),
        now + Duration::from_secs(3600),
    );
}

/// Retain `routes` LLGR-stale routes of `family` through the actual GR
/// timer promotion, after announcing `vacated` more unicast routes and
/// withdrawing them so the slab keeps vacant slots, then run the actual
/// LLGR timer arm under the readiness probe.
fn run_llgr_expiry_case(
    family: (Afi, Safi),
    routes: u8,
    vacated: u8,
) -> BTreeMap<&'static str, usize> {
    run_llgr_expiry_case_with_fresh(family, routes, vacated, 0)
}

/// Announce one route that is neither GR- nor LLGR-stale and never expires
/// with `family`: an IPv6 `FlowSpec` rule beside expiring IPv4 `FlowSpec`, or a
/// fresh RT-Constrain route beside expiring RTC routes.
fn announce_fresh(manager: &mut RibManager, family: (Afi, Safi), index: u8) {
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = peer_v4(addr);
    let update = match family.1 {
        Safi::FlowSpec => {
            let mut route = make_flowspec_route(addr);
            route.afi = Afi::Ipv6;
            route.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
                rustbgpd_wire::FlowSpecPrefix::V6(rustbgpd_wire::Ipv6PrefixOffset {
                    prefix: Ipv6Prefix::new(
                        Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, u16::from(index), 0),
                        112,
                    ),
                    offset: 0,
                }),
            )];
            RibUpdate::RoutesReceived {
                session_id: 0,
                peer,
                announced: Vec::new(),
                withdrawn: Vec::new(),
                flowspec_announced: vec![route],
                flowspec_withdrawn: Vec::new(),
                evpn_announced: Vec::new(),
                evpn_withdrawn: Vec::new(),
                validated_with: None,
            }
        }
        Safi::RtConstrain => RibUpdate::RtcRoutesReceived {
            session_id: 0,
            peer,
            announced: vec![make_rtc_rib_route(addr, 1000 + u16::from(index), 100)],
            withdrawn: Vec::new(),
        },
        _ => unreachable!("fresh fixture families"),
    };
    manager.handle_update(update);
    drain_route_chunks(manager);
}

/// [`run_llgr_expiry_case`] with `fresh` non-expiring routes announced
/// after promotion, before the LLGR deadline fires.
fn run_llgr_expiry_case_with_fresh(
    family: (Afi, Safi),
    routes: u8,
    vacated: u8,
    fresh: u8,
) -> BTreeMap<&'static str, usize> {
    let (mut manager, readiness_tx) = readiness_manager();
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = peer_v4(addr);
    manager.ribs.insert(peer, AdjRibIn::new(peer));
    for index in 5..5 + vacated + routes {
        announce_case(&mut manager, family, index, false);
    }
    if vacated > 0 {
        assert_eq!(
            family,
            (Afi::Ipv4, Safi::Unicast),
            "slab vacancies are unicast"
        );
        manager.handle_update(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: Vec::new(),
            withdrawn: (5..5 + vacated)
                .map(|index| {
                    (
                        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, index, 0), 24)),
                        0,
                    )
                })
                .collect(),
            flowspec_announced: Vec::new(),
            flowspec_withdrawn: Vec::new(),
            evpn_announced: Vec::new(),
            evpn_withdrawn: Vec::new(),
            validated_with: None,
        });
        drain_route_chunks(&mut manager);
    }
    manager.handle_update(gr_with_llgr(peer, 120, vec![family], vec![family], 3600));
    manager.sweep_gr_stale(peer);
    let retained = |manager: &RibManager| {
        manager.ribs[&peer]
            .stale_route_counts()
            .find(|(seen, _)| *seen == family)
            .map_or(0, |(_, counts)| counts.llgr_stale)
    };
    assert_eq!(retained(&manager), u64::from(routes), "{family:?}");
    for index in 0..fresh {
        announce_fresh(&mut manager, family, index);
    }
    make_llgr_expiry_due(&mut manager, peer, family);
    let initial_count = manager.loc_rib.len();

    // Growth recorded during setup is not the expiry's.
    crate::orr::rebuild_growth::take();
    let answered = run_with_readiness_probe(
        &mut manager,
        readiness_tx,
        RibManager::sweep_expired_llgr_stale,
    );
    assert_eq!(
        retained(&manager),
        0,
        "{family:?}: expiry purges the family"
    );
    let survivors = match family.1 {
        Safi::FlowSpec => manager.ribs[&peer].flowspec_lens()[1],
        Safi::RtConstrain => manager.ribs[&peer].rtc_len(),
        _ => 0,
    };
    assert_eq!(
        survivors,
        usize::from(fresh),
        "{family:?}: fresh routes survive"
    );
    assert!(
        !manager
            .llgr_stale_deadlines
            .contains_key(&(peer, family.0, family.1))
    );
    let expected = if family.1 == Safi::Unicast {
        initial_count - usize::from(routes)
    } else {
        initial_count
    };
    assert_eq!(manager.loc_rib.len(), expected, "{family:?}");
    assert_eq!(
        manager.ribs[&peer].maintained_stale_route_counts(),
        manager.ribs[&peer].scanned_stale_route_counts()
    );
    answered
}

/// The LLGR timer arm sweeps every family under the readiness owner: a
/// query queued before the sweep and one queued at each checkpoint of the
/// purge, affected-inventory and intern-cleanup units are answered inside
/// the sweep.
#[test]
fn llgr_expiry_timer_answers_readiness_inside_every_family_sweep() {
    let mut failures = Vec::new();
    for family in FAMILIES {
        let answered = run_llgr_expiry_case(family, 32, 0);
        for stage in std::iter::once(PRE_QUEUED).chain(EXPIRY_UNITS) {
            let count = answered.get(stage).copied().unwrap_or(0);
            if count < usize::from(stage != PRE_QUEUED) + 1 {
                failures.push((family, stage, count));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "(family, stage, answered) without interior readiness service: {failures:?}"
    );
}

/// Per-unit work-count control: as the retained inventory grows from 8 to
/// 40 routes, the purge unit answers at least twice per added route (walk
/// and removal) and the inventory unit at least once per added key, for
/// every family. A unicast slab with 240 vacant slots adds a purge answer
/// per vacancy.
#[test]
fn llgr_expiry_work_counts_grow_per_unit() {
    let count = |answered: &BTreeMap<&str, usize>, stage| answered.get(stage).copied().unwrap_or(0);
    let mut failures = Vec::new();
    for family in FAMILIES {
        let small = run_llgr_expiry_case(family, 8, 0);
        let large = run_llgr_expiry_case(family, 40, 0);
        for (stage, per_route) in [("llgr_expiry_purge", 2), ("llgr_expiry_inventory", 1)] {
            let (small, large) = (count(&small, stage), count(&large, stage));
            if large < small + per_route * 32 {
                failures.push((family, stage, small, large));
            }
        }
    }
    let unicast = (Afi::Ipv4, Safi::Unicast);
    let dense = count(&run_llgr_expiry_case(unicast, 8, 0), "llgr_expiry_purge");
    let sparse = count(&run_llgr_expiry_case(unicast, 8, 240), "llgr_expiry_purge");
    if sparse < dense + 240 {
        failures.push((unicast, "llgr_expiry_purge vacant slots", dense, sparse));
    }
    assert!(
        failures.is_empty(),
        "(family, unit, small, large) answered counts do not grow with the work: {failures:?}"
    );
}

/// LLGR expiry of a BGP-LS feeder with ORR configured rebuilds ORR inside
/// the readiness owner, and retires a topology page cache inside it too.
#[test]
fn llgr_expiry_rebuilds_orr_and_retires_page_cache_under_readiness() {
    for vantage in [true, false] {
        let (mut manager, readiness_tx) = readiness_manager();
        let restarting = Ipv4Addr::new(10, 9, 9, 1);
        let steady = Ipv4Addr::new(10, 9, 9, 2);
        if vantage {
            manager
                .peer_orr_vantage
                .insert(peer_v4(Ipv4Addr::new(10, 0, 0, 2)), orr_vantage());
        }
        for feed in [restarting, steady] {
            let peer = peer_v4(feed);
            manager.ribs.insert(peer, AdjRibIn::new(peer));
            manager.handle_update(RibUpdate::BgpLsRoutesReceived {
                session_id: 0,
                peer,
                announced: chain_topology(feed, 16),
                withdrawn: Vec::new(),
            });
            drain_route_chunks(&mut manager);
        }
        let peer = peer_v4(restarting);
        manager.handle_update(gr_with_llgr(peer, 120, vec![BGPLS], vec![BGPLS], 3600));
        manager.sweep_gr_stale(peer);
        make_llgr_expiry_due(&mut manager, peer, BGPLS);
        let mut links = 0;
        if !vantage {
            // An operator walks the retained topology during LLGR.
            let (reply, mut page) = oneshot::channel();
            manager.handle_update(RibUpdate::QueryOrrTopologyLinksPage {
                after: None,
                expected_version: None,
                page_size: 1000,
                reply,
            });
            links = page.try_recv().unwrap().unwrap().total;
            assert_eq!(links, 30);
            assert!(manager.orr_page_topology.is_some());
        }

        let answered = run_with_readiness_probe(
            &mut manager,
            readiness_tx,
            RibManager::sweep_expired_llgr_stale,
        );
        assert_eq!(manager.ribs[&peer].bgpls_len(), 0);
        if vantage {
            assert_eq!(manager.orr.resolved.get(&orr_vantage()), Some(&true));
            for stage in ORR_STAGES {
                assert!(
                    answered.get(stage).copied().unwrap_or(0) >= 2,
                    "no interior {stage} service during LLGR expiry: {answered:?}"
                );
            }
        } else {
            assert!(manager.orr_page_topology.is_none());
            let retired = answered.get("llgr_orr_page_retire").copied().unwrap_or(0);
            assert!(
                u64::try_from(retired).unwrap() >= 2 * links,
                "cached graph of {links} links retired with {retired} answered queries: \
                 {answered:?}"
            );
        }
    }
}

/// Expiring IPv4 `FlowSpec` beside a large non-expiring IPv6 inventory: the
/// per-AFI recount for the prefix gauge answers readiness per route.
#[test]
fn llgr_expiry_flowspec_recount_services_readiness_per_route() {
    let flowspec = (Afi::Ipv4, Safi::FlowSpec);
    let count = |answered: &BTreeMap<&str, usize>| {
        answered.get("llgr_expiry_metrics").copied().unwrap_or(0)
    };
    let small = count(&run_llgr_expiry_case_with_fresh(flowspec, 8, 0, 0));
    let large = count(&run_llgr_expiry_case_with_fresh(flowspec, 8, 0, 128));
    assert!(
        large >= small + 128,
        "FlowSpec recount answered {small} with no IPv6 rules and {large} with 128"
    );
}

/// Expiring RT-Constrain routes beside fresh ones: rebuilding the surviving
/// membership answers readiness per collected entry, per sort/dedup
/// comparison and per published entry, each counted separately.
#[test]
fn llgr_expiry_rtc_membership_rebuild_services_readiness_per_unit() {
    let rtc = (Afi::Ipv4, Safi::RtConstrain);
    let small = run_llgr_expiry_case_with_fresh(rtc, 8, 0, 8);
    let large = run_llgr_expiry_case_with_fresh(rtc, 8, 0, 136);
    let failures: Vec<_> = [
        "selection_rtc_membership",
        "rtc_membership_sort",
        "rtc_membership_publish",
    ]
    .into_iter()
    .map(|stage| {
        (
            stage,
            small.get(stage).copied().unwrap_or(0),
            large.get(stage).copied().unwrap_or(0),
        )
    })
    .filter(|&(_, small, large)| large < small + 128)
    .collect();
    assert!(
        failures.is_empty(),
        "(unit, answered with 8 fresh, with 136 fresh) must grow per fresh route: {failures:?}"
    );
}

/// A large unicast expiry selects into a `changed` set reserved up front,
/// so no insert rehashes between selection checkpoints.
#[test]
fn llgr_expiry_unicast_selection_changed_set_never_grows() {
    let answered = run_llgr_expiry_case((Afi::Ipv4, Safi::Unicast), 200, 0);
    let growth = crate::orr::rebuild_growth::take();
    assert!(answered.get("selection_recompute").copied().unwrap_or(0) >= 200);
    assert_eq!(
        growth.get("recompute_best_changed"),
        Some(&(1, 0)),
        "one selection pass, no capacity growth inside it: {growth:?}"
    );
}
