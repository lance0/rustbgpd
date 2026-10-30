//! Work-count scaling contracts for the RIB lifecycle paths.
//!
//! Each contract runs one path at two sizes, 8 and 32, scaling the member
//! count and the path's route count together, and asserts how much the work
//! grows, never how long it takes. Work that is linear in the size grows
//! about 4x; a members x routes term grows 16x. The bar sits at the
//! geometric midpoint, 8x, so constant terms cannot push a linear path over
//! it and a quadratic one cannot hide under it.
//!
//! The units are the actor's readiness checkpoints
//! ([`slice_timing::checkpoints`]). Every long actor loop checkpoints once
//! per item, so the count is the number of per-item steps the path took;
//! work in a loop without a checkpoint is invisible to it. A contract
//! bounds the total and, where the path has one, the named stage that is
//! its unit of work: a members x routes term with a small coefficient can
//! stay under the bar in the total at these sizes, but not in its own
//! stage. Inbound distribution also counts member envelopes: its regression
//! shape is one distribution pass per message, which multiplies passes.
//!
//! Members share one exact-export wire profile, as route-server sessions on
//! one LAN do, so a grouped pass probes the shared payload once and every
//! other member reuses that result. A per-member probe of every route would
//! be a members x routes term.
//!
//! Every scenario also pins its exact wire output, so a setup that stops
//! installing routes cannot pass as flat work.

use crate::PeerId;
use crate::test_support::peer_v4;

use super::exportability::ReusableExactExportEncoder;
use super::lifecycle::{finish_clean_transition, test_peer_up, test_routes_received};
use super::*;
use crate::manager::slice_timing::{self, checkpoints};

/// The route server's ASN for the rs-control members.
const RS_AS: u32 = 65_000;
/// Peers that go down in the burst, or join in the peer-up contract.
const BURST: usize = 4;
const SMALL: usize = 8;
const LARGE: usize = 32;
/// Routes per unit of size, so per-route terms outweigh per-member ones.
const ROUTES: usize = 8;

/// Work counts by unit: checkpoints by stage name (`""` when unnamed),
/// their total under [`ALL`], and any unit a scenario adds.
type Work = BTreeMap<&'static str, usize>;

/// Every checkpoint, named or not.
const ALL: &str = "checkpoints";
/// Member envelopes carrying routes, one per member per distribution pass.
const ENVELOPES: &str = "member envelopes";

/// Assert that each of `units` grows linearly from [`SMALL`] to [`LARGE`].
fn assert_linear(contract: &str, units: &[&str], measure: impl Fn(usize) -> Work) {
    let small = measure(SMALL);
    let large = measure(LARGE);
    let scale = LARGE / SMALL;
    for unit in units {
        let count = |work: &Work| work.get(unit).copied().unwrap_or(0);
        let (before, after) = (count(&small), count(&large));
        assert!(before > 0, "{contract}: no {unit} counted at size {SMALL}");
        let tenths = after * 10 / before;
        assert!(
            after <= before * scale * 2,
            "{contract}: {unit} grew {before} -> {after} ({}.{}x) from size {SMALL} to \
             {LARGE}; linear growth is about {scale}x and a quadratic term {}x\n\
             size {SMALL}: {small:?}\nsize {LARGE}: {large:?}",
            tenths / 10,
            tenths % 10,
            scale * scale,
        );
    }
}

/// The checkpoints `work` passes on this thread.
fn checkpoints_in(work: impl FnOnce()) -> Work {
    let before = checkpoints();
    work();
    let mut counts: Work = checkpoints()
        .into_iter()
        .map(|(stage, count)| (stage, count - before.get(stage).copied().unwrap_or(0)))
        .filter(|&(_, count)| count > 0)
        .collect();
    counts.insert(ALL, counts.values().sum());
    counts
}

fn prefix(source: usize, index: usize) -> Ipv4Prefix {
    let [high, low] = u16::try_from(index).unwrap().to_be_bytes();
    Ipv4Prefix::new(
        Ipv4Addr::new(10, u8::try_from(source).unwrap(), high, low),
        32,
    )
}

fn member(index: usize) -> PeerId {
    let [high, low] = u16::try_from(index).unwrap().to_be_bytes();
    peer_v4(Ipv4Addr::new(192, 0, high, low))
}

/// A route source that is not an outbound member.
fn external() -> PeerId {
    peer_v4(Ipv4Addr::new(198, 51, 100, 1))
}

fn manager() -> (mpsc::Sender<RibUpdate>, RibManager) {
    let (tx, rx) = mpsc::channel(4096);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    super::distribution_window::untimed_window(&mut manager);
    (tx, manager)
}

/// The exact-export wire profile every member shares.
const WIRE_PROFILE: u64 = 1;

/// Register member `index` the way a session does: its own exact-export
/// encoder with the shared wire profile, optional RFC 7947 control, then
/// `PeerUp`.
fn join(
    manager: &mut RibManager,
    index: usize,
    rs_control: bool,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
) -> (
    mpsc::Receiver<OutboundRouteUpdate>,
    Arc<ReusableExactExportEncoder>,
) {
    let peer = member(index);
    let encoder = ReusableExactExportEncoder::new(u64::try_from(index).unwrap() + 1, WIRE_PROFILE);
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 1,
        encoder: encoder.clone(),
    });
    if rs_control {
        manager.handle_update(RibUpdate::SetPeerRsControl {
            peer,
            session_id: 1,
            rs_control_asn: Some(RS_AS),
        });
    }
    let (outbound_tx, outbound_rx) = mpsc::channel(4096);
    let mut up = test_peer_up(peer, 1, outbound_tx);
    if let RibUpdate::PeerUp {
        export_policy: policy,
        peer_asn,
        ..
    } = &mut up
    {
        *policy = export_policy;
        *peer_asn = 65_100 + u32::try_from(index).unwrap();
    }
    manager.handle_update(up);
    (outbound_rx, encoder)
}

fn members(
    manager: &mut RibManager,
    count: usize,
    rs_control: bool,
    export_policy: Option<&rustbgpd_policy::PolicyChain>,
) -> Vec<mpsc::Receiver<OutboundRouteUpdate>> {
    (0..count)
        .map(|index| join(manager, index, rs_control, export_policy.cloned()).0)
        .collect()
}

/// `count` routes from `from`, numbered within `source`'s prefix block.
fn routes_from(from: PeerId, session_id: u64, source: usize, count: usize) -> RibUpdate {
    let IpAddr::V4(next_hop) = from.addr() else {
        unreachable!("test peers are IPv4")
    };
    let routes = (0..count)
        .map(|index| make_route(prefix(source, index), next_hop))
        .collect();
    let mut update = test_routes_received(from, routes);
    if let RibUpdate::RoutesReceived { session_id: id, .. } = &mut update {
        *id = session_id;
    }
    update
}

/// Announced and withdrawn route counts across `receivers`.
fn drain(receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>]) -> (usize, usize) {
    let (mut announced, mut withdrawn) = (0, 0);
    for rx in receivers {
        while let Ok(update) = rx.try_recv() {
            announced += update.announce.len();
            withdrawn += update.withdraw.len();
        }
    }
    (announced, withdrawn)
}

/// [`BURST`] route-server clients, each the source of `ROUTES * size`
/// prefixes, go down back to back in a group of `size` rs-control members.
/// Each down must cost its own withdrawals plus a fixed amount per member,
/// not members x withdrawals: an admitted-prior set built per member on
/// every withdrawal pass made the burst quadratic.
fn peer_down_burst(size: usize) -> Work {
    let (_tx, mut manager) = manager();
    let mut receivers = members(&mut manager, size, true, None);
    for source in 0..BURST {
        manager.handle_update(routes_from(member(source), 1, source, ROUTES * size));
        drain_route_chunks(&mut manager);
    }
    // Every member holds every source's routes but its own.
    assert_eq!(
        drain(&mut receivers),
        (BURST * ROUTES * size * (size - 1), 0),
        "setup, size {size}"
    );
    let work = checkpoints_in(|| {
        for source in 0..BURST {
            manager.handle_update(RibUpdate::PeerDown {
                peer: member(source),
                session_id: 1,
            });
        }
    });
    // The k-th down withdraws from every member still up but the source.
    let expected: usize = (0..BURST)
        .map(|down| ROUTES * size * (size - 1 - down))
        .sum();
    assert_eq!(drain(&mut receivers), (0, expected), "size {size}");
    work
}

/// [`BURST`] peers join a group of `size` members holding `ROUTES * size`
/// prefixes. A join costs its own initial table; it must not touch the
/// members already in the group.
fn peer_up_initial_table(size: usize) -> Work {
    let (_tx, mut manager) = manager();
    let mut receivers = members(&mut manager, size, false, None);
    manager.handle_update(routes_from(external(), 0, 1, ROUTES * size));
    drain_route_chunks(&mut manager);
    assert_eq!(
        drain(&mut receivers),
        (size * ROUTES * size, 0),
        "setup, size {size}"
    );
    let mut joiners = Vec::new();
    let work = checkpoints_in(|| {
        joiners.extend((size..size + BURST).map(|index| join(&mut manager, index, false, None).0));
    });
    assert_eq!(
        drain(&mut joiners),
        (BURST * ROUTES * size, 0),
        "size {size}"
    );
    assert_eq!(drain(&mut receivers), (0, 0), "size {size}");
    work
}

/// One reload moves all `size` members of a group holding `ROUTES * size`
/// prefixes to a policy that denies one of them. The table is walked once
/// for the group; each member costs the change, not the table.
fn policy_reload(size: usize) -> Work {
    let (_tx, mut manager) = manager();
    let old = deny_prefixes_chain(&[]);
    let mut receivers = members(&mut manager, size, false, Some(&old));
    manager.handle_update(routes_from(external(), 0, 1, ROUTES * size));
    drain_route_chunks(&mut manager);
    assert_eq!(
        drain(&mut receivers),
        (size * ROUTES * size, 0),
        "setup, size {size}"
    );
    let new = deny_prefixes_chain(&[Prefix::V4(prefix(1, 0))]);
    let replacements: Vec<_> = (0..size)
        .map(|index| crate::update::PeerExportPolicyReplacement {
            peer: member(index),
            export_policy: Some(new.clone()),
        })
        .collect();
    // The daemon's reload sequence: offer the cohort, and apply it
    // authoritatively when the cohort hands it back.
    let work = checkpoints_in(|| {
        let (reply, mut response) = tokio::sync::oneshot::channel();
        manager.handle_update(RibUpdate::ReplacePeerExportPolicies {
            replacements: replacements.clone(),
            reply,
        });
        finish_clean_transition(&mut manager);
        if response.try_recv().unwrap().unwrap()
            == crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply
        {
            manager
                .apply_export_policy_replacements_synchronously(replacements)
                .unwrap();
        }
    });
    assert_eq!(drain(&mut receivers), (0, size), "size {size}");
    work
}

/// `size` one-prefix UPDATEs arrive already queued for a group of `size`
/// members. They share distribution passes, so the member envelopes grow
/// with the members, not messages x members, and the members share the
/// pass's exact-export probes, so the checkpoints do too.
fn inbound_update_distribution(size: usize) -> Work {
    let (tx, mut manager) = manager();
    let mut receivers = members(&mut manager, size, false, None);
    assert_eq!(drain(&mut receivers), (0, 0), "setup, size {size}");
    for index in 0..size {
        let mut update = routes_from(external(), 0, 1, 0);
        if let RibUpdate::RoutesReceived { announced, .. } = &mut update {
            announced.push(make_route(prefix(1, index), Ipv4Addr::new(198, 51, 100, 1)));
        }
        tx.try_send(update).unwrap();
    }
    let before = manager.adj_rib_out_commit_stats.successful_enqueues;
    // The run loop's turns: finish the queued batch chunk by chunk, then
    // admit the next primary update.
    let mut work = checkpoints_in(|| {
        loop {
            if manager.process_next_route_chunk() {
                continue;
            }
            let Some(update) = manager.try_recv_primary() else {
                break;
            };
            manager.handle_update(update);
        }
    });
    work.insert(
        ENVELOPES,
        manager.adj_rib_out_commit_stats.successful_enqueues - before,
    );
    assert_eq!(drain(&mut receivers), (size * size, 0), "size {size}");
    work
}

#[test]
fn peer_down_burst_work_is_linear() {
    assert_linear("peer-down burst", &[ALL], peer_down_burst);
}

#[test]
fn peer_up_initial_table_work_is_linear() {
    assert_linear(
        "peer-up initial table",
        &[ALL, "initial_group_replay"],
        peer_up_initial_table,
    );
}

#[test]
fn policy_reload_work_is_linear() {
    assert_linear(
        "policy reload",
        &[ALL, "shared_inventory", "policy_filtered_retained"],
        policy_reload,
    );
}

#[test]
fn inbound_update_distribution_work_is_linear() {
    assert_linear(
        "inbound UPDATE distribution",
        &[ALL, "exact_probe_retirement", ENVELOPES],
        inbound_update_distribution,
    );
}

/// The tally reads only this thread's checkpoints, by stage.
#[test]
fn checkpoint_tally_counts_this_thread_by_stage() {
    let work = checkpoints_in(|| {
        slice_timing::checkpoint(None);
        slice_timing::checkpoint(Some("peer_adj_out_retirement"));
        std::thread::spawn(|| slice_timing::checkpoint(None))
            .join()
            .unwrap();
    });
    assert_eq!(
        work,
        BTreeMap::from([("", 1), ("peer_adj_out_retirement", 1), (ALL, 2)])
    );
}

/// Churn updates the live source and the memberless prepared destination.
/// Only the source needs an emission payload; the destination's table and
/// inventory journal must still carry that churn into the later transition.
#[expect(
    clippy::too_many_lines,
    reason = "one fixture attributes prestage phases and checks churn through the committing cohort"
)]
fn destination_prestage_churn(size: usize, prepare: bool) -> Work {
    const OLD: u32 = 0xFC00_0001;
    const NEW: u32 = 0xFC00_0002;
    let (tx, mut manager) = manager();
    manager.flush_poll_budget = Duration::ZERO;
    let old = super::update_groups::community_chain(OLD);
    let new = super::update_groups::community_chain(NEW);
    let (mut receivers, encoders): (Vec<_>, Vec<_>) = (0..size)
        .map(|index| join(&mut manager, index, true, Some(old.clone())))
        .unzip();
    let routes = ROUTES * size;
    manager.handle_update(routes_from(external(), 0, 1, routes));
    drain_route_chunks(&mut manager);
    assert_eq!(drain(&mut receivers), (size * routes, 0));
    let (reply, mut response) = oneshot::channel();
    let mut work = Work::new();
    if prepare {
        let begin = checkpoints_in(|| {
            manager.begin_destination_prestage(member(0), Some(&new), reply);
        });
        work.insert("prestage begin", begin[ALL]);
        let staging = checkpoints_in(|| {
            while manager.prestaged_inventory.is_none() {
                assert!(manager.pending_destination_prestage.is_some());
                manager.advance_destination_prestage();
            }
        });
        work.insert("prestage staging", staging[ALL]);
        // Visit one inventory slot before churn, so reconciliation must
        // replace an already-captured row as well as see later rows.
        let first_inventory = checkpoints_in(|| manager.advance_destination_prestage());
        work.insert("prestage inventory", first_inventory[ALL]);
    }
    let mut changed: BTreeSet<_> = (0..size).map(|index| prefix(1, index)).collect();
    if prepare {
        let Prefix::V4(captured) = manager.prestaged_inventory.as_ref().unwrap().announce[0].prefix
        else {
            unreachable!("IPv4 fixture")
        };
        if !changed.contains(&captured) {
            changed.pop_last();
            changed.insert(captured);
        }
    }
    let before = manager.adj_rib_out_commit_stats.successful_enqueues;
    for &prefix in &changed {
        let mut update = routes_from(external(), 0, 1, 0);
        if let RibUpdate::RoutesReceived { announced, .. } = &mut update {
            announced.push(make_route_with_lp(
                prefix,
                Ipv4Addr::new(198, 51, 100, 1),
                200,
            ));
        }
        tx.try_send(update).unwrap();
    }
    let churn = checkpoints_in(|| {
        while let Some(update) = manager.try_recv_primary() {
            manager.handle_update(update);
            drain_route_chunks(&mut manager);
        }
    });
    work.insert("churn checkpoints", churn[ALL]);
    work.insert("staging_shared_emit", churn["staging_shared_emit"]);
    work.insert(
        ENVELOPES,
        manager.adj_rib_out_commit_stats.successful_enqueues - before,
    );
    for rx in &mut receivers {
        let update = rx.try_recv().unwrap();
        assert_eq!(update.withdraw.len(), 0);
        assert_eq!(update.announce.len(), size);
        assert_eq!(
            update
                .announce
                .iter()
                .map(|route| route.prefix)
                .collect::<BTreeSet<_>>(),
            changed.iter().copied().map(Prefix::V4).collect(),
        );
        assert!(
            update
                .announce
                .iter()
                .all(|route| { route.local_pref() == 200 && route.communities() == [OLD] })
        );
        assert!(rx.try_recv().is_err());
    }
    if prepare {
        let before: usize = encoders.iter().map(|encoder| encoder.probe_count()).sum();
        let inventory = checkpoints_in(|| {
            while manager.prestaged_inventory.as_ref().unwrap().announce.len() < routes {
                manager.advance_destination_prestage();
            }
        });
        *work.get_mut("prestage inventory").unwrap() += inventory[ALL];
        let probes = checkpoints_in(|| {
            while manager.pending_destination_prestage.is_some() {
                manager.advance_destination_prestage();
            }
        });
        work.insert("prestage probe checkpoints", probes[ALL]);
        let after: usize = encoders.iter().map(|encoder| encoder.probe_count()).sum();
        work.insert("prestage exact probes", after - before);
        assert_eq!(after - before, routes, "one probe per destination row");
        assert_eq!(response.try_recv().unwrap(), Ok(()));
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::ReplacePeerExportPolicies {
            replacements: (0..size)
                .map(|index| crate::update::PeerExportPolicyReplacement {
                    peer: member(index),
                    export_policy: Some(new.clone()),
                })
                .collect(),
            reply,
        });
        finish_clean_transition(&mut manager);
        assert_eq!(
            response.try_recv().unwrap().unwrap(),
            crate::update::ExportPolicyCohortOutcome::Committed
        );
        // The dirty set exceeds the test-sized retained-proof bound (one),
        // so the fenced fallback probes once; all members reuse that proof.
        let committed: usize = encoders.iter().map(|encoder| encoder.probe_count()).sum();
        work.insert("transition exact probes", committed - after);
        assert_eq!(committed - after, routes);
        for rx in &mut receivers {
            let update = rx.try_recv().unwrap();
            assert_eq!(update.withdraw.len(), 0);
            assert_eq!(update.announce.len(), routes);
            assert_eq!(
                update
                    .announce
                    .iter()
                    .map(|route| route.prefix)
                    .collect::<BTreeSet<_>>(),
                (0..routes)
                    .map(|index| Prefix::V4(prefix(1, index)))
                    .collect(),
            );
            for route in update.announce.iter() {
                let was_changed = changed
                    .iter()
                    .any(|prefix| route.prefix == Prefix::V4(*prefix));
                assert_eq!(route.local_pref(), if was_changed { 200 } else { 100 });
                assert_eq!(route.communities(), [NEW]);
            }
            assert!(rx.try_recv().is_err());
        }
    }
    eprintln!("prestage={prepare}, size={size}: {work:?}");
    work
}

#[test]
fn destination_prestage_churn_builds_only_owned_emission() {
    for size in [SMALL, LARGE] {
        let ordinary = destination_prestage_churn(size, false);
        let prepared = destination_prestage_churn(size, true);
        assert_eq!(
            prepared["staging_shared_emit"], ordinary["staging_shared_emit"],
            "a memberless destination must not build another wire payload"
        );
        assert_eq!(prepared[ENVELOPES], size);
    }
}

#[test]
fn destination_prestage_work_is_linear() {
    assert_linear(
        "destination prestage",
        &[
            "prestage begin",
            "prestage staging",
            "prestage inventory",
            "prestage probe checkpoints",
            "prestage exact probes",
            "churn checkpoints",
            "staging_shared_emit",
            "transition exact probes",
            ENVELOPES,
        ],
        |size| destination_prestage_churn(size, true),
    );
}

/// One received `FlowSpec` table replayed while RFC 4724 selection deferral
/// holds the family, beside one injected rule. Only the injected rule is
/// selected; every received rule waits for the release. Selection must not
/// scan the retained table once per replayed key.
fn deferred_flowspec_replay(size: usize) -> Work {
    const FLOWSPEC: (Afi, Safi) = (Afi::Ipv4, Safi::FlowSpec);
    let (_tx, manager) = manager();
    let mut manager = manager.with_selection_deferral(crate::SelectionDeferralConfig {
        timeout: Duration::from_mins(2),
        waiters: vec![crate::SelectionDeferralWaiterConfig {
            peer: peer_v4(Ipv4Addr::new(192, 0, 2, 1)),
            families: vec![FLOWSPEC],
        }],
    });
    arm_selection_waiter(
        &mut manager,
        peer_v4(Ipv4Addr::new(192, 0, 2, 1)),
        &[FLOWSPEC],
    );
    let mut local = crate::test_support::make_flowspec_route(Ipv4Addr::UNSPECIFIED);
    local.peer = LOCAL_PEER;
    local.origin_type = crate::route::RouteOrigin::Local;
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectFlowSpec {
        route: local,
        reply,
    });
    rx.try_recv().unwrap().unwrap();
    let rules = (0..size * ROUTES)
        .map(|index| {
            let mut rule = crate::test_support::make_flowspec_route(Ipv4Addr::new(198, 51, 100, 1));
            rule.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
                rustbgpd_wire::FlowSpecPrefix::V4(prefix(1, index)),
            )];
            rule
        })
        .collect();
    let mut update = routes_from(external(), 0, 1, 0);
    if let RibUpdate::RoutesReceived {
        flowspec_announced, ..
    } = &mut update
    {
        *flowspec_announced = rules;
    }
    let work = checkpoints_in(|| {
        manager.handle_update(update);
        while manager.process_next_route_chunk() {}
    });
    assert!(manager.selection_deferred(FLOWSPEC));
    assert_eq!(
        manager.ribs[&external()].iter_flowspec().count(),
        size * ROUTES,
        "size {size}"
    );
    assert_eq!(
        manager
            .loc_rib
            .iter_flowspec()
            .map(|route| route.peer)
            .collect::<Vec<_>>(),
        vec![LOCAL_PEER],
        "size {size}"
    );
    work
}

#[test]
fn deferred_flowspec_replay_work_is_linear() {
    assert_linear(
        "received FlowSpec replay during selection deferral",
        &[ALL, "selection_flowspec"],
        deferred_flowspec_replay,
    );
}

fn deferred_unicast_manager() -> (mpsc::Sender<RibUpdate>, RibManager) {
    let (tx, manager) = manager();
    let mut manager = manager.with_selection_deferral(crate::SelectionDeferralConfig {
        timeout: Duration::from_mins(2),
        waiters: vec![crate::SelectionDeferralWaiterConfig {
            peer: peer_v4(Ipv4Addr::new(192, 0, 2, 1)),
            families: vec![(Afi::Ipv4, Safi::Unicast)],
        }],
    });
    arm_selection_waiter(
        &mut manager,
        peer_v4(Ipv4Addr::new(192, 0, 2, 1)),
        &[(Afi::Ipv4, Safi::Unicast)],
    );
    (tx, manager)
}

fn deferred_local_unicast(prefix: Ipv4Prefix) -> Route {
    let mut route = make_route(prefix, Ipv4Addr::UNSPECIFIED);
    route.peer = LOCAL_PEER;
    route.origin_type = crate::route::RouteOrigin::Local;
    route.path_id = 17;
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::NextHop(Ipv4Addr::UNSPECIFIED),
        PathAttribute::Communities(vec![0xFFFF_029A]),
    ]);
    route
}

fn inject_deferred_unicast(manager: &mut RibManager, route: Route) -> crate::update::InjectOutcome {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute { route, reply });
    response.try_recv().unwrap().unwrap()
}

/// A received-only prefix must not start an Add-Path candidate walk for
/// every receiver during the hold. The measured local replacement keeps
/// selection and output live, so skipping all work cannot satisfy the bar.
fn deferred_unicast_received_replay(size: usize) -> Work {
    let (_tx, mut manager) = deferred_unicast_manager();
    let mut receivers = Vec::new();
    for index in 0..size {
        let peer = member(index);
        manager.handle_update(RibUpdate::SetPeerExportEncoder {
            peer,
            session_id: 1,
            encoder: ReusableExactExportEncoder::new(
                u64::try_from(index).unwrap() + 1,
                WIRE_PROFILE,
            ),
        });
        let (outbound_tx, rx) = mpsc::channel(4096);
        let mut up = test_peer_up(peer, 1, outbound_tx);
        if let RibUpdate::PeerUp {
            add_path_send_families,
            add_path_send_max,
            ..
        } = &mut up
        {
            *add_path_send_families = vec![(Afi::Ipv4, Safi::Unicast)];
            *add_path_send_max = 2;
        }
        manager.handle_update(up);
        receivers.push(rx);
    }
    let mut local = deferred_local_unicast(prefix(200, 0));
    assert_eq!(
        inject_deferred_unicast(&mut manager, local.clone()),
        crate::update::InjectOutcome::Created
    );
    for receiver in &mut receivers {
        assert_eq!(drain(std::slice::from_mut(receiver)), (1, 0));
    }

    let work = checkpoints_in(|| {
        manager.handle_update(routes_from(external(), 0, 1, size * ROUTES));
        drain_route_chunks(&mut manager);
        AttrSet::edit(&mut local.attributes, |attributes| {
            attributes.push(PathAttribute::Med(17));
        });
        assert_eq!(
            inject_deferred_unicast(&mut manager, local),
            crate::update::InjectOutcome::Replaced
        );
    });

    assert!(manager.selection_deferred((Afi::Ipv4, Safi::Unicast)));
    assert_eq!(manager.ribs[&external()].len(), size * ROUTES);
    assert_eq!(manager.ribs[&LOCAL_PEER].len(), 1);
    assert_eq!(
        manager.ribs.values().map(AdjRibIn::len).sum::<usize>(),
        size * ROUTES + 1
    );
    assert_eq!(
        manager
            .ribs
            .values()
            .map(AdjRibIn::retained_stale_count)
            .sum::<u64>(),
        0
    );
    let selected: Vec<_> = manager.loc_rib.iter().collect();
    assert_eq!(selected.len(), 1);
    assert_eq!((selected[0].peer, selected[0].path_id), (LOCAL_PEER, 17));
    assert!(!selected[0].is_stale && !selected[0].is_llgr_stale);
    for receiver in &mut receivers {
        let mut announcements = Vec::new();
        while let Ok(update) = receiver.try_recv() {
            assert_eq!(update.withdraw, Vec::new());
            assert_eq!(update.end_of_rib, Vec::new());
            announcements.extend(update.announce.iter().cloned());
        }
        assert_eq!(
            announcements.len(),
            1,
            "one changed local announcement per receiver"
        );
        assert_eq!(
            (
                announcements[0].peer,
                announcements[0].prefix,
                announcements[0].path_id
            ),
            (LOCAL_PEER, Prefix::V4(prefix(200, 0)), 1)
        );
    }
    eprintln!("deferred unicast received replay size {size}: {work:?}");
    work
}

#[test]
fn deferred_unicast_received_replay_work_is_linear() {
    assert_linear(
        "received unicast replay during selection deferral",
        &[ALL, "selection_candidates"],
        deferred_unicast_received_replay,
    );
}

/// Grow retained source RIBs alongside distinct local injections, keeping
/// one outbound receiver. A local lookup must not scan every retained RIB
/// for every injected prefix.
fn deferred_unicast_local_replay(size: usize) -> Work {
    let (_tx, mut manager) = deferred_unicast_manager();
    let mut receivers = members(&mut manager, 1, false, None);
    for index in 0..size {
        let source = peer_v4(Ipv4Addr::new(
            198,
            51,
            100,
            u8::try_from(index + 1).unwrap(),
        ));
        manager.handle_update(routes_from(source, 0, index, ROUTES));
        drain_route_chunks(&mut manager);
        assert_eq!(manager.ribs[&source].len(), ROUTES);
    }
    assert_eq!(drain(&mut receivers), (0, 0));
    assert_eq!(manager.loc_rib.len(), 0);

    let work = checkpoints_in(|| {
        for index in 0..size * ROUTES {
            assert_eq!(
                inject_deferred_unicast(&mut manager, deferred_local_unicast(prefix(200, index))),
                crate::update::InjectOutcome::Created
            );
        }
    });

    assert!(manager.selection_deferred((Afi::Ipv4, Safi::Unicast)));
    assert_eq!(manager.ribs[&LOCAL_PEER].len(), size * ROUTES);
    assert_eq!(
        manager.ribs.values().map(AdjRibIn::len).sum::<usize>(),
        2 * size * ROUTES
    );
    assert_eq!(
        manager
            .ribs
            .values()
            .map(AdjRibIn::retained_stale_count)
            .sum::<u64>(),
        0
    );
    assert_eq!(manager.loc_rib.len(), size * ROUTES);
    assert!(manager.loc_rib.iter().all(|route| {
        route.peer == LOCAL_PEER && route.path_id == 17 && !route.is_stale && !route.is_llgr_stale
    }));
    let mut announcements = Vec::new();
    while let Ok(update) = receivers[0].try_recv() {
        assert_eq!(update.withdraw, Vec::new());
        assert_eq!(update.end_of_rib, Vec::new());
        announcements.extend(update.announce.iter().cloned());
    }
    assert_eq!(announcements.len(), size * ROUTES);
    assert!(
        announcements
            .iter()
            .all(|route| route.peer == LOCAL_PEER && route.path_id == 0)
    );
    let actual: BTreeSet<_> = announcements
        .into_iter()
        .map(|route| route.prefix)
        .collect();
    let expected: BTreeSet<_> = (0..size * ROUTES)
        .map(|index| Prefix::V4(prefix(200, index)))
        .collect();
    assert_eq!(actual, expected);
    eprintln!("deferred unicast local replay size {size}: {work:?}");
    work
}

#[test]
fn deferred_unicast_local_replay_work_is_linear() {
    assert_linear(
        "local unicast replay during selection deferral",
        &[ALL, "selection_candidates"],
        deferred_unicast_local_replay,
    );
}

/// All paths share an NLRI. Original ordinary paths precede eligible paths,
/// so rescanning original intent per outbound rank would add quadratic work.
fn deferred_unicast_sibling_initial_replay(size: usize) -> Work {
    let count = size * ROUTES;
    let (_tx, mut manager) = deferred_unicast_manager();
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 0), 24);
    for index in 0..count {
        let mut route = deferred_local_unicast(prefix);
        route.path_id = u32::try_from(index).unwrap();
        AttrSet::edit(&mut route.attributes, |attrs| {
            attrs.retain(|attr| !matches!(attr, PathAttribute::Communities(_)));
        });
        assert_eq!(
            inject_deferred_unicast(&mut manager, route),
            crate::update::InjectOutcome::Created
        );
    }
    assert_eq!(manager.loc_rib.len(), 0);
    for index in count..2 * count - 1 {
        let mut route = deferred_local_unicast(prefix);
        route.path_id = u32::try_from(index).unwrap();
        assert_eq!(
            inject_deferred_unicast(&mut manager, route),
            crate::update::InjectOutcome::Created
        );
    }
    let target = member(2);
    let mut receiver = None;
    let work = checkpoints_in(|| {
        let mut route = deferred_local_unicast(prefix);
        route.path_id = u32::try_from(2 * count - 1).unwrap();
        assert_eq!(
            inject_deferred_unicast(&mut manager, route),
            crate::update::InjectOutcome::Created
        );
        let (outbound_tx, rx) = mpsc::channel(16);
        let mut up = test_peer_up(target, 1, outbound_tx);
        if let RibUpdate::PeerUp {
            add_path_send_families,
            add_path_send_max,
            ..
        } = &mut up
        {
            *add_path_send_families = vec![(Afi::Ipv4, Safi::Unicast)];
            *add_path_send_max = u32::try_from(count).unwrap();
        }
        manager.handle_update(up);
        receiver = Some(rx);
    });
    assert!(manager.selection_deferred((Afi::Ipv4, Safi::Unicast)));
    assert_eq!(manager.ribs[&LOCAL_PEER].len(), 2 * count);
    assert_eq!(
        manager.ribs.values().map(AdjRibIn::len).sum::<usize>(),
        2 * count
    );
    assert_eq!(
        manager
            .ribs
            .values()
            .map(AdjRibIn::retained_stale_count)
            .sum::<u64>(),
        0
    );
    let selected: Vec<_> = manager.loc_rib.iter().collect();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].peer, LOCAL_PEER);
    assert!(selected[0].path_id >= u32::try_from(count).unwrap());
    assert!(
        selected[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE)
    );
    let mut paths = BTreeSet::new();
    while let Ok(update) = receiver.as_mut().unwrap().try_recv() {
        assert_eq!(update.withdraw, [] as [(Prefix, u32); 0]);
        assert_eq!(update.end_of_rib, [] as [(Afi, Safi); 0]);
        for route in update.announce.iter() {
            assert_eq!(route.prefix, Prefix::V4(prefix));
            assert_eq!(route.peer, LOCAL_PEER);
            assert!(
                route
                    .communities()
                    .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE)
            );
            assert!(paths.insert(route.path_id), "each wire path appears once");
        }
    }
    assert_eq!(paths, (1..=u32::try_from(count).unwrap()).collect());
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryAdvertisedCount {
        peer: target,
        reply,
    });
    assert_eq!(response.try_recv().unwrap(), count);
    eprintln!("deferred unicast sibling initial replay size {size}: {work:?}");
    work
}

#[test]
fn deferred_unicast_sibling_initial_replay_work_is_linear() {
    assert_linear(
        "same-prefix RTBH Add-Path initial replay during selection deferral",
        &[ALL, "selection_candidates"],
        deferred_unicast_sibling_initial_replay,
    );
}

/// A late grouped member has no proof of frozen ordinary rows. Replaying
/// local RTBH must maintain its actual counts without walking the growing
/// frozen table or admitted-key proof after every single-route commit.
#[expect(
    clippy::too_many_lines,
    reason = "the dormant-to-held growth shape keeps exact wire, public count and stale-count assertions beside the measured injection loop"
)]
fn deferred_initial_admission_local_replay(size: usize) -> Work {
    let family = (Afi::Ipv4, Safi::Unicast);
    let count = size * ROUTES;
    let source = member(0);
    let observer = member(1);
    let waiter = member(2);
    let late = member(3);
    let (_tx, manager) = manager();
    let mut manager = manager.with_selection_deferral(crate::SelectionDeferralConfig {
        timeout: Duration::from_mins(2),
        waiters: vec![crate::SelectionDeferralWaiterConfig {
            peer: waiter,
            families: vec![family],
        }],
    });
    let mut source_rx = join(&mut manager, 0, false, None).0;
    let mut observer_rx = join(&mut manager, 1, false, None).0;
    assert!(!manager.selection_deferred(family));
    for receiver in [&mut source_rx, &mut observer_rx] {
        let initial = receiver.try_recv().unwrap();
        assert!(initial.announce.is_empty());
        assert_eq!(initial.end_of_rib, vec![family]);
        assert!(receiver.try_recv().is_err());
    }
    manager.handle_update(routes_from(source, 1, 1, count));
    drain_route_chunks(&mut manager);
    let ordinary: BTreeSet<_> = (0..count)
        .map(|index| Prefix::V4(prefix(1, index)))
        .collect();
    let mut before = BTreeSet::new();
    while let Ok(update) = observer_rx.try_recv() {
        assert!(update.withdraw.is_empty() && update.end_of_rib.is_empty());
        assert_eq!(
            update.refresh_markers,
            [] as [(Afi, Safi, rustbgpd_wire::RouteRefreshSubtype); 0]
        );
        for route in update.announce.iter() {
            assert_eq!(route.peer, source);
            assert!(
                before.insert(route.prefix),
                "setup cannot duplicate a route"
            );
        }
    }
    assert_eq!(before, ordinary);
    let gid = manager.grouped_member_of(observer).unwrap();
    assert_eq!(manager.group_ribs[&gid].table.len(), count);

    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: waiter,
        session_id: 1,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![family],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let mut waiter_rx = join(&mut manager, 2, false, None).0;
    assert!(manager.selection_deferred(family));
    let mut late_rx = join(&mut manager, 3, false, None).0;
    assert_eq!(manager.grouped_member_of(late), Some(gid));
    assert!(
        manager
            .pending_group_admitted
            .get(&late)
            .unwrap()
            .is_empty()
    );
    assert!(waiter_rx.try_recv().is_err() && late_rx.try_recv().is_err());

    let work = checkpoints_in(|| {
        for index in 0..count {
            assert_eq!(
                inject_deferred_unicast(&mut manager, deferred_local_unicast(prefix(200, index))),
                crate::update::InjectOutcome::Created
            );
        }
    });

    assert!(manager.selection_deferred(family));
    assert_eq!(manager.ribs[&source].len(), count);
    assert_eq!(manager.ribs[&LOCAL_PEER].len(), count);
    assert_eq!(
        manager.ribs.values().map(AdjRibIn::len).sum::<usize>(),
        2 * count
    );
    assert_eq!(
        manager
            .ribs
            .values()
            .map(AdjRibIn::retained_stale_count)
            .sum::<u64>(),
        0
    );
    assert_eq!(manager.loc_rib.len(), 2 * count);
    assert!(
        manager
            .loc_rib
            .iter()
            .all(|route| !route.is_stale && !route.is_llgr_stale)
    );
    let local: BTreeSet<_> = (0..count)
        .map(|index| Prefix::V4(prefix(200, index)))
        .collect();
    for receiver in [
        &mut source_rx,
        &mut observer_rx,
        &mut waiter_rx,
        &mut late_rx,
    ] {
        let mut actual = BTreeSet::new();
        while let Ok(update) = receiver.try_recv() {
            assert!(update.withdraw.is_empty() && update.end_of_rib.is_empty());
            assert_eq!(
                update.refresh_markers,
                [] as [(Afi, Safi, rustbgpd_wire::RouteRefreshSubtype); 0]
            );
            for route in update.announce.iter() {
                assert_eq!(route.peer, LOCAL_PEER);
                assert!(
                    actual.insert(route.prefix),
                    "one local announcement per receiver"
                );
            }
        }
        assert_eq!(actual, local);
    }
    let (reply, mut bmp) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryBmpPeerStats { reply });
    let bmp = bmp.try_recv().unwrap();
    for (peer, expected) in [(observer, 2 * count), (late, count)] {
        let expected_prefixes: BTreeSet<_> = local
            .iter()
            .copied()
            .chain(ordinary.iter().copied().filter(|_| peer == observer))
            .collect();
        let advertised = manager.grouped_advertised_routes(peer).unwrap();
        assert_eq!(advertised.len(), expected);
        assert_eq!(
            advertised
                .iter()
                .map(|route| route.prefix)
                .collect::<BTreeSet<_>>(),
            expected_prefixes
        );
        let (reply, mut public_count) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryAdvertisedCount { peer, reply });
        assert_eq!(public_count.try_recv().unwrap(), expected);
        assert_eq!(
            manager.grouped_advertised_unicast_lens(peer),
            Some([expected, 0])
        );
        assert_eq!(
            bmp.adj_rib_out_post[&peer],
            vec![(family, u64::try_from(expected).unwrap())]
        );
    }
    eprintln!("deferred initial-admission local replay size {size}: {work:?}");
    work
}

#[test]
fn deferred_initial_admission_local_replay_work_is_linear() {
    assert_linear(
        "local RTBH replay beside frozen initial-admission proofs",
        &[ALL, "selection_candidates"],
        deferred_initial_admission_local_replay,
    );
}

fn post_miss_observer(manager: &mut RibManager) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = member(1);
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 1,
        encoder: ReusableExactExportEncoder::new(2, WIRE_PROFILE),
    });
    let (outbound_tx, outbound_rx) = mpsc::channel(1);
    let mut up = test_peer_up(peer, 1, outbound_tx);
    if let RibUpdate::PeerUp { peer_asn, .. } = &mut up {
        *peer_asn = 65_101;
    }
    manager.handle_update(up);
    outbound_rx
}

fn post_miss_drain(
    receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>],
    wires: &mut [BTreeMap<Prefix, Route>],
) -> Vec<usize> {
    receivers
        .iter_mut()
        .zip(wires)
        .map(|(rx, wire)| {
            let mut markers = 0;
            while let Ok(update) = rx.try_recv() {
                assert_eq!(update.withdraw, [] as [(Prefix, u32); 0]);
                assert_eq!(
                    update.refresh_markers,
                    [] as [(Afi, Safi, rustbgpd_wire::RouteRefreshSubtype); 0]
                );
                for route in update.announce.iter() {
                    assert_eq!(route.path_id, 0);
                    assert!(!route.is_stale && !route.is_llgr_stale);
                    wire.insert(route.prefix, route.clone());
                }
                for family in update.end_of_rib {
                    assert_eq!(family, (Afi::Ipv4, Safi::Unicast));
                    markers += 1;
                }
            }
            markers
        })
        .collect()
}

fn post_miss_advertised_counts(manager: &mut RibManager, expected: [usize; 4]) {
    let family = (Afi::Ipv4, Safi::Unicast);
    let (reply, mut bmp) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryBmpPeerStats { reply });
    let bmp = bmp.try_recv().unwrap();
    for (index, count) in expected.into_iter().enumerate() {
        let peer = member(index);
        let (reply, mut public) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryAdvertisedCount { peer, reply });
        assert_eq!(public.try_recv().unwrap(), count);
        assert_eq!(
            manager.grouped_advertised_unicast_lens(peer),
            Some([count, 0])
        );
        assert_eq!(
            bmp.adj_rib_out_post[&peer],
            vec![(family, u64::try_from(count).unwrap())]
        );
    }
}

/// A real writer miss must not turn subsequent held RTBH deltas into full
/// resyncs of the growing table, while frozen admitted rows remain owned.
#[expect(
    clippy::too_many_lines,
    reason = "the post-miss growth transcript keeps exact writer, retained-intent, count and release-cleanup assertions beside measured injections"
)]
fn deferred_post_miss_rtbh_replay(size: usize) -> Work {
    let family = (Afi::Ipv4, Safi::Unicast);
    let count = size * ROUTES;
    let source = member(0);
    let observer = member(1);
    let waiter = member(2);
    let (_tx, manager) = manager();
    let mut manager = manager.with_selection_deferral(crate::SelectionDeferralConfig {
        timeout: Duration::from_mins(2),
        waiters: vec![crate::SelectionDeferralWaiterConfig {
            peer: waiter,
            families: vec![family],
        }],
    });
    let mut receivers = vec![
        join(&mut manager, 0, false, None).0,
        post_miss_observer(&mut manager),
        join(&mut manager, 3, false, None).0,
    ];
    let mut wires = vec![BTreeMap::new(); 3];
    assert!(!manager.selection_deferred(family));
    assert_eq!(post_miss_drain(&mut receivers, &mut wires), [1, 1, 1]);
    let ordinary: BTreeSet<_> = (0..count)
        .map(|index| Prefix::V4(prefix(1, index)))
        .collect();
    for index in 0..count {
        let IpAddr::V4(next_hop) = source.addr() else {
            unreachable!("test source is IPv4")
        };
        let mut update = test_routes_received(source, vec![make_route(prefix(1, index), next_hop)]);
        if let RibUpdate::RoutesReceived { session_id, .. } = &mut update {
            *session_id = 1;
        }
        manager.handle_update(update);
        drain_route_chunks(&mut manager);
        assert_eq!(post_miss_drain(&mut receivers, &mut wires), [0, 0, 0]);
    }
    assert!(wires[0].is_empty());
    for wire in &wires[1..] {
        assert_eq!(wire.keys().copied().collect::<BTreeSet<_>>(), ordinary);
    }
    assert!(!manager.dirty_peers.contains(&observer));
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: waiter,
        session_id: 1,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![family],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    receivers.insert(2, join(&mut manager, 2, false, None).0);
    wires.insert(2, BTreeMap::new());
    assert!(manager.selection_deferred(family));
    assert_eq!(post_miss_drain(&mut receivers, &mut wires), [0; 4]);
    for index in [count, count + 1] {
        assert_eq!(
            inject_deferred_unicast(&mut manager, deferred_local_unicast(prefix(200, index))),
            crate::update::InjectOutcome::Created
        );
        if index == count {
            assert_eq!(manager.outbound_peers[&observer].capacity(), 0);
            assert!(!manager.dirty_peers.contains(&observer));
        }
    }
    assert!(manager.dirty_peers.contains(&observer));
    assert_eq!(post_miss_drain(&mut receivers, &mut wires), [0; 4]);
    assert!(!wires[1].contains_key(&Prefix::V4(prefix(200, count + 1))));
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert_eq!(post_miss_drain(&mut receivers, &mut wires), [0; 4]);
    assert!(wires[1].contains_key(&Prefix::V4(prefix(200, count + 1))));
    assert!(manager.dirty_peers.contains(&observer));
    assert!(manager.pending_group_admitted.contains_record(observer));
    let work = checkpoints_in(|| {
        for index in 0..count {
            assert_eq!(
                inject_deferred_unicast(&mut manager, deferred_local_unicast(prefix(200, index))),
                crate::update::InjectOutcome::Created
            );
            assert_eq!(post_miss_drain(&mut receivers, &mut wires), [0; 4]);
        }
    });
    let local: BTreeSet<_> = (0..count + 2)
        .map(|index| Prefix::V4(prefix(200, index)))
        .collect();
    let all: BTreeSet<_> = ordinary.union(&local).copied().collect();
    for (index, wire) in wires.iter().enumerate() {
        assert_eq!(
            wire.keys().copied().collect::<BTreeSet<_>>(),
            if index == 0 || index == 2 {
                &local
            } else {
                &all
            }
            .clone()
        );
    }
    assert_eq!(wires[1].len(), 2 * count + 2);
    assert_eq!(manager.ribs[&source].len(), count);
    assert_eq!(manager.ribs[&LOCAL_PEER].len(), count + 2);
    assert_eq!(
        manager.ribs.values().map(AdjRibIn::len).sum::<usize>(),
        2 * count + 2
    );
    assert_eq!(manager.loc_rib.len(), 2 * count + 2);
    assert_eq!(
        manager
            .ribs
            .values()
            .map(AdjRibIn::retained_stale_count)
            .sum::<u64>(),
        0
    );
    assert!(
        manager
            .loc_rib
            .iter()
            .all(|route| !route.is_stale && !route.is_llgr_stale)
    );
    assert!(manager.selection_deferred(family));
    assert!(manager.dirty_peers.contains(&observer));
    let admitted = manager.pending_group_admitted.get(&observer).unwrap();
    assert_eq!(admitted.len(), all.len());
    for prefix in &all {
        assert!(admitted.contains(&crate::update::ExactExportKey::Unicast(*prefix, 0)));
    }
    post_miss_advertised_counts(
        &mut manager,
        [count + 2, 2 * count + 2, count + 2, 2 * count + 2],
    );
    manager.handle_update(RibUpdate::EndOfRib {
        peer: waiter,
        session_id: 1,
        afi: family.0,
        safi: family.1,
    });
    let mut release_markers = post_miss_drain(&mut receivers, &mut wires);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    for (total, markers) in release_markers
        .iter_mut()
        .zip(post_miss_drain(&mut receivers, &mut wires))
    {
        *total += markers;
    }
    assert_eq!(release_markers, [0, 0, 1, 0]);
    assert!(!manager.selection_deferred(family));
    assert!(manager.dirty_peers.is_empty());
    for (index, wire) in wires.iter().enumerate() {
        assert!(
            !manager
                .pending_group_admitted
                .contains_record(member(index)),
            "peer {index} retains its proof after release"
        );
        assert_eq!(
            wire.keys().copied().collect::<BTreeSet<_>>(),
            if index == 0 { &local } else { &all }.clone()
        );
    }
    post_miss_advertised_counts(
        &mut manager,
        [count + 2, 2 * count + 2, 2 * count + 2, 2 * count + 2],
    );
    eprintln!("deferred post-miss RTBH replay size {size}: {work:?}");
    work
}

#[test]
fn deferred_post_miss_rtbh_replay_work_is_linear() {
    assert_linear(
        "post-miss RTBH replay beside frozen admitted routes",
        &[ALL, "selection_candidates"],
        deferred_post_miss_rtbh_replay,
    );
}

fn receive_policy_rejection(manager: &mut RibManager, index: usize, local_pref: u32) {
    let source = member(0);
    let IpAddr::V4(next_hop) = source.addr() else {
        unreachable!("test source is IPv4")
    };
    let mut update = test_routes_received(
        source,
        vec![make_route_with_lp(prefix(1, index), next_hop, local_pref)],
    );
    if let RibUpdate::RoutesReceived { session_id, .. } = &mut update {
        *session_id = 1;
    }
    manager.handle_update(update);
    drain_route_chunks(manager);
}

fn policy_rejection_events(manager: &RibManager, target: PeerId) -> usize {
    manager
        .route_event_history
        .iter()
        .filter(|event| {
            event.event_type == RouteEventType::PolicyFiltered
                && event.target_peer == Some(target.addr())
        })
        .count()
}

#[expect(
    clippy::too_many_lines,
    reason = "one actual-caller growth transcript pins retained history, event edges, wire output and withdrawal cleanup"
)]
fn incremental_policy_rejection_updates(size: usize) -> Work {
    let count = size * ROUTES;
    let source = member(0);
    let target = member(1);
    let (_tx, mut manager) = manager();
    let policy = super::export_explain::deny_local_pref_at_least(200);
    let mut receivers = vec![
        join(&mut manager, 0, false, None).0,
        join(&mut manager, 1, false, Some(policy)).0,
    ];
    for rx in &mut receivers {
        let initial = rx.try_recv().unwrap();
        assert!(initial.announce.is_empty());
        assert_eq!(initial.end_of_rib, [(Afi::Ipv4, Safi::Unicast)]);
        assert!(rx.try_recv().is_err());
    }
    let work = checkpoints_in(|| {
        for index in 0..count {
            receive_policy_rejection(&mut manager, index, 200);
            assert_eq!(drain(&mut receivers), (0, 0));
        }
    });
    let expected: HashSet<_> = (0..count)
        .map(|index| PolicyFilteredRouteKey {
            target_peer: target,
            source_peer: source,
            prefix: Prefix::V4(prefix(1, index)),
            path_id: 0,
        })
        .collect();
    assert_eq!(retained_policy_rejection_keys(&manager, target), expected);
    assert_eq!(policy_rejection_events(&manager, target), count);
    for event in manager.route_event_history.iter().filter(|event| {
        event.event_type == RouteEventType::PolicyFiltered
            && event.target_peer == Some(target.addr())
    }) {
        assert_eq!(event.peer, Some(source.addr()));
        assert_eq!(event.path_id, 0);
        assert_eq!(event.reason, "policy_denied");
        assert!(expected.iter().any(|key| key.prefix == event.prefix));
    }
    assert_eq!(manager.ribs[&source].len(), count);
    assert_eq!(
        manager.ribs.values().map(AdjRibIn::len).sum::<usize>(),
        count
    );
    assert_eq!(manager.loc_rib.len(), count);
    assert_eq!(
        manager
            .ribs
            .values()
            .map(AdjRibIn::retained_stale_count)
            .sum::<u64>(),
        0
    );
    assert!(
        manager
            .loc_rib
            .iter()
            .all(|route| !route.is_stale && !route.is_llgr_stale)
    );
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryAdvertisedCount {
        peer: target,
        reply,
    });
    assert_eq!(response.try_recv().unwrap(), 0);

    let last = count - 1;
    receive_policy_rejection(&mut manager, last, 200);
    assert_eq!(drain(&mut receivers), (0, 0));
    assert_eq!(policy_rejection_events(&manager, target), count);
    assert_eq!(retained_policy_rejection_keys(&manager, target), expected);
    receive_policy_rejection(&mut manager, last, 100);
    assert_eq!(drain(&mut receivers), (1, 0));
    assert_eq!(policy_rejection_events(&manager, target), count);
    assert_eq!(
        retained_policy_rejection_keys(&manager, target).len(),
        count - 1
    );
    receive_policy_rejection(&mut manager, last, 200);
    assert_eq!(drain(&mut receivers), (0, 1));
    assert_eq!(policy_rejection_events(&manager, target), count + 1);
    assert_eq!(retained_policy_rejection_keys(&manager, target), expected);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 1,
        announced: Vec::new(),
        withdrawn: vec![(Prefix::V4(prefix(1, last)), 0)],
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    assert_eq!(drain(&mut receivers), (0, 0));
    let mut without_last = expected.clone();
    without_last.retain(|key| key.prefix != Prefix::V4(prefix(1, last)));
    assert_eq!(
        retained_policy_rejection_keys(&manager, target),
        without_last
    );
    assert_eq!(policy_rejection_events(&manager, target), count + 1);
    receive_policy_rejection(&mut manager, last, 200);
    assert_eq!(drain(&mut receivers), (0, 0));
    assert_eq!(retained_policy_rejection_keys(&manager, target), expected);
    assert_eq!(policy_rejection_events(&manager, target), count + 2);
    assert_eq!(manager.ribs[&source].len(), count);
    assert_eq!(manager.loc_rib.len(), count);
    manager.handle_update(RibUpdate::PeerDown {
        peer: target,
        session_id: 1,
    });
    assert!(!manager.policy_filtered_routes.contains_key(&target));
    assert_eq!(manager.ribs[&source].len(), count);
    assert_eq!(manager.loc_rib.len(), count);
    eprintln!("incremental policy rejection size {size}: {work:?}");
    work
}

#[test]
fn incremental_policy_rejection_updates_work_is_linear() {
    assert_linear(
        "incremental policy rejection retention",
        &[ALL, "policy_filtered_retained"],
        incremental_policy_rejection_updates,
    );
}

fn withdraw_policy_rejection(manager: &mut RibManager, index: usize) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: member(0),
        session_id: 1,
        announced: Vec::new(),
        withdrawn: vec![(Prefix::V4(prefix(1, index)), 0)],
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    });
    drain_route_chunks(manager);
}

/// A deny-all-above-LP-200 target holding one permitted route (index 1)
/// and one denied route (index 0), with the target's channel then filled.
fn rejection_history_with_full_target(
    ungrouped: bool,
) -> (RibManager, Vec<mpsc::Receiver<OutboundRouteUpdate>>) {
    let target = member(1);
    let (_tx, mut manager) = manager();
    manager.test_force_ungrouped = ungrouped;
    let policy = super::export_explain::deny_local_pref_at_least(200);
    let mut receivers = vec![
        join(&mut manager, 0, false, None).0,
        join(&mut manager, 1, false, Some(policy)).0,
    ];
    assert_eq!(manager.grouped_member_of(target).is_none(), ungrouped);
    receive_policy_rejection(&mut manager, 1, 100);
    receive_policy_rejection(&mut manager, 0, 200);
    drain(&mut receivers);
    assert_eq!(policy_rejection_events(&manager, target), 1);
    assert_eq!(retained_policy_rejection_keys(&manager, target).len(), 1);
    let sender = manager.outbound_peers[&target].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    (manager, receivers)
}

/// The dirty resync after the channel drains must retire the withdrawn
/// denial's history, so its next denial is a new `PolicyFiltered` event.
fn resync_retires_stale_rejection_history(
    mut manager: RibManager,
    mut receivers: Vec<mpsc::Receiver<OutboundRouteUpdate>>,
) {
    let target = member(1);
    assert!(manager.dirty_peers.contains(&target));
    drain(&mut receivers);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert!(!manager.dirty_peers.contains(&target), "resync committed");
    assert!(
        retained_policy_rejection_keys(&manager, target).is_empty(),
        "the dirty resync must retire the withdrawn route's denial"
    );
    receive_policy_rejection(&mut manager, 0, 200);
    assert_eq!(retained_policy_rejection_keys(&manager, target).len(), 1);
    assert_eq!(
        policy_rejection_events(&manager, target),
        2,
        "a denial after the withdrawal is a new PolicyFiltered event"
    );
}

/// The denied route is withdrawn while the dirty target's resync waits on
/// its full channel.
fn deferred_withdraw_rejection_history(ungrouped: bool) {
    let (mut manager, receivers) = rejection_history_with_full_target(ungrouped);
    manager.mark_outbound_dirty(member(1));
    withdraw_policy_rejection(&mut manager, 0);
    assert_eq!(manager.loc_rib.len(), 1);
    assert_eq!(retained_policy_rejection_keys(&manager, member(1)).len(), 1);
    resync_retires_stale_rejection_history(manager, receivers);
}

#[test]
fn deferred_withdraw_rejection_history_grouped() {
    deferred_withdraw_rejection_history(false);
}

#[test]
fn deferred_withdraw_rejection_history_ungrouped() {
    deferred_withdraw_rejection_history(true);
}

/// One UPDATE withdraws the denied route and announces a permitted one; the
/// clean target's send fails on its full channel, so the pass's history
/// refresh never commits.
fn failed_send_rejection_history(ungrouped: bool) {
    let (mut manager, receivers) = rejection_history_with_full_target(ungrouped);
    let source = member(0);
    let IpAddr::V4(next_hop) = source.addr() else {
        unreachable!("test source is IPv4")
    };
    let mut update = test_routes_received(
        source,
        vec![make_route_with_lp(prefix(1, 2), next_hop, 100)],
    );
    if let RibUpdate::RoutesReceived {
        session_id,
        withdrawn,
        ..
    } = &mut update
    {
        *session_id = 1;
        withdrawn.push((Prefix::V4(prefix(1, 0)), 0));
    }
    manager.handle_update(update);
    drain_route_chunks(&mut manager);
    assert_eq!(manager.loc_rib.len(), 2);
    assert_eq!(retained_policy_rejection_keys(&manager, member(1)).len(), 1);
    resync_retires_stale_rejection_history(manager, receivers);
}

#[test]
fn failed_send_rejection_history_grouped() {
    failed_send_rejection_history(false);
}

#[test]
fn failed_send_rejection_history_ungrouped() {
    failed_send_rejection_history(true);
}

/// One clean single-prefix pass to [`SMALL`] members without export
/// policies has no replay or rejection-inventory work: it creates no
/// readiness owner, and a readiness query queued across it is answered at
/// the actor-loop seam.
fn clean_pass_owns_no_readiness(ungrouped: bool) {
    let (_tx, mut manager) = manager();
    manager.test_force_ungrouped = ungrouped;
    let mut receivers = members(&mut manager, SMALL, false, None);
    assert_eq!(manager.grouped_member_of(member(0)).is_none(), ungrouped);
    manager.handle_update(routes_from(external(), 0, 1, 1));
    drain_route_chunks(&mut manager);
    assert_eq!(drain(&mut receivers), (SMALL, 0));
    let (tx, rx) = mpsc::channel(1);
    manager.readiness_rx = Some(rx);
    let (reply, mut response) = oneshot::channel();
    tx.try_send(crate::update::RibReadinessQuery::LocRibCount {
        reply,
        enqueued: std::time::Instant::now(),
    })
    .unwrap();
    manager.replacement_readiness_receipts.clear();
    let (handoffs, _) = crate::manager::executor_handoffs();
    manager.handle_update(routes_from(external(), 0, 2, 1));
    drain_route_chunks(&mut manager);
    assert_eq!(drain(&mut receivers), (SMALL, 0));
    assert_eq!(
        manager.replacement_readiness_receipts.len(),
        0,
        "{:?}",
        manager.replacement_readiness_receipts
    );
    assert_eq!(
        crate::manager::executor_handoffs().0,
        handoffs,
        "clean fanout stays on the synchronous fast path"
    );
    assert_eq!(response.try_recv().unwrap(), Ok(2));
    let seams = histogram_sample_counts_by_label(
        &manager.metrics,
        "bgp_rib_readiness_query_wait_seconds",
        "seam",
    );
    assert_eq!(seams["actor_loop"], 1, "{seams:?}");
    assert_eq!(seams["policy_transition_fence"], 0, "{seams:?}");
}

/// Every owned readiness episode of a distribution pass, a clean member's
/// rejection-inventory transaction or a replay pass's preparation, member
/// and retirement, runs inside an executor handoff, so a one-worker runtime
/// keeps other tasks moving.
fn owned_distribution_runs_under_handoff(ungrouped: bool) {
    let target = member(1);
    let (_tx, mut manager) = manager();
    manager.test_force_ungrouped = ungrouped;
    let policy = super::export_explain::deny_local_pref_at_least(200);
    let mut receivers = vec![
        join(&mut manager, 0, false, None).0,
        join(&mut manager, 1, false, Some(policy)).0,
    ];
    assert_eq!(manager.grouped_member_of(target).is_none(), ungrouped);
    drain(&mut receivers);
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let observed = Arc::clone(&observed);
        move |stage| {
            let open = crate::manager::executor_handoffs().1;
            observed.lock().unwrap().push((stage, open > 0));
        }
    }));
    let owned = |manager: &mut RibManager, pass: &str, work: &dyn Fn(&mut RibManager)| {
        manager.replacement_readiness_receipts.clear();
        work(manager);
        let observed = std::mem::take(&mut *observed.lock().unwrap());
        let owners = manager.replacement_readiness_receipts.len();
        assert!(owners > 0, "{pass}: no owned episode");
        assert_eq!(
            observed
                .iter()
                .filter(|(stage, _)| *stage == "terminal_cleanup")
                .count(),
            owners,
            "{pass}: {observed:?}"
        );
        assert!(
            observed.iter().all(|(_, handed_off)| *handed_off),
            "{pass}: owned checkpoint outside an executor handoff: {observed:?}"
        );
        owners
    };
    owned(&mut manager, "clean rejection", &|manager| {
        receive_policy_rejection(manager, 0, 200);
    });
    assert_eq!(policy_rejection_events(&manager, target), 1);
    let owners = owned(&mut manager, "replay", &|manager| {
        manager.mark_outbound_dirty(target);
        manager.distribute_changes(&HashSet::new(), &HashSet::new());
    });
    // Preparation, the dirty member and retirement, after a grouped
    // member's own dirty-marking capture.
    assert_eq!(owners, 3 + usize::from(!ungrouped));
    assert!(!manager.dirty_peers.contains(&target));
    manager.replacement_readiness_test_hook = None;
}

#[test]
fn owned_grouped_distribution_runs_under_handoff() {
    owned_distribution_runs_under_handoff(false);
}

#[test]
fn owned_ungrouped_distribution_runs_under_handoff() {
    owned_distribution_runs_under_handoff(true);
}

#[test]
fn clean_grouped_pass_owns_no_readiness() {
    clean_pass_owns_no_readiness(false);
}

#[test]
fn clean_ungrouped_pass_owns_no_readiness() {
    clean_pass_owns_no_readiness(true);
}

/// A prefix with one retained denial keeps it inline; only two or more
/// allocate a set.
#[test]
fn single_denial_history_bucket_is_inline() {
    use std::mem::size_of;
    let key = |source| PolicyFilteredRouteKey {
        target_peer: member(1),
        source_peer: member(source),
        prefix: Prefix::V4(prefix(1, 0)),
        path_id: 0,
    };
    let (_tx, mut manager) = manager();
    manager.update_policy_filtered_routes_for_prefixes(
        member(1),
        &HashSet::from([Prefix::V4(prefix(1, 0))]),
        &HashSet::from([key(0)]),
    );
    let history = &manager.policy_filtered_routes[&member(1)];
    assert!(matches!(
        history[&Prefix::V4(prefix(1, 0))],
        PolicyFilteredBucket::One(retained) if retained == key(0)
    ));
    manager.update_policy_filtered_routes_for_prefixes(
        member(1),
        &HashSet::from([Prefix::V4(prefix(1, 0))]),
        &HashSet::from([key(0), key(2)]),
    );
    let history = &manager.policy_filtered_routes[&member(1)];
    let PolicyFilteredBucket::Many(keys) = &history[&Prefix::V4(prefix(1, 0))] else {
        panic!("two denials share a set");
    };
    assert_eq!(keys, &HashSet::from([key(0), key(2)]));
    // Back to one denial: the set's allocation is released.
    manager.update_policy_filtered_routes_for_prefixes(
        member(1),
        &HashSet::from([Prefix::V4(prefix(1, 0))]),
        &HashSet::from([key(2)]),
    );
    let history = &manager.policy_filtered_routes[&member(1)];
    assert!(matches!(
        history[&Prefix::V4(prefix(1, 0))],
        PolicyFilteredBucket::One(retained) if retained == key(2)
    ));
    // One retained slot: the map entry plus, before, a set allocated for a
    // single key (hashbrown: 4 buckets of keys plus 4 + 16 control bytes).
    let inline = size_of::<(Prefix, PolicyFilteredBucket)>();
    let set = size_of::<(Prefix, HashSet<PolicyFilteredRouteKey>)>()
        + 4 * size_of::<PolicyFilteredRouteKey>()
        + 4
        + 16;
    eprintln!("single-denial history slot: {set} B before, {inline} B inline");
    assert!(inline <= size_of::<(Prefix, HashSet<PolicyFilteredRouteKey>)>());
}

fn late_private_up(peer: PeerId, outbound_tx: mpsc::Sender<OutboundRouteUpdate>) -> RibUpdate {
    let mut up = test_peer_up(peer, 1, outbound_tx);
    if let RibUpdate::PeerUp {
        per_client_best,
        add_path_send_families,
        add_path_send_max,
        ..
    } = &mut up
    {
        *per_client_best = true;
        *add_path_send_families = vec![(Afi::Ipv4, Safi::Unicast)];
        *add_path_send_max = 2;
    }
    up
}

#[expect(
    clippy::too_many_lines,
    reason = "one actual-caller shape measures private capture and replay with exact wire, public-count and release assertions"
)]
fn late_private_arm(size: usize) -> Work {
    let count = size * ROUTES;
    let family = (Afi::Ipv4, Safi::Unicast);
    let source = member(4);
    let waiter = member(5);
    let (_tx, mut manager) = manager();
    manager = manager.with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: waiter,
            families: vec![family],
        }],
    });
    let mut source_rx = join(&mut manager, 4, false, None).0;
    let mut receivers = Vec::new();
    let mut senders = Vec::new();
    for index in 0..4 {
        manager.handle_update(RibUpdate::SetPeerExportEncoder {
            peer: member(index),
            session_id: 1,
            encoder: ReusableExactExportEncoder::new(
                u64::try_from(index).unwrap() + 10,
                WIRE_PROFILE,
            ),
        });
        let (tx, mut rx) = mpsc::channel(4096);
        manager.handle_update(late_private_up(member(index), tx.clone()));
        assert_eq!(rx.try_recv().unwrap().end_of_rib, [family]);
        senders.push(tx);
        receivers.push(rx);
    }
    let host = prefix(200, 0);
    let mut local = deferred_local_unicast(host);
    local.path_id = 17;
    inject_deferred_unicast(&mut manager, local);
    let mut received = (0..count)
        .map(|index| {
            make_route(
                prefix(1, index),
                match source.addr() {
                    IpAddr::V4(address) => address,
                    IpAddr::V6(_) => unreachable!(),
                },
            )
        })
        .collect::<Vec<_>>();
    let mut sibling = make_route_with_lp(
        host,
        match source.addr() {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => unreachable!(),
        },
        10,
    );
    sibling.path_id = 11;
    received.push(sibling);
    let mut update = test_routes_received(source, received);
    if let RibUpdate::RoutesReceived { session_id, .. } = &mut update {
        *session_id = 1;
    }
    manager.handle_update(update);
    drain_route_chunks(&mut manager);
    let mut wires = vec![BTreeMap::new(); 4];
    let apply = |receivers: &mut Vec<mpsc::Receiver<OutboundRouteUpdate>>,
                 wires: &mut Vec<BTreeMap<(Prefix, u32), Route>>,
                 allow_marker: bool| {
        for (rx, wire) in receivers.iter_mut().zip(wires) {
            while let Ok(update) = rx.try_recv() {
                assert!(allow_marker || update.end_of_rib.is_empty());
                assert!(update.end_of_rib.iter().all(|marker| *marker == family));
                for key in update.withdraw {
                    assert!(wire.remove(&key).is_some());
                }
                for route in update.announce.iter() {
                    assert!(!route.is_stale && !route.is_llgr_stale);
                    wire.insert((route.prefix, route.path_id), route.clone());
                }
            }
        }
    };
    apply(&mut receivers, &mut wires, false);
    assert!(wires.iter().all(|wire| wire.len() == count + 2));
    while source_rx.try_recv().is_ok() {}
    let mut waiter_rx = None;
    let work = checkpoints_in(|| {
        manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
            peer: waiter,
            session_id: 1,
            peer_restart_state: false,
            peer_gr_helper: true,
            peer_gr_families: vec![family],
            peer_enhanced_refresh: true,
            peer_llgr_families: vec![],
            local_llgr_stale_time: 0,
        });
        waiter_rx = Some(join(&mut manager, 5, false, None).0);
    });
    assert!(manager.selection_deferred(family));
    apply(&mut receivers, &mut wires, false);
    let (reply, mut bmp) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryBmpPeerStats { reply });
    let bmp = bmp.try_recv().unwrap();
    for (index, wire) in wires.iter().enumerate() {
        let peer = member(index);
        assert_eq!(wire.len(), count + 2);
        let (reply, mut public) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryAdvertisedCount { peer, reply });
        assert_eq!(public.try_recv().unwrap(), wire.len());
        assert_eq!(
            bmp.adj_rib_out_post[&peer]
                .iter()
                .find(|(f, _)| *f == family)
                .unwrap()
                .1,
            u64::try_from(wire.len()).unwrap()
        );
        assert!(manager.pending_group_admitted.get(&peer).is_some());
    }
    manager.handle_update(RibUpdate::EndOfRib {
        peer: waiter,
        session_id: 1,
        afi: family.0,
        safi: family.1,
    });
    apply(&mut receivers, &mut wires, true);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    apply(&mut receivers, &mut wires, true);
    for (index, wire) in wires.iter().enumerate() {
        assert_eq!(wire.len(), count + 2);
        assert!(
            !manager
                .pending_group_admitted
                .contains_record(member(index))
        );
        assert!(!manager.dirty_peers.contains(&member(index)));
    }
    drop((waiter_rx, senders));
    eprintln!("private late-GR capture N={count}: {work:?}");
    work
}

#[test]
fn private_late_gr_capture_work_is_linear() {
    assert_linear("private late-GR capture", &[ALL, ""], late_private_arm);
}

/// Demoting every local RTBH path of one Add-Path prefix in one pass, ranks
/// unchanged, reclaims each path's own key from the departing pool in
/// ascending order. Each reclaim must cost a constant number of steps, not
/// a shift of the pool behind it.
fn add_path_rtbh_demotion(size: usize) -> Work {
    let count = size * ROUTES;
    let (_tx, mut manager) = manager();
    let target = member(3);
    let (outbound_tx, mut receiver) = mpsc::channel(16);
    let mut up = test_peer_up(target, 1, outbound_tx);
    if let RibUpdate::PeerUp {
        add_path_send_families,
        add_path_send_max,
        ..
    } = &mut up
    {
        *add_path_send_families = vec![(Afi::Ipv4, Safi::Unicast)];
        *add_path_send_max = u32::MAX;
    }
    manager.handle_update(up);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 0), 24);
    let route = |index: usize, blackhole: bool| {
        let mut route = deferred_local_unicast(prefix);
        route.path_id = u32::try_from(index).unwrap();
        AttrSet::edit(&mut route.attributes, |attrs| {
            attrs.retain(|attr| !matches!(attr, PathAttribute::Communities(_)));
            if blackhole {
                attrs.push(PathAttribute::Communities(vec![
                    rustbgpd_wire::COMMUNITY_BLACKHOLE,
                ]));
            }
            attrs.push(PathAttribute::LocalPref(
                1000 - u32::try_from(index).unwrap(),
            ));
        });
        route
    };
    let mut wire = BTreeMap::new();
    let apply = |receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
                 wire: &mut BTreeMap<u32, bool>| {
        let mut withdrawn = 0;
        while let Ok(update) = receiver.try_recv() {
            withdrawn += update.withdraw.len();
            for key in &update.withdraw {
                wire.remove(&key.1);
            }
            for route in update.announce.iter() {
                wire.insert(
                    route.path_id,
                    route
                        .communities()
                        .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE),
                );
            }
        }
        withdrawn
    };
    for index in 0..count {
        inject_deferred_unicast(&mut manager, route(index, true));
        apply(&mut receiver, &mut wire);
    }
    let keys: Vec<u32> = (1..=u32::try_from(count).unwrap()).collect();
    assert_eq!(wire.keys().copied().collect::<Vec<_>>(), keys);
    assert!(wire.values().all(|&blackhole| blackhole));
    // A full writer holds every demotion for one dirty resync.
    let writer = manager.outbound_peers[&target].clone();
    let occupied: Vec<_> = std::iter::from_fn(|| writer.clone().try_reserve_owned().ok()).collect();
    for index in 0..count {
        inject_deferred_unicast(&mut manager, route(index, false));
    }
    drop(occupied);
    let work = checkpoints_in(|| {
        manager.distribute_changes_to_targets(&HashSet::new(), &HashSet::from([target]));
    });
    let withdrawn = apply(&mut receiver, &mut wire);
    assert_eq!(withdrawn, 0, "every demoted path keeps its own key");
    assert_eq!(wire.keys().copied().collect::<Vec<_>>(), keys);
    assert!(wire.values().all(|&blackhole| !blackhole));
    eprintln!("add-path rtbh demotion size {size}: {work:?}");
    work
}

#[test]
fn add_path_rtbh_demotion_work_is_linear() {
    assert_linear(
        "Add-Path RTBH demotion reclaiming own keys in one pass",
        &[ALL],
        add_path_rtbh_demotion,
    );
}
