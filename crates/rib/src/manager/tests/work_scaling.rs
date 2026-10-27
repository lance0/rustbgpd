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
    assert_linear("policy reload", &[ALL, "shared_inventory"], policy_reload);
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
    (
        tx,
        manager.with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_mins(2),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: peer_v4(Ipv4Addr::new(192, 0, 2, 1)),
                families: vec![(Afi::Ipv4, Safi::Unicast)],
            }],
        }),
    )
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
