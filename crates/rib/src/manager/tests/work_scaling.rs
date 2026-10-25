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
//! stage. Inbound distribution counts member envelopes instead: the
//! regression shape there is one distribution pass per message, which
//! multiplies passes, and every member is sent every announced route, so
//! its checkpoint total grows with members x routes by design.
//!
//! Every scenario also pins its exact wire output, so a setup that stops
//! installing routes cannot pass as flat work.

use crate::PeerId;
use crate::test_support::peer_v4;

use super::exportability::MockExactExportEncoder;
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

/// Register member `index` the way a session does: exact-export encoder,
/// optional RFC 7947 control, then `PeerUp`.
fn join(
    manager: &mut RibManager,
    index: usize,
    rs_control: bool,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = member(index);
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 1,
        encoder: MockExactExportEncoder::accepting(1),
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
    outbound_rx
}

fn members(
    manager: &mut RibManager,
    count: usize,
    rs_control: bool,
    export_policy: Option<&rustbgpd_policy::PolicyChain>,
) -> Vec<mpsc::Receiver<OutboundRouteUpdate>> {
    (0..count)
        .map(|index| join(manager, index, rs_control, export_policy.cloned()))
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
    drain(&mut receivers);
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
    drain(&mut receivers);
    let mut joiners = Vec::new();
    let work = checkpoints_in(|| {
        joiners.extend((size..size + BURST).map(|index| join(&mut manager, index, false, None)));
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
    drain(&mut receivers);
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
/// with the members, not messages x members.
fn inbound_update_distribution(size: usize) -> Work {
    let (tx, mut manager) = manager();
    let mut receivers = members(&mut manager, size, false, None);
    drain(&mut receivers);
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
fn inbound_update_distribution_envelopes_are_linear() {
    assert_linear(
        "inbound UPDATE distribution",
        &[ENVELOPES],
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
