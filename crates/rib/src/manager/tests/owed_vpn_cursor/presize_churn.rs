//! What the receiver accepts changes between the walk's starting log and
//! the step that completes its sample. The rate is read from rows the
//! early steps committed, so a change after them is invisible to it: keys
//! the receiver accepted are re-marked so it denies them (a MED,
//! community or next-hop change; a policy dataset re-evaluation logs the
//! same keys), or withdrawn. Each change logs keys in the list after the
//! starting log, and the walk then makes no estimate: every table ends at
//! or below the same walk with the presize off, within 2.3 times what it
//! holds.

use std::cell::RefCell;

use rustbgpd_policy::datasets::{DatasetBindings, DatasetHandle, DatasetKind};

use super::super::cursor_presize::{
    Growth, assert_at_or_below_control, assert_fitted, dataset_chain, deny_med_chain,
    prefix_dataset, rpol_chain, set_med, with_control, with_control_async,
};
use super::*;

fn row(index: u32, med: u32) -> VpnRibRoute {
    let mut route = route_from(SOURCE, P4, index, 100, 200);
    set_med(&mut route.attributes, med);
    route
}

/// The receiver's table: rows, keys, and the capacities of its route and
/// key indexes.
fn table(manager: &RibManager, peer: PeerId) -> (usize, usize, [usize; 2]) {
    let out = &manager.adj_ribs_out[&peer];
    let (routes, keys) = out.bench_vpn_capacities();
    (out.vpn_len(), out.vpn_key_len(), [routes, keys])
}

/// At or below the control within the spread of its 16 shards, and
/// within 2.3 times what the table holds. Each run hashes its keys with
/// its own seed, so with no presize at all a few shards of one run sit a
/// capacity class above the other's (up to about 7% here); an estimate
/// from a stale sample moves every shard one class or more.
fn assert_fits(head: (usize, usize, [usize; 2]), control: [usize; 2], case: &str) {
    let spread = control.map(|capacity| capacity + capacity / 4);
    assert_at_or_below_control(&head.2, &spread, case);
    assert_fitted(head.2[0], head.0, &format!("{case}: route index"));
    assert_fitted(head.2[1], head.1, &format!("{case}: key index"));
}

/// How the source changes the starting log after the walk's first steps.
#[derive(Clone, Copy)]
enum Change {
    /// Re-announce the keys with MED 1: still in the Loc-RIB, now denied.
    Deny,
    /// Withdraw the keys.
    Withdraw,
}

/// Credit `credit`; one pass (the starting log) of `total` keys behind
/// [`deny_med_chain`], `accepted(i)` of them accepted; `first` steps, all
/// before the estimate; then every accepted key but `kept(i)` is changed
/// by `change`, and the walk drains.
fn changed_after_first_steps(
    credit: usize,
    total: u32,
    first: usize,
    accepted: fn(u32) -> bool,
    kept: fn(u32) -> bool,
    change: Change,
) -> (usize, usize, [usize; 2]) {
    let mut manager = manager(credit);
    sources_up(&mut manager);
    let peer = receiver(0);
    let mut rx = up_with(
        &mut manager,
        peer,
        0,
        4096,
        &[P4],
        0,
        Some(deny_med_chain()),
    );
    Wire::default().write(&mut rx);
    manager.owe_eor(peer, P4);
    manager.owe_whole_family(peer, F4);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    let rows = (0..total)
        .map(|i| row(i, u32::from(!accepted(i))))
        .collect();
    send(&mut manager, SOURCE, rows, vec![]);
    for _ in 0..first {
        tick(&mut manager, &mut receivers);
    }
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes, 0,
        "the change lands before the estimate"
    );
    let changed = (0..total).filter(|&i| accepted(i) && !kept(i));
    match change {
        Change::Deny => send(
            &mut manager,
            SOURCE,
            changed.map(|i| row(i, 1)).collect(),
            vec![],
        ),
        Change::Withdraw => send(
            &mut manager,
            SOURCE,
            vec![],
            changed.map(|i| key(P4, i)).collect(),
        ),
    }
    drain(&mut manager, &mut receivers);
    let expected = (0..total).filter(|&i| accepted(i) && kept(i)).count();
    assert_eq!(receivers[0].wire.table.len(), expected, "exact table");
    table(&manager, peer)
}

fn assert_changed_fits(
    credit: usize,
    total: u32,
    first: usize,
    accepted: fn(u32) -> bool,
    kept: fn(u32) -> bool,
    change: Change,
    case: &str,
) {
    let (head, (_, _, control)) =
        with_control(|| changed_after_first_steps(credit, total, first, accepted, kept, change));
    assert_fits(head, control, case);
}

/// Credit 400 (steps of 200 keys): 40,000 keys, nine in ten accepted.
/// After one step the source re-marks every accepted key but one in a
/// hundred so the receiver denies it. Red when the walk estimates from a
/// sample that a logged change followed: 4.5 times what the table holds,
/// against 2.2 times.
#[test]
fn accepted_keys_denied_after_the_first_vpn_step_fit() {
    assert_changed_fits(
        400,
        40_000,
        1,
        |i| i % 10 != 0,
        |i| i % 100 == 1,
        Change::Deny,
        "denied after step 1",
    );
}

/// The same after two steps (400 keys read, about 360 rows: past the
/// sample's rows, under its keys). Red as above: 18 to 36 times, against
/// about 2.
#[test]
fn accepted_keys_denied_after_two_vpn_steps_fit() {
    assert_changed_fits(
        400,
        40_000,
        2,
        |i| i % 10 != 0,
        |i| i % 100 == 1,
        Change::Deny,
        "denied after step 2",
    );
}

/// The default step (credit 4,096, 1,024 keys): one in five of 100,000
/// accepted, so the first step commits about 205 rows, under the sample's
/// 256. After it the source re-marks nine in ten accepted keys denied.
/// Red as above: 3.6 to 7.2 times, against 1.8.
#[test]
fn accepted_keys_denied_after_a_default_vpn_step_fit() {
    assert_changed_fits(
        4 * CHUNK_ROWS,
        100_000,
        1,
        |i| i % 5 == 0,
        |i| i % 50 == 0,
        Change::Deny,
        "denied after a default step",
    );
}

/// Credit 480: six in ten of 40,000 accepted; after one step the source
/// withdraws every accepted key but one in a hundred.
#[test]
fn accepted_keys_withdrawn_after_the_first_vpn_step_fit() {
    assert_changed_fits(
        480,
        40_000,
        1,
        |i| i % 5 < 3,
        |i| i % 100 == 1,
        Change::Withdraw,
        "accepted withdrawn after step 1",
    );
}

/// Every key accepted; after one step one key in two is withdrawn.
#[test]
fn a_uniform_withdrawal_after_the_first_vpn_step_fits() {
    assert_changed_fits(
        480,
        40_000,
        1,
        |_| true,
        |i| i % 2 == 0,
        Change::Withdraw,
        "uniform withdrawal after step 1",
    );
}

// ---- Through `RibManager::run` on a paused clock.

thread_local! {
    /// The joiner, the growth of its table, its last state and the
    /// presizes made so far.
    static WATCHED: RefCell<Option<Watched>> = const { RefCell::new(None) };
}

type Watched = (PeerId, Growth, (usize, usize, [usize; 2]), usize);

fn watch(manager: &RibManager) {
    WATCHED.with(|watched| {
        if let Some((peer, growth, last, presizes)) = watched.borrow_mut().as_mut()
            && manager.adj_ribs_out.contains_key(peer)
        {
            *last = table(manager, *peer);
            growth.observe(last.0, last.2);
            *presizes = manager.adj_rib_out_commit_stats.walk_presizes;
        }
    });
}

fn vpn_pass(rows: Vec<VpnRibRoute>) -> RibUpdate {
    RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: rows,
        withdrawn: vec![],
    }
}

/// Release-started: SOURCE's 40,000 keys (nine in ten accepted by the
/// joiner) are held behind the waiter, whose End-of-RIBs release them; the
/// release logs the inventory. The joiner does not read for 20 ticks, so
/// its 400-row credit stops its walk at about 444 keys, under the sample.
/// The source then re-marks every accepted key but one in a hundred
/// denied, and the joiner reads again. Returns the joiner's last table and
/// its growth.
async fn denied_mid_sample_in_the_run_loop() -> ((usize, usize, [usize; 2]), Growth) {
    const TOTAL: u32 = 40_000;
    let accepted = |i: u32| !i.is_multiple_of(10);
    let kept = |i: u32| i % 100 == 1;
    let mut manager = deferral_manager(400, &[P4, P6]);
    manager.actor_turn_check = Some(watch);
    let (tx, rx) = mpsc::channel(256);
    manager.rx = rx;
    let run = tokio::spawn(manager.run());
    let mut sources = Vec::new();
    for source in [SOURCE, SECOND] {
        let (update, rx) = actor::peer_up(peer_v4(source), 0, 4096, &[V4]);
        tx.send(update).await.unwrap();
        sources.push(rx);
    }
    let rows = (0..TOTAL)
        .map(|i| row(i, u32::from(!accepted(i))))
        .collect();
    tx.send(vpn_pass(rows)).await.unwrap();
    tx.send(gr_context(&[P4, P6])).await.unwrap();
    let (update, waiter_rx) = actor::peer_up(peer_v4(WAITER), 7, 4096, &[P4, P6]);
    tx.send(update).await.unwrap();
    let joiner = receiver(0);
    let (outbound_tx, joiner_rx) = mpsc::channel(4096);
    tx.send(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: joiner,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy: Some(deny_med_chain()),
        sendable_families: vec![P4, P6],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    let mut receivers = vec![
        Receiver {
            peer: joiner,
            rx: joiner_rx,
            wire: Wire::default(),
        },
        Receiver {
            peer: peer_v4(WAITER),
            rx: waiter_rx,
            wire: Wire::default(),
        },
    ];
    actor::run_for(&tx, &mut receivers, &[true; 2], 5).await;
    assert!(receivers[0].wire.table.is_empty(), "the joiner waits");
    WATCHED.with(|watched| {
        *watched.borrow_mut() = Some((joiner, Growth::default(), (0, 0, [0; 2]), 0));
    });
    for family in [P4, P6] {
        tx.send(RibUpdate::EndOfRib {
            peer: peer_v4(WAITER),
            session_id: 7,
            afi: family.0,
            safi: family.1,
        })
        .await
        .unwrap();
    }
    actor::run_for(&tx, &mut receivers, &[false, true], 20).await;
    let paused = WATCHED.with(|watched| {
        watched
            .borrow()
            .as_ref()
            .map(|(_, _, last, presizes)| (last.0, *presizes))
    });
    // Nine in ten accepted: under 460 rows, the joiner has read fewer
    // keys than its sample's 512 and made no estimate (the waiter's own
    // walk may have).
    assert!(
        paused.is_some_and(|(rows, _)| rows > 0 && rows * 10 < 512 * 9),
        "the joiner stopped mid-sample: {paused:?} (rows, presizes)"
    );
    let again = (0..TOTAL)
        .filter(|&i| accepted(i) && !kept(i))
        .map(|i| row(i, 1))
        .collect();
    tx.send(vpn_pass(again)).await.unwrap();
    actor::run_for(&tx, &mut receivers, &[true; 2], 3_000).await;
    drop(tx);
    run.await.unwrap();
    drop(sources);
    let (_, growth, last, _) = WATCHED.with(|watched| watched.borrow_mut().take()).unwrap();
    assert_eq!(receivers[0].wire.markers, [1, 1], "the joiner settled");
    let expected = (0..TOTAL).filter(|&i| accepted(i) && kept(i)).count();
    assert_eq!(receivers[0].wire.table.len(), expected, "exact table");
    assert_eq!(last.0, expected);
    (last, growth)
}

/// Red when the walk estimates from a sample that a logged change
/// followed: 18 to 36 times what the table holds, against about 1.9.
#[tokio::test(start_paused = true)]
async fn accepted_keys_denied_mid_sample_through_the_run_loop_fit() {
    let ((head, _), (control, _)) = Box::pin(with_control_async(|| {
        Box::pin(denied_mid_sample_in_the_run_loop())
    }))
    .await;
    assert_fits(head, control.2, "denied mid-sample, run loop");
}

/// The dataset that accepts the hosts (row `index / 2`: each prefix is
/// under two RDs) of `total` rows for which `allowed` holds.
fn allowed_hosts(total: u32, allowed: fn(u32) -> bool) -> rustbgpd_policy::datasets::DatasetData {
    prefix_dataset((0..total).step_by(2).filter(|i| allowed(i / 2)).map(|i| {
        let VpnPrefix::V4 { addr, len } = key(P4, i).prefix else {
            unreachable!()
        };
        Prefix::V4(Ipv4Prefix::new(addr, len))
    }))
}

/// Credit `credit`; one pass (the starting log) of `total` keys behind
/// [`dataset_chain`], the hosts where `before` holds accepted. After
/// `first` steps the dataset is swapped to `after` on the shared handle,
/// as the peer manager publishes it; `window` steps run before the RIB
/// receives the re-evaluation, then the walk drains. Returns the table
/// and the estimates made.
fn dataset_swapped_after_first_steps(
    credit: usize,
    total: u32,
    first: usize,
    window: usize,
    before: fn(u32) -> bool,
    after: fn(u32) -> bool,
) -> ((usize, usize, [usize; 2]), usize) {
    let handle = Arc::new(DatasetHandle::new(
        "allowed",
        DatasetKind::Prefix,
        allowed_hosts(total, before),
    ));
    let mut manager = manager(credit);
    sources_up(&mut manager);
    let peer = receiver(0);
    let mut rx = up_with(
        &mut manager,
        peer,
        0,
        4096,
        &[P4],
        0,
        Some(dataset_chain(&handle)),
    );
    Wire::default().write(&mut rx);
    manager.owe_eor(peer, P4);
    manager.owe_whole_family(peer, F4);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    received(&mut manager, P4, &all(total), &[]);
    for _ in 0..first {
        tick(&mut manager, &mut receivers);
    }
    let prior = handle.pin();
    assert!(handle.refresh(allowed_hosts(total, after)).is_some());
    for _ in 0..window {
        tick(&mut manager, &mut receivers);
    }
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReevaluatePeerExportPolicies {
        peers: vec![peer],
        swaps: Some(vec![crate::update::DatasetSwap {
            handle: Arc::clone(&handle),
            prior,
        }]),
        reply,
    });
    result.try_recv().unwrap().unwrap();
    drain(&mut manager, &mut receivers);
    let expected = (0..total).filter(|i| after(i / 2)).count();
    assert_eq!(receivers[0].wire.table.len(), expected, "exact table");
    (
        table(&manager, peer),
        manager.adj_rib_out_commit_stats.walk_presizes,
    )
}

fn assert_dataset_swap_fits(
    credit: usize,
    total: u32,
    first: usize,
    windows: &[usize],
    rates: [fn(u32) -> bool; 2],
    case: &str,
) {
    for &window in windows {
        let case = format!("{case}, {window} steps before the re-evaluation");
        let ((head, presizes), ((_, _, control), _)) = with_control(|| {
            dataset_swapped_after_first_steps(credit, total, first, window, rates[0], rates[1])
        });
        assert_eq!(
            presizes, 0,
            "{case}: no estimate (capacities {:?}, control {control:?})",
            head.2
        );
        assert_fits(head, control, &case);
    }
}

/// The default step (1,024 keys): 100,000 keys, one host in five
/// accepted; after one step (about 205 rows) the dataset keeps one in
/// fifty. The peer manager publishes the swap before the RIB is told, and
/// the walk steps on in between at the new contents with nothing logged.
/// Red when a receiver whose export policy reads a dataset estimates: two
/// to four times the control with 8 steps before the re-evaluation.
#[test]
fn a_dataset_swap_published_before_its_re_evaluation_fits() {
    assert_dataset_swap_fits(
        4 * CHUNK_ROWS,
        100_000,
        1,
        &[0, 8],
        [|h| h % 5 == 0, |h| h % 50 == 0],
        "one in five, then one in fifty",
    );
}

/// Credit 400 (200-key steps): 40,000 keys, nine hosts in ten accepted;
/// after two steps (about 360 rows) the dataset keeps one in a hundred.
/// Red as above: about 36 times the control with 2 steps before the
/// re-evaluation.
#[test]
fn a_dataset_swap_published_before_its_re_evaluation_fits_credit_limited() {
    assert_dataset_swap_fits(
        400,
        40_000,
        2,
        &[0, 2],
        [|h| h % 10 != 0, |h| h % 100 == 1],
        "nine in ten, then one in a hundred",
    );
}

/// A receiver whose export policy reads no dataset still sizes its table
/// once from a quiet sample. Red when every receiver with an export
/// policy is denied the estimate.
#[test]
fn a_receiver_whose_export_policy_reads_no_dataset_still_presizes() {
    const TOTAL: u32 = 20_000;
    let shape = || {
        let mut manager = manager(4 * CHUNK_ROWS);
        sources_up(&mut manager);
        let peer = receiver(0);
        let chain = rpol_chain("policy p { term t { accept } }", &DatasetBindings::new());
        let mut rx = up_with(&mut manager, peer, 0, 4096, &[P4], 0, Some(chain));
        Wire::default().write(&mut rx);
        manager.owe_eor(peer, P4);
        manager.owe_whole_family(peer, F4);
        let mut receivers = vec![Receiver {
            peer,
            rx,
            wire: Wire::default(),
        }];
        received(&mut manager, P4, &all(TOTAL), &[]);
        drain(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.table.len(), TOTAL as usize, "exact table");
        (
            table(&manager, peer),
            manager.adj_rib_out_commit_stats.walk_presizes,
        )
    };
    let ((head, presizes), ((_, _, control), _)) = with_control(shape);
    assert_eq!(presizes, 1, "one estimate");
    assert_fits(head, control, "no dataset");
}

const WAITER2: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);

/// The kept-walk branch of `owing_resync_covered`: a collision-failback
/// stage owes R the family and its walk reads under 512 keys; a second
/// waiter re-holds selection; R's export policy changes and it is resynced
/// inside the hold, which keeps the walk. Returns the table, the estimates
/// made and the walk's keys read just after the resync.
fn re_held_resync() -> ((usize, usize, [usize; 2]), usize, usize) {
    const TOTAL: u32 = 40_000;
    let (a, b) = (peer_v4(WAITER), peer_v4(WAITER2));
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    )
    .with_outbound_row_credit(400)
    .with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: [a, b]
            .into_iter()
            .map(|peer| SelectionDeferralWaiterConfig {
                peer: peer.into(),
                families: vec![P4],
            })
            .collect(),
    });
    manager.test_force_ungrouped = true;
    manager.flush_poll_budget = Duration::ZERO;
    let metrics = manager.metrics.clone();
    let families = HashSet::from([P4]);
    let classify = |manager: &mut RibManager, peer, session| {
        assert!(
            manager
                .selection_deferral
                .as_mut()
                .unwrap()
                .classify_session(peer, session, false, &families, &metrics)
                .is_empty(),
            "the waiter holds selection"
        );
    };
    classify(&mut manager, a, 11);
    assert!(manager.selection_deferred(P4));
    sources_up(&mut manager);
    let peer = receiver(0);
    let mut rx = up_with(&mut manager, peer, 0, 4096, &[P4], 0, None);
    Wire::default().write(&mut rx);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    // Every key accepted now; after the policy change one in a hundred.
    let rows = (0..TOTAL)
        .map(|i| row(i, u32::from(i % 100 != 1)))
        .collect();
    send(&mut manager, SOURCE, rows, vec![]);
    tick(&mut manager, &mut receivers);
    assert!(receivers[0].wire.table.is_empty(), "held");
    let stage = {
        let selection = manager.selection_deferral.as_mut().unwrap();
        selection.session_down(a, 11, &metrics);
        selection
            .await_collision_failback_refresh(a, 11, false, &families, true, &metrics)
            .unwrap()
    };
    manager.apply_selection_deferral_transitions(stage, "collision failback");
    assert!(!manager.selection_deferred(P4));
    assert!(manager.owes_whole(peer, F4), "R walks");
    for _ in 0..2 {
        tick(&mut manager, &mut receivers);
    }
    let read = manager.walk_keys_read(peer, F4);
    assert!(read > 0 && read < 512, "mid-sample: {read}");
    classify(&mut manager, b, 22);
    assert!(manager.selection_deferred(P4), "re-held");
    manager
        .replace_peer_export_policy_synchronously(peer, Some(deny_med_chain()))
        .unwrap();
    for _ in 0..20 {
        tick(&mut manager, &mut receivers);
        if !manager.dirty_peers.contains(&peer) {
            break;
        }
    }
    assert!(manager.owes_whole(peer, F4), "the walk is kept");
    let read_after = manager.walk_keys_read(peer, F4);
    let transitions: Vec<_> = {
        let selection = manager.selection_deferral.as_mut().unwrap();
        let mut transitions: Vec<_> = selection
            .end_of_rib(b, 22, P4, &metrics)
            .into_iter()
            .collect();
        assert!(selection.begin_route_refresh(a, 11, P4).is_none());
        transitions.extend(selection.end_route_refresh(a, 11, P4, &metrics));
        transitions
    };
    manager.apply_selection_deferral_transitions(transitions, "release");
    drain(&mut manager, &mut receivers);
    let expected = (0..TOTAL).filter(|i| i % 100 == 1).count();
    assert_eq!(receivers[0].wire.table.len(), expected, "exact table");
    (
        table(&manager, peer),
        manager.adj_rib_out_commit_stats.walk_presizes,
        read_after,
    )
}

/// A walk kept across a resync inside a selection hold drops its sample,
/// and makes no estimate after the release. Defense in depth: no step runs
/// while the family is deferred and the release relogs the inventory, so
/// the table matches the control even without the reset.
#[test]
fn a_walk_kept_across_a_re_held_resync_drops_its_sample() {
    let ((head, presizes, read), ((_, _, control), _, _)) = with_control(re_held_resync);
    assert_eq!(read, 0, "the resync dropped the sample");
    assert_eq!(presizes, 0, "no estimate");
    assert_fits(head, control, "re-held resync");
}
