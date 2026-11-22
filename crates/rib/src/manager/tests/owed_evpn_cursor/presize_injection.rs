//! Rows that reach a walking receiver's EVPN table outside its cursor
//! steps: an RT-Constrain membership change restages every EVPN key into
//! the receiver's own owed set, which drains ahead of the cursor, and
//! ordinary passes, relogs, withdrawals and a route refresh land while the
//! walk runs. The presize rate counts only what the cursor steps read and
//! committed, so none of these rows can raise it: every table ends at or
//! below the capacities of the same walk with the presize off.

use std::cell::RefCell;

use super::super::cursor_presize::{
    Growth, assert_at_or_below_control, assert_fitted, deny_med_chain, tenth_med, with_control,
    with_control_async,
};
use super::*;

/// The EVPN table of `peer`: rows, and the capacities of its index and of
/// the slab's first segment.
fn evpn_table(manager: &RibManager, peer: PeerId) -> (usize, [usize; 2]) {
    let out = &manager.adj_ribs_out[&peer];
    let (index, segment) = out.evpn_capacities();
    (out.evpn_len(), [index, segment])
}

/// A manager whose VPN peers group (RT-Constrain membership is grouped
/// state), one receiver step per resync tick.
fn rtc_manager(credit: usize) -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    )
    .with_outbound_row_credit(credit);
    manager.flush_poll_budget = Duration::ZERO;
    manager
}

/// Receiver `index` imports Route Target `add` (and drops `drop`).
fn membership_update(index: u8, add: u16, drop: Option<u16>) -> RibUpdate {
    let address = Ipv4Addr::new(10, 0, 9, index + 1);
    RibUpdate::RtcRoutesReceived {
        peer: receiver(index),
        session_id: 0,
        announced: vec![make_rtc_rib_route(address, add, 100)],
        withdrawn: drop
            .map(|value| make_rtc_rib_route(address, value, 100).key())
            .into_iter()
            .collect(),
    }
}

fn rtc_eor(index: u8) -> RibUpdate {
    RibUpdate::EndOfRib {
        peer: receiver(index),
        session_id: 0,
        afi: RTC.0,
        safi: RTC.1,
    }
}

/// Keys of `rows` the cursor of `peer` has passed.
fn passed(manager: &RibManager, peer: PeerId, rows: u32) -> usize {
    (0..rows)
        .filter(|&index| manager.owed_evpn_cursor_passed(peer, &key(index)))
        .count()
}

/// The source installs `routes`, EVPN selection is held while receivers 0
/// (R) and 1 join (VPN in one update group, EVPN privately, importing
/// Route Target 100), and the waiter's End-of-RIB releases it: the release
/// owes both EVPN whole and logs its whole inventory once, the walks'
/// starting log. The waiter, last, walks too.
fn released_rtc_walk(credit: usize, routes: Vec<EvpnRibRoute>) -> (RibManager, Vec<Receiver>) {
    let mut manager = rtc_manager(credit).with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer_v4(WAITER).into(),
            families: vec![EVPN],
        }],
    });
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    received_routes(&mut manager, routes, &[]);
    let waiter = hold(&mut manager);
    let mut receivers = rtc_receivers_up(&mut manager);
    for receiver in &mut receivers {
        receiver.write();
        assert!(receiver.wire.table.is_empty(), "held");
    }
    release(&mut manager);
    assert!(manager.owes_whole(receivers[0].peer, FAMILY), "R walks");
    receivers.push(waiter);
    (manager, receivers)
}

/// Receivers 0 (R) and 1 hold VPN in one update group and EVPN privately,
/// and import Route Target 100.
fn rtc_receivers_up(manager: &mut RibManager) -> Vec<Receiver> {
    let mut families = vpn_rtc_sendable();
    families.push(EVPN);
    (0..2)
        .map(|index| {
            let peer = receiver(index);
            let mut rx = up_sized(manager, peer, 0, 4096, &families);
            manager.handle_update(membership_update(index, 100, None));
            manager.handle_update(rtc_eor(index));
            Wire::default().write(&mut rx);
            assert!(manager.vpn_grouped_member_of(peer).is_some(), "grouped VPN");
            assert!(
                manager.evpn_grouped_member_of(peer).is_none(),
                "private EVPN"
            );
            Receiver {
                peer,
                rx,
                wire: Wire::default(),
            }
        })
        .collect()
}

// ---- A membership change under a live cursor.

const RESTAGE_ROWS: u32 = 20_000;

/// One in 97 keys carries RT 100 (imported from the start), one in 13 of
/// the rest RT 200 (imported after the membership change), the rest RT 300.
fn rt_of(index: u32) -> u16 {
    if index.is_multiple_of(97) {
        100
    } else if index.is_multiple_of(13) {
        200
    } else {
        300
    }
}

fn restaged_rows() -> usize {
    (0..RESTAGE_ROWS).filter(|&i| rt_of(i) != 300).count()
}

/// R walks a released 20,000-key EVPN debt at 128 keys a step, importing
/// 1% of them. After its first step its membership adds RT 200 (7.6% of
/// keys, no winner changed): the restage joins R's own set, which drains
/// ahead of the cursor, so about 1,540 rows land in the table outside the
/// cursor steps.
fn restage_under_a_cursor() -> (usize, [usize; 2]) {
    let routes = (0..RESTAGE_ROWS)
        .map(|i| route_rt(i, 0, &[rt_of(i)]))
        .collect();
    let (mut manager, mut receivers) = released_rtc_walk(256, routes);
    let r = receivers[0].peer;
    let mut walked = 0;
    for _ in 0..50 {
        tick(&mut manager, &mut receivers);
        walked = passed(&manager, r, RESTAGE_ROWS);
        if walked != 0 {
            break;
        }
    }
    assert!(walked != 0 && walked < 512, "walked {walked}");
    manager.handle_update(membership_update(0, 200, None));
    assert!(!manager.dirty_peers.contains(&r), "no resync");
    assert!(manager.owed_key_count(r, FAMILY) > 0, "R's set restaged");
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), restaged_rows(), "R's table");
    evpn_table(&manager, r)
}

/// Red with the rate taken from the table's growth since the walk began:
/// the restaged rows read as several rows a key, clamped to one, and the
/// index is reserved for every key ahead (about 16 times what it holds,
/// against 1.04 times without the presize).
#[test]
fn an_rtc_restage_under_an_evpn_cursor_does_not_raise_the_rate() {
    let ((rows, head), (_, control)) = with_control(restage_under_a_cursor);
    assert_at_or_below_control(&head, &control, "RTC restage");
    assert_fitted(head[0], rows, "RTC restage");
}

// The same restage through `RibManager::run_actor` on a paused clock.

thread_local! {
    /// (R, R's EVPN rows, R's own owed keys, whether R owes EVPN whole,
    /// keys R's cursor has passed) after the last actor turn.
    static R_STATE: RefCell<(Option<PeerId>, usize, usize, bool, usize)> =
        const { RefCell::new((None, 0, 0, false, 0)) };
}

fn watch_r(manager: &RibManager) {
    R_STATE.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(r) = state.0 {
            state.1 = manager
                .adj_ribs_out
                .get(&r)
                .map_or(0, crate::adj_rib_out::AdjRibOut::evpn_len);
            state.2 = manager.owed_key_count(r, FAMILY);
            state.3 = manager.owes_whole(r, FAMILY);
            state.4 = passed(manager, r, RESTAGE_ROWS);
        }
    });
}

fn r_state() -> (usize, usize, bool, usize) {
    R_STATE.with(|state| {
        let state = state.borrow();
        (state.1, state.2, state.3, state.4)
    })
}

fn actor_peer_up(
    peer: PeerId,
    families: &[(Afi, Safi)],
) -> (RibUpdate, mpsc::Receiver<OutboundRouteUpdate>) {
    let (outbound_tx, output) = mpsc::channel(4096);
    let update = RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy: None,
        sendable_families: families.to_vec(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    };
    (update, output)
}

fn evpn_routes(routes: Vec<EvpnRibRoute>) -> RibUpdate {
    RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: routes,
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

/// Two queries in turn: every message queued before them has run.
async fn barrier(tx: &mpsc::Sender<RibUpdate>) {
    for _ in 0..2 {
        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::QueryLocRibCount { reply })
            .await
            .unwrap();
        response.await.unwrap();
    }
}

/// `ticks` 10 ms ticks; the receivers marked `reading` write after each.
async fn run_ticks(
    tx: &mpsc::Sender<RibUpdate>,
    receivers: &mut [Receiver],
    reading: &[bool],
    ticks: usize,
) {
    for _ in 0..ticks {
        tokio::time::advance(Duration::from_millis(10)).await;
        barrier(tx).await;
        for (receiver, &reading) in receivers.iter_mut().zip(reading) {
            if reading {
                receiver.write();
            }
        }
    }
}

/// No direct call: R and a sibling come up, R stops reading, 150 RT 100
/// rows spend R's credit and overflow its owed set past the byte cap (a
/// cursor at the list head, the set kept), and 20,000 rows are logged
/// ahead of it. A byte-cap cursor has no starting log, so its walk makes
/// no estimate. R reads until its kept set has drained and its cursor has
/// stepped, and its membership then adds RT 200; then it reads to the end.
async fn actor_restage_under_a_cursor() -> (usize, [usize; 2]) {
    const EARLY: u32 = 150;
    let mut manager = rtc_manager(64);
    manager.actor_turn_check = Some(watch_r);
    let (tx, rx) = mpsc::channel(256);
    manager.rx = rx;
    let actor = tokio::spawn(manager.run_actor());
    let (update, source_rx) = actor_peer_up(peer_v4(SOURCE), &[V4]);
    tx.send(update).await.unwrap();
    let mut families = vpn_rtc_sendable();
    families.push(EVPN);
    let mut receivers = Vec::new();
    for index in 0..2 {
        let (update, rx) = actor_peer_up(receiver(index), &families);
        tx.send(update).await.unwrap();
        tx.send(membership_update(index, 100, None)).await.unwrap();
        tx.send(rtc_eor(index)).await.unwrap();
        receivers.push(Receiver {
            peer: receiver(index),
            rx,
            wire: Wire::default(),
        });
    }
    run_ticks(&tx, &mut receivers, &[true; 2], 20).await;
    let r = receivers[0].peer;
    R_STATE.with(|state| state.borrow_mut().0 = Some(r));
    let early = (0..EARLY)
        .map(|i| route_rt(1_000_000 + i, 0, &[100]))
        .collect();
    tx.send(evpn_routes(early)).await.unwrap();
    run_ticks(&tx, &mut receivers, &[false, true], 3).await;
    assert!(r_state().2, "the byte cap started a cursor");
    let routes = (0..RESTAGE_ROWS)
        .map(|i| route_rt(i, 0, &[rt_of(i)]))
        .collect();
    tx.send(evpn_routes(routes)).await.unwrap();
    run_ticks(&tx, &mut receivers, &[false, true], 3).await;
    let mut walked = 0;
    for _ in 0..200 {
        run_ticks(&tx, &mut receivers, &[true; 2], 1).await;
        walked = r_state().3;
        if walked != 0 {
            break;
        }
    }
    assert!(walked != 0 && walked < 512, "walked {walked}");
    tx.send(membership_update(0, 200, None)).await.unwrap();
    barrier(&tx).await;
    assert!(r_state().1 > 0, "R's set restaged");
    let expected = restaged_rows() + EARLY as usize;
    for _ in 0..100 {
        run_ticks(&tx, &mut receivers, &[true; 2], 50).await;
        let (_, owed, whole, _) = r_state();
        if receivers[0].wire.table.len() == expected && owed == 0 && !whole {
            break;
        }
    }
    drop(tx);
    let manager = actor.await.unwrap();
    drop(source_rx);
    R_STATE.with(|state| state.borrow_mut().0 = None);
    assert!(!manager.owes(r, EVPN), "R settled");
    assert_eq!(receivers[0].wire.table.len(), expected, "R's table");
    evpn_table(&manager, r)
}

/// The byte-cap cursor makes no estimate, so the table grows as with the
/// presize off. Red with the rate taken from the table's growth since the
/// walk began and the list read past any starting log: about 15 times
/// what it holds, against 1.9 times without the presize.
#[tokio::test(start_paused = true)]
async fn an_rtc_restage_under_an_evpn_cursor_through_the_actor_loop_fits() {
    let ((rows, head), (_, control)) = with_control_async(actor_restage_under_a_cursor).await;
    assert_at_or_below_control(&head, &control, "actor RTC restage");
    assert_fitted(head[0], rows, "actor RTC restage");
}

// ---- Injection at random points of a walk.

/// Keys of the injected walk, and the ticks injections fall in: R's cursor
/// reads 128 keys a step, and R, receiver 1 and the waiter each walk the
/// release, so the injections fall in the first part of R's walk, while
/// its sample is still forming.
const WALK_ROWS: u32 = 20_000;
const WALK_TICKS: u64 = 160;

/// One in 40 keys carries RT 100 (imported from the start: the cursor's
/// sample completes after about 10,000 keys), the other multiples of 20 RT
/// 200 (500 more rows, imported on a restage), the rest RT 300. R's final
/// table stays under the presize limit and mid-way in its index's capacity
/// class, so only an over-reservation crosses it.
fn walk_rt(index: u32) -> u16 {
    if index.is_multiple_of(40) {
        100
    } else if index.is_multiple_of(20) {
        200
    } else {
        300
    }
}

/// A non-cursor path into R's table.
#[derive(Debug, Clone, Copy)]
enum Inject {
    /// An ordinary pass: 200 new RT 100 keys.
    Distribute,
    /// R's membership adds RT 200: every EVPN key joins R's own set.
    Restage,
    /// 300 keys change payload, logged again ahead of the cursor.
    Relog,
    /// 300 keys withdrawn.
    Withdraw,
    /// R asks for a route refresh of EVPN.
    Refresh,
}

/// Tiny deterministic generator (xorshift64).
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// The injections of `seed`: each path at a random tick of the walk (a
/// refresh in half the seeds), with a random key range.
fn schedule(seed: u64) -> Vec<(u64, Inject, u32)> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut plan = Vec::new();
    for inject in [
        Inject::Distribute,
        Inject::Restage,
        Inject::Relog,
        Inject::Withdraw,
        Inject::Refresh,
    ] {
        if matches!(inject, Inject::Refresh) && next(&mut state).is_multiple_of(2) {
            continue;
        }
        // Half the points fall in the first eight ticks, while the cursor's
        // sample is still forming; the rest anywhere in the walk.
        let window = if next(&mut state).is_multiple_of(2) {
            8
        } else {
            WALK_TICKS
        };
        let at = next(&mut state) % window;
        let from = u32::try_from(next(&mut state) % u64::from(WALK_ROWS - 300)).unwrap();
        plan.push((at, inject, from));
    }
    plan
}

fn inject(manager: &mut RibManager, r: PeerId, inject: Inject, from: u32) {
    match inject {
        Inject::Distribute => {
            let fresh = (0..200)
                .map(|i| route_rt(2_000_000 + from + i, 0, &[100]))
                .collect();
            received_routes(manager, fresh, &[]);
        }
        Inject::Restage => manager.handle_update(membership_update(0, 200, None)),
        Inject::Relog => {
            let again = (from..from + 300)
                .map(|i| route_rt(i, 1, &[walk_rt(i)]))
                .collect();
            received_routes(manager, again, &[]);
        }
        Inject::Withdraw => {
            let gone: Vec<u32> = (from..from + 300).collect();
            received_routes(manager, vec![], &gone);
        }
        Inject::Refresh => refresh_request(manager, r),
    }
}

/// R walks [`WALK_ROWS`] keys at 128 keys a step while `plan` injects
/// rows into its table. Returns R's table as sent, its rows, the
/// capacities and the presizes made.
fn injected_walk(
    plan: &[(u64, Inject, u32)],
) -> (BTreeMap<EvpnRouteKey, String>, usize, [usize; 2], usize) {
    let routes = (0..WALK_ROWS)
        .map(|i| route_rt(i, 0, &[walk_rt(i)]))
        .collect();
    let (mut manager, mut receivers) = released_rtc_walk(256, routes);
    let r = receivers[0].peer;
    for at in 0..WALK_TICKS {
        for &(_, path, from) in plan.iter().filter(|(when, _, _)| *when == at) {
            inject(&mut manager, r, path, from);
        }
        tick(&mut manager, &mut receivers);
    }
    drain(&mut manager, &mut receivers);
    assert!(!manager.owes(r, EVPN), "R settled");
    let (rows, capacities) = evpn_table(&manager, r);
    assert_eq!(receivers[0].wire.table.len(), rows, "R's table as sent");
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    (receivers[0].wire.table.clone(), rows, capacities, presizes)
}

/// Every seed's walk, with rows injected from each non-cursor path at
/// random points, ends with the same table as the control and capacities
/// at or below its, and some seeds do presize. Red with the rate taken
/// from the table's growth since the walk began: a restage while the
/// sample is still short reads as one row a key.
#[test]
fn rows_injected_outside_the_cursor_never_size_past_the_control() {
    let mut seeds_presized = 0;
    for seed in 0..12 {
        let plan = schedule(seed);
        let ((table, rows, head, presizes), (control_table, _, control, _)) =
            with_control(|| injected_walk(&plan));
        let case = format!("seed {seed} {plan:?}");
        assert_eq!(table, control_table, "{case}: same table");
        assert_at_or_below_control(&head, &control, &case);
        assert_fitted(head[0], rows, &case);
        seeds_presized += usize::from(presizes != 0);
    }
    assert!(seeds_presized > 0, "no seed presized");
}

// ---- Acceptance in blocks after a release.

/// What a block passes: every key, none, or one in ten.
#[derive(Debug, Clone, Copy)]
enum Block {
    Accepted,
    Rejected,
    Tenth,
}

impl Block {
    fn med(self, index: u32) -> u32 {
        match self {
            Self::Accepted => 0,
            Self::Rejected => 1,
            Self::Tenth => tenth_med(index),
        }
    }
}

/// Seed `seed`'s shape: a release of 600 to 2,600 keys the receiver all
/// accepts, then two to six blocks of 300 to 6,300 fresh keys, each in its
/// own pass at a tick among the walk's first four (most in the first,
/// before the walk's first step), half of them rejected.
fn clustered_schedule(seed: u64) -> (u32, Vec<(u64, Block, u32)>) {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut draw = |range: u64| next(&mut state) % range;
    let released = 600 + u32::try_from(draw(2_000)).unwrap();
    let blocks = (0..2 + draw(5))
        .map(|_| {
            let at = if draw(3) == 0 { draw(4) } else { 0 };
            let block = match draw(4) {
                0 => Block::Accepted,
                1 => Block::Tenth,
                _ => Block::Rejected,
            };
            (at, block, 300 + u32::try_from(draw(6_000)).unwrap())
        })
        .collect();
    (released, blocks)
}

/// The receiver behind [`deny_med_chain`] is released `released` keys,
/// then `blocks` arrive, each its own pass at its tick. Returns its table
/// as sent, its capacities, and the steps in which its index changed
/// capacity.
fn clustered_walk(
    released: u32,
    blocks: &[(u64, Block, u32)],
) -> (BTreeMap<EvpnRouteKey, String>, [usize; 2], usize) {
    let rows: Vec<(u32, u32)> = (0..released).map(|index| (index, 0)).collect();
    let (mut manager, mut receivers) = super::presize::released(&rows, Some(deny_med_chain()));
    let r = receivers[0].peer;
    let mut growth = Growth::default();
    let mut observe = |manager: &RibManager| {
        let (rows, capacities) = manager
            .adj_ribs_out
            .get(&r)
            .map_or((0, [0, 0]), |_| evpn_table(manager, r));
        growth.observe(rows, capacities);
    };
    let mut fresh = released;
    for at in 0.. {
        for &(_, block, keys) in blocks.iter().filter(|(when, _, _)| *when == at) {
            let rows: Vec<(u32, u32)> = (fresh..fresh + keys)
                .map(|index| (index, block.med(index)))
                .collect();
            received(&mut manager, &rows, &[]);
            fresh += keys;
        }
        for receiver in &mut receivers {
            receiver.write();
        }
        if at >= 4 && !manager.resync_tick_pending() {
            break;
        }
        tick(&mut manager, &mut receivers);
        observe(&manager);
    }
    assert!(!manager.owes(r, EVPN), "R settled");
    let (rows, capacities) = evpn_table(&manager, r);
    assert_eq!(receivers[0].wire.table.len(), rows, "R's table as sent");
    (
        receivers[0].wire.table.clone(),
        capacities,
        growth.rebuilds[0],
    )
}

/// Every seed's walk, with acceptance arriving in blocks after the release
/// (another source, VRF or Route Target), ends with the same table as the
/// control and capacities at or below its, and the release still sizes
/// R's index in fewer steps than the control for some seeds. Red when the
/// estimate extrapolates the release's rate over keys logged after it: an
/// accepted release ahead of rejected blocks reserves the index for every
/// key of every block.
#[test]
fn acceptance_in_blocks_after_a_release_never_sizes_past_the_control() {
    let mut seeds_presized = 0;
    for seed in 0..12 {
        let (released, blocks) = clustered_schedule(seed);
        let ((table, head, rebuilds), (control_table, control, control_rebuilds)) =
            with_control(|| clustered_walk(released, &blocks));
        let case = format!("seed {seed}: release {released}, blocks {blocks:?}");
        assert_eq!(table, control_table, "{case}: same table");
        assert_at_or_below_control(&head, &control, &case);
        seeds_presized += usize::from(rebuilds < control_rebuilds);
    }
    assert!(seeds_presized > 0, "no seed presized");
}

/// R imports RT 100 and owes EVPN whole; 1,024 RT 100 routes arrive, then
/// 20,000 RT 300 routes in later passes. Only the first pass after the
/// cursor starts (its starting log) is a sample of its own keys. Red when
/// the estimate extrapolates past it: the index 28 times what it holds and
/// the slab's first segment 65,536 slots, against 1.75 times and 1,024.
#[test]
fn an_imported_evpn_block_ahead_of_an_unimported_one_fits() {
    const ACCEPTED: u32 = 1_024;
    let shape = || {
        let mut manager = rtc_manager(4096);
        std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
        let mut receivers = rtc_receivers_up(&mut manager);
        let r = receivers[0].peer;
        manager.owe_eor(r, EVPN);
        manager.owe_whole_family(r, FAMILY);
        let imported = (0..ACCEPTED).map(|i| route_rt(i, 0, &[100])).collect();
        received_routes(&mut manager, imported, &[]);
        let other = (ACCEPTED..ACCEPTED + 20_000)
            .map(|i| route_rt(i, 0, &[300]))
            .collect();
        received_routes(&mut manager, other, &[]);
        drain(&mut manager, &mut receivers);
        assert_eq!(
            receivers[0].wire.table.len(),
            ACCEPTED as usize,
            "R's table"
        );
        let (rows, capacities) = evpn_table(&manager, r);
        assert_fitted(capacities[0], rows, "imported, then not");
        capacities
    };
    let (head, control) = with_control(shape);
    assert_at_or_below_control(&head, &control, "imported, then not");
}

// ---- What R accepts changes between the release and the estimate.

/// [`assert_at_or_below_control`] within the spread of the index's 16
/// shards: each run hashes its keys with its own seed, so with no presize
/// at all a few shards of one run sit a capacity class above the other's;
/// an estimate from a stale sample moves every shard one class or more.
fn assert_within_control(head: &[usize; 2], control: &[usize; 2], case: &str) {
    let spread = control.map(|capacity| capacity + capacity / 4);
    assert_at_or_below_control(head, &spread, case);
}

const MIXED_ROWS: u32 = 20_000;

/// 15 in 20 keys carry RT 100, 1 in 20 RT 200 (R imports both), the rest
/// RT 300: R's first steps commit their sample's rows before they have
/// read its keys.
fn mixed_rt(index: u32) -> u16 {
    match index % 20 {
        0 => 200,
        1..=15 => 100,
        _ => 300,
    }
}

/// A change in what R accepts.
#[derive(Debug, Clone, Copy)]
enum Change {
    /// R's membership drops RT 100: no key is logged, R's set restages.
    DropRt100,
    /// R's membership adds RT 300: no key is logged, R's set restages.
    AddRt300,
    /// The source moves the RT 100 keys of 2,000 from `from` to RT 300:
    /// logged, and R denies them.
    Deny(u32),
    /// The source moves the RT 300 keys of 2,000 from `from` to RT 100:
    /// logged, and R accepts them.
    Accept(u32),
}

fn apply(manager: &mut RibManager, change: Change) {
    let moved = |from: u32, was: u16, now: u16| {
        (from..from + 2_000)
            .filter(|&i| mixed_rt(i) == was)
            .map(|i| route_rt(i, 1, &[now]))
            .collect()
    };
    match change {
        Change::DropRt100 => manager.handle_update(membership_update(0, 999, Some(100))),
        Change::AddRt300 => manager.handle_update(membership_update(0, 300, None)),
        Change::Deny(from) => received_routes(manager, moved(from, 100, 300), &[]),
        Change::Accept(from) => received_routes(manager, moved(from, 300, 100), &[]),
    }
}

/// [`MIXED_ROWS`] keys released to R and receiver 1 (EVPN private, both
/// importing RT 100 and RT 200) at 128 keys a step. Each change of
/// `changes` lands once R's cursor steps have read its keys. Returns R's table
/// as sent, its rows, its capacities, the presizes made, and R's keys
/// read and rows at the first change.
fn mixed_walk(
    changes: &[(usize, Change)],
) -> (
    BTreeMap<EvpnRouteKey, String>,
    usize,
    [usize; 2],
    usize,
    (usize, usize),
) {
    let mut manager = rtc_manager(256).with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer_v4(WAITER).into(),
            families: vec![EVPN],
        }],
    });
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let routes = (0..MIXED_ROWS)
        .map(|i| route_rt(i, 0, &[mixed_rt(i)]))
        .collect();
    received_routes(&mut manager, routes, &[]);
    let waiter = hold(&mut manager);
    let mut families = vpn_rtc_sendable();
    families.push(EVPN);
    let mut receivers: Vec<Receiver> = (0..2)
        .map(|index| {
            let peer = receiver(index);
            let mut rx = up_sized(&mut manager, peer, 0, 4096, &families);
            manager.handle_update(membership_update(index, 100, None));
            manager.handle_update(membership_update(index, 200, None));
            manager.handle_update(rtc_eor(index));
            Wire::default().write(&mut rx);
            assert!(manager.evpn_grouped_member_of(peer).is_none(), "private");
            Receiver {
                peer,
                rx,
                wire: Wire::default(),
            }
        })
        .collect();
    release(&mut manager);
    receivers.push(waiter);
    let r = receivers[0].peer;
    assert!(manager.owes_whole(r, FAMILY), "R walks");
    let mut pending = changes.to_vec();
    pending.sort_by_key(|(at, _)| *at);
    let mut first = None;
    // Keys R's cursor has read, across a dropped sample (which zeroes the
    // count).
    let (mut base, mut last) = (0, 0);
    // A restage drains R's own set (every key) before the cursor steps on.
    for _ in 0..4_000 {
        let now = manager.walk_keys_read(r, FAMILY);
        if now < last {
            base += last;
        }
        last = now;
        let read = base + now;
        while let Some(&(at, change)) = pending.first()
            && at <= read
        {
            let rows = manager.adj_ribs_out[&r].evpn_len();
            first.get_or_insert((read, rows));
            apply(&mut manager, change);
            pending.remove(0);
        }
        if pending.is_empty() {
            break;
        }
        tick(&mut manager, &mut receivers);
    }
    assert!(pending.is_empty(), "every change landed: {pending:?}");
    assert!(!manager.dirty_peers.contains(&r), "no resync");
    drain(&mut manager, &mut receivers);
    assert!(!manager.owes(r, EVPN), "R settled");
    let (rows, capacities) = evpn_table(&manager, r);
    assert_eq!(receivers[0].wire.table.len(), rows, "R's table as sent");
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    (
        receivers[0].wire.table.clone(),
        rows,
        capacities,
        presizes,
        first.unwrap_or_default(),
    )
}

/// After R's walk has read 384 keys (under the sample's 512, past its 256
/// rows), its membership drops RT 100: R now denies most keys ahead, which
/// stay where they are in the starting log. The unlogged change drops the
/// walk's sample, so it makes no estimate. Red without that: the index 14
/// times what it holds and the slab's first segment 65,536 slots, against
/// 1.8 times and 1,024.
#[test]
fn an_rtc_drop_mid_sample_under_an_evpn_cursor_fits() {
    let shape = || mixed_walk(&[(384, Change::DropRt100)]);
    let ((table, rows, head, _, (read, sampled)), (control_table, _, control, _, _)) =
        with_control(shape);
    assert!(
        read < 512 && sampled >= 256,
        "under the sample's keys, past its rows: {read} keys, {sampled} rows"
    );
    assert_eq!(table, control_table, "same table");
    let expected = (0..MIXED_ROWS).filter(|&i| mixed_rt(i) == 200).count();
    assert_eq!(rows, expected, "R's table");
    assert_within_control(&head, &control, "RTC drop mid-sample");
    assert_fitted(head[0], rows, "RTC drop mid-sample");
}

/// The changes of `seed`: one or two, each logged or not, raising or
/// lowering what R accepts, at a step boundary among R's first four.
fn mixed_schedule(seed: u64) -> Vec<(usize, Change)> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut draw = |range: u64| next(&mut state) % range;
    (0..1 + draw(2))
        .map(|_| {
            let at = 128 * usize::try_from(draw(4)).unwrap();
            let from = u32::try_from(draw(u64::from(MIXED_ROWS - 2_000))).unwrap();
            let change = match draw(4) {
                0 => Change::DropRt100,
                1 => Change::AddRt300,
                2 => Change::Deny(from),
                _ => Change::Accept(from),
            };
            (at, change)
        })
        .collect()
}

/// Every seed's walk, with what R accepts changed at random points
/// between the release's starting log and the estimate (by a logged pass
/// or an unlogged membership change, up or down), ends with the same
/// table as the control and capacities at or below its. Red when the
/// estimate trusts a sample taken before such a change.
#[test]
fn acceptance_changes_before_the_estimate_never_size_past_the_control() {
    for seed in 0..16 {
        let plan = mixed_schedule(seed);
        let ((table, rows, head, _, _), (control_table, _, control, _, _)) =
            with_control(|| mixed_walk(&plan));
        let case = format!("seed {seed} {plan:?}");
        assert_eq!(table, control_table, "{case}: same table");
        assert_within_control(&head, &control, &case);
        if rows != 0 {
            assert_fitted(head[0], rows, &case);
        }
    }
}
