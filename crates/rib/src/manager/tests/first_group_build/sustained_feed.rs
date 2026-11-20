//! A cold first-member build on 16,384 routes while another peer keeps
//! sending route messages that each span several route chunks. Work counts.

use super::*;

const THIRD: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 3);
const TABLE_PER_FAMILY: u16 = 8192;
const PAGE: usize = crate::loc_rib::REGISTRATION_PAGE_SIZE;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Feed {
    /// Every row is a new prefix, so the table grows by the whole feed.
    Announce,
    /// Every row withdraws a prefix whose only path is the sender's. The
    /// table starts with every row the feed will withdraw.
    Withdraw,
    /// Every message replaces the same block of best paths. The table keeps
    /// its size, so the stream can be any length.
    Replace,
}

fn feed_key(n: u32) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x0b00_0000 + n), 32))
}

fn feed_message(feed: Feed, message: u32, rows: u32) -> RibUpdate {
    let announce = |keys: std::ops::Range<u32>, pref| {
        test_routes_received(
            peer_v4(OTHER),
            keys.map(|n| route(feed_key(n), OTHER, pref)).collect(),
        )
    };
    let block = message * rows..(message + 1) * rows;
    match feed {
        Feed::Announce => announce(block, 100),
        Feed::Replace => announce(0..rows, 100 + message % 2),
        Feed::Withdraw => {
            let mut update = test_routes_received(peer_v4(OTHER), Vec::new());
            let RibUpdate::RoutesReceived { withdrawn, .. } = &mut update else {
                unreachable!()
            };
            *withdrawn = block.map(|n| (feed_key(n), 0)).collect();
            update
        }
    }
}

/// Returns the manager, its primary sender and the prefix an unrelated third
/// peer announces in the middle of the feed.
fn feed_fixture(
    feed: Feed,
    messages: u32,
    rows: u32,
) -> (RibManager, mpsc::Sender<RibUpdate>, Prefix) {
    let (mut manager, _tx, _) = fixture(TABLE_PER_FAMILY);
    register_test_peer(&mut manager, peer_v4(THIRD), 0);
    let installed = match feed {
        Feed::Announce => 0,
        Feed::Replace => rows,
        Feed::Withdraw => messages * rows,
    };
    if installed > 0 {
        manager.handle_update(test_routes_received(
            peer_v4(OTHER),
            (0..installed)
                .map(|n| route(feed_key(n), OTHER, 99))
                .collect(),
        ));
        drain_route_chunks(&mut manager);
    }
    let (primary, rx) = mpsc::channel(messages as usize + 16);
    manager.rx = rx;
    let marker = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    (manager, primary, marker)
}

fn marker_message(marker: Prefix) -> RibUpdate {
    test_routes_received(peer_v4(THIRD), vec![route(marker, THIRD, 100)])
}

#[derive(Debug, Default)]
struct Counts {
    primary_turns: usize,
    build_turns: usize,
    starts: usize,
    overflows: usize,
    discarded_scan_pages: usize,
    retire_turns: usize,
    max_slots_retired_in_a_turn: usize,
    marker_primary_turn: usize,
    grouped_primary_turn: Option<usize>,
    feed_end_primary_turn: usize,
}

impl Counts {
    fn grouped_during_feed(&self) -> bool {
        self.grouped_primary_turn
            .is_some_and(|turn| turn < self.feed_end_primary_turn)
    }
}

/// The run loop's registration branch (`run_actor`: "Private construction
/// alternates with queued primary work"), with the production
/// `drain_ready_updates`, `advance_busy_first_group` and
/// `advance_pending_initial_registration`, one call per owner turn. The
/// staging turn itself asserts its page bound.
async fn feed_counts(feed: Feed, messages: u32, rows: u32, joiner: bool) -> Counts {
    let (mut manager, primary, marker) = feed_fixture(feed, messages, rows);
    let table = manager.loc_rib.len();
    let mut counts = Counts::default();
    let founder = receiver(1);
    let mut founder_rx = None;
    if joiner {
        founder_rx = Some(join(&mut manager, founder, 1, &DUAL));
        assert!(manager.first_group_build.is_some());
        counts.starts = 1;
    }
    for message in 0..messages {
        if message == messages / 2 {
            primary.try_send(marker_message(marker)).unwrap();
        }
        primary.try_send(feed_message(feed, message, rows)).unwrap();
    }

    let mut primary_due = true;
    let mut search = 0;
    let mut attempt_pages = 0usize;
    let mut feed_ended = false;
    loop {
        assert!(counts.primary_turns + counts.build_turns < 4_000_000);
        if let Some(rx) = &mut founder_rx {
            while rx.try_recv().is_ok() {}
        }
        if counts.marker_primary_turn == 0 && manager.loc_rib.get(&marker).is_some() {
            counts.marker_primary_turn = counts.primary_turns;
        }
        if counts.grouped_primary_turn.is_none() && manager.grouped_member_of(founder).is_some() {
            counts.grouped_primary_turn = Some(counts.primary_turns);
        }
        let busy = !manager.pending_route_batches.is_empty() || manager.primary_backlog() > 0;
        if !busy && !feed_ended {
            feed_ended = true;
            counts.feed_end_primary_turn = counts.primary_turns;
        }
        let registration_branch = manager.first_group_build.is_some()
            || !manager.pending_initial_registrations.is_empty();
        if !registration_branch {
            if !manager.drain_ready_updates().await {
                break;
            }
            counts.primary_turns += 1;
            continue;
        }
        if primary_due && manager.drain_ready_updates().await {
            primary_due = false;
            counts.primary_turns += 1;
            continue;
        }
        primary_due = true;
        let had_build = manager.first_group_build.is_some();
        let was_retiring = manager.first_group_retiring_slots();
        let accept_primary = manager.can_receive_release_primary();
        if !manager.pending_route_batches.is_empty()
            || (accept_primary && manager.primary_backlog() > 0)
        {
            manager.advance_busy_first_group(&mut search);
        } else {
            manager.advance_pending_initial_registration();
        }
        counts.build_turns += 1;
        let has_build = manager.first_group_build.is_some();
        let retiring = manager.first_group_retiring_slots();
        let grouped = manager.grouped_member_of(founder).is_some();
        if let Some(old) = was_retiring {
            // A later retirement page. Slot counts are physical slab slots.
            counts.retire_turns += 1;
            counts.max_slots_retired_in_a_turn = counts
                .max_slots_retired_in_a_turn
                .max(old.saturating_sub(retiring.unwrap_or(0)));
        } else if !had_build && has_build {
            counts.starts += 1;
            attempt_pages = 1;
        } else if had_build && (retiring.is_some() || (!has_build && !grouped)) {
            // The turn that saw the overflow also retired the first page.
            counts.overflows += 1;
            counts.discarded_scan_pages += attempt_pages;
            attempt_pages = 0;
            counts.retire_turns += 1;
        } else if had_build {
            attempt_pages += 1;
        }
    }
    assert!(manager.loc_rib.get(&marker).is_some());
    let fed = (messages * rows) as usize;
    let final_len = match feed {
        Feed::Announce => table + fed + 1,
        Feed::Withdraw => table - fed + 1,
        Feed::Replace => table + 1,
    };
    assert_eq!(manager.loc_rib.len(), final_len);
    assert_eq!(joiner, manager.grouped_member_of(founder).is_some());
    counts
}

/// Rows per message: 2, 4 and 16 route chunks. 16,378 is the largest run of
/// /24 withdrawals one Extended Message UPDATE carries.
const MULTI_CHUNK_ROWS: [u32; 3] = [2048, 4096, 16378];

/// A message of one chunk already could not outrun the build.
#[tokio::test]
async fn single_chunk_messages_never_restart_the_cold_build() {
    for feed in [Feed::Announce, Feed::Withdraw, Feed::Replace] {
        for messages in [48, 96] {
            let c = feed_counts(feed, messages, 1024, true).await;
            eprintln!("{feed:?} {messages}x1024 {c:?}");
            assert_eq!(
                (c.starts, c.overflows),
                (1, 0),
                "{feed:?} {messages}: {c:?}"
            );
            // The withdrawal table (16,384 plus every row the feed withdraws)
            // needs more pages than the feed has turns, and so does a table
            // that the shorter announcement feed is still growing.
            if feed == Feed::Replace {
                assert!(c.grouped_during_feed(), "{feed:?} {messages}: {c:?}");
            }
        }
    }
}

/// The build keeps its one table however long a multi-chunk stream lasts, in
/// the three ways a row can change the Loc-RIB.
#[tokio::test]
async fn multi_chunk_messages_never_restart_the_cold_build() {
    let mut failures = Vec::new();
    for feed in [Feed::Announce, Feed::Withdraw, Feed::Replace] {
        for rows in MULTI_CHUNK_ROWS {
            let chunks = rows.div_ceil(1024);
            for messages in [48 / chunks, 96 / chunks] {
                let c = feed_counts(feed, messages, rows, true).await;
                let row = format!("{feed:?} {messages}x{rows} {c:?}");
                eprintln!("{row}");
                if (
                    c.starts,
                    c.overflows,
                    c.discarded_scan_pages,
                    c.retire_turns,
                ) != (1, 0, 0, 0)
                {
                    failures.push(row);
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "the cold build restarted during a multi-chunk feed:\n{}",
        failures.join("\n")
    );
}

/// A stream that keeps replacing the same block leaves the table its size, so
/// the build's own work is fixed. The joiner registers during the stream, at
/// a turn that does not grow with the length of the stream. A message of
/// sixteen chunks leaves discovery one turn in seventeen.
#[tokio::test]
async fn joiner_registers_during_a_multi_chunk_stream_of_any_length() {
    let mut failures = Vec::new();
    for (rows, lengths) in [(2048, &[64, 128][..]), (4096, &[48, 96]), (16378, &[80])] {
        let mut registered = Vec::new();
        for &messages in lengths {
            let c = feed_counts(Feed::Replace, messages, rows, true).await;
            eprintln!("Replace {messages}x{rows} {c:?}");
            if !c.grouped_during_feed() || c.overflows > 0 {
                failures.push(format!("{messages}x{rows}: {c:?}"));
            }
            registered.push(c.grouped_primary_turn.unwrap_or(usize::MAX));
        }
        // The third peer's message falls before or after registration.
        if registered
            .iter()
            .any(|turn| turn.abs_diff(registered[0]) > 2)
        {
            failures.push(format!("x{rows}: registered at {registered:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "the joiner waited for the stream to end:\n{}",
        failures.join("\n")
    );
}

/// An unrelated peer's UPDATE in the middle of the feed is installed at the
/// same primary turn with and without the cold joiner.
#[tokio::test]
async fn unrelated_update_keeps_its_turn_during_a_multi_chunk_feed() {
    for feed in [Feed::Announce, Feed::Withdraw, Feed::Replace] {
        for (messages, rows) in [(48, 1024), (24, 2048), (3, 16378)] {
            let with = feed_counts(feed, messages, rows, true).await;
            let without = feed_counts(feed, messages, rows, false).await;
            assert_eq!(
                with.marker_primary_turn, without.marker_primary_turn,
                "{feed:?} {messages}x{rows}: {with:?}"
            );
            assert!(with.max_slots_retired_in_a_turn <= PAGE, "{with:?}");
        }
    }
}

/// The real actor loop with the whole feed queued. FIFO queries record the
/// joiner's group before the last quarter of the feed and after it; the
/// joiner's channel is read to the end and compared with the Loc-RIB.
async fn actor_case(feed: Feed, messages: u32, rows: u32) -> (String, String) {
    let (mut manager, primary, marker) = feed_fixture(feed, messages, rows);
    let founder = receiver(1);
    let mut founder_rx = join(&mut manager, founder, 1, &DUAL);
    assert!(manager.first_group_build.is_some());
    let query = |tx: &mpsc::Sender<RibUpdate>| {
        let (reply, response) = oneshot::channel();
        tx.try_send(RibUpdate::QueryPeerUpdateGroup {
            peer: founder,
            reply,
        })
        .unwrap();
        response
    };
    let mut during = None;
    for message in 0..messages {
        if message == messages / 2 {
            primary.try_send(marker_message(marker)).unwrap();
        }
        if message == messages * 3 / 4 {
            during = Some(query(&primary));
        }
        primary.try_send(feed_message(feed, message, rows)).unwrap();
    }
    let mut during = during.unwrap();
    let mut after = query(&primary);

    let mut actor = tokio::spawn(manager.run_actor());
    let mut view = Inventory::new();
    let mut ends = Vec::new();
    let mut apply = |update: OutboundRouteUpdate, ends: &mut Vec<(Afi, Safi)>| {
        for (prefix, _) in update.unicast_withdrawals() {
            view.remove(prefix);
        }
        for row in update.announce.iter() {
            view.insert(row.prefix, (row.peer, row.local_pref()));
        }
        ends.extend(update.end_of_rib);
    };
    let (mut at_during, mut at_after) = (None, None);
    tokio::time::timeout(Duration::from_secs(300), async {
        while at_after.is_none() || ends.len() < DUAL.len() {
            tokio::select! {
                biased;
                update = founder_rx.recv() => apply(update.unwrap(), &mut ends),
                reply = &mut during, if at_during.is_none() => at_during = Some(reply.unwrap()),
                reply = &mut after, if at_after.is_none() => at_after = Some(reply.unwrap()),
            }
        }
    })
    .await
    .expect("the joiner got its table and End-of-RIB");
    // Rows that followed the initial table are sent before the actor returns.
    drop(primary);
    let manager = loop {
        tokio::select! {
            biased;
            Some(update) = founder_rx.recv() => apply(update, &mut ends),
            manager = &mut actor => break manager.unwrap(),
        }
    };
    while let Ok(update) = founder_rx.try_recv() {
        apply(update, &mut ends);
    }
    assert!(
        ends.len() == DUAL.len() && DUAL.iter().all(|family| ends.contains(family)),
        "{feed:?} {messages}x{rows}: one End-of-RIB per family, got {ends:?}"
    );
    let wanted: Inventory = manager
        .loc_rib
        .iter()
        .map(|route| (route.prefix, (route.peer, route.local_pref())))
        .collect();
    assert!(
        view == wanted,
        "{feed:?} {messages}x{rows}: final view differs"
    );
    assert!(manager.grouped_member_of(founder).is_some());
    (at_during.unwrap(), at_after.unwrap())
}

#[tokio::test]
async fn actor_registers_the_joiner_during_a_multi_chunk_stream() {
    for (messages, rows) in [(64, 2048), (48, 4096)] {
        let (during, after) = actor_case(Feed::Replace, messages, rows).await;
        assert!(
            !during.is_empty() && during == after,
            "x{rows}: group {during:?} with a quarter of the stream left, {after:?} after it"
        );
    }
    // The table-sized feeds only have to end with one complete table.
    for feed in [Feed::Announce, Feed::Withdraw] {
        for (messages, rows) in [(24, 2048), (3, 16378)] {
            actor_case(feed, messages, rows).await;
        }
    }
}
