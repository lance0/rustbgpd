//! Primary updates the actor has received from its channel and not yet
//! admitted, in FIFO order, with the bounded overtake lane.
//!
//! Every ordinary consumer sees only the head ([`ParkedPrimaries::peek`],
//! [`ParkedPrimaries::take`], [`ParkedPrimaries::put`]), exactly as it saw
//! the single held message this replaces: strict FIFO.
//!
//! The lane lets one small unicast UPDATE pass the session bring-up and
//! teardown work queued ahead of it, so an unrelated peer's change does not
//! wait for a flap's whole fan-out. A message is marked a candidate once,
//! when it is parked, and only if all of these hold for what is parked ahead
//! of it at that moment:
//!
//! - it is unicast-only route input of at most [`OVERTAKE_ROWS`] rows;
//! - nothing from its own session is ahead, so per-session order holds;
//! - everything ahead is on the passable allowlist ([`classify`]): another
//!   session's `PeerUp`, `PeerDown`, session context or unicast-only route
//!   input. Any other kind is a barrier, and a new kind is a barrier until
//!   it is listed;
//! - none of its prefixes appears in a route message ahead, so cross-source
//!   order on a shared prefix holds;
//! - no `PeerUp` or `PeerDown` ahead belongs to a session whose Adj-RIB-In
//!   holds one of its prefixes. Such a message resets that table, which can
//!   withdraw the winning path for the prefix without naming it, and a
//!   receiver would then see a different UPDATE sequence.
//!
//! The set ahead of a parked message only shrinks (the head leaves, or
//! returns unchanged), and a session's table gains a prefix only through its
//! own route messages, which are parked ahead and indexed, or already
//! applied. So a candidate stays valid until it is admitted. A message that
//! is not a candidate when parked keeps FIFO.
//!
//! Cost per seam: at most [`INSPECT_MESSAGES_PER_SEAM`] newly received
//! messages are classified, within [`INSPECT_WORK_PER_SEAM`] row hashes and
//! table lookups (the message that crosses the budget completes), then one
//! binary search and one removal from a deque of at most [`PARK_LIMIT`]
//! entries. Each message is classified once.

use std::collections::{HashMap, VecDeque};

use tokio::sync::mpsc;

use super::source_departure::KEYS_PER_PAGE;
use crate::PeerId;
use crate::adj_rib_in::AdjRibIn;
use crate::fast_hash::FastMap;
use crate::route::Route;
use crate::update::RibUpdate;
use rustbgpd_wire::Prefix;

/// Rows a message may carry and still overtake: the width one departure seam
/// already checks before it dispatches an independent UPDATE.
pub(super) const OVERTAKE_ROWS: usize = KEYS_PER_PAGE;
/// Messages one seam classifies at most. A flap of 50 sessions queues about
/// 500 bring-up messages, so a small UPDATE behind them is found in one
/// seam; a session message costs a few map operations.
pub(super) const INSPECT_MESSAGES_PER_SEAM: usize = 512;
/// Row hashes plus Adj-RIB-In lookups one seam spends classifying: about a
/// millisecond, and the tables of 50 rejoining members of 572 routes each.
/// The message that crosses it completes. A deeper backlog is inspected over
/// further seams, each of which also admits its head.
pub(super) const INSPECT_WORK_PER_SEAM: usize = 32_768;
/// Messages buffered here beyond the channel's own bound: a quarter of the
/// default channel capacity, and twice the bring-up backlog of a 50-session
/// flap. Beyond it the lane sees nothing new until the head drains.
pub(super) const PARK_LIMIT: usize = 1024;
/// Unicast rows buffered here at most, which bounds the prefix index: 64
/// full pages of the largest route chunk.
pub(super) const PARK_ROW_LIMIT: usize = 65_536;
/// Sessions with a parked `PeerUp` or `PeerDown` that a candidate is checked
/// against, at [`OVERTAKE_ROWS`] lookups each. With more of them parked,
/// nothing passes until they drain.
pub(super) const RESET_SESSIONS_LIMIT: usize = 64;

/// What a parked message is to the messages behind it.
enum Parked<'a> {
    /// Unicast-only route input.
    Routes {
        peer: PeerId,
        announced: &'a [Route],
        withdrawn: &'a [(Prefix, u32)],
    },
    /// Session bring-up or teardown: it resets the session's Adj-RIB-In.
    Reset(PeerId),
    /// Session context.
    Session(PeerId),
    /// Everything else: nothing behind it may pass.
    Barrier,
}

/// The passable allowlist. A kind not named here is a barrier.
fn classify(update: &RibUpdate) -> Parked<'_> {
    match update.unmetered() {
        RibUpdate::RoutesReceived {
            peer,
            announced,
            withdrawn,
            flowspec_announced,
            flowspec_withdrawn,
            evpn_announced,
            evpn_withdrawn,
            ..
        } if flowspec_announced.is_empty()
            && flowspec_withdrawn.is_empty()
            && evpn_announced.is_empty()
            && evpn_withdrawn.is_empty() =>
        {
            Parked::Routes {
                peer: *peer,
                announced,
                withdrawn,
            }
        }
        RibUpdate::WireRoutesReceived(batch)
            if batch.flowspec_announced.is_empty()
                && batch.flowspec_withdrawn.is_empty()
                && batch.evpn_announced.is_empty()
                && batch.evpn_withdrawn.is_empty() =>
        {
            Parked::Routes {
                peer: batch.peer,
                announced: &batch.announced,
                withdrawn: &batch.withdrawn,
            }
        }
        RibUpdate::PeerUp { peer, .. } | RibUpdate::PeerDown { peer, .. } => Parked::Reset(*peer),
        RibUpdate::PeerAddPathLimits { peer, .. }
        | RibUpdate::PeerFamilySendable { peer, .. }
        | RibUpdate::PeerOrfUpdate { peer, .. }
        | RibUpdate::PeerSlowState { peer, .. }
        | RibUpdate::SetPeerSessionExportPolicy { peer, .. }
        | RibUpdate::SetPeerSourceContext { peer, .. }
        | RibUpdate::SetPeerPolicyContext { peer, .. }
        | RibUpdate::SetPeerExportPolicyCounters { peer, .. }
        | RibUpdate::SetPeerExportContext { peer, .. }
        | RibUpdate::SetPeerWithheldFamilies { peer, .. }
        | RibUpdate::SetPeerRsControl { peer, .. }
        | RibUpdate::SetPeerExportEncoder { peer, .. }
        | RibUpdate::SetPeerGracefulRestartContext { peer, .. } => Parked::Session(*peer),
        _ => Parked::Barrier,
    }
}

fn prefixes<'a>(
    announced: &'a [Route],
    withdrawn: &'a [(Prefix, u32)],
) -> impl Iterator<Item = Prefix> + 'a {
    announced
        .iter()
        .map(|route| route.prefix)
        .chain(withdrawn.iter().map(|&(prefix, _)| prefix))
}

struct Entry {
    /// Strictly increasing from head to tail.
    seq: u64,
    update: RibUpdate,
    /// Whether [`Ahead`] counts this entry.
    indexed: bool,
}

/// What the indexed parked messages hold, for the messages behind them.
#[derive(Default)]
struct Ahead {
    /// Session and route messages, by session.
    sessions: FastMap<PeerId, usize>,
    /// Rows of route messages, by prefix.
    prefixes: FastMap<Prefix, usize>,
    /// `PeerUp` and `PeerDown` messages, by session.
    resets: FastMap<PeerId, usize>,
    rows: usize,
    barriers: usize,
}

fn forget<K: std::hash::Hash + Eq>(counts: &mut FastMap<K, usize>, key: &K) {
    if let Some(count) = counts.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            counts.remove(key);
        }
    }
}

impl Ahead {
    /// Count `update`; returns the rows hashed.
    fn add(&mut self, update: &RibUpdate) -> usize {
        match classify(update) {
            Parked::Routes {
                peer,
                announced,
                withdrawn,
            } => {
                *self.sessions.entry(peer).or_default() += 1;
                for prefix in prefixes(announced, withdrawn) {
                    *self.prefixes.entry(prefix).or_default() += 1;
                }
                let rows = announced.len() + withdrawn.len();
                self.rows += rows;
                return rows;
            }
            Parked::Reset(peer) => {
                *self.sessions.entry(peer).or_default() += 1;
                *self.resets.entry(peer).or_default() += 1;
            }
            Parked::Session(peer) => *self.sessions.entry(peer).or_default() += 1,
            Parked::Barrier => self.barriers += 1,
        }
        0
    }

    fn remove(&mut self, update: &RibUpdate) {
        match classify(update) {
            Parked::Routes {
                peer,
                announced,
                withdrawn,
            } => {
                forget(&mut self.sessions, &peer);
                for prefix in prefixes(announced, withdrawn) {
                    forget(&mut self.prefixes, &prefix);
                }
                self.rows -= announced.len() + withdrawn.len();
            }
            Parked::Reset(peer) => {
                forget(&mut self.sessions, &peer);
                forget(&mut self.resets, &peer);
            }
            Parked::Session(peer) => forget(&mut self.sessions, &peer),
            Parked::Barrier => self.barriers -= 1,
        }
    }

    /// Whether `update` may pass everything counted here, and the table
    /// lookups spent deciding.
    fn passes(&self, update: &RibUpdate, ribs: &HashMap<PeerId, AdjRibIn>) -> (bool, usize) {
        let Parked::Routes {
            peer,
            announced,
            withdrawn,
        } = classify(update)
        else {
            return (false, 0);
        };
        let rows = announced.len() + withdrawn.len();
        if self.barriers != 0
            || !(1..=OVERTAKE_ROWS).contains(&rows)
            || self.sessions.contains_key(&peer)
            || self.resets.len() > RESET_SESSIONS_LIMIT
            || prefixes(announced, withdrawn).any(|prefix| self.prefixes.contains_key(&prefix))
        {
            return (false, 0);
        }
        let held = self.resets.keys().any(|reset| {
            ribs.get(reset).is_some_and(|rib| {
                prefixes(announced, withdrawn)
                    .any(|prefix| rib.iter_prefix(&prefix).next().is_some())
            })
        });
        (!held, self.resets.len() * rows)
    }
}

/// The actor's received, unadmitted primary updates.
pub(super) struct ParkedPrimaries {
    entries: VecDeque<Entry>,
    next_seq: u64,
    /// Entries [`Ahead`] does not count yet: a head parked by an ordinary
    /// peek or returned by [`Self::put`]. Indexed before the next read-ahead.
    unindexed: usize,
    ahead: Ahead,
    /// Sequence number of the first parked candidate. Read-ahead stops at
    /// it, so at most one is tracked.
    candidate: Option<u64>,
    /// The last admission passed the head. The next admission at an intake
    /// seam takes the head, so the lane cannot starve the queue.
    head_owed: bool,
    /// TEST ONLY: keep strict FIFO, as the reference arm of the ordering
    /// oracle and for cases that pin the FIFO path.
    #[cfg(test)]
    pub(super) strict_fifo: bool,
}

impl Default for ParkedPrimaries {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            // Leaves room below for returned heads.
            next_seq: 1 << 32,
            unindexed: 0,
            ahead: Ahead::default(),
            candidate: None,
            head_owed: false,
            #[cfg(test)]
            strict_fifo: false,
        }
    }
}

impl ParkedPrimaries {
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the head must be admitted before another message passes it.
    pub(super) fn head_owed(&self) -> bool {
        self.head_owed
    }

    /// Record an admission: of the head, or of a message that passed it.
    pub(super) fn admitted(&mut self, passed_head: bool) {
        self.head_owed = passed_head;
    }

    /// The FIFO head, if one is parked.
    pub(super) fn head(&self) -> Option<&RibUpdate> {
        self.entries.front().map(|entry| &entry.update)
    }

    /// The FIFO head, receiving it without waiting when nothing is parked.
    pub(super) fn peek(&mut self, rx: &mut mpsc::Receiver<RibUpdate>) -> Option<&RibUpdate> {
        if self.entries.is_empty()
            && let Ok(update) = rx.try_recv()
        {
            self.put(update);
        }
        self.head()
    }

    /// Remove the FIFO head.
    pub(super) fn take(&mut self) -> Option<RibUpdate> {
        let entry = self.entries.pop_front()?;
        if self.candidate == Some(entry.seq) {
            self.candidate = None;
        }
        Some(self.release(entry))
    }

    /// Park a message at the front: one just received with nothing parked,
    /// or a head just taken, which keeps its FIFO position.
    pub(super) fn put(&mut self, update: RibUpdate) {
        let seq = match self.entries.front() {
            Some(head) => head.seq - 1,
            None => self.take_seq(),
        };
        self.entries.push_front(Entry {
            seq,
            update,
            indexed: false,
        });
        self.unindexed += 1;
    }

    fn take_seq(&mut self) -> u64 {
        self.next_seq += 1;
        self.next_seq
    }

    /// Drop a removed entry from the index and return its message.
    fn release(&mut self, entry: Entry) -> RibUpdate {
        if entry.indexed {
            self.ahead.remove(&entry.update);
        } else {
            self.unindexed -= 1;
        }
        entry.update
    }

    /// Receive queued messages behind the parked ones until one is a
    /// candidate, a barrier is parked, a bound is reached or the channel is
    /// empty. Never waits.
    pub(super) fn read_ahead(
        &mut self,
        rx: &mut mpsc::Receiver<RibUpdate>,
        ribs: &HashMap<PeerId, AdjRibIn>,
    ) {
        let (mut messages, mut work) = (0, 0);
        if self.unindexed > 0 {
            for entry in &mut self.entries {
                if !entry.indexed {
                    work += self.ahead.add(&entry.update);
                    entry.indexed = true;
                }
            }
            self.unindexed = 0;
        }
        while self.candidate.is_none()
            && self.ahead.barriers == 0
            && self.entries.len() < PARK_LIMIT
            && self.ahead.rows < PARK_ROW_LIMIT
            && messages < INSPECT_MESSAGES_PER_SEAM
            && work < INSPECT_WORK_PER_SEAM
        {
            let Ok(update) = rx.try_recv() else {
                break;
            };
            messages += 1;
            let seq = self.take_seq();
            if !self.entries.is_empty() {
                let (passes, lookups) = self.ahead.passes(&update, ribs);
                work += lookups;
                if passes {
                    self.candidate = Some(seq);
                }
            }
            work += self.ahead.add(&update);
            self.entries.push_back(Entry {
                seq,
                update,
                indexed: true,
            });
        }
    }

    fn candidate_at(&self) -> Option<usize> {
        let seq = self.candidate?;
        let at = self
            .entries
            .binary_search_by_key(&seq, |entry| entry.seq)
            .expect("a candidate is parked until it leaves");
        // The head is admitted by the ordinary FIFO path, and a head that is
        // itself a small UPDATE is not worth passing: small UPDATEs keep
        // their arrival order among themselves.
        let small_head = self.entries.front().is_some_and(|head| {
            matches!(
                classify(&head.update),
                Parked::Routes { announced, withdrawn, .. }
                    if announced.len() + withdrawn.len() <= OVERTAKE_ROWS
            )
        });
        (at > 0 && !small_head).then_some(at)
    }

    /// The first parked message that may pass what is ahead of it. `None`
    /// when it is the head itself.
    pub(super) fn candidate(&self) -> Option<&RibUpdate> {
        self.candidate_at().map(|at| &self.entries[at].update)
    }

    /// Remove the message [`Self::candidate`] returned.
    pub(super) fn take_candidate(&mut self) -> Option<RibUpdate> {
        let at = self.candidate_at()?;
        self.candidate = None;
        let entry = self.entries.remove(at)?;
        Some(self.release(entry))
    }
}
