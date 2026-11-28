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
//! Cost. Receiving and counting a message is a few map operations, and at
//! most [`INSPECT_MESSAGES_PER_SEAM`] are received per seam. A parked route
//! message's rows are hashed only when a message that could pass arrives
//! behind it, at most once, and a seam spends at most
//! [`INSPECT_WORK_PER_SEAM`] row hashes and table lookups; a message whose
//! rows do not fit what is left waits for the next seam. Admission is one
//! binary search and one removal from a deque of at most [`PARK_LIMIT`]
//! entries. Nothing is read while the head is itself a small UPDATE, so a
//! stream of small UPDATEs, and a burst of tables with none behind it, pay
//! no hashing at all.

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
/// Row hashes plus Adj-RIB-In lookups one seam spends: about a millisecond,
/// and the tables of 50 rejoining members of 572 routes each. A route
/// message whose rows do not fit what is left of it waits for the next seam;
/// one with more rows than this is a barrier and is never hashed.
pub(super) const INSPECT_WORK_PER_SEAM: usize = 32_768;
/// Messages buffered here beyond the channel's own bound: a quarter of the
/// default channel capacity, and twice the bring-up backlog of a 50-session
/// flap. Beyond it the lane sees nothing new until the head drains.
pub(super) const PARK_LIMIT: usize = 1024;
/// Unicast rows parked here before reading ahead stops: 64 full pages of
/// the largest route chunk. The message that crosses it is parked, so at
/// most one message's rows are buffered beyond it. The prefix index holds a
/// subset of the parked rows.
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

/// How far [`Ahead`] has taken a parked entry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Indexed {
    /// Not at all: the head returned by [`ParkedPrimaries::put`], or the
    /// tail, which is counted only when another message arrives behind it.
    No,
    /// Its session, kind and row count are counted. Its rows are not hashed.
    Counted,
    /// Counted, and its rows are in the prefix index.
    Hashed,
    /// Counted, and a route message with more rows than one seam may hash:
    /// a barrier, its rows are never hashed.
    Oversized,
}

struct Entry {
    /// Strictly increasing from head to tail.
    seq: u64,
    update: RibUpdate,
    indexed: Indexed,
}

/// Unicast rows of a passable route message; zero for any other message.
fn route_rows(update: &RibUpdate) -> usize {
    match classify(update) {
        Parked::Routes {
            announced,
            withdrawn,
            ..
        } => announced.len() + withdrawn.len(),
        _ => 0,
    }
}

/// What the parked messages hold, for the messages behind them.
///
/// Counting a message is a few map operations. Hashing its rows is the
/// expensive part and is done only when a message that could pass arrives
/// behind it, so a burst of tables with no small UPDATE behind is never
/// hashed.
#[derive(Default)]
struct Ahead {
    /// Counted session and route messages, by session.
    sessions: FastMap<PeerId, usize>,
    /// Counted `PeerUp` and `PeerDown` messages, by session.
    resets: FastMap<PeerId, usize>,
    /// Counted messages off the allowlist, and oversized route messages.
    barriers: usize,
    /// Rows of counted route messages.
    parked_rows: usize,
    /// Rows of hashed route messages, by prefix.
    prefixes: FastMap<Prefix, usize>,
    hashed_rows: usize,
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
    fn count(&mut self, update: &RibUpdate) {
        match classify(update) {
            Parked::Routes {
                peer,
                announced,
                withdrawn,
            } => {
                *self.sessions.entry(peer).or_default() += 1;
                self.parked_rows += announced.len() + withdrawn.len();
            }
            Parked::Reset(peer) => {
                *self.sessions.entry(peer).or_default() += 1;
                *self.resets.entry(peer).or_default() += 1;
            }
            Parked::Session(peer) => *self.sessions.entry(peer).or_default() += 1,
            Parked::Barrier => self.barriers += 1,
        }
    }

    fn uncount(&mut self, update: &RibUpdate) {
        match classify(update) {
            Parked::Routes {
                peer,
                announced,
                withdrawn,
            } => {
                forget(&mut self.sessions, &peer);
                self.parked_rows -= announced.len() + withdrawn.len();
            }
            Parked::Reset(peer) => {
                forget(&mut self.sessions, &peer);
                forget(&mut self.resets, &peer);
            }
            Parked::Session(peer) => forget(&mut self.sessions, &peer),
            Parked::Barrier => self.barriers -= 1,
        }
    }

    /// Put a counted route message's rows in the prefix index.
    fn hash(&mut self, update: &RibUpdate) {
        if let Parked::Routes {
            announced,
            withdrawn,
            ..
        } = classify(update)
        {
            for prefix in prefixes(announced, withdrawn) {
                *self.prefixes.entry(prefix).or_default() += 1;
            }
            self.hashed_rows += announced.len() + withdrawn.len();
        }
    }

    fn unhash(&mut self, update: &RibUpdate) {
        if let Parked::Routes {
            announced,
            withdrawn,
            ..
        } = classify(update)
        {
            for prefix in prefixes(announced, withdrawn) {
                forget(&mut self.prefixes, &prefix);
            }
            self.hashed_rows -= announced.len() + withdrawn.len();
        }
    }

    /// Whether `update` could pass by what is counted alone: its shape, its
    /// session and the kinds ahead. Decides whether hashing is worth it.
    fn could_pass(&self, update: &RibUpdate) -> bool {
        let Parked::Routes {
            peer,
            announced,
            withdrawn,
        } = classify(update)
        else {
            return false;
        };
        self.barriers == 0
            && (1..=OVERTAKE_ROWS).contains(&(announced.len() + withdrawn.len()))
            && !self.sessions.contains_key(&peer)
            && self.resets.len() <= RESET_SESSIONS_LIMIT
    }

    /// Whether `update`, which [`Self::could_pass`], shares no prefix with a
    /// route message ahead or with the table of a session whose `PeerUp` or
    /// `PeerDown` is ahead; and the table lookups spent deciding. Every
    /// route message ahead must be hashed.
    fn passes(&self, update: &RibUpdate, ribs: &HashMap<PeerId, AdjRibIn>) -> (bool, usize) {
        let Parked::Routes {
            announced,
            withdrawn,
            ..
        } = classify(update)
        else {
            return (false, 0);
        };
        if self.barriers != 0
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
        (
            !held,
            self.resets.len() * (announced.len() + withdrawn.len()),
        )
    }
}

fn small_routes(update: &RibUpdate) -> bool {
    matches!(
        classify(update),
        Parked::Routes { announced, withdrawn, .. }
            if announced.len() + withdrawn.len() <= OVERTAKE_ROWS
    )
}

/// The actor's received, unadmitted primary updates.
pub(super) struct ParkedPrimaries {
    entries: VecDeque<Entry>,
    next_seq: u64,
    /// Entries [`Ahead`] does not count yet: a head parked by an ordinary
    /// peek or returned by [`Self::put`], and the tail.
    uncounted: usize,
    ahead: Ahead,
    /// The tail could pass by what is counted, and waits for the route
    /// messages ahead of it to be hashed before that is decided.
    tail_pending: bool,
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
            uncounted: 0,
            ahead: Ahead::default(),
            tail_pending: false,
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
        if self.entries.is_empty() {
            self.tail_pending = false;
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
            indexed: Indexed::No,
        });
        self.uncounted += 1;
    }

    fn take_seq(&mut self) -> u64 {
        self.next_seq += 1;
        self.next_seq
    }

    /// Drop a removed entry from the counts and the index, and return its
    /// message.
    fn release(&mut self, entry: Entry) -> RibUpdate {
        match entry.indexed {
            Indexed::No => self.uncounted -= 1,
            Indexed::Counted => self.ahead.uncount(&entry.update),
            Indexed::Hashed => {
                self.ahead.unhash(&entry.update);
                self.ahead.uncount(&entry.update);
            }
            Indexed::Oversized => {
                self.ahead.barriers -= 1;
                self.ahead.uncount(&entry.update);
            }
        }
        entry.update
    }

    /// Count every parked entry that is not, except the last `keep`.
    fn count_parked(&mut self, keep: usize) {
        if self.uncounted <= keep {
            return;
        }
        let end = self.entries.len() - keep;
        for entry in self.entries.iter_mut().take(end) {
            if entry.indexed == Indexed::No {
                self.ahead.count(&entry.update);
                entry.indexed = Indexed::Counted;
                self.uncounted -= 1;
            }
        }
    }

    /// Decide the pending tail: hash the route messages ahead of it, within
    /// the seam's budget, then check its prefixes. Returns `false` when the
    /// budget ran out first; the next seam resumes.
    ///
    /// A route message with more rows than a whole seam may hash is counted
    /// as a barrier instead, and its rows are never hashed.
    fn decide_tail(&mut self, ribs: &HashMap<PeerId, AdjRibIn>, work: &mut usize) -> bool {
        self.count_parked(1);
        let ahead = self.entries.len() - 1;
        for entry in self.entries.iter_mut().take(ahead) {
            if entry.indexed != Indexed::Counted {
                continue;
            }
            let rows = route_rows(&entry.update);
            if rows == 0 {
                continue;
            }
            if rows > INSPECT_WORK_PER_SEAM {
                self.ahead.barriers += 1;
                entry.indexed = Indexed::Oversized;
            } else if *work > 0 && *work + rows > INSPECT_WORK_PER_SEAM {
                return false;
            } else {
                self.ahead.hash(&entry.update);
                entry.indexed = Indexed::Hashed;
                *work += rows;
            }
        }
        self.tail_pending = false;
        let Some(tail) = self.entries.back() else {
            return true;
        };
        let (passes, lookups) = self.ahead.passes(&tail.update, ribs);
        *work += lookups;
        if passes {
            self.candidate = Some(tail.seq);
        }
        true
    }

    /// Receive queued messages behind the parked ones until one is a
    /// candidate, a barrier is parked, a bound is reached or the channel is
    /// empty. Never waits. Returns the row hashes and table lookups spent.
    ///
    /// That is zero unless a message that could pass arrived: a parked
    /// message is only counted, and its rows are hashed when a small UPDATE
    /// from a session with nothing parked arrives behind it. Nothing is read
    /// while the head is itself a small UPDATE, which is never passed.
    pub(super) fn read_ahead(
        &mut self,
        rx: &mut mpsc::Receiver<RibUpdate>,
        ribs: &HashMap<PeerId, AdjRibIn>,
    ) -> usize {
        if self.peek(rx).is_none_or(small_routes) {
            return 0;
        }
        let (mut messages, mut work) = (0, 0);
        while self.candidate.is_none()
            && messages < INSPECT_MESSAGES_PER_SEAM
            && work < INSPECT_WORK_PER_SEAM
        {
            if self.tail_pending {
                if !self.decide_tail(ribs, &mut work) {
                    break;
                }
                continue;
            }
            if self.entries.len() >= PARK_LIMIT || rx.is_empty() {
                break;
            }
            self.count_parked(0);
            if self.ahead.barriers > 0 || self.ahead.parked_rows >= PARK_ROW_LIMIT {
                break;
            }
            let Ok(update) = rx.try_recv() else {
                break;
            };
            messages += 1;
            self.tail_pending = self.ahead.could_pass(&update);
            let seq = self.take_seq();
            self.entries.push_back(Entry {
                seq,
                update,
                indexed: Indexed::No,
            });
            self.uncounted += 1;
        }
        work
    }

    /// Rows in the prefix index.
    #[cfg(test)]
    pub(super) fn indexed_rows(&self) -> usize {
        self.ahead.hashed_rows
    }

    /// Rows of the counted route messages.
    #[cfg(test)]
    pub(super) fn parked_rows(&self) -> usize {
        self.ahead.parked_rows
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
        let small_head = self
            .entries
            .front()
            .is_some_and(|head| small_routes(&head.update));
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
