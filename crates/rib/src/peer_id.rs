//! The RIB's neighbor identity and the peer table that resolves it.
//!
//! Every RIB structure that belongs to a neighbor (Adj-RIB-In/Out, per-peer
//! state, distribution, update groups, Graceful Restart and route refresh)
//! keys on [`PeerId`], never on the neighbor's transport address. A scoped
//! IPv6 link-local address can belong to a different neighbor on each
//! interface, so the address alone cannot identify one.
//!
//! A `PeerId` is a compact generational handle: a slot index plus the slot's
//! generation. The peer manager allocates one per neighbor; it stays the same
//! across a reconfigure and across a learned-address change, and a deleted
//! neighbor's slot returns to a FIFO free list with its generation bumped, so
//! a re-added neighbor gets a new handle and a late message carrying the old
//! one fails [`PeerId::is_live`]. A slot is retired instead of reused once
//! its generation reaches the last one, so a generation never wraps.
//!
//! The peer table maps each handle to its current [`PeerEndpoint`]: the
//! address and, for a scoped neighbor, the interface name. The selection
//! tie-break, queries, MRT, BMP and metrics resolve the endpoint through it.
//! Only the allocation sets an endpoint, and only the RIB changes one
//! (a [`RebindPeer`](crate::update::RibUpdate::RebindPeer) message), after it
//! has purged every route the neighbor's earlier session left behind, so a
//! retained route always resolves to the endpoint of the session that learned
//! it. A released slot keeps its endpoint until the slot is reused, which
//! waits until `REUSE_QUARANTINE` later releases, so history and query
//! replies that name a deleted neighbor still render; once reused, the stale
//! handle resolves to nothing rather than to the new neighbor.
//!
//! [`PeerId::from_addr`] gives routes that come from no managed neighbor
//! (MRT files, test and benchmark fixtures) a pinned identity per address.
//! An IPv4 pinned identity is encoded in the handle itself (the address as
//! the index, under a reserved generation), so it needs no table slot and
//! can be built in a `const`.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

use arc_swap::{ArcSwap, Cache};

/// Opaque identity of one RIB neighbor: 8 bytes, `Copy`, cheap to hash.
///
/// Equality says whether two handles name the same neighbor. The derived
/// order is a stable map order (slot index, then generation) and never a
/// route preference: selection compares endpoints through
/// [`PeerId::cmp_selection`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerId {
    index: u32,
    generation: NonZeroU32,
}

/// The number of released slots held back from reuse. A released handle keeps
/// resolving its endpoint until this many neighbors have been released after
/// it, so a query reply or event that left the RIB with the handle still
/// renders the neighbor it named, however late it is converted.
// ponytail: a count bound, not a reader lifetime; a reply converted after
// 1024 later deletions renders `peer#<index>.<generation>`. Per-reply endpoint
// capture if that window ever matters.
const REUSE_QUARANTINE: usize = 1024;

/// Generation of the reserved [`PeerId::UNASSIGNED`].
const RESERVED: NonZeroU32 = NonZeroU32::MAX;
/// Generation marking a pinned IPv4 identity, whose index is the address.
const PINNED_V4: NonZeroU32 = NonZeroU32::new(u32::MAX - 1).unwrap();
/// The last generation an allocated slot reaches; it is retired after it.
const LAST_GENERATION: NonZeroU32 = NonZeroU32::new(u32::MAX - 2).unwrap();

/// Where a neighbor's session runs: its transport address and, for an IPv6
/// link-local neighbor, the interface that scopes the address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PeerEndpoint {
    /// Transport address of the neighbor.
    pub addr: IpAddr,
    /// Interface name for a scoped neighbor, `None` for a numbered one.
    pub interface: Option<Arc<str>>,
}

impl PeerEndpoint {
    /// A neighbor at `addr`, scoped to `interface` when one is given.
    #[must_use]
    pub fn new(addr: IpAddr, interface: Option<&str>) -> Self {
        Self {
            addr,
            interface: interface.map(Arc::from),
        }
    }

    /// The selection tie-break order: numeric address (IPv4 before IPv6),
    /// then interface name compared bytewise, an unscoped endpoint first.
    /// Never an interface index: indexes change when an interface is
    /// recreated, which would flip the winner after maintenance.
    #[must_use]
    pub fn cmp_selection(&self, other: &Self) -> Ordering {
        self.addr.cmp(&other.addr).then_with(|| {
            let a = self.interface.as_deref().map(str::as_bytes);
            a.cmp(&other.interface.as_deref().map(str::as_bytes))
        })
    }
}

impl fmt::Display for PeerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.interface {
            Some(interface) => write!(f, "{}%{interface}", self.addr),
            None => fmt::Display::fmt(&self.addr, f),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    /// Allocated to a neighbor the peer manager owns.
    Live,
    /// Interned for an unscoped IPv6 address; never released.
    Pinned,
    /// Returned to the free list; keeps its endpoint until reused.
    Released,
    /// Reached the last generation; never reused.
    Retired,
}

#[derive(Debug, Clone)]
struct Slot {
    generation: NonZeroU32,
    state: SlotState,
    endpoint: PeerEndpoint,
}

/// The slot allocator and endpoint store behind every allocated [`PeerId`].
#[derive(Debug, Default)]
struct Slots {
    entries: Vec<Slot>,
    /// Released slots, reused oldest first and only beyond
    /// [`REUSE_QUARANTINE`], so a stale handle keeps resolving for as long as
    /// possible.
    free: VecDeque<u32>,
    /// Pinned slot of each unscoped IPv6 address [`PeerId::from_addr`]
    /// interned.
    pinned: HashMap<Ipv6Addr, u32>,
}

impl Slots {
    #[cfg(test)]
    fn slot(&self, peer: PeerId) -> Option<&Slot> {
        slot_of(&self.entries, peer)
    }

    fn allocate(&mut self, endpoint: PeerEndpoint, state: SlotState) -> PeerId {
        let reused = if self.free.len() > REUSE_QUARANTINE {
            self.free.pop_front()
        } else {
            None
        };
        if let Some(index) = reused {
            let slot = &mut self.entries[index as usize];
            // Only a slot below the last generation enters the free list.
            slot.generation = slot
                .generation
                .checked_add(1)
                .expect("a free slot is below the last generation");
            slot.state = state;
            slot.endpoint = endpoint;
            return PeerId {
                index,
                generation: slot.generation,
            };
        }
        // ponytail: 2^32 slots live or retired at once would exhaust the
        // index; each slot serves about 2^32 handles before it retires, so
        // reaching this needs billions of concurrent neighbors.
        let index = u32::try_from(self.entries.len())
            .ok()
            .filter(|&index| index != PeerId::UNASSIGNED.index)
            .expect("peer slot index space exhausted");
        self.entries.push(Slot {
            generation: NonZeroU32::MIN,
            state,
            endpoint,
        });
        PeerId {
            index,
            generation: NonZeroU32::MIN,
        }
    }

    fn release(&mut self, peer: PeerId) -> bool {
        let Some(slot) = self.entries.get_mut(peer.index as usize) else {
            return false;
        };
        if slot.generation != peer.generation || slot.state != SlotState::Live {
            return false;
        }
        if slot.generation >= LAST_GENERATION {
            slot.state = SlotState::Retired;
        } else {
            slot.state = SlotState::Released;
            self.free.push_back(peer.index);
        }
        true
    }

    fn rebind(&mut self, peer: PeerId, endpoint: PeerEndpoint) -> bool {
        match self.entries.get_mut(peer.index as usize) {
            Some(slot) if slot.generation == peer.generation && slot.state == SlotState::Live => {
                slot.endpoint = endpoint;
                true
            }
            _ => false,
        }
    }

    fn pin(&mut self, addr: Ipv6Addr) -> PeerId {
        if let Some(&index) = self.pinned.get(&addr) {
            return PeerId {
                index,
                generation: self.entries[index as usize].generation,
            };
        }
        let peer = self.allocate(PeerEndpoint::new(IpAddr::V6(addr), None), SlotState::Pinned);
        self.pinned.insert(addr, peer.index);
        peer
    }
}

/// The slot a handle names, `None` once its generation has moved on.
fn slot_of(entries: &[Slot], peer: PeerId) -> Option<&Slot> {
    entries
        .get(peer.index as usize)
        .filter(|slot| slot.generation == peer.generation)
}

/// What readers resolve handles through: a copy of every slot, plus each
/// slot's generation and endpoint rank in [`PeerEndpoint::cmp_selection`]
/// order (equal endpoints share a rank), so the tie-break compares two
/// integers.
#[derive(Default)]
struct Snapshot {
    entries: Vec<Slot>,
    keys: Vec<(NonZeroU32, u32)>,
}

impl Snapshot {
    fn of(entries: &[Slot]) -> Self {
        let order_of = |a: usize, b: usize| entries[a].endpoint.cmp_selection(&entries[b].endpoint);
        let mut order: Vec<usize> = (0..entries.len()).collect();
        order.sort_unstable_by(|&a, &b| order_of(a, b));
        let mut keys: Vec<_> = entries.iter().map(|slot| (slot.generation, 0)).collect();
        let mut rank = 0;
        for pair in order.windows(2) {
            if order_of(pair[0], pair[1]) != Ordering::Equal {
                rank += 1;
            }
            keys[pair[1]].1 = rank;
        }
        Self {
            entries: entries.to_vec(),
            keys,
        }
    }

    /// The handle's endpoint rank, `None` once its generation has moved on.
    fn rank(&self, peer: PeerId) -> Option<u32> {
        self.keys
            .get(peer.index as usize)
            .filter(|(generation, _)| *generation == peer.generation)
            .map(|&(_, rank)| rank)
    }
}

/// Writers serialize on `slots`; readers go through `published`, rebuilt
/// after every change, so the selection tie-break never waits on a lock.
struct Table {
    slots: Mutex<Slots>,
    published: ArcSwap<Snapshot>,
}

static TABLE: LazyLock<Table> = LazyLock::new(|| Table {
    slots: Mutex::default(),
    published: ArcSwap::from_pointee(Snapshot::default()),
});

thread_local! {
    /// This thread's handle on the published snapshot: one relaxed pointer
    /// check per read while the table is unchanged.
    static SNAPSHOT: RefCell<Cache<&'static ArcSwap<Snapshot>, Arc<Snapshot>>> =
        RefCell::new(Cache::new(&TABLE.published));
}

fn read<T>(f: impl FnOnce(&Snapshot) -> T) -> T {
    let mut f = Some(f);
    let cached = SNAPSHOT.try_with(|cache| {
        let mut cache = cache.try_borrow_mut().ok()?;
        f.take().map(|f| f(cache.load()))
    });
    match (cached, f) {
        (Ok(Some(out)), _) => out,
        // A read nested in another, or during thread teardown.
        (_, Some(f)) => f(&TABLE.published.load()),
        (_, None) => unreachable!("the cached read consumed the closure and returned"),
    }
}

fn lock() -> MutexGuard<'static, Slots> {
    TABLE.slots.lock().unwrap_or_else(PoisonError::into_inner)
}

fn write<T>(f: impl FnOnce(&mut Slots) -> T) -> T {
    let mut slots = lock();
    let out = f(&mut slots);
    // ponytail: copies and re-sorts every slot on each allocate, release or
    // rebind, so N neighbor changes cost O(N * slots log slots); neighbors
    // change rarely. Per-slot cells if bulk churn at large peer counts shows.
    TABLE
        .published
        .store(Arc::new(Snapshot::of(&slots.entries)));
    out
}

impl PeerId {
    /// The identity of locally originated and injected routes: the pinned
    /// identity of `0.0.0.0`.
    pub const LOCAL: Self = Self::from_ipv4(Ipv4Addr::UNSPECIFIED);

    /// A handle no neighbor holds and the table never issues: a command
    /// naming it finds no RIB state. For a neighbor that has no handle yet
    /// (a dynamic neighbor before its OPEN validates).
    pub const UNASSIGNED: Self = Self {
        index: u32::MAX,
        generation: RESERVED,
    };

    /// Allocate a handle for a new neighbor at `endpoint`. The peer manager
    /// calls this once per neighbor (for a dynamic neighbor, once its OPEN
    /// validates) and keeps the handle across reconfigures.
    #[must_use]
    pub fn allocate(endpoint: PeerEndpoint) -> Self {
        write(|slots| slots.allocate(endpoint, SlotState::Live))
    }

    /// Return a deleted neighbor's handle to the free list. Afterwards
    /// [`Self::is_live`] is false, so a late message carrying it is dropped;
    /// at the last generation the slot is retired instead. A no-op for a
    /// pinned, already released or stale handle; returns whether it acted.
    #[must_use = "a false return means the handle was not live"]
    pub fn release(self) -> bool {
        self.pinned_v4().is_none() && write(|slots| slots.release(self))
    }

    /// Move a live neighbor to a new endpoint (an interface-only neighbor
    /// that learned a new address). The RIB applies this in its message
    /// order; returns whether the handle was live.
    #[must_use = "a false return means the handle was not live"]
    pub fn rebind(self, endpoint: PeerEndpoint) -> bool {
        self.pinned_v4().is_none() && write(|slots| slots.rebind(self, endpoint))
    }

    /// The pinned identity of the unscoped address `addr`: the same handle
    /// for the same address for the life of the process, never released.
    /// For routes that come from no managed neighbor (MRT files, test and
    /// benchmark fixtures); a managed neighbor uses its allocated handle.
    #[must_use]
    pub fn from_addr(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => Self::from_ipv4(addr),
            IpAddr::V6(addr) => {
                let pinned = {
                    let slots = lock();
                    slots.pinned.get(&addr).map(|&index| Self {
                        index,
                        generation: slots.entries[index as usize].generation,
                    })
                };
                pinned.unwrap_or_else(|| write(|slots| slots.pin(addr)))
            }
        }
    }

    /// [`Self::from_addr`] for an IPv4 address, usable in a `const`.
    #[must_use]
    pub const fn from_ipv4(addr: Ipv4Addr) -> Self {
        Self {
            index: addr.to_bits(),
            generation: PINNED_V4,
        }
    }

    fn pinned_v4(self) -> Option<Ipv4Addr> {
        (self.generation == PINNED_V4).then(|| Ipv4Addr::from_bits(self.index))
    }

    /// Run `f` on the handle's endpoint, `None` once a released handle's
    /// slot has been reused.
    fn with_endpoint<T>(self, f: impl FnOnce(Option<&PeerEndpoint>) -> T) -> T {
        match self.pinned_v4() {
            Some(addr) => f(Some(&PeerEndpoint {
                addr: IpAddr::V4(addr),
                interface: None,
            })),
            None => read(|table| f(slot_of(&table.entries, self).map(|slot| &slot.endpoint))),
        }
    }

    /// Whether the handle still names a neighbor: allocated and not yet
    /// released, or pinned.
    #[must_use]
    pub fn is_live(self) -> bool {
        self.pinned_v4().is_some()
            || read(|table| {
                slot_of(&table.entries, self)
                    .is_some_and(|slot| matches!(slot.state, SlotState::Live | SlotState::Pinned))
            })
    }

    /// The neighbor's endpoint, or `None` once a released handle's slot has
    /// been reused.
    #[must_use]
    pub fn endpoint(self) -> Option<PeerEndpoint> {
        fn owned(endpoint: Option<&PeerEndpoint>) -> Option<PeerEndpoint> {
            endpoint.cloned()
        }
        self.with_endpoint(owned)
    }

    /// The neighbor's transport address; `::` once a released handle's slot
    /// has been reused.
    #[must_use]
    pub fn addr(self) -> IpAddr {
        self.with_endpoint(|endpoint| {
            endpoint.map_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED), |endpoint| endpoint.addr)
        })
    }

    /// The interface of a scoped neighbor; `None` for a numbered one.
    #[must_use]
    pub fn interface(self) -> Option<Arc<str>> {
        self.with_endpoint(|endpoint| endpoint.and_then(|endpoint| endpoint.interface.clone()))
    }

    /// The selection tie-break between two neighbors: their endpoints in
    /// [`PeerEndpoint::cmp_selection`] order, never the handles' order.
    /// Equal for the same handle. A handle whose slot was reused sorts
    /// after every resolvable one.
    #[inline]
    #[must_use]
    pub fn cmp_selection(self, other: Self) -> Ordering {
        // A pinned IPv4 index is the address bits, so it orders numerically.
        if self.generation == PINNED_V4 && other.generation == PINNED_V4 {
            return self.index.cmp(&other.index);
        }
        self.cmp_resolved(other)
    }

    /// The table half of [`Self::cmp_selection`], kept out of line so the
    /// comparators that inline it stay small; both endpoints come from one
    /// published snapshot.
    #[inline(never)]
    fn cmp_resolved(self, other: Self) -> Ordering {
        fn resolved<T>(a: Option<T>, b: Option<T>, cmp: impl FnOnce(T, T) -> Ordering) -> Ordering {
            match (a, b) {
                (Some(a), Some(b)) => cmp(a, b),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            }
        }
        if self == other {
            return Ordering::Equal;
        }
        if self.generation != PINNED_V4 && other.generation != PINNED_V4 {
            return read(|table| resolved(table.rank(self), table.rank(other), |a, b| a.cmp(&b)));
        }
        // A pinned IPv4 identity against a table handle (MRT and fixtures).
        let pinned = |peer: Self| {
            peer.pinned_v4().map(|addr| PeerEndpoint {
                addr: IpAddr::V4(addr),
                interface: None,
            })
        };
        let (pinned_a, pinned_b) = (pinned(self), pinned(other));
        read(|table| {
            let a = pinned_a
                .as_ref()
                .or_else(|| slot_of(&table.entries, self).map(|s| &s.endpoint));
            let b = pinned_b
                .as_ref()
                .or_else(|| slot_of(&table.entries, other).map(|s| &s.endpoint));
            resolved(a, b, PeerEndpoint::cmp_selection)
        })
    }

    /// The handle's bits, for process-local opaque tokens such as page
    /// cursors; [`Self::from_raw`] reverses it.
    #[must_use]
    pub fn to_raw(self) -> u64 {
        u64::from(self.generation.get()) << 32 | u64::from(self.index)
    }

    /// The handle [`Self::to_raw`] produced, or `None` for bits no handle
    /// has. It may name a released or unknown slot, which names no state.
    #[must_use]
    pub fn from_raw(raw: u64) -> Option<Self> {
        Some(Self {
            index: u32::try_from(raw & u64::from(u32::MAX)).ok()?,
            generation: NonZeroU32::new(u32::try_from(raw >> 32).ok()?)?,
        })
    }

    #[cfg(test)]
    fn force_generation(self, generation: NonZeroU32) -> Self {
        write(|slots| {
            slots.entries[self.index as usize].generation = generation;
        });
        Self {
            index: self.index,
            generation,
        }
    }
}

impl Hash for PeerId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.to_raw());
    }
}

/// Formats as the neighbor's address, so logs, metric labels and operator
/// text read as they did when the RIB keyed peers by address. A handle whose
/// slot was reused formats as `peer#<index>.<generation>`.
impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.with_endpoint(|endpoint| endpoint.map(|endpoint| endpoint.addr)) {
            Some(addr) => fmt::Display::fmt(&addr, f),
            None => write!(f, "peer#{}.{}", self.index, self.generation),
        }
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.pinned_v4().is_some() {
            write!(f, "PeerId({self})")
        } else {
            write!(f, "PeerId({}.{} {self})", self.index, self.generation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(addr: &str, interface: Option<&str>) -> PeerEndpoint {
        PeerEndpoint::new(addr.parse().unwrap(), interface)
    }

    #[test]
    fn handle_is_eight_bytes_and_option_is_free() {
        assert_eq!(size_of::<PeerId>(), 8);
        assert_eq!(size_of::<Option<PeerId>>(), 8);
    }

    /// Acceptance: a slot at its last generation is retired, not reused,
    /// so its generation never wraps back to a handle already issued.
    #[test]
    fn a_slot_at_the_last_generation_is_retired() {
        let mut slots = Slots::default();
        let first = slots.allocate(endpoint("192.0.2.1", None), SlotState::Live);
        slots.entries[first.index as usize].generation = LAST_GENERATION;
        let last = PeerId {
            index: first.index,
            generation: LAST_GENERATION,
        };
        assert!(slots.release(last));
        assert_eq!(slots.entries[last.index as usize].state, SlotState::Retired);
        assert!(
            slots.free.is_empty(),
            "a retired slot never enters the free list"
        );
        let next = slots.allocate(endpoint("192.0.2.2", None), SlotState::Live);
        assert_ne!(next.index, last.index);
        assert_eq!(next.generation, NonZeroU32::MIN);
        // The retired handle still resolves its last endpoint for history.
        assert_eq!(
            slots.slot(last).map(|slot| slot.endpoint.addr),
            Some("192.0.2.1".parse().unwrap())
        );
    }

    /// The same, through the process-wide table the daemon uses.
    #[test]
    fn a_global_slot_at_the_last_generation_is_retired() {
        let peer = PeerId::allocate(endpoint("198.51.100.250", None));
        let last = peer.force_generation(LAST_GENERATION);
        assert!(last.is_live());
        assert!(last.release());
        assert!(!last.is_live());
        assert!(!last.release(), "release is idempotent");
        assert!(!lock().free.contains(&last.index));
        assert_eq!(last.addr(), "198.51.100.250".parse::<IpAddr>().unwrap());
    }

    /// Released slots stay out of reuse until the quarantine is full, then
    /// are reused oldest first. Red proof: ignoring the quarantine reuses `b`'s
    /// slot for the first allocation after it is released.
    #[test]
    fn released_slots_are_reused_oldest_first_with_a_new_generation() {
        let mut slots = Slots::default();
        let a = slots.allocate(endpoint("192.0.2.1", None), SlotState::Live);
        let b = slots.allocate(endpoint("192.0.2.2", None), SlotState::Live);
        assert!(slots.release(b));
        assert!(slots.release(a));
        // Released handles keep resolving while the quarantine fills.
        for _ in 0..REUSE_QUARANTINE - 1 {
            let other = slots.allocate(endpoint("198.18.0.1", None), SlotState::Live);
            assert_ne!(other.index, b.index);
            assert_ne!(other.index, a.index);
            assert!(slots.release(other));
        }
        assert_eq!(slots.slot(b).unwrap().endpoint, endpoint("192.0.2.2", None));
        assert!(slots.slot(a).is_some());
        let c = slots.allocate(endpoint("192.0.2.3", None), SlotState::Live);
        assert_eq!(
            c.index, b.index,
            "FIFO: the first slot released is reused first"
        );
        assert_ne!(c, b);
        assert_eq!(c.generation.get(), b.generation.get() + 1);
        assert!(
            slots.slot(b).is_none(),
            "the stale handle no longer resolves"
        );
        assert!(
            !slots.release(b),
            "a stale handle cannot release the new owner"
        );
        assert!(!slots.rebind(b, endpoint("192.0.2.9", None)));
        assert_eq!(slots.slot(c).unwrap().endpoint, endpoint("192.0.2.3", None));
    }

    #[test]
    fn delete_and_re_add_issues_a_new_handle() {
        let at = endpoint("fe80::1", Some("eth0"));
        let first = PeerId::allocate(at.clone());
        assert!(first.release());
        let second = PeerId::allocate(at);
        assert_ne!(first, second);
        assert!(!first.is_live());
        assert!(second.is_live());
    }

    #[test]
    fn pinned_handles_are_stable_and_never_released() {
        for addr in ["203.0.113.77", "2001:db8::77"] {
            let addr: IpAddr = addr.parse().unwrap();
            let peer = PeerId::from_addr(addr);
            assert_eq!(PeerId::from_addr(addr), peer);
            assert!(!peer.release());
            assert!(!peer.rebind(endpoint("192.0.2.1", None)));
            assert!(peer.is_live());
            assert_eq!(peer.addr(), addr);
            assert_eq!(peer.to_string(), addr.to_string());
            assert_ne!(peer, PeerId::allocate(PeerEndpoint::new(addr, None)));
        }
        assert_eq!(
            PeerId::from_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            PeerId::LOCAL
        );
        assert_eq!(PeerId::LOCAL.addr(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert!(!PeerId::UNASSIGNED.is_live());
        assert!(PeerId::UNASSIGNED.endpoint().is_none());
    }

    #[test]
    fn rebind_moves_a_live_handle_only() {
        let peer = PeerId::allocate(endpoint("fe80::1", Some("swp1")));
        assert!(peer.rebind(endpoint("fe80::2", Some("swp1"))));
        assert_eq!(peer.addr(), "fe80::2".parse::<IpAddr>().unwrap());
        assert_eq!(peer.interface().as_deref(), Some("swp1"));
        assert!(peer.release());
        assert!(!peer.rebind(endpoint("fe80::3", Some("swp1"))));
    }

    /// The tie-break orders by address, then interface name bytewise, and
    /// never by handle: allocation order does not move the winner.
    #[test]
    fn selection_order_is_endpoint_order_not_handle_order() {
        for names in [["eth1", "eth0"], ["eth0", "eth1"]] {
            let first = PeerId::allocate(endpoint("fe80::1", Some(names[0])));
            let second = PeerId::allocate(endpoint("fe80::1", Some(names[1])));
            let (eth0, eth1) = if names[0] == "eth0" {
                (first, second)
            } else {
                (second, first)
            };
            assert_eq!(eth0.cmp_selection(eth1), Ordering::Less);
            assert_eq!(eth1.cmp_selection(eth0), Ordering::Greater);
            assert_eq!(eth0.cmp_selection(eth0), Ordering::Equal);
            assert!(first.release());
            assert!(second.release());
        }
        let low = PeerId::allocate(endpoint("10.0.0.9", None));
        let high = PeerId::allocate(endpoint("10.0.0.10", None));
        assert_eq!(
            low.cmp_selection(high),
            Ordering::Less,
            "numeric, not textual"
        );
        let v6 = PeerId::allocate(endpoint("::1", None));
        assert_eq!(high.cmp_selection(v6), Ordering::Less, "IPv4 before IPv6");
        let pinned = PeerId::from_addr("10.0.0.10".parse().unwrap());
        assert_eq!(low.cmp_selection(pinned), Ordering::Less);
        assert_eq!(pinned.cmp_selection(v6), Ordering::Less);
        // Bytewise, so uppercase sorts before lowercase and no locale applies.
        assert_eq!(
            endpoint("fe80::1", Some("Eth9")).cmp_selection(&endpoint("fe80::1", Some("eth0"))),
            Ordering::Less
        );
        assert_eq!(
            endpoint("fe80::1", None).cmp_selection(&endpoint("fe80::1", Some("eth0"))),
            Ordering::Less
        );
        for peer in [low, high, v6] {
            assert!(peer.release());
        }
    }

    /// Selection reads the published snapshot: equal endpoints tie, a rebind
    /// moves the handle's place, and a handle whose generation is not the
    /// slot's sorts after every resolvable one instead of taking the
    /// owner's place.
    #[test]
    fn selection_follows_the_published_snapshot() {
        let a = PeerId::allocate(endpoint("fe80::5", Some("swp1")));
        let twin = PeerId::allocate(endpoint("fe80::5", Some("swp1")));
        let b = PeerId::allocate(endpoint("fe80::3", Some("swp1")));
        assert_eq!(a.cmp_selection(twin), Ordering::Equal);
        assert_eq!(a.cmp_selection(b), Ordering::Greater);
        assert!(a.rebind(endpoint("fe80::1", Some("swp1"))));
        assert_eq!(a.cmp_selection(b), Ordering::Less);
        assert_eq!(a.cmp_selection(twin), Ordering::Less);
        let stale = PeerId {
            index: b.index,
            generation: b.generation.checked_add(1).unwrap(),
        };
        assert_eq!(stale.cmp_selection(b), Ordering::Greater);
        assert_eq!(b.cmp_selection(stale), Ordering::Less);
        // A read nested in another still sees the table.
        assert_eq!(read(|_| b.addr()), "fe80::3".parse::<IpAddr>().unwrap());
        for peer in [a, twin, b] {
            assert!(peer.release());
        }
    }

    #[test]
    fn raw_bits_round_trip() {
        for peer in [
            PeerId::LOCAL,
            PeerId::UNASSIGNED,
            PeerId::from_addr("2001:db8::200".parse().unwrap()),
            PeerId::allocate(endpoint("192.0.2.201", None)),
        ] {
            assert_eq!(PeerId::from_raw(peer.to_raw()), Some(peer));
        }
        assert_eq!(PeerId::from_raw(7), None, "generation zero is no handle");
    }

    #[test]
    fn formats_as_the_address() {
        let peer = PeerId::allocate(endpoint("fe80::1", Some("eth0")));
        assert_eq!(peer.to_string(), "fe80::1");
        assert!(format!("{peer:?}").ends_with(" fe80::1)"));
        assert_eq!(
            peer.endpoint()
                .map(|endpoint| endpoint.to_string())
                .as_deref(),
            Some("fe80::1%eth0")
        );
        assert!(peer.release());
        assert_eq!(
            format!("{:?}", PeerId::from_ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            "PeerId(192.0.2.1)"
        );
    }
}
