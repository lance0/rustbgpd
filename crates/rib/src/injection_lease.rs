//! Owner-scoped leases on controller-injected routes (ADR-0141).
//!
//! One daemon-wide [`InjectionLeases`](crate::injection_lease::InjectionLeases)
//! table is shared by every `InjectionService` instance, the RIB manager and
//! the expiry task. It holds only bounded owner-level state: each owner's
//! lease and the pending-expiry queue, at most
//! [`MAX_LIVE_OWNERS`](crate::injection_lease::MAX_LIVE_OWNERS) live
//! entries. Which local keys an owner holds is indexed in the RIB actor, so
//! sweeping a large owner's routes never holds this lock. Renewal and lease
//! listing touch only this table, never the RIB actor, so a backlogged RIB
//! cannot delay a renewal into an expiry. Every operation samples the clock
//! after taking the lock, so a renewal that waited for the lock past the
//! deadline is judged at the time it is applied, and none holds the lock
//! across an `.await`.
//!
//! Guarded `FlowSpec` owners (ADR-0144) also hold mutation windows here, at
//! most [`MAX_LIVE_WINDOWS`](crate::injection_lease::MAX_LIVE_WINDOWS) live.
//! A guarded add or renewal checks its window, and caps the deadline at the
//! window's expiry, under the same lock and clock read as the admission.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rustbgpd_wire::Prefix;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time::Instant;

use crate::route::FlowSpecKey;
use crate::update::RibUpdate;

/// Shortest accepted lease.
pub const MIN_LEASE_SECONDS: u32 = 5;
/// Longest accepted lease.
pub const MAX_LEASE_SECONDS: u32 = 3600;
/// Most owners with a live lease at once.
pub const MAX_LIVE_OWNERS: usize = 64;

/// Most keys, unicast and `FlowSpec` together, one owner may hold. With
/// [`MAX_LIVE_OWNERS`] this bounds one expiry batch near a full-table
/// peer-down (64 x 16,384 = 1,048,576 withdrawals).
pub const MAX_KEYS_PER_OWNER: usize = 16_384;
/// Longest accepted owner name, in bytes.
pub const MAX_OWNER_LEN: usize = 64;

/// Longest mutation window, in seconds (ADR-0144 §2).
pub const MAX_WINDOW_SECONDS: u32 = 120;
/// Most live mutation windows one guarded owner may hold.
pub const MAX_LIVE_WINDOWS_PER_OWNER: usize = 64;
/// Most live mutation windows in the table, so window state stays bounded
/// however many owner names are used.
pub const MAX_LIVE_WINDOWS: usize = MAX_LIVE_OWNERS * MAX_LIVE_WINDOWS_PER_OWNER;

/// Prefix of a guarded owner's stored name (ADR-0144 §4). `:` is outside the
/// owner alphabet [`validate_owner`] accepts, so no legacy add, renewal or
/// owner-scoped delete can name a guarded owner.
pub const GUARDED_OWNER_PREFIX: &str = "guarded:";

/// The name under which guarded owner `owner` is stored, tagged and labelled.
#[must_use]
pub fn guarded_owner(owner: &str) -> String {
    format!("{GUARDED_OWNER_PREFIX}{owner}")
}

/// A server-issued mutation window (ADR-0144 §2). It must match both fields;
/// a window from a previous process never matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MutationWindowId {
    /// The issuing process's incarnation.
    pub incarnation: u64,
    /// Daemon-wide window counter, only increasing.
    pub sequence: u64,
}

/// What fences a guarded `FlowSpec` add: the window it must commit within and
/// its client-chosen admission revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardedFence {
    /// Window checked, and capping the lease deadline, at commit.
    pub window: MutationWindowId,
    /// Admission revision stored with the key's tag.
    pub revision: NonZeroU64,
}

/// One owner's lease generation. A renewal must match both fields; the
/// incarnation is drawn once per process, so a generation from a previous
/// process never matches one started after a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeaseGeneration {
    /// Random per-process value.
    pub incarnation: u64,
    /// Daemon-wide, only increasing.
    pub sequence: u64,
}

/// A locally injected entry's identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InjectedKey {
    /// Unicast `(prefix, path_id)`.
    Unicast(Prefix, u32),
    /// `FlowSpec` `(afi, rule)`.
    FlowSpec(FlowSpecKey),
}

/// Position of an injected key in the fixed order of per-owner key listings:
/// unicast by `(prefix, path_id)`, then `FlowSpec` by AFI and the rule's
/// encoded NLRI. A listing resumes strictly after a cursor, so a page
/// boundary survives keys added or removed elsewhere in the order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InjectedKeyCursor {
    /// Unicast `(prefix, path_id)`.
    Unicast(Prefix, u32),
    /// `FlowSpec` AFI code and encoded rule (with its length prefix).
    FlowSpec(u16, Vec<u8>),
}

impl InjectedKeyCursor {
    /// The cursor of `key`.
    #[must_use]
    pub fn of(key: &InjectedKey) -> Self {
        match key {
            InjectedKey::Unicast(prefix, path_id) => Self::Unicast(*prefix, *path_id),
            InjectedKey::FlowSpec(key) => {
                let mut nlri = Vec::new();
                // Injected rules passed the same length check at the API, so
                // encoding cannot fail here.
                let encoded = rustbgpd_wire::flowspec::try_encode_flowspec_nlri(
                    std::slice::from_ref(&key.rule),
                    &mut nlri,
                    key.afi,
                );
                debug_assert!(encoded.is_ok(), "an injected rule encodes");
                Self::FlowSpec(key.afi as u16, nlri)
            }
        }
    }
}

/// One key an owner holds, as `ListLeasedKeys` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeasedKeyRow {
    /// The key.
    pub key: InjectedKey,
    /// Its position in the listing order.
    pub cursor: InjectedKeyCursor,
    /// Generation the key is tagged with.
    pub generation: LeaseGeneration,
    /// Admission revision of a guarded key; `None` for a legacy one.
    pub revision: Option<NonZeroU64>,
    /// Time to that generation's deadline; zero once it expired.
    pub remaining: Duration,
}

/// One page of an owner's keys in [`InjectedKeyCursor`] order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeasedKeysPage {
    /// Rows for this page.
    pub rows: Vec<LeasedKeyRow>,
    /// Whether keys remain after the last row.
    pub more: bool,
    /// This process's lease-table incarnation, which the walk is bound to.
    pub incarnation: u64,
    /// The owner's live generation the walk is bound to; `None` when the
    /// owner has no live lease.
    pub generation: Option<LeaseGeneration>,
    /// With no live generation, the next generation sequence when the walk
    /// began; a generation started since, live or expired, aborts the walk.
    pub watermark: u64,
}

/// Where a later page of a per-owner key walk resumes, and the state the
/// walk's first page saw. A page whose daemon incarnation or owner
/// generation no longer matches is refused, so a walk never continues into
/// a different process or a different generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeasedKeysResume {
    /// Lease-table incarnation of the first page.
    pub incarnation: u64,
    /// The owner's live generation at the first page.
    pub generation: Option<LeaseGeneration>,
    /// The page's watermark, compared only when `generation` is `None`.
    pub watermark: u64,
    /// Resume strictly after this key.
    pub after: InjectedKeyCursor,
}

/// A generation that left the table, with the deadline it had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredLease {
    /// Owner whose lease expired.
    pub owner: Arc<str>,
    /// The expired generation.
    pub generation: LeaseGeneration,
    /// Its deadline, so the RIB reports the deadline-to-apply lag of this
    /// generation, not of one started after it.
    pub deadline: Instant,
}

/// One row of [`InjectionLeases::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRow {
    /// Lease owner.
    pub owner: Arc<str>,
    /// Current generation.
    pub generation: LeaseGeneration,
    /// The `lease_seconds` that last set the deadline.
    pub lease_seconds: u32,
    /// Time to the deadline; 0 once it has passed.
    pub remaining: Duration,
}

/// The owner and generation a local key is tagged with, captured in the RIB
/// turn that reads or changes the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionTag {
    /// Lease owner.
    pub owner: Arc<str>,
    /// Generation the key is tagged with.
    pub generation: LeaseGeneration,
    /// Admission revision of a guarded add (ADR-0144 §3); `None` for a
    /// legacy leased add.
    pub revision: Option<NonZeroU64>,
}

/// A lease table admission (ADR-0141 §4, ADR-0144 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Admission {
    /// The owner and generation joined or started.
    pub(crate) tag: InjectionTag,
    /// Live owners, read under the admission's lock, so the caller need not
    /// take it again before the RIB insert.
    pub(crate) live_owners: usize,
    /// Whether the admission started a new generation. The caller logs it
    /// with [`log_generation_started`] after the commit, so a slow log write
    /// never sits between the window check and the RIB insert.
    pub(crate) started: bool,
}

/// Log that `tag`'s generation started under a lease of `lease_seconds`.
pub(crate) fn log_generation_started(tag: &InjectionTag, lease_seconds: u32) {
    tracing::info!(
        owner = &*tag.owner,
        incarnation = tag.generation.incarnation,
        sequence = tag.generation.sequence,
        lease_seconds,
        "injection lease generation started"
    );
}

/// Why a lease table admission was refused. The table, the RIB and the wire
/// are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseRejection {
    /// A new owner would exceed [`MAX_LIVE_OWNERS`].
    OwnerCap,
    /// A new window would exceed [`MAX_LIVE_WINDOWS_PER_OWNER`] or
    /// [`MAX_LIVE_WINDOWS`].
    WindowCap,
    /// A guarded add's window is unknown, expired, another owner's or another
    /// process's.
    WindowNotLive,
}

/// Which ADR-0141 ownership or generation check refused a command. The API
/// reports it as the `google.rpc.ErrorInfo` reason of the
/// `FAILED_PRECONDITION`, so controllers can tell the cases apart without
/// reading the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseConflict {
    /// The key is held by a different owner.
    OwnerMismatch,
    /// The key is held by no owner: a leased add or an owner-scoped delete
    /// must not take it over.
    KeyUnowned,
    /// The renewed generation is unknown, superseded or expired.
    GenerationNotLive,
    /// A replay-complete signal named another daemon incarnation than this
    /// process's: the controller replayed into a previous process.
    IncarnationMismatch,
    /// A guarded add or renewal named a mutation window that is unknown,
    /// expired, another owner's or another process's (ADR-0144 §2).
    WindowNotLive,
    /// A guarded add or delete named another admission revision than the
    /// key's, or a guarded add repeated the key's revision with a different
    /// payload (ADR-0144 §3).
    RevisionMismatch,
}

impl LeaseConflict {
    /// The stable `ErrorInfo.reason` for this conflict.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::OwnerMismatch => "OWNER_MISMATCH",
            Self::KeyUnowned => "KEY_UNOWNED",
            Self::GenerationNotLive => "GENERATION_NOT_LIVE",
            Self::IncarnationMismatch => "INCARNATION_MISMATCH",
            Self::WindowNotLive => "WINDOW_NOT_LIVE",
            Self::RevisionMismatch => "REVISION_MISMATCH",
        }
    }
}

/// Validate a lease request's owner and duration. The message names the
/// field for an `INVALID_ARGUMENT` reply.
///
/// # Errors
///
/// Returns a description of the first invalid field.
pub fn validate_lease(owner: &str, lease_seconds: u32) -> Result<(), String> {
    validate_owner(owner)?;
    if !(MIN_LEASE_SECONDS..=MAX_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(format!(
            "lease_seconds must be {MIN_LEASE_SECONDS}..={MAX_LEASE_SECONDS}; got {lease_seconds}"
        ));
    }
    Ok(())
}

/// Validate a mutation window request's owner and lifetime.
///
/// # Errors
///
/// Returns a description of the first invalid field.
pub fn validate_window(owner: &str, window_seconds: u32) -> Result<(), String> {
    validate_owner(owner)?;
    if !(1..=MAX_WINDOW_SECONDS).contains(&window_seconds) {
        return Err(format!(
            "window_seconds must be 1..={MAX_WINDOW_SECONDS}; got {window_seconds}"
        ));
    }
    Ok(())
}

/// Validate an owner name: 1-64 bytes of `[A-Za-z0-9._-]`.
///
/// # Errors
///
/// Returns a description of the problem.
pub fn validate_owner(owner: &str) -> Result<(), String> {
    if owner.is_empty() || owner.len() > MAX_OWNER_LEN {
        return Err(format!(
            "owner must be 1..={MAX_OWNER_LEN} bytes; got {}",
            owner.len()
        ));
    }
    if !owner
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("owner may contain only A-Z, a-z, 0-9, '.', '_' and '-'".to_string());
    }
    Ok(())
}

#[derive(Debug)]
struct LiveLease {
    generation: LeaseGeneration,
    deadline: Instant,
    lease_seconds: u32,
}

#[derive(Debug)]
struct Window {
    owner: Arc<str>,
    expiry: Instant,
}

#[derive(Debug, Default)]
struct State {
    next_sequence: u64,
    next_window: u64,
    /// Issued mutation windows by sequence. Expired entries stay until the
    /// next successful issue prunes them, so a refusal moves nothing.
    windows: HashMap<u64, Window>,
    /// Current lease per owner. A lease is live iff `now < deadline`; an
    /// entry past its deadline stays here until the tick, or a successful
    /// leased add for the same owner, moves it to `pending`.
    owners: HashMap<Arc<str>, LiveLease>,
    pending: Vec<ExpiredLease>,
}

impl State {
    fn reap(&mut self, owner: &str) {
        if let Some((owner, lease)) = self.owners.remove_entry(owner) {
            self.pending.push(ExpiredLease {
                owner,
                generation: lease.generation,
                deadline: lease.deadline,
            });
        }
    }

    fn live_count(&self, now: Instant) -> usize {
        self.owners
            .values()
            .filter(|lease| now < lease.deadline)
            .count()
    }

    /// The expiry of `window` if it is live now and issued to `owner`.
    fn window_expiry(
        &self,
        incarnation: u64,
        owner: &str,
        window: MutationWindowId,
        now: Instant,
    ) -> Option<Instant> {
        if window.incarnation != incarnation {
            return None;
        }
        self.windows
            .get(&window.sequence)
            .filter(|entry| &*entry.owner == owner && now < entry.expiry)
            .map(|entry| entry.expiry)
    }
}

/// Why [`InjectionLeases::run_expiry`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum ExpiryExit {
    /// The cancel signal fired or its sender was dropped.
    Cancelled,
    /// The RIB's receiver is gone, so an expiry batch could not be sent.
    /// The RIB task's own result explains the failure.
    RibChannelClosed,
}

/// The daemon-wide lease table (ADR-0141 §4).
#[derive(Debug)]
pub struct InjectionLeases {
    incarnation: u64,
    state: Mutex<State>,
    changed: Notify,
    /// Expiry-loop passes, so a test can prove an idle table never wakes.
    #[cfg(test)]
    expiry_passes: std::sync::atomic::AtomicUsize,
}

impl Default for InjectionLeases {
    fn default() -> Self {
        Self::new()
    }
}

impl InjectionLeases {
    /// A table with a fresh random incarnation.
    #[must_use]
    pub fn new() -> Self {
        // std's randomly keyed hasher: OS-seeded keys, distinct per instance,
        // no clock involved and no new dependency. Never zero, which
        // `CheckLivenessResponse` reserves for a server without the field.
        let incarnation = RandomState::new().build_hasher().finish().max(1);
        Self {
            incarnation,
            state: Mutex::new(State {
                next_sequence: 1,
                next_window: 1,
                ..State::default()
            }),
            changed: Notify::new(),
            #[cfg(test)]
            expiry_passes: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// This process's incarnation.
    #[must_use]
    pub fn incarnation(&self) -> u64 {
        self.incarnation
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic under this lock leaves no partial invariant worth refusing
        // service over; keep expiring.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Join `owner`'s live lease, extending it to
    /// `max(deadline, now + lease_seconds)`, or start a new generation. Runs
    /// in the RIB turn that commits the leased add, after the RIB has checked
    /// the key's ownership.
    ///
    /// # Errors
    ///
    /// [`LeaseRejection::OwnerCap`] when a new owner would exceed
    /// [`MAX_LIVE_OWNERS`] live leases; nothing changes.
    pub fn admit(&self, owner: &str, lease_seconds: u32) -> Result<InjectionTag, LeaseRejection> {
        let admission = self.admit_at(owner, lease_seconds, None, Instant::now)?;
        if admission.started {
            log_generation_started(&admission.tag, lease_seconds);
        }
        Ok(admission.tag)
    }

    /// [`admit`](Self::admit), and with `window` a guarded admission
    /// (ADR-0144 §2): `owner` is the stored guarded name, the window must be
    /// live and issued to it at this instant, and the deadline becomes
    /// `max(current, min(now + lease_seconds, window expiry))`: never
    /// shortened, and never extended past the window. Logs nothing: the
    /// caller logs a started generation after its commit.
    ///
    /// # Errors
    ///
    /// [`LeaseRejection::WindowNotLive`] or [`LeaseRejection::OwnerCap`];
    /// nothing changes.
    pub(crate) fn admit_with(
        &self,
        owner: &str,
        lease_seconds: u32,
        window: Option<MutationWindowId>,
    ) -> Result<Admission, LeaseRejection> {
        self.admit_at(owner, lease_seconds, window, Instant::now)
    }

    fn admit_at(
        &self,
        owner: &str,
        lease_seconds: u32,
        window: Option<MutationWindowId>,
        clock: impl FnOnce() -> Instant,
    ) -> Result<Admission, LeaseRejection> {
        let mut state = self.lock();
        let now = clock();
        let cap = match window {
            Some(window) => Some(
                state
                    .window_expiry(self.incarnation, owner, window, now)
                    .ok_or(LeaseRejection::WindowNotLive)?,
            ),
            None => None,
        };
        let capped = |deadline: Instant| cap.map_or(deadline, |expiry| deadline.min(expiry));
        let lease_for = Duration::from_secs(u64::from(lease_seconds));
        if let Some((name, lease)) = state.owners.get_key_value(owner)
            && now < lease.deadline
        {
            let tag = InjectionTag {
                owner: Arc::clone(name),
                generation: lease.generation,
                revision: None,
            };
            let lease = state.owners.get_mut(owner).expect("present above");
            // An add never shortens the shared deadline, so a delayed add
            // with an older window cannot expire live sibling keys early.
            let extended = capped(now + lease_for);
            if extended > lease.deadline {
                lease.deadline = extended;
                lease.lease_seconds = lease_seconds;
            }
            let live_owners = state.live_count(now);
            drop(state);
            self.changed.notify_one();
            return Ok(Admission {
                tag,
                live_owners,
                started: false,
            });
        }
        // Capacity counts live leases by deadline: unreaped expired records
        // do not hold a slot, and a rejection moves nothing.
        if state.live_count(now) >= MAX_LIVE_OWNERS {
            return Err(LeaseRejection::OwnerCap);
        }
        state.reap(owner);
        let generation = LeaseGeneration {
            incarnation: self.incarnation,
            sequence: state.next_sequence,
        };
        state.next_sequence += 1;
        let name: Arc<str> = Arc::from(owner);
        state.owners.insert(
            Arc::clone(&name),
            LiveLease {
                generation,
                deadline: capped(now + lease_for),
                lease_seconds,
            },
        );
        let live_owners = state.live_count(now);
        drop(state);
        self.changed.notify_one();
        Ok(Admission {
            tag: InjectionTag {
                owner: name,
                generation,
                revision: None,
            },
            live_owners,
            started: true,
        })
    }

    /// Renew `owner`'s lease if `generation` is live, setting the deadline to
    /// exactly `now + lease_seconds` (which may shorten it). Returns `None`,
    /// changing nothing, for an unknown owner, a superseded generation or an
    /// expired lease, reaped or not. A renewal at exactly the deadline loses;
    /// `now` is read after the lock is taken.
    #[must_use]
    pub fn renew(
        &self,
        owner: &str,
        generation: LeaseGeneration,
        lease_seconds: u32,
    ) -> Option<Duration> {
        self.renew_at(owner, generation, lease_seconds, None, Instant::now)
            .ok()
    }

    /// Renew guarded owner `owner`'s lease within `window` (ADR-0144 §2):
    /// as [`renew`](Self::renew), but the window must be live and issued to
    /// `owner` at this instant, and the deadline becomes
    /// `min(now + lease_seconds, window expiry)`. Returns the time to the new
    /// deadline.
    ///
    /// # Errors
    ///
    /// [`LeaseConflict::WindowNotLive`] or
    /// [`LeaseConflict::GenerationNotLive`]; nothing changes.
    pub fn renew_guarded(
        &self,
        owner: &str,
        generation: LeaseGeneration,
        lease_seconds: u32,
        window: MutationWindowId,
    ) -> Result<Duration, LeaseConflict> {
        self.renew_at(
            &guarded_owner(owner),
            generation,
            lease_seconds,
            Some(window),
            Instant::now,
        )
    }

    fn renew_at(
        &self,
        owner: &str,
        generation: LeaseGeneration,
        lease_seconds: u32,
        window: Option<MutationWindowId>,
        clock: impl FnOnce() -> Instant,
    ) -> Result<Duration, LeaseConflict> {
        let mut state = self.lock();
        let now = clock();
        let cap = match window {
            Some(window) => Some(
                state
                    .window_expiry(self.incarnation, owner, window, now)
                    .ok_or(LeaseConflict::WindowNotLive)?,
            ),
            None => None,
        };
        let lease = state
            .owners
            .get_mut(owner)
            .filter(|lease| lease.generation == generation && now < lease.deadline)
            .ok_or(LeaseConflict::GenerationNotLive)?;
        let extended = now + Duration::from_secs(u64::from(lease_seconds));
        let deadline = cap.map_or(extended, |expiry| extended.min(expiry));
        lease.deadline = deadline;
        lease.lease_seconds = lease_seconds;
        drop(state);
        self.changed.notify_one();
        Ok(deadline.saturating_duration_since(now))
    }

    /// Issue a mutation window to guarded owner `owner` (ADR-0144 §2),
    /// living `window_seconds`, at most [`MAX_WINDOW_SECONDS`]. Returns the
    /// window and its lifetime.
    ///
    /// # Errors
    ///
    /// [`LeaseRejection::WindowCap`] when `owner` already holds
    /// [`MAX_LIVE_WINDOWS_PER_OWNER`] live windows or the table holds
    /// [`MAX_LIVE_WINDOWS`]; nothing changes.
    pub fn issue_window(
        &self,
        owner: &str,
        window_seconds: u32,
    ) -> Result<(MutationWindowId, Duration), LeaseRejection> {
        self.issue_window_at(owner, window_seconds, Instant::now)
    }

    fn issue_window_at(
        &self,
        owner: &str,
        window_seconds: u32,
        clock: impl FnOnce() -> Instant,
    ) -> Result<(MutationWindowId, Duration), LeaseRejection> {
        let owner: Arc<str> = Arc::from(guarded_owner(owner));
        let mut state = self.lock();
        let now = clock();
        let (total, held) = state
            .windows
            .values()
            .filter(|window| now < window.expiry)
            .fold((0, 0), |(total, held), window| {
                (total + 1, held + usize::from(window.owner == owner))
            });
        if total >= MAX_LIVE_WINDOWS || held >= MAX_LIVE_WINDOWS_PER_OWNER {
            return Err(LeaseRejection::WindowCap);
        }
        state.windows.retain(|_, window| now < window.expiry);
        let lifetime = Duration::from_secs(u64::from(window_seconds.min(MAX_WINDOW_SECONDS)));
        let sequence = state.next_window;
        state.next_window += 1;
        state.windows.insert(
            sequence,
            Window {
                owner,
                expiry: now + lifetime,
            },
        );
        Ok((
            MutationWindowId {
                incarnation: self.incarnation,
                sequence,
            },
            lifetime,
        ))
    }

    /// Time left on `tag`'s generation; zero once it has expired or been
    /// superseded, while its withdrawal is pending.
    #[must_use]
    pub fn remaining(&self, tag: &InjectionTag) -> Duration {
        let state = self.lock();
        let now = Instant::now();
        state
            .owners
            .get(&tag.owner)
            .filter(|lease| lease.generation == tag.generation)
            .map_or(Duration::ZERO, |lease| {
                lease.deadline.saturating_duration_since(now)
            })
    }

    /// `owner`'s generation if its lease is live now, and the sequence the
    /// next generation of any owner will take. The second value moves when
    /// any generation starts, even one that expires again unobserved, so a
    /// walk that saw no live lease can still tell that one came and went.
    #[must_use]
    pub fn live_generation(&self, owner: &str) -> (Option<LeaseGeneration>, u64) {
        let state = self.lock();
        let now = Instant::now();
        let live = state
            .owners
            .get(owner)
            .filter(|lease| now < lease.deadline)
            .map(|lease| lease.generation);
        (live, state.next_sequence)
    }

    /// Current leases, optionally for one owner, sorted by owner.
    #[must_use]
    pub fn list(&self, owner: Option<&str>) -> Vec<LeaseRow> {
        let state = self.lock();
        let now = Instant::now();
        let mut rows: Vec<LeaseRow> = state
            .owners
            .iter()
            .filter(|(name, _)| owner.is_none_or(|wanted| &***name == wanted))
            .map(|(name, lease)| LeaseRow {
                owner: Arc::clone(name),
                generation: lease.generation,
                lease_seconds: lease.lease_seconds,
                remaining: lease.deadline.saturating_duration_since(now),
            })
            .collect();
        rows.sort_by(|a, b| a.owner.cmp(&b.owner));
        rows
    }

    /// Owners with a live lease now.
    #[must_use]
    pub fn live_owner_count(&self) -> usize {
        let state = self.lock();
        state.live_count(Instant::now())
    }

    /// Move every lease whose deadline has passed to the pending queue, drain
    /// the queue, and return it with the next deadline still ahead.
    #[must_use]
    pub fn take_expired(&self) -> (Vec<ExpiredLease>, Option<Instant>) {
        let mut state = self.lock();
        let now = Instant::now();
        let dead: Vec<Arc<str>> = state
            .owners
            .iter()
            .filter(|(_, lease)| lease.deadline <= now)
            .map(|(owner, _)| Arc::clone(owner))
            .collect();
        for owner in dead {
            state.reap(&owner);
        }
        let next = state.owners.values().map(|lease| lease.deadline).min();
        (std::mem::take(&mut state.pending), next)
    }

    /// Passes the expiry loop has made.
    #[cfg(test)]
    pub(crate) fn expiry_passes(&self) -> usize {
        self.expiry_passes.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether the lock is free, for tests that prove a code path does not
    /// hold it.
    #[cfg(test)]
    pub(crate) fn is_unlocked(&self) -> bool {
        self.state.try_lock().is_ok()
    }

    /// Drive expiry until cancelled: sleep to the earliest deadline (or until
    /// the table changes), move dead generations to the pending queue and send
    /// them to the RIB as one `ExpireInjectionLeases` batch. `cancel` firing,
    /// or its sender being dropped, stops the task both while it sleeps and
    /// while it waits for RIB queue admission; a cancelled expiry sends
    /// nothing.
    pub async fn run_expiry(
        self: Arc<Self>,
        rib_tx: mpsc::Sender<RibUpdate>,
        mut cancel: oneshot::Receiver<()>,
    ) -> ExpiryExit {
        loop {
            #[cfg(test)]
            self.expiry_passes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (expired, next) = self.take_expired();
            if !expired.is_empty() {
                tokio::select! {
                    biased;
                    _ = &mut cancel => return ExpiryExit::Cancelled,
                    sent = rib_tx.send(RibUpdate::ExpireInjectionLeases { leases: expired }) => {
                        if sent.is_err() {
                            return ExpiryExit::RibChannelClosed;
                        }
                    }
                }
                continue;
            }
            let sleep = async {
                match next {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                biased;
                _ = &mut cancel => return ExpiryExit::Cancelled,
                () = self.changed.notified() => {}
                () = sleep => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn validation_bounds() {
        assert!(validate_lease("a", 5).is_ok());
        assert!(validate_lease(&"a".repeat(64), 3600).is_ok());
        for (owner, secs) in [
            ("", 30),
            (&*"a".repeat(65), 30),
            ("bad owner", 30),
            ("ctl/1", 30),
            ("ok", 0),
            ("ok", 4),
            ("ok", 3601),
        ] {
            assert!(validate_lease(owner, secs).is_err(), "{owner:?} {secs}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn adds_never_shorten_and_renew_sets_exactly() {
        let table = InjectionLeases::new();
        let g = table.admit("ctl", 60).unwrap();
        let joined = table.admit("ctl", 5).unwrap();
        assert_eq!(joined, g);
        assert_eq!(
            table.list(Some("ctl"))[0].remaining,
            Duration::from_secs(60)
        );
        assert_eq!(
            table.renew("ctl", g.generation, 5),
            Some(Duration::from_secs(5))
        );
        assert_eq!(table.list(Some("ctl"))[0].remaining, Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn renewal_at_the_deadline_loses_and_never_resurrects() {
        let table = InjectionLeases::new();
        let start = Instant::now();
        let g = table.admit("ctl", 5).unwrap().generation;
        let deadline = start + Duration::from_secs(5);
        let just_before = deadline - Duration::from_nanos(1);
        assert!(table.renew_at("ctl", g, 5, None, || just_before).is_ok());
        let deadline = just_before + Duration::from_secs(5);
        assert_eq!(
            table.renew_at("ctl", g, 5, None, || deadline),
            Err(LeaseConflict::GenerationNotLive)
        );
        tokio::time::advance(Duration::from_secs(10)).await;
        let (expired, _) = table.take_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(table.renew("ctl", g, 5), None);
        assert_eq!(table.list(None), Vec::new());
    }

    #[test]
    fn incarnations_differ_between_tables_and_fence_generations() {
        let a = InjectionLeases::new();
        let b = InjectionLeases::new();
        assert_ne!(a.incarnation(), b.incarnation());
        let ga = a.admit("ctl", 30).unwrap().generation;
        let gb = b.admit("ctl", 30).unwrap().generation;
        assert_eq!(ga.sequence, gb.sequence);
        assert_eq!(b.renew("ctl", ga, 30), None);
        assert!(b.renew("ctl", gb, 30).is_some());
    }

    /// The cap counts live leases by deadline, so expired records awaiting
    /// the tick do not refuse a new owner; a refusal moves nothing.
    #[tokio::test(start_paused = true)]
    async fn owner_cap_counts_live_leases_and_a_rejection_mutates_nothing() {
        let table = InjectionLeases::new();
        for i in 0..MAX_LIVE_OWNERS {
            table.admit(&format!("o{i}"), 5).unwrap();
        }
        assert_eq!(table.admit("late", 30), Err(LeaseRejection::OwnerCap));
        tokio::time::advance(Duration::from_secs(5)).await;
        // All 64 expired but none was reaped: a new owner is admitted.
        table.admit("late", 30).unwrap();
        for i in 1..MAX_LIVE_OWNERS {
            table.admit(&format!("n{i}"), 30).unwrap();
        }
        // 64 live again plus 64 unreaped records; a refused owner whose own
        // record expired keeps that record where it is.
        let before = table.list(Some("o0"));
        assert_eq!(table.admit("o0", 30), Err(LeaseRejection::OwnerCap));
        assert_eq!(table.list(Some("o0")), before);
        assert_eq!(table.live_owner_count(), MAX_LIVE_OWNERS);
    }

    /// The clock is read after the lock: a renewal or leased add that waits
    /// for the lock across the deadline is judged at the later time. The fake
    /// clock counts reads; the holder advances it past the deadline only
    /// after the contender has had a chance to read it before locking.
    #[test]
    fn a_wait_for_the_lock_across_the_deadline_is_judged_after_it() {
        for leased_add in [false, true] {
            let table = Arc::new(InjectionLeases::new());
            let base = Instant::now();
            let offset_ms = Arc::new(AtomicU64::new(0));
            let reads = Arc::new(AtomicUsize::new(0));
            let g = table
                .admit_at("ctl", 5, None, || base)
                .unwrap()
                .tag
                .generation;

            let guard = table.lock();
            let contender = {
                let (table, offset_ms, reads) = (
                    Arc::clone(&table),
                    Arc::clone(&offset_ms),
                    Arc::clone(&reads),
                );
                std::thread::spawn(move || {
                    // Take the time before announcing the read, so the
                    // holder cannot advance it between the two.
                    let clock = || {
                        let now = base + Duration::from_millis(offset_ms.load(Ordering::SeqCst));
                        reads.fetch_add(1, Ordering::SeqCst);
                        now
                    };
                    if leased_add {
                        table
                            .admit_at("ctl", 5, None, clock)
                            .map(|admission| admission.tag.generation)
                            .ok()
                    } else {
                        table.renew_at("ctl", g, 5, None, clock).ok().map(|_| g)
                    }
                })
            };
            // Give a pre-lock read every chance to happen first.
            let waited = std::time::Instant::now();
            while reads.load(Ordering::SeqCst) == 0
                && waited.elapsed() < std::time::Duration::from_millis(200)
            {
                std::thread::yield_now();
            }
            offset_ms.store(5_000, Ordering::SeqCst);
            drop(guard);
            let result = contender.join().unwrap();
            if leased_add {
                assert_ne!(result, Some(g), "joined an expired generation");
            } else {
                assert_eq!(result, None, "renewed an expired generation");
            }
        }
    }

    fn guarded_tag(
        table: &InjectionLeases,
        owner: &str,
        lease_seconds: u32,
        window: MutationWindowId,
    ) -> Result<InjectionTag, LeaseRejection> {
        table
            .admit_with(&guarded_owner(owner), lease_seconds, Some(window))
            .map(|admission| admission.tag)
    }

    fn remaining(table: &InjectionLeases, owner: &str) -> Duration {
        table.list(Some(&guarded_owner(owner)))[0].remaining
    }

    /// The window cap refuses a 65th live window for one owner and a
    /// 4,097th in the table. A refusal changes nothing, so an issued window
    /// still admits, and expired windows free their slots.
    ///
    /// Break-to-red: dropping either cap issues the extra window.
    #[tokio::test(start_paused = true)]
    async fn window_caps_refuse_and_change_nothing() {
        let table = InjectionLeases::new();
        let (oldest, lifetime) = table.issue_window("ctl", 30).unwrap();
        assert_eq!(lifetime, Duration::from_secs(30));
        for _ in 1..MAX_LIVE_WINDOWS_PER_OWNER {
            table.issue_window("ctl", 30).unwrap();
        }
        assert_eq!(
            table.issue_window("ctl", 30),
            Err(LeaseRejection::WindowCap)
        );
        assert_eq!(table.lock().windows.len(), MAX_LIVE_WINDOWS_PER_OWNER);
        guarded_tag(&table, "ctl", 60, oldest).unwrap();
        // Other owners have their own allowance until the table is full.
        for owner in 1..MAX_LIVE_OWNERS {
            for _ in 0..MAX_LIVE_WINDOWS_PER_OWNER {
                table.issue_window(&format!("o{owner}"), 30).unwrap();
            }
        }
        assert_eq!(
            table.issue_window("late", 30),
            Err(LeaseRejection::WindowCap)
        );
        assert_eq!(table.lock().windows.len(), MAX_LIVE_WINDOWS);
        tokio::time::advance(Duration::from_secs(30)).await;
        table.issue_window("late", 30).unwrap();
        table.issue_window("ctl", 30).unwrap();
        assert_eq!(table.lock().windows.len(), 2, "expired windows pruned");
    }

    /// A guarded admission or renewal is refused, changing nothing, for a
    /// window that is expired, another owner's, another process's, unknown,
    /// or presented under the bare owner name.
    #[tokio::test(start_paused = true)]
    async fn only_a_live_window_of_the_same_owner_admits() {
        let table = InjectionLeases::new();
        let other = InjectionLeases::new();
        let (window, lifetime) = table.issue_window("ctl", 500).unwrap();
        assert_eq!(lifetime, Duration::from_secs(u64::from(MAX_WINDOW_SECONDS)));
        let (foreign, _) = table.issue_window("b", 30).unwrap();
        let (elsewhere, _) = other.issue_window("ctl", 30).unwrap();
        let unknown = MutationWindowId {
            sequence: 99,
            ..window
        };
        for refused in [foreign, elsewhere, unknown] {
            assert_eq!(
                guarded_tag(&table, "ctl", 60, refused),
                Err(LeaseRejection::WindowNotLive)
            );
        }
        assert_eq!(
            table
                .admit_with("ctl", 60, Some(window))
                .map(|admission| admission.tag),
            Err(LeaseRejection::WindowNotLive),
            "the window belongs to the guarded name"
        );
        assert_eq!(table.list(None), Vec::new());
        let g = guarded_tag(&table, "ctl", 60, window).unwrap().generation;
        assert_eq!(
            table.renew_guarded("ctl", g, 60, foreign),
            Err(LeaseConflict::WindowNotLive)
        );
        tokio::time::advance(Duration::from_secs(u64::from(MAX_WINDOW_SECONDS))).await;
        let before = table.list(None);
        assert_eq!(
            guarded_tag(&table, "ctl", 60, window),
            Err(LeaseRejection::WindowNotLive)
        );
        assert_eq!(
            table.renew_guarded("ctl", g, 60, window),
            Err(LeaseConflict::WindowNotLive)
        );
        assert_eq!(table.list(None), before);
    }

    /// The deadline never passes the window's expiry: on a new generation,
    /// on a renewal (which sets it exactly and may shorten it), and on a
    /// join, which never shortens it either.
    #[tokio::test(start_paused = true)]
    async fn the_window_caps_the_deadline() {
        let table = InjectionLeases::new();
        let (short, _) = table.issue_window("ctl", 30).unwrap();
        let g = guarded_tag(&table, "ctl", 60, short).unwrap().generation;
        assert_eq!(remaining(&table, "ctl"), Duration::from_secs(30));
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(
            table.renew_guarded("ctl", g, 5, short),
            Ok(Duration::from_secs(5))
        );
        // A join extends to its own window's expiry, not past it.
        assert_eq!(guarded_tag(&table, "ctl", 60, short).unwrap().generation, g);
        assert_eq!(remaining(&table, "ctl"), Duration::from_secs(20));
        let (long, _) = table.issue_window("ctl", 120).unwrap();
        assert_eq!(
            table.renew_guarded("ctl", g, 60, long),
            Ok(Duration::from_secs(60))
        );
        // A join through the older, shorter window keeps the later deadline.
        assert_eq!(guarded_tag(&table, "ctl", 60, short).unwrap().generation, g);
        assert_eq!(remaining(&table, "ctl"), Duration::from_secs(60));
    }

    /// Guarded names are outside the owner alphabet, so a legacy request can
    /// never name one, and a legacy renewal or add of the bare name cannot
    /// reach a guarded lease.
    #[tokio::test(start_paused = true)]
    async fn guarded_names_are_unreachable_by_legacy_names() {
        let table = InjectionLeases::new();
        assert!(validate_owner(&guarded_owner("ctl")).is_err());
        assert!(validate_window("ctl", 1).is_ok());
        assert!(validate_window("ctl", MAX_WINDOW_SECONDS).is_ok());
        assert!(validate_window("ctl", 0).is_err());
        assert!(validate_window("ctl", MAX_WINDOW_SECONDS + 1).is_err());
        assert!(validate_window("ctl:x", 30).is_err());
        let (window, _) = table.issue_window("ctl", 30).unwrap();
        let g = guarded_tag(&table, "ctl", 30, window).unwrap().generation;
        assert_eq!(table.renew("ctl", g, 3600), None);
        let legacy = table.admit("ctl", 3600).unwrap();
        assert_ne!(legacy.generation, g);
        assert_eq!(remaining(&table, "ctl"), Duration::from_secs(30));
    }
}
