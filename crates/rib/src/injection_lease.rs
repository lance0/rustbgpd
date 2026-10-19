//! Owner-scoped leases on controller-injected routes (ADR-0141).
//!
//! One daemon-wide [`InjectionLeases`](crate::injection_lease::InjectionLeases) table is shared by every
//! `InjectionService` instance, the RIB manager and the expiry task. It holds
//! each owner's live lease, the pending-expiry queue, and the ownership tag of
//! every owned local key. Only RIB turns tag or untag keys, so the tags change
//! in the same turn as the local Adj-RIB-In. Renewal and lease listing touch
//! only this table, never the RIB actor, so a backlogged RIB cannot delay a
//! renewal into an expiry. Every operation under the lock is O(1), or
//! O(live owners) for the expiry tick; no lock is held across an `.await`.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
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
/// Longest accepted owner name, in bytes.
pub const MAX_OWNER_LEN: usize = 64;

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

/// Ownership read-back for one local key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLease {
    /// Owner of the key.
    pub owner: Arc<str>,
    /// Generation the key is tagged with.
    pub generation: LeaseGeneration,
    /// Time to the deadline; 0 when expired and withdrawal is pending.
    pub remaining: Duration,
}

/// Why a leased add or an ownership check was refused. The table, the RIB
/// and the wire are unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseRejection {
    /// The key belongs to another owner, or to no owner.
    OwnerMismatch(String),
    /// A new owner would exceed [`MAX_LIVE_OWNERS`].
    OwnerCap,
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

#[derive(Debug, Default)]
struct State {
    next_sequence: u64,
    /// Current lease per owner. A lease is live iff `now < deadline`; an
    /// entry past its deadline stays here until the tick or a leased add
    /// moves it to `pending`.
    owners: HashMap<Arc<str>, LiveLease>,
    pending: Vec<ExpiredLease>,
    owned: HashMap<InjectedKey, (Arc<str>, LeaseGeneration)>,
    owner_keys: HashMap<Arc<str>, HashSet<InjectedKey>>,
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
}

/// The daemon-wide lease table (ADR-0141 §4).
#[derive(Debug)]
pub struct InjectionLeases {
    incarnation: u64,
    state: Mutex<State>,
    changed: Notify,
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
        // no clock involved and no new dependency.
        let incarnation = RandomState::new().build_hasher().finish();
        Self {
            incarnation,
            state: Mutex::new(State {
                next_sequence: 1,
                ..State::default()
            }),
            changed: Notify::new(),
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

    /// The owner and generation `key` is tagged with, if owned.
    #[must_use]
    pub fn owner_of(&self, key: &InjectedKey) -> Option<(Arc<str>, LeaseGeneration)> {
        self.lock().owned.get(key).cloned()
    }

    /// Admit a leased add of `key` for `owner` at `now`, in the RIB turn that
    /// commits it: reject an ownership mismatch, then join the owner's live
    /// lease (extending it to `max(deadline, now + lease_seconds)`) or start
    /// a new generation, then tag the key. `key_present` says whether the
    /// local Adj-RIB-In already holds the key; a present unowned key is never
    /// adopted.
    ///
    /// # Errors
    ///
    /// [`LeaseRejection`] with no change to the table.
    ///
    /// # Panics
    ///
    /// Never: the owner's entry is joined or inserted under the same lock
    /// before it is read back.
    pub fn admit_leased_add(
        &self,
        owner: &str,
        lease_seconds: u32,
        key: &InjectedKey,
        key_present: bool,
        now: Instant,
    ) -> Result<LeaseGeneration, LeaseRejection> {
        let mut state = self.lock();
        match state.owned.get(key) {
            Some((holder, _)) if &**holder != owner => {
                return Err(LeaseRejection::OwnerMismatch(format!(
                    "key is held by owner {holder:?}"
                )));
            }
            None if key_present => {
                return Err(LeaseRejection::OwnerMismatch(
                    "key is held by no owner; delete it before a leased add".to_string(),
                ));
            }
            _ => {}
        }
        let lease_for = Duration::from_secs(u64::from(lease_seconds));
        let live = state
            .owners
            .get(owner)
            .is_some_and(|lease| now < lease.deadline);
        let generation = if live {
            let lease = state.owners.get_mut(owner).expect("checked live above");
            let extended = now + lease_for;
            if extended > lease.deadline {
                lease.deadline = extended;
                lease.lease_seconds = lease_seconds;
            }
            lease.generation
        } else {
            state.reap(owner);
            if state.owners.len() >= MAX_LIVE_OWNERS {
                return Err(LeaseRejection::OwnerCap);
            }
            let generation = LeaseGeneration {
                incarnation: self.incarnation,
                sequence: state.next_sequence,
            };
            state.next_sequence += 1;
            state.owners.insert(
                Arc::from(owner),
                LiveLease {
                    generation,
                    deadline: now + lease_for,
                    lease_seconds,
                },
            );
            tracing::info!(
                owner,
                incarnation = generation.incarnation,
                sequence = generation.sequence,
                lease_seconds,
                "injection lease generation started"
            );
            generation
        };
        let owner: Arc<str> = Arc::clone(
            state
                .owners
                .get_key_value(owner)
                .expect("owner was just inserted or joined")
                .0,
        );
        state
            .owned
            .insert(key.clone(), (Arc::clone(&owner), generation));
        state
            .owner_keys
            .entry(owner)
            .or_default()
            .insert(key.clone());
        drop(state);
        self.changed.notify_one();
        Ok(generation)
    }

    /// Check that `owner` (`""` for unowned) may delete or replace `key`.
    ///
    /// # Errors
    ///
    /// [`LeaseRejection::OwnerMismatch`] when the key's owner differs.
    pub fn check_owner(&self, key: &InjectedKey, owner: &str) -> Result<(), LeaseRejection> {
        let state = self.lock();
        let holder = state.owned.get(key).map_or("", |(holder, _)| &**holder);
        if holder == owner {
            Ok(())
        } else if holder.is_empty() {
            Err(LeaseRejection::OwnerMismatch(format!(
                "key is held by no owner, not {owner:?}"
            )))
        } else {
            Err(LeaseRejection::OwnerMismatch(format!(
                "key is held by owner {holder:?}"
            )))
        }
    }

    /// Drop `key`'s ownership tag after the RIB removed it.
    pub fn forget(&self, key: &InjectedKey) {
        let mut state = self.lock();
        if let Some((owner, _)) = state.owned.remove(key)
            && let Some(keys) = state.owner_keys.get_mut(&owner)
        {
            keys.remove(key);
            if keys.is_empty() {
                state.owner_keys.remove(&owner);
            }
        }
    }

    /// Renew `owner`'s lease if `generation` is live at `now`, setting the
    /// deadline to exactly `now + lease_seconds` (which may shorten it).
    /// Returns `None`, changing nothing, for an unknown owner, a superseded
    /// generation or an expired lease, reaped or not. A renewal at exactly
    /// the deadline loses.
    #[must_use]
    pub fn renew(
        &self,
        owner: &str,
        generation: LeaseGeneration,
        lease_seconds: u32,
        now: Instant,
    ) -> Option<Duration> {
        let mut state = self.lock();
        let lease = state.owners.get_mut(owner)?;
        if lease.generation != generation || now >= lease.deadline {
            return None;
        }
        let lease_for = Duration::from_secs(u64::from(lease_seconds));
        lease.deadline = now + lease_for;
        lease.lease_seconds = lease_seconds;
        drop(state);
        self.changed.notify_one();
        Some(lease_for)
    }

    /// Ownership and remaining lease for `key`, for read-back.
    #[must_use]
    pub fn key_lease(&self, key: &InjectedKey, now: Instant) -> Option<KeyLease> {
        let state = self.lock();
        let (owner, generation) = state.owned.get(key)?;
        let remaining = state
            .owners
            .get(owner)
            .filter(|lease| lease.generation == *generation)
            .map_or(Duration::ZERO, |lease| {
                lease.deadline.saturating_duration_since(now)
            });
        Some(KeyLease {
            owner: Arc::clone(owner),
            generation: *generation,
            remaining,
        })
    }

    /// Current leases, optionally for one owner, sorted by owner.
    #[must_use]
    pub fn list(&self, owner: Option<&str>, now: Instant) -> Vec<LeaseRow> {
        let state = self.lock();
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

    /// Owners with a lease in the table, live or awaiting the tick.
    #[must_use]
    pub fn owner_count(&self) -> usize {
        self.lock().owners.len()
    }

    /// Move every lease whose deadline is `<= now` to the pending queue,
    /// drain the queue, and return it with the next deadline still ahead.
    #[must_use]
    pub fn take_expired(&self, now: Instant) -> (Vec<ExpiredLease>, Option<Instant>) {
        let mut state = self.lock();
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

    /// Untag and return every key of `expired.owner` tagged at or below its
    /// generation. Keys a newer generation retagged are kept.
    #[must_use]
    pub fn take_expired_keys(&self, expired: &ExpiredLease) -> Vec<InjectedKey> {
        let mut state = self.lock();
        let Some(keys) = state.owner_keys.get(&expired.owner) else {
            return Vec::new();
        };
        let dead: Vec<InjectedKey> = keys
            .iter()
            .filter(|key| {
                state.owned.get(*key).is_some_and(|(_, tag)| {
                    tag.incarnation == expired.generation.incarnation
                        && tag.sequence <= expired.generation.sequence
                })
            })
            .cloned()
            .collect();
        for key in &dead {
            state.owned.remove(key);
        }
        if let Some(keys) = state.owner_keys.get_mut(&expired.owner) {
            for key in &dead {
                keys.remove(key);
            }
            if keys.is_empty() {
                state.owner_keys.remove(&expired.owner);
            }
        }
        dead
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
    ) {
        loop {
            let (expired, next) = self.take_expired(Instant::now());
            if !expired.is_empty() {
                tokio::select! {
                    biased;
                    _ = &mut cancel => return,
                    sent = rib_tx.send(RibUpdate::ExpireInjectionLeases { leases: expired }) => {
                        if sent.is_err() {
                            return;
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
                _ = &mut cancel => return,
                () = self.changed.notified() => {}
                () = sleep => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rustbgpd_wire::Ipv4Prefix;

    use super::*;

    fn key(octet: u8) -> InjectedKey {
        InjectedKey::Unicast(
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32)),
            0,
        )
    }

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
        let now = Instant::now();
        let g = table
            .admit_leased_add("ctl", 60, &key(1), false, now)
            .unwrap();
        let joined = table
            .admit_leased_add("ctl", 5, &key(2), false, now)
            .unwrap();
        assert_eq!(joined, g);
        assert_eq!(
            table.list(Some("ctl"), now)[0].remaining,
            Duration::from_secs(60)
        );
        assert_eq!(table.renew("ctl", g, 5, now), Some(Duration::from_secs(5)));
        assert_eq!(
            table.list(Some("ctl"), now)[0].remaining,
            Duration::from_secs(5)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn renewal_at_the_deadline_loses_and_never_resurrects() {
        let table = InjectionLeases::new();
        let start = Instant::now();
        let g = table
            .admit_leased_add("ctl", 5, &key(1), false, start)
            .unwrap();
        let deadline = start + Duration::from_secs(5);
        assert!(
            table
                .renew("ctl", g, 5, deadline - Duration::from_nanos(1))
                .is_some()
        );
        let deadline = deadline - Duration::from_nanos(1) + Duration::from_secs(5);
        assert_eq!(table.renew("ctl", g, 5, deadline), None);
        let (expired, _) = table.take_expired(deadline);
        assert_eq!(expired.len(), 1);
        assert_eq!(table.renew("ctl", g, 5, deadline), None);
        assert_eq!(table.list(None, deadline), Vec::new());
    }

    #[test]
    fn incarnations_differ_between_tables_and_fence_generations() {
        let a = InjectionLeases::new();
        let b = InjectionLeases::new();
        assert_ne!(a.incarnation(), b.incarnation());
        let now = Instant::now();
        let ga = a.admit_leased_add("ctl", 30, &key(1), false, now).unwrap();
        let gb = b.admit_leased_add("ctl", 30, &key(1), false, now).unwrap();
        assert_eq!(ga.sequence, gb.sequence);
        assert_eq!(b.renew("ctl", ga, 30, now), None);
        assert!(b.renew("ctl", gb, 30, now).is_some());
    }

    #[test]
    fn owner_cap_and_mismatches_change_nothing() {
        let now = Instant::now();
        let table = InjectionLeases::new();
        for i in 0..MAX_LIVE_OWNERS {
            let octet = u8::try_from(i).unwrap();
            table
                .admit_leased_add(&format!("o{i}"), 30, &key(octet), false, now)
                .unwrap();
        }
        assert_eq!(
            table.admit_leased_add("late", 30, &key(200), false, now),
            Err(LeaseRejection::OwnerCap)
        );
        assert_eq!(table.owner_of(&key(200)), None);
        assert_eq!(table.owner_count(), MAX_LIVE_OWNERS);
        assert!(matches!(
            table.admit_leased_add("o1", 30, &key(0), false, now),
            Err(LeaseRejection::OwnerMismatch(_))
        ));
        assert!(matches!(
            table.admit_leased_add("o0", 30, &key(201), true, now),
            Err(LeaseRejection::OwnerMismatch(_))
        ));
        assert_eq!(table.owner_of(&key(201)), None);
    }
}
