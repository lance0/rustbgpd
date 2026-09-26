//! The RIB manager's published export roster (ADR-0136).
//!
//! The roster is an immutable projection of the RIB's per-peer export map and
//! global fallback slot: for each peer with an entry, the counter instance of
//! its installed export chain or "explicitly disabled", plus the global
//! fallback instance. The RIB rebuilds and publishes it whole at its single
//! publication point, after a completed unit of work and never between the
//! `CommitMembers` batches of a grouped transition; nothing edits a published
//! roster. `GetPolicyStats` takes one [`ExportRosterReader::load`](crate::export_roster::ExportRosterReader::load) per request
//! and reads the live counters the roster designates without messaging the
//! RIB manager.
//!
//! Readers and the publisher cannot block each other: the cell is an
//! `ArcSwap`, whose loads and stores are lock-free. Dropping the publisher
//! (the RIB manager exiting or unwinding) closes the cell and releases the
//! published instances; a request checks the closure after capture, so a
//! roster loaded before the owner stopped cannot report its values as success.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::TryLockError;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use rustbgpd_policy::{PolicyHitCounters, TermHitRow};

use crate::update::ExportPolicyTermHits;

/// One peer's export-map entry: its installed chain's counter instance, or
/// `None` when export policy is explicitly disabled for the peer (the global
/// fallback does not apply to it).
pub type ExportRosterPeer = (IpAddr, Option<Arc<PolicyHitCounters>>);

/// One immutable roster publication.
#[derive(Debug, Default)]
pub struct ExportRoster {
    version: u64,
    peers: Vec<ExportRosterPeer>,
    global: Option<Arc<PolicyHitCounters>>,
}

impl ExportRoster {
    /// Publication sequence number; 0 is the empty roster before the first
    /// publication.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Peers with an export-map entry, ordered by address.
    #[must_use]
    pub fn peers(&self) -> &[ExportRosterPeer] {
        &self.peers
    }

    /// The global fallback instance, used by peers without an entry.
    #[must_use]
    pub fn global(&self) -> Option<&Arc<PolicyHitCounters>> {
        self.global.as_ref()
    }

    /// The instance that evaluates `peer`'s exports: its own entry if it has
    /// one (`None` when explicitly disabled), otherwise the global fallback.
    #[must_use]
    pub fn for_peer(&self, peer: IpAddr) -> Option<&Arc<PolicyHitCounters>> {
        match self
            .peers
            .binary_search_by_key(&peer, |(address, _)| *address)
        {
            Ok(index) => self.peers[index].1.as_ref(),
            Err(_) => self.global.as_ref(),
        }
    }
}

#[derive(Debug, Default)]
struct RosterCell {
    roster: ArcSwap<ExportRoster>,
    closed: AtomicBool,
}

/// The RIB manager's publishing end. Not `Clone`: one owner publishes.
/// Dropping it, on normal exit or unwind, closes the cell and releases the
/// published instances once in-flight readers drop theirs.
#[derive(Debug, Default)]
pub struct ExportRosterPublisher {
    cell: Arc<RosterCell>,
    version: u64,
}

impl ExportRosterPublisher {
    /// A publisher whose readers see an empty roster until the first
    /// publication.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A reading end for `GetPolicyStats` listeners.
    #[must_use]
    pub fn reader(&self) -> ExportRosterReader {
        ExportRosterReader {
            cell: Arc::clone(&self.cell),
        }
    }

    /// Replace the published roster with a new projection. Readers holding
    /// an earlier roster keep it until their request ends.
    pub fn publish(
        &mut self,
        mut peers: Vec<ExportRosterPeer>,
        global: Option<Arc<PolicyHitCounters>>,
    ) {
        peers.sort_unstable_by_key(|(address, _)| *address);
        self.version += 1;
        self.cell.roster.store(Arc::new(ExportRoster {
            version: self.version,
            peers,
            global,
        }));
    }

    /// The roster readers currently load.
    #[must_use]
    pub fn published(&self) -> Arc<ExportRoster> {
        self.cell.roster.load_full()
    }
}

impl Drop for ExportRosterPublisher {
    fn drop(&mut self) {
        // Close first: a reader that loads the empty roster below also
        // observes the closure after its capture.
        self.cell.closed.store(true, Ordering::Release);
        self.cell.roster.store(Arc::new(ExportRoster::default()));
    }
}

/// A reading end of the export roster.
#[derive(Debug, Clone)]
pub struct ExportRosterReader {
    cell: Arc<RosterCell>,
}

impl ExportRosterReader {
    /// Load the current roster as an owned `Arc`, safe to hold across awaits.
    #[must_use]
    pub fn load(&self) -> Arc<ExportRoster> {
        self.cell.roster.load_full()
    }

    /// Whether the publishing RIB manager has stopped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.cell.closed.load(Ordering::Acquire)
    }
}

/// Why an export capture failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportCaptureError {
    /// The request deadline passed during the capture.
    TimedOut,
    /// A counter instance's error lock is poisoned.
    Unavailable,
}

/// Term rows read between deadline checks, as in the import capture
/// (`rustbgpd_transport::handle`): a row costs about 30 ns with short labels
/// and 250 ns with 256-byte labels, so one clock read per stride is well under
/// 1% of the pass, and a chain of about 500,000 terms stops within about 30 to
/// 250 us of its deadline.
const DEADLINE_CHECK_ROWS: usize = 1024;

/// Read the export counters `roster` designates, in one pass: for `peer`, the
/// instance that evaluates its exports (none when disabled); for a fleet
/// read, every peer's installed instance ordered by address, then the global
/// fallback. Each counter is read once when the request runs. The pass
/// yields only while an instance's error lock is busy, and checks the
/// deadline without yielding at each instance and every
/// 1,024 term rows.
///
/// # Errors
///
/// Deadline expiry or a poisoned error lock fails the whole capture.
pub async fn capture_export(
    roster: &ExportRoster,
    peer: Option<IpAddr>,
    deadline: tokio::time::Instant,
) -> Result<Vec<ExportPolicyTermHits>, ExportCaptureError> {
    capture_export_until(roster, peer, |_| deadline <= tokio::time::Instant::now()).await
}

/// [`capture_export`] with the deadline as a predicate over the term rows
/// read so far, so a test can pass it mid-pass.
async fn capture_export_until(
    roster: &ExportRoster,
    peer: Option<IpAddr>,
    mut expired: impl FnMut(usize) -> bool,
) -> Result<Vec<ExportPolicyTermHits>, ExportCaptureError> {
    let selected: Vec<(Option<IpAddr>, &Arc<PolicyHitCounters>)> = match peer {
        Some(peer) => roster
            .for_peer(peer)
            .map(|counters| (Some(peer), counters))
            .into_iter()
            .collect(),
        None => roster
            .peers
            .iter()
            .filter_map(|(peer, counters)| {
                counters.as_ref().map(|counters| (Some(*peer), counters))
            })
            .chain(roster.global.iter().map(|counters| (None, counters)))
            .collect(),
    };
    let mut rows = Vec::with_capacity(selected.len());
    let mut read = 0_usize;
    for (peer, counters) in selected {
        let (eval_errors, last_error) = loop {
            if expired(read) {
                return Err(ExportCaptureError::TimedOut);
            }
            match counters.try_snapshot_error() {
                Ok(snapshot) => break snapshot,
                // The RIB is recording an evaluation error; never block it
                // or this worker behind the lock.
                Err(TryLockError::WouldBlock) => tokio::task::yield_now().await,
                Err(TryLockError::Poisoned(_)) => return Err(ExportCaptureError::Unavailable),
            }
        };
        let labels = counters.labels();
        let mut terms = Vec::with_capacity(labels.iter().map(|(_, terms)| terms.len()).sum());
        for (policy_index, (policy, labels)) in labels.iter().enumerate() {
            for (term_index, term) in labels.iter().enumerate() {
                // No await in this pass, so the caller's `timeout_at` cannot
                // interrupt it: bound a large chain here, without yielding.
                if terms.len() % DEADLINE_CHECK_ROWS == DEADLINE_CHECK_ROWS - 1 && expired(read) {
                    return Err(ExportCaptureError::TimedOut);
                }
                let hits = counters
                    .term_hits(policy_index, term_index)
                    .ok_or(ExportCaptureError::Unavailable)?;
                terms.push(TermHitRow {
                    policy_index,
                    policy: policy.as_ref().map(ToString::to_string),
                    term_index,
                    term: term.clone(),
                    hits,
                });
                read += 1;
            }
        }
        rows.push(ExportPolicyTermHits {
            peer,
            counter_instance: counters.id(),
            evals: counters.evals(),
            eval_errors,
            last_error: last_error.map(|error| error.to_string()),
            terms,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    use std::time::Duration;

    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement};

    use super::*;

    fn chain(terms: usize) -> PolicyChain {
        let statement = PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: rustbgpd_policy::RouteModifications::default(),
        };
        PolicyChain::new(vec![Policy {
            entries: vec![statement; terms],
            default_action: PolicyAction::Deny,
        }])
    }

    fn counters(terms: usize) -> Arc<PolicyHitCounters> {
        Arc::clone(chain(terms).hit_counters())
    }

    fn far() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(60)
    }

    fn address(last: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, last])
    }

    /// Poll a capture once: it must complete without yielding.
    async fn capture_in_one_poll(
        roster: &ExportRoster,
        peer: Option<IpAddr>,
        expired: impl FnMut(usize) -> bool,
    ) -> Result<Vec<ExportPolicyTermHits>, ExportCaptureError> {
        let capture = capture_export_until(roster, peer, expired);
        tokio::pin!(capture);
        let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(capture.as_mut().poll(cx))).await else {
            panic!("an export capture with free error locks must not yield");
        };
        result
    }

    /// Per-peer reads apply the RIB's rule (own entry, disabled, or global
    /// fallback); fleet reads list installed entries by address, then the
    /// global instance. Each row names its instance and reads live counters.
    #[tokio::test]
    async fn capture_applies_the_fallback_rule_and_reads_live_counters() {
        let global = counters(1);
        let own = counters(2);
        let mut publisher = ExportRosterPublisher::new();
        publisher.publish(
            vec![(address(3), None), (address(2), Some(Arc::clone(&own)))],
            Some(Arc::clone(&global)),
        );
        let roster = publisher.reader().load();
        assert_eq!(roster.version(), 1);

        let fleet = capture_in_one_poll(&roster, None, |_| false).await.unwrap();
        let shape: Vec<_> = fleet
            .iter()
            .map(|row| (row.peer, row.counter_instance, row.terms.len()))
            .collect();
        assert_eq!(
            shape,
            [(Some(address(2)), own.id(), 2), (None, global.id(), 1)]
        );
        assert!(own.id() != 0 && global.id() != 0);

        let one = |peer| {
            let roster = Arc::clone(&roster);
            async move {
                capture_in_one_poll(&roster, Some(peer), |_| false)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|row| (row.peer, row.counter_instance))
                    .collect::<Vec<_>>()
            }
        };
        assert_eq!(one(address(2)).await, [(Some(address(2)), own.id())]);
        assert!(one(address(3)).await.is_empty(), "explicitly disabled");
        assert_eq!(
            one(address(9)).await,
            [(Some(address(9)), global.id())],
            "a peer without an entry reads the global fallback"
        );
    }

    /// Each counter is read when the request runs: an evaluation after the
    /// roster was published and loaded, with no owner operation between, is
    /// visible to the capture. Nothing is cached at publication.
    #[tokio::test]
    async fn capture_reads_increments_made_after_publication() {
        let installed = chain(2);
        let mut publisher = ExportRosterPublisher::new();
        publisher.publish(
            vec![(address(1), Some(Arc::clone(installed.hit_counters())))],
            None,
        );
        let roster = publisher.reader().load();
        let context = rustbgpd_policy::RouteContext {
            prefix: None,
            next_hop: None,
            extended_communities: &[],
            communities: &[],
            large_communities: &[],
            as_path_str: "",
            as_path: None,
            as_path_len: 0,
            origin_asn: None,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            peer_address: None,
            peer_asn: None,
            peer_group: None,
            route_type: None,
            family: None,
            evpn_route_type: None,
            local_pref: None,
            med: None,
        };
        for _ in 0..3 {
            let _ = installed.evaluate(&context);
        }
        let rows = capture_in_one_poll(&roster, None, |_| false).await.unwrap();
        assert_eq!(
            rows[0].evals, 3,
            "live counters, not a publication-time copy"
        );
        assert_eq!(rows[0].terms[0].hits, 3);
        assert_eq!(rows[0].terms[1].hits, 0);
    }

    /// The term pass has no await, so the caller's `timeout_at` cannot stop
    /// it: a deadline passed mid-pass must end it at the next stride check.
    /// The test clock passes the deadline after 2,000 rows of 5,000; without
    /// the stride check the pass returns all 5,000 rows.
    #[tokio::test]
    async fn capture_stops_at_a_deadline_passed_mid_pass() {
        let mut publisher = ExportRosterPublisher::new();
        publisher.publish(vec![(address(1), Some(counters(5_000)))], None);
        let roster = publisher.reader().load();
        let rows = capture_in_one_poll(&roster, None, |_| false).await.unwrap();
        assert_eq!(
            rows[0].terms.len(),
            5_000,
            "an unexpired pass reads every term"
        );

        let outcome = capture_in_one_poll(&roster, None, |read| read >= 2_000).await;
        assert_eq!(
            outcome.map(|rows| rows[0].terms.len()),
            Err(ExportCaptureError::TimedOut),
            "the pass ran past its deadline"
        );
    }

    /// A fleet of small chains checks the deadline between instances.
    #[tokio::test]
    async fn capture_checks_the_deadline_between_instances() {
        let mut publisher = ExportRosterPublisher::new();
        publisher.publish(
            (1..=4)
                .map(|last| (address(last), Some(counters(2))))
                .collect(),
            None,
        );
        let roster = publisher.reader().load();
        let outcome = capture_in_one_poll(&roster, None, |read| read >= 4).await;
        assert_eq!(
            outcome.map(|rows| rows.len()),
            Err(ExportCaptureError::TimedOut)
        );
        let expired = tokio::time::Instant::now();
        assert_eq!(
            capture_export(&roster, None, expired)
                .await
                .map(|rows| rows.len()),
            Err(ExportCaptureError::TimedOut)
        );
        assert_eq!(
            capture_export(&roster, None, far())
                .await
                .map(|rows| rows.len()),
            Ok(4)
        );
    }

    /// A reader holding a loaded roster across an await never delays the
    /// owner's next publication, and keeps its own roster until it drops it.
    #[tokio::test]
    async fn held_roster_does_not_delay_republication() {
        let mut publisher = ExportRosterPublisher::new();
        publisher.publish(vec![(address(1), Some(counters(1)))], None);
        let reader = publisher.reader();
        let held = reader.load();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let holder = tokio::spawn(async move {
            let _ = released.await;
            held.peers().len()
        });
        publisher.publish(Vec::new(), None);
        let current = reader.load();
        assert_eq!(current.version(), 2);
        assert!(current.peers().is_empty());
        release.send(()).unwrap();
        assert_eq!(holder.await.unwrap(), 1, "the held roster is unchanged");
    }

    /// Dropping the publisher closes every reader and releases the published
    /// instances once in-flight rosters drop.
    #[test]
    fn dropping_the_publisher_closes_and_releases() {
        let instance = counters(1);
        let retired = Arc::downgrade(&instance);
        let mut publisher = ExportRosterPublisher::new();
        publisher.publish(vec![(address(1), Some(instance))], None);
        let reader = publisher.reader();
        let in_flight = reader.load();
        assert!(!reader.is_closed());
        drop(publisher);
        assert!(reader.is_closed() && reader.clone().is_closed());
        assert!(reader.load().peers().is_empty());
        assert!(retired.upgrade().is_some(), "an in-flight request keeps it");
        drop(in_flight);
        assert!(retired.upgrade().is_none());
    }
}
