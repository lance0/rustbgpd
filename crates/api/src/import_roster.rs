//! The peer manager's published import roster (ADR-0136).
//!
//! The roster is an immutable projection of the peer table and the bound
//! policy datasets: for each managed peer, its current session's installed
//! import-policy publication, plus each dataset handle with its configured
//! path. The peer manager rebuilds and publishes it whole at its single
//! publication point; nothing edits a published roster. `GetPolicyStats` takes
//! one [`ImportRosterReader::load`] per request and reads the live counters
//! and dataset status the roster designates, without messaging the peer
//! manager or a session.
//!
//! Readers and the publisher never wait on each other: the cell is an
//! `ArcSwap`, whose loads and stores are lock-free. Dropping the publisher
//! (the peer manager exiting or unwinding) closes the cell; a request checks
//! that after capture, so a roster loaded before the owner stopped cannot
//! report its values as success.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::TryLockError;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use rustbgpd_policy::datasets::{DatasetHandle, DatasetStatus};
use rustbgpd_transport::handle::{ImportPolicyStatsError, InstalledImportPolicy};
use rustbgpd_transport::{ImportPolicyTermHits, PeerHandle};
use tokio::sync::watch;

use crate::peer_types::PeerKey;

/// One managed peer's current session, as the roster designates it.
#[derive(Debug, Clone)]
pub struct ImportRosterPeer {
    /// Configured peer identity.
    pub key: PeerKey,
    /// Peer-manager session identity of the designated session.
    pub session_id: u64,
    /// That session's installed import-policy publication.
    pub publication: watch::Receiver<Option<Arc<InstalledImportPolicy>>>,
}

/// One bound policy dataset and its configured source path.
#[derive(Debug, Clone)]
pub struct ImportRosterDataset {
    /// The shared dataset cell compiled chains evaluate against.
    pub handle: Arc<DatasetHandle>,
    /// Configured source path, empty when the binding has none.
    pub path: String,
}

/// One immutable roster publication.
#[derive(Debug, Default)]
pub struct ImportRoster {
    version: u64,
    peers: Vec<ImportRosterPeer>,
    datasets: Arc<[ImportRosterDataset]>,
}

impl ImportRoster {
    /// Publication sequence number; 0 is the empty roster before the first
    /// publication.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Managed peers, ordered by peer key (address, then interface).
    #[must_use]
    pub fn peers(&self) -> &[ImportRosterPeer] {
        &self.peers
    }

    /// Bound datasets, ordered by name.
    #[must_use]
    pub fn datasets(&self) -> &[ImportRosterDataset] {
        &self.datasets
    }

    /// The one managed peer at `address`, or `None` when no peer or several
    /// scoped peers (link-local addresses on different interfaces) use it.
    #[must_use]
    pub fn unique_peer(&self, address: IpAddr) -> Option<&ImportRosterPeer> {
        let start = self
            .peers
            .partition_point(|peer| peer.key.address < address);
        match self.peers.get(start..)? {
            [first, rest @ ..]
                if first.key.address == address
                    && rest.first().is_none_or(|next| next.key.address != address) =>
            {
                Some(first)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
struct RosterCell {
    roster: ArcSwap<ImportRoster>,
    closed: AtomicBool,
}

/// The peer manager's publishing end. Not `Clone`: one owner publishes.
/// Dropping it, on normal exit or unwind, closes the cell for readers.
#[derive(Debug, Default)]
pub struct ImportRosterPublisher {
    cell: Arc<RosterCell>,
    version: u64,
}

impl ImportRosterPublisher {
    /// A publisher whose readers see an empty roster until the first
    /// publication.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A reading end for `GetPolicyStats` listeners.
    #[must_use]
    pub fn reader(&self) -> ImportRosterReader {
        ImportRosterReader {
            cell: Arc::clone(&self.cell),
        }
    }

    /// Replace the published roster with a new projection. Readers holding
    /// an earlier roster keep it until their request ends.
    pub fn publish(
        &mut self,
        mut peers: Vec<ImportRosterPeer>,
        datasets: Arc<[ImportRosterDataset]>,
    ) {
        peers.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        self.version += 1;
        self.cell.roster.store(Arc::new(ImportRoster {
            version: self.version,
            peers,
            datasets,
        }));
    }

    /// The roster readers currently load.
    #[must_use]
    pub fn published(&self) -> Arc<ImportRoster> {
        self.cell.roster.load_full()
    }
}

impl Drop for ImportRosterPublisher {
    fn drop(&mut self) {
        self.cell.closed.store(true, Ordering::Release);
    }
}

/// A reading end of the import roster.
#[derive(Debug, Clone)]
pub struct ImportRosterReader {
    cell: Arc<RosterCell>,
}

impl ImportRosterReader {
    /// Load the current roster as an owned `Arc`, safe to hold across awaits.
    #[must_use]
    pub fn load(&self) -> Arc<ImportRoster> {
        self.cell.roster.load_full()
    }

    /// Whether the publishing peer manager has stopped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.cell.closed.load(Ordering::Acquire)
    }
}

/// Counts for one import capture's audit record.
#[derive(Debug, Default)]
pub struct ImportCaptureProgress {
    /// Publications selected for capture.
    pub selected: usize,
    /// Publications whose counters were read.
    pub read: usize,
    /// Waits taken: Pending publications awaited and busy error-mutex
    /// retries. Installed publications add none.
    pub yields: AtomicU64,
}

/// Read every selected peer's installed import counters in one pass,
/// ordered as `peers` is. Chainless sessions contribute no row. The pass
/// yields only while a publication is Pending or a counter's error mutex is
/// busy; any failure fails the whole capture.
///
/// # Errors
///
/// Deadline expiry, a selected session that exited, or unavailable counters.
pub async fn capture_import(
    peers: &[ImportRosterPeer],
    deadline: tokio::time::Instant,
    progress: &mut ImportCaptureProgress,
) -> Result<Vec<(IpAddr, ImportPolicyTermHits)>, ImportPolicyStatsError> {
    progress.selected = peers.len();
    let mut rows = Vec::with_capacity(peers.len());
    for peer in peers {
        let snapshot = PeerHandle::read_import_policy_counters_counting(
            &peer.publication,
            deadline,
            &progress.yields,
        )
        .await?;
        progress.read += 1;
        if let Some(snapshot) = snapshot {
            rows.push((peer.key.address, snapshot));
        }
    }
    Ok(rows)
}

/// Why a dataset status capture failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatasetCaptureError {
    /// A refresh held a dataset's error lock past the deadline.
    TimedOut,
    /// A dataset's error lock is poisoned.
    Unavailable,
}

/// Read each dataset's status once. A busy error lock is retried with
/// `try_lock` and a yield under `deadline`; it never blocks the thread or
/// the refreshing owner.
///
/// # Errors
///
/// See [`DatasetCaptureError`].
pub async fn capture_datasets(
    datasets: &[ImportRosterDataset],
    deadline: tokio::time::Instant,
) -> Result<Vec<(DatasetStatus, &str)>, DatasetCaptureError> {
    let mut rows = Vec::with_capacity(datasets.len());
    for dataset in datasets {
        let status = loop {
            if deadline <= tokio::time::Instant::now() {
                return Err(DatasetCaptureError::TimedOut);
            }
            match dataset.handle.try_status() {
                Ok(status) => break status,
                Err(TryLockError::WouldBlock) => tokio::task::yield_now().await,
                Err(TryLockError::Poisoned(_)) => return Err(DatasetCaptureError::Unavailable),
            }
        };
        rows.push((status, dataset.path.as_str()));
    }
    Ok(rows)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use rustbgpd_policy::{NamedPolicy, Policy, PolicyAction, PolicyChain, PolicyStatement};

    /// A route context every permit-all statement matches.
    pub(crate) fn route_context() -> rustbgpd_policy::RouteContext<'static> {
        rustbgpd_policy::RouteContext {
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
        }
    }

    /// One named policy with `terms` unconditional permit statements; every
    /// evaluation hits the first.
    pub(crate) fn chain(name: &str, terms: usize) -> PolicyChain {
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
        PolicyChain::from_named(vec![NamedPolicy {
            name: Some(name.to_string()),
            policy: Policy {
                entries: vec![statement; terms],
                default_action: PolicyAction::Deny,
            },
            rpol: None,
        }])
    }

    pub(crate) fn installed(
        generation: u64,
        chain: Option<&PolicyChain>,
    ) -> Arc<InstalledImportPolicy> {
        Arc::new(InstalledImportPolicy::new(
            rustbgpd_transport::SessionIdentity::default(),
            generation,
            chain,
        ))
    }

    pub(crate) fn peer(
        address: &str,
        publication: watch::Receiver<Option<Arc<InstalledImportPolicy>>>,
    ) -> ImportRosterPeer {
        ImportRosterPeer {
            key: PeerKey::new(address.parse().unwrap(), None),
            session_id: 1,
            publication,
        }
    }

    pub(crate) fn dataset(name: &str, path: &str) -> ImportRosterDataset {
        use rustbgpd_policy::datasets::{DatasetData, DatasetKind};
        use rustbgpd_policy::sets::AsnSet;

        ImportRosterDataset {
            handle: Arc::new(DatasetHandle::new(
                name,
                DatasetKind::Asn,
                DatasetData::Asn(AsnSet::new([64500, 64501])),
            )),
            path: path.to_string(),
        }
    }

    /// A publisher whose roster lists `peers` and `datasets`.
    pub(crate) fn publisher(
        peers: Vec<ImportRosterPeer>,
        datasets: Vec<ImportRosterDataset>,
    ) -> ImportRosterPublisher {
        let mut publisher = ImportRosterPublisher::new();
        publisher.publish(peers, datasets.into());
        publisher
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    use std::time::Duration;

    use super::test_support::*;
    use super::*;

    fn far() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(2)
    }

    #[test]
    fn unique_peer_resolves_one_managed_address_only() {
        let (_tx, rx) = watch::channel(None);
        let scoped = |interface: &str| ImportRosterPeer {
            key: PeerKey::new("fe80::1".parse().unwrap(), Some(interface.to_string())),
            session_id: 1,
            publication: rx.clone(),
        };
        let publisher = publisher(
            vec![
                peer("192.0.2.2", rx.clone()),
                scoped("eth1"),
                peer("192.0.2.1", rx.clone()),
                scoped("eth0"),
            ],
            Vec::new(),
        );
        let roster = publisher.reader().load();
        assert_eq!(roster.version(), 1);
        let addresses: Vec<_> = roster.peers().iter().map(|p| p.key.to_string()).collect();
        assert_eq!(
            addresses,
            ["192.0.2.1", "192.0.2.2", "fe80::1%eth0", "fe80::1%eth1"]
        );
        for address in ["192.0.2.1", "192.0.2.2"] {
            assert_eq!(
                roster
                    .unique_peer(address.parse().unwrap())
                    .map(|peer| peer.key.address.to_string()),
                Some(address.to_string())
            );
        }
        assert!(roster.unique_peer("fe80::1".parse().unwrap()).is_none());
        assert!(roster.unique_peer("192.0.2.3".parse().unwrap()).is_none());
        assert!(roster.unique_peer("0.0.0.0".parse().unwrap()).is_none());
    }

    /// Installed publications are read in one poll with no yield: a fleet
    /// capture makes no trip through the run queue. Each counter is read
    /// when the request runs, not cached at publication.
    #[tokio::test]
    async fn installed_fleet_capture_completes_in_one_poll_with_live_counters() {
        let context = route_context();
        let mut senders = Vec::new();
        let mut peers = Vec::new();
        let mut chains = Vec::new();
        for index in 0..1000_u32 {
            let chain = chain("fleet-in", 2);
            let (tx, rx) = watch::channel(Some(installed(0, Some(&chain))));
            let address = std::net::Ipv4Addr::from(0x0a00_0000 + index).to_string();
            peers.push(peer(&address, rx));
            senders.push(tx);
            chains.push(chain);
        }
        let publisher = publisher(peers, Vec::new());
        let roster = publisher.reader().load();
        // Evaluated after publication, with no owner operation between.
        for _ in 0..3 {
            let _ = chains[7].evaluate(&context);
        }
        let mut progress = ImportCaptureProgress::default();
        let rows = {
            let capture = capture_import(roster.peers(), far(), &mut progress);
            tokio::pin!(capture);
            let Poll::Ready(rows) = poll_fn(|cx| Poll::Ready(capture.as_mut().poll(cx))).await
            else {
                panic!("an installed fleet must be captured without yielding");
            };
            rows.unwrap()
        };
        assert_eq!(rows.len(), 1000);
        assert_eq!(
            rows[7].1.evals, 3,
            "live counters, not a publication-time copy"
        );
        assert_eq!(rows[7].1.terms.len(), 2);
        assert_eq!(rows[7].1.terms[0].hits, 3);
        assert_eq!(rows[0].1.evals, 0);
        assert_eq!((progress.selected, progress.read), (1000, 1000));
        assert_eq!(progress.yields.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn capture_waits_for_pending_and_fails_whole_on_closure_or_deadline() {
        let chain = chain("pending-in", 1);
        let (installed_tx, installed_rx) = watch::channel(Some(installed(4, Some(&chain))));
        let (pending_tx, pending_rx) = watch::channel(None);
        let (_chainless_tx, chainless_rx) = watch::channel(Some(installed(0, None)));
        let publisher = publisher(
            vec![
                peer("192.0.2.1", installed_rx),
                peer("192.0.2.2", pending_rx),
                peer("192.0.2.3", chainless_rx),
            ],
            Vec::new(),
        );
        let roster = publisher.reader().load();

        // Pending: awaited, then read; a chainless session adds no row.
        let mut progress = ImportCaptureProgress::default();
        let rows = {
            let capture = capture_import(roster.peers(), far(), &mut progress);
            tokio::pin!(capture);
            assert!(
                poll_fn(|cx| Poll::Ready(capture.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            pending_tx.send_replace(Some(installed(0, Some(&chain))));
            capture.await.unwrap()
        };
        let generations: Vec<_> = rows
            .iter()
            .map(|(peer, row)| (peer.to_string(), row.generation))
            .collect();
        assert_eq!(
            generations,
            [("192.0.2.1".to_string(), 4), ("192.0.2.2".to_string(), 0)]
        );
        assert_eq!((progress.selected, progress.read), (3, 3));
        assert_eq!(progress.yields.load(Ordering::Relaxed), 1);

        // A selected session that exited fails the whole capture.
        drop(installed_tx);
        let error = capture_import(roster.peers(), far(), &mut ImportCaptureProgress::default())
            .await
            .unwrap_err();
        assert_eq!(error, ImportPolicyStatsError::SessionGone);

        // A publication still Pending at the deadline fails it too.
        let (_pending_tx, pending_rx) = watch::channel(None);
        let publisher =
            super::test_support::publisher(vec![peer("192.0.2.4", pending_rx)], Vec::new());
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let error = capture_import(
            publisher.reader().load().peers(),
            deadline,
            &mut ImportCaptureProgress::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(error, ImportPolicyStatsError::TimedOut);
        assert_eq!(tokio::time::Instant::now(), deadline);
    }

    /// A reader holding a loaded roster across an await never delays the
    /// owner's next publication, and keeps its own roster until it drops it.
    #[tokio::test]
    async fn held_roster_does_not_delay_republication() {
        let (_tx, rx) = watch::channel(None);
        let mut publisher = publisher(vec![peer("192.0.2.1", rx)], Vec::new());
        let reader = publisher.reader();
        let held = reader.load();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let holder = tokio::spawn(async move {
            let _ = released.await;
            held.peers().len()
        });
        publisher.publish(Vec::new(), Vec::new().into());
        let current = reader.load();
        assert_eq!(current.version(), 2);
        assert!(current.peers().is_empty());
        release.send(()).unwrap();
        assert_eq!(holder.await.unwrap(), 1, "the held roster is unchanged");
    }

    #[test]
    fn dropping_the_publisher_closes_every_reader() {
        let publisher = ImportRosterPublisher::new();
        let reader = publisher.reader();
        let clone = reader.clone();
        assert!(!reader.is_closed());
        drop(publisher);
        assert!(reader.is_closed() && clone.is_closed());
    }

    /// A refresh holding a dataset's error lock bounds the read by the
    /// deadline instead of blocking the worker thread. With a blocking
    /// `lock()` the capture parks its thread until the lock is released,
    /// so the outer timeout fires first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn held_dataset_error_lock_bounds_the_read_by_its_deadline() {
        let datasets: Arc<[ImportRosterDataset]> = vec![dataset("customers", "c.list")].into();
        // A refresh on another thread holds the error lock.
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let refresh = std::thread::spawn({
            let handle = Arc::clone(&datasets[0].handle);
            move || {
                let _held = handle.hold_error_lock_for_test();
                locked_tx.send(()).unwrap();
                let _ = release_rx.recv();
            }
        });
        locked_rx.recv().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let read = tokio::spawn({
            let datasets = Arc::clone(&datasets);
            async move {
                capture_datasets(&datasets, deadline)
                    .await
                    .map(|rows| rows.len())
            }
        });
        let result = tokio::time::timeout(Duration::from_secs(2), read).await;
        release_tx.send(()).unwrap();
        refresh.join().unwrap();
        assert_eq!(
            result
                .expect("a held error lock must not block the read past its deadline")
                .unwrap(),
            Err(DatasetCaptureError::TimedOut)
        );
        let rows = capture_datasets(&datasets, far()).await.unwrap();
        assert_eq!(rows[0].0.records, 2);
        assert_eq!(rows[0].1, "c.list");
    }
}
