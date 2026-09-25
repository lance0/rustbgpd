//! The managed-peer table and its import-roster publication point
//! (ADR-0136).
//!
//! The table owns every managed peer's current session handle and session
//! identity. Its fields are private, and so are those two fields of
//! [`ManagedPeer`]: code outside this module cannot insert, remove or drain a
//! peer, or swap a peer's session, without going through a method here, and
//! each such method republishes the import roster before it returns. Mutable
//! access to the rest of a peer's state ([`ManagedPeerState`]) does not
//! reach the session fields. Dataset-binding changes use
//! [`PeerTable::set_datasets`], which republishes the same way.

use std::collections::HashMap;
use std::collections::hash_map;
use std::sync::Arc;

use rustbgpd_api::import_roster::{
    ImportRosterDataset, ImportRosterPeer, ImportRosterPublisher, ImportRosterReader,
};
use rustbgpd_api::peer_types::PeerKey;
use rustbgpd_transport::PeerHandle;

use super::ManagedPeerState;
use crate::config::Config;

/// One managed peer: its current session and the manager's state for it.
pub(super) struct ManagedPeer {
    handle: PeerHandle,
    session_id: u64,
    state: ManagedPeerState,
}

impl ManagedPeer {
    pub(super) fn new(handle: PeerHandle, session_id: u64, state: ManagedPeerState) -> Self {
        Self {
            handle,
            session_id,
            state,
        }
    }

    /// The current session's handle.
    pub(super) fn handle(&self) -> &PeerHandle {
        &self.handle
    }

    /// The current session's peer-manager identity.
    pub(super) fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Take a peer that is no longer in the table apart, for example to
    /// retire its session and re-insert its state with a new one.
    pub(super) fn into_parts(self) -> (PeerHandle, u64, ManagedPeerState) {
        (self.handle, self.session_id, self.state)
    }
}

impl std::ops::Deref for ManagedPeer {
    type Target = ManagedPeerState;

    fn deref(&self) -> &ManagedPeerState {
        &self.state
    }
}

/// Every managed peer, keyed by peer identity, plus the published roster.
pub(super) struct PeerTable {
    peers: HashMap<PeerKey, ManagedPeer>,
    datasets: Arc<[ImportRosterDataset]>,
    publisher: ImportRosterPublisher,
}

impl PeerTable {
    pub(super) fn new(config: &Config) -> Self {
        let mut table = Self {
            peers: HashMap::new(),
            datasets: dataset_projection(config),
            publisher: ImportRosterPublisher::new(),
        };
        table.publish();
        table
    }

    /// A reading end for `GetPolicyStats`.
    pub(super) fn roster(&self) -> ImportRosterReader {
        self.publisher.reader()
    }

    pub(super) fn get(&self, key: &PeerKey) -> Option<&ManagedPeer> {
        self.peers.get(key)
    }

    pub(super) fn get_mut(&mut self, key: &PeerKey) -> Option<&mut ManagedPeerState> {
        self.peers.get_mut(key).map(|peer| &mut peer.state)
    }

    /// Mutable state together with the current session's handle, which
    /// stays read-only.
    pub(super) fn get_mut_with_handle(
        &mut self,
        key: &PeerKey,
    ) -> Option<(&PeerHandle, &mut ManagedPeerState)> {
        self.peers
            .get_mut(key)
            .map(|peer| (&peer.handle, &mut peer.state))
    }

    pub(super) fn contains_key(&self, key: &PeerKey) -> bool {
        self.peers.contains_key(key)
    }

    pub(super) fn len(&self) -> usize {
        self.peers.len()
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub(super) fn keys(&self) -> hash_map::Keys<'_, PeerKey, ManagedPeer> {
        self.peers.keys()
    }

    pub(super) fn values(&self) -> hash_map::Values<'_, PeerKey, ManagedPeer> {
        self.peers.values()
    }

    pub(super) fn iter(&self) -> hash_map::Iter<'_, PeerKey, ManagedPeer> {
        self.peers.iter()
    }

    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut ManagedPeerState> {
        self.peers.values_mut().map(|peer| &mut peer.state)
    }

    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = (&PeerKey, &mut ManagedPeerState)> {
        self.peers
            .iter_mut()
            .map(|(key, peer)| (key, &mut peer.state))
    }

    pub(super) fn insert(&mut self, key: PeerKey, peer: ManagedPeer) -> Option<ManagedPeer> {
        #[cfg(test)]
        self.assert_published();
        let previous = self.peers.insert(key, peer);
        self.publish();
        previous
    }

    pub(super) fn remove(&mut self, key: &PeerKey) -> Option<ManagedPeer> {
        #[cfg(test)]
        self.assert_published();
        let removed = self.peers.remove(key);
        self.publish();
        removed
    }

    /// Remove every peer, publishing the empty roster.
    pub(super) fn drain(&mut self) -> Vec<(PeerKey, ManagedPeer)> {
        #[cfg(test)]
        self.assert_published();
        let drained = self.peers.drain().collect();
        self.publish();
        drained
    }

    /// Make `handle` the peer's current session and return the one it
    /// replaces. `None` (and no change) when the peer is not managed.
    pub(super) fn replace_handle(
        &mut self,
        key: &PeerKey,
        handle: PeerHandle,
        session_id: u64,
    ) -> Option<(PeerHandle, u64)> {
        #[cfg(test)]
        self.assert_published();
        let peer = self.peers.get_mut(key)?;
        let previous = (
            std::mem::replace(&mut peer.handle, handle),
            std::mem::replace(&mut peer.session_id, session_id),
        );
        self.publish();
        Some(previous)
    }

    /// Adopt `config`'s dataset bindings. Every change of the live config's
    /// bindings, including wholesale replacement, goes through here.
    pub(super) fn set_datasets(&mut self, config: &Config) {
        #[cfg(test)]
        self.assert_published();
        self.datasets = dataset_projection(config);
        self.publish();
    }

    /// The single publication point: rebuild the roster from the table.
    fn publish(&mut self) {
        let peers = self
            .peers
            .iter()
            .map(|(key, peer)| ImportRosterPeer {
                key: key.clone(),
                session_id: peer.session_id,
                publication: peer.handle.import_policy_counters(),
            })
            .collect();
        self.publisher.publish(peers, Arc::clone(&self.datasets));
        #[cfg(test)]
        self.assert_published();
    }

    /// Test builds: the published roster is exactly the table's projection.
    /// Every mutator checks it on entry (so a predecessor that skipped its
    /// republication fails the next mutation) and after publishing.
    #[cfg(test)]
    pub(super) fn assert_published(&self) {
        let published = self.publisher.published();
        let mut expected: Vec<_> = self.peers.iter().collect();
        expected.sort_unstable_by(|a, b| a.0.cmp(b.0));
        assert_eq!(
            published.peers().len(),
            expected.len(),
            "published roster lists every managed peer"
        );
        for (row, (key, peer)) in published.peers().iter().zip(expected) {
            assert_eq!(&row.key, key, "published roster keys match the table");
            assert_eq!(row.session_id, peer.session_id, "{key:?} session identity");
            assert!(
                row.publication
                    .same_channel(&peer.handle.import_policy_counters()),
                "{key:?} publication is the current session's"
            );
        }
        assert!(
            same_datasets(published.datasets(), &self.datasets),
            "published datasets are the table's"
        );
    }
}

impl std::ops::Index<&PeerKey> for PeerTable {
    type Output = ManagedPeer;

    fn index(&self, key: &PeerKey) -> &ManagedPeer {
        &self.peers[key]
    }
}

impl<'a> IntoIterator for &'a PeerTable {
    type Item = (&'a PeerKey, &'a ManagedPeer);
    type IntoIter = hash_map::Iter<'a, PeerKey, ManagedPeer>;

    fn into_iter(self) -> Self::IntoIter {
        self.peers.iter()
    }
}

/// Bound datasets and their configured paths, ordered by name.
pub(super) fn dataset_projection(config: &Config) -> Arc<[ImportRosterDataset]> {
    let mut datasets: Vec<_> = config
        .policy
        .dataset_bindings
        .handles()
        .map(|handle| ImportRosterDataset {
            handle: Arc::clone(handle),
            path: config
                .policy
                .datasets
                .get(handle.name().as_ref())
                .map(|entry| entry.path.clone())
                .unwrap_or_default(),
        })
        .collect();
    datasets.sort_unstable_by(|a, b| a.handle.name().cmp(b.handle.name()));
    datasets.into()
}

/// Same bindings: identical handles and paths, in order.
#[cfg(test)]
pub(super) fn same_datasets(a: &[ImportRosterDataset], b: &[ImportRosterDataset]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(a, b)| Arc::ptr_eq(&a.handle, &b.handle) && a.path == b.path)
}
