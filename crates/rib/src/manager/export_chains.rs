//! The RIB's installed export chains and their published roster (ADR-0136).
//!
//! The per-peer export map and the global fallback slot live here, behind
//! accessors: every mutation advances a change version, and nothing outside
//! this module can change a chain without doing so. The run loop calls
//! [`ExportChains::publish_if_changed`] in one place, after a completed unit
//! of work and never between the `CommitMembers` batches of a grouped
//! transition, so the published roster is always the projection of a
//! completed operation.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use rustbgpd_policy::PolicyChain;

use crate::export_roster::{ExportRosterPeer, ExportRosterPublisher, ExportRosterReader};

pub(super) struct ExportChains {
    global: Option<PolicyChain>,
    peers: HashMap<IpAddr, Option<PolicyChain>>,
    /// Advanced by every mutation.
    version: u64,
    /// The version the published roster projects.
    published: u64,
    /// Dropped with the RIB manager, closing the cell.
    publisher: ExportRosterPublisher,
}

impl ExportChains {
    /// Install the global fallback and publish the first roster.
    pub(super) fn new(global: Option<PolicyChain>) -> Self {
        let mut chains = Self {
            global,
            peers: HashMap::new(),
            version: 1,
            published: 0,
            publisher: ExportRosterPublisher::new(),
        };
        chains.publish_if_changed();
        chains
    }

    /// The global fallback chain.
    pub(super) fn global(&self) -> Option<&PolicyChain> {
        self.global.as_ref()
    }

    /// `peer`'s own entry: `Some(None)` when explicitly disabled, `None`
    /// when the peer falls back to the global chain.
    pub(super) fn get(&self, peer: &IpAddr) -> Option<&Option<PolicyChain>> {
        self.peers.get(peer)
    }

    /// The chain that evaluates `peer`'s exports: per-peer if set, else
    /// global.
    pub(super) fn for_peer(&self, peer: IpAddr) -> Option<&PolicyChain> {
        match self.peers.get(&peer) {
            Some(chain) => chain.as_ref(),
            None => self.global.as_ref(),
        }
    }

    #[cfg(test)]
    pub(super) fn contains_key(&self, peer: &IpAddr) -> bool {
        self.peers.contains_key(peer)
    }

    /// Install `peer`'s entry (`None` disables export policy for it).
    pub(super) fn insert(&mut self, peer: IpAddr, chain: Option<PolicyChain>) {
        self.version += 1;
        self.peers.insert(peer, chain);
    }

    /// Remove `peer`'s entry, so it falls back to the global chain.
    pub(super) fn remove(&mut self, peer: &IpAddr) {
        if self.peers.remove(peer).is_some() {
            self.version += 1;
        }
    }

    #[cfg(test)]
    pub(super) fn set_global(&mut self, global: Option<PolicyChain>) {
        self.version += 1;
        self.global = global;
    }

    /// A reading end for `GetPolicyStats` listeners.
    pub(super) fn reader(&self) -> ExportRosterReader {
        self.publisher.reader()
    }

    /// Publish the projection if any mutation happened since the last
    /// publication. Returns whether it published.
    pub(super) fn publish_if_changed(&mut self) -> bool {
        if self.version == self.published {
            return false;
        }
        let (peers, global) = self.projection();
        self.publisher.publish(peers, global);
        self.published = self.version;
        true
    }

    /// The roster this state projects. Creates an installed chain's counter
    /// instance if nothing has yet, so an installed chain always has one.
    fn projection(
        &self,
    ) -> (
        Vec<ExportRosterPeer>,
        Option<Arc<rustbgpd_policy::PolicyHitCounters>>,
    ) {
        let counters = |chain: &PolicyChain| Arc::clone(chain.hit_counters());
        (
            self.peers
                .iter()
                .map(|(peer, chain)| (*peer, chain.as_ref().map(counters)))
                .collect(),
            self.global.as_ref().map(counters),
        )
    }

    /// Published rosters since construction.
    #[cfg(test)]
    pub(super) fn publications(&self) -> u64 {
        self.publisher.published().version()
    }

    /// Test builds: when nothing is pending publication, the published
    /// roster is exactly this state's projection, instance for instance.
    #[cfg(test)]
    pub(super) fn assert_published(&self) {
        if self.version != self.published {
            return;
        }
        let published = self.publisher.published();
        let (mut peers, global) = self.projection();
        peers.sort_unstable_by_key(|(peer, _)| *peer);
        let ids = |peers: &[ExportRosterPeer]| -> Vec<(IpAddr, Option<u64>)> {
            peers
                .iter()
                .map(|(peer, counters)| (*peer, counters.as_ref().map(|c| c.id())))
                .collect()
        };
        assert_eq!(
            ids(published.peers()),
            ids(&peers),
            "published export roster differs from the RIB's export map"
        );
        assert_eq!(
            published.global().map(|c| c.id()),
            global.map(|c| c.id()),
            "published export roster differs from the RIB's global slot"
        );
    }
}

#[cfg(test)]
impl std::ops::Index<&IpAddr> for ExportChains {
    type Output = Option<PolicyChain>;

    fn index(&self, peer: &IpAddr) -> &Self::Output {
        &self.peers[peer]
    }
}
