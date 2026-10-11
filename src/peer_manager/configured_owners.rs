use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::sync::Arc;

use rustbgpd_api::peer_types::{
    ConfiguredOwnerPublicationError as PublicationError,
    ConfiguredOwnerPublicationOperation as PublicationOperation,
    ConfiguredOwnerPublicationReceipt as PublicationReceipt, PeerKey,
};
use rustbgpd_rib::RibUpdate;
use rustbgpd_rib::dampening::{DampeningAdmission, DampeningOwner};
use rustbgpd_rib::update::AcceptedDynamicRange;
use tokio::sync::oneshot;

use crate::config::Config;

use super::{PeerManager, RIB_REPLY_TIMEOUT};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum OwnerIdentity {
    Static(PeerKey, u32),
    Dynamic(IpAddr, u8, String, u32),
}

#[derive(Clone)]
struct OwnerEntry {
    owner: Arc<DampeningOwner>,
    // One publication authority per owner; static recovery survives replacement.
    // Dynamic children fork only recovery state, keeping this authority.
    admission: DampeningAdmission,
}

struct PendingPublication {
    receipt: PublicationReceipt,
    reservations: BTreeMap<OwnerIdentity, OwnerEntry>,
}

pub(super) struct ConfiguredOwners {
    committed: BTreeMap<OwnerIdentity, OwnerEntry>,
    pending: Option<PendingPublication>,
    last_publication: PublicationReceipt,
    next_publication: u64,
    next_owner: u64,
}

impl ConfiguredOwners {
    pub(super) fn new(config: &Config) -> Self {
        let mut owners = Self {
            committed: BTreeMap::new(),
            pending: None,
            last_publication: PublicationReceipt(0),
            next_publication: 1,
            next_owner: 1,
        };
        for identity in Self::projection(config) {
            let entry = owners
                .allocate()
                .expect("an allocated configuration cannot exhaust u64 owner identities");
            owners.committed.insert(identity, entry);
        }
        owners
    }

    fn projection(config: &Config) -> BTreeSet<OwnerIdentity> {
        config
            .neighbors
            .iter()
            .filter_map(|neighbor| {
                let address = neighbor.address.parse().ok()?;
                Some(OwnerIdentity::Static(
                    PeerKey::new(address, neighbor.interface.clone()),
                    neighbor.remote_asn,
                ))
            })
            .chain(config.dynamic_neighbors.iter().filter_map(|range| {
                let (address, length) = crate::config::effective_prefix_str(&range.prefix)?;
                Some(OwnerIdentity::Dynamic(
                    address,
                    length,
                    range.peer_group.clone(),
                    range.remote_asn,
                ))
            }))
            .collect()
    }

    fn allocate(&mut self) -> Result<OwnerEntry, PublicationError> {
        let next = self
            .next_owner
            .checked_add(1)
            .ok_or(PublicationError::IdentityExhausted)?;
        let id = NonZeroU64::new(self.next_owner).ok_or(PublicationError::IdentityExhausted)?;
        self.next_owner = next;
        let owner = Arc::new(DampeningOwner::new(id));
        let admission = DampeningAdmission::new(Arc::clone(&owner));
        Ok(OwnerEntry { owner, admission })
    }

    fn begin(&mut self) -> Result<PublicationReceipt, PublicationError> {
        if self.pending.is_some() {
            return Err(PublicationError::StaleAuthority);
        }
        let next = self
            .next_publication
            .checked_add(1)
            .ok_or(PublicationError::IdentityExhausted)?;
        let receipt = PublicationReceipt(self.next_publication);
        self.next_publication = next;
        self.pending = Some(PendingPublication {
            receipt,
            reservations: BTreeMap::new(),
        });
        Ok(receipt)
    }

    fn capture(&mut self, identity: OwnerIdentity) -> Result<Option<OwnerEntry>, PublicationError> {
        let Some(pending) = &self.pending else {
            // Legacy direct lifecycle callers cannot create committed authority.
            return Ok(self.committed.get(&identity).cloned());
        };
        if let Some(entry) = pending.reservations.get(&identity) {
            return Ok(Some(entry.clone()));
        }
        let mut entry = if let Some(entry) = self.committed.get(&identity) {
            entry.clone()
        } else {
            self.allocate()?
        };
        entry.admission = entry.admission.tentative_publication();
        self.pending
            .as_mut()
            .expect("publication remains owned during synchronous reservation")
            .reservations
            .insert(identity, entry.clone());
        Ok(Some(entry))
    }

    fn discard(&mut self, receipt: PublicationReceipt) -> Result<(), PublicationError> {
        if self.pending.as_ref().map(|pending| pending.receipt) != Some(receipt) {
            return Err(PublicationError::StaleAuthority);
        }
        // Clean compensation has restored the prior snapshot and static
        // sessions. Staged transactions reject new dynamic children; existing
        // collisions retain their captured roles. Reload runs inside this actor.
        // Release restored sessions without upgrading their already accepted
        // input, whose publication classification was captured by transport.
        for (identity, entry) in &self.pending.as_ref().unwrap().reservations {
            if self.committed.contains_key(identity) {
                entry.admission.acknowledge_publication();
            }
        }
        self.pending = None;
        Ok(())
    }

    fn prepare(
        &mut self,
        receipt: PublicationReceipt,
        config: &Config,
    ) -> Result<BTreeMap<OwnerIdentity, OwnerEntry>, PublicationError> {
        if self.pending.as_ref().map(|pending| pending.receipt) != Some(receipt) {
            return Err(PublicationError::StaleAuthority);
        }
        Self::projection(config)
            .into_iter()
            .map(|identity| {
                let entry = self
                    .capture(identity.clone())?
                    .ok_or(PublicationError::StaleAuthority)?;
                Ok((identity, entry))
            })
            .collect()
    }
}

impl PeerManager {
    pub(super) fn configured_owner_admission_for_static(
        &mut self,
        peer: PeerKey,
        asn: u32,
    ) -> Result<Option<DampeningAdmission>, PublicationError> {
        Ok(self
            .configured_owners
            .capture(OwnerIdentity::Static(peer, asn))?
            .map(|entry| entry.admission))
    }

    pub(super) fn configured_owner_admission_for_dynamic(
        &mut self,
        range: &AcceptedDynamicRange,
        asn: u32,
    ) -> Result<Option<DampeningAdmission>, PublicationError> {
        Ok(self
            .configured_owners
            .capture(OwnerIdentity::Dynamic(
                range.addr,
                range.prefix_len,
                range.peer_group.clone(),
                asn,
            ))?
            .map(|entry| entry.admission.independent_recovery()))
    }

    async fn send_configured_owners(
        &self,
        receipt: PublicationReceipt,
        owners: Vec<Arc<DampeningOwner>>,
    ) -> Result<(), PublicationError> {
        let (reply, response) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + RIB_REPLY_TIMEOUT;
        tokio::time::timeout_at(
            deadline,
            self.rib_tx.send(RibUpdate::PublishDampeningOwners {
                publication: receipt.0,
                owners,
                reply,
            }),
        )
        .await
        .map_err(|_| {
            PublicationError::RibNotAccepted("RIB owner publication queue timed out".into())
        })?
        .map_err(|error| PublicationError::RibNotAccepted(error.to_string()))?;
        tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| PublicationError::RibAcknowledgementLost)?
            .map_err(|_| PublicationError::RibAcknowledgementLost)?
            .map_err(|error| PublicationError::RibRejected(error.to_string()))
    }

    pub(super) async fn publish_initial_configured_owners(&self) -> Result<(), PublicationError> {
        if self.configured_owners.committed.is_empty() {
            return Ok(());
        }
        self.send_configured_owners(
            self.configured_owners.last_publication,
            self.configured_owners
                .committed
                .values()
                .map(|entry| Arc::clone(&entry.owner))
                .collect(),
        )
        .await
    }

    pub(super) async fn configured_owner_publication(
        &mut self,
        operation: PublicationOperation,
    ) -> Result<PublicationReceipt, PublicationError> {
        match operation {
            PublicationOperation::Begin => self.configured_owners.begin(),
            PublicationOperation::Discard(receipt) => {
                self.configured_owners.discard(receipt)?;
                Ok(receipt)
            }
            PublicationOperation::Publish(receipt) => {
                if receipt == self.configured_owners.last_publication {
                    return Ok(receipt);
                }
                let next = self
                    .configured_owners
                    .prepare(receipt, &self.current_config)?;
                self.send_configured_owners(
                    receipt,
                    next.values()
                        .map(|entry| Arc::clone(&entry.owner))
                        .collect(),
                )
                .await?;
                for entry in next.values() {
                    entry.admission.acknowledge_publication();
                }
                self.configured_owners.committed = next;
                self.configured_owners.pending = None;
                self.configured_owners.last_publication = receipt;
                Ok(receipt)
            }
        }
    }
}
