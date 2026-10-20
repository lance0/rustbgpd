//! ADR-0141 ownership of locally injected keys and lease expiry. The
//! ownership index lives in the RIB actor; only bounded owner-level lease
//! state is shared, behind the lease table's lock.

use std::collections::HashSet;
use std::sync::Arc;

use tracing::warn;

use super::helpers::{LOCAL_PEER, gauge_val};
use super::{AdjRibIn, ExactExportKey, RibManager};
use crate::injection_lease::{
    ExpiredLease, InjectedKey, InjectionTag, MAX_KEYS_PER_OWNER, MAX_LIVE_OWNERS,
};
use crate::route::FlowSpecRouteKey;
use crate::update::RibCommandError;

/// Owner label used once [`MAX_LIVE_OWNERS`] distinct owners have been seen.
const OTHER_OWNER_LABEL: &str = "_other";

#[cfg(test)]
thread_local! {
    /// Called once per key while an expiry is swept, so a test can observe
    /// what the sweep holds.
    pub(super) static EXPIRY_SWEEP_PROBE: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        std::cell::RefCell::new(None);
}

impl RibManager {
    /// The owner and generation `key` is tagged with, if owned.
    pub(crate) fn injection_tag(&self, key: &InjectedKey) -> Option<InjectionTag> {
        self.injected_owners.get(key).cloned()
    }

    /// Capture the lease tags of a page's locally injected rows in the turn
    /// that read them.
    pub(super) fn tag_injected_rows(&self, page: &mut crate::update::RoutePage) {
        if self.injected_owners.is_empty() {
            return;
        }
        let tags: Vec<Option<InjectionTag>> = page
            .routes
            .iter()
            .map(|route| {
                (route.peer == LOCAL_PEER)
                    .then(|| self.injection_tag(&InjectedKey::Unicast(route.prefix, route.path_id)))
                    .flatten()
            })
            .collect();
        if tags.iter().any(Option::is_some) {
            page.injection = tags;
        }
    }

    /// Refuse a change to `key` by `owner` (`""` = unowned) when the key is
    /// held by a different owner, or by no owner when `owner` is set.
    pub(super) fn check_injected_owner(
        &self,
        key: &InjectedKey,
        owner: &str,
    ) -> Result<(), RibCommandError> {
        let holder = self.injected_owners.get(key).map_or("", |tag| &*tag.owner);
        if holder == owner {
            Ok(())
        } else if holder.is_empty() {
            Err(RibCommandError::FailedPrecondition(format!(
                "key is held by no owner, not {owner:?}"
            )))
        } else {
            Err(RibCommandError::FailedPrecondition(format!(
                "key is held by owner {holder:?}"
            )))
        }
    }

    /// Admit a leased add of `key` in the turn that commits it: refuse an
    /// ownership mismatch or a new key past [`MAX_KEYS_PER_OWNER`], then join
    /// or start the owner's lease, then tag the key. A present unowned key is
    /// never adopted. Nothing changes on a refusal.
    pub(super) fn admit_injected_lease(
        &mut self,
        key: &InjectedKey,
        present: bool,
        owner: &str,
        lease_seconds: u32,
    ) -> Result<InjectionTag, RibCommandError> {
        match self.injected_owners.get(key) {
            Some(tag) if &*tag.owner != owner => {
                return Err(RibCommandError::FailedPrecondition(format!(
                    "key is held by owner {:?}",
                    tag.owner
                )));
            }
            None if present => {
                return Err(RibCommandError::FailedPrecondition(
                    "key is held by no owner; delete it before a leased add".to_string(),
                ));
            }
            // A new key for this owner; keys awaiting expiry still count.
            None if self
                .owner_keys
                .get(owner)
                .is_some_and(|keys| keys.len() >= MAX_KEYS_PER_OWNER) =>
            {
                return Err(RibCommandError::ResourceExhausted(format!(
                    "owner {owner:?} already holds {MAX_KEYS_PER_OWNER} injected keys"
                )));
            }
            _ => {}
        }
        let tag = self
            .injection_leases
            .admit(owner, lease_seconds)
            .map_err(super::distribution::lease_rejection)?;
        self.owner_keys
            .entry(Arc::clone(&tag.owner))
            .or_default()
            .insert(key.clone());
        self.injected_owners.insert(key.clone(), tag.clone());
        self.metrics
            .set_injection_leases(gauge_val(self.injection_leases.live_owner_count()));
        Ok(tag)
    }

    /// Drop `key`'s ownership tag after the RIB removed it, returning it.
    pub(super) fn forget_injected(&mut self, key: &InjectedKey) -> Option<InjectionTag> {
        let tag = self.injected_owners.remove(key)?;
        if let Some(keys) = self.owner_keys.get_mut(&tag.owner) {
            keys.remove(key);
            if keys.is_empty() {
                self.owner_keys.remove(&tag.owner);
            }
        }
        Some(tag)
    }

    /// Untag and return every key of `expired.owner` tagged at or below its
    /// generation. Keys a newer generation retagged are kept.
    fn take_expired_keys(&mut self, expired: &ExpiredLease) -> Vec<InjectedKey> {
        let Some(keys) = self.owner_keys.get_mut(&expired.owner) else {
            return Vec::new();
        };
        let injected_owners = &mut self.injected_owners;
        let mut dead = Vec::new();
        keys.retain(|key| {
            let dies = injected_owners.get(key).is_some_and(|tag| {
                tag.generation.incarnation == expired.generation.incarnation
                    && tag.generation.sequence <= expired.generation.sequence
            });
            if dies {
                injected_owners.remove(key);
                dead.push(key.clone());
            }
            !dies
        });
        if keys.is_empty() {
            self.owner_keys.remove(&expired.owner);
        }
        dead
    }

    pub(super) fn handle_expire_injection_leases(&mut self, leases: &[ExpiredLease]) {
        let applied_at = tokio::time::Instant::now();
        let mut unicast = HashSet::new();
        let mut flowspec = HashSet::new();
        let mut retired = Vec::new();
        for lease in leases {
            let keys = self.take_expired_keys(lease);
            let rib = self
                .ribs
                .entry(LOCAL_PEER)
                .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
            let (mut unicast_count, mut flowspec_count) = (0usize, 0usize);
            for key in keys {
                #[cfg(test)]
                EXPIRY_SWEEP_PROBE.with(|probe| {
                    if let Some(probe) = probe.borrow_mut().as_mut() {
                        probe();
                    }
                });
                match key {
                    InjectedKey::Unicast(prefix, path_id) => {
                        if rib.withdraw(&prefix, path_id) {
                            unicast_count += 1;
                            unicast.insert(prefix);
                            retired.push(ExactExportKey::Unicast(prefix, path_id));
                        }
                    }
                    InjectedKey::FlowSpec(key) => {
                        let route_key = FlowSpecRouteKey {
                            afi: key.afi,
                            rule: key.rule.clone(),
                            path_id: 0,
                        };
                        if rib.withdraw_flowspec(&route_key) {
                            flowspec_count += 1;
                            retired.push(ExactExportKey::FlowSpec(key.clone()));
                            flowspec.insert(key);
                        }
                    }
                }
            }
            let lag = applied_at.saturating_duration_since(lease.deadline);
            warn!(
                owner = %lease.owner,
                incarnation = lease.generation.incarnation,
                sequence = lease.generation.sequence,
                unicast_withdrawn = unicast_count,
                flowspec_withdrawn = flowspec_count,
                lag_ms = u64::try_from(lag.as_millis()).unwrap_or(u64::MAX),
                "injection lease expired; withdrew the owner's routes"
            );
            let label = self.lease_owner_label(&lease.owner);
            self.metrics.record_injection_lease_expiry(&label);
        }
        self.metrics
            .set_injection_leases(gauge_val(self.injection_leases.live_owner_count()));
        let rib = self
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
        let (unicast_lens, flowspec_lens) = (rib.unicast_lens(), rib.flowspec_lens());
        if !unicast.is_empty() {
            self.finish_local_unicast_withdrawals(&unicast, unicast_lens);
        }
        if !flowspec.is_empty() {
            super::helpers::set_rib_prefixes(
                &self.metrics,
                &LOCAL_PEER.to_string(),
                super::helpers::FLOWSPEC_FAMILIES,
                flowspec_lens,
            );
            self.recompute_and_distribute_flowspec(&flowspec);
        }
        self.retire_exact_export_rejections(retired);
    }

    /// The bounded owner label for the expiry counter.
    fn lease_owner_label(&mut self, owner: &Arc<str>) -> Arc<str> {
        if self.lease_metric_owners.contains(owner) {
            return Arc::clone(owner);
        }
        if self.lease_metric_owners.len() < MAX_LIVE_OWNERS {
            self.lease_metric_owners.insert(Arc::clone(owner));
            return Arc::clone(owner);
        }
        Arc::from(OTHER_OWNER_LABEL)
    }
}
