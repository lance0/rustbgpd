//! Apply ADR-0141 lease expiry: withdraw every key of each expired generation
//! in one RIB turn.

use std::collections::HashSet;
use std::sync::Arc;

use tracing::warn;

use super::helpers::{LOCAL_PEER, gauge_val};
use super::{AdjRibIn, ExactExportKey, RibManager};
use crate::injection_lease::{ExpiredLease, InjectedKey, MAX_LIVE_OWNERS};
use crate::route::FlowSpecRouteKey;

/// Owner label used once [`MAX_LIVE_OWNERS`] distinct owners have been seen.
const OTHER_OWNER_LABEL: &str = "_other";

impl RibManager {
    pub(super) fn handle_expire_injection_leases(&mut self, leases: &[ExpiredLease]) {
        let applied_at = tokio::time::Instant::now();
        let mut unicast = HashSet::new();
        let mut flowspec = HashSet::new();
        let mut retired = Vec::new();
        for lease in leases {
            let keys = self.injection_leases.take_expired_keys(lease);
            let rib = self
                .ribs
                .entry(LOCAL_PEER)
                .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
            let (mut unicast_count, mut flowspec_count) = (0usize, 0usize);
            for key in keys {
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
            .set_injection_leases(gauge_val(self.injection_leases.owner_count()));
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
