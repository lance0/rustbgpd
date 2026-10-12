//! Accounting and `block` admission for the non-unicast per-family bounds
//! (`max_prefixes_<family>`). Counts follow the unicast rule: unique accepted
//! routes, with the Add-Path paths of one route collapsed to one slot.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use rustbgpd_rib::{
    EvpnRibRoute, FlowSpecKey, FlowSpecRoute, LabeledRibRoute, LabeledRibRouteKey, RtcRibRoute,
    VpnRibRoute, VpnRibRouteKey,
};
use rustbgpd_wire::{Afi, Prefix, VpnRouteKey};

use super::{MaxPrefixScope, PeerSession};
use crate::config::PrefixLimitFamily;

const fn afi_index(afi: Afi) -> usize {
    match afi {
        Afi::Ipv6 => 1,
        _ => 0,
    }
}

/// Unique accepted identities of a table that holds both IPv4 and IPv6
/// routes, per AFI. Without Add-Path every key is its own identity and only
/// the counters move; under Add-Path receive `paths` reference-counts each
/// identity, like the unicast `known_prefix_refcounts`.
pub(super) struct UniqueAfiCounts<U> {
    paths: HashMap<U, usize>,
    counts: [usize; 2],
}

impl<U> Default for UniqueAfiCounts<U> {
    fn default() -> Self {
        Self {
            paths: HashMap::new(),
            counts: [0; 2],
        }
    }
}

impl<U: Eq + Hash> UniqueAfiCounts<U> {
    /// Record a newly accepted key; `identity` is `Some` under Add-Path.
    fn add(&mut self, afi: Afi, identity: Option<U>) {
        let first = identity.is_none_or(|identity| {
            let paths = self.paths.entry(identity).or_default();
            *paths += 1;
            *paths == 1
        });
        if first {
            self.counts[afi_index(afi)] += 1;
        }
    }

    /// Release a removed key; `identity` is `Some` under Add-Path.
    fn remove(&mut self, afi: Afi, identity: Option<U>) {
        let last = identity.is_none_or(|identity| match self.paths.get_mut(&identity) {
            Some(paths) if *paths > 1 => {
                *paths -= 1;
                false
            }
            Some(_) => {
                self.paths.remove(&identity);
                true
            }
            None => {
                debug_assert!(false, "per-family Add-Path refcount missing an identity");
                false
            }
        });
        if last {
            let count = &mut self.counts[afi_index(afi)];
            *count = count.saturating_sub(1);
        }
    }

    fn contains(&self, identity: &U) -> bool {
        self.paths.contains_key(identity)
    }

    fn count(&self, afi: Afi) -> usize {
        self.counts[afi_index(afi)]
    }

    pub(super) fn clear(&mut self) {
        self.paths.clear();
        self.counts = [0; 2];
    }
}

impl PeerSession {
    /// Current per-family usage, consistent with the unicast accepted count.
    pub(super) fn family_prefix_usage(&self, family: PrefixLimitFamily) -> usize {
        let (afi, _) = family.afi_safi();
        match family {
            PrefixLimitFamily::L3vpnIpv4 | PrefixLimitFamily::L3vpnIpv6 => {
                self.vpn_counts.count(afi)
            }
            PrefixLimitFamily::Ipv4LabeledUnicast | PrefixLimitFamily::Ipv6LabeledUnicast => {
                self.labeled_counts.count(afi)
            }
            PrefixLimitFamily::L2vpnEvpn => self.known_evpn.len(),
            PrefixLimitFamily::Ipv4Flowspec | PrefixLimitFamily::Ipv6Flowspec => {
                self.flowspec_counts[afi_index(afi)]
            }
            PrefixLimitFamily::Rtc => self.known_rtc.len(),
        }
    }

    pub(super) fn remember_flowspec(&mut self, key: FlowSpecKey) {
        let afi = key.afi;
        if self.known_flowspec.insert(key) {
            self.flowspec_counts[afi_index(afi)] += 1;
        }
    }

    pub(super) fn forget_flowspec(&mut self, key: &FlowSpecKey) -> bool {
        let removed = self.known_flowspec.remove(key);
        if removed {
            let count = &mut self.flowspec_counts[afi_index(key.afi)];
            *count = count.saturating_sub(1);
        }
        removed
    }

    fn vpn_identity(&self, key: &VpnRibRouteKey) -> Option<VpnRouteKey> {
        self.receives_add_path_for_family(key.afi_safi())
            .then_some(key.nlri_key)
    }

    pub(super) fn remember_vpn(&mut self, key: VpnRibRouteKey) {
        let afi = key.afi_safi().0;
        let identity = self.vpn_identity(&key);
        if self.known_vpn.insert(key) {
            self.vpn_counts.add(afi, identity);
        }
    }

    pub(super) fn forget_vpn(&mut self, key: &VpnRibRouteKey) -> bool {
        let removed = self.known_vpn.remove(key);
        if removed {
            let identity = self.vpn_identity(key);
            self.vpn_counts.remove(key.afi_safi().0, identity);
        }
        removed
    }

    fn labeled_identity(&self, key: LabeledRibRouteKey) -> Option<Prefix> {
        self.receives_add_path_for_family(key.afi_safi())
            .then_some(key.prefix)
    }

    pub(super) fn remember_labeled(&mut self, key: LabeledRibRouteKey) {
        let identity = self.labeled_identity(key);
        if self.known_labeled.insert(key) {
            self.labeled_counts.add(key.afi_safi().0, identity);
        }
    }

    pub(super) fn forget_labeled(&mut self, key: &LabeledRibRouteKey) -> bool {
        let removed = self.known_labeled.remove(key);
        if removed {
            let identity = self.labeled_identity(*key);
            self.labeled_counts.remove(key.afi_safi().0, identity);
        }
        removed
    }

    /// Whether a VPN route's identity (RD + prefix, Add-Path collapsed)
    /// already holds an accepted slot.
    fn vpn_identity_accepted(&self, key: &VpnRibRouteKey) -> bool {
        match self.vpn_identity(key) {
            Some(identity) => self.vpn_counts.contains(&identity),
            None => self.known_vpn.contains(key),
        }
    }

    /// Labeled sibling of [`Self::vpn_identity_accepted`].
    fn labeled_identity_accepted(&self, key: &LabeledRibRouteKey) -> bool {
        match self.labeled_identity(*key) {
            Some(prefix) => self.labeled_counts.contains(&prefix),
            None => self.known_labeled.contains(key),
        }
    }

    pub(super) fn block_over_limit_flowspec(&mut self, announced: &mut Vec<FlowSpecRoute>) {
        self.block_over_limit_family_routes(announced, |session, route| {
            let key = route.selection_key();
            let family = match key.afi {
                Afi::Ipv6 => PrefixLimitFamily::Ipv6Flowspec,
                _ => PrefixLimitFamily::Ipv4Flowspec,
            };
            let accepted = session.known_flowspec.contains(&key);
            (family, key, accepted)
        });
    }

    pub(super) fn block_over_limit_evpn(&mut self, announced: &mut Vec<EvpnRibRoute>) {
        self.block_over_limit_family_routes(announced, |session, route| {
            let key = route.key();
            let accepted = session.known_evpn.contains(&key);
            (PrefixLimitFamily::L2vpnEvpn, key, accepted)
        });
    }

    pub(super) fn block_over_limit_vpn(&mut self, announced: &mut Vec<VpnRibRoute>) {
        self.block_over_limit_family_routes(announced, |session, route| {
            let key = route.key();
            let family = match key.afi_safi().0 {
                Afi::Ipv6 => PrefixLimitFamily::L3vpnIpv6,
                _ => PrefixLimitFamily::L3vpnIpv4,
            };
            let accepted = session.vpn_identity_accepted(&key);
            (family, key.nlri_key, accepted)
        });
    }

    pub(super) fn block_over_limit_labeled(&mut self, announced: &mut Vec<LabeledRibRoute>) {
        self.block_over_limit_family_routes(announced, |session, route| {
            let key = route.key();
            let family = match key.afi_safi().0 {
                Afi::Ipv6 => PrefixLimitFamily::Ipv6LabeledUnicast,
                _ => PrefixLimitFamily::Ipv4LabeledUnicast,
            };
            (family, key.prefix, session.labeled_identity_accepted(&key))
        });
    }

    pub(super) fn block_over_limit_rtc(&mut self, announced: &mut Vec<RtcRibRoute>) {
        self.block_over_limit_family_routes(announced, |session, route| {
            let key = route.key();
            let accepted = session.known_rtc.contains(&key);
            (PrefixLimitFamily::Rtc, key, accepted)
        });
    }

    /// Under `Block`, drop every announced route of a bounded family that
    /// would take a net-new slot beyond the family's bound, before it is
    /// accounted or delivered. A route whose identity is already accepted
    /// (attribute change, another Add-Path path) always passes; withdrawals in
    /// the same UPDATE have already freed their slots. `classify` returns the
    /// route's family, its identity, and whether that identity is accepted.
    fn block_over_limit_family_routes<R, I: Eq + Hash>(
        &mut self,
        announced: &mut Vec<R>,
        classify: impl Fn(&Self, &R) -> (PrefixLimitFamily, I, bool),
    ) {
        if !self.blocks_over_limit()
            || announced.is_empty()
            || !self.config.max_prefixes_family.any()
        {
            return;
        }
        let mut reserved = HashSet::new();
        let mut reserved_counts = [0_usize; PrefixLimitFamily::ALL.len()];
        let mut blocked = [false; PrefixLimitFamily::ALL.len()];
        announced.retain(|route| {
            let (family, identity, accepted) = classify(self, route);
            if accepted || reserved.contains(&identity) {
                return true;
            }
            let Some(bound) = self.config.max_prefixes_family.get(family) else {
                return true;
            };
            let index = family as usize;
            if self
                .family_prefix_usage(family)
                .saturating_add(reserved_counts[index])
                >= bound as usize
            {
                blocked[index] = true;
                return false;
            }
            reserved.insert(identity);
            reserved_counts[index] += 1;
            true
        });
        for family in PrefixLimitFamily::ALL {
            if blocked[family as usize] {
                self.note_max_prefix_block(MaxPrefixScope::Family(family));
            }
        }
    }
}
