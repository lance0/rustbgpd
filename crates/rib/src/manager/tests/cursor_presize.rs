//! Work counts shared by the cursor presize tests of the VPN, labeled and
//! EVPN walks: in how many steps a receiver's own table changed capacity,
//! and how full it was then.

use super::*;
use crate::outbound_credit::CHUNK_ROWS;

/// The table size under which a cursor step may size the table for the
/// rest of the walk.
pub(super) const PRESIZE_ROWS: usize = 2 * CHUNK_ROWS;

/// Capacity changes of one receiver's walk tables (a route index and a key
/// index), read once per step.
#[derive(Debug, Default)]
pub(super) struct Growth {
    capacities: [usize; 2],
    /// Steps in which each index changed capacity.
    pub(super) rebuilds: [usize; 2],
    /// Of those, steps that found the index already allocated.
    pub(super) resized: [usize; 2],
    /// Most rows the table held after a step that changed a capacity.
    pub(super) rows_at_rebuild: usize,
}

impl Growth {
    /// The table after one step: `rows` routes, `capacities` of its two
    /// indexes.
    pub(super) fn observe(&mut self, rows: usize, capacities: [usize; 2]) {
        for (index, &capacity) in capacities.iter().enumerate() {
            if capacity != self.capacities[index] {
                self.rebuilds[index] += 1;
                self.resized[index] += usize::from(self.capacities[index] != 0);
                self.rows_at_rebuild = self.rows_at_rebuild.max(rows);
            }
        }
        self.capacities = capacities;
    }

    /// At most one capacity change per index over the walk, and none once
    /// the table was past the presize limit.
    pub(super) fn assert_sized_once(&self, case: &str) {
        self.assert_sized_per_walk(1, case);
    }

    /// Two AFIs filling one table: each index is allocated empty, then
    /// rebuilt at most once, and not once the table was past the presize
    /// limit. The first AFI's step allocates the table; the step that
    /// gives the second AFI its own rate sizes it for both. Sizing it at
    /// the first step would apply the first AFI's acceptance to the
    /// second's keys.
    pub(super) fn assert_sized_once_for_two_afis(&self, case: &str) {
        assert!(
            self.resized.iter().all(|&resized| resized <= 1),
            "{case}: a populated index rebuilt in {:?} steps",
            self.resized
        );
        self.assert_sized_per_walk(2, case);
    }

    fn assert_sized_per_walk(&self, walks: usize, case: &str) {
        assert!(
            self.rebuilds.iter().all(|&rebuilds| rebuilds <= walks),
            "{case}: capacity changed in {:?} steps (route index, key index)",
            self.rebuilds
        );
        assert!(
            self.rows_at_rebuild <= PRESIZE_ROWS,
            "{case}: a capacity change at {} rows",
            self.rows_at_rebuild
        );
    }
}

/// Capacity of an index holding `len` entries, at most 2.3 times `len`:
/// the reserve followed what the receiver accepted, within hashbrown's
/// power-of-two rounding.
pub(super) fn assert_fitted(capacity: usize, len: usize, case: &str) {
    assert!(len > 0, "{case}: the table is empty");
    assert!(
        capacity * 10 <= len * 23,
        "{case}: capacity {capacity} for {len} entries ({}.{:02}x)",
        capacity / len,
        capacity % len * 100 / len
    );
}

/// An export chain that denies every route with a MED of 1 or more.
pub(super) fn deny_med_chain() -> rustbgpd_policy::PolicyChain {
    rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![rustbgpd_policy::PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: rustbgpd_policy::PolicyAction::Deny,
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
            match_med_ge: Some(1),
            match_med_le: None,
            match_next_hop: None,
            modifications: rustbgpd_policy::RouteModifications::default(),
        }],
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }])
}

/// The MED that [`deny_med_chain`] lets one row in ten through with:
/// row `index` is accepted when `index` is a multiple of ten.
pub(super) fn tenth_med(index: u32) -> u32 {
    u32::from(!index.is_multiple_of(10))
}

/// Set the MED of `attributes` to `med`.
pub(super) fn set_med(attributes: &mut Arc<AttrSet>, med: u32) {
    AttrSet::edit(attributes, |attrs| {
        attrs.retain(|attr| !matches!(attr, PathAttribute::Med(_)));
        attrs.push(PathAttribute::Med(med));
    });
}
