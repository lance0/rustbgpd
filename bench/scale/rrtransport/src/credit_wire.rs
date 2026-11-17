//! Receiver-side wire checks for the outbound-credit cells.
//!
//! Every check here reads only decoded UPDATEs and the harness's own
//! injection log, never the daemon's Adj-RIB-Out, so a storage defect in
//! the daemon cannot also corrupt the reference it is compared with.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_wire::{
    Afi, EvpnRoute, Message, PathAttribute, Prefix, RouteDistinguisher, Safi, UpdateMessage,
};

/// First burst prefix, `10.0.0.0/24`; route `i` is the `i`-th /24 after it,
/// up to `13.255.255.0/24` (262,144 routes), all inside [`BURST_RANGE`].
pub const UNICAST_BASE: u32 = 0x0a00_0000;
/// The aggregate covering every burst prefix: `8.0.0.0/5`.
pub const BURST_RANGE: (Ipv4Addr, u8) = (Ipv4Addr::new(8, 0, 0, 0), 5);

/// The family a burst receiver checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireFamily {
    Unicast,
    Evpn,
}

/// Burst route index of an IPv4 /24 inside the burst range.
pub fn unicast_index(prefix: Prefix) -> Option<usize> {
    let Prefix::V4(prefix) = prefix else {
        return None;
    };
    let offset = u32::from(prefix.addr).checked_sub(UNICAST_BASE)?;
    (prefix.len == 24 && offset & 0xff == 0 && offset < 1 << 26).then_some((offset >> 8) as usize)
}

/// The `i`-th burst /24.
pub fn unicast_prefix(index: usize) -> Ipv4Addr {
    Ipv4Addr::from(UNICAST_BASE + (u32::try_from(index).expect("index fits u32") << 8))
}

/// Route distinguisher of every burst EVPN route.
pub const EVPN_RD: RouteDistinguisher = RouteDistinguisher([0, 0, 0xfc, 0x00, 0, 0, 0, 1]);
/// Originator IP of every burst EVPN route: the restarting source.
pub const EVPN_ORIGINATOR: Ipv4Addr = Ipv4Addr::new(127, 254, 0, 1);

/// Burst route index of an EVPN IMET route: its Ethernet tag minus one, for
/// the burst's own RD and originator only. The tag alone is not the key.
pub fn evpn_index(route: &EvpnRoute) -> Option<usize> {
    match route {
        EvpnRoute::Imet(imet)
            if imet.rd == EVPN_RD && imet.originator_ip == IpAddr::V4(EVPN_ORIGINATOR) =>
        {
            (imet.ethernet_tag.0 as usize).checked_sub(1)
        }
        _ => None,
    }
}

fn med(attributes: &[PathAttribute]) -> Option<u32> {
    attributes.iter().find_map(|attribute| match attribute {
        PathAttribute::Med(med) => Some(*med),
        _ => None,
    })
}

/// One decoded UPDATE reduced to what the checks need.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Observed {
    /// `(index, MED)` per announced burst-family route.
    pub announced: Vec<(usize, Option<u32>)>,
    pub withdrawn: Vec<usize>,
    /// NLRI of the family that is outside the burst key space.
    pub outside: usize,
    pub end_of_rib: bool,
}

/// Decode `update` for `family`.
///
/// # Errors
/// Returns the wire decode error.
pub fn observe(
    update: &UpdateMessage,
    family: WireFamily,
) -> Result<Observed, rustbgpd_wire::DecodeError> {
    let parsed = update.parse(true, false, &[])?;
    let mut observed = Observed::default();
    let version = med(&parsed.attributes);
    match family {
        WireFamily::Unicast => {
            observed.end_of_rib = update.withdrawn_routes.is_empty()
                && update.path_attributes.is_empty()
                && update.nlri.is_empty();
            for entry in parsed.announced {
                match unicast_index(Prefix::V4(entry.prefix)) {
                    Some(index) => observed.announced.push((index, version)),
                    None => observed.outside += 1,
                }
            }
            for entry in parsed.withdrawn {
                match unicast_index(Prefix::V4(entry.prefix)) {
                    Some(index) => observed.withdrawn.push(index),
                    None => observed.outside += 1,
                }
            }
        }
        WireFamily::Evpn => {
            for attribute in &parsed.attributes {
                match attribute {
                    PathAttribute::MpReachNlri(mp)
                        if mp.afi == Afi::L2Vpn && mp.safi == Safi::Evpn =>
                    {
                        for route in &mp.evpn_announced {
                            match evpn_index(route) {
                                Some(index) => observed.announced.push((index, version)),
                                None => observed.outside += 1,
                            }
                        }
                    }
                    PathAttribute::MpUnreachNlri(mp)
                        if mp.afi == Afi::L2Vpn && mp.safi == Safi::Evpn =>
                    {
                        for route in &mp.evpn_withdrawn {
                            match evpn_index(route) {
                                Some(index) => observed.withdrawn.push(index),
                                None => observed.outside += 1,
                            }
                        }
                        if mp.evpn_withdrawn.is_empty() && parsed.attributes.len() == 1 {
                            observed.end_of_rib = true;
                        }
                    }
                    _ => {}
                }
            }
            observed.outside += parsed.announced.len() + parsed.withdrawn.len();
        }
    }
    Ok(observed)
}

/// The table every burst receiver must end with, shared by all of them.
#[derive(Debug)]
pub struct Reference {
    /// Final MED per route index; 0 = absent.
    meds: Vec<u32>,
    /// Routes the harness withdrew (and maybe re-announced) during the
    /// drain. They may arrive on either side of the End-of-RIB; every other
    /// route must precede it.
    churned: Vec<bool>,
}

impl Reference {
    /// Routes `0..rows`, every one at `med`.
    pub fn uniform(rows: usize, med: u32) -> Self {
        assert_ne!(med, 0, "MED 0 marks an absent route");
        Self {
            meds: vec![med; rows],
            churned: vec![false; rows],
        }
    }

    /// `uniform`, then `withdrawn` routes withdrawn and `reannounced` ones
    /// announced again at `version`.
    pub fn churned(
        rows: usize,
        med: u32,
        withdrawn: &[usize],
        reannounced: &[usize],
        version: u32,
    ) -> Self {
        assert_ne!(version, 0, "MED 0 marks an absent route");
        let mut reference = Self::uniform(rows, med);
        for &index in withdrawn {
            reference.meds[index] = 0;
            reference.churned[index] = true;
        }
        for &index in reannounced {
            reference.meds[index] = version;
            reference.churned[index] = true;
        }
        reference
    }
}

/// One burst receiver's decoded table against the harness reference.
#[derive(Debug)]
pub struct WireState {
    family: WireFamily,
    reference: Arc<Reference>,
    /// MED last announced per route index; 0 = absent.
    table: Vec<u32>,
    /// Routes that differ from the reference.
    mismatch: usize,
    /// Routes outside the churned set that differ from the reference.
    stable_mismatch: usize,
    pub eor_seen: bool,
    /// When the first End-of-RIB of the family was decoded.
    pub eor_at: Option<Instant>,
    /// The family's End-of-RIB arrived while a route outside the churned
    /// set was still missing or stale.
    pub eor_premature: bool,
    /// Burst-family NLRI outside the churned set decoded after the
    /// family's End-of-RIB.
    pub routes_after_eor: u64,
    /// Churned NLRI decoded after the End-of-RIB: allowed, report-only.
    pub churned_after_eor: u64,
    /// First MED announced before the End-of-RIB, per churned route.
    first_churned: HashMap<usize, u32>,
    /// At the first End-of-RIB: churned routes whose state before the
    /// marker already reflected the churn (a withdrawn route never
    /// announced, a re-announced one first seen at its new MED). Nonzero
    /// shows the churn reached the RIB before the release sent those rows.
    pub churn_reflected_before_eor: Option<usize>,
    /// Announcements before the End-of-RIB that repeat the MED already
    /// held: report-only.
    pub duplicates_before_eor: u64,
    /// Burst-family NLRI decoded before the family's first End-of-RIB.
    pub routes_before_eor: u64,
    /// End-of-RIB markers of the family.
    pub eors: u64,
    pub messages: u64,
    pub announced: u64,
    pub withdrawals: u64,
    /// The fewest wire bytes per announced row over every UPDATE that
    /// announced one: the message less its withdrawn routes, divided by its
    /// announced routes, rounded down.
    pub min_row_bytes: Option<u64>,
    pub outside: u64,
    pub decode_failures: u64,
    /// Session ended (decoded-message channel closed) or a NOTIFICATION
    /// arrived.
    pub resets: u64,
    /// Latest time the table became exact with its End-of-RIB seen.
    pub settled_at: Option<Instant>,
}

impl WireState {
    /// A receiver that must end holding routes `0..rows` at MED `expected`.
    #[cfg(test)]
    pub fn new(family: WireFamily, rows: usize, expected: u32) -> Self {
        Self::with_reference(family, Arc::new(Reference::uniform(rows, expected)))
    }

    /// A receiver that must end holding `reference`.
    pub fn with_reference(family: WireFamily, reference: Arc<Reference>) -> Self {
        let rows = reference.meds.len();
        let absent = reference.meds.iter().filter(|&&med| med == 0).count();
        let churned = reference.churned.iter().filter(|&&churned| churned).count();
        Self {
            family,
            table: vec![0; rows],
            mismatch: rows - absent,
            stable_mismatch: rows - churned,
            reference,
            eor_seen: false,
            eor_at: None,
            eor_premature: false,
            routes_after_eor: 0,
            churned_after_eor: 0,
            first_churned: HashMap::new(),
            churn_reflected_before_eor: None,
            duplicates_before_eor: 0,
            routes_before_eor: 0,
            eors: 0,
            messages: 0,
            announced: 0,
            withdrawals: 0,
            min_row_bytes: None,
            outside: 0,
            decode_failures: 0,
            resets: 0,
            settled_at: None,
        }
    }

    fn set(&mut self, index: usize, value: u32) {
        let Some(slot) = self.table.get_mut(index) else {
            self.outside += 1;
            return;
        };
        let reference = self.reference.meds[index];
        let was = *slot == reference;
        *slot = value;
        let is = value == reference;
        let stable = usize::from(!self.reference.churned[index]);
        match (was, is) {
            (true, false) => {
                self.mismatch += 1;
                self.stable_mismatch += stable;
            }
            (false, true) => {
                self.mismatch -= 1;
                self.stable_mismatch -= stable;
            }
            _ => {}
        }
    }

    /// Apply one message received at `now`.
    pub fn apply(&mut self, message: &Message, now: Instant) {
        match message {
            Message::Notification(_) => self.resets += 1,
            Message::Update(update) => {
                self.messages += 1;
                match observe(update, self.family) {
                    Ok(observed) => {
                        if let Ok(rows @ 1..) = u64::try_from(observed.announced.len()) {
                            // Header, both length fields, attributes, NLRI.
                            let bytes = 19 + 4 + update.path_attributes.len() + update.nlri.len();
                            let per_row = bytes as u64 / rows;
                            self.min_row_bytes =
                                Some(self.min_row_bytes.map_or(per_row, |min| min.min(per_row)));
                        }
                        self.apply_observed(&observed, now);
                    }
                    Err(_) => self.decode_failures += 1,
                }
            }
            _ => {}
        }
    }

    pub fn apply_observed(&mut self, observed: &Observed, now: Instant) {
        self.outside += observed.outside as u64;
        // Only routes inside the burst key space count; others are `outside`.
        let rows = self.table.len();
        let (mut routes, mut churned) = (0, 0);
        let indices = observed
            .announced
            .iter()
            .map(|&(index, _)| index)
            .chain(observed.withdrawn.iter().copied());
        for index in indices.filter(|&index| index < rows) {
            routes += 1;
            churned += u64::from(self.reference.churned[index]);
        }
        if self.eor_seen {
            self.routes_after_eor += routes - churned;
            self.churned_after_eor += churned;
        } else {
            self.routes_before_eor += routes;
        }
        self.eors += u64::from(observed.end_of_rib);
        for &(index, med) in &observed.announced {
            self.announced += 1;
            if !self.eor_seen && index < rows {
                let held = self.table[index];
                self.duplicates_before_eor += u64::from(held != 0 && Some(held) == med);
                if self.reference.churned[index] {
                    self.first_churned
                        .entry(index)
                        .or_insert(med.unwrap_or(u32::MAX));
                }
            }
            // A route without MED can never equal the reference.
            self.set(index, med.unwrap_or(u32::MAX));
        }
        for &index in &observed.withdrawn {
            self.withdrawals += 1;
            self.set(index, 0);
        }
        if observed.end_of_rib && !self.eor_seen {
            self.eor_seen = true;
            self.eor_at = Some(now);
            self.eor_premature = self.stable_mismatch != 0;
            self.churn_reflected_before_eor = Some(self.churn_reflected());
        }
        self.settled_at = if self.exact() {
            self.settled_at.or(Some(now))
        } else {
            None
        };
    }

    /// The decoded table equals the reference and its End-of-RIB arrived.
    /// Every route at its reference MED and nothing else: no route outside
    /// the burst key space and no undecodable UPDATE.
    pub fn exact(&self) -> bool {
        self.mismatch == 0 && self.eor_seen && self.outside == 0 && self.decode_failures == 0
    }

    pub fn missing(&self) -> usize {
        self.mismatch
    }

    /// Churned routes whose first announcement so far (none: 0) is already
    /// their post-churn reference state.
    fn churn_reflected(&self) -> usize {
        let churned = self.reference.churned.iter().enumerate();
        churned
            .filter(|&(index, &churned)| {
                churned
                    && self.first_churned.get(&index).copied().unwrap_or(0)
                        == self.reference.meds[index]
            })
            .count()
    }

    /// Routes the reference withdrew for good that the receiver still holds.
    pub fn withdrawn_survivors(&self) -> usize {
        self.table
            .iter()
            .zip(&self.reference.meds)
            .filter(|&(&held, &med)| med == 0 && held != 0)
            .count()
    }

    /// The decoded-message channel closed while the harness still needed it.
    pub fn closed(&mut self) {
        self.resets += 1;
    }
}

/// The healthy receiver's churn arrivals: `(sequence, time)`.
#[derive(Debug, Default)]
pub struct ChurnState {
    pub arrivals: Vec<(u32, Instant)>,
    pub resets: u64,
    pub decode_failures: u64,
}

/// The single churn prefix.
pub const CHURN_PREFIX: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 0);

impl ChurnState {
    pub fn apply(&mut self, message: &Message, now: Instant) {
        match message {
            Message::Notification(_) => self.resets += 1,
            Message::Update(update) => match update.parse(true, false, &[]) {
                Ok(parsed) => {
                    let churn = parsed
                        .announced
                        .iter()
                        .any(|entry| IpAddr::V4(entry.prefix.addr) == IpAddr::V4(CHURN_PREFIX));
                    if let Some(sequence) = med(&parsed.attributes).filter(|_| churn) {
                        self.arrivals.push((sequence, now));
                    }
                }
                Err(_) => self.decode_failures += 1,
            },
            _ => {}
        }
    }
}

/// Delivery statistics of the churn route over `[start, end]`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Delivery {
    pub injected: usize,
    pub delivered: usize,
    /// Longest interval with no churn arrival, from `start` to the first
    /// arrival, between arrivals, and from the last arrival to `end`, less
    /// its overlap with the excluded window.
    pub max_gap: Duration,
    /// The same without the exclusion.
    pub max_gap_raw: Duration,
    pub p50: Duration,
    pub p99: Duration,
    pub max: Duration,
}

/// Each injected sequence counts as delivered at the first arrival of any
/// sequence at or after it, so coalesced replacements count as delivered
/// late rather than lost; one still pending at `end` counts as `end`.
/// `excluded` is the harness's own churn-free window: a gap counts only
/// its part outside it.
pub fn delivery(
    injected: &[(u32, Instant)],
    arrivals: &[(u32, Instant)],
    start: Instant,
    end: Instant,
    excluded: Option<(Instant, Instant)>,
) -> Delivery {
    let mut latencies = Vec::with_capacity(injected.len());
    let mut delivered = 0;
    for &(sequence, sent) in injected {
        let at = arrivals
            .iter()
            .find(|&&(seen, at)| seen >= sequence && at >= sent)
            .map(|&(_, at)| at);
        if at.is_some() {
            delivered += 1;
        }
        latencies.push(at.unwrap_or(end).saturating_duration_since(sent));
    }
    latencies.sort_unstable();
    let pick = |quantile: f64| {
        if latencies.is_empty() {
            return Duration::ZERO;
        }
        let rank = ((latencies.len() as f64) * quantile).ceil() as usize;
        latencies[rank.clamp(1, latencies.len()) - 1]
    };
    let mut times: Vec<Instant> = arrivals
        .iter()
        .map(|&(_, at)| at)
        .filter(|&at| at >= start && at <= end)
        .collect();
    times.sort_unstable();
    let overlap = |from: Instant, to: Instant| {
        excluded.map_or(Duration::ZERO, |(low, high)| {
            to.min(high).saturating_duration_since(from.max(low))
        })
    };
    let (mut max_gap, mut max_gap_raw) = (Duration::ZERO, Duration::ZERO);
    let mut previous = start;
    for at in times.into_iter().chain([end]) {
        let gap = at.saturating_duration_since(previous);
        max_gap_raw = max_gap_raw.max(gap);
        max_gap = max_gap.max(gap - overlap(previous, at));
        previous = at;
    }
    Delivery {
        injected: injected.len(),
        delivered,
        max_gap,
        max_gap_raw,
        p50: pick(0.50),
        p99: pick(0.99),
        max: latencies.last().copied().unwrap_or(Duration::ZERO),
    }
}

#[cfg(test)]
mod tests {
    //! Seeded defects: each one must turn exactly its own check red.
    use super::*;

    const ROWS: usize = 4;

    fn routes(indices: impl IntoIterator<Item = usize>, med: u32) -> Observed {
        Observed {
            announced: indices
                .into_iter()
                .map(|index| (index, Some(med)))
                .collect(),
            ..Observed::default()
        }
    }

    fn eor() -> Observed {
        Observed {
            end_of_rib: true,
            ..Observed::default()
        }
    }

    /// The three wire checks the exhaustion cell reports, in its order.
    fn checks(state: &WireState) -> [bool; 3] {
        [
            state.exact(),
            !state.eor_premature && state.routes_after_eor == 0,
            state.resets == 0,
        ]
    }

    fn run(steps: &[Observed]) -> WireState {
        let mut state = WireState::new(WireFamily::Unicast, ROWS, 7);
        let now = Instant::now();
        for step in steps {
            state.apply_observed(step, now);
        }
        state
    }

    #[test]
    fn min_row_bytes_is_the_encoded_message_per_announced_row() {
        let entry = |index| rustbgpd_wire::Ipv4NlriEntry {
            path_id: 0,
            prefix: rustbgpd_wire::Ipv4Prefix::new(unicast_prefix(index), 24),
        };
        let attributes = [
            PathAttribute::Origin(rustbgpd_wire::Origin::Igp),
            PathAttribute::NextHop(Ipv4Addr::new(127, 0, 0, 1)),
            PathAttribute::Med(7),
        ];
        let update = |announced: &[usize], withdrawn: &[usize]| {
            let announced: Vec<_> = announced.iter().map(|&index| entry(index)).collect();
            let withdrawn: Vec<_> = withdrawn.iter().map(|&index| entry(index)).collect();
            Message::Update(UpdateMessage::build(
                &announced,
                &withdrawn,
                &attributes,
                true,
                false,
                rustbgpd_wire::Ipv4UnicastMode::Body,
            ))
        };
        let length = |message: &Message| {
            rustbgpd_wire::encode_message(message)
                .expect("encodes")
                .len() as u64
        };
        let mut state = WireState::new(WireFamily::Unicast, ROWS, 7);
        let now = Instant::now();
        // A withdrawal alone counts no row; its bytes never count.
        state.apply(&update(&[], &[0, 1, 2]), now);
        assert_eq!(state.min_row_bytes, None);
        let one = update(&[0], &[1, 2, 3]);
        let withdrawn_bytes = 3 * 4;
        state.apply(&one, now);
        assert_eq!(state.min_row_bytes, Some(length(&one) - withdrawn_bytes));
        let two = update(&[1, 2], &[]);
        state.apply(&two, now);
        assert_eq!(state.min_row_bytes, Some(length(&two) / 2));
        // A larger per-row size later does not raise the minimum.
        state.apply(&update(&[3], &[]), now);
        assert_eq!(state.min_row_bytes, Some(length(&two) / 2));
    }

    #[test]
    fn clean_transcript_passes_every_check() {
        let state = run(&[routes(0..ROWS, 7), eor()]);
        assert_eq!(checks(&state), [true, true, true]);
        assert!(state.settled_at.is_some());
    }

    #[test]
    fn seeded_dropped_route_fails_only_final_state() {
        // Route 2 never arrives; the End-of-RIB is honest about the rest.
        let mut state = run(&[routes([0, 1, 3], 7)]);
        state.eor_seen = true;
        assert_eq!(checks(&state), [false, true, true]);
        assert_eq!(state.missing(), 1);
    }

    #[test]
    fn seeded_stale_version_fails_only_final_state() {
        let mut state = run(&[routes(0..ROWS, 7), routes([1], 6)]);
        state.eor_seen = true;
        assert_eq!(checks(&state), [false, true, true]);
    }

    #[test]
    fn seeded_route_after_eor_fails_only_eor_order() {
        let state = run(&[routes(0..3, 7), eor(), routes([3], 7)]);
        assert!(state.eor_premature);
        assert_eq!(state.routes_after_eor, 1);
        assert_eq!(checks(&state), [true, false, true]);
    }

    #[test]
    fn seeded_session_reset_fails_only_resets() {
        let mut state = run(&[routes(0..ROWS, 7), eor()]);
        state.closed();
        assert_eq!(checks(&state), [true, true, false]);
    }

    #[test]
    fn seeded_extra_route_fails_only_final_state() {
        let extra = Observed {
            outside: 1,
            ..Observed::default()
        };
        let state = run(&[routes(0..ROWS, 7), extra, eor()]);
        assert_eq!(checks(&state), [false, true, true]);
        assert!(state.settled_at.is_none());
    }

    #[test]
    fn seeded_extra_route_after_eor_fails_final_state() {
        let extra = Observed {
            outside: 1,
            ..Observed::default()
        };
        let state = run(&[routes(0..ROWS, 7), eor(), extra]);
        assert!(!state.exact());
    }

    #[test]
    fn seeded_decode_failure_fails_final_state() {
        let mut state = run(&[routes(0..ROWS, 7), eor()]);
        state.decode_failures = 1;
        assert_eq!(checks(&state), [false, true, true]);
    }

    fn imet(rd: RouteDistinguisher, originator: Ipv4Addr, tag: u32) -> EvpnRoute {
        EvpnRoute::Imet(rustbgpd_wire::EvpnImet {
            rd,
            ethernet_tag: rustbgpd_wire::EthernetTagId(tag),
            originator_ip: IpAddr::V4(originator),
        })
    }

    #[test]
    fn seeded_foreign_imet_key_is_outside() {
        assert_eq!(evpn_index(&imet(EVPN_RD, EVPN_ORIGINATOR, 5)), Some(4));
        let other_rd = RouteDistinguisher([0, 0, 0xfc, 0x00, 0, 0, 0, 2]);
        assert_eq!(evpn_index(&imet(other_rd, EVPN_ORIGINATOR, 5)), None);
        let other_originator = Ipv4Addr::new(127, 254, 0, 9);
        assert_eq!(evpn_index(&imet(EVPN_RD, other_originator, 5)), None);
    }

    #[test]
    fn notification_counts_as_reset() {
        let mut state = WireState::new(WireFamily::Unicast, 1, 1);
        let notification = rustbgpd_wire::NotificationMessage {
            code: rustbgpd_wire::NotificationCode::Cease,
            subcode: 2,
            data: Default::default(),
        };
        state.apply(&Message::Notification(notification), Instant::now());
        assert_eq!(state.resets, 1);
    }

    #[test]
    fn withdrawal_of_a_settled_route_unsettles() {
        let mut state = run(&[routes(0..ROWS, 7), eor()]);
        state.apply_observed(
            &Observed {
                withdrawn: vec![0],
                ..Observed::default()
            },
            Instant::now(),
        );
        assert!(!state.exact());
        assert!(state.settled_at.is_none());
    }

    #[test]
    fn unicast_index_round_trips_and_rejects_outside() {
        for index in [0, 1, 255, 149_999] {
            let prefix = Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(unicast_prefix(index), 24));
            assert_eq!(unicast_index(prefix), Some(index));
        }
        let outside = Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(CHURN_PREFIX, 24));
        assert_eq!(unicast_index(outside), None);
    }

    #[test]
    fn delivery_reports_gap_and_latency() {
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let injected = [(1, at(0)), (2, at(100)), (3, at(200)), (4, at(300))];
        // Sequence 2 is coalesced into 3; nothing arrives for 1.5 s.
        let arrivals = [(1, at(5)), (3, at(1_700)), (4, at(1_705))];
        let delivery = delivery(&injected, &arrivals, start, at(1_800), None);
        assert_eq!(delivery.delivered, 4);
        assert_eq!(delivery.max_gap, Duration::from_millis(1_695));
        assert_eq!(delivery.p99, Duration::from_millis(1_600));
        assert_eq!(delivery.p50, Duration::from_millis(1_405));
    }

    #[test]
    fn undelivered_churn_counts_to_the_end() {
        let start = Instant::now();
        let injected = [(1, start)];
        let delivery = delivery(&injected, &[], start, start + Duration::from_secs(3), None);
        assert_eq!(delivery.delivered, 0);
        assert_eq!(delivery.max_gap, Duration::from_secs(3));
        assert_eq!(delivery.p99, Duration::from_secs(3));
    }

    /// Routes 0..4 at MED 7; the harness withdrew 1 and 2 during the drain
    /// and re-announced 2 at MED 9.
    fn churned_run(steps: &[Observed]) -> WireState {
        let reference = Reference::churned(ROWS, 7, &[1, 2], &[2], 9);
        let mut state = WireState::with_reference(WireFamily::Unicast, Arc::new(reference));
        let now = Instant::now();
        for step in steps {
            state.apply_observed(step, now);
        }
        state
    }

    fn withdrawn(indices: impl IntoIterator<Item = usize>) -> Observed {
        Observed {
            withdrawn: indices.into_iter().collect(),
            ..Observed::default()
        }
    }

    #[test]
    fn churned_routes_may_follow_the_end_of_rib() {
        // The release table, its End-of-RIB, then the churn behind it.
        let state = churned_run(&[routes(0..ROWS, 7), eor(), withdrawn([1, 2]), routes([2], 9)]);
        assert_eq!(checks(&state), [true, true, true]);
        assert_eq!(state.churned_after_eor, 3);
        assert_eq!(state.withdrawn_survivors(), 0);
        // Or ahead of it, with the churned routes absent at the marker.
        let state = churned_run(&[routes([0, 3], 7), routes([2], 9), eor()]);
        assert_eq!(checks(&state), [true, true, true]);
        assert_eq!(state.churned_after_eor, 0);
    }

    #[test]
    fn seeded_surviving_withdrawn_route_fails_only_final_state() {
        // Route 1 was never withdrawn on the wire.
        let state = churned_run(&[routes(0..ROWS, 7), eor(), withdrawn([2]), routes([2], 9)]);
        assert_eq!(checks(&state), [false, true, true]);
        assert_eq!(state.withdrawn_survivors(), 1);
    }

    #[test]
    fn seeded_stale_reannouncement_fails_only_final_state() {
        // Route 2 kept its pre-churn version.
        let state = churned_run(&[routes(0..ROWS, 7), eor(), withdrawn([1])]);
        assert_eq!(checks(&state), [false, true, true]);
        assert_eq!(state.withdrawn_survivors(), 0);
    }

    #[test]
    fn seeded_unchurned_route_after_eor_fails_only_eor_order() {
        // Route 3 was never churned, so it belongs before the marker.
        let state = churned_run(&[routes([0], 7), routes([2], 9), eor(), routes([3], 7)]);
        assert_eq!(checks(&state), [true, false, true]);
        assert!(state.eor_premature);
        assert_eq!(state.routes_after_eor, 1);
    }

    #[test]
    fn churn_witness_counts_routes_already_churned_at_the_end_of_rib() {
        // The release sent every row at MED 7 before the churn reached the
        // RIB: nothing before the marker reflects it.
        let late = churned_run(&[routes(0..ROWS, 7), eor(), withdrawn([1, 2]), routes([2], 9)]);
        assert_eq!(late.churn_reflected_before_eor, Some(0));
        // The churn reached the RIB first: route 1 never announced, route 2
        // first seen at MED 9.
        let early = churned_run(&[routes([0, 3], 7), routes([2], 9), eor()]);
        assert_eq!(early.churn_reflected_before_eor, Some(2));
        // Seeded: route 1 announced at 7 and withdrawn before the marker,
        // route 2 seen at 7 before 9. Neither counts.
        let mixed = churned_run(&[routes(0..ROWS, 7), withdrawn([1]), routes([2], 9), eor()]);
        assert_eq!(mixed.churn_reflected_before_eor, Some(0));
        // No marker, no witness.
        assert_eq!(
            churned_run(&[routes([0, 3], 7)]).churn_reflected_before_eor,
            None
        );
    }

    #[test]
    fn duplicate_announcements_before_the_end_of_rib_are_counted() {
        let state = run(&[routes(0..ROWS, 7), routes([1], 7), routes([1], 6), eor()]);
        assert_eq!(state.duplicates_before_eor, 1);
        // After the marker a repeat is not counted here.
        let state = run(&[routes(0..ROWS, 7), eor(), routes([1], 7)]);
        assert_eq!(state.duplicates_before_eor, 0);
    }

    #[test]
    fn seeded_second_eor_is_counted() {
        let state = churned_run(&[routes([0, 3], 7), routes([2], 9), eor(), eor()]);
        assert_eq!(state.eors, 2);
        assert!(state.eor_at.is_some());
    }

    #[test]
    fn excluded_window_removes_only_its_overlap_from_a_gap() {
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let injected = [(1, at(0))];
        // Arrivals every 20 ms but for one 400 ms hole.
        let arrivals = [(1, at(20)), (2, at(40)), (3, at(440)), (4, at(460))];
        let window = |from, to| Some((at(from), at(to)));
        let gap = |excluded| delivery(&injected, &arrivals, start, at(480), excluded).max_gap;
        assert_eq!(gap(None), Duration::from_millis(400));
        // The hole lies inside the window: what is left is a 20 ms gap.
        assert_eq!(gap(window(30, 450)), Duration::from_millis(20));
        // The window covers 300 ms of it: 100 ms still counts.
        assert_eq!(gap(window(60, 360)), Duration::from_millis(100));
        // A window elsewhere changes nothing.
        assert_eq!(gap(window(460, 470)), Duration::from_millis(400));
        let both = delivery(&injected, &arrivals, start, at(480), window(30, 450));
        assert_eq!(both.max_gap_raw, Duration::from_millis(400));
    }
}
