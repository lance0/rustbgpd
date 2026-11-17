//! Receiver-side wire checks for the outbound-credit cells.
//!
//! Every check here reads only decoded UPDATEs and the harness's own
//! injection log, never the daemon's Adj-RIB-Out, so a storage defect in
//! the daemon cannot also corrupt the reference it is compared with.

use std::net::{IpAddr, Ipv4Addr};
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

/// One burst receiver's decoded table against the harness reference.
#[derive(Debug)]
pub struct WireState {
    family: WireFamily,
    expected: u32,
    /// MED last announced per route index; 0 = absent.
    table: Vec<u32>,
    mismatch: usize,
    pub eor_seen: bool,
    /// The family's End-of-RIB arrived while routes were still missing.
    pub eor_premature: bool,
    /// Burst-family NLRI decoded after the family's End-of-RIB.
    pub routes_after_eor: u64,
    /// Burst-family NLRI decoded before the family's first End-of-RIB.
    pub routes_before_eor: u64,
    /// End-of-RIB markers of the family.
    pub eors: u64,
    pub messages: u64,
    pub announced: u64,
    pub withdrawals: u64,
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
    pub fn new(family: WireFamily, rows: usize, expected: u32) -> Self {
        assert_ne!(expected, 0, "MED 0 marks an absent route");
        Self {
            family,
            expected,
            table: vec![0; rows],
            mismatch: rows,
            eor_seen: false,
            eor_premature: false,
            routes_after_eor: 0,
            routes_before_eor: 0,
            eors: 0,
            messages: 0,
            announced: 0,
            withdrawals: 0,
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
        let was = *slot == self.expected;
        *slot = value;
        let is = value == self.expected;
        match (was, is) {
            (true, false) => self.mismatch += 1,
            (false, true) => self.mismatch -= 1,
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
                    Ok(observed) => self.apply_observed(&observed, now),
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
        let routes = observed
            .announced
            .iter()
            .filter(|(index, _)| *index < rows)
            .count()
            + observed
                .withdrawn
                .iter()
                .filter(|&&index| index < rows)
                .count();
        if self.eor_seen {
            self.routes_after_eor += routes as u64;
        } else {
            self.routes_before_eor += routes as u64;
        }
        self.eors += u64::from(observed.end_of_rib);
        for &(index, med) in &observed.announced {
            self.announced += 1;
            // A route without MED can never equal the reference.
            self.set(index, med.unwrap_or(u32::MAX));
        }
        for &index in &observed.withdrawn {
            self.withdrawals += 1;
            self.set(index, 0);
        }
        if observed.end_of_rib && !self.eor_seen {
            self.eor_seen = true;
            self.eor_premature = self.mismatch != 0;
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
    /// arrival, between arrivals, and from the last arrival to `end`.
    pub max_gap: Duration,
    pub p50: Duration,
    pub p99: Duration,
    pub max: Duration,
}

/// Each injected sequence counts as delivered at the first arrival of any
/// sequence at or after it, so coalesced replacements count as delivered
/// late rather than lost; one still pending at `end` counts as `end`.
pub fn delivery(
    injected: &[(u32, Instant)],
    arrivals: &[(u32, Instant)],
    start: Instant,
    end: Instant,
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
    let mut max_gap = Duration::ZERO;
    let mut previous = start;
    for at in times.into_iter().chain([end]) {
        max_gap = max_gap.max(at.saturating_duration_since(previous));
        previous = at;
    }
    Delivery {
        injected: injected.len(),
        delivered,
        max_gap,
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
        let delivery = delivery(&injected, &arrivals, start, at(1_800));
        assert_eq!(delivery.delivered, 4);
        assert_eq!(delivery.max_gap, Duration::from_millis(1_695));
        assert_eq!(delivery.p99, Duration::from_millis(1_600));
        assert_eq!(delivery.p50, Duration::from_millis(1_405));
    }

    #[test]
    fn undelivered_churn_counts_to_the_end() {
        let start = Instant::now();
        let injected = [(1, start)];
        let delivery = delivery(&injected, &[], start, start + Duration::from_secs(3));
        assert_eq!(delivery.delivered, 0);
        assert_eq!(delivery.max_gap, Duration::from_secs(3));
        assert_eq!(delivery.p99, Duration::from_secs(3));
    }
}
