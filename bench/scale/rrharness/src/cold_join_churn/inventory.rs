//! Fold the peer's RIB-to-writer envelopes in delivery order. Repeated
//! announcements from resync replace the same identity. The stable inventory
//! must be complete at EoR; concurrent churn has its exact cut at the final fence.
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_rib::{
    route::{Route, RouteOrigin},
    update::OutboundRouteUpdate,
    PeerId,
};
use rustbgpd_wire::{Afi, Origin, PathAttribute, Prefix, Safi};

const POLICY_TAG: u32 = (64_512 << 16) | 31;
const STREAM_SOURCES: usize = 8;
const STREAM_STRIDE: usize = 16;

#[derive(Default)]
pub(super) struct Observed {
    pub base_rows: usize,
    pub markers: Vec<u16>,
    pub eor: bool,
    pub flap_change: bool,
    pub stream_change: bool,
    pub stream_announced: u8,
    pub stream_withdrawn: u8,
}

enum Key {
    Base(usize),
    Flap(usize),
    Stream(usize),
    Burst(usize),
    Marker(u16),
}

struct EorCut {
    ready: bool,
    quiet: bool,
    marker_free: bool,
}

pub(super) struct Inventory {
    base: Vec<bool>,
    base_present: usize,
    flap_lp: Vec<u8>,
    flap_new: usize,
    flap_present: usize,
    stream: [bool; STREAM_SOURCES * STREAM_STRIDE],
    stream_width: usize,
    burst: Vec<bool>,
    burst_present: usize,
    markers: Vec<bool>,
    cut: Option<EorCut>,
    tagged: bool,
}

impl Inventory {
    pub(super) fn new(rows: usize, flap_rows: usize, stream_width: usize, tagged: bool) -> Self {
        assert!(flap_rows <= 1 << 16);
        assert!(stream_width <= STREAM_STRIDE);
        Self {
            base: vec![false; rows],
            base_present: 0,
            flap_lp: vec![0; flap_rows],
            flap_new: 0,
            flap_present: 0,
            stream: [false; STREAM_SOURCES * STREAM_STRIDE],
            stream_width,
            burst: Vec::new(),
            burst_present: 0,
            markers: vec![false; 1 << 16],
            cut: None,
            tagged,
        }
    }

    /// Accept a one-message burst of `rows` new marker-source prefixes.
    pub(super) fn with_burst(mut self, rows: usize) -> Self {
        assert!(rows <= 1 << 16);
        self.burst = vec![false; rows];
        self
    }

    pub(super) fn burst_complete(&self) -> bool {
        self.burst_present == self.burst.len()
    }

    fn key(&self, prefix: Prefix, path_id: u32) -> Result<Key, String> {
        let Prefix::V4(p) = prefix else {
            return Err(format!("unexpected address family for {prefix:?}"));
        };
        if path_id != 0 {
            return Err(format!("unexpected path ID {path_id} for {p:?}"));
        }
        let [a, b, c, d] = p.addr.octets();
        let slot = u16::from_be_bytes([c, d]);
        let i = usize::from(slot);
        match (p.len, a, b, d) {
            (32, 198, 18, _) => Ok(Key::Marker(slot)),
            (32, 198, 20, _) if i < self.flap_lp.len() => Ok(Key::Flap(i)),
            (32, 198, 21, _) if i < self.burst.len() => Ok(Key::Burst(i)),
            (32, 198, 19, _) if i < self.stream.len() && i % STREAM_STRIDE < self.stream_width => {
                Ok(Key::Stream(i))
            }
            (24, 20.., _, 0) => {
                let row = (usize::from(a - 20) << 16) | (usize::from(b) << 8) | usize::from(c);
                if row < self.base.len() {
                    Ok(Key::Base(row))
                } else {
                    Err(format!("extra base prefix {p:?}"))
                }
            }
            _ => Err(format!("unexpected prefix {p:?}")),
        }
    }

    fn announce(&mut self, route: &Route, observed: &mut Observed) -> Result<(), String> {
        let key = self.key(route.prefix, route.path_id)?;
        let source = match key {
            Key::Base(i) => {
                // The fourth source takes the remainder when the seed is uneven.
                let quarter = self.base.len() / 4;
                let src = i.checked_div(quarter).unwrap_or(3).min(3);
                Ipv4Addr::new(10, 0, 0, 1 + src as u8)
            }
            Key::Flap(_) => Ipv4Addr::new(10, 2, 0, 1),
            Key::Stream(i) => Ipv4Addr::new(10, 2, 1, 1 + (i / STREAM_STRIDE) as u8),
            Key::Marker(_) | Key::Burst(_) => Ipv4Addr::new(10, 0, 0, 5),
        };
        let lp = check_attributes(route, source, matches!(key, Key::Flap(_)), self.tagged)?;
        match key {
            Key::Base(i) => {
                if !self.base[i] {
                    self.base[i] = true;
                    self.base_present += 1;
                }
                observed.base_rows += 1;
            }
            Key::Flap(i) => {
                if self.flap_lp[i] == 110 && lp == 100 {
                    return Err(format!("stale flap epoch for {:?}", route.prefix));
                }
                observed.flap_change |= lp == 110;
                self.flap_new += usize::from(lp == 110 && self.flap_lp[i] != 110);
                self.flap_present += usize::from(self.flap_lp[i] == 0);
                self.flap_lp[i] = lp;
            }
            Key::Stream(i) => {
                if !self.stream[i] {
                    observed.stream_announced |= 1 << (i / STREAM_STRIDE);
                }
                observed.stream_change = true;
                self.stream[i] = true;
            }
            Key::Burst(i) => {
                self.burst_present += usize::from(!self.burst[i]);
                self.burst[i] = true;
            }
            Key::Marker(seq) => {
                if seq == u16::MAX && self.cut.is_none() {
                    return Err("final fence before initial End-of-RIB".into());
                }
                self.markers[usize::from(seq)] = true;
                observed.markers.push(seq);
            }
        }
        Ok(())
    }

    pub(super) fn fold(&mut self, u: &OutboundRouteUpdate) -> Result<Observed, String> {
        if self.markers[usize::from(u16::MAX)] {
            return Err("output after the final fence".into());
        }
        if !u.flowspec_announce.is_empty()
            || !u.flowspec_withdraw.is_empty()
            || !u.evpn_announce.is_empty()
            || !u.evpn_withdraw.is_empty()
            || !u.bgpls_announce.is_empty()
            || !u.bgpls_withdraw.is_empty()
            || !u.vpn_announce.is_empty()
            || !u.vpn_withdraw.is_empty()
            || !u.labeled_announce.is_empty()
            || !u.labeled_withdraw.is_empty()
            || !u.rtc_announce.is_empty()
            || !u.rtc_withdraw.is_empty()
            || !u.otc_blocked.is_empty()
            || !u.refresh_markers.is_empty()
            || u.request_refresh_all_negotiated
            || u.replay.is_some()
        {
            return Err("unexpected family or control in IPv4-unicast inventory".into());
        }
        if (!u.next_hop_override.is_empty() && u.next_hop_override.len() != u.announce.len())
            || u.next_hop_override.iter().any(Option::is_some)
        {
            return Err("unexpected export next-hop override".into());
        }
        let mut observed = Observed::default();
        for &(prefix, id) in u.unicast_withdrawals() {
            match self.key(prefix, id)? {
                Key::Flap(i) => {
                    if self.flap_lp[i] == 110 {
                        return Err(format!("restored flap route withdrawn: {prefix:?}"));
                    }
                    observed.flap_change = true;
                    self.flap_present -= usize::from(self.flap_lp[i] != 0);
                    self.flap_lp[i] = 0;
                }
                Key::Stream(i) => {
                    if self.stream[i] {
                        observed.stream_withdrawn |= 1 << (i / STREAM_STRIDE);
                    }
                    observed.stream_change = true;
                    self.stream[i] = false;
                }
                _ => return Err(format!("stable route withdrawn: {prefix:?}")),
            }
        }
        for route in u.announce.iter() {
            if u.announce_source_exclusion != Some(route.peer) {
                self.announce(route, &mut observed)?;
            }
        }
        for &family in &u.end_of_rib {
            if family != (Afi::Ipv4, Safi::Unicast) || self.cut.is_some() {
                return Err(format!("wrong or duplicate End-of-RIB: {family:?}"));
            }
            if self.base_present != self.base.len() {
                return Err(format!(
                    "early End-of-RIB: {} of {} steady routes",
                    self.base_present,
                    self.base.len()
                ));
            }
            self.cut = Some(EorCut {
                ready: self.markers[0],
                quiet: self.flap_lp.iter().all(|&lp| lp == 100) && !self.stream.contains(&true),
                marker_free: !self.markers.contains(&true),
            });
            observed.eor = true;
        }
        Ok(observed)
    }

    pub(super) fn check_seed(&self) -> Result<(), String> {
        if self.cut.as_ref().is_some_and(|c| c.quiet && c.marker_free) {
            Ok(())
        } else {
            Err(
                "witness EoR did not contain exactly the seeded base and original flap routes"
                    .into(),
            )
        }
    }

    pub(super) fn check_initial(&self) -> Result<(), String> {
        if self.cut.as_ref().is_some_and(|c| c.ready) {
            Ok(())
        } else {
            Err("initial End-of-RIB missing or preceding the prejoin readiness marker".into())
        }
    }

    pub(super) fn check_quiet_initial(&self) -> Result<(), String> {
        self.check_initial()?;
        if self.cut.as_ref().is_some_and(|c| c.quiet) {
            Ok(())
        } else {
            Err(
                "clean initial End-of-RIB missing original flap rows or carrying stream rows"
                    .into(),
            )
        }
    }

    pub(super) fn flap_gone(&self) -> bool {
        self.flap_present == 0 && self.cut.as_ref().is_some_and(|c| c.quiet && c.marker_free)
    }

    pub(super) fn flap_restored(&self) -> bool {
        self.flap_new == self.flap_lp.len()
    }

    pub(super) fn check_final(&self, last_marker: u16, flap_final_lp: u32) -> Result<(), String> {
        if self.cut.is_none() {
            return Err("missing initial End-of-RIB at final fence".into());
        }
        if last_marker == u16::MAX || !self.markers[usize::from(u16::MAX)] {
            return Err("missing or colliding final fence marker".into());
        }
        if let Some(i) = self.markers[..usize::from(u16::MAX)]
            .iter()
            .enumerate()
            .position(|(i, &seen)| seen != (i <= usize::from(last_marker)))
        {
            return Err(format!(
                "missing or extra marker {i} (last expected {last_marker})"
            ));
        }
        if !matches!(flap_final_lp, 100 | 110) {
            return Err(format!(
                "invalid final flap local preference {flap_final_lp}"
            ));
        }
        if let Some(i) = self
            .flap_lp
            .iter()
            .position(|&lp| u32::from(lp) != flap_final_lp)
        {
            return Err(format!(
                "flap row {i} has LP {} at fence (expected {flap_final_lp})",
                self.flap_lp[i]
            ));
        }
        if let Some(i) = self.stream.iter().position(|&present| present) {
            return Err(format!("stream slot {i} remains at the final fence"));
        }
        Ok(())
    }
}

// Match the full attribute multiset, including duplicate/unexpected attributes.
// The harness observes RIB envelopes, before transport's RR reflection changes.
fn check_attributes(
    route: &Route,
    source: Ipv4Addr,
    flap: bool,
    tagged: bool,
) -> Result<u8, String> {
    if route.next_hop != IpAddr::V4(source)
        || route.peer != PeerId::from_ipv4(source)
        || route.peer_router_id != source
        || route.origin_type != RouteOrigin::Ibgp
        || route.link_local_next_hop.is_some()
        || route.next_hop_scope.is_some()
        || route.is_stale
        || route.is_llgr_stale
    {
        return Err(format!(
            "incorrect source, next hop, or stale flag on {:?}",
            route.prefix
        ));
    }
    let mut mask = 0u8;
    let mut lp = 0;
    for attr in route.attributes.iter() {
        let bit = match attr {
            PathAttribute::Origin(Origin::Igp) => 1,
            PathAttribute::AsPath(p) if p.segments.is_empty() => 2,
            PathAttribute::NextHop(addr) if *addr == source => 4,
            PathAttribute::LocalPref(pref) if *pref == 100 || (flap && *pref == 110) => {
                lp = *pref as u8;
                8
            }
            PathAttribute::Communities(cs) if tagged && cs.as_slice() == [POLICY_TAG] => 16,
            _ => {
                return Err(format!(
                    "unexpected attribute {attr:?} on {:?}",
                    route.prefix
                ))
            }
        };
        if mask & bit != 0 {
            return Err(format!(
                "duplicate attribute {attr:?} on {:?}",
                route.prefix
            ));
        }
        mask |= bit;
    }
    let required = if tagged { 31 } else { 15 };
    if mask != required {
        return Err(format!(
            "missing attributes on {:?}: {:?}",
            route.prefix, route.attributes
        ));
    }
    Ok(lp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flood_prefix, route};
    use rustbgpd_rib::AttrSet;
    use rustbgpd_wire::Ipv4Prefix;
    use std::sync::Arc;

    fn dynamic(second: u8, slot: u16, source: Ipv4Addr, pref: u32) -> Route {
        let [hi, lo] = slot.to_be_bytes();
        route(
            Ipv4Prefix::new(Ipv4Addr::new(198, second, hi, lo), 32),
            source,
            pref,
        )
    }

    fn base(i: u64) -> Route {
        route(flood_prefix(i), Ipv4Addr::new(10, 0, 0, 1 + i as u8), 100)
    }

    fn flap(pref: u32) -> Route {
        dynamic(20, 0, Ipv4Addr::new(10, 2, 0, 1), pref)
    }

    fn marker(seq: u16) -> Route {
        dynamic(18, seq, Ipv4Addr::new(10, 0, 0, 5), 100)
    }

    fn stream() -> Route {
        dynamic(19, 16, Ipv4Addr::new(10, 2, 1, 2), 100)
    }

    fn update(announcements: Vec<Route>) -> OutboundRouteUpdate {
        OutboundRouteUpdate {
            announce: Arc::new(announcements),
            ..Default::default()
        }
    }

    fn eor() -> OutboundRouteUpdate {
        OutboundRouteUpdate {
            end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
            ..Default::default()
        }
    }

    fn populated() -> Inventory {
        let mut inv = Inventory::new(4, 1, 1, false);
        inv.fold(&update((0..4).map(base).collect())).unwrap();
        inv
    }

    #[test]
    fn cuts_distinguish_seed_join_and_quiescent_fence() {
        let mut witness = populated();
        witness.fold(&update(vec![flap(100)])).unwrap();
        witness.fold(&eor()).unwrap();
        witness.check_seed().unwrap();
        witness.fold(&update(vec![marker(0)])).unwrap();
        assert!(
            witness.check_initial().is_err(),
            "a late readiness marker cannot repair an early cut"
        );

        let mut inv = populated();
        inv.fold(&update(vec![marker(0), flap(100), stream()]))
            .unwrap();
        let mut at_eor = eor();
        at_eor.withdraw.push((flap(100).prefix, 0));
        assert!(inv.fold(&at_eor).unwrap().flap_change);
        inv.check_initial().unwrap();
        assert!(inv.check_quiet_initial().is_err());
        assert!(!inv.flap_restored());
        assert!(inv.fold(&update(vec![flap(110)])).unwrap().flap_change);
        assert!(inv.flap_restored());
        inv.fold(&update(vec![marker(1)])).unwrap();
        assert!(
            inv.fold(&OutboundRouteUpdate {
                withdraw: vec![(stream().prefix, 0)],
                ..Default::default()
            })
            .unwrap()
            .stream_change
        );
        inv.fold(&update(vec![marker(u16::MAX)])).unwrap();
        inv.check_final(1, 110).unwrap();
        assert!(
            inv.check_final(2, 110).is_err(),
            "missing intermediate marker"
        );
        assert!(
            inv.fold(&update(vec![marker(2)])).is_err(),
            "late row cannot repair fence"
        );
        assert!(inv.check_final(1, 100).is_err(), "wrong flap generation");
        assert!(
            inv.check_final(0, 110).is_err(),
            "extra intermediate marker"
        );
    }

    #[test]
    fn witness_handshakes_require_distinct_keys_and_real_stream_transitions() {
        let mut inv = Inventory::new(0, 2, 1, false);
        let src = Ipv4Addr::new(10, 2, 0, 1);
        let second = dynamic(20, 1, src, 100);
        let withdraw = |row: &Route| OutboundRouteUpdate {
            withdraw: vec![(row.prefix, 0)],
            ..Default::default()
        };
        assert!(!inv.flap_gone());
        inv.fold(&update(vec![flap(100), second.clone(), second.clone()]))
            .unwrap();
        inv.fold(&eor()).unwrap();
        inv.check_seed().unwrap();
        inv.fold(&withdraw(&second)).unwrap();
        inv.fold(&withdraw(&second)).unwrap();
        assert!(!inv.flap_gone());
        inv.fold(&withdraw(&flap(100))).unwrap();
        assert!(inv.flap_gone());
        inv.fold(&update(vec![flap(110), flap(110)])).unwrap();
        assert!(!inv.flap_gone());
        assert!(!inv.flap_restored());
        inv.fold(&update(vec![dynamic(20, 1, src, 110)])).unwrap();
        assert!(inv.flap_restored());

        let mut announced = 0;
        let mut withdrawn = 0;
        for source in 0..8u8 {
            let row = dynamic(
                19,
                u16::from(source) * 16,
                Ipv4Addr::new(10, 2, 1, source + 1),
                100,
            );
            let change = inv.fold(&update(vec![row.clone()])).unwrap();
            assert_eq!(
                (change.stream_announced, change.stream_withdrawn),
                (1 << source, 0)
            );
            announced |= change.stream_announced;
            assert_eq!(
                inv.fold(&update(vec![row.clone()]))
                    .unwrap()
                    .stream_announced,
                0
            );
            let change = inv.fold(&withdraw(&row)).unwrap();
            assert_eq!(
                (change.stream_announced, change.stream_withdrawn),
                (0, 1 << source)
            );
            withdrawn |= change.stream_withdrawn;
            assert_eq!(inv.fold(&withdraw(&row)).unwrap().stream_withdrawn, 0);
        }
        assert_eq!((announced, withdrawn), (u8::MAX, u8::MAX));
    }

    #[test]
    fn missing_base_identity_cannot_be_replaced_by_duplicate_or_later_rows() {
        let mut inv = Inventory::new(4, 1, 1, false);
        inv.fold(&update(vec![base(0), base(1), base(2), base(2)]))
            .unwrap();
        assert!(inv.fold(&eor()).is_err());
        assert!(inv.fold(&update(vec![base(4)])).is_err());
        let mut wrong_path = base(3);
        wrong_path.path_id = 1;
        assert!(inv.fold(&update(vec![wrong_path])).is_err());
        inv.fold(&update(vec![base(3)])).unwrap();
        assert!(inv.check_final(0, 100).is_err(), "missing EoR");
        let mut wrong_family = eor();
        wrong_family.end_of_rib[0] = (Afi::Ipv6, Safi::Unicast);
        assert!(inv.fold(&wrong_family).is_err());
        assert!(
            inv.fold(&update(vec![marker(u16::MAX)])).is_err(),
            "early fence"
        );
        inv.fold(&eor()).unwrap();
        assert!(
            inv.fold(&eor()).is_err(),
            "duplicate EoR before final fence"
        );
    }

    #[test]
    fn require_the_correct_source_and_complete_plain_or_policy_attributes() {
        let mut inv = Inventory::new(4, 1, 1, true);
        assert!(
            inv.fold(&update(vec![base(0)])).is_err(),
            "missing policy tag"
        );
        let mut tagged = base(0);
        AttrSet::edit(&mut tagged.attributes, |attrs| {
            attrs.push(PathAttribute::Communities(vec![POLICY_TAG]));
        });
        inv.fold(&update(vec![tagged.clone()])).unwrap();
        let mut plain = Inventory::new(4, 1, 1, false);
        assert!(
            plain.fold(&update(vec![tagged.clone()])).is_err(),
            "extra tag"
        );
        AttrSet::edit(&mut tagged.attributes, |attrs| {
            attrs.push(PathAttribute::LocalPref(100));
        });
        assert!(
            inv.fold(&update(vec![tagged])).is_err(),
            "duplicate attribute"
        );
        let mut wrong_nh = base(0);
        wrong_nh.next_hop = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(plain.fold(&update(vec![wrong_nh])).is_err());
        assert!(plain.fold(&update(vec![flap(109)])).is_err());
        assert!(plain
            .fold(&update(vec![dynamic(
                19,
                16,
                Ipv4Addr::new(10, 2, 1, 1),
                100
            )]))
            .is_err());
    }

    #[test]
    fn burst_rows_are_accepted_only_when_configured_and_must_all_arrive() {
        let row = |slot| dynamic(21, slot, Ipv4Addr::new(10, 0, 0, 5), 100);
        assert!(populated().fold(&update(vec![row(0)])).is_err());
        let mut inv = populated().with_burst(2);
        assert!(!inv.burst_complete());
        inv.fold(&update(vec![row(0), row(0)])).unwrap();
        assert!(!inv.burst_complete(), "a repeated row is not a second row");
        assert!(inv.fold(&update(vec![row(2)])).is_err());
        inv.fold(&update(vec![row(1)])).unwrap();
        assert!(inv.burst_complete());
        let withdraw = OutboundRouteUpdate {
            withdraw: vec![(row(1).prefix, 0)],
            ..Default::default()
        };
        assert!(
            inv.fold(&withdraw).is_err(),
            "burst rows are never withdrawn"
        );
    }

    #[test]
    fn reject_stream_outside_the_configured_block_and_missing_final_fence() {
        let mut inv = populated();
        let outside = dynamic(19, 17, Ipv4Addr::new(10, 2, 1, 2), 100);
        assert!(inv.fold(&update(vec![outside])).is_err());
        inv.fold(&update(vec![flap(100), marker(0)])).unwrap();
        inv.fold(&eor()).unwrap();
        inv.check_quiet_initial().unwrap();
        assert!(inv.check_final(0, 100).is_err());
        assert!(
            inv.fold(&update(vec![stream(), marker(u16::MAX)]))
                .unwrap()
                .stream_change
        );
        assert!(inv.check_final(0, 100).unwrap_err().contains("stream slot"));
    }
}
