//! Independently fold the accepted session envelopes or the stub's decoded
//! IPv4 UPDATEs. Each observer owns one bit per seed prefix. Only key 1
//! changes payload, so the remaining versions need no per-route storage.

use std::net::{IpAddr, Ipv4Addr};

use anyhow::{bail, ensure, Result};
use rustbgpd_rib::update::OutboundRouteUpdate;
use rustbgpd_rib::PeerId;
use rustbgpd_wire::{Afi, AsPathSegment, Ipv4Prefix, Message, Origin, PathAttribute, Prefix, Safi};
use serde_json::{json, Value};

const BASE: u32 = 0x0a00_0000;
const SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const PROBE_SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const TRIGGER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 253);
const PROBE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 254);
const RECOVERY_PROBE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 252);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Seed,
    Fill,
    Final,
}

/// The route server preserves the origin, source AS, next hop and community.
/// LOCAL_PREF is internal to the RIB and must be stripped on this eBGP wire.
fn payload(attrs: &[PathAttribute], internal: bool) -> Result<(Ipv4Addr, u32)> {
    let mut origin = None;
    let mut asn = None;
    let mut next_hop = None;
    let mut community = None;
    for attr in attrs {
        match attr {
            PathAttribute::Origin(value) if origin.is_none() => origin = Some(*value),
            PathAttribute::AsPath(path) if asn.is_none() => {
                let [AsPathSegment::AsSequence(seg)] = path.segments.as_slice() else {
                    bail!("expected a single AS_SEQUENCE");
                };
                let [value] = seg.as_slice() else {
                    bail!("expected one source AS")
                };
                asn = Some(*value);
            }
            PathAttribute::NextHop(ip) if next_hop.is_none() => next_hop = Some(*ip),
            PathAttribute::Communities(tags) if community.is_none() => {
                let [tag] = tags.as_slice() else {
                    bail!("expected one export community")
                };
                ensure!(*tag >> 16 == 64_512, "wrong export community {tag}");
                community = Some(*tag & 0xffff);
            }
            PathAttribute::LocalPref(100) if internal => {}
            _ => bail!("unexpected grouped route attribute {attr:?}"),
        }
    }
    ensure!(origin == Some(Origin::Igp), "missing or wrong ORIGIN");
    let source = match (asn, next_hop) {
        (Some(65_000), Some(SOURCE)) => SOURCE,
        (Some(65_002), Some(PROBE_SOURCE)) => PROBE_SOURCE,
        _ => bail!("wrong AS_PATH or NEXT_HOP: {asn:?}/{next_hop:?}"),
    };
    Ok((
        source,
        community.ok_or_else(|| anyhow::anyhow!("missing export community"))?,
    ))
}

pub(crate) struct GroupedWire {
    rows: usize,
    held: Vec<u64>,
    seed_present: usize,
    mutable_version: u32,
    saw_fill: bool,
    trigger: bool,
    probe: bool,
    recovery_probe: bool,
    eors: usize,
    announcements: u64,
    withdrawals: u64,
}

impl GroupedWire {
    pub(crate) fn new(rows: usize) -> Self {
        Self {
            rows,
            held: vec![0; rows.div_ceil(64)],
            seed_present: 0,
            mutable_version: 0,
            saw_fill: false,
            trigger: false,
            probe: false,
            recovery_probe: false,
            eors: 0,
            announcements: 0,
            withdrawals: 0,
        }
    }

    fn announce(&mut self, p: Ipv4Prefix, source: Ipv4Addr, tag: u32) -> Result<()> {
        ensure!(p.len == 32, "unexpected prefix {p:?}");
        ensure!(
            self.eors == 1,
            "row before the established session's empty initial EoR"
        );
        if p.addr == PROBE {
            ensure!(source == PROBE_SOURCE && tag == 4, "wrong probe payload");
            self.probe = true;
        } else if p.addr == RECOVERY_PROBE {
            ensure!(
                source == PROBE_SOURCE && tag == 5,
                "wrong recovery probe payload"
            );
            self.recovery_probe = true;
        } else if p.addr == TRIGGER {
            ensure!(source == SOURCE && tag == 3, "wrong trigger payload");
            self.trigger = true;
        } else {
            let index = u32::from(p.addr)
                .checked_sub(BASE)
                .map(|offset| offset as usize)
                .filter(|&i| i < self.rows)
                .ok_or_else(|| anyhow::anyhow!("unexpected announcement {p:?}"))?;
            ensure!(source == SOURCE, "wrong source for seed key {index}");
            if index == 1 {
                ensure!((1..=3).contains(&tag), "wrong replacement community {tag}");
                self.mutable_version = tag;
                self.saw_fill |= tag == 2;
            } else {
                ensure!(tag == 1, "wrong payload for seed key {index}");
            }
            let mask = 1u64 << (index % 64);
            let word = &mut self.held[index / 64];
            self.seed_present += usize::from(*word & mask == 0);
            *word |= mask;
        }
        self.announcements += 1;
        Ok(())
    }

    fn withdraw(&mut self, prefix: Prefix, path_id: u32) -> Result<()> {
        ensure!(
            path_id == 0 && prefix == Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(BASE), 32)),
            "unexpected withdrawal {prefix:?} path {path_id}"
        );
        ensure!(
            self.held.first().is_some_and(|word| word & 1 != 0),
            "withdrawal for a key this receiver does not hold"
        );
        self.held[0] &= !1;
        self.seed_present -= 1;
        self.withdrawals += 1;
        Ok(())
    }

    /// Consume an admitted RIB envelope before forwarding it to its session.
    pub(crate) fn apply(&mut self, update: &OutboundRouteUpdate) -> Result<()> {
        ensure!(
            update.flowspec_announce.is_empty()
                && update.flowspec_withdraw.is_empty()
                && update.evpn_announce.is_empty()
                && update.evpn_withdraw.is_empty()
                && update.vpn_announce.is_empty()
                && update.vpn_withdraw.is_empty()
                && update.labeled_announce.is_empty()
                && update.labeled_withdraw.is_empty()
                && update.bgpls_announce.is_empty()
                && update.bgpls_withdraw.is_empty()
                && update.rtc_announce.is_empty()
                && update.rtc_withdraw.is_empty()
                && update.otc_blocked.is_empty()
                && update.refresh_markers.is_empty()
                && !update.request_refresh_all_negotiated,
            "unexpected family or control in grouped output"
        );
        for &(p, id) in update.unicast_withdrawals() {
            self.withdraw(p, id)?;
        }
        let mut previous = None;
        for (index, route) in update.announce.iter().enumerate() {
            if update.announce_source_exclusion == Some(route.peer) {
                continue;
            }
            let Prefix::V4(p) = route.prefix else {
                bail!("IPv6 on grouped IPv4 receiver")
            };
            let attrs = route.attributes.as_ref();
            let (source, tag) = match previous {
                Some((prior, value)) if std::ptr::eq(prior, attrs) => value,
                _ => {
                    let value = payload(attrs, true)?;
                    previous = Some((attrs, value));
                    value
                }
            };
            ensure!(
                route.path_id == 0
                    && route.next_hop == IpAddr::V4(source)
                    && route.peer == PeerId::from_ipv4(source)
                    && update
                        .next_hop_override
                        .get(index)
                        .is_none_or(Option::is_none),
                "wrong path identity or next-hop override for {p:?}"
            );
            self.announce(p, source, tag)?;
        }
        for &family in &update.end_of_rib {
            ensure!(
                family == (Afi::Ipv4, Safi::Unicast),
                "foreign EoR {family:?}"
            );
            self.end_of_rib()?;
        }
        Ok(())
    }

    /// Consume the real loopback stub's decoded message. The dedicated flush
    /// fence is removed by its reader and does not count as a route or EoR.
    pub(crate) fn apply_message(&mut self, message: &Message) -> Result<()> {
        let update = match message {
            Message::Keepalive => return Ok(()),
            Message::Update(update) => update,
            _ => bail!("unexpected message on established grouped session: {message:?}"),
        };
        if update.withdrawn_routes.is_empty()
            && update.path_attributes.is_empty()
            && update.nlri.is_empty()
        {
            return self.end_of_rib();
        }
        let parsed = update.parse(true, false, &[])?;
        for row in &parsed.withdrawn {
            self.withdraw(Prefix::V4(row.prefix), row.path_id)?;
        }
        if parsed.announced.is_empty() {
            ensure!(
                !parsed.withdrawn.is_empty() && parsed.attributes.is_empty(),
                "foreign family or unexpected attributes on withdrawal"
            );
        } else {
            let (source, tag) = payload(&parsed.attributes, false)?;
            for row in &parsed.announced {
                ensure!(row.path_id == 0, "unexpected path id");
                self.announce(row.prefix, source, tag)?;
            }
        }
        Ok(())
    }

    fn end_of_rib(&mut self) -> Result<()> {
        self.eors += 1;
        ensure!(
            self.eors == 1,
            "duplicated End-of-RIB: marker {} on a session that sends one",
            self.eors
        );
        Ok(())
    }

    pub(crate) fn verify(&self, phase: Phase) -> Result<()> {
        let final_table = phase == Phase::Final;
        ensure!(
            self.rows >= 2 && self.eors == 1,
            "{phase:?}: expected one initial EoR; saw {}",
            self.eors
        );
        ensure!(
            self.seed_present == self.rows - usize::from(final_table)
                && (self.held[0] & 1 == 0) == final_table,
            "{phase:?}: wrong initial prefix inventory ({} of {} present)",
            self.seed_present,
            self.rows
        );
        let expected_version = if phase == Phase::Seed { 1 } else { 3 };
        ensure!(
            self.mutable_version == expected_version && self.saw_fill == (phase != Phase::Seed),
            "{phase:?}: key 1 is version {}, saw intermediate fill {}",
            self.mutable_version,
            self.saw_fill
        );
        ensure!(
            self.trigger == final_table
                && self.probe == final_table
                && self.recovery_probe == final_table
                && self.withdrawals == u64::from(final_table),
            "{phase:?}: trigger {}, probe {}, recovery probe {}, withdrawals {}",
            self.trigger,
            self.probe,
            self.recovery_probe,
            self.withdrawals
        );
        Ok(())
    }

    pub(crate) fn receipt(&self) -> Value {
        json!({"present": self.seed_present + usize::from(self.trigger) + usize::from(self.probe)
                + usize::from(self.recovery_probe),
            "recovery_probe_present": self.recovery_probe,
            "announcements": self.announcements, "withdrawals": self.withdrawals, "empty_initial_eors": self.eors,
            "replacement_version": self.mutable_version, "intermediate_fill_seen": self.saw_fill,
            "trigger_present": self.trigger, "probe_present": self.probe})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_wire::{AsPath, Ipv4NlriEntry, Ipv4UnicastMode, UpdateMessage};

    fn frame(
        add: &[Ipv4Addr],
        remove: &[Ipv4Addr],
        source: Ipv4Addr,
        asn: u32,
        stage: u32,
    ) -> Message {
        let nlri = |ips: &[Ipv4Addr]| {
            ips.iter()
                .map(|&ip| Ipv4NlriEntry {
                    prefix: Ipv4Prefix::new(ip, 32),
                    path_id: 0,
                })
                .collect::<Vec<_>>()
        };
        let attrs = [
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop(source),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![asn])],
            }),
            PathAttribute::Communities(vec![(64_512 << 16) + stage]),
        ];
        Message::Update(UpdateMessage::build(
            &nlri(add),
            &nlri(remove),
            if add.is_empty() { &[] } else { &attrs },
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
    }

    #[test]
    fn folded_table_requires_each_seed_key_replacements_and_the_actual_withdrawal() {
        let mut peer = GroupedWire::new(3);
        let keys = [BASE, BASE + 1, BASE + 2].map(Ipv4Addr::from);
        let send = |keys: &[Ipv4Addr], removed: &[Ipv4Addr], stage| {
            frame(keys, removed, SOURCE, 65_000, stage)
        };
        peer.apply_message(&send(&[], &[], 1)).unwrap();
        let mut twice = GroupedWire::new(3);
        twice.apply_message(&send(&[], &[], 1)).unwrap();
        let duplicate = twice.apply_message(&send(&[], &[], 1)).unwrap_err();
        assert!(duplicate.to_string().contains("duplicated End-of-RIB"));
        // Same number of announcements, different actual inventory.
        peer.apply_message(&send(&[keys[0], keys[1], keys[1]], &[], 1))
            .unwrap();
        assert!(peer.verify(Phase::Seed).is_err());
        peer.apply_message(&send(&keys[2..], &[], 1)).unwrap();
        peer.verify(Phase::Seed).unwrap();
        peer.apply_message(&send(&keys[1..2], &[], 3)).unwrap();
        assert!(peer.verify(Phase::Fill).is_err());
        peer.apply_message(&send(&keys[1..2], &[], 2)).unwrap();
        assert!(peer.verify(Phase::Fill).is_err());
        peer.apply_message(&send(&keys[1..2], &[], 3)).unwrap();
        peer.verify(Phase::Fill).unwrap();

        // Same number of rows across the table after replacing a withdrawn
        // seed prefix with the trigger. Each source's payload is checked.
        peer.apply_message(&send(&[TRIGGER], &[], 3)).unwrap();
        assert!(peer
            .apply_message(&frame(&[PROBE], &[], SOURCE, 65_000, 4))
            .is_err());
        peer.apply_message(&frame(&[PROBE], &[], PROBE_SOURCE, 65_002, 4))
            .unwrap();
        assert!(peer
            .apply_message(&frame(&[RECOVERY_PROBE], &[], PROBE_SOURCE, 65_002, 4))
            .is_err());
        peer.apply_message(&frame(&[RECOVERY_PROBE], &[], PROBE_SOURCE, 65_002, 5))
            .unwrap();
        assert!(peer.verify(Phase::Final).is_err(), "dropped withdrawal");
        assert!(
            peer.apply_message(&send(&[], &keys[1..2], 1)).is_err(),
            "wrong key"
        );
        // The product can put the withdrawal in its shared vector.
        peer.apply(&OutboundRouteUpdate {
            shared_withdraw: std::sync::Arc::new(vec![(
                Prefix::V4(Ipv4Prefix::new(keys[0], 32)),
                0,
            )])
            .into(),
            ..Default::default()
        })
        .unwrap();
        peer.verify(Phase::Final).unwrap();
        assert!(
            peer.apply_message(&send(&[], &keys[..1], 1)).is_err(),
            "withdrawn twice"
        );
        assert!(
            peer.apply_message(&send(&keys[2..], &[], 9)).is_err(),
            "changed stable payload"
        );
        assert!(peer
            .apply_message(&Message::Notification(rustbgpd_wire::NotificationMessage {
                code: rustbgpd_wire::NotificationCode::Cease,
                subcode: 2,
                data: Default::default()
            }))
            .is_err());
    }
}
