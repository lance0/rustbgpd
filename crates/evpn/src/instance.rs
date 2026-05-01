//! Local EVPN instance state — VNI, RD, RTs, source VTEP IP, bridge.
//!
//! An [`EvpnInstance`] is the daemon's resolved view of one local EVI on
//! this VTEP. The shape mirrors the durable bits operators set in TOML
//! — VNI, RD, RTs, local VTEP source IP, optional Linux bridge name,
//! and the `advertise_svi_mac` flag — and nothing else. Runtime state
//! the kernel/RIB will own (learned MACs, sequence numbers, peer
//! adjacency lists) lives elsewhere.
//!
//! Identity is the VNI (24-bit per RFC 8365 §5). The RD is required for
//! correctness — RFC 7432 §7 mandates a unique RD per MAC-VRF — but
//! it's *not* a primary key. [`EvpnInstanceTable`] keeps a parallel RD
//! index so two instances accidentally sharing an RD fail to install
//! with a clear error rather than silently colliding when the
//! origination path lights up later.

use std::collections::HashMap;
use std::net::IpAddr;

use rustbgpd_wire::RouteDistinguisher;

use crate::route_target::RouteTarget;

/// Maximum 24-bit VXLAN Network Identifier (RFC 8365 §5).
pub const MAX_VNI: u32 = (1 << 24) - 1;

/// A validated 24-bit VXLAN Network Identifier (RFC 8365 §5).
///
/// Constructed only via [`EvpnInstanceId::new`], which rejects 0 (RFC
/// 8365 reserves VNI 0) and anything past 24 bits. Once held, the value
/// is guaranteed to be in the legal `1..=MAX_VNI` range — downstream
/// code never has to re-validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvpnInstanceId(u32);

impl EvpnInstanceId {
    /// Construct from a raw VNI, rejecting 0 and values past 24 bits.
    ///
    /// # Errors
    /// Returns [`EvpnInstanceIdError`] if `vni == 0` or `vni > MAX_VNI`.
    pub fn new(vni: u32) -> Result<Self, EvpnInstanceIdError> {
        if vni == 0 {
            return Err(EvpnInstanceIdError::Zero);
        }
        if vni > MAX_VNI {
            return Err(EvpnInstanceIdError::TooLarge(vni));
        }
        Ok(Self(vni))
    }

    /// Raw 24-bit VNI.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for EvpnInstanceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Errors produced when constructing an [`EvpnInstanceId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EvpnInstanceIdError {
    /// VNI 0 is reserved by RFC 8365 §5 and never valid.
    #[error("VNI 0 is reserved by RFC 8365 §5")]
    Zero,
    /// The VNI exceeds the 24-bit ceiling defined by RFC 8365 §5.
    #[error("VNI {0} exceeds 24-bit maximum {MAX_VNI}")]
    TooLarge(u32),
}

/// One local EVPN instance on this VTEP.
///
/// `route_targets` is a single bidirectional list — RTs apply to both
/// import and export. Most operators set them equal; if a future use
/// case needs split import/export RT lists, the field can be replaced
/// without touching the rest of this surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnInstance {
    /// Local VNI for this instance.
    pub id: EvpnInstanceId,
    /// Route Distinguisher (RFC 4364 §4.2). Must be unique per EVI per
    /// RFC 7432 §7.
    pub rd: RouteDistinguisher,
    /// Bidirectional Route Targets — applied to both import and export.
    /// Always non-empty; deduplicated and canonically sorted by
    /// [`EvpnInstance::new`] so two instances built from the same
    /// inputs in different orders compare equal.
    pub route_targets: Vec<RouteTarget>,
    /// Source IP the local VTEP uses for VXLAN encap on this EVI.
    /// Must be unicast.
    pub local_vtep_ip: IpAddr,
    /// Optional Linux bridge name this EVI is bound to. Reserved for
    /// the kernel-reconciliation slice; carrying it on the domain
    /// type now lets validation reject duplicate bindings without a
    /// later schema break.
    pub bridge: Option<String>,
    /// Originate Type 2 routes for the SVI's MAC address (RFC 9135 §6.1).
    /// Wired through to origination only once Type 2 origination
    /// lands; persisted on the domain type so the operator-facing
    /// config doesn't churn between phases.
    pub advertise_svi_mac: bool,
}

impl EvpnInstance {
    /// Build a new instance, normalizing the RT list (dedupe + sort).
    ///
    /// # Errors
    /// Returns [`EvpnInstanceTableError::EmptyRouteTargets`] when
    /// `route_targets` is empty, and [`EvpnInstanceTableError::NonUnicastVtepIp`]
    /// when `local_vtep_ip` is unspecified, multicast, or loopback.
    pub fn new(
        id: EvpnInstanceId,
        rd: RouteDistinguisher,
        route_targets: Vec<RouteTarget>,
        local_vtep_ip: IpAddr,
        bridge: Option<String>,
        advertise_svi_mac: bool,
    ) -> Result<Self, EvpnInstanceTableError> {
        if route_targets.is_empty() {
            return Err(EvpnInstanceTableError::EmptyRouteTargets { vni: id.as_u32() });
        }
        if !is_unicast_vtep_ip(local_vtep_ip) {
            return Err(EvpnInstanceTableError::NonUnicastVtepIp {
                vni: id.as_u32(),
                ip: local_vtep_ip,
            });
        }
        let mut rts = route_targets;
        rts.sort();
        rts.dedup();
        Ok(Self {
            id,
            rd,
            route_targets: rts,
            local_vtep_ip,
            bridge,
            advertise_svi_mac,
        })
    }
}

impl std::fmt::Display for EvpnInstance {
    /// One-line operator-facing summary, suitable for logs and CLI list output.
    /// Format is intentionally stable — RT list joined with `,`, RD/VTEP/RTs
    /// laid out in the order operators are used to from FRR.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "vni={} rd={} vtep={} rts=[",
            self.id, self.rd, self.local_vtep_ip
        )?;
        for (i, rt) in self.route_targets.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{rt}")?;
        }
        f.write_str("]")?;
        if let Some(ref br) = self.bridge {
            write!(f, " bridge={br}")?;
        }
        if self.advertise_svi_mac {
            f.write_str(" advertise-svi-mac")?;
        }
        Ok(())
    }
}

/// Reject VTEP source addresses that can't be a real VXLAN tunnel
/// endpoint: unspecified, multicast, and loopback. Link-local is
/// permitted to support IPv6 link-local VTEP loopbacks if an operator
/// wants them.
fn is_unicast_vtep_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_multicast() && !v4.is_loopback(),
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast() && !v6.is_loopback(),
    }
}

/// A uniqueness-enforcing collection of local EVPN instances.
///
/// Two indexes are kept in lock-step:
///
/// - `by_vni: HashMap<EvpnInstanceId, EvpnInstance>` — primary store.
/// - `rds: HashMap<RouteDistinguisher, EvpnInstanceId>` — secondary
///   index that surfaces RD collisions at insert time. RFC 7432 §7
///   requires a unique RD per MAC-VRF; without this index, a collision
///   would silently produce a malformed control plane the moment
///   origination starts emitting routes.
///
/// `insert` is all-or-nothing: a rejected instance leaves both indexes
/// unchanged, so operators can resolve the collision and retry without
/// half-applied state.
#[derive(Debug, Clone, Default)]
pub struct EvpnInstanceTable {
    by_vni: HashMap<EvpnInstanceId, EvpnInstance>,
    rds: HashMap<RouteDistinguisher, EvpnInstanceId>,
}

impl EvpnInstanceTable {
    /// Empty table — no local EVPN instances yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of installed instances.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_vni.len()
    }

    /// `true` when no instance is installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_vni.is_empty()
    }

    /// Look up an instance by VNI.
    #[must_use]
    pub fn get(&self, id: EvpnInstanceId) -> Option<&EvpnInstance> {
        self.by_vni.get(&id)
    }

    /// Iterate installed instances in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = &EvpnInstance> {
        self.by_vni.values()
    }

    /// Snapshot of installed instances, sorted by VNI ascending. Stable
    /// ordering is a deliberate choice for CLI list output and for
    /// any diff comparison done across reloads.
    #[must_use]
    pub fn sorted(&self) -> Vec<&EvpnInstance> {
        let mut out: Vec<&EvpnInstance> = self.by_vni.values().collect();
        out.sort_by_key(|i| i.id);
        out
    }

    /// Install an instance.
    ///
    /// # Errors
    /// - [`EvpnInstanceTableError::DuplicateVni`] when an instance with
    ///   the same VNI is already installed.
    /// - [`EvpnInstanceTableError::DuplicateRd`] when the RD is already
    ///   used by a different VNI.
    pub fn insert(&mut self, instance: EvpnInstance) -> Result<(), EvpnInstanceTableError> {
        if let Some(existing) = self.by_vni.get(&instance.id) {
            return Err(EvpnInstanceTableError::DuplicateVni {
                vni: instance.id.as_u32(),
                existing_rd: existing.rd,
            });
        }
        if let Some(other_id) = self.rds.get(&instance.rd) {
            return Err(EvpnInstanceTableError::DuplicateRd {
                rd: instance.rd,
                existing_vni: other_id.as_u32(),
                attempted_vni: instance.id.as_u32(),
            });
        }
        self.rds.insert(instance.rd, instance.id);
        self.by_vni.insert(instance.id, instance);
        Ok(())
    }
}

/// Errors raised by [`EvpnInstance::new`] and [`EvpnInstanceTable::insert`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvpnInstanceTableError {
    /// An instance with this VNI is already installed.
    #[error(
        "duplicate VNI {vni}: an EVPN instance with that VNI is already installed (existing rd={existing_rd})"
    )]
    DuplicateVni {
        /// The VNI that collided.
        vni: u32,
        /// The RD already bound to that VNI in the table — included
        /// in the error so operators can identify which prior block
        /// they're conflicting with without needing to dump the whole
        /// table.
        existing_rd: RouteDistinguisher,
    },
    /// Two instances claim the same Route Distinguisher.
    #[error(
        "duplicate route distinguisher {rd}: VNI {existing_vni} already uses this RD (attempted VNI {attempted_vni})"
    )]
    DuplicateRd {
        /// The RD that collided.
        rd: RouteDistinguisher,
        /// The VNI already bound to that RD in the table.
        existing_vni: u32,
        /// The VNI of the instance being rejected.
        attempted_vni: u32,
    },
    /// `route_targets` was empty. Each EVPN instance must have at least
    /// one Route Target so import/export filtering has a key to match.
    #[error("EVPN instance with VNI {vni} has no route_targets")]
    EmptyRouteTargets {
        /// The VNI of the instance being rejected.
        vni: u32,
    },
    /// `local_vtep_ip` was unspecified, multicast, or loopback.
    #[error("EVPN instance with VNI {vni} has non-unicast local_vtep_ip {ip}")]
    NonUnicastVtepIp {
        /// The VNI of the instance being rejected.
        vni: u32,
        /// The bad IP address.
        ip: IpAddr,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn rd(s: &str) -> RouteDistinguisher {
        s.parse().unwrap()
    }

    fn rt(s: &str) -> RouteTarget {
        s.parse().unwrap()
    }

    fn vtep_ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn make_instance(vni: u32, rd_str: &str, vtep: &str) -> EvpnInstance {
        EvpnInstance::new(
            EvpnInstanceId::new(vni).unwrap(),
            rd(rd_str),
            vec![rt("65000:100")],
            vtep_ip(vtep),
            None,
            false,
        )
        .unwrap()
    }

    #[test]
    fn instance_id_rejects_zero() {
        assert_eq!(EvpnInstanceId::new(0), Err(EvpnInstanceIdError::Zero));
    }

    #[test]
    fn instance_id_rejects_overflow() {
        assert_eq!(
            EvpnInstanceId::new(MAX_VNI + 1),
            Err(EvpnInstanceIdError::TooLarge(MAX_VNI + 1))
        );
    }

    #[test]
    fn instance_id_accepts_extremes() {
        assert_eq!(EvpnInstanceId::new(1).unwrap().as_u32(), 1);
        assert_eq!(EvpnInstanceId::new(MAX_VNI).unwrap().as_u32(), MAX_VNI);
    }

    #[test]
    fn instance_rejects_empty_rt_list() {
        let err = EvpnInstance::new(
            EvpnInstanceId::new(100).unwrap(),
            rd("65000:100"),
            vec![],
            vtep_ip("10.0.0.1"),
            None,
            false,
        )
        .unwrap_err();
        assert_eq!(err, EvpnInstanceTableError::EmptyRouteTargets { vni: 100 });
    }

    #[test]
    fn instance_rejects_non_unicast_vtep_ip() {
        for bad in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "::", "::1", "ff02::1"] {
            let err = EvpnInstance::new(
                EvpnInstanceId::new(100).unwrap(),
                rd("65000:100"),
                vec![rt("65000:100")],
                vtep_ip(bad),
                None,
                false,
            )
            .unwrap_err();
            assert!(
                matches!(err, EvpnInstanceTableError::NonUnicastVtepIp { .. }),
                "expected NonUnicastVtepIp for {bad}, got {err:?}",
            );
        }
    }

    #[test]
    fn instance_dedupes_and_sorts_route_targets() {
        let inst = EvpnInstance::new(
            EvpnInstanceId::new(100).unwrap(),
            rd("65000:100"),
            vec![rt("65000:200"), rt("65000:100"), rt("65000:200")],
            vtep_ip("10.0.0.1"),
            None,
            false,
        )
        .unwrap();
        assert_eq!(inst.route_targets, vec![rt("65000:100"), rt("65000:200")]);
    }

    #[test]
    fn instance_display_format_is_stable() {
        let inst = make_instance(100, "65000:100", "10.0.0.1");
        assert_eq!(
            inst.to_string(),
            "vni=100 rd=65000:100 vtep=10.0.0.1 rts=[65000:100]"
        );
    }

    #[test]
    fn instance_display_includes_optional_fields() {
        let inst = EvpnInstance::new(
            EvpnInstanceId::new(100).unwrap(),
            rd("65000:100"),
            vec![rt("65000:100"), rt("65000:200")],
            vtep_ip("10.0.0.1"),
            Some("br100".into()),
            true,
        )
        .unwrap();
        assert_eq!(
            inst.to_string(),
            "vni=100 rd=65000:100 vtep=10.0.0.1 rts=[65000:100,65000:200] bridge=br100 advertise-svi-mac"
        );
    }

    #[test]
    fn table_insert_lookup_roundtrip() {
        let mut t = EvpnInstanceTable::new();
        assert!(t.is_empty());
        let inst = make_instance(100, "65000:100", "10.0.0.1");
        t.insert(inst.clone()).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(EvpnInstanceId::new(100).unwrap()), Some(&inst));
        assert!(t.get(EvpnInstanceId::new(101).unwrap()).is_none());
    }

    #[test]
    fn table_rejects_duplicate_vni() {
        let mut t = EvpnInstanceTable::new();
        t.insert(make_instance(100, "65000:100", "10.0.0.1"))
            .unwrap();
        let err = t
            .insert(make_instance(100, "65000:200", "10.0.0.2"))
            .unwrap_err();
        assert!(matches!(
            err,
            EvpnInstanceTableError::DuplicateVni { vni: 100, .. }
        ));
        // Insert was rejected — both indexes still reflect only the first install.
        assert_eq!(t.len(), 1);
        assert_eq!(
            t.get(EvpnInstanceId::new(100).unwrap()).unwrap().rd,
            rd("65000:100")
        );
    }

    #[test]
    fn table_rejects_duplicate_rd_across_different_vnis() {
        let mut t = EvpnInstanceTable::new();
        t.insert(make_instance(100, "65000:100", "10.0.0.1"))
            .unwrap();
        let err = t
            .insert(make_instance(200, "65000:100", "10.0.0.2"))
            .unwrap_err();
        assert!(matches!(
            err,
            EvpnInstanceTableError::DuplicateRd {
                existing_vni: 100,
                attempted_vni: 200,
                ..
            }
        ));
        // Both indexes intact: VNI 200 wasn't partially installed.
        assert_eq!(t.len(), 1);
        assert!(t.get(EvpnInstanceId::new(200).unwrap()).is_none());
    }

    #[test]
    fn table_sorted_returns_ascending_vnis() {
        let mut t = EvpnInstanceTable::new();
        t.insert(make_instance(300, "65000:300", "10.0.0.3"))
            .unwrap();
        t.insert(make_instance(100, "65000:100", "10.0.0.1"))
            .unwrap();
        t.insert(make_instance(200, "65000:200", "10.0.0.2"))
            .unwrap();
        let ids: Vec<u32> = t.sorted().iter().map(|i| i.id.as_u32()).collect();
        assert_eq!(ids, vec![100, 200, 300]);
    }

    #[test]
    fn ipv6_vtep_ip_accepted() {
        // Globally routable IPv6 should pass the unicast check.
        let inst = EvpnInstance::new(
            EvpnInstanceId::new(100).unwrap(),
            rd("65000:100"),
            vec![rt("65000:100")],
            vtep_ip("2001:db8::1"),
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            inst.local_vtep_ip,
            IpAddr::V6("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn instance_id_display() {
        assert_eq!(EvpnInstanceId::new(100).unwrap().to_string(), "100");
        assert_eq!(
            EvpnInstanceId::new(MAX_VNI).unwrap().to_string(),
            "16777215"
        );
    }

    #[test]
    fn instance_id_ordering() {
        let mut ids = [
            EvpnInstanceId::new(300).unwrap(),
            EvpnInstanceId::new(100).unwrap(),
            EvpnInstanceId::new(200).unwrap(),
        ];
        ids.sort();
        assert_eq!(ids[0].as_u32(), 100);
        assert_eq!(ids[2].as_u32(), 300);
    }

    #[test]
    fn ipv4_link_local_accepted() {
        // 169.254.0.0/16 — link-local IPv4. We accept it; operators
        // running unusual lab topologies should not be blocked here.
        let ip = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));
        assert!(is_unicast_vtep_ip(ip));
    }
}
