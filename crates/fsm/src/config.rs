//! Peer session configuration used by the FSM.

use std::net::Ipv4Addr;

use rustbgpd_wire::constants::AS_TRANS;
use rustbgpd_wire::{
    AddPathFamily, AddPathMode, Afi, BgpRole, Capability, ExtendedNextHopFamily,
    GracefulRestartFamily, LlgrFamily, OrfCapEntry, OrfCapType, OrfSendReceive, OrfType,
    PathsLimitFamily, Safi,
};

/// Whether the RIB currently has GR/LLGR stale-retention handling for a family.
///
/// Every typed Adj-RIB-In with a wired stale lifecycle is listed: unicast,
/// `FlowSpec`, EVPN, VPNv4/VPNv6 (SAFI 128), labeled-unicast (SAFI 4),
/// BGP-LS/BGP-LS-VPN (AFI 16388),
/// and RT-Constrain (SAFI 132). A family absent here is excluded from the
/// GR/LLGR capability sets and therefore withdrawn (not retained stale) on
/// session drop.
#[must_use]
pub fn graceful_restart_preserves_family((afi, safi): (Afi, Safi)) -> bool {
    matches!(
        (afi, safi),
        (
            Afi::Ipv4 | Afi::Ipv6,
            Safi::Unicast | Safi::FlowSpec | Safi::MplsVpn | Safi::LabeledUnicast
        ) | (Afi::L2Vpn, Safi::Evpn)
            | (Afi::BgpLs, Safi::BgpLs | Safi::BgpLsVpn)
            | (Afi::Ipv4, Safi::RtConstrain)
    )
}

/// Default proposed hold time in seconds (RFC 4271 §4.2 suggested value).
/// Single source of truth for the daemon default — other crates (e.g. the
/// gRPC neighbor service's send-hold-time validation) reuse this rather
/// than re-hardcoding 90.
pub const DEFAULT_HOLD_TIME: u16 = 90;

/// Minimum default `SendHoldTime` in seconds: 8 minutes (RFC 9687 §6).
pub const MIN_DEFAULT_SEND_HOLD_TIME: u32 = 480;

/// Derive the default `SendHoldTime` for a configured hold time.
///
/// RFC 9687 §6 recommends a default of the greater of 8 minutes or 2×
/// the *negotiated* hold time. The negotiated hold time is not known at
/// configuration time, but it can never exceed the configured value
/// (RFC 4271 §4.2 takes the minimum of both proposals), so deriving
/// from the configured hold time always yields a value ≥ the RFC's
/// recommendation and always > `hold_time` as §4.4 requires.
#[must_use]
pub fn default_send_hold_time(hold_time: u16) -> u32 {
    MIN_DEFAULT_SEND_HOLD_TIME.max(2 * u32::from(hold_time))
}

/// Configuration for a single BGP peer session.
///
/// `#[non_exhaustive]`: future BGP features add fields here, so external
/// crates must build it via [`PeerConfig::new`] (then set optional fields)
/// rather than a struct literal. The fields stay `pub` for in-place
/// mutation and read access.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[expect(
    clippy::struct_excessive_bools,
    reason = "PeerConfig mirrors independent negotiated BGP feature knobs"
)]
pub struct PeerConfig {
    /// Our ASN (4-byte).
    pub local_asn: u32,
    /// Expected remote ASN (4-byte).
    pub remote_asn: u32,
    /// Our router ID.
    pub local_router_id: Ipv4Addr,
    /// Proposed hold time in seconds (0 = no keepalives, or >= 3).
    pub hold_time: u16,
    /// Send hold time in seconds (RFC 9687): tear the session down when
    /// outbound BGP data cannot be handed to the peer's TCP stream for
    /// this long. 0 = disabled. When non-zero it MUST be greater than
    /// `hold_time` (RFC 9687 §4.4) — config validation enforces this.
    /// Use [`default_send_hold_time`] to derive the RFC 9687 §6 default.
    pub send_hold_time: u32,
    /// Base connect-retry timer in seconds.
    pub connect_retry_secs: u32,
    /// Address families to advertise in OPEN capabilities.
    pub families: Vec<(Afi, Safi)>,
    /// Enable Graceful Restart capability (RFC 4724).
    pub graceful_restart: bool,
    /// Restart time advertised in GR capability (seconds, max 4095).
    pub gr_restart_time: u16,
    /// Long-lived stale routes time (RFC 9494, seconds). 0 = disabled.
    pub llgr_stale_time: u32,
    /// Accept multiple paths per prefix from this peer (RFC 7911).
    pub add_path_receive: bool,
    /// Advertise multiple paths per prefix to this peer (RFC 7911).
    pub add_path_send: bool,
    /// Maximum paths per prefix to advertise (0 = unlimited).
    pub add_path_send_max: u32,
    /// Preferred maximum paths to receive per Add-Path family (0 = do not advertise).
    pub paths_limit_receive_max: u16,
    /// Local BGP Role advertised to this eBGP peer (RFC 9234).
    pub local_role: Option<BgpRole>,
    /// Require the peer to advertise a compatible BGP Role.
    pub strict_role: bool,
    /// Advertise willingness to receive Address-Prefix ORF entries from this
    /// peer and apply them to our outbound advertisements (RFC 5291/5292).
    pub prefix_orf_receive: bool,
    /// Never treat IPv4 unicast as available on this session (IPv6-only
    /// peering). When set, IPv4 unicast is excluded from our advertised
    /// `MultiProtocol` capability (and every family-derived capability) and
    /// the RFC 4760 §8 implicit-IPv4 fallback is suppressed during
    /// negotiation.
    pub disable_ipv4_unicast: bool,
}

impl Default for PeerConfig {
    /// Defaults suitable for a plain IPv4-unicast eBGP peer with no optional
    /// capabilities negotiated: zero ASNs, an unspecified router ID, a 90s
    /// hold time, a 120s connect-retry, an empty family set, and every
    /// optional feature disabled. `Ipv4Addr` has no `Default`, so this is
    /// written by hand.
    fn default() -> Self {
        Self {
            local_asn: 0,
            remote_asn: 0,
            local_router_id: Ipv4Addr::UNSPECIFIED,
            hold_time: DEFAULT_HOLD_TIME,
            send_hold_time: default_send_hold_time(DEFAULT_HOLD_TIME),
            connect_retry_secs: 120,
            families: Vec::new(),
            graceful_restart: false,
            gr_restart_time: 0,
            llgr_stale_time: 0,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
            paths_limit_receive_max: 0,
            local_role: None,
            strict_role: false,
            prefix_orf_receive: false,
            disable_ipv4_unicast: false,
        }
    }
}

impl PeerConfig {
    /// Construct a `PeerConfig` for an IPv4-unicast eBGP peer with default
    /// optional settings.
    ///
    /// Because `PeerConfig` is `#[non_exhaustive]`, external crates cannot
    /// build it with a struct literal; use this constructor and then set any
    /// optional fields in place (the fields are `pub`). The remaining fields
    /// take their [`Default`] values.
    #[must_use]
    pub fn new(local_asn: u32, remote_asn: u32, local_router_id: Ipv4Addr) -> Self {
        Self {
            local_asn,
            remote_asn,
            local_router_id,
            ..Default::default()
        }
    }

    /// The configured families minus IPv4 unicast when
    /// `disable_ipv4_unicast` is set — the family set every advertised
    /// capability and the negotiation intersection derive from. With the
    /// flag clear this is exactly `families`.
    #[must_use]
    pub fn effective_families(&self) -> Vec<(Afi, Safi)> {
        self.families
            .iter()
            .copied()
            .filter(|&family| !(self.disable_ipv4_unicast && family == (Afi::Ipv4, Safi::Unicast)))
            .collect()
    }

    /// Build the capability list for our outgoing OPEN message.
    #[must_use]
    pub fn local_capabilities(&self) -> Vec<Capability> {
        let families = self.effective_families();
        let restart_families: Vec<_> = families
            .iter()
            .copied()
            .filter(|family| graceful_restart_preserves_family(*family))
            .collect();
        let mut caps = Vec::new();
        for &(afi, safi) in &families {
            caps.push(Capability::MultiProtocol { afi, safi });
        }
        if self.graceful_restart && !restart_families.is_empty() {
            caps.push(Capability::GracefulRestart {
                restart_state: false,
                notification: true,
                restart_time: self.gr_restart_time,
                families: restart_families
                    .iter()
                    .map(|&(afi, safi)| GracefulRestartFamily {
                        afi,
                        safi,
                        forwarding_preserved: false,
                    })
                    .collect(),
            });
        }
        // LLGR requires GR — only advertise when both are enabled (RFC 9494 §3).
        if self.graceful_restart && self.llgr_stale_time > 0 && !restart_families.is_empty() {
            caps.push(Capability::LongLivedGracefulRestart(
                restart_families
                    .iter()
                    .map(|&(afi, safi)| LlgrFamily {
                        afi,
                        safi,
                        forwarding_preserved: false,
                        stale_time: self.llgr_stale_time,
                    })
                    .collect(),
            ));
        }
        let add_path_caps = self.add_path_capabilities();
        if !add_path_caps.is_empty() {
            caps.push(Capability::AddPath(add_path_caps));
        }
        let paths_limit_caps = self.paths_limit_capabilities();
        if !paths_limit_caps.is_empty() {
            caps.push(Capability::PathsLimit(paths_limit_caps));
        }
        let orf_caps = self.orf_capabilities();
        if !orf_caps.is_empty() {
            caps.push(Capability::OutboundRouteFilter(orf_caps));
        }
        caps.push(Capability::RouteRefresh);
        caps.push(Capability::EnhancedRouteRefresh);
        caps.push(Capability::ExtendedMessage);
        let extended_nexthop_caps = self.extended_nexthop_capabilities();
        if !extended_nexthop_caps.is_empty() {
            caps.push(Capability::ExtendedNextHop(extended_nexthop_caps));
        }
        if let Some(role) = self.local_role {
            caps.push(Capability::Role { role });
        }
        caps.push(Capability::FourOctetAs {
            asn: self.local_asn,
        });
        caps
    }

    /// Build Add-Path capability entries for our outgoing OPEN message.
    ///
    /// Advertises the appropriate mode (Receive, Send, or Both) for all
    /// configured unicast, VPNv4/VPNv6 (SAFI 128), and labeled-unicast
    /// (SAFI 4) families. The single
    /// `add_path_receive`/`add_path_send` knob pair is family-blind: it
    /// covers every family this filter admits. Add-Path is not implemented
    /// for the other SAFIs — `FlowSpec`/EVPN (no demand), BGP-LS (no demand
    /// for multi-path topology feeds), and RT-Constrain (Add-Path semantics
    /// for membership NLRI are undefined-ish) — so those families are
    /// omitted from the advertised capability even when configured on the
    /// session. The RIB applies the configured `send_max` numerically per
    /// peer, but only to families that actually negotiate Add-Path Send/Both.
    #[must_use]
    pub fn add_path_capabilities(&self) -> Vec<AddPathFamily> {
        if !self.add_path_receive && !self.add_path_send {
            return Vec::new();
        }
        let mode = match (self.add_path_send, self.add_path_receive) {
            (true, true) => AddPathMode::Both,
            (true, false) => AddPathMode::Send,
            (false, true) => AddPathMode::Receive,
            (false, false) => unreachable!(),
        };
        self.effective_families()
            .into_iter()
            .filter(|(_, safi)| {
                matches!(safi, Safi::Unicast | Safi::MplsVpn | Safi::LabeledUnicast)
            })
            .map(|(afi, safi)| AddPathFamily {
                afi,
                safi,
                send_receive: mode,
            })
            .collect()
    }

    /// Build experimental Paths-Limit entries for locally receivable
    /// Add-Path families. A configured limit without Add-Path receive is not
    /// advertised because the tuple would have no effect.
    #[must_use]
    pub fn paths_limit_capabilities(&self) -> Vec<PathsLimitFamily> {
        if self.paths_limit_receive_max == 0 || !self.add_path_receive {
            return Vec::new();
        }
        self.add_path_capabilities()
            .into_iter()
            .filter(|family| {
                matches!(
                    family.send_receive,
                    AddPathMode::Receive | AddPathMode::Both
                )
            })
            .map(|family| PathsLimitFamily {
                afi: family.afi,
                safi: family.safi,
                receive_limit: self.paths_limit_receive_max,
            })
            .collect()
    }

    /// Build Outbound Route Filtering capability entries for our outgoing
    /// OPEN message (RFC 5291/5292).
    ///
    /// rustbgpd advertises the **Receive** role for the standard Address-Prefix
    /// ORF-Type (64) on each configured unicast family: it is willing to
    /// receive ORF entries from the peer and apply them to its outbound
    /// advertisements. It never advertises the Send role or the legacy
    /// type 128. Non-unicast families are omitted.
    #[must_use]
    pub fn orf_capabilities(&self) -> Vec<OrfCapEntry> {
        if !self.prefix_orf_receive {
            return Vec::new();
        }
        self.effective_families()
            .into_iter()
            .filter(|(_, safi)| *safi == Safi::Unicast)
            .map(|(afi, safi)| OrfCapEntry {
                afi,
                safi,
                orf_types: vec![OrfCapType {
                    orf_type: OrfType::AddressPrefix,
                    send_receive: OrfSendReceive::Receive,
                }],
            })
            .collect()
    }

    /// Build Extended Next Hop capability entries for our outgoing OPEN
    /// message (RFC 8950).
    ///
    /// The capability is advertised automatically when both IPv4 and IPv6
    /// unicast are configured. We advertise support for IPv4 unicast NLRI
    /// using an IPv6 next hop. With `disable_ipv4_unicast` set the IPv4
    /// unicast family is never negotiated, so the capability is omitted.
    #[must_use]
    pub fn extended_nexthop_capabilities(&self) -> Vec<ExtendedNextHopFamily> {
        let families = self.effective_families();
        let has_ipv4 = families.contains(&(Afi::Ipv4, Safi::Unicast));
        let has_ipv6 = families.contains(&(Afi::Ipv6, Safi::Unicast));
        if has_ipv4 && has_ipv6 {
            vec![ExtendedNextHopFamily {
                nlri_afi: Afi::Ipv4,
                nlri_safi: Safi::Unicast,
                next_hop_afi: Afi::Ipv6,
            }]
        } else {
            Vec::new()
        }
    }

    /// The 2-byte `my_as` field for the OPEN wire format.
    /// Returns `AS_TRANS` (23456) if `local_asn` > 65535.
    #[must_use]
    pub fn open_my_as(&self) -> u16 {
        if self.local_asn > u32::from(u16::MAX) {
            AS_TRANS
        } else {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "guard above proves local_asn fits the OPEN my_as u16 field"
            )]
            let v = self.local_asn as u16;
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PeerConfig {
        PeerConfig {
            local_asn: 65001,
            remote_asn: 65002,
            local_router_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            send_hold_time: default_send_hold_time(90),
            connect_retry_secs: 30,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
            graceful_restart: false,
            gr_restart_time: 120,
            llgr_stale_time: 0,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
            paths_limit_receive_max: 0,
            local_role: None,
            strict_role: false,
            prefix_orf_receive: false,
            disable_ipv4_unicast: false,
        }
    }

    #[test]
    fn local_capabilities_includes_families_rr_ext_msg_and_four_octet() {
        let cfg = test_config();
        let caps = cfg.local_capabilities();
        assert_eq!(caps.len(), 5);
        assert!(matches!(
            caps[0],
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast
            }
        ));
        assert!(matches!(caps[1], Capability::RouteRefresh));
        assert!(matches!(caps[2], Capability::EnhancedRouteRefresh));
        assert!(matches!(caps[3], Capability::ExtendedMessage));
        assert!(matches!(caps[4], Capability::FourOctetAs { asn: 65001 }));
    }

    #[test]
    fn local_capabilities_includes_role_when_configured() {
        let mut cfg = test_config();
        cfg.local_role = Some(BgpRole::Provider);

        let caps = cfg.local_capabilities();

        assert!(matches!(
            caps.iter()
                .find(|cap| matches!(cap, Capability::Role { .. })),
            Some(Capability::Role {
                role: BgpRole::Provider
            })
        ));
    }

    #[test]
    fn local_capabilities_include_extended_nexthop_when_dual_stack() {
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        let caps = cfg.local_capabilities();
        assert!(caps.iter().any(|cap| matches!(
            cap,
            Capability::ExtendedNextHop(families)
                if families == &[ExtendedNextHopFamily {
                    nlri_afi: Afi::Ipv4,
                    nlri_safi: Safi::Unicast,
                    next_hop_afi: Afi::Ipv6,
                }]
        )));
    }

    #[test]
    fn local_capabilities_omit_extended_nexthop_without_dual_stack() {
        let cfg = test_config();
        let caps = cfg.local_capabilities();
        assert!(
            !caps
                .iter()
                .any(|cap| matches!(cap, Capability::ExtendedNextHop(_)))
        );
    }

    #[test]
    fn default_send_hold_time_is_rfc9687_section6() {
        // Greater of 8 minutes or 2× hold time, always > hold_time.
        assert_eq!(default_send_hold_time(0), 480);
        assert_eq!(default_send_hold_time(90), 480);
        assert_eq!(default_send_hold_time(240), 480);
        assert_eq!(default_send_hold_time(241), 482);
        assert_eq!(default_send_hold_time(u16::MAX), 131_070);
        assert_eq!(PeerConfig::default().send_hold_time, 480);
    }

    #[test]
    fn open_my_as_two_byte() {
        let cfg = test_config();
        assert_eq!(cfg.open_my_as(), 65001);
    }

    #[test]
    fn open_my_as_four_byte_uses_as_trans() {
        let mut cfg = test_config();
        cfg.local_asn = 4_200_000_001;
        assert_eq!(cfg.open_my_as(), AS_TRANS);
    }

    #[test]
    fn local_capabilities_includes_graceful_restart_when_enabled() {
        let mut cfg = test_config();
        cfg.graceful_restart = true;
        cfg.gr_restart_time = 120;
        let caps = cfg.local_capabilities();
        // MultiProtocol + GracefulRestart + RouteRefresh + ExtendedMessage + FourOctetAs
        assert_eq!(caps.len(), 6);
        assert!(matches!(
            &caps[1],
            Capability::GracefulRestart {
                restart_state: false,
                notification: true,
                restart_time: 120,
                families,
            } if families.len() == 1
                && families[0].afi == Afi::Ipv4
                && families[0].safi == Safi::Unicast
                && !families[0].forwarding_preserved
        ));
    }

    #[test]
    fn local_capabilities_omits_graceful_restart_when_disabled() {
        let cfg = test_config(); // graceful_restart = false
        let caps = cfg.local_capabilities();
        assert_eq!(caps.len(), 5); // MultiProtocol + RouteRefresh + EnhancedRouteRefresh + ExtendedMessage + FourOctetAs
        assert!(
            !caps
                .iter()
                .any(|c| matches!(c, Capability::GracefulRestart { .. }))
        );
    }

    #[test]
    fn restart_capabilities_include_preserved_typed_families() {
        // The GR/LLGR stale lifecycle is wired for BGP-LS, VPN,
        // labeled-unicast, and RTC, so the advertised GR and LLGR
        // capability sets carry every configured family in the
        // preservation allowlist.
        let mut cfg = test_config();
        cfg.families = vec![
            (Afi::Ipv4, Safi::Unicast),
            (Afi::BgpLs, Safi::BgpLs),
            (Afi::BgpLs, Safi::BgpLsVpn),
            (Afi::Ipv4, Safi::MplsVpn),
            (Afi::Ipv6, Safi::MplsVpn),
            (Afi::Ipv4, Safi::LabeledUnicast),
            (Afi::Ipv6, Safi::LabeledUnicast),
            (Afi::Ipv4, Safi::RtConstrain),
        ];
        cfg.graceful_restart = true;
        cfg.llgr_stale_time = 3600;
        let caps = cfg.local_capabilities();

        let gr_families: Vec<_> = caps
            .iter()
            .find_map(|cap| match cap {
                Capability::GracefulRestart { families, .. } => Some(families),
                _ => None,
            })
            .expect("GR capability advertised")
            .iter()
            .map(|f| (f.afi, f.safi))
            .collect();
        assert_eq!(gr_families, cfg.families);

        let llgr_families: Vec<_> = caps
            .iter()
            .find_map(|cap| match cap {
                Capability::LongLivedGracefulRestart(families) => Some(families),
                _ => None,
            })
            .expect("LLGR capability advertised")
            .iter()
            .map(|f| (f.afi, f.safi))
            .collect();
        assert_eq!(llgr_families, cfg.families);
    }

    #[test]
    fn paths_limit_requires_add_path_receive() {
        let mut cfg = test_config();
        cfg.paths_limit_receive_max = 4;
        assert!(cfg.paths_limit_capabilities().is_empty());
        cfg.add_path_receive = true;
        assert_eq!(cfg.paths_limit_capabilities().len(), 1);
        assert_eq!(cfg.paths_limit_capabilities()[0].receive_limit, 4);
    }

    #[test]
    fn add_path_capabilities_empty_when_disabled() {
        let cfg = test_config(); // add_path_receive = false
        assert!(cfg.add_path_capabilities().is_empty());
    }

    #[test]
    fn add_path_capabilities_dual_stack() {
        let mut cfg = test_config();
        cfg.add_path_receive = true;
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        let caps = cfg.add_path_capabilities();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].afi, Afi::Ipv4);
        assert_eq!(caps[1].afi, Afi::Ipv6);
        assert_eq!(caps[0].send_receive, AddPathMode::Receive);
        assert_eq!(caps[1].send_receive, AddPathMode::Receive);
    }

    #[test]
    fn add_path_capabilities_ipv6_only_peer() {
        let mut cfg = test_config();
        cfg.add_path_receive = true;
        cfg.families = vec![(Afi::Ipv6, Safi::Unicast)];
        let caps = cfg.add_path_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].afi, Afi::Ipv6);
    }

    #[test]
    fn local_capabilities_includes_add_path_when_enabled() {
        let mut cfg = test_config();
        cfg.add_path_receive = true;
        let caps = cfg.local_capabilities();
        // MultiProtocol + AddPath + RouteRefresh + EnhancedRouteRefresh
        // + ExtendedMessage + FourOctetAs
        assert_eq!(caps.len(), 6);
        assert!(matches!(&caps[1], Capability::AddPath(families) if families.len() == 1));
    }

    #[test]
    fn local_capabilities_omits_add_path_when_disabled() {
        let cfg = test_config(); // add_path_receive = false
        let caps = cfg.local_capabilities();
        assert!(!caps.iter().any(|c| matches!(c, Capability::AddPath(..))));
    }

    #[test]
    fn add_path_capabilities_send_only() {
        let mut cfg = test_config();
        cfg.add_path_send = true;
        let caps = cfg.add_path_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].send_receive, AddPathMode::Send);
    }

    #[test]
    fn add_path_capabilities_both() {
        let mut cfg = test_config();
        cfg.add_path_receive = true;
        cfg.add_path_send = true;
        let caps = cfg.add_path_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].send_receive, AddPathMode::Both);
    }

    #[test]
    fn add_path_capabilities_send_dual_stack() {
        let mut cfg = test_config();
        cfg.add_path_send = true;
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        let caps = cfg.add_path_capabilities();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].afi, Afi::Ipv4);
        assert_eq!(caps[1].afi, Afi::Ipv6);
    }

    #[test]
    fn add_path_capabilities_include_vpn_families() {
        // The family-blind add_path knobs cover SAFI 128 (RFC 9107 needs
        // Add-Path between RRs) and SAFI 4; BGP-LS and RT-Constrain stay
        // excluded.
        let mut cfg = test_config();
        cfg.add_path_receive = true;
        cfg.add_path_send = true;
        cfg.families = vec![
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv4, Safi::MplsVpn),
            (Afi::Ipv6, Safi::MplsVpn),
            (Afi::Ipv4, Safi::LabeledUnicast),
            (Afi::Ipv6, Safi::LabeledUnicast),
            (Afi::BgpLs, Safi::BgpLs),
            (Afi::Ipv4, Safi::RtConstrain),
        ];
        let caps = cfg.add_path_capabilities();
        let families: Vec<(Afi, Safi)> = caps.iter().map(|c| (c.afi, c.safi)).collect();
        assert_eq!(
            families,
            vec![
                (Afi::Ipv4, Safi::Unicast),
                (Afi::Ipv4, Safi::MplsVpn),
                (Afi::Ipv6, Safi::MplsVpn),
                (Afi::Ipv4, Safi::LabeledUnicast),
                (Afi::Ipv6, Safi::LabeledUnicast),
            ]
        );
        assert!(caps.iter().all(|c| c.send_receive == AddPathMode::Both));
    }

    #[test]
    fn local_capabilities_includes_orf_when_enabled() {
        let mut cfg = test_config();
        cfg.prefix_orf_receive = true;
        let caps = cfg.local_capabilities();
        let orf = caps
            .iter()
            .find_map(|c| match c {
                Capability::OutboundRouteFilter(entries) => Some(entries),
                _ => None,
            })
            .expect("ORF capability advertised");
        assert_eq!(orf.len(), 1);
        assert_eq!(orf[0].afi, Afi::Ipv4);
        assert_eq!(orf[0].safi, Safi::Unicast);
        assert_eq!(orf[0].orf_types.len(), 1);
        assert_eq!(orf[0].orf_types[0].orf_type, OrfType::AddressPrefix);
        assert_eq!(orf[0].orf_types[0].send_receive, OrfSendReceive::Receive);
    }

    #[test]
    fn local_capabilities_omits_orf_when_disabled() {
        let cfg = test_config(); // prefix_orf_receive = false
        assert!(
            !cfg.local_capabilities()
                .iter()
                .any(|c| matches!(c, Capability::OutboundRouteFilter(_)))
        );
    }

    #[test]
    fn orf_capabilities_omit_non_unicast_families() {
        let mut cfg = test_config();
        cfg.prefix_orf_receive = true;
        cfg.families = vec![
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv6, Safi::Unicast),
            (Afi::Ipv4, Safi::FlowSpec),
        ];
        let orf = cfg.orf_capabilities();
        assert_eq!(orf.len(), 2, "only unicast families advertise ORF");
        assert!(orf.iter().all(|e| e.safi == Safi::Unicast));
    }

    #[test]
    fn effective_families_drop_ipv4_unicast_when_disabled() {
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        cfg.disable_ipv4_unicast = true;
        assert_eq!(cfg.effective_families(), vec![(Afi::Ipv6, Safi::Unicast)]);
    }

    #[test]
    fn effective_families_keep_non_unicast_ipv4_when_disabled() {
        // Only IPv4 *unicast* is excluded — e.g. IPv4 FlowSpec survives.
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::FlowSpec)];
        cfg.disable_ipv4_unicast = true;
        assert_eq!(cfg.effective_families(), vec![(Afi::Ipv4, Safi::FlowSpec)]);
    }

    #[test]
    fn local_capabilities_omit_ipv4_unicast_mp_when_disabled() {
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        cfg.disable_ipv4_unicast = true;
        let caps = cfg.local_capabilities();
        assert!(!caps.iter().any(|c| matches!(
            c,
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast
            }
        )));
        assert!(caps.iter().any(|c| matches!(
            c,
            Capability::MultiProtocol {
                afi: Afi::Ipv6,
                safi: Safi::Unicast
            }
        )));
        // Extended next hop only applies to IPv4 NLRI — never negotiated
        // when IPv4 unicast itself is disabled.
        assert!(
            !caps
                .iter()
                .any(|c| matches!(c, Capability::ExtendedNextHop(_)))
        );
    }

    #[test]
    fn graceful_restart_families_omit_ipv4_unicast_when_disabled() {
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        cfg.graceful_restart = true;
        cfg.disable_ipv4_unicast = true;
        let caps = cfg.local_capabilities();
        let gr_families = caps
            .iter()
            .find_map(|c| match c {
                Capability::GracefulRestart { families, .. } => Some(families),
                _ => None,
            })
            .expect("GR capability advertised");
        assert_eq!(gr_families.len(), 1);
        assert_eq!(gr_families[0].afi, Afi::Ipv6);
    }

    #[test]
    fn add_path_and_orf_capabilities_omit_ipv4_unicast_when_disabled() {
        let mut cfg = test_config();
        cfg.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        cfg.add_path_receive = true;
        cfg.prefix_orf_receive = true;
        cfg.disable_ipv4_unicast = true;
        let add_path = cfg.add_path_capabilities();
        assert_eq!(add_path.len(), 1);
        assert_eq!(add_path[0].afi, Afi::Ipv6);
        let orf = cfg.orf_capabilities();
        assert_eq!(orf.len(), 1);
        assert_eq!(orf[0].afi, Afi::Ipv6);
    }

    #[test]
    fn add_path_capabilities_omit_flowspec_families() {
        let mut cfg = test_config();
        cfg.add_path_receive = true;
        cfg.families = vec![
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv4, Safi::FlowSpec),
            (Afi::Ipv6, Safi::FlowSpec),
        ];

        let caps = cfg.add_path_capabilities();
        assert_eq!(caps.len(), 1, "only unicast families should be advertised");
        assert_eq!(caps[0].afi, Afi::Ipv4);
        assert_eq!(caps[0].safi, Safi::Unicast);
        assert_eq!(caps[0].send_receive, AddPathMode::Receive);
    }
}
