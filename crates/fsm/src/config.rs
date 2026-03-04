use std::net::Ipv4Addr;

use rustbgpd_wire::constants::AS_TRANS;
use rustbgpd_wire::{AddPathFamily, AddPathMode, Afi, Capability, GracefulRestartFamily, Safi};

/// Configuration for a single BGP peer session.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Our ASN (4-byte).
    pub local_asn: u32,
    /// Expected remote ASN (4-byte).
    pub remote_asn: u32,
    /// Our router ID.
    pub local_router_id: Ipv4Addr,
    /// Proposed hold time in seconds (0 = no keepalives, or >= 3).
    pub hold_time: u16,
    /// Base connect-retry timer in seconds.
    pub connect_retry_secs: u32,
    /// Address families to advertise in OPEN capabilities.
    pub families: Vec<(Afi, Safi)>,
    /// Enable Graceful Restart capability (RFC 4724).
    pub graceful_restart: bool,
    /// Restart time advertised in GR capability (seconds, max 4095).
    pub gr_restart_time: u16,
    /// Accept multiple paths per prefix from this peer (RFC 7911).
    pub add_path_receive: bool,
    /// Advertise multiple paths per prefix to this peer (RFC 7911).
    pub add_path_send: bool,
    /// Maximum paths per prefix to advertise (0 = unlimited).
    pub add_path_send_max: u32,
}

impl PeerConfig {
    /// Build the capability list for our outgoing OPEN message.
    #[must_use]
    pub fn local_capabilities(&self) -> Vec<Capability> {
        let mut caps = Vec::new();
        for &(afi, safi) in &self.families {
            caps.push(Capability::MultiProtocol { afi, safi });
        }
        if self.graceful_restart {
            caps.push(Capability::GracefulRestart {
                restart_state: false,
                restart_time: self.gr_restart_time,
                families: self
                    .families
                    .iter()
                    .map(|&(afi, safi)| GracefulRestartFamily {
                        afi,
                        safi,
                        forwarding_preserved: false,
                    })
                    .collect(),
            });
        }
        let add_path_caps = self.add_path_capabilities();
        if !add_path_caps.is_empty() {
            caps.push(Capability::AddPath(add_path_caps));
        }
        caps.push(Capability::RouteRefresh);
        caps.push(Capability::ExtendedMessage);
        caps.push(Capability::FourOctetAs {
            asn: self.local_asn,
        });
        caps
    }

    /// Build Add-Path capability entries for our outgoing OPEN message.
    ///
    /// Advertises the appropriate mode (Receive, Send, or Both) for all
    /// configured unicast families. Add-Path is not currently implemented
    /// for non-unicast SAFIs such as `FlowSpec`, so those families are
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
        self.families
            .iter()
            .filter(|(_, safi)| *safi == Safi::Unicast)
            .map(|&(afi, safi)| AddPathFamily {
                afi,
                safi,
                send_receive: mode,
            })
            .collect()
    }

    /// The 2-byte `my_as` field for the OPEN wire format.
    /// Returns `AS_TRANS` (23456) if `local_asn` > 65535.
    #[must_use]
    pub fn open_my_as(&self) -> u16 {
        if self.local_asn > u32::from(u16::MAX) {
            AS_TRANS
        } else {
            #[expect(clippy::cast_possible_truncation)]
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
            connect_retry_secs: 30,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
            graceful_restart: false,
            gr_restart_time: 120,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
        }
    }

    #[test]
    fn local_capabilities_includes_families_rr_ext_msg_and_four_octet() {
        let cfg = test_config();
        let caps = cfg.local_capabilities();
        assert_eq!(caps.len(), 4);
        assert!(matches!(
            caps[0],
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast
            }
        ));
        assert!(matches!(caps[1], Capability::RouteRefresh));
        assert!(matches!(caps[2], Capability::ExtendedMessage));
        assert!(matches!(caps[3], Capability::FourOctetAs { asn: 65001 }));
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
        assert_eq!(caps.len(), 5);
        assert!(matches!(
            &caps[1],
            Capability::GracefulRestart {
                restart_state: false,
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
        assert_eq!(caps.len(), 4); // MultiProtocol + RouteRefresh + ExtendedMessage + FourOctetAs
        assert!(
            !caps
                .iter()
                .any(|c| matches!(c, Capability::GracefulRestart { .. }))
        );
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
        // MultiProtocol + AddPath + RouteRefresh + ExtendedMessage + FourOctetAs
        assert_eq!(caps.len(), 5);
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
