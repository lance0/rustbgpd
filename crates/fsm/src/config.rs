use std::net::Ipv4Addr;

use rustbgpd_wire::constants::AS_TRANS;
use rustbgpd_wire::{Afi, Capability, GracefulRestartFamily, Safi};

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
        caps.push(Capability::FourOctetAs {
            asn: self.local_asn,
        });
        caps
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
        }
    }

    #[test]
    fn local_capabilities_includes_families_and_four_octet() {
        let cfg = test_config();
        let caps = cfg.local_capabilities();
        assert_eq!(caps.len(), 2);
        assert!(matches!(
            caps[0],
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast
            }
        ));
        assert!(matches!(caps[1], Capability::FourOctetAs { asn: 65001 }));
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
        // MultiProtocol + GracefulRestart + FourOctetAs
        assert_eq!(caps.len(), 3);
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
        assert_eq!(caps.len(), 2);
        assert!(
            !caps
                .iter()
                .any(|c| matches!(c, Capability::GracefulRestart { .. }))
        );
    }
}
