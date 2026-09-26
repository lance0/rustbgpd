//! Committed local dataplane responsibility for outgoing GR/LLGR capabilities.

use std::sync::RwLock;

use rustbgpd_transport::LocalForwardingState;
use rustbgpd_wire::{Afi, Safi};

use crate::config::{Config, FibTableConfig};

fn fib_families(tables: &[FibTableConfig]) -> Vec<(Afi, Safi)> {
    let mut families = Vec::new();
    for (name, afi) in [("ipv4_unicast", Afi::Ipv4), ("ipv6_unicast", Afi::Ipv6)] {
        if tables
            .iter()
            .any(|table| table.families.iter().any(|family| family == name))
        {
            families.push((afi, Safi::Unicast));
        }
    }
    families
}

pub(crate) fn configured_kernel_families(config: &Config) -> Vec<(Afi, Safi)> {
    let mut families = fib_families(&config.fib_tables);
    if config.global.honor_blackhole && config.global.install_blackhole_discard {
        families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    }
    if !config.evpn_instances.is_empty() || !config.evpn_ip_vrfs.is_empty() {
        families.push((Afi::L2Vpn, Safi::Evpn));
    }
    families
}

/// A tiny projection of committed forwarding responsibility. OPEN emission
/// never takes the config-transaction or EVPN planning locks.
#[derive(Debug)]
pub(crate) struct ForwardingState {
    blackhole: bool,
    // IPv4 unicast, IPv6 unicast, EVPN. Both capabilities use one snapshot.
    families: RwLock<[bool; 3]>,
}

impl ForwardingState {
    pub(crate) fn new(config: &Config) -> Self {
        let kernel = configured_kernel_families(config);
        Self {
            blackhole: config.global.honor_blackhole && config.global.install_blackhole_discard,
            families: RwLock::new([
                kernel.contains(&(Afi::Ipv4, Safi::Unicast)),
                kernel.contains(&(Afi::Ipv6, Safi::Unicast)),
                kernel.contains(&(Afi::L2Vpn, Safi::Evpn)),
            ]),
        }
    }

    pub(crate) fn publish_fib(&self, tables: &[FibTableConfig]) {
        let fib = fib_families(tables);
        let mut committed = self
            .families
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        committed[0] = self.blackhole || fib.contains(&(Afi::Ipv4, Safi::Unicast));
        committed[1] = self.blackhole || fib.contains(&(Afi::Ipv6, Safi::Unicast));
    }

    pub(crate) fn publish_evpn(&self, installs: bool) {
        self.families
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[2] = installs;
    }
}

impl LocalForwardingState for ForwardingState {
    fn kernel_families(&self) -> Vec<(Afi, Safi)> {
        let committed = *self
            .families
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        [
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv6, Safi::Unicast),
            (Afi::L2Vpn, Safi::Evpn),
        ]
        .into_iter()
        .zip(committed)
        .filter_map(|(family, installs)| installs.then_some(family))
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> Config {
        toml::from_str(&format!(
            "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n{extra}\n[global.telemetry]\nlog_format = \"json\""
        ))
        .unwrap()
    }

    #[test]
    fn forwarding_state_blackhole_requires_both_flags_and_stays_startup_pinned() {
        for honor in [false, true] {
            for install in [false, true] {
                let config = config(&format!(
                    "honor_blackhole = {honor}\ninstall_blackhole_discard = {install}"
                ));
                let state = ForwardingState::new(&config);
                assert_eq!(
                    state.kernel_families().len(),
                    if honor && install { 2 } else { 0 }
                );
                let mut staged = config.clone();
                staged.global.honor_blackhole = !honor;
                staged.global.install_blackhole_discard = !install;
                state.publish_fib(&staged.fib_tables);
                assert_eq!(state.kernel_families(), configured_kernel_families(&config));
            }
        }
    }

    #[test]
    fn forwarding_state_evpn_l2_or_l3_is_family_specific() {
        for section in [
            "[[evpn_instances]]\nvni = 100\nrd = \"65001:100\"\nroute_targets = [\"65001:100\"]\nlocal_vtep_ip = \"10.0.0.1\"",
            "[[evpn_ip_vrfs]]\nname = \"blue\"\nvni = 5000\nrd = \"65001:5000\"\nroute_targets = [\"65001:5000\"]\nlocal_vtep_ip = \"10.0.0.1\"\nrouter_mac = \"02:00:00:00:00:01\"\nvrf_device = \"vrf-blue\"\nl3vxlan_device = \"vni5000\"\ntable_id = 5000",
        ] {
            let config = config(section);
            assert_eq!(
                configured_kernel_families(&config),
                vec![(Afi::L2Vpn, Safi::Evpn)]
            );
        }
    }

    #[test]
    fn forwarding_state_mixed_commit_removal_keeps_other_role() {
        let state = ForwardingState::new(&config(""));
        state.publish_evpn(true);
        let mut table = crate::test_support::basic_fib_table("v6", 1001);
        table.families = vec!["ipv6_unicast".into()];
        state.publish_fib(&[table]);
        assert_eq!(
            state.kernel_families(),
            vec![(Afi::Ipv6, Safi::Unicast), (Afi::L2Vpn, Safi::Evpn)]
        );
        state.publish_evpn(false);
        assert_eq!(state.kernel_families(), vec![(Afi::Ipv6, Safi::Unicast)]);
        state.publish_evpn(true);
        state.publish_fib(&[]);
        assert_eq!(state.kernel_families(), vec![(Afi::L2Vpn, Safi::Evpn)]);
    }
}
