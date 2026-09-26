//! Local dataplane responsibility and uncertain effects for outgoing GR/LLGR.

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

/// One snapshot of committed responsibility and possible unconfirmed effects.
#[derive(Debug)]
struct Roles {
    committed: [bool; 3],
    potential: [bool; 3],
    evpn_uncertain: bool,
}

/// OPEN emission never takes config-transaction or EVPN planning locks.
#[derive(Debug)]
pub(crate) struct ForwardingState {
    blackhole: bool,
    // IPv4 unicast, IPv6 unicast, EVPN. Both capabilities use one snapshot.
    roles: RwLock<Roles>,
    settlement: Option<rustbgpd_api::runtime_config_settlement::RuntimeConfigSettlementWatchdog>,
}

impl ForwardingState {
    pub(crate) fn new(config: &Config) -> Self {
        let kernel = configured_kernel_families(config);
        Self {
            blackhole: config.global.honor_blackhole && config.global.install_blackhole_discard,
            roles: RwLock::new(Roles {
                committed: [
                    kernel.contains(&(Afi::Ipv4, Safi::Unicast)),
                    kernel.contains(&(Afi::Ipv6, Safi::Unicast)),
                    kernel.contains(&(Afi::L2Vpn, Safi::Evpn)),
                ],
                potential: [false; 3],
                evpn_uncertain: false,
            }),
            settlement: None,
        }
    }

    pub(crate) fn with_settlement(
        mut self,
        settlement: rustbgpd_api::runtime_config_settlement::RuntimeConfigSettlementWatchdog,
    ) -> Self {
        self.settlement = Some(settlement);
        self
    }

    fn fenced(&self) -> bool {
        self.settlement
            .as_ref()
            .is_some_and(|watchdog| watchdog.owner_fence_reason().is_some())
    }

    /// Record possible effects before the shared FIB actor touches the kernel.
    /// Compensation accumulates in the same union until authority is proved.
    pub(crate) fn record_fib_attempt(&self, tables: &[FibTableConfig]) {
        let fib = fib_families(tables);
        let mut roles = self
            .roles
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (index, afi) in [Afi::Ipv4, Afi::Ipv6].into_iter().enumerate() {
            roles.potential[index] = roles.potential[index]
                || roles.committed[index]
                || fib.contains(&(afi, Safi::Unicast));
        }
    }

    pub(crate) fn publish_fib(&self, tables: &[FibTableConfig]) {
        let fib = fib_families(tables);
        let mut roles = self
            .roles
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Publication linearizes at this terminal read under the write lock.
        // A later OPEN cannot observe a partially cleared snapshot. If already
        // fenced, even a late acknowledgement cannot erase possible effects.
        let fenced = self.fenced();
        for (index, afi) in [Afi::Ipv4, Afi::Ipv6].into_iter().enumerate() {
            if fenced {
                roles.potential[index] = roles.potential[index] || roles.committed[index];
            } else {
                roles.potential[index] = false;
            }
            roles.committed[index] = self.blackhole || fib.contains(&(afi, Safi::Unicast));
        }
    }

    pub(crate) fn publish_evpn(&self, installs: bool) {
        let mut roles = self
            .roles
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.fenced() {
            roles.potential[2] = roles.potential[2] || roles.committed[2];
        } else {
            roles.potential[2] = false;
            roles.evpn_uncertain = false;
        }
        roles.committed[2] = installs;
    }

    pub(crate) fn begin_evpn_attempt(&self, installs: bool) -> EvpnAttempt<'_> {
        let mut roles = self
            .roles
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prior_potential = roles.potential[2];
        roles.potential[2] = roles.potential[2] || roles.committed[2] || installs;
        EvpnAttempt {
            state: self,
            prior_potential,
            settled: false,
        }
    }
}

/// Failed converge or executor loss must retain possible EVPN kernel effects.
/// The existing apply lock serializes attempts; no-op/validation never arm one.
pub(crate) struct EvpnAttempt<'a> {
    state: &'a ForwardingState,
    prior_potential: bool,
    settled: bool,
}

impl EvpnAttempt<'_> {
    pub(crate) fn reject_no_effect(mut self) {
        let mut roles = self
            .state
            .roles
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.state.fenced() {
            roles.potential[2] = self.prior_potential;
        }
        self.settled = true;
    }

    /// Called only after acknowledged convergence and committed publication.
    pub(crate) fn finish(mut self) {
        self.settled = true;
    }
}

impl Drop for EvpnAttempt<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.state
                .roles
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .evpn_uncertain = true;
        }
    }
}

impl LocalForwardingState for ForwardingState {
    fn kernel_families(&self) -> Vec<(Afi, Safi)> {
        let roles = self
            .roles
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The terminal read while holding the role lock is this OPEN's
        // linearization point relative to publication and fence transitions.
        let fenced = self.fenced();
        let mut kernel = roles.committed;
        for (index, installs) in kernel.iter_mut().enumerate() {
            if fenced || (index == 2 && roles.evpn_uncertain) {
                *installs |= roles.potential[index];
            }
        }
        drop(roles);
        [
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv6, Safi::Unicast),
            (Afi::L2Vpn, Safi::Evpn),
        ]
        .into_iter()
        .zip(kernel)
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
