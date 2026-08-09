use serde::Serialize;

use super::{
    BfdProfileConfig, BmpConfig, Config, ConfigEpoch, ConfigError, DynamicNeighborConfig,
    EthernetSegmentConfig, EventHistoryConfig, EvpnInstanceConfig, EvpnIpVrfConfig, FibTableConfig,
    Global, GnmiDialoutConfig, InboundAdmissionConfig, ManagedNetdevsConfig, MrtConfig, Neighbor,
    PeerGroupConfig, PolicyConfig, RpkiConfig, SecurityConfig,
};

/// Borrowed canonical projection used only by durable/effective sinks.
///
/// The large policy and map state remains borrowed. Only `Global` is cloned so
/// the two RFC 8212 effective values can be materialized without mutating the
/// raw candidate representation.
#[derive(Serialize)]
struct CanonicalConfig<'a> {
    config_epoch: ConfigEpoch,
    global: Global,
    security: &'a SecurityConfig,
    neighbors: &'a [Neighbor],
    #[serde(serialize_with = "super::schema::serialize_sorted_hash_map")]
    peer_groups: &'a std::collections::HashMap<String, PeerGroupConfig>,
    policy: &'a PolicyConfig,
    dynamic_neighbors: &'a [DynamicNeighborConfig],
    rpki: &'a Option<RpkiConfig>,
    bmp: &'a Option<BmpConfig>,
    gnmi_dialout: &'a Option<GnmiDialoutConfig>,
    mrt: &'a Option<MrtConfig>,
    evpn_instances: &'a [EvpnInstanceConfig],
    ethernet_segments: &'a [EthernetSegmentConfig],
    evpn_ip_vrfs: &'a [EvpnIpVrfConfig],
    fib_tables: &'a [FibTableConfig],
    managed_netdevs: &'a ManagedNetdevsConfig,
    bfd_profiles: &'a [BfdProfileConfig],
    apply_bum_enforcement: bool,
    event_history: &'a EventHistoryConfig,
    inbound_admission: &'a InboundAdmissionConfig,
}

impl<'a> From<&'a Config> for CanonicalConfig<'a> {
    fn from(config: &'a Config) -> Self {
        let Config {
            config_epoch: _,
            global,
            security,
            neighbors,
            peer_groups,
            policy,
            dynamic_neighbors,
            rpki,
            bmp,
            gnmi_dialout,
            mrt,
            evpn_instances,
            ethernet_segments,
            evpn_ip_vrfs,
            fib_tables,
            managed_netdevs,
            bfd_profiles,
            apply_bum_enforcement,
            event_history,
            inbound_admission,
            file_path: _,
        } = config;
        let posture = config.rfc8212_posture();
        let mut canonical_global = global.clone();
        canonical_global.ebgp_requires_policy = Some(posture.policy_effective);
        Self {
            config_epoch: posture.config_epoch_effective,
            global: canonical_global,
            security,
            neighbors,
            peer_groups,
            policy,
            dynamic_neighbors,
            rpki,
            bmp,
            gnmi_dialout,
            mrt,
            evpn_instances,
            ethernet_segments,
            evpn_ip_vrfs,
            fib_tables,
            managed_netdevs,
            bfd_profiles,
            apply_bum_enforcement: *apply_bum_enforcement,
            event_history,
            inbound_admission,
        }
    }
}

pub(super) fn render(config: &Config) -> Result<String, toml::ser::Error> {
    let posture = config.rfc8212_posture();
    if posture.requires_explicit_policy {
        return Err(serde::ser::Error::custom(
            ConfigError::Rfc8212Epoch2PolicyOmission,
        ));
    }
    toml::to_string_pretty(&CanonicalConfig::from(config))
}

/// Test-only decomposition of [`render`] at the TOML ownership boundaries.
/// The observer runs while the serializer's table graph and then its rendered
/// string are still live, so a release child can attribute their memory.
#[cfg(all(test, target_os = "linux", feature = "jemalloc"))]
pub(super) fn render_with_phase_observer(
    config: &Config,
    mut observe: impl FnMut(&'static str),
) -> Result<String, toml::ser::Error> {
    let posture = config.rfc8212_posture();
    if posture.requires_explicit_policy {
        return Err(serde::ser::Error::custom(
            ConfigError::Rfc8212Epoch2PolicyOmission,
        ));
    }
    let canonical = CanonicalConfig::from(config);
    let mut graph = toml::ser::Buffer::new();
    canonical.serialize(toml::ser::Serializer::pretty(&mut graph))?;
    observe("graph-built");
    let rendered = graph.to_string();
    observe("rendered-with-graph");
    drop(graph);
    observe("graph-dropped");
    Ok(rendered)
}
