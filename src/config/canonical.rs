use std::collections::HashMap;

use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};

use super::{
    BfdProfileConfig, BmpConfig, Config, ConfigEpoch, ConfigError, DynamicNeighborConfig,
    EthernetSegmentConfig, EventHistoryConfig, EvpnInstanceConfig, EvpnIpVrfConfig, FibTableConfig,
    Global, GnmiDialoutConfig, InboundAdmissionConfig, ManagedNetdevsConfig, MrtConfig, Neighbor,
    PeerGroupConfig, PolicyConfig, PolicyStatementConfig, RpkiConfig, SecurityConfig,
};

const STATEMENT_CHUNK_LEN: usize = 256;
const SENTINEL_ONE: &str = "rustbgpd_bounded_writer_sentinel_one";
const SENTINEL_TWO: &str = "rustbgpd_bounded_writer_sentinel_two";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct BoundedRenderStats {
    pub(super) neighbor_import_lanes: usize,
    pub(super) neighbor_export_lanes: usize,
    pub(super) peer_group_import_lanes: usize,
    pub(super) peer_group_export_lanes: usize,
    pub(super) named_policy_lanes: usize,
    pub(super) statements: usize,
    pub(super) max_chunk_statements: usize,
    pub(super) max_chunk_bytes: usize,
}

#[derive(Debug)]
enum LaneLocation {
    NeighborImport(usize),
    NeighborExport(usize),
    PeerGroupImport(String),
    PeerGroupExport(String),
    NamedPolicy(String),
}

#[derive(Debug)]
struct ExtractedLane {
    location: LaneLocation,
    statements: Vec<PolicyStatementConfig>,
    first_sentinel: String,
    second_sentinel: String,
}

impl ExtractedLane {
    fn new(location: LaneLocation, statements: Vec<PolicyStatementConfig>, ordinal: usize) -> Self {
        Self {
            location,
            statements,
            first_sentinel: format!("{SENTINEL_ONE}_{ordinal}_end"),
            second_sentinel: format!("{SENTINEL_TWO}_{ordinal}_end"),
        }
    }
}

/// Temporarily replaces every large statement lane with two tiny markers.
///
/// The exclusive config borrow prevents any other mutation while the lanes are
/// extracted. `Drop` restores the exact vectors (including allocation and
/// order) on success, serialization error, or an injected test failure.
struct StatementExtraction<'a> {
    config: &'a mut Config,
    lanes: Vec<ExtractedLane>,
}

impl<'a> StatementExtraction<'a> {
    fn new(config: &'a mut Config) -> Self {
        let mut lanes = Vec::new();
        for (index, neighbor) in config.neighbors.iter_mut().enumerate() {
            extract_lane(
                &mut lanes,
                LaneLocation::NeighborImport(index),
                &mut neighbor.import_policy,
            );
            extract_lane(
                &mut lanes,
                LaneLocation::NeighborExport(index),
                &mut neighbor.export_policy,
            );
        }
        for (name, peer_group) in &mut config.peer_groups {
            extract_lane(
                &mut lanes,
                LaneLocation::PeerGroupImport(name.clone()),
                &mut peer_group.import_policy,
            );
            extract_lane(
                &mut lanes,
                LaneLocation::PeerGroupExport(name.clone()),
                &mut peer_group.export_policy,
            );
        }
        for (name, policy) in &mut config.policy.definitions {
            extract_lane(
                &mut lanes,
                LaneLocation::NamedPolicy(name.clone()),
                &mut policy.statements,
            );
        }
        for lane in &lanes {
            let target = lane_mut(config, &lane.location);
            target.push(sentinel_statement(&lane.first_sentinel));
            target.push(sentinel_statement(&lane.second_sentinel));
        }
        Self { config, lanes }
    }
}

impl Drop for StatementExtraction<'_> {
    fn drop(&mut self) {
        for lane in &mut self.lanes {
            *lane_mut(self.config, &lane.location) = std::mem::take(&mut lane.statements);
        }
    }
}

fn extract_lane(
    lanes: &mut Vec<ExtractedLane>,
    location: LaneLocation,
    statements: &mut Vec<PolicyStatementConfig>,
) {
    if statements.is_empty() {
        return;
    }
    let ordinal = lanes.len();
    lanes.push(ExtractedLane::new(
        location,
        std::mem::take(statements),
        ordinal,
    ));
}

fn lane_mut<'a>(
    config: &'a mut Config,
    location: &LaneLocation,
) -> &'a mut Vec<PolicyStatementConfig> {
    match location {
        LaneLocation::NeighborImport(index) => &mut config.neighbors[*index].import_policy,
        LaneLocation::NeighborExport(index) => &mut config.neighbors[*index].export_policy,
        LaneLocation::PeerGroupImport(name) => {
            &mut config
                .peer_groups
                .get_mut(name)
                .expect("extracted peer group")
                .import_policy
        }
        LaneLocation::PeerGroupExport(name) => {
            &mut config
                .peer_groups
                .get_mut(name)
                .expect("extracted peer group")
                .export_policy
        }
        LaneLocation::NamedPolicy(name) => {
            &mut config
                .policy
                .definitions
                .get_mut(name)
                .expect("extracted policy")
                .statements
        }
    }
}

fn sentinel_statement(action: &str) -> PolicyStatementConfig {
    PolicyStatementConfig {
        action: action.to_string(),
        prefix: None,
        ge: None,
        le: None,
        match_community: Vec::new(),
        match_as_path: None,
        match_neighbor_set: None,
        match_route_type: None,
        match_evpn_route_type: None,
        match_as_path_length_ge: None,
        match_as_path_length_le: None,
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        match_rpki_validation: None,
        match_aspa_validation: None,
        set_local_pref: None,
        set_med: None,
        set_next_hop: None,
        set_community_add: Vec::new(),
        set_community_remove: Vec::new(),
        set_as_path_prepend: None,
    }
}

struct LaneProjection<'a> {
    location: &'a LaneLocation,
    statements: &'a [PolicyStatementConfig],
}

struct OneNeighbor<'a>(&'a LaneProjection<'a>);

impl Serialize for OneNeighbor<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        sequence.serialize_element(self.0)?;
        sequence.end()
    }
}

struct SingletonMap<'a> {
    key: &'a str,
    value: &'a LaneProjection<'a>,
}

impl Serialize for SingletonMap<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(self.key, self.value)?;
        map.end()
    }
}

struct Definitions<'a>(&'a SingletonMap<'a>);

impl Serialize for Definitions<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("definitions", self.0)?;
        map.end()
    }
}

impl Serialize for LaneProjection<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        match self.location {
            LaneLocation::NeighborImport(_) | LaneLocation::PeerGroupImport(_) => {
                map.serialize_entry("import_policy", self.statements)?;
            }
            LaneLocation::NeighborExport(_) | LaneLocation::PeerGroupExport(_) => {
                map.serialize_entry("export_policy", self.statements)?;
            }
            LaneLocation::NamedPolicy(_) => {
                map.serialize_entry("statements", self.statements)?;
            }
        }
        map.end()
    }
}

fn render_lane_projection(
    lane: &ExtractedLane,
    statements: &[PolicyStatementConfig],
    header: &str,
) -> Result<String, toml::ser::Error> {
    let projection = LaneProjection {
        location: &lane.location,
        statements,
    };
    let rendered = match &lane.location {
        LaneLocation::NeighborImport(_) | LaneLocation::NeighborExport(_) => {
            let mut root = HashMap::new();
            root.insert("neighbors", OneNeighbor(&projection));
            toml::to_string_pretty(&root)?
        }
        LaneLocation::PeerGroupImport(name) | LaneLocation::PeerGroupExport(name) => {
            let peer_groups = SingletonMap {
                key: name,
                value: &projection,
            };
            let mut root = HashMap::new();
            root.insert("peer_groups", peer_groups);
            toml::to_string_pretty(&root)?
        }
        LaneLocation::NamedPolicy(name) => {
            let policies = SingletonMap {
                key: name,
                value: &projection,
            };
            let policy = Definitions(&policies);
            let mut root = HashMap::new();
            root.insert("policy", policy);
            toml::to_string_pretty(&root)?
        }
    };
    let table = rendered.find(header).ok_or_else(|| {
        serialization_error("statement projection did not reproduce its canonical table header")
    })?;
    Ok(rendered[table..].to_string())
}

#[derive(Debug)]
struct LaneTemplate {
    range: std::ops::Range<usize>,
    header: String,
    separator: String,
}

fn lane_template(skeleton: &str, lane: &ExtractedLane) -> Result<LaneTemplate, toml::ser::Error> {
    let first = skeleton
        .find(&lane.first_sentinel)
        .ok_or_else(|| serialization_error("missing first statement sentinel"))?;
    let second = skeleton
        .find(&lane.second_sentinel)
        .ok_or_else(|| serialization_error("missing second statement sentinel"))?;
    let header_start = skeleton[..first]
        .rfind("[[")
        .ok_or_else(|| serialization_error("missing first statement header"))?;
    let first_body = skeleton[..first]
        .rfind('\n')
        .map_or(header_start, |index| index + 1);
    let first_end = skeleton[first..]
        .find('\n')
        .map_or(skeleton.len(), |index| first + index + 1);
    let second_header = skeleton[..second]
        .rfind("[[")
        .ok_or_else(|| serialization_error("missing second statement header"))?;
    let second_body = skeleton[..second]
        .rfind('\n')
        .map_or(second_header, |index| index + 1);
    let second_end = skeleton[second..]
        .find('\n')
        .map_or(skeleton.len(), |index| second + index + 1);
    let header = skeleton[header_start..first_body].to_string();
    if header != skeleton[second_header..second_body] {
        return Err(serialization_error(
            "statement sentinel headers are not byte-identical",
        ));
    }
    Ok(LaneTemplate {
        range: header_start..second_end,
        header,
        separator: skeleton[first_end..second_header].to_string(),
    })
}

fn serialization_error(message: &str) -> toml::ser::Error {
    <toml::ser::Error as serde::ser::Error>::custom(message)
}

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

/// Render the one header-bearing document retained by durable config sinks.
///
/// Large statement vectors are moved out under an RAII guard. The ordinary
/// serializer builds only a small sentinel skeleton; each real lane is then
/// serialized in bounded borrowed chunks through the same serializer. Table
/// headers, quoted map keys, separators, and statement bodies therefore remain
/// serializer-owned rather than being formatted here.
pub(super) fn render_document_bounded(
    config: &mut Config,
) -> Result<(String, BoundedRenderStats), toml::ser::Error> {
    render_document_bounded_with_hook(config, |_| Ok(()))
}

fn render_document_bounded_with_hook(
    config: &mut Config,
    mut hook: impl FnMut(&'static str) -> Result<(), toml::ser::Error>,
) -> Result<(String, BoundedRenderStats), toml::ser::Error> {
    let posture = config.rfc8212_posture();
    if posture.requires_explicit_policy {
        return Err(serde::ser::Error::custom(
            ConfigError::Rfc8212Epoch2PolicyOmission,
        ));
    }

    let extraction = StatementExtraction::new(config);
    hook("after-extraction")?;
    let skeleton = toml::to_string_pretty(&CanonicalConfig::from(&*extraction.config))?;
    let mut templates = extraction
        .lanes
        .iter()
        .enumerate()
        .map(|(index, lane)| Ok((index, lane_template(&skeleton, lane)?)))
        .collect::<Result<Vec<_>, toml::ser::Error>>()?;
    templates.sort_by_key(|(_, template)| template.range.start);
    if templates
        .windows(2)
        .any(|pair| pair[0].1.range.end > pair[1].1.range.start)
    {
        return Err(serialization_error("statement sentinel ranges overlap"));
    }

    let mut stats = BoundedRenderStats::default();
    for lane in &extraction.lanes {
        stats.statements += lane.statements.len();
        match lane.location {
            LaneLocation::NeighborImport(_) => stats.neighbor_import_lanes += 1,
            LaneLocation::NeighborExport(_) => stats.neighbor_export_lanes += 1,
            LaneLocation::PeerGroupImport(_) => stats.peer_group_import_lanes += 1,
            LaneLocation::PeerGroupExport(_) => stats.peer_group_export_lanes += 1,
            LaneLocation::NamedPolicy(_) => stats.named_policy_lanes += 1,
        }
    }

    let mut document = String::with_capacity(
        super::PERSISTED_CONFIG_HEADER.len()
            + 1
            + skeleton.len()
            + stats.statements.saturating_mul(64),
    );
    document.push_str(super::PERSISTED_CONFIG_HEADER);
    document.push('\n');
    let mut cursor = 0;
    for (lane_index, template) in templates {
        document.push_str(&skeleton[cursor..template.range.start]);
        let lane = &extraction.lanes[lane_index];
        for (chunk_index, chunk) in lane.statements.chunks(STATEMENT_CHUNK_LEN).enumerate() {
            hook("before-statement-chunk")?;
            let rendered = render_lane_projection(lane, chunk, &template.header)?;
            if chunk_index != 0 {
                document.push_str(&template.separator);
            }
            stats.max_chunk_statements = stats.max_chunk_statements.max(chunk.len());
            stats.max_chunk_bytes = stats.max_chunk_bytes.max(rendered.len());
            document.push_str(&rendered);
        }
        cursor = template.range.end;
    }
    document.push_str(&skeleton[cursor..]);
    Ok((document, stats))
}

#[cfg(test)]
pub(super) fn render_document_bounded_with_test_hook(
    config: &mut Config,
    hook: impl FnMut(&'static str) -> Result<(), toml::ser::Error>,
) -> Result<(String, BoundedRenderStats), toml::ser::Error> {
    render_document_bounded_with_hook(config, hook)
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
