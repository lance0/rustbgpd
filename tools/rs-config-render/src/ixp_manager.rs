//! Strict, manual IXP Manager v7.4 candidate rendering.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Exit;
use crate::ixp_manager_host::RenderBinding;

#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

const SCHEMA_V1: &str = "rustbgpd.ixp-manager.router-config/v1";
const SCHEMA_V2: &str = "rustbgpd.ixp-manager.router-config/v2";
const IXP_VERSION: &str = "7.4.0";
const MAX_FILTERS_PER_CLIENT: usize = 256;
const MAX_FILTERS_TOTAL: usize = 4096;
const MAX_COMPILED_RECEIVE_CELLS: usize = 4096;
const MAX_PROTOCOL_ALIASES: usize = 4096;
const BASE_HYGIENE: &str = include_str!("../../../examples/route-server/hygiene.rpol");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaVersion {
    V1,
    V2,
}

impl SchemaVersion {
    const fn schema(self) -> &'static str {
        match self {
            Self::V1 => SCHEMA_V1,
            Self::V2 => SCHEMA_V2,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Refused(&'static str),
    Input,
    Output,
    Checker,
}

impl Error {
    pub const fn exit_code(&self) -> Exit {
        match self {
            Self::Input => Exit::InvalidInput,
            Self::Refused(_) => Exit::Refused,
            Self::Output => Exit::OutputUnusable,
            Self::Checker => Exit::StrictCheckFailed,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => write!(f, "IXP Manager input refused: {reason}"),
            Self::Input => f.write_str("IXP Manager input is invalid or has an unknown field"),
            Self::Output => {
                f.write_str("candidate output must be an absent or empty private directory")
            }
            Self::Checker => f.write_str("strict checker failed; candidate has no receipt"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    ixp_manager: IxpManager,
    router: Router,
    policy: Policy,
    clients: Vec<Client>,
    #[serde(default)]
    ui_filters: Option<Vec<UiFilter>>,
    unsupported: Unsupported,
    complete: Complete,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IxpManager {
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Router {
    handle: String,
    #[serde(rename = "type")]
    kind: String,
    protocol: u8,
    asn: u32,
    router_id: String,
    peering_ip: String,
    vlan_id: u64,
    quarantine: bool,
    bgp_lc: bool,
    rfc1997_passthru: bool,
    rpki: bool,
    skip_md5: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    minimum_prefix_length: u8,
    rtr_caches: Vec<String>,
    no_transit: NoTransit,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoTransit {
    source: String,
    asns: Vec<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Client {
    customer_id: u64,
    vlan_interface_id: u64,
    name: String,
    asn: u32,
    address: String,
    peering_ips: Vec<String>,
    max_prefix: u32,
    auth: Auth,
    irr_filter: bool,
    more_specifics: bool,
    origins: Vec<u32>,
    prefixes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum Auth {
    None,
    Md5 { value: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Unsupported {
    active_ui_filters: Vec<ActiveFilter>,
    route_server_skin_files: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveFilter {
    customer_id: u64,
    filter_ids: Vec<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum FilterAction {
    AsIs,
    NoAdvertise,
    PrependOnce,
    PrependTwice,
    PrependThrice,
}

impl FilterAction {
    const fn prepend_count(self) -> Option<u8> {
        match self {
            Self::PrependOnce => Some(1),
            Self::PrependTwice => Some(2),
            Self::PrependThrice => Some(3),
            Self::AsIs | Self::NoAdvertise => None,
        }
    }

    const fn advertise_function(self) -> Option<u32> {
        match self {
            Self::AsIs => None,
            Self::NoAdvertise => Some(0),
            Self::PrependOnce => Some(101),
            Self::PrependTwice => Some(102),
            Self::PrependThrice => Some(103),
        }
    }

    const fn terminates_receive(self) -> bool {
        matches!(self, Self::AsIs | Self::NoAdvertise)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilterPeer {
    customer_id: u64,
    asn: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UiFilter {
    id: u64,
    customer_id: u64,
    #[serde(deserialize_with = "required_nullable")]
    peer: Option<FilterPeer>,
    #[serde(deserialize_with = "required_nullable")]
    received_prefix: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    advertised_prefix: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    protocol: Option<u8>,
    action_advertise: FilterAction,
    action_receive: FilterAction,
    order_by: u32,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Complete {
    handle: String,
    client_count: usize,
    #[serde(default)]
    ui_filter_count: Option<usize>,
    marker: String,
}

#[derive(Debug)]
pub struct Candidate {
    pub files: BTreeMap<String, String>,
    metadata: Value,
}

fn quoted(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization cannot fail")
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            write!(out, "{byte:02x}").expect("String writes cannot fail");
            out
        })
}

fn strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

fn prefix_key(raw: &str, family: u8) -> Option<(u128, u8)> {
    let (address, length) = raw.split_once('/')?;
    if address.contains('/') {
        return None;
    }
    let address: IpAddr = address.parse().ok()?;
    let length: u8 = length.parse().ok()?;
    let (bits, width) = match (family, address) {
        (4, IpAddr::V4(ip)) => Some((u128::from(u32::from(ip)), 32)),
        (6, IpAddr::V6(ip)) => Some((u128::from(ip), 128)),
        _ => None,
    }?;
    if length > width {
        return None;
    }
    let host = width - length;
    let host_mask = if host == 128 {
        u128::MAX
    } else {
        (1u128 << host) - 1
    };
    (bits & host_mask == 0).then_some((bits, length))
}

fn canonical_filter_prefix(raw: &str, family: u8) -> bool {
    let Some((address, raw_length)) = raw.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(length) = raw_length.parse::<u8>() else {
        return false;
    };
    prefix_key(raw, family).is_some() && raw == format!("{address}/{length}")
}

#[derive(Clone, Copy)]
struct FilterScope<'a> {
    peer: Option<u32>,
    prefix: Option<&'a str>,
}

fn intersect_axis<T: Copy + Eq>(left: Option<T>, right: Option<T>) -> Option<Option<T>> {
    match (left, right) {
        (Some(left), Some(right)) if left != right => None,
        (Some(value), _) | (_, Some(value)) => Some(Some(value)),
        (None, None) => Some(None),
    }
}

fn scope(filter: &UiFilter) -> FilterScope<'_> {
    FilterScope {
        peer: filter.peer.as_ref().and_then(|peer| peer.asn),
        prefix: filter.received_prefix.as_deref(),
    }
}

fn intersection<'a>(left: &'a UiFilter, right: &'a UiFilter) -> Option<FilterScope<'a>> {
    Some(FilterScope {
        peer: intersect_axis(scope(left).peer, scope(right).peer)?,
        prefix: intersect_axis(scope(left).prefix, scope(right).prefix)?,
    })
}

fn scope_covers(filter: &UiFilter, covered: FilterScope<'_>) -> bool {
    let candidate = scope(filter);
    (candidate.peer.is_none() || candidate.peer == covered.peer)
        && (candidate.prefix.is_none() || candidate.prefix == covered.prefix)
}

#[derive(Debug)]
struct ReceiveCell {
    peer: Option<u32>,
    prefix: Option<String>,
    prepend: u8,
    reject: bool,
}

struct CompiledReceive {
    cells: Vec<ReceiveCell>,
    peers: Vec<u32>,
    prefixes: Vec<String>,
}

fn reachable_receive_overlap(filters: &[&UiFilter]) -> bool {
    filters.iter().enumerate().any(|(right_index, right)| {
        right.action_receive.prepend_count().is_some()
            && filters[..right_index].iter().any(|left| {
                left.action_receive.prepend_count().is_some()
                    && intersection(left, right).is_some_and(|overlap| {
                        !filters[..right_index].iter().rev().any(|filter| {
                            filter.action_receive.terminates_receive()
                                && scope_covers(filter, overlap)
                        })
                    })
            })
    })
}

fn reachable_receive_filters<'a>(filters: &[&'a UiFilter]) -> Vec<&'a UiFilter> {
    filters
        .iter()
        .enumerate()
        .filter_map(|(index, filter)| {
            (!filters[..index].iter().any(|earlier| {
                earlier.action_receive.terminates_receive() && scope_covers(earlier, scope(filter))
            }))
            .then_some(*filter)
        })
        .collect()
}

fn compile_receive_cells(filters: &[&UiFilter]) -> Result<CompiledReceive, Error> {
    let peers = filters
        .iter()
        .filter_map(|filter| scope(filter).peer)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let prefixes = filters
        .iter()
        .filter_map(|filter| filter.received_prefix.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let count = (peers.len() + 1)
        .checked_mul(prefixes.len() + 1)
        .filter(|count| *count <= MAX_COMPILED_RECEIVE_CELLS)
        .ok_or(Error::Refused("receive UI-filter cell cap exceeded"))?;
    let mut cells = Vec::with_capacity(count);
    for peer in peers.iter().copied().map(Some).chain(std::iter::once(None)) {
        for prefix in prefixes
            .iter()
            .cloned()
            .map(Some)
            .chain(std::iter::once(None))
        {
            let mut prepend = 0_u8;
            let mut reject = false;
            for filter in filters {
                let candidate = scope(filter);
                if candidate.peer.is_some() && candidate.peer != peer
                    || candidate.prefix.is_some() && candidate.prefix != prefix.as_deref()
                {
                    continue;
                }
                match filter.action_receive {
                    FilterAction::AsIs => {
                        reject = false;
                        break;
                    }
                    FilterAction::NoAdvertise => {
                        reject = true;
                        break;
                    }
                    action => {
                        prepend = prepend
                            .checked_add(action.prepend_count().expect("PREPEND action"))
                            .ok_or(Error::Refused("receive prepend accumulation exceeds 255"))?;
                    }
                }
            }
            cells.push(ReceiveCell {
                peer,
                prefix,
                prepend,
                reject,
            });
        }
    }
    Ok(CompiledReceive {
        cells,
        peers,
        prefixes,
    })
}

fn valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= 128
        && handle
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn validate(
    document: &Document,
    expected: SchemaVersion,
    ui_filters_present: bool,
    ui_filter_count_present: bool,
) -> Result<Vec<Vec<String>>, Error> {
    if document.schema != expected.schema() || document.ixp_manager.version != IXP_VERSION {
        return Err(Error::Refused("unsupported schema or IXP Manager version"));
    }
    match expected {
        SchemaVersion::V1 if ui_filters_present || ui_filter_count_present => {
            return Err(Error::Refused("router-config/v2 fields require v2"));
        }
        SchemaVersion::V2
            if !ui_filters_present
                || !ui_filter_count_present
                || document.ui_filters.is_none()
                || document.complete.ui_filter_count
                    != document.ui_filters.as_ref().map(Vec::len) =>
        {
            return Err(Error::Refused("incomplete UI-filter export"));
        }
        SchemaVersion::V1 | SchemaVersion::V2 => {}
    }
    let router = &document.router;
    if !valid_handle(&router.handle)
        || router.kind != "route-server"
        || !matches!(router.protocol, 4 | 6)
        || router.asn == 0
        || router.vlan_id == 0
        || router.router_id.parse::<Ipv4Addr>().is_err()
    {
        return Err(Error::Refused("invalid route-server identity"));
    }
    if router.quarantine || !router.bgp_lc {
        return Err(Error::Refused("unsupported route-server mode"));
    }
    let local: IpAddr = router
        .peering_ip
        .parse()
        .map_err(|_| Error::Refused("invalid addressing"))?;
    if (router.protocol == 4) != local.is_ipv4() {
        return Err(Error::Refused("invalid addressing"));
    }
    if document.policy.no_transit.source != "IXP_NO_TRANSIT_ASNS_OVERRIDE"
        && !(expected == SchemaVersion::V2
            && document.policy.no_transit.source == "IXP_MANAGER_EFFECTIVE_DEFAULT")
    {
        return Err(Error::Refused("unsupported no-transit source"));
    }
    if !strictly_sorted(&document.policy.no_transit.asns)
        || document.policy.no_transit.asns.contains(&0)
    {
        return Err(Error::Refused("invalid no-transit data"));
    }
    if let Some(filter) = document.unsupported.active_ui_filters.first() {
        let _validated_shape = (filter.customer_id, &filter.filter_ids);
        return Err(Error::Refused(
            "active production UI filters are unsupported",
        ));
    }
    if !document.unsupported.route_server_skin_files.is_empty() {
        return Err(Error::Refused(
            "active BIRD skin customization is unsupported",
        ));
    }
    let maximum = if router.protocol == 4 { 32 } else { 128 };
    if document.policy.minimum_prefix_length == 0
        || document.policy.minimum_prefix_length > maximum
        || !strictly_sorted(&document.policy.rtr_caches)
        || document
            .policy
            .rtr_caches
            .iter()
            .any(|cache| match cache.parse::<SocketAddr>() {
                Ok(address) => address.port() == 0,
                Err(_) => true,
            })
        || (router.rpki && document.policy.rtr_caches.is_empty())
    {
        return Err(Error::Refused("invalid RPKI or prefix-length policy"));
    }
    if document.complete.handle != router.handle
        || document.complete.client_count != document.clients.len()
        || document.complete.marker
            != format!("END_OF_RUSTBGPD_IXP_MANAGER_CONFIG_{}", router.handle)
    {
        return Err(Error::Refused("incomplete export marker"));
    }
    if document.clients.len() > MAX_PROTOCOL_ALIASES {
        return Err(Error::Refused("Birdwatcher protocol alias cap exceeded"));
    }
    let mut customers = BTreeMap::new();
    let mut vlis = BTreeSet::new();
    let mut asns = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut effective = Vec::new();
    for client in &document.clients {
        let address: IpAddr = client
            .address
            .parse()
            .map_err(|_| Error::Refused("invalid addressing"))?;
        if client.customer_id == 0
            || client.vlan_interface_id == 0
            || client.asn == 0
            || client.max_prefix == 0
            || (router.protocol == 4) != address.is_ipv4()
            || customers.insert(client.customer_id, client.asn).is_some()
            || !vlis.insert(client.vlan_interface_id)
            || !asns.insert(client.asn)
            || !addresses.insert(address)
            || client.peering_ips.len() != 1
            || client.peering_ips[0] != client.address
        {
            return Err(Error::Refused("invalid or duplicate client data"));
        }
        if !client.irr_filter
            || client.origins.is_empty()
            || client.origins.contains(&0)
            || !strictly_sorted(&client.origins)
        {
            return Err(Error::Refused("effective IRR origins are unavailable"));
        }
        let keys = client
            .prefixes
            .iter()
            .map(|prefix| prefix_key(prefix, router.protocol))
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::Refused("invalid addressing"))?;
        if keys.is_empty() || !strictly_sorted(&keys) {
            return Err(Error::Refused("effective IRR prefixes are unavailable"));
        }
        let prefixes = client
            .prefixes
            .iter()
            .zip(keys)
            .filter_map(|(prefix, (_, length))| {
                if client.more_specifics && length > document.policy.minimum_prefix_length {
                    None
                } else if client.more_specifics && length < document.policy.minimum_prefix_length {
                    Some(format!(
                        "{prefix} le {}",
                        document.policy.minimum_prefix_length
                    ))
                } else {
                    Some(prefix.clone())
                }
            })
            .collect::<Vec<_>>();
        if prefixes.is_empty() {
            return Err(Error::Refused("effective IRR prefixes are unavailable"));
        }
        match &client.auth {
            Auth::None => {}
            Auth::Md5 { .. } if router.skip_md5 => {
                return Err(Error::Refused("MD5 present while skip_md5 is active"));
            }
            Auth::Md5 { value }
                if value.is_empty() || value.len() > 80 || is_placeholder(value) =>
            {
                return Err(Error::Refused("invalid MD5 secret"));
            }
            Auth::Md5 { .. } => {}
        }
        effective.push(prefixes);
    }
    validate_ui_filters(document, expected, &customers)?;
    Ok(effective)
}

fn validate_ui_filters(
    document: &Document,
    expected: SchemaVersion,
    customers: &BTreeMap<u64, u32>,
) -> Result<(), Error> {
    let Some(filters) = document.ui_filters.as_deref() else {
        return Ok(());
    };
    if expected != SchemaVersion::V2 || filters.len() > MAX_FILTERS_TOTAL {
        return Err(Error::Refused("UI-filter schema or total cap exceeded"));
    }
    let mut ids = BTreeSet::new();
    let mut per_customer = BTreeMap::<u64, usize>::new();
    let mut previous = None;
    for filter in filters {
        let order_key = (filter.customer_id, filter.order_by);
        let count = per_customer.entry(filter.customer_id).or_default();
        *count += 1;
        if filter.id == 0
            || filter.order_by == 0
            || !ids.insert(filter.id)
            || previous.is_some_and(|previous| previous >= order_key)
            || *count > MAX_FILTERS_PER_CLIENT
            || !customers.contains_key(&filter.customer_id)
            || filter
                .protocol
                .is_some_and(|value| value != document.router.protocol)
            || filter
                .advertised_prefix
                .as_deref()
                .is_some_and(|prefix| !canonical_filter_prefix(prefix, document.router.protocol))
            || filter
                .received_prefix
                .as_deref()
                .is_some_and(|prefix| !canonical_filter_prefix(prefix, document.router.protocol))
        {
            return Err(Error::Refused(
                "invalid UI-filter identity, order, prefix, or cap",
            ));
        }
        if let Some(peer) = &filter.peer
            && (peer.customer_id == 0 || peer.asn.is_none_or(|asn| asn == 0))
        {
            return Err(Error::Refused("UI-filter peer identity is missing"));
        }
        previous = Some(order_key);
    }
    Ok(())
}

fn is_placeholder(secret: &str) -> bool {
    matches!(
        secret.trim().to_ascii_lowercase().as_str(),
        "changeme" | "placeholder" | "<redacted>" | "redacted" | "todo"
    )
}

pub fn render_document(
    input: &[u8],
    restart_seconds: u32,
    binding: &RenderBinding,
    expected: SchemaVersion,
) -> Result<Candidate, Error> {
    if !binding.valid() {
        return Err(Error::Refused("invalid router host binding"));
    }
    if restart_seconds == 0 {
        return Err(Error::Refused("max-prefix restart must be positive"));
    }
    let input_value: Value = serde_json::from_slice(input).map_err(|_| Error::Input)?;
    let ui_filters_present = input_value
        .as_object()
        .is_some_and(|object| object.contains_key("ui_filters"));
    let ui_filter_count_present = input_value
        .get("complete")
        .and_then(Value::as_object)
        .is_some_and(|object| object.contains_key("ui_filter_count"));
    let document: Document = serde_json::from_value(input_value).map_err(|_| Error::Input)?;
    let effective = validate(
        &document,
        expected,
        ui_filters_present,
        ui_filter_count_present,
    )?;
    if document.router.handle != binding.router_handle {
        return Err(Error::Refused("router handle does not match host binding"));
    }
    let runtime = binding
        .runtime_state_dir
        .to_str()
        .ok_or(Error::Refused("runtime state directory must be UTF-8"))?;
    let mut files = BTreeMap::new();
    let mut filters = BTreeMap::<u64, Vec<&UiFilter>>::new();
    for filter in document.ui_filters.as_deref().unwrap_or_default() {
        filters.entry(filter.customer_id).or_default().push(filter);
    }
    files.insert("policy/ixp-hygiene.rpol".into(), render_hygiene(&document));
    for (client, prefixes) in document.clients.iter().zip(&effective) {
        files.insert(
            format!("policy/client-{}.rpol", client.vlan_interface_id),
            render_client(
                client,
                prefixes,
                filters.get(&client.customer_id).map_or(&[], Vec::as_slice),
                document.router.asn,
            )?,
        );
    }
    files.insert(
        "birdwatcher-protocol-aliases.conf".into(),
        render_protocol_aliases(&document),
    );
    files.insert(
        "config.toml".into(),
        render_config(&document, restart_seconds, runtime, expected),
    );
    let metadata = json!({
        "input": {"schema": expected.schema(), "ixp_manager_version": IXP_VERSION,
            "router_handle": document.router.handle, "sha256": sha256(input)},
        "counts": {"clients": document.clients.len(),
            "prefixes": effective.iter().map(Vec::len).sum::<usize>(),
            "origins": document.clients.iter().map(|c| c.origins.len()).sum::<usize>()},
        "refusals": {"status": "passed", "active_ui_filters": 0,
            "route_server_skin_files": 0, "multi_address_clients": 0},
        "host": binding
    });
    Ok(Candidate { files, metadata })
}

fn render_protocol_aliases(document: &Document) -> String {
    let mut clients = document.clients.iter().collect::<Vec<_>>();
    clients.sort_unstable_by_key(|client| client.vlan_interface_id);
    clients.into_iter().fold(String::new(), |mut out, client| {
        writeln!(
            out,
            "pb_{:04}_as{}={}@master{}",
            client.vlan_interface_id, client.asn, client.address, document.router.protocol
        )
        .expect("String writes cannot fail");
        out
    })
}

fn render_config(
    document: &Document,
    restart_seconds: u32,
    runtime: &str,
    expected: SchemaVersion,
) -> String {
    let router = &document.router;
    let mut out = format!(
        "# GENERATED candidate from IXP Manager {}.\n[global]\nasn = {}\nrouter_id = {}\nruntime_state_dir = {}\nlisten_port = 179\nlisten_addresses = [{}]\nebgp_requires_policy = true\n\n[global.telemetry]\nlog_format = \"json\"\n\n[global.telemetry.grpc_uds]\npath = {}\nmode = 0o600\n",
        document.ixp_manager.version,
        router.asn,
        quoted(&router.router_id),
        quoted(runtime),
        quoted(&router.peering_ip),
        quoted(&format!("{runtime}/grpc.sock"))
    );
    if router.rpki {
        out.push_str("\n[rpki]\n");
        for cache in &document.policy.rtr_caches {
            let _ = writeln!(out, "[[rpki.cache_servers]]\naddress = {}", quoted(cache));
        }
    }
    out.push_str("\n[policy.definitions.ixp-transparent-export]\ndefault_action = \"permit\"\n\n[policy]\nrpol_files = [\n    \"policy/ixp-hygiene.rpol\",\n");
    for client in &document.clients {
        let _ = writeln!(
            out,
            "    \"policy/client-{}.rpol\",",
            client.vlan_interface_id
        );
    }
    out.push_str(
        "]\nexport_chain = [\"ixp-transparent-export\", \"ixp-manager-own-as-export-scrub\"]\n",
    );
    for client in &document.clients {
        let family = if router.protocol == 4 {
            "ipv4_unicast"
        } else {
            "ipv6_unicast"
        };
        let _ = write!(
            out,
            "\n[[neighbors]]\naddress = {}\nremote_asn = {}\ndescription = {}\nfamilies = [{}]\nroute_server_client = true\nrole = \"route_server\"\nnext_hop_ownership = \"strict_peer\"\nper_client_best = true\nrs_control_communities = true\ninterpret_rfc1997 = {}\nmax_prefixes_{} = {}\nmax_prefix_restart_seconds = {}\nimport_policy_chain = [\"reject-special-purpose\", \"ixp-hygiene\", \"ixp-manager-hygiene\", \"client-{}\"]\n",
            quoted(&client.address),
            client.asn,
            quoted(&client.name),
            quoted(family),
            !router.rfc1997_passthru,
            if router.protocol == 4 { "ipv4" } else { "ipv6" },
            client.max_prefix,
            restart_seconds,
            client.vlan_interface_id
        );
        if expected == SchemaVersion::V2
            && document
                .ui_filters
                .as_ref()
                .is_some_and(|filters| filters.iter().any(|f| f.customer_id == client.customer_id))
        {
            let _ = writeln!(
                out,
                "export_policy_chain = [\"ixp-transparent-export\", \"client-{}-receive\", \"ixp-manager-own-as-export-scrub\"]",
                client.vlan_interface_id
            );
        }
        if let Auth::Md5 { value } = &client.auth {
            let _ = writeln!(out, "md5_password = {}", quoted(value));
        }
    }
    out
}

fn render_hygiene(document: &Document) -> String {
    let mut out = BASE_HYGIENE.to_owned();
    out.push_str("\n# IXP Manager effective policy additions.\n");
    let no_transit = &document.policy.no_transit.asns;
    if !no_transit.is_empty() {
        let values = no_transit
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let regex = no_transit
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join("|");
        let _ = writeln!(out, "asn-set ixp-manager-no-transit-asns {{ {values} }}");
        let _ = writeln!(
            out,
            "policy ixp-manager-hygiene {{\n    term reject-transit-leak {{ if route.as-path matches \"_({regex})_\" {{ reject }} }}"
        );
    } else {
        out.push_str("policy ixp-manager-hygiene {\n");
    }
    let root = if document.router.protocol == 4 {
        "0.0.0.0/0"
    } else {
        "::/0"
    };
    let maximum = if document.router.protocol == 4 {
        32
    } else {
        128
    };
    if document.policy.minimum_prefix_length < maximum {
        let _ = writeln!(
            out,
            "    term reject-too-specific {{ if route.prefix in ixp-manager-too-specific {{ reject }} }}"
        );
    }
    out.push_str("    term reject-as-path-too-short { if route.as-path.len == 0 { reject } }\n");
    out.push_str("    term reject-as-path-too-long { if route.as-path.len >= 65 { reject } }\n");
    if document.router.rpki {
        out.push_str("    term reject-rpki-invalid { if route.rpki == invalid { reject } }\n");
    }
    out.push_str("}\n");
    if document.policy.minimum_prefix_length < maximum {
        let _ = writeln!(
            out,
            "prefix-set ixp-manager-too-specific {{ {root} ge {} }}",
            document.policy.minimum_prefix_length + 1
        );
    }
    let _ = writeln!(
        out,
        "policy ixp-manager-own-as-export-scrub {{\n    term remove-own-as-large-communities {{ remove large-community {}:*:* }}\n    term accept-unmatched {{ accept }}\n}}",
        document.router.asn
    );
    out
}

fn write_filter_term(out: &mut String, name: &str, guards: &[String], action: &str) {
    if guards.is_empty() {
        let _ = writeln!(out, "    term {name} {{ {action} }}");
    } else {
        let _ = writeln!(
            out,
            "    term {name} {{ if {} {{ {action} }} }}",
            guards.join(" && ")
        );
    }
}

fn render_client(
    client: &Client,
    prefixes: &[String],
    filters: &[&UiFilter],
    router_asn: u32,
) -> Result<String, Error> {
    let slug = client.vlan_interface_id;
    let reachable_receive = reachable_receive_filters(filters);
    let compiled_receive = reachable_receive_overlap(&reachable_receive)
        .then(|| compile_receive_cells(&reachable_receive))
        .transpose()?;
    let origins = client
        .origins
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = format!(
        "# GENERATED IXP Manager IRR policy.\nasn-set client-{slug}-origins {{ {origins} }}\nprefix-set client-{slug}-prefixes {{\n"
    );
    for prefix in prefixes {
        let _ = writeln!(out, "    {prefix},");
    }
    out.push_str("}\n");
    if let Some(compiled) = &compiled_receive
        && !compiled.prefixes.is_empty()
    {
        let _ = writeln!(out, "prefix-set client-{slug}-ui-receive-prefixes {{");
        for prefix in &compiled.prefixes {
            let _ = writeln!(out, "    {prefix},");
        }
        out.push_str("}\n");
    }
    let _ = write!(
        out,
        "policy client-{slug} {{\n    term reject-first-as-not-peer-as {{ if route.as-path.len >= 1 && !(route.as-path matches \"^{}_\") {{ reject }} }}\n    term reject-irrdb-origin-as-filtered {{ if !(route.origin-as in client-{slug}-origins) {{ reject }} }}\n    term reject-irrdb-prefix-filtered {{ if !(route.prefix in client-{slug}-prefixes) {{ reject }} }}\n",
        client.asn
    );
    for filter in filters {
        let Some(function) = filter.action_advertise.advertise_function() else {
            continue;
        };
        let target = filter.peer.as_ref().and_then(|peer| peer.asn).unwrap_or(0);
        let guards = filter
            .advertised_prefix
            .as_ref()
            .map(|prefix| vec![format!("route.prefix == {prefix}")])
            .unwrap_or_default();
        write_filter_term(
            &mut out,
            &format!("ui-advertise-{}", filter.id),
            &guards,
            &format!("add large-community {router_asn}:{function}:{target}"),
        );
    }
    out.push_str("    term accept-authorized { accept }\n}\n");
    if filters.is_empty() {
        return Ok(out);
    }
    let _ = writeln!(out, "policy client-{slug}-receive {{");
    if let Some(compiled) = compiled_receive {
        let other_peers = (!compiled.peers.is_empty()).then(|| {
            format!(
                "!(route.as-path matches \"^({})_\")",
                compiled
                    .peers
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join("|")
            )
        });
        for (index, cell) in compiled.cells.iter().enumerate() {
            let mut guards = Vec::new();
            match cell.peer {
                Some(peer) => guards.push(format!("route.as-path matches \"^{peer}_\"")),
                None => guards.extend(other_peers.iter().cloned()),
            }
            match &cell.prefix {
                Some(prefix) => guards.push(format!("route.prefix == {prefix}")),
                None if !compiled.prefixes.is_empty() => guards.push(format!(
                    "!(route.prefix in client-{slug}-ui-receive-prefixes)"
                )),
                None => {}
            }
            let action = if cell.reject {
                "reject".to_owned()
            } else if cell.prepend == 0 {
                "accept".to_owned()
            } else {
                format!(
                    "prepend as {} {}; accept",
                    cell.peer
                        .map_or_else(|| "path-first".to_owned(), |peer| peer.to_string()),
                    cell.prepend
                )
            };
            write_filter_term(
                &mut out,
                &format!("ui-receive-cell-{index:04}"),
                &guards,
                &action,
            );
        }
    } else {
        for (index, filter) in filters.iter().enumerate() {
            if filters[..index].iter().any(|earlier| {
                earlier.action_receive.terminates_receive() && scope_covers(earlier, scope(filter))
            }) {
                continue;
            }
            let mut guards = Vec::new();
            if let Some(peer) = &filter.peer {
                guards.push(format!(
                    "route.as-path matches \"^{}_\"",
                    peer.asn.expect("validated peer ASN")
                ));
            }
            if let Some(prefix) = &filter.received_prefix {
                guards.push(format!("route.prefix == {prefix}"));
            }
            let action = match filter.action_receive {
                FilterAction::AsIs => "accept".to_owned(),
                FilterAction::NoAdvertise => "reject".to_owned(),
                action => format!(
                    "prepend as {} {}",
                    filter
                        .peer
                        .as_ref()
                        .and_then(|peer| peer.asn)
                        .map_or_else(|| "path-first".to_owned(), |asn| asn.to_string()),
                    action.prepend_count().expect("PREPEND action")
                ),
            };
            write_filter_term(
                &mut out,
                &format!("ui-receive-{}", filter.id),
                &guards,
                &action,
            );
        }
    }
    out.push_str("    term accept-unmatched { accept }\n}\n");
    Ok(out)
}

#[cfg(unix)]
fn private_file(path: &Path, mode: u32) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|m| m.file_type().is_file() && m.permissions().mode() & 0o777 == mode)
}

#[cfg(not(unix))]
fn private_file(_: &Path, _: u32) -> bool {
    false
}

#[cfg(unix)]
fn private_dir(path: &Path, mode: u32) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|m| m.file_type().is_dir() && m.permissions().mode() & 0o777 == mode)
}

#[cfg(not(unix))]
fn private_dir(_: &Path, _: u32) -> bool {
    false
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(not(unix))]
fn create_private_dir(_: &Path) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)
}

#[cfg(not(unix))]
fn write_private(_: &Path, _: &[u8]) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

fn prepare_output(out: &Path) -> Result<(), Error> {
    if out.exists() {
        if !out.is_dir()
            || !private_dir(out, 0o700)
            || fs::read_dir(out)
                .map_err(|_| Error::Output)?
                .next()
                .is_some()
        {
            return Err(Error::Output);
        }
    } else {
        create_private_dir(out).map_err(|_| Error::Output)?;
    }
    Ok(())
}

fn safe_version(output: &[u8]) -> Result<String, Error> {
    let text = std::str::from_utf8(output).map_err(|_| Error::Checker)?;
    let mut words = text
        .lines()
        .next()
        .ok_or(Error::Checker)?
        .split_ascii_whitespace();
    let name = words.next().ok_or(Error::Checker)?;
    let version = words.next().ok_or(Error::Checker)?;
    if name != "rustbgpd"
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-_".contains(&b))
    {
        return Err(Error::Checker);
    }
    Ok(format!("rustbgpd {version}"))
}

pub fn write_checked_candidate(
    context: &Path,
    out: &Path,
    restart_seconds: u32,
    checker: &Path,
    binding: &RenderBinding,
    expected: SchemaVersion,
) -> Result<usize, Error> {
    if !private_file(context, 0o600) {
        return Err(Error::Refused("input capture must be mode 0600"));
    }
    let input = fs::read(context).map_err(|_| Error::Input)?;
    write_checked_candidate_for(&input, out, restart_seconds, checker, binding, expected)
}

/// Render and strictly validate a private in-memory IXP Manager capture.
///
/// This is the authenticated-lifecycle entry point: callers retain ownership
/// of the fetched secret-bearing bytes and never need to persist a raw capture.
pub fn write_checked_candidate_bytes(
    input: &[u8],
    out: &Path,
    restart_seconds: u32,
    checker: &Path,
    binding: &RenderBinding,
) -> Result<usize, Error> {
    write_checked_candidate_for(
        input,
        out,
        restart_seconds,
        checker,
        binding,
        SchemaVersion::V2,
    )
}

fn write_checked_candidate_for(
    input: &[u8],
    out: &Path,
    restart_seconds: u32,
    checker: &Path,
    binding: &RenderBinding,
    expected: SchemaVersion,
) -> Result<usize, Error> {
    let candidate = render_document(input, restart_seconds, binding, expected)?;
    prepare_output(out)?;
    for (relative, contents) in &candidate.files {
        let path = out.join(relative);
        if let Some(parent) = path.parent() {
            create_private_dir(parent).map_err(|_| Error::Output)?;
        }
        write_private(&path, contents.as_bytes()).map_err(|_| Error::Output)?;
    }
    let version = Command::new(checker)
        .arg("--version")
        .output()
        .map_err(|_| Error::Checker)?;
    if !version.status.success() {
        return Err(Error::Checker);
    }
    let mut version_bytes = version.stdout;
    version_bytes.extend(version.stderr);
    let version = safe_version(&version_bytes)?;
    let checked = Command::new(checker)
        .arg("--check")
        .arg("--strict")
        .arg(out.join("config.toml"))
        .output()
        .map_err(|_| Error::Checker)?;
    if !checked.status.success() {
        return Err(Error::Checker);
    }
    let hashes = candidate
        .files
        .iter()
        .map(|(path, contents)| (path.clone(), sha256(contents.as_bytes())))
        .collect::<BTreeMap<_, _>>();
    let mut receipt = candidate.metadata;
    receipt["generated_files"] = serde_json::to_value(hashes).expect("hash map serializes");
    receipt["strict_check"] = json!({"binary_version": version, "passed": true});
    let mut encoded = serde_json::to_vec_pretty(&receipt).expect("receipt serializes");
    encoded.push(b'\n');
    write_private(&out.join("render-receipt.json"), &encoded).map_err(|_| Error::Output)?;
    Ok(candidate.files.len())
}
