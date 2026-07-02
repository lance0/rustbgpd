//! Optimal Route Reflection topology engine (RFC 9107).
//!
//! Pure data structures and algorithms: BGP-LS routes in, a directed
//! weighted graph out, hand-rolled Dijkstra SPF per vantage, and BGP
//! next-hop cost resolution. No manager state lives here in this slice —
//! the manager builds a topology on demand for the read-only API
//! (`RibUpdate::QueryOrrTopology`); the cached `OrrState` arrives with the
//! `orr_vantage` config plumbing.
//!
//! Design points (ADR-0095):
//! - Node identity is the canonical descriptor-byte
//!   [`BgpLsNodeKey`](rustbgpd_wire::BgpLsNodeKey); no
//!   router-ID interpretation for graph construction (display only).
//! - The BGP-LS Attribute (path attribute type 29) stays
//!   `PathAttribute::Unknown(RawAttribute)` end-to-end and is parsed
//!   lazily here; typing it in the wire enum would risk the reflection
//!   byte-fidelity M73 pins.
//! - Link cost is the IGP Metric (TLV 1095). A link without it is
//!   unusable and contributes no edge; its endpoints and addresses are
//!   still interned so the nodes stay observable.
//! - Unknown cost to a next-hop is `None` — the caller must treat it as
//!   least preferred (RFC 9107 §3.1).

use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::num::NonZeroUsize;

use ipnet::{Ipv4Net, Ipv6Net};
use lru::LruCache;
use prefix_trie::PrefixMap;
use rustbgpd_wire::{
    BGP_LS_TLV_AUTONOMOUS_SYSTEM, BGP_LS_TLV_BGP_LS_IDENTIFIER, BGP_LS_TLV_IGP_ROUTER_ID,
    BgpLsNlri, BgpLsNlriType, BgpLsNodeKey, BgpLsTlv, PathAttribute, Prefix, bgp_ls_attribute_tlvs,
    decode_bgpls_tlvs, igp_metric, prefix_metric,
};

use crate::route::BgpLsRibRoute;

/// BGP-LS Attribute path-attribute type code (RFC 9552 §5.3). The daemon
/// stores it as `PathAttribute::Unknown(RawAttribute)` on purpose; this is
/// the only place that needs the code point.
const BGP_LS_ATTRIBUTE_TYPE_CODE: u8 = 29;

/// Next-hop cost LRU capacity per [`SpfResult`]. A fresh cache is created
/// per SPF run, so a topology rebuild invalidates it by construction.
const NH_COST_CACHE_CAPACITY: usize = 1024;

/// Index of an interned topology node. Valid only against the
/// [`OrrTopology`] that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeIx(u32);

impl NodeIx {
    fn index(self) -> usize {
        self.0 as usize
    }
}

/// A usable directed link (carries an IGP metric).
#[derive(Debug, Clone)]
pub struct OrrLink {
    /// Interned local endpoint.
    pub local: NodeIx,
    /// Interned remote endpoint.
    pub remote: NodeIx,
    /// IGP Metric (TLV 1095).
    pub cost: u32,
    /// Interface + neighbor addresses from the link descriptors
    /// (TLVs 259-262), in interface-then-neighbor order.
    pub addresses: Vec<IpAddr>,
}

/// Display-only node descriptor fields parsed from a canonical node key.
///
/// Never used for graph identity — byte equality of the full key is the
/// identity contract; these exist for the CLI/API surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeDescriptors {
    /// Autonomous System sub-TLV 512.
    pub asn: Option<u32>,
    /// BGP-LS Identifier sub-TLV 513.
    pub bgp_ls_id: Option<u32>,
    /// IGP Router-ID sub-TLV 515, raw bytes (4-8 octets depending on IGP).
    pub router_id: Option<Vec<u8>>,
}

impl NodeDescriptors {
    /// Parse the display descriptors out of a canonical node key
    /// (protocol-id + identifier + descriptor-container sub-TLV bytes).
    /// Malformed containers yield empty descriptors, never an error.
    #[must_use]
    pub fn parse(key: &BgpLsNodeKey) -> Self {
        let container = key.as_bytes().get(9..).unwrap_or_default();
        let Ok(tlvs) = decode_bgpls_tlvs(container) else {
            return Self::default();
        };
        let u32_tlv = |type_code: u16| {
            tlvs.iter()
                .find(|tlv| tlv.type_code == type_code)
                .filter(|tlv| tlv.value.len() == 4)
                .map(|tlv| {
                    u32::from_be_bytes([tlv.value[0], tlv.value[1], tlv.value[2], tlv.value[3]])
                })
        };
        Self {
            asn: u32_tlv(BGP_LS_TLV_AUTONOMOUS_SYSTEM),
            bgp_ls_id: u32_tlv(BGP_LS_TLV_BGP_LS_IDENTIFIER),
            router_id: tlvs
                .iter()
                .find(|tlv| tlv.type_code == BGP_LS_TLV_IGP_ROUTER_ID)
                .map(|tlv| tlv.value.to_vec()),
        }
    }
}

/// The route's BGP-LS Attribute TLVs, parsed lazily from the raw
/// `PathAttribute::Unknown` bytes. Absent or malformed attributes yield no
/// TLVs (the route then simply carries no metrics).
fn attribute_tlvs(route: &BgpLsRibRoute) -> Vec<BgpLsTlv> {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::Unknown(raw) if raw.type_code == BGP_LS_ATTRIBUTE_TYPE_CODE => Some(raw),
            _ => None,
        })
        .and_then(|raw| bgp_ls_attribute_tlvs(&raw.data).ok())
        .unwrap_or_default()
}

/// Directed weighted topology graph built from BGP-LS routes.
#[derive(Debug)]
pub struct OrrTopology {
    /// Interned node keys, indexed by [`NodeIx`].
    node_keys: Vec<BgpLsNodeKey>,
    node_ix: HashMap<BgpLsNodeKey, NodeIx>,
    /// Adjacency lists of usable directed edges, indexed by [`NodeIx`].
    adj: Vec<Vec<(NodeIx, u32)>>,
    /// Usable directed links (observability record behind `adj`).
    links: Vec<OrrLink>,
    /// Link interface/neighbor address to node. Interface addresses
    /// (TLVs 259/261) map to the LOCAL node, neighbor addresses
    /// (TLVs 260/262) to the REMOTE node. Conflicts are first-writer-wins
    /// in route iteration order — a coherent IGP feed does not re-use
    /// link addresses across nodes, so this stays log-free.
    addr_index: HashMap<IpAddr, NodeIx>,
    /// Prefix NLRI reachability: advertising node + prefix metric
    /// (TLV 1155, 0 when absent).
    prefix_v4: PrefixMap<Ipv4Net, Vec<(NodeIx, u32)>>,
    prefix_v6: PrefixMap<Ipv6Net, Vec<(NodeIx, u32)>>,
}

/// Deduped graph element parsed from one NLRI.
enum Element {
    Node,
    Link {
        /// Min IGP metric across peers; `None` = unusable link.
        metric: Option<u32>,
    },
    IpPrefix {
        /// Min prefix metric across peers (absent = 0).
        metric: u32,
    },
}

impl OrrTopology {
    /// Build a topology from BGP-LS routes (typically every peer's
    /// Adj-RIB-In, NOT the Loc-RIB — RFC 9107 wants the union view).
    ///
    /// The same NLRI advertised by multiple peers is one graph element;
    /// when peers disagree on the BGP-LS Attribute, the minimum metric
    /// wins (conservative SPF input). Parallel links (distinct NLRIs
    /// between the same endpoints) are all kept — Dijkstra takes the min
    /// naturally. Nodes materialize from Link NLRI endpoints; Node NLRIs
    /// contribute keys too but are not required.
    pub fn build<'a>(routes: impl Iterator<Item = &'a BgpLsRibRoute>) -> Self {
        // Pass 1: dedup by NLRI across peers, folding metrics to the min,
        // preserving first-seen order for deterministic node indexes.
        let mut order: Vec<(&'a BgpLsNlri, Element)> = Vec::new();
        let mut seen: HashMap<&'a BgpLsNlri, usize> = HashMap::new();
        for route in routes {
            let element = match route.nlri.nlri_type {
                BgpLsNlriType::Node => Element::Node,
                BgpLsNlriType::Link => Element::Link {
                    metric: igp_metric(&attribute_tlvs(route)),
                },
                BgpLsNlriType::Ipv4TopologyPrefix | BgpLsNlriType::Ipv6TopologyPrefix => {
                    Element::IpPrefix {
                        metric: prefix_metric(&attribute_tlvs(route)).unwrap_or(0),
                    }
                }
                BgpLsNlriType::Unknown(_) => continue,
            };
            match seen.get(&route.nlri) {
                None => {
                    seen.insert(&route.nlri, order.len());
                    order.push((&route.nlri, element));
                }
                Some(&at) => match (&mut order[at].1, element) {
                    (Element::Link { metric }, Element::Link { metric: other }) => {
                        *metric = match (*metric, other) {
                            (Some(a), Some(b)) => Some(a.min(b)),
                            (a, b) => a.or(b),
                        };
                    }
                    (Element::IpPrefix { metric }, Element::IpPrefix { metric: other }) => {
                        *metric = (*metric).min(other);
                    }
                    _ => {}
                },
            }
        }

        // Pass 2: intern nodes, index addresses, and emit edges.
        let mut topo = Self {
            node_keys: Vec::new(),
            node_ix: HashMap::new(),
            adj: Vec::new(),
            links: Vec::new(),
            addr_index: HashMap::new(),
            prefix_v4: PrefixMap::new(),
            prefix_v6: PrefixMap::new(),
        };
        for (nlri, element) in order {
            match element {
                Element::Node => {
                    if let Some(key) = nlri.local_node_key() {
                        topo.intern(key);
                    }
                }
                Element::Link { metric } => topo.add_link(nlri, metric),
                Element::IpPrefix { metric } => topo.add_prefix(nlri, metric),
            }
        }
        topo
    }

    fn intern(&mut self, key: BgpLsNodeKey) -> NodeIx {
        if let Some(&ix) = self.node_ix.get(&key) {
            return ix;
        }
        let ix = NodeIx(u32::try_from(self.node_keys.len()).expect("more than u32::MAX nodes"));
        self.node_keys.push(key.clone());
        self.adj.push(Vec::new());
        self.node_ix.insert(key, ix);
        ix
    }

    fn add_link(&mut self, nlri: &BgpLsNlri, metric: Option<u32>) {
        let (Some(local_key), Some(remote_key)) = (nlri.local_node_key(), nlri.remote_node_key())
        else {
            return;
        };
        let local = self.intern(local_key);
        let remote = self.intern(remote_key);

        // Interface addresses resolve to the local node, neighbor
        // addresses to the remote node — regardless of link usability,
        // so an unmetered link still anchors NH resolution.
        let mut addresses = Vec::new();
        for (addr, node) in [
            (nlri.link_ipv4_interface_address().map(IpAddr::V4), local),
            (nlri.link_ipv6_interface_address().map(IpAddr::V6), local),
            (nlri.link_ipv4_neighbor_address().map(IpAddr::V4), remote),
            (nlri.link_ipv6_neighbor_address().map(IpAddr::V6), remote),
        ] {
            if let Some(addr) = addr {
                addresses.push(addr);
                self.addr_index.entry(addr).or_insert(node);
            }
        }

        if let Some(cost) = metric {
            self.adj[local.index()].push((remote, cost));
            self.links.push(OrrLink {
                local,
                remote,
                cost,
                addresses,
            });
        }
    }

    fn add_prefix(&mut self, nlri: &BgpLsNlri, metric: u32) {
        let (Some(prefix), Some(node_key)) = (nlri.ip_reachability(), nlri.local_node_key()) else {
            return;
        };
        let node = self.intern(node_key);
        match prefix {
            Prefix::V4(p) => {
                let net = Ipv4Net::new(p.addr, p.len).expect("ip_reachability validates length");
                self.prefix_v4.entry(net).or_default().push((node, metric));
            }
            Prefix::V6(p) => {
                let net = Ipv6Net::new(p.addr, p.len).expect("ip_reachability validates length");
                self.prefix_v6.entry(net).or_default().push((node, metric));
            }
        }
    }

    /// Number of interned nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.node_keys.len()
    }

    /// Number of usable directed links.
    #[must_use]
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Usable directed links.
    #[must_use]
    pub fn links(&self) -> &[OrrLink] {
        &self.links
    }

    /// The canonical key of an interned node.
    #[must_use]
    pub fn node_key(&self, node: NodeIx) -> Option<&BgpLsNodeKey> {
        self.node_keys.get(node.index())
    }

    /// Look up an interned node by canonical key.
    #[must_use]
    pub fn node_ix(&self, key: &BgpLsNodeKey) -> Option<NodeIx> {
        self.node_ix.get(key).copied()
    }

    /// Resolve an IP address to a topology node: (a) exact link
    /// interface/neighbor address hit; (b) longest-prefix match over
    /// Prefix NLRIs, picking the advertising node with the lowest prefix
    /// metric. `None` when the address is outside the topology.
    #[must_use]
    pub fn resolve_node(&self, ip: IpAddr) -> Option<NodeIx> {
        if let Some(&ix) = self.addr_index.get(&ip) {
            return Some(ix);
        }
        self.prefix_lpm(ip)?
            .iter()
            .min_by_key(|(_, metric)| *metric)
            .map(|&(ix, _)| ix)
    }

    fn prefix_lpm(&self, ip: IpAddr) -> Option<&[(NodeIx, u32)]> {
        match ip {
            IpAddr::V4(addr) => self
                .prefix_v4
                .get_lpm(&Ipv4Net::new(addr, 32).expect("/32 is a valid IPv4 length"))
                .map(|(_, advertisers)| advertisers.as_slice()),
            IpAddr::V6(addr) => self
                .prefix_v6
                .get_lpm(&Ipv6Net::new(addr, 128).expect("/128 is a valid IPv6 length"))
                .map(|(_, advertisers)| advertisers.as_slice()),
        }
    }

    /// Dijkstra shortest-path-first from `source` over usable links.
    /// Distances saturate at `u64::MAX`; unreachable nodes are absent
    /// from the result.
    #[must_use]
    pub fn spf(&self, source: NodeIx) -> SpfResult {
        let mut dist: Vec<Option<u64>> = vec![None; self.node_keys.len()];
        let mut heap: BinaryHeap<Reverse<(u64, u32)>> = BinaryHeap::new();
        if let Some(entry) = dist.get_mut(source.index()) {
            *entry = Some(0);
            heap.push(Reverse((0, source.0)));
        }
        while let Some(Reverse((d, ix))) = heap.pop() {
            if dist[ix as usize] != Some(d) {
                continue; // stale heap entry
            }
            for &(next, cost) in &self.adj[ix as usize] {
                let nd = d.saturating_add(u64::from(cost));
                if dist[next.index()].is_none_or(|current| nd < current) {
                    dist[next.index()] = Some(nd);
                    heap.push(Reverse((nd, next.0)));
                }
            }
        }
        SpfResult {
            dist,
            nh_cache: RefCell::new(LruCache::new(
                NonZeroUsize::new(NH_COST_CACHE_CAPACITY).unwrap_or(NonZeroUsize::MIN),
            )),
        }
    }

    /// Serializable snapshot for the read-only topology API.
    #[must_use]
    pub fn snapshot(&self) -> OrrTopologySnapshot {
        let mut link_counts = vec![0_u32; self.node_keys.len()];
        for link in &self.links {
            link_counts[link.local.index()] += 1;
        }
        let descriptors: Vec<NodeDescriptors> =
            self.node_keys.iter().map(NodeDescriptors::parse).collect();
        let router_id_hex = |ix: NodeIx| {
            descriptors[ix.index()]
                .router_id
                .as_deref()
                .map(hex)
                .unwrap_or_default()
        };

        let nodes = self
            .node_keys
            .iter()
            .zip(&descriptors)
            .zip(&link_counts)
            .map(|((key, desc), &link_count)| OrrNodeSnapshot {
                key_hex: hex(key.as_bytes()),
                asn: desc.asn,
                bgp_ls_id: desc.bgp_ls_id,
                router_id_hex: desc.router_id.as_deref().map(hex).unwrap_or_default(),
                link_count,
            })
            .collect();

        let links = self
            .links
            .iter()
            .map(|link| OrrLinkSnapshot {
                local_key_hex: hex(self.node_keys[link.local.index()].as_bytes()),
                local_router_id_hex: router_id_hex(link.local),
                remote_key_hex: hex(self.node_keys[link.remote.index()].as_bytes()),
                remote_router_id_hex: router_id_hex(link.remote),
                cost: link.cost,
                addresses: link.addresses.iter().map(ToString::to_string).collect(),
            })
            .collect();

        let mut prefixes = Vec::new();
        for (net, advertisers) in &self.prefix_v4 {
            for &(node, metric) in advertisers {
                prefixes.push(OrrPrefixSnapshot {
                    prefix: net.to_string(),
                    node_key_hex: hex(self.node_keys[node.index()].as_bytes()),
                    metric,
                });
            }
        }
        for (net, advertisers) in &self.prefix_v6 {
            for &(node, metric) in advertisers {
                prefixes.push(OrrPrefixSnapshot {
                    prefix: net.to_string(),
                    node_key_hex: hex(self.node_keys[node.index()].as_bytes()),
                    metric,
                });
            }
        }

        OrrTopologySnapshot {
            nodes,
            links,
            prefixes,
        }
    }
}

/// SPF distance map from one vantage node, with a per-run next-hop cost
/// LRU (a rebuild produces a fresh `SpfResult`, so the cache can never go
/// stale against its topology).
#[derive(Debug)]
pub struct SpfResult {
    dist: Vec<Option<u64>>,
    nh_cache: RefCell<LruCache<IpAddr, Option<u64>>>,
}

impl SpfResult {
    /// Distance from the vantage to `node`; `None` when unreachable.
    #[must_use]
    pub fn dist_to(&self, node: NodeIx) -> Option<u64> {
        self.dist.get(node.index()).copied().flatten()
    }

    /// Interior cost from the vantage to a BGP next-hop: (a) exact link
    /// address hit yields the node distance; (b) longest-prefix match
    /// yields the min over advertisers of distance + prefix metric;
    /// (c) `None` — the caller must rank unknown-cost as least preferred.
    ///
    /// `topo` must be the topology this SPF was computed over.
    #[must_use]
    pub fn cost_to(&self, topo: &OrrTopology, nh: IpAddr) -> Option<u64> {
        if let Some(&cached) = self.nh_cache.borrow_mut().get(&nh) {
            return cached;
        }
        let cost = self.compute_cost(topo, nh);
        self.nh_cache.borrow_mut().put(nh, cost);
        cost
    }

    fn compute_cost(&self, topo: &OrrTopology, nh: IpAddr) -> Option<u64> {
        if let Some(&ix) = topo.addr_index.get(&nh) {
            // Exact hit wins outright; an unreachable owner is a real
            // unknown-cost answer, not a fall-through to LPM.
            return self.dist_to(ix);
        }
        topo.prefix_lpm(nh)?
            .iter()
            .filter_map(|&(node, metric)| {
                self.dist_to(node)
                    .map(|d| d.saturating_add(u64::from(metric)))
            })
            .min()
    }
}

/// Serializable topology snapshot for `ListTopologyNodes`/`ListTopologyLinks`.
#[derive(Debug, Clone, Default)]
pub struct OrrTopologySnapshot {
    /// Interned nodes in index order.
    pub nodes: Vec<OrrNodeSnapshot>,
    /// Usable directed links.
    pub links: Vec<OrrLinkSnapshot>,
    /// Prefix NLRI reachability entries.
    pub prefixes: Vec<OrrPrefixSnapshot>,
}

/// One topology node, display-ready.
#[derive(Debug, Clone)]
pub struct OrrNodeSnapshot {
    /// Full canonical node key, lowercase hex.
    pub key_hex: String,
    /// AS sub-TLV 512.
    pub asn: Option<u32>,
    /// BGP-LS Identifier sub-TLV 513.
    pub bgp_ls_id: Option<u32>,
    /// IGP Router-ID sub-TLV 515, lowercase hex; empty when absent.
    pub router_id_hex: String,
    /// Outgoing usable links.
    pub link_count: u32,
}

/// One usable directed link, display-ready.
#[derive(Debug, Clone)]
pub struct OrrLinkSnapshot {
    /// Local endpoint canonical key, lowercase hex.
    pub local_key_hex: String,
    /// Local endpoint IGP Router-ID, lowercase hex; empty when absent.
    pub local_router_id_hex: String,
    /// Remote endpoint canonical key, lowercase hex.
    pub remote_key_hex: String,
    /// Remote endpoint IGP Router-ID, lowercase hex; empty when absent.
    pub remote_router_id_hex: String,
    /// IGP Metric (TLV 1095).
    pub cost: u32,
    /// Link interface/neighbor addresses.
    pub addresses: Vec<String>,
}

/// One Prefix NLRI reachability entry, display-ready.
#[derive(Debug, Clone)]
pub struct OrrPrefixSnapshot {
    /// Advertised prefix in CIDR form.
    pub prefix: String,
    /// Advertising node canonical key, lowercase hex.
    pub node_key_hex: String,
    /// Prefix Metric (TLV 1155), 0 when absent.
    pub metric: u32,
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Canonical BGP-LS topology fixtures shared across the ORR arc's tests
/// (the square topology here is the same shape the M76 interop injects).
#[cfg(test)]
pub(crate) mod fixtures {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Instant;

    use bytes::Bytes;
    use rustbgpd_wire::{
        BGP_LS_TLV_AUTONOMOUS_SYSTEM, BGP_LS_TLV_IGP_METRIC, BGP_LS_TLV_IGP_ROUTER_ID,
        BGP_LS_TLV_IP_REACHABILITY, BGP_LS_TLV_IPV4_INTERFACE_ADDRESS,
        BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS, BGP_LS_TLV_IPV6_INTERFACE_ADDRESS,
        BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS, BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS,
        BGP_LS_TLV_PREFIX_METRIC, BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS, BgpLsNlri, BgpLsNlriType,
        BgpLsNodeKey, BgpLsTlv, PathAttribute, RawAttribute, encode_bgpls_tlvs,
    };

    use crate::route::{BgpLsFamily, BgpLsRibRoute, RouteOrigin};

    fn sub_tlvs(tlvs: &[BgpLsTlv]) -> Bytes {
        let mut bytes = Vec::new();
        encode_bgpls_tlvs(tlvs, &mut bytes).expect("fixture sub-TLVs encode");
        Bytes::from(bytes)
    }

    /// Node descriptors container for fixture node `id`: AS 64512 + a
    /// 6-byte IS-IS system-ID ending in `id`.
    pub(crate) fn node_container(id: u8) -> Bytes {
        sub_tlvs(&[
            BgpLsTlv::new(
                BGP_LS_TLV_AUTONOMOUS_SYSTEM,
                Bytes::from_static(&[0, 0, 0xfc, 0x00]),
            ),
            BgpLsTlv::new(
                BGP_LS_TLV_IGP_ROUTER_ID,
                Bytes::from(vec![0, 0, 0, 0, 0, id]),
            ),
        ])
    }

    fn build_nlri(nlri_type: BgpLsNlriType, tlvs: &[BgpLsTlv]) -> BgpLsNlri {
        let mut payload = vec![2]; // protocol-id: IS-IS L2
        payload.extend_from_slice(&0_u64.to_be_bytes()); // identifier
        encode_bgpls_tlvs(tlvs, &mut payload).expect("fixture TLVs encode");
        BgpLsNlri::try_new(nlri_type, None, Bytes::from(payload)).expect("fixture NLRI fits")
    }

    /// The canonical key of fixture node `id`.
    pub(crate) fn node_key(id: u8) -> BgpLsNodeKey {
        node_nlri(id)
            .local_node_key()
            .expect("fixture node has a key")
    }

    /// A Node NLRI for fixture node `id`.
    pub(crate) fn node_nlri(id: u8) -> BgpLsNlri {
        build_nlri(
            BgpLsNlriType::Node,
            &[BgpLsTlv::new(
                BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS,
                node_container(id),
            )],
        )
    }

    /// An IPv4 interface-address link descriptor (TLV 259).
    pub(crate) fn v4_interface(addr: Ipv4Addr) -> BgpLsTlv {
        BgpLsTlv::new(
            BGP_LS_TLV_IPV4_INTERFACE_ADDRESS,
            Bytes::from(addr.octets().to_vec()),
        )
    }

    /// An IPv4 neighbor-address link descriptor (TLV 260).
    pub(crate) fn v4_neighbor(addr: Ipv4Addr) -> BgpLsTlv {
        BgpLsTlv::new(
            BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS,
            Bytes::from(addr.octets().to_vec()),
        )
    }

    /// An IPv6 interface-address link descriptor (TLV 261).
    pub(crate) fn v6_interface(addr: std::net::Ipv6Addr) -> BgpLsTlv {
        BgpLsTlv::new(
            BGP_LS_TLV_IPV6_INTERFACE_ADDRESS,
            Bytes::from(addr.octets().to_vec()),
        )
    }

    /// An IPv6 neighbor-address link descriptor (TLV 262).
    pub(crate) fn v6_neighbor(addr: std::net::Ipv6Addr) -> BgpLsTlv {
        BgpLsTlv::new(
            BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS,
            Bytes::from(addr.octets().to_vec()),
        )
    }

    /// A BGP-LS Attribute (type 29) carrying the given TLVs, kept as the
    /// raw `PathAttribute::Unknown` shape the daemon stores.
    pub(crate) fn bgp_ls_attribute(tlvs: &[BgpLsTlv]) -> PathAttribute {
        let mut bytes = Vec::new();
        encode_bgpls_tlvs(tlvs, &mut bytes).expect("fixture attribute encodes");
        PathAttribute::Unknown(RawAttribute {
            flags: 0x80, // optional non-transitive
            type_code: 29,
            data: Bytes::from(bytes),
        })
    }

    /// A 3-byte IGP Metric TLV (1095).
    pub(crate) fn igp_metric_tlv(metric: u32) -> BgpLsTlv {
        let be = metric.to_be_bytes();
        BgpLsTlv::new(
            BGP_LS_TLV_IGP_METRIC,
            Bytes::from(vec![be[1], be[2], be[3]]),
        )
    }

    fn rib_route(peer: Ipv4Addr, nlri: BgpLsNlri, attributes: Vec<PathAttribute>) -> BgpLsRibRoute {
        BgpLsRibRoute {
            family: BgpLsFamily::LinkState,
            nlri,
            next_hop: IpAddr::V4(peer),
            peer: IpAddr::V4(peer),
            attributes: Arc::new(attributes),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: peer,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }
    }

    /// A Link NLRI route `local -> remote` with optional IGP metric and
    /// extra link descriptor TLVs (addresses).
    pub(crate) fn link_route(
        peer: Ipv4Addr,
        local: u8,
        remote: u8,
        metric: Option<u32>,
        extra_descriptors: &[BgpLsTlv],
    ) -> BgpLsRibRoute {
        let mut tlvs = vec![
            BgpLsTlv::new(BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS, node_container(local)),
            BgpLsTlv::new(BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS, node_container(remote)),
        ];
        tlvs.extend_from_slice(extra_descriptors);
        let attributes = metric
            .map(|m| vec![bgp_ls_attribute(&[igp_metric_tlv(m)])])
            .unwrap_or_default();
        rib_route(peer, build_nlri(BgpLsNlriType::Link, &tlvs), attributes)
    }

    /// An IPv4 Topology Prefix NLRI route advertised by fixture node
    /// `node`, with an optional Prefix Metric (TLV 1155).
    pub(crate) fn prefix_route(
        peer: Ipv4Addr,
        node: u8,
        prefix: Ipv4Addr,
        prefix_len: u8,
        metric: Option<u32>,
    ) -> BgpLsRibRoute {
        let mut reach = vec![prefix_len];
        reach.extend_from_slice(&prefix.octets()[..usize::from(prefix_len.div_ceil(8))]);
        let tlvs = vec![
            BgpLsTlv::new(BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS, node_container(node)),
            BgpLsTlv::new(BGP_LS_TLV_IP_REACHABILITY, Bytes::from(reach)),
        ];
        let attributes = metric
            .map(|m| {
                vec![bgp_ls_attribute(&[BgpLsTlv::new(
                    BGP_LS_TLV_PREFIX_METRIC,
                    Bytes::from(m.to_be_bytes().to_vec()),
                )])]
            })
            .unwrap_or_default();
        rib_route(
            peer,
            build_nlri(BgpLsNlriType::Ipv4TopologyPrefix, &tlvs),
            attributes,
        )
    }

    /// Fixture node ids for the square topology.
    pub(crate) const A: u8 = 1;
    /// Node B.
    pub(crate) const B: u8 = 2;
    /// Node X.
    pub(crate) const X: u8 = 3;
    /// Node Y.
    pub(crate) const Y: u8 = 4;

    /// THE arc-wide square topology: A→X=1, A→Y=10, B→X=10, B→Y=1.
    /// Interface addresses are 10.0.{local}.{remote} (map to the local
    /// node), neighbor addresses 10.0.{remote}.{local} (map to the remote
    /// node). Same shape as the M76 interop injection.
    pub(crate) fn square_topology(peer: Ipv4Addr) -> Vec<BgpLsRibRoute> {
        [(A, X, 1), (A, Y, 10), (B, X, 10), (B, Y, 1)]
            .into_iter()
            .map(|(local, remote, cost)| {
                link_route(
                    peer,
                    local,
                    remote,
                    Some(cost),
                    &[
                        v4_interface(Ipv4Addr::new(10, 0, local, remote)),
                        v4_neighbor(Ipv4Addr::new(10, 0, remote, local)),
                    ],
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::fixtures::*;
    use super::*;

    const PEER1: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
    const PEER2: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);

    fn square() -> OrrTopology {
        let routes = square_topology(PEER1);
        OrrTopology::build(routes.iter())
    }

    fn ix(topo: &OrrTopology, id: u8) -> NodeIx {
        topo.node_ix(&node_key(id)).expect("fixture node interned")
    }

    #[test]
    fn topology_builds_nodes_from_link_endpoints_without_node_nlris() {
        let topo = square();
        assert_eq!(topo.node_count(), 4);
        assert_eq!(topo.link_count(), 4);
        for id in [A, B, X, Y] {
            assert!(topo.node_ix(&node_key(id)).is_some(), "node {id} interned");
        }
    }

    #[test]
    fn spf_square_topology_asymmetric_costs() {
        let topo = square();
        let (a, b, x, y) = (ix(&topo, A), ix(&topo, B), ix(&topo, X), ix(&topo, Y));

        let from_a = topo.spf(a);
        assert_eq!(from_a.dist_to(a), Some(0));
        assert_eq!(from_a.dist_to(x), Some(1));
        assert_eq!(from_a.dist_to(y), Some(10));
        assert_eq!(from_a.dist_to(b), None, "no edge reaches B from A");

        let from_b = topo.spf(b);
        assert_eq!(from_b.dist_to(b), Some(0));
        assert_eq!(from_b.dist_to(x), Some(10));
        assert_eq!(from_b.dist_to(y), Some(1));
        assert_eq!(from_b.dist_to(a), None);
    }

    #[test]
    fn link_without_igp_metric_is_unusable() {
        let routes = [link_route(PEER1, A, X, None, &[])];
        let topo = OrrTopology::build(routes.iter());
        // Endpoints still materialize; the edge does not.
        assert_eq!(topo.node_count(), 2);
        assert_eq!(topo.link_count(), 0);
        let spf = topo.spf(ix(&topo, A));
        assert_eq!(spf.dist_to(ix(&topo, X)), None);
    }

    #[test]
    fn parallel_links_take_min_cost() {
        // Two distinct Link NLRIs (different interface addresses) between
        // the same endpoints; Dijkstra takes the min naturally.
        let routes = [
            link_route(
                PEER1,
                A,
                X,
                Some(5),
                &[v4_interface(Ipv4Addr::new(10, 0, 0, 1))],
            ),
            link_route(
                PEER1,
                A,
                X,
                Some(2),
                &[v4_interface(Ipv4Addr::new(10, 0, 0, 5))],
            ),
        ];
        let topo = OrrTopology::build(routes.iter());
        assert_eq!(topo.node_count(), 2);
        assert_eq!(topo.link_count(), 2, "parallel links are both kept");
        let spf = topo.spf(ix(&topo, A));
        assert_eq!(spf.dist_to(ix(&topo, X)), Some(2));
    }

    #[test]
    fn duplicate_nlri_across_peers_dedups_min_metric() {
        // Identical NLRI from two peers with different attr-29 metrics:
        // one graph element, min metric.
        let routes = [
            link_route(PEER1, A, X, Some(7), &[]),
            link_route(PEER2, A, X, Some(3), &[]),
        ];
        assert_eq!(
            routes[0].nlri, routes[1].nlri,
            "fixture NLRIs are identical"
        );
        let topo = OrrTopology::build(routes.iter());
        assert_eq!(topo.link_count(), 1);
        assert_eq!(topo.links()[0].cost, 3);
        let spf = topo.spf(ix(&topo, A));
        assert_eq!(spf.dist_to(ix(&topo, X)), Some(3));
    }

    #[test]
    fn nh_resolution_exact_link_address() {
        let topo = square();
        let spf = topo.spf(ix(&topo, A));
        // Interface address of A→X maps to A (the local node).
        assert_eq!(
            spf.cost_to(&topo, IpAddr::V4(Ipv4Addr::new(10, 0, A, X))),
            Some(0)
        );
        // Neighbor address of A→X maps to X (the remote node).
        assert_eq!(
            spf.cost_to(&topo, IpAddr::V4(Ipv4Addr::new(10, 0, X, A))),
            Some(1)
        );
        assert_eq!(
            topo.resolve_node(IpAddr::V4(Ipv4Addr::new(10, 0, X, A))),
            Some(ix(&topo, X))
        );
    }

    #[test]
    fn nh_resolution_lpm_prefix_plus_metric() {
        let mut routes = square_topology(PEER1);
        // 192.0.2.0/24 advertised by X (metric 5) and Y (metric 100):
        // from A, min(1 + 5, 10 + 100) = 6.
        routes.push(prefix_route(
            PEER1,
            X,
            Ipv4Addr::new(192, 0, 2, 0),
            24,
            Some(5),
        ));
        routes.push(prefix_route(
            PEER2,
            Y,
            Ipv4Addr::new(192, 0, 2, 0),
            24,
            Some(100),
        ));
        let topo = OrrTopology::build(routes.iter());
        let spf = topo.spf(ix(&topo, A));
        assert_eq!(
            spf.cost_to(&topo, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77))),
            Some(6)
        );
        // resolve_node picks the advertiser with the min PREFIX metric.
        assert_eq!(
            topo.resolve_node(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77))),
            Some(ix(&topo, X))
        );
        // Absent TLV 1155 counts as metric 0.
        let mut zero = square_topology(PEER1);
        zero.push(prefix_route(
            PEER1,
            Y,
            Ipv4Addr::new(198, 18, 0, 0),
            15,
            None,
        ));
        let topo = OrrTopology::build(zero.iter());
        let spf = topo.spf(ix(&topo, A));
        assert_eq!(
            spf.cost_to(&topo, IpAddr::V4(Ipv4Addr::new(198, 19, 1, 1))),
            Some(10)
        );
    }

    #[test]
    fn nh_resolution_unresolvable_is_none() {
        let topo = square();
        let spf = topo.spf(ix(&topo, A));
        let outside = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(topo.resolve_node(outside), None);
        assert_eq!(spf.cost_to(&topo, outside), None);
        // Resolvable node, but unreachable from the vantage: still None.
        assert_eq!(
            spf.cost_to(&topo, IpAddr::V4(Ipv4Addr::new(10, 0, B, X))),
            None
        );
    }

    #[test]
    fn mixed_v4_v6_link_addresses_indexed() {
        let v6_if: Ipv6Addr = "2001:db8::1".parse().expect("fixture address parses");
        let v6_nb: Ipv6Addr = "2001:db8::2".parse().expect("fixture address parses");
        let routes = [link_route(
            PEER1,
            A,
            X,
            Some(4),
            &[
                v4_interface(Ipv4Addr::new(10, 0, 8, 1)),
                v4_neighbor(Ipv4Addr::new(10, 0, 8, 2)),
                v6_interface(v6_if),
                v6_neighbor(v6_nb),
            ],
        )];
        let topo = OrrTopology::build(routes.iter());
        let (a, x) = (ix(&topo, A), ix(&topo, X));
        assert_eq!(
            topo.resolve_node(IpAddr::V4(Ipv4Addr::new(10, 0, 8, 1))),
            Some(a)
        );
        assert_eq!(topo.resolve_node(IpAddr::V6(v6_if)), Some(a));
        assert_eq!(
            topo.resolve_node(IpAddr::V4(Ipv4Addr::new(10, 0, 8, 2))),
            Some(x)
        );
        assert_eq!(topo.resolve_node(IpAddr::V6(v6_nb)), Some(x));
    }

    #[test]
    fn spf_unreachable_nodes_absent_from_result() {
        let topo = square();
        let spf = topo.spf(ix(&topo, A));
        assert_eq!(spf.dist_to(ix(&topo, B)), None);
        // A neighbor address owned by the unreachable node resolves but
        // costs None.
        assert_eq!(
            spf.cost_to(&topo, IpAddr::V4(Ipv4Addr::new(10, 0, A, X))),
            Some(0)
        );
    }

    #[test]
    fn cost_to_lru_returns_consistent_results() {
        let mut routes = square_topology(PEER1);
        routes.push(prefix_route(
            PEER1,
            Y,
            Ipv4Addr::new(192, 0, 2, 0),
            24,
            Some(3),
        ));
        let topo = OrrTopology::build(routes.iter());
        let spf = topo.spf(ix(&topo, A));
        for nh in [
            IpAddr::V4(Ipv4Addr::new(10, 0, X, A)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        ] {
            let miss = spf.cost_to(&topo, nh); // cold: computed, then cached
            let hit = spf.cost_to(&topo, nh); // warm: served from the LRU
            assert_eq!(
                miss, hit,
                "cache hit must equal the computed result for {nh}"
            );
        }
    }

    #[test]
    fn snapshot_renders_nodes_links_and_prefixes() {
        let mut routes = square_topology(PEER1);
        routes.push(prefix_route(
            PEER1,
            X,
            Ipv4Addr::new(192, 0, 2, 0),
            24,
            Some(5),
        ));
        let topo = OrrTopology::build(routes.iter());
        let snapshot = topo.snapshot();

        assert_eq!(snapshot.nodes.len(), 4);
        assert_eq!(snapshot.links.len(), 4);
        assert_eq!(snapshot.prefixes.len(), 1);

        let a = &snapshot.nodes[0];
        assert_eq!(a.asn, Some(64512));
        assert_eq!(a.router_id_hex, format!("00000000000{A:x}"));
        assert_eq!(a.link_count, 2, "A has two outgoing links");
        assert_eq!(a.key_hex, hex(node_key(A).as_bytes()));

        let ax = &snapshot.links[0];
        assert_eq!(ax.cost, 1);
        assert_eq!(ax.local_router_id_hex, format!("00000000000{A:x}"));
        assert_eq!(ax.remote_router_id_hex, format!("00000000000{X:x}"));
        assert_eq!(
            ax.addresses,
            vec!["10.0.1.3".to_string(), "10.0.3.1".to_string()]
        );

        assert_eq!(snapshot.prefixes[0].prefix, "192.0.2.0/24");
        assert_eq!(snapshot.prefixes[0].metric, 5);
        assert_eq!(
            snapshot.prefixes[0].node_key_hex,
            hex(node_key(X).as_bytes())
        );
    }
}
