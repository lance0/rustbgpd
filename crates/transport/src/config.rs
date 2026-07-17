//! Transport-layer configuration types.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_fsm::PeerConfig;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Authentication secret owned by the transport runtime.
///
/// The wrapper deliberately exposes only borrowed plaintext access. Its inner
/// wrapper allocation is zeroized when that runtime copy is dropped; schema,
/// parser, API, and kernel copies have separate lifetimes.
#[derive(Clone)]
pub struct TransportAuthSecret(Zeroizing<String>);

/// Constant-time equality. Comparison cost depends only on the longer
/// input's length — no early return on the first mismatching byte and no
/// length-based short-circuit — so config-diff paths can't be turned into
/// a byte-by-byte timing oracle if one side is ever attacker-influenced.
impl PartialEq for TransportAuthSecret {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl Eq for TransportAuthSecret {}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for idx in 0..max_len {
        let lhs = a.get(idx).copied().unwrap_or(0);
        let rhs = b.get(idx).copied().unwrap_or(0);
        diff |= usize::from(lhs ^ rhs);
    }
    diff == 0
}

impl From<String> for TransportAuthSecret {
    fn from(secret: String) -> Self {
        Self(Zeroizing::new(secret))
    }
}

impl From<&str> for TransportAuthSecret {
    fn from(secret: &str) -> Self {
        Self::from(secret.to_owned())
    }
}

impl AsRef<str> for TransportAuthSecret {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for TransportAuthSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Zeroize for TransportAuthSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for TransportAuthSecret {}

/// Monotonic identity for one immutable TCP-AO desired inventory.
///
/// Generation one is the socket inventory installed at daemon startup. Live
/// add-only rotation publishes later generations only after every configured
/// owner has passed preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcpAoRotationGeneration(u64);

impl TcpAoRotationGeneration {
    /// Startup inventory generation.
    pub const STARTUP: Self = Self(1);

    /// Construct a checked generation from an operator/runtime value.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Raw generation value used by API projections.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Next desired generation. Saturation is fail-closed: callers can detect
    /// that no distinct successor exists instead of wrapping to startup.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Operator-visible phase of the non-destructive TCP-AO rotation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpAoRotationPhase {
    /// Desired and applied inventories are equal; no mutation is pending.
    Idle,
    /// A successor inventory is being installed without selecting or deleting
    /// any MKT.
    AddOnly,
    /// The add-only attempt failed. Old usable MKTs remain installed; the
    /// generation must be retried or the daemon restarted.
    AddOnlyFailed,
}

impl TcpAoRotationPhase {
    /// Stable wire/CLI spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::AddOnly => "add_only",
            Self::AddOnlyFailed => "add_only_failed",
        }
    }
}

/// Secret-free, truthful desired/applied TCP-AO rotation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpAoRotationStatus {
    /// Immutable inventory requested by the current/retryable rollout.
    pub desired: TcpAoRotationGeneration,
    /// Inventory completely applied to this owner/session.
    pub applied: TcpAoRotationGeneration,
    /// Current rollout phase.
    pub phase: TcpAoRotationPhase,
    /// Secret-free actionable failure detail.
    pub last_error: Option<String>,
}

/// One configured selector/keyring in an established session's desired
/// accepted-socket inventory. Covering owners remain separate so overlapping
/// dynamic ranges are reconciled as their complete union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpAoRotationOwner {
    /// Configured listener selector network.
    pub peer: IpAddr,
    /// Configured listener selector prefix length.
    pub prefix_len: u8,
    /// Complete ordered desired keyring for this owner.
    pub keyring: TcpAoKeyring,
}

/// Immutable per-session projection of a global add-only generation.
#[derive(Debug, Clone)]
pub struct TcpAoSessionGeneration {
    /// Global immutable inventory identity.
    pub generation: TcpAoRotationGeneration,
    /// Exact static owner used by active-open sockets. Dynamic peers have no
    /// active-open target.
    pub active_keyring: Option<TcpAoKeyring>,
    /// Full owned union used by protected accepted sockets.
    pub accepted_owners: Arc<[TcpAoRotationOwner]>,
}

impl Default for TcpAoRotationStatus {
    fn default() -> Self {
        Self {
            desired: TcpAoRotationGeneration::STARTUP,
            applied: TcpAoRotationGeneration::STARTUP,
            phase: TcpAoRotationPhase::Idle,
            last_error: None,
        }
    }
}

/// Maximum TCP-AO Master Key Tuples that may be installed on and inspected
/// from one listener socket.
///
/// Linux reports the complete inherited MKT inventory for an accepted socket.
/// Bounding the listener inventory to the inspection ceiling keeps the
/// fail-closed accepted-socket reconciliation reachable for every valid
/// configuration.
pub const TCP_AO_MAX_INSPECT_KEYS: usize = 4096;

/// Private AS removal mode for eBGP outbound `AS_PATH` manipulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RemovePrivateAs {
    /// No removal (default).
    #[default]
    Disabled,
    /// Remove all private ASNs only if the entire path is private.
    Remove,
    /// Unconditionally remove all private ASNs from every segment.
    All,
    /// Replace each private ASN with the local ASN.
    Replace,
}

/// TCP-AO MAC/KDF algorithm names accepted by Linux's TCP-AO UAPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpAoAlgorithm {
    HmacSha1,
    HmacSha256,
    CmacAes128,
}

impl TcpAoAlgorithm {
    /// Return the Linux UAPI algorithm name.
    #[must_use]
    pub const fn linux_name(self) -> &'static str {
        match self {
            Self::HmacSha1 => "hmac(sha1)",
            Self::HmacSha256 => "hmac(sha256)",
            Self::CmacAes128 => "cmac(aes128)",
        }
    }

    /// Parse a Linux UAPI algorithm name.
    #[must_use]
    pub fn from_linux_name(name: &str) -> Option<Self> {
        match name {
            "hmac(sha1)" => Some(Self::HmacSha1),
            "hmac(sha256)" => Some(Self::HmacSha256),
            "cmac(aes128)" => Some(Self::CmacAes128),
            _ => None,
        }
    }
}

/// TCP-AO configuration for one MKT in a peer or listener-selector keyring.
#[derive(Clone, PartialEq, Eq)]
pub struct TcpAoConfig {
    /// TCP-AO Master Key Tuple secret.
    pub key: TransportAuthSecret,
    /// Sender `KeyID` (`sndid` in Linux's TCP-AO UAPI).
    pub send_id: u8,
    /// Receiver `KeyID` (`rcvid` in Linux's TCP-AO UAPI).
    pub recv_id: u8,
    /// TCP-AO MAC/KDF algorithm.
    pub algorithm: TcpAoAlgorithm,
    /// Local metadata that prefers this key for startup transmission.
    pub preferred: bool,
    /// Local metadata that excludes this key from automatic startup selection.
    /// The MKT is still installed and may remain usable when peer-selected.
    pub deprecated: bool,
}

impl fmt::Debug for TcpAoConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpAoConfig")
            .field("key", &"<redacted>")
            .field("send_id", &self.send_id)
            .field("recv_id", &self.recv_id)
            .field("algorithm", &self.algorithm)
            .field("preferred", &self.preferred)
            .field("deprecated", &self.deprecated)
            .finish()
    }
}

/// Ordered TCP-AO keyring for one peer or listener selector.
#[derive(Clone, PartialEq, Eq)]
pub struct TcpAoKeyring(pub Vec<TcpAoConfig>);

impl TcpAoKeyring {
    /// Preferred key, or the first declared non-deprecated key.
    #[must_use]
    pub fn selected(&self) -> Option<&TcpAoConfig> {
        self.0
            .iter()
            .find(|key| key.preferred)
            .or_else(|| self.0.iter().find(|key| !key.deprecated))
    }

    pub fn iter(&self) -> std::slice::Iter<'_, TcpAoConfig> {
        self.0.iter()
    }

    /// Selected key first, followed by every remaining key in declaration
    /// order. This is the fail-closed active-open installation order.
    #[must_use]
    pub fn startup_order(&self) -> Vec<&TcpAoConfig> {
        let Some(selected) = self.selected() else {
            return Vec::new();
        };
        std::iter::once(selected)
            .chain(self.iter().filter(|key| !std::ptr::eq(*key, selected)))
            .collect()
    }
}

impl<'a> IntoIterator for &'a TcpAoKeyring {
    type Item = &'a TcpAoConfig;
    type IntoIter = std::slice::Iter<'a, TcpAoConfig>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl fmt::Debug for TcpAoKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TcpAoKeyring").field(&self.0).finish()
    }
}

impl From<TcpAoConfig> for TcpAoKeyring {
    fn from(key: TcpAoConfig) -> Self {
        Self(vec![key])
    }
}

/// Transport-layer configuration for a single BGP peer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "flat per-peer transport config; each bool is an independent BGP feature toggle, not a state enum"
)]
pub struct TransportConfig {
    /// FSM-level peer configuration (ASN, hold time, router ID, etc.).
    pub peer: PeerConfig,
    /// TCP address of the remote peer (typically port 179).
    pub remote_addr: SocketAddr,
    /// Configured interface for IPv6 link-local / unnumbered peers.
    pub peer_interface: Option<String>,
    /// Resolved interface index for scoped IPv6 link-local peers.
    pub peer_scope_id: Option<u32>,
    /// Timeout for outbound TCP connect attempts.
    pub connect_timeout: Duration,
    /// Maximum number of prefixes accepted from this peer before Cease/1.
    pub max_prefixes: Option<u32>,
    /// Maximum unique IPv4-unicast prefixes accepted before Cease/1.
    /// Enforced independently of `max_prefixes` (ADR-0108).
    pub max_prefixes_ipv4: Option<u32>,
    /// Maximum unique IPv6-unicast prefixes accepted before Cease/1.
    /// Enforced independently of `max_prefixes` (ADR-0108).
    pub max_prefixes_ipv6: Option<u32>,
    /// Optional peer-group name used for policy matching and operator visibility.
    pub peer_group: Option<String>,
    /// TCP MD5 authentication password (RFC 2385).
    pub md5_password: Option<TransportAuthSecret>,
    /// TCP-AO authentication key (RFC 5925).
    pub tcp_ao: Option<TcpAoKeyring>,
    /// Enable GTSM / TTL security (RFC 5082).
    pub ttl_security: bool,
    /// Explicit IPv6 next-hop for eBGP advertisements. Used when the TCP
    /// session is IPv4 but IPv6 routes need a valid next-hop in
    /// `MP_REACH_NLRI`. If `None`, the local IPv6 socket address is used
    /// (if available); otherwise IPv6 routes are suppressed.
    pub local_ipv6_nexthop: Option<Ipv6Addr>,
    /// Time to retain stale routes after peer restart (seconds). RFC 4724.
    pub gr_stale_routes_time: u64,
    /// Long-lived stale routes time (RFC 9494, seconds). 0 = disabled.
    pub llgr_stale_time: u32,
    /// Local restarting-speaker GR window. When set, outbound OPEN messages
    /// advertise `restart_state = true` until this deadline.
    pub gr_restart_until: Option<Instant>,
    /// Whether this neighbor is a route reflector client (RFC 4456).
    pub route_reflector_client: bool,
    /// Optimal Route Reflection vantage point (RFC 9107): an IP address
    /// identifying this client's IGP location as a BGP-LS topology node.
    /// Only meaningful when `route_reflector_client` is set.
    pub orr_vantage: Option<IpAddr>,
    /// Whether this eBGP neighbor is a transparent route-server client.
    pub route_server_client: bool,
    /// RFC 7947 §2.3.2 per-client best-path for a route-server client:
    /// the RIB stages the first export-policy-permitted candidate for
    /// this peer instead of the Loc-RIB best (path-hiding mitigation
    /// for clients without Add-Path). Requires `route_server_client`;
    /// families with negotiated Add-Path send ignore it.
    pub per_client_best: bool,
    /// ADR-0107 strict-peer `NEXT_HOP` ownership enforcement for a
    /// route-server client (RFC 7948 §4.8). When `true`, an inbound
    /// unicast announcement is accepted only when every address
    /// component of its decoded wire next-hop identity is the
    /// advertising session's own address; non-conforming announcements
    /// are rejected before import policy runs (fail-closed,
    /// treat-as-withdraw for accepted replacements). Requires
    /// `route_server_client`. Operator knob:
    /// `next_hop_ownership = "strict_peer"`.
    pub next_hop_ownership_strict_peer: bool,
    /// RFC 1997 `NO_EXPORT`/`NO_EXPORT_SUBCONFED` egress enforcement:
    /// when `true` and this peer is eBGP, the RIB suppresses source
    /// routes carrying either community at export staging. Resolved in
    /// config with default `!route_server_client` (plain eBGP/iBGP
    /// peers honor RFC 1997; route-server clients are transparent).
    pub interpret_rfc1997: bool,
    /// RFC 7947 §2.3.2 route-server control communities: when `true`,
    /// the RIB interprets member-set control communities
    /// (`0:PEER`/`RS:PEER`/`0:RS` and the RFC 8195 large forms
    /// `RS:{0,1,101,102,103}:PEER`) at export staging toward this peer
    /// — per-target announce suppression, prepend, and outbound scrub.
    /// Resolved in config with default `route_server_client`. Enabled
    /// sessions are disqualified from update-group sharing.
    pub rs_control_communities: bool,
    /// Private AS removal mode for eBGP outbound `AS_PATH`.
    pub remove_private_as: RemovePrivateAs,
    /// Local cluster ID for route reflection. `Some` means this speaker is a
    /// route reflector; used for `CLUSTER_LIST` prepend and loop detection.
    pub cluster_id: Option<Ipv4Addr>,
    /// Whether the per-session import-decision cache is populated
    /// (ADR-0073). When `false`, the inbound UPDATE path skips building
    /// and storing any decision snapshot — the write-path cost control.
    /// Operator knob: `[policy.explain] enabled`.
    pub explain_enabled: bool,
    /// Per-session import-decision cache capacity (ADR-0073). Bounds the
    /// number of `(AFI, SAFI, prefix, path_id)` import decisions retained
    /// for `PolicyService.ExplainImportPolicy`. Operator knob:
    /// `[policy.explain] cache_size`.
    pub explain_cache_size: usize,
    /// Emit RFC 8671 post-policy Adj-RIB-Out BMP route monitoring for
    /// every outbound UPDATE. Set when at least one BMP collector
    /// monitors `rib_out_post`; kept off otherwise so the lossy BMP
    /// event channel is not doubled for collectors that never see the
    /// rib-out stream.
    pub bmp_rib_out: bool,
    /// Slow-peer detection backlog threshold, as a percentage of the
    /// writer's outbound bulk-buffer capacity (1–100). The peer is a
    /// slow-peer candidate while its buffered outbound frames stay at
    /// or above this fraction. Operator knob: `slow_peer_threshold_pct`.
    pub slow_peer_threshold_pct: u8,
    /// How long (seconds) the backlog must stay above the threshold
    /// before the peer is flagged slow. `0` disables detection.
    /// Operator knob: `slow_peer_duration`.
    pub slow_peer_duration: u32,
    /// Move a flagged-slow peer onto the per-peer (ungrouped) update
    /// path so it stops holding back its update-group's shared encode;
    /// it regroups when the flag clears. Operator knob:
    /// `slow_peer_isolation`. Default off — detection alone is purely
    /// observational.
    pub slow_peer_isolation: bool,
}

/// Default slow-peer backlog threshold: half the writer's outbound
/// bulk-buffer capacity.
pub const DEFAULT_SLOW_PEER_THRESHOLD_PCT: u8 = 50;

/// Default slow-peer persistence duration (seconds) before the flag is
/// raised.
pub const DEFAULT_SLOW_PEER_DURATION_SECS: u32 = 30;

impl TransportConfig {
    /// Default TCP connect timeout (30 seconds).
    const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Create a new transport config with default connect timeout.
    #[must_use]
    pub fn new(peer: PeerConfig, remote_addr: SocketAddr) -> Self {
        Self {
            peer,
            remote_addr,
            peer_interface: None,
            peer_scope_id: None,
            connect_timeout: Self::DEFAULT_CONNECT_TIMEOUT,
            max_prefixes: None,
            max_prefixes_ipv4: None,
            max_prefixes_ipv6: None,
            peer_group: None,
            md5_password: None,
            tcp_ao: None,
            ttl_security: false,
            local_ipv6_nexthop: None,
            gr_stale_routes_time: 360,
            llgr_stale_time: 0,
            gr_restart_until: None,
            route_reflector_client: false,
            orr_vantage: None,
            route_server_client: false,
            per_client_best: false,
            next_hop_ownership_strict_peer: false,
            interpret_rfc1997: true,
            rs_control_communities: false,
            remove_private_as: RemovePrivateAs::Disabled,
            cluster_id: None,
            explain_enabled: true,
            explain_cache_size: crate::session::import_decision_cache::DEFAULT_EXPLAIN_CACHE_SIZE,
            bmp_rib_out: false,
            slow_peer_threshold_pct: DEFAULT_SLOW_PEER_THRESHOLD_PCT,
            slow_peer_duration: DEFAULT_SLOW_PEER_DURATION_SECS,
            slow_peer_isolation: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_auth_secret_clones_independently_redacts_and_zeroizes() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<TransportAuthSecret>();
        let mut secret = TransportAuthSecret::from("transport-secret-sentinel");
        let retained_clone = secret.clone();

        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert!(!format!("{secret:?}").contains("transport-secret-sentinel"));
        secret.zeroize();
        assert!(secret.as_ref().is_empty());
        assert_eq!(retained_clone.as_ref(), "transport-secret-sentinel");
    }

    #[test]
    fn transport_auth_secret_eq_matches_value_semantics() {
        let a = TransportAuthSecret::from("secret");
        assert_eq!(a, TransportAuthSecret::from("secret"));
        assert_ne!(a, TransportAuthSecret::from("secreT"));
        // Length differences (prefix and empty) must also compare unequal.
        assert_ne!(a, TransportAuthSecret::from("secret-longer"));
        assert_ne!(a, TransportAuthSecret::from(""));
        assert_eq!(TransportAuthSecret::from(""), TransportAuthSecret::from(""));
    }

    #[test]
    fn transport_config_debug_redacts_md5_password() {
        let peer = PeerConfig::new(65_001, 65_002, Ipv4Addr::new(10, 0, 0, 1));
        let mut config = TransportConfig::new(peer, "10.0.0.2:179".parse().unwrap());
        config.md5_password = Some("md5-secret-sentinel".into());

        let rendered = format!("{config:?}");

        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("md5-secret-sentinel"));
    }

    #[test]
    fn tcp_ao_rotation_generation_is_nonzero_monotonic_and_checked() {
        assert!(TcpAoRotationGeneration::new(0).is_none());
        assert_eq!(TcpAoRotationGeneration::STARTUP.as_u64(), 1);
        assert_eq!(TcpAoRotationGeneration::STARTUP.next().unwrap().as_u64(), 2);
        assert!(
            TcpAoRotationGeneration::new(u64::MAX)
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn tcp_ao_config_debug_redacts_key() {
        let config = TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        };

        let rendered = format!("{config:?}");

        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn tcp_ao_keyring_selection_is_preferred_then_first_nondeprecated() {
        let key = |send_id, preferred, deprecated| TcpAoConfig {
            key: format!("secret-{send_id}").into(),
            send_id,
            recv_id: send_id + 10,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred,
            deprecated,
        };
        let fallback = TcpAoKeyring(vec![
            key(1, false, true),
            key(2, false, false),
            key(3, false, false),
        ]);
        assert_eq!(fallback.selected().unwrap().send_id, 2);
        let preferred = TcpAoKeyring(vec![key(1, false, false), key(2, true, false)]);
        assert_eq!(preferred.selected().unwrap().send_id, 2);
        assert_eq!(
            preferred
                .startup_order()
                .iter()
                .map(|key| key.send_id)
                .collect::<Vec<_>>(),
            [2, 1]
        );
    }
}
