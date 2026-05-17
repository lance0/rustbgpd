pub mod diagnostic;
mod parse;
mod schema;
mod validation;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use rustbgpd_evpn::{
    DfAlgorithm, DuplicateMacAction, DuplicateMacConfig, EthernetSegment, EvpnInstance,
    EvpnInstanceId, EvpnInstanceTable, IpVrf, IpVrfId, IpVrfTable, RouteTarget,
};
use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::{
    CommunityMatch, NextHopAction, Policy, PolicyAction, PolicyChain, PolicyStatement,
    RouteModifications, parse_community_match,
};
use rustbgpd_transport::{RemovePrivateAs, TransportConfig};
use rustbgpd_wire::{
    Afi, EthernetSegmentIdentifier, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, LargeCommunity,
    MacAddress, Prefix, RouteDistinguisher, Safi,
};

pub use schema::*;

use self::parse::{parse_families, parse_policy, resolve_chain};
use self::schema::{BGP_PORT, DEFAULT_CONNECT_RETRY_SECS, DEFAULT_HOLD_TIME};

#[cfg(test)]
use self::parse::parse_named_policy;

impl Config {
    fn load_from_toml_source(content: &str, source_name: &str) -> Result<Self, String> {
        let config: Config = match toml::from_str(content) {
            Ok(c) => c,
            Err(e) => {
                let error = ConfigError::Parse(e);
                return Err(diagnostic::render_diagnostic(content, source_name, &error)
                    .unwrap_or_else(|| format!("error: {error}")));
            }
        };
        if let Err(error) = config.validate() {
            return Err(diagnostic::render_diagnostic(content, source_name, &error)
                .unwrap_or_else(|| format!("error: {error}")));
        }
        Ok(config)
    }

    /// Load config from TOML text and render diagnostics against `source_name`.
    ///
    /// Used by read-only API surfaces that receive candidate config
    /// content instead of a filesystem path. The returned config does
    /// not expose a `file_path`.
    pub fn load_toml_with_diagnostics(content: &str, source_name: &str) -> Result<Self, String> {
        Self::load_from_toml_source(content, source_name)
    }

    /// Load config and, on failure, render a diagnostic with source context.
    ///
    /// Returns the rendered diagnostic string on error (suitable for direct
    /// printing to stderr). Falls back to plain `Display` if no source span
    /// can be determined.
    pub fn load_with_diagnostics(path: &str) -> Result<Self, String> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => return Err(format!("error: failed to read {path}: {e}")),
        };
        let mut config = Self::load_from_toml_source(&content, path)?;
        config.file_path = Some(PathBuf::from(path));
        Ok(config)
    }

    pub fn prometheus_addr(&self) -> Option<SocketAddr> {
        self.global
            .telemetry
            .prometheus_addr
            .as_ref()
            .map(|s| s.parse().expect("validated in Config::load"))
    }

    pub fn looking_glass_addr(&self) -> Option<SocketAddr> {
        self.global
            .telemetry
            .looking_glass
            .as_ref()
            .map(|lg| lg.addr.parse().expect("validated in Config::load"))
    }

    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            self.global.listen_port,
        )
    }

    /// Resolve the configured gRPC listeners.
    ///
    /// If neither TCP nor UDS is configured explicitly, a secure local-only UDS
    /// listener is enabled at `<runtime_state_dir>/grpc.sock`.
    pub fn grpc_listeners(&self) -> Vec<GrpcListener> {
        let telemetry = &self.global.telemetry;
        let tcp = telemetry.grpc_tcp.as_ref().filter(|cfg| cfg.enabled);
        let uds = telemetry.grpc_uds.as_ref().filter(|cfg| cfg.enabled);

        if tcp.is_none() && uds.is_none() {
            return vec![GrpcListener::Uds {
                path: self.default_grpc_uds_path(),
                mode: 0o600,
                access_mode: GrpcAccessMode::ReadWrite,
                token_file: None,
            }];
        }

        let mut listeners = Vec::new();
        if let Some(cfg) = tcp {
            let addr = cfg
                .address
                .as_ref()
                .expect("validated in Config::load")
                .parse()
                .expect("validated in Config::load");
            let tls = match (
                cfg.tls_cert_file.as_ref(),
                cfg.tls_key_file.as_ref(),
                cfg.tls_client_ca_file.as_ref(),
            ) {
                (Some(cert), Some(key), Some(ca)) => Some(GrpcTlsPaths {
                    cert_file: PathBuf::from(cert),
                    key_file: PathBuf::from(key),
                    client_ca_file: PathBuf::from(ca),
                }),
                // Partial TLS config rejected at Config::load via
                // validate_grpc_tls_config(); the all-None and
                // any-partial cases both resolve to no-TLS here.
                _ => None,
            };
            listeners.push(GrpcListener::Tcp {
                addr,
                access_mode: cfg
                    .access_mode
                    .map_or(GrpcAccessMode::ReadWrite, Into::into),
                token_file: cfg.token_file.as_ref().map(PathBuf::from),
                tls,
            });
        }
        if let Some(cfg) = uds {
            let path = cfg
                .path
                .as_ref()
                .map_or_else(|| self.default_grpc_uds_path(), PathBuf::from);
            listeners.push(GrpcListener::Uds {
                path,
                mode: cfg.mode,
                access_mode: cfg
                    .access_mode
                    .map_or(GrpcAccessMode::ReadWrite, Into::into),
                token_file: cfg.token_file.as_ref().map(PathBuf::from),
            });
        }
        listeners
    }

    /// Directory for daemon-owned runtime state files.
    #[must_use]
    pub fn runtime_state_dir(&self) -> PathBuf {
        PathBuf::from(&self.global.runtime_state_dir)
    }

    /// Marker file used for restarting-speaker Graceful Restart.
    #[must_use]
    pub fn gr_restart_marker_path(&self) -> PathBuf {
        self.runtime_state_dir().join("gr-restart.toml")
    }

    #[must_use]
    pub fn default_grpc_uds_path(&self) -> PathBuf {
        self.runtime_state_dir().join("grpc.sock")
    }

    /// Resolve the effective cluster ID.
    ///
    /// Returns `Some` if explicitly configured, or if any neighbor is an RR client
    /// (defaults to `router_id`). Returns `None` when not acting as a route reflector.
    pub fn cluster_id(&self) -> Option<Ipv4Addr> {
        if let Some(ref cid) = self.global.cluster_id {
            return Some(cid.parse().expect("validated in Config::load"));
        }
        if self.neighbors.iter().any(|n| {
            n.route_reflector_client.unwrap_or_else(|| {
                n.peer_group
                    .as_deref()
                    .and_then(|name| self.peer_groups.get(name))
                    .and_then(|group| group.route_reflector_client)
                    .unwrap_or(false)
            })
        }) {
            let router_id: Ipv4Addr = self
                .global
                .router_id
                .parse()
                .expect("validated in Config::load");
            return Some(router_id);
        }
        None
    }

    /// Resolve the global import policy chain.
    ///
    /// If `import_chain` is set, resolves named policies. Otherwise wraps
    /// the inline `import` entries as a single-policy chain.
    pub fn import_chain(&self) -> Result<Option<PolicyChain>, ConfigError> {
        if self.policy.import_chain.is_empty() {
            let policy = parse_policy(
                &self.policy.import,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?;

            Ok(policy.map(|p| PolicyChain::new(vec![p])))
        } else {
            let chain = resolve_chain(
                &self.policy.import_chain,
                &self.policy.definitions,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?;

            Ok(chain)
        }
    }

    /// Resolve the global export policy chain.
    pub fn export_chain(&self) -> Result<Option<PolicyChain>, ConfigError> {
        if self.policy.export_chain.is_empty() {
            Ok(parse_policy(
                &self.policy.export,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?
            .map(|p| PolicyChain::new(vec![p])))
        } else {
            resolve_chain(
                &self.policy.export_chain,
                &self.policy.definitions,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )
        }
    }

    /// Build the implicit RFC 8326 chain-tail import rule:
    /// `match community = GRACEFUL_SHUTDOWN → permit, set local_pref = 0`.
    ///
    /// **Runs LAST in the resolved chain**, not first. `PolicyChain::evaluate`
    /// short-circuits on `Deny` but accumulates modifications across `Permit`
    /// matches with last-writer-wins semantics on scalar fields like
    /// `set_local_pref`. If the implicit rule ran at index 0 and a later
    /// operator policy explicitly set `local_pref = 200` on the same route,
    /// the operator's value would overwrite the `GShut` demotion — silently
    /// breaking the RFC 8326 §4 receiver guarantee. Running at the chain
    /// tail flips the precedence: operator policy still gets to deny
    /// (short-circuits), but any route that survives the chain as `Permit`
    /// has the canonical `local_pref = 0` in the accumulated modifications.
    fn build_implicit_gshut_policy() -> Policy {
        Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Permit,
                match_community: vec![CommunityMatch::Standard {
                    value: rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN,
                }],
                match_as_path: None,
                match_neighbor_set: None,
                match_route_type: None,
                match_evpn_route_type: None,
                match_rpki_validation: None,
                match_aspa_validation: None,
                match_as_path_length_ge: None,
                match_as_path_length_le: None,
                match_local_pref_ge: None,
                match_local_pref_le: None,
                match_med_ge: None,
                match_med_le: None,
                match_next_hop: None,
                modifications: RouteModifications {
                    set_local_pref: Some(0),
                    ..Default::default()
                },
            }],
            default_action: PolicyAction::Permit,
        }
    }

    /// Build the implicit RFC 7999 chain-tail import rule:
    /// `match community = BLACKHOLE → permit, add BLACKHOLE + NO_ADVERTISE`.
    ///
    /// RFC 7999 leaves honoring semantics to explicit operator policy. This
    /// built-in receiver rule does the safe control-plane half only: it keeps
    /// the `BLACKHOLE` marker present even if an earlier policy tried to
    /// remove it, and adds `NO_ADVERTISE` so the request stays local unless an
    /// operator deliberately writes a different policy. Kernel discard route
    /// installation is a separate `install_blackhole_discard` opt-in.
    fn build_implicit_blackhole_policy() -> Policy {
        Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Permit,
                match_community: vec![CommunityMatch::Standard {
                    value: rustbgpd_wire::COMMUNITY_BLACKHOLE,
                }],
                match_as_path: None,
                match_neighbor_set: None,
                match_route_type: None,
                match_evpn_route_type: None,
                match_rpki_validation: None,
                match_aspa_validation: None,
                match_as_path_length_ge: None,
                match_as_path_length_le: None,
                match_local_pref_ge: None,
                match_local_pref_le: None,
                match_med_ge: None,
                match_med_le: None,
                match_next_hop: None,
                modifications: RouteModifications {
                    communities_add: vec![
                        rustbgpd_wire::COMMUNITY_BLACKHOLE,
                        rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
                    ],
                    ..Default::default()
                },
            }],
            default_action: PolicyAction::Permit,
        }
    }

    /// Resolve the effective import/export policy chains for one neighbor.
    ///
    /// Per-neighbor named chain overrides per-neighbor inline policy, which
    /// overrides the corresponding global named chain or global inline policy.
    ///
    /// When `[global] honor_graceful_shutdown = true` and/or
    /// `[global] honor_blackhole = true` AND the neighbor is EBGP, the
    /// resolved import chain is appended with the corresponding implicit
    /// receiver rule. iBGP is intentionally exempt — these are EBGP-edge
    /// receiver behaviors, and re-applying them per iBGP hop would overwrite
    /// values or scoping set legitimately upstream at the EBGP edge.
    pub fn effective_policy_chains_for_neighbor(
        &self,
        neighbor: &Neighbor,
    ) -> Result<(Option<PolicyChain>, Option<PolicyChain>), ConfigError> {
        let group = self.peer_group_for_neighbor(neighbor)?;
        let global_import = self.import_chain()?;
        let global_export = self.export_chain()?;
        let group_import = if let Some(group) = group {
            if group.import_policy_chain.is_empty() {
                let policy = parse_policy(
                    &group.import_policy,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?;

                policy.map(|p| PolicyChain::new(vec![p]))
            } else {
                resolve_chain(
                    &group.import_policy_chain,
                    &self.policy.definitions,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?
            }
        } else {
            None
        };
        let group_export = if let Some(group) = group {
            if group.export_policy_chain.is_empty() {
                parse_policy(
                    &group.export_policy,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?
                .map(|p| PolicyChain::new(vec![p]))
            } else {
                resolve_chain(
                    &group.export_policy_chain,
                    &self.policy.definitions,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?
            }
        } else {
            None
        };

        let import = if neighbor.import_policy_chain.is_empty() {
            if neighbor.import_policy.is_empty() {
                group_import
            } else {
                let policy = parse_policy(
                    &neighbor.import_policy,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?;
                policy.map(|p| PolicyChain::new(vec![p]))
            }
        } else {
            resolve_chain(
                &neighbor.import_policy_chain,
                &self.policy.definitions,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?
        }
        .or_else(|| global_import.clone());
        let export = if neighbor.export_policy_chain.is_empty() {
            if neighbor.export_policy.is_empty() {
                group_export
            } else {
                parse_policy(
                    &neighbor.export_policy,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?
                .map(|p| PolicyChain::new(vec![p]))
            }
        } else {
            resolve_chain(
                &neighbor.export_policy_chain,
                &self.policy.definitions,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?
        }
        .or_else(|| global_export.clone());

        // RFC 8326 §4 / RFC 7999 receiver behavior: append implicit rules to
        // the end of the EBGP import chain when the corresponding honor knob
        // is on. Running LAST guarantees the implicit modification wins over
        // earlier operator policy modifications. Operator denies still
        // short-circuit.
        //
        // FUTURE: when confederation support lands, the EBGP gate
        // should key off an explicit `is_external_neighbor()` helper
        // that knows about confederation sub-AS topology rather than
        // the simple `remote_asn != global.asn` shortcut. Tracked in
        // ROADMAP under "RFC 8326 confederation gating".
        let is_ebgp = neighbor.remote_asn != self.global.asn;
        let import =
            if (self.global.honor_graceful_shutdown || self.global.honor_blackhole) && is_ebgp {
                let mut chain = import.unwrap_or_default();
                if self.global.honor_graceful_shutdown {
                    chain.policies.push(Self::build_implicit_gshut_policy());
                }
                if self.global.honor_blackhole {
                    chain.policies.push(Self::build_implicit_blackhole_policy());
                }
                Some(chain)
            } else {
                import
            };

        Ok((import, export))
    }

    fn peer_group_for_neighbor(
        &self,
        neighbor: &Neighbor,
    ) -> Result<Option<&PeerGroupConfig>, ConfigError> {
        neighbor
            .peer_group
            .as_deref()
            .map(|name| {
                self.peer_groups
                    .get(name)
                    .ok_or_else(|| ConfigError::UndefinedPeerGroup {
                        name: name.to_string(),
                    })
            })
            .transpose()
    }

    fn resolved_families(
        neighbor: &Neighbor,
        group: Option<&PeerGroupConfig>,
        peer_addr: IpAddr,
    ) -> Result<Vec<(Afi, Safi)>, ConfigError> {
        if !neighbor.families.is_empty() {
            return parse_families(&neighbor.families);
        }
        if let Some(group) = group
            && !group.families.is_empty()
        {
            return parse_families(&group.families);
        }

        let mut f = vec![(Afi::Ipv4, Safi::Unicast)];
        if peer_addr.is_ipv6() {
            f.push((Afi::Ipv6, Safi::Unicast));
        }
        Ok(f)
    }

    fn resolved_remove_private_as(
        neighbor: &Neighbor,
        group: Option<&PeerGroupConfig>,
    ) -> RemovePrivateAs {
        match neighbor
            .remove_private_as
            .as_deref()
            .or_else(|| group.and_then(|g| g.remove_private_as.as_deref()))
        {
            Some("remove") => RemovePrivateAs::Remove,
            Some("all") => RemovePrivateAs::All,
            Some("replace") => RemovePrivateAs::Replace,
            _ => RemovePrivateAs::Disabled,
        }
    }

    fn resolved_add_path(
        neighbor: &Neighbor,
        group: Option<&PeerGroupConfig>,
    ) -> Option<AddPathConfig> {
        neighbor
            .add_path
            .clone()
            .or_else(|| group.and_then(|g| g.add_path.clone()))
    }

    pub(crate) fn resolve_neighbor(
        &self,
        neighbor: &Neighbor,
    ) -> Result<ResolvedNeighbor, ConfigError> {
        let router_id: Ipv4Addr = self
            .global
            .router_id
            .parse()
            .expect("validated in Config::load");
        let peer_addr: IpAddr = neighbor.address.parse().expect("validated in Config::load");
        let group = self.peer_group_for_neighbor(neighbor)?;
        let families = Self::resolved_families(neighbor, group, peer_addr)?;
        let add_path = Self::resolved_add_path(neighbor, group);

        let peer = PeerConfig {
            local_asn: self.global.asn,
            remote_asn: neighbor.remote_asn,
            local_router_id: router_id,
            hold_time: neighbor
                .hold_time
                .or_else(|| group.and_then(|g| g.hold_time))
                .unwrap_or(DEFAULT_HOLD_TIME),
            connect_retry_secs: DEFAULT_CONNECT_RETRY_SECS,
            families,
            graceful_restart: neighbor
                .graceful_restart
                .or_else(|| group.and_then(|g| g.graceful_restart))
                .unwrap_or(true),
            gr_restart_time: neighbor
                .gr_restart_time
                .or_else(|| group.and_then(|g| g.gr_restart_time))
                .unwrap_or(120),
            llgr_stale_time: neighbor
                .llgr_stale_time
                .or_else(|| group.and_then(|g| g.llgr_stale_time))
                .unwrap_or(0),
            add_path_receive: add_path.as_ref().is_some_and(|c| c.receive),
            add_path_send: add_path.as_ref().is_some_and(|c| c.send),
            add_path_send_max: add_path.as_ref().and_then(|c| c.send_max).unwrap_or(0),
        };

        let remote_addr = SocketAddr::new(peer_addr, BGP_PORT);
        let mut transport = TransportConfig::new(peer, remote_addr);
        transport.max_prefixes = neighbor
            .max_prefixes
            .or_else(|| group.and_then(|g| g.max_prefixes));
        transport.peer_group.clone_from(&neighbor.peer_group);
        transport.md5_password = neighbor
            .md5_password
            .clone()
            .or_else(|| group.and_then(|g| g.md5_password.clone()));
        transport.ttl_security = neighbor
            .ttl_security
            .or_else(|| group.and_then(|g| g.ttl_security))
            .unwrap_or(false);
        transport.local_ipv6_nexthop = neighbor
            .local_ipv6_nexthop
            .as_ref()
            .or_else(|| group.and_then(|g| g.local_ipv6_nexthop.as_ref()))
            .map(|s| s.parse::<Ipv6Addr>().expect("validated in Config::load"));
        transport.gr_stale_routes_time = neighbor
            .gr_stale_routes_time
            .or_else(|| group.and_then(|g| g.gr_stale_routes_time))
            .unwrap_or(360);
        transport.llgr_stale_time = neighbor
            .llgr_stale_time
            .or_else(|| group.and_then(|g| g.llgr_stale_time))
            .unwrap_or(0);
        transport.route_server_client = neighbor
            .route_server_client
            .or_else(|| group.and_then(|g| g.route_server_client))
            .unwrap_or(false);
        transport.route_reflector_client = neighbor
            .route_reflector_client
            .or_else(|| group.and_then(|g| g.route_reflector_client))
            .unwrap_or(false);
        transport.remove_private_as = Self::resolved_remove_private_as(neighbor, group);

        let (import_policy, export_policy) = self.effective_policy_chains_for_neighbor(neighbor)?;

        Ok(ResolvedNeighbor {
            transport_config: transport,
            label: neighbor
                .description
                .clone()
                .unwrap_or_else(|| neighbor.address.clone()),
            import_policy,
            export_policy,
            peer_group: neighbor.peer_group.clone(),
        })
    }

    /// Resolve a dynamic neighbor config from a peer group.
    /// Builds a synthetic `Neighbor` inheriting all settings from the group.
    pub(crate) fn resolve_dynamic_neighbor(
        &self,
        addr: IpAddr,
        remote_asn: u32,
        description: &str,
        _group: &PeerGroupConfig,
        peer_group_name: &str,
    ) -> Result<ResolvedNeighbor, ConfigError> {
        // Build a synthetic Neighbor that references the peer group.
        // All fields come from the group via the normal resolution path.
        let neighbor = Neighbor {
            address: addr.to_string(),
            remote_asn,
            description: Some(description.to_string()),
            peer_group: Some(peer_group_name.to_string()),
            hold_time: None,
            max_prefixes: None,
            md5_password: None,
            ttl_security: None,
            families: Vec::new(),
            graceful_restart: None,
            gr_restart_time: None,
            gr_stale_routes_time: None,
            llgr_stale_time: None,
            local_ipv6_nexthop: None,
            route_reflector_client: None,
            route_server_client: None,
            remove_private_as: None,
            add_path: None,
            log_level: None,
            import_policy: Vec::new(),
            export_policy: Vec::new(),
            import_policy_chain: Vec::new(),
            export_policy_chain: Vec::new(),
        };
        self.resolve_neighbor(&neighbor)
    }

    pub fn resolved_neighbors(&self) -> Result<Vec<ResolvedNeighbor>, ConfigError> {
        self.neighbors
            .iter()
            .map(|neighbor| self.resolve_neighbor(neighbor))
            .collect()
    }

    /// Resolve `[[evpn_instances]]` entries into a runtime
    /// [`EvpnInstanceTable`].
    ///
    /// Mirrors the per-entry validation done at `Config::load` time —
    /// VNI range, RD/RT parsing, unicast VTEP IP — and additionally
    /// enforces table-level uniqueness on VNI and RD. The validation
    /// pass already runs the same checks; this method exists to give
    /// the daemon and the gRPC layer a typed, indexed view that they
    /// can hand to downstream consumers (CLI list output today, kernel
    /// reconciliation tomorrow).
    ///
    /// # Errors
    /// Surfaces every malformed entry as a [`ConfigError::InvalidEvpnInstance`]
    /// with the offending VNI or duplicate marker in the message — the
    /// entries are processed in declaration order so the first error
    /// reflects the first bad block.
    pub fn resolve_evpn_instances(&self) -> Result<EvpnInstanceTable, ConfigError> {
        let mut table = EvpnInstanceTable::new();
        for cfg in &self.evpn_instances {
            let inst = parse_evpn_instance(cfg)?;
            table
                .insert(inst)
                .map_err(|e| ConfigError::InvalidEvpnInstance {
                    reason: e.to_string(),
                })?;
        }
        Ok(table)
    }

    /// Resolve `[[ethernet_segments]]` entries into runtime
    /// [`EthernetSegment`] domain objects.
    ///
    /// Validates that every member VNI is also declared in
    /// `[[evpn_instances]]` — orphan members are rejected at config
    /// load time so the daemon never spawns a Type 1 EAD-per-EVI
    /// originator for a VNI it has no instance for.
    ///
    /// # Errors
    /// Surfaces every malformed entry as a
    /// [`ConfigError::InvalidEthernetSegment`] with the offending
    /// ESI string in the message.
    pub fn resolve_ethernet_segments(&self) -> Result<Vec<EthernetSegment>, ConfigError> {
        let mut known_vnis: BTreeSet<EvpnInstanceId> = BTreeSet::new();
        for cfg in &self.evpn_instances {
            if let Ok(id) = EvpnInstanceId::new(cfg.vni) {
                known_vnis.insert(id);
            }
        }
        let mut seen_esis: BTreeSet<EthernetSegmentIdentifier> = BTreeSet::new();
        // ESI-aware MAC origination resolves a Type 2 NLRI's ESI by
        // looking up the MAC's VNI in `vni_to_esi` (built in
        // `src/main.rs` from the resolved segments). That model
        // requires each member VNI to belong to **at most one**
        // segment on this PE — otherwise the daemon would have to
        // know the learned MAC's CE-side ifindex to disambiguate,
        // which Gate 8b doesn't yet plumb. Reject the ambiguous
        // shape at config load so silent wrong-ESI origination is
        // structurally impossible.
        let mut vni_owner: BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier> = BTreeMap::new();
        let mut out = Vec::with_capacity(self.ethernet_segments.len());
        for cfg in &self.ethernet_segments {
            let seg = parse_ethernet_segment(cfg, &known_vnis)?;
            if !seen_esis.insert(seg.esi) {
                return Err(ConfigError::InvalidEthernetSegment {
                    reason: format!(
                        "duplicate ESI {:?} (every [[ethernet_segments]] entry must have a unique ESI)",
                        cfg.esi
                    ),
                });
            }
            for &vni in &seg.member_vnis {
                if let Some(prior_esi) = vni_owner.insert(vni, seg.esi) {
                    return Err(ConfigError::InvalidEthernetSegment {
                        reason: format!(
                            "VNI {} is listed under multiple ethernet_segments \
                             (current segment esi {:?}, prior segment esi {:02x?}); \
                             one local Ethernet Segment per VNI is required for \
                             ESI-aware MAC origination — disambiguation by \
                             learned-port ifindex is not yet plumbed",
                            vni.as_u32(),
                            cfg.esi,
                            prior_esi.octets(),
                        ),
                    });
                }
            }
            out.push(seg);
        }
        Ok(out)
    }

    /// Resolve `[[evpn_ip_vrfs]]` entries into runtime [`IpVrfTable`].
    ///
    /// Validates:
    ///
    /// - Each IP-VRF entry's own field constraints (delegates to
    ///   `parse_evpn_ip_vrf`).
    /// - Uniqueness of `name` and `vni` across the table (delegated to
    ///   [`IpVrfTable::insert`]).
    /// - No L3VNI collides with any L2VNI in `[[evpn_instances]]` —
    ///   the wire VNI space is shared, so reusing a number across L2
    ///   and L3 would create wire ambiguity.
    /// - Every `[[evpn_instances]].ip_vrf` reference resolves to a
    ///   declared IP-VRF. Marks each referenced IP-VRF in the table
    ///   so downstream layers can spot "declared but unused" entries.
    ///
    /// # Errors
    /// Surfaces every malformed or conflicting entry as a
    /// [`ConfigError::InvalidEvpnIpVrf`] with the offending name in
    /// the message.
    pub fn resolve_evpn_ip_vrfs(&self) -> Result<IpVrfTable, ConfigError> {
        let mut table = IpVrfTable::new();
        // Pre-compute the L2VNI set so we can reject any L3VNI that
        // collides with one.
        let l2_vnis: BTreeSet<u32> = self.evpn_instances.iter().map(|c| c.vni).collect();
        for cfg in &self.evpn_ip_vrfs {
            let vrf = parse_evpn_ip_vrf(cfg)?;
            if l2_vnis.contains(&vrf.id.as_u32()) {
                return Err(ConfigError::InvalidEvpnIpVrf {
                    reason: format!(
                        "evpn_ip_vrfs[{}]: L3VNI {} collides with an [[evpn_instances]] entry of the same VNI; \
                         L2VNIs and L3VNIs share the wire VNI space and must not overlap",
                        cfg.name,
                        vrf.id.as_u32()
                    ),
                });
            }
            table
                .insert(vrf)
                .map_err(|e| ConfigError::InvalidEvpnIpVrf {
                    reason: e.to_string(),
                })?;
        }
        // Validate L2→L3 bindings + record references.
        for inst in &self.evpn_instances {
            if let Some(ref name) = inst.ip_vrf {
                if table.get(name).is_none() {
                    return Err(ConfigError::InvalidEvpnIpVrf {
                        reason: format!(
                            "evpn_instances[vni={}]: ip_vrf {:?} does not match any declared [[evpn_ip_vrfs]] entry",
                            inst.vni, name
                        ),
                    });
                }
                table.mark_referenced(name.clone());
            }
        }
        Ok(table)
    }

    /// Returns `(TransportConfig, label, import_chain, export_chain)` per neighbor.
    ///
    /// Per-neighbor policy overrides global; if neighbor has no policy entries,
    /// the corresponding value is `None` (caller falls back to global).
    #[expect(clippy::type_complexity)]
    #[cfg(test)]
    pub fn to_peer_configs(
        &self,
    ) -> Result<
        Vec<(
            TransportConfig,
            String,
            Option<PolicyChain>,
            Option<PolicyChain>,
        )>,
        ConfigError,
    > {
        self.resolved_neighbors().map(|neighbors| {
            neighbors
                .into_iter()
                .map(|neighbor| {
                    (
                        neighbor.transport_config,
                        neighbor.label,
                        neighbor.import_policy,
                        neighbor.export_policy,
                    )
                })
                .collect()
        })
    }
    /// Build `tracing` filter directives for per-peer log level overrides.
    ///
    /// Returns directives like `peer{peer_addr=10.0.0.1}=debug` that can be
    /// appended to an `EnvFilter`.
    pub fn per_peer_log_directives(&self) -> Vec<String> {
        let mut directives = Vec::new();
        for neighbor in &self.neighbors {
            let level = neighbor.log_level.as_deref().or_else(|| {
                neighbor
                    .peer_group
                    .as_deref()
                    .and_then(|name| self.peer_groups.get(name))
                    .and_then(|g| g.log_level.as_deref())
            });
            if let Some(level) = level {
                directives.push(format!(
                    "peer{{peer_addr={addr}}}={level}",
                    addr = neighbor.address
                ));
            }
        }
        directives
    }
}

#[derive(Clone)]
pub struct ResolvedNeighbor {
    pub transport_config: TransportConfig,
    pub label: String,
    pub import_policy: Option<PolicyChain>,
    pub export_policy: Option<PolicyChain>,
    pub peer_group: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GrpcListener {
    Tcp {
        addr: SocketAddr,
        access_mode: GrpcAccessMode,
        token_file: Option<PathBuf>,
        tls: Option<GrpcTlsPaths>,
    },
    Uds {
        path: PathBuf,
        mode: u32,
        access_mode: GrpcAccessMode,
        token_file: Option<PathBuf>,
    },
}

/// PEM file paths for native gRPC mTLS on a TCP listener. All three
/// fields are required together — there is no "TLS-without-mTLS"
/// half-mode.
#[derive(Debug, Clone, PartialEq)]
#[expect(
    clippy::struct_field_names,
    reason = "field-name-postfix repetition mirrors the TOML schema (tls_cert_file / tls_key_file / tls_client_ca_file); operators read TOML, so dropping the suffix here would diverge from the user-facing config keys"
)]
pub struct GrpcTlsPaths {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub client_ca_file: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcAccessMode {
    ReadOnly,
    ReadWrite,
}

/// Differences between two neighbor lists, keyed by address.
pub struct NeighborDiff {
    pub added: Vec<Neighbor>,
    pub removed: Vec<IpAddr>,
    pub changed: Vec<Neighbor>,
}

/// Describe which fields changed between two `Neighbor` configurations.
///
/// Returns a list of human-readable change descriptions (e.g. "`hold_time`: 90 → 45").
pub fn describe_neighbor_changes(old: &Neighbor, new: &Neighbor) -> Vec<String> {
    let mut changes = Vec::new();

    macro_rules! cmp_field {
        ($field:ident) => {
            if old.$field != new.$field {
                changes.push(format!(
                    "{}: {:?} → {:?}",
                    stringify!($field),
                    old.$field,
                    new.$field
                ));
            }
        };
    }

    cmp_field!(remote_asn);
    cmp_field!(description);
    cmp_field!(peer_group);
    cmp_field!(hold_time);
    cmp_field!(max_prefixes);
    cmp_field!(ttl_security);
    cmp_field!(families);
    cmp_field!(graceful_restart);
    cmp_field!(gr_restart_time);
    cmp_field!(gr_stale_routes_time);
    cmp_field!(llgr_stale_time);
    cmp_field!(local_ipv6_nexthop);
    cmp_field!(route_reflector_client);
    cmp_field!(route_server_client);
    cmp_field!(remove_private_as);
    cmp_field!(add_path);
    cmp_field!(log_level);

    // md5_password: log change without revealing values
    if old.md5_password != new.md5_password {
        changes.push("md5_password: <changed>".to_string());
    }

    // Policy changes: summarize rather than dump full config
    if old.import_policy != new.import_policy {
        changes.push("import_policy: <changed>".to_string());
    }
    if old.export_policy != new.export_policy {
        changes.push("export_policy: <changed>".to_string());
    }
    if old.import_policy_chain != new.import_policy_chain {
        changes.push(format!(
            "import_policy_chain: {:?} → {:?}",
            old.import_policy_chain, new.import_policy_chain
        ));
    }
    if old.export_policy_chain != new.export_policy_chain {
        changes.push(format!(
            "export_policy_chain: {:?} → {:?}",
            old.export_policy_chain, new.export_policy_chain
        ));
    }

    changes
}

/// Compare two neighbor lists and return the differences.
///
/// Two neighbors with the same address but different configuration
/// (any field difference) are reported in `changed`.
pub fn diff_neighbors(old: &[Neighbor], new: &[Neighbor]) -> NeighborDiff {
    let old_map: std::collections::HashMap<&str, &Neighbor> =
        old.iter().map(|n| (n.address.as_str(), n)).collect();
    let new_map: std::collections::HashMap<&str, &Neighbor> =
        new.iter().map(|n| (n.address.as_str(), n)).collect();

    let mut added = Vec::new();
    let mut changed = Vec::new();
    for (addr, new_n) in &new_map {
        match old_map.get(addr) {
            None => added.push((*new_n).clone()),
            Some(old_n) => {
                if *old_n != *new_n {
                    changed.push((*new_n).clone());
                }
            }
        }
    }

    let removed: Vec<IpAddr> = old_map
        .keys()
        .filter(|addr| !new_map.contains_key(*addr))
        .filter_map(|addr| addr.parse::<IpAddr>().ok())
        .collect();

    NeighborDiff {
        added,
        removed,
        changed,
    }
}

/// Differences between two peer group maps, keyed by name.
#[derive(Debug, serde::Serialize)]
pub struct PeerGroupDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

/// Differences between two policy configurations.
#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, serde::Serialize)]
pub struct PolicyDiff {
    pub definitions_added: Vec<String>,
    pub definitions_removed: Vec<String>,
    pub definitions_changed: Vec<String>,
    pub neighbor_sets_added: Vec<String>,
    pub neighbor_sets_removed: Vec<String>,
    pub neighbor_sets_changed: Vec<String>,
    pub import_changed: bool,
    pub export_changed: bool,
    pub import_chain_changed: bool,
    pub export_chain_changed: bool,
}

impl PolicyDiff {
    pub fn has_changes(&self) -> bool {
        !self.definitions_added.is_empty()
            || !self.definitions_removed.is_empty()
            || !self.definitions_changed.is_empty()
            || !self.neighbor_sets_added.is_empty()
            || !self.neighbor_sets_removed.is_empty()
            || !self.neighbor_sets_changed.is_empty()
            || self.import_changed
            || self.export_changed
            || self.import_chain_changed
            || self.export_chain_changed
    }
}

/// Full config diff result.
#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, serde::Serialize)]
pub struct ConfigDiff {
    pub neighbors: NeighborDiffSummary,
    /// Neighbors whose effective config — after peer-group inheritance
    /// and policy-chain resolution — differs between old and new
    /// configs, even though their direct neighbor record may be
    /// unchanged. Surfaces inheritance-driven impact: a peer-group or
    /// policy edit that flows down to existing members shows up here,
    /// not just in the raw `peer_groups` / `policy` diffs.
    pub effective_neighbor_impact: Vec<EffectiveNeighborImpact>,
    pub peer_groups: PeerGroupDiff,
    pub peer_group_details: Vec<(String, Vec<String>)>,
    pub policy: PolicyDiff,
    /// `[global] honor_graceful_shutdown` changed. This is
    /// reload-applied through the peer manager, not restart-required.
    pub honor_graceful_shutdown_changed: bool,
    /// `[global] honor_blackhole` changed in the control-plane-only
    /// case. When BLACKHOLE FIB discard is enabled or requested, the
    /// same raw edit is represented by `blackhole_fib_discard_changed`
    /// instead because it affects the startup-only reconciler spawn
    /// gate.
    pub honor_blackhole_changed: bool,
    pub global_changed: bool,
    pub rpki_changed: bool,
    pub bmp_changed: bool,
    pub mrt_changed: bool,
    /// `[[evpn_instances]]` blocks added/removed/modified between old and
    /// new. Surfaced as restart-required today — the Phase-2 foundation
    /// slice has no SIGHUP reconcile path; mutation lands with kernel
    /// reconciliation. Flagging here ensures `--diff` operators don't
    /// silently miss schema edits.
    pub evpn_instances_changed: bool,
    /// `[[evpn_ip_vrfs]]` blocks added/removed/modified between old
    /// and new. Gate 9's foundation slice validates this schema at
    /// startup but has no runtime swap/reconcile surface, so edits are
    /// restart-required and must remain visible across SIGHUPs.
    pub evpn_ip_vrfs_changed: bool,
    /// `[[ethernet_segments]]` blocks added/removed/modified between
    /// old and new. The segment orchestrator resolves this table once
    /// at startup, so edits are restart-required until a runtime swap
    /// surface exists.
    pub ethernet_segments_changed: bool,
    /// `[[fib_tables]]` blocks added/removed/modified between old
    /// and new. The ADR-0061 general-FIB actor resolves the table set
    /// once at startup, so edits are restart-required until runtime
    /// swap semantics are deliberately implemented.
    pub fib_tables_changed: bool,
    /// Top-level Gate 8b kernel-enforcement opt-in changed. The
    /// dataplane actor reads this once at startup, so SIGHUP must not
    /// silently advance the in-memory snapshot.
    pub apply_bum_enforcement_changed: bool,
    /// `[global] install_blackhole_discard`,
    /// `[global] allow_blackhole_broad_prefixes`, or the
    /// `honor_blackhole` component of an enabled/requested FIB
    /// discard spawn gate changed. The BLACKHOLE FIB actor is spawned
    /// once at startup, so edits are restart-required and must remain
    /// visible in `--diff`.
    pub blackhole_fib_discard_changed: bool,
}

/// Per-neighbor impact derived from inheritance / chain resolution.
///
/// `reasons` is a short list of upstream changes that flow down to
/// this neighbor. Possible entries (subset, not exhaustive):
///
/// - `"import policy resolved differently"` — the resolved import
///   chain (peer-group inherited + neighbor inline + global) moved.
/// - `"export policy resolved differently"` — same, for export.
/// - `"peer_group \"X\" changed"` — the named peer-group this
///   neighbor belongs to had a field edit that flows down (no
///   reassignment, just the group's record moved).
/// - `"peer_group resolved as <new> (was <old>)"` — the neighbor was
///   reassigned to a different peer-group.
/// - `"policy \"foo\" changed"` — a named policy referenced via the
///   neighbor's chain or peer-group's chain moved.
/// - `"global import/export chain changed"` — the top-level chain
///   reference list was edited.
/// - `"referenced neighbor_set changed"` — a `neighbor_set` edit
///   may reshape match results for any policy that uses it
///   (coarse: not resolved per neighbor).
///
/// The neighbor address may already appear in the raw `neighbors`
/// diff (added/removed/changed); the effective view is additive — it
/// catches the case where the raw record didn't move but the
/// resolved chain did.
///
/// Restart-required `[global]` / `[rpki]` / `[bmp]` / `[mrt]` edits
/// are deliberately excluded: those flow through different fields
/// (`local_asn`, `local_router_id` on `PeerConfig`) and reload
/// can't apply them, so surfacing them under `effective_neighbor_impact`
/// (which lands under "Reload-applied" in `--diff`) would mislead
/// operators into expecting a reload to absorb a restart-only edit.
#[derive(Debug, serde::Serialize)]
pub struct EffectiveNeighborImpact {
    pub address: String,
    pub reasons: Vec<String>,
}

/// Serializable neighbor diff summary (`NeighborDiff` uses `IpAddr` which is fine,
/// but we want address strings + field-level details).
#[derive(Debug, serde::Serialize)]
pub struct NeighborDiffSummary {
    pub added: Vec<NeighborAddSummary>,
    pub removed: Vec<String>,
    pub changed: Vec<NeighborChangeSummary>,
}

#[derive(Debug, serde::Serialize)]
pub struct NeighborAddSummary {
    pub address: String,
    pub remote_asn: u32,
}

#[derive(Debug, serde::Serialize)]
pub struct NeighborChangeSummary {
    pub address: String,
    pub changes: Vec<String>,
}

impl ConfigDiff {
    /// Changes that SIGHUP will actually reconcile: neighbor
    /// add/remove/modify, plus policy / peer-group / neighbor-set /
    /// global-chain edits that flow down through inheritance.
    pub fn has_reload_applied_changes(&self) -> bool {
        !self.neighbors.added.is_empty()
            || !self.neighbors.removed.is_empty()
            || !self.neighbors.changed.is_empty()
            || !self.peer_groups.added.is_empty()
            || !self.peer_groups.removed.is_empty()
            || !self.peer_groups.changed.is_empty()
            || !self.policy.definitions_added.is_empty()
            || !self.policy.definitions_removed.is_empty()
            || !self.policy.definitions_changed.is_empty()
            || !self.policy.neighbor_sets_added.is_empty()
            || !self.policy.neighbor_sets_removed.is_empty()
            || !self.policy.neighbor_sets_changed.is_empty()
            || self.policy.import_chain_changed
            || self.policy.export_chain_changed
            || self.honor_graceful_shutdown_changed
            || self.honor_blackhole_changed
    }

    /// Changes that require a full daemon restart.
    pub fn has_restart_required_changes(&self) -> bool {
        self.global_changed
            || self.rpki_changed
            || self.bmp_changed
            || self.mrt_changed
            || self.policy.import_changed
            || self.policy.export_changed
            || self.evpn_instances_changed
            || self.evpn_ip_vrfs_changed
            || self.ethernet_segments_changed
            || self.fib_tables_changed
            || self.apply_bum_enforcement_changed
            || self.blackhole_fib_discard_changed
    }

    /// Changes detected but not applied by current SIGHUP. Empty
    /// post the policy / peer-group / chain reload work — kept on
    /// the public surface as a stable predicate so external diff
    /// consumers don't break, and as a hook for future "detected but
    /// not yet applied" buckets (e.g., when a future TOML field
    /// lands ahead of its reload wiring).
    #[expect(
        clippy::unused_self,
        reason = "method preserved on the public surface for external --diff consumers; will gain logic when a future field lands ahead of its reload wiring"
    )]
    pub const fn has_informational_changes(&self) -> bool {
        false
    }

    /// Whether SIGHUP would take any action (reload-applied or restart-required).
    pub fn has_actionable_changes(&self) -> bool {
        self.has_reload_applied_changes() || self.has_restart_required_changes()
    }

    /// Whether any difference exists at all.
    pub fn has_any_changes(&self) -> bool {
        self.has_actionable_changes() || self.has_informational_changes()
    }
}

/// JSON schema shared by `rustbgpd --diff --json` and the live runtime
/// config-diff API. The schema mirrors the human diff buckets:
/// reload-applied, restart-required, and informational.
pub fn config_diff_json_value(diff: &ConfigDiff) -> serde_json::Value {
    serde_json::json!({
        "has_actionable_changes": diff.has_actionable_changes(),
        "has_informational_changes": diff.has_informational_changes(),
        "has_any_changes": diff.has_any_changes(),
        "reload_applied": {
            "neighbors": &diff.neighbors,
            "peer_groups": &diff.peer_groups,
            "peer_group_details": &diff.peer_group_details,
            "policy_definitions_added": &diff.policy.definitions_added,
            "policy_definitions_removed": &diff.policy.definitions_removed,
            "policy_definitions_changed": &diff.policy.definitions_changed,
            "neighbor_sets_added": &diff.policy.neighbor_sets_added,
            "neighbor_sets_removed": &diff.policy.neighbor_sets_removed,
            "neighbor_sets_changed": &diff.policy.neighbor_sets_changed,
            "import_chain_changed": diff.policy.import_chain_changed,
            "export_chain_changed": diff.policy.export_chain_changed,
            "honor_graceful_shutdown_changed": diff.honor_graceful_shutdown_changed,
            "honor_blackhole_changed": diff.honor_blackhole_changed,
            "effective_neighbor_impact": &diff.effective_neighbor_impact,
        },
        "restart_required": {
            "global_changed": diff.global_changed,
            "rpki_changed": diff.rpki_changed,
            "bmp_changed": diff.bmp_changed,
            "mrt_changed": diff.mrt_changed,
            "evpn_instances_changed": diff.evpn_instances_changed,
            "evpn_ip_vrfs_changed": diff.evpn_ip_vrfs_changed,
            "ethernet_segments_changed": diff.ethernet_segments_changed,
            "fib_tables_changed": diff.fib_tables_changed,
            "apply_bum_enforcement_changed": diff.apply_bum_enforcement_changed,
            "blackhole_fib_discard_changed": diff.blackhole_fib_discard_changed,
            "inline_policy_import_changed": diff.policy.import_changed,
            "inline_policy_export_changed": diff.policy.export_changed,
        },
        "informational": serde_json::Value::Object(serde_json::Map::new()),
    })
}

/// Text styling hooks for config-diff renderers.
///
/// The default style is intentionally plain so API and `rustbgpctl`
/// clients never receive terminal escape codes. The daemon CLI can pass
/// colored markers without duplicating the section logic.
pub struct ConfigDiffTextStyle<'a> {
    pub reload_header: std::borrow::Cow<'a, str>,
    pub restart_header: std::borrow::Cow<'a, str>,
    pub add_marker: std::borrow::Cow<'a, str>,
    pub remove_marker: std::borrow::Cow<'a, str>,
    pub change_marker: std::borrow::Cow<'a, str>,
    pub restart_marker: std::borrow::Cow<'a, str>,
    pub inline_policy_hint: std::borrow::Cow<'a, str>,
    pub no_changes: std::borrow::Cow<'a, str>,
}

impl Default for ConfigDiffTextStyle<'_> {
    fn default() -> Self {
        Self {
            reload_header: "Reload-applied changes:".into(),
            restart_header: "Restart-required changes:".into(),
            add_marker: "+".into(),
            remove_marker: "-".into(),
            change_marker: "~".into(),
            restart_marker: "!".into(),
            inline_policy_hint:
                "(migrate inline policy to named definitions + import_chain/export_chain for hot reload)"
                    .into(),
            no_changes: "No changes.".into(),
        }
    }
}

/// Plain-text config diff for API/CLI clients that should not receive
/// terminal color escapes. Secret-bearing values remain redacted by
/// the underlying `ConfigDiff` change descriptions.
pub fn format_config_diff(diff: &ConfigDiff) -> String {
    format_config_diff_with_style(diff, &ConfigDiffTextStyle::default())
}

/// Shared config-diff text renderer used by `rustbgpd --diff` and the
/// live runtime config-diff API. Only markers/headings are styleable;
/// section ordering and field coverage live in one place to avoid drift.
#[expect(
    clippy::too_many_lines,
    reason = "plain renderer intentionally mirrors the human config-diff sections"
)]
pub fn format_config_diff_with_style(diff: &ConfigDiff, style: &ConfigDiffTextStyle<'_>) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let has_pg_changes = !diff.peer_groups.added.is_empty()
        || !diff.peer_groups.removed.is_empty()
        || !diff.peer_groups.changed.is_empty();
    let p = &diff.policy;
    let has_named_policy_changes = !p.definitions_added.is_empty()
        || !p.definitions_removed.is_empty()
        || !p.definitions_changed.is_empty()
        || !p.neighbor_sets_added.is_empty()
        || !p.neighbor_sets_removed.is_empty()
        || !p.neighbor_sets_changed.is_empty()
        || p.import_chain_changed
        || p.export_chain_changed;

    if diff.has_reload_applied_changes() {
        let _ = writeln!(out, "{}\n", style.reload_header);
        let raw_neighbor_changes = !diff.neighbors.added.is_empty()
            || !diff.neighbors.removed.is_empty()
            || !diff.neighbors.changed.is_empty();
        if raw_neighbor_changes {
            out.push_str("  Neighbors:\n");
            for n in &diff.neighbors.added {
                let _ = writeln!(
                    out,
                    "    {} {} (AS {})",
                    style.add_marker, n.address, n.remote_asn
                );
            }
            for addr in &diff.neighbors.removed {
                let _ = writeln!(out, "    {} {addr}", style.remove_marker);
            }
            for n in &diff.neighbors.changed {
                let _ = writeln!(out, "    {} {}:", style.change_marker, n.address);
                for change in &n.changes {
                    let _ = writeln!(out, "        {change}");
                }
            }
            out.push('\n');
        }

        if has_pg_changes {
            out.push_str("  Peer groups:\n");
            for name in &diff.peer_groups.added {
                let _ = writeln!(out, "    {} {name}", style.add_marker);
            }
            for name in &diff.peer_groups.removed {
                let _ = writeln!(out, "    {} {name}", style.remove_marker);
            }
            for (name, details) in &diff.peer_group_details {
                let _ = writeln!(out, "    {} {name}:", style.change_marker);
                for change in details {
                    let _ = writeln!(out, "        {change}");
                }
            }
            out.push('\n');
        }

        if has_named_policy_changes {
            out.push_str("  Policy:\n");
            for name in &p.definitions_added {
                let _ = writeln!(out, "    {} definition \"{name}\"", style.add_marker);
            }
            for name in &p.definitions_removed {
                let _ = writeln!(out, "    {} definition \"{name}\"", style.remove_marker);
            }
            for name in &p.definitions_changed {
                let _ = writeln!(out, "    {} definition \"{name}\"", style.change_marker);
            }
            for name in &p.neighbor_sets_added {
                let _ = writeln!(out, "    {} neighbor_set \"{name}\"", style.add_marker);
            }
            for name in &p.neighbor_sets_removed {
                let _ = writeln!(out, "    {} neighbor_set \"{name}\"", style.remove_marker);
            }
            for name in &p.neighbor_sets_changed {
                let _ = writeln!(out, "    {} neighbor_set \"{name}\"", style.change_marker);
            }
            if p.import_chain_changed {
                let _ = writeln!(out, "    {} import_chain", style.change_marker);
            }
            if p.export_chain_changed {
                let _ = writeln!(out, "    {} export_chain", style.change_marker);
            }
            out.push('\n');
        }

        if !diff.effective_neighbor_impact.is_empty() {
            out.push_str("  Effectively impacted neighbors (via inheritance):\n");
            for impact in &diff.effective_neighbor_impact {
                let _ = writeln!(out, "    {} {}:", style.change_marker, impact.address);
                for reason in &impact.reasons {
                    let _ = writeln!(out, "        {reason}");
                }
            }
            out.push('\n');
        }

        let mut hot_applied_global_flags = Vec::new();
        if diff.honor_graceful_shutdown_changed {
            hot_applied_global_flags.push("honor_graceful_shutdown");
        }
        if diff.honor_blackhole_changed {
            hot_applied_global_flags.push("honor_blackhole");
        }
        if !hot_applied_global_flags.is_empty() {
            out.push_str("  Global hot-applied flags:\n");
            for flag in hot_applied_global_flags {
                let _ = writeln!(out, "    {} {flag}", style.change_marker);
            }
            out.push('\n');
        }
    }

    let mut restart_sections = Vec::new();
    if diff.global_changed {
        restart_sections.push("[global]");
    }
    if diff.rpki_changed {
        restart_sections.push("[rpki]");
    }
    if diff.bmp_changed {
        restart_sections.push("[bmp]");
    }
    if diff.mrt_changed {
        restart_sections.push("[mrt]");
    }
    if diff.evpn_instances_changed {
        restart_sections.push("[[evpn_instances]]");
    }
    if diff.evpn_ip_vrfs_changed {
        restart_sections.push("[[evpn_ip_vrfs]]");
    }
    if diff.ethernet_segments_changed {
        restart_sections.push("[[ethernet_segments]]");
    }
    if diff.fib_tables_changed {
        restart_sections.push("[[fib_tables]]");
    }
    if diff.apply_bum_enforcement_changed {
        restart_sections.push("apply_bum_enforcement");
    }
    if diff.blackhole_fib_discard_changed {
        restart_sections.push("BLACKHOLE FIB discard");
    }
    if p.import_changed {
        restart_sections.push("[policy.import] (inline)");
    }
    if p.export_changed {
        restart_sections.push("[policy.export] (inline)");
    }
    if !restart_sections.is_empty() {
        let _ = writeln!(out, "{}", style.restart_header);
        for section in &restart_sections {
            let _ = writeln!(out, "  {} {section} changed", style.restart_marker);
        }
        if p.import_changed || p.export_changed {
            let _ = writeln!(out, "    {}", style.inline_policy_hint);
        }
        out.push('\n');
    }

    if !diff.has_any_changes() {
        let _ = writeln!(out, "{}", style.no_changes);
    }
    out
}

/// Compare two full configurations and return a structured diff.
pub fn diff_config(old: &Config, new: &Config) -> ConfigDiff {
    let neighbor_diff = diff_neighbors(&old.neighbors, &new.neighbors);

    let old_map: HashMap<&str, &Neighbor> = old
        .neighbors
        .iter()
        .map(|n| (n.address.as_str(), n))
        .collect();

    let neighbors = NeighborDiffSummary {
        added: neighbor_diff
            .added
            .iter()
            .map(|n| NeighborAddSummary {
                address: n.address.clone(),
                remote_asn: n.remote_asn,
            })
            .collect(),
        removed: neighbor_diff
            .removed
            .iter()
            .map(IpAddr::to_string)
            .collect(),
        changed: neighbor_diff
            .changed
            .iter()
            .filter_map(|n| {
                old_map
                    .get(n.address.as_str())
                    .map(|old_n| NeighborChangeSummary {
                        address: n.address.clone(),
                        changes: describe_neighbor_changes(old_n, n),
                    })
            })
            .collect(),
    };

    let peer_groups = diff_peer_groups(&old.peer_groups, &new.peer_groups);
    let peer_group_details = peer_groups
        .changed
        .iter()
        .filter_map(|name| {
            let old_pg = old.peer_groups.get(name)?;
            let new_pg = new.peer_groups.get(name)?;
            let changes = describe_peer_group_changes(old_pg, new_pg);
            if changes.is_empty() {
                None
            } else {
                Some((name.clone(), changes))
            }
        })
        .collect();

    let policy = diff_policy(&old.policy, &new.policy);
    let effective_neighbor_impact =
        compute_effective_neighbor_impact(old, new, &peer_groups, &policy);
    let blackhole_fib_discard_changed = old.global.install_blackhole_discard
        != new.global.install_blackhole_discard
        || old.global.allow_blackhole_broad_prefixes != new.global.allow_blackhole_broad_prefixes
        || ((old.global.install_blackhole_discard || new.global.install_blackhole_discard)
            && old.global.honor_blackhole != new.global.honor_blackhole);

    ConfigDiff {
        neighbors,
        effective_neighbor_impact,
        peer_groups,
        peer_group_details,
        policy,
        honor_graceful_shutdown_changed: old.global.honor_graceful_shutdown
            != new.global.honor_graceful_shutdown,
        honor_blackhole_changed: old.global.honor_blackhole != new.global.honor_blackhole
            && !blackhole_fib_discard_changed,
        global_changed: global_restart_required_changed(old, new),
        rpki_changed: old.rpki != new.rpki,
        bmp_changed: old.bmp != new.bmp,
        mrt_changed: old.mrt != new.mrt,
        evpn_instances_changed: old.evpn_instances != new.evpn_instances,
        evpn_ip_vrfs_changed: old.evpn_ip_vrfs != new.evpn_ip_vrfs,
        ethernet_segments_changed: old.ethernet_segments != new.ethernet_segments,
        fib_tables_changed: old.fib_tables != new.fib_tables,
        apply_bum_enforcement_changed: old.apply_bum_enforcement != new.apply_bum_enforcement,
        blackhole_fib_discard_changed,
    }
}

fn global_restart_required_changed(old: &Config, new: &Config) -> bool {
    let old_global = old.global.clone();
    let mut new_global = new.global.clone();

    // These knobs have explicit reload behavior and must not make the
    // coarse `[global] changed` restart bucket fire by themselves.
    // `honor_blackhole` becomes restart-required only as part of the
    // BLACKHOLE FIB actor's startup gate, reported separately through
    // `blackhole_fib_discard_changed`.
    new_global.honor_graceful_shutdown = old_global.honor_graceful_shutdown;
    new_global.honor_blackhole = old_global.honor_blackhole;
    new_global.install_blackhole_discard = old_global.install_blackhole_discard;
    new_global.allow_blackhole_broad_prefixes = old_global.allow_blackhole_broad_prefixes;

    old_global != new_global
}

/// Walk neighbors that exist in both configs and surface those whose
/// resolved effective config differs between old and new through a
/// reload-applied path — peer-group inheritance, named policy chain
/// edits, neighbor-set membership shifts, peer-group reassignment.
///
/// Deliberately scoped to *reload-applied* signals only: comparing
/// the full resolved `transport_config` would also flag
/// global-derived fields like `local_asn` / `local_router_id` (from
/// `[global]`), which are restart-required and shouldn't surface
/// under `--diff`'s "Reload-applied" bucket. Operators looking at
/// `effective_neighbor_impact` should be able to act on every entry
/// without restarting the daemon.
///
/// What's compared (each contributes a distinct reason string):
///
/// - **Resolved import / export policy chain.** Catches the
///   transitive cases the prior heuristic missed: a
///   `policy.definitions.foo` edit when `foo` is referenced via
///   the unchanged global `import_chain`, or via a peer-group's
///   chain whose record itself is unchanged.
/// - **Peer-group reassignment.** The neighbor moved between
///   peer-groups (its raw record changed, but the cascade is
///   surfaced here too for visibility).
/// - **Peer-group field edits.** The neighbor's peer-group is in
///   `peer_groups.changed`/`added`/`removed`; field edits like
///   `hold_time` flow down via `apply_peer_group_change`'s
///   delete-and-readd path.
/// - **Named policy / neighbor-set / global-chain edits.**
///   Attributed to the specific name where the change was the
///   chain-reference itself; otherwise tagged as a coarse
///   `neighbor_set` or global-chain reason.
///
/// `PolicyChain` doesn't derive `PartialEq` (would require touching
/// nested types in other crates); resolved chain equality goes via
/// `format!("{:?}", ...)`. Both sides come from the same
/// `effective_policy_chains_for_neighbor` resolver and
/// `PolicyChain.policies` is a `Vec` (stable order), so the Debug
/// output is deterministic enough for diff-style equality.
///
/// Resolution failure (invalid chain reference) is treated as
/// "skip" — the load path already validates the new config, so
/// failures here indicate a transient inconsistency we don't want
/// to surface as effective impact.
fn compute_effective_neighbor_impact(
    old: &Config,
    new: &Config,
    peer_groups: &PeerGroupDiff,
    policy: &PolicyDiff,
) -> Vec<EffectiveNeighborImpact> {
    let pg_changed: HashSet<&str> = peer_groups
        .changed
        .iter()
        .map(String::as_str)
        .chain(peer_groups.added.iter().map(String::as_str))
        .chain(peer_groups.removed.iter().map(String::as_str))
        .collect();
    let policy_changed: HashSet<&str> = policy
        .definitions_changed
        .iter()
        .map(String::as_str)
        .chain(policy.definitions_added.iter().map(String::as_str))
        .chain(policy.definitions_removed.iter().map(String::as_str))
        .collect();
    let nset_changed = !policy.neighbor_sets_added.is_empty()
        || !policy.neighbor_sets_removed.is_empty()
        || !policy.neighbor_sets_changed.is_empty();
    let global_chain_changed = policy.import_chain_changed || policy.export_chain_changed;

    let new_by_addr: HashMap<&str, &Neighbor> = new
        .neighbors
        .iter()
        .map(|n| (n.address.as_str(), n))
        .collect();

    let mut out: Vec<EffectiveNeighborImpact> = Vec::new();
    for old_neighbor in &old.neighbors {
        let Some(new_neighbor) = new_by_addr.get(old_neighbor.address.as_str()) else {
            continue;
        };
        let Ok(old_resolved) = old.resolve_neighbor(old_neighbor) else {
            continue;
        };
        let Ok(new_resolved) = new.resolve_neighbor(new_neighbor) else {
            continue;
        };

        let import_moved = format!("{:?}", old_resolved.import_policy)
            != format!("{:?}", new_resolved.import_policy);
        let export_moved = format!("{:?}", old_resolved.export_policy)
            != format!("{:?}", new_resolved.export_policy);

        let mut reasons: Vec<String> = Vec::new();
        if import_moved {
            reasons.push("import policy resolved differently".to_string());
        }
        if export_moved {
            reasons.push("export policy resolved differently".to_string());
        }

        if old_resolved.peer_group != new_resolved.peer_group {
            reasons.push(format!(
                "peer_group resolved as {:?} (was {:?})",
                new_resolved.peer_group, old_resolved.peer_group
            ));
        } else if let Some(name) = new_resolved.peer_group.as_deref()
            && pg_changed.contains(name)
        {
            reasons.push(format!("peer_group {name:?} changed"));
        }

        // Attribute moved chains to specific changed policies / sets
        // / global chain, but only when something *did* move at the
        // resolved-chain level — otherwise we'd surface every
        // neighbor for any neighbor_set edit.
        if import_moved || export_moved {
            let mut chain_refs: Vec<&str> = Vec::new();
            chain_refs.extend(new_neighbor.import_policy_chain.iter().map(String::as_str));
            chain_refs.extend(new_neighbor.export_policy_chain.iter().map(String::as_str));
            chain_refs.extend(old_neighbor.import_policy_chain.iter().map(String::as_str));
            chain_refs.extend(old_neighbor.export_policy_chain.iter().map(String::as_str));
            if let Some(pg_name) = new_resolved.peer_group.as_deref()
                && let Some(pg) = new.peer_groups.get(pg_name)
            {
                chain_refs.extend(pg.import_policy_chain.iter().map(String::as_str));
                chain_refs.extend(pg.export_policy_chain.iter().map(String::as_str));
            }
            for name in chain_refs {
                if policy_changed.contains(name) {
                    let entry = format!("policy {name:?} changed");
                    if !reasons.contains(&entry) {
                        reasons.push(entry);
                    }
                }
            }
            if global_chain_changed {
                let entry = "global import/export chain changed".to_string();
                if !reasons.contains(&entry) {
                    reasons.push(entry);
                }
            }
            if nset_changed {
                let entry = "referenced neighbor_set changed".to_string();
                if !reasons.contains(&entry) {
                    reasons.push(entry);
                }
            }
        }

        if !reasons.is_empty() {
            out.push(EffectiveNeighborImpact {
                address: old_neighbor.address.clone(),
                reasons,
            });
        }
    }
    out.sort_by(|a, b| a.address.cmp(&b.address));
    out
}

/// Compare two peer group maps and return names of added/removed/changed groups.
pub fn diff_peer_groups(
    old: &HashMap<String, PeerGroupConfig>,
    new: &HashMap<String, PeerGroupConfig>,
) -> PeerGroupDiff {
    let mut added = Vec::new();
    let mut changed = Vec::new();
    for (name, new_pg) in new {
        match old.get(name) {
            None => added.push(name.clone()),
            Some(old_pg) => {
                if old_pg != new_pg {
                    changed.push(name.clone());
                }
            }
        }
    }
    added.sort();
    changed.sort();

    let mut removed: Vec<String> = old
        .keys()
        .filter(|name| !new.contains_key(*name))
        .cloned()
        .collect();
    removed.sort();

    PeerGroupDiff {
        added,
        removed,
        changed,
    }
}

/// Describe which fields changed between two `PeerGroupConfig` values.
pub fn describe_peer_group_changes(old: &PeerGroupConfig, new: &PeerGroupConfig) -> Vec<String> {
    let mut changes = Vec::new();

    macro_rules! cmp_field {
        ($field:ident) => {
            if old.$field != new.$field {
                changes.push(format!(
                    "{}: {:?} → {:?}",
                    stringify!($field),
                    old.$field,
                    new.$field
                ));
            }
        };
    }

    cmp_field!(hold_time);
    cmp_field!(max_prefixes);
    cmp_field!(ttl_security);
    cmp_field!(families);
    cmp_field!(graceful_restart);
    cmp_field!(gr_restart_time);
    cmp_field!(gr_stale_routes_time);
    cmp_field!(llgr_stale_time);
    cmp_field!(local_ipv6_nexthop);
    cmp_field!(route_reflector_client);
    cmp_field!(route_server_client);
    cmp_field!(remove_private_as);
    cmp_field!(add_path);
    cmp_field!(log_level);

    if old.md5_password != new.md5_password {
        changes.push("md5_password: <changed>".to_string());
    }
    if old.import_policy != new.import_policy {
        changes.push("import_policy: <changed>".to_string());
    }
    if old.export_policy != new.export_policy {
        changes.push("export_policy: <changed>".to_string());
    }
    if old.import_policy_chain != new.import_policy_chain {
        changes.push(format!(
            "import_policy_chain: {:?} → {:?}",
            old.import_policy_chain, new.import_policy_chain
        ));
    }
    if old.export_policy_chain != new.export_policy_chain {
        changes.push(format!(
            "export_policy_chain: {:?} → {:?}",
            old.export_policy_chain, new.export_policy_chain
        ));
    }

    changes
}

/// Compare two policy configurations.
pub fn diff_policy(old: &PolicyConfig, new: &PolicyConfig) -> PolicyDiff {
    let definitions_added: Vec<String> = new
        .definitions
        .keys()
        .filter(|k| !old.definitions.contains_key(*k))
        .cloned()
        .collect();
    let definitions_removed: Vec<String> = old
        .definitions
        .keys()
        .filter(|k| !new.definitions.contains_key(*k))
        .cloned()
        .collect();
    let definitions_changed: Vec<String> = new
        .definitions
        .iter()
        .filter(|(k, v)| old.definitions.get(*k).is_some_and(|old_v| old_v != *v))
        .map(|(k, _)| k.clone())
        .collect();

    let neighbor_sets_added: Vec<String> = new
        .neighbor_sets
        .keys()
        .filter(|k| !old.neighbor_sets.contains_key(*k))
        .cloned()
        .collect();
    let neighbor_sets_removed: Vec<String> = old
        .neighbor_sets
        .keys()
        .filter(|k| !new.neighbor_sets.contains_key(*k))
        .cloned()
        .collect();
    let neighbor_sets_changed: Vec<String> = new
        .neighbor_sets
        .iter()
        .filter(|(k, v)| old.neighbor_sets.get(*k).is_some_and(|old_v| old_v != *v))
        .map(|(k, _)| k.clone())
        .collect();

    PolicyDiff {
        definitions_added,
        definitions_removed,
        definitions_changed,
        neighbor_sets_added,
        neighbor_sets_removed,
        neighbor_sets_changed,
        import_changed: old.import != new.import,
        export_changed: old.export != new.export,
        import_chain_changed: old.import_chain != new.import_chain,
        export_chain_changed: old.export_chain != new.export_chain,
    }
}

impl From<GrpcAccessModeConfig> for GrpcAccessMode {
    fn from(value: GrpcAccessModeConfig) -> Self {
        match value {
            GrpcAccessModeConfig::ReadOnly => Self::ReadOnly,
            GrpcAccessModeConfig::ReadWrite => Self::ReadWrite,
        }
    }
}

/// Parse one [`EvpnInstanceConfig`] entry into the runtime
/// [`EvpnInstance`] domain type.
///
/// All operator-input fields are revalidated here even though
/// `Config::validate` already touched them — `resolve_evpn_instances`
/// is called from non-load paths (gRPC `ListEvpnInstances`, future
/// SIGHUP reconcile) where the config has already passed `validate`,
/// so the second pass is cheap and protects against misuse if a caller
/// ever skips validation.
fn parse_evpn_instance(cfg: &EvpnInstanceConfig) -> Result<EvpnInstance, ConfigError> {
    let id = EvpnInstanceId::new(cfg.vni).map_err(|e| ConfigError::InvalidEvpnInstance {
        reason: format!("vni {}: {e}", cfg.vni),
    })?;

    let rd =
        cfg.rd
            .parse::<RouteDistinguisher>()
            .map_err(|e| ConfigError::InvalidEvpnInstance {
                reason: format!("vni {}: invalid rd {:?}: {e}", cfg.vni, cfg.rd),
            })?;

    if cfg.route_targets.is_empty() {
        return Err(ConfigError::InvalidEvpnInstance {
            reason: format!("vni {}: route_targets must not be empty", cfg.vni),
        });
    }
    let mut rts: Vec<RouteTarget> = Vec::with_capacity(cfg.route_targets.len());
    for raw in &cfg.route_targets {
        let rt = raw
            .parse::<RouteTarget>()
            .map_err(|e| ConfigError::InvalidEvpnInstance {
                reason: format!("vni {}: invalid route_target {:?}: {e}", cfg.vni, raw),
            })?;
        rts.push(rt);
    }

    let local_vtep_ip =
        cfg.local_vtep_ip
            .parse::<IpAddr>()
            .map_err(|e| ConfigError::InvalidEvpnInstance {
                reason: format!(
                    "vni {}: invalid local_vtep_ip {:?}: {e}",
                    cfg.vni, cfg.local_vtep_ip
                ),
            })?;

    if let Some(bridge) = cfg.bridge.as_deref()
        && bridge.trim().is_empty()
    {
        return Err(ConfigError::InvalidEvpnInstance {
            reason: format!("vni {}: bridge name must not be empty", cfg.vni),
        });
    }

    let mut sticky_macs: BTreeSet<MacAddress> = BTreeSet::new();
    for raw in &cfg.sticky_macs {
        let mac = parse_mac_address(raw).map_err(|e| ConfigError::InvalidEvpnInstance {
            reason: format!("vni {}: invalid sticky_mac {raw:?}: {e}", cfg.vni),
        })?;
        if !sticky_macs.insert(mac) {
            return Err(ConfigError::InvalidEvpnInstance {
                reason: format!(
                    "vni {}: duplicate sticky_mac {raw:?} (sticky_macs entries must be unique within an instance)",
                    cfg.vni
                ),
            });
        }
    }

    let inst = EvpnInstance::new(
        id,
        rd,
        rts,
        local_vtep_ip,
        cfg.bridge.clone(),
        cfg.advertise_svi_mac,
    )
    .map_err(|e| ConfigError::InvalidEvpnInstance {
        reason: format!("vni {}: {e}", cfg.vni),
    })?;
    let duplicate_mac_detection =
        parse_duplicate_mac_detection(cfg.vni, &cfg.duplicate_mac_detection)?;
    Ok(inst
        .with_sticky_macs(sticky_macs)
        .with_apply_aliasing_ecmp(cfg.apply_aliasing_ecmp)
        .with_duplicate_mac_detection(duplicate_mac_detection))
}

fn parse_duplicate_mac_detection(
    vni: u32,
    cfg: &EvpnDuplicateMacDetectionConfig,
) -> Result<DuplicateMacConfig, ConfigError> {
    let action = match cfg.action {
        EvpnDuplicateMacActionConfig::Detect => DuplicateMacAction::DetectOnly,
        EvpnDuplicateMacActionConfig::SuppressLocal => DuplicateMacAction::SuppressLocal,
    };
    DuplicateMacConfig::new(
        action,
        std::time::Duration::from_secs(cfg.window_seconds),
        cfg.threshold,
        std::time::Duration::from_secs(cfg.recovery_seconds),
    )
    .map_err(|e| ConfigError::InvalidEvpnInstance {
        reason: format!("vni {vni}: {e}"),
    })
}

/// Parse a `aa:bb:cc:dd:ee:ff` MAC string into a [`MacAddress`]. The
/// wire crate intentionally does not implement `FromStr` on
/// `MacAddress` (RFC 7432 NLRI uses raw bytes, not the operator
/// notation), so the daemon owns this parse.
fn parse_mac_address(raw: &str) -> Result<MacAddress, &'static str> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 6 {
        return Err("expected 6 colon-separated octets");
    }
    let mut bytes = [0u8; 6];
    for (i, octet) in parts.iter().enumerate() {
        if octet.len() != 2 {
            return Err("each octet must be exactly 2 hex digits");
        }
        bytes[i] = u8::from_str_radix(octet, 16).map_err(|_| "invalid hex octet")?;
    }
    Ok(MacAddress::new(bytes))
}

/// Parse one [`EthernetSegmentConfig`] entry into the runtime
/// [`EthernetSegment`] domain type. Validates the ESI text form,
/// rejects Type 0 (single-homed sentinel), and confirms every
/// member VNI exists in the resolved EVPN instance set.
fn parse_ethernet_segment(
    cfg: &EthernetSegmentConfig,
    known_vnis: &BTreeSet<EvpnInstanceId>,
) -> Result<EthernetSegment, ConfigError> {
    let esi = parse_esi(&cfg.esi).map_err(|e| ConfigError::InvalidEthernetSegment {
        reason: format!("esi {:?}: {e}", cfg.esi),
    })?;
    if esi.esi_type() == 0 && esi.octets().iter().all(|&b| b == 0) {
        return Err(ConfigError::InvalidEthernetSegment {
            reason: format!(
                "esi {:?}: Type 0 (all-zero) ESI is the single-homed sentinel; \
                 [[ethernet_segments]] entries must use a non-zero ESI",
                cfg.esi
            ),
        });
    }

    if cfg.member_vnis.is_empty() {
        return Err(ConfigError::InvalidEthernetSegment {
            reason: format!(
                "esi {:?}: member_vnis must contain at least one configured EVPN instance",
                cfg.esi
            ),
        });
    }

    let mut member_vnis: BTreeSet<EvpnInstanceId> = BTreeSet::new();
    for raw in &cfg.member_vnis {
        let id = EvpnInstanceId::new(*raw).map_err(|e| ConfigError::InvalidEthernetSegment {
            reason: format!("member_vni {raw}: {e}"),
        })?;
        if !known_vnis.contains(&id) {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "member_vni {raw} not declared in [[evpn_instances]] — every \
                     ES member VNI must have a matching EVPN instance"
                ),
            });
        }
        if !member_vnis.insert(id) {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!("duplicate member_vni {raw} within ESI {:?}", cfg.esi),
            });
        }
    }

    let default_preference = 32_768;
    if cfg.df_preference != default_preference {
        return Err(ConfigError::InvalidEthernetSegment {
            reason: format!(
                "df_preference {}: reserved for a future preference-based DF election \
                 implementation; Gate 8 accepts only the default {default_preference}",
                cfg.df_preference
            ),
        });
    }

    let df_algorithm = match cfg.df_algorithm.as_str() {
        "default-modulo" => DfAlgorithm::DefaultModulo,
        "highest-random-weight" | "preference-based" => {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "df_algorithm {:?}: reserved for a future Gate 8b/8c implementation; \
                     Gate 8 accepts only \"default-modulo\"",
                    cfg.df_algorithm
                ),
            });
        }
        other => {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!("df_algorithm {other:?}: must be \"default-modulo\""),
            });
        }
    };

    let originator_ip =
        cfg.originator_ip
            .parse::<IpAddr>()
            .map_err(|e| ConfigError::InvalidEthernetSegment {
                reason: format!("originator_ip {:?}: {e}", cfg.originator_ip),
            })?;

    Ok(EthernetSegment {
        esi,
        member_vnis,
        df_preference: cfg.df_preference,
        df_algorithm,
        originator_ip,
    })
}

/// Parse one [`EvpnIpVrfConfig`] entry into the runtime [`IpVrf`]
/// domain type. Validates the VNI range, RD / RT / Router MAC /
/// device-name shape, and table id; uniqueness across
/// `[[evpn_ip_vrfs]]` and L3↔L2 VNI overlap are checked at the
/// table-build level in `resolve_evpn_ip_vrfs`.
fn parse_evpn_ip_vrf(cfg: &EvpnIpVrfConfig) -> Result<IpVrf, ConfigError> {
    if cfg.name.trim().is_empty() {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!("evpn_ip_vrfs[vni={}]: name must not be empty", cfg.vni),
        });
    }
    // Restrict the name to a safe identifier shape — operators may
    // pass these to gRPC / logging / config diffs, and an
    // unrestricted-character name complicates every downstream tool.
    if !cfg
        .name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        || !cfg
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!("name {:?}: must match ^[a-zA-Z][a-zA-Z0-9_-]*$", cfg.name),
        });
    }

    let id = IpVrfId::new(cfg.vni).map_err(|e| ConfigError::InvalidEvpnIpVrf {
        reason: format!("name {:?}: {e}", cfg.name),
    })?;

    let rd = cfg
        .rd
        .parse::<RouteDistinguisher>()
        .map_err(|e| ConfigError::InvalidEvpnIpVrf {
            reason: format!("name {:?}: invalid rd {:?}: {e}", cfg.name, cfg.rd),
        })?;

    if cfg.route_targets.is_empty() {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!("name {:?}: route_targets must not be empty", cfg.name),
        });
    }
    let mut rts: Vec<RouteTarget> = Vec::with_capacity(cfg.route_targets.len());
    for raw in &cfg.route_targets {
        let rt = raw
            .parse::<RouteTarget>()
            .map_err(|e| ConfigError::InvalidEvpnIpVrf {
                reason: format!("name {:?}: invalid route_target {:?}: {e}", cfg.name, raw),
            })?;
        rts.push(rt);
    }

    let local_vtep_ip =
        cfg.local_vtep_ip
            .parse::<IpAddr>()
            .map_err(|e| ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "name {:?}: invalid local_vtep_ip {:?}: {e}",
                    cfg.name, cfg.local_vtep_ip
                ),
            })?;

    let router_mac =
        parse_mac_address(&cfg.router_mac).map_err(|e| ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "name {:?}: invalid router_mac {:?}: {e}",
                cfg.name, cfg.router_mac
            ),
        })?;

    IpVrf::new(
        cfg.name.clone(),
        id,
        rd,
        rts,
        local_vtep_ip,
        router_mac,
        cfg.vrf_device.clone(),
        cfg.l3vxlan_device.clone(),
        cfg.table_id,
    )
    .map_err(|e| ConfigError::InvalidEvpnIpVrf {
        reason: e.to_string(),
    })
}

/// Parse a 10-byte ESI from operator text form
/// (`XX:XX:XX:XX:XX:XX:XX:XX:XX:XX`). Each octet must be exactly
/// two hex digits. The wire crate intentionally doesn't implement
/// `FromStr` on `EthernetSegmentIdentifier` (the on-the-wire form
/// is raw bytes, not the operator notation), so the daemon owns
/// this parse.
fn parse_esi(raw: &str) -> Result<EthernetSegmentIdentifier, &'static str> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 10 {
        return Err("expected 10 colon-separated hex octets");
    }
    let mut bytes = [0u8; 10];
    for (i, octet) in parts.iter().enumerate() {
        if octet.len() != 2 {
            return Err("each octet must be exactly 2 hex digits");
        }
        bytes[i] = u8::from_str_radix(octet, 16).map_err(|_| "invalid hex octet")?;
    }
    Ok(EthernetSegmentIdentifier::new(bytes))
}

#[cfg(test)]
mod tests;
