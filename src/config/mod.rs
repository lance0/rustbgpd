pub mod diagnostic;
mod parse;
pub mod profiles;
mod schema;
mod validation;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::PathBuf;

use rustbgpd_evpn::{
    DfAlgorithm, DuplicateMacAction, DuplicateMacConfig, EthernetSegment, EvpnInstance,
    EvpnInstanceId, EvpnInstanceTable, EvpnRuntimeCandidate, EvpnRuntimeModel, EvpnRuntimePlan,
    IpVrf, IpVrfId, IpVrfTable, OverlayIndexMode, RedundancyMode, RouteTarget,
};
use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::{
    CommunityMatch, NextHopAction, Policy, PolicyAction, PolicyChain, PolicyStatement,
    RouteModifications, parse_community_match,
};
use rustbgpd_transport::{
    RemovePrivateAs, TcpAoAlgorithm, TcpAoConfig as TransportTcpAoConfig, TransportConfig,
};
use rustbgpd_wire::{
    Afi, EthernetSegmentIdentifier, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, LargeCommunity,
    MacAddress, Prefix, RouteDistinguisher, Safi,
};

pub use schema::*;
pub(crate) use validation::{effective_prefix, effective_prefix_str};

use self::parse::{parse_families, parse_policy, resolve_chain};
use self::schema::{BGP_PORT, DEFAULT_CONNECT_RETRY_SECS, DEFAULT_HOLD_TIME};

#[cfg(test)]
use self::parse::parse_named_policy;

impl Config {
    fn interface_index(interface: &str) -> Result<u32, String> {
        nix::net::if_::if_nametoindex(interface)
            .map_err(|err| format!("interface {interface:?} does not exist or is invalid: {err}"))
    }

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
        let content = test_only_inject_legacy_grpc_security(content);
        Self::load_from_toml_source(content.as_ref(), source_name)
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
        let content = test_only_inject_legacy_grpc_security(&content);
        let mut config = Self::load_from_toml_source(content.as_ref(), path)?;
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
                max_tier: GrpcMaxTier::OperatorOnly,
                token_file: None,
                principal: None,
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
            let access_mode = cfg
                .access_mode
                .map_or(GrpcAccessMode::ReadWrite, Into::into);
            listeners.push(GrpcListener::Tcp {
                addr,
                access_mode,
                max_tier: effective_grpc_max_tier(access_mode, cfg.max_tier),
                token_file: cfg.token_file.as_ref().map(PathBuf::from),
                principal: cfg.principal.clone(),
                tls,
            });
        }
        if let Some(cfg) = uds {
            let path = cfg
                .path
                .as_ref()
                .map_or_else(|| self.default_grpc_uds_path(), PathBuf::from);
            let access_mode = cfg
                .access_mode
                .map_or(GrpcAccessMode::ReadWrite, Into::into);
            listeners.push(GrpcListener::Uds {
                path,
                mode: cfg.mode,
                access_mode,
                max_tier: effective_grpc_max_tier(access_mode, cfg.max_tier),
                token_file: cfg.token_file.as_ref().map(PathBuf::from),
                principal: cfg.principal.clone(),
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

    /// Resolved path for the durable event-history outbox (ADR-0072).
    /// Honors `[event_history].path` when set; defaults to
    /// `<runtime_state_dir>/events.db`. Consumed by the daemon when
    /// it starts the `EventHistoryManager` actor.
    #[must_use]
    pub fn event_history_db_path(&self) -> PathBuf {
        let configured = &self.event_history.path;
        if configured.is_empty() {
            self.runtime_state_dir().join("events.db")
        } else {
            let p = PathBuf::from(configured);
            if p.is_absolute() {
                p
            } else {
                self.runtime_state_dir().join(p)
            }
        }
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
                    chain
                        .policies
                        .push(Self::build_implicit_gshut_policy().into());
                }
                if self.global.honor_blackhole {
                    chain
                        .policies
                        .push(Self::build_implicit_blackhole_policy().into());
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

    fn resolved_role(
        neighbor: &Neighbor,
        group: Option<&PeerGroupConfig>,
    ) -> Option<rustbgpd_wire::BgpRole> {
        neighbor
            .role
            .or_else(|| group.and_then(|g| g.role))
            .map(BgpRoleConfig::to_wire)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "neighbor resolution centralizes inheritance, validation, and transport projection"
    )]
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
            local_role: Self::resolved_role(neighbor, group),
            strict_role: neighbor
                .strict_role
                .or_else(|| group.and_then(|g| g.strict_role))
                .unwrap_or(false),
            prefix_orf_receive: neighbor
                .prefix_orf_receive
                .or_else(|| group.and_then(|g| g.prefix_orf_receive))
                .unwrap_or(false),
            disable_ipv4_unicast: neighbor
                .disable_ipv4_unicast
                .or_else(|| group.and_then(|g| g.disable_ipv4_unicast))
                .unwrap_or(false),
        };

        let (remote_addr, peer_interface, peer_scope_id) =
            if let (IpAddr::V6(v6), Some(interface)) = (peer_addr, neighbor.interface.as_ref()) {
                let scope_id = Self::interface_index(interface).map_err(|err| {
                    ConfigError::InvalidNeighborConfig {
                        address: neighbor.address.clone(),
                        field: "interface".to_string(),
                        reason: err,
                    }
                })?;
                (
                    SocketAddr::V6(SocketAddrV6::new(v6, BGP_PORT, 0, scope_id)),
                    Some(interface.clone()),
                    Some(scope_id),
                )
            } else {
                (SocketAddr::new(peer_addr, BGP_PORT), None, None)
            };
        let mut transport = TransportConfig::new(peer, remote_addr);
        transport.peer_interface = peer_interface;
        transport.peer_scope_id = peer_scope_id;
        transport.max_prefixes = neighbor
            .max_prefixes
            .or_else(|| group.and_then(|g| g.max_prefixes));
        transport.peer_group.clone_from(&neighbor.peer_group);
        transport.md5_password = neighbor
            .md5_password
            .clone()
            .or_else(|| group.and_then(|g| g.md5_password.clone()));
        transport.tcp_ao = neighbor.tcp_ao.as_ref().map(|tcp_ao| TransportTcpAoConfig {
            key: tcp_ao.key.clone(),
            send_id: tcp_ao.send_id,
            recv_id: tcp_ao.recv_id,
            algorithm: TcpAoAlgorithm::from_linux_name(&tcp_ao.algorithm)
                .expect("validated in Config::load"),
            preferred: tcp_ao.preferred,
            deprecated: tcp_ao.deprecated,
        });
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
        // RFC 4456: thread the local cluster-id just like
        // `PeerManager::build_transport_config`. Without it a runtime-added
        // iBGP client (this path backs the snapshot-sync gRPC peer adds)
        // reflects routes with no CLUSTER_LIST prepend and skips inbound
        // cluster-loop detection until the daemon restarts.
        transport.cluster_id = self.cluster_id();
        // ADR-0073: this is the second transport-construction path (the
        // resolved-neighbor one used by snapshot-sync gRPC peer adds);
        // it must thread the explain knobs just like
        // PeerManager::build_transport_config, or a gRPC-added peer
        // silently gets the `TransportConfig::new` defaults regardless
        // of `[policy.explain]`.
        transport.explain_enabled = self.policy.explain.enabled;
        transport.explain_cache_size = self.policy.explain.cache_size;

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
            interface: None,
            remote_asn,
            description: Some(description.to_string()),
            peer_group: Some(peer_group_name.to_string()),
            hold_time: None,
            max_prefixes: None,
            md5_password: None,
            tcp_ao: None,
            bfd: None,
            ttl_security: None,
            families: Vec::new(),
            graceful_restart: None,
            gr_restart_time: None,
            gr_stale_routes_time: None,
            llgr_stale_time: None,
            local_ipv6_nexthop: None,
            route_reflector_client: None,
            route_server_client: None,
            role: None,
            strict_role: None,
            prefix_orf_receive: None,
            disable_ipv4_unicast: None,
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
            let inst = parse_evpn_instance(cfg, self.global.asn)?;
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

    /// Resolve the ADR-0085 attachment-circuit bindings declared on
    /// `[[ethernet_segments]]` entries (`interface` +
    /// `recovery_delay_secs`) into the daemon-side map keyed by ESI.
    ///
    /// Deliberately separate from [`Self::resolve_ethernet_segments`]:
    /// the binding is coordinator-side trigger state, not part of the
    /// [`EthernetSegment`] domain type the segment actor diffs — a
    /// binding-only edit must not register as a "redefined" segment
    /// and re-originate its routes. Binding-field validation lives in
    /// `parse_ethernet_segment` so every config path rejects malformed
    /// bindings.
    ///
    /// # Errors
    /// Surfaces a malformed ESI as
    /// [`ConfigError::InvalidEthernetSegment`] (already rejected by
    /// full validation; kept as an error so this resolver is safe to
    /// call on any `Config`).
    pub fn resolve_es_link_bindings(
        &self,
    ) -> Result<BTreeMap<EthernetSegmentIdentifier, EsLinkBinding>, ConfigError> {
        let mut out = BTreeMap::new();
        for cfg in &self.ethernet_segments {
            let Some(interface) = cfg.interface.clone() else {
                continue;
            };
            let esi = parse_esi(&cfg.esi).map_err(|e| ConfigError::InvalidEthernetSegment {
                reason: format!("esi {:?}: {e}", cfg.esi),
            })?;
            out.insert(
                esi,
                EsLinkBinding {
                    interface,
                    recovery_delay: std::time::Duration::from_secs(
                        cfg.recovery_delay_secs
                            .unwrap_or(DEFAULT_ES_RECOVERY_DELAY_SECS),
                    ),
                },
            );
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
            let vrf = parse_evpn_ip_vrf(cfg, self.global.asn)?;
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
                let vni = rustbgpd_evpn::EvpnInstanceId::new(inst.vni).map_err(|e| {
                    ConfigError::InvalidEvpnIpVrf {
                        reason: format!(
                            "evpn_instances[vni={}]: cannot record ip_vrf {:?} reference: {e}",
                            inst.vni, name
                        ),
                    }
                })?;
                table.mark_referenced_by_l2vni(name.clone(), vni);
            }
        }
        // ADR-0087: GW-IP overlay-index origination requires a linked
        // L2VNI — the receive side scopes the recursive Type 2 lookup
        // to the tenant's MAC-VRFs through that link, so a gateway_ip
        // VRF with no L2VNI could never produce a resolvable route.
        // ESI overlay-index mode needs the same IP-VRF<->MAC-VRF link
        // plus a configured Ethernet Segment member to make EAD-based
        // recursive resolution possible.
        // Reject at load rather than silently originate unresolvable
        // Type 5s. Checked after references are recorded so the
        // L2VNI->IP-VRF bindings are complete.
        let es_members_by_esi = if table
            .iter()
            .any(|vrf| vrf.overlay_index_mode == OverlayIndexMode::Esi)
        {
            Some(self.overlay_index_esi_member_map()?)
        } else {
            None
        };
        for vrf in table.iter() {
            if vrf.overlay_index_mode == OverlayIndexMode::GatewayIp
                && table
                    .referenced_l2vnis(&vrf.name)
                    .is_none_or(std::collections::BTreeSet::is_empty)
            {
                return Err(ConfigError::InvalidEvpnIpVrf {
                    reason: format!(
                        "evpn_ip_vrfs[{}]: overlay_index_mode = \"gateway_ip\" requires at least one \
                         [[evpn_instances]] with ip_vrf = {:?} (the GW-IP receive side scopes its \
                         recursive Type 2 lookup to the linked L2VNIs); link an L2VNI or use \
                         \"interface_less\"",
                        vrf.name, vrf.name
                    ),
                });
            }
            if vrf.overlay_index_mode == OverlayIndexMode::Esi {
                validate_esi_overlay_index_vrf(
                    vrf,
                    &table,
                    es_members_by_esi
                        .as_ref()
                        .expect("ES member map exists when any VRF uses ESI mode"),
                )?;
            }
        }
        Ok(table)
    }

    fn overlay_index_esi_member_map(
        &self,
    ) -> Result<BTreeMap<EthernetSegmentIdentifier, BTreeSet<EvpnInstanceId>>, ConfigError> {
        let mut out = BTreeMap::new();
        for cfg in &self.ethernet_segments {
            let esi = parse_esi(&cfg.esi).map_err(|e| ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "ethernet_segments[esi={:?}]: invalid ESI needed for ESI overlay-index validation: {e}",
                    cfg.esi
                ),
            })?;
            let mut members = BTreeSet::new();
            for &raw_vni in &cfg.member_vnis {
                let vni =
                    EvpnInstanceId::new(raw_vni).map_err(|e| ConfigError::InvalidEvpnIpVrf {
                        reason: format!(
                            "ethernet_segments[esi={:?}]: invalid member VNI {raw_vni} needed for \
                             ESI overlay-index validation: {e}",
                            cfg.esi
                        ),
                    })?;
                members.insert(vni);
            }
            out.insert(esi, members);
        }
        Ok(out)
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
        max_tier: GrpcMaxTier,
        token_file: Option<PathBuf>,
        principal: Option<String>,
        tls: Option<GrpcTlsPaths>,
    },
    Uds {
        path: PathBuf,
        mode: u32,
        access_mode: GrpcAccessMode,
        max_tier: GrpcMaxTier,
        token_file: Option<PathBuf>,
        principal: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GrpcMaxTier {
    Read,
    SensitiveRead,
    Mutating,
    OperatorOnly,
}

const fn access_mode_compatibility_max_tier(access_mode: GrpcAccessMode) -> GrpcMaxTier {
    match access_mode {
        GrpcAccessMode::ReadOnly => GrpcMaxTier::SensitiveRead,
        GrpcAccessMode::ReadWrite => GrpcMaxTier::OperatorOnly,
    }
}

const TRANSACTION_FIB_SECTION: &str = "[[fib_tables]]";
const TRANSACTION_DYNAMIC_SECTION: &str = "[[dynamic_neighbors]]";
const TRANSACTION_NEIGHBOR_ADD_SECTION: &str = "[[neighbors]] add";
const TRANSACTION_NEIGHBOR_DELETE_SECTION: &str = "[[neighbors]] delete";
const TRANSACTION_NEIGHBOR_MODIFY_SECTION: &str = "[[neighbors]] modify";
const TRANSACTION_PEER_GROUP_CATALOG_SECTION: &str = "[peer_groups] catalog";
const TRANSACTION_POLICY_DEFINITIONS_SECTION: &str = "[policy] definitions";
const TRANSACTION_POLICY_NEIGHBOR_SETS_SECTION: &str = "[policy] neighbor_sets";
const TRANSACTION_POLICY_GLOBAL_CHAINS_SECTION: &str = "[policy] global chains";
const TRANSACTION_POLICY_LIVE_IMPACT_SECTION: &str = "[policy] live impact";
const TRANSACTION_SESSION_RESHAPE_SECTION: &str = "effective neighbor session reshape";

/// Test-only auto-inject for the v0.24.0 `enforcement = "tier"`
/// default flip. When compiled with `#[cfg(test)]` and the supplied
/// TOML declares no `security.grpc` table or sub-table, appends an
/// explicit `enforcement = "legacy"` so existing test fixtures
/// continue to exercise pre-flip behavior without per-test churn.
/// Production builds compile this as an identity passthrough —
/// operators see the real default flip without any test-only
/// divergence.
#[cfg(test)]
fn test_only_inject_legacy_grpc_security(content: &str) -> std::borrow::Cow<'_, str> {
    // Skip the inject if the TOML declares ANY `security.grpc`
    // configuration — the `[security.grpc]` table header or any
    // sub-table such as `[security.grpc.roles]`. A fixture that
    // configures roles but omits `enforcement` deliberately relies
    // on the production default (Tier), so we must not override it
    // with a legacy inject.
    if content.contains("[security.grpc]") || content.contains("[security.grpc.") {
        std::borrow::Cow::Borrowed(content)
    } else {
        // Append the injected table to the END of the content. A
        // prepend would cause any subsequent bare-key (top-level)
        // declarations in the test TOML to be parsed under the
        // injected `[security.grpc]` table, producing
        // "unknown field" errors.
        std::borrow::Cow::Owned(format!(
            "{content}\n[security.grpc]\nenforcement = \"legacy\"\n"
        ))
    }
}

#[cfg(not(test))]
fn test_only_inject_legacy_grpc_security(content: &str) -> std::borrow::Cow<'_, str> {
    std::borrow::Cow::Borrowed(content)
}

fn effective_grpc_max_tier(
    access_mode: GrpcAccessMode,
    configured: Option<GrpcMaxTierConfig>,
) -> GrpcMaxTier {
    access_mode_compatibility_max_tier(access_mode)
        .min(configured.map_or(GrpcMaxTier::OperatorOnly, GrpcMaxTier::from))
}

/// Differences between two neighbor lists, keyed by address.
pub struct NeighborDiff {
    pub added: Vec<Neighbor>,
    pub removed: Vec<rustbgpd_api::peer_types::PeerKey>,
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
    cmp_field!(role);
    cmp_field!(strict_role);
    cmp_field!(prefix_orf_receive);
    cmp_field!(disable_ipv4_unicast);
    cmp_field!(remove_private_as);
    cmp_field!(add_path);
    cmp_field!(log_level);

    // md5_password: log change without revealing values
    if old.md5_password != new.md5_password {
        changes.push("md5_password: <changed>".to_string());
    }
    if old.tcp_ao != new.tcp_ao {
        changes.push("tcp_ao: <changed restart-required>".to_string());
    }
    if old.bfd != new.bfd {
        changes.push("bfd: <changed restart-required>".to_string());
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
/// Two neighbors with the same address but different runtime-affecting
/// configuration are reported in `changed`. TCP-AO edits are deliberately
/// excluded here because they are startup-listener key material: `diff_config`
/// reports them through `neighbor_tcp_ao_changed`, and SIGHUP pins them until
/// daemon restart rather than hot-reconciling a peer with stale listener MKTs.
pub fn diff_neighbors(old: &[Neighbor], new: &[Neighbor]) -> NeighborDiff {
    let key = |n: &Neighbor| (n.address.clone(), n.interface.clone());
    let old_map: std::collections::HashMap<(String, Option<String>), &Neighbor> =
        old.iter().map(|n| (key(n), n)).collect();
    let new_map: std::collections::HashMap<(String, Option<String>), &Neighbor> =
        new.iter().map(|n| (key(n), n)).collect();

    let mut added = Vec::new();
    let mut changed = Vec::new();
    for (addr, new_n) in &new_map {
        match old_map.get(addr) {
            None => added.push((*new_n).clone()),
            Some(old_n) => {
                if !neighbor_runtime_equal(old_n, new_n) {
                    changed.push((*new_n).clone());
                }
            }
        }
    }

    let removed: Vec<rustbgpd_api::peer_types::PeerKey> = old_map
        .iter()
        .filter(|(key, _)| !new_map.contains_key(key))
        .filter_map(|((_addr, _interface), neighbor)| {
            neighbor.address.parse::<IpAddr>().ok().map(|address| {
                rustbgpd_api::peer_types::PeerKey::new(address, neighbor.interface.clone())
            })
        })
        .collect();

    NeighborDiff {
        added,
        removed,
        changed,
    }
}

fn neighbor_runtime_equal(old: &Neighbor, new: &Neighbor) -> bool {
    old.address == new.address
        && old.interface == new.interface
        && old.remote_asn == new.remote_asn
        && old.description == new.description
        && old.peer_group == new.peer_group
        && old.hold_time == new.hold_time
        && old.max_prefixes == new.max_prefixes
        && old.md5_password == new.md5_password
        && old.ttl_security == new.ttl_security
        && old.families == new.families
        && old.graceful_restart == new.graceful_restart
        && old.gr_restart_time == new.gr_restart_time
        && old.gr_stale_routes_time == new.gr_stale_routes_time
        && old.llgr_stale_time == new.llgr_stale_time
        && old.local_ipv6_nexthop == new.local_ipv6_nexthop
        && old.route_reflector_client == new.route_reflector_client
        && old.route_server_client == new.route_server_client
        && old.role == new.role
        && old.strict_role == new.strict_role
        && old.prefix_orf_receive == new.prefix_orf_receive
        && old.disable_ipv4_unicast == new.disable_ipv4_unicast
        && old.remove_private_as == new.remove_private_as
        && old.add_path == new.add_path
        && old.log_level == new.log_level
        && old.import_policy == new.import_policy
        && old.export_policy == new.export_policy
        && old.import_policy_chain == new.import_policy_chain
        && old.export_policy_chain == new.export_policy_chain
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
    /// `[[fib_tables]]` blocks added/removed/modified between old and new.
    /// Reload-applied in the common case: the ADR-0061 general-FIB actor
    /// accepts a runtime table-set swap on SIGHUP
    /// (`FibRuntimeCommand::ReplaceTables`), so edits hot-apply when the
    /// reconciler is running. The one exception the static diff *can* know is
    /// the startup-from-empty case — see [`Self::fib_tables_requires_restart`].
    pub fib_tables_changed: bool,
    /// The `[[fib_tables]]` change is the startup-from-empty (0→N) case: old
    /// had no tables, new has at least one. The reconciler is spawned only
    /// when ≥1 table is present at startup, so SIGHUP rejects this as
    /// restart-required (`src/reload.rs` logs it; the runtime cannot hot-start
    /// the actor). The static diff cannot predict a netlink spawn *failure*,
    /// but it can know the empty-startup case, so it classifies 0→N as
    /// restart-required to match the runtime. All other edits (N→M, N→0) stay
    /// reload-applied.
    pub fib_tables_requires_restart: bool,
    /// `[[dynamic_neighbors]]` blocks added/removed/modified between old and
    /// new. Reload-applied by replacing the peer-manager config snapshot and
    /// rebuilding the live longest-prefix matcher.
    pub dynamic_neighbors_changed: bool,
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
    /// Static-neighbor TCP-AO startup keys changed. The active and
    /// passive sockets install MKTs only at peer/listener creation, so
    /// edits require a daemon restart until runtime listener key
    /// rotation exists.
    pub neighbor_tcp_ao_changed: bool,
    /// Effective BFD session set changed — `[[bfd_profiles]]` referenced by a
    /// live session, or a neighbor/peer-group `bfd` block. The ADR-0067 BFD
    /// actor resolves its session set once at startup, so edits are
    /// restart-required until actor reconfiguration is implemented and must
    /// remain visible in `--diff`.
    pub bfd_changed: bool,
    /// `[policy.explain]` (`enabled` / `cache_size`, ADR-0073) changed.
    /// These are read by `build_transport_config` / `resolve_neighbor`
    /// when a session is constructed, so they do not hot-apply to live
    /// sessions — surfaced as restart-required (the new value reaches a
    /// peer only on its next session establishment). Diagnostic
    /// retention only; never affects which routes are accepted.
    pub policy_explain_changed: bool,
    /// Shape-aware ADR-0063 / ADR-0085 classification for EVPN runtime
    /// table changes. The raw `evpn_*_changed` booleans above still say
    /// which TOML tables moved; this field says whether SIGHUP can route
    /// that specific shape through the EVPN runtime coordinator or must
    /// leave it restart-required.
    pub evpn_runtime_change_class: EvpnRuntimeChangeClass,
}

/// Static SIGHUP classification for EVPN runtime table edits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvpnRuntimeChangeClass {
    /// No `[[evpn_instances]]`, `[[evpn_ip_vrfs]]`, or
    /// `[[ethernet_segments]]` TOML changed.
    Unchanged,
    /// The edit is in an ADR-0063/0085 shape the runtime coordinator
    /// can hot-apply on SIGHUP, subject to the live actor being
    /// present and accepting the candidate.
    ReloadApplied,
    /// The edit is a generic/mixed/identity shape the current
    /// runtime coordinator rejects, or the diff could not resolve a
    /// typed EVPN model defensively. A restart is required.
    RestartRequired,
}

impl EvpnRuntimeChangeClass {
    const fn is_reload_applied(self) -> bool {
        matches!(self, Self::ReloadApplied)
    }

    const fn is_restart_required(self) -> bool {
        matches!(self, Self::RestartRequired)
    }
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveNeighborImpactKind {
    /// The resolved import/export policy chain moved and can be handled by the
    /// live-policy transaction executor.
    PolicyChain,
    /// Resolved transport/session state or peer-group membership moved. These
    /// impacts route to the session reshape executor: static members get a
    /// rollback-capable in-place reconfigure; live dynamic sessions get a
    /// post-persist graceful reset and re-accept under the committed config.
    SessionReshape,
}

impl EffectiveNeighborImpactKind {
    /// True when this impact is a pure resolved import/export `PolicyChain`
    /// move that can be applied without rebuilding the session.
    pub const fn is_policy_chain(self) -> bool {
        matches!(self, Self::PolicyChain)
    }

    /// Stable `snake_case` label (matches the serde rename) for human-readable
    /// rendering and the `--diff` JSON.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyChain => "policy_chain",
            Self::SessionReshape => "session_reshape",
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct EffectiveNeighborImpact {
    pub address: String,
    pub reasons: Vec<String>,
    /// Operator-visible impact kind. `policy_chain` commits through the
    /// live-policy executor; `session_reshape` commits through the session
    /// reshape executor (static members are reconfigured in place, live
    /// dynamic sessions are gracefully reset to re-accept under the committed
    /// config) unless mixed with `policy_chain` impacts.
    pub kind: EffectiveNeighborImpactKind,
    /// True when `address` identifies a `[[dynamic_neighbors]]` range rather
    /// than a static neighbor. Skipped from `--diff`; used to route the
    /// impact to the matching executor arm (dynamic ranges expand to live
    /// sessions inside the peer manager rather than resolving to a static
    /// neighbor record).
    #[serde(skip)]
    pub is_dynamic_range: bool,
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
            || self.dynamic_neighbors_changed
            || (self.fib_tables_changed && !self.fib_tables_requires_restart)
            || self.evpn_runtime_change_class.is_reload_applied()
    }

    /// Changes that require a full daemon restart.
    pub fn has_restart_required_changes(&self) -> bool {
        self.global_changed
            || self.rpki_changed
            || self.bmp_changed
            || self.mrt_changed
            || self.policy.import_changed
            || self.policy.export_changed
            || self.evpn_runtime_change_class.is_restart_required()
            || self.apply_bum_enforcement_changed
            || self.blackhole_fib_discard_changed
            || self.neighbor_tcp_ao_changed
            || self.bfd_changed
            || self.policy_explain_changed
            || self.fib_tables_requires_restart
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

/// Section-level v1 transaction support classification.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[expect(
    clippy::struct_field_names,
    reason = "field names mirror ConfigTransactionPlanResponse proto repeated fields"
)]
pub struct ConfigTransactionSectionClassification {
    /// Sections the v1 transaction model can commit atomically.
    pub supported_sections: Vec<String>,
    /// Hot-reloadable sections that are intentionally outside v1's commit
    /// executor set.
    pub unsupported_sections: Vec<String>,
    /// Sections that still require a daemon restart.
    pub restart_required_sections: Vec<String>,
}

impl ConfigTransactionSectionClassification {
    /// The candidate contains no differences.
    pub fn is_noop(&self) -> bool {
        self.supported_sections.is_empty()
            && self.unsupported_sections.is_empty()
            && self.restart_required_sections.is_empty()
    }

    /// The candidate is wholly inside v1's supported commit surface.
    pub fn is_committable(&self) -> bool {
        !self.supported_sections.is_empty()
            && self.unsupported_sections.is_empty()
            && self.restart_required_sections.is_empty()
    }
}

/// Per-process key for the optimistic config-transaction snapshot token.
///
/// The snapshot token is a change detector handed to `sensitive_read` plan
/// callers — not a credential or a config document. But hashing the canonical
/// config *unkeyed* would turn it into an offline oracle: the serialization
/// includes secret-bearing fields (`md5_password`, `tcp_ao.key`), so a caller
/// who already knows the rest of the config could brute-force a weak secret by
/// hashing guesses and matching the returned token. A per-process random key
/// closes that — without the key a caller cannot recompute the digest for a
/// guessed secret. The full config (secrets included) is still hashed, so a
/// secret rotation invalidates a stale plan.
///
/// The key is seeded once when the peer manager is constructed and never leaves
/// the process, so tokens are **process-local**: a token does not survive a
/// daemon restart, and a client holding a pre-restart token must re-plan (apply
/// returns `FAILED_PRECONDITION` on mismatch). Plan and apply both run in this
/// process against the same peer-manager key, so they compare correctly within
/// a daemon lifetime.
#[derive(Clone)]
pub struct RuntimeSnapshotKey(std::collections::hash_map::RandomState);

impl std::fmt::Debug for RuntimeSnapshotKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key material.
        f.write_str("RuntimeSnapshotKey(<redacted>)")
    }
}

impl RuntimeSnapshotKey {
    /// Seed a fresh per-process key from the OS RNG (via `RandomState`).
    #[must_use]
    pub fn random() -> Self {
        Self(std::collections::hash_map::RandomState::new())
    }

    /// Keyed change-detector token for `config`. Hashes the canonical TOML
    /// serialization under this key, so the token changes when any config byte
    /// relevant to a candidate changes (secrets included) but cannot be
    /// reproduced by a caller who does not hold the key.
    pub fn token(&self, config: &Config) -> Result<String, String> {
        use std::hash::{BuildHasher, Hasher};
        // Canonical because `toml::Value::Table` is `BTreeMap`-backed (keys
        // sorted) unless toml's `preserve_order` feature is enabled, which it is
        // not here. That makes the token independent of `HashMap` insertion
        // order for map-valued config (peer_groups, roles, policy definitions,
        // neighbor_sets). If `preserve_order` is ever turned on, this token
        // would silently become order-dependent — re-establish canonicalization
        // (e.g. sort) before doing so.
        let canonical = toml::Value::try_from(config)
            .map_err(|error| format!("failed to canonicalize runtime config snapshot: {error}"))?;
        let normalized = toml::to_string_pretty(&canonical)
            .map_err(|error| format!("failed to serialize runtime config snapshot: {error}"))?;
        let mut hasher = self.0.build_hasher();
        hasher.write(normalized.as_bytes());
        Ok(format!("kv1:{:016x}:{}", hasher.finish(), normalized.len()))
    }
}

/// Classify a validated config diff for the v1 config transaction model.
///
/// This deliberately does not mirror all SIGHUP reload-applied sections. The
/// transaction model needs an atomic executor for each section it claims; PR1
/// only exposes the validate-only planner and the safe surface that later PRs
/// will execute.
#[expect(
    clippy::too_many_lines,
    reason = "section classifier intentionally lists every diff bucket explicitly"
)]
pub fn classify_config_transaction_v1(diff: &ConfigDiff) -> ConfigTransactionSectionClassification {
    let mut class = ConfigTransactionSectionClassification::default();

    if !diff.neighbors.added.is_empty() {
        class
            .supported_sections
            .push(TRANSACTION_NEIGHBOR_ADD_SECTION.to_string());
    }
    if !diff.neighbors.removed.is_empty() {
        class
            .supported_sections
            .push(TRANSACTION_NEIGHBOR_DELETE_SECTION.to_string());
    }
    if !diff.neighbors.changed.is_empty() {
        class
            .supported_sections
            .push(TRANSACTION_NEIGHBOR_MODIFY_SECTION.to_string());
    }
    if diff.dynamic_neighbors_changed {
        class
            .supported_sections
            .push(TRANSACTION_DYNAMIC_SECTION.to_string());
    }
    if diff.fib_tables_changed && !diff.fib_tables_requires_restart {
        class
            .supported_sections
            .push(TRANSACTION_FIB_SECTION.to_string());
    }
    if !diff.policy.definitions_added.is_empty()
        || !diff.policy.definitions_removed.is_empty()
        || !diff.policy.definitions_changed.is_empty()
    {
        class
            .supported_sections
            .push(TRANSACTION_POLICY_DEFINITIONS_SECTION.to_string());
    }
    if !diff.policy.neighbor_sets_added.is_empty()
        || !diff.policy.neighbor_sets_removed.is_empty()
        || !diff.policy.neighbor_sets_changed.is_empty()
    {
        class
            .supported_sections
            .push(TRANSACTION_POLICY_NEIGHBOR_SETS_SECTION.to_string());
    }
    if diff.policy.import_chain_changed || diff.policy.export_chain_changed {
        class
            .supported_sections
            .push(TRANSACTION_POLICY_GLOBAL_CHAINS_SECTION.to_string());
    }
    if !diff.peer_groups.added.is_empty()
        || !diff.peer_groups.removed.is_empty()
        || !diff.peer_groups.changed.is_empty()
    {
        class
            .supported_sections
            .push(TRANSACTION_PEER_GROUP_CATALOG_SECTION.to_string());
    }
    if !diff.effective_neighbor_impact.is_empty() {
        // A live-impact transaction is committable only when every impacted
        // entry belongs to one executor family. Pure resolved-policy-chain
        // moves use the live-policy executor. Session reshapes use the peer
        // reconfigure executor: static members are reconfigured in place with
        // captured priors, and live dynamic sessions are gracefully reset
        // after persist so they re-accept under the committed config. Mixed
        // policy/session impacts remain rejected until they have a combined
        // rollback story.
        let all_policy_chain = diff
            .effective_neighbor_impact
            .iter()
            .all(|impact| impact.kind.is_policy_chain());
        if all_policy_chain {
            class
                .supported_sections
                .push(TRANSACTION_POLICY_LIVE_IMPACT_SECTION.to_string());
        } else if session_reshape_transaction(diff) {
            class
                .supported_sections
                .push(TRANSACTION_SESSION_RESHAPE_SECTION.to_string());
        } else if diff
            .effective_neighbor_impact
            .iter()
            .any(|impact| !impact.kind.is_policy_chain())
        {
            class
                .unsupported_sections
                .push("effective neighbor inheritance impact".to_string());
        }
    }
    if !transaction_sections_are_one_family(&class.supported_sections) {
        class
            .unsupported_sections
            .push("mixed transaction families".to_string());
    }
    if diff.honor_graceful_shutdown_changed {
        class
            .unsupported_sections
            .push("[global].honor_graceful_shutdown".to_string());
    }
    if diff.honor_blackhole_changed {
        class
            .unsupported_sections
            .push("[global].honor_blackhole".to_string());
    }
    if diff.evpn_runtime_change_class.is_reload_applied() {
        class
            .unsupported_sections
            .push("EVPN runtime coordinator".to_string());
    }

    if diff.global_changed {
        class.restart_required_sections.push("[global]".to_string());
    }
    if diff.rpki_changed {
        class.restart_required_sections.push("[rpki]".to_string());
    }
    if diff.bmp_changed {
        class.restart_required_sections.push("[bmp]".to_string());
    }
    if diff.mrt_changed {
        class.restart_required_sections.push("[mrt]".to_string());
    }
    if diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_instances_changed {
        class
            .restart_required_sections
            .push("[[evpn_instances]]".to_string());
    }
    if diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_ip_vrfs_changed {
        class
            .restart_required_sections
            .push("[[evpn_ip_vrfs]]".to_string());
    }
    if diff.evpn_runtime_change_class.is_restart_required() && diff.ethernet_segments_changed {
        class
            .restart_required_sections
            .push("[[ethernet_segments]]".to_string());
    }
    if diff.fib_tables_requires_restart {
        class
            .restart_required_sections
            .push("[[fib_tables]] startup-from-empty".to_string());
    }
    if diff.apply_bum_enforcement_changed {
        class
            .restart_required_sections
            .push("apply_bum_enforcement".to_string());
    }
    if diff.blackhole_fib_discard_changed {
        class
            .restart_required_sections
            .push("BLACKHOLE FIB discard".to_string());
    }
    if diff.neighbor_tcp_ao_changed {
        class
            .restart_required_sections
            .push("[[neighbors]].tcp_ao".to_string());
    }
    if diff.bfd_changed {
        class
            .restart_required_sections
            .push("[[bfd_profiles]] / neighbor BFD".to_string());
    }
    if diff.policy_explain_changed {
        class
            .restart_required_sections
            .push("[policy.explain]".to_string());
    }
    if diff.policy.import_changed {
        class
            .restart_required_sections
            .push("[policy.import] inline".to_string());
    }
    if diff.policy.export_changed {
        class
            .restart_required_sections
            .push("[policy.export] inline".to_string());
    }

    class
}

fn session_reshape_transaction(diff: &ConfigDiff) -> bool {
    if !diff.neighbors.added.is_empty() || !diff.neighbors.removed.is_empty() {
        return false;
    }
    // A `[[dynamic_neighbors]]` record edit (range add/remove, peer-group
    // reassignment) belongs to the dynamic-neighbor executor family, and a
    // reassigned range cannot be applied to sessions accepted under the old
    // group anyway — so any record-level dynamic change keeps the impact out
    // of the reshape family. With records unchanged, a dynamic-range
    // `SessionReshape` impact is a pure peer-group field reshape, which the
    // executor commits by gracefully resetting the affected live dynamic
    // sessions (they re-accept under the committed config on reconnect).
    if diff.dynamic_neighbors_changed {
        return false;
    }
    if !diff
        .effective_neighbor_impact
        .iter()
        .all(|impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape)
    {
        return false;
    }
    if diff.neighbors.changed.is_empty() {
        return true;
    }
    let impacted: HashSet<&str> = diff
        .effective_neighbor_impact
        .iter()
        .map(|impact| impact.address.as_str())
        .collect();
    diff.neighbors
        .changed
        .iter()
        .all(|neighbor| impacted.contains(neighbor.address.as_str()))
}

fn transaction_sections_are_one_family(sections: &[String]) -> bool {
    let mut has_fib = false;
    let mut has_dynamic = false;
    let mut has_static_neighbor = false;
    let mut has_catalog = false;
    for section in sections {
        match section.as_str() {
            TRANSACTION_FIB_SECTION => has_fib = true,
            TRANSACTION_DYNAMIC_SECTION => has_dynamic = true,
            TRANSACTION_NEIGHBOR_ADD_SECTION
            | TRANSACTION_NEIGHBOR_DELETE_SECTION
            | TRANSACTION_NEIGHBOR_MODIFY_SECTION => {
                has_static_neighbor = true;
            }
            TRANSACTION_PEER_GROUP_CATALOG_SECTION
            | TRANSACTION_POLICY_DEFINITIONS_SECTION
            | TRANSACTION_POLICY_NEIGHBOR_SETS_SECTION
            | TRANSACTION_POLICY_GLOBAL_CHAINS_SECTION
            // The live-impact section co-occurs with the catalog record sections
            // it stems from (a policy/peer-group/chain edit), so it counts as
            // the same family rather than tripping the mixed-family guard.
            | TRANSACTION_POLICY_LIVE_IMPACT_SECTION => {
                has_catalog = true;
            }
            _ => {
                // `TRANSACTION_SESSION_RESHAPE_SECTION` is a family-neutral
                // modifier: it can stem from catalog inheritance (peer-group
                // field edit) or from a direct static neighbor peer-group
                // reassignment, so the underlying changed section decides the
                // family. Unknown sections are ignored here and rejected later
                // by the apply-family dispatcher if they ever reach apply.
            }
        }
    }
    u8::from(has_fib)
        + u8::from(has_dynamic)
        + u8::from(has_static_neighbor)
        + u8::from(has_catalog)
        <= 1
}

/// JSON schema shared by `rustbgpd --diff --json` and the live runtime
/// config-diff API. The schema mirrors the human diff buckets:
/// reload-applied, restart-required, and informational.
pub fn config_diff_json_value(diff: &ConfigDiff) -> serde_json::Value {
    serde_json::json!({
        "has_actionable_changes": diff.has_actionable_changes(),
        "has_informational_changes": diff.has_informational_changes(),
        "has_any_changes": diff.has_any_changes(),
        "evpn_runtime_change_class": diff.evpn_runtime_change_class,
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
            "dynamic_neighbors_changed": diff.dynamic_neighbors_changed,
            "fib_tables_changed": diff.fib_tables_changed && !diff.fib_tables_requires_restart,
            "evpn_runtime_changed": diff.evpn_runtime_change_class.is_reload_applied(),
            "evpn_instances_changed": diff.evpn_runtime_change_class.is_reload_applied() && diff.evpn_instances_changed,
            "evpn_ip_vrfs_changed": diff.evpn_runtime_change_class.is_reload_applied() && diff.evpn_ip_vrfs_changed,
            "ethernet_segments_changed": diff.evpn_runtime_change_class.is_reload_applied() && diff.ethernet_segments_changed,
            "effective_neighbor_impact": &diff.effective_neighbor_impact,
        },
        "restart_required": {
            "global_changed": diff.global_changed,
            "rpki_changed": diff.rpki_changed,
            "bmp_changed": diff.bmp_changed,
            "mrt_changed": diff.mrt_changed,
            "evpn_instances_changed": diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_instances_changed,
            "evpn_ip_vrfs_changed": diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_ip_vrfs_changed,
            "ethernet_segments_changed": diff.evpn_runtime_change_class.is_restart_required() && diff.ethernet_segments_changed,
            "fib_tables_requires_restart": diff.fib_tables_requires_restart,
            "apply_bum_enforcement_changed": diff.apply_bum_enforcement_changed,
            "blackhole_fib_discard_changed": diff.blackhole_fib_discard_changed,
            "neighbor_tcp_ao_changed": diff.neighbor_tcp_ao_changed,
            "bfd_changed": diff.bfd_changed,
            "policy_explain_changed": diff.policy_explain_changed,
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
                let _ = writeln!(
                    out,
                    "    {} {} [{}]:",
                    style.change_marker,
                    impact.address,
                    impact.kind.as_str()
                );
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
        if diff.fib_tables_changed && !diff.fib_tables_requires_restart {
            let _ = writeln!(
                out,
                "  {} [[fib_tables]] hot-applied to the running FIB reconciler",
                style.change_marker
            );
        }
        if diff.dynamic_neighbors_changed {
            let _ = writeln!(
                out,
                "  {} [[dynamic_neighbors]] matcher rebuilt",
                style.change_marker
            );
        }
        if diff.evpn_runtime_change_class.is_reload_applied() {
            let _ = writeln!(
                out,
                "  {} EVPN runtime model hot-applied through the ADR-0063 coordinator",
                style.change_marker
            );
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
    if diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_instances_changed {
        restart_sections.push("[[evpn_instances]]");
    }
    if diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_ip_vrfs_changed {
        restart_sections.push("[[evpn_ip_vrfs]]");
    }
    if diff.evpn_runtime_change_class.is_restart_required() && diff.ethernet_segments_changed {
        restart_sections.push("[[ethernet_segments]]");
    }
    if diff.fib_tables_requires_restart {
        restart_sections.push("[[fib_tables]] (start FIB from an empty config)");
    }
    if diff.apply_bum_enforcement_changed {
        restart_sections.push("apply_bum_enforcement");
    }
    if diff.blackhole_fib_discard_changed {
        restart_sections.push("BLACKHOLE FIB discard");
    }
    if diff.neighbor_tcp_ao_changed {
        restart_sections.push("[[neighbors]].tcp_ao");
    }
    if diff.bfd_changed {
        restart_sections.push("[[bfd_profiles]] / [neighbors.bfd] / [peer_groups.*.bfd]");
    }
    if diff.policy_explain_changed {
        restart_sections.push("[policy.explain] (per-peer; applies on next session)");
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
    let neighbor_tcp_ao_changed = neighbor_tcp_ao_restart_required_changed(old, new);
    let bfd_changed = bfd_restart_required_changed(old, new);
    let mut reload_new = new.clone();
    pin_tcp_ao_startup_only_runtime(&mut reload_new, old);
    // Pin BFD too so the hot-reload neighbor/peer-group diff does not report
    // startup-only BFD edits as if they apply live; the restart-required
    // surface is carried by `bfd_changed` above.
    pin_bfd_startup_only_runtime(&mut reload_new, old);
    let neighbor_diff = diff_neighbors(&old.neighbors, &reload_new.neighbors);

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
            .map(ToString::to_string)
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

    let peer_groups = diff_peer_groups(&old.peer_groups, &reload_new.peer_groups);
    let peer_group_details = peer_groups
        .changed
        .iter()
        .filter_map(|name| {
            let old_pg = old.peer_groups.get(name)?;
            let new_pg = reload_new.peer_groups.get(name)?;
            let changes = describe_peer_group_changes(old_pg, new_pg);
            if changes.is_empty() {
                None
            } else {
                Some((name.clone(), changes))
            }
        })
        .collect();

    let policy = diff_policy(&old.policy, &reload_new.policy);
    let effective_neighbor_impact =
        compute_effective_neighbor_impact(old, &reload_new, &peer_groups, &policy);
    let blackhole_fib_discard_changed = old.global.install_blackhole_discard
        != new.global.install_blackhole_discard
        || old.global.allow_blackhole_broad_prefixes != new.global.allow_blackhole_broad_prefixes
        || ((old.global.install_blackhole_discard || new.global.install_blackhole_discard)
            && old.global.honor_blackhole != new.global.honor_blackhole);
    let evpn_runtime_change_class = classify_evpn_runtime_change(old, new);

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
        fib_tables_requires_restart: old.fib_tables.is_empty() && !new.fib_tables.is_empty(),
        dynamic_neighbors_changed: old.dynamic_neighbors != new.dynamic_neighbors,
        apply_bum_enforcement_changed: old.apply_bum_enforcement != new.apply_bum_enforcement,
        blackhole_fib_discard_changed,
        neighbor_tcp_ao_changed,
        bfd_changed,
        policy_explain_changed: old.policy.explain != new.policy.explain,
        evpn_runtime_change_class,
    }
}

fn evpn_runtime_config_changed(old: &Config, new: &Config) -> bool {
    old.evpn_instances != new.evpn_instances
        || old.evpn_ip_vrfs != new.evpn_ip_vrfs
        || old.ethernet_segments != new.ethernet_segments
}

fn classify_evpn_runtime_change(old: &Config, new: &Config) -> EvpnRuntimeChangeClass {
    if !evpn_runtime_config_changed(old, new) {
        return EvpnRuntimeChangeClass::Unchanged;
    }
    let Ok(current) = evpn_runtime_model_from_config(old) else {
        return EvpnRuntimeChangeClass::RestartRequired;
    };
    let Ok(candidate) = evpn_runtime_candidate_from_config(new) else {
        return EvpnRuntimeChangeClass::RestartRequired;
    };
    let plan = current.plan_candidate(&candidate);
    if evpn_runtime_plan_is_reload_applied(&current, &candidate, &plan) {
        EvpnRuntimeChangeClass::ReloadApplied
    } else {
        EvpnRuntimeChangeClass::RestartRequired
    }
}

fn evpn_runtime_model_from_config(config: &Config) -> Result<EvpnRuntimeModel, ConfigError> {
    let instances = config.resolve_evpn_instances()?;
    let ip_vrfs = config.resolve_evpn_ip_vrfs()?;
    let ethernet_segments = config.resolve_ethernet_segments()?;
    Ok(EvpnRuntimeModel::startup(
        instances,
        ip_vrfs,
        ethernet_segments,
    ))
}

fn evpn_runtime_candidate_from_config(
    config: &Config,
) -> Result<EvpnRuntimeCandidate, ConfigError> {
    Ok(EvpnRuntimeCandidate::new(
        config.resolve_evpn_instances()?,
        config.resolve_evpn_ip_vrfs()?,
        config.resolve_ethernet_segments()?,
    ))
}

fn evpn_runtime_plan_is_reload_applied(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if plan.is_noop() {
        // ADR-0085 binding-only edits change the TOML
        // `[[ethernet_segments]]` row but not the EVPN domain model.
        // SIGHUP still commits them so the binding watcher republishes.
        return true;
    }
    if evpn_runtime_is_tenant_teardown_plan(plan, current) {
        return evpn_runtime_validate_tenant_teardown_shape(current, candidate, plan);
    }
    if evpn_runtime_is_ip_vrf_relink_plan(plan) {
        return true;
    }
    if evpn_runtime_is_additive_build_up_plan(plan) {
        return evpn_runtime_validate_additive_build_up_shape(current, candidate, plan);
    }
    if evpn_runtime_is_l2vni_swap_plan(plan) {
        return evpn_runtime_validate_l2vni_swap_shape(current, candidate, plan);
    }
    if !evpn_runtime_no_unexpected_relink(current, candidate, plan) {
        return false;
    }

    if plan.evpn_instances.has_changes() {
        return evpn_runtime_l2vni_shape_is_reload_applied(current, candidate, plan);
    }
    if plan.ip_vrfs.has_changes() {
        return evpn_runtime_ip_vrf_shape_is_reload_applied(current, candidate, plan);
    }
    if plan.ethernet_segments.has_changes() {
        return evpn_runtime_es_shape_is_reload_applied(current, candidate, plan);
    }
    false
}

fn evpn_runtime_is_ip_vrf_relink_plan(plan: &EvpnRuntimePlan) -> bool {
    plan.ip_vrf_references_changed
        && !plan.evpn_instances.has_changes()
        && !plan.ip_vrfs.has_changes()
        && !plan.ethernet_segments.has_changes()
}

fn evpn_runtime_is_additive_build_up_plan(plan: &EvpnRuntimePlan) -> bool {
    let no_deletes_or_redefines = plan.evpn_instances.deleted.is_empty()
        && plan.evpn_instances.redefined.is_empty()
        && plan.ip_vrfs.deleted.is_empty()
        && plan.ip_vrfs.redefined.is_empty()
        && plan.ethernet_segments.deleted.is_empty()
        && plan.ethernet_segments.redefined.is_empty();
    let has_add = !plan.evpn_instances.added.is_empty()
        || !plan.ip_vrfs.added.is_empty()
        || !plan.ethernet_segments.added.is_empty();
    if !(no_deletes_or_redefines && has_add) {
        return false;
    }
    let resource_types_added = [
        !plan.evpn_instances.added.is_empty(),
        !plan.ip_vrfs.added.is_empty(),
        !plan.ethernet_segments.added.is_empty(),
    ]
    .into_iter()
    .filter(|changed| *changed)
    .count();
    resource_types_added > 1
        || plan.evpn_instances.added.len() > 1
        || plan.ip_vrfs.added.len() > 1
        || plan.ethernet_segments.added.len() > 1
}

fn evpn_runtime_validate_additive_build_up_shape(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if !evpn_runtime_no_unexpected_relink(current, candidate, plan) {
        return false;
    }
    plan.evpn_instances.added.iter().all(|&raw_vni| {
        EvpnInstanceId::new(raw_vni).is_ok_and(|vni| {
            current.instances().get(vni).is_none() && candidate.instances().get(vni).is_some()
        })
    }) && plan.ip_vrfs.added.iter().all(|name| {
        current.ip_vrfs().get(name).is_none() && candidate.ip_vrfs().get(name).is_some()
    }) && plan.ethernet_segments.added.iter().all(|esi| {
        current
            .ethernet_segments()
            .iter()
            .all(|segment| segment.esi != *esi)
            && candidate
                .ethernet_segments()
                .iter()
                .find(|segment| segment.esi == *esi)
                .is_some_and(|segment| {
                    !segment.member_vnis.is_empty()
                        && segment
                            .member_vnis
                            .iter()
                            .all(|&vni| candidate.instances().get(vni).is_some())
                })
    })
}

fn evpn_runtime_is_l2vni_swap_plan(plan: &EvpnRuntimePlan) -> bool {
    !plan.evpn_instances.added.is_empty()
        && !plan.evpn_instances.deleted.is_empty()
        && plan.evpn_instances.redefined.is_empty()
        && !plan.ip_vrfs.has_changes()
        && !plan.ethernet_segments.has_changes()
}

fn evpn_runtime_validate_l2vni_swap_shape(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if !evpn_runtime_no_unexpected_relink(current, candidate, plan) {
        return false;
    }
    plan.evpn_instances.added.iter().all(|&raw_vni| {
        EvpnInstanceId::new(raw_vni).is_ok_and(|vni| {
            current.instances().get(vni).is_none() && candidate.instances().get(vni).is_some()
        })
    }) && plan.evpn_instances.deleted.iter().all(|&raw_vni| {
        EvpnInstanceId::new(raw_vni).is_ok_and(|vni| {
            current.instances().get(vni).is_some()
                && candidate.instances().get(vni).is_none()
                && current
                    .ethernet_segments()
                    .iter()
                    .all(|segment| !segment.member_vnis.contains(&vni))
        })
    })
}

fn evpn_runtime_is_tenant_teardown_plan(
    plan: &EvpnRuntimePlan,
    current: &EvpnRuntimeModel,
) -> bool {
    let no_adds = plan.evpn_instances.added.is_empty()
        && plan.ip_vrfs.added.is_empty()
        && plan.ethernet_segments.added.is_empty();
    let no_l2_ipvrf_redefine =
        plan.evpn_instances.redefined.is_empty() && plan.ip_vrfs.redefined.is_empty();
    let has_deletion = !plan.evpn_instances.deleted.is_empty()
        || !plan.ip_vrfs.deleted.is_empty()
        || !plan.ethernet_segments.deleted.is_empty();
    if !(no_adds && no_l2_ipvrf_redefine && has_deletion) {
        return false;
    }
    let resource_types_changed = [
        plan.evpn_instances.has_changes(),
        plan.ip_vrfs.has_changes(),
        plan.ethernet_segments.has_changes(),
    ]
    .into_iter()
    .filter(|changed| *changed)
    .count();
    let multi_resource = resource_types_changed > 1;
    let multi_element = plan.evpn_instances.deleted.len() > 1
        || plan.ip_vrfs.deleted.len() > 1
        || plan.ethernet_segments.deleted.len() > 1;
    let es_member_l2vni_deleted = plan.evpn_instances.deleted.iter().any(|&raw| {
        EvpnInstanceId::new(raw).is_ok_and(|vni| {
            current
                .ethernet_segments()
                .iter()
                .any(|segment| segment.member_vnis.contains(&vni))
        })
    });
    let referenced_ip_vrf_deleted = plan
        .ip_vrfs
        .deleted
        .iter()
        .any(|name| current.ip_vrfs().is_referenced(name));

    multi_resource || multi_element || es_member_l2vni_deleted || referenced_ip_vrf_deleted
}

fn evpn_runtime_validate_tenant_teardown_shape(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if !plan.evpn_instances.added.is_empty()
        || !plan.ip_vrfs.added.is_empty()
        || !plan.ethernet_segments.added.is_empty()
        || !plan.evpn_instances.redefined.is_empty()
        || !plan.ip_vrfs.redefined.is_empty()
    {
        return false;
    }
    if plan.evpn_instances.deleted.is_empty()
        && plan.ip_vrfs.deleted.is_empty()
        && plan.ethernet_segments.deleted.is_empty()
    {
        return false;
    }

    let mut deleted_vnis = BTreeSet::new();
    for &raw_vni in &plan.evpn_instances.deleted {
        let Ok(vni) = EvpnInstanceId::new(raw_vni) else {
            return false;
        };
        if current.instances().get(vni).is_none() || candidate.instances().get(vni).is_some() {
            return false;
        }
        deleted_vnis.insert(vni);
    }

    for name in &plan.ip_vrfs.deleted {
        if current.ip_vrfs().get(name).is_none() || candidate.ip_vrfs().get(name).is_some() {
            return false;
        }
        let refs = current
            .ip_vrfs()
            .referenced_l2vnis(name)
            .cloned()
            .unwrap_or_default();
        if refs.iter().any(|vni| !deleted_vnis.contains(vni)) {
            return false;
        }
    }

    for esi in &plan.ethernet_segments.deleted {
        if !current
            .ethernet_segments()
            .iter()
            .any(|segment| segment.esi == *esi)
            || candidate
                .ethernet_segments()
                .iter()
                .any(|segment| segment.esi == *esi)
        {
            return false;
        }
    }

    for esi in &plan.ethernet_segments.redefined {
        let Some(cur) = current
            .ethernet_segments()
            .iter()
            .find(|segment| segment.esi == *esi)
        else {
            return false;
        };
        let Some(cand) = candidate
            .ethernet_segments()
            .iter()
            .find(|segment| segment.esi == *esi)
        else {
            return false;
        };
        let member_shrink_only = cand.member_vnis.len() < cur.member_vnis.len()
            && cand
                .member_vnis
                .iter()
                .all(|vni| cur.member_vnis.contains(vni))
            && {
                let mut probe = cur.clone();
                probe.member_vnis.clone_from(&cand.member_vnis);
                &probe == cand
            };
        if !member_shrink_only {
            return false;
        }
    }

    candidate.ethernet_segments().iter().all(|segment| {
        segment
            .member_vnis
            .iter()
            .all(|vni| !deleted_vnis.contains(vni))
    })
}

fn evpn_runtime_no_unexpected_relink(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if !plan.ip_vrf_references_changed {
        return true;
    }
    let touched: BTreeSet<EvpnInstanceId> = plan
        .evpn_instances
        .added
        .iter()
        .chain(plan.evpn_instances.deleted.iter())
        .filter_map(|raw| EvpnInstanceId::new(*raw).ok())
        .collect();
    let current_links = current.ip_vrfs().l2vni_link_map();
    let candidate_links = candidate.ip_vrfs().l2vni_link_map();
    let mut vnis: BTreeSet<EvpnInstanceId> = current_links.keys().copied().collect();
    vnis.extend(candidate_links.keys().copied());
    vnis.into_iter()
        .all(|vni| current_links.get(&vni) == candidate_links.get(&vni) || touched.contains(&vni))
}

fn evpn_runtime_l2vni_shape_is_reload_applied(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if plan.ip_vrfs.has_changes() || plan.ethernet_segments.has_changes() {
        return false;
    }
    if !plan.evpn_instances.added.is_empty() {
        return plan.evpn_instances.added.len() == 1
            && plan.evpn_instances.deleted.is_empty()
            && plan.evpn_instances.redefined.is_empty()
            && EvpnInstanceId::new(plan.evpn_instances.added[0]).is_ok_and(|vni| {
                current.instances().get(vni).is_none() && candidate.instances().get(vni).is_some()
            });
    }
    if !plan.evpn_instances.deleted.is_empty() {
        return plan.evpn_instances.deleted.len() == 1
            && plan.evpn_instances.redefined.is_empty()
            && EvpnInstanceId::new(plan.evpn_instances.deleted[0]).is_ok_and(|vni| {
                current.instances().get(vni).is_some()
                    && candidate.instances().get(vni).is_none()
                    && !current
                        .ethernet_segments()
                        .iter()
                        .any(|segment| segment.member_vnis.contains(&vni))
            });
    }
    plan.evpn_instances.redefined.len() == 1
        && plan.evpn_instances.added.is_empty()
        && plan.evpn_instances.deleted.is_empty()
        && EvpnInstanceId::new(plan.evpn_instances.redefined[0]).is_ok_and(|vni| {
            current.instances().get(vni).is_some()
                && candidate.instances().get(vni).is_some()
                && current.ip_vrfs() == candidate.ip_vrfs()
        })
}

fn evpn_runtime_ip_vrf_shape_is_reload_applied(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if plan.evpn_instances.has_changes() || plan.ethernet_segments.has_changes() {
        return false;
    }
    if !plan.ip_vrfs.added.is_empty() {
        return plan.ip_vrfs.added.len() == 1
            && plan.ip_vrfs.deleted.is_empty()
            && plan.ip_vrfs.redefined.is_empty()
            && current.ip_vrfs().get(&plan.ip_vrfs.added[0]).is_none()
            && candidate.ip_vrfs().get(&plan.ip_vrfs.added[0]).is_some();
    }
    if !plan.ip_vrfs.deleted.is_empty() {
        let name = &plan.ip_vrfs.deleted[0];
        return plan.ip_vrfs.deleted.len() == 1
            && plan.ip_vrfs.redefined.is_empty()
            && current.ip_vrfs().get(name).is_some()
            && candidate.ip_vrfs().get(name).is_none()
            && !current.ip_vrfs().is_referenced(name);
    }
    if plan.ip_vrfs.redefined.len() != 1
        || !plan.ip_vrfs.added.is_empty()
        || !plan.ip_vrfs.deleted.is_empty()
    {
        return false;
    }
    let name = &plan.ip_vrfs.redefined[0];
    let Some(old) = current.ip_vrfs().get(name) else {
        return false;
    };
    let Some(new) = candidate.ip_vrfs().get(name) else {
        return false;
    };
    let current_refs = current
        .ip_vrfs()
        .referenced_l2vnis(name)
        .cloned()
        .unwrap_or_default();
    let candidate_refs = candidate
        .ip_vrfs()
        .referenced_l2vnis(name)
        .cloned()
        .unwrap_or_default();
    old.id == new.id
        && old.vrf_device == new.vrf_device
        && old.l3vxlan_device == new.l3vxlan_device
        && old.table_id == new.table_id
        && current_refs == candidate_refs
        && current.ip_vrfs().is_referenced(name) == candidate.ip_vrfs().is_referenced(name)
}

fn evpn_runtime_es_shape_is_reload_applied(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if plan.evpn_instances.has_changes() || plan.ip_vrfs.has_changes() {
        return false;
    }
    if !plan.ethernet_segments.added.is_empty() {
        let esi = plan.ethernet_segments.added[0];
        return plan.ethernet_segments.added.len() == 1
            && plan.ethernet_segments.deleted.is_empty()
            && plan.ethernet_segments.redefined.is_empty()
            && current
                .ethernet_segments()
                .iter()
                .all(|segment| segment.esi != esi)
            && candidate
                .ethernet_segments()
                .iter()
                .find(|segment| segment.esi == esi)
                .is_some_and(|segment| {
                    !segment.member_vnis.is_empty()
                        && segment
                            .member_vnis
                            .iter()
                            .all(|&vni| candidate.instances().get(vni).is_some())
                });
    }
    if !plan.ethernet_segments.deleted.is_empty() {
        let esi = plan.ethernet_segments.deleted[0];
        return plan.ethernet_segments.deleted.len() == 1
            && plan.ethernet_segments.redefined.is_empty()
            && current
                .ethernet_segments()
                .iter()
                .any(|segment| segment.esi == esi)
            && candidate
                .ethernet_segments()
                .iter()
                .all(|segment| segment.esi != esi);
    }
    let Some(&esi) = plan.ethernet_segments.redefined.first() else {
        return false;
    };
    plan.ethernet_segments.redefined.len() == 1
        && plan.ethernet_segments.added.is_empty()
        && plan.ethernet_segments.deleted.is_empty()
        && current
            .ethernet_segments()
            .iter()
            .any(|segment| segment.esi == esi)
        && candidate
            .ethernet_segments()
            .iter()
            .find(|segment| segment.esi == esi)
            .is_some_and(|segment| {
                !segment.member_vnis.is_empty()
                    && segment
                        .member_vnis
                        .iter()
                        .all(|&vni| candidate.instances().get(vni).is_some())
            })
}

/// Effective BFD config for a neighbor: its own `bfd`, else its peer-group's.
fn neighbor_effective_bfd<'a>(neighbor: &'a Neighbor, config: &'a Config) -> Option<&'a BfdConfig> {
    let resolved = if neighbor.bfd.is_some() {
        neighbor.bfd.as_ref()
    } else {
        config
            .peer_groups
            .get(neighbor.peer_group.as_deref()?)?
            .bfd
            .as_ref()
    };
    // A disabled block (`enabled = false`) runs no session, so it is not part of
    // the effective set — this is how a neighbor overrides an inherited
    // peer-group block to turn BFD off.
    resolved.filter(|bfd| bfd.enabled)
}

/// The effective BFD session set: one tuple per neighbor whose own or inherited
/// `bfd` references a defined profile, resolved to the timers the actor would
/// run. Sorted so it is order-insensitive. This is exactly the actor's startup
/// input, so comparing it across configs detects restart-required BFD drift.
fn effective_bfd_sessions(config: &Config) -> Vec<(String, u32, u32, u32, bool)> {
    let mut out: Vec<(String, u32, u32, u32, bool)> = config
        .neighbors
        .iter()
        .filter_map(|n| {
            let bfd = neighbor_effective_bfd(n, config)?;
            let profile = config.bfd_profiles.iter().find(|p| p.name == bfd.profile)?;
            Some((
                n.address.clone(),
                profile.min_tx_interval,
                profile.min_rx_interval,
                profile.multiplier,
                bfd.strict,
            ))
        })
        .collect();
    out.sort();
    out
}

/// Whether the effective BFD session set differs — restart-required because the
/// ADR-0067 actor resolves its sessions once at startup.
fn bfd_restart_required_changed(old: &Config, new: &Config) -> bool {
    effective_bfd_sessions(old) != effective_bfd_sessions(new)
}

/// Resolved (effective) BFD per neighbor address — its own `bfd`, else its
/// peer-group's. Used to pin/compare the *effective* session set, which
/// peer-group inheritance makes irreducible to raw field comparison.
fn effective_bfd_by_addr(config: &Config) -> HashMap<String, Option<BfdConfig>> {
    config
        .neighbors
        .iter()
        .map(|n| {
            (
                n.address.clone(),
                neighbor_effective_bfd(n, config).cloned(),
            )
        })
        .collect()
}

/// Pin BFD startup-only runtime state to the live snapshot. When the effective
/// session set differs, restore `bfd_profiles` and every peer-group `bfd`
/// field, and — for each neighbor whose *effective* BFD attachment changed —
/// pin its `bfd` and `peer_group` membership back to the live values, so a
/// SIGHUP reload cannot advance the persisted snapshot past what the running
/// actor is using. Pinning membership (not just the raw `bfd` field) is
/// required because BFD can be inherited from a peer group: a reload that moves
/// a neighbor between peer groups, or in/out of a BFD-bearing one, changes the
/// effective session without touching `neighbor.bfd`. This mirrors the
/// whole-neighbor `tcp_ao` pin — a neighbor with a changed startup-only
/// attachment is restart-required this reload. Returns whether anything was
/// pinned.
///
/// Residual: a neighbor *added* in the same reload that *inherits* BFD has no
/// live session to preserve; its inline `bfd` is dropped, but inherited BFD
/// will only start on the next restart (surfaced by `bfd_changed`). A neighbor
/// *removed* while it had BFD likewise leaves a session running until restart.
pub(crate) fn pin_bfd_startup_only_runtime(new_config: &mut Config, current: &Config) -> bool {
    if !bfd_restart_required_changed(current, new_config) {
        return false;
    }
    // Snapshot effective BFD per address for both configs before mutating.
    let live_effective = effective_bfd_by_addr(current);
    let new_effective = effective_bfd_by_addr(new_config);

    new_config.bfd_profiles.clone_from(&current.bfd_profiles);
    for (name, group) in &mut new_config.peer_groups {
        group.bfd = current.peer_groups.get(name).and_then(|g| g.bfd.clone());
    }

    let current_by_addr: HashMap<&str, &Neighbor> = current
        .neighbors
        .iter()
        .map(|n| (n.address.as_str(), n))
        .collect();
    for neighbor in &mut new_config.neighbors {
        let addr = neighbor.address.as_str();
        if live_effective.get(addr) == new_effective.get(addr) {
            continue;
        }
        if let Some(live) = current_by_addr.get(addr) {
            neighbor.bfd.clone_from(&live.bfd);
            neighbor.peer_group.clone_from(&live.peer_group);
        } else {
            // Newly added neighbor — no live session exists. If it carries its
            // own inline bfd, dropping it removes the effective session. If it
            // has no inline bfd but would *inherit* an enabled block, materialize
            // a disabled inline override so the pinned runtime's effective set
            // matches the actor (no session) — the `BfdConfig.enabled` tri-state
            // makes this expressible without editing peer-group membership.
            let pinned_bfd = if neighbor.bfd.is_some() {
                None
            } else {
                match new_effective.get(addr) {
                    Some(Some(inherited)) => Some(BfdConfig {
                        profile: inherited.profile.clone(),
                        enabled: false,
                        strict: inherited.strict,
                    }),
                    _ => None,
                }
            };
            neighbor.bfd = pinned_bfd;
        }
    }
    true
}

fn neighbor_tcp_ao_restart_required_changed(old: &Config, new: &Config) -> bool {
    let old_by_addr: HashMap<&str, &Neighbor> = old
        .neighbors
        .iter()
        .map(|neighbor| (neighbor.address.as_str(), neighbor))
        .collect();
    let new_by_addr: HashMap<&str, &Neighbor> = new
        .neighbors
        .iter()
        .map(|neighbor| (neighbor.address.as_str(), neighbor))
        .collect();

    for new_neighbor in &new.neighbors {
        match old_by_addr.get(new_neighbor.address.as_str()) {
            Some(old_neighbor) if old_neighbor.tcp_ao != new_neighbor.tcp_ao => return true,
            None if new_neighbor.tcp_ao.is_some() => return true,
            _ => {}
        }
    }

    old.neighbors.iter().any(|old_neighbor| {
        old_neighbor.tcp_ao.is_some() && !new_by_addr.contains_key(old_neighbor.address.as_str())
    })
}

/// Pin TCP-AO runtime state to the live startup snapshot.
///
/// A reload that keeps a live TCP-AO neighbor but hot-applies its inherited
/// dependencies can synthesize an invalid runtime shape, for example old
/// TCP-AO plus newly-inherited TCP MD5, or an old route-reflector client under
/// a newly edited local ASN. When any TCP-AO neighbor is pinned, pin the
/// restart-required global fields and the peer-group/policy dependency graph
/// with it.
pub(crate) fn pin_tcp_ao_startup_only_runtime(new_config: &mut Config, current: &Config) -> usize {
    let result = pin_tcp_ao_startup_only_neighbors(&mut new_config.neighbors, &current.neighbors);
    if result.pinned > 0 {
        pin_tcp_ao_restart_required_globals(new_config, current);
        pin_tcp_ao_dependency_graph(
            new_config,
            current,
            result.pinned_current_neighbors.iter().map(String::as_str),
        );
    }
    result.pinned
}

fn pin_tcp_ao_restart_required_globals(new_config: &mut Config, current: &Config) {
    let honor_graceful_shutdown = new_config.global.honor_graceful_shutdown;
    let honor_blackhole = new_config.global.honor_blackhole;
    let install_blackhole_discard = new_config.global.install_blackhole_discard;
    let allow_blackhole_broad_prefixes = new_config.global.allow_blackhole_broad_prefixes;

    new_config.global.clone_from(&current.global);

    // These knobs have explicit reload paths or are pinned before TCP-AO
    // pinning when their startup-gated actor is live. Preserve the already
    // shaped value so TCP-AO dependency pinning does not hide unrelated
    // hot-apply intent.
    new_config.global.honor_graceful_shutdown = honor_graceful_shutdown;
    new_config.global.honor_blackhole = honor_blackhole;
    new_config.global.install_blackhole_discard = install_blackhole_discard;
    new_config.global.allow_blackhole_broad_prefixes = allow_blackhole_broad_prefixes;
}

struct TcpAoPinResult {
    pinned: usize,
    pinned_current_neighbors: Vec<String>,
}

fn pin_tcp_ao_startup_only_neighbors(
    new_neighbors: &mut Vec<Neighbor>,
    current_neighbors: &[Neighbor],
) -> TcpAoPinResult {
    let current_by_addr: HashMap<&str, &Neighbor> = current_neighbors
        .iter()
        .map(|neighbor| (neighbor.address.as_str(), neighbor))
        .collect();

    let mut pinned = 0usize;
    let mut pinned_current_neighbors = Vec::new();
    for neighbor in new_neighbors.iter_mut() {
        match current_by_addr.get(neighbor.address.as_str()) {
            Some(current_neighbor) if current_neighbor.tcp_ao != neighbor.tcp_ao => {
                *neighbor = (*current_neighbor).clone();
                pinned += 1;
                pinned_current_neighbors.push(current_neighbor.address.clone());
            }
            _ => {}
        }
    }

    let before_len = new_neighbors.len();
    new_neighbors.retain(|neighbor| {
        current_by_addr.contains_key(neighbor.address.as_str()) || neighbor.tcp_ao.is_none()
    });
    pinned += before_len - new_neighbors.len();

    let new_addrs: HashSet<String> = new_neighbors
        .iter()
        .map(|neighbor| neighbor.address.clone())
        .collect();
    for current_neighbor in current_neighbors {
        if current_neighbor.tcp_ao.is_some() && !new_addrs.contains(&current_neighbor.address) {
            new_neighbors.push(current_neighbor.clone());
            pinned += 1;
            pinned_current_neighbors.push(current_neighbor.address.clone());
        }
    }

    TcpAoPinResult {
        pinned,
        pinned_current_neighbors,
    }
}

fn pin_tcp_ao_dependency_graph<'a>(
    new_config: &mut Config,
    current: &Config,
    pinned_current_neighbors: impl Iterator<Item = &'a str>,
) {
    let current_by_addr: HashMap<&str, &Neighbor> = current
        .neighbors
        .iter()
        .map(|neighbor| (neighbor.address.as_str(), neighbor))
        .collect();

    let mut policy_names = HashSet::new();
    let mut neighbor_set_names = HashSet::new();
    let mut peer_group_names = HashSet::new();
    let mut pin_global_import_chain = false;
    let mut pin_global_export_chain = false;

    for address in pinned_current_neighbors {
        let Some(neighbor) = current_by_addr.get(address) else {
            continue;
        };
        let pinned_global = collect_tcp_ao_neighbor_dependency_refs(
            neighbor,
            current,
            &mut policy_names,
            &mut neighbor_set_names,
            &mut peer_group_names,
        );
        pin_global_import_chain |= pinned_global.import;
        pin_global_export_chain |= pinned_global.export;
    }

    if pin_global_import_chain {
        new_config
            .policy
            .import_chain
            .clone_from(&current.policy.import_chain);
    }
    if pin_global_export_chain {
        new_config
            .policy
            .export_chain
            .clone_from(&current.policy.export_chain);
    }

    let mut processed_peer_groups = HashSet::new();
    let mut processed_policies = HashSet::new();
    let mut processed_neighbor_sets = HashSet::new();
    loop {
        let mut progressed = false;

        for name in peer_group_names
            .difference(&processed_peer_groups)
            .cloned()
            .collect::<Vec<_>>()
        {
            processed_peer_groups.insert(name.clone());
            progressed = true;
            if let Some(group) = current.peer_groups.get(&name) {
                new_config.peer_groups.insert(name, group.clone());
                collect_policy_refs_from_peer_group(
                    group,
                    &mut policy_names,
                    &mut neighbor_set_names,
                );
            }
        }

        for name in policy_names
            .difference(&processed_policies)
            .cloned()
            .collect::<Vec<_>>()
        {
            processed_policies.insert(name.clone());
            progressed = true;
            if let Some(policy) = current.policy.definitions.get(&name) {
                collect_neighbor_set_refs_from_policy(policy, &mut neighbor_set_names);
                new_config.policy.definitions.insert(name, policy.clone());
            }
        }

        for name in neighbor_set_names
            .difference(&processed_neighbor_sets)
            .cloned()
            .collect::<Vec<_>>()
        {
            processed_neighbor_sets.insert(name.clone());
            progressed = true;
            if let Some(set) = current.policy.neighbor_sets.get(&name) {
                peer_group_names.extend(set.peer_groups.iter().cloned());
                new_config.policy.neighbor_sets.insert(name, set.clone());
            }
        }

        if !progressed {
            break;
        }
    }
}

struct PinnedGlobalPolicyChains {
    import: bool,
    export: bool,
}

fn collect_tcp_ao_neighbor_dependency_refs(
    neighbor: &Neighbor,
    current: &Config,
    policy_names: &mut HashSet<String>,
    neighbor_set_names: &mut HashSet<String>,
    peer_group_names: &mut HashSet<String>,
) -> PinnedGlobalPolicyChains {
    collect_policy_refs_from_neighbor(neighbor, policy_names, neighbor_set_names);

    let group = neighbor
        .peer_group
        .as_deref()
        .and_then(|group_name| current.peer_groups.get(group_name));

    if let Some(group_name) = neighbor.peer_group.as_deref() {
        peer_group_names.insert(group_name.to_string());
    }

    let import = neighbor.import_policy_chain.is_empty()
        && neighbor.import_policy.is_empty()
        && group.is_none_or(|group| {
            group.import_policy_chain.is_empty() && group.import_policy.is_empty()
        })
        && !current.policy.import_chain.is_empty();
    if import {
        policy_names.extend(current.policy.import_chain.iter().cloned());
    }

    let export = neighbor.export_policy_chain.is_empty()
        && neighbor.export_policy.is_empty()
        && group.is_none_or(|group| {
            group.export_policy_chain.is_empty() && group.export_policy.is_empty()
        })
        && !current.policy.export_chain.is_empty();
    if export {
        policy_names.extend(current.policy.export_chain.iter().cloned());
    }

    PinnedGlobalPolicyChains { import, export }
}

fn collect_policy_refs_from_neighbor(
    neighbor: &Neighbor,
    policy_names: &mut HashSet<String>,
    neighbor_set_names: &mut HashSet<String>,
) {
    policy_names.extend(neighbor.import_policy_chain.iter().cloned());
    policy_names.extend(neighbor.export_policy_chain.iter().cloned());
    collect_neighbor_set_refs_from_statements(&neighbor.import_policy, neighbor_set_names);
    collect_neighbor_set_refs_from_statements(&neighbor.export_policy, neighbor_set_names);
}

fn collect_policy_refs_from_peer_group(
    group: &PeerGroupConfig,
    policy_names: &mut HashSet<String>,
    neighbor_set_names: &mut HashSet<String>,
) {
    policy_names.extend(group.import_policy_chain.iter().cloned());
    policy_names.extend(group.export_policy_chain.iter().cloned());
    collect_neighbor_set_refs_from_statements(&group.import_policy, neighbor_set_names);
    collect_neighbor_set_refs_from_statements(&group.export_policy, neighbor_set_names);
}

fn collect_neighbor_set_refs_from_policy(
    policy: &NamedPolicyConfig,
    neighbor_set_names: &mut HashSet<String>,
) {
    collect_neighbor_set_refs_from_statements(&policy.statements, neighbor_set_names);
}

fn collect_neighbor_set_refs_from_statements(
    statements: &[PolicyStatementConfig],
    neighbor_set_names: &mut HashSet<String>,
) {
    neighbor_set_names.extend(
        statements
            .iter()
            .filter_map(|statement| statement.match_neighbor_set.clone()),
    );
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

/// Network address of a `[[dynamic_neighbors]]` prefix, used only to resolve a
/// representative neighbor for effective-policy comparison. The address selects
/// the address family but does not affect import/export chain resolution, so
/// the network address of the range is a faithful stand-in.
fn dynamic_range_representative_addr(prefix: &str) -> Option<IpAddr> {
    prefix.split_once('/')?.0.parse::<IpAddr>().ok()
}

/// Attribute a neighbor's moved resolved chain to the specific changed policy
/// definition / neighbor-set / global chain responsible, appending dedup'd
/// reason strings. Called only when the resolved import/export chain actually
/// moved, so a coarse neighbor-set/global-chain edit doesn't tag every neighbor.
fn attribute_chain_move_reasons(
    reasons: &mut Vec<String>,
    old_neighbor: &Neighbor,
    new_neighbor: &Neighbor,
    new_peer_group: Option<&str>,
    new: &Config,
    policy: &PolicyDiff,
) {
    let policy_changed: HashSet<&str> = policy
        .definitions_changed
        .iter()
        .map(String::as_str)
        .chain(policy.definitions_added.iter().map(String::as_str))
        .chain(policy.definitions_removed.iter().map(String::as_str))
        .collect();
    let mut chain_refs: Vec<&str> = Vec::new();
    chain_refs.extend(new_neighbor.import_policy_chain.iter().map(String::as_str));
    chain_refs.extend(new_neighbor.export_policy_chain.iter().map(String::as_str));
    chain_refs.extend(old_neighbor.import_policy_chain.iter().map(String::as_str));
    chain_refs.extend(old_neighbor.export_policy_chain.iter().map(String::as_str));
    if let Some(pg_name) = new_peer_group
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
    if policy.import_chain_changed || policy.export_chain_changed {
        let entry = "global import/export chain changed".to_string();
        if !reasons.contains(&entry) {
            reasons.push(entry);
        }
    }
    if !policy.neighbor_sets_added.is_empty()
        || !policy.neighbor_sets_removed.is_empty()
        || !policy.neighbor_sets_changed.is_empty()
    {
        let entry = "referenced neighbor_set changed".to_string();
        if !reasons.contains(&entry) {
            reasons.push(entry);
        }
    }
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
        // A non-policy resolved change (hold_time, families, md5, tcp_ao, role,
        // add_path, ...) lives in transport_config; a group reassignment changes
        // the neighbor's raw record. Either means the impact is not a pure
        // policy-chain move the live-impact executor can re-apply in place; it
        // must route through a session reconfigure instead.
        let transport_changed = old_resolved.transport_config != new_resolved.transport_config;
        let peer_group_reassigned = old_resolved.peer_group != new_resolved.peer_group;

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

        // Attribute moved chains to specific changed policies / sets / global
        // chain, but only when something *did* move at the resolved-chain level
        // — otherwise we'd surface every neighbor for any neighbor_set edit.
        if import_moved || export_moved {
            attribute_chain_move_reasons(
                &mut reasons,
                old_neighbor,
                new_neighbor,
                new_resolved.peer_group.as_deref(),
                new,
                policy,
            );
        }

        if !reasons.is_empty() {
            let kind =
                if (import_moved || export_moved) && !transport_changed && !peer_group_reassigned {
                    EffectiveNeighborImpactKind::PolicyChain
                } else {
                    EffectiveNeighborImpactKind::SessionReshape
                };
            out.push(EffectiveNeighborImpact {
                address: old_neighbor.address.clone(),
                reasons,
                kind,
                is_dynamic_range: false,
            });
        }
    }

    out.extend(dynamic_range_effective_impact(old, new, &pg_changed));

    out.sort_by(|a, b| a.address.cmp(&b.address));
    out
}

/// Surface `[[dynamic_neighbors]]` ranges whose resolved effective policy moves
/// between `old` and `new`.
///
/// An established session accepted into a range inherits its peer group's
/// resolved policy, and SIGHUP live-reconciles those dynamic peers on a policy /
/// peer-group / chain edit. A catalog-only transaction stages such an edit
/// without that live reconcile, so a range whose resolved import/export policy
/// moves is not actually "catalog-only" and must surface as effective impact.
///
/// Ranges are paired by prefix (the stable key); a prefix that was added or
/// removed is a `[[dynamic_neighbors]]` family edit handled by the
/// dynamic-neighbor executor, not here. For a range whose prefix is unchanged,
/// only a pure policy-chain move is `EffectiveNeighborImpactKind::PolicyChain`: a peer-group
/// reassignment or a transport/session change is reported as non-committable so
/// it routes to a reconfigure rather than a live policy refresh. (The executor
/// expands a range to its live peers by the peer's *accepted* peer group, so a
/// reassignment cannot be live-applied to already-established sessions.)
///
/// The prefix's network address is a faithful stand-in for resolution (it only
/// picks the address family, which does not affect policy chains).
fn dynamic_range_effective_impact(
    old: &Config,
    new: &Config,
    pg_changed: &HashSet<&str>,
) -> Vec<EffectiveNeighborImpact> {
    let new_ranges: HashMap<&str, &DynamicNeighborConfig> = new
        .dynamic_neighbors
        .iter()
        .map(|dn| (dn.prefix.as_str(), dn))
        .collect();
    let mut out = Vec::new();
    for old_range in &old.dynamic_neighbors {
        let Some(new_range) = new_ranges.get(old_range.prefix.as_str()) else {
            continue;
        };
        let Some(addr) = dynamic_range_representative_addr(&old_range.prefix) else {
            continue;
        };
        let Some(old_group) = old.peer_groups.get(&old_range.peer_group) else {
            continue;
        };
        let Some(new_group) = new.peer_groups.get(&new_range.peer_group) else {
            continue;
        };
        let Ok(old_resolved) = old.resolve_dynamic_neighbor(
            addr,
            old_range.remote_asn,
            old_range.description.as_deref().unwrap_or_default(),
            old_group,
            &old_range.peer_group,
        ) else {
            continue;
        };
        let Ok(new_resolved) = new.resolve_dynamic_neighbor(
            addr,
            new_range.remote_asn,
            new_range.description.as_deref().unwrap_or_default(),
            new_group,
            &new_range.peer_group,
        ) else {
            continue;
        };

        let import_moved = format!("{:?}", old_resolved.import_policy)
            != format!("{:?}", new_resolved.import_policy);
        let export_moved = format!("{:?}", old_resolved.export_policy)
            != format!("{:?}", new_resolved.export_policy);
        let peer_group_reassigned = old_range.peer_group != new_range.peer_group;
        // A non-policy resolved change (hold_time, families, md5, tcp_ao, role,
        // ...) lives in transport_config and cannot be live-applied by a policy
        // refresh; it needs a session reconfigure. Mirror the static-neighbor
        // classifier so a combined transport + policy edit is not mistaken for a
        // pure policy-chain move and silently committed without the reconfigure.
        let transport_changed = old_resolved.transport_config != new_resolved.transport_config;

        let mut reasons: Vec<String> = Vec::new();
        if import_moved {
            reasons.push("dynamic-range import policy resolved differently".to_string());
        }
        if export_moved {
            reasons.push("dynamic-range export policy resolved differently".to_string());
        }
        if peer_group_reassigned {
            reasons.push(format!(
                "dynamic-range peer_group resolved as {:?} (was {:?})",
                new_range.peer_group, old_range.peer_group
            ));
        }
        if transport_changed {
            reasons
                .push("dynamic-range transport/session settings resolved differently".to_string());
        }
        if pg_changed.contains(old_range.peer_group.as_str()) {
            reasons.push(format!("peer_group {:?} changed", old_range.peer_group));
        }
        if !reasons.is_empty() {
            let kind =
                if (import_moved || export_moved) && !transport_changed && !peer_group_reassigned {
                    EffectiveNeighborImpactKind::PolicyChain
                } else {
                    EffectiveNeighborImpactKind::SessionReshape
                };
            out.push(EffectiveNeighborImpact {
                address: old_range.prefix.clone(),
                reasons,
                kind,
                is_dynamic_range: true,
            });
        }
    }
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
    cmp_field!(role);
    cmp_field!(strict_role);
    cmp_field!(prefix_orf_receive);
    cmp_field!(disable_ipv4_unicast);
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

impl From<GrpcMaxTierConfig> for GrpcMaxTier {
    fn from(value: GrpcMaxTierConfig) -> Self {
        match value {
            GrpcMaxTierConfig::Read => Self::Read,
            GrpcMaxTierConfig::SensitiveRead => Self::SensitiveRead,
            GrpcMaxTierConfig::Mutating => Self::Mutating,
            GrpcMaxTierConfig::OperatorOnly => Self::OperatorOnly,
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
fn parse_evpn_instance(
    cfg: &EvpnInstanceConfig,
    local_asn: u32,
) -> Result<EvpnInstance, ConfigError> {
    let id = EvpnInstanceId::new(cfg.vni).map_err(|e| ConfigError::InvalidEvpnInstance {
        reason: format!("vni {}: {e}", cfg.vni),
    })?;

    let rd =
        cfg.rd
            .parse::<RouteDistinguisher>()
            .map_err(|e| ConfigError::InvalidEvpnInstance {
                reason: format!("vni {}: invalid rd {:?}: {e}", cfg.vni, cfg.rd),
            })?;

    let mut rts: Vec<RouteTarget> =
        Vec::with_capacity(cfg.route_targets.len() + usize::from(cfg.auto_derive_route_target));
    for raw in &cfg.route_targets {
        let rt = raw
            .parse::<RouteTarget>()
            .map_err(|e| ConfigError::InvalidEvpnInstance {
                reason: format!("vni {}: invalid route_target {:?}: {e}", cfg.vni, raw),
            })?;
        rts.push(rt);
    }
    if cfg.auto_derive_route_target {
        // L2VNI / MAC-VRF: RFC 8365 §5.1.2.1 opaque VXLAN RT.
        let rt = RouteTarget::auto_derived_vxlan_l2_rfc8365(local_asn, cfg.vni).map_err(|e| {
            ConfigError::InvalidEvpnInstance {
                reason: format!(
                    "vni {}: cannot auto_derive_route_target: {e}; disable auto_derive_route_target or configure route_targets manually",
                    cfg.vni
                ),
            }
        })?;
        rts.push(rt);
    }
    if rts.is_empty() {
        return Err(ConfigError::InvalidEvpnInstance {
            reason: format!("vni {}: route_targets must not be empty", cfg.vni),
        });
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

/// Default ADR-0085 decision 3 recovery hold-off: how long a bound
/// ES's link drain is held after carrier returns. Mirrors the RFC
/// 8584 §3 DF-wait rationale (don't attract traffic before the
/// segment re-converges); FRR ships the same concept as its EVPN-MH
/// startup/recovery delay.
pub const DEFAULT_ES_RECOVERY_DELAY_SECS: u64 = 30;

/// Upper bound for `recovery_delay_secs` (one hour). Beyond this an
/// operator wants a manual ADR-0084 drain, not a timer.
pub const MAX_ES_RECOVERY_DELAY_SECS: u64 = 3600;

/// Resolved ADR-0085 attachment-circuit binding for one Ethernet
/// Segment: the link whose carrier drives the ES's `Link` drain
/// reason, plus the decision-3 recovery hold-off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsLinkBinding {
    /// Kernel link name (the operator contract — resolution is by
    /// name on every transition; ifindex can be reused).
    pub interface: String,
    /// Hold-off between carrier return and link-drain release.
    pub recovery_delay: std::time::Duration,
}

/// Parse one [`EthernetSegmentConfig`] entry into the runtime
/// [`EthernetSegment`] domain type. Validates the ESI text form,
/// rejects Type 0 (single-homed sentinel), confirms every member
/// VNI exists in the resolved EVPN instance set, and validates the
/// ADR-0085 `interface` / `recovery_delay_secs` binding fields.
#[expect(
    clippy::too_many_lines,
    reason = "linear ESI/member-VNI/DF-algorithm/preference/redundancy-mode/binding validation reads clearest as one sequence"
)]
fn parse_ethernet_segment(
    cfg: &EthernetSegmentConfig,
    known_vnis: &BTreeSet<EvpnInstanceId>,
) -> Result<EthernetSegment, ConfigError> {
    // IFNAMSIZ-1 — the longest interface name the kernel can hold.
    const IFNAMSIZ_MAX: usize = 15;
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

    let df_algorithm = match cfg.df_algorithm.as_str() {
        "default-modulo" => DfAlgorithm::DefaultModulo,
        "highest-random-weight" => DfAlgorithm::HighestRandomWeight,
        "highest-preference" => DfAlgorithm::HighestPreference,
        "lowest-preference" => DfAlgorithm::LowestPreference,
        "preference-based" => {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: "df_algorithm \"preference-based\": ambiguous RFC 9785 alias; use \
                         \"highest-preference\" or \"lowest-preference\""
                    .to_string(),
            });
        }
        other => {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "df_algorithm {other:?}: must be \"default-modulo\", \
                     \"highest-random-weight\", \"highest-preference\", or \
                     \"lowest-preference\""
                ),
            });
        }
    };
    let default_preference = 32_768;
    if !matches!(
        df_algorithm,
        DfAlgorithm::HighestPreference | DfAlgorithm::LowestPreference
    ) && cfg.df_preference != default_preference
    {
        return Err(ConfigError::InvalidEthernetSegment {
            reason: format!(
                "df_preference {}: only RFC 9785 highest-/lowest-preference DF election \
                 uses preference; default-modulo and highest-random-weight require \
                 the default {default_preference}",
                cfg.df_preference
            ),
        });
    }
    if cfg.df_preference > u32::from(u16::MAX) {
        return Err(ConfigError::InvalidEthernetSegment {
            reason: format!(
                "df_preference {}: must be in the RFC 9785 range 0..=65535",
                cfg.df_preference
            ),
        });
    }
    if cfg.df_dont_preempt
        && !matches!(
            df_algorithm,
            DfAlgorithm::HighestPreference | DfAlgorithm::LowestPreference
        )
    {
        return Err(ConfigError::InvalidEthernetSegment {
            reason: "df_dont_preempt: RFC 9785 Don't-Preempt only applies to the \
                     highest-/lowest-preference DF algorithms; remove it or set \
                     df_algorithm to a preference algorithm"
                .to_string(),
        });
    }

    let redundancy_mode = match cfg.redundancy_mode.as_str() {
        "all-active" => RedundancyMode::AllActive,
        "single-active" => RedundancyMode::SingleActive,
        other => {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "redundancy_mode {other:?}: must be \"all-active\" or \"single-active\""
                ),
            });
        }
    };

    let originator_ip =
        cfg.originator_ip
            .parse::<IpAddr>()
            .map_err(|e| ConfigError::InvalidEthernetSegment {
                reason: format!("originator_ip {:?}: {e}", cfg.originator_ip),
            })?;

    // ADR-0085 decision 1: the attachment-circuit binding. Validated
    // here so EVERY config path (startup, SIGHUP, runtime apply)
    // rejects a malformed binding; the resolved daemon-side map is
    // built separately by `Config::resolve_es_link_bindings` so the
    // domain type the segment actor diffs stays binding-free.
    if let Some(interface) = cfg.interface.as_deref() {
        if interface.is_empty() {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!("esi {:?}: interface must not be empty", cfg.esi),
            });
        }
        // IFNAMSIZ-1: a longer name can never exist in the kernel, so
        // the binding would silently fail closed into a permanent
        // drain — reject the typo at config load instead.
        if interface.len() > IFNAMSIZ_MAX {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "esi {:?}: interface {interface:?} exceeds the Linux IFNAMSIZ limit \
                     of {IFNAMSIZ_MAX} characters; no kernel link can ever match it",
                    cfg.esi
                ),
            });
        }
    }
    if let Some(delay) = cfg.recovery_delay_secs {
        if cfg.interface.is_none() {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "esi {:?}: recovery_delay_secs is only meaningful with an \
                     `interface` binding (ADR-0085); remove it or bind the \
                     attachment-circuit link",
                    cfg.esi
                ),
            });
        }
        if delay > MAX_ES_RECOVERY_DELAY_SECS {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "esi {:?}: recovery_delay_secs {delay} outside the supported \
                     range 0..={MAX_ES_RECOVERY_DELAY_SECS}",
                    cfg.esi
                ),
            });
        }
    }

    Ok(EthernetSegment {
        esi,
        member_vnis,
        df_preference: cfg.df_preference,
        df_algorithm,
        df_dont_preempt: cfg.df_dont_preempt,
        redundancy_mode,
        originator_ip,
    })
}

/// Parse one [`EvpnIpVrfConfig`] entry into the runtime [`IpVrf`]
/// domain type. Validates the VNI range, RD / RT / Router MAC /
/// device-name shape, and table id; uniqueness across
/// `[[evpn_ip_vrfs]]` and L3↔L2 VNI overlap are checked at the
/// table-build level in `resolve_evpn_ip_vrfs`.
fn parse_evpn_ip_vrf(cfg: &EvpnIpVrfConfig, local_asn: u32) -> Result<IpVrf, ConfigError> {
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

    let mut rts: Vec<RouteTarget> =
        Vec::with_capacity(cfg.route_targets.len() + usize::from(cfg.auto_derive_route_target));
    for raw in &cfg.route_targets {
        let rt = raw
            .parse::<RouteTarget>()
            .map_err(|e| ConfigError::InvalidEvpnIpVrf {
                reason: format!("name {:?}: invalid route_target {:?}: {e}", cfg.name, raw),
            })?;
        rts.push(rt);
    }
    if cfg.auto_derive_route_target {
        // L3VNI / IP-VRF: plain AS:VNI to match FRR's default tenant-VRF
        // auto-RT (the RFC 8365 opaque form is MAC-VRF-only and FRR does
        // not use it for L3VNIs, so it would not import cross-vendor).
        let rt = RouteTarget::auto_derived_ip_vrf_as_vni(local_asn, cfg.vni).map_err(|e| {
            ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "name {:?}: cannot auto_derive_route_target: {e}; disable auto_derive_route_target or configure route_targets manually",
                    cfg.name
                ),
            }
        })?;
        rts.push(rt);
    }
    if rts.is_empty() {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!("name {:?}: route_targets must not be empty", cfg.name),
        });
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

    let (overlay_index_mode, esi_overlay_index) = parse_evpn_ip_vrf_overlay_index(cfg)?;
    let vrf = IpVrf::new(
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
    })?;

    if let Some(index) = esi_overlay_index {
        Ok(vrf.with_esi_overlay_index(index.esi, index.mac, index.l2vni))
    } else {
        Ok(vrf.with_overlay_index_mode(overlay_index_mode))
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedEsiOverlayIndex {
    esi: EthernetSegmentIdentifier,
    mac: MacAddress,
    l2vni: Option<EvpnInstanceId>,
}

fn parse_evpn_ip_vrf_overlay_index(
    cfg: &EvpnIpVrfConfig,
) -> Result<(OverlayIndexMode, Option<ParsedEsiOverlayIndex>), ConfigError> {
    let mode = match cfg.overlay_index_mode {
        OverlayIndexModeConfig::InterfaceLess => OverlayIndexMode::InterfaceLess,
        OverlayIndexModeConfig::GatewayIp => OverlayIndexMode::GatewayIp,
        OverlayIndexModeConfig::Esi => OverlayIndexMode::Esi,
    };
    let l2vni = cfg
        .overlay_index_l2vni
        .map(EvpnInstanceId::new)
        .transpose()
        .map_err(|e| ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "name {:?}: invalid overlay_index_l2vni {:?}: {e}",
                cfg.name, cfg.overlay_index_l2vni
            ),
        })?;
    let esi = cfg
        .overlay_index_esi
        .as_deref()
        .map(parse_esi)
        .transpose()
        .map_err(|e| ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "name {:?}: invalid overlay_index_esi {:?}: {e}",
                cfg.name, cfg.overlay_index_esi
            ),
        })?;
    let mac = cfg
        .overlay_index_mac
        .as_deref()
        .map(parse_mac_address)
        .transpose()
        .map_err(|e| ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "name {:?}: invalid overlay_index_mac {:?}: {e}",
                cfg.name, cfg.overlay_index_mac
            ),
        })?;

    if mode != OverlayIndexMode::Esi {
        if esi.is_some() || mac.is_some() || l2vni.is_some() {
            return Err(ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "evpn_ip_vrfs[{}]: overlay_index_esi, overlay_index_mac, and \
                     overlay_index_l2vni are only valid when overlay_index_mode = \"esi\"",
                    cfg.name
                ),
            });
        }
        return Ok((mode, None));
    }

    let Some(esi) = esi else {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" requires overlay_index_esi",
                cfg.name
            ),
        });
    };
    if esi == EthernetSegmentIdentifier::ZERO {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_esi must be non-zero for ESI overlay-index Type 5",
                cfg.name
            ),
        });
    }
    let Some(mac) = mac else {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" requires overlay_index_mac",
                cfg.name
            ),
        });
    };
    if !is_unicast_nonzero_mac(mac) {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mac must be a unicast non-zero MAC",
                cfg.name
            ),
        });
    }
    Ok((mode, Some(ParsedEsiOverlayIndex { esi, mac, l2vni })))
}

fn validate_esi_overlay_index_vrf(
    vrf: &IpVrf,
    table: &IpVrfTable,
    es_members_by_esi: &BTreeMap<EthernetSegmentIdentifier, BTreeSet<EvpnInstanceId>>,
) -> Result<(), ConfigError> {
    let esi = vrf
        .overlay_index_esi
        .ok_or_else(|| ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" requires overlay_index_esi",
                vrf.name
            ),
        })?;
    let Some(segment_members) = es_members_by_esi.get(&esi) else {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_esi {:02x?} does not match any configured \
                 [[ethernet_segments]].esi",
                vrf.name,
                esi.octets()
            ),
        });
    };
    let linked =
        table
            .referenced_l2vnis(&vrf.name)
            .ok_or_else(|| ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" requires at least one \
                 [[evpn_instances]] with ip_vrf = {:?}",
                    vrf.name, vrf.name
                ),
            })?;
    if linked.is_empty() {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" requires at least one \
                 [[evpn_instances]] with ip_vrf = {:?}",
                vrf.name, vrf.name
            ),
        });
    }
    let selected = if let Some(vni) = vrf.overlay_index_l2vni {
        if !linked.contains(&vni) {
            return Err(ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "evpn_ip_vrfs[{}]: overlay_index_l2vni {} is not linked to this IP-VRF",
                    vrf.name,
                    vni.as_u32()
                ),
            });
        }
        vni
    } else if linked.len() == 1 {
        *linked.iter().next().expect("len checked")
    } else {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" with multiple linked L2VNIs \
                 requires overlay_index_l2vni",
                vrf.name
            ),
        });
    };
    if !segment_members.contains(&selected) {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_l2vni {} is not a member of overlay_index_esi {:02x?}",
                vrf.name,
                selected.as_u32(),
                esi.octets()
            ),
        });
    }
    Ok(())
}

fn is_unicast_nonzero_mac(mac: MacAddress) -> bool {
    let octets = mac.octets();
    octets != [0; 6] && (octets[0] & 1) == 0
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
