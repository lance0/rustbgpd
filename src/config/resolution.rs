//! Neighbor, effective-policy, and inherited per-peer configuration resolution.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::sets::SetStore;
use rustbgpd_policy::{
    CommunityMatch, NamedPolicy, Policy, PolicyAction, PolicyChain, PolicyStatement,
    RouteModifications,
};
use rustbgpd_transport::{
    RemovePrivateAs, TcpAoAlgorithm, TcpAoConfig as TransportTcpAoConfig, TcpAoKeyring,
    TransportConfig,
};
use rustbgpd_wire::{Afi, Safi};

use super::parse::{
    ChainDirection, parse_families, parse_policy, resolve_chain, resolve_chain_with_store,
};
use super::schema::{
    BGP_PORT, DEFAULT_CONNECT_RETRY_SECS, DEFAULT_DYNAMIC_NEIGHBOR_LIMIT, DEFAULT_HOLD_TIME,
};
use super::{
    AddPathConfig, BgpRoleConfig, Config, ConfigError, Neighbor, NextHopOwnershipConfig,
    PeerGroupConfig, RFC8212_MISSING_EXPORT_POLICY, RFC8212_MISSING_IMPORT_POLICY,
};

/// Bound canonical policy-set key retention while still sharing common sets
/// across the dominant contiguous roster shape.
const RESOLVED_NEIGHBOR_SET_STORE_CHUNK_SIZE: usize = 32;

impl Config {
    fn interface_index(interface: &str) -> Result<u32, String> {
        nix::net::if_::if_nametoindex(interface)
            .map_err(|err| format!("interface {interface:?} does not exist or is invalid: {err}"))
    }

    /// Resolve the effective cluster ID.
    ///
    /// Returns `Some` if explicitly configured, or if any neighbor is an RR client
    /// (defaults to `router_id`). Returns `None` when not acting as a route reflector.
    pub fn cluster_id(&self) -> Option<Ipv4Addr> {
        if let Some(ref cid) = self.global.cluster_id {
            return Some(cid.parse().expect("validated in Config::load"));
        }
        let static_rr = self.neighbors.iter().any(|n| {
            n.route_reflector_client.unwrap_or_else(|| {
                n.peer_group
                    .as_deref()
                    .and_then(|name| self.peer_groups.get(name))
                    .and_then(|group| group.route_reflector_client)
                    .unwrap_or(false)
            })
        });
        let dynamic_rr = self.dynamic_neighbors.iter().any(|range| {
            range.remote_asn == self.global.asn
                && self
                    .peer_groups
                    .get(&range.peer_group)
                    .and_then(|group| group.route_reflector_client)
                    .unwrap_or(false)
        });
        if static_rr || dynamic_rr {
            let router_id: Ipv4Addr = self
                .global
                .router_id
                .parse()
                .expect("validated in Config::load");
            return Some(router_id);
        }
        None
    }

    /// Resolve the process-wide cap for accepted dynamic neighbors.
    #[must_use]
    pub(crate) fn effective_dynamic_neighbor_limit(&self) -> u32 {
        self.global
            .dynamic_neighbor_limit
            .unwrap_or(DEFAULT_DYNAMIC_NEIGHBOR_LIMIT)
    }

    /// ADR-0112 RFC 8212 external classification for a configured remote ASN.
    ///
    /// `0` is the accept-any dynamic sentinel, not AS 0 and never an iBGP
    /// match, so it always classifies external. This is deliberately separate
    /// from the RFC 8326 / RFC 7999 implicit-tail `is_ebgp` gate, which keeps
    /// its plain `remote_asn != global.asn` comparison.
    #[must_use]
    pub fn rfc8212_external_asn(&self, remote_asn: u32) -> bool {
        remote_asn == 0 || remote_asn != self.global.asn
    }

    /// Every eBGP neighbor that resolves no explicit operator policy in at
    /// least one direction, with the direction(s) named.
    ///
    /// Both outcomes are reportable, and which one applies is
    /// `[global] ebgp_requires_policy`: off, the direction is permit-all and
    /// the session accepts and re-advertises everything; on, the direction
    /// runs the RFC 8212 reserved deny and carries nothing. Neither is an
    /// error — a permit-all route server is a legitimate configuration and a
    /// fail-closed one is the documented effect of the knob — but a config
    /// gate that says nothing about either lets both ship unnoticed.
    ///
    /// Neighbors whose chains fail to resolve are skipped: validation already
    /// rejects those, so this is only reachable on an already-valid config.
    #[must_use]
    pub fn unpoliced_ebgp_neighbors(&self) -> Vec<UnpolicedEbgpNeighbor> {
        self.neighbors
            .iter()
            .filter_map(|neighbor| {
                let resolved = self.effective_policy_for_neighbor(neighbor, false).ok()?;
                (resolved.external && !(resolved.import_explicit && resolved.export_explicit)).then(
                    || UnpolicedEbgpNeighbor {
                        address: neighbor.address.clone(),
                        remote_asn: neighbor.remote_asn,
                        import_missing: !resolved.import_explicit,
                        export_missing: !resolved.export_explicit,
                    },
                )
            })
            .collect()
    }

    pub(crate) fn unpoliced_ebgp_boundaries(&self) -> Vec<UnpolicedEbgpBoundary> {
        let static_neighbors =
            self.unpoliced_ebgp_neighbors()
                .into_iter()
                .map(|neighbor| UnpolicedEbgpBoundary {
                    import_missing: neighbor.import_missing,
                    export_missing: neighbor.export_missing,
                    subject: UnpolicedEbgpSubject::StaticNeighbor(neighbor),
                });
        let dynamic_ranges = self.dynamic_neighbors.iter().filter_map(|range| {
            let addr = super::dynamic_range_representative_addr(&range.prefix)?;
            let neighbor = Self::synthetic_dynamic_neighbor(
                addr,
                range.remote_asn,
                range.description.as_deref().unwrap_or(&range.peer_group),
                &range.peer_group,
            );
            let resolved = self.effective_policy_for_neighbor(&neighbor, false).ok()?;
            (resolved.external && !(resolved.import_explicit && resolved.export_explicit)).then(
                || UnpolicedEbgpBoundary {
                    subject: UnpolicedEbgpSubject::DynamicRange {
                        prefix: range.prefix.clone(),
                        peer_group: range.peer_group.clone(),
                        remote_asn: std::num::NonZeroU32::new(range.remote_asn),
                    },
                    import_missing: !resolved.import_explicit,
                    export_missing: !resolved.export_explicit,
                },
            )
        });
        static_neighbors.chain(dynamic_ranges).collect()
    }

    /// Resolve the global import policy chain (named policies referenced
    /// by `[policy] import_chain`). `None` when no chain is configured.
    #[allow(
        dead_code,
        reason = "direct global-chain probe used by config/reload tests; retained to keep per-chain resolution lifetimes explicit"
    )]
    pub fn import_chain(&self) -> Result<Option<PolicyChain>, ConfigError> {
        if self.policy.import_chain.is_empty() {
            return Ok(None);
        }
        resolve_chain(
            &self.policy.import_chain,
            &self.policy.definitions,
            &self.policy.rpol,
            &self.policy.dataset_bindings,
            &self.policy.neighbor_sets,
            &self.peer_groups,
            ChainDirection::Import,
            self.global.asn,
        )
    }

    fn import_chain_with_store(
        &self,
        store: &mut SetStore,
    ) -> Result<Option<PolicyChain>, ConfigError> {
        if self.policy.import_chain.is_empty() {
            return Ok(None);
        }
        resolve_chain_with_store(
            &self.policy.import_chain,
            &self.policy.definitions,
            &self.policy.rpol,
            &self.policy.dataset_bindings,
            &self.policy.neighbor_sets,
            &self.peer_groups,
            ChainDirection::Import,
            self.global.asn,
            store,
        )
    }

    /// Resolve the global export policy chain.
    pub fn export_chain(&self) -> Result<Option<PolicyChain>, ConfigError> {
        if self.policy.export_chain.is_empty() {
            return Ok(None);
        }
        resolve_chain(
            &self.policy.export_chain,
            &self.policy.definitions,
            &self.policy.rpol,
            &self.policy.dataset_bindings,
            &self.policy.neighbor_sets,
            &self.peer_groups,
            ChainDirection::Export,
            self.global.asn,
        )
    }

    fn export_chain_with_store(
        &self,
        store: &mut SetStore,
    ) -> Result<Option<PolicyChain>, ConfigError> {
        if self.policy.export_chain.is_empty() {
            return Ok(None);
        }
        resolve_chain_with_store(
            &self.policy.export_chain,
            &self.policy.definitions,
            &self.policy.rpol,
            &self.policy.dataset_bindings,
            &self.policy.neighbor_sets,
            &self.peer_groups,
            ChainDirection::Export,
            self.global.asn,
            store,
        )
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
    /// remove it, and adds `NO_ADVERTISE` so the request stays local. RFC 1997
    /// egress enforcement runs before export policy, so a policy cannot make
    /// the scoped route exportable by removing `NO_ADVERTISE`. Kernel discard
    /// route installation is a separate `install_blackhole_discard` opt-in.
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

    /// Resolve the effective import/export policy chains for one neighbor,
    /// discarding the ADR-0112 provenance metadata.
    ///
    /// Test-only: every production resolution site either needs the RFC 8212
    /// verdict or resolves a peer whose external classification is pinned
    /// rather than derived from the record's `remote_asn`, so they all call
    /// [`Self::effective_policy_for_neighbor`] directly.
    ///
    /// # Errors
    /// Propagates any [`ConfigError`] from
    /// [`Self::effective_policy_for_neighbor`].
    #[cfg(test)]
    pub fn effective_policy_chains_for_neighbor(
        &self,
        neighbor: &Neighbor,
    ) -> Result<(Option<PolicyChain>, Option<PolicyChain>), ConfigError> {
        let resolved = self.effective_policy_for_neighbor(neighbor, false)?;
        Ok((resolved.import, resolved.export))
    }

    /// Resolve the effective import/export policy chains for one neighbor,
    /// together with the ADR-0112 directional explicit-policy provenance.
    ///
    /// Per-neighbor named chain overrides per-neighbor inline policy, which
    /// overrides the corresponding peer-group source, which overrides the
    /// corresponding global named chain.
    ///
    /// When `[global] honor_graceful_shutdown = true` and/or
    /// `[global] honor_blackhole = true` AND the neighbor is EBGP, the
    /// resolved import chain is appended with the corresponding implicit
    /// receiver rule. iBGP is intentionally exempt — these are EBGP-edge
    /// receiver behaviors, and re-applying them per iBGP hop would overwrite
    /// values or scoping set legitimately upstream at the EBGP edge.
    ///
    /// `external_pinned` forces the RFC 8212 external classification on. It
    /// exists for one case: a child accepted by an accept-any (`remote_asn =
    /// 0`) dynamic range. The peer manager replaces that sentinel with the ASN
    /// learned from OPEN, so a later re-resolution would otherwise be able to
    /// reclassify a live session as iBGP and drop its enforcement. The flag
    /// deliberately does **not** feed the RFC 8326 / RFC 7999 implicit-tail
    /// gate, which keeps reading the record's `remote_asn`.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when the neighbor references an undefined peer
    /// group, or when any referenced policy/chain fails to resolve or parse.
    pub fn effective_policy_for_neighbor(
        &self,
        neighbor: &Neighbor,
        external_pinned: bool,
    ) -> Result<EffectivePolicyChains, ConfigError> {
        let mut store = SetStore::new();
        self.effective_policy_for_neighbor_with_store(neighbor, external_pinned, &mut store)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one linear inheritance resolution (global, group, neighbor, implicit tails); splitting would hide the precedence order"
    )]
    fn effective_policy_for_neighbor_with_store(
        &self,
        neighbor: &Neighbor,
        external_pinned: bool,
        store: &mut SetStore,
    ) -> Result<EffectivePolicyChains, ConfigError> {
        let group = self.peer_group_for_neighbor(neighbor)?;
        let global_import = self.import_chain_with_store(store)?;
        let global_export = self.export_chain_with_store(store)?;
        let group_import = if let Some(group) = group {
            if group.import_policy_chain.is_empty() {
                let policy = parse_policy(
                    &group.import_policy,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?;

                policy.map(|p| PolicyChain::new(vec![p]))
            } else {
                resolve_chain_with_store(
                    &group.import_policy_chain,
                    &self.policy.definitions,
                    &self.policy.rpol,
                    &self.policy.dataset_bindings,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                    ChainDirection::Import,
                    self.global.asn,
                    store,
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
                resolve_chain_with_store(
                    &group.export_policy_chain,
                    &self.policy.definitions,
                    &self.policy.rpol,
                    &self.policy.dataset_bindings,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                    ChainDirection::Export,
                    self.global.asn,
                    store,
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
            resolve_chain_with_store(
                &neighbor.import_policy_chain,
                &self.policy.definitions,
                &self.policy.rpol,
                &self.policy.dataset_bindings,
                &self.policy.neighbor_sets,
                &self.peer_groups,
                ChainDirection::Import,
                self.global.asn,
                store,
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
            resolve_chain_with_store(
                &neighbor.export_policy_chain,
                &self.policy.definitions,
                &self.policy.rpol,
                &self.policy.dataset_bindings,
                &self.policy.neighbor_sets,
                &self.peer_groups,
                ChainDirection::Export,
                self.global.asn,
                store,
            )?
        }
        .or_else(|| global_export.clone());

        // ADR-0112 explicit-policy provenance, decided HERE — before the
        // implicit tails below can manufacture a chain. Every source that
        // counts as operator provenance (neighbor named, neighbor inline,
        // group named, group inline, global named) is the only thing that can
        // have produced a `Some` at this point: `parse_policy` returns `None`
        // for an empty inline policy and `resolve_chain` returns `None` for an
        // empty name list, so an empty field that fell through to the next
        // level never counts. A permit-all chain still counts — RFC 8212 wants
        // a deliberate policy, not a particular filtering strategy.
        let import_explicit = import.is_some();
        let export_explicit = export.is_some();

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

        // ADR-0112 RFC 8212 external classification. `remote_asn = 0` is the
        // accept-any dynamic sentinel, never AS 0 and never a real iBGP match,
        // so it is always external; `external_pinned` keeps a session that was
        // accepted through such a range external after OPEN overwrote the
        // sentinel with a learned ASN.
        let external = external_pinned || self.rfc8212_external_asn(neighbor.remote_asn);
        let enforced = self.global.ebgp_requires_policy && external;
        // Substituting the whole direction (rather than prepending) keeps the
        // reserved deny unambiguous: nothing an operator can name or configure
        // is left in a denied direction, and the implicit GSHUT/BLACKHOLE
        // import tails cannot make a missing import policy look satisfied.
        let import = if enforced && !import_explicit {
            Some(reserved_rfc8212_deny_chain(RFC8212_MISSING_IMPORT_POLICY))
        } else {
            import
        };
        let export = if enforced && !export_explicit {
            Some(reserved_rfc8212_deny_chain(RFC8212_MISSING_EXPORT_POLICY))
        } else {
            export
        };

        Ok(EffectivePolicyChains {
            import,
            export,
            import_explicit,
            export_explicit,
            external,
        })
    }

    pub(super) fn resolved_families(
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

    fn resolved_required_families(
        neighbor: &Neighbor,
        group: Option<&PeerGroupConfig>,
    ) -> Result<Vec<(Afi, Safi)>, ConfigError> {
        if !neighbor.required_families.is_empty() {
            return parse_families(&neighbor.required_families);
        }
        group
            .filter(|group| !group.required_families.is_empty())
            .map_or_else(
                || Ok(Vec::new()),
                |group| parse_families(&group.required_families),
            )
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

    pub(crate) fn resolve_neighbor(
        &self,
        neighbor: &Neighbor,
    ) -> Result<ResolvedNeighbor, ConfigError> {
        self.resolve_neighbor_pinned(neighbor, false)
    }

    /// [`Self::resolve_neighbor`] with the ADR-0112 external classification
    /// pinned on — see [`Self::effective_policy_for_neighbor`] for when that
    /// is required.
    pub(crate) fn resolve_neighbor_pinned(
        &self,
        neighbor: &Neighbor,
        external_pinned: bool,
    ) -> Result<ResolvedNeighbor, ConfigError> {
        let mut store = SetStore::new();
        self.resolve_neighbor_pinned_with_store(neighbor, external_pinned, &mut store)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "neighbor resolution centralizes inheritance, validation, and transport projection"
    )]
    fn resolve_neighbor_pinned_with_store(
        &self,
        neighbor: &Neighbor,
        external_pinned: bool,
        store: &mut SetStore,
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

        let mut peer = PeerConfig::new(self.global.asn, neighbor.remote_asn, router_id);
        peer.hold_time = neighbor
            .hold_time
            .or_else(|| group.and_then(|g| g.hold_time))
            .unwrap_or(DEFAULT_HOLD_TIME);
        peer.min_hold_time = neighbor
            .min_hold_time
            .or_else(|| group.and_then(|g| g.min_hold_time));
        // RFC 9687 §6 default: greater of 8 minutes or 2× hold time.
        peer.send_hold_time = neighbor
            .send_hold_time
            .or_else(|| group.and_then(|g| g.send_hold_time))
            .unwrap_or_else(|| rustbgpd_fsm::default_send_hold_time(peer.hold_time));
        peer.connect_retry_secs = DEFAULT_CONNECT_RETRY_SECS;
        peer.families = families;
        peer.required_families = Self::resolved_required_families(neighbor, group)?;
        peer.graceful_restart = neighbor
            .graceful_restart
            .or_else(|| group.and_then(|g| g.graceful_restart))
            .unwrap_or(true);
        peer.gr_restart_time = neighbor
            .gr_restart_time
            .or_else(|| group.and_then(|g| g.gr_restart_time))
            .unwrap_or(120);
        peer.llgr_stale_time = neighbor
            .llgr_stale_time
            .or_else(|| group.and_then(|g| g.llgr_stale_time))
            .unwrap_or(0);
        peer.add_path_receive = add_path.as_ref().is_some_and(|c| c.receive);
        peer.add_path_send = add_path.as_ref().is_some_and(|c| c.send);
        peer.add_path_send_max = add_path.as_ref().and_then(|c| c.send_max).unwrap_or(0);
        peer.paths_limit_receive_max = add_path.as_ref().and_then(|c| c.receive_max).unwrap_or(0);
        peer.local_role = Self::resolved_role(neighbor, group);
        peer.strict_role = neighbor
            .strict_role
            .or_else(|| group.and_then(|g| g.strict_role))
            .unwrap_or(false);
        peer.prefix_orf_receive = neighbor
            .prefix_orf_receive
            .or_else(|| group.and_then(|g| g.prefix_orf_receive))
            .unwrap_or(false);
        peer.disable_ipv4_unicast = neighbor
            .disable_ipv4_unicast
            .or_else(|| group.and_then(|g| g.disable_ipv4_unicast))
            .unwrap_or(false);

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
        transport.max_prefixes_ipv4 = neighbor
            .max_prefixes_ipv4
            .or_else(|| group.and_then(|g| g.max_prefixes_ipv4));
        transport.max_prefixes_ipv6 = neighbor
            .max_prefixes_ipv6
            .or_else(|| group.and_then(|g| g.max_prefixes_ipv6));
        transport.peer_group.clone_from(&neighbor.peer_group);
        transport.md5_password = neighbor
            .md5_password
            .clone()
            .or_else(|| group.and_then(|g| g.md5_password.clone()))
            .map(Into::into);
        transport.tcp_ao = neighbor.tcp_ao.as_ref().map(|tcp_ao| {
            TcpAoKeyring(
                tcp_ao
                    .iter()
                    .map(|key| TransportTcpAoConfig {
                        key: key.key.clone().into(),
                        send_id: key.send_id,
                        recv_id: key.recv_id,
                        algorithm: TcpAoAlgorithm::from_linux_name(&key.algorithm)
                            .expect("validated in Config::load"),
                        preferred: key.preferred,
                        deprecated: key.deprecated,
                    })
                    .collect(),
            )
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
        transport.gr_peer_restart_time_max = neighbor
            .gr_peer_restart_time_max
            .or_else(|| group.and_then(|g| g.gr_peer_restart_time_max))
            .unwrap_or(4095);
        transport.llgr_stale_time = neighbor
            .llgr_stale_time
            .or_else(|| group.and_then(|g| g.llgr_stale_time))
            .unwrap_or(0);
        transport.route_server_client = neighbor
            .route_server_client
            .or_else(|| group.and_then(|g| g.route_server_client))
            .unwrap_or(false);
        transport.per_client_best = neighbor
            .per_client_best
            .or_else(|| group.and_then(|g| g.per_client_best))
            .unwrap_or(false);
        // ADR-0107: strict-peer NEXT_HOP ownership for route-server
        // clients; the single shipped mode resolves to a bool here.
        transport.next_hop_ownership_strict_peer = matches!(
            neighbor
                .next_hop_ownership
                .or_else(|| group.and_then(|g| g.next_hop_ownership)),
            Some(NextHopOwnershipConfig::StrictPeer)
        );
        transport.slow_peer_threshold_pct = neighbor
            .slow_peer_threshold_pct
            .or_else(|| group.and_then(|g| g.slow_peer_threshold_pct))
            .unwrap_or(rustbgpd_transport::DEFAULT_SLOW_PEER_THRESHOLD_PCT);
        transport.slow_peer_duration = neighbor
            .slow_peer_duration
            .or_else(|| group.and_then(|g| g.slow_peer_duration))
            .unwrap_or(rustbgpd_transport::DEFAULT_SLOW_PEER_DURATION_SECS);
        transport.slow_peer_isolation = neighbor
            .slow_peer_isolation
            .or_else(|| group.and_then(|g| g.slow_peer_isolation))
            .unwrap_or(false);
        // RFC 1997 egress enforcement defaults to on, except for
        // route-server clients (transparent pass-through unless the
        // operator opts in explicitly).
        transport.interpret_rfc1997 = neighbor
            .interpret_rfc1997
            .or_else(|| group.and_then(|g| g.interpret_rfc1997))
            .unwrap_or(!transport.route_server_client);
        // RFC 7947 §2.3.2 control communities default on for
        // route-server clients (the standard IXP posture) and off for
        // everyone else; set explicitly to override either default.
        // Safe to default on since the route-granular emit-time filter
        // (ADR-0101 Decision 3): enabled sessions stay in shared
        // update-groups, and only routes actually carrying a
        // control-form community pay per-target divergence at emit.
        transport.rs_control_communities = neighbor
            .rs_control_communities
            .or_else(|| group.and_then(|g| g.rs_control_communities))
            .unwrap_or(transport.route_server_client);
        transport.route_reflector_client = neighbor
            .route_reflector_client
            .or_else(|| group.and_then(|g| g.route_reflector_client))
            .unwrap_or(false);
        transport.orr_vantage = neighbor
            .orr_vantage
            .or_else(|| group.and_then(|g| g.orr_vantage));
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
        // LAN-472: same threading hazard for the rejected-route
        // retention knobs — both construction paths must see them.
        transport.reject_retention_enabled = self.policy.reject_retention.enabled;
        transport.reject_retention_capacity = self.policy.reject_retention.capacity;

        let policy =
            self.effective_policy_for_neighbor_with_store(neighbor, external_pinned, store)?;

        Ok(ResolvedNeighbor {
            transport_config: transport,
            max_prefix_restart_seconds: neighbor
                .max_prefix_restart_seconds
                .or_else(|| group.and_then(|group| group.max_prefix_restart_seconds))
                .map(std::num::NonZeroU32::get),
            label: neighbor
                .description
                .clone()
                .unwrap_or_else(|| neighbor.address.clone()),
            import_policy: policy.import,
            export_policy: policy.export,
            peer_group: neighbor.peer_group.clone(),
            rfc8212_external: policy.external,
        })
    }

    /// Resolve a dynamic neighbor config from a peer group.
    /// Builds a synthetic `Neighbor` inheriting all settings from the group.
    ///
    /// `remote_asn` is the accepting range's configured value at accept time —
    /// including the `0` accept-any sentinel, which classifies the child as
    /// external per ADR-0112. A caller that instead passes the ASN learned from
    /// OPEN must set `external_pinned` from the session's pinned
    /// classification, or a wildcard-accepted child could be re-resolved as
    /// iBGP mid-session.
    fn synthetic_dynamic_neighbor(
        addr: IpAddr,
        remote_asn: u32,
        description: &str,
        peer_group_name: &str,
    ) -> Neighbor {
        Neighbor {
            min_hold_time: None,
            address: addr.to_string(),
            interface: None,
            remote_asn,
            description: Some(description.to_string()),
            peer_group: Some(peer_group_name.to_string()),
            hold_time: None,
            send_hold_time: None,
            slow_peer_threshold_pct: None,
            slow_peer_duration: None,
            slow_peer_isolation: None,
            max_prefixes: None,
            max_prefixes_ipv4: None,
            max_prefixes_ipv6: None,
            max_prefixes_out_ipv4: None,
            max_prefixes_out_ipv6: None,
            max_prefix_restart_seconds: None,
            md5_password: None,
            tcp_ao: None,
            bfd: None,
            ttl_security: None,
            families: Vec::new(),
            required_families: Vec::new(),
            graceful_restart: None,
            gr_restart_time: None,
            gr_peer_restart_time_max: None,
            gr_stale_routes_time: None,
            llgr_stale_time: None,
            local_ipv6_nexthop: None,
            route_reflector_client: None,
            orr_vantage: None,
            route_server_client: None,
            per_client_best: None,
            next_hop_ownership: None,
            interpret_rfc1997: None,
            rs_control_communities: None,
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
        }
    }

    pub(crate) fn resolve_dynamic_neighbor(
        &self,
        addr: IpAddr,
        remote_asn: u32,
        description: &str,
        _group: &PeerGroupConfig,
        peer_group_name: &str,
        external_pinned: bool,
    ) -> Result<ResolvedNeighbor, ConfigError> {
        // Build a synthetic Neighbor that references the peer group.
        // All fields come from the group via the normal resolution path.
        let neighbor =
            Self::synthetic_dynamic_neighbor(addr, remote_asn, description, peer_group_name);
        self.resolve_neighbor_pinned(&neighbor, external_pinned)
    }

    pub fn resolved_neighbors(&self) -> Result<Vec<ResolvedNeighbor>, ConfigError> {
        let mut resolved = Vec::with_capacity(self.neighbors.len());
        for chunk in self
            .neighbors
            .chunks(RESOLVED_NEIGHBOR_SET_STORE_CHUNK_SIZE)
        {
            let mut store = SetStore::new();
            for neighbor in chunk {
                resolved
                    .push(self.resolve_neighbor_pinned_with_store(neighbor, false, &mut store)?);
            }
        }
        Ok(resolved)
    }

    /// Returns `(TransportConfig, label, import_chain, export_chain)` per neighbor.
    ///
    /// Per-neighbor policy overrides global; if neighbor has no policy entries,
    /// the corresponding value is `None` (caller falls back to global).
    #[expect(
        clippy::type_complexity,
        reason = "the return preserves peer configuration and validation diagnostics together"
    )]
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
    /// Returns directives like `[peer{peer_addr=10.0.0.1}]=debug` that can
    /// be appended to an `EnvFilter`. The span directive MUST be wrapped in
    /// square brackets — `peer{...}=level` (no brackets) is rejected by the
    /// `EnvFilter` directive parser (`error parsing level filter`), which
    /// would make `init_logging` fail and abort daemon boot the moment any
    /// neighbor set a `log_level`.
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
                    "[peer{{peer_addr={addr}}}]={level}",
                    addr = neighbor.address
                ));
            }
        }
        directives
    }

    /// Resolver tables for the ADR-0113 outbound unicast prefix maxima.
    ///
    /// The RIB manager owns the inheritance walk so an accepted dynamic
    /// child — which has no `[[neighbors]]` row — resolves the same
    /// effective values as a static member of the same group. These tables
    /// carry the configuration as written; absence at both levels is
    /// unlimited.
    #[must_use]
    pub fn outbound_prefix_limits(&self) -> rustbgpd_rib::OutboundPrefixLimitConfig {
        use rustbgpd_rib::{OutboundPrefixLimitConfig, OutboundPrefixLimitPair};

        let pair = |ipv4, ipv6| OutboundPrefixLimitPair { ipv4, ipv6 };
        OutboundPrefixLimitConfig {
            neighbors: self
                .neighbors
                .iter()
                .filter(|neighbor| {
                    neighbor.max_prefixes_out_ipv4.is_some()
                        || neighbor.max_prefixes_out_ipv6.is_some()
                })
                .filter_map(|neighbor| {
                    Some((
                        neighbor.address.parse().ok()?,
                        pair(
                            neighbor.max_prefixes_out_ipv4,
                            neighbor.max_prefixes_out_ipv6,
                        ),
                    ))
                })
                .collect(),
            groups: self
                .peer_groups
                .iter()
                .filter(|(_, group)| {
                    group.max_prefixes_out_ipv4.is_some() || group.max_prefixes_out_ipv6.is_some()
                })
                .map(|(name, group)| {
                    (
                        name.clone(),
                        pair(group.max_prefixes_out_ipv4, group.max_prefixes_out_ipv6),
                    )
                })
                .collect(),
        }
    }
}

/// Whether reverting from `candidate` to `rollback` would have to LOWER an
/// outbound prefix maximum (ADR-0113).
///
/// A commit-confirmed transaction may tighten a maximum at or above current
/// usage, because its automatic undo only ever loosens. It must reject a
/// raise or removal, whose undo could become an invalid lowering once the
/// new capacity has admitted routes; an operator makes that change through
/// an ordinary committed transaction instead.
#[must_use]
pub fn outbound_prefix_limits_loosen(rollback: &Config, candidate: &Config) -> bool {
    fn looser(from: Option<std::num::NonZeroU32>, to: Option<std::num::NonZeroU32>) -> bool {
        match (from, to) {
            (Some(_), None) => true,
            (Some(from), Some(to)) => to > from,
            (None, _) => false,
        }
    }
    fn effective(
        config: &Config,
        neighbor: &Neighbor,
    ) -> (Option<std::num::NonZeroU32>, Option<std::num::NonZeroU32>) {
        let group = neighbor
            .peer_group
            .as_deref()
            .and_then(|name| config.peer_groups.get(name));
        (
            neighbor
                .max_prefixes_out_ipv4
                .or_else(|| group.and_then(|group| group.max_prefixes_out_ipv4)),
            neighbor
                .max_prefixes_out_ipv6
                .or_else(|| group.and_then(|group| group.max_prefixes_out_ipv6)),
        )
    }

    // Dynamic children have no `[[neighbors]]` row, so group defaults are
    // compared directly as well as through each static member.
    let groups_loosen = candidate.peer_groups.iter().any(|(name, group)| {
        let prior = rollback.peer_groups.get(name);
        looser(
            prior.and_then(|prior| prior.max_prefixes_out_ipv4),
            group.max_prefixes_out_ipv4,
        ) || looser(
            prior.and_then(|prior| prior.max_prefixes_out_ipv6),
            group.max_prefixes_out_ipv6,
        )
    });
    groups_loosen
        || candidate.neighbors.iter().any(|neighbor| {
            let Some(prior) = rollback
                .neighbors
                .iter()
                .find(|prior| prior.address == neighbor.address)
            else {
                return false;
            };
            let (prior_v4, prior_v6) = effective(rollback, prior);
            let (v4, v6) = effective(candidate, neighbor);
            looser(prior_v4, v4) || looser(prior_v6, v6)
        })
}

#[derive(Clone)]
pub struct ResolvedNeighbor {
    pub transport_config: TransportConfig,
    pub max_prefix_restart_seconds: Option<u32>,
    pub label: String,
    pub import_policy: Option<PolicyChain>,
    pub export_policy: Option<PolicyChain>,
    pub peer_group: Option<String>,
    /// ADR-0112 RFC 8212 external classification, decided from the neighbor
    /// record that produced this resolution (accept-any dynamic ranges
    /// included). The peer manager pins it for the session's lifetime because
    /// the record's `remote_asn` is overwritten with the ASN learned from OPEN.
    pub rfc8212_external: bool,
}

/// Build the ADR-0112 reserved internal deny-all chain for one direction.
///
/// Constructed directly rather than looked up in `[policy] definitions`, so no
/// configured name can reference or replace it. It denies by `default_action`
/// with no statements: `evaluate_chain(Some(..))` still runs, which is what
/// keeps `evaluate_chain(None, ..)` permit-all semantics untouched for every
/// session RFC 8212 enforcement does not govern.
pub(crate) fn reserved_rfc8212_deny_chain(name: &str) -> PolicyChain {
    PolicyChain::from_named(vec![NamedPolicy {
        name: Some(name.to_string()),
        policy: Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        },
        rpol: None,
    }])
}

/// True when `chain` is exactly the reserved RFC 8212 deny for `name`
/// (ADR-0112).
///
/// This is the whole directional status derivation: the operator surface asks
/// the *installed* chain what is installed instead of storing a second verdict
/// beside it. That is deliberate. A stored `present` bool has to be threaded
/// through every resolution, live-apply, and rollback path in lockstep with
/// the chain it describes, and the moment one path advances without it the
/// surface reports `present` while the deny is live — which is worse than no
/// surface at all in a fail-closed feature. Reading the chain cannot drift
/// from the chain.
///
/// This does not reconstruct the *provenance* verdict ADR-0112 forbids
/// rebuilding from compiled content, and it could not: the reserved deny
/// replaces the whole direction, so there is no operator policy or implicit
/// tail left to tell apart. It is an identity test against the one chain
/// `reserved_rfc8212_deny_chain` builds, and `Config::validate` refuses
/// both reserved names to operator policies, so nothing configurable compares
/// equal to it.
#[must_use]
pub fn is_reserved_rfc8212_deny(chain: Option<&PolicyChain>, name: &str) -> bool {
    chain.is_some_and(|chain| *chain == reserved_rfc8212_deny_chain(name))
}

/// One eBGP neighbor with no explicit operator policy in at least one
/// direction. Produced by [`Config::unpoliced_ebgp_neighbors`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnpolicedEbgpNeighbor {
    pub address: String,
    pub remote_asn: u32,
    pub import_missing: bool,
    pub export_missing: bool,
}

impl UnpolicedEbgpNeighbor {
    /// The missing direction(s) as a report phrase.
    #[must_use]
    pub fn missing_phrase(&self) -> &'static str {
        match (self.import_missing, self.export_missing) {
            (true, true) => "no import policy and no export policy",
            (true, false) => "no import policy",
            (false, true) => "no export policy",
            // Not constructed: the resolver only yields a record when at
            // least one direction is missing.
            (false, false) => "",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum UnpolicedEbgpSubject {
    StaticNeighbor(UnpolicedEbgpNeighbor),
    DynamicRange {
        prefix: String,
        peer_group: String,
        /// `None` is the configured wildcard, rendered as `any AS`.
        remote_asn: Option<std::num::NonZeroU32>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnpolicedEbgpBoundary {
    subject: UnpolicedEbgpSubject,
    import_missing: bool,
    export_missing: bool,
}

impl UnpolicedEbgpBoundary {
    pub(crate) fn is_dynamic_range(&self) -> bool {
        matches!(self.subject, UnpolicedEbgpSubject::DynamicRange { .. })
    }

    pub(crate) fn identity_phrase(&self) -> String {
        match &self.subject {
            UnpolicedEbgpSubject::StaticNeighbor(neighbor) => {
                format!("{} (AS {})", neighbor.address, neighbor.remote_asn)
            }
            UnpolicedEbgpSubject::DynamicRange {
                prefix,
                peer_group,
                remote_asn,
            } => {
                let asn =
                    remote_asn.map_or_else(|| "any AS".to_string(), |asn| format!("AS {asn}"));
                format!("dynamic range {prefix} via peer group {peer_group:?} ({asn})")
            }
        }
    }

    pub(crate) fn missing_phrase(&self) -> &'static str {
        if let UnpolicedEbgpSubject::StaticNeighbor(neighbor) = &self.subject {
            return neighbor.missing_phrase();
        }
        match (self.import_missing, self.export_missing) {
            (true, true) => "no import policy and no export policy",
            (true, false) => "no import policy",
            (false, true) => "no export policy",
            // Not constructed: the resolver only yields a record when at
            // least one direction is missing.
            (false, false) => "",
        }
    }
}

/// Resolved policy chains for one neighbor plus the ADR-0112 directional
/// explicit-policy provenance they were resolved with.
///
/// The provenance verdict is attached to the direction at resolution time. It
/// is never reconstructed by inspecting a compiled [`PolicyChain`]: compiled
/// content cannot tell an operator policy apart from a daemon-owned implicit
/// tail or from the reserved deny.
#[derive(Clone, Debug, PartialEq)]
pub struct EffectivePolicyChains {
    /// Effective import chain, including any implicit RFC 8326 / RFC 7999
    /// tails and any RFC 8212 reserved deny substitution.
    pub import: Option<PolicyChain>,
    /// Effective export chain, including any RFC 8212 reserved deny
    /// substitution.
    pub export: Option<PolicyChain>,
    /// Explicit operator import policy resolved, decided before the implicit
    /// tails were appended and before any reserved deny substitution.
    pub import_explicit: bool,
    /// Explicit operator export policy resolved.
    pub export_explicit: bool,
    /// RFC 8212 external (eBGP) classification for this resolution.
    pub external: bool,
}
