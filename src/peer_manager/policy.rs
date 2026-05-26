use std::net::IpAddr;

use rustbgpd_api::peer_types::{ConfigEvent, PeerKey, PeerManagerNeighborConfig};
use rustbgpd_fsm::SessionState;
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::RibUpdate;
use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::config::Config;
use crate::policy_admin::{
    apply_config_event, neighbor_set_references, peer_group_references, policy_references,
};

use super::{ManagedPeer, PEER_POLICY_UPDATE_TIMEOUT, PEER_QUERY_TIMEOUT, PeerManager};

impl PeerManager {
    #[cfg(test)]
    pub(super) async fn update_runtime_policies(
        &mut self,
        address: IpAddr,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
    ) -> Result<(), String> {
        let Some(peer_key) = self.unique_peer_key_for_address(address) else {
            return Ok(());
        };
        self.update_runtime_policies_for_peer_key(peer_key, import_policy, export_policy)
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn update_runtime_policies_for_peer_key(
        &mut self,
        peer_key: PeerKey,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
    ) -> Result<(), String> {
        use std::fmt::Write as _;
        let address = peer_key.address;
        let Some(managed) = self.peers.get_mut(&peer_key) else {
            return Ok(());
        };

        // Capture the *prior* import policy before clobbering so we
        // can decide at the end whether to issue a Route Refresh.
        // `update_import_policy_timeout` only swaps the policy
        // reference for *future* inbound UPDATEs — routes already in
        // AdjRibIn were accepted under the old policy and stay there
        // until the peer re-advertises. Without an automatic refresh
        // here, a permit→deny edit silently leaves forbidden routes
        // flowing. PolicyChain doesn't derive PartialEq (would
        // require touching nested types in other crates); the Debug
        // representation is deterministic for this comparison since
        // both sides come from the same `effective_policy_chains_for_neighbor`
        // resolver and `PolicyChain.policies` is a `Vec` (stable order).
        let import_changed = format!("{:?}", managed.import_policy) != format!("{import_policy:?}");
        let export_changed = format!("{:?}", managed.export_policy) != format!("{export_policy:?}");

        // Drain any pending refresh / pending export-apply from a
        // prior call. If a previous round wanted to retry but the
        // session-side update failed (or the peer wasn't Established
        // yet for the import refresh), we re-arm so this call retries
        // in lockstep with whatever new edits the current call brings.
        let had_pending_refresh = std::mem::take(&mut managed.pending_refresh);
        let had_pending_export_apply = std::mem::take(&mut managed.pending_export_apply);

        // Bounded deadlines on the per-peer session round-trips. Without
        // them a back-pressured peer parks the peer-manager actor here,
        // which then can't service `ListPeers` (or any other command), so
        // a `GetHealth` RPC issued during the reload would wedge for as
        // long as the back-pressure lasts. Same wedge class fixed by
        // `query_state_timeout` for the read path; this closes the
        // hot-apply path.
        //
        // Hot-apply to the session FIRST and defer advancing
        // `managed.import_policy` / `managed.export_policy` until the
        // session acknowledges. If the session-side update fails (task
        // back-pressured past the deadline, task exited, mpsc full),
        // leaving the daemon's bookkeeping at the prior value lets the
        // next call's `import_changed` / `export_changed` comparisons
        // still see a delta and retry. The previous "advance
        // bookkeeping then warn-and-continue on session error" pattern
        // allowed the daemon to believe the new policy was live while
        // the session task still held the old one — and worse, would
        // then fire Route Refresh against the session, which would
        // re-evaluate AdjRibIn against the *old* policy and silently
        // keep forbidden routes flowing.
        let import_apply_result = managed
            .handle
            .update_import_policy_timeout(import_policy.clone(), PEER_POLICY_UPDATE_TIMEOUT)
            .await;
        let import_apply_failed = if let Err(error) = &import_apply_result {
            warn!(
                %address,
                error = %error,
                "failed to hot-apply import policy to peer session; retaining prior policy in daemon bookkeeping for retry"
            );
            true
        } else {
            managed.import_policy = import_policy;
            false
        };

        let export_apply_result = managed
            .handle
            .update_export_policy_timeout(export_policy.clone(), PEER_POLICY_UPDATE_TIMEOUT)
            .await;
        let export_apply_failed = if let Err(error) = &export_apply_result {
            warn!(
                %address,
                error = %error,
                "failed to hot-apply export policy to peer session; retaining prior policy in daemon bookkeeping for retry"
            );
            true
        } else {
            managed.export_policy.clone_from(&export_policy);
            false
        };

        let session_state = managed.handle.query_state_timeout(PEER_QUERY_TIMEOUT).await;
        let is_established = session_state
            .as_ref()
            .is_some_and(|s| s.fsm_state == SessionState::Established);

        let needs_refresh = import_changed || had_pending_refresh;
        let needs_export_apply = export_changed || had_pending_export_apply;

        // Bail before the RIB update and Route Refresh if either side
        // failed under an apply-changing intent. The bail decision is
        // not gated on `is_established` for either side: Route Refresh
        // is gated separately by `soft_reset_in`'s own Established
        // check, but the *failure-surfacing* decision is independent.
        // For non-Established peers the same staleness exists — the
        // session task may eventually drop the queued command (task
        // dies before processing) and reach Established holding the
        // prior policy. Without bailing, `apply_policy_change` would
        // advance `current_config`, leaving no signal that the edit
        // didn't actually land.
        //
        //   - Import bail: session didn't acknowledge the new import
        //     policy under refresh intent. For Established peers this
        //     also prevents firing Route Refresh against a session
        //     that still holds the prior policy, which would
        //     re-evaluate AdjRibIn against the *old* policy.
        //
        //   - Export bail: session didn't acknowledge the new export
        //     policy under export-apply intent. Letting bookkeeping
        //     advance here would (a) leave the peer announcing under
        //     the prior export policy until something else triggered
        //     a re-apply, and (b) drift the RIB's view
        //     (`ReplacePeerExportPolicy`) away from the session's
        //     view if we proceeded to the RIB update step.
        //
        // Set the matching pending flag(s) so the next call retries,
        // then return Err so the caller (gRPC reply, SIGHUP reload
        // halt path) surfaces the failure rather than logging-and-
        // forgetting.
        let import_bail = import_apply_failed && needs_refresh;
        let export_bail = export_apply_failed && needs_export_apply;
        if import_bail || export_bail {
            if let Some(managed) = self.peers.get_mut(&peer_key) {
                // Carry forward *all* unfired apply / refresh intent
                // across the bail, not just the side that triggered
                // the bail. Critical cross-side case: import-apply
                // succeeded (so `managed.import_policy` already
                // advanced) but the export bail stops us before
                // `soft_reset_in`. If we only set the bail-triggering
                // flag, the next retry would see `import_changed =
                // false` (bookkeeping already advanced) and
                // `had_pending_refresh = false`, compute
                // `needs_refresh = false`, and silently skip Route
                // Refresh — leaving AdjRibIn routes accepted under
                // the prior import policy stuck against a session
                // that now has the new policy. Setting both flags
                // whenever the corresponding intent was present
                // makes the retry pipeline pick up *every* unfired
                // step regardless of which side bailed.
                if needs_refresh {
                    managed.pending_refresh = true;
                }
                if needs_export_apply {
                    managed.pending_export_apply = true;
                }
            }
            let mut detail = String::new();
            if import_bail {
                let import_err = import_apply_result.err().unwrap_or_default();
                let _ = write!(detail, "import: {import_err}");
            }
            if export_bail {
                if !detail.is_empty() {
                    detail.push_str("; ");
                }
                let export_err = export_apply_result.err().unwrap_or_default();
                let _ = write!(detail, "export: {export_err}");
            }
            return Err(format!(
                "policy hot-apply to peer {address} failed; retry deferred to next \
                 update_runtime_policies call: {detail}"
            ));
        }

        if is_established {
            // The RIB step sits between session-side hot-apply (already
            // succeeded if we reached here) and Route Refresh. If it
            // fails, we still need to preserve any unfired refresh
            // intent: bookkeeping has already advanced (because session
            // ACKed), so on the next call `import_changed` would be
            // false and `needs_refresh` would compute false without a
            // `pending_refresh` carry — the same silent-skip class as
            // the cross-side bail bug. Use explicit match so the Err
            // arms can re-arm `pending_refresh` before returning.
            let (reply_tx, reply_rx) = oneshot::channel();
            let send_outcome = self
                .rib_tx
                .send(RibUpdate::ReplacePeerExportPolicy {
                    peer: address,
                    export_policy,
                    reply: reply_tx,
                })
                .await;
            let rib_outcome: Result<(), String> = match send_outcome {
                Err(_) => Err("RIB manager unavailable".to_string()),
                Ok(()) => match reply_rx.await {
                    Err(_) => Err("RIB manager dropped reply".to_string()),
                    Ok(Err(e)) => Err(format!("failed to update export policy: {e}")),
                    Ok(Ok(())) => Ok(()),
                },
            };
            if let Err(error) = rib_outcome {
                if needs_refresh && let Some(managed) = self.peers.get_mut(&peer_key) {
                    managed.pending_refresh = true;
                }
                return Err(error);
            }
        }

        // Issue Route Refresh (RFC 2918) to re-evaluate routes already
        // in this peer's AdjRibIn against the new import policy.
        // Driven from here rather than from the SIGHUP-only reload
        // path so dynamic peers, gRPC mutations, and any other call
        // site that goes through `apply_policy_change` get the same
        // correctness guarantee — the loop above iterates
        // `self.peers`, which includes dynamic peers.
        //
        // Gated on (a) the import policy materially changing — re-
        // applying the same chain (no-op edits, redundant mutations)
        // shouldn't trigger Route Refresh storms — and (b) the
        // session being Established. Idle / Connect-state peers
        // have nothing in AdjRibIn yet; they'll receive routes
        // under the new policy when the session reaches
        // Established naturally. Without the Established gate,
        // `send_route_refresh` would error for any non-Established
        // peer ("session not Established"), and an operator gRPC
        // `SetPolicy` issued while one of N peers is mid-reconnect
        // would fail.
        //
        // Failure for an Established peer bubbles up to
        // `apply_policy_change`'s caller — for SIGHUP reloads, that
        // halts the reload via `halt_partial` so the failure is
        // surfaced rather than logged-and-forgotten. Before bubbling
        // up, set `pending_refresh` so the next operator action
        // retries the refresh — otherwise a single transient send
        // failure (peer task mid-restart, mpsc backpressure) would
        // leave the new policy applied to *future* UPDATEs while
        // routes already in AdjRibIn keep flowing under the prior
        // policy until the operator reissues a SetPolicy.
        if needs_refresh && is_established {
            if let Err(error) = self.soft_reset_in(peer_key.clone(), Vec::new()).await {
                if let Some(managed) = self.peers.get_mut(&peer_key) {
                    managed.pending_refresh = true;
                }
                return Err(error);
            }
        } else if needs_refresh {
            // `!is_established` here means one of: the peer really is
            // Idle / Connect / OpenSent (no AdjRibIn to refresh — the
            // refresh next call would be a no-op), OR
            // `query_state_timeout` returned None for an
            // actually-Established peer (back-pressured session task
            // missed the deadline) and we cannot distinguish the two
            // from this side. Re-arm `pending_refresh` unconditionally
            // so that a subsequent call — once the session unblocks
            // or the peer reaches Established — fires the refresh.
            // Without this, a fresh `import_changed = true` in this
            // call combined with a stale state query would silently
            // drop refresh intent: bookkeeping advances, the retry
            // sees `import_changed = false`, and AdjRibIn routes
            // accepted under the prior policy stay stuck. The
            // wasted-refresh cost on a genuinely Idle peer (next call
            // sends Route Refresh against an empty / freshly-populated
            // AdjRibIn) is small and acceptable next to silent
            // staleness.
            if let Some(managed) = self.peers.get_mut(&peer_key) {
                managed.pending_refresh = true;
            }
        }

        Ok(())
    }

    pub(super) async fn apply_policy_change(
        &mut self,
        event: ConfigEvent,
        affected_peers: Option<Vec<IpAddr>>,
    ) -> Result<(), String> {
        if let ConfigEvent::DeletePolicy { name } = &event {
            let refs = policy_references(&self.current_config, name);
            if !refs.is_empty() {
                return Err(format!(
                    "policy {name} is still referenced by {}",
                    refs.join(", ")
                ));
            }
        }
        if let ConfigEvent::DeleteNeighborSet { name } = &event {
            let refs = neighbor_set_references(&self.current_config, name);
            if !refs.is_empty() {
                return Err(format!(
                    "neighbor set {name} is still referenced by {}",
                    refs.join(", ")
                ));
            }
        }

        let mut next_config = self.current_config.clone();
        apply_config_event(&mut next_config, &event).map_err(|e| e.to_string())?;

        let peers: Vec<PeerKey> = affected_peers.map_or_else(
            || self.peers.keys().cloned().collect(),
            |peers| {
                peers
                    .into_iter()
                    .flat_map(|address| self.peer_keys_for_address(address))
                    .collect()
            },
        );
        let mut affected_peer_count = 0usize;
        for peer_key in peers {
            if !self.peers.contains_key(&peer_key) {
                continue;
            }
            let address = peer_key.address;
            let Some(neighbor) = next_config.neighbors.iter().find(|neighbor| {
                neighbor.address == address.to_string() && neighbor.interface == peer_key.interface
            }) else {
                continue;
            };
            affected_peer_count += 1;
            let (import_policy, export_policy) = next_config
                .effective_policy_chains_for_neighbor(neighbor)
                .map_err(|e| e.to_string())?;
            self.update_runtime_policies_for_peer_key(peer_key, import_policy, export_policy)
                .await?;
        }

        self.current_config = next_config;
        self.publish_policy_config_event(&event, affected_peer_count);
        Ok(())
    }

    pub(super) fn policy_resolution_neighbor(
        config: &Config,
        address: IpAddr,
        managed: &ManagedPeer,
    ) -> crate::config::Neighbor {
        config
            .neighbors
            .iter()
            .find(|neighbor| {
                neighbor.address == address.to_string()
                    && neighbor.interface == managed.transport_config.peer_interface
            })
            .cloned()
            .unwrap_or_else(|| crate::config::Neighbor {
                address: address.to_string(),
                interface: managed.transport_config.peer_interface.clone(),
                remote_asn: managed.remote_asn,
                description: None,
                peer_group: managed.peer_group.clone(),
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
                remove_private_as: None,
                add_path: None,
                log_level: None,
                import_policy: Vec::new(),
                export_policy: Vec::new(),
                import_policy_chain: Vec::new(),
                export_policy_chain: Vec::new(),
            })
    }

    pub(super) async fn set_honor_graceful_shutdown(
        &mut self,
        enabled: bool,
    ) -> Result<(), String> {
        if self.current_config.global.honor_graceful_shutdown == enabled {
            return Ok(());
        }

        // Best-effort fan-out: precompute every EBGP peer's resolved chains
        // against the *new* snapshot, advance the snapshot unconditionally,
        // then iterate applying. A failure on peer B must not leave peer A
        // running with the new effective policy while `current_config`
        // still shows the old knob value — that drift is what the prior
        // `?`-shortcircuit shape produced and is hard to debug
        // operationally. Failed peers will pick up the stale state on
        // their next `update_runtime_policies` call thanks to the
        // existing bail-and-carry plumbing (`pending_refresh` /
        // `pending_export_apply` flags retry on the next policy edit).
        //
        // Resolution failures are also non-fatal at the per-peer scope:
        // if a single neighbor's effective chain can't be resolved
        // (e.g. peer-group reference broken mid-flight), other peers
        // shouldn't be punished for it.
        let mut next_config = self.current_config.clone();
        next_config.global.honor_graceful_shutdown = enabled;

        let targets: Vec<PeerKey> = self
            .peers
            .iter()
            .filter_map(|(peer, managed)| {
                (managed.remote_asn != self.local_asn).then_some(peer.clone())
            })
            .collect();

        let mut failures: Vec<String> = Vec::new();
        for peer_key in targets {
            let address = peer_key.address;
            let Some(managed) = self.peers.get(&peer_key) else {
                continue;
            };
            let neighbor = Self::policy_resolution_neighbor(&next_config, address, managed);
            let chains = next_config.effective_policy_chains_for_neighbor(&neighbor);
            let (import_policy, export_policy) = match chains {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        %address,
                        error = %e,
                        "honor_graceful_shutdown: failed to resolve effective chain — skipping peer"
                    );
                    failures.push(format!("{address}: chain-resolve: {e}"));
                    continue;
                }
            };
            if let Err(e) = self
                .update_runtime_policies_for_peer_key(peer_key, import_policy, export_policy)
                .await
            {
                warn!(
                    %address,
                    error = %e,
                    "honor_graceful_shutdown: failed to hot-apply on peer — desired snapshot \
                     advances anyway; bail-and-carry will retry on next policy edit"
                );
                failures.push(format!("{address}: hot-apply: {e}"));
            }
        }

        // Snapshot advances regardless of per-peer outcomes — the
        // authoritative knob value matches the operator's intent. The
        // alternative (shortcircuit on first failure with no rollback)
        // leaves successfully-updated peers running ahead of the
        // snapshot, which is the worse drift.
        self.current_config = next_config;

        if failures.is_empty() {
            info!(
                enabled,
                "hot-applied [global] honor_graceful_shutdown to EBGP peers"
            );
            Ok(())
        } else {
            Err(format!(
                "honor_graceful_shutdown applied with {} of {} EBGP peers failing \
                 (snapshot advanced anyway): {}",
                failures.len(),
                self.peers
                    .values()
                    .filter(|m| m.remote_asn != self.local_asn)
                    .count(),
                failures.join("; ")
            ))
        }
    }

    pub(super) async fn set_honor_blackhole(&mut self, enabled: bool) -> Result<(), String> {
        if self.current_config.global.honor_blackhole == enabled {
            return Ok(());
        }

        let mut next_config = self.current_config.clone();
        next_config.global.honor_blackhole = enabled;

        let targets: Vec<PeerKey> = self
            .peers
            .iter()
            .filter_map(|(peer, managed)| {
                (managed.remote_asn != self.local_asn).then_some(peer.clone())
            })
            .collect();

        let mut failures: Vec<String> = Vec::new();
        for peer_key in targets {
            let address = peer_key.address;
            let Some(managed) = self.peers.get(&peer_key) else {
                continue;
            };
            let neighbor = Self::policy_resolution_neighbor(&next_config, address, managed);
            let chains = next_config.effective_policy_chains_for_neighbor(&neighbor);
            let (import_policy, export_policy) = match chains {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        %address,
                        error = %e,
                        "honor_blackhole: failed to resolve effective chain — skipping peer"
                    );
                    failures.push(format!("{address}: chain-resolve: {e}"));
                    continue;
                }
            };
            if let Err(e) = self
                .update_runtime_policies_for_peer_key(peer_key, import_policy, export_policy)
                .await
            {
                warn!(
                    %address,
                    error = %e,
                    "honor_blackhole: failed to hot-apply on peer — desired snapshot \
                     advances anyway; bail-and-carry will retry on next policy edit"
                );
                failures.push(format!("{address}: hot-apply: {e}"));
            }
        }

        self.current_config = next_config;

        if failures.is_empty() {
            info!(
                enabled,
                "hot-applied [global] honor_blackhole to EBGP peers"
            );
            Ok(())
        } else {
            Err(format!(
                "honor_blackhole applied with {} of {} EBGP peers failing \
                 (snapshot advanced anyway): {}",
                failures.len(),
                self.peers
                    .values()
                    .filter(|m| m.remote_asn != self.local_asn)
                    .count(),
                failures.join("; ")
            ))
        }
    }

    pub(super) fn peer_manager_config_from_resolved(
        resolved: crate::config::ResolvedNeighbor,
        gr_restart_eligible: bool,
    ) -> PeerManagerNeighborConfig {
        let tc = resolved.transport_config;
        PeerManagerNeighborConfig {
            address: tc.remote_addr.ip(),
            interface: tc.peer_interface.clone(),
            scope_id: tc.peer_scope_id,
            remote_asn: tc.peer.remote_asn,
            description: resolved.label,
            peer_group: resolved.peer_group,
            hold_time: Some(tc.peer.hold_time),
            max_prefixes: tc.max_prefixes,
            md5_password: tc.md5_password.clone(),
            tcp_ao: tc.tcp_ao.clone(),
            ttl_security: tc.ttl_security,
            families: tc.peer.families.clone(),
            graceful_restart: tc.peer.graceful_restart,
            gr_restart_time: tc.peer.gr_restart_time,
            gr_stale_routes_time: tc.gr_stale_routes_time,
            llgr_stale_time: tc.llgr_stale_time,
            gr_restart_eligible,
            local_ipv6_nexthop: tc.local_ipv6_nexthop,
            route_reflector_client: tc.route_reflector_client,
            route_server_client: tc.route_server_client,
            remove_private_as: tc.remove_private_as,
            add_path_receive: tc.peer.add_path_receive,
            add_path_send: tc.peer.add_path_send,
            add_path_send_max: tc.peer.add_path_send_max,
            local_role: tc.peer.local_role,
            strict_role: tc.peer.strict_role,
            import_policy: resolved.import_policy,
            export_policy: resolved.export_policy,
        }
    }

    pub(super) async fn apply_peer_group_change(
        &mut self,
        event: ConfigEvent,
        affected_peers: Vec<IpAddr>,
    ) -> Result<(), String> {
        if let ConfigEvent::DeletePeerGroup { name } = &event {
            let refs = peer_group_references(&self.current_config, name);
            if !refs.is_empty() {
                return Err(format!(
                    "peer group {name} is still referenced by {}",
                    refs.join(", ")
                ));
            }
        }

        let mut next_config = self.current_config.clone();
        apply_config_event(&mut next_config, &event).map_err(|e| e.to_string())?;

        let targets: Vec<PeerKey> = affected_peers
            .into_iter()
            .flat_map(|address| self.peer_keys_for_address(address))
            .collect();
        let mut affected_peer_count = 0usize;
        for peer_key in targets {
            let address = peer_key.address;
            let was_enabled = self
                .peers
                .get(&peer_key)
                .is_none_or(|managed| managed.enabled);
            let next_peer_config = if let Some(neighbor) =
                next_config.neighbors.iter().find(|neighbor| {
                    neighbor.address == address.to_string()
                        && neighbor.interface == peer_key.interface
                }) {
                let resolved = next_config
                    .resolve_neighbor(neighbor)
                    .map_err(|e| e.to_string())?;
                Some(Self::peer_manager_config_from_resolved(resolved, false))
            } else {
                None
            };

            if let Some(cfg) = next_peer_config.as_ref() {
                self.delete_peer_for_reconfigure(peer_key, cfg.tcp_ao.as_ref())
                    .await?;
            } else {
                self.delete_peer(peer_key, false).await?;
            }

            if let Some(cfg) = next_peer_config {
                let added_key = PeerKey::new(cfg.address, cfg.interface.clone());
                self.add_peer(cfg, false).await?;
                affected_peer_count += 1;
                if !was_enabled {
                    self.disable_peer(added_key, None).await?;
                }
            }
        }

        self.current_config = next_config;
        self.publish_policy_config_event(&event, affected_peer_count);
        Ok(())
    }
}
