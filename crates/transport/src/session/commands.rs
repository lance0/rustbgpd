use super::{
    ControlFlow, Event, Message, NotificationCode, PeerCommand, PeerSession, PeerSessionState,
    RibUpdate, RouteRefreshMessage, SessionNotificationDirection, SessionState, cease_subcode,
    info,
};
use crate::handle::PeerCommandError;

impl PeerSession {
    /// Map external commands to FSM events.
    #[expect(
        clippy::too_many_lines,
        reason = "command dispatch centralizes all external peer-session control paths"
    )]
    pub(super) async fn handle_command(&mut self, cmd: PeerCommand) -> ControlFlow<()> {
        match cmd {
            PeerCommand::Start => {
                self.stop_requested = false;
                self.reconnect_timer = None;
                self.drive_fsm(Event::ManualStart).await;
                ControlFlow::Continue(())
            }
            PeerCommand::Stop { reason } => {
                self.stop_requested = true;
                self.reconnect_timer = None;
                self.drive_fsm(Event::ManualStop { reason }).await;
                ControlFlow::Continue(())
            }
            PeerCommand::Shutdown => {
                self.stop_requested = true;
                self.reconnect_timer = None;
                info!(peer = %self.peer_label, "shutdown requested");
                if self.fsm.state() == SessionState::Established {
                    self.drive_fsm(Event::ManualStop { reason: None }).await;
                }
                self.close_tcp();
                self.timers.stop_all();
                ControlFlow::Break(())
            }
            PeerCommand::QueryState { reply } => {
                let uptime_secs = self.established_at.map_or(0, |t| t.elapsed().as_secs());
                // Prefer FSM's negotiated (available at OpenConfirm) over
                // self.negotiated (set later at SessionEstablished). This is
                // critical for collision detection: handle_inbound() reads
                // remote_router_id via QueryState when the session is in
                // OpenConfirm.
                let neg = self.fsm.negotiated().or(self.negotiated.as_ref());
                let (messages_received, messages_sent) =
                    self.metrics.peer_message_totals(&self.peer_label);
                let state = PeerSessionState {
                    fsm_state: self.fsm.state(),
                    peer_ip: self.peer_ip,
                    peer_asn: neg.map(|n| n.peer_asn),
                    prefix_count: self.known_prefix_count(),
                    negotiated_hold_time: neg.map(|n| n.hold_time),
                    four_octet_as: neg.map(|n| n.four_octet_as),
                    remote_router_id: neg.map(|n| n.peer_router_id),
                    local_role: neg.and_then(|n| n.local_role),
                    remote_role: neg.and_then(|n| n.remote_role),
                    role_negotiated: neg.is_some_and(|n| n.role_negotiated),
                    updates_received: self.updates_received,
                    updates_sent: self.updates_sent,
                    notifications_received: self.notifications_received,
                    notifications_sent: self.notifications_sent,
                    messages_received,
                    messages_sent,
                    otc_routes_blocked: self.otc_routes_blocked,
                    import_policy_routes_permitted: self.import_policy_routes_permitted,
                    import_policy_routes_denied: self.import_policy_routes_denied,
                    flap_count: self.flap_count,
                    uptime_secs,
                    last_error: self.last_error.clone(),
                };
                let _ = reply.send(state);
                ControlFlow::Continue(())
            }
            PeerCommand::SendRouteRefresh { afi, safi, reply } => {
                if self.fsm.state() != SessionState::Established {
                    let _ = reply.send(Err(PeerCommandError::NotEstablished));
                    return ControlFlow::Continue(());
                }
                if !self
                    .negotiated
                    .as_ref()
                    .is_some_and(|n| n.peer_route_refresh)
                {
                    let _ = reply.send(Err(PeerCommandError::RouteRefreshUnsupported));
                    return ControlFlow::Continue(());
                }
                if !self.negotiated_families.contains(&(afi, safi)) {
                    let _ = reply.send(Err(PeerCommandError::FamilyNotNegotiated { afi, safi }));
                    return ControlFlow::Continue(());
                }
                let msg = Message::RouteRefresh(RouteRefreshMessage::new(afi, safi));
                if let Err(e) = self.enqueue_priority(&msg) {
                    let _ = reply.send(Err(PeerCommandError::SendFailed(e.to_string())));
                } else {
                    info!(peer = %self.peer_label, ?afi, ?safi, "sent ROUTE-REFRESH");
                    self.metrics
                        .record_message_sent(&self.peer_label, "route_refresh");
                    let _ = reply.send(Ok(()));
                }
                ControlFlow::Continue(())
            }
            PeerCommand::UpdateImportPolicy { policy, reply } => {
                self.install_import_policy(policy);
                // ADR-0073: advancing the session-local generation makes
                // every decision recorded under the prior chain read as
                // STALE on a subsequent explain lookup. saturating_add so
                // a pathologically long-lived session that somehow wraps
                // u64 degrades to "always current" rather than panicking.
                self.import_policy_generation = self.import_policy_generation.saturating_add(1);
                let _ = reply.send(Ok(()));
                ControlFlow::Continue(())
            }
            PeerCommand::ExplainImportPolicy {
                afi,
                safi,
                prefix,
                path_id,
                reply,
            } => {
                use super::import_decision_cache::{ImportDecisionKey, ResolvedMatch};
                let generation = self.import_policy_generation;
                let mut matches = match path_id {
                    Some(path_id) => {
                        let key = ImportDecisionKey {
                            afi,
                            safi,
                            prefix,
                            path_id,
                        };
                        vec![ResolvedMatch {
                            path_id,
                            result: self.import_decision_cache.lookup(&key, generation),
                            statements: Vec::new(),
                        }]
                    }
                    None => self
                        .import_decision_cache
                        .lookup_all_paths(afi, safi, &prefix, generation),
                };
                // Statement-level attribution, re-derived on demand from the
                // cached pre-policy context against the session's import
                // chain. Explain-only work on the command path — the inbound
                // UPDATE hot path is untouched.
                // Typed family from the explain key's AFI/SAFI — the
                // same pair the cached decision was recorded under
                // (LAN-295).
                let family = rustbgpd_policy::RouteFamily::from_afi_safi(afi, safi);
                for m in &mut matches {
                    m.statements = self.statement_trace_for(prefix, family, &m.result);
                }
                let _ = reply.send(super::import_decision_cache::ImportExplainReply {
                    current_generation: generation,
                    cache_enabled: self.import_explain_enabled,
                    matches,
                });
                ControlFlow::Continue(())
            }
            PeerCommand::QueryImportPolicyTermHits { reply } => {
                // Read-only snapshot of the live counters (ADR-0096
                // Decision 3.3). No counter moves; a session without an
                // installed import chain has nothing to report.
                let snapshot =
                    self.import_policy
                        .as_ref()
                        .map(|chain| crate::handle::ImportPolicyTermHits {
                            generation: self.import_policy_generation,
                            evals: chain.hit_counters().evals(),
                            eval_errors: chain.hit_counters().eval_errors(),
                            last_error: chain
                                .hit_counters()
                                .last_error()
                                .map(|error| error.to_string()),
                            terms: chain.term_hit_rows(),
                        });
                let _ = reply.send(snapshot);
                ControlFlow::Continue(())
            }
            PeerCommand::UpdateExportPolicy { policy, reply } => {
                self.export_policy = policy;
                let _ = reply.send(Ok(()));
                ControlFlow::Continue(())
            }
            PeerCommand::UpdateRuntimeConfig {
                max_prefixes,
                gr_stale_routes_time,
                local_ipv6_nexthop,
                remove_private_as,
                reply,
            } => {
                // LAN-341 hot-apply: these knobs are read from
                // `self.config` on every evaluation (see the command's
                // doc), so swapping them here is the whole apply — no
                // FSM event, no TCP impact. A lowered `max_prefixes`
                // trips on the next received UPDATE, matching the
                // reload matrix's documented semantics.
                self.config.max_prefixes = max_prefixes;
                self.config.gr_stale_routes_time = gr_stale_routes_time;
                self.config.local_ipv6_nexthop = local_ipv6_nexthop;
                self.config.remove_private_as = remove_private_as;
                info!(peer = %self.peer_label, "hot-applied runtime config knobs");
                let _ = reply.send(Ok(()));
                ControlFlow::Continue(())
            }
            PeerCommand::UpdateGracefulShutdown { enabled, reply } => {
                // Idempotent: re-setting to the same value is a no-op.
                // The toggle takes effect for the next outbound update;
                // RFC 8326 §5 expects the operator to follow this with
                // a re-advertise so peers see the tagged routes.
                self.advertise_graceful_shutdown = enabled;
                info!(
                    peer = %self.peer_label,
                    enabled,
                    "RFC 8326 graceful-shutdown advertise toggled"
                );
                let _ = reply.send(Ok(()));
                ControlFlow::Continue(())
            }
            PeerCommand::CollisionDump => {
                info!(peer = %self.peer_label, "collision dump: sending Cease/7");
                self.stop_requested = true;
                self.reconnect_timer = None;
                // Send Cease/7 NOTIFICATION
                let notif = rustbgpd_wire::NotificationMessage::new(
                    NotificationCode::Cease,
                    cease_subcode::CONNECTION_COLLISION_RESOLUTION,
                    bytes::Bytes::new(),
                );
                self.emit_notification_event(SessionNotificationDirection::Sent, &notif, None);
                let _ = self.enqueue_priority(&Message::Notification(notif));
                self.notifications_sent += 1;
                // Clean up RIB if Established
                if self.fsm.state() == SessionState::Established {
                    let _ = self
                        .rib_tx
                        .send(RibUpdate::PeerDown {
                            peer: self.peer_ip,
                            session_id: self.session_identity.id,
                        })
                        .await;
                }
                self.close_tcp();
                self.timers.stop_all();
                ControlFlow::Break(())
            }
        }
    }

    /// Re-derive the statement-level trace for one resolved explain
    /// match (ADR-0073 statement-level enrichment).
    ///
    /// Only a current-generation `Hit` with a `Permit` / `Deny` outcome
    /// qualifies: a same-generation hit guarantees the session's import
    /// chain is byte-for-byte the chain that produced the cached
    /// decision, so walking it again against the cached pre-policy
    /// context reproduces the original evaluation. `Stale` entries
    /// are skipped (their chain is gone — tracing the *current* chain
    /// could contradict the recorded outcome) and `Withdrawn`
    /// tombstones shed the context the reconstruction needs.
    ///
    /// The cached context is an owned copy of the fields produced by the same
    /// extractor the inbound hot path uses (`PolicyAttrSummary::from_route_attrs`)
    /// plus the stored evaluation-time next-hop, so the trace cannot drift from
    /// the live evaluation's view of the route. As a final belt-and-braces gate,
    /// a trace whose terminal action disagrees with the recorded outcome is
    /// dropped rather than rendered — an explain surface must never contradict
    /// its own headline answer.
    fn statement_trace_for(
        &self,
        prefix: rustbgpd_wire::Prefix,
        family: Option<rustbgpd_policy::RouteFamily>,
        result: &super::import_decision_cache::LookupResult,
    ) -> Vec<rustbgpd_policy::StatementAttribution> {
        use super::import_decision_cache::{CachedOutcome, LookupResult};
        use rustbgpd_policy::{PolicyAction, RouteContext, RouteType, explain_chain_statements};

        let LookupResult::Hit(decision) = result else {
            return Vec::new();
        };
        let expected_action = match decision.outcome {
            CachedOutcome::Permit => PolicyAction::Permit,
            CachedOutcome::Deny => PolicyAction::Deny,
            CachedOutcome::Withdrawn => return Vec::new(),
        };

        let cached = &decision.policy_context;
        // Session-identity fields mirror the inbound eval sites: the
        // peer's negotiated ASN and eBGP/iBGP classification are
        // properties of the established session and cannot have
        // changed since the decision was recorded on it.
        let is_ebgp = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_asn != self.config.peer.local_asn);
        let ctx = RouteContext {
            prefix: Some(prefix),
            next_hop: decision.next_hop,
            extended_communities: &cached.extended_communities,
            communities: &cached.communities,
            large_communities: &cached.large_communities,
            as_path_str: &cached.as_path_str,
            as_path: cached.as_path.as_ref(),
            as_path_len: cached.as_path_len,
            origin_asn: cached.origin_asn,
            validation_state: decision.rpki,
            aspa_state: decision.aspa,
            peer_address: Some(self.peer_ip),
            peer_asn: self.negotiated.as_ref().map(|n| n.peer_asn),
            peer_group: self.config.peer_group.as_deref(),
            route_type: Some(if is_ebgp {
                RouteType::External
            } else {
                RouteType::Internal
            }),
            family,
            evpn_route_type: None,
            local_pref: cached.local_pref,
            med: cached.med,
        };
        let trace = explain_chain_statements(self.import_policy.as_ref(), &ctx);
        if trace.action == expected_action {
            trace.steps
        } else {
            // Should be unreachable for a same-generation hit; pinned
            // by the policy-crate agreement tests. Prefer "no trace"
            // over a trace that contradicts the recorded outcome.
            debug_assert_eq!(trace.action, expected_action, "explain trace diverged");
            Vec::new()
        }
    }
}
