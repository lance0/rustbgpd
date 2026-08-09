use super::*;

// ---------------------------------------------------------------------------
// A rejected mutation leaves no observable trace.
//
// `FAILED_PRECONDITION` from a mutating RPC means the request did nothing.
// These drive the real pipeline end to end — peer-manager actor, gRPC neighbor
// service, config bridge, config persister — against a config directory the
// process cannot write, which is the persistence failure an operator actually
// hits on a read-only or root-owned config mount.
// ---------------------------------------------------------------------------

/// A session task that answers `QueryState` with a fixed, non-zero identity.
///
/// A torn-down-and-recreated session cannot reproduce these values: rebuilding
/// the peer installs a real session task reporting a zeroed uptime and zeroed
/// counters, so a teardown stays visible in the peer list even when the peer
/// address comes back.
fn persistence_probe_handle(peer_addr: IpAddr) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: peer_addr,
                        peer_asn: Some(65002),
                        prefix_count: 17,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
                        negotiated_session: None,
                        local_role: None,
                        remote_role: None,
                        role_negotiated: false,
                        peer_paths_limits: Vec::new(),
                        effective_add_path_send_limits: Vec::new(),
                        updates_received: 4_242,
                        updates_sent: 1_337,
                        notifications_received: 0,
                        notifications_sent: 0,
                        messages_received: 9_001,
                        messages_sent: 8_128,
                        otc_routes_blocked: 0,
                        import_policy_routes_permitted: 0,
                        import_policy_routes_denied: 0,
                        flap_count: 3,
                        uptime_secs: 86_400,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } | PeerCommand::CollisionDump => {
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

/// The session identity and counters an operator watches: every one of these
/// changes when a session is torn down and rebuilt, and none of them changes
/// while it is left alone.
fn observable_session(
    info: &rustbgpd_api::peer_types::PeerInfo,
) -> (SessionState, u64, u64, u64, u64, u64, u64, usize, bool) {
    (
        info.state,
        info.updates_received,
        info.updates_sent,
        info.messages_received,
        info.messages_sent,
        info.flap_count,
        info.uptime_secs,
        info.prefix_count,
        info.stale,
    )
}

/// Peer-manager actor, config bridge, config persister, and neighbor service —
/// all real — wired to a config file inside a temp directory.
struct PersistenceRig {
    dir: tempfile::TempDir,
    config_path: std::path::PathBuf,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    rib_rx: mpsc::Receiver<RibUpdate>,
    service: rustbgpd_api::NeighborService,
}

impl PersistenceRig {
    /// The peer that exists both on disk and as a live Established session.
    const PEER: &'static str = "10.0.0.2";
    /// A second configured neighbor, so deleting `PEER` is a targeted removal
    /// rather than emptying the file.
    const OTHER_PEER: &'static str = "10.0.0.4";

    /// Not `async`: everything here is either synchronous or a `tokio::spawn`,
    /// which only needs the caller's runtime, so the rig is fully wired the
    /// moment this returns.
    fn start() -> Self {
        let dir = tempfile::tempdir().expect("temp config dir");
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            crate::test_support::tier_authorized_uds_test_config(
                r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.ix-members]
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true
per_client_best = true
graceful_restart = false
role = "route_server"
strict_role = true

[peer_groups.ix-members.add_path]
receive = true
send = true
send_max = 4
receive_max = 8

[peer_groups.rr-clients]
families = ["ipv6_unicast"]
route_reflector_client = true
graceful_restart = false

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
hold_time = 90
"#,
            ),
        )
        .expect("seed config file");
        let config = Config::load_with_diagnostics(config_path.to_str().unwrap())
            .expect("seed config parses");
        assert_tier_authorized_test_config(&config);

        // Real persister writing to the real path, behind the real bridge.
        let (mutation_tx, mutation_rx) = mpsc::channel(8);
        tokio::spawn(
            crate::config_persister::ConfigPersister::new(
                mutation_rx,
                config_path.clone(),
                config.clone(),
                None,
            )
            .run(),
        );
        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (_replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let actor_config = config.clone();
        tokio::spawn(crate::reload::run_config_bridge(
            event_rx,
            replace_rx,
            mutation_tx,
            config,
        ));

        // Real peer-manager actor holding one Established session.
        let (peer_mgr_tx, peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let mut mgr = PeerManager::new(
            peer_mgr_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            BgpMetrics::new(),
            rib_tx.clone(),
            None,
        );
        mgr.current_config = actor_config;
        let peer_addr: IpAddr = Self::PEER.parse().unwrap();
        insert_test_managed_peer_with_asn(
            &mut mgr,
            peer_addr,
            65002,
            persistence_probe_handle(peer_addr),
            false,
        );
        tokio::spawn(mgr.run());

        let service = rustbgpd_api::NeighborService::with_runtime_config_lock(
            65001,
            rustbgpd_api::server::AccessMode::ReadWrite,
            peer_mgr_tx.clone(),
            rib_tx,
            Some(event_tx),
            Arc::new(tokio::sync::Mutex::new(())),
            None,
        );

        Self {
            dir,
            config_path,
            peer_mgr_tx,
            rib_rx,
            service,
        }
    }

    async fn list_peers(&self) -> Vec<rustbgpd_api::peer_types::PeerInfo> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ListPeers { reply: reply_tx })
            .await
            .expect("peer-manager actor alive");
        tokio::time::timeout(Duration::from_secs(5), reply_rx)
            .await
            .expect("peer-manager actor answered ListPeers")
            .expect("peer-manager actor kept the reply channel")
    }

    async fn peer(&self, address: &str) -> Option<rustbgpd_api::peer_types::PeerInfo> {
        let wanted: IpAddr = address.parse().unwrap();
        self.list_peers()
            .await
            .into_iter()
            .find(|info| info.address == wanted)
    }

    fn config_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.config_path).expect("config file readable")
    }

    fn staged_temp_path(&self) -> std::path::PathBuf {
        self.dir.path().join("config.toml.tmp")
    }

    /// Take write permission away from the config *directory* so the real
    /// staging write fails with `EACCES`.
    ///
    /// Returns `false` when the mode bits do not bind — uid 0 ignores them —
    /// so the caller skips instead of asserting a failure the kernel will not
    /// produce. Probing with an actual write is the honest check: the whole
    /// premise is that writing fails, so ask the filesystem rather than
    /// guessing from the effective uid.
    fn seal_config_dir(&self) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(self.dir.path(), std::fs::Permissions::from_mode(0o500))
            .expect("seal config dir");
        let probe = self.dir.path().join("write-probe");
        if std::fs::write(&probe, b"probe").is_ok() {
            std::fs::remove_file(&probe).ok();
            self.unseal_config_dir();
            return false;
        }
        true
    }

    /// Restore write permission so the temp directory can be cleaned up.
    fn unseal_config_dir(&self) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(self.dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("unseal config dir");
    }

    /// Nothing peer-deleting reached the RIB.
    fn assert_no_rib_peer_deletion(&mut self, peer: IpAddr) {
        while let Ok(update) = self.rib_rx.try_recv() {
            assert!(
                !matches!(update, RibUpdate::PeerDeleted { peer: deleted } if deleted == peer),
                "a rejected mutation must not reap the peer's RIB state"
            );
        }
    }

    async fn delete_neighbor(&self, address: &str) -> Result<(), tonic::Status> {
        use rustbgpd_api::proto::neighbor_service_server::NeighborService as _;

        tokio::time::timeout(
            Duration::from_secs(10),
            self.service.delete_neighbor(tonic::Request::new(
                rustbgpd_api::proto::DeleteNeighborRequest {
                    address: address.to_string(),
                    interface: String::new(),
                },
            )),
        )
        .await
        .expect("delete_neighbor must answer, not hang")
        .map(|_| ())
    }

    async fn add_neighbor(&self, address: &str, remote_asn: u32) -> Result<(), tonic::Status> {
        self.add_presence_neighbor(
            rustbgpd_api::proto::NeighborConfig {
                address: address.to_string(),
                remote_asn,
                hold_time: 90,
                ..Default::default()
            },
            &[],
        )
        .await
    }

    #[expect(
        clippy::default_trait_access,
        reason = "the API crate does not re-export prost_types::FieldMask"
    )]
    async fn add_presence_neighbor(
        &self,
        config: rustbgpd_api::proto::NeighborConfig,
        paths: &[&str],
    ) -> Result<(), tonic::Status> {
        use rustbgpd_api::proto::neighbor_service_server::NeighborService as _;

        let mut intent = rustbgpd_api::proto::NeighborCreateIntent {
            config: Some(config),
            override_mask: Some(Default::default()),
        };
        intent.override_mask.as_mut().unwrap().paths =
            paths.iter().map(|path| (*path).to_string()).collect();
        tokio::time::timeout(
            Duration::from_secs(10),
            self.service.add_neighbor(tonic::Request::new(
                rustbgpd_api::proto::AddNeighborRequest {
                    intent: Some(intent),
                },
            )),
        )
        .await
        .expect("presence-aware add must answer, not hang")
        .map(|_| ())
    }

    async fn session_history(&self) -> Vec<rustbgpd_api::peer_types::SessionLifecycleEvent> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::QuerySessionEventHistory {
                peer: None,
                event_types: BTreeSet::new(),
                limit: 0,
                reply: reply_tx,
            })
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }

    async fn runtime_config(&self) -> Config {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::RuntimeConfigSnapshot { reply: reply_tx })
            .await
            .unwrap();
        let snapshot = reply_rx.await.unwrap().unwrap();
        Config::load_toml_with_diagnostics(&snapshot.toml, "actor runtime snapshot").unwrap()
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario verifies raw, resolved, persisted, actor, and reload parity"
)]
async fn presence_create_preserves_raw_inheritance_over_disk_actor_and_reload() {
    const INHERITED: &str = "10.0.0.9";
    const MASKED: &str = "10.0.0.10";
    const IPV6_DEFAULT: &str = "2001:db8::9";
    const RR_CLIENT: &str = "10.0.0.14";
    let rig = PersistenceRig::start();
    assert!(
        Config::load_with_diagnostics(rig.config_path.to_str().unwrap())
            .unwrap()
            .peer_groups
            .contains_key("ix-members")
    );
    assert!(
        rig.runtime_config()
            .await
            .peer_groups
            .contains_key("ix-members")
    );

    rig.add_presence_neighbor(
        rustbgpd_api::proto::NeighborConfig {
            address: INHERITED.into(),
            remote_asn: 65009,
            peer_group: "ix-members".into(),
            ..Default::default()
        },
        &[],
    )
    .await
    .unwrap();
    let inherited = rig.peer(INHERITED).await.unwrap();
    assert_eq!(
        inherited.families,
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
    );
    assert!(inherited.route_server_client && inherited.per_client_best);
    assert_eq!(
        inherited.local_role,
        Some(rustbgpd_wire::BgpRole::RouteServer)
    );
    assert!(inherited.strict_role && inherited.add_path_receive && inherited.add_path_send);
    assert_eq!(inherited.add_path_send_max, 4);
    assert_eq!(inherited.paths_limit_receive_max, 8);

    rig.add_presence_neighbor(
        rustbgpd_api::proto::NeighborConfig {
            address: MASKED.into(),
            remote_asn: 65010,
            peer_group: "ix-members".into(),
            families: vec!["ipv6_unicast".into()],
            ..Default::default()
        },
        &[
            "families",
            "route_server_client",
            "per_client_best",
            "strict_role",
            "add_path_receive",
            "add_path_send",
            "add_path_send_max",
            "paths_limit_receive_max",
        ],
    )
    .await
    .unwrap();
    let masked = rig.peer(MASKED).await.unwrap();
    assert_eq!(masked.families, vec![(Afi::Ipv6, Safi::Unicast)]);
    assert!(!masked.route_server_client && !masked.per_client_best && !masked.strict_role);
    assert!(!masked.add_path_receive && !masked.add_path_send);

    rig.add_presence_neighbor(
        rustbgpd_api::proto::NeighborConfig {
            address: IPV6_DEFAULT.into(),
            remote_asn: 65011,
            ..Default::default()
        },
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        rig.peer(IPV6_DEFAULT).await.unwrap().families,
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
        "presence-aware IPv6 omission must reach the resolver, not legacy IPv4 materialization"
    );
    rig.add_presence_neighbor(
        rustbgpd_api::proto::NeighborConfig {
            address: RR_CLIENT.into(),
            remote_asn: 65001,
            peer_group: "rr-clients".into(),
            ..Default::default()
        },
        &[],
    )
    .await
    .unwrap();
    let rr = rig.peer(RR_CLIENT).await.unwrap();
    assert!(rr.route_reflector_client);
    assert_eq!(rr.families, vec![(Afi::Ipv6, Safi::Unicast)]);

    let disk = Config::load_with_diagnostics(rig.config_path.to_str().unwrap()).unwrap();
    let actor = rig.runtime_config().await;
    for snapshot in [&disk, &actor] {
        let raw = snapshot
            .neighbors
            .iter()
            .find(|neighbor| neighbor.address == INHERITED)
            .unwrap();
        assert!(raw.families.is_empty());
        assert_eq!(raw.route_server_client, None);
        assert_eq!(raw.per_client_best, None);
        // `ttl_security` (and `md5_password`) are deliberately absent from
        // the fixture group: a presence-create resolving either is rejected
        // at runtime because inbound listener enforcement is
        // startup/SIGHUP-pinned (covered by
        // `runtime_create_peer_rejects_listener_enforced_group_auth`).
        assert_eq!(raw.ttl_security, None);
        assert_eq!(raw.graceful_restart, None);
        assert_eq!(raw.role, None);
        assert_eq!(raw.strict_role, None);
        assert_eq!(raw.add_path, None);
        let effective = snapshot.resolve_neighbor(raw).unwrap();
        assert!(!effective.transport_config.peer.graceful_restart);

        let raw = snapshot
            .neighbors
            .iter()
            .find(|neighbor| neighbor.address == MASKED)
            .unwrap();
        assert_eq!(raw.families, vec!["ipv6_unicast"]);
        assert_eq!(raw.route_server_client, Some(false));
        assert_eq!(raw.per_client_best, Some(false));
        assert_eq!(raw.strict_role, Some(false));
        let add_path = raw.add_path.as_ref().unwrap();
        assert!(!add_path.receive && !add_path.send);
        let effective = snapshot.resolve_neighbor(raw).unwrap();
        assert!(!effective.transport_config.peer.add_path_receive);
        assert!(!effective.transport_config.peer.add_path_send);

        let raw = snapshot
            .neighbors
            .iter()
            .find(|neighbor| neighbor.address == RR_CLIENT)
            .unwrap();
        assert!(raw.families.is_empty());
        assert_eq!(raw.route_reflector_client, None);
        assert_eq!(raw.graceful_restart, None);
        let effective = snapshot.resolve_neighbor(raw).unwrap();
        assert!(effective.transport_config.route_reflector_client);
        assert_eq!(
            effective.transport_config.cluster_id,
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert!(!effective.transport_config.peer.graceful_restart);
    }
}

#[tokio::test]
async fn presence_create_rejections_leave_no_disk_history_or_live_half_state() {
    let rig = PersistenceRig::start();
    let config_before = rig.config_bytes();
    let history_before = rig.session_history().await;

    let actor_error = rig
        .add_presence_neighbor(
            rustbgpd_api::proto::NeighborConfig {
                address: PersistenceRig::PEER.into(),
                remote_asn: 65002,
                ..Default::default()
            },
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(actor_error.code(), tonic::Code::AlreadyExists);
    assert_eq!(rig.config_bytes(), config_before);
    assert_eq!(rig.session_history().await, history_before);
    assert!(rig.peer(PersistenceRig::PEER).await.is_some());

    let effective_error = rig
        .add_presence_neighbor(
            rustbgpd_api::proto::NeighborConfig {
                address: "10.0.0.12".into(),
                remote_asn: 65012,
                peer_group: "ix-members".into(),
                ..Default::default()
            },
            &["route_server_client"],
        )
        .await
        .unwrap_err();
    assert_eq!(effective_error.code(), tonic::Code::InvalidArgument);
    assert!(
        effective_error.message().contains("per_client_best"),
        "{effective_error}"
    );
    assert!(rig.peer("10.0.0.12").await.is_none());
    assert_eq!(rig.config_bytes(), config_before);
    assert_eq!(rig.session_history().await, history_before);

    if !rig.seal_config_dir() {
        return;
    }
    let persistence_error = rig
        .add_presence_neighbor(
            rustbgpd_api::proto::NeighborConfig {
                address: "10.0.0.13".into(),
                remote_asn: 65013,
                peer_group: "ix-members".into(),
                ..Default::default()
            },
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(
        persistence_error.code(),
        tonic::Code::FailedPrecondition,
        "{persistence_error}"
    );
    assert!(rig.peer("10.0.0.13").await.is_none());
    assert_eq!(rig.config_bytes(), config_before);
    assert_eq!(rig.session_history().await, history_before);
    rig.unseal_config_dir();
    assert!(!rig.staged_temp_path().exists());
}

#[test]
fn presence_create_policy_event_keeps_the_neighbor_sentinel() {
    let raw = rustbgpd_api::peer_types::PresenceAwareNeighborCreate {
        address: "10.0.0.9".parse().unwrap(),
        interface: None,
        remote_asn: 65009,
        description: None,
        peer_group: None,
        hold_time: None,
        min_hold_time: None,
        send_hold_time: None,
        max_prefixes: None,
        max_prefix_restart_seconds: None,
        remove_private_as: None,
        local_role: None,
        families: None,
        required_families: None,
        route_server_client: None,
        per_client_best: None,
        strict_role: None,
        add_path: None,
    };
    let event = ConfigEvent::PresenceAwareNeighborAdded {
        spec: Box::new(raw),
        ack: None,
    };
    assert_eq!(
        PeerManager::policy_event_details(&event),
        ("change", "neighbor", String::new(), None)
    );
}

/// A `DeleteNeighbor` that cannot persist must return without touching the
/// session. Applying first and compensating afterwards cannot satisfy this:
/// the re-added peer is a *new* session with a new identity, a zeroed uptime,
/// zeroed counters, and a fresh metric series, and the teardown never reaches
/// the operator's flap count.
#[tokio::test]
async fn neighbor_delete_persistence_failure_leaves_the_session_untouched() {
    let mut rig = PersistenceRig::start();
    let peer_addr: IpAddr = PersistenceRig::PEER.parse().unwrap();

    let before = rig
        .peer(PersistenceRig::PEER)
        .await
        .expect("peer is present before the rejected delete");
    assert_eq!(before.state, SessionState::Established);
    assert!(
        before.updates_received > 0 && before.updates_sent > 0,
        "the probe session must carry counters a rebuilt session could not reproduce"
    );
    let before_observable = observable_session(&before);
    let config_before = rig.config_bytes();

    if !rig.seal_config_dir() {
        return;
    }

    let error = rig
        .delete_neighbor(PersistenceRig::PEER)
        .await
        .expect_err("an unwritable config directory must reject the delete");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{error}");
    assert!(
        error.message().contains("config persistence failed"),
        "{}",
        error.message()
    );

    let after = rig
        .peer(PersistenceRig::PEER)
        .await
        .expect("the rejected delete must leave the peer in the list");
    assert_eq!(
        observable_session(&after),
        before_observable,
        "the session must be untouched, not restored: a rebuilt session reports a \
         zeroed uptime and zeroed counters"
    );
    assert_eq!(after.remote_asn, before.remote_asn);
    assert_eq!(after.description, before.description);

    rig.assert_no_rib_peer_deletion(peer_addr);

    assert_eq!(
        rig.config_bytes(),
        config_before,
        "the config file must be byte-for-byte unchanged"
    );
    let staged = rig.staged_temp_path();
    rig.unseal_config_dir();
    assert!(
        !staged.exists(),
        "no staged temp file may be left behind: {}",
        staged.display()
    );
}

/// An `AddNeighbor` that cannot persist must create nothing at all — not a
/// peer that is created and then deleted again, and not a config file edit.
#[tokio::test]
async fn neighbor_add_persistence_failure_creates_no_session() {
    const NEW_PEER: &str = "10.0.0.9";

    let rig = PersistenceRig::start();
    let existing_before = observable_session(
        &rig.peer(PersistenceRig::PEER)
            .await
            .expect("pre-existing peer is present"),
    );
    let config_before = rig.config_bytes();

    if !rig.seal_config_dir() {
        return;
    }

    let error = rig
        .add_neighbor(NEW_PEER, 65009)
        .await
        .expect_err("an unwritable config directory must reject the add");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{error}");
    assert!(
        error.message().contains("config persistence failed"),
        "{}",
        error.message()
    );

    assert!(
        rig.peer(NEW_PEER).await.is_none(),
        "the rejected add must never create the peer — not even briefly"
    );
    assert_eq!(
        observable_session(
            &rig.peer(PersistenceRig::PEER)
                .await
                .expect("pre-existing peer survives an unrelated rejected add")
        ),
        existing_before,
        "an unrelated peer must not be disturbed by a rejected add"
    );

    assert_eq!(
        rig.config_bytes(),
        config_before,
        "the config file must be byte-for-byte unchanged"
    );
    let staged = rig.staged_temp_path();
    rig.unseal_config_dir();
    assert!(
        !staged.exists(),
        "no staged temp file may be left behind: {}",
        staged.display()
    );
}

/// The success path still works: staging before applying must not turn a
/// writable config into a no-op.
#[tokio::test]
async fn neighbor_delete_persists_and_applies_when_the_config_is_writable() {
    let rig = PersistenceRig::start();
    assert!(rig.peer(PersistenceRig::PEER).await.is_some());

    rig.delete_neighbor(PersistenceRig::PEER)
        .await
        .expect("a writable config directory must accept the delete");

    assert!(
        rig.peer(PersistenceRig::PEER).await.is_none(),
        "the accepted delete must remove the session"
    );
    let persisted = String::from_utf8(rig.config_bytes()).expect("config is UTF-8");
    assert!(
        !persisted.contains(PersistenceRig::PEER),
        "the accepted delete must remove the neighbor from disk: {persisted}"
    );
    assert!(
        persisted.contains(PersistenceRig::OTHER_PEER),
        "the accepted delete must not disturb the other neighbor: {persisted}"
    );
    assert!(
        !rig.staged_temp_path().exists(),
        "the staged temp file must be renamed into place, not left behind"
    );
}

/// A whole-peer Route Refresh is bounded by what the session negotiated: a
/// configured family the peer never accepted has no `AdjRibIn` to re-evaluate,
/// so it is skipped rather than failing the refresh. An explicitly requested
/// family still errors.
///
/// Load-bearing: dropping the `refresh_all` guard in `soft_reset_in` makes the
/// first case red; dropping the whole arm makes it red the other way, because
/// every policy edit on an asymmetric session would fail.
#[tokio::test]
async fn soft_reset_in_skips_configured_families_the_peer_never_negotiated() {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let refreshed = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&refreshed);
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                // IPv4 unicast negotiated, IPv6 unicast configured but not.
                PeerCommand::SendRouteRefresh { afi, safi, reply } => {
                    if (afi, safi) == (Afi::Ipv4, Safi::Unicast) {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ =
                            reply.send(Err(PeerCommandError::FamilyNotNegotiated { afi, safi }));
                    }
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } => break,
                _ => {}
            }
        }
        Ok(())
    });

    let mut mgr = test_peer_manager();
    insert_test_managed_peer(
        &mut mgr,
        addr,
        PeerHandle::from_parts(session_tx, task),
        false,
    );
    mgr.peers
        .get_mut(&key(addr))
        .unwrap()
        .transport_config
        .peer
        .families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];

    mgr.soft_reset_in(key(addr), Vec::new())
        .await
        .expect("an un-negotiated configured family must not fail the whole refresh");
    assert_eq!(
        refreshed.load(Ordering::SeqCst),
        1,
        "the negotiated family must still be refreshed"
    );

    mgr.soft_reset_in(key(addr), vec![(Afi::Ipv6, Safi::Unicast)])
        .await
        .expect_err("an explicitly named un-negotiated family still errors");

    let managed = mgr.peers.remove(&key(addr)).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
}

/// A forward apply that fails *at the Route Refresh step* may already have
/// delivered one family's request: `soft_reset_in` queues families
/// sequentially, so IPv4 can be accepted before IPv6 fails, and a timeout is
/// ambiguous either way. Adj-RIB-In may therefore already sit on the candidate
/// policy. When the rollback's own refresh then fails, that is real unfinished
/// convergence debt and `pending_refresh` must stay armed.
///
/// Load-bearing: this is the case `forward_completed = false` used to swallow.
/// With the pre-fix `BestEffortRestorePrior { pending_refresh: false }`
/// selection, the rollback clears the flag and the final assertion fails.
///
/// Its discriminator is
/// `rfc8212_import_presence_edit_fails_when_the_peer_flaps_after_preflight`,
/// which asserts the opposite for a forward that never reached the refresh
/// step at all. Neither test means anything without the other.
#[tokio::test]
async fn rollback_arms_retry_when_a_partially_delivered_refresh_cannot_be_undone() {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11));
    let ipv4_refreshes = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&ipv4_refreshes);
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let mut state = policy_test_peer_state(addr, SessionState::Established);
                    state.negotiated_session = Some(test_negotiated_session(true));
                    let _ = reply.send(state);
                }
                // Both families negotiated. IPv4's request is accepted and
                // queued; IPv6's send fails. Deliberately NOT
                // `FamilyNotNegotiated`, which a whole-peer refresh skips.
                PeerCommand::SendRouteRefresh { afi, safi, reply } => {
                    if (afi, safi) == (Afi::Ipv4, Safi::Unicast) {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ = reply
                            .send(Err(PeerCommandError::SendFailed("link wedged".to_string())));
                    }
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } => break,
                _ => {}
            }
        }
        Ok(())
    });

    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    insert_test_managed_peer(
        &mut mgr,
        addr,
        PeerHandle::from_parts(session_tx, task),
        false,
    );
    {
        let managed = mgr.peers.get_mut(&key(addr)).unwrap();
        managed.transport_config.peer.families =
            vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        managed.import_policy = Some(deny_policy_chain());
        managed.export_policy = Some(distinct_deny_policy_chain(3));
    }

    // Export is unchanged, so no RIB replacement runs and the rollback is
    // purely the import chain plus its refresh.
    let error = mgr
        .apply_resolved_policy_snapshot(vec![rustbgpd_api::peer_types::ResolvedPeerPolicy {
            address: addr,
            interface: None,
            import_policy: Some(distinct_deny_policy_chain(5)),
            export_policy: Some(distinct_deny_policy_chain(3)),
        }])
        .await
        .expect_err("a failed Route Refresh fails the forward apply");
    assert!(
        error.contains("already-applied peers restored"),
        "the forward failure must have rolled back: {error}"
    );
    assert!(
        ipv4_refreshes.load(Ordering::SeqCst) >= 1,
        "the IPv4 request must have been accepted before IPv6 failed — otherwise \
         this test proves nothing about a partially delivered refresh"
    );

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(
        managed.import_policy,
        Some(deny_policy_chain()),
        "rollback must restore the prior import chain"
    );
    assert!(
        managed.pending_refresh,
        "a partially delivered forward refresh whose rollback refresh also failed \
         leaves real convergence debt; retry intent must stay armed"
    );

    let managed = mgr.peers.remove(&key(addr)).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
    drop(mgr);
    rib.await.unwrap();
}
