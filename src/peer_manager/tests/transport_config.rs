use super::*;

#[test]
fn build_transport_config_preserves_local_ipv6_nexthop() {
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let nh: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    config.local_ipv6_nexthop = Some(nh);

    let transport = mgr.build_transport_config(&config);
    assert_eq!(transport.local_ipv6_nexthop, Some(nh));
}

#[test]
fn build_transport_config_threads_policy_explain_settings() {
    // ADR-0073: both [policy.explain] knobs must propagate from the
    // daemon config snapshot into the per-session TransportConfig.
    // A regression here would silently leave `enabled` at its
    // TransportConfig::new default (true), ignoring the operator's
    // off-switch in production sessions.
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    mgr.current_config.policy.explain.enabled = false;
    mgr.current_config.policy.explain.cache_size = 256;

    let config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    let transport = mgr.build_transport_config(&config);
    assert!(!transport.explain_enabled, "enabled must propagate");
    assert_eq!(
        transport.explain_cache_size, 256,
        "cache_size must propagate"
    );
}

#[test]
fn build_transport_config_threads_reject_retention_settings() {
    // LAN-472: both [policy.reject_retention] knobs must propagate from
    // the daemon config snapshot into the per-session TransportConfig —
    // same threading hazard as the [policy.explain] siblings above.
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    mgr.current_config.policy.reject_retention.enabled = false;
    mgr.current_config.policy.reject_retention.capacity = 64;

    let config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    let transport = mgr.build_transport_config(&config);
    assert!(
        !transport.reject_retention_enabled,
        "enabled must propagate"
    );
    assert_eq!(
        transport.reject_retention_capacity, 64,
        "capacity must propagate"
    );
}

#[test]
fn build_transport_config_preserves_route_server_client() {
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    config.route_server_client = true;

    let transport = mgr.build_transport_config(&config);
    assert!(transport.route_server_client);
}

/// RFC 7947 §2.3.2 / ADR-0101: `per_client_best` on a neighbor config
/// must reach the transport session config — the session-up event
/// registers the mode with the RIB manager from exactly this field.
/// M83 caught this dropped at the `build_transport_config` seam while
/// the RIB/CLI layers (wired above it) tested green.
#[test]
fn build_transport_config_preserves_per_client_best() {
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    config.route_server_client = true;
    config.per_client_best = true;

    let transport = mgr.build_transport_config(&config);
    assert!(transport.per_client_best);
}

/// RFC 9234 OTC for dynamic/gRPC-added peers: `local_role` set on a
/// runtime `PeerConfig` (the `AddNeighbor` / dynamic-range path) reaches
/// the transport session config verbatim — transport attaches OTC on
/// eBGP egress for `Provider`/`Peer`/`RouteServer` roles from exactly
/// this field (`otc_egress_adds_local_asn_for_provider_peer_and_route_server`
/// in the transport crate pins the attach itself).
#[test]
fn build_transport_config_preserves_local_role_for_otc() {
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    config.route_server_client = true;
    config.local_role = Some(rustbgpd_wire::BgpRole::RouteServer);

    let transport = mgr.build_transport_config(&config);
    assert_eq!(
        transport.peer.local_role,
        Some(rustbgpd_wire::BgpRole::RouteServer)
    );
}

/// Class guard for the "config knob parsed/validated/displayed but never
/// reaches its runtime consumer" bug (#702, `per_client_best` dropped in
/// `build_transport_config`; caught only by the M83 real-stack lab because
/// the RIB/CLI unit layers are wired above this seam). This pins the
/// `PeerManagerNeighborConfig` → `TransportConfig` seam as a whole so a
/// future dropped copy fails a unit test, not a lab.
///
/// Two guards, deliberately layered:
///
/// 1. **Compile-time (new field):** the destructure below names EVERY
///    field with NO `..`. Add a field to `PeerManagerNeighborConfig` and
///    THIS test stops compiling — forcing an explicit decision: transport
///    field (assert it) or one of the three non-transport fields
///    (`description`, `import_policy`, `export_policy` — RIB/label side,
///    not a session property; add it to the `_`-bound exclusions).
///
/// 2. **Run-time (dropped copy of an existing field):** every transport
///    field is set to a non-default sentinel and asserted against the
///    resulting `TransportConfig`. A field left at `TransportConfig::new`'s
///    default would pass a weaker test even with the copy missing, so the
///    sentinels are chosen to differ from those defaults.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the inventory test keeps every transport field in one exact assertion"
)]
fn build_transport_config_reflects_every_transport_field() {
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let config = PeerManagerNeighborConfig {
        min_hold_time: Some(30),
        address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        interface: Some("test-if".to_string()),
        scope_id: Some(7),
        remote_asn: 65002,
        description: "sentinel-description".to_string(),
        peer_group: Some("rr-clients".to_string()),
        hold_time: Some(240),
        send_hold_time: Some(600),
        slow_peer_threshold_pct: 77,
        slow_peer_duration: 120,
        slow_peer_isolation: true,
        max_prefixes: Some(1000),
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefix_restart_seconds: Some(30),
        md5_password: Some("hunter2".into()),
        tcp_ao: Some(
            rustbgpd_transport::TcpAoConfig {
                key: "ao-secret".into(),
                send_id: 11,
                recv_id: 22,
                algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
                preferred: true,
                deprecated: false,
            }
            .into(),
        ),
        ttl_security: true,
        families: vec![(Afi::Ipv6, Safi::Unicast)],
        required_families: vec![(Afi::Ipv6, Safi::Unicast)],
        graceful_restart: true,
        gr_restart_time: 300,
        gr_peer_restart_time_max: 301,
        gr_stale_routes_time: 720,
        llgr_stale_time: 3600,
        gr_restart_eligible: false,
        local_ipv6_nexthop: Some("2001:db8::1".parse().unwrap()),
        route_reflector_client: true,
        orr_vantage: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        route_server_client: true,
        per_client_best: true,
        next_hop_ownership_strict_peer: true,
        interpret_rfc1997: false,
        rs_control_communities: true,
        remove_private_as: rustbgpd_transport::RemovePrivateAs::All,
        add_path_receive: true,
        add_path_send: true,
        add_path_send_max: 4,
        paths_limit_receive_max: 3,
        local_role: Some(rustbgpd_wire::BgpRole::RouteServer),
        strict_role: true,
        prefix_orf_receive: true,
        disable_ipv4_unicast: true,
        import_policy: None,
        export_policy: None,
    };

    // Destructure with NO `..`: a new field breaks compilation here.
    let PeerManagerNeighborConfig {
        address,
        interface,
        scope_id,
        remote_asn,
        description: _description, // NON-TRANSPORT: operator label only.
        peer_group,
        hold_time,
        send_hold_time,
        max_prefixes,
        max_prefixes_ipv4,
        max_prefixes_ipv6,
        max_prefix_restart_seconds: _max_prefix_restart_seconds,
        md5_password,
        tcp_ao,
        ttl_security,
        families,
        required_families,
        graceful_restart,
        gr_restart_time,
        gr_peer_restart_time_max,
        gr_stale_routes_time,
        llgr_stale_time,
        gr_restart_eligible,
        local_ipv6_nexthop,
        route_reflector_client,
        orr_vantage,
        route_server_client,
        per_client_best,
        next_hop_ownership_strict_peer,
        slow_peer_threshold_pct,
        slow_peer_duration,
        slow_peer_isolation,
        interpret_rfc1997,
        rs_control_communities,
        remove_private_as,
        add_path_receive,
        add_path_send,
        add_path_send_max,
        paths_limit_receive_max,
        local_role,
        strict_role,
        prefix_orf_receive,
        disable_ipv4_unicast,
        import_policy: _import_policy, // NON-TRANSPORT: RIB-side policy chain.
        export_policy: _export_policy, // NON-TRANSPORT: RIB-side policy chain.
        min_hold_time,
    } = &config;

    let t = mgr.build_transport_config(&config);

    assert_eq!(t.remote_addr.ip(), *address, "address");
    assert_eq!(t.peer_interface, *interface, "interface");
    assert_eq!(t.peer_scope_id, *scope_id, "scope_id");
    assert_eq!(t.peer.remote_asn, *remote_asn, "remote_asn");
    assert_eq!(t.peer_group, *peer_group, "peer_group");
    assert_eq!(t.peer.hold_time, hold_time.unwrap(), "hold_time");
    assert_eq!(t.peer.min_hold_time, *min_hold_time, "min_hold_time");
    assert_eq!(t.max_prefixes_ipv4, *max_prefixes_ipv4, "max_prefixes_ipv4");
    assert_eq!(t.max_prefixes_ipv6, *max_prefixes_ipv6, "max_prefixes_ipv6");
    assert_eq!(
        t.peer.send_hold_time,
        send_hold_time.unwrap(),
        "send_hold_time"
    );
    assert_eq!(t.max_prefixes, *max_prefixes, "max_prefixes");
    assert_eq!(
        t.md5_password.as_ref().map(std::convert::AsRef::as_ref),
        md5_password.as_ref().map(std::convert::AsRef::as_ref),
        "md5_password"
    );
    assert_eq!(t.tcp_ao, *tcp_ao, "tcp_ao");
    assert_eq!(t.ttl_security, *ttl_security, "ttl_security");
    assert_eq!(t.peer.families, *families, "families");
    assert_eq!(
        t.peer.required_families, *required_families,
        "required_families"
    );
    assert_eq!(
        t.peer.graceful_restart, *graceful_restart,
        "graceful_restart"
    );
    assert_eq!(t.peer.gr_restart_time, *gr_restart_time, "gr_restart_time");
    assert_eq!(
        t.gr_peer_restart_time_max, *gr_peer_restart_time_max,
        "gr_peer_restart_time_max"
    );
    assert_eq!(
        t.gr_stale_routes_time, *gr_stale_routes_time,
        "gr_stale_routes_time"
    );
    assert_eq!(t.llgr_stale_time, *llgr_stale_time, "llgr_stale_time");
    // `gr_restart_eligible` only opens the restart window when the manager
    // holds a live `local_gr_restart_until` deadline (none here), so it
    // resolves to `None`. The window→Some path has its own dedicated test
    // (`build_transport_config_sets_restart_window_for_eligible_static_peer`);
    // here we just keep the field named/consumed and pin the disabled outcome.
    assert!(!*gr_restart_eligible);
    assert!(t.gr_restart_until.is_none(), "gr_restart_until");
    assert_eq!(
        t.local_ipv6_nexthop, *local_ipv6_nexthop,
        "local_ipv6_nexthop"
    );
    assert_eq!(
        t.route_reflector_client, *route_reflector_client,
        "route_reflector_client"
    );
    assert_eq!(t.orr_vantage, *orr_vantage, "orr_vantage");
    assert_eq!(
        t.route_server_client, *route_server_client,
        "route_server_client"
    );
    // The #702 field: this is the exact assertion the class of tests exists
    // to make impossible to lose again.
    assert_eq!(t.per_client_best, *per_client_best, "per_client_best");
    // ADR-0107: same #702 threading class — the fixture value (true)
    // differs from the TransportConfig::new default (false), so a
    // dropped assignment fails here rather than shipping silently.
    assert_eq!(
        t.next_hop_ownership_strict_peer, *next_hop_ownership_strict_peer,
        "next_hop_ownership_strict_peer"
    );
    assert_eq!(
        t.slow_peer_threshold_pct, *slow_peer_threshold_pct,
        "slow_peer_threshold_pct"
    );
    assert_eq!(
        t.slow_peer_duration, *slow_peer_duration,
        "slow_peer_duration"
    );
    assert_eq!(
        t.slow_peer_isolation, *slow_peer_isolation,
        "slow_peer_isolation"
    );
    // Same class of pin for the RFC 1997 egress knob: the fixture value
    // (false) differs from the TransportConfig::new default (true), so a
    // dropped assignment fails here rather than shipping silently.
    assert_eq!(t.interpret_rfc1997, *interpret_rfc1997, "interpret_rfc1997");
    // RFC 7947 control communities: fixture value (true) differs from the
    // TransportConfig::new default (false) — a dropped assignment fails
    // here rather than shipping silently.
    assert_eq!(
        t.rs_control_communities, *rs_control_communities,
        "rs_control_communities"
    );
    assert_eq!(t.remove_private_as, *remove_private_as, "remove_private_as");
    assert_eq!(
        t.peer.add_path_receive, *add_path_receive,
        "add_path_receive"
    );
    assert_eq!(t.peer.add_path_send, *add_path_send, "add_path_send");
    assert_eq!(
        t.peer.add_path_send_max, *add_path_send_max,
        "add_path_send_max"
    );
    assert_eq!(
        t.peer.paths_limit_receive_max, *paths_limit_receive_max,
        "paths_limit_receive_max"
    );
    assert_eq!(t.peer.local_role, *local_role, "local_role");
    assert_eq!(t.peer.strict_role, *strict_role, "strict_role");
    assert_eq!(
        t.peer.prefix_orf_receive, *prefix_orf_receive,
        "prefix_orf_receive"
    );
    assert_eq!(
        t.peer.disable_ipv4_unicast, *disable_ipv4_unicast,
        "disable_ipv4_unicast"
    );
}

#[test]
fn build_transport_config_sets_restart_window_for_eligible_static_peer() {
    let (_tx, rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        Some(Instant::now() + Duration::from_secs(30)),
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let mut cfg = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    cfg.gr_restart_eligible = true;

    let transport = mgr.build_transport_config(&cfg);
    assert!(transport.gr_restart_until.is_some());
}

#[test]
fn build_transport_config_omits_restart_window_for_dynamic_peer() {
    let (_tx, rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        Some(Instant::now() + Duration::from_secs(30)),
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let cfg = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);

    let transport = mgr.build_transport_config(&cfg);
    assert!(transport.gr_restart_until.is_none());
}

#[test]
fn build_transport_config_carries_tcp_ao_key() {
    let (_tx, rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let mut cfg = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    cfg.tcp_ao = Some(
        rustbgpd_transport::TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 2,
            algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }
        .into(),
    );

    let transport = mgr.build_transport_config(&cfg);

    let tcp_ao = transport.tcp_ao.as_ref().expect("tcp_ao carried");
    let tcp_ao = &tcp_ao.0[0];
    assert_eq!(tcp_ao.key.as_ref(), "secret");
    assert_eq!(tcp_ao.send_id, 1);
    assert_eq!(tcp_ao.recv_id, 2);
    assert_eq!(
        tcp_ao.algorithm,
        rustbgpd_transport::TcpAoAlgorithm::HmacSha256
    );
}

/// Two-path transport-construction parity. Sessions are built from two
/// independent paths: `Config::resolve_neighbor` (snapshot-sync gRPC peer
/// adds spawn directly from `resolved.transport_config`) and
/// `PeerManager::build_transport_config` (startup + reconcile). Fields have
/// drifted between them before — the ADR-0073 explain knobs, and
/// `cluster_id` (a gRPC-added iBGP RR client ran without `CLUSTER_LIST`
/// prepend or cluster-loop detection until restart). Pin full struct
/// equality so the next added field cannot silently diverge.
#[tokio::test]
async fn resolved_transport_config_matches_build_transport_config() {
    let cluster = Ipv4Addr::new(10, 0, 0, 99);
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        Some(cluster),
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );

    // An iBGP route-reflector client with a few non-default knobs set, so
    // the comparison exercises more than the defaults.
    let mut neighbor = config_neighbor(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65001);
    neighbor.route_reflector_client = Some(true);
    neighbor.hold_time = Some(90);
    neighbor.gr_stale_routes_time = Some(120);

    // Resolve against the manager's own config snapshot (same global
    // ASN/router-id/cluster-id), as the runtime-add path does.
    let mut config = mgr.current_config.clone();
    config.neighbors = vec![neighbor.clone()];
    let resolved = config
        .resolve_neighbor(&neighbor)
        .expect("neighbor resolves");

    let pm_cfg = PeerManager::peer_manager_config_from_resolved(resolved.clone(), false);
    let rebuilt = mgr.build_transport_config(&pm_cfg);

    assert_eq!(
        rebuilt.cluster_id,
        Some(cluster),
        "reconcile path must carry the cluster id"
    );
    assert_eq!(
        resolved.transport_config, rebuilt,
        "resolve_neighbor and build_transport_config must produce identical \
         TransportConfigs — a field set on only one path silently diverges \
         runtime-added peers from restart-built peers"
    );
}
