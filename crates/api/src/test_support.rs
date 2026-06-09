use std::net::IpAddr;

use prometheus::Encoder;
use rustbgpd_fsm::SessionState;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::RemovePrivateAs;

use crate::peer_types::PeerInfo;

pub(crate) fn metrics_text(metrics: &BgpMetrics) -> String {
    let encoder = prometheus::TextEncoder::new();
    let families = metrics.registry().gather();
    let mut out = Vec::new();
    encoder.encode(&families, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

pub(crate) fn peer_info(address: IpAddr) -> PeerInfo {
    PeerInfo {
        address,
        interface: None,
        remote_asn: 65002,
        description: String::new(),
        peer_group: None,
        state: SessionState::Established,
        enabled: true,
        prefix_count: 0,
        hold_time: None,
        max_prefixes: None,
        families: Vec::new(),
        remove_private_as: RemovePrivateAs::Disabled,
        route_server_client: false,
        local_role: None,
        strict_role: false,
        remote_role: None,
        role_negotiated: false,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        updates_received: 0,
        updates_sent: 0,
        notifications_received: 0,
        notifications_sent: 0,
        otc_routes_blocked: 0,
        import_policy_routes_permitted: 0,
        import_policy_routes_denied: 0,
        export_policy_routes_permitted: 0,
        export_policy_routes_denied: 0,
        flap_count: 0,
        uptime_secs: 0,
        last_error: String::new(),
        is_dynamic: false,
        stale: false,
    }
}
