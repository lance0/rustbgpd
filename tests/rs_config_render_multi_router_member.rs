//! Real-daemon proof for an IXP Manager member with two router connections
//! rendered by `rs-config-render`: one `[[neighbors]]` per VLAN interface,
//! both sessions establish from the same ASN, and a route whose NEXT_HOP is
//! not the announcing session's own address is retained under the
//! `next_hop_ownership` reason that the cookbook documents.
//!
//! This test uses loopback member addresses, and both announcements carry a
//! foreign next hop, so it pins only the two-session shape and the
//! `next_hop_ownership` reason token. RFC 4271 §6.3 makes a 127/8 NEXT_HOP
//! invalid before ownership is evaluated, so accepting a member's own next
//! hop and rejecting a sibling router's next hop both need routable member
//! addresses; those two cases were proven separately against FRR, not here.

#![cfg(unix)]

#[path = "support/mod.rs"]
mod support;

use std::fs;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rs_config_render::ixp_manager;
use rs_config_render::ixp_manager_host::RenderBinding;
use rustbgpd_wire::attribute::{AsPath, AsPathSegment, Origin, PathAttribute};
use rustbgpd_wire::message::{Message, encode_message};
use rustbgpd_wire::open::OpenMessage;
use rustbgpd_wire::update::UpdateMessage;
use rustbgpd_wire::{Afi, Capability, Safi};
use serde_json::{Value, json};

const HANDLE: &str = "rs1-lan1-ipv4";
const MEMBER_ASN: u32 = 65001;
const ROUTER_A: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const ROUTER_B: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const FOREIGN_NEXT_HOP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set permissions");
}

fn rbgp(addr: &str, args: &[&str]) -> Value {
    let output = Command::new(support::rbgp_binary())
        .args(["--addr", addr, "--json"])
        .args(args)
        .output()
        .expect("run rbgp");
    assert!(
        output.status.success(),
        "rbgp {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("rbgp JSON")
}

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    predicate()
}

/// One member router: OPEN as the member ASN from its own loopback address,
/// KEEPALIVE, then announce `prefix` with `next_hop`. The stream must stay
/// alive for the session to survive; the daemon's messages are left unread.
fn router(source: Ipv4Addr, daemon: SocketAddr, prefix: [u8; 3], next_hop: Ipv4Addr) -> TcpStream {
    let socket =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).expect("socket");
    socket
        .bind(&SocketAddr::new(source.into(), 0).into())
        .expect("bind member address");
    socket
        .connect(&daemon.into())
        .expect("connect to the daemon");
    let mut stream: TcpStream = socket.into();
    let open = Message::Open(OpenMessage {
        version: 4,
        my_as: 23456,
        hold_time: 90,
        // Above the daemon's 192.0.2.1 so RFC 6286 collision resolution
        // keeps this inbound stream over the daemon's own connect attempt.
        bgp_identifier: Ipv4Addr::new(240, 9, 1, source.octets()[3]),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: MEMBER_ASN },
        ],
    });
    let mut attrs = Vec::new();
    rustbgpd_wire::attribute::encode_path_attributes(
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![MEMBER_ASN])],
            }),
            PathAttribute::NextHop(next_hop),
        ],
        &mut attrs,
        true,
        false,
    )
    .expect("encode path attributes");
    let update = Message::Update(UpdateMessage {
        withdrawn_routes: bytes::Bytes::new(),
        path_attributes: attrs.into(),
        nlri: bytes::Bytes::from(vec![24, prefix[0], prefix[1], prefix[2]]),
    });
    for message in [&open, &Message::Keepalive, &update] {
        stream
            .write_all(&encode_message(message).expect("encode"))
            .expect("write to the daemon");
    }
    stream
}

#[test]
fn two_router_member_sessions_establish_and_foreign_next_hops_are_rejected() {
    let evidence = support::RetainOnPanic::new(
        tempfile::Builder::new()
            .prefix("rs-multi-router-")
            .tempdir()
            .expect("temporary directory"),
    );
    let root = evidence.path();
    set_mode(root, 0o700);
    let runtime = root.join(HANDLE);
    let candidate = root.join("candidate");
    for path in [&runtime, &candidate] {
        fs::create_dir(path).expect("create directory");
        set_mode(path, 0o700);
    }
    let bgp_port = TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("port")
        .port();
    let client = |vli: u64, address: Ipv4Addr| {
        json!({
            "customer_id": 1, "vlan_interface_id": vli, "name": "TwoRouterMember",
            "asn": MEMBER_ASN, "address": address.to_string(),
            "peering_ips": [ROUTER_A.to_string(), ROUTER_B.to_string()],
            "max_prefix": 100, "auth": {"type": "none"},
            "irr_filter": true, "more_specifics": false,
            "origins": [MEMBER_ASN], "prefixes": ["45.45.44.0/22"]
        })
    };
    let export = json!({
        "schema": "rustbgpd.ixp-manager.router-config/v2",
        "ixp_manager": {"version": "7.4.0"},
        "router": {
            "handle": HANDLE, "type": "route-server", "protocol": 4, "asn": 65500,
            "router_id": "192.0.2.1", "peering_ip": "127.0.0.1", "listen_port": bgp_port,
            "vlan_id": 1, "quarantine": false, "bgp_lc": true, "rfc1997_passthru": false,
            "rpki": false, "skip_md5": true
        },
        "policy": {
            "minimum_prefix_length": 24, "rtr_caches": [],
            "no_transit": {"source": "IXP_NO_TRANSIT_ASNS_OVERRIDE", "asns": []}
        },
        "clients": [client(1, ROUTER_A), client(2, ROUTER_B)],
        "ui_filters": [],
        "unsupported": {"active_ui_filters": [], "route_server_skin_files": []},
        "complete": {
            "handle": HANDLE, "client_count": 2, "ui_filter_count": 0,
            "marker": format!("END_OF_RUSTBGPD_IXP_MANAGER_CONFIG_{HANDLE}")
        }
    });
    let daemon_bin = Path::new(env!("CARGO_BIN_EXE_rustbgpd"));
    let binding = RenderBinding::new(HANDLE, &runtime).expect("render binding");
    ixp_manager::write_checked_candidate_bytes(
        &serde_json::to_vec(&export).expect("serialize export"),
        &candidate,
        300,
        daemon_bin,
        &binding,
    )
    .expect("two-router member renders and passes the strict check");
    let config = fs::read_to_string(candidate.join("config.toml")).expect("rendered config");
    assert_eq!(config.matches("[[neighbors]]").count(), 2, "{config}");
    assert_eq!(config.matches("remote_asn = 65001").count(), 2, "{config}");
    assert_eq!(
        config
            .matches("next_hop_ownership = \"strict_peer\"")
            .count(),
        2,
        "{config}"
    );

    let log = fs::File::create(root.join("daemon.log")).expect("daemon log");
    let _daemon = Daemon(
        Command::new(daemon_bin)
            .arg(candidate.join("config.toml"))
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn rustbgpd"),
    );
    let daemon_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bgp_port);
    assert!(
        wait_until(Duration::from_secs(20), || TcpStream::connect(daemon_addr)
            .is_ok()),
        "daemon listens on {daemon_addr}"
    );
    let grpc = format!("unix://{}", runtime.join("grpc.sock").display());
    // Router A announces with a next hop that is neither of the member's
    // addresses; router B announces a second prefix the same way.
    let _router_a = router(ROUTER_A, daemon_addr, [45, 45, 45], FOREIGN_NEXT_HOP);
    let _router_b = router(ROUTER_B, daemon_addr, [45, 45, 46], FOREIGN_NEXT_HOP);

    let established = wait_until(Duration::from_secs(20), || {
        rbgp(&grpc, &["neighbor"])
            .as_array()
            .is_some_and(|neighbors| {
                neighbors.len() == 2
                    && neighbors.iter().all(|n| {
                        n["state"] == "Established" && n["description"] == "TwoRouterMember"
                    })
            })
    });
    assert!(established, "{:#}", rbgp(&grpc, &["neighbor"]));

    for (address, prefix) in [(ROUTER_A, "45.45.45.0/24"), (ROUTER_B, "45.45.46.0/24")] {
        let address = address.to_string();
        let mut rejected = Value::Null;
        let retained = wait_until(Duration::from_secs(10), || {
            rejected = rbgp(&grpc, &["rib", "received", &address, "--rejected"]);
            !rejected["rejected_routes"]
                .as_array()
                .is_none_or(Vec::is_empty)
        });
        assert!(retained, "{address}: {rejected:#}");
        let routes = rejected["rejected_routes"].as_array().unwrap();
        assert_eq!(routes.len(), 1, "{address}: {rejected:#}");
        assert_eq!(routes[0]["prefix"], prefix, "{address}: {rejected:#}");
        assert_eq!(
            routes[0]["reason"], "next_hop_ownership",
            "{address}: {rejected:#}"
        );
        assert_eq!(
            routes[0]["next_hop"],
            FOREIGN_NEXT_HOP.to_string(),
            "{address}: {rejected:#}"
        );
        let accepted = rbgp(&grpc, &["rib", "received", &address, "--count"]);
        assert_eq!(accepted["total_count"], 0, "{address}: {accepted:#}");
    }
}
