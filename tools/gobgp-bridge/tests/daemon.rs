//! The bridge binary against a real rustbgpd binary: announce, duplicate
//! announce, withdraw, duplicate withdraw, daemon unavailable, and the
//! restart behaviour recorded in the README.
//!
//! `cargo test --workspace` builds the daemon. For a focused run, build it
//! first: `cargo build --locked -p rustbgpd --bin rustbgpd`, then
//! `cargo test --locked -p rustbgpd-gobgp-bridge --test daemon`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rustbgpd_gobgp_bridge::gobgp::{self, gobgp_api_client::GobgpApiClient};
use rustbgpd_gobgp_bridge::rustbgpd::{self as rbgp, rib_service_client::RibServiceClient};
use tonic::Code;
use tonic::transport::{Channel, Endpoint};

const BAN_V4: &[u8] = &[32, 203, 0, 113, 7];
const BAN_V6: &[u8] = &[
    128, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07,
];
const ORIGIN_IGP: &[u8] = &[0x40, 1, 1, 0];
const NEXT_HOP_V4: &[u8] = &[0x40, 3, 4, 192, 0, 2, 1];
const NEXT_HOP_ZERO: &[u8] = &[0x40, 3, 4, 0, 0, 0, 0];
const COMMUNITY_BLACKHOLE: &[u8] = &[0xc0, 8, 4, 0xff, 0xff, 0x02, 0x9a];
const BLACKHOLE: u32 = 0xffff_029a;

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn daemon_binary() -> PathBuf {
    // target/<profile>/deps/<this test> -> target/<profile>/rustbgpd
    let exe = std::env::current_exe().unwrap();
    let path = exe.parent().unwrap().parent().unwrap().join("rustbgpd");
    assert!(
        path.is_file(),
        "missing {}; build it with cargo build --locked -p rustbgpd --bin rustbgpd \
         (cargo test --workspace builds it)",
        path.display()
    );
    path
}

fn write_config(dir: &Path) -> PathBuf {
    let config = dir.join("rustbgpd.toml");
    std::fs::write(
        &config,
        format!(
            r#"
config_epoch = 1
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
listen_addresses = ["127.0.0.1"]
runtime_state_dir = "{dir}/state"
ebgp_requires_policy = false
[global.telemetry]
log_format = "json"
prometheus_addr = "127.0.0.1:0"
[global.telemetry.grpc_uds]
path = "{dir}/api/grpc.sock"
[global.telemetry.grpc_tcp]
address = "127.0.0.1:0"
token_file = "{dir}/daemon.token"
principal = "rustbgpd://bridge/test"
[security.grpc]
enforcement = "tier"
[security.grpc.roles]
"rustbgpd://bridge/test" = "operator"
"#,
            dir = dir.display()
        ),
    )
    .unwrap();
    config
}

/// The daemon's TCP gRPC address, from its JSON log.
async fn tcp_endpoint(dir: &Path) -> String {
    for _ in 0..200 {
        let log = std::fs::read_to_string(dir.join("daemon.stdout.log")).unwrap_or_default();
        if let Some(port) = log
            .split("\"bound_addr\":\"127.0.0.1:")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
        {
            return format!("http://127.0.0.1:{port}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("daemon logged no TCP gRPC address");
}

fn socket(dir: &Path) -> PathBuf {
    dir.join("api/grpc.sock")
}

/// Start the daemon and wait until its socket answers a RIB read.
async fn start_daemon(dir: &Path) -> (Killed, RibServiceClient<Channel>) {
    std::fs::write(dir.join("daemon.token"), "bridge-secret\n").unwrap();
    let child = Command::new(daemon_binary())
        .arg(write_config(dir))
        .stdout(std::fs::File::create(dir.join("daemon.stdout.log")).unwrap())
        .stderr(std::fs::File::create(dir.join("daemon.stderr.log")).unwrap())
        .spawn()
        .unwrap();
    let mut daemon = Killed(child);
    let channel = rustbgpd_gobgp_bridge::daemon_channel(
        &format!("unix://{}", socket(dir).display()).parse().unwrap(),
    )
    .unwrap();
    let mut rib = RibServiceClient::new(channel);
    for _ in 0..400 {
        if rib
            .list_best_routes(rbgp::ListRoutesRequest::default())
            .await
            .is_ok()
        {
            return (daemon, rib);
        }
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "daemon exited: {}",
            std::fs::read_to_string(dir.join("daemon.stdout.log")).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("daemon socket did not become ready");
}

fn stop_daemon(daemon: Killed) {
    let status = Command::new("kill")
        .args(["-TERM", &daemon.0.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let mut daemon = daemon;
    let exit = daemon.0.wait().unwrap();
    assert!(exit.success(), "daemon shutdown: {exit}");
}

/// Start the bridge binary on an ephemeral loopback port and connect to it.
async fn start_bridge(daemon_args: &[&str]) -> (Killed, GobgpApiClient<Channel>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustbgpd-gobgp-bridge"))
        .args(["--listen", "127.0.0.1:0", "--daemon"])
        .args(daemon_args)
        .env("NO_COLOR", "1")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let bridge = Killed(child);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if let Some(addr) = line.split("listen=").nth(1)
                && let Some(tx) = tx.take()
            {
                let _ = tx.send(addr.split_whitespace().next().unwrap().to_string());
            }
        }
    });
    let addr = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("bridge did not report its listen address");
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (bridge, GobgpApiClient::new(channel))
}

fn path(
    afi: gobgp::family::Afi,
    nlri: &[u8],
    attrs: &[&[u8]],
    withdraw: bool,
) -> gobgp::AddPathRequest {
    gobgp::AddPathRequest {
        table_type: gobgp::TableType::Global as i32,
        vrf_id: String::new(),
        path: Some(gobgp::Path {
            family: Some(gobgp::Family {
                afi: afi as i32,
                safi: gobgp::family::Safi::Unicast as i32,
            }),
            nlri_binary: nlri.to_vec(),
            pattrs_binary: attrs.iter().map(|a| a.to_vec()).collect(),
            is_withdraw: withdraw,
            ..Default::default()
        }),
    }
}

fn ban_v4(withdraw: bool) -> gobgp::AddPathRequest {
    path(
        gobgp::family::Afi::Ip,
        BAN_V4,
        &[ORIGIN_IGP, NEXT_HOP_V4, COMMUNITY_BLACKHOLE],
        withdraw,
    )
}

fn ban_v6(withdraw: bool) -> gobgp::AddPathRequest {
    ban_v6_via(
        "2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
        withdraw,
    )
}

fn ban_v6_via(next_hop: [u8; 16], withdraw: bool) -> gobgp::AddPathRequest {
    let mut mp = vec![0x80, 14, 38, 0, 2, 1, 16];
    mp.extend_from_slice(&next_hop);
    mp.push(0);
    mp.extend_from_slice(BAN_V6);
    path(
        gobgp::family::Afi::Ip6,
        BAN_V6,
        &[&mp, ORIGIN_IGP, COMMUNITY_BLACKHOLE],
        withdraw,
    )
}

/// The daemon's best routes for one prefix.
async fn routes(rib: &mut RibServiceClient<Channel>, prefix: &str, len: u32) -> Vec<rbgp::Route> {
    let afi_safi = if prefix.contains(':') {
        rbgp::AddressFamily::Ipv6Unicast
    } else {
        rbgp::AddressFamily::Ipv4Unicast
    };
    rib.list_best_routes(rbgp::ListRoutesRequest {
        afi_safi: afi_safi as i32,
        prefix_filter: prefix.into(),
        prefix_filter_length: len,
        ..Default::default()
    })
    .await
    .unwrap()
    .into_inner()
    .routes
}

#[tokio::test(flavor = "multi_thread")]
async fn bridge_against_real_daemon() {
    let dir = tempfile::Builder::new()
        .prefix("gbb")
        .tempdir_in("/tmp")
        .unwrap();
    let dir = dir.path();
    // The daemon refuses a socket under a group- or world-writable ancestor.
    std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let (daemon, mut rib) = start_daemon(dir).await;
    let uds = format!("unix://{}", socket(dir).display());
    let (bridge, mut gobgp) = start_bridge(&[&uds]).await;

    // Announce, then a duplicate announce: both succeed with one identifier
    // and leave one route carrying the community.
    let first = gobgp
        .add_path(ban_v4(false))
        .await
        .unwrap()
        .into_inner()
        .uuid;
    let second = gobgp
        .add_path(ban_v4(false))
        .await
        .unwrap()
        .into_inner()
        .uuid;
    assert_eq!(first.len(), 16);
    assert_eq!(first, second);
    let installed = routes(&mut rib, "203.0.113.7", 32).await;
    assert_eq!(installed.len(), 1, "{installed:?}");
    assert_eq!(installed[0].next_hop, "192.0.2.1");
    assert_eq!(installed[0].communities, vec![BLACKHOLE]);

    // IPv6 in GoBGP's shape: prefix in nlri_binary, next hop in MP_REACH_NLRI.
    gobgp.add_path(ban_v6(false)).await.unwrap();
    let installed = routes(&mut rib, "2001:db8::7", 128).await;
    assert_eq!(installed.len(), 1, "{installed:?}");
    assert_eq!(installed[0].next_hop, "2001:db8::1");
    assert_eq!(installed[0].communities, vec![BLACKHOLE]);

    // Withdraw, then a duplicate withdraw: both succeed.
    gobgp.add_path(ban_v6(true)).await.unwrap();
    assert!(routes(&mut rib, "2001:db8::7", 128).await.is_empty());
    gobgp.add_path(ban_v4(true)).await.unwrap();
    gobgp.add_path(ban_v4(true)).await.unwrap();
    assert!(routes(&mut rib, "203.0.113.7", 32).await.is_empty());

    // The detector default next hop 0.0.0.0 (and :: for IPv6) passes
    // through. The daemon stores it unspecified and resolves it to
    // next-hop-self on each session at export.
    let zero = path(
        gobgp::family::Afi::Ip,
        BAN_V4,
        &[ORIGIN_IGP, NEXT_HOP_ZERO, COMMUNITY_BLACKHOLE],
        false,
    );
    gobgp.add_path(zero).await.unwrap();
    let installed = routes(&mut rib, "203.0.113.7", 32).await;
    assert_eq!(installed.len(), 1, "{installed:?}");
    assert_eq!(installed[0].next_hop, "0.0.0.0");
    gobgp.add_path(ban_v4(true)).await.unwrap();
    gobgp.add_path(ban_v6_via([0; 16], false)).await.unwrap();
    let installed = routes(&mut rib, "2001:db8::7", 128).await;
    assert_eq!(installed.len(), 1, "{installed:?}");
    assert_eq!(installed[0].next_hop, "::");
    gobgp.add_path(ban_v6(true)).await.unwrap();
    assert!(routes(&mut rib, "203.0.113.7", 32).await.is_empty());
    assert!(routes(&mut rib, "2001:db8::7", 128).await.is_empty());
    // Every other GoBGP method is UNIMPLEMENTED.
    assert_eq!(
        gobgp
            .get_bgp(gobgp::GetBgpRequest::default())
            .await
            .unwrap_err()
            .code(),
        Code::Unimplemented
    );

    // TCP with the daemon's bearer token. A wrong token is the daemon's
    // UNAUTHENTICATED, returned to the client unchanged.
    let tcp = tcp_endpoint(dir).await;
    let token = dir.join("daemon.token");
    let (_tcp_bridge, mut tcp_gobgp) =
        start_bridge(&[&tcp, "--token-file", token.to_str().unwrap()]).await;
    tcp_gobgp.add_path(ban_v4(false)).await.unwrap();
    assert_eq!(routes(&mut rib, "203.0.113.7", 32).await.len(), 1);
    tcp_gobgp.add_path(ban_v4(true)).await.unwrap();
    assert!(routes(&mut rib, "203.0.113.7", 32).await.is_empty());
    let wrong = dir.join("wrong.token");
    std::fs::write(&wrong, "not-the-token\n").unwrap();
    let (_wrong_bridge, mut wrong_gobgp) =
        start_bridge(&[&tcp, "--token-file", wrong.to_str().unwrap()]).await;
    assert_eq!(
        wrong_gobgp
            .add_path(ban_v4(false))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );

    // Bridge restart: the ban stays in the daemon and a new bridge process
    // can withdraw it, because the bridge holds no state.
    gobgp.add_path(ban_v4(false)).await.unwrap();
    drop(bridge);
    let (_bridge, mut gobgp) = start_bridge(&[&uds]).await;
    assert_eq!(routes(&mut rib, "203.0.113.7", 32).await.len(), 1);
    gobgp.add_path(ban_v4(true)).await.unwrap();
    assert!(routes(&mut rib, "203.0.113.7", 32).await.is_empty());

    // Daemon unavailable: a ban and an unban both fail with UNAVAILABLE.
    gobgp.add_path(ban_v4(false)).await.unwrap();
    stop_daemon(daemon);
    assert_eq!(
        gobgp.add_path(ban_v4(true)).await.unwrap_err().code(),
        Code::Unavailable
    );
    assert_eq!(
        gobgp.add_path(ban_v6(false)).await.unwrap_err().code(),
        Code::Unavailable
    );

    // Daemon restart: injected routes are process-local, so the ban made
    // before the stop is gone. The same bridge reconnects; the unban the
    // detector missed now succeeds as a no-op, and a re-announce restores it.
    let (_daemon, mut rib) = start_daemon(dir).await;
    assert!(routes(&mut rib, "203.0.113.7", 32).await.is_empty());
    gobgp.add_path(ban_v4(true)).await.unwrap();
    gobgp.add_path(ban_v4(false)).await.unwrap();
    assert_eq!(routes(&mut rib, "203.0.113.7", 32).await.len(), 1);
}
