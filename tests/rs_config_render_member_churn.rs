//! Real-daemon regression for route-server member join and leave through
//! `rs-config-render activate` (ADR-0110).
//! Verifies that `rs-config-render activate` drives member churn against a real
//! running daemon with live eBGP members without error, session disturbance,
//! or false rollback:
//!
//! 1. `activate --initial` spawns the real daemon and leaves an activation receipt
//!    with `runtime_equal: true`.
//! 2. Two initial eBGP route-server members connect, complete OPEN/KEEPALIVE, and
//!    reach `Established`.
//! 3. Member join (adding a 3rd member with its two rendered datasets in `[policy.datasets]`)
//!    through `activate` settles cleanly without error (exit code 0), verifies
//!    prior `rbgp config diff` reported changes while post-activation reports no changes,
//!    proves existing members' sessions remain undisturbed (no flap, uptime continuous),
//!    and allows the 3rd member to establish.
//! 4. Member leave (removing the 3rd member) through `activate` settles cleanly with
//!    the same invariants.

#[path = "support/mod.rs"]
mod support;

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rs_config_render::activation::{self, Options, Status};
use rs_config_render::ixp_manager;
use rs_config_render::ixp_manager_host::{Binding, RenderBinding};
use rustbgpd_wire::header::peek_message_length;
use rustbgpd_wire::{
    Afi, Capability, MAX_MESSAGE_LEN, Message, OpenMessage, Safi, decode_message, encode_message,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;

const ROUTER_HANDLE: &str = "rs1-lan1-ipv4";
const ROUTER_ASN: u32 = 65501;
const HOLD_TIME: u16 = 90;

struct MemberSpec {
    customer_id: u64,
    vlan_id: u64,
    name: &'static str,
    asn: u32,
    address: &'static str,
    prefix: &'static str,
}

const MEMBER_1: MemberSpec = MemberSpec {
    customer_id: 1,
    vlan_id: 1,
    name: "Member1",
    asn: 65001,
    address: "127.0.0.2",
    prefix: "198.51.100.0/24",
};

const MEMBER_2: MemberSpec = MemberSpec {
    customer_id: 2,
    vlan_id: 2,
    name: "Member2",
    asn: 65002,
    address: "127.0.0.3",
    prefix: "198.51.101.0/24",
};

const MEMBER_3: MemberSpec = MemberSpec {
    customer_id: 3,
    vlan_id: 3,
    name: "Member3",
    asn: 65003,
    address: "127.0.0.4",
    prefix: "198.51.102.0/24",
};

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set permissions");
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve loopback port")
        .local_addr()
        .expect("read loopback port")
        .port()
}

fn ixp_manager_json(bgp_port: u16, members: &[&MemberSpec]) -> Vec<u8> {
    let clients: Vec<_> = members
        .iter()
        .map(|m| {
            json!({
                "customer_id": m.customer_id,
                "vlan_interface_id": m.vlan_id,
                "name": m.name,
                "asn": m.asn,
                "address": m.address,
                "peering_ips": [m.address],
                "max_prefix": 100,
                "auth": {"type": "none"},
                "irr_filter": true,
                "more_specifics": false,
                "origins": [m.asn],
                "prefixes": [m.prefix]
            })
        })
        .collect();

    let doc = json!({
        "schema": "rustbgpd.ixp-manager.router-config/v2",
        "ixp_manager": {
            "version": "7.4.0"
        },
        "router": {
            "handle": ROUTER_HANDLE,
            "type": "route-server",
            "protocol": 4,
            "asn": ROUTER_ASN,
            "router_id": "192.0.2.1",
            "peering_ip": "127.0.0.1",
            "listen_port": bgp_port,
            "vlan_id": 1,
            "quarantine": false,
            "bgp_lc": true,
            "rfc1997_passthru": false,
            "rpki": false,
            "skip_md5": true
        },
        "policy": {
            "minimum_prefix_length": 24,
            "rtr_caches": [],
            "no_transit": {
                "source": "IXP_NO_TRANSIT_ASNS_OVERRIDE",
                "asns": []
            }
        },
        "clients": clients,
        "ui_filters": [],
        "unsupported": {
            "active_ui_filters": [],
            "route_server_skin_files": []
        },
        "complete": {
            "handle": ROUTER_HANDLE,
            "client_count": members.len(),
            "ui_filter_count": 0,
            "marker": format!("END_OF_RUSTBGPD_IXP_MANAGER_CONFIG_{ROUTER_HANDLE}")
        }
    });

    serde_json::to_vec_pretty(&doc).expect("serialize ixp fixture")
}

fn write_candidate(
    candidate_dir: &Path,
    bgp_port: u16,
    members: &[&MemberSpec],
    checker: &Path,
    binding: &RenderBinding,
) {
    if candidate_dir.exists() {
        fs::remove_dir_all(candidate_dir).expect("clean candidate dir");
    }
    fs::create_dir_all(candidate_dir).expect("create candidate dir");
    set_mode(candidate_dir, 0o700);

    let json_bytes = ixp_manager_json(bgp_port, members);
    ixp_manager::write_checked_candidate_bytes(&json_bytes, candidate_dir, 300, checker, binding)
        .expect("write checked candidate");
}

fn rbgp(grpc_addr: &str, args: &[&str]) -> Output {
    Command::new(support::rbgp_binary())
        .arg("--addr")
        .arg(grpc_addr)
        .args(args)
        .output()
        .expect("execute rbgp")
}

fn rbgp_json(grpc_addr: &str, args: &[&str]) -> serde_json::Value {
    let output = rbgp(grpc_addr, args);
    let code = output.status.code();
    assert!(
        output.status.success() || code == Some(2),
        "rbgp failed with code {code:?}:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).expect("parse rbgp JSON")
}

struct DaemonKiller {
    pid_file: PathBuf,
}

impl Drop for DaemonKiller {
    fn drop(&mut self) {
        if let Ok(text) = fs::read_to_string(&self.pid_file)
            && let Ok(pid) = text.trim().parse::<i32>()
        {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}

struct PeerHandle {
    /// Set once the daemon's first KEEPALIVE arrives (its OPEN was already
    /// read during the handshake); cleared when the peer task exits.
    established: Arc<AtomicBool>,
    /// `(code, subcode)` of a NOTIFICATION received from the daemon, so a
    /// daemon-initiated teardown is attributable rather than a later socket close.
    notification: Arc<Mutex<Option<(u8, u8)>>>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl PeerHandle {
    fn is_established(&self) -> bool {
        self.established.load(Ordering::Acquire)
    }

    fn notification(&self) -> Option<(u8, u8)> {
        *self.notification.lock().expect("notification lock")
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.join.await;
    }
}

/// Decode every complete inbound message: the first KEEPALIVE marks the
/// session established on the peer side; a NOTIFICATION is recorded.
fn drain_inbound(
    read_buf: &mut BytesMut,
    established: &AtomicBool,
    notification: &Mutex<Option<(u8, u8)>>,
) {
    while let Ok(Some(total)) = peek_message_length(read_buf, MAX_MESSAGE_LEN) {
        if read_buf.len() < usize::from(total) {
            break;
        }
        let mut body = read_buf.split_to(usize::from(total)).freeze();
        match decode_message(&mut body, MAX_MESSAGE_LEN) {
            Ok(Message::Keepalive) => established.store(true, Ordering::Release),
            Ok(Message::Notification(n)) => {
                *notification.lock().expect("notification lock") =
                    Some((n.code.as_u8(), n.subcode));
            }
            _ => {}
        }
    }
}

async fn spawn_ebgp_peer(
    member: &'static MemberSpec,
    daemon_addr: SocketAddr,
) -> Result<PeerHandle, String> {
    let local: Ipv4Addr = member.address.parse().map_err(|e| format!("{e}"))?;
    let sock = TcpSocket::new_v4().map_err(|e| format!("socket: {e}"))?;
    sock.bind(SocketAddr::new(local.into(), 0))
        .map_err(|e| format!("bind {local}: {e}"))?;

    let mut stream = sock
        .connect(daemon_addr)
        .await
        .map_err(|e| format!("connect from {local} to {daemon_addr}: {e}"))?;
    stream.set_nodelay(true).ok();

    let open = OpenMessage {
        version: 4,
        my_as: u16::try_from(member.asn).expect("member ASN fits two octets"),
        hold_time: HOLD_TIME,
        // Higher than daemon's 192.0.2.1 so RFC 6286 collision keeps this inbound stream
        bgp_identifier: Ipv4Addr::new(
            240,
            9,
            1,
            u8::try_from(member.customer_id).expect("customer_id fits u8"),
        ),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: member.asn },
            Capability::RouteRefresh,
        ],
    };

    let open_bytes =
        encode_message(&Message::Open(open)).map_err(|e| format!("open encode: {e}"))?;
    stream
        .write_all(&open_bytes)
        .await
        .map_err(|e| format!("open write: {e}"))?;

    let mut buf = BytesMut::with_capacity(4096);
    let mut early_keepalive = false;
    loop {
        if let Ok(Some(total)) = peek_message_length(&buf, MAX_MESSAGE_LEN)
            && buf.len() >= usize::from(total)
        {
            let mut body = buf.split_to(usize::from(total)).freeze();
            match decode_message(&mut body, MAX_MESSAGE_LEN) {
                Ok(Message::Open(_)) => break,
                Ok(Message::Notification(n)) => {
                    return Err(format!(
                        "NOTIFICATION during open: code {} subcode {}",
                        n.code, n.subcode
                    ));
                }
                Ok(Message::Keepalive) => early_keepalive = true,
                Ok(_) => continue,
                Err(e) => return Err(format!("decode error during open: {e}")),
            }
        }
        let mut tmp = [0u8; 4096];
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read from daemon: {e}"))?;
        if n == 0 {
            return Err(format!("daemon closed connection to {local} before OPEN"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let keepalive_bytes =
        encode_message(&Message::Keepalive).expect("keepalive encoding cannot fail");
    stream
        .write_all(&keepalive_bytes)
        .await
        .map_err(|e| format!("keepalive write: {e}"))?;

    let established = Arc::new(AtomicBool::new(early_keepalive));
    let est_flag = Arc::clone(&established);
    let notification = Arc::new(Mutex::new(None));
    let notification_slot = Arc::clone(&notification);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let (mut reader, mut writer) = stream.into_split();

    let join = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(u64::from(HOLD_TIME) / 3));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;

        // Bytes read past the daemon's OPEN during the handshake may already
        // hold its first KEEPALIVE.
        let mut read_buf = buf;
        let mut tmp = [0u8; 4096];
        drain_inbound(&mut read_buf, &est_flag, &notification_slot);

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                _ = tick.tick() => {
                    let ka = encode_message(&Message::Keepalive).expect("keepalive encodes");
                    if writer.write_all(&ka).await.is_err() {
                        break;
                    }
                }
                read_res = reader.read(&mut tmp) => {
                    let Ok(n) = read_res else { break };
                    if n == 0 { break; }
                    read_buf.extend_from_slice(&tmp[..n]);
                    drain_inbound(&mut read_buf, &est_flag, &notification_slot);
                }
            }
        }
        est_flag.store(false, Ordering::Release);
    });

    Ok(PeerHandle {
        established,
        notification,
        shutdown_tx: Some(shutdown_tx),
        join,
    })
}

async fn wait_until<F>(timeout: Duration, mut predicate: F) -> bool
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    predicate()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_daemon_member_join_and_leave_through_activate() {
    let evidence = support::RetainOnPanic::new(
        tempfile::Builder::new()
            .prefix("rs-churn-")
            .tempdir()
            .expect("temporary evidence directory"),
    );
    let root = evidence.path();
    set_mode(root, 0o700);
    let runtime = root.join(ROUTER_HANDLE);
    let state = runtime.join("activation");
    let host = root.join("host-state");
    let candidate = root.join("candidate");
    let pid_file = root.join("rustbgpd.pid");
    let daemon_log = root.join("daemon.log");

    fs::create_dir(&runtime).expect("create runtime dir");
    set_mode(&runtime, 0o700);
    fs::create_dir(&state).expect("create state dir");
    set_mode(&state, 0o700);
    fs::create_dir(&host).expect("create host dir");
    set_mode(&host, 0o700);
    fs::create_dir(&candidate).expect("create candidate dir");
    set_mode(&candidate, 0o700);

    let _daemon_guard = DaemonKiller {
        pid_file: pid_file.clone(),
    };

    let daemon_bin = Path::new(env!("CARGO_BIN_EXE_rustbgpd"));
    let rbgp_bin = support::rbgp_binary();
    let rbgp_addr = format!("unix://{}/grpc.sock", runtime.display());

    let binding = Binding::new(ROUTER_HANDLE, &runtime, &state, &host, &rbgp_addr)
        .expect("construct valid host binding");
    let render_binding = binding.render_binding();

    let bgp_port = free_port();
    let daemon_bgp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bgp_port);

    // Write the activation script used by `activate` on initial start and reload.
    let activate_sh = root.join("activate.sh");
    let script_content = format!(
        r#"#!/bin/sh
set -eu
PID_FILE="{pid}"
LOG_FILE="{log}"
DAEMON="{daemon}"
CONFIG="{state}/current/config.toml"

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    kill -HUP "$(cat "$PID_FILE")"
else
    "$DAEMON" "$CONFIG" >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
fi
"#,
        pid = pid_file.display(),
        log = daemon_log.display(),
        daemon = daemon_bin.display(),
        state = state.display(),
    );
    fs::write(&activate_sh, script_content).expect("write activate.sh");
    set_mode(&activate_sh, 0o700);

    // =========================================================================
    // Phase 1: Render 2-member configuration and run activate --initial
    // =========================================================================
    write_candidate(
        &candidate,
        bgp_port,
        &[&MEMBER_1, &MEMBER_2],
        daemon_bin,
        &render_binding,
    );

    let initial_status = activation::activate(&Options {
        candidate: &candidate,
        state_dir: &state,
        checker: daemon_bin,
        rbgp: rbgp_bin,
        rbgp_addr: &rbgp_addr,
        settle: Duration::from_secs(10),
        initial: true,
        activation_command: &activate_sh,
        activation_args: &[],
        binding: &binding,
    })
    .expect("activate --initial must succeed");

    assert_eq!(
        initial_status,
        Status::Activated,
        "initial activation must yield Activated"
    );

    let initial_receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(state.join("activation-receipt.json")).expect("read activation receipt"),
    )
    .expect("parse activation receipt JSON");

    assert_eq!(initial_receipt["status"], "activated");
    assert_eq!(
        initial_receipt["phases"]["runtime_equal"], true,
        "initial activation must record runtime_equal = true"
    );

    // =========================================================================
    // Phase 2: Connect 2 live eBGP members and wait for Established
    // =========================================================================
    let peer1 = spawn_ebgp_peer(&MEMBER_1, daemon_bgp_addr)
        .await
        .expect("peer 1 establishes");
    let peer2 = spawn_ebgp_peer(&MEMBER_2, daemon_bgp_addr)
        .await
        .expect("peer 2 establishes");

    // Wait until daemon gRPC reports both peers in state Established
    let both_established = wait_until(Duration::from_secs(5), || {
        let list = rbgp_json(&rbgp_addr, &["--json", "neighbor"]);
        let Some(neighbors) = list.as_array() else {
            return false;
        };
        neighbors.len() == 2
            && neighbors
                .iter()
                .all(|n| n["state"] == "Established" && n["flap_count"] == 0)
            && peer1.is_established()
            && peer2.is_established()
    })
    .await;
    assert!(
        both_established,
        "both initial neighbors must appear Established with 0 flaps in rbgp"
    );
    assert!(peer1.is_established(), "peer 1 must be established");
    assert!(peer2.is_established(), "peer 2 must be established");
    assert_eq!(
        peer1.notification(),
        None,
        "peer 1 must not receive a NOTIFICATION"
    );
    assert_eq!(
        peer2.notification(),
        None,
        "peer 2 must not receive a NOTIFICATION"
    );

    // Record initial session statistics
    let neighbors_before_join = rbgp_json(&rbgp_addr, &["--json", "neighbor"]);
    let n1_before = neighbors_before_join
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["address"] == MEMBER_1.address)
        .expect("member 1 in neighbor list");
    let n2_before = neighbors_before_join
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["address"] == MEMBER_2.address)
        .expect("member 2 in neighbor list");
    assert_eq!(n1_before["flap_count"], 0);
    assert_eq!(n2_before["flap_count"], 0);

    // =========================================================================
    // Phase 3: Member Join (add 3rd member with its two datasets)
    // =========================================================================
    write_candidate(
        &candidate,
        bgp_port,
        &[&MEMBER_1, &MEMBER_2, &MEMBER_3],
        daemon_bin,
        &render_binding,
    );

    // Before activation, rbgp config diff against the candidate reports changes (exit code 2)
    let pre_diff = rbgp(
        &rbgp_addr,
        &[
            "--json",
            "config",
            "diff",
            candidate.join("config.toml").to_str().unwrap(),
        ],
    );
    assert_eq!(
        pre_diff.status.code(),
        Some(2),
        "pre-activation diff must exit 2 indicating pending candidate changes"
    );
    let pre_diff_json: serde_json::Value =
        serde_json::from_slice(&pre_diff.stdout).expect("parse pre-activation diff JSON");
    assert_eq!(
        pre_diff_json["has_any_changes"], true,
        "pre-activation diff must report changes:\n{pre_diff_json:#}"
    );
    assert_eq!(
        pre_diff_json["summary"]["neighbors_added"], 1,
        "pre-activation diff must add exactly member 3:\n{pre_diff_json:#}"
    );
    assert_eq!(
        pre_diff_json["sighup_reload"]["route"], "generation",
        "member join with dataset bindings must route through the generation executor:\n{pre_diff_json:#}"
    );

    // Activate the 3-member candidate
    let join_status = activation::activate(&Options {
        candidate: &candidate,
        state_dir: &state,
        checker: daemon_bin,
        rbgp: rbgp_bin,
        rbgp_addr: &rbgp_addr,
        settle: Duration::from_secs(10),
        initial: false,
        activation_command: &activate_sh,
        activation_args: &[],
        binding: &binding,
    })
    .expect("activate member join must succeed");

    assert_eq!(
        join_status,
        Status::Activated,
        "member join activation must yield Activated"
    );

    let join_receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(state.join("activation-receipt.json")).expect("read activation receipt"),
    )
    .expect("parse activation receipt JSON");

    assert_eq!(join_receipt["status"], "activated");
    assert_eq!(
        join_receipt["phases"]["runtime_equal"], true,
        "member join activation must record runtime_equal = true"
    );

    // Post-activation, diff against current config must report no changes (exit code 0)
    let post_diff = rbgp(
        &rbgp_addr,
        &[
            "config",
            "diff",
            state.join("current/config.toml").to_str().unwrap(),
        ],
    );
    assert_eq!(
        post_diff.status.code(),
        Some(0),
        "post-activation diff against current must exit 0:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&post_diff.stdout),
        String::from_utf8_lossy(&post_diff.stderr)
    );

    // Existing members must remain established with flap_count == 0
    let neighbors_after_join = rbgp_json(&rbgp_addr, &["--json", "neighbor"]);
    let n1_after = neighbors_after_join
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["address"] == MEMBER_1.address)
        .expect("member 1 in neighbor list");
    let n2_after = neighbors_after_join
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["address"] == MEMBER_2.address)
        .expect("member 2 in neighbor list");
    assert_eq!(
        n1_after["state"], "Established",
        "member 1 must remain Established after join reload"
    );
    assert_eq!(
        n2_after["state"], "Established",
        "member 2 must remain Established after join reload"
    );
    assert_eq!(n1_after["flap_count"], 0, "member 1 flap count must stay 0");
    assert_eq!(n2_after["flap_count"], 0, "member 2 flap count must stay 0");
    assert!(
        peer1.is_established(),
        "peer 1 must remain established after join reload"
    );
    assert!(
        peer2.is_established(),
        "peer 2 must remain established after join reload"
    );
    assert_eq!(
        peer1.notification(),
        None,
        "peer 1 must not receive a NOTIFICATION"
    );
    assert_eq!(
        peer2.notification(),
        None,
        "peer 2 must not receive a NOTIFICATION"
    );

    // Now connect Member 3
    let peer3 = spawn_ebgp_peer(&MEMBER_3, daemon_bgp_addr)
        .await
        .expect("peer 3 establishes");

    let all_three_established = wait_until(Duration::from_secs(5), || {
        let list = rbgp_json(&rbgp_addr, &["--json", "neighbor"]);
        let Some(neighbors) = list.as_array() else {
            return false;
        };
        neighbors.len() == 3
            && neighbors
                .iter()
                .all(|n| n["state"] == "Established" && n["flap_count"] == 0)
            && peer3.is_established()
    })
    .await;
    assert!(
        all_three_established,
        "all three neighbors must be Established with 0 flaps"
    );
    assert!(peer3.is_established(), "peer 3 must be established");
    assert_eq!(
        peer3.notification(),
        None,
        "peer 3 must not receive a NOTIFICATION"
    );

    // =========================================================================
    // Phase 4: Member Leave (remove 3rd member)
    // =========================================================================
    // Drop peer 3 connection before or during leave
    peer3.shutdown().await;

    write_candidate(
        &candidate,
        bgp_port,
        &[&MEMBER_1, &MEMBER_2],
        daemon_bin,
        &render_binding,
    );

    let leave_status = activation::activate(&Options {
        candidate: &candidate,
        state_dir: &state,
        checker: daemon_bin,
        rbgp: rbgp_bin,
        rbgp_addr: &rbgp_addr,
        settle: Duration::from_secs(10),
        initial: false,
        activation_command: &activate_sh,
        activation_args: &[],
        binding: &binding,
    })
    .expect("activate member leave must succeed");

    assert_eq!(
        leave_status,
        Status::Activated,
        "member leave activation must yield Activated"
    );

    let leave_receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(state.join("activation-receipt.json")).expect("read activation receipt"),
    )
    .expect("parse activation receipt JSON");

    assert_eq!(leave_receipt["status"], "activated");
    assert_eq!(
        leave_receipt["phases"]["runtime_equal"], true,
        "member leave activation must record runtime_equal = true"
    );

    let post_leave_diff = rbgp(
        &rbgp_addr,
        &[
            "config",
            "diff",
            state.join("current/config.toml").to_str().unwrap(),
        ],
    );
    assert_eq!(
        post_leave_diff.status.code(),
        Some(0),
        "post-leave diff against current must exit 0:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&post_leave_diff.stdout),
        String::from_utf8_lossy(&post_leave_diff.stderr)
    );

    // Member 1 and Member 2 remain established with 0 flaps
    let neighbors_after_leave = rbgp_json(&rbgp_addr, &["--json", "neighbor"]);
    let list = neighbors_after_leave.as_array().unwrap();
    assert_eq!(list.len(), 2, "neighbor count must return to 2 after leave");

    let n1_final = list
        .iter()
        .find(|n| n["address"] == MEMBER_1.address)
        .expect("member 1 in final neighbor list");
    let n2_final = list
        .iter()
        .find(|n| n["address"] == MEMBER_2.address)
        .expect("member 2 in final neighbor list");

    assert_eq!(n1_final["state"], "Established");
    assert_eq!(n2_final["state"], "Established");
    assert_eq!(n1_final["flap_count"], 0);
    assert_eq!(n2_final["flap_count"], 0);
    assert!(
        peer1.is_established(),
        "peer 1 must remain established after leave reload"
    );
    assert!(
        peer2.is_established(),
        "peer 2 must remain established after leave reload"
    );
    assert_eq!(
        peer1.notification(),
        None,
        "peer 1 must not receive a NOTIFICATION"
    );
    assert_eq!(
        peer2.notification(),
        None,
        "peer 2 must not receive a NOTIFICATION"
    );

    // Cleanly shutdown peers 1 and 2
    peer1.shutdown().await;
    peer2.shutdown().await;
}
