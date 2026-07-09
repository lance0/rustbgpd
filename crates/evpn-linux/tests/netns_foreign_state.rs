//! Privileged netns integration tests for LAN-283 foreign-state
//! ownership protection.
//!
//! Drives the real [`ReconcileActor`] + `LinuxDataplane` inside an
//! isolated network namespace and pins, against a real kernel, that:
//!
//! 1. a foreign same-key row that REPLACES a rustbgpd-owned row is
//!    never "repaired" back over (ownership is relinquished), and
//! 2. the foreign row survives rustbgpd's withdrawal and shutdown
//!    drain — for the L2 bridge FDB row and for the Gate 9 L3 triple
//!    (VRF route, L3 neighbor, L3VXLAN FDB row).
//!
//! The in-memory equivalents live in `tests/reconcile_actor.rs`; this
//! file validates that the netlink dump surfaces (FDB flags for L2,
//! the ADR-0079 marker/foreign classification for L3) really carry
//! the ownership signals the actor's guards key on.
//!
//! ## Why gated
//!
//! Creating a netns + bridge / VRF / VXLAN devices requires
//! `CAP_NET_ADMIN`. PR-CI runners don't have it, so these tests are
//! gated by the `EVPN_LINUX_NETNS=1` environment variable and skip
//! cleanly without it.
//!
//! ```bash
//! sudo -E env EVPN_LINUX_NETNS=1 \
//!   cargo test -p rustbgpd-evpn-linux --test netns_foreign_state
//! ```

#![cfg(target_os = "linux")]

use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_evpn::ip_vrf::{RemoteIpPrefixEntry, RemoteIpPrefixTable};
use rustbgpd_evpn::{
    BumEnforcementTable, DataplaneIntent, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, IpVrf,
    IpVrfId, IpVrfTable, Ipv4Prefix, MacAddress, RemoteMacEntry, RemoteMacSource, RemoteMacTable,
    RouteDistinguisher, RouteTarget,
};
use rustbgpd_evpn_linux::{LinuxDataplane, ReconcileActor, ReconcileActorConfig};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

fn netns_gate() -> bool {
    std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1")
}

fn run(cmd: &str, args: &[&str]) -> std::process::Output {
    let out = Command::new(cmd).args(args).output().expect("spawn");
    if !out.status.success() {
        panic!(
            "{cmd} {args:?} failed: status={} stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    out
}

fn try_run(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}

/// Run a command in the current (inner) netns context and capture
/// stdout.
fn shell(cmd: &str, args: &[&str]) -> String {
    String::from_utf8_lossy(&run(cmd, args).stdout).into_owned()
}

struct NetnsFixture {
    name: String,
}

impl NetnsFixture {
    fn create(test_name: &str) -> Self {
        let name = format!("rustbgpd-foreign-{test_name}-{}", std::process::id());
        try_run("ip", &["netns", "delete", &name]);
        run("ip", &["netns", "add", &name]);
        run("ip", &["-n", &name, "link", "set", "lo", "up"]);
        Self { name }
    }

    fn exec(&self, cmd: &str, args: &[&str]) -> String {
        let mut full = vec!["netns", "exec", self.name.as_str(), cmd];
        full.extend(args);
        String::from_utf8_lossy(&run("ip", &full).stdout).into_owned()
    }
}

impl Drop for NetnsFixture {
    fn drop(&mut self) {
        try_run("ip", &["netns", "delete", &self.name]);
    }
}

/// Re-exec the named test inside the netns; the inner invocation
/// opens the netlink socket in the netns context.
fn run_inner(ns: &NetnsFixture, test_name: &str) {
    let exe = std::env::current_exe().expect("self-exe");
    let status = Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "1")
        .env("EVPN_LINUX_NETNS", "1")
        .status()
        .expect("spawn inner");
    assert!(status.success(), "inner test invocation failed");
}

fn is_inner() -> bool {
    std::env::var("RUSTBGPD_NETNS_INNER").is_ok()
}

async fn spawn_reconcile_actor() -> (
    watch::Sender<Arc<DataplaneIntent>>,
    mpsc::Receiver<rustbgpd_evpn::DataplaneReport>,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let dataplane = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");
    let (intent_tx, intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
    let (report_tx, report_rx) = mpsc::channel(16);
    let shutdown = CancellationToken::new();
    let actor = ReconcileActor::new(
        ReconcileActorConfig::for_tests(),
        dataplane,
        intent_rx,
        report_tx,
        shutdown.clone(),
    );
    let actor_join = tokio::spawn(actor.run());
    (intent_tx, report_rx, shutdown, actor_join)
}

async fn wait_for_report_generation(
    report_rx: &mut mpsc::Receiver<rustbgpd_evpn::DataplaneReport>,
    generation: u64,
) -> rustbgpd_evpn::DataplaneReport {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let report = report_rx.recv().await.expect("dataplane report channel");
            if report.intent_generation >= generation {
                return report;
            }
        }
    })
    .await
    .expect("timed out waiting for dataplane report")
}

fn mac_str(m: MacAddress) -> String {
    let o = m.octets();
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        o[0], o[1], o[2], o[3], o[4], o[5]
    )
}

// ─────────────────────────────────────────────────────────────────
// L2: bridge FDB
// ─────────────────────────────────────────────────────────────────

const L2_VNI: u32 = 100;
const L2_LOCAL_IP: &str = "10.0.0.1";

fn l2_mac() -> MacAddress {
    MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x33])
}

fn l2_rd() -> RouteDistinguisher {
    let mut bytes = [0u8; 8];
    bytes[2..4].copy_from_slice(&65001u16.to_be_bytes());
    bytes[4..8].copy_from_slice(&L2_VNI.to_be_bytes());
    RouteDistinguisher::new(bytes)
}

fn l2_instances() -> EvpnInstanceTable {
    let mut table = EvpnInstanceTable::new();
    table
        .insert(
            EvpnInstance::new(
                EvpnInstanceId::new(L2_VNI).unwrap(),
                l2_rd(),
                vec![RouteTarget::TwoOctetAs {
                    asn: 65001,
                    value: L2_VNI,
                }],
                L2_LOCAL_IP.parse::<IpAddr>().unwrap(),
                Some("br100".to_string()),
                false,
            )
            .expect("EvpnInstance"),
        )
        .expect("insert");
    table
}

fn l2_macs(desired: bool) -> RemoteMacTable {
    let mut builder = RemoteMacTable::builder();
    if desired {
        builder
            .insert(
                EvpnInstanceId::new(L2_VNI).unwrap(),
                l2_mac(),
                RemoteMacEntry {
                    remote_vtep_ip: "10.0.0.2".parse().unwrap(),
                    mobility_sequence: None,
                    alias_vtep_ips: Vec::new(),
                    alias_group_key: None,
                    single_active_backup_vtep_ip: None,
                    source: RemoteMacSource::EvpnRibBestPath,
                },
            )
            .unwrap();
    }
    builder.build()
}

fn l2_intent(generation: u64, desired: bool) -> Arc<DataplaneIntent> {
    Arc::new(DataplaneIntent {
        generation,
        instances: Arc::new(l2_instances()),
        remote_macs: Arc::new(l2_macs(desired)),
        bum_enforcement: Arc::new(BumEnforcementTable::new()),
        ip_vrfs: Arc::new(IpVrfTable::new()),
        remote_ip_prefixes: Arc::new(RemoteIpPrefixTable::new()),
        managed_netdevs: Arc::new(rustbgpd_evpn::ManagedNetdevTable::new()),
    })
}

fn setup_l2_topology(ns: &NetnsFixture) {
    ns.exec(
        "ip",
        &["addr", "add", &format!("{L2_LOCAL_IP}/32"), "dev", "lo"],
    );
    ns.exec("ip", &["link", "add", "name", "br100", "type", "bridge"]);
    ns.exec("ip", &["link", "set", "br100", "up"]);
    ns.exec(
        "ip",
        &[
            "link",
            "add",
            "name",
            "vxlan100",
            "type",
            "vxlan",
            "id",
            "100",
            "local",
            L2_LOCAL_IP,
            "dstport",
            "4789",
            "nolearning",
        ],
    );
    ns.exec("ip", &["link", "set", "vxlan100", "master", "br100"]);
    ns.exec("ip", &["link", "set", "vxlan100", "up"]);
}

fn l2_fdb_line(dump: &str, mac: &str) -> Option<String> {
    dump.lines()
        .find(|line| line.contains(mac) && !line.contains("dst"))
        .map(str::to_owned)
        .or_else(|| {
            dump.lines()
                .find(|line| line.contains(mac))
                .map(str::to_owned)
        })
}

/// LAN-283 L2: a foreign `static` FDB row that replaces the owned row
/// under the same `(vni, mac)` blocks repair, survives withdrawal,
/// and survives the shutdown drain.
#[tokio::test]
async fn l2_foreign_takeover_row_survives_withdrawal_and_shutdown() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged foreign-state test");
        return;
    }
    if !is_inner() {
        let ns = NetnsFixture::create("l2");
        setup_l2_topology(&ns);
        run_inner(
            &ns,
            "l2_foreign_takeover_row_survives_withdrawal_and_shutdown",
        );
        return;
    }

    // ── inner: actor runs inside the netns ──
    let (intent_tx, mut report_rx, shutdown, actor_join) = spawn_reconcile_actor().await;
    let mac = mac_str(l2_mac());

    // 1. Install the remote MAC through the normal reconcile path.
    intent_tx.send(l2_intent(1, true)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 1).await;
    assert!(report.failed.is_empty(), "install: {:?}", report.failed);
    let dump = shell("bridge", &["fdb", "show", "dev", "vxlan100"]);
    assert!(
        dump.lines()
            .any(|l| l.contains(&mac) && l.contains("extern_learn")),
        "owned row missing:\n{dump}"
    );

    // 2. Foreign takeover: operator replaces the row (permanent, no
    //    extern_learn) under the same key.
    run(
        "bridge",
        &[
            "fdb", "replace", &mac, "dev", "vxlan100", "master", "static",
        ],
    );

    // 3. Re-reconcile with the MAC still desired — rustbgpd must NOT
    //    repair its row back over the foreign one.
    intent_tx.send(l2_intent(2, true)).unwrap();
    let _ = wait_for_report_generation(&mut report_rx, 2).await;
    let dump = shell("bridge", &["fdb", "show", "dev", "vxlan100"]);
    let line = l2_fdb_line(&dump, &mac).expect("foreign row present");
    assert!(
        !line.contains("extern_learn"),
        "foreign row must not be replaced by an extern_learn repair:\n{dump}"
    );

    // 4. Withdraw the MAC — the foreign row must survive.
    intent_tx.send(l2_intent(3, false)).unwrap();
    let _ = wait_for_report_generation(&mut report_rx, 3).await;
    let dump = shell("bridge", &["fdb", "show", "dev", "vxlan100"]);
    assert!(
        l2_fdb_line(&dump, &mac).is_some(),
        "foreign row must survive withdrawal:\n{dump}"
    );

    // 5. Shutdown drain — the foreign row must survive that too.
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), actor_join).await;
    let dump = shell("bridge", &["fdb", "show", "dev", "vxlan100"]);
    assert!(
        l2_fdb_line(&dump, &mac).is_some(),
        "foreign row must survive the shutdown drain:\n{dump}"
    );
}

// ─────────────────────────────────────────────────────────────────
// L3: VRF route + L3 neighbor + L3VXLAN FDB
// ─────────────────────────────────────────────────────────────────

const L3_TABLE_ID: u32 = 200;
const L3_VNI: u32 = 101;
const L3_LOCAL_IP: &str = "10.0.0.1";
const L3_PREFIX: &str = "198.51.100.0/24";

fn l3_router_mac() -> MacAddress {
    MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x01, 0xaa])
}

fn l3_local_mac() -> MacAddress {
    MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x01, 0x10])
}

fn l3_prefix() -> rustbgpd_evpn::EvpnIpPrefixValue {
    rustbgpd_evpn::EvpnIpPrefixValue::V4(Ipv4Prefix::new("198.51.100.0".parse().unwrap(), 24))
}

fn l3_ip_vrfs() -> IpVrfTable {
    let mut table = IpVrfTable::new();
    table
        .insert(
            IpVrf::new(
                "vrf-test".to_string(),
                IpVrfId::new(L3_VNI).unwrap(),
                RouteDistinguisher::new([0, 0, 0xfd, 0xe8, 0, 0, 0, 101]),
                vec!["65000:101".parse::<RouteTarget>().unwrap()],
                L3_LOCAL_IP.parse().unwrap(),
                l3_local_mac(),
                "vrf-test".to_string(),
                "l3vxlan-test".to_string(),
                L3_TABLE_ID,
            )
            .unwrap(),
        )
        .unwrap();
    table
}

fn l3_prefixes(desired: bool) -> RemoteIpPrefixTable {
    let mut table = RemoteIpPrefixTable::new();
    if desired {
        table.insert_resolved(
            IpVrfId::new(L3_VNI).unwrap(),
            RemoteIpPrefixEntry::single(
                l3_prefix(),
                "10.0.0.2".parse().unwrap(),
                L3_VNI,
                l3_router_mac(),
            ),
        );
    }
    table
}

fn l3_intent(generation: u64, desired: bool) -> Arc<DataplaneIntent> {
    Arc::new(DataplaneIntent {
        generation,
        instances: Arc::new(EvpnInstanceTable::new()),
        remote_macs: Arc::new(RemoteMacTable::new()),
        bum_enforcement: Arc::new(BumEnforcementTable::new()),
        ip_vrfs: Arc::new(l3_ip_vrfs()),
        remote_ip_prefixes: Arc::new(l3_prefixes(desired)),
        managed_netdevs: Arc::new(rustbgpd_evpn::ManagedNetdevTable::new()),
    })
}

fn setup_l3_topology(ns: &NetnsFixture) {
    let mac = mac_str(l3_router_mac());
    ns.exec(
        "ip",
        &["addr", "add", &format!("{L3_LOCAL_IP}/32"), "dev", "lo"],
    );
    ns.exec(
        "ip",
        &[
            "link",
            "add",
            "vrf-test",
            "type",
            "vrf",
            "table",
            &L3_TABLE_ID.to_string(),
        ],
    );
    ns.exec("ip", &["link", "set", "vrf-test", "up"]);
    ns.exec(
        "ip",
        &[
            "link",
            "add",
            "name",
            "l3vxlan-test",
            "address",
            &mac,
            "type",
            "vxlan",
            "id",
            &L3_VNI.to_string(),
            "local",
            L3_LOCAL_IP,
            "dstport",
            "4789",
            "nolearning",
        ],
    );
    ns.exec("ip", &["link", "set", "l3vxlan-test", "master", "vrf-test"]);
    ns.exec("ip", &["link", "set", "l3vxlan-test", "up"]);
}

fn assert_foreign_l3_triple_present(context: &str) {
    let routes = shell("ip", &["route", "show", "table", &L3_TABLE_ID.to_string()]);
    let route_line = routes
        .lines()
        .find(|l| l.contains(L3_PREFIX))
        .unwrap_or_else(|| panic!("{context}: foreign route missing:\n{routes}"));
    assert!(
        route_line.contains("static") && route_line.contains("10.0.0.9"),
        "{context}: foreign route must keep its proto static identity:\n{routes}"
    );

    let neigh = shell("ip", &["neigh", "show", "dev", "l3vxlan-test"]);
    let neigh_line = neigh
        .lines()
        .find(|l| l.starts_with("10.0.0.2"))
        .unwrap_or_else(|| panic!("{context}: foreign neighbor missing:\n{neigh}"));
    assert!(
        neigh_line.contains("de:ad:be:ef:00:01") && !neigh_line.contains("extern_learn"),
        "{context}: foreign neighbor must keep its identity:\n{neigh}"
    );

    let fdb = shell("bridge", &["fdb", "show", "dev", "l3vxlan-test"]);
    let mac = mac_str(l3_router_mac());
    let fdb_line = fdb
        .lines()
        .find(|l| l.contains(&mac))
        .unwrap_or_else(|| panic!("{context}: foreign FDB row missing:\n{fdb}"));
    assert!(
        fdb_line.contains("10.0.0.9") && !fdb_line.contains("extern_learn"),
        "{context}: foreign FDB row must keep its identity:\n{fdb}"
    );
}

/// LAN-283 L3: foreign rows that replace the owned route / neighbor /
/// L3VXLAN-FDB triple under the same keys block repair, survive
/// withdrawal, and survive the shutdown drain.
#[tokio::test]
async fn l3_foreign_takeover_triple_survives_withdrawal_and_shutdown() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged foreign-state test");
        return;
    }
    if !is_inner() {
        let ns = NetnsFixture::create("l3");
        setup_l3_topology(&ns);
        run_inner(
            &ns,
            "l3_foreign_takeover_triple_survives_withdrawal_and_shutdown",
        );
        return;
    }

    // ── inner: actor runs inside the netns ──
    let (intent_tx, mut report_rx, shutdown, actor_join) = spawn_reconcile_actor().await;
    let mac = mac_str(l3_router_mac());

    // 1. Install the L3 triple through the normal reconcile path.
    intent_tx.send(l3_intent(1, true)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 1).await;
    assert!(report.failed.is_empty(), "install: {:?}", report.failed);
    let routes = shell("ip", &["route", "show", "table", &L3_TABLE_ID.to_string()]);
    assert!(routes.contains(L3_PREFIX), "owned route missing:\n{routes}");

    // 2. Foreign takeover of all three rows under the same keys.
    run(
        "ip",
        &[
            "route",
            "replace",
            L3_PREFIX,
            "via",
            "10.0.0.9",
            "dev",
            "l3vxlan-test",
            "table",
            &L3_TABLE_ID.to_string(),
            "proto",
            "static",
            "onlink",
        ],
    );
    run(
        "ip",
        &[
            "neigh",
            "replace",
            "10.0.0.2",
            "lladdr",
            "de:ad:be:ef:00:01",
            "dev",
            "l3vxlan-test",
            "nud",
            "permanent",
        ],
    );
    run(
        "bridge",
        &[
            "fdb",
            "replace",
            &mac,
            "dev",
            "l3vxlan-test",
            "self",
            "static",
            "dst",
            "10.0.0.9",
        ],
    );

    // 3. Re-reconcile with the prefix still desired — no repair over
    //    the foreign rows.
    intent_tx.send(l3_intent(2, true)).unwrap();
    let _ = wait_for_report_generation(&mut report_rx, 2).await;
    assert_foreign_l3_triple_present("after re-reconcile");

    // 4. Withdraw the prefix — every foreign row must survive.
    intent_tx.send(l3_intent(3, false)).unwrap();
    let _ = wait_for_report_generation(&mut report_rx, 3).await;
    assert_foreign_l3_triple_present("after withdrawal");

    // 5. Shutdown drain — the foreign triple must survive that too.
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), actor_join).await;
    assert_foreign_l3_triple_present("after shutdown drain");
}
