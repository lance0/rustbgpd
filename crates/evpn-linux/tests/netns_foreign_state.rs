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

use rustbgpd_evpn::ip_vrf::{IpVrfStatus, RemoteIpPrefixEntry, RemoteIpPrefixTable};
use rustbgpd_evpn::{
    BumEnforcementTable, DataplaneIntent, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, IpVrf,
    IpVrfId, IpVrfTable, Ipv4Prefix, MacAddress, RemoteMacEntry, RemoteMacSource, RemoteMacTable,
    RouteDistinguisher, RouteTarget,
};
use rustbgpd_evpn_linux::dataplane::NexthopOps;
use rustbgpd_evpn_linux::group_state::GroupOwnedMap;
use rustbgpd_evpn_linux::{
    Dataplane, DataplaneOp, FailureClass, LinuxDataplane, OwnedEntry, OwnedSet, ReconcileActor,
    ReconcileActorConfig, compute_diff,
};
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

/// Wait for the first report at or past `generation`. Its
/// `foreign_state_counters` are replaced by the sum over every report
/// received while waiting. The counters are per pass, and a pass woken
/// by a kernel event (for example the bridge's delayed operstate
/// `RTM_NEWLINK` after setup) can observe the test's last kernel write
/// before the pass for the next intent generation does.
async fn wait_for_report_generation(
    report_rx: &mut mpsc::Receiver<rustbgpd_evpn::DataplaneReport>,
    generation: u64,
) -> rustbgpd_evpn::DataplaneReport {
    let mut total = rustbgpd_evpn::ForeignStateCounters::default();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut report = report_rx.recv().await.expect("dataplane report channel");
            let pass = report.foreign_state_counters;
            total.replaces_blocked += pass.replaces_blocked;
            total.deletes_skipped += pass.deletes_skipped;
            total.owned_relinquished += pass.owned_relinquished;
            total.nhid_range_conflicts += pass.nhid_range_conflicts;
            if report.intent_generation >= generation {
                report.foreign_state_counters = total;
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

fn l2_rows_match(dump: &str, mac: &str, owned_sibling: bool) -> bool {
    let rows: Vec<_> = dump.lines().filter(|line| line.starts_with(mac)).collect();
    let has = |required: &str, forbidden: &str| {
        rows.iter().any(|row| {
            let tokens: Vec<_> = row.split_whitespace().collect();
            let required = required
                .split_whitespace()
                .all(|token| tokens.contains(&token));
            let allowed = forbidden
                .split_whitespace()
                .all(|token| !tokens.contains(&token));
            required && allowed
        })
    };
    rows.len() == 2 + usize::from(owned_sibling)
        && has("master br100 static", "vlan dst extern_learn self")
        && has("vlan 1 master br100 static", "dst extern_learn self")
        && (!owned_sibling || has("dst 10.0.0.2 self extern_learn permanent", "master vlan"))
}

fn l2_mac_rows() -> Vec<String> {
    let mut rows: Vec<_> = shell("bridge", &["fdb", "show", "br", "br100"])
        .lines()
        .filter(|row| row.starts_with(&mac_str(l2_mac())))
        .map(str::to_owned)
        .collect();
    rows.sort();
    rows
}

fn replace_l2_pvid_with_foreign() {
    let mac = mac_str(l2_mac());
    run(
        "bridge",
        &["fdb", "del", &mac, "dev", "vxlan100", "master", "vlan", "1"],
    );
    run(
        "bridge",
        &[
            "fdb", "add", &mac, "dev", "vxlan100", "master", "static", "vlan", "1",
        ],
    );
    assert!(l2_mac_rows().iter().any(|row| {
        row.contains("dev vxlan100 vlan 1 master br100 static") && !row.contains("extern_learn")
    }));
}

#[tokio::test]
async fn l2_foreign_pvid_only_row_survives_legacy_reconciliation() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged foreign-state test");
        return;
    }
    if !is_inner() {
        let ns = NetnsFixture::create("l2-pvid-only");
        setup_l2_topology(&ns);
        ns.exec("ip", &["link", "add", "ce0", "type", "dummy"]);
        ns.exec("ip", &["link", "set", "ce0", "master", "br100"]);
        ns.exec("ip", &["link", "set", "ce0", "up"]);
        run_inner(
            &ns,
            "l2_foreign_pvid_only_row_survives_legacy_reconciliation",
        );
        return;
    }

    let mac = mac_str(l2_mac());
    run(
        "bridge",
        &[
            "fdb", "add", &mac, "dev", "ce0", "master", "static", "vlan", "1",
        ],
    );
    let before = l2_mac_rows();
    assert_eq!(before.len(), 1, "only the PVID row may exist: {before:?}");
    assert!(
        before[0].contains("dev ce0 vlan 1 master br100 static"),
        "{before:?}"
    );
    let (intent_tx, mut report_rx, shutdown, actor_join) = spawn_reconcile_actor().await;
    intent_tx.send(l2_intent(1, true)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 1).await;
    assert!(report.failed.is_empty(), "install: {:?}", report.failed);
    assert_eq!(
        l2_mac_rows(),
        before,
        "remote install must preserve the PVID-only foreign row"
    );
    assert_eq!(report.foreign_state_counters.replaces_blocked, 1);

    intent_tx.send(l2_intent(2, false)).unwrap();
    wait_for_report_generation(&mut report_rx, 2).await;
    assert_eq!(
        l2_mac_rows(),
        before,
        "withdrawal must preserve the foreign row"
    );

    // Once the foreign row is removed, ordinary programming resumes.
    run(
        "bridge",
        &["fdb", "del", &mac, "dev", "ce0", "master", "vlan", "1"],
    );
    intent_tx.send(l2_intent(3, true)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 3).await;
    assert!(report.failed.is_empty());
    assert_eq!(l2_mac_rows().len(), 3);

    // Replace only the PVID sibling; the unscoped row is still ours.
    replace_l2_pvid_with_foreign();
    let mixed = l2_mac_rows();
    intent_tx.send(l2_intent(4, true)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 4).await;
    assert_eq!(report.foreign_state_counters.owned_relinquished, 0);
    assert_eq!(
        l2_mac_rows(),
        mixed,
        "repair must preserve the foreign sibling"
    );
    intent_tx.send(l2_intent(5, false)).unwrap();
    wait_for_report_generation(&mut report_rx, 5).await;
    assert_eq!(
        l2_mac_rows(),
        mixed,
        "withdrawal must preserve all mixed rows"
    );

    run(
        "bridge",
        &["fdb", "del", &mac, "dev", "vxlan100", "master", "vlan", "1"],
    );
    intent_tx.send(l2_intent(6, false)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 6).await;
    assert!(
        report.failed.is_empty(),
        "owned cleanup: {:?}",
        report.failed
    );
    assert!(
        l2_mac_rows().is_empty(),
        "owned rows must remain tracked for cleanup"
    );

    intent_tx.send(l2_intent(7, true)).unwrap();
    wait_for_report_generation(&mut report_rx, 7).await;
    replace_l2_pvid_with_foreign();
    let mixed = l2_mac_rows();
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), actor_join)
        .await
        .expect("actor shutdown timed out")
        .expect("actor panicked");
    assert_eq!(
        l2_mac_rows(),
        mixed,
        "shutdown must preserve the foreign sibling"
    );
}

#[tokio::test]
async fn l2_foreign_pvid_stale_operations_are_rechecked_before_apply() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged foreign-state test");
        return;
    }
    if !is_inner() {
        let ns = NetnsFixture::create("l2-pvid-stale");
        setup_l2_topology(&ns);
        ns.exec("ip", &["link", "add", "ce0", "type", "dummy"]);
        ns.exec("ip", &["link", "set", "ce0", "master", "br100"]);
        ns.exec("ip", &["link", "set", "ce0", "up"]);
        run_inner(
            &ns,
            "l2_foreign_pvid_stale_operations_are_rechecked_before_apply",
        );
        return;
    }

    let mut dp = LinuxDataplane::connect().await.expect("netlink connect");
    let instances = l2_instances();
    let probes = dp.probe(&instances).await;
    let vni = EvpnInstanceId::new(L2_VNI).unwrap();
    let mac = mac_str(l2_mac());
    let add = compute_diff(
        &l2_macs(true),
        &dp.dump_snapshot().await.unwrap(),
        &OwnedSet::new(),
        &probes,
        &GroupOwnedMap::new(),
        &instances,
    );
    assert!(matches!(
        add.ops.as_slice(),
        [DataplaneOp::AddRemoteFdb { .. }]
    ));
    run(
        "bridge",
        &[
            "fdb", "add", &mac, "dev", "ce0", "master", "static", "vlan", "1",
        ],
    );
    let foreign = l2_mac_rows();
    let error = dp
        .apply(&add.ops[0])
        .await
        .expect_err("stale add must conflict");
    assert_eq!(error.class(), FailureClass::Conflict);
    assert_eq!(l2_mac_rows(), foreign);

    run(
        "bridge",
        &["fdb", "del", &mac, "dev", "ce0", "master", "vlan", "1"],
    );
    run(
        "bridge",
        &["fdb", "add", &mac, "dev", "ce0", "master", "dynamic"],
    );
    dp.apply(&add.ops[0])
        .await
        .expect("dynamic local mobility remains permitted");
    let mut owned = OwnedSet::new();
    owned.record_applied(
        vni,
        l2_mac(),
        OwnedEntry::single_dst("10.0.0.2".parse().unwrap(), None),
    );
    let snapshot = dp.dump_snapshot().await.unwrap();
    let remove = compute_diff(
        &RemoteMacTable::new(),
        &snapshot,
        &owned,
        &probes,
        &GroupOwnedMap::new(),
        &instances,
    );
    assert!(matches!(
        remove.ops.as_slice(),
        [DataplaneOp::RemoveRemoteFdb { .. }]
    ));
    let mut moved = l2_macs(true).get(vni, l2_mac()).unwrap().clone();
    moved.remote_vtep_ip = "10.0.0.3".parse().unwrap();
    let mut desired = RemoteMacTable::builder();
    desired.insert(vni, l2_mac(), moved).unwrap();
    let update = compute_diff(
        &desired.build(),
        &snapshot,
        &owned,
        &probes,
        &GroupOwnedMap::new(),
        &instances,
    );
    assert!(matches!(
        update.ops.as_slice(),
        [DataplaneOp::UpdateRemoteFdb { .. }]
    ));
    replace_l2_pvid_with_foreign();
    let mixed = l2_mac_rows();
    for op in [&update.ops[0], &remove.ops[0]] {
        let error = dp
            .apply(op)
            .await
            .expect_err("stale mutation must conflict");
        assert_eq!(error.class(), FailureClass::Conflict, "{op:?}: {error}");
        assert_eq!(l2_mac_rows(), mixed, "{op:?}");
    }
    let error = dp
        .install_fdb_nhg_row(vni, l2_mac(), None, 0x4000_0001)
        .await
        .expect_err("NHG install must check the same scope before mutation");
    assert_eq!(error.class(), FailureClass::Conflict);
    let error = dp
        .remove_fdb_nhg_row(vni, l2_mac(), None)
        .await
        .expect_err("NHG removal must check the same scope before mutation");
    assert_eq!(error.class(), FailureClass::Conflict);
    assert_eq!(l2_mac_rows(), mixed);

    run(
        "bridge",
        &["fdb", "del", &mac, "dev", "vxlan100", "master", "vlan", "1"],
    );
    dp.apply(&update.ops[0])
        .await
        .expect("remote mobility resumes after conflict removal");
    assert!(l2_mac_rows().iter().any(|row| row.contains("dst 10.0.0.3")));
    dp.apply(&remove.ops[0])
        .await
        .expect("owned cleanup remains permitted");
    assert!(l2_mac_rows().is_empty());
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
    //    extern_learn) after deleting the owned master contributor.
    run("bridge", &["fdb", "del", &mac, "dev", "vxlan100", "master"]);
    run(
        "bridge",
        &["fdb", "add", &mac, "dev", "vxlan100", "master", "static"],
    );
    let dump = shell("bridge", &["fdb", "show", "dev", "vxlan100"]);
    assert!(l2_rows_match(&dump, &mac, true), "takeover:\n{dump}");

    // 3. Re-reconcile with the MAC still desired — rustbgpd must NOT
    //    repair its row back over the foreign one.
    intent_tx.send(l2_intent(2, true)).unwrap();
    let counters = wait_for_report_generation(&mut report_rx, 2)
        .await
        .foreign_state_counters;
    assert_eq!(
        (counters.owned_relinquished, counters.replaces_blocked),
        (1, 1)
    );
    let dump = shell("bridge", &["fdb", "show", "dev", "vxlan100"]);
    assert!(
        l2_rows_match(&dump, &mac, true),
        "foreign row must not be replaced by an extern_learn repair:\n{dump}"
    );

    run(
        "bridge",
        &[
            "fdb", "del", &mac, "dev", "vxlan100", "self", "dst", "10.0.0.2",
        ],
    );
    let dump = shell("bridge", &["fdb", "show", "dev", "vxlan100"]);
    assert!(l2_rows_match(&dump, &mac, false), "cleanup:\n{dump}");
    intent_tx.send(l2_intent(3, true)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 3).await;
    assert_eq!(report.foreign_state_counters, Default::default());
    let dump = shell("bridge", &["fdb", "show", "dev", "vxlan100"]);
    assert!(l2_rows_match(&dump, &mac, false), "reconcile:\n{dump}");

    // 4. Withdraw the MAC — the foreign row must survive.
    intent_tx.send(l2_intent(4, false)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 4).await;
    assert_eq!(report.foreign_state_counters, Default::default());
    let dump = shell("bridge", &["fdb", "show", "dev", "vxlan100"]);
    assert!(l2_rows_match(&dump, &mac, false), "withdrawal:\n{dump}");

    // 5. Shutdown drain — the foreign row must survive that too.
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), actor_join)
        .await
        .expect("actor shutdown timed out")
        .expect("actor panicked");
    let dump = shell("bridge", &["fdb", "show", "dev", "vxlan100"]);
    assert!(
        l2_rows_match(&dump, &mac, false),
        "foreign row must survive the shutdown drain:\n{dump}"
    );
}

/// The VXLAN self row (the encap destination) for `mac`, if any.
fn l2_self_row(mac: &str) -> Option<String> {
    shell("bridge", &["fdb", "show", "dev", "vxlan100"])
        .lines()
        .find(|line| line.starts_with(mac) && line.split_whitespace().any(|t| t == "self"))
        .map(str::to_owned)
}

fn has_tokens(row: &Option<String>, tokens: &str) -> bool {
    row.as_deref().is_some_and(|row| {
        let have: Vec<_> = row.split_whitespace().collect();
        tokens.split_whitespace().all(|t| have.contains(&t))
    })
}

/// An owned remote MAC whose VXLAN destination changes out of band.
/// The kernel keeps `extern_learn` per row:
///
/// - `bridge fdb replace ... self dst X extern_learn` keeps the marker on
///   the self row, so the next reconcile rewrites it to the route's VTEP;
/// - `bridge fdb del ... self` leaves our marked bridge master row with
///   no destination; the delete wakes the actor, which restores the row;
/// - `bridge fdb replace ... self dst X` without the marker is an
///   operator write: ownership is relinquished and the row survives
///   withdrawal and shutdown.
#[tokio::test]
async fn l2_owned_destination_drift_is_repaired_and_unmarked_rewrite_relinquished() {
    const TEST: &str = "l2_owned_destination_drift_is_repaired_and_unmarked_rewrite_relinquished";
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged foreign-state test");
        return;
    }
    if !is_inner() {
        let ns = NetnsFixture::create("l2drift");
        setup_l2_topology(&ns);
        run_inner(&ns, TEST);
        return;
    }

    let (intent_tx, mut report_rx, shutdown, actor_join) = spawn_reconcile_actor().await;
    let mac = mac_str(l2_mac());
    let owned = "dst 10.0.0.2 self extern_learn";

    intent_tx.send(l2_intent(1, true)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 1).await;
    assert!(report.failed.is_empty(), "install: {:?}", report.failed);
    assert!(has_tokens(&l2_self_row(&mac), owned), "install");

    // 1. Marker-preserving destination change: repaired in one pass.
    run(
        "bridge",
        &[
            "fdb",
            "replace",
            &mac,
            "dev",
            "vxlan100",
            "self",
            "dst",
            "10.0.0.9",
            "extern_learn",
        ],
    );
    let row = l2_self_row(&mac);
    assert!(has_tokens(&row, "dst 10.0.0.9 extern_learn"), "{row:?}");
    intent_tx.send(l2_intent(2, true)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 2).await;
    assert!(report.failed.is_empty(), "repair: {:?}", report.failed);
    assert_eq!(report.foreign_state_counters, Default::default());
    let row = l2_self_row(&mac);
    assert!(has_tokens(&row, owned), "drifted dst not repaired: {row:?}");

    // 2. Self row deleted, marked master row left without a destination.
    //    The delete wakes the actor (FDB drift), and that pass restores it.
    run("bridge", &["fdb", "del", &mac, "dev", "vxlan100", "self"]);
    let report = tokio::time::timeout(Duration::from_secs(10), report_rx.recv())
        .await
        .expect("timed out waiting for the drift-wake pass")
        .expect("dataplane report channel");
    assert!(report.failed.is_empty(), "restore: {:?}", report.failed);
    let row = l2_self_row(&mac);
    assert!(has_tokens(&row, owned), "self row not restored: {row:?}");

    // 3. Marker-clearing rewrite: foreign, never repaired over.
    run(
        "bridge",
        &[
            "fdb", "replace", &mac, "dev", "vxlan100", "self", "dst", "10.0.0.9",
        ],
    );
    let row = l2_self_row(&mac);
    assert!(
        has_tokens(&row, "dst 10.0.0.9") && !has_tokens(&row, "extern_learn"),
        "{row:?}"
    );
    intent_tx.send(l2_intent(3, true)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 3).await;
    assert_eq!(report.foreign_state_counters.owned_relinquished, 1);
    let foreign = l2_self_row(&mac);
    assert_eq!(foreign, row, "foreign self row was rewritten");

    intent_tx.send(l2_intent(4, false)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 4).await;
    assert_eq!(report.foreign_state_counters.owned_relinquished, 0);
    assert_eq!(l2_self_row(&mac), foreign, "withdrawal");
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), actor_join)
        .await
        .expect("actor shutdown timed out")
        .expect("actor panicked");
    assert_eq!(l2_self_row(&mac), foreign, "shutdown drain");
}

// ─────────────────────────────────────────────────────────────────
// LAN-290: reserved NHID range single-writer contract
// ─────────────────────────────────────────────────────────────────

/// The exact ID the actor's allocator would otherwise hand out first
/// for a per-VTEP member (`VTEP_NH_TAG | 1` = 0x3000_0001) — the
/// strongest clobber proof: without quarantine, `add_nexthop_member`
/// would `NLM_F_REPLACE` the foreign object at this ID.
const FOREIGN_NHID: u32 = 0x3000_0001;

fn l2_nhg_macs(desired: bool) -> RemoteMacTable {
    let mut builder = RemoteMacTable::builder();
    if desired {
        builder
            .insert(
                EvpnInstanceId::new(L2_VNI).unwrap(),
                l2_mac(),
                RemoteMacEntry {
                    remote_vtep_ip: "10.0.0.2".parse().unwrap(),
                    mobility_sequence: None,
                    alias_vtep_ips: vec!["10.0.0.3".parse().unwrap()],
                    alias_group_key: Some((
                        rustbgpd_evpn::EthernetSegmentIdentifier::new([7; 10]),
                        rustbgpd_evpn::EthernetTagId(0),
                    )),
                    single_active_backup_vtep_ip: None,
                    source: RemoteMacSource::EvpnRibBestPath,
                },
            )
            .unwrap();
    }
    builder.build()
}

fn l2_nhg_intent(generation: u64, desired: bool) -> Arc<DataplaneIntent> {
    Arc::new(DataplaneIntent {
        generation,
        instances: Arc::new(l2_instances()),
        remote_macs: Arc::new(l2_nhg_macs(desired)),
        bum_enforcement: Arc::new(BumEnforcementTable::new()),
        ip_vrfs: Arc::new(IpVrfTable::new()),
        remote_ip_prefixes: Arc::new(RemoteIpPrefixTable::new()),
        managed_netdevs: Arc::new(rustbgpd_evpn::ManagedNetdevTable::new()),
    })
}

fn foreign_nhid_line() -> String {
    // `ip nexthop show id <id>` prints one line for the object or
    // nothing when it is absent.
    shell("ip", &["nexthop", "show", "id", &FOREIGN_NHID.to_string()])
}

/// LAN-290: a co-resident netlink writer creates a shape-conflicting
/// object (`ip nexthop add id 0x3000_0001 dev lo` — non-FDB, device
/// nexthop) inside rustbgpd's reserved per-VTEP member range before
/// the daemon starts. rustbgpd must fail closed: quarantine the ID
/// (never hand it out — its own members/groups land on other IDs),
/// never adopt it, never reap it, and spare it through withdrawal and
/// the shutdown drain.
#[tokio::test]
async fn nhid_reserved_range_foreign_object_not_clobbered_adopted_or_reaped() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged foreign-state test");
        return;
    }
    if !is_inner() {
        let ns = NetnsFixture::create("nhid");
        setup_l2_topology(&ns);
        // Co-resident writer squats on the reserved range with a
        // shape rustbgpd never writes (no NHA_FDB, has a device).
        ns.exec(
            "ip",
            &[
                "nexthop",
                "add",
                "id",
                &FOREIGN_NHID.to_string(),
                "dev",
                "lo",
            ],
        );
        run_inner(
            &ns,
            "nhid_reserved_range_foreign_object_not_clobbered_adopted_or_reaped",
        );
        return;
    }

    // ── inner: actor runs inside the netns ──
    let (intent_tx, mut report_rx, shutdown, actor_join) = spawn_reconcile_actor().await;
    let mac = mac_str(l2_mac());

    let before = foreign_nhid_line();
    assert!(
        before.contains("dev lo"),
        "foreign in-range nexthop missing before start: {before}"
    );

    // 1. Install a multi-homed MAC (member NHs + FDB group + row)
    //    through the normal reconcile path. Startup adoption sees the
    //    foreign object and must quarantine, not adopt or delete.
    intent_tx.send(l2_nhg_intent(1, true)).unwrap();
    let report = wait_for_report_generation(&mut report_rx, 1).await;
    assert!(report.failed.is_empty(), "install: {:?}", report.failed);
    let fdb = shell("bridge", &["fdb", "show", "dev", "vxlan100"]);
    assert!(
        fdb.lines().any(|l| l.contains(&mac) && l.contains("nhid")),
        "multi-homed MAC should land as an FDB-NHG row:\n{fdb}"
    );

    // Not clobbered: still a plain `dev lo` object, no gateway, not
    // FDB — the actor's own member NHs landed on other IDs.
    let line = foreign_nhid_line();
    assert!(
        line.contains("dev lo") && !line.contains("via") && !line.contains("fdb"),
        "foreign in-range object must not be NLM_F_REPLACE-clobbered: {line}"
    );

    // 2. A second pass (post-adoption cleanup) must not reap it.
    intent_tx.send(l2_nhg_intent(2, true)).unwrap();
    let _ = wait_for_report_generation(&mut report_rx, 2).await;
    let line = foreign_nhid_line();
    assert!(
        line.contains("dev lo"),
        "foreign object must survive adoption cleanup: {line}"
    );

    // 3. Withdraw the MAC — group/member teardown must spare it.
    intent_tx.send(l2_nhg_intent(3, false)).unwrap();
    let _ = wait_for_report_generation(&mut report_rx, 3).await;
    let line = foreign_nhid_line();
    assert!(
        line.contains("dev lo"),
        "foreign object must survive withdrawal teardown: {line}"
    );

    // 4. Shutdown drain — must spare it too.
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), actor_join).await;
    let line = foreign_nhid_line();
    assert!(
        line.contains("dev lo"),
        "foreign object must survive the shutdown drain: {line}"
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
    let mac = mac_str(l3_local_mac());
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
    assert!(
        matches!(
            report.ip_vrf_status.as_slice(),
            [row] if row.vrf_id == IpVrfId::new(L3_VNI).unwrap()
                && matches!(&row.status, IpVrfStatus::Ready { .. })
        ),
        "install: sole IP-VRF 101 must be Ready: {:?}",
        report.ip_vrf_status
    );
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
    tokio::time::timeout(Duration::from_secs(10), actor_join)
        .await
        .expect("actor shutdown timed out")
        .expect("actor panicked");
    assert_foreign_l3_triple_present("after shutdown drain");
}

/// A bundle member can share its connected subnet with another VTEP. The
/// remote Type 5 for that subnet must not replace the local SVI route, while
/// an unrelated remote-only prefix must still install through the real actor.
#[tokio::test]
async fn l3_connected_prefix_survives_remote_import_withdraw_restore_and_shutdown() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged foreign-state test");
        return;
    }
    if !is_inner() {
        let ns = NetnsFixture::create("l3-connected");
        setup_l3_topology(&ns);
        ns.exec("ip", &["link", "add", "local-ac", "type", "dummy"]);
        ns.exec("ip", &["link", "set", "local-ac", "master", "vrf-test"]);
        ns.exec("ip", &["link", "set", "local-ac", "up"]);
        ns.exec("ip", &["addr", "add", "198.51.100.1/24", "dev", "local-ac"]);
        run_inner(
            &ns,
            "l3_connected_prefix_survives_remote_import_withdraw_restore_and_shutdown",
        );
        return;
    }

    let connected = || {
        let routes = shell("ip", &["route", "show", "table", &L3_TABLE_ID.to_string()]);
        let rows: Vec<_> = routes
            .lines()
            .filter(|line| line.starts_with(L3_PREFIX))
            .collect();
        assert_eq!(rows.len(), 1, "connected prefix inventory: {routes}");
        assert!(
            rows[0].contains("dev local-ac proto kernel scope link src 198.51.100.1"),
            "{routes}"
        );
        let lookup = shell("ip", &["route", "get", "198.51.100.42", "vrf", "vrf-test"]);
        assert!(
            lookup.contains("dev local-ac"),
            "connected lookup changed: {lookup}"
        );
        assert!(
            !lookup.contains("via"),
            "connected lookup recursed: {lookup}"
        );
        rows[0].to_owned()
    };
    let original = connected();
    let control =
        rustbgpd_evpn::EvpnIpPrefixValue::V4(Ipv4Prefix::new("203.0.113.0".parse().unwrap(), 24));
    let (intent_tx, mut report_rx, shutdown, actor_join) = spawn_reconcile_actor().await;
    for (generation, desired) in [(1, true), (2, false), (3, true)] {
        let mut intent = l3_intent(generation, desired);
        if desired {
            Arc::get_mut(&mut Arc::get_mut(&mut intent).unwrap().remote_ip_prefixes)
                .unwrap()
                .insert_resolved(
                    IpVrfId::new(L3_VNI).unwrap(),
                    RemoteIpPrefixEntry::single(
                        control,
                        "10.0.0.2".parse().unwrap(),
                        L3_VNI,
                        l3_router_mac(),
                    ),
                );
        }
        intent_tx.send(intent).unwrap();
        let report = wait_for_report_generation(&mut report_rx, generation).await;
        assert!(
            report.failed.is_empty(),
            "actor apply failures: {:?}",
            report.failed
        );
        assert_eq!(connected(), original);
        let routes = shell("ip", &["route", "show", "table", &L3_TABLE_ID.to_string()]);
        let controls: Vec<_> = routes
            .lines()
            .filter(|line| line.starts_with("203.0.113.0/24"))
            .collect();
        assert_eq!(
            controls.len(),
            usize::from(desired),
            "control prefix: {routes}"
        );
        if desired {
            assert!(
                controls[0].contains("via 10.0.0.2 dev l3vxlan-test proto bgp"),
                "{routes}"
            );
        }
        eprintln!("generation {generation}, desired={desired}:\n{routes}");
    }
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), actor_join)
        .await
        .expect("actor shutdown timed out")
        .expect("actor panicked");
    assert_eq!(connected(), original);
    let routes = shell("ip", &["route", "show", "table", &L3_TABLE_ID.to_string()]);
    assert!(
        !routes.contains("203.0.113.0/24"),
        "shutdown retained owned prefix: {routes}"
    );
}
