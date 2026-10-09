//! Privileged netns proof for ingress-replication flood lists.
//!
//! Drives the real [`ReconcileActor`] + `LinuxDataplane` inside an
//! isolated network namespace and pins, against a real kernel, that:
//!
//! - a flood list of two remote VTEPs programs two all-zero-MAC
//!   `NTF_SELF` rows on the instance's VXLAN port, carrying
//!   `extern_learn`;
//! - removing one remote from the list deletes exactly its row;
//! - an operator's static zero-MAC entry on another VNI is never
//!   appended into or deleted, including at shutdown;
//! - on an SVD / collect-metadata VXLAN port the rows are scoped per
//!   VNI with `src_vni`.
//!
//! Gated by `EVPN_LINUX_NETNS=1`; run through `just netns flood_list`
//! or `just netns svd_flood_list`.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_evpn::ip_vrf::RemoteIpPrefixTable;
use rustbgpd_evpn::{
    BridgeVlan, BumEnforcementTable, DataplaneIntent, EvpnInstance, EvpnInstanceId,
    EvpnInstanceTable, IpVrfTable, RemoteMacTable, RouteDistinguisher, RouteTarget,
};
use rustbgpd_evpn_linux::{LinuxDataplane, ReconcileActor, ReconcileActorConfig};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

const LOCAL_IP: &str = "10.255.0.10";

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

struct NetnsFixture {
    name: String,
}

impl NetnsFixture {
    fn create(test_name: &str) -> Self {
        let name = format!("rustbgpd-flood-{test_name}-{}", std::process::id());
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

    /// Re-exec `test_name` inside the netns so the actor's netlink
    /// socket opens there.
    fn run_inner(&self, test_name: &str) {
        let exe = std::env::current_exe().expect("self-exe");
        let status = Command::new("ip")
            .args(["netns", "exec", &self.name])
            .arg(&exe)
            .args(["--exact", "--nocapture", test_name])
            .env("RUSTBGPD_NETNS_INNER", "1")
            .env("EVPN_LINUX_NETNS", "1")
            .status()
            .expect("spawn inner");
        assert!(status.success(), "inner test invocation failed");
    }
}

impl Drop for NetnsFixture {
    fn drop(&mut self) {
        try_run("ip", &["netns", "delete", &self.name]);
    }
}

fn is_inner() -> bool {
    std::env::var("RUSTBGPD_NETNS_INNER").is_ok()
}

fn vni(raw: u32) -> EvpnInstanceId {
    EvpnInstanceId::new(raw).unwrap()
}

fn instance(raw: u32, bridge: &str, vlan: Option<u16>) -> EvpnInstance {
    let mut rd = [0u8; 8];
    rd[2..4].copy_from_slice(&65001u16.to_be_bytes());
    rd[4..8].copy_from_slice(&raw.to_be_bytes());
    EvpnInstance::new(
        vni(raw),
        RouteDistinguisher::new(rd),
        vec![RouteTarget::TwoOctetAs {
            asn: 65001,
            value: raw,
        }],
        LOCAL_IP.parse::<IpAddr>().unwrap(),
        Some(bridge.to_string()),
        false,
    )
    .expect("EvpnInstance")
    .with_bridge_vlan(vlan.map(|v| BridgeVlan::new(u32::from(v)).unwrap()))
}

fn flood_intent(
    generation: u64,
    instances: &[EvpnInstance],
    flood: &[(u32, &[&str])],
) -> Arc<DataplaneIntent> {
    let mut table = EvpnInstanceTable::new();
    for inst in instances {
        table.insert(inst.clone()).expect("insert");
    }
    let flood: BTreeMap<EvpnInstanceId, BTreeSet<IpAddr>> = flood
        .iter()
        .map(|(raw, dsts)| (vni(*raw), dsts.iter().map(|d| d.parse().unwrap()).collect()))
        .collect();
    Arc::new(DataplaneIntent {
        generation,
        instances: Arc::new(table),
        remote_macs: Arc::new(RemoteMacTable::new().with_flood_vteps(flood)),
        bum_enforcement: Arc::new(BumEnforcementTable::new()),
        ip_vrfs: Arc::new(IpVrfTable::new()),
        remote_ip_prefixes: Arc::new(RemoteIpPrefixTable::new()),
        managed_netdevs: Arc::new(rustbgpd_evpn::ManagedNetdevTable::new()),
    })
}

struct Actor {
    intent_tx: watch::Sender<Arc<DataplaneIntent>>,
    report_rx: mpsc::Receiver<rustbgpd_evpn::DataplaneReport>,
    shutdown: CancellationToken,
    join: tokio::task::JoinHandle<()>,
}

impl Actor {
    async fn spawn() -> Self {
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
        let join = tokio::spawn(actor.run());
        Self {
            intent_tx,
            report_rx,
            shutdown,
            join,
        }
    }

    /// Publish `intent` and wait for the pass that applied it.
    async fn publish(&mut self, intent: Arc<DataplaneIntent>) {
        let generation = intent.generation;
        self.intent_tx.send(intent).expect("intent receiver");
        let report = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let report = self.report_rx.recv().await.expect("report channel");
                if report.intent_generation >= generation {
                    return report;
                }
            }
        })
        .await
        .expect("timed out waiting for dataplane report");
        assert!(report.failed.is_empty(), "failed ops: {:?}", report.failed);
    }

    async fn shutdown(self) {
        self.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(10), self.join)
            .await
            .expect("actor drained")
            .expect("actor task");
    }
}

/// Zero-MAC rows on `dev` as `(dst, src_vni, extern_learn)`.
fn flood_rows(dev: &str) -> BTreeSet<(String, Option<String>, bool)> {
    let dump = String::from_utf8_lossy(&run("bridge", &["-d", "fdb", "show", "dev", dev]).stdout)
        .into_owned();
    dump.lines()
        .filter(|line| line.starts_with("00:00:00:00:00:00"))
        .map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let after = |key: &str| {
                words
                    .iter()
                    .position(|w| *w == key)
                    .and_then(|i| words.get(i + 1))
                    .map(|w| (*w).to_string())
            };
            (
                after("dst").expect("flood row carries dst"),
                after("src_vni"),
                words.contains(&"extern_learn"),
            )
        })
        .collect()
}

fn owned_rows(dsts: &[&str], src_vni: Option<&str>) -> BTreeSet<(String, Option<String>, bool)> {
    dsts.iter()
        .map(|d| ((*d).to_string(), src_vni.map(str::to_string), true))
        .collect()
}

fn add_fixed_vxlan(ns: &NetnsFixture, bridge: &str, vxlan: &str, id: &str) {
    ns.exec("ip", &["link", "add", "name", bridge, "type", "bridge"]);
    ns.exec("ip", &["link", "set", bridge, "up"]);
    ns.exec(
        "ip",
        &[
            "link",
            "add",
            "name",
            vxlan,
            "type",
            "vxlan",
            "id",
            id,
            "local",
            LOCAL_IP,
            "dstport",
            "4789",
            "nolearning",
        ],
    );
    ns.exec("ip", &["link", "set", vxlan, "master", bridge]);
    ns.exec("ip", &["link", "set", vxlan, "up"]);
}

#[tokio::test]
async fn linux_reconcile_programs_imet_flood_rows_and_spares_foreign_entry() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }
    let test_name = "linux_reconcile_programs_imet_flood_rows_and_spares_foreign_entry";
    if !is_inner() {
        let ns = NetnsFixture::create("fixed");
        ns.exec(
            "ip",
            &["addr", "add", &format!("{LOCAL_IP}/32"), "dev", "lo"],
        );
        add_fixed_vxlan(&ns, "br100", "vxlan100", "100");
        add_fixed_vxlan(&ns, "br200", "vxlan200", "200");
        // Operator-managed flood row: foreign to rustbgpd.
        ns.exec(
            "bridge",
            &[
                "fdb",
                "append",
                "00:00:00:00:00:00",
                "dev",
                "vxlan200",
                "dst",
                "10.0.0.99",
                "self",
                "permanent",
            ],
        );
        ns.run_inner(test_name);
        return;
    }

    let instances = [instance(100, "br100", None), instance(200, "br200", None)];
    let foreign = BTreeSet::from([("10.0.0.99".to_string(), None, false)]);
    let mut actor = Actor::spawn().await;

    // Two received IMETs for VNI 100, one for VNI 200.
    actor
        .publish(flood_intent(
            1,
            &instances,
            &[(100, &["10.0.0.2", "10.0.0.3"]), (200, &["10.0.0.4"])],
        ))
        .await;
    assert_eq!(
        flood_rows("vxlan100"),
        owned_rows(&["10.0.0.2", "10.0.0.3"], None)
    );
    assert_eq!(
        flood_rows("vxlan200"),
        foreign,
        "a foreign zero-MAC entry must not be appended into"
    );

    // The 10.0.0.3 IMET is withdrawn.
    actor
        .publish(flood_intent(
            2,
            &instances,
            &[(100, &["10.0.0.2"]), (200, &["10.0.0.4"])],
        ))
        .await;
    assert_eq!(flood_rows("vxlan100"), owned_rows(&["10.0.0.2"], None));
    assert_eq!(flood_rows("vxlan200"), foreign);

    actor.shutdown().await;
    assert!(
        flood_rows("vxlan100").is_empty(),
        "shutdown drains owned rows"
    );
    assert_eq!(
        flood_rows("vxlan200"),
        foreign,
        "shutdown drain spares the foreign entry"
    );
}

#[tokio::test]
async fn linux_reconcile_programs_svd_flood_rows_per_vni() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }
    let test_name = "linux_reconcile_programs_svd_flood_rows_per_vni";
    if !is_inner() {
        let ns = NetnsFixture::create("svd");
        ns.exec(
            "ip",
            &["addr", "add", &format!("{LOCAL_IP}/32"), "dev", "lo"],
        );
        ns.exec(
            "ip",
            &[
                "link",
                "add",
                "name",
                "brvlan",
                "type",
                "bridge",
                "vlan_filtering",
                "1",
                "vlan_default_pvid",
                "0",
            ],
        );
        ns.exec("ip", &["link", "set", "brvlan", "up"]);
        ns.exec(
            "ip",
            &[
                "link",
                "add",
                "name",
                "vxlan0",
                "type",
                "vxlan",
                "external",
                "vnifilter",
                "dstport",
                "4789",
                "nolearning",
            ],
        );
        ns.exec("ip", &["link", "set", "vxlan0", "master", "brvlan"]);
        ns.exec("ip", &["link", "set", "vxlan0", "up"]);
        ns.exec(
            "bridge",
            &["link", "set", "dev", "vxlan0", "vlan_tunnel", "on"],
        );
        for (vlan, id) in [("10", "100"), ("20", "200")] {
            ns.exec(
                "bridge",
                &["vlan", "add", "vid", vlan, "dev", "brvlan", "self"],
            );
            ns.exec("bridge", &["vlan", "add", "vid", vlan, "dev", "vxlan0"]);
            ns.exec(
                "bridge",
                &[
                    "vlan",
                    "add",
                    "vid",
                    vlan,
                    "dev",
                    "vxlan0",
                    "tunnel_info",
                    "id",
                    id,
                ],
            );
        }
        ns.run_inner(test_name);
        return;
    }

    let instances = [
        instance(100, "brvlan", Some(10)),
        instance(200, "brvlan", Some(20)),
    ];
    let mut actor = Actor::spawn().await;
    actor
        .publish(flood_intent(
            1,
            &instances,
            &[(100, &["10.0.0.2", "10.0.0.3"]), (200, &["10.0.0.3"])],
        ))
        .await;
    let mut want = owned_rows(&["10.0.0.2", "10.0.0.3"], Some("100"));
    want.extend(owned_rows(&["10.0.0.3"], Some("200")));
    assert_eq!(flood_rows("vxlan0"), want);

    // Withdrawing 10.0.0.3 from VNI 100 leaves VNI 200's row for the
    // same VTEP in place.
    actor
        .publish(flood_intent(
            2,
            &instances,
            &[(100, &["10.0.0.2"]), (200, &["10.0.0.3"])],
        ))
        .await;
    let mut want = owned_rows(&["10.0.0.2"], Some("100"));
    want.extend(owned_rows(&["10.0.0.3"], Some("200")));
    assert_eq!(flood_rows("vxlan0"), want);

    actor.shutdown().await;
    assert!(
        flood_rows("vxlan0").is_empty(),
        "shutdown drains owned rows"
    );
}
