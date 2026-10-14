//! Privileged netns proofs for the ADR-0140 hold: the real controller
//! against real bonds and veths, with a scripted RIB.
//!
//! Each test re-runs itself inside a throwaway network namespace. Gated
//! on `EVPN_LINUX_NETNS=1`; run via
//! `bash crates/evpn-linux/tests/docker/run-netns-tests.sh core_isolation`.

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prometheus::Registry;
use rustbgpd_rib::EvpnSessionsSync;
use tokio::sync::{mpsc, watch};

use super::super::receipt::{LOCK_FILE, RECEIPT_FILE};
use super::super::*;
use super::{esi, remote_type4, settings};
use crate::config::{CoreIsolationBinding, CoreIsolationSnapshot};

const INNER: &str = "RUSTBGPD_CORE_ISOLATION_NETNS_INNER";

fn netns_gate() -> bool {
    let enabled = std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1");
    if !enabled {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run the privileged core-isolation tests");
    }
    enabled
}

/// Outer pass: re-run `test` in a throwaway netns and return `false`.
/// Inner pass: return `true`.
fn inner_pass(test: &str) -> bool {
    if std::env::var(INNER).is_ok() {
        return true;
    }
    let ns = format!("rbgp-ci-{}-{}", std::process::id(), test.len());
    let _ = Command::new("ip").args(["netns", "delete", &ns]).output();
    ip(&["netns", "add", &ns]);
    let status = Command::new("ip")
        .args(["netns", "exec", &ns])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "--nocapture",
            &format!("evpn_core_isolation::tests::netns::{test}"),
        ])
        .env(INNER, "1")
        .status()
        .expect("spawn inner");
    let _ = Command::new("ip").args(["netns", "delete", &ns]).output();
    assert!(status.success(), "inner test invocation failed");
    false
}

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().expect("spawn ip");
    assert!(
        out.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn admin_up(name: &str) -> bool {
    let flags = std::fs::read_to_string(format!("/sys/class/net/{name}/flags"))
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap() & 1 == 1
}

fn carrier(name: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{name}/carrier")).is_ok_and(|c| c.trim() == "1")
}

async fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Member names recorded in the receipt; empty when it is absent.
fn receipt_names(dir: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(dir.join(RECEIPT_FILE)) else {
        return Vec::new();
    };
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut names: Vec<String> = json["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["link"]["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

/// A veth pair whose far end (the CE side) is up.
fn veth(name: &str, peer: &str) {
    ip(&["link", "add", name, "type", "veth", "peer", "name", peer]);
    ip(&["link", "set", peer, "up"]);
}

/// `bond0` (802.3ad) with admin-up veth members `m0..mN`.
fn bond_with_members(count: usize) {
    ip(&["link", "set", "lo", "up"]);
    ip(&[
        "link",
        "add",
        "bond0",
        "type",
        "bond",
        "mode",
        "802.3ad",
        "lacp_rate",
        "fast",
    ]);
    for i in 0..count {
        enslave(&format!("m{i}"), &format!("p{i}"));
    }
    ip(&["link", "set", "bond0", "up"]);
}

fn enslave(member: &str, peer: &str) {
    veth(member, peer);
    ip(&["link", "set", member, "master", "bond0"]);
    ip(&["link", "set", member, "up"]);
}

#[derive(Clone)]
struct ScriptedRib(Arc<Mutex<EvpnSessionsSync>>);

impl ScriptedRib {
    fn set(&self, established: usize, synced: bool) {
        *self.0.lock().unwrap() = EvpnSessionsSync {
            established,
            stale: 0,
            synced,
        };
    }
}

/// Answer the controller's RIB reads: one remote Type 4 peer for ESI 1
/// while a session is established, and the scripted session counts.
fn scripted_rib(initial: EvpnSessionsSync) -> (mpsc::Sender<RibUpdate>, ScriptedRib) {
    let state = ScriptedRib(Arc::new(Mutex::new(initial)));
    let (tx, mut rx) = mpsc::channel(16);
    let rib = state.clone();
    tokio::spawn(async move {
        while let Some(update) = rx.recv().await {
            let sync = *rib.0.lock().unwrap();
            if let RibUpdate::QueryEvpnEsSnapshot { reply } = update {
                let es_routes = if sync.established > 0 {
                    vec![remote_type4(esi(1), "10.0.0.2")]
                } else {
                    Vec::new()
                };
                let _ = reply.send(rustbgpd_rib::EvpnEsSnapshot {
                    sessions: sync,
                    es_routes,
                });
            }
        }
    });
    (tx, state)
}

fn binding_snapshot(interfaces: &[&str], hold: u64, backstop: u64) -> Arc<CoreIsolationSnapshot> {
    Arc::new(CoreIsolationSnapshot {
        settings: Some(settings(hold, backstop)),
        bindings: interfaces
            .iter()
            .map(|interface| {
                (
                    (*interface).to_string(),
                    CoreIsolationBinding {
                        esi_text: "00:00:00:00:00:00:00:00:00:01".to_string(),
                        esi: Some(esi(1)),
                        originator_ip: Some("10.0.0.1".parse().unwrap()),
                    },
                )
            })
            .collect(),
    })
}

struct Rig {
    handle: CoreIsolationHandle,
    config: watch::Sender<Arc<CoreIsolationSnapshot>>,
    metrics: BgpMetrics,
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    dir
}

fn start(dir: &Path, rib_tx: mpsc::Sender<RibUpdate>, snapshot: Arc<CoreIsolationSnapshot>) -> Rig {
    let metrics = BgpMetrics::with_registry(Registry::new());
    let (config, config_rx) = watch::channel(snapshot);
    let handle = spawn(
        config_rx,
        CoreIsolationDeps {
            rib_tx,
            metrics: metrics.clone(),
            directory: Some(std::fs::File::open(dir).unwrap()),
            start: tokio::time::Instant::now(),
        },
    );
    Rig {
        handle,
        config,
        metrics,
    }
}

/// Run the release helper on a plain thread: it builds its own runtime,
/// as the one-shot command does.
fn helper(dir: &Path) -> u8 {
    let dir = dir.to_path_buf();
    std::thread::spawn(move || release_core_isolation(&dir))
        .join()
        .unwrap()
}

/// The state at 1 for `interface`, if exactly one.
fn state(metrics: &BgpMetrics, interface: &str) -> Option<String> {
    let mut active = Vec::new();
    for family in metrics.registry().gather() {
        if family.name() != "evpn_es_core_isolation_state" {
            continue;
        }
        for metric in family.get_metric() {
            let labels: std::collections::BTreeMap<_, _> = metric
                .get_label()
                .iter()
                .map(|l| (l.name().to_string(), l.value().to_string()))
                .collect();
            if labels["interface"] == interface
                && (metric.get_gauge().get_value() - 1.0).abs() < f64::EPSILON
            {
                active.push(labels["state"].clone());
            }
        }
    }
    (active.len() == 1).then(|| active.remove(0))
}

/// Isolation downs every bond member with a write-ahead receipt, a member
/// enslaved while isolated is taken down too, a member some other writer
/// took down first is left alone, recovery raises after sync and the
/// settle hold, and clean shutdown raises everything and removes the
/// receipt.
#[tokio::test]
async fn netns_isolation_holds_bond_members_and_shutdown_raises_them() {
    if !netns_gate() || !inner_pass("netns_isolation_holds_bond_members_and_shutdown_raises_them") {
        return;
    }
    bond_with_members(3);
    let dir = private_dir();
    let (rib_tx, rib) = scripted_rib(EvpnSessionsSync {
        established: 1,
        stale: 0,
        synced: true,
    });
    let rig = start(dir.path(), rib_tx, binding_snapshot(&["bond0"], 2, 600));

    // Boot hold: down until EVPN has been synced for the settle time.
    wait_for("startup hold", || !admin_up("m0") && !admin_up("m1")).await;
    // The state publishes after the pass that took the links down.
    wait_for("startup_hold state", || {
        state(&rig.metrics, "bond0").as_deref() == Some("startup_hold")
    })
    .await;
    wait_for("startup release", || admin_up("m0") && admin_up("m1")).await;
    wait_for("receipt cleared", || receipt_names(dir.path()).is_empty()).await;
    assert!(dir.path().join(LOCK_FILE).exists());

    // Another writer takes m2 down; the hold must never raise it.
    ip(&["link", "set", "m2", "down"]);

    // Core lost: m0 and m1 go down with receipt entries; m2 is not owned.
    rib.set(0, false);
    wait_for("isolation", || !admin_up("m0") && !admin_up("m1")).await;
    assert!(!carrier("p0"), "the CE side loses carrier");
    assert_eq!(receipt_names(dir.path()), ["m0", "m1"]);
    wait_for("isolated state", || {
        state(&rig.metrics, "bond0").as_deref() == Some("isolated")
    })
    .await;

    // A member enslaved admin-up while isolated is recorded, then downed.
    enslave("m3", "p3");
    wait_for("new member held", || !admin_up("m3")).await;
    assert_eq!(receipt_names(dir.path()), ["m0", "m1", "m3"]);

    // A held member released from the bond, then enslaved again, comes
    // back admin-up from the kernel; it is taken down again, not left up
    // as overridden.
    ip(&["link", "set", "m1", "nomaster"]);
    wait_for("released member seen outside the bond", || {
        state(&rig.metrics, "bond0").as_deref() == Some("ownership_ambiguous")
    })
    .await;
    ip(&["link", "set", "m1", "master", "bond0"]);
    ip(&["link", "set", "m1", "up"]);
    wait_for("re-enslaved member held again", || {
        !admin_up("m1") && state(&rig.metrics, "bond0").as_deref() == Some("isolated")
    })
    .await;
    assert_eq!(receipt_names(dir.path()), ["m0", "m1", "m3"]);

    // Core back and synced: held through the settle hold, then raised.
    rib.set(1, true);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!admin_up("m0"), "released before the settle hold");
    wait_for("recovery release", || {
        admin_up("m0") && admin_up("m1") && admin_up("m3")
    })
    .await;
    assert!(!admin_up("m2"), "a foreign admin-down is never raised");
    wait_for("receipt cleared", || receipt_names(dir.path()).is_empty()).await;

    // Isolated again, then a clean shutdown raises the owned members.
    rib.set(0, false);
    wait_for("isolation", || !admin_up("m0") && !admin_up("m3")).await;
    rig.handle.release().await;
    assert!(admin_up("m0") && admin_up("m1") && admin_up("m3"));
    assert!(!admin_up("m2"));
    assert!(!dir.path().join(RECEIPT_FILE).exists());
    drop(rig.config);
}

/// A receipt that cannot be published blocks the admin-down: the write is
/// never made ahead of its receipt.
#[tokio::test]
async fn netns_receipt_publication_failure_blocks_the_admin_down() {
    if !netns_gate() || !inner_pass("netns_receipt_publication_failure_blocks_the_admin_down") {
        return;
    }
    bond_with_members(1);
    let dir = private_dir();
    let (rib_tx, _rib) = scripted_rib(EvpnSessionsSync::default());
    // Load an empty receipt while bound to a link that does not exist.
    let rig = start(dir.path(), rib_tx, binding_snapshot(&["absent0"], 1, 600));
    wait_for("startup hold armed", || {
        state(&rig.metrics, "absent0").as_deref() == Some("startup_hold")
    })
    .await;
    // A non-empty directory in the receipt's place defeats the rename
    // even for root.
    std::fs::create_dir(dir.path().join(RECEIPT_FILE)).unwrap();
    std::fs::write(dir.path().join(RECEIPT_FILE).join("x"), b"x").unwrap();
    rig.config
        .send(binding_snapshot(&["bond0"], 1, 600))
        .unwrap();
    wait_for("action_failed", || {
        state(&rig.metrics, "bond0").as_deref() == Some("action_failed")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(admin_up("m0"), "no admin-down without a durable receipt");

    std::fs::remove_dir_all(dir.path().join(RECEIPT_FILE)).unwrap();
    wait_for("held after the receipt publishes", || !admin_up("m0")).await;
    assert_eq!(receipt_names(dir.path()), ["m0"]);
    rig.handle.release().await;
    assert!(admin_up("m0"));
}

/// A renamed owned member stays down as `ownership_ambiguous`; after a
/// simulated crash a restart adopts the matching entry without
/// duplicating it, and the release helper raises exactly the guarded
/// member, discards a foreign-boot entry, and exits non-zero while the
/// ambiguous one remains.
#[tokio::test]
async fn netns_renamed_member_is_ambiguous_and_helper_releases_after_crash() {
    if !netns_gate()
        || !inner_pass("netns_renamed_member_is_ambiguous_and_helper_releases_after_crash")
    {
        return;
    }
    bond_with_members(2);
    let dir = private_dir();
    let dir_path = dir.path().to_path_buf();
    let (rib_tx, _rib) = scripted_rib(EvpnSessionsSync::default());
    let rig = start(
        dir.path(),
        rib_tx.clone(),
        binding_snapshot(&["bond0"], 1, 600),
    );
    wait_for("startup hold", || !admin_up("m0") && !admin_up("m1")).await;
    assert_eq!(receipt_names(dir.path()), ["m0", "m1"]);

    // The helper refuses while the daemon holds the lock, including after
    // the receipt's inode has been replaced by an update.
    assert_eq!(release_core_isolation(dir.path()), 1);

    ip(&["link", "set", "m1", "name", "m1x"]);
    wait_for("ownership_ambiguous", || {
        state(&rig.metrics, "bond0").as_deref() == Some("ownership_ambiguous")
    })
    .await;
    assert!(!admin_up("m1x"), "an ambiguous member is never raised");

    // Crash: the task dies without a release; the kernel drops the lock.
    rig.handle.task.abort();
    let _ = rig.handle.task.await;
    assert!(!admin_up("m0") && !admin_up("m1x"));

    // Restart: the matching entry is adopted into the startup hold, not
    // duplicated; the ambiguous one is kept.
    let restarted = start(dir.path(), rib_tx, binding_snapshot(&["bond0"], 1, 600));
    wait_for("restart reports ambiguity", || {
        state(&restarted.metrics, "bond0").as_deref() == Some("ownership_ambiguous")
    })
    .await;
    assert_eq!(receipt_names(dir.path()), ["m0", "m1"]);
    assert!(!admin_up("m0"));
    restarted.handle.task.abort();
    let _ = restarted.handle.task.await;

    // A foreign-boot entry for a down link is discarded, untouched.
    veth("fx", "fxp");
    let receipt = dir.path().join(RECEIPT_FILE);
    let mut json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&receipt).unwrap()).unwrap();
    let mut foreign = json["links"][0].clone();
    foreign["boot_id"] = "00000000-0000-0000-0000-000000000000".into();
    foreign["link"]["name"] = "fx".into();
    json["links"].as_array_mut().unwrap().push(foreign);
    std::fs::write(&receipt, serde_json::to_vec(&json).unwrap()).unwrap();

    let status = helper(&dir_path);
    assert_eq!(status, 1, "an ambiguous entry keeps the helper non-zero");
    assert!(admin_up("m0"), "the guarded member is raised");
    assert!(!admin_up("m1x"), "the renamed member stays down");
    assert!(!admin_up("fx"), "a foreign-boot entry touches nothing");
    assert_eq!(receipt_names(&dir_path), ["m1"]);

    // The operator raises the renamed link by hand: nothing owned is left
    // down, so the helper drops the entry and succeeds.
    ip(&["link", "set", "m1x", "up"]);
    let status = helper(&dir_path);
    assert_eq!(status, 0);
    assert!(!receipt.exists());
    // Nothing left: a readable directory without a receipt is success.
    assert_eq!(release_core_isolation(&dir_path), 0);
    assert_eq!(release_core_isolation(&dir_path.join("missing")), 1);
}

/// A directly bound veth is its own member; removing the binding
/// releases it through the guarded path.
#[tokio::test]
async fn netns_bound_veth_is_released_when_its_binding_is_removed() {
    if !netns_gate() || !inner_pass("netns_bound_veth_is_released_when_its_binding_is_removed") {
        return;
    }
    veth("v0", "ce0");
    ip(&["link", "set", "v0", "up"]);
    let dir = private_dir();
    let (rib_tx, _rib) = scripted_rib(EvpnSessionsSync::default());
    let rig = start(dir.path(), rib_tx, binding_snapshot(&["v0"], 1, 600));
    wait_for("startup hold", || !admin_up("v0")).await;
    assert!(!carrier("ce0"), "the CE end loses carrier");
    assert_eq!(receipt_names(dir.path()), ["v0"]);

    rig.config.send(binding_snapshot(&[], 1, 600)).unwrap();
    wait_for("released on unbind", || admin_up("v0")).await;
    wait_for("receipt cleared", || receipt_names(dir.path()).is_empty()).await;
    rig.handle.release().await;
}

/// A VLAN on the bound bond, configured as the only uplink, loses carrier
/// when the hold downs the members. The kernel's `IFLA_LINK` names the
/// bond, so the uplink is excluded as `uplink_overlap` and the startup
/// hold still releases instead of reading the VLAN as an isolated core.
#[tokio::test]
async fn netns_vlan_on_bound_bond_uplink_is_excluded_and_releases() {
    if !netns_gate() || !inner_pass("netns_vlan_on_bound_bond_uplink_is_excluded_and_releases") {
        return;
    }
    bond_with_members(2);
    ip(&[
        "link",
        "add",
        "link",
        "bond0",
        "name",
        "bond0.100",
        "type",
        "vlan",
        "id",
        "100",
    ]);
    ip(&["link", "set", "bond0.100", "up"]);
    let dir = private_dir();
    let (rib_tx, _rib) = scripted_rib(EvpnSessionsSync {
        established: 1,
        stale: 0,
        synced: true,
    });
    let mut snapshot = binding_snapshot(&["bond0"], 2, 600);
    Arc::get_mut(&mut snapshot)
        .unwrap()
        .settings
        .as_mut()
        .unwrap()
        .uplinks = vec!["bond0.100".to_string()];
    let rig = start(dir.path(), rib_tx, snapshot);

    wait_for("startup hold", || !admin_up("m0") && !admin_up("m1")).await;
    wait_for("uplink_overlap state", || {
        state(&rig.metrics, "bond0").as_deref() == Some("uplink_overlap")
    })
    .await;
    wait_for("startup release", || admin_up("m0") && admin_up("m1")).await;
    wait_for("receipt cleared", || receipt_names(dir.path()).is_empty()).await;
    rig.handle.release().await;
}
