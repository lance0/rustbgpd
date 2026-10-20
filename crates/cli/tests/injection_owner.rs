//! ADR-0141 lease ownership on `rbgp rib delete` and `rbgp flowspec delete`,
//! and the lease read-back, through the mock gRPC server.

use std::process::{Command, Output};

use rustbgpd_api::proto;

#[path = "../src/test_support.rs"]
#[allow(
    dead_code,
    reason = "shared CLI mock includes services unused by this contract"
)]
mod test_support;

fn rbgp(addr: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", addr])
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run rbgp")
}

const RIB_DELETE: &[&str] = &["rib", "delete", "198.51.100.7/32"];
const FLOWSPEC_DELETE: &[&str] = &[
    "flowspec",
    "delete",
    "-a",
    "ipv4_flowspec",
    "--match",
    "dest=203.0.113.7/32",
];

/// A delete of an owned entry without the owner fails with exit 1, names
/// the owner, and points at both flags; `--owner` and `--override-owner`
/// reach the daemon and succeed; the two flags together are a usage error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_names_the_owner_and_points_at_the_flags() {
    let server = test_support::spawn_mock_server(None).await;
    *server.state.injected_entry_owner.lock().await = "rtbh-pop1".to_string();
    *server.state.delete_flowspec_matches.lock().await = true;

    for base in [RIB_DELETE, FLOWSPEC_DELETE] {
        let refused = rbgp(&server.addr, base);
        assert_eq!(refused.status.code(), Some(1), "{refused:?}");
        assert!(refused.stdout.is_empty(), "{refused:?}");
        assert_eq!(
            String::from_utf8(refused.stderr).unwrap(),
            "Error: precondition failed: key is held by owner \"rtbh-pop1\"\n  \
             hint: pass --owner with the entry's lease owner (omit it for an unowned entry), \
             or --override-owner to delete it whatever its owner\n"
        );

        for flags in [&["--owner", "rtbh-pop1"][..], &["--override-owner"][..]] {
            let args: Vec<&str> = base.iter().chain(flags).copied().collect();
            let deleted = rbgp(&server.addr, &args);
            assert!(deleted.status.success(), "{args:?}: {deleted:?}");
        }

        let args: Vec<&str> = base
            .iter()
            .chain(&["--owner", "rtbh-pop1", "--override-owner"])
            .copied()
            .collect();
        let usage = rbgp(&server.addr, &args);
        assert_eq!(usage.status.code(), Some(64), "{usage:?}");
    }

    let path = server.state.last_delete_path.lock().await.clone().unwrap();
    assert_eq!((path.owner.as_str(), path.override_owner), ("", true));
    let rule = server
        .state
        .last_delete_flowspec
        .lock()
        .await
        .clone()
        .unwrap();
    assert_eq!((rule.owner.as_str(), rule.override_owner), ("", true));
}

/// `--owner` is sent verbatim; without it the delete names no owner.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_sends_the_named_owner() {
    let server = test_support::spawn_mock_server(None).await;
    *server.state.injected_entry_owner.lock().await = "ctl".to_string();
    let args: Vec<&str> = RIB_DELETE
        .iter()
        .chain(&["--owner", "ctl"])
        .copied()
        .collect();
    assert!(rbgp(&server.addr, &args).status.success());
    let path = server.state.last_delete_path.lock().await.clone().unwrap();
    assert_eq!((path.owner.as_str(), path.override_owner), ("ctl", false));

    *server.state.injected_entry_owner.lock().await = String::new();
    assert!(rbgp(&server.addr, RIB_DELETE).status.success());
    let path = server.state.last_delete_path.lock().await.clone().unwrap();
    assert_eq!((path.owner.as_str(), path.override_owner), ("", false));
}

/// The locally injected FlowSpec view shows an owned rule's lease in text
/// and JSON.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flowspec_rows_show_the_lease() {
    let server = test_support::spawn_mock_server(None).await;
    *server.state.list_flowspec_response.lock().await = proto::ListFlowSpecResponse {
        received_routes: vec![proto::ReceivedFlowSpecRouteEntry {
            route: Some(proto::FlowSpecRouteEntry {
                components: vec![proto::FlowSpecComponent {
                    r#type: 1,
                    prefix: "203.0.113.7/32".into(),
                    value: String::new(),
                    offset: 0,
                }],
                peer_address: "0.0.0.0".into(),
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                injection_owner: "rtbh-pop1".into(),
                lease_generation: Some(proto::LeaseGeneration {
                    incarnation: 42,
                    sequence: 3,
                }),
                lease_remaining_ms: Some(0),
                ..Default::default()
            }),
            selected: true,
            ..Default::default()
        }],
        received_view: true,
        ..Default::default()
    };
    let text = rbgp(&server.addr, &["flowspec", "received", "0.0.0.0"]);
    assert!(text.status.success(), "{text:?}");
    assert!(
        String::from_utf8(text.stdout).unwrap().starts_with(
            "  match [dest=203.0.113.7/32] action [] from 0.0.0.0 (ipv4_flowspec) lease rtbh-pop1 expired\n"
        )
    );
    let json = rbgp(&server.addr, &["--json", "flowspec", "received", "0.0.0.0"]);
    assert!(json.status.success(), "{json:?}");
    let rows: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        rows[0]["route"]["lease"],
        serde_json::json!({
            "owner": "rtbh-pop1",
            "generation": {"incarnation": "42", "sequence": 3},
            "remaining_ms": 0,
        })
    );
}
