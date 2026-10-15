//! Actual actor retirement boundaries; no daemon/fleet readiness qualification.

use super::recovery_memory::{populate, verify_memory_identity, RecoveryHarness, Spec};
use super::{oneshot, RibManager, RibUpdate};
use std::time::{Duration, Instant};

fn optional_ns(value: Option<u128>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

fn phase_json(values: &[u64], measured: bool) -> String {
    let elapsed = (measured && values[0] > 0).then_some(u128::from(values[3]));
    format!(
        "{{\"calls\":{},\"keys\":{},\"groups\":{},\"elapsed_ns\":{}}}",
        values[0],
        values[1],
        values[2],
        optional_ns(elapsed)
    )
}

async fn run(spec: Spec, empty: bool, measured: bool) {
    let expected = if empty { [0; 4] } else { spec.seed };
    let harness = RecoveryHarness::setup(1, spec, spec.seed).await;
    harness.verify_group().await;
    populate(&harness, expected).await;
    if empty {
        // PeerUp alone creates no received table. An actual empty receipt
        // creates the empty Adj-RIB-In that the control must then destroy.
        let update = if spec.seed[2] + spec.seed[3] > 0 {
            RibUpdate::VpnRoutesReceived {
                peer: harness.source,
                session_id: 1,
                announced: Vec::new(),
                withdrawn: Vec::new(),
            }
        } else {
            let mut update = super::empty_routes_received(harness.source, Vec::new());
            if let RibUpdate::RoutesReceived { session_id, .. } = &mut update {
                *session_id = 1;
            }
            update
        };
        harness.tx.send(update).await.unwrap();
    }
    let initial = harness.settle(expected).await;
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].announces, expected.map(|n| n as u64));
    assert_eq!(initial[0].withdraws, [0; 4]);
    RibManager::bench_start_retirement_capture(measured);
    let started = measured.then(Instant::now);
    harness
        .tx
        .send(RibUpdate::PeerDown {
            peer: harness.source,
            session_id: 1,
        })
        .await
        .unwrap();
    // The same primary-channel FIFO barrier as the existing peer-down cell.
    let staged = harness.staged().await;
    let operation_ns = started.map(|started| started.elapsed().as_nanos());
    let phases = RibManager::bench_finish_retirement_capture();
    assert!(staged.values().all(|counts| *counts == [0; 4]));
    let settled = harness.settle([0; 4]).await;
    assert_eq!(settled[0].present, [0; 4]);
    assert_eq!(settled[0].announces, initial[0].announces);
    assert_eq!(settled[0].withdraws, expected.map(|n| n as u64));
    let keys = expected.iter().sum::<usize>() as u64;
    assert_eq!(phases[4], 1, "actual detached Adj-RIB-In drop must run");
    assert_eq!(phases[5], keys, "detached Adj-RIB-In cardinality differs");
    if expected[2] + expected[3] > 0 {
        assert_eq!(phases[0], 1, "actual bulk VPN-stage retirement must run");
        assert_eq!(
            phases[1], keys,
            "VPN stage must own the full changed inventory"
        );
        assert!(phases[2] > 0);
    } else {
        assert_eq!(&phases[..4], &[0; 4]);
    }
    // This query is a second actual actor barrier, after folded withdrawal.
    let (reply, answer) = oneshot::channel();
    harness
        .tx
        .send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    assert_eq!(answer.await.unwrap(), 0);
    println!(
        "retirement_receipt {{\"profile\":\"{}\",\"cell\":\"{}\",\"measured\":{},\"receivers\":1,\"keys\":{},\"initial\":{},\"settled\":{},\"vpn_stage\":{},\"adj_rib_in\":{},\"operation_to_barrier_ns\":{}}}",
        spec.name,
        if empty {
            "retirement-empty"
        } else {
            "retirement-full"
        },
        measured,
        keys,
        initial[0].json(),
        settled[0].json(),
        phase_json(&phases[..4], measured),
        phase_json(&phases[4..], measured),
        optional_ns(operation_ns)
    );
}

pub(super) fn main(args: &[String]) {
    assert!(
        args.len() == 2 || (args.len() == 3 && args[2] == "--correctness-only"),
        "usage: rrharness recovery-retirement <retirement-full|retirement-empty> <profile> [--correctness-only]"
    );
    let empty = match args[0].as_str() {
        "retirement-full" => false,
        "retirement-empty" => true,
        _ => panic!("unknown retirement cell"),
    };
    let measured = args.len() == 2;
    assert!(
        matches!(args[1].as_str(), "full-uc" | "full-vpn")
            || (!measured && matches!(args[1].as_str(), "smoke-uc" | "smoke-vpn"))
    );
    if measured {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::env::var("RECOVERY_MEMORY_RUNNER_ENVIRONMENT").as_deref(),
            Ok("github-hosted")
        );
        let cgroup =
            std::env::var("RRHARNESS_RECOVERY_CGROUP").expect("swap-fenced launcher required");
        verify_memory_identity(std::path::Path::new(&cgroup));
    }
    let spec = Spec::named(&args[1]);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(1800), run(spec, empty, measured))
                .await
                .expect("retirement cell did not complete its actual actor barriers");
        });
}
