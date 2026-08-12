use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use rustbgpd_api::health_probe::DaemonGate;
use rustbgpd_api::runtime_config_settlement::{
    AMBIGUOUS_CONFIG_EXIT_STATUS, RuntimeConfigOperationKind, RuntimeConfigSettlementWatchdog,
};
use rustbgpd_api::server::RuntimeConfigCoordinator;
use tokio::sync::Semaphore;

const CHILD_ENV: &str = "RUSTBGPD_SETTLEMENT_EXIT_CHILD";

#[test]
fn executor_loss_uses_production_exit_status() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let coordinator = RuntimeConfigCoordinator::new();
            let coordinator_permit = coordinator.acquire().await.unwrap();
            let stream_admission = Arc::new(Semaphore::new(1));
            let stream_permit = Arc::clone(&stream_admission).acquire_owned().await.unwrap();
            let watchdog = RuntimeConfigSettlementWatchdog::new();
            let (_operation, guard) = watchdog.register_owned(
                RuntimeConfigOperationKind::Apply,
                coordinator,
                coordinator_permit,
                DaemonGate::new(),
                Some(stream_permit),
                Some(stream_admission),
                Arc::new(AtomicBool::new(false)),
            );
            drop(guard);
            std::future::pending::<()>().await;
        });
        unreachable!();
    }

    let started = Instant::now();
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("executor_loss_uses_production_exit_status")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(AMBIGUOUS_CONFIG_EXIT_STATUS));
    assert!(started.elapsed() <= Duration::from_secs(15));
}
