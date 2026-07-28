use std::fs;

use anyhow::{Context, Result};
use rustbgpd_fsm::SessionState;
use rustbgpd_transport::PeerHandle;
use rustbgpd_wire::UpdateMessage;

pub fn runtime(workers: usize) -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?)
}

pub fn is_eor(update: &UpdateMessage) -> bool {
    update.withdrawn_routes.is_empty()
        && update.path_attributes.is_empty()
        && update.nlri.is_empty()
}

pub fn rss_kib() -> Result<(u64, u64)> {
    let status = fs::read_to_string("/proc/self/status")?;
    let field = |name: &str| -> Result<u64> {
        status
            .lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .context("missing process RSS field")?
            .parse()
            .context("invalid process RSS field")
    };
    Ok((field("VmRSS:")?, field("VmHWM:")?))
}

pub async fn assert_established(
    sessions: &[PeerHandle],
    deadline: tokio::time::Instant,
) -> Result<()> {
    for session in sessions {
        loop {
            let state = tokio::time::timeout_at(deadline, session.query_state())
                .await?
                .context("session closed before Established")?;
            if state.fsm_state == SessionState::Established {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    Ok(())
}

pub async fn shutdown(sessions: Vec<PeerHandle>, deadline: tokio::time::Instant) -> Result<()> {
    let tasks = sessions
        .into_iter()
        .map(|session| tokio::spawn(async move { session.shutdown().await }))
        .collect::<Vec<_>>();
    for task in tasks {
        let _ = tokio::time::timeout_at(deadline, task).await???;
    }
    Ok(())
}
