use std::fs;

use anyhow::{ensure, Context, Result};
use rustbgpd_fsm::SessionState;
use rustbgpd_transport::PeerHandle;
use rustbgpd_wire::{Message, UpdateMessage};
use tokio::sync::{mpsc, oneshot};

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

pub async fn send_before<T>(
    sender: &mpsc::Sender<T>,
    update: T,
    deadline: tokio::time::Instant,
) -> Result<()> {
    tokio::time::timeout_at(deadline, sender.send(update))
        .await?
        .map_err(|_| anyhow::anyhow!("injection channel closed"))?;
    Ok(())
}

pub async fn start_after_keepalives(
    receiver: &mut mpsc::Receiver<Message>,
    start: oneshot::Receiver<std::time::Instant>,
    deadline: tokio::time::Instant,
) -> Result<std::time::Instant> {
    let started = tokio::time::timeout_at(deadline, start).await??;
    loop {
        match receiver.try_recv() {
            Ok(Message::Keepalive) => {}
            Err(mpsc::error::TryRecvError::Empty) => return Ok(started),
            Ok(_) | Err(mpsc::error::TryRecvError::Disconnected) => {
                ensure!(false, "non-KEEPALIVE message queued before T0")
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn full_injection_channel_obeys_absolute_deadline() {
        let (sender, _receiver) = mpsc::channel(1);
        sender.send(1_u8).await.unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(10);
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            send_before(&sender, 2_u8, deadline),
        )
        .await
        .expect("injection helper ignored its deadline");
        assert!(result.is_err());
    }
}
