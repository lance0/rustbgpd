//! ADR-0137 conditional-advertisement install.
//!
//! The RIB holds the one copy of the definitions and the address-keyed
//! attachments that the export gate reads. This module installs it,
//! restores a captured install on compensation, and reconciles it after
//! config mutations that do not install it explicitly.

use std::time::Duration;

use rustbgpd_rib::{ConditionalAdvertisementCapture, ConditionalAdvertisementSet, RibUpdate};
use tokio::sync::oneshot;
use tracing::{info, warn};

use super::{PeerManager, RIB_REPLY_TIMEOUT};
use crate::config::Config;

/// First retry delay after a failed reconcile; doubles per failure.
const RECONCILE_RETRY_INITIAL: Duration = Duration::from_secs(1);
/// Ceiling on the reconcile retry delay.
const RECONCILE_RETRY_MAX: Duration = Duration::from_secs(60);

/// A committed install and the state that restores it.
pub(super) struct ConditionalAdvertisementPrior {
    capture: ConditionalAdvertisementCapture,
    set: ConditionalAdvertisementSet,
}

impl PeerManager {
    /// Send one request to the RIB and wait for its reply. Mailbox admission
    /// and the acknowledgement share one absolute deadline, so a full actor
    /// mailbox cannot stretch the request past `RIB_REPLY_TIMEOUT`. Any
    /// failure after the send leaves the RIB outcome unknown.
    async fn conditional_rib_request<T>(
        &self,
        request: impl FnOnce(oneshot::Sender<T>) -> RibUpdate,
    ) -> Result<T, String> {
        let (reply, response) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + RIB_REPLY_TIMEOUT;
        tokio::time::timeout_at(deadline, self.rib_tx.send(request(reply)))
            .await
            .map_err(|_| "RIB conditional-advertisement request timed out before dispatch")?
            .map_err(|_| "RIB unavailable for conditional-advertisement request")?;
        tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| "RIB conditional-advertisement acknowledgement timed out".to_string())?
            .map_err(|_| "RIB dropped conditional-advertisement acknowledgement".to_string())
    }

    /// Install `set` unless the RIB already holds it. `Ok(None)` means
    /// nothing changed; `Ok(Some(prior))` restores the previous install.
    pub(super) async fn install_conditional_advertisements(
        &mut self,
        set: ConditionalAdvertisementSet,
    ) -> Result<Option<ConditionalAdvertisementPrior>, String> {
        if set == self.conditional_advertisements {
            return Ok(None);
        }
        let capture = self
            .conditional_rib_request(|reply| RibUpdate::InstallConditionalAdvertisements {
                set: set.clone(),
                reply,
            })
            .await?;
        info!(
            definitions = set.definitions.len(),
            attached_peers = set.attachments.len(),
            "installed conditional advertisements"
        );
        let set = std::mem::replace(&mut self.conditional_advertisements, set);
        Ok(Some(ConditionalAdvertisementPrior { capture, set }))
    }

    /// Reinstate a captured install (generation compensation). Applied
    /// states and settle deadlines are restored, not evaluated again.
    pub(super) async fn restore_conditional_advertisements(
        &mut self,
        prior: ConditionalAdvertisementPrior,
    ) -> Result<(), String> {
        self.conditional_rib_request(|reply| RibUpdate::RestoreConditionalAdvertisements {
            capture: prior.capture,
            reply,
        })
        .await?;
        self.conditional_advertisements = prior.set;
        Ok(())
    }

    /// Install `candidate`'s set ahead of a mutation that commits it.
    pub(super) async fn install_conditional_advertisements_for(
        &mut self,
        candidate: &Config,
    ) -> Result<Option<ConditionalAdvertisementPrior>, String> {
        let set = candidate
            .conditional_advertisement_set()
            .map_err(|error| format!("conditional advertisements: {error}"))?;
        self.install_conditional_advertisements(set).await
    }

    /// Bring the RIB install in line with `current_config` after a config
    /// replacement that did not install it itself, such as a neighbor
    /// removal dropping its attachments. A failure is retried from the run
    /// loop's `select!` after an exponential backoff, so an unresponsive or
    /// closed RIB costs one bounded attempt per backoff interval instead of
    /// one before every command.
    pub(super) async fn reconcile_conditional_advertisements(&mut self) {
        self.conditional_reconcile_pending = false;
        let set = match self.current_config.conditional_advertisement_set() {
            Ok(set) => set,
            Err(error) => {
                warn!(%error, "conditional advertisements unresolvable; RIB install unchanged");
                self.conditional_reconcile_retry = None;
                return;
            }
        };
        match self.install_conditional_advertisements(set).await {
            Ok(_) => self.conditional_reconcile_retry = None,
            Err(error) => {
                let backoff = self
                    .conditional_reconcile_retry
                    .map_or(RECONCILE_RETRY_INITIAL, |(_, prior)| {
                        (prior * 2).min(RECONCILE_RETRY_MAX)
                    });
                warn!(
                    %error,
                    retry_in_ms = backoff.as_millis(),
                    "conditional advertisement reconcile failed; retrying after backoff"
                );
                self.conditional_reconcile_retry =
                    Some((tokio::time::Instant::now() + backoff, backoff));
            }
        }
    }

    /// Whether an `advertise_policy` attached to `peer` reads a swapped
    /// dataset (the peer then joins the export re-evaluation).
    pub(super) fn conditional_advertise_policy_references(
        &self,
        peer: std::net::IpAddr,
        datasets: &[String],
    ) -> bool {
        self.conditional_advertisements
            .advertise_policy_references(peer, datasets)
    }

    /// Re-observe conditions whose `condition_policy` reads a swapped
    /// dataset, under the ordinary settle debounce. `Ok(Some(prior))`
    /// restores the tracker state from before the re-observation, for a
    /// generation that rolls the dataset swap back.
    pub(super) async fn reobserve_conditional_advertisement_datasets(
        &self,
        datasets: &[String],
    ) -> Result<Option<ConditionalAdvertisementPrior>, String> {
        if !self
            .conditional_advertisements
            .condition_policy_references(datasets)
        {
            return Ok(None);
        }
        let datasets = datasets.to_vec();
        let capture = self
            .conditional_rib_request(|reply| RibUpdate::ReobserveConditionalAdvertisements {
                datasets,
                reply,
            })
            .await?;
        Ok(Some(ConditionalAdvertisementPrior {
            capture,
            set: self.conditional_advertisements.clone(),
        }))
    }
}
