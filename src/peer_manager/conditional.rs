//! ADR-0137 conditional-advertisement install.
//!
//! The RIB holds the one copy of the definitions and the address-keyed
//! attachments that the export gate reads. This module installs it,
//! restores a captured install on compensation, and reconciles it after
//! config mutations that do not install it explicitly.

use std::sync::Arc;
use std::time::Duration;

use rustbgpd_api::peer_types::PeerKey;
use rustbgpd_rib::{ConditionalAdvertisementCapture, ConditionalAdvertisementSet, RibUpdate};
use tokio::sync::oneshot;
use tracing::{info, warn};

use super::{OperatorReadAdmission, PeerManager, RIB_REPLY_TIMEOUT};
use crate::config::Config;

/// First retry delay after a failed reconcile; doubles per failure.
const RECONCILE_RETRY_INITIAL: Duration = Duration::from_secs(1);
/// Ceiling on the reconcile retry delay.
const RECONCILE_RETRY_MAX: Duration = Duration::from_secs(60);

/// A committed install and the state that restores it.
pub(super) struct ConditionalAdvertisementPrior {
    capture: ConditionalAdvertisementCapture,
    set: ConditionalAdvertisementSet,
    /// Whether `set` was known not to match the RIB when captured: a restore
    /// brings back that doubt with the cache it restores.
    uncertain: bool,
}

/// How long a dispatched conditional-advertisement request waits for the
/// RIB's reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConditionalReplyWait {
    /// Until the RIB answers. The RIB cannot cancel a dequeued request, so a
    /// timer could only misreport a slow but healthy completion as
    /// ambiguous; the owning operation's settlement budget bounds a RIB that
    /// never answers.
    Owned,
    /// At most `RIB_REPLY_TIMEOUT` from the request, for a caller outside any
    /// settlement owner that retries: nothing else would bound the wait, and
    /// readiness is served during it.
    Retrying,
}

/// Why a conditional-advertisement request failed.
#[derive(Debug)]
pub(super) enum ConditionalRequestError {
    /// The request never reached the RIB: nothing changed.
    NotDispatched(String),
    /// The request was dispatched without an acknowledgement: the RIB may
    /// have applied it.
    Unacknowledged(String),
}

impl std::fmt::Display for ConditionalRequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDispatched(message) | Self::Unacknowledged(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl PeerManager {
    /// Send one request to the RIB and wait for its reply. Mailbox admission
    /// has a `RIB_REPLY_TIMEOUT` deadline; nothing is dispatched before it,
    /// so expiry is [`ConditionalRequestError::NotDispatched`] and leaves the
    /// install's certainty as it was. `wait` bounds the reply. A dropped or,
    /// for [`ConditionalReplyWait::Retrying`], late reply leaves the RIB
    /// outcome unknown.
    ///
    /// The request queues behind the RIB's primary-lane work, which can take
    /// seconds after a large export commit, so the wait serves readiness.
    /// It serves operator reads too: they report peer-table and session
    /// state, which the install does not change. The run-loop reconcile has
    /// nothing in flight, and reload and catalog changes already admit reads
    /// at the policy steps around this one.
    async fn conditional_rib_request<T>(
        &mut self,
        wait: ConditionalReplyWait,
        request: impl FnOnce(oneshot::Sender<T>) -> RibUpdate,
    ) -> Result<T, ConditionalRequestError> {
        use ConditionalRequestError::{NotDispatched, Unacknowledged};
        let (reply, response) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + RIB_REPLY_TIMEOUT;
        let rib_tx = self.rib_tx.clone();
        let request = request(reply);
        let round_trip = async move {
            tokio::time::timeout_at(deadline, rib_tx.send(request))
                .await
                .map_err(|_| {
                    NotDispatched(
                        "RIB conditional-advertisement request timed out before dispatch".into(),
                    )
                })?
                .map_err(|_| {
                    NotDispatched("RIB unavailable for conditional-advertisement request".into())
                })?;
            let reply = match wait {
                ConditionalReplyWait::Owned => Ok(response.await),
                ConditionalReplyWait::Retrying => tokio::time::timeout_at(deadline, response).await,
            };
            reply
                .map_err(|_| {
                    Unacknowledged("RIB conditional-advertisement acknowledgement timed out".into())
                })?
                .map_err(|_| {
                    Unacknowledged("RIB dropped conditional-advertisement acknowledgement".into())
                })
        };
        let result = self
            .await_with_readiness(round_trip, OperatorReadAdmission::Served)
            .await;
        if matches!(result, Err(Unacknowledged(_))) {
            self.conditional_install_uncertain = true;
        }
        result
    }

    /// Install `set` unless the RIB already holds it. `Ok(None)` means
    /// nothing changed; `Ok(Some(prior))` restores the previous install.
    pub(super) async fn install_conditional_advertisements(
        &mut self,
        set: ConditionalAdvertisementSet,
        swapping_datasets: &[String],
        wait: ConditionalReplyWait,
    ) -> Result<Option<ConditionalAdvertisementPrior>, ConditionalRequestError> {
        let uncertain = self.conditional_install_uncertain;
        if !uncertain && set == self.conditional_advertisements {
            return Ok(None);
        }
        let capture = self
            .conditional_rib_request(wait, |reply| RibUpdate::InstallConditionalAdvertisements {
                set: set.clone(),
                swapping_datasets: swapping_datasets.to_vec(),
                reply,
            })
            .await?;
        self.conditional_install_uncertain = false;
        info!(
            definitions = set.definitions.len(),
            attached_peers = set.attachments.len(),
            "installed conditional advertisements"
        );
        let set = std::mem::replace(&mut self.conditional_advertisements, set);
        Ok(Some(ConditionalAdvertisementPrior {
            capture,
            set,
            uncertain,
        }))
    }

    /// Reinstate a captured install (generation compensation). Applied
    /// states and settle deadlines are restored, not evaluated again.
    pub(super) async fn restore_conditional_advertisements(
        &mut self,
        prior: ConditionalAdvertisementPrior,
    ) -> Result<(), ConditionalRequestError> {
        self.conditional_rib_request(ConditionalReplyWait::Owned, |reply| {
            RibUpdate::RestoreConditionalAdvertisements {
                capture: prior.capture,
                reply,
            }
        })
        .await?;
        self.conditional_advertisements = prior.set;
        // The restored cache is as certain as it was when captured: one
        // that predates a lost acknowledgement may still name a gate the
        // RIB has removed.
        self.conditional_install_uncertain = prior.uncertain;
        Ok(())
    }

    /// `config`'s install, with the attachments of every live interface-only
    /// binding: a learned endpoint is not in configuration (ADR-0142).
    pub(super) fn conditional_set(
        &self,
        config: &Config,
    ) -> Result<ConditionalAdvertisementSet, crate::config::ConfigError> {
        self.conditional_set_with_bindings(config, &self.unnumbered_binding_endpoints())
    }

    /// [`Self::conditional_set`] for the interface-only `bindings` given.
    ///
    /// A peer whose own neighbor `config` no longer configures keeps the
    /// gate installed for it while it is still in the table: its session is
    /// torn down after this install, and dropping or changing the gate first
    /// could let the RIB export to it what the gate suppresses. Each
    /// definition it names stays as installed, unless `config` edits it:
    /// the edit applies at once to every neighbor `config` attaches, and the
    /// retiring peer is attached instead to a never-evaluated copy of the
    /// installed definition ([`retiring_copy`]), which suppresses everything
    /// that definition controls. Deleting the peer asks for the reconcile
    /// that prunes the gate.
    pub(super) fn conditional_set_with_bindings(
        &self,
        config: &Config,
        bindings: &[(std::net::IpAddr, String)],
    ) -> Result<ConditionalAdvertisementSet, crate::config::ConfigError> {
        let mut set = config.conditional_advertisement_set_with_bindings(bindings)?;
        let installed = &self.conditional_advertisements;
        for (key, peer) in &self.peers {
            let endpoint = key.rib_endpoint();
            let Some(names) = installed.attachments.get(&endpoint) else {
                continue;
            };
            if owner_configured(config, key, peer.transport_config.interface_only) {
                continue;
            }
            let mut kept = Vec::with_capacity(names.len());
            for name in names {
                let Some(definition) = installed
                    .definitions
                    .iter()
                    .find(|definition| definition.name == *name)
                else {
                    kept.push(Arc::clone(name));
                    continue;
                };
                match set
                    .definitions
                    .iter()
                    .find(|candidate| candidate.name == *name)
                {
                    None => {
                        set.definitions.push(definition.clone());
                        kept.push(Arc::clone(name));
                    }
                    Some(candidate) if candidate == definition => kept.push(Arc::clone(name)),
                    Some(_) => {
                        let copy = retiring_copy(definition, &set.definitions);
                        kept.push(Arc::clone(&copy.name));
                        if !set.definitions.contains(&copy) {
                            set.definitions.push(copy);
                        }
                    }
                }
            }
            set.attachments.insert(endpoint, kept);
        }
        Ok(set)
    }

    /// Install `candidate`'s set ahead of a mutation that commits it.
    pub(super) async fn install_conditional_advertisements_for(
        &mut self,
        candidate: &Config,
    ) -> Result<Option<ConditionalAdvertisementPrior>, ConditionalRequestError> {
        let set = self.conditional_set(candidate).map_err(|error| {
            ConditionalRequestError::NotDispatched(format!("conditional advertisements: {error}"))
        })?;
        self.install_conditional_advertisements(set, &[], ConditionalReplyWait::Owned)
            .await
    }

    /// Bring the RIB install in line with `current_config` after a config
    /// replacement that did not install it itself, such as a neighbor
    /// removal dropping its attachments. A failure is retried from the run
    /// loop's `select!` after an exponential backoff, so an unresponsive or
    /// closed RIB costs one bounded attempt per backoff interval instead of
    /// one before every command.
    pub(super) async fn reconcile_conditional_advertisements(&mut self) {
        self.conditional_reconcile_pending = false;
        let set = match self.conditional_set(&self.current_config) {
            Ok(set) => set,
            Err(error) => {
                warn!(%error, "conditional advertisements unresolvable; RIB install unchanged");
                self.conditional_reconcile_retry = None;
                return;
            }
        };
        match self
            .install_conditional_advertisements(set, &[], ConditionalReplyWait::Retrying)
            .await
        {
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
        peer: &PeerKey,
        datasets: &[String],
    ) -> bool {
        self.conditional_advertisements
            .advertise_policy_references(&peer.rib_endpoint(), datasets)
    }

    /// Re-observe conditions whose `condition_policy` reads a swapped
    /// dataset, under the ordinary settle debounce; `changed` definitions,
    /// installed earlier in the same generation, apply immediately.
    /// `Ok(Some(prior))` restores the tracker state from before the
    /// re-observation, for a generation that rolls the dataset swap back.
    pub(super) async fn reobserve_conditional_advertisement_datasets(
        &mut self,
        datasets: &[String],
        changed: Vec<Arc<str>>,
    ) -> Result<Option<ConditionalAdvertisementPrior>, ConditionalRequestError> {
        if !self
            .conditional_advertisements
            .condition_policy_references(datasets)
        {
            return Ok(None);
        }
        let datasets = datasets.to_vec();
        let capture = self
            .conditional_rib_request(ConditionalReplyWait::Owned, |reply| {
                RibUpdate::ReobserveConditionalAdvertisements {
                    datasets,
                    changed,
                    reply,
                }
            })
            .await?;
        Ok(Some(ConditionalAdvertisementPrior {
            capture,
            set: self.conditional_advertisements.clone(),
            uncertain: self.conditional_install_uncertain,
        }))
    }
}

/// Whether `config` still configures the neighbor that owns the peer at
/// `key`: its interface-only neighbor for a learned endpoint, else its
/// static `[[neighbors]]` entry. Another kind of neighbor resolving the same
/// key, such as an interface-only neighbor replacing a static link-local
/// one on its interface, is a different owner.
fn owner_configured(config: &Config, key: &PeerKey, interface_only: bool) -> bool {
    if interface_only {
        return key
            .interface
            .as_deref()
            .is_some_and(|interface| config.neighbors.interface_only_on(interface).is_some());
    }
    let address = key.address.to_string();
    config
        .neighbors
        .iter()
        .any(|neighbor| neighbor.address == address && neighbor.interface == key.interface)
}

/// The retiring copy of an installed `definition` whose name the candidate
/// `definitions` give an edited definition: the same content, marked
/// `retiring`, under a name no other entry of `definitions` uses. The name is
/// derived only from `definition` and `definitions`, so reinstalling an
/// unchanged candidate yields the same copy and the RIB keeps its state.
fn retiring_copy(
    definition: &rustbgpd_rib::ConditionalAdvertisement,
    definitions: &[rustbgpd_rib::ConditionalAdvertisement],
) -> rustbgpd_rib::ConditionalAdvertisement {
    let mut copy = definition.clone();
    copy.retiring = true;
    let mut name = format!("{} (retiring)", definition.name);
    loop {
        copy.name = Arc::from(name.as_str());
        if definitions
            .iter()
            .all(|other| other.name != copy.name || *other == copy)
        {
            return copy;
        }
        name.push('\'');
    }
}
