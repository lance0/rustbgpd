use std::net::IpAddr;

use tracing::{info, warn};

use rustbgpd_api::peer_types::{DynamicRangeError, PeerKey};
use rustbgpd_transport::{TcpAoAlgorithm, TcpAoConfig as TransportTcpAoConfig, TcpAoKeyring};

use crate::config::Config;

use super::{ManagedPeer, PeerManager};

/// Resolved dynamic neighbor range used for prefix matching at connection time.
pub(super) struct DynamicRange {
    pub(super) addr: IpAddr,
    pub(super) prefix_len: u8,
    pub(super) peer_group: String,
    pub(super) remote_asn: u32,
    pub(super) description: Option<String>,
    /// Exact keyring for this direct listener owner. This is seeded into an
    /// accepted dynamic session's transport config; it is not inferred from a
    /// covering-owner socket inventory.
    pub(super) tcp_ao: Option<TcpAoKeyring>,
}

/// Canonical dynamic range that accepted a live peer.
///
/// Stored on `ManagedPeer` for future transaction targeting. It deliberately
/// uses the effective prefix key instead of the literal TOML prefix, so host-bit
/// or formatting variants cannot split attribution for the same address set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AcceptedDynamicRange {
    pub(super) addr: IpAddr,
    pub(super) prefix_len: u8,
    pub(super) peer_group: String,
}

impl DynamicRange {
    /// True when `addr` falls within this range's prefix.
    fn covers(&self, addr: IpAddr) -> bool {
        match (addr, self.addr) {
            (IpAddr::V4(peer), IpAddr::V4(net)) => {
                if self.prefix_len > 32 {
                    return false;
                }
                let mask = if self.prefix_len == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (u32::from(peer) & mask) == (u32::from(net) & mask)
            }
            (IpAddr::V6(peer), IpAddr::V6(net)) => {
                if self.prefix_len > 128 {
                    return false;
                }
                let mask = if self.prefix_len == 0 {
                    0u128
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (u128::from(peer) & mask) == (u128::from(net) & mask)
            }
            _ => false, // IPv4/IPv6 mismatch
        }
    }

    pub(super) fn accepted_attribution(&self) -> AcceptedDynamicRange {
        let (addr, prefix_len) = crate::config::effective_prefix(self.addr, self.prefix_len);
        AcceptedDynamicRange {
            addr,
            prefix_len,
            peer_group: self.peer_group.clone(),
        }
    }
}

/// Select the most-specific (longest-prefix) dynamic range covering `addr`.
///
/// Overlapping ranges resolve by prefix length, not declaration order, so a
/// `/24` wins over a `/16` regardless of TOML order — the longest-prefix-match
/// behavior operators expect from FRR/GoBGP. Among equal-length matches (an
/// exact-duplicate prefix, which is a config-level concern) the last declared
/// wins, per `Iterator::max_by_key`.
fn select_dynamic_range(ranges: &[DynamicRange], addr: IpAddr) -> Option<&DynamicRange> {
    ranges
        .iter()
        .filter(|r| r.covers(addr))
        .max_by_key(|r| r.prefix_len)
}

/// Parse an `addr/len` dynamic-range prefix with the same bounds as
/// config-load validation. Returns the unmasked address + length.
fn parse_dynamic_prefix(prefix: &str) -> Result<(IpAddr, u8), String> {
    let (addr_s, len_s) = prefix
        .split_once('/')
        .ok_or_else(|| format!("invalid prefix {prefix:?}: expected addr/len"))?;
    let addr: IpAddr = addr_s
        .parse()
        .map_err(|e| format!("invalid prefix {prefix:?}: {e}"))?;
    let len: u8 = len_s
        .parse()
        .map_err(|e| format!("invalid prefix {prefix:?}: {e}"))?;
    match addr {
        IpAddr::V4(_) if len > 32 => Err(format!(
            "invalid prefix {prefix:?}: IPv4 prefix length must be 0..=32"
        )),
        IpAddr::V6(_) if len > 128 => Err(format!(
            "invalid prefix {prefix:?}: IPv6 prefix length must be 0..=128"
        )),
        _ => Ok((addr, len)),
    }
}

/// Snapshot of a removed dynamic peer's unfired hot-apply intent. Carried
/// across the auto-removal that fires when a dynamic peer goes back to
/// Idle so a re-establishing peer at the same address inherits the retry.
/// Without this, a transient TCP drop on a `[[dynamic_neighbors]]` peer
/// that was mid-`pending_refresh` would silently drop the unfired Route
/// Refresh / export-apply — same correctness risk that
/// `ManagedPeer::pending_refresh` / `pending_export_apply` exist to close.
/// The RFC 8326 initiator toggle lives here too: dynamic auto-removal drops
/// the whole `ManagedPeer`, so this side table is the only place to preserve
/// an operator's maintenance-window `GShut` toggle across re-establishment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct DeadLetteredPending {
    pub(super) refresh: bool,
    pub(super) export_apply: bool,
    pub(super) graceful_shutdown: bool,
}

impl PeerManager {
    pub(super) fn parse_dynamic_ranges(config: &Config) -> Vec<DynamicRange> {
        config
            .dynamic_neighbors
            .iter()
            .filter_map(|dn| {
                let parts: Vec<&str> = dn.prefix.split('/').collect();
                let addr: IpAddr = parts.first()?.parse().ok()?;
                let prefix_len: u8 = parts.get(1)?.parse().ok()?;
                Some(DynamicRange {
                    addr,
                    prefix_len,
                    peer_group: dn.peer_group.clone(),
                    remote_asn: dn.remote_asn,
                    description: dn.description.clone(),
                    tcp_ao: dn.tcp_ao.as_ref().map(|tcp_ao| {
                        TcpAoKeyring(
                            tcp_ao
                                .iter()
                                .map(|key| TransportTcpAoConfig {
                                    key: key.key.clone().into(),
                                    send_id: key.send_id,
                                    recv_id: key.recv_id,
                                    algorithm: TcpAoAlgorithm::from_linux_name(&key.algorithm)
                                        .expect("validated dynamic TCP-AO algorithm"),
                                    preferred: key.preferred,
                                    deprecated: key.deprecated,
                                })
                                .collect(),
                        )
                    }),
                })
            })
            .collect()
    }

    /// Find the dynamic neighbor range covering `addr`, preferring the
    /// **most specific** (longest-prefix) match when ranges overlap — so a
    /// `/24` wins over a `/16` regardless of TOML declaration order. This is
    /// the longest-prefix-match behavior operators expect from FRR/GoBGP;
    /// first-match-by-declaration-order would make the winning peer-group
    /// depend on config ordering, which surprises operators.
    pub(super) fn match_dynamic_range(&self, addr: IpAddr) -> Option<&DynamicRange> {
        select_dynamic_range(&self.dynamic_ranges, addr)
    }

    /// Add a dynamic neighbor range at runtime. Validates identically to
    /// config-load (peer-group exists, peer-group not BFD-enabled, prefix
    /// bounds, no exact-duplicate effective prefix), then updates both the
    /// live `dynamic_ranges` and the `current_config` snapshot so a later
    /// `ConfigEvent` persists it. Overlapping ranges of different lengths are
    /// allowed — longest-prefix-match resolves them at accept time.
    pub(super) fn add_dynamic_range(
        &mut self,
        prefix: String,
        peer_group: String,
        remote_asn: u32,
        description: Option<String>,
    ) -> Result<(), DynamicRangeError> {
        let (addr, prefix_len) =
            parse_dynamic_prefix(&prefix).map_err(DynamicRangeError::Invalid)?;

        let Some(group) = self.current_config.peer_groups.get(&peer_group) else {
            return Err(DynamicRangeError::NotFound(format!(
                "peer_group {peer_group:?} not defined"
            )));
        };
        if group.bfd.as_ref().is_some_and(|b| b.enabled) {
            return Err(DynamicRangeError::Invalid(format!(
                "peer_group {peer_group:?} enables BFD, which is not supported for \
                 dynamic neighbors (static neighbors only in v1 — see ADR-0067)"
            )));
        }

        let key = crate::config::effective_prefix(addr, prefix_len);
        if self.current_config.dynamic_neighbors.iter().any(|range| {
            range.tcp_ao.is_some()
                && crate::config::effective_prefix_str(&range.prefix).is_some_and(|protected| {
                    crate::config::dynamic_prefixes_intersect(key, protected)
                })
        }) {
            return Err(DynamicRangeError::Invalid(format!(
                "dynamic range {}/{} overlaps a startup-pinned TCP-AO range; restart \
                 rustbgpd with an updated configuration instead",
                key.0, key.1
            )));
        }
        if self.current_config.neighbors.iter().any(|neighbor| {
            neighbor.tcp_ao.is_some()
                && neighbor.address.parse::<IpAddr>().is_ok_and(|address| {
                    crate::config::dynamic_prefixes_intersect(
                        key,
                        (address, if address.is_ipv4() { 32 } else { 128 }),
                    )
                })
        }) {
            return Err(DynamicRangeError::Invalid(format!(
                "dynamic range {}/{} contains a startup-pinned static TCP-AO neighbor; \
                 restart rustbgpd with an updated configuration instead",
                key.0, key.1
            )));
        }
        if self
            .dynamic_ranges
            .iter()
            .any(|r| crate::config::effective_prefix(r.addr, r.prefix_len) == key)
        {
            return Err(DynamicRangeError::AlreadyExists(format!(
                "dynamic range {}/{} already exists",
                key.0, key.1
            )));
        }

        self.dynamic_ranges.push(DynamicRange {
            addr,
            prefix_len,
            peer_group: peer_group.clone(),
            remote_asn,
            description: description.clone(),
            tcp_ao: None,
        });
        self.current_config
            .dynamic_neighbors
            .push(crate::config::DynamicNeighborConfig {
                prefix,
                peer_group,
                remote_asn,
                description,
                tcp_ao: None,
            });
        Ok(())
    }

    /// Remove a dynamic neighbor range at runtime, matched by effective prefix
    /// (so a host-bit or formatting variant of the same network still removes
    /// the right entry). Does **not** tear down already-established dynamic
    /// peers — they keep running and auto-remove when they next hit Idle; the
    /// removal only stops *future* accepts.
    /// Returns the removed range's config so a failed persist can roll the
    /// mutation back by re-adding the exact range.
    pub(super) fn delete_dynamic_range(
        &mut self,
        prefix: &str,
    ) -> Result<crate::config::DynamicNeighborConfig, DynamicRangeError> {
        let (addr, prefix_len) =
            parse_dynamic_prefix(prefix).map_err(DynamicRangeError::Invalid)?;
        let key = crate::config::effective_prefix(addr, prefix_len);

        if self.current_config.dynamic_neighbors.iter().any(|range| {
            range.tcp_ao.is_some()
                && crate::config::effective_prefix_str(&range.prefix) == Some(key)
        }) {
            return Err(DynamicRangeError::Invalid(format!(
                "dynamic TCP-AO range {}/{} is startup-pinned; restart rustbgpd to remove it",
                key.0, key.1
            )));
        }

        // Snapshot the config entry being removed (owned) before mutating, so
        // rollback can restore the exact range. dynamic_ranges and
        // current_config.dynamic_neighbors are kept in lockstep by add/delete,
        // so this is Some whenever the matcher held the range.
        let removed = self
            .current_config
            .dynamic_neighbors
            .iter()
            .find(|dn| {
                parse_dynamic_prefix(&dn.prefix)
                    .is_ok_and(|(a, l)| crate::config::effective_prefix(a, l) == key)
            })
            .cloned()
            .ok_or_else(|| {
                DynamicRangeError::NotFound(format!("dynamic range {}/{} not found", key.0, key.1))
            })?;

        let before = self.dynamic_ranges.len();
        self.dynamic_ranges
            .retain(|r| crate::config::effective_prefix(r.addr, r.prefix_len) != key);
        if self.dynamic_ranges.len() == before {
            return Err(DynamicRangeError::NotFound(format!(
                "dynamic range {}/{} not found",
                key.0, key.1
            )));
        }

        self.current_config.dynamic_neighbors.retain(|dn| {
            parse_dynamic_prefix(&dn.prefix)
                .map_or(true, |(a, l)| crate::config::effective_prefix(a, l) != key)
        });
        let affected: Vec<PeerKey> = self
            .peers
            .iter()
            .filter(|(_, managed)| {
                managed.is_dynamic
                    && managed
                        .accepted_dynamic_range
                        .as_ref()
                        .is_some_and(|accepted| {
                            accepted.addr == key.0 && accepted.prefix_len == key.1
                        })
            })
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in affected {
            self.invalidate_max_prefix_restart(&peer);
        }
        Ok(removed)
    }

    pub(super) fn dynamic_peer_still_allowed_by_current_ranges(
        &self,
        managed: &ManagedPeer,
    ) -> bool {
        let Some(accepted) = managed.accepted_dynamic_range.as_ref() else {
            return false;
        };
        self.dynamic_ranges.iter().any(|range| {
            // `accepted` is masked via `effective_prefix` (see
            // `accepted_attribution`), but `DynamicRange` keeps the raw
            // configured addr/len. Normalize the range side the same way the
            // live-policy targeter and the dynamic-range matchers do, so a
            // host-bit-bearing prefix (`192.0.2.5/24`) still matches its masked
            // attribution (`192.0.2.0/24`) and isn't wrongly reaped on rollback.
            let (range_addr, range_len) =
                crate::config::effective_prefix(range.addr, range.prefix_len);
            range_addr == accepted.addr
                && range_len == accepted.prefix_len
                && range.peer_group == accepted.peer_group
                && (range.remote_asn == 0 || range.remote_asn == managed.remote_asn)
        })
    }

    pub(super) fn reconcile_stale_dynamic_max_prefix_restarts(&mut self) {
        let mut unmatched: Vec<PeerKey> = Vec::new();
        let mut policy_changed: Vec<PeerKey> = Vec::new();
        for (peer, latch) in &self.max_prefix_latches {
            if latch.deadline.is_none() {
                continue;
            }
            let Some(managed) = self.peers.get(peer) else {
                continue;
            };
            if !managed.is_dynamic {
                continue;
            }
            if !self.dynamic_peer_still_allowed_by_current_ranges(managed) {
                unmatched.push(peer.clone());
            } else if !self.dynamic_restart_policy_still_current(managed) {
                policy_changed.push(peer.clone());
            }
        }
        // A peer no longer matched by any current range loses its countdown
        // outright — the accepting policy it would restart under is gone.
        for peer in unmatched {
            self.invalidate_max_prefix_restart(&peer);
        }
        // A still-matched peer whose group edited the duration follows the
        // same contract as a static hot edit: an armed countdown reschedules
        // to now + new (or cancels when the duration was removed), and the
        // managed copy syncs so the due-time policy check passes.
        for peer in policy_changed {
            let restart_seconds = self
                .peers
                .get(&peer)
                .and_then(|managed| managed.accepted_dynamic_range.as_ref())
                .and_then(|accepted| self.current_config.peer_groups.get(&accepted.peer_group))
                .and_then(|group| group.max_prefix_restart_seconds)
                .map(std::num::NonZeroU32::get);
            self.rearm_max_prefix_restart(&peer, restart_seconds);
            if let Some(managed) = self.peers.get_mut(&peer) {
                managed.max_prefix_restart_seconds = restart_seconds;
            }
        }
    }

    /// Remove dynamic peers whose accepting range is absent from the current
    /// runtime snapshot. Used after config-transaction rollback: the restored
    /// snapshot is authoritative, so peers born from the abandoned candidate
    /// must not survive until a later `BackToIdle`.
    pub(super) async fn reap_dynamic_peers_not_allowed_by_current_ranges(&mut self) -> usize {
        let mut stale: Vec<PeerKey> = self
            .peers
            .iter()
            .filter(|(_, managed)| {
                managed.is_dynamic && !self.dynamic_peer_still_allowed_by_current_ranges(managed)
            })
            .map(|(key, _)| key.clone())
            .collect();
        stale.sort();

        let mut removed = 0;
        for peer_key in stale {
            let Some(mut managed) = self.peers.remove(&peer_key) else {
                continue;
            };
            self.remove_max_prefix_latch(&peer_key);
            self.unregister_session(managed.session_id);
            if let Some(pending) = managed.pending_inbound.take() {
                self.unregister_session(pending.session_id);
                let _ = self
                    .shutdown_handle_bounded(
                        peer_key.address,
                        "dynamic rollback pending inbound",
                        pending.handle,
                    )
                    .await;
            }
            let _ = self
                .shutdown_handle_bounded(
                    peer_key.address,
                    "dynamic rollback primary",
                    managed.handle,
                )
                .await;
            self.reap_deleted_peer_metric_series_for_key(&peer_key)
                .await;
            self.dynamic_peer_count = self.dynamic_peer_count.saturating_sub(1);
            self.refresh_dynamic_neighbor_capacity_metrics();
            removed += 1;
            info!(
                peer = %peer_key,
                "config rollback: removed dynamic peer whose accepting range is no longer present"
            );
        }
        removed
    }

    /// Snapshot any unfired hot-apply / Route Refresh intent for a peer
    /// about to be auto-removed, so a re-establishing peer at the same
    /// address inherits the retry. No-op if neither flag is set.
    /// Bounded at `dynamic_neighbor_limit` — over-cap evicts the oldest
    /// live entry with `warn!` to surface pathological churn.
    pub(super) fn dead_letter_pending_for(&mut self, peer_addr: IpAddr) {
        let Some(peer_key) = self.unique_peer_key_for_address(peer_addr) else {
            return;
        };
        let Some(managed) = self.peers.get(&peer_key) else {
            return;
        };
        if !managed.pending_refresh
            && !managed.pending_export_apply
            && !managed.advertise_graceful_shutdown
        {
            return;
        }
        let entry = DeadLetteredPending {
            refresh: managed.pending_refresh,
            export_apply: managed.pending_export_apply,
            graceful_shutdown: managed.advertise_graceful_shutdown,
        };
        let cap = self.dynamic_neighbor_limit as usize;
        let is_new = !self.dead_lettered_pending.contains_key(&peer_addr);
        if cap > 0 && is_new && self.dead_lettered_pending.len() >= cap {
            while let Some(victim) = self.dead_lettered_pending_order.pop_front() {
                if self.dead_lettered_pending.remove(&victim).is_some() {
                    warn!(
                        %peer_addr,
                        evicted = %victim,
                        cap,
                        "dead-letter pending table at cap, evicting oldest existing entry — \
                         dynamic peers churning faster than they re-establish"
                    );
                    break;
                }
            }
        }
        if is_new {
            self.dead_lettered_pending_order.push_back(peer_addr);
        }
        self.dead_lettered_pending.insert(peer_addr, entry);
    }

    /// Drain any dead-lettered hot-apply / Route Refresh intent for a
    /// freshly accepted dynamic peer at this address and apply it to the
    /// new `ManagedPeer`. No-op if no entry exists.
    pub(super) fn restore_dead_lettered_pending(&mut self, peer_addr: IpAddr) {
        let Some(prev) = self.dead_lettered_pending.remove(&peer_addr) else {
            return;
        };
        self.dead_lettered_pending_order
            .retain(|candidate| *candidate != peer_addr);
        let Some(managed) = self
            .unique_peer_key_for_address(peer_addr)
            .and_then(|key| self.peers.get_mut(&key))
        else {
            return;
        };
        managed.pending_refresh = prev.refresh;
        managed.pending_export_apply = prev.export_apply;
        managed.advertise_graceful_shutdown = prev.graceful_shutdown;
        info!(
            %peer_addr,
            pending_refresh = prev.refresh,
            pending_export_apply = prev.export_apply,
            advertise_graceful_shutdown = prev.graceful_shutdown,
            "restored dead-lettered hot-apply intent on dynamic peer re-establishment"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{AcceptedDynamicRange, DynamicRange, select_dynamic_range};

    fn range(prefix: &str, group: &str) -> DynamicRange {
        let (addr, len) = prefix.split_once('/').expect("prefix has a '/'");
        DynamicRange {
            addr: addr.parse().expect("valid IP"),
            prefix_len: len.parse().expect("valid prefix length"),
            peer_group: group.to_string(),
            remote_asn: 65000,
            description: None,
            tcp_ao: None,
        }
    }

    fn matched_group(ranges: &[DynamicRange], addr: &str) -> Option<String> {
        select_dynamic_range(ranges, addr.parse::<IpAddr>().expect("valid IP"))
            .map(|r| r.peer_group.clone())
    }

    fn matched_attribution(ranges: &[DynamicRange], addr: &str) -> Option<AcceptedDynamicRange> {
        select_dynamic_range(ranges, addr.parse::<IpAddr>().expect("valid IP"))
            .map(DynamicRange::accepted_attribution)
    }

    #[test]
    fn most_specific_range_wins_when_wide_declared_first() {
        // /16 declared before the more-specific /24.
        let ranges = vec![range("10.0.0.0/16", "wide"), range("10.0.5.0/24", "narrow")];
        assert_eq!(
            matched_group(&ranges, "10.0.5.7").as_deref(),
            Some("narrow")
        );
        // An address inside the /16 but outside the /24 falls to the wider range.
        assert_eq!(matched_group(&ranges, "10.0.9.7").as_deref(), Some("wide"));
    }

    #[test]
    fn most_specific_range_wins_when_narrow_declared_first() {
        // Reversed declaration order — the result must not depend on it.
        let ranges = vec![range("10.0.5.0/24", "narrow"), range("10.0.0.0/16", "wide")];
        assert_eq!(
            matched_group(&ranges, "10.0.5.7").as_deref(),
            Some("narrow")
        );
        assert_eq!(matched_group(&ranges, "10.0.9.7").as_deref(), Some("wide"));
    }

    #[test]
    fn catch_all_default_route_loses_to_a_more_specific_range() {
        let ranges = vec![range("0.0.0.0/0", "any"), range("192.0.2.0/24", "doc")];
        assert_eq!(matched_group(&ranges, "192.0.2.1").as_deref(), Some("doc"));
        assert_eq!(
            matched_group(&ranges, "203.0.113.9").as_deref(),
            Some("any")
        );
    }

    #[test]
    fn accepted_attribution_uses_effective_prefix_key() {
        let ranges = vec![range("10.0.0.9/24", "ix-members")];
        assert_eq!(
            matched_attribution(&ranges, "10.0.0.77"),
            Some(AcceptedDynamicRange {
                addr: "10.0.0.0".parse().unwrap(),
                prefix_len: 24,
                peer_group: "ix-members".to_string(),
            })
        );
    }

    #[test]
    fn no_match_returns_none_and_v4_v6_do_not_cross() {
        let ranges = vec![range("10.0.0.0/8", "v4"), range("2001:db8::/32", "v6")];
        assert_eq!(matched_group(&ranges, "192.168.1.1"), None);
        // A v6 peer must not match a v4 range, and vice versa.
        assert_eq!(matched_group(&ranges, "2001:db8::1").as_deref(), Some("v6"));
        assert_eq!(matched_group(&ranges, "10.1.2.3").as_deref(), Some("v4"));
    }
}
