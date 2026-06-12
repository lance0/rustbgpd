//! `RTNLGRP_LINK` carrier monitor — ADR-0085 Decision 4.
//!
//! Projects per-link **carrier** state for a configured set of link
//! names into a `tokio::sync::watch` channel: the `IFF_LOWER_UP` bit
//! in the rtnetlink link flags (`ifi_flags`). Explicitly **not**
//! `IFLA_OPERSTATE` — that is a separate attribute with different
//! semantics (RFC 2863 operational state, which can sit in `UNKNOWN`
//! or `DORMANT` while the physical layer is fine) — and explicitly
//! not admin state alone: an operator `ip link set ... down` clears
//! `IFF_LOWER_UP` just like a cable pull, which is the correct
//! forwarding answer in both cases (ADR-0085 Decision 1).
//!
//! ## Shape
//!
//! [`spawn_link_carrier_monitor`] opens a **dedicated** rtnetlink
//! connection (same precedent as `nexthop_raw::NexthopSocket`: a
//! long-lived subscription should not compete with the primary
//! socket's dump/program traffic), subscribes to `RTNLGRP_LINK`, and
//! spawns a monitor task. The returned [`LinkCarrierHandle`] is the
//! owner: dropping it stops the monitor.
//!
//! - **Initial state** comes from a full link walk performed *before*
//!   the event loop starts; the watch channel is constructed with
//!   that first-probe projection (ADR-0085 Decision 3: startup
//!   applies first-probe state directly, no hold-off).
//! - **Events** (`RTM_NEWLINK` / `RTM_DELLINK`) update single names.
//!   Resolution is by **name** on every event — ifindex reuse is
//!   real, and names are the operator contract (ADR-0085 Decision 1).
//! - **Poll backstop**: a fixed-cadence re-walk heals a missed or
//!   never-delivered netlink message — the same event-driven +
//!   backstop shape the dataplane supervisor (5 s) and the segment
//!   re-election actor (10 s) use.
//! - **Fail-closed**: a watched name with no kernel link is `false`
//!   (down) — never "unknown", never absent from the published map.
//! - **Edge discipline**: the watch is only written when the
//!   projected map actually changes, so consumers are not woken by
//!   the kernel's unrelated link chatter.
//!
//! The watched-name set is replaceable at runtime via
//! [`LinkCarrierHandle::replace_watched_links`] (SIGHUP adds/removes
//! `[[ethernet_segments]]` bindings in the next slice); a replace
//! re-evaluates immediately against current kernel state.
//!
//! Parsing keeps the crate's established `LinkMessage` discipline:
//! scalars out of the message (name `String`, carrier `bool`), no
//! enum round-tripping.
//!
//! Nothing consumes this monitor yet — ADR-0085 slice 2 wires it
//! into the drain coordinator.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::stream::TryStreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_sys::AsyncSocket;
use rtnetlink::Handle;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use crate::error::DataplaneError;

/// Multicast group ID for link changes — enum value `RTNLGRP_LINK`
/// from `<linux/rtnetlink.h>` (second entry in `enum
/// rtnetlink_groups`, hence value `1`).
///
/// Same enum-vs-bitmask discipline as
/// [`super::notify::RTNLGRP_NEIGH`]: `Socket::add_membership` takes
/// the enum value via `NETLINK_ADD_MEMBERSHIP`, not the legacy
/// `RTMGRP_*` bitmask. For `LINK` the two happen to coincide
/// (`RTMGRP_LINK = 1 << (RTNLGRP_LINK - 1) = 1`), so this constant
/// can't repeat the off-by-one the NEIGH/ROUTE groups suffered — the
/// doc note exists so nobody "fixes" it against the bitmask table.
pub(crate) const RTNLGRP_LINK: u32 = 1;

/// Poll-backstop cadence for the full link re-walk.
///
/// 10 s, matching the segment re-election actor's backstop tick: the
/// hot path is the edge-triggered `RTNLGRP_LINK` event (a carrier
/// loss reaches the projection within milliseconds), so the walk
/// only bounds the staleness window after a *missed* netlink message
/// (socket overflow, subscription failure). The dataplane
/// supervisor's tighter 5 s exists because its poll *is* a primary
/// trigger; here it is purely a healer, so the cheaper cadence wins.
const POLL_BACKSTOP_INTERVAL: Duration = Duration::from_secs(10);

/// Published projection: watched link name → carrier-up
/// (`IFF_LOWER_UP`). Contains exactly the watched names — a watched
/// name with no kernel link is present and `false` (fail-closed).
pub type LinkCarrierMap = Arc<BTreeMap<String, bool>>;

/// Owning handle for the link carrier monitor.
///
/// Holds the command channel and the root watch receiver; dropping
/// the handle closes the command channel, which stops the monitor
/// task (already-subscribed receivers then stop updating). Keep it
/// alive for as long as carrier state should flow.
#[derive(Debug)]
pub struct LinkCarrierHandle {
    carrier_rx: watch::Receiver<LinkCarrierMap>,
    cmd_tx: mpsc::Sender<BTreeSet<String>>,
}

impl LinkCarrierHandle {
    /// Subscribe to carrier-state updates. The receiver's initial
    /// value is the most recently published projection (at spawn:
    /// the first-walk state).
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<LinkCarrierMap> {
        self.carrier_rx.clone()
    }

    /// Most recently published projection.
    #[must_use]
    pub fn current(&self) -> LinkCarrierMap {
        self.carrier_rx.borrow().clone()
    }

    /// Replace the watched-name set. The monitor re-evaluates
    /// immediately from current kernel state (fresh walk; names the
    /// walk cannot see start down, fail-closed) and publishes if the
    /// projection changed.
    ///
    /// Returns `false` if the monitor task has already exited.
    pub async fn replace_watched_links(&self, watched: BTreeSet<String>) -> bool {
        self.cmd_tx.send(watched).await.is_ok()
    }
}

/// Open a dedicated rtnetlink connection, subscribe to
/// `RTNLGRP_LINK`, walk current kernel links for the initial
/// projection, and spawn the monitor task.
///
/// The initial projection is published as the watch channel's first
/// value *before* any netlink event is processed. If the initial
/// walk fails, every watched name starts down (fail-closed) and the
/// poll backstop heals within one cadence.
///
/// # Errors
/// Returns [`DataplaneError::Io`] if `rtnetlink::new_connection`
/// fails (no `CAP_NET_ADMIN`, `AF_NETLINK` unavailable). A failed
/// `RTNLGRP_LINK` subscription is *not* an error — the monitor
/// degrades to poll-only and logs `warn!`.
pub async fn spawn_link_carrier_monitor(
    watched: BTreeSet<String>,
) -> Result<LinkCarrierHandle, DataplaneError> {
    let (mut connection, handle, messages) =
        rtnetlink::new_connection().map_err(DataplaneError::Io)?;

    // Synchronous setsockopt — must happen before the connection is
    // handed to the runtime (same ordering rule as the NEIGH/ROUTE
    // subscriptions in `LinuxDataplane::connect`). Non-fatal: the
    // poll backstop keeps the projection honest, just slower.
    if let Err(e) = connection
        .socket_mut()
        .socket_mut()
        .add_membership(RTNLGRP_LINK)
    {
        warn!(
            error = %e,
            "RTNLGRP_LINK subscription failed; link carrier monitor degrades to poll-only"
        );
    }
    tokio::spawn(connection);

    let mut projection = CarrierProjection::new(watched);
    // First-probe state, applied before the event loop starts
    // (ADR-0085 Decision 3: startup is not held).
    match dump_link_carrier(&handle).await {
        Ok(kernel) => {
            projection.apply_walk(&kernel);
        }
        Err(e) => {
            warn!(
                error = %e,
                "initial link carrier walk failed; watched links start down (fail-closed) \
                 until the poll backstop heals"
            );
        }
    }

    let (carrier_tx, carrier_rx) = watch::channel(projection.snapshot());
    // Tiny command buffer: replaces are operator-cadence (SIGHUP /
    // config transactions), never bursty.
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    tokio::spawn(monitor_loop(
        handle, messages, carrier_tx, cmd_rx, projection,
    ));

    Ok(LinkCarrierHandle { carrier_rx, cmd_tx })
}

/// Event/poll/command loop. Exits when the owning handle is dropped
/// (command channel closed) or the rtnetlink connection task dies.
async fn monitor_loop(
    handle: Handle,
    mut messages: futures::channel::mpsc::UnboundedReceiver<(
        NetlinkMessage<RouteNetlinkMessage>,
        netlink_sys::SocketAddr,
    )>,
    carrier_tx: watch::Sender<LinkCarrierMap>,
    mut cmd_rx: mpsc::Receiver<BTreeSet<String>>,
    mut projection: CarrierProjection,
) {
    // First tick one full cadence out — spawn already walked.
    let mut tick = tokio::time::interval_at(
        tokio::time::Instant::now() + POLL_BACKSTOP_INTERVAL,
        POLL_BACKSTOP_INTERVAL,
    );
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let changed = tokio::select! {
            maybe_msg = messages.next() => {
                let Some((msg, _src)) = maybe_msg else {
                    warn!("rtnetlink connection closed; link carrier monitor exiting");
                    return;
                };
                let NetlinkPayload::InnerMessage(payload) = msg.payload else {
                    continue;
                };
                match payload {
                    RouteNetlinkMessage::NewLink(link) => link_name_and_carrier(&link)
                        .is_some_and(|(name, carrier)| {
                            projection.apply_event(&name, Some(carrier))
                        }),
                    // Link deleted → down (fail-closed). A *rename*
                    // emits only RTM_NEWLINK under the new name, so
                    // the old watched name goes stale until the next
                    // backstop walk marks it down — exactly the gap
                    // the poll exists to heal.
                    RouteNetlinkMessage::DelLink(link) => link_name_and_carrier(&link)
                        .is_some_and(|(name, _)| projection.apply_event(&name, None)),
                    _ => false,
                }
            }
            _ = tick.tick() => {
                match dump_link_carrier(&handle).await {
                    Ok(kernel) => projection.apply_walk(&kernel),
                    Err(e) => {
                        // Keep the last projection rather than
                        // flapping everything down on a transient
                        // netlink hiccup; the next tick retries.
                        warn!(error = %e, "link carrier backstop walk failed; retaining last state");
                        false
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                let Some(watched) = cmd else {
                    debug!("link carrier handle dropped; monitor exiting");
                    return;
                };
                // Re-evaluate immediately from current kernel state.
                // On walk failure, fall back to the previous
                // projection as the kernel view: retained names keep
                // their last-known state, names new to the set start
                // down (fail-closed) until the backstop heals.
                let kernel = match dump_link_carrier(&handle).await {
                    Ok(k) => k,
                    Err(e) => {
                        warn!(
                            error = %e,
                            "link carrier walk failed during watched-set replace; \
                             new names start down until the poll backstop heals"
                        );
                        projection.current().clone()
                    }
                };
                projection.replace_watched(watched, &kernel)
            }
        };
        if changed {
            // Send errors mean every receiver is gone; the command
            // channel closing exits the loop on the next iteration.
            let _ = carrier_tx.send(projection.snapshot());
        }
    }
}

/// Walk every kernel link and project `name → IFF_LOWER_UP`.
async fn dump_link_carrier(handle: &Handle) -> Result<BTreeMap<String, bool>, DataplaneError> {
    let mut out = BTreeMap::new();
    let mut stream = handle.link().get().execute();
    while let Some(msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("link carrier dump: {e}")))?
    {
        if let Some((name, carrier)) = link_name_and_carrier(&msg) {
            out.insert(name, carrier);
        }
    }
    Ok(out)
}

/// Extract `(name, carrier)` from one `LinkMessage` — the name from
/// the `IFLA_IFNAME` attribute, carrier from the `IFF_LOWER_UP` bit
/// in the header flags (`ifi_flags`).
///
/// Deliberately ignores `IFLA_OPERSTATE`: it is a distinct attribute
/// with RFC 2863 semantics (`UNKNOWN` / `DORMANT` states that do not
/// answer "can this AC forward"), while `IFF_LOWER_UP` composes both
/// admin-down and physical carrier loss into the one bit ADR-0085
/// Decision 1 keys drain on. Scalars out, no enum round-tripping.
fn link_name_and_carrier(msg: &LinkMessage) -> Option<(String, bool)> {
    let carrier = msg.header.flags.contains(LinkFlags::LowerUp);
    for attr in &msg.attributes {
        if let LinkAttribute::IfName(name) = attr {
            return Some((name.clone(), carrier));
        }
    }
    None
}

/// Pure projection state: the watched-name set and the current
/// carrier map (always exactly the watched names). Every mutator
/// returns `true` only when the published map must change — the
/// loop's change-only publication rule rides on these return values.
#[derive(Debug)]
struct CarrierProjection {
    watched: BTreeSet<String>,
    current: BTreeMap<String, bool>,
}

impl CarrierProjection {
    /// All watched names start down (fail-closed) until the first
    /// walk says otherwise.
    fn new(watched: BTreeSet<String>) -> Self {
        let current = watched.iter().map(|n| (n.clone(), false)).collect();
        Self { watched, current }
    }

    fn snapshot(&self) -> LinkCarrierMap {
        Arc::new(self.current.clone())
    }

    fn current(&self) -> &BTreeMap<String, bool> {
        &self.current
    }

    /// Fold a full kernel walk into the projection. Watched names
    /// the walk did not report are down (fail-closed).
    fn apply_walk(&mut self, kernel: &BTreeMap<String, bool>) -> bool {
        let next: BTreeMap<String, bool> = self
            .watched
            .iter()
            .map(|name| (name.clone(), kernel.get(name).copied().unwrap_or(false)))
            .collect();
        let changed = next != self.current;
        self.current = next;
        changed
    }

    /// Fold one link event. `Some(carrier)` for `RTM_NEWLINK`,
    /// `None` for `RTM_DELLINK` (deleted → down). Non-watched names
    /// are ignored.
    fn apply_event(&mut self, name: &str, carrier_up: Option<bool>) -> bool {
        if !self.watched.contains(name) {
            return false;
        }
        let next = carrier_up.unwrap_or(false);
        match self.current.get_mut(name) {
            Some(slot) if *slot == next => false,
            Some(slot) => {
                *slot = next;
                true
            }
            // Unreachable while the watched/current invariant holds,
            // but stay total: insert rather than panic.
            None => {
                self.current.insert(name.to_string(), next);
                true
            }
        }
    }

    /// Replace the watched-name set, re-evaluating every name
    /// against the supplied kernel view.
    fn replace_watched(
        &mut self,
        watched: BTreeSet<String>,
        kernel: &BTreeMap<String, bool>,
    ) -> bool {
        self.watched = watched;
        self.apply_walk(kernel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::link::State;

    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    fn kernel(entries: &[(&str, bool)]) -> BTreeMap<String, bool> {
        entries
            .iter()
            .map(|(n, c)| ((*n).to_string(), *c))
            .collect()
    }

    fn link_msg(name: Option<&str>, flags: LinkFlags) -> LinkMessage {
        let mut msg = LinkMessage::default();
        msg.header.flags = flags;
        if let Some(name) = name {
            msg.attributes.push(LinkAttribute::IfName(name.to_string()));
        }
        msg
    }

    #[test]
    fn carrier_comes_from_the_lower_up_flag_bit() {
        let msg = link_msg(
            Some("es0"),
            LinkFlags::Up | LinkFlags::LowerUp | LinkFlags::Running,
        );
        assert_eq!(link_name_and_carrier(&msg), Some(("es0".to_string(), true)));

        // Admin-up but no carrier (cable pulled / peer down):
        // IFF_LOWER_UP clear → down, regardless of IFF_UP/RUNNING.
        let msg = link_msg(Some("es0"), LinkFlags::Up);
        assert_eq!(
            link_name_and_carrier(&msg),
            Some(("es0".to_string(), false))
        );
    }

    #[test]
    fn carrier_projection_ignores_ifla_operstate() {
        // ADR-0085 Decision 1 pins carrier to the IFF_LOWER_UP flag
        // bit, NOT the IFLA_OPERSTATE attribute. A message whose
        // operstate says Down but whose flags carry LOWER_UP must
        // project up — and vice versa.
        let mut msg = link_msg(Some("es0"), LinkFlags::Up | LinkFlags::LowerUp);
        msg.attributes.push(LinkAttribute::OperState(State::Down));
        assert_eq!(link_name_and_carrier(&msg), Some(("es0".to_string(), true)));

        let mut msg = link_msg(Some("es0"), LinkFlags::Up);
        msg.attributes.push(LinkAttribute::OperState(State::Up));
        assert_eq!(
            link_name_and_carrier(&msg),
            Some(("es0".to_string(), false))
        );
    }

    #[test]
    fn message_without_a_name_projects_nothing() {
        let msg = link_msg(None, LinkFlags::Up | LinkFlags::LowerUp);
        assert_eq!(link_name_and_carrier(&msg), None);
    }

    #[test]
    fn watched_name_with_no_kernel_link_is_down() {
        let mut proj = CarrierProjection::new(names(&["es0", "ghost0"]));
        // Initial state: everything down until a walk says otherwise.
        assert_eq!(
            *proj.snapshot(),
            kernel(&[("es0", false), ("ghost0", false)])
        );

        // Walk reports only es0 — ghost0 stays present and down
        // (fail-closed), never absent.
        assert!(proj.apply_walk(&kernel(&[("es0", true), ("eth0", true)])));
        assert_eq!(
            *proj.snapshot(),
            kernel(&[("es0", true), ("ghost0", false)])
        );
    }

    #[test]
    fn link_delete_is_down_and_recreate_with_carrier_is_up() {
        let mut proj = CarrierProjection::new(names(&["es0"]));
        assert!(proj.apply_event("es0", Some(true)));
        assert_eq!(*proj.snapshot(), kernel(&[("es0", true)]));

        // RTM_DELLINK → down.
        assert!(proj.apply_event("es0", None));
        assert_eq!(*proj.snapshot(), kernel(&[("es0", false)]));

        // Re-created with carrier already up → up.
        assert!(proj.apply_event("es0", Some(true)));
        assert_eq!(*proj.snapshot(), kernel(&[("es0", true)]));
    }

    #[test]
    fn replace_watched_links_re_evaluates_from_kernel_state() {
        let mut proj = CarrierProjection::new(names(&["es0"]));
        assert!(proj.apply_event("es0", Some(true)));

        // Swap es0 out for es1 + ghost0: es1 picks up its kernel
        // state immediately, ghost0 fails closed, es0 disappears.
        let kernel_view = kernel(&[("es0", true), ("es1", true)]);
        assert!(proj.replace_watched(names(&["es1", "ghost0"]), &kernel_view));
        assert_eq!(
            *proj.snapshot(),
            kernel(&[("es1", true), ("ghost0", false)])
        );

        // Replacing with the same set + same kernel view is a no-op.
        assert!(!proj.replace_watched(names(&["es1", "ghost0"]), &kernel_view));
    }

    #[test]
    fn only_actual_changes_report_changed() {
        let mut proj = CarrierProjection::new(names(&["es0"]));

        // Same value as current → no publication.
        assert!(!proj.apply_event("es0", Some(false)));
        // Event for a name we don't watch → no publication.
        assert!(!proj.apply_event("eth0", Some(true)));
        // Identical walk → no publication.
        assert!(!proj.apply_walk(&kernel(&[("es0", false)])));

        // Real edge → publication...
        assert!(proj.apply_event("es0", Some(true)));
        // ...and the kernel's repeat NEWLINK chatter (MTU change,
        // address add) at the same carrier state stays silent.
        assert!(!proj.apply_event("es0", Some(true)));
        assert!(!proj.apply_walk(&kernel(&[("es0", true)])));
    }

    /// Enum-vs-bitmask pin, mirroring the `RTNLGRP_NEIGH = 3 vs 4`
    /// and route-group pins in `notify.rs`: `Socket::add_membership`
    /// takes the ENUM group id (`RTNLGRP_LINK = 1` per
    /// `<linux/rtnetlink.h>`), not the legacy `RTMGRP_LINK` bitmask
    /// (also 1 here by coincidence — which is exactly why the pin
    /// matters: a future "fix" toward bitmask thinking on a group
    /// where they differ would silently subscribe to the wrong
    /// events).
    #[test]
    fn link_rtnlgrp_constant_matches_kernel_enum_value() {
        assert_eq!(RTNLGRP_LINK, 1);
    }

    #[test]
    fn empty_watched_set_projects_an_empty_map() {
        let mut proj = CarrierProjection::new(BTreeSet::new());
        assert!(proj.snapshot().is_empty());
        // Kernel churn with nothing watched never reports a change.
        assert!(!proj.apply_walk(&kernel(&[("eth0", true)])));
        assert!(!proj.apply_event("eth0", Some(true)));
    }
}
