//! EVPN Type 3 Inclusive Multicast Ethernet Tag (IMET) origination
//! per L2VNI (Gate 7b+1, RFC 7432 §7.3 + RFC 6514 §5).
//!
//! # What IMET advertises
//!
//! Type 3 IMET is how a VTEP tells its peers "I am a member of this
//! L2VNI; include me in the ingress-replication list for BUM traffic."
//! It carries:
//!
//! - **NLRI**: RD (per-EVI, per-VTEP), Ethernet Tag, Originator IP.
//! - **PMSI Tunnel attribute** (RFC 6514 §5): tunnel type =
//!   Ingress Replication (6), Label = raw 24-bit VNI (RFC 8365 §5.1.3
//!   redefines the field semantics for EVPN-VXLAN), Tunnel Identifier
//!   = the VTEP's own loopback IP.
//! - **Route Target extended communities** matching the L2VNI's RT
//!   set so importers route the membership advertisement into the
//!   right EVI.
//!
//! # Lifecycle
//!
//! Type 3 IMET is **not** conditioned on kernel readiness — it
//! represents BGP-level VNI membership intent, not data-plane
//! programmability. The originator emits one Inject per configured
//! `EvpnInstance` at daemon start; the daemon's shutdown path
//! withdraws each one before the RIB stops accepting work.
//!
//! ADR-0054's level-triggered model still applies: peers periodically
//! re-receive the same Type 3 (no-op at the `LocRib` level) until the
//! daemon withdraws.
//!
//! # Controller shape
//!
//! The daemon owns an [`EvpnImetController`] for the life of the
//! process. Startup still originates one route per configured
//! `EvpnInstance`, and shutdown still withdraws those routes before
//! peer sessions drain. The difference is that the originated key set
//! now has an owner with per-VNI originate/withdraw methods, which is
//! the command target ADR-0063 needs before non-noop runtime
//! `[[evpn_instances]]` commits can safely converge.
//!
//! # Reference
//!
//! - RFC 7432 §7.3 — Inclusive Multicast Ethernet Tag Route
//! - RFC 6514 §5 — PMSI Tunnel attribute (Ingress Replication = 6)
//! - RFC 8365 §5.1.3 — VXLAN encap convention (label field = raw
//!   24-bit VNI; the §5 MPLS-style high-20-bits shift does not apply)

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use rustbgpd_evpn::{EvpnInstance, EvpnInstanceId};
use rustbgpd_rib::{RibUpdate, route::EvpnRibRoute};
use rustbgpd_wire::{
    AsPath, EthernetTagId, EvpnImet, EvpnRoute, EvpnRouteKey, ExtendedCommunity, Origin,
    PathAttribute, PmsiTunnel,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::evpn_ack::{NOACK_REPLY_DROPPED, RibAckOutcome, send_and_ack};

/// Result of asking the IMET controller to originate one VNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImetOriginateOutcome {
    /// The route was accepted by the RIB and recorded by the controller.
    Originated {
        /// Originated Type 3 route key.
        key: EvpnRouteKey,
    },
    /// The VNI was already originated; no duplicate inject was sent.
    AlreadyOriginated {
        /// Existing Type 3 route key.
        key: EvpnRouteKey,
    },
    /// The RIB command channel closed before the inject could be sent,
    /// or the RIB failed to acknowledge it within the ADR-0102
    /// [`crate::evpn_ack::RIB_ACK_TIMEOUT`]. The route is not tracked;
    /// converge callers report a failure and may retry (the inject is
    /// idempotent per key).
    RibUnavailable {
        /// Type 3 route key that would have been injected.
        key: EvpnRouteKey,
    },
    /// The RIB rejected the inject request.
    Rejected {
        /// Type 3 route key rejected by the RIB.
        key: EvpnRouteKey,
    },
    /// The RIB dropped the oneshot reply before confirming the inject.
    ReplyDropped {
        /// Type 3 route key whose inject result is unknown.
        key: EvpnRouteKey,
    },
}

/// Result of asking the IMET controller to withdraw one VNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImetWithdrawOutcome {
    /// The route was withdrawn by the RIB and removed from the controller.
    Withdrawn {
        /// Withdrawn Type 3 route key.
        key: EvpnRouteKey,
    },
    /// The VNI was not currently originated.
    NotOriginated {
        /// Requested VNI.
        vni: EvpnInstanceId,
    },
    /// The RIB command channel closed before the withdraw could be sent,
    /// or the RIB failed to acknowledge it within the ADR-0102
    /// [`crate::evpn_ack::RIB_ACK_TIMEOUT`]. The key stays tracked so a
    /// later converge retries the withdraw.
    RibUnavailable {
        /// Type 3 route key that would have been withdrawn.
        key: EvpnRouteKey,
    },
    /// The RIB rejected the withdraw request.
    Rejected {
        /// Type 3 route key rejected by the RIB.
        key: EvpnRouteKey,
    },
    /// The RIB dropped the oneshot reply before confirming the withdraw.
    ReplyDropped {
        /// Type 3 route key whose withdraw result is unknown.
        key: EvpnRouteKey,
    },
}

/// Daemon-owned Type 3 IMET lifecycle state.
#[derive(Debug, Default)]
pub struct EvpnImetController {
    originated: BTreeMap<EvpnInstanceId, EvpnRouteKey>,
}

impl EvpnImetController {
    /// Create an empty controller.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of currently originated VNIs tracked by the controller.
    #[must_use]
    pub fn len(&self) -> usize {
        self.originated.len()
    }

    /// Whether the controller is tracking no originated IMET routes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.originated.is_empty()
    }

    /// Return the currently originated Type 3 key for `vni`, if any.
    #[must_use]
    pub fn originated_key(&self, vni: EvpnInstanceId) -> Option<EvpnRouteKey> {
        self.originated.get(&vni).copied()
    }

    /// Originate Type 3 IMET for one instance unless it is already present.
    pub async fn originate_instance(
        &mut self,
        instance: EvpnInstance,
        rib_tx: &mpsc::Sender<RibUpdate>,
    ) -> ImetOriginateOutcome {
        if let Some(key) = self.originated_key(instance.id) {
            debug!(
                ?key,
                vni = instance.id.as_u32(),
                "Type 3 IMET already originated"
            );
            return ImetOriginateOutcome::AlreadyOriginated { key };
        }

        let route = build_imet_route(&instance);
        debug_assert!(matches!(route.route, EvpnRoute::Imet(_)));
        let key = route.key();
        let outcome = inject_imet_route(route, instance.id, rib_tx).await;
        if matches!(
            outcome,
            ImetOriginateOutcome::Originated { .. } | ImetOriginateOutcome::ReplyDropped { .. }
        ) {
            self.originated.insert(instance.id, key);
        }
        outcome
    }

    /// Withdraw Type 3 IMET for one VNI if the controller owns it.
    pub async fn withdraw_instance(
        &mut self,
        vni: EvpnInstanceId,
        rib_tx: &mpsc::Sender<RibUpdate>,
    ) -> ImetWithdrawOutcome {
        let Some(key) = self.originated_key(vni) else {
            debug!(vni = vni.as_u32(), "Type 3 IMET not originated");
            return ImetWithdrawOutcome::NotOriginated { vni };
        };

        let outcome = withdraw_imet_key(key, rib_tx).await;
        if matches!(outcome, ImetWithdrawOutcome::Withdrawn { .. }) {
            self.originated.remove(&vni);
        }
        outcome
    }

    /// Originate one Type 3 IMET route per instance.
    ///
    /// Per-instance failures are logged and do not abort later instances.
    /// Returns the accepted, already-originated, or reply-unknown tracked
    /// route keys.
    pub async fn originate_all(
        &mut self,
        instances: impl IntoIterator<Item = EvpnInstance>,
        rib_tx: &mpsc::Sender<RibUpdate>,
    ) -> Vec<EvpnRouteKey> {
        let mut keys: Vec<EvpnRouteKey> = Vec::new();
        for inst in instances {
            match self.originate_instance(inst, rib_tx).await {
                ImetOriginateOutcome::Originated { key }
                | ImetOriginateOutcome::AlreadyOriginated { key }
                | ImetOriginateOutcome::ReplyDropped { key } => keys.push(key),
                ImetOriginateOutcome::RibUnavailable { .. }
                | ImetOriginateOutcome::Rejected { .. } => {}
            }
        }
        keys
    }

    /// Withdraw every Type 3 IMET route currently owned by the controller.
    pub async fn withdraw_all(&mut self, rib_tx: &mpsc::Sender<RibUpdate>) {
        let vnis: Vec<EvpnInstanceId> = self.originated.keys().copied().collect();
        for vni in vnis {
            let _ = self.withdraw_instance(vni, rib_tx).await;
        }
    }
}

async fn inject_imet_route(
    route: EvpnRibRoute,
    vni: EvpnInstanceId,
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> ImetOriginateOutcome {
    let key = route.key();
    // ADR-0102 `send_and_ack` bounds the wait: converge callers hold the
    // daemon's IMET controller mutex across this await, so an unbounded
    // wait on a wedged RIB would hold that mutex forever and lock every
    // later EVPN runtime converge out until restart.
    match send_and_ack(rib_tx, |reply| RibUpdate::InjectEvpn { route, reply }).await {
        RibAckOutcome::Acked => {
            debug!(?key, vni = vni.as_u32(), "originated Type 3 IMET");
            ImetOriginateOutcome::Originated { key }
        }
        RibAckOutcome::Rejected(e) => {
            warn!(?key, vni = vni.as_u32(), error = %e, "RIB rejected IMET inject");
            ImetOriginateOutcome::Rejected { key }
        }
        RibAckOutcome::NoAck(NOACK_REPLY_DROPPED) => {
            warn!(?key, vni = vni.as_u32(), "RIB IMET inject reply dropped");
            ImetOriginateOutcome::ReplyDropped { key }
        }
        // Channel closed or ack timeout: the RIB is unavailable as far as
        // this converge is concerned — report a real failure rather than
        // claiming success against a wedged RIB.
        RibAckOutcome::NoAck(reason) => {
            warn!(?key, vni = vni.as_u32(), reason, "cannot originate IMET");
            ImetOriginateOutcome::RibUnavailable { key }
        }
    }
}

async fn withdraw_imet_key(
    key: EvpnRouteKey,
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> ImetWithdrawOutcome {
    // Bounded for the same converge-holds-the-mutex reason as
    // [`inject_imet_route`].
    match send_and_ack(rib_tx, |reply| RibUpdate::WithdrawEvpn { key, reply }).await {
        RibAckOutcome::Acked => {
            debug!(?key, "withdrew Type 3 IMET");
            ImetWithdrawOutcome::Withdrawn { key }
        }
        // The RIB doesn't hold this key: the route is already gone (e.g. a
        // prior withdraw whose oneshot reply was dropped). Converge the
        // controller to RIB reality instead of treating this as a failure —
        // a Rejected here keeps the key tracked forever, and a tracked key
        // the RIB doesn't hold makes the VNI permanently un-deletable and
        // un-redefinable: re-origination short-circuits on AlreadyOriginated
        // and every later delete/redefine converge rejects until restart.
        RibAckOutcome::Rejected(rustbgpd_rib::RibCommandError::NotFound(message)) => {
            warn!(
                ?key,
                %message,
                "RIB IMET withdraw: key already absent — treating as withdrawn"
            );
            ImetWithdrawOutcome::Withdrawn { key }
        }
        RibAckOutcome::Rejected(e) => {
            debug!(?key, error = %e, "RIB IMET withdraw declined");
            ImetWithdrawOutcome::Rejected { key }
        }
        RibAckOutcome::NoAck(NOACK_REPLY_DROPPED) => {
            warn!(?key, "RIB IMET withdraw reply dropped");
            ImetWithdrawOutcome::ReplyDropped { key }
        }
        RibAckOutcome::NoAck(reason) => {
            warn!(?key, reason, "cannot withdraw IMET");
            ImetWithdrawOutcome::RibUnavailable { key }
        }
    }
}

/// Build the wire-shaped Type 3 IMET `EvpnRibRoute` for `instance`.
///
/// Path attribute set:
/// - `Origin::Igp` (locally originated)
/// - empty `AsPath`
/// - `NextHop` matching the VTEP IP
/// - `ExtendedCommunities` carrying every configured Route Target
/// - `PmsiTunnel` for Ingress Replication, label = raw 24-bit VNI
///   (RFC 8365 §5.1.3), tunnel id = the VTEP's loopback IP
fn build_imet_route(instance: &EvpnInstance) -> EvpnRibRoute {
    let imet = EvpnImet {
        rd: instance.rd,
        ethernet_tag: EthernetTagId(0),
        originator_ip: instance.local_vtep_ip,
    };

    let ext_communities: Vec<ExtendedCommunity> = instance
        .route_targets
        .iter()
        .copied()
        .map(crate::evpn_originator::route_target_to_extcomm)
        .collect();

    let pmsi =
        PmsiTunnel::for_evpn_ingress_replication(instance.id.as_u32(), instance.local_vtep_ip);

    let attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        next_hop_path_attribute(instance.local_vtep_ip),
        PathAttribute::ExtendedCommunities(ext_communities),
        PathAttribute::PmsiTunnel(pmsi),
    ];

    EvpnRibRoute {
        route: EvpnRoute::Imet(imet),
        next_hop: instance.local_vtep_ip,
        link_local_next_hop: None,
        peer: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        attributes: Arc::new(attributes),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::route::RouteOrigin::Local,
        peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
    }
}

/// IPv4 next-hop attribute — see [`crate::evpn_originator`] for the
/// matching convention.
fn next_hop_path_attribute(vtep_ip: IpAddr) -> PathAttribute {
    match vtep_ip {
        IpAddr::V4(v4) => PathAttribute::NextHop(v4),
        IpAddr::V6(_) => PathAttribute::NextHop(std::net::Ipv4Addr::UNSPECIFIED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rustbgpd_rib::{RibCommandError, route::RouteOrigin};
    use rustbgpd_wire::{PmsiTunnelIdentifier, PmsiTunnelType};

    use crate::test_support::{evpn_instance, rd, vni};

    fn local_instance(v: u32) -> EvpnInstance {
        evpn_instance(65000, v, v, Some(format!("br{v}")), false)
    }

    #[test]
    fn build_imet_route_carries_pmsi_tunnel_for_ingress_replication() {
        let inst = local_instance(100);
        let route = build_imet_route(&inst);

        // Type 3 NLRI shape.
        let EvpnRoute::Imet(imet) = &route.route else {
            panic!("expected Imet, got {:?}", route.route);
        };
        assert_eq!(imet.rd, rd(65000, 100));
        assert_eq!(imet.ethernet_tag, EthernetTagId(0));
        assert_eq!(imet.originator_ip, "10.0.0.1".parse::<IpAddr>().unwrap());

        // Path attributes contain a PMSI Tunnel with type = IR.
        let pmsi = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::PmsiTunnel(p) => Some(p),
                _ => None,
            })
            .expect("PMSI Tunnel present");
        assert_eq!(pmsi.tunnel_type, PmsiTunnelType::IngressReplication);
        // RFC 8365 §5.1.3: label = raw 24-bit VNI (no shift).
        assert_eq!(pmsi.mpls_label, 100);
        match &pmsi.tunnel_identifier {
            PmsiTunnelIdentifier::Ipv4(v4) => {
                assert_eq!(*v4, "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap());
            }
            other => panic!("expected IPv4 tunnel id, got {other:?}"),
        }
    }

    #[test]
    fn build_imet_route_carries_route_targets() {
        let inst = local_instance(100);
        let route = build_imet_route(&inst);
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v),
                _ => None,
            })
            .unwrap();
        // 1 RT, no MAC Mobility (this is Type 3, not Type 2).
        assert_eq!(extcomms.len(), 1);
        // 2-octet AS RT for 65000:100 — verify the encoded form decodes.
        let (admin, value) = extcomms[0].route_target().expect("RT extcomm");
        assert_eq!(admin, 65000);
        assert_eq!(value, 100);
    }

    #[test]
    fn build_imet_route_marks_origin_type_local() {
        let inst = local_instance(100);
        let route = build_imet_route(&inst);
        assert_eq!(route.origin_type, RouteOrigin::Local);
        assert_eq!(route.next_hop, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn build_imet_route_emits_origin_aspath_nexthop() {
        let inst = local_instance(100);
        let route = build_imet_route(&inst);
        assert!(matches!(
            route.attributes[0],
            PathAttribute::Origin(Origin::Igp)
        ));
        assert!(matches!(
            route.attributes[1],
            PathAttribute::AsPath(AsPath { ref segments }) if segments.is_empty()
        ));
        assert!(matches!(route.attributes[2], PathAttribute::NextHop(_)));
    }

    #[tokio::test]
    async fn controller_originate_all_returns_one_key_per_instance_and_emits_inject() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let responder = tokio::spawn(async move {
            let mut keys = Vec::new();
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::InjectEvpn { route, reply } = msg {
                    keys.push(route.key());
                    let _ = reply.send(Ok(()));
                }
            }
            keys
        });

        let instances = vec![local_instance(100), local_instance(200)];
        let mut controller = EvpnImetController::new();
        let keys = controller.originate_all(instances, &rib_tx).await;
        drop(rib_tx);
        let observed = responder.await.unwrap();

        assert_eq!(keys.len(), 2);
        assert_eq!(observed.len(), 2);
        // Every observed key must be Type 3.
        for k in &observed {
            assert!(matches!(k, EvpnRouteKey::Imet { .. }));
        }
    }

    #[tokio::test]
    async fn controller_originate_all_swallows_per_instance_failures_without_aborting() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let responder = tokio::spawn(async move {
            let mut count = 0;
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::InjectEvpn { reply, .. } = msg {
                    count += 1;
                    let result = if count == 1 {
                        Err(RibCommandError::internal("simulated"))
                    } else {
                        Ok(())
                    };
                    let _ = reply.send(result);
                }
            }
            count
        });

        let instances = vec![
            local_instance(100),
            local_instance(200),
            local_instance(300),
        ];
        let mut controller = EvpnImetController::new();
        let keys = controller.originate_all(instances, &rib_tx).await;
        drop(rib_tx);
        let observed = responder.await.unwrap();

        // Three instances tried; the first one's reject should not
        // have aborted the rest.
        assert_eq!(observed, 3);
        // The successful set is two routes.
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn controller_originates_once_and_tracks_key_by_vni() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let responder = tokio::spawn(async move {
            let mut keys = Vec::new();
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::InjectEvpn { route, reply } = msg {
                    keys.push(route.key());
                    let _ = reply.send(Ok(()));
                }
            }
            keys
        });

        let mut controller = EvpnImetController::new();
        let first = controller
            .originate_instance(local_instance(100), &rib_tx)
            .await;
        let second = controller
            .originate_instance(local_instance(100), &rib_tx)
            .await;
        drop(rib_tx);
        let observed = responder.await.unwrap();

        let ImetOriginateOutcome::Originated { key } = first else {
            panic!("expected first originate, got {first:?}");
        };
        assert_eq!(second, ImetOriginateOutcome::AlreadyOriginated { key });
        assert_eq!(observed, vec![key]);
        assert_eq!(controller.len(), 1);
        assert_eq!(controller.originated_key(vni(100)), Some(key));
    }

    #[tokio::test]
    async fn controller_does_not_record_rejected_originates() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::InjectEvpn { reply, .. } = msg {
                    let _ = reply.send(Err(RibCommandError::internal("simulated")));
                }
            }
        });

        let mut controller = EvpnImetController::new();
        let outcome = controller
            .originate_instance(local_instance(100), &rib_tx)
            .await;
        drop(rib_tx);
        responder.await.unwrap();

        assert!(matches!(outcome, ImetOriginateOutcome::Rejected { .. }));
        assert!(controller.is_empty());
    }

    #[tokio::test]
    async fn controller_tracks_reply_dropped_originates_for_shutdown_withdraw() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let responder = tokio::spawn(async move {
            let mut saw_inject = false;
            let mut saw_withdraw = false;
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::InjectEvpn { reply, .. } => {
                        saw_inject = true;
                        drop(reply);
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        saw_withdraw = true;
                        let _ = reply.send(Ok(()));
                        break;
                    }
                    _ => {}
                }
            }
            (saw_inject, saw_withdraw)
        });

        let mut controller = EvpnImetController::new();
        let ImetOriginateOutcome::ReplyDropped { key } = controller
            .originate_instance(local_instance(100), &rib_tx)
            .await
        else {
            panic!("expected reply-dropped originate");
        };
        assert_eq!(controller.originated_key(vni(100)), Some(key));

        let outcome = controller.withdraw_instance(vni(100), &rib_tx).await;
        drop(rib_tx);
        let observed = responder.await.unwrap();

        assert_eq!(outcome, ImetWithdrawOutcome::Withdrawn { key });
        assert!(controller.is_empty());
        assert_eq!(observed, (true, true));
    }

    #[tokio::test]
    async fn controller_withdraw_removes_key_after_rib_accepts() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let responder = tokio::spawn(async move {
            let mut injects = 0;
            let mut withdraws = 0;
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::InjectEvpn { reply, .. } => {
                        injects += 1;
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        withdraws += 1;
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
            (injects, withdraws)
        });

        let mut controller = EvpnImetController::new();
        let ImetOriginateOutcome::Originated { key } = controller
            .originate_instance(local_instance(100), &rib_tx)
            .await
        else {
            panic!("expected originate");
        };
        let outcome = controller.withdraw_instance(vni(100), &rib_tx).await;
        drop(rib_tx);
        let observed = responder.await.unwrap();

        assert_eq!(outcome, ImetWithdrawOutcome::Withdrawn { key });
        assert!(controller.is_empty());
        assert_eq!(observed, (1, 1));
    }

    #[tokio::test]
    async fn controller_keeps_key_when_withdraw_rejected() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::InjectEvpn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        let _ = reply.send(Err(RibCommandError::internal("simulated")));
                    }
                    _ => {}
                }
            }
        });

        let mut controller = EvpnImetController::new();
        let ImetOriginateOutcome::Originated { key } = controller
            .originate_instance(local_instance(100), &rib_tx)
            .await
        else {
            panic!("expected originate");
        };
        let outcome = controller.withdraw_instance(vni(100), &rib_tx).await;
        drop(rib_tx);
        responder.await.unwrap();

        assert_eq!(outcome, ImetWithdrawOutcome::Rejected { key });
        assert_eq!(controller.originated_key(vni(100)), Some(key));
    }

    /// Regression: a withdraw the RIB answers with `NotFound` must converge
    /// the controller to RIB reality (untrack, report withdrawn) instead of
    /// `Rejected`. A tracked key the RIB doesn't hold — e.g. after a dropped
    /// oneshot reply on a prior withdraw — previously made the VNI
    /// permanently un-deletable and un-redefinable: re-origination
    /// short-circuited on `AlreadyOriginated` and every later
    /// delete/redefine converge rejected until daemon restart.
    #[tokio::test]
    async fn controller_untracks_key_when_withdraw_not_found() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::InjectEvpn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        let _ =
                            reply.send(Err(RibCommandError::not_found("EVPN route key not found")));
                    }
                    _ => {}
                }
            }
        });

        let mut controller = EvpnImetController::new();
        let ImetOriginateOutcome::Originated { key } = controller
            .originate_instance(local_instance(100), &rib_tx)
            .await
        else {
            panic!("expected originate");
        };
        let outcome = controller.withdraw_instance(vni(100), &rib_tx).await;
        assert_eq!(
            outcome,
            ImetWithdrawOutcome::Withdrawn { key },
            "not_found must converge to withdrawn, not Rejected"
        );
        assert!(
            controller.is_empty(),
            "controller must untrack the key the RIB doesn't hold"
        );

        // The VNI is deletable/redefinable again: a follow-up withdraw is a
        // local no-op and a re-originate actually injects.
        let outcome = controller.withdraw_instance(vni(100), &rib_tx).await;
        assert_eq!(
            outcome,
            ImetWithdrawOutcome::NotOriginated { vni: vni(100) }
        );
        drop(rib_tx);
        responder.await.unwrap();
    }

    /// Regression: converge paths (`converge_l2vni_add` / `_swap` /
    /// `_redefine` / `_delete`) hold the daemon's IMET controller mutex
    /// across the RIB ack await. A wedged RIB — command received, reply
    /// neither sent nor dropped — previously parked that await forever,
    /// holding the mutex and locking every later EVPN runtime converge out
    /// until restart. The ADR-0102 `send_and_ack` timeout bounds the await;
    /// the timeout maps to `RibUnavailable` so the converge reports a real
    /// failure instead of claiming success.
    #[tokio::test(start_paused = true)]
    async fn stalled_rib_originate_releases_controller_lock_at_ack_timeout() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let controller = Arc::new(tokio::sync::Mutex::new(EvpnImetController::new()));

        // First converge: lock the controller across the originate await,
        // exactly like converge_l2vni_add does.
        let converge = {
            let controller = controller.clone();
            let rib_tx = rib_tx.clone();
            tokio::spawn(async move {
                controller
                    .lock()
                    .await
                    .originate_instance(local_instance(100), &rib_tx)
                    .await
            })
        };

        // Wedged RIB: receive the inject but never answer — keep the reply
        // sender alive (dropping it would signal "reply dropped" instead).
        let parked_reply = match rib_rx.recv().await.expect("inject reaches the RIB") {
            RibUpdate::InjectEvpn { reply, .. } => reply,
            _other => panic!("expected InjectEvpn"),
        };

        // Second converge attempt: must acquire the lock once the ack
        // timeout releases the first holder.
        let second = tokio::time::timeout(
            crate::evpn_ack::RIB_ACK_TIMEOUT + std::time::Duration::from_secs(1),
            controller.lock(),
        )
        .await;
        assert!(
            second.is_ok(),
            "a stalled RIB must not hold the IMET controller lock past the ack timeout"
        );
        drop(second);

        let outcome = converge.await.unwrap();
        assert!(
            matches!(outcome, ImetOriginateOutcome::RibUnavailable { .. }),
            "ack timeout must surface as a converge failure, got {outcome:?}"
        );
        assert!(
            controller.lock().await.is_empty(),
            "an unacknowledged originate must not be tracked"
        );
        drop(parked_reply);
    }

    /// Same wedged-RIB bound for the withdraw path: the ack timeout maps to
    /// `RibUnavailable` and the key stays tracked so a later converge can
    /// retry the withdraw.
    #[tokio::test(start_paused = true)]
    async fn stalled_rib_withdraw_times_out_as_rib_unavailable() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let mut controller = EvpnImetController::new();

        let (outcome, ()) = tokio::join!(
            controller.originate_instance(local_instance(100), &rib_tx),
            async {
                if let Some(RibUpdate::InjectEvpn { reply, .. }) = rib_rx.recv().await {
                    let _ = reply.send(Ok(()));
                }
            }
        );
        let ImetOriginateOutcome::Originated { key } = outcome else {
            panic!("expected originate, got {outcome:?}");
        };

        let (outcome, _parked_reply) =
            tokio::join!(controller.withdraw_instance(vni(100), &rib_tx), async {
                match rib_rx.recv().await.expect("withdraw reaches the RIB") {
                    RibUpdate::WithdrawEvpn { reply, .. } => reply,
                    _other => panic!("expected WithdrawEvpn"),
                }
            });
        assert_eq!(
            outcome,
            ImetWithdrawOutcome::RibUnavailable { key },
            "withdraw ack timeout must report RibUnavailable, not hang"
        );
        assert_eq!(
            controller.originated_key(vni(100)),
            Some(key),
            "an unacknowledged withdraw must keep the key tracked for retry"
        );
    }

    #[tokio::test]
    async fn controller_withdraw_unknown_vni_is_local_noop() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let responder = tokio::spawn(async move {
            let mut messages = 0;
            while rib_rx.recv().await.is_some() {
                messages += 1;
            }
            messages
        });

        let mut controller = EvpnImetController::new();
        let outcome = controller.withdraw_instance(vni(100), &rib_tx).await;
        drop(rib_tx);
        let observed = responder.await.unwrap();

        assert_eq!(
            outcome,
            ImetWithdrawOutcome::NotOriginated { vni: vni(100) }
        );
        assert_eq!(observed, 0);
    }

    #[tokio::test]
    async fn controller_withdraw_all_emits_one_withdraw_per_originated_key() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let responder = tokio::spawn(async move {
            let mut injects = 0;
            let mut withdraws = 0;
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::InjectEvpn { reply, .. } => {
                        injects += 1;
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        withdraws += 1;
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
            (injects, withdraws)
        });

        let mut controller = EvpnImetController::new();
        controller
            .originate_all(vec![local_instance(100), local_instance(200)], &rib_tx)
            .await;

        controller.withdraw_all(&rib_tx).await;
        drop(rib_tx);
        let observed = responder.await.unwrap();
        assert!(controller.is_empty());
        assert_eq!(observed, (2, 2));
    }
}
