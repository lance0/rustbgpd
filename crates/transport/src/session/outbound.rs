use super::export::{
    DroppedIpv6NextHops, ExportProbeError, ExportWithdrawal, MpAttrCache, PreparedAttrCache,
    PreparedMpCandidate, PreparedUnicastCandidate, PreparedWithdrawal, ReachNlri,
    SessionExportProfile, UnreachNlri, has_otc,
};
use super::packing::{ChunkSizer, Fit, entry_len, ipv4_entry_len, prefix_len, within};
use super::{
    Afi, BgpRole, EvpnRoute, FlowSpecRule, IpAddr, Ipv4Addr, Ipv4NlriEntry, Ipv4UnicastMode,
    Ipv6Addr, Message, NlriEntry, OutboundRouteUpdate, PathAttribute, PeerSession, Prefix, Route,
    RouteRefreshMessage, RouteRefreshSubtype, Safi, UpdateMessage, debug, info, warn,
};
use super::{
    BgpLsRibRoute, BgpLsRouteKey, EvpnRibRoute, FlowSpecKey, FlowSpecRoute, LabeledRibRoute,
    RtcRibRoute, VpnRibRoute,
};
use rustbgpd_wire::VpnFlowSpecRule;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Worker time one ordinary slice may take, encode and release included,
/// before the next slice is cut smaller. The session shares tokio workers
/// with the readiness endpoint and every other session.
pub(super) const SLICE_TIME_BUDGET: Duration = Duration::from_millis(4);
/// Floor for a shrunken slice, so per-slice overhead stays amortized.
const MIN_SLICE_ROUTES: usize = 64;

/// A paused slice keeps source identity, never copied attributes or encoded frames.
struct PendingSlice {
    groups: VecDeque<PendingGroup>,
    source_start: usize,
    phase: OutboundPhase,
    moved: MovedSlice,
}

struct PendingGroup {
    wire: GroupWire,
    rows: Vec<usize>,
    next: usize,
}

#[derive(Clone, Copy)]
enum GroupWire {
    Ipv4Body,
    Mp {
        afi: Afi,
        safi: Safi,
        mode: Ipv4UnicastMode,
        next_hop: Option<(IpAddr, Option<Ipv6Addr>)>,
    },
    Refresh(Afi, Safi, RouteRefreshSubtype),
    Eor(Afi, Safi),
}

/// These rows were already moved from the envelope. Their indices stay fixed
/// while groups remain; only retirement consumes the iterator.
#[derive(Default)]
enum MovedSlice {
    #[default]
    None,
    Evpn(std::vec::IntoIter<EvpnRibRoute>),
    Vpn(std::vec::IntoIter<VpnRibRoute>),
    Labeled(std::vec::IntoIter<LabeledRibRoute>),
}

impl MovedSlice {
    fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Evpn(rows) => rows.len(),
            Self::Vpn(rows) => rows.len(),
            Self::Labeled(rows) => rows.len(),
        }
    }

    fn release(&mut self, left: &mut usize) {
        let released = match self {
            Self::None => 0,
            Self::Evpn(rows) => rows.by_ref().take(*left).count(),
            Self::Vpn(rows) => rows.by_ref().take(*left).count(),
            Self::Labeled(rows) => rows.by_ref().take(*left).count(),
        };
        *left -= released;
    }
}

impl PendingGroup {
    fn new(wire: GroupWire, rows: Vec<usize>) -> Self {
        Self {
            wire,
            rows,
            next: 0,
        }
    }
}

impl PendingSlice {
    fn evpn<'a>(&'a self, update: &'a OutboundRouteUpdate, row: usize) -> &'a EvpnRibRoute {
        match &self.moved {
            MovedSlice::Evpn(rows) => &rows.as_slice()[row],
            _ => &update.evpn_announce[self.source_start + row],
        }
    }

    fn vpn<'a>(&'a self, update: &'a OutboundRouteUpdate, row: usize) -> &'a VpnRibRoute {
        match &self.moved {
            MovedSlice::Vpn(rows) => &rows.as_slice()[row],
            _ => &update.vpn_announce[self.source_start + row],
        }
    }

    fn labeled(&self, row: usize) -> &LabeledRibRoute {
        let MovedSlice::Labeled(rows) = &self.moved else {
            unreachable!("labeled source rows move into the active slice")
        };
        &rows.as_slice()[row]
    }

    fn withdrawal(&self, update: &OutboundRouteUpdate, row: usize) -> (Prefix, u32) {
        let index = self.source_start + row;
        if index < update.shared_withdraw.len() {
            update.shared_withdraw[index]
        } else {
            update.withdraw[index - update.shared_withdraw.len()]
        }
    }

    /// Only the current group's attributes are rebuilt, after the frame guard.
    /// The immutable source and exact snapshot are the same ones used before
    /// parking; the first member remains the representative even after it sent.
    fn attributes(
        &self,
        group: &PendingGroup,
        update: &OutboundRouteUpdate,
        export: &SessionExportProfile,
    ) -> Arc<Vec<PathAttribute>> {
        let row = group.rows[0];
        let index = self.source_start + row;
        let attrs = match self.phase {
            OutboundPhase::Announce => {
                let mut attrs = export.prepare_unicast_attribute_bundle(
                    &update.announce[index],
                    export.local_ipv4(),
                    update.next_hop_override.get(index).and_then(Option::as_ref),
                );
                return if matches!(group.wire, GroupWire::Ipv4Body) {
                    attrs.with_next_hop()
                } else {
                    attrs.without_next_hop()
                };
            }
            OutboundPhase::FlowspecAnnounce => {
                export.prepare_flowspec_attributes(&update.flowspec_announce[index])
            }
            OutboundPhase::EvpnAnnounce => export.prepare_evpn_attributes(self.evpn(update, row)),
            OutboundPhase::BgplsAnnounce => {
                export.prepare_bgpls_attributes(&update.bgpls_announce[index])
            }
            OutboundPhase::VpnAnnounce => export.prepare_vpn_attributes(self.vpn(update, row)),
            OutboundPhase::LabeledAnnounce => export.prepare_labeled_attributes(self.labeled(row)),
            OutboundPhase::RtcAnnounce => {
                export.prepare_rtc_attributes(&update.rtc_announce[index])
            }
            _ => Vec::new(),
        };
        Arc::new(attrs)
    }

    /// Gather only the chunk being probed. No prepared attributes or copied
    /// NLRI survive a return to the actor, and no sent prefix is visited again.
    #[expect(
        clippy::too_many_lines,
        reason = "source-index reconstruction covers the existing outbound families in one exhaustive match"
    )]
    fn build_chunk(
        &self,
        group: &PendingGroup,
        rows: &[usize],
        update: &OutboundRouteUpdate,
        export: &SessionExportProfile,
        attrs: &[PathAttribute],
    ) -> Result<UpdateMessage, rustbgpd_wire::EncodeError> {
        let unicast = |row: usize| {
            let (prefix, path_id) = if matches!(self.phase, OutboundPhase::Announce) {
                let route = &update.announce[self.source_start + row];
                (route.prefix, route.path_id)
            } else {
                self.withdrawal(update, row)
            };
            NlriEntry { prefix, path_id }
        };
        if matches!(group.wire, GroupWire::Ipv4Body) {
            let entries: Vec<_> = rows
                .iter()
                .map(|&row| {
                    let entry = unicast(row);
                    let Prefix::V4(prefix) = entry.prefix else {
                        unreachable!("an IPv4 body group contains only IPv4 source rows")
                    };
                    Ipv4NlriEntry {
                        prefix,
                        path_id: entry.path_id,
                    }
                })
                .collect();
            return if matches!(self.phase, OutboundPhase::Announce) {
                export.build_ipv4_body(&entries, &[], attrs)
            } else {
                export.build_ipv4_body(&[], &entries, &[])
            };
        }
        let GroupWire::Mp {
            afi,
            safi,
            mode,
            next_hop,
        } = group.wire
        else {
            unreachable!("markers have their own guarded sender")
        };
        macro_rules! reach {
            ($variant:ident, $entry:expr) => {{
                let entries: Vec<_> = rows.iter().map(|&row| $entry(row)).collect();
                let (nh, ll) = next_hop.expect("an announcement group has a next hop");
                export.build_mp_reach(
                    afi,
                    safi,
                    nh,
                    ll,
                    attrs,
                    ReachNlri::$variant(&entries),
                    mode,
                )
            }};
        }
        macro_rules! unreach {
            ($variant:ident, $entry:expr) => {{
                let entries: Vec<_> = rows.iter().map(|&row| $entry(row)).collect();
                export.build_mp_unreach(afi, safi, UnreachNlri::$variant(&entries), mode)
            }};
        }
        macro_rules! withdrawn {
            ($variant:ident, $field:ident, $row:expr) => {{
                let prepared = export.prepare_withdrawal(ExportWithdrawal::$variant(
                    &update.$field[self.source_start + $row],
                )).expect("the same immutable source and export snapshot were validated before parking");
                let PreparedWithdrawal::$variant(prepared) = prepared else {
                    unreachable!("withdrawal preparation preserves its family")
                };
                prepared.nlri
            }};
        }
        match self.phase {
            OutboundPhase::Announce => reach!(Unicast, unicast),
            OutboundPhase::Withdraw => unreach!(Unicast, unicast),
            OutboundPhase::FlowspecAnnounce => {
                if safi == Safi::FlowSpecVpn {
                    reach!(VpnFlowSpec, |row: usize| {
                        let route = &update.flowspec_announce[self.source_start + row];
                        VpnFlowSpecRule {
                            rd: route.rd.expect("VPN group retains its RD"),
                            rule: route.rule.clone(),
                        }
                    })
                } else {
                    reach!(FlowSpec, |row: usize| update.flowspec_announce
                        [self.source_start + row]
                        .rule
                        .clone())
                }
            }
            OutboundPhase::FlowspecWithdraw => {
                if safi == Safi::FlowSpecVpn {
                    unreach!(VpnFlowSpec, |row: usize| {
                        let key = &update.flowspec_withdraw[self.source_start + row];
                        VpnFlowSpecRule {
                            rd: key.rd.expect("VPN group retains its RD"),
                            rule: key.rule.clone(),
                        }
                    })
                } else {
                    unreach!(FlowSpec, |row: usize| update.flowspec_withdraw
                        [self.source_start + row]
                        .rule
                        .clone())
                }
            }
            OutboundPhase::EvpnAnnounce => {
                reach!(Evpn, |row: usize| self.evpn(update, row).route.clone())
            }
            OutboundPhase::EvpnWithdraw => {
                unreach!(Evpn, |row: usize| withdrawn!(Evpn, evpn_withdraw, row))
            }
            OutboundPhase::BgplsAnnounce => reach!(BgpLs, |row: usize| update.bgpls_announce
                [self.source_start + row]
                .nlri
                .clone()),
            OutboundPhase::BgplsWithdraw => {
                unreach!(BgpLs, |row: usize| withdrawn!(BgpLs, bgpls_withdraw, row))
            }
            OutboundPhase::VpnAnnounce => reach!(Vpn, |row: usize| export
                .prepare_vpn_candidate_with(self.vpn(update, row), || ())
                .expect("same validated VPN source and snapshot")
                .nlri),
            OutboundPhase::VpnWithdraw => {
                unreach!(Vpn, |row: usize| withdrawn!(Vpn, vpn_withdraw, row))
            }
            OutboundPhase::LabeledAnnounce => reach!(Labeled, |row: usize| export
                .prepare_labeled_candidate_with(self.labeled(row), || ())
                .expect("same validated labeled source and snapshot")
                .nlri),
            OutboundPhase::LabeledWithdraw => {
                unreach!(Labeled, |row: usize| withdrawn!(
                    Labeled,
                    labeled_withdraw,
                    row
                ))
            }
            OutboundPhase::RtcAnnounce => {
                reach!(Rtc, |row: usize| update.rtc_announce
                    [self.source_start + row]
                    .nlri)
            }
            OutboundPhase::RtcWithdraw => {
                unreach!(Rtc, |row: usize| withdrawn!(Rtc, rtc_withdraw, row))
            }
            OutboundPhase::Requests
            | OutboundPhase::Begin
            | OutboundPhase::End
            | OutboundPhase::Eor => {
                unreachable!("markers have their own guarded sender")
            }
        }
    }
}

/// One envelope remains owned until its final marker is admitted. Slices
/// reuse the exact export snapshot, without growing the bounded writer queue.
pub(super) struct PendingOutbound {
    pub(super) shared: Option<(Arc<super::shared_group::ProgressiveGroupEncode>, usize)>,
    requests: Vec<(Afi, Safi)>,
    phase: usize,
    offset: usize,
    capacity_blocked: bool,
    /// Set while the next frame allowance does not fit the writer budget:
    /// the completion watermark at which that allowance fits again. The cursor stays
    /// where it is. A paused peer is not a failed one: with RFC 9687 send
    /// hold enabled no admission deadline runs, since the writer's send hold
    /// bounds the write in flight; with it disabled the admission deadline
    /// does, re-armed by every completed write.
    bytes_wait: Option<(tokio::sync::watch::Receiver<u64>, u64)>,
    /// Route budget for the next ordinary slice. It halves after a slice
    /// overruns [`SLICE_TIME_BUDGET`] and doubles back after a cheap one, so
    /// a slow encode yields sooner. A slice within budget keeps the
    /// shared-group slice size; UPDATE packing is not part of the export
    /// contract (ADR-0099), only per-key order is.
    slice_routes: usize,
    /// EVPN, VPN and labeled announcements, moved out a slice at a time:
    /// a slice owns its routes without cloning them, and each slice releases
    /// its share of the envelope instead of the final advance dropping it
    /// whole.
    evpn_announce: std::vec::IntoIter<EvpnRibRoute>,
    vpn_announce: std::vec::IntoIter<VpnRibRoute>,
    labeled_announce: std::vec::IntoIter<LabeledRibRoute>,
    /// Unicast announcements, filled only once the envelope retires (see
    /// [`Self::begin_retirement`]); until then they stay in `update`.
    announce: std::vec::IntoIter<Route>,
    /// The other heap-owning payloads, likewise moved out of `update` only
    /// once the envelope retires.
    retiring_rest: RetiringRest,
    pending_slice: Option<PendingSlice>,
    /// The envelope. Declared after the inventory moved out of it, so its
    /// outbound credit charge and operation latch drop last, after every
    /// moved route, on every destructor path.
    pub(super) update: OutboundRouteUpdate,
    /// Spans every announce slice, so the envelope reports dropped IPv6
    /// next hops once, when its announce phase completes.
    dropped_ipv6_next_hops: DroppedIpv6NextHops,
    #[cfg(test)]
    pub(super) test_slice_cost: Option<Duration>,
}

/// Payload vectors whose elements own heap memory or a shared reference, and
/// which the encode path reads in place from `update`. A retiring envelope
/// releases them under the same slice budget as its announcements.
#[derive(Default)]
struct RetiringRest {
    flowspec_announce: std::vec::IntoIter<FlowSpecRoute>,
    flowspec_withdraw: std::vec::IntoIter<FlowSpecKey>,
    bgpls_announce: std::vec::IntoIter<BgpLsRibRoute>,
    bgpls_withdraw: std::vec::IntoIter<BgpLsRouteKey>,
    rtc_announce: std::vec::IntoIter<RtcRibRoute>,
    otc_blocked: std::vec::IntoIter<Route>,
}

/// A payload left in `update` frees in one step whatever its length, so its
/// elements must own nothing to drop; a heap-owning one fails to compile
/// here and belongs in [`RetiringRest`].
fn freed_in_one_step<T>(_: &[T]) {
    const { assert!(!std::mem::needs_drop::<T>()) }
}

impl RetiringRest {
    fn take(update: &mut OutboundRouteUpdate) -> Self {
        // Exhaustive, so a new payload field does not compile until it is
        // classified here.
        let OutboundRouteUpdate {
            exact_export_snapshot: _,
            announce_source_exclusion: _,
            // Retired through `own_if_last`, or moved out at admission.
            announce: _,
            evpn_announce: _,
            vpn_announce: _,
            labeled_announce: _,
            shared_withdraw,
            withdraw,
            end_of_rib,
            replay: _,
            refresh_markers,
            next_hop_override,
            flowspec_announce,
            flowspec_withdraw,
            evpn_withdraw,
            bgpls_announce,
            bgpls_withdraw,
            vpn_withdraw,
            labeled_withdraw,
            rtc_announce,
            rtc_withdraw,
            otc_blocked,
            request_refresh_all_negotiated: _,
            shared_group_encode: _,
            exempt_announce: _,
            // Released when the original envelope drops, after its inventory.
            credit: _,
            latch: _,
        } = update;
        freed_in_one_step(shared_withdraw.as_slice());
        freed_in_one_step(withdraw);
        freed_in_one_step(end_of_rib);
        freed_in_one_step(refresh_markers);
        freed_in_one_step(next_hop_override.as_slice());
        freed_in_one_step(evpn_withdraw);
        freed_in_one_step(vpn_withdraw);
        freed_in_one_step(labeled_withdraw);
        freed_in_one_step(rtc_withdraw);
        Self {
            flowspec_announce: std::mem::take(flowspec_announce).into_iter(),
            flowspec_withdraw: std::mem::take(flowspec_withdraw).into_iter(),
            bgpls_announce: std::mem::take(bgpls_announce).into_iter(),
            bgpls_withdraw: std::mem::take(bgpls_withdraw).into_iter(),
            rtc_announce: std::mem::take(rtc_announce).into_iter(),
            otc_blocked: std::mem::take(otc_blocked).into_iter(),
        }
    }

    fn release(&mut self, left: &mut usize) {
        *left -= self.flowspec_announce.by_ref().take(*left).count();
        *left -= self.flowspec_withdraw.by_ref().take(*left).count();
        *left -= self.bgpls_announce.by_ref().take(*left).count();
        *left -= self.bgpls_withdraw.by_ref().take(*left).count();
        *left -= self.rtc_announce.by_ref().take(*left).count();
        *left -= self.otc_blocked.by_ref().take(*left).count();
    }

    fn len(&self) -> usize {
        self.flowspec_announce.len()
            + self.flowspec_withdraw.len()
            + self.bgpls_announce.len()
            + self.bgpls_withdraw.len()
            + self.rtc_announce.len()
            + self.otc_blocked.len()
    }
}

#[derive(Clone, Copy)]
enum OutboundPhase {
    Requests,
    Begin,
    Withdraw,
    Announce,
    FlowspecWithdraw,
    EvpnWithdraw,
    BgplsWithdraw,
    VpnWithdraw,
    LabeledWithdraw,
    RtcWithdraw,
    EvpnAnnounce,
    BgplsAnnounce,
    VpnAnnounce,
    LabeledAnnounce,
    RtcAnnounce,
    FlowspecAnnounce,
    End,
    Eor,
}

const OUTBOUND_PHASES: &[OutboundPhase] = &[
    OutboundPhase::Requests,
    OutboundPhase::Begin,
    OutboundPhase::Withdraw,
    OutboundPhase::Announce,
    OutboundPhase::FlowspecWithdraw,
    OutboundPhase::EvpnWithdraw,
    OutboundPhase::BgplsWithdraw,
    OutboundPhase::VpnWithdraw,
    OutboundPhase::LabeledWithdraw,
    OutboundPhase::RtcWithdraw,
    OutboundPhase::EvpnAnnounce,
    OutboundPhase::BgplsAnnounce,
    OutboundPhase::VpnAnnounce,
    OutboundPhase::LabeledAnnounce,
    OutboundPhase::RtcAnnounce,
    OutboundPhase::FlowspecAnnounce,
    OutboundPhase::End,
    OutboundPhase::Eor,
];

const ANNOUNCE_PHASE: usize = 3;
const VPN_ANNOUNCE_PHASE: usize = 12;
const EVPN_ANNOUNCE_PHASE: usize = 10;
const _: () = assert!(matches!(
    OUTBOUND_PHASES[EVPN_ANNOUNCE_PHASE],
    OutboundPhase::EvpnAnnounce
));
const _: () = assert!(matches!(
    OUTBOUND_PHASES[VPN_ANNOUNCE_PHASE],
    OutboundPhase::VpnAnnounce
));
const _: () = assert!(matches!(
    OUTBOUND_PHASES[ANNOUNCE_PHASE],
    OutboundPhase::Announce
));

/// Private payloads retain slice-by-slice ownership and retirement; shared
/// payloads stay borrowed for streaming and complete local fallback.
fn take_private_announcements<T>(
    announce: &mut Arc<Vec<T>>,
    shared: bool,
) -> std::vec::IntoIter<T> {
    if shared {
        return Vec::new().into_iter();
    }
    match Arc::try_unwrap(std::mem::take(announce)) {
        Ok(routes) => routes.into_iter(),
        Err(routes) => {
            *announce = routes;
            Vec::new().into_iter()
        }
    }
}

/// Consume one envelope's reference to `shared`. `Arc::into_inner`, unlike
/// `Arc::try_unwrap`, hands the inventory to exactly one of several members
/// completing at once, so it is never left to whichever drops last. A moved
/// private remainder already in `owned` is kept.
fn own_if_last<T>(owned: &mut std::vec::IntoIter<T>, shared: &mut Arc<Vec<T>>) {
    if let Some(routes) = Arc::into_inner(std::mem::take(shared))
        && !routes.is_empty()
    {
        debug_assert_eq!(owned.len(), 0, "a shared inventory has no moved remainder");
        *owned = routes.into_iter();
    }
}

/// The family name and direction the first-pass senders log for `phase`,
/// so a resumed send reports a teardown the same way.
fn resumed_log_names(phase: OutboundPhase, afi: Afi, safi: Safi) -> (&'static str, bool) {
    use OutboundPhase as P;
    let family = match phase {
        P::Announce | P::Withdraw if afi == Afi::Ipv4 => "IPv4 unicast",
        P::Announce | P::Withdraw => "IPv6 unicast",
        P::FlowspecAnnounce | P::FlowspecWithdraw if safi == Safi::FlowSpecVpn => "VPN FlowSpec",
        P::FlowspecAnnounce | P::FlowspecWithdraw => "FlowSpec",
        P::EvpnAnnounce | P::EvpnWithdraw => "EVPN",
        P::BgplsAnnounce | P::BgplsWithdraw => "BGP-LS",
        P::VpnAnnounce | P::VpnWithdraw => "VPN",
        P::LabeledAnnounce | P::LabeledWithdraw => "labeled",
        P::RtcAnnounce | P::RtcWithdraw => "RTC",
        P::Requests | P::Begin | P::End | P::Eor => {
            unreachable!("markers have their own guarded sender")
        }
    };
    let withdrawal = matches!(
        phase,
        P::Withdraw
            | P::FlowspecWithdraw
            | P::EvpnWithdraw
            | P::BgplsWithdraw
            | P::VpnWithdraw
            | P::LabeledWithdraw
            | P::RtcWithdraw
    );
    (family, withdrawal)
}

impl PendingOutbound {
    fn new(
        mut update: OutboundRouteUpdate,
        shared: Option<(Arc<super::shared_group::ProgressiveGroupEncode>, usize)>,
        requests: Vec<(Afi, Safi)>,
    ) -> Self {
        // Election is finished. The cursor owns any stream this member uses;
        // the envelope must not retain its chunks through EoR or retirement.
        update.shared_group_encode = None;
        let evpn_announce = take_private_announcements(&mut update.evpn_announce, shared.is_some());
        let vpn_announce = take_private_announcements(&mut update.vpn_announce, shared.is_some());
        Self {
            evpn_announce,
            vpn_announce,
            labeled_announce: std::mem::take(&mut update.labeled_announce).into_iter(),
            announce: Vec::new().into_iter(),
            retiring_rest: RetiringRest::default(),
            pending_slice: None,
            update,
            shared,
            requests,
            phase: 0,
            offset: 0,
            capacity_blocked: false,
            bytes_wait: None,
            slice_routes: super::shared_group::PROGRESSIVE_SLICE_ROUTES,
            dropped_ipv6_next_hops: DroppedIpv6NextHops::default(),
            #[cfg(test)]
            test_slice_cost: None,
        }
    }

    /// Keep a completed or abandoned envelope only while its inventory is
    /// released in bounded steps; nothing more is sent from it. A replay
    /// envelope carries no announcement inventory and is dropped as before.
    /// An envelope already retiring takes no extra step, so teardown paths
    /// that meet in one turn still release at most one slice.
    pub(super) fn into_retiring(mut self) -> Option<Self> {
        if self.retiring() {
            return Some(self);
        }
        (self.update.replay.is_none() && self.begin_retirement()).then_some(self)
    }

    /// Once the envelope completes or is abandoned, no fallback can read the
    /// announcements again. Each envelope consumes its own reference to a
    /// shared (or private unicast) inventory; the one that held the last
    /// reference takes ownership, so the inventory is released a bounded batch
    /// per advance, like moved private payloads, instead of in one synchronous
    /// drop. Returns whether any remains after the first batch.
    pub(super) fn begin_retirement(&mut self) -> bool {
        if let Some(slice) = &mut self.pending_slice {
            slice.groups.clear();
        }
        own_if_last(&mut self.announce, &mut self.update.announce);
        own_if_last(&mut self.vpn_announce, &mut self.update.vpn_announce);
        own_if_last(&mut self.evpn_announce, &mut self.update.evpn_announce);
        // A repeated call must not drop an undrained remainder whole.
        if self.retiring_rest.len() == 0 {
            self.retiring_rest = RetiringRest::take(&mut self.update);
        }
        self.shared = None;
        self.capacity_blocked = false;
        self.bytes_wait = None;
        self.phase = OUTBOUND_PHASES.len();
        self.retire_step()
    }

    /// Release one slice-sized batch of a completed envelope's inventory,
    /// sized by the same slice-cost feedback as encode slices. The families
    /// share that one budget, so a mixed envelope stays within a slice.
    fn retire_step(&mut self) -> bool {
        let started = Instant::now();
        let mut left = self.slice_routes;
        if let Some(slice) = &mut self.pending_slice {
            slice.moved.release(&mut left);
            if slice.moved.len() == 0 {
                self.pending_slice = None;
            }
        }
        left -= self.announce.by_ref().take(left).count();
        left -= self.vpn_announce.by_ref().take(left).count();
        left -= self.evpn_announce.by_ref().take(left).count();
        left -= self.labeled_announce.by_ref().take(left).count();
        self.retiring_rest.release(&mut left);
        let released = self.slice_routes - left;
        let cost = started.elapsed();
        #[cfg(test)]
        let cost = self.test_slice_cost.unwrap_or(cost);
        if released > 0 {
            self.charge_slice(cost);
        }
        self.retiring()
    }

    /// Whether a partly sent slice is parked for resumption.
    #[cfg(test)]
    pub(super) fn slice_parked(&self) -> bool {
        self.pending_slice.is_some()
    }

    /// Whether admission waits for the writer to drain under its byte
    /// budget.
    #[cfg(test)]
    pub(super) fn bytes_blocked(&self) -> bool {
        self.bytes_wait
            .as_ref()
            .is_some_and(|(completed, target)| *completed.borrow() < *target)
    }

    /// Only a completed or abandoned envelope retires: before that, the
    /// moved private iterators still hold routes to send.
    pub(super) fn retiring(&self) -> bool {
        self.phase == OUTBOUND_PHASES.len()
            && self.announce.len()
                + self.vpn_announce.len()
                + self.evpn_announce.len()
                + self.labeled_announce.len()
                + self.retiring_rest.len()
                + self
                    .pending_slice
                    .as_ref()
                    .map_or(0, |slice| slice.moved.len())
                > 0
    }

    fn shared_announce_phase(&self) -> usize {
        if !self.update.evpn_announce.is_empty() {
            EVPN_ANNOUNCE_PHASE
        } else if !self.update.vpn_announce.is_empty() {
            VPN_ANNOUNCE_PHASE
        } else {
            ANNOUNCE_PHASE
        }
    }

    /// Waits inside the existing run-loop select, never inside a sender.
    /// The shared stream is awaited only once the cursor reaches the announce
    /// phase: a member's own withdrawals go first and must not wait for the
    /// encoder to publish.
    pub(super) async fn ready(&self, writer: Option<&tokio::sync::mpsc::Sender<bytes::Bytes>>) {
        if let Some((shared, next)) = &self.shared
            && self.phase >= self.shared_announce_phase()
        {
            shared.ready(*next).await;
        }
        if self.capacity_blocked
            && let Some(writer) = writer
        {
            // The session is the sole bulk producer. The temporary permit only
            // waits for space; synchronous admission rechecks the full budget.
            let _ = writer.reserve().await;
        }
        if let Some((completed, target)) = &self.bytes_wait {
            // A writer that exits drops the sender, which ends the wait too.
            let mut completed = completed.clone();
            let _ = completed.wait_for(|done| *done >= *target).await;
        }
    }

    fn finish_empty_phases(&mut self) -> bool {
        if self.pending_slice.is_some() {
            return false;
        }
        self.skip_empty_phases_before(OUTBOUND_PHASES.len())
    }

    /// A shared announce stream starts only after every earlier phase (the
    /// member's own withdrawals) is admitted, so withdrawals keep preceding
    /// announcements exactly as on the per-session path.
    fn withdrawals_admitted(&mut self) -> bool {
        if self.pending_slice.is_some() {
            return false;
        }
        self.skip_empty_phases_before(self.shared_announce_phase())
    }

    fn skip_empty_phases_before(&mut self, stop: usize) -> bool {
        while self.phase < stop
            && let Some(phase) = OUTBOUND_PHASES.get(self.phase)
        {
            let len = match phase {
                OutboundPhase::Requests => self.requests.len(),
                OutboundPhase::Begin => self
                    .update
                    .refresh_markers
                    .iter()
                    .filter(|(_, _, kind)| *kind == RouteRefreshSubtype::BoRR)
                    .count(),
                OutboundPhase::End => self
                    .update
                    .refresh_markers
                    .iter()
                    .filter(|(_, _, kind)| *kind == RouteRefreshSubtype::EoRR)
                    .count(),
                OutboundPhase::Withdraw => {
                    self.update.shared_withdraw.len() + self.update.withdraw.len()
                }
                OutboundPhase::Announce => self.update.announce.len(),
                OutboundPhase::FlowspecWithdraw => self.update.flowspec_withdraw.len(),
                OutboundPhase::EvpnWithdraw => self.update.evpn_withdraw.len(),
                OutboundPhase::BgplsWithdraw => self.update.bgpls_withdraw.len(),
                OutboundPhase::VpnWithdraw => self.update.vpn_withdraw.len(),
                OutboundPhase::LabeledWithdraw => self.update.labeled_withdraw.len(),
                OutboundPhase::RtcWithdraw => self.update.rtc_withdraw.len(),
                OutboundPhase::EvpnAnnounce => self
                    .update
                    .evpn_announce
                    .len()
                    .max(self.offset + self.evpn_announce.len()),
                OutboundPhase::BgplsAnnounce => self.update.bgpls_announce.len(),
                OutboundPhase::VpnAnnounce => self
                    .update
                    .vpn_announce
                    .len()
                    .max(self.offset + self.vpn_announce.len()),
                OutboundPhase::LabeledAnnounce => self.offset + self.labeled_announce.len(),
                OutboundPhase::RtcAnnounce => self.update.rtc_announce.len(),
                OutboundPhase::FlowspecAnnounce => self.update.flowspec_announce.len(),
                OutboundPhase::Eor => self.update.end_of_rib.len(),
            };
            if self.offset < len {
                return false;
            }
            self.phase += 1;
            self.offset = 0;
        }
        true
    }

    fn next_slice(&mut self, budget: usize) -> Option<(usize, OutboundRouteUpdate)> {
        while let Some(phase) = OUTBOUND_PHASES.get(self.phase) {
            let mut slice = OutboundRouteUpdate {
                exact_export_snapshot: self.update.exact_export_snapshot.clone(),
                announce_source_exclusion: self.update.announce_source_exclusion,
                ..OutboundRouteUpdate::default()
            };
            macro_rules! payload {
                ($field:ident) => {{
                    let end = (self.offset + budget).min(self.update.$field.len());
                    slice.$field = self.update.$field[self.offset..end].to_vec().into();
                    end
                }};
            }
            macro_rules! moved {
                ($field:ident) => {{
                    slice.$field = self.$field.by_ref().take(budget).collect();
                    self.offset + slice.$field.len()
                }};
            }
            macro_rules! shared_or_moved {
                ($field:ident) => {{
                    if self.update.$field.is_empty() {
                        slice.$field = self.$field.by_ref().take(budget).collect::<Vec<_>>().into();
                        self.offset + slice.$field.len()
                    } else {
                        payload!($field)
                    }
                }};
            }
            let end = match phase {
                // Requests are sent directly, one frame at a time by advance.
                OutboundPhase::Requests => self.requests.len(),
                OutboundPhase::Begin | OutboundPhase::End => {
                    let wanted = if matches!(phase, OutboundPhase::Begin) {
                        RouteRefreshSubtype::BoRR
                    } else {
                        RouteRefreshSubtype::EoRR
                    };
                    slice.refresh_markers = self
                        .update
                        .refresh_markers
                        .iter()
                        .copied()
                        .filter(|(_, _, subtype)| *subtype == wanted)
                        .skip(self.offset)
                        .take(budget)
                        .collect();
                    self.offset + slice.refresh_markers.len()
                }
                OutboundPhase::Withdraw => {
                    let end = (self.offset + budget)
                        .min(self.update.shared_withdraw.len() + self.update.withdraw.len());
                    slice.withdraw = self.withdraw_rows(end);
                    end
                }
                OutboundPhase::Announce => {
                    // Blackholing rows lead the envelope and go out in slices
                    // of their own, so no slice mixes them with ordinary rows
                    // that its attribute groups could send first.
                    let exempt = self.update.exempt_announce.min(self.update.announce.len());
                    let end = if self.offset < exempt {
                        (self.offset + budget).min(exempt)
                    } else {
                        (self.offset + budget).min(self.update.announce.len())
                    };
                    slice.announce = self.update.announce[self.offset..end].to_vec().into();
                    let overrides_end = end.min(self.update.next_hop_override.len());
                    if self.offset < overrides_end {
                        slice.next_hop_override = self.update.next_hop_override
                            [self.offset..overrides_end]
                            .to_vec()
                            .into();
                    }
                    end
                }
                OutboundPhase::FlowspecWithdraw => payload!(flowspec_withdraw),
                OutboundPhase::EvpnWithdraw => payload!(evpn_withdraw),
                OutboundPhase::BgplsWithdraw => payload!(bgpls_withdraw),
                OutboundPhase::VpnWithdraw => payload!(vpn_withdraw),
                OutboundPhase::LabeledWithdraw => payload!(labeled_withdraw),
                OutboundPhase::RtcWithdraw => payload!(rtc_withdraw),
                OutboundPhase::EvpnAnnounce => shared_or_moved!(evpn_announce),
                OutboundPhase::BgplsAnnounce => payload!(bgpls_announce),
                OutboundPhase::VpnAnnounce => shared_or_moved!(vpn_announce),
                OutboundPhase::LabeledAnnounce => moved!(labeled_announce),
                OutboundPhase::RtcAnnounce => payload!(rtc_announce),
                OutboundPhase::FlowspecAnnounce => payload!(flowspec_announce),
                OutboundPhase::Eor => payload!(end_of_rib),
            };
            if end == self.offset {
                self.phase += 1;
                self.offset = 0;
            } else {
                let start = self.offset;
                self.offset = end;
                return Some((start, slice));
            }
        }
        None
    }

    /// Unicast withdraw rows `offset..end`: the group's shared rows, then
    /// this envelope's own.
    fn withdraw_rows(&self, end: usize) -> Vec<(Prefix, u32)> {
        let shared = &self.update.shared_withdraw;
        let own = &self.update.withdraw;
        let mut rows = Vec::with_capacity(end - self.offset);
        if self.offset < shared.len() {
            rows.extend_from_slice(&shared[self.offset..end.min(shared.len())]);
        }
        if end > shared.len() {
            rows.extend_from_slice(
                &own[self.offset.max(shared.len()) - shared.len()..end - shared.len()],
            );
        }
        rows
    }

    /// Size the next ordinary slice from what this one cost.
    fn charge_slice(&mut self, cost: Duration) {
        if cost > SLICE_TIME_BUDGET {
            self.slice_routes = (self.slice_routes / 2).max(MIN_SLICE_ROUTES);
        } else if cost < SLICE_TIME_BUDGET / 4 {
            self.slice_routes =
                (self.slice_routes * 2).min(super::shared_group::PROGRESSIVE_SLICE_ROUTES);
        }
    }
}

/// An envelope held across `prepare_shared_group`, whose encoder role yields
/// between slices. A task cancelled at one of those yields drops this before
/// the session, so it hands the inventory to the paced release itself, under
/// the same guards as the session's `Drop`.
struct PreparingOutbound(Option<OutboundRouteUpdate>);

impl Drop for PreparingOutbound {
    fn drop(&mut self) {
        if let Some(update) = self.0.take()
            && !std::thread::panicking()
            && tokio::runtime::Handle::try_current().is_ok()
            && let Some(mut pending) =
                PendingOutbound::new(update, None, Vec::new()).into_retiring()
        {
            tokio::spawn(async move {
                while pending.retire_step() {
                    tokio::task::yield_now().await;
                }
            });
        }
    }
}

impl PeerSession {
    pub(super) async fn handle_outbound_route_update(&mut self, mut update: OutboundRouteUpdate) {
        debug_assert!(self.pending_outbound.is_none());
        let shared = if update.replay.is_none() {
            let mut preparing = PreparingOutbound(Some(update));
            let shared = self
                .prepare_shared_group(preparing.0.as_ref().expect("held until taken"))
                .await;
            update = preparing.0.take().expect("held until taken");
            shared
        } else {
            None
        };
        let mut requests = Vec::new();
        if update.request_refresh_all_negotiated {
            if let Some(negotiated) = &self.negotiated
                && negotiated.peer_route_refresh
            {
                requests.extend(
                    negotiated
                        .negotiated_families
                        .iter()
                        .copied()
                        .filter(|&family| super::commands::requests_route_refresh(family)),
                );
            } else {
                warn!(peer = %self.peer_label, "ROUTE-REFRESH request skipped: peer lacks the capability");
            }
        }
        if update.replay.is_none() {
            let peer_err = self
                .negotiated
                .as_ref()
                .is_some_and(|n| n.peer_enhanced_route_refresh);
            update.end_of_rib.retain(|(afi, safi)| {
                !peer_err
                    || !update.refresh_markers.iter().any(|(ma, ms, kind)| {
                        ma == afi
                            && ms == safi
                            && matches!(kind, RouteRefreshSubtype::BoRR | RouteRefreshSubtype::EoRR)
                    })
            });
            if !peer_err {
                update.refresh_markers.clear();
            }
            // Validate before even the first marker, and publish OTC diagnostics
            // once for the original envelope, not once per payload slice.
            if self.outbound_snapshot(&update).is_none() {
                return;
            }
            for route in std::mem::take(&mut update.otc_blocked) {
                self.record_otc_egress_block(&route);
            }
        }
        self.pending_outbound = Some(PendingOutbound::new(update, shared, requests));
        self.advance_pending_outbound();
    }

    /// Before an administrative close's NOTIFICATION, admit the outbound
    /// updates the RIB has already queued for this session, so that a
    /// withdraw staged just before the close (shutdown drains EVPN withdraws
    /// ahead of `PeerManagerCommand::Shutdown` for exactly this) reaches the
    /// peer ahead of the Cease. A GR peer that receives Cease/2 rather than a
    /// Hard Reset may otherwise keep the withdrawn route as stale.
    ///
    /// The drain shares the writer's close flush budget: it marks the close
    /// as started, which starts the writer's
    /// [`super::writer::CLOSE_FLUSH_BUDGET`] clock now, and it stops at the
    /// same deadline, so admitting more updates can never push the Cease
    /// past that bound. It checks the deadline and yields after every bounded
    /// admission step, as the run loop does, so a long envelope cannot run
    /// past the budget in one poll. Admission is capacity-checked, so the
    /// drain waits for writer room rather than tripping the saturation
    /// teardown; the hard-teardown signal stays live, so a Cease/8 raised
    /// during the drain still discards the backlog. Cease/8 and
    /// fast-failover aborts never come through here.
    ///
    /// Returns `true` when admission raised that Cease/8 during the drain.
    /// The connection is then already closing with its own NOTIFICATION, and
    /// the caller must finish with [`Self::finish_drain_teardown`] instead of
    /// its administrative NOTIFICATION.
    #[must_use]
    pub(super) async fn drain_outbound_before_close(&mut self) -> bool {
        if self.fsm.state() != rustbgpd_fsm::SessionState::Established
            || self.writer_bulk_tx.is_none()
        {
            return false;
        }
        let started = tokio::time::Instant::now();
        if let Some(close_started) = &self.writer_close_started {
            let _ = close_started.set(started);
        }
        let deadline = started + super::writer::CLOSE_FLUSH_BUDGET;
        let drain = async {
            while tokio::time::Instant::now() < deadline {
                if let Some(pending) = self.pending_outbound.as_ref() {
                    pending.ready(self.writer_bulk_tx.as_ref()).await;
                    self.advance_pending_outbound();
                    tokio::task::yield_now().await;
                    continue;
                }
                let replay_waiting = self
                    .pending_replay
                    .as_ref()
                    .is_some_and(|pending| pending.target.is_some());
                if replay_waiting || self.writer_bulk_tx.is_none() {
                    break;
                }
                let Ok(update) = self.outbound_rx.try_recv() else {
                    break;
                };
                self.handle_outbound_route_update(update).await;
                tokio::task::yield_now().await;
            }
        };
        if tokio::time::timeout_at(deadline, drain).await.is_err() {
            debug!(
                peer = %self.peer_label,
                "close drain reached its budget; queued outbound updates are not sent"
            );
        }
        // Only the Cease/8 teardown clears the priority sender mid-drain.
        self.writer_priority_tx.is_none()
    }

    /// Finish a close whose drain raised Cease/8 the way the run loop's
    /// writer-exit arm finishes any hard teardown: wait for the writer to
    /// put the Cease/8 out (bounded by its teardown linger), then take the
    /// session down through `TcpConnectionFails`. No second NOTIFICATION is
    /// recorded, so its counters, events, BMP Peer Down reason and teardown
    /// cause stay those of the Cease/8 that reached the wire.
    pub(super) async fn finish_drain_teardown(&mut self) {
        if let Some(join) = self.writer_join.take() {
            let result = join.await;
            self.handle_writer_exit(result).await;
        } else {
            self.handle_tcp_disconnect();
            self.drive_fsm(rustbgpd_fsm::Event::TcpConnectionFails)
                .await;
        }
    }

    /// Teardown abandons the envelope but still releases its inventory in
    /// bounded steps (see [`PendingOutbound::into_retiring`]).
    pub(super) fn retire_pending_outbound(&mut self) {
        self.pending_outbound = self
            .pending_outbound
            .take()
            .and_then(PendingOutbound::into_retiring);
    }

    /// An exiting session task would drop the session, and any inventory
    /// still retiring with it, in one turn. Hand that remainder to its own
    /// task, which releases one slice per yield; the exit never waits on it.
    pub(super) fn hand_off_retirement(&mut self) {
        let pending = self
            .pending_outbound
            .take()
            .and_then(PendingOutbound::into_retiring);
        self.retire_off_turn(pending);
    }

    /// Replace the outbound channel, discarding the envelopes still queued
    /// for a dying session unsent. One can hold the last reference to a
    /// shared inventory once the RIB and faster members have released
    /// theirs, so they retire on the same paced task as `pending`, one slice
    /// per yield, never in this turn.
    pub(super) fn retire_off_turn(&mut self, pending: Option<PendingOutbound>) {
        let (tx, rx) = tokio::sync::mpsc::channel(super::OUTBOUND_BUFFER);
        self.outbound_tx = tx;
        let mut queued = std::mem::replace(&mut self.outbound_rx, rx);
        // A permit reserved before the close still delivers after it, so
        // the task keeps the receiver until `recv` returns `None`, which it
        // does only once the queue is empty and no permit is outstanding.
        queued.close();
        if pending.is_none() && queued.capacity() == queued.max_capacity() {
            return;
        }
        tokio::spawn(async move {
            if let Some(mut pending) = pending {
                while pending.retire_step() {
                    tokio::task::yield_now().await;
                }
            }
            while let Some(update) = queued.recv().await {
                tokio::task::yield_now().await;
                let Some(mut pending) =
                    PendingOutbound::new(update, None, Vec::new()).into_retiring()
                else {
                    continue;
                };
                loop {
                    tokio::task::yield_now().await;
                    if !pending.retire_step() {
                        break;
                    }
                }
            }
        });
    }

    pub(super) fn expire_outbound_admission(&mut self) {
        // A write that completed in the same turn as the deadline is
        // progress the run loop has not seen yet: it re-arms the deadline
        // rather than losing the race to it.
        if let Some(progress) = &mut self.admission_progress
            && progress.has_changed().unwrap_or(false)
        {
            progress.borrow_and_update();
            self.note_write_progress(true);
            return;
        }
        self.outbound_admission_timer = None;
        if self
            .writer_bulk_tx
            .as_ref()
            .is_none_or(tokio::sync::mpsc::Sender::is_closed)
        {
            // Writer closure and resource expiry can be ready in the same
            // select turn. The writer-exit arm must retain its actual cause.
            self.retire_pending_outbound();
            return;
        }
        warn!(peer = %self.peer_label, "outbound writer capacity admission deadline expired — sending Cease/Out-of-Resources and tearing down");
        self.trigger_outbound_out_of_resources_teardown(
            crate::handle::SessionFailureCause::OutboundSaturation,
        );
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one bounded admission step keeps shared, ordinary, and terminal cursor ownership together"
    )]
    pub(super) fn advance_pending_outbound(&mut self) {
        let Some(mut pending) = self.pending_outbound.take() else {
            return;
        };
        if pending.retiring() {
            // Every frame is already admitted; only the release remains.
            if pending.retire_step() {
                self.pending_outbound = Some(pending);
            }
            return;
        }
        let Some(writer) = &self.writer_bulk_tx else {
            self.outbound_admission_timer = None;
            self.pending_outbound = pending.into_retiring();
            return;
        };
        if writer.is_closed() {
            // The writer-exit arm owns its actual failure cause. A stale
            // admission deadline must not relabel it as resource saturation.
            self.outbound_admission_timer = None;
            self.pending_outbound = pending.into_retiring();
            return;
        }
        // Every valid payload entry contributes at most one UPDATE frame;
        // grouping can only reduce that count. Requests and terminal markers
        // consume their own exact frame budget in separate phases.
        let budget = writer
            .capacity()
            .min(super::shared_group::PROGRESSIVE_SLICE_ROUTES);
        let max_len = usize::from(self.outbound_max_message_len());
        let mut bytes_needed = max_len;
        let before = self.writer_bulk_admitted;
        let mut finished = false;
        pending.capacity_blocked = budget == 0;
        let shared_ready = pending.shared.is_some() && pending.withdrawals_admitted();
        if shared_ready && let Some((shared, next)) = &mut pending.shared {
            let (chunks, terminal) =
                shared.snapshot_from(*next, super::shared_group::PROGRESSIVE_SLICE_ROUTES);
            let end = *next + chunks.len();
            let mut available = budget;
            pending.capacity_blocked = false;
            for chunk in chunks {
                if self.wants_shared_chunk(&pending.update, &chunk) {
                    if available == 0 {
                        pending.capacity_blocked = true;
                        break;
                    }
                    if chunk.bytes.len() > self.writer_bytes_available() {
                        // Resumes from this chunk once the writer drains.
                        bytes_needed = chunk.bytes.len();
                        break;
                    }
                    if self.enqueue_bulk_encoded(chunk.bytes, true).is_err() {
                        self.outbound_admission_timer = None;
                        self.pending_outbound = pending.into_retiring();
                        return;
                    }
                    available -= 1;
                    self.config.neighbor_counters.record_update_sent();
                    self.metrics.record_message_sent(&self.peer_label, "update");
                }
                *next += 1;
            }
            if *next == end {
                match terminal {
                    Some(super::shared_group::StreamTerminal::Complete) => {
                        // Only this announce phase was shared. Each member still owes
                        // its own terminal refresh/EoR phases, under the same
                        // writer capacity and envelope ownership as before.
                        pending.shared = None;
                        pending.phase = pending.shared_announce_phase() + 1;
                        pending.offset = 0;
                    }
                    Some(super::shared_group::StreamTerminal::Failed) => pending.shared = None,
                    None => {}
                }
            }
        } else if pending.update.replay.is_some() {
            // Even without writer capacity, cancellation must discard a terminal.
            finished =
                self.enqueue_replay_terminal_slice(&pending.update, &mut pending.offset, budget);
        } else if budget > 0 && self.writer_frame_room(max_len) == Ok(true) {
            if pending.pending_slice.is_some() {
                let started = Instant::now();
                if self.resume_pending_slice(&mut pending).is_err() {
                    self.outbound_admission_timer = None;
                    self.pending_outbound = pending.into_retiring();
                    return;
                }
                let cost = started.elapsed();
                // Tests pin resumes as cheap; `test_slice_cost` prices fresh slices.
                #[cfg(test)]
                let cost = {
                    let _ = cost;
                    Duration::ZERO
                };
                // Writer bytes, not routes, bound a resume, so a cheap one says
                // nothing about the next fresh slice: it may only shrink it.
                if cost > SLICE_TIME_BUDGET {
                    pending.charge_slice(cost);
                }
            } else if pending.phase == 0 && pending.offset < pending.requests.len() {
                let (afi, safi) = pending.requests[pending.offset];
                match self.send_refresh_frame(afi, safi, RouteRefreshSubtype::Normal, max_len) {
                    Ok(1) => pending.offset += 1,
                    Ok(_) => {}
                    Err(()) => {
                        self.outbound_admission_timer = None;
                        self.pending_outbound = pending.into_retiring();
                        return;
                    }
                }
            } else {
                if pending.phase == 0 {
                    pending.phase = 1;
                    pending.offset = 0;
                }
                if let Some((source_start, mut slice)) =
                    pending.next_slice(budget.min(pending.slice_routes))
                {
                    let started = Instant::now();
                    let mut groups = VecDeque::new();
                    let sent = self.send_route_update_slice(
                        &slice,
                        &mut pending.dropped_ipv6_next_hops,
                        &mut groups,
                    );
                    if !sent || !groups.is_empty() {
                        let moved = match OUTBOUND_PHASES[pending.phase] {
                            OutboundPhase::EvpnAnnounce
                                if pending.update.evpn_announce.is_empty() =>
                            {
                                MovedSlice::Evpn(
                                    Arc::try_unwrap(std::mem::take(&mut slice.evpn_announce))
                                        .expect("fresh moved slice has one owner")
                                        .into_iter(),
                                )
                            }
                            OutboundPhase::VpnAnnounce
                                if pending.update.vpn_announce.is_empty() =>
                            {
                                MovedSlice::Vpn(
                                    Arc::try_unwrap(std::mem::take(&mut slice.vpn_announce))
                                        .expect("fresh moved slice has one owner")
                                        .into_iter(),
                                )
                            }
                            OutboundPhase::LabeledAnnounce => MovedSlice::Labeled(
                                std::mem::take(&mut slice.labeled_announce).into_iter(),
                            ),
                            _ => MovedSlice::None,
                        };
                        pending.pending_slice = Some(PendingSlice {
                            groups,
                            source_start,
                            phase: OUTBOUND_PHASES[pending.phase],
                            moved,
                        });
                    }
                    drop(slice);
                    if !sent {
                        self.outbound_admission_timer = None;
                        self.pending_outbound = pending.into_retiring();
                        return;
                    }
                    let cost = started.elapsed();
                    // Tests pin the cost so slice sizes never follow host speed.
                    #[cfg(test)]
                    let cost = {
                        let _ = cost;
                        pending.test_slice_cost.unwrap_or_default()
                    };
                    pending.charge_slice(cost);
                } else {
                    finished = true;
                }
            }
        }
        if pending.shared.is_none() && pending.update.replay.is_none() {
            finished |= pending.finish_empty_phases();
        }
        if pending.phase > ANNOUNCE_PHASE {
            pending.dropped_ipv6_next_hops.warn(&self.peer_label, false);
        }
        if self.writer_bulk_admitted != before {
            self.outbound_admission_timer = None;
        }
        pending.bytes_wait = self.writer_bytes_wait(bytes_needed);
        if !finished
            && self
                .writer_bulk_tx
                .as_ref()
                .is_some_and(|tx| !tx.is_closed())
        {
            if pending.shared.is_none() || !shared_ready {
                pending.capacity_blocked = self
                    .writer_bulk_tx
                    .as_ref()
                    .is_some_and(|tx| tx.capacity() == 0);
            }
            let slots_full = self
                .writer_bulk_tx
                .as_ref()
                .is_some_and(|tx| tx.capacity() == 0);
            // The deadline bounds a wait for writer room during which no
            // write completes: the run loop re-arms it on every completed
            // write, so a slow peer that keeps reading is never torn down.
            // A byte wait runs it only with RFC 9687 send hold disabled;
            // otherwise a write is in flight and the writer's send hold
            // bounds it. Filtering can advance a slice without admitting a
            // frame, so the deadline belongs only to a continuous wait.
            let deadline = if pending.bytes_wait.is_some() {
                self.config.peer.send_hold_time == 0
            } else {
                pending.capacity_blocked && slots_full
            };
            self.pending_outbound = Some(pending);
            if !deadline {
                self.outbound_admission_timer = None;
            } else if self.outbound_admission_timer.is_none() {
                self.outbound_admission_timer =
                    Some(Box::pin(tokio::time::sleep(self.admission_deadline())));
                self.admission_progress = self.writer_completed.clone();
                if let Some(progress) = &mut self.admission_progress {
                    progress.borrow_and_update();
                }
            }
        } else {
            // Finished, or the writer closed: either way only release remains.
            self.outbound_admission_timer = None;
            self.pending_outbound = pending.into_retiring();
        }
        self.sample_outbound_queue_depth();
    }
}

impl PeerSession {
    /// How long admission may wait for writer room with no completed write
    /// before the session ends with Cease/Out-of-Resources: the send hold
    /// time, or its default when send hold is disabled.
    pub(super) fn admission_deadline(&self) -> Duration {
        let seconds = if self.config.peer.send_hold_time == 0 {
            rustbgpd_fsm::default_send_hold_time(self.config.peer.hold_time)
        } else {
            self.config.peer.send_hold_time
        };
        Duration::from_secs(u64::from(seconds))
    }

    /// A completed write is progress: re-arm a running admission deadline
    /// from now. A writer that has gone ends the watch; its exit arm owns
    /// the outcome.
    pub(super) fn note_write_progress(&mut self, progressed: bool) {
        if !progressed {
            self.admission_progress = None;
            return;
        }
        let deadline = tokio::time::Instant::now() + self.admission_deadline();
        if let Some(timer) = &mut self.outbound_admission_timer {
            timer.as_mut().reset(deadline);
        }
    }

    /// The completion watermark that leaves room for the next frame. Watching
    /// a target also observes progress racing with registration of the wait.
    fn writer_bytes_wait(&self, needed: usize) -> Option<(tokio::sync::watch::Receiver<u64>, u64)> {
        let completed = self.writer_completed.as_ref()?;
        (needed > self.writer_bytes_available()).then(|| {
            (
                completed.clone(),
                self.writer_bulk_admitted.saturating_sub(
                    super::writer::WRITER_BYTE_BUDGET.saturating_sub(needed as u64),
                ),
            )
        })
    }
}

// The per-batch outbound maps (`PreparedAttrCacheKey` cache + the
// `AttrGroupKey` UPDATE-grouping indices) use address-aware Fx hashing
// rather than the default SipHash: keying is once per announced route,
// and SipHash on these wide keys was the top prepare+encode line in the
// RR fanout flamegraph. HashDoS tradeoff (deliberate), mirroring the
// route-map rationale at the top of `rib::adj_rib_in`: keys include
// peer-derived attributes, next hops and router ids. Ordinary maps live
// for one family's grouping pass in an outbound slice; shared encoding
// keeps its attribute cache for the group payload. The hasher is not
// collision-resistant.
// Optional `max_prefixes` limits count unique prefixes, not Add-Path paths
// or distinct attribute sets, so they do not bound collision-chain length.
use crate::fast_hash::FastMap as HashMap;
use std::collections::hash_map::Entry;

fn has_route_payload(update: &OutboundRouteUpdate) -> bool {
    !update.announce.is_empty()
        || !update.shared_withdraw.is_empty()
        || !update.withdraw.is_empty()
        || !update.flowspec_announce.is_empty()
        || !update.flowspec_withdraw.is_empty()
        || !update.evpn_announce.is_empty()
        || !update.evpn_withdraw.is_empty()
        || !update.bgpls_announce.is_empty()
        || !update.bgpls_withdraw.is_empty()
        || !update.vpn_announce.is_empty()
        || !update.vpn_withdraw.is_empty()
        || !update.labeled_announce.is_empty()
        || !update.labeled_withdraw.is_empty()
        || !update.rtc_announce.is_empty()
        || !update.rtc_withdraw.is_empty()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct AttrGroupKey {
    attrs_ptr: usize,
    next_hop: Option<IpAddr>,
    link_local_next_hop: Option<Ipv6Addr>,
}

type AttrGroupValue = (Arc<Vec<PathAttribute>>, Option<IpAddr>, Option<Ipv6Addr>);

/// A value-map key carrying its value hash, computed once when the key is
/// built. The map hashes only the stored `u64`, so lookups hash each
/// attribute vector once and table growth never re-walks the attributes.
struct HashedAttrGroupValue {
    hash: u64,
    value: AttrGroupValue,
}

impl HashedAttrGroupValue {
    /// `hasher` must be the value map's own hasher. A seeded hasher gives
    /// each instance its own seed, so a hash from any other instance would
    /// never match a stored key and equal values would stop grouping.
    fn new(value: AttrGroupValue, hasher: &impl std::hash::BuildHasher) -> Self {
        Self {
            hash: hasher.hash_one(&value),
            value,
        }
    }
}

impl std::hash::Hash for HashedAttrGroupValue {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl PartialEq for HashedAttrGroupValue {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.value == other.value
    }
}

impl Eq for HashedAttrGroupValue {}

/// Groups one envelope's announcements by final attribute *value*, so
/// routes whose attributes are equal but separately allocated share
/// UPDATEs. Post-policy attribute `Arc`s are allocated per RIB distribution
/// pass, so a resync replaying routes stored across many passes would
/// otherwise emit one UPDATE per original pass and can overrun the bounded
/// writer queue. Pointer lookups stay the fast path, and the value map is
/// built only once a second distinct value appears, so the common
/// one-allocation envelope never hashes an attribute vector. Once the value
/// map exists, a pointer enters `by_ptr` only when it repeats or joins
/// another group, so a distinct-valued route costs one map insert, not
/// two; a repeated pointer pays one extra value hash. A pointer that
/// opens a group is kept alive by that group; one that joins an existing
/// group by value is pinned here, so a freed allocation cannot alias a
/// later one.
#[derive(Default)]
struct AttrGroupIndex {
    by_ptr: HashMap<AttrGroupKey, usize>,
    first: Option<(AttrGroupValue, usize)>,
    by_value: HashMap<HashedAttrGroupValue, usize>,
    pinned: Vec<Arc<Vec<PathAttribute>>>,
}

impl AttrGroupIndex {
    /// The group for these attributes: `Ok(existing)`, or `Err(next)` after
    /// registering `next` as the index of a new group the caller pushes
    /// holding `attrs`.
    fn group(
        &mut self,
        attrs: &Arc<Vec<PathAttribute>>,
        next_hop: Option<IpAddr>,
        link_local_next_hop: Option<Ipv6Addr>,
        next: usize,
    ) -> Result<usize, usize> {
        let key = AttrGroupKey {
            attrs_ptr: Arc::as_ptr(attrs) as usize,
            next_hop,
            link_local_next_hop,
        };
        if let Some(&idx) = self.by_ptr.get(&key) {
            return Ok(idx);
        }
        let idx = match &self.first {
            None => {
                self.first = Some(((Arc::clone(attrs), next_hop, link_local_next_hop), next));
                next
            }
            Some(((first, first_nh, first_ll), first_idx))
                if self.by_value.is_empty()
                    && *first_nh == next_hop
                    && *first_ll == link_local_next_hop
                    && **first == **attrs =>
            {
                *first_idx
            }
            Some((first, first_idx)) => {
                if self.by_value.is_empty() {
                    let key = HashedAttrGroupValue::new(first.clone(), self.by_value.hasher());
                    self.by_value.insert(key, *first_idx);
                }
                let value_key = HashedAttrGroupValue::new(
                    (Arc::clone(attrs), next_hop, link_local_next_hop),
                    self.by_value.hasher(),
                );
                match self.by_value.entry(value_key) {
                    // A pointer that opens a group is found again through the
                    // value map, so it skips `by_ptr` until it repeats: with
                    // mostly distinct attributes that saves a second map
                    // insert per route.
                    Entry::Vacant(vacant) => {
                        vacant.insert(next);
                        return Err(next);
                    }
                    // Its own group again: remember the pointer, no pin needed.
                    Entry::Occupied(own) if Arc::ptr_eq(&own.key().value.0, attrs) => {
                        let idx = *own.get();
                        self.by_ptr.insert(key, idx);
                        return Ok(idx);
                    }
                    Entry::Occupied(other) => *other.get(),
                }
            }
        };
        self.by_ptr.insert(key, idx);
        if idx == next {
            Err(next)
        } else {
            self.pinned.push(Arc::clone(attrs));
            Ok(idx)
        }
    }
}
struct V4BodyGroup {
    attrs: Arc<Vec<PathAttribute>>,
    prefixes: Vec<Ipv4NlriEntry>,
    sources: Vec<usize>,
}
struct MpGroup {
    attrs: Arc<Vec<PathAttribute>>,
    next_hop: IpAddr,
    link_local_next_hop: Option<Ipv6Addr>,
    prefixes: Vec<NlriEntry>,
    sources: Vec<usize>,
}

/// One VPN or labeled UPDATE group: family, next hop, link-local companion,
/// prepared attributes, and its routes in arrival order.
pub(super) type MpRouteGroup<T> = (
    (Afi, Safi),
    IpAddr,
    Option<Ipv6Addr>,
    Arc<Vec<PathAttribute>>,
    Vec<T>,
);

/// [`AttrGroupIndex`] per family. Equal attribute values in different
/// families must not share a group, and every family's index registers
/// positions in one shared group vector so groups keep first-arrival order.
#[derive(Default)]
pub(super) struct MpGroupIndex(HashMap<(Afi, Safi), AttrGroupIndex>);

impl MpGroupIndex {
    pub(super) fn push<T>(
        &mut self,
        groups: &mut Vec<MpRouteGroup<T>>,
        family: (Afi, Safi),
        prepared: PreparedMpCandidate<T, Arc<Vec<PathAttribute>>>,
    ) -> usize {
        let nh = prepared.next_hop;
        let ll = prepared.link_local_next_hop;
        match self
            .0
            .entry(family)
            .or_default()
            .group(&prepared.attrs, Some(nh), ll, groups.len())
        {
            Ok(idx) => {
                groups[idx].4.push(prepared.nlri);
                idx
            }
            Err(idx) => {
                groups.push((family, nh, ll, prepared.attrs, vec![prepared.nlri]));
                idx
            }
        }
    }
}
impl PeerSession {
    pub(super) fn otc_egress_blocks_unicast(&self, route: &Route) -> bool {
        has_otc(&route.attributes)
            && matches!(
                self.config.peer.local_role,
                Some(BgpRole::Customer | BgpRole::Peer | BgpRole::RouteServerClient)
            )
    }
    fn record_otc_egress_block(&mut self, route: &Route) {
        debug!(
            peer = %self.peer_label,
            prefix = %route.prefix,
            "not advertising unicast route with OTC to Provider/Peer/RouteServer"
        );
        self.record_otc_routes_blocked(
            rustbgpd_telemetry::reason_labels::OtcBlockReason::EgressToUpstreamViaOtc,
            1,
        );
    }
    /// Validate the original envelope before admitting any payload or marker.
    fn outbound_snapshot(
        &mut self,
        update: &OutboundRouteUpdate,
    ) -> Option<Arc<dyn rustbgpd_rib::ExactExportSnapshot>> {
        let snapshot: Arc<dyn rustbgpd_rib::ExactExportSnapshot> = match update
            .exact_export_snapshot
            .as_ref()
        {
            Some(snapshot) => Arc::clone(snapshot),
            None if !has_route_payload(update) => self.export_encoder.snapshot(),
            None => {
                warn!(
                    peer = %self.peer_label,
                    "RIB route-bearing envelope omitted its exact export snapshot — sending Cease/Out-of-Resources and tearing down"
                );
                self.trigger_outbound_out_of_resources_teardown(
                    crate::handle::SessionFailureCause::ExportSnapshotMissing,
                );
                return None;
            }
        };
        let Some(export) = snapshot.as_any().downcast_ref::<SessionExportProfile>() else {
            warn!(
                peer = %self.peer_label,
                "RIB outbound envelope carries an exact export snapshot from the wrong encoder — sending Cease/Out-of-Resources and tearing down"
            );
            self.trigger_outbound_out_of_resources_teardown(
                crate::handle::SessionFailureCause::ExportSnapshotIncompatible,
            );
            return None;
        };
        if rustbgpd_rib::ExactExportSnapshot::owner_id(export)
            != rustbgpd_rib::ExactExportEncoder::owner_id(self.export_encoder.as_ref())
        {
            warn!(
                peer = %self.peer_label,
                "RIB outbound envelope carries an exact export snapshot owned by another session — sending Cease/Out-of-Resources and tearing down"
            );
            self.trigger_outbound_out_of_resources_teardown(
                crate::handle::SessionFailureCause::ExportSnapshotWrongOwner,
            );
            return None;
        }
        Some(snapshot)
    }

    /// Send a whole envelope as one pass and report its dropped IPv6 next
    /// hops once. The run loop slices envelopes through
    /// `advance_pending_outbound` instead.
    #[cfg(any(test, feature = "bench-internals"))]
    pub(super) fn send_route_update(&mut self, update: OutboundRouteUpdate) {
        let mut dropped_ipv6_next_hops = DroppedIpv6NextHops::default();
        let mut deferred = VecDeque::new();
        let sent =
            self.send_route_update_slice(&update, &mut dropped_ipv6_next_hops, &mut deferred);
        assert!(
            !sent || deferred.is_empty(),
            "direct test/benchmark sender did not complete its update"
        );
        dropped_ipv6_next_hops.warn(&self.peer_label, false);
        drop(update);
    }

    /// Send an outbound route update slice as wire UPDATE messages.
    ///
    /// Encodes each piece (`BoRR` markers, withdrawals, announcements,
    /// `FlowSpec`, EVPN, `EoR` markers, `EoRR` markers) and pushes the bytes
    /// onto the writer task's bulk channel via [`Self::enqueue_bulk`].
    /// Returns synchronously — there's no awaiting on TCP writes here
    /// after the writer-task split (ADR-0051). Dropped IPv6 next hops are
    /// noted in `dropped_ipv6_next_hops`; the caller reports them once per
    /// envelope.
    #[expect(
        clippy::too_many_lines,
        reason = "export pipeline keeps policy, ORF, and advertisement ordering in one pass"
    )]
    fn send_route_update_slice(
        &mut self,
        update: &OutboundRouteUpdate,
        dropped_ipv6_next_hops: &mut DroppedIpv6NextHops,
        deferred: &mut VecDeque<PendingGroup>,
    ) -> bool {
        let Some(snapshot) = self.outbound_snapshot(update) else {
            return false;
        };
        let export = snapshot
            .as_any()
            .downcast_ref::<SessionExportProfile>()
            .expect("validated session export snapshot");
        for route in &update.otc_blocked {
            self.record_otc_egress_block(route);
        }
        let peer_err = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_enhanced_route_refresh);
        // ROUTE-REFRESH *requests* toward the peer (RFC 2918), asked for by
        // the RIB manager (outbound-registration failover: the survivor's
        // Adj-RIB-In must be re-learned from the peer). The manager only
        // sets a flag — family selection happens HERE, over the session's
        // authoritative negotiated set, because the manager sees only the
        // sendable (outbound) subset while the refresh repopulates inbound
        // state. Gated on the negotiated capability, mirroring
        // `PeerCommand::SendRouteRefresh`; a peer without the capability
        // cannot be asked, so the staleness window lasts until its next
        // natural re-advertisement — surfaced by the warning.
        if update.request_refresh_all_negotiated {
            let negotiated = match self.negotiated.clone() {
                Some(negotiated) if negotiated.peer_route_refresh => Some(negotiated),
                _ => None,
            };
            if let Some(negotiated) = negotiated {
                for &(afi, safi) in negotiated
                    .negotiated_families
                    .iter()
                    .filter(|&&family| super::commands::requests_route_refresh(family))
                {
                    if !self.send_or_defer(
                        deferred,
                        PendingGroup::new(
                            GroupWire::Refresh(afi, safi, RouteRefreshSubtype::Normal),
                            vec![0],
                        ),
                        |session| {
                            session.send_refresh_frame(
                                afi,
                                safi,
                                RouteRefreshSubtype::Normal,
                                export.max_message_len(),
                            )
                        },
                    ) {
                        return false;
                    }
                }
            } else {
                warn!(
                    peer = %self.peer_label,
                    "ROUTE-REFRESH request skipped — peer lacks the Route Refresh \
                     capability; inbound routes recover only on the peer's natural \
                     re-advertisement"
                );
            }
        }
        if peer_err {
            for (afi, safi, subtype) in update
                .refresh_markers
                .iter()
                .copied()
                .filter(|(_, _, subtype)| matches!(subtype, RouteRefreshSubtype::BoRR))
            {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(GroupWire::Refresh(afi, safi, subtype), vec![0]),
                    |session| {
                        session.send_refresh_frame(afi, safi, subtype, export.max_message_len())
                    },
                ) {
                    return false;
                }
            }
        }
        let use_extended_nexthop_ipv4 = export.use_extended_nexthop_ipv4();
        let local_ipv4 = export.local_ipv4();
        // Split withdrawals by address family, filtering by negotiated families
        let mut v4_body_withdraw: Vec<Ipv4NlriEntry> = Vec::new();
        let mut v4_body_sources = Vec::new();
        let mut v4_mp_sources = Vec::new();
        let mut v6_sources = Vec::new();
        let mut v4_mp_withdraw: Vec<NlriEntry> = Vec::new();
        let mut v4_mp_wire = None;
        let mut v6_withdraw: Vec<NlriEntry> = Vec::new();
        let mut v6_wire = None;
        let mut scoped_ipv4_without_extended_nexthop = 0usize;
        for (source, &(ref prefix, path_id)) in update.unicast_withdrawals().enumerate() {
            if !self.is_family_negotiated(prefix) {
                continue;
            }
            match export.prepare_withdrawal(ExportWithdrawal::Unicast {
                prefix: *prefix,
                path_id,
            }) {
                Ok(PreparedWithdrawal::Ipv4Body(entry)) => {
                    v4_body_withdraw.push(entry);
                    v4_body_sources.push(source);
                }
                Ok(PreparedWithdrawal::Unicast(prepared)) => {
                    let wire = (prepared.afi, prepared.safi, prepared.ipv4_mode);
                    if prepared.afi == Afi::Ipv4 {
                        v4_mp_wire = Some(wire);
                        v4_mp_withdraw.push(prepared.nlri);
                        v4_mp_sources.push(source);
                    } else {
                        v6_wire = Some(wire);
                        v6_withdraw.push(prepared.nlri);
                        v6_sources.push(source);
                    }
                }
                Ok(_) => unreachable!("unicast withdrawal must prepare as unicast"),
                Err(ExportProbeError::Ipv4RequiresExtendedNextHop) => {
                    scoped_ipv4_without_extended_nexthop =
                        scoped_ipv4_without_extended_nexthop.saturating_add(1);
                }
                Err(error) => warn!(
                    peer = %self.peer_label,
                    %prefix,
                    %error,
                    "not sending unicast withdrawal: exact export preparation failed"
                ),
            }
        }
        if scoped_ipv4_without_extended_nexthop != 0 {
            warn!(
                peer = %self.peer_label,
                dropped = scoped_ipv4_without_extended_nexthop,
                "not sending IPv4 withdrawals to scoped link-local peer without negotiated Extended Next Hop"
            );
        }
        if !v4_body_withdraw.is_empty() {
            let max_len = export.max_message_len();
            if !self.send_or_defer(
                deferred,
                PendingGroup::new(GroupWire::Ipv4Body, v4_body_sources),
                |session| {
                    session.send_v4_chunked(
                        &v4_body_withdraw,
                        max_len,
                        "withdraw",
                        Some(&ipv4_entry_len(
                            export.add_path_send((Afi::Ipv4, Safi::Unicast)),
                        )),
                        |chunk| {
                            export.build_ipv4_body(&[], chunk, &[]).expect(
                                "IPv4 body withdrawal construction was previously infallible",
                            )
                        },
                    )
                },
            ) {
                return false;
            }
        }
        if let Some((afi, safi, ipv4_mode)) = v4_mp_wire {
            let max_len = export.max_message_len();
            if !self.send_or_defer(
                deferred,
                PendingGroup::new(
                    GroupWire::Mp {
                        afi,
                        safi,
                        mode: ipv4_mode,
                        next_hop: None,
                    },
                    v4_mp_sources,
                ),
                |session| {
                    session.send_mp_chunked(
                        &v4_mp_withdraw,
                        max_len,
                        "IPv4 unicast",
                        "withdrawal",
                        Some(&entry_len(export.add_path_send((afi, safi)))),
                        |chunk| {
                            export.build_mp_unreach(
                                afi,
                                safi,
                                UnreachNlri::Unicast(chunk),
                                ipv4_mode,
                            )
                        },
                    )
                },
            ) {
                return false;
            }
        }
        // Send IPv6 withdrawals via `MP_UNREACH_NLRI`, chunked to the
        // negotiated message ceiling just like IPv4. A large Add-Path
        // withdrawal set must not be handed to `enqueue_bulk` as one
        // oversized message after the RIB has already committed it.
        if let Some((afi, safi, ipv4_mode)) = v6_wire {
            let max_len = export.max_message_len();
            if !self.send_or_defer(
                deferred,
                PendingGroup::new(
                    GroupWire::Mp {
                        afi,
                        safi,
                        mode: ipv4_mode,
                        next_hop: None,
                    },
                    v6_sources,
                ),
                |session| {
                    session.send_mp_chunked(
                        &v6_withdraw,
                        max_len,
                        "IPv6 unicast",
                        "withdrawal",
                        Some(&entry_len(export.add_path_send((afi, safi)))),
                        |chunk| {
                            export.build_mp_unreach(
                                afi,
                                safi,
                                UnreachNlri::Unicast(chunk),
                                ipv4_mode,
                            )
                        },
                    )
                },
            ) {
                return false;
            }
        }
        // Split announcements by address family, filtering by negotiated families
        let mut v4_routes: Vec<(&Route, Option<&rustbgpd_policy::NextHopAction>, usize)> =
            Vec::new();
        let mut v6_routes: Vec<(&Route, Option<&rustbgpd_policy::NextHopAction>, usize)> =
            Vec::new();
        for (i, route) in update.announce.iter().enumerate() {
            // Group-transition envelopes may share one immutable full-cohort
            // payload. Split horizon is still member-specific: never encode a
            // route learned from this target back to it. Ordinary RIB paths
            // already exclude these routes, making this branch a cheap
            // defense-in-depth no-op outside the shared transition seam.
            if update.announce_source_exclusion == Some(route.peer) {
                continue;
            }
            if !self.is_family_negotiated(&route.prefix) {
                continue;
            }
            if self.otc_egress_blocks_unicast(route) {
                // Defense-in-depth for legacy/manual RIB producers. Normal
                // RIB staging already removed this route before commit and
                // carried it in `otc_blocked` above.
                self.record_otc_egress_block(route);
                continue;
            }
            let nh_override = update.next_hop_override.get(i).and_then(|o| o.as_ref());
            match route.prefix {
                Prefix::V4(_) => v4_routes.push((route, nh_override, i)),
                Prefix::V6(_) => v6_routes.push((route, nh_override, i)),
            }
        }
        // Send IPv4 announcements via body NLRI or IPv4 MP_REACH_NLRI;
        // `finish_unicast_candidate` picks the form per route (MP_REACH only
        // for an Extended Next Hop IPv6 next hop or a scoped link-local peer).
        if !use_extended_nexthop_ipv4 && export.is_scoped_link_local_peer() {
            if !v4_routes.is_empty() {
                warn!(
                    peer = %self.peer_label,
                    "not sending IPv4 routes to scoped link-local peer without negotiated Extended Next Hop"
                );
            }
        } else {
            let mut v4_body_index = AttrGroupIndex::default();
            let mut v4_body_groups: Vec<V4BodyGroup> = Vec::new();
            let mut v4_mp_index = AttrGroupIndex::default();
            let mut v4_mp_groups: Vec<MpGroup> = Vec::new();
            let mut prepared_attr_cache = PreparedAttrCache::default();
            for (route, nh_override, source) in &v4_routes {
                let cached_attrs = export.prepared_unicast_attributes_cached(
                    &mut prepared_attr_cache,
                    route,
                    local_ipv4,
                    *nh_override,
                );
                match export.finish_unicast_candidate(route, *nh_override, cached_attrs) {
                    Ok(PreparedUnicastCandidate::Ipv4Body { attrs, entry }) => {
                        dropped_ipv6_next_hops.note_ipv4_body(*nh_override, entry.prefix);
                        match v4_body_index.group(&attrs, None, None, v4_body_groups.len()) {
                            Ok(idx) => {
                                v4_body_groups[idx].prefixes.push(entry);
                                v4_body_groups[idx].sources.push(*source);
                            }
                            Err(_) => v4_body_groups.push(V4BodyGroup {
                                attrs,
                                prefixes: vec![entry],
                                sources: vec![*source],
                            }),
                        }
                    }
                    Ok(PreparedUnicastCandidate::Mp {
                        next_hop,
                        link_local_next_hop,
                        attrs,
                        entry,
                        ..
                    }) => {
                        match v4_mp_index.group(
                            &attrs,
                            Some(next_hop),
                            link_local_next_hop,
                            v4_mp_groups.len(),
                        ) {
                            Ok(idx) => {
                                v4_mp_groups[idx].prefixes.push(entry);
                                v4_mp_groups[idx].sources.push(*source);
                            }
                            Err(_) => v4_mp_groups.push(MpGroup {
                                attrs,
                                next_hop,
                                link_local_next_hop,
                                prefixes: vec![entry],
                                sources: vec![*source],
                            }),
                        }
                    }
                    Err(error) if use_extended_nexthop_ipv4 => {
                        // Unreachable while every producer runs the
                        // exact-export preflight on this same snapshot;
                        // if it ever fires, a silent drop would leave
                        // Adj-RIB-Out ahead of the wire, so fail closed
                        // like the oversize branches.
                        warn!(
                            peer = %self.peer_label,
                            prefix = %route.prefix,
                            %error,
                            "IPv4 Extended Next Hop route failed exact export preparation after RIB commit — sending Cease/Out-of-Resources and tearing down"
                        );
                        self.trigger_outbound_out_of_resources_teardown(
                            crate::handle::SessionFailureCause::PostCommitInvariant,
                        );
                        return false;
                    }
                    Err(_) => {}
                }
            }
            // Grouping is done, so its lookup state goes now. Each group
            // then owns its prepared attributes alone and frees them once it
            // is sent or deferred, not after the whole slice is encoded.
            drop((prepared_attr_cache, v4_body_index, v4_mp_index));
            let max_len = export.max_message_len();
            let add_path = export.add_path_send((Afi::Ipv4, Safi::Unicast));
            let (body_fit, mp_fit) = (ipv4_entry_len(add_path), entry_len(add_path));
            for group in v4_body_groups {
                let attrs = group.attrs.as_ref();
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(GroupWire::Ipv4Body, group.sources),
                    |session| {
                        session.send_v4_chunked(
                            &group.prefixes,
                            max_len,
                            "announce",
                            Some(&body_fit),
                            |chunk| {
                                export.build_ipv4_body(chunk, &[], attrs).expect(
                                    "IPv4 body announcement construction was previously infallible",
                                )
                            },
                        )
                    },
                ) {
                    return false;
                }
            }
            for group in v4_mp_groups {
                let base_attrs = group.attrs.as_ref();
                let next_hop = group.next_hop;
                let link_local_next_hop = group.link_local_next_hop;
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi: Afi::Ipv4,
                            safi: Safi::Unicast,
                            mode: Ipv4UnicastMode::MpReach,
                            next_hop: Some((next_hop, link_local_next_hop)),
                        },
                        group.sources,
                    ),
                    |session| {
                        session.send_v4_chunked(
                            &group.prefixes,
                            max_len,
                            "announce",
                            Some(&mp_fit),
                            |chunk| {
                                export
                                    .build_mp_reach(
                                        Afi::Ipv4,
                                        Safi::Unicast,
                                        next_hop,
                                        link_local_next_hop,
                                        base_attrs,
                                        ReachNlri::Unicast(chunk),
                                        Ipv4UnicastMode::MpReach,
                                    )
                                    .expect("IPv4 MP_REACH construction was previously infallible")
                            },
                        )
                    },
                ) {
                    return false;
                }
            }
        }
        // Resolve IPv6 eBGP next-hop: config override > socket address > suppress.
        // The RIB already filters unsendable families via sendable_families, so
        // v6_routes should be empty here for eBGP peers without a valid IPv6 NH.
        // The is_family_negotiated filter above is retained as a safety net.
        // Group by (attributes, next-hop) so routes with different next-hops
        // get separate UPDATEs with correct MP_REACH_NLRI next-hop values.
        let mut v6_group_index = AttrGroupIndex::default();
        let mut v6_groups: Vec<MpGroup> = Vec::new();
        let mut prepared_attr_cache = PreparedAttrCache::default();
        for (route, nh_override_ref, source) in &v6_routes {
            let nh_override = *nh_override_ref;
            let cached_attrs = export.prepared_unicast_attributes_cached(
                &mut prepared_attr_cache,
                route,
                local_ipv4,
                nh_override,
            );
            let prepared = match export.finish_unicast_candidate(route, nh_override, cached_attrs) {
                Ok(PreparedUnicastCandidate::Mp {
                    next_hop,
                    link_local_next_hop,
                    attrs,
                    entry,
                    ..
                }) => (attrs, next_hop, link_local_next_hop, entry),
                Ok(PreparedUnicastCandidate::Ipv4Body { .. }) => {
                    unreachable!("IPv6 must prepare as MP_REACH")
                }
                Err(error) => {
                    debug_assert!(
                        !matches!(&error, ExportProbeError::MissingIpv6NextHop),
                        "RIB sent IPv6 route to eBGP peer with no valid IPv6 next-hop"
                    );
                    // Unreachable while every producer runs the exact-export
                    // preflight on this same snapshot; if it ever fires, a
                    // silent drop would leave Adj-RIB-Out ahead of the wire,
                    // so fail closed like the oversize branches.
                    warn!(
                        peer = %self.peer_label,
                        prefix = %route.prefix,
                        %error,
                        "IPv6 route failed exact export preparation after RIB commit — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return false;
                }
            };
            let (attrs, nh, link_local_next_hop, nlri_entry) = prepared;
            match v6_group_index.group(&attrs, Some(nh), link_local_next_hop, v6_groups.len()) {
                Ok(idx) => {
                    v6_groups[idx].prefixes.push(nlri_entry);
                    v6_groups[idx].sources.push(*source);
                }
                Err(_) => v6_groups.push(MpGroup {
                    attrs,
                    next_hop: nh,
                    link_local_next_hop,
                    prefixes: vec![nlri_entry],
                    sources: vec![*source],
                }),
            }
        }
        // As for IPv4 above: release the lookup state before sending.
        drop((prepared_attr_cache, v6_group_index));
        let max_len = export.max_message_len();
        let v6_fit = entry_len(export.add_path_send((Afi::Ipv6, Safi::Unicast)));
        for group in v6_groups {
            let base_attrs = group.attrs.as_ref();
            let next_hop = group.next_hop;
            let link_local_next_hop = group.link_local_next_hop;
            if !self.send_or_defer(
                deferred,
                PendingGroup::new(
                    GroupWire::Mp {
                        afi: Afi::Ipv6,
                        safi: Safi::Unicast,
                        mode: Ipv4UnicastMode::Body,
                        next_hop: Some((next_hop, link_local_next_hop)),
                    },
                    group.sources,
                ),
                |session| {
                    session.send_mp_chunked(
                        &group.prefixes,
                        max_len,
                        "IPv6 unicast",
                        "announcement",
                        Some(&v6_fit),
                        |chunk| {
                            export.build_mp_reach(
                                Afi::Ipv6,
                                Safi::Unicast,
                                next_hop,
                                link_local_next_hop,
                                base_attrs,
                                ReachNlri::Unicast(chunk),
                                Ipv4UnicastMode::Body,
                            )
                        },
                    )
                },
            ) {
                return false;
            }
        }
        // Send FlowSpec withdrawals via MP_UNREACH_NLRI, grouped by family:
        // global rules by AFI, VPN rules apart, each in its own typed list.
        if !update.flowspec_withdraw.is_empty() {
            use super::export::FlowSpecNlri;
            type GlobalGroup = Option<(Afi, Ipv4UnicastMode, Vec<FlowSpecRule>, Vec<usize>)>;
            type VpnGroup = Option<(Afi, Ipv4UnicastMode, Vec<VpnFlowSpecRule>, Vec<usize>)>;
            // Preserve the established deterministic wire order: IPv4, then
            // IPv6, then IPv4/IPv6 VPN (SAFI 134).
            let mut global: [GlobalGroup; 2] = [None, None];
            let mut vpn: [VpnGroup; 2] = [None, None];
            for (source, key) in update.flowspec_withdraw.iter().enumerate() {
                let PreparedWithdrawal::FlowSpec(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::FlowSpec(key))
                    .expect("FlowSpec withdrawal preparation is infallible")
                else {
                    unreachable!("FlowSpec key must prepare as FlowSpec")
                };
                match prepared.nlri {
                    FlowSpecNlri::Global(rule) => {
                        let slot = match prepared.afi {
                            Afi::Ipv4 => &mut global[0],
                            Afi::Ipv6 => &mut global[1],
                            // FlowSpec is defined for IPv4/IPv6 only (RFC 8955/8956).
                            _ => {
                                warn!(afi = ?prepared.afi, "ignoring FlowSpec withdrawal with non-IP AFI");
                                continue;
                            }
                        };
                        let group = slot.get_or_insert_with(|| {
                            (prepared.afi, prepared.ipv4_mode, Vec::new(), Vec::new())
                        });
                        group.2.push(rule);
                        group.3.push(source);
                    }
                    FlowSpecNlri::Vpn(rule) => {
                        let slot = match prepared.afi {
                            Afi::Ipv4 => &mut vpn[0],
                            Afi::Ipv6 => &mut vpn[1],
                            _ => {
                                warn!(afi = ?prepared.afi, "ignoring VPN FlowSpec withdrawal with non-IP AFI");
                                continue;
                            }
                        };
                        let group = slot.get_or_insert_with(|| {
                            (prepared.afi, prepared.ipv4_mode, Vec::new(), Vec::new())
                        });
                        group.2.push(rule);
                        group.3.push(source);
                    }
                }
            }
            let max_len = export.max_message_len();
            for (afi, ipv4_mode, rules, sources) in global.into_iter().flatten() {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi,
                            safi: Safi::FlowSpec,
                            mode: ipv4_mode,
                            next_hop: None,
                        },
                        sources,
                    ),
                    |session| {
                        session.send_mp_chunked(
                            &rules,
                            max_len,
                            "FlowSpec",
                            "withdrawal",
                            None,
                            |chunk| {
                                export.build_mp_unreach(
                                    afi,
                                    Safi::FlowSpec,
                                    UnreachNlri::FlowSpec(chunk),
                                    ipv4_mode,
                                )
                            },
                        )
                    },
                ) {
                    return false;
                }
            }
            for (afi, ipv4_mode, rules, sources) in vpn.into_iter().flatten() {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi,
                            safi: Safi::FlowSpecVpn,
                            mode: ipv4_mode,
                            next_hop: None,
                        },
                        sources,
                    ),
                    |session| {
                        session.send_mp_chunked(
                            &rules,
                            max_len,
                            "VPN FlowSpec",
                            "withdrawal",
                            None,
                            |chunk| {
                                export.build_mp_unreach(
                                    afi,
                                    Safi::FlowSpecVpn,
                                    UnreachNlri::VpnFlowSpec(chunk),
                                    ipv4_mode,
                                )
                            },
                        )
                    },
                ) {
                    return false;
                }
            }
        }
        // Send EVPN withdrawals via MP_UNREACH_NLRI, chunked so each UPDATE
        // fits the negotiated maximum message length (4096 / 65535 with
        // RFC 8654 Extended Messages). A bulk withdrawal of an entire fabric
        // can otherwise exceed the limit and `enqueue_bulk` returns
        // `MessageTooLong`, dropping the rest of the update.
        if !update.evpn_withdraw.is_empty() {
            let mut routes = Vec::with_capacity(update.evpn_withdraw.len());
            let mut wire = None;
            let mut sources = Vec::new();
            for (source, key) in update.evpn_withdraw.iter().enumerate() {
                let PreparedWithdrawal::Evpn(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::Evpn(key))
                    .expect("EVPN withdrawal preparation is infallible")
                else {
                    unreachable!("EVPN key must prepare as EVPN")
                };
                wire = Some((prepared.afi, prepared.safi, prepared.ipv4_mode));
                routes.push(prepared.nlri);
                sources.push(source);
            }
            let max_len = export.max_message_len();
            let (afi, safi, ipv4_mode) = wire.expect("non-empty EVPN withdrawal batch");
            if !self.send_or_defer(
                deferred,
                PendingGroup::new(
                    GroupWire::Mp {
                        afi,
                        safi,
                        mode: ipv4_mode,
                        next_hop: None,
                    },
                    sources,
                ),
                |session| {
                    session
                        .send_evpn_unreach_chunked(export, afi, safi, ipv4_mode, &routes, max_len)
                },
            ) {
                return false;
            }
        }
        // Send BGP-LS withdrawals via MP_UNREACH_NLRI, grouped by SAFI and
        // chunked so the RIB never commits a route that transport could not
        // enqueue.
        if !update.bgpls_withdraw.is_empty() {
            let mut groups = Vec::<(
                Afi,
                Safi,
                Ipv4UnicastMode,
                Vec<rustbgpd_wire::bgpls::BgpLsNlri>,
                Vec<usize>,
            )>::new();
            for (source, key) in update.bgpls_withdraw.iter().enumerate() {
                let PreparedWithdrawal::BgpLs(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::BgpLs(key))
                    .expect("BGP-LS withdrawal preparation is infallible")
                else {
                    unreachable!("BGP-LS key must prepare as BGP-LS")
                };
                if !self
                    .negotiated_families()
                    .contains(&(prepared.afi, prepared.safi))
                {
                    continue;
                }
                if let Some((_, _, _, routes, sources)) =
                    groups.iter_mut().find(|(afi, safi, mode, _, _)| {
                        (*afi, *safi, *mode) == (prepared.afi, prepared.safi, prepared.ipv4_mode)
                    })
                {
                    routes.push(prepared.nlri);
                    sources.push(source);
                } else {
                    groups.push((
                        prepared.afi,
                        prepared.safi,
                        prepared.ipv4_mode,
                        vec![prepared.nlri],
                        vec![source],
                    ));
                }
            }
            let max_len = export.max_message_len();
            groups.sort_by_key(|(_, safi, _, _, _)| match safi {
                Safi::BgpLs => 0,
                Safi::BgpLsVpn => 1,
                _ => 2,
            });
            for (afi, safi, ipv4_mode, routes, sources) in groups {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi,
                            safi,
                            mode: ipv4_mode,
                            next_hop: None,
                        },
                        sources,
                    ),
                    |session| {
                        session.send_bgpls_unreach_chunked(
                            afi, safi, ipv4_mode, &routes, export, max_len,
                        )
                    },
                ) {
                    return false;
                }
            }
        }
        // Send VPNv4/VPNv6 withdrawals via MP_UNREACH_NLRI, grouped by AFI
        // and chunked. RFC 8277 §2.4 withdraw-mode NLRI carries a 3-octet
        // compatibility field instead of a label stack, so the rebuilt NLRI
        // carries no labels (the withdraw encoder ignores them).
        if !update.vpn_withdraw.is_empty() {
            let mut groups = Vec::<(
                Afi,
                Safi,
                Ipv4UnicastMode,
                Vec<rustbgpd_wire::VpnNlriEntry>,
                Vec<usize>,
            )>::new();
            for (source, key) in update.vpn_withdraw.iter().enumerate() {
                let PreparedWithdrawal::Vpn(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::Vpn(key))
                    .expect("VPN withdrawal preparation is infallible")
                else {
                    unreachable!("VPN key must prepare as VPN")
                };
                let family = (prepared.afi, prepared.safi);
                if !self.negotiated_families().contains(&family) {
                    continue;
                }
                if let Some((_, _, _, routes, sources)) =
                    groups.iter_mut().find(|(afi, safi, mode, _, _)| {
                        (*afi, *safi, *mode) == (prepared.afi, prepared.safi, prepared.ipv4_mode)
                    })
                {
                    routes.push(prepared.nlri);
                    sources.push(source);
                } else {
                    groups.push((
                        prepared.afi,
                        prepared.safi,
                        prepared.ipv4_mode,
                        vec![prepared.nlri],
                        vec![source],
                    ));
                }
            }
            let max_len = export.max_message_len();
            groups.sort_by_key(|(afi, _, _, _, _)| match afi {
                Afi::Ipv4 => 0,
                Afi::Ipv6 => 1,
                // Non-IP families (and future AFIs) keep a stable tail slot.
                _ => 2,
            });
            for (afi, safi, ipv4_mode, routes, sources) in groups {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi,
                            safi,
                            mode: ipv4_mode,
                            next_hop: None,
                        },
                        sources,
                    ),
                    |session| {
                        session.send_vpn_unreach_chunked(
                            afi, safi, ipv4_mode, &routes, export, max_len,
                        )
                    },
                ) {
                    return false;
                }
            }
        }
        // Send labeled-unicast withdrawals via MP_UNREACH_NLRI, grouped by
        // AFI and chunked. RFC 8277 §2.4 withdraw-mode NLRI carries a
        // 3-octet compatibility field instead of a label stack, so the
        // rebuilt NLRI carries no labels (the withdraw encoder ignores
        // them).
        if !update.labeled_withdraw.is_empty() {
            let mut groups = Vec::<(
                Afi,
                Safi,
                Ipv4UnicastMode,
                Vec<rustbgpd_wire::LabeledNlriEntry>,
                Vec<usize>,
            )>::new();
            for (source, key) in update.labeled_withdraw.iter().enumerate() {
                let PreparedWithdrawal::Labeled(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::Labeled(key))
                    .expect("labeled withdrawal preparation is infallible")
                else {
                    unreachable!("labeled key must prepare as labeled unicast")
                };
                let family = (prepared.afi, prepared.safi);
                if !self.negotiated_families().contains(&family) {
                    continue;
                }
                if let Some((_, _, _, routes, sources)) =
                    groups.iter_mut().find(|(afi, safi, mode, _, _)| {
                        (*afi, *safi, *mode) == (prepared.afi, prepared.safi, prepared.ipv4_mode)
                    })
                {
                    routes.push(prepared.nlri);
                    sources.push(source);
                } else {
                    groups.push((
                        prepared.afi,
                        prepared.safi,
                        prepared.ipv4_mode,
                        vec![prepared.nlri],
                        vec![source],
                    ));
                }
            }
            let max_len = export.max_message_len();
            groups.sort_by_key(|(afi, _, _, _, _)| match afi {
                Afi::Ipv4 => 0,
                Afi::Ipv6 => 1,
                // Non-IP families (and future AFIs) keep a stable tail slot.
                _ => 2,
            });
            for (afi, safi, ipv4_mode, routes, sources) in groups {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi,
                            safi,
                            mode: ipv4_mode,
                            next_hop: None,
                        },
                        sources,
                    ),
                    |session| {
                        session.send_labeled_unreach_chunked(
                            afi, safi, ipv4_mode, &routes, export, max_len,
                        )
                    },
                ) {
                    return false;
                }
            }
        }
        // Send RT-Constrain withdrawals via MP_UNREACH_NLRI. One codec for
        // both directions (RFC 4684 has no withdraw-mode split); single
        // family tuple (AFI 1 only).
        if !update.rtc_withdraw.is_empty()
            && self
                .negotiated_families()
                .contains(&(Afi::Ipv4, Safi::RtConstrain))
        {
            let mut routes = Vec::with_capacity(update.rtc_withdraw.len());
            let mut wire = None;
            let mut sources = Vec::new();
            for (source, key) in update.rtc_withdraw.iter().enumerate() {
                let PreparedWithdrawal::Rtc(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::Rtc(key))
                    .expect("RTC withdrawal preparation is infallible")
                else {
                    unreachable!("RTC key must prepare as RTC")
                };
                wire = Some((prepared.afi, prepared.safi, prepared.ipv4_mode));
                routes.push(prepared.nlri);
                sources.push(source);
            }
            let max_len = export.max_message_len();
            let (afi, safi, ipv4_mode) = wire.expect("non-empty RTC withdrawal batch");
            if !self.send_or_defer(
                deferred,
                PendingGroup::new(
                    GroupWire::Mp {
                        afi,
                        safi,
                        mode: ipv4_mode,
                        next_hop: None,
                    },
                    sources,
                ),
                |session| {
                    session.send_rtc_unreach_chunked(export, afi, safi, ipv4_mode, &routes, max_len)
                },
            ) {
                return false;
            }
        }
        // Send EVPN announcements via MP_REACH_NLRI, grouped by (next-hop, attributes)
        // and chunked so each UPDATE fits the negotiated maximum message length.
        if !update.evpn_announce.is_empty() {
            type EvpnGroup = (IpAddr, Arc<Vec<PathAttribute>>, Vec<EvpnRoute>, Vec<usize>);
            let mut attr_cache = MpAttrCache::default();
            let mut index = AttrGroupIndex::default();
            let mut evpn_groups: Vec<EvpnGroup> = Vec::new();
            for (source, evpn_route) in update.evpn_announce.iter().enumerate() {
                let prepared =
                    SessionExportProfile::prepare_evpn_candidate_with(evpn_route, || {
                        export.prepare_mp_attributes_cached(
                            &mut attr_cache,
                            &evpn_route.attributes,
                            evpn_route.origin_type,
                            evpn_route.peer_router_id,
                            (Afi::L2Vpn, Safi::Evpn),
                        )
                    });
                let nh = prepared.next_hop;
                match index.group(&prepared.attrs, Some(nh), None, evpn_groups.len()) {
                    Ok(idx) => {
                        evpn_groups[idx].2.push(prepared.nlri);
                        evpn_groups[idx].3.push(source);
                    }
                    Err(_) => {
                        evpn_groups.push((nh, prepared.attrs, vec![prepared.nlri], vec![source]));
                    }
                }
            }
            let max_len = export.max_message_len();
            for (next_hop, attrs, routes, sources) in evpn_groups {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi: Afi::L2Vpn,
                            safi: Safi::Evpn,
                            mode: Ipv4UnicastMode::Body,
                            next_hop: Some((next_hop, None)),
                        },
                        sources,
                    ),
                    |session| {
                        session.send_evpn_reach_chunked(export, next_hop, &attrs, &routes, max_len)
                    },
                ) {
                    return false;
                }
            }
        }
        // Send BGP-LS announcements via MP_REACH_NLRI, grouped by
        // (family, next-hop, attributes) and chunked.
        if !update.bgpls_announce.is_empty() {
            #[allow(
                clippy::type_complexity,
                reason = "BGP-LS UPDATE grouping keeps family, next-hop, attributes, and route batch identity explicit"
            )]
            let mut bgpls_groups: Vec<(
                rustbgpd_rib::BgpLsFamily,
                IpAddr,
                Vec<PathAttribute>,
                Vec<rustbgpd_wire::bgpls::BgpLsNlri>,
                Vec<usize>,
            )> = Vec::new();
            for (source, bgpls_route) in update.bgpls_announce.iter().enumerate() {
                let safi = bgpls_route.family.to_afi_safi().1;
                if !self.negotiated_families().contains(&(Afi::BgpLs, safi)) {
                    continue;
                }
                let prepared = export.prepare_bgpls_candidate(bgpls_route);
                let attrs = prepared.attrs;
                let nh = prepared.next_hop;
                if let Some(group) =
                    bgpls_groups
                        .iter_mut()
                        .find(|(family, g_nh, g_attrs, _, _)| {
                            *family == bgpls_route.family && *g_nh == nh && *g_attrs == attrs
                        })
                {
                    group.3.push(prepared.nlri);
                    group.4.push(source);
                } else {
                    bgpls_groups.push((
                        bgpls_route.family,
                        nh,
                        attrs,
                        vec![prepared.nlri],
                        vec![source],
                    ));
                }
            }
            let max_len = export.max_message_len();
            for (family, next_hop, attrs, routes, sources) in bgpls_groups {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi: Afi::BgpLs,
                            safi: family.to_afi_safi().1,
                            mode: Ipv4UnicastMode::Body,
                            next_hop: Some((next_hop, None)),
                        },
                        sources,
                    ),
                    |session| {
                        session.send_bgpls_reach_chunked(
                            family.to_afi_safi().1,
                            next_hop,
                            &attrs,
                            &routes,
                            export,
                            max_len,
                        )
                    },
                ) {
                    return false;
                }
            }
        }
        // Send VPNv4/VPNv6 announcements via MP_REACH_NLRI, grouped by
        // (family, next-hop, attributes) and chunked. ADR-0077 §6: the
        // original NLRI (RD + MPLS label stack) and the stored VPN next-hop
        // pass through reflection verbatim.
        if !update.vpn_announce.is_empty() {
            let mut attr_cache = MpAttrCache::default();
            let mut index = MpGroupIndex::default();
            let mut source_groups: Vec<Vec<usize>> = Vec::new();
            let mut vpn_groups: Vec<MpRouteGroup<rustbgpd_wire::VpnNlriEntry>> = Vec::new();
            for (source, vpn_route) in update.vpn_announce.iter().enumerate() {
                let family = vpn_route.afi_safi();
                if !self.negotiated_families().contains(&family) {
                    continue;
                }
                let prepared = match export.prepare_vpn_candidate_with(vpn_route, || {
                    export.prepare_mp_attributes_cached(
                        &mut attr_cache,
                        &vpn_route.attributes,
                        vpn_route.origin_type,
                        vpn_route.peer_router_id,
                        family,
                    )
                }) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        warn!(
                            peer = %self.peer_label,
                            %error,
                            "not sending VPN announcement: exact export preparation failed"
                        );
                        continue;
                    }
                };
                let group = index.push(&mut vpn_groups, family, prepared);
                if group == source_groups.len() {
                    source_groups.push(Vec::new());
                }
                source_groups[group].push(source);
            }
            let max_len = export.max_message_len();
            for (((afi, _), next_hop, link_local_next_hop, attrs, routes), sources) in
                vpn_groups.into_iter().zip(source_groups)
            {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi,
                            safi: Safi::MplsVpn,
                            mode: Ipv4UnicastMode::Body,
                            next_hop: Some((next_hop, link_local_next_hop)),
                        },
                        sources,
                    ),
                    |session| {
                        session.send_vpn_reach_chunked(
                            afi,
                            next_hop,
                            link_local_next_hop,
                            &attrs,
                            &routes,
                            export,
                            max_len,
                        )
                    },
                ) {
                    return false;
                }
            }
        }
        // Send labeled-unicast announcements via MP_REACH_NLRI, grouped by
        // (family, next-hop, attributes) and chunked. ADR-0077 §4/§6: the
        // stored MPLS label stack and next-hop pass through reflection
        // verbatim — transport never rewrites either.
        if !update.labeled_announce.is_empty() {
            let mut attr_cache = MpAttrCache::default();
            let mut index = MpGroupIndex::default();
            let mut source_groups: Vec<Vec<usize>> = Vec::new();
            let mut labeled_groups: Vec<MpRouteGroup<rustbgpd_wire::LabeledNlriEntry>> = Vec::new();
            for (source, labeled_route) in update.labeled_announce.iter().enumerate() {
                let family = labeled_route.afi_safi();
                if !self.negotiated_families().contains(&family) {
                    continue;
                }
                let prepared = match export.prepare_labeled_candidate_with(labeled_route, || {
                    export.prepare_mp_attributes_cached(
                        &mut attr_cache,
                        &labeled_route.attributes,
                        labeled_route.origin_type,
                        labeled_route.peer_router_id,
                        family,
                    )
                }) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        warn!(
                            peer = %self.peer_label,
                            %error,
                            "not sending labeled announcement: exact export preparation failed"
                        );
                        continue;
                    }
                };
                let group = index.push(&mut labeled_groups, family, prepared);
                if group == source_groups.len() {
                    source_groups.push(Vec::new());
                }
                source_groups[group].push(source);
            }
            let max_len = export.max_message_len();
            for (((afi, _), next_hop, link_local_next_hop, attrs, routes), sources) in
                labeled_groups.into_iter().zip(source_groups)
            {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi,
                            safi: Safi::LabeledUnicast,
                            mode: Ipv4UnicastMode::Body,
                            next_hop: Some((next_hop, link_local_next_hop)),
                        },
                        sources,
                    ),
                    |session| {
                        session.send_labeled_reach_chunked(
                            afi,
                            next_hop,
                            link_local_next_hop,
                            &attrs,
                            &routes,
                            export,
                            max_len,
                        )
                    },
                ) {
                    return false;
                }
            }
        }
        // Send RT-Constrain announcements via MP_REACH_NLRI, grouped by
        // (next-hop, attributes) and chunked. The stored next-hop passes
        // through reflection unchanged; the one exception is the locally-
        // originated default NLRI, whose next-hop is stored unspecified and
        // emitted as the session-local address (mirroring next-hop-self).
        if !update.rtc_announce.is_empty()
            && self
                .negotiated_families()
                .contains(&(Afi::Ipv4, Safi::RtConstrain))
        {
            type RtcGroup = (
                IpAddr,
                Vec<PathAttribute>,
                Vec<rustbgpd_wire::RtcNlri>,
                Vec<usize>,
            );
            let mut rtc_groups: Vec<RtcGroup> = Vec::new();
            for (source, rtc_route) in update.rtc_announce.iter().enumerate() {
                let prepared = export.prepare_rtc_candidate(rtc_route);
                let attrs = prepared.attrs;
                let nh = prepared.next_hop;
                if let Some(group) = rtc_groups
                    .iter_mut()
                    .find(|(g_nh, g_attrs, _, _)| *g_nh == nh && *g_attrs == attrs)
                {
                    group.2.push(prepared.nlri);
                    group.3.push(source);
                } else {
                    rtc_groups.push((nh, attrs, vec![prepared.nlri], vec![source]));
                }
            }
            let max_len = export.max_message_len();
            for (next_hop, attrs, routes, sources) in rtc_groups {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi: Afi::Ipv4,
                            safi: Safi::RtConstrain,
                            mode: Ipv4UnicastMode::Body,
                            next_hop: Some((next_hop, None)),
                        },
                        sources,
                    ),
                    |session| {
                        session.send_rtc_reach_chunked(export, next_hop, &attrs, &routes, max_len)
                    },
                ) {
                    return false;
                }
            }
        }
        // Send FlowSpec announcements via MP_REACH_NLRI, grouped by (family,
        // attributes) in typed lists: one UPDATE never mixes SAFI 133 and 134.
        if !update.flowspec_announce.is_empty() {
            use super::export::FlowSpecNlri;
            type Group<T> = (Afi, Vec<PathAttribute>, Vec<T>, Vec<usize>);
            fn push<T>(
                groups: &mut Vec<Group<T>>,
                afi: Afi,
                attrs: Vec<PathAttribute>,
                nlri: T,
                source: usize,
            ) {
                if let Some(group) = groups
                    .iter_mut()
                    .find(|(a, ga, _, _)| *a == afi && *ga == attrs)
                {
                    group.2.push(nlri);
                    group.3.push(source);
                } else {
                    groups.push((afi, attrs, vec![nlri], vec![source]));
                }
            }
            let mut global: Vec<Group<FlowSpecRule>> = Vec::new();
            let mut vpn: Vec<Group<VpnFlowSpecRule>> = Vec::new();
            for (source, fs_route) in update.flowspec_announce.iter().enumerate() {
                let prepared = export.prepare_flowspec_candidate(fs_route);
                match prepared.nlri {
                    FlowSpecNlri::Global(rule) => {
                        push(&mut global, prepared.afi, prepared.attrs, rule, source);
                    }
                    FlowSpecNlri::Vpn(rule) => {
                        push(&mut vpn, prepared.afi, prepared.attrs, rule, source);
                    }
                }
            }
            let max_len = export.max_message_len();
            for (afi, attrs, rules, sources) in global {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi,
                            safi: Safi::FlowSpec,
                            mode: Ipv4UnicastMode::Body,
                            next_hop: Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), None)),
                        },
                        sources,
                    ),
                    |session| {
                        session.send_mp_chunked(
                            &rules,
                            max_len,
                            "FlowSpec",
                            "announcement",
                            None,
                            |chunk| {
                                export.build_mp_reach(
                                    afi,
                                    Safi::FlowSpec,
                                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                    None,
                                    &attrs,
                                    ReachNlri::FlowSpec(chunk),
                                    Ipv4UnicastMode::Body,
                                )
                            },
                        )
                    },
                ) {
                    return false;
                }
            }
            for (afi, attrs, rules, sources) in vpn {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(
                        GroupWire::Mp {
                            afi,
                            safi: Safi::FlowSpecVpn,
                            mode: Ipv4UnicastMode::Body,
                            next_hop: Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), None)),
                        },
                        sources,
                    ),
                    |session| {
                        session.send_mp_chunked(
                            &rules,
                            max_len,
                            "VPN FlowSpec",
                            "announcement",
                            None,
                            |chunk| {
                                export.build_mp_reach(
                                    afi,
                                    Safi::FlowSpecVpn,
                                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                    None,
                                    &attrs,
                                    ReachNlri::VpnFlowSpec(chunk),
                                    Ipv4UnicastMode::Body,
                                )
                            },
                        )
                    },
                ) {
                    return false;
                }
            }
        }
        if peer_err {
            for (afi, safi, subtype) in update
                .refresh_markers
                .iter()
                .copied()
                .filter(|(_, _, subtype)| matches!(subtype, RouteRefreshSubtype::EoRR))
            {
                if !self.send_or_defer(
                    deferred,
                    PendingGroup::new(GroupWire::Refresh(afi, safi, subtype), vec![0]),
                    |session| {
                        session.send_refresh_frame(afi, safi, subtype, export.max_message_len())
                    },
                ) {
                    return false;
                }
            }
        }
        // Send End-of-RIB markers
        for (afi, safi) in &update.end_of_rib {
            if peer_err
                && update
                    .refresh_markers
                    .iter()
                    .any(|(m_afi, m_safi, subtype)| {
                        *m_afi == *afi
                            && *m_safi == *safi
                            && matches!(
                                subtype,
                                RouteRefreshSubtype::BoRR | RouteRefreshSubtype::EoRR
                            )
                    })
            {
                continue;
            }
            if !self.send_or_defer(
                deferred,
                PendingGroup::new(GroupWire::Eor(*afi, *safi), vec![0]),
                |session| session.send_eor_frame(export, *afi, *safi),
            ) {
                return false;
            }
        }
        true
    }
    fn send_refresh_frame(
        &mut self,
        afi: Afi,
        safi: Safi,
        subtype: RouteRefreshSubtype,
        max_len: usize,
    ) -> Result<usize, ()> {
        if !self.writer_frame_room(max_len)? {
            return Ok(0);
        }
        let message =
            Message::RouteRefresh(RouteRefreshMessage::new_with_subtype(afi, safi, subtype));
        if let Err(error) = self.enqueue_bulk(&message) {
            warn!(peer = %self.peer_label, %error, "failed to send ROUTE-REFRESH frame");
            return Err(());
        }
        if subtype == RouteRefreshSubtype::Normal {
            info!(peer = %self.peer_label, ?afi, ?safi, "sent ROUTE-REFRESH request (RIB-manager initiated)");
        }
        self.metrics
            .record_message_sent(&self.peer_label, "route_refresh");
        Ok(1)
    }

    fn send_eor_frame(
        &mut self,
        export: &SessionExportProfile,
        afi: Afi,
        safi: Safi,
    ) -> Result<usize, ()> {
        if !self.writer_frame_room(export.max_message_len())? {
            return Ok(0);
        }
        let message = export
            .build_end_of_rib(afi, safi)
            .expect("empty End-of-RIB construction is infallible");
        if let Err(error) = self.enqueue_bulk(&Message::Update(message)) {
            warn!(peer = %self.peer_label, %error, "failed to send End-of-RIB for {afi:?}/{safi:?}");
            return Err(());
        }
        info!(peer = %self.peer_label, ?afi, ?safi, "sent End-of-RIB");
        self.config.neighbor_counters.record_update_sent();
        self.metrics.record_message_sent(&self.peer_label, "update");
        Ok(1)
    }

    /// A blocked group and every following group keep only source indices.
    fn send_or_defer(
        &mut self,
        deferred: &mut VecDeque<PendingGroup>,
        mut group: PendingGroup,
        send: impl FnOnce(&mut Self) -> Result<usize, ()>,
    ) -> bool {
        if deferred.is_empty() {
            match send(self) {
                Ok(count) if count == group.rows.len() => return true,
                Ok(count) => group.next = count,
                Err(()) => return false,
            }
        }
        deferred.push_back(group);
        true
    }

    /// Drain a parked slice before advancing its source cursor. The temporary
    /// attributes and chunk copies are dropped before another actor turn.
    fn resume_pending_slice(&mut self, pending: &mut PendingOutbound) -> Result<(), ()> {
        let snapshot = self.outbound_snapshot(&pending.update).ok_or(())?;
        let export = snapshot
            .as_any()
            .downcast_ref::<SessionExportProfile>()
            .expect("validated session export snapshot");
        let max_len = export.max_message_len();
        let slice = pending.pending_slice.as_mut().expect("active slice");
        while let Some(group) = slice.groups.front() {
            if !self.writer_frame_room(max_len)? {
                break;
            }
            let sent = match group.wire {
                GroupWire::Refresh(afi, safi, subtype) => {
                    self.send_refresh_frame(afi, safi, subtype, max_len)?
                }
                GroupWire::Eor(afi, safi) => self.send_eor_frame(export, afi, safi)?,
                wire => {
                    let (afi, safi) = match wire {
                        GroupWire::Mp { afi, safi, .. } => (afi, safi),
                        _ => (Afi::Ipv4, Safi::Unicast),
                    };
                    let (family, withdrawal) = resumed_log_names(slice.phase, afi, safi);
                    let attrs = slice.attributes(group, &pending.update, export);
                    let rows = &group.rows[group.next..];
                    let build = |chunk: &[usize]| {
                        slice.build_chunk(group, chunk, &pending.update, export, &attrs)
                    };
                    let add_path = export.add_path_send((afi, safi));
                    let unicast_len = |rows: &[usize], room: usize| {
                        within(rows, room, |&row| {
                            let prefix = if matches!(slice.phase, OutboundPhase::Announce) {
                                pending.update.announce[slice.source_start + row].prefix
                            } else {
                                slice.withdrawal(&pending.update, row).0
                            };
                            prefix_len(prefix, add_path)
                        })
                    };
                    if matches!(wire, GroupWire::Ipv4Body)
                        || matches!(
                            (slice.phase, wire),
                            (
                                OutboundPhase::Announce,
                                GroupWire::Mp {
                                    afi: Afi::Ipv4,
                                    safi: Safi::Unicast,
                                    ..
                                }
                            )
                        )
                    {
                        let kind = if withdrawal { "withdraw" } else { "announce" };
                        self.send_v4_chunked(rows, max_len, kind, Some(&unicast_len), |chunk| {
                            build(chunk).expect("validated unicast chunk")
                        })?
                    } else if matches!(
                        slice.phase,
                        OutboundPhase::Announce
                            | OutboundPhase::Withdraw
                            | OutboundPhase::FlowspecAnnounce
                            | OutboundPhase::FlowspecWithdraw
                    ) {
                        let kind = if withdrawal {
                            "withdrawal"
                        } else {
                            "announcement"
                        };
                        let size: Option<Fit<'_, usize>> = matches!(
                            slice.phase,
                            OutboundPhase::Announce | OutboundPhase::Withdraw
                        )
                        .then_some(&unicast_len as Fit<'_, usize>);
                        self.send_mp_chunked(rows, max_len, family, kind, size, build)?
                    } else {
                        self.send_resumed_family_chunked(
                            rows,
                            max_len,
                            (family, withdrawal),
                            build,
                        )?
                    }
                }
            };
            let group = slice.groups.front_mut().expect("current group remains");
            group.next += sent;
            if group.next < group.rows.len() {
                break;
            }
            slice.groups.pop_front();
        }
        if slice.groups.is_empty() {
            pending.pending_slice = None;
        }
        Ok(())
    }

    /// The typed MP family senders' byte-sized chunking, applied to source
    /// indices on cold resume.
    fn send_resumed_family_chunked(
        &mut self,
        rows: &[usize],
        max_len: usize,
        (family, withdrawal): (&'static str, bool),
        mut build: impl FnMut(&[usize]) -> Result<UpdateMessage, rustbgpd_wire::EncodeError>,
    ) -> Result<usize, ()> {
        let mut sizer = ChunkSizer::new(max_len);
        let mut next = 0;
        while next < rows.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(next);
            }
            let end = next + sizer.next(&rows[next..], None);
            let message = build(&rows[next..end]).expect("previously validated family chunk");
            if sizer.measured_only(Some(&message)) {
                continue;
            }
            if message.encoded_len() > max_len {
                if end - next == 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = message.encoded_len(),
                        max = max_len,
                        "single {family} {} exceeds maximum message length — sending Cease/Out-of-Resources and tearing down",
                        if withdrawal { "withdrawal" } else { "route" }
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - next, Some(&message));
                continue;
            }
            sizer.accepted(&message, end - next);
            if let Err(error) = self.enqueue_bulk(&Message::Update(message)) {
                warn!(
                    peer = %self.peer_label,
                    %error,
                    "failed to send {family} {} UPDATE",
                    if withdrawal { "withdrawal" } else { "announce" }
                );
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            next = end;
        }
        Ok(next)
    }

    /// Split `entries` into as many wire UPDATEs as needed so each
    /// `build`-produced message fits `max_len`, enqueueing each in order.
    /// The exact profile builder emits one message regardless of size, so a
    /// large same-attribute IPv4 group (e.g. 1000 /24s ≈ 4114 bytes) exceeds
    /// the 4096-byte limit: `enqueue_bulk` would reject it, and that partial
    /// delivery is never reported back across the RIB/session boundary, so
    /// the RIB would believe the whole group was advertised. Chunking keeps
    /// every prefix on the wire. Each chunk is the longest run of entries
    /// whose encoded bytes fit (see [`ChunkSizer`]); the exact
    /// `encoded_len()` check still guards every enqueue, and a lone entry
    /// that cannot fit tears the session down (see below). `kind` names the
    /// traffic for the failure log. Returns the successful entry count, or
    /// an error so the caller stops. Used by all four IPv4-unicast paths
    /// (body/MP announce and withdrawal); the per-family helpers below
    /// follow the same shape.
    fn send_v4_chunked<E, F>(
        &mut self,
        entries: &[E],
        max_len: usize,
        kind: &'static str,
        size: Option<Fit<'_, E>>,
        mut build: F,
    ) -> Result<usize, ()>
    where
        F: FnMut(&[E]) -> UpdateMessage,
    {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx: usize = 0;
        while idx < entries.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&entries[idx..], size);
            let msg = build(&entries[idx..end]);
            if sizer.measured_only(Some(&msg)) {
                continue;
            }
            let encoded_len = msg.encoded_len();
            if encoded_len > max_len {
                if end - idx <= 1 {
                    // A single entry plus its attributes exceeds the negotiated
                    // maximum. The RIB has already committed this batch to
                    // logical Adj-RIB-Out and this local encode failure is
                    // invisible to the dirty/resync path, so just returning
                    // would leave the wire permanently behind the RIB with the
                    // session still Established. Tear the session down instead
                    // (matching the BGP-LS/VPN chunkers): reconnect rebuilds
                    // Adj-RIB-Out from scratch, so the peer is visibly unhealthy
                    // rather than falsely advertised. An intrinsically
                    // un-sendable route no longer flap-loops here: the RIB's
                    // exact-export preflight probes encodability before the
                    // Adj-RIB-Out commit and suppresses such routes as
                    // peer-unexportable (re-probed on outbound refresh), so
                    // this branch only fires if the wire encoding diverges
                    // from that probe.
                    warn!(
                        peer = %self.peer_label,
                        size = encoded_len,
                        max = max_len,
                        "single IPv4 {kind} entry exceeds maximum message length — tearing down the session so Adj-RIB-Out is rebuilt on reconnect"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - idx, Some(&msg));
                continue;
            }
            sizer.accepted(&msg, end - idx);
            if let Err(e) = self.enqueue_bulk(&Message::Update(msg)) {
                warn!(peer = %self.peer_label, error = %e, "failed to send IPv4 {kind} UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }

    /// Fallible size-aware sender for `MP_REACH/MP_UNREACH` families whose
    /// structured NLRI codec can reject an individual entry (notably
    /// `FlowSpec`). Chunks are sized from encoded bytes like
    /// [`Self::send_v4_chunked`]; `size` is `None` for families whose entry
    /// size is not arithmetic. Both an encoded-size overflow and a
    /// structured-build error shrink a multi-entry chunk. A single entry
    /// that still fails is the existing wire/RIB invariant breach: tear the
    /// session down so it cannot remain Established with logical
    /// Adj-RIB-Out ahead of the wire. LAN-361 will move that single-entry
    /// decision before the RIB commit.
    fn send_mp_chunked<E, F>(
        &mut self,
        entries: &[E],
        max_len: usize,
        family: &'static str,
        kind: &'static str,
        size: Option<Fit<'_, E>>,
        mut build: F,
    ) -> Result<usize, ()>
    where
        F: FnMut(&[E]) -> Result<UpdateMessage, rustbgpd_wire::EncodeError>,
    {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx = 0;
        while idx < entries.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&entries[idx..], size);
            let candidate = build(&entries[idx..end]);
            if sizer.measured_only(candidate.as_ref().ok()) {
                continue;
            }
            let needs_smaller = candidate
                .as_ref()
                .map_or(true, |message| message.encoded_len() > max_len);
            if needs_smaller {
                if end - idx > 1 {
                    sizer.rejected(end - idx, candidate.as_ref().ok());
                    continue;
                }
                match candidate {
                    Ok(message) => warn!(
                        peer = %self.peer_label,
                        size = message.encoded_len(),
                        max = max_len,
                        "single {family} {kind} exceeds maximum message length — tearing down the session so Adj-RIB-Out is rebuilt on reconnect"
                    ),
                    Err(error) => warn!(
                        peer = %self.peer_label,
                        %error,
                        max = max_len,
                        "single {family} {kind} cannot be encoded — tearing down the session so Adj-RIB-Out is rebuilt on reconnect"
                    ),
                }
                self.trigger_outbound_out_of_resources_teardown(
                    crate::handle::SessionFailureCause::PostCommitInvariant,
                );
                return Err(());
            }
            let message = candidate.expect("successful MP build checked above");
            sizer.accepted(&message, end - idx);
            if let Err(error) = self.enqueue_bulk(&Message::Update(message)) {
                warn!(peer = %self.peer_label, %error, "failed to send {family} {kind} UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }

    /// Send a batch of EVPN announcements as one or more `MP_REACH_NLRI`
    /// UPDATEs, splitting so each encoded message fits `max_len` bytes.
    /// Chunks are sized from measured bytes per route (see [`ChunkSizer`]).
    /// Returns an error on send failure so the caller can abort the whole
    /// route batch the same way the unicast path does.
    fn send_evpn_reach_chunked(
        &mut self,
        profile: &SessionExportProfile,
        next_hop: IpAddr,
        base_attrs: &[PathAttribute],
        routes: &[EvpnRoute],
        max_len: usize,
    ) -> Result<usize, ()> {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx: usize = 0;
        while idx < routes.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&routes[idx..], None);
            let msg = profile
                .build_mp_reach(
                    Afi::L2Vpn,
                    Safi::Evpn,
                    next_hop,
                    None,
                    base_attrs,
                    ReachNlri::Evpn(&routes[idx..end]),
                    Ipv4UnicastMode::Body,
                )
                .expect("EVPN MP_REACH construction was previously infallible");
            if sizer.measured_only(Some(&msg)) {
                continue;
            }
            if msg.encoded_len() > max_len {
                if end - idx <= 1 {
                    // Single-route oversize: a single EVPN route plus its
                    // attribute set exceeds the negotiated maximum BGP
                    // message length. Previously the loop logged + skipped
                    // and continued, returning `true` — a silent desync
                    // because RIB has already committed the route to
                    // Adj-RIB-Out and now believes the peer holds it.
                    // The caller cannot report this synchronous failure back
                    // across the RIB/session boundary. Use the established
                    // Cease/8 hard teardown so the stream cannot remain
                    // Established with Adj-RIB-Out ahead of the wire.
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single EVPN route exceeds maximum message length — tearing down the session so Adj-RIB-Out is rebuilt on reconnect"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - idx, Some(&msg));
                continue;
            }
            sizer.accepted(&msg, end - idx);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send EVPN announce UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }
    /// Send a batch of EVPN withdrawals as one or more `MP_UNREACH_NLRI`
    /// UPDATEs, splitting so each encoded message fits `max_len` bytes.
    fn send_evpn_unreach_chunked(
        &mut self,
        profile: &SessionExportProfile,
        afi: Afi,
        safi: Safi,
        ipv4_mode: Ipv4UnicastMode,
        routes: &[EvpnRoute],
        max_len: usize,
    ) -> Result<usize, ()> {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx: usize = 0;
        while idx < routes.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&routes[idx..], None);
            let msg = profile
                .build_mp_unreach(afi, safi, UnreachNlri::Evpn(&routes[idx..end]), ipv4_mode)
                .expect("EVPN MP_UNREACH construction was previously infallible");
            if sizer.measured_only(Some(&msg)) {
                continue;
            }
            if msg.encoded_len() > max_len {
                if end - idx <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single EVPN withdrawal exceeds maximum message length — tearing down the session so Adj-RIB-Out is rebuilt on reconnect"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - idx, Some(&msg));
                continue;
            }
            sizer.accepted(&msg, end - idx);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send EVPN withdrawal UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }
    /// Send a batch of BGP-LS announcements as one or more `MP_REACH_NLRI`
    /// UPDATEs, splitting so each encoded message fits `max_len` bytes.
    fn send_bgpls_reach_chunked(
        &mut self,
        safi: Safi,
        next_hop: IpAddr,
        base_attrs: &[PathAttribute],
        routes: &[rustbgpd_wire::bgpls::BgpLsNlri],
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> Result<usize, ()> {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx: usize = 0;
        while idx < routes.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&routes[idx..], None);
            let msg = profile
                .build_mp_reach(
                    Afi::BgpLs,
                    safi,
                    next_hop,
                    None,
                    base_attrs,
                    ReachNlri::BgpLs(&routes[idx..end]),
                    Ipv4UnicastMode::Body,
                )
                .expect("BGP-LS MP_REACH construction was previously infallible");
            if sizer.measured_only(Some(&msg)) {
                continue;
            }
            if msg.encoded_len() > max_len {
                if end - idx <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single BGP-LS route exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - idx, Some(&msg));
                continue;
            }
            sizer.accepted(&msg, end - idx);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send BGP-LS announce UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }
    /// Send a batch of BGP-LS withdrawals as one or more `MP_UNREACH_NLRI`
    /// UPDATEs, splitting so each encoded message fits `max_len` bytes.
    fn send_bgpls_unreach_chunked(
        &mut self,
        afi: Afi,
        safi: Safi,
        ipv4_mode: Ipv4UnicastMode,
        routes: &[rustbgpd_wire::bgpls::BgpLsNlri],
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> Result<usize, ()> {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx: usize = 0;
        while idx < routes.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&routes[idx..], None);
            let msg = profile
                .build_mp_unreach(afi, safi, UnreachNlri::BgpLs(&routes[idx..end]), ipv4_mode)
                .expect("BGP-LS MP_UNREACH construction was previously infallible");
            if sizer.measured_only(Some(&msg)) {
                continue;
            }
            if msg.encoded_len() > max_len {
                if end - idx <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single BGP-LS withdrawal exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - idx, Some(&msg));
                continue;
            }
            sizer.accepted(&msg, end - idx);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send BGP-LS withdrawal UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }
    /// Send a batch of VPNv4/VPNv6 announcements as one or more
    /// `MP_REACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes.
    ///
    /// The `MP_REACH_NLRI` next-hop is the route's stored VPN next-hop,
    /// preserved verbatim (ADR-0077 §6): SAFI 128 reflection never applies
    /// next-hop-self, so any next-hop-self behavior (policy override or eBGP
    /// default rewrite) is deliberately inert for this family — rewriting it
    /// would break the remote PE's transport-label resolution toward the
    /// originating PE.
    #[expect(
        clippy::too_many_arguments,
        reason = "the MP_REACH chunker receives each wire component explicitly"
    )]
    fn send_vpn_reach_chunked(
        &mut self,
        afi: Afi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
        base_attrs: &[PathAttribute],
        routes: &[rustbgpd_wire::VpnNlriEntry],
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> Result<usize, ()> {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx: usize = 0;
        while idx < routes.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&routes[idx..], None);
            let msg = profile
                .build_mp_reach(
                    afi,
                    Safi::MplsVpn,
                    next_hop,
                    link_local_next_hop,
                    base_attrs,
                    ReachNlri::Vpn(&routes[idx..end]),
                    Ipv4UnicastMode::Body,
                )
                .expect("VPN MP_REACH construction was previously infallible");
            if sizer.measured_only(Some(&msg)) {
                continue;
            }
            if msg.encoded_len() > max_len {
                if end - idx <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single VPN route exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - idx, Some(&msg));
                continue;
            }
            sizer.accepted(&msg, end - idx);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send VPN announce UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }
    /// Send a batch of VPNv4/VPNv6 withdrawals as one or more
    /// `MP_UNREACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes.
    fn send_vpn_unreach_chunked(
        &mut self,
        afi: Afi,
        safi: Safi,
        ipv4_mode: Ipv4UnicastMode,
        routes: &[rustbgpd_wire::VpnNlriEntry],
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> Result<usize, ()> {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx: usize = 0;
        while idx < routes.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&routes[idx..], None);
            let msg = profile
                .build_mp_unreach(afi, safi, UnreachNlri::Vpn(&routes[idx..end]), ipv4_mode)
                .expect("VPN MP_UNREACH construction was previously infallible");
            if sizer.measured_only(Some(&msg)) {
                continue;
            }
            if msg.encoded_len() > max_len {
                if end - idx <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single VPN withdrawal exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - idx, Some(&msg));
                continue;
            }
            sizer.accepted(&msg, end - idx);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send VPN withdrawal UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }
    /// Send a batch of labeled-unicast announcements as one or more
    /// `MP_REACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes. Mirrors the VPN sender minus the RD-prefixed
    /// next-hop (RFC 8277 uses the ordinary host next-hop forms).
    #[expect(
        clippy::too_many_arguments,
        reason = "the MP_REACH chunker receives each wire component explicitly"
    )]
    fn send_labeled_reach_chunked(
        &mut self,
        afi: Afi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
        base_attrs: &[PathAttribute],
        routes: &[rustbgpd_wire::LabeledNlriEntry],
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> Result<usize, ()> {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx: usize = 0;
        while idx < routes.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&routes[idx..], None);
            let msg = profile
                .build_mp_reach(
                    afi,
                    Safi::LabeledUnicast,
                    next_hop,
                    link_local_next_hop,
                    base_attrs,
                    ReachNlri::Labeled(&routes[idx..end]),
                    Ipv4UnicastMode::Body,
                )
                .expect("labeled-unicast MP_REACH construction was previously infallible");
            if sizer.measured_only(Some(&msg)) {
                continue;
            }
            if msg.encoded_len() > max_len {
                if end - idx <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single labeled route exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - idx, Some(&msg));
                continue;
            }
            sizer.accepted(&msg, end - idx);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send labeled announce UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }
    /// Send a batch of labeled-unicast withdrawals as one or more
    /// `MP_UNREACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes. RFC 8277 §2.4: the withdraw encoder emits the
    /// 3-octet compatibility field, never a label stack.
    fn send_labeled_unreach_chunked(
        &mut self,
        afi: Afi,
        safi: Safi,
        ipv4_mode: Ipv4UnicastMode,
        routes: &[rustbgpd_wire::LabeledNlriEntry],
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> Result<usize, ()> {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx: usize = 0;
        while idx < routes.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&routes[idx..], None);
            let msg = profile
                .build_mp_unreach(
                    afi,
                    safi,
                    UnreachNlri::Labeled(&routes[idx..end]),
                    ipv4_mode,
                )
                .expect("labeled-unicast MP_UNREACH construction was previously infallible");
            if sizer.measured_only(Some(&msg)) {
                continue;
            }
            if msg.encoded_len() > max_len {
                if end - idx <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single labeled withdrawal exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - idx, Some(&msg));
                continue;
            }
            sizer.accepted(&msg, end - idx);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send labeled withdrawal UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }
    /// Send a batch of RT-Constrain announcements as one or more
    /// `MP_REACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes. Mirrors the VPN sender minus label handling.
    fn send_rtc_reach_chunked(
        &mut self,
        profile: &SessionExportProfile,
        next_hop: IpAddr,
        base_attrs: &[PathAttribute],
        routes: &[rustbgpd_wire::RtcNlri],
        max_len: usize,
    ) -> Result<usize, ()> {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx: usize = 0;
        while idx < routes.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&routes[idx..], None);
            let msg = profile
                .build_mp_reach(
                    Afi::Ipv4,
                    Safi::RtConstrain,
                    next_hop,
                    None,
                    base_attrs,
                    ReachNlri::Rtc(&routes[idx..end]),
                    Ipv4UnicastMode::Body,
                )
                .expect("RTC MP_REACH construction was previously infallible");
            if sizer.measured_only(Some(&msg)) {
                continue;
            }
            if msg.encoded_len() > max_len {
                if end - idx <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single RTC route exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - idx, Some(&msg));
                continue;
            }
            sizer.accepted(&msg, end - idx);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send RTC announce UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }
    /// Send a batch of RT-Constrain withdrawals as one or more
    /// `MP_UNREACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes.
    fn send_rtc_unreach_chunked(
        &mut self,
        profile: &SessionExportProfile,
        afi: Afi,
        safi: Safi,
        ipv4_mode: Ipv4UnicastMode,
        routes: &[rustbgpd_wire::RtcNlri],
        max_len: usize,
    ) -> Result<usize, ()> {
        let mut sizer = ChunkSizer::new(max_len);
        let mut idx: usize = 0;
        while idx < routes.len() {
            if !self.writer_frame_room(max_len)? {
                return Ok(idx);
            }
            let end = idx + sizer.next(&routes[idx..], None);
            let msg = profile
                .build_mp_unreach(afi, safi, UnreachNlri::Rtc(&routes[idx..end]), ipv4_mode)
                .expect("RTC MP_UNREACH construction was previously infallible");
            if sizer.measured_only(Some(&msg)) {
                continue;
            }
            if msg.encoded_len() > max_len {
                if end - idx <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single RTC withdrawal exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_out_of_resources_teardown(
                        crate::handle::SessionFailureCause::PostCommitInvariant,
                    );
                    return Err(());
                }
                sizer.rejected(end - idx, Some(&msg));
                continue;
            }
            sizer.accepted(&msg, end - idx);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send RTC withdrawal UPDATE");
                return Err(());
            }
            self.config.neighbor_counters.record_update_sent();
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        Ok(idx)
    }
    // Test-facing compatibility helpers delegate to the same immutable
    // profile preparation used by live emission. They republish first because
    // focused fixtures intentionally mutate config/negotiation fields directly.
    #[cfg(test)]
    pub(super) fn prepare_outbound_attributes(
        &self,
        route: &Route,
        is_ebgp: bool,
        local_ipv4: Ipv4Addr,
        nh_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> Vec<PathAttribute> {
        SessionExportProfile::capture(self)
            .with_test_ebgp(is_ebgp)
            .prepare_unicast_attributes(route, local_ipv4, nh_override)
    }

    #[cfg(test)]
    pub(super) fn prepare_outbound_attributes_flowspec(
        &self,
        route: &FlowSpecRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        SessionExportProfile::capture(self)
            .with_test_ebgp(is_ebgp)
            .prepare_flowspec_attributes(route)
    }

    #[cfg(test)]
    pub(super) fn prepare_outbound_attributes_vpn(
        &self,
        route: &VpnRibRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        SessionExportProfile::capture(self)
            .with_test_ebgp(is_ebgp)
            .prepare_vpn_attributes(route)
    }

    #[cfg(test)]
    pub(super) fn prepare_outbound_attributes_labeled(
        &self,
        route: &LabeledRibRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        SessionExportProfile::capture(self)
            .with_test_ebgp(is_ebgp)
            .prepare_labeled_attributes(route)
    }

    #[cfg(test)]
    pub(super) fn prepare_outbound_attributes_rtc(
        &self,
        route: &RtcRibRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        SessionExportProfile::capture(self)
            .with_test_ebgp(is_ebgp)
            .prepare_rtc_attributes(route)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rustbgpd_fsm::PeerConfig;
    use rustbgpd_rib::AttrSet;
    use rustbgpd_rib::PeerId;
    use rustbgpd_wire::{
        AsPath, AsPathSegment, EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, Ipv6Prefix,
        MacAddress, MplsLabel, Origin, RouteDistinguisher, notification::NotificationCode,
        notification::cease_subcode,
    };
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::{Duration, timeout};

    /// `FlowSpec` withdrawals own their rule components but no shared handle
    /// a session test can count, so the retirement budget is pinned here:
    /// at most one slice per step, a repeated `begin_retirement` included,
    /// until the family is empty.
    #[test]
    fn retirement_releases_flowspec_withdrawals_a_slice_per_step() {
        const SLICE: usize = super::super::shared_group::PROGRESSIVE_SLICE_ROUTES;
        let total = 2 * SLICE + 1;
        let update = OutboundRouteUpdate {
            flowspec_withdraw: (0..total)
                .map(|_| FlowSpecKey {
                    afi: Afi::Ipv4,
                    rd: None,
                    rule: rustbgpd_wire::FlowSpecRule {
                        components: Vec::new(),
                    },
                })
                .collect(),
            ..OutboundRouteUpdate::default()
        };
        let mut pending = PendingOutbound::new(update, None, Vec::new());
        pending.test_slice_cost = Some(Duration::ZERO);
        let remaining = |pending: &PendingOutbound| pending.retiring_rest.flowspec_withdraw.len();
        let mut left = total;
        let mut steps = Vec::new();
        let mut more = pending.begin_retirement();
        steps.push(left - remaining(&pending));
        left = remaining(&pending);
        if more {
            more = pending.begin_retirement();
            steps.push(left - remaining(&pending));
            left = remaining(&pending);
        }
        while more && steps.len() <= total / SLICE + 2 {
            more = pending.retire_step();
            steps.push(left - remaining(&pending));
            left = remaining(&pending);
        }
        assert!(
            steps.iter().all(|&released| released <= SLICE),
            "a step released more than {SLICE} FlowSpec withdrawals: {steps:?}"
        );
        assert_eq!(left, 0, "every FlowSpec withdrawal is released: {steps:?}");
        assert!(!more);
    }

    /// Blackholing rows lead the envelope and fill slices of their own:
    /// no announce slice mixes them with ordinary rows, and each slice's
    /// next-hop overrides stay aligned with its routes.
    #[test]
    fn exempt_rows_fill_announce_slices_of_their_own() {
        let routes: Vec<Route> = (1..=5)
            .map(|path_id| {
                let mut route = super::super::tests::make_route(100);
                route.path_id = path_id;
                route
            })
            .collect();
        let overrides = (1..=5u32)
            .map(|path_id| {
                (path_id % 2 == 0).then(|| {
                    rustbgpd_policy::NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(
                        192,
                        0,
                        2,
                        u8::try_from(path_id).unwrap(),
                    )))
                })
            })
            .collect::<Vec<_>>();
        let mut pending = PendingOutbound {
            update: OutboundRouteUpdate {
                announce: Arc::new(routes),
                next_hop_override: Arc::new(overrides.clone()),
                exempt_announce: 2,
                ..OutboundRouteUpdate::default()
            },
            shared: None,
            requests: Vec::new(),
            phase: ANNOUNCE_PHASE,
            offset: 0,
            capacity_blocked: false,
            bytes_wait: None,
            slice_routes: 3,
            evpn_announce: Vec::new().into_iter(),
            vpn_announce: Vec::new().into_iter(),
            labeled_announce: Vec::new().into_iter(),
            announce: Vec::new().into_iter(),
            retiring_rest: RetiringRest::default(),
            pending_slice: None,
            dropped_ipv6_next_hops: DroppedIpv6NextHops::default(),
            test_slice_cost: None,
        };
        let mut sliced = Vec::new();
        while let Some((_, slice)) = pending.next_slice(3) {
            if slice.announce.is_empty() {
                continue;
            }
            let path_ids: Vec<u32> = slice.announce.iter().map(|route| route.path_id).collect();
            let aligned: Vec<_> = path_ids
                .iter()
                .map(|&path_id| overrides[usize::try_from(path_id).unwrap() - 1].clone())
                .collect();
            assert_eq!(slice.next_hop_override.to_vec(), aligned);
            sliced.push(path_ids);
        }
        assert_eq!(sliced, [vec![1, 2], vec![3, 4, 5]]);
    }

    fn make_test_session() -> PeerSession {
        let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
        peer_config.families = vec![(Afi::L2Vpn, Safi::Evpn)];
        let config =
            crate::config::TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
        let (_command_tx, command_rx) = mpsc::channel(8);
        let (rib_tx, _rib_rx) = mpsc::channel(8);
        PeerSession::new(
            config,
            rustbgpd_telemetry::BgpMetrics::new(),
            command_rx,
            rib_tx,
            None,
            None,
            None,
            None,
            None,
            false,
        )
    }

    async fn connected_stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    async fn read_message(stream: &mut TcpStream) -> Message {
        let mut header = [0_u8; 19];
        stream.read_exact(&mut header).await.unwrap();
        let message_len = usize::from(u16::from_be_bytes([header[16], header[17]]));
        let mut body = vec![0_u8; message_len - header.len()];
        stream.read_exact(&mut body).await.unwrap();
        let mut complete = header.to_vec();
        complete.extend_from_slice(&body);
        let mut bytes = Bytes::from(complete);
        rustbgpd_wire::decode_message(&mut bytes, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "RIB sent IPv6 route to eBGP peer with no valid IPv6 next-hop")]
    fn ipv6_ebgp_without_local_next_hop_trips_debug_contract() {
        let mut session = make_test_session();
        session.config.peer.families = vec![(Afi::Ipv6, Safi::Unicast)];
        let mut negotiated = rustbgpd_fsm::NegotiatedSession::default();
        negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
        session.negotiated = Some(Arc::new(negotiated));
        let snapshot = session
            .export_encoder
            .publish(SessionExportProfile::capture(&session).with_test_ebgp(true));
        let route = Route {
            prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64)),
            next_hop: IpAddr::V6("2001:db8::2".parse().unwrap()),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: PeerId::from_addr(IpAddr::V6("2001:db8::2".parse().unwrap())),
            attributes: AttrSet::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
            ]),
            received_at: rustbgpd_rib::route::ReceivedAt::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            received_as_path: None,
            aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
        };
        session.send_route_update(OutboundRouteUpdate {
            exact_export_snapshot: Some(snapshot),
            announce: vec![route].into(),
            next_hop_override: vec![None].into(),
            ..OutboundRouteUpdate::default()
        });
    }

    /// A single EVPN NLRI that cannot fit the negotiated message ceiling is
    /// not a recoverable batch error: the RIB has already committed the
    /// logical advertisement or withdrawal. Pin both private helper branches
    /// with an artificial ceiling so even the otherwise-unreachable valid
    /// withdrawal overflow emits a final Cease/8 and hard-closes the stream.
    #[tokio::test]
    async fn evpn_single_entry_overflow_tears_down_announce_and_withdraw() {
        let route = EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress([0x02, 0, 0, 0xaa, 0xbb, 0xcc]),
            ip: Some(IpAddr::V6("2001:db8::1".parse().unwrap())),
            label1: MplsLabel::new(10_000),
            label2: None,
        });

        for announce in [true, false] {
            let mut session = make_test_session();
            let (client, mut server) = connected_stream_pair().await;
            session.test_install_stream(client);
            let profile = SessionExportProfile::capture(&session).with_test_ebgp(true);

            let sent = if announce {
                session.send_evpn_reach_chunked(
                    &profile,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    &[PathAttribute::Origin(Origin::Igp)],
                    std::slice::from_ref(&route),
                    1,
                )
            } else {
                session.send_evpn_unreach_chunked(
                    &profile,
                    Afi::L2Vpn,
                    Safi::Evpn,
                    Ipv4UnicastMode::Body,
                    std::slice::from_ref(&route),
                    1,
                )
            };
            assert!(sent.is_err(), "overflowing EVPN send must fail closed");
            assert!(session.read_half.is_none());
            assert!(session.writer_bulk_tx.is_none());
            assert!(session.writer_priority_tx.is_none());

            let Message::Notification(notification) = read_message(&mut server).await else {
                panic!("overflowing EVPN send must emit a NOTIFICATION");
            };
            assert_eq!(notification.code, NotificationCode::Cease);
            assert_eq!(notification.subcode, cease_subcode::OUT_OF_RESOURCES);
            assert_eq!(
                session.pending_outbound_teardown_cause,
                Some(crate::handle::SessionFailureCause::PostCommitInvariant)
            );
            assert_eq!(
                session.last_error,
                crate::handle::SessionFailureCause::PostCommitInvariant.to_string()
            );

            let join = session
                .writer_join
                .take()
                .expect("teardown keeps writer join handle for run-loop observation");
            let result = timeout(Duration::from_secs(2), join)
                .await
                .expect("writer exits after EVPN overflow")
                .expect("writer task must not panic");
            assert!(matches!(
                result,
                Err(super::super::writer::WriterExit::TornDown)
            ));
            let mut trailing = [0_u8; 1];
            assert_eq!(
                timeout(Duration::from_secs(1), server.read(&mut trailing))
                    .await
                    .expect("writer hard-close reaches EOF")
                    .unwrap(),
                0,
                "Cease/8 must be the final frame"
            );
        }
    }
}

#[cfg(test)]
mod attr_group_index_tests {
    use super::*;

    fn attrs(med: u32) -> Arc<Vec<PathAttribute>> {
        Arc::new(vec![PathAttribute::Med(med)])
    }

    /// Equal values rejoin their group by value both before and after the
    /// value map exists; a different next hop never joins.
    #[test]
    fn rejoins_by_value_across_the_lazy_value_map() {
        let mut index = AttrGroupIndex::default();
        let nh = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let other_nh = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(index.group(&attrs(1), nh, None, 0), Err(0));
        assert_eq!(index.group(&attrs(1), nh, None, 1), Ok(0));
        assert_eq!(index.group(&attrs(1), other_nh, None, 1), Err(1));
        assert_eq!(index.group(&attrs(2), nh, None, 2), Err(2));
        assert_eq!(index.group(&attrs(1), nh, None, 3), Ok(0));
        assert_eq!(index.group(&attrs(1), other_nh, None, 3), Ok(1));
        assert_eq!(index.group(&attrs(2), nh, None, 3), Ok(2));
        let shared = attrs(3);
        assert_eq!(index.group(&shared, nh, None, 3), Err(3));
        assert_eq!(index.group(&shared, nh, None, 4), Ok(3));
    }

    /// Once the value map exists, a group-opening pointer is indexed by
    /// value only; seeing it again rejoins its own group without a pin and
    /// records it for the pointer fast path. A different allocation of the
    /// same value still joins by value and is pinned.
    #[test]
    fn value_map_defers_pointer_entries_until_repeat() {
        let mut index = AttrGroupIndex::default();
        assert_eq!(index.group(&attrs(1), None, None, 0), Err(0));
        let opener = attrs(2);
        assert_eq!(index.group(&opener, None, None, 1), Err(1));
        assert_eq!(index.by_ptr.len(), 1, "only the pre-map first pointer");
        assert_eq!(index.group(&opener, None, None, 2), Ok(1));
        assert_eq!(index.pinned.len(), 0);
        assert_eq!(index.by_ptr.len(), 2);
        assert_eq!(index.group(&opener, None, None, 2), Ok(1));
        let twin = attrs(2);
        assert_eq!(index.group(&twin, None, None, 2), Ok(1));
        assert_eq!(index.pinned.len(), 1);
        assert_eq!(index.by_ptr.len(), 3);
    }
}

/// How the chunkers pack one same-attribute group: the frames are read back
/// off the wire and every chunk build is counted, builds that were not sent
/// included.
#[cfg(test)]
mod packing_tests {
    use super::super::packing::{BUILT, CREATED};
    use super::*;
    use rustbgpd_fsm::{NegotiatedSession, PeerConfig};
    use rustbgpd_wire::{
        AddPathMode, AsPath, AsPathSegment, EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp,
        Ipv4Prefix, Ipv6Prefix, MacAddress, MplsLabel, Origin, RouteDistinguisher,
    };
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    /// The largest group the slicer hands a chunker.
    const SLICE: usize = super::super::shared_group::PROGRESSIVE_SLICE_ROUTES;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Wire {
        V4Announce,
        V4Withdraw,
        V6Announce,
        V6Withdraw,
        EvpnAnnounce,
        SharedV4Announce,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Lengths {
        Uniform,
        Mixed,
    }

    fn base_attrs() -> Vec<PathAttribute> {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65_001, 65_010, 65_020])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            PathAttribute::Communities(vec![0xFDE9_0001, 0xFDE9_0002, 0xFDE9_0003]),
        ]
    }

    fn v4_entries(rows: usize, lengths: Lengths, add_path: bool) -> Vec<Ipv4NlriEntry> {
        (0..u32::try_from(rows).unwrap())
            .map(|i| Ipv4NlriEntry {
                path_id: if add_path { i + 1 } else { 0 },
                prefix: Ipv4Prefix::new(
                    Ipv4Addr::from(0x0B00_0000 + (i << 8)),
                    match lengths {
                        Lengths::Uniform => 24,
                        Lengths::Mixed => [24, 24, 24, 22, 20, 16, 23, 19][i as usize % 8],
                    },
                ),
            })
            .collect()
    }

    fn v6_entries(rows: usize, lengths: Lengths, add_path: bool) -> Vec<NlriEntry> {
        (0..u32::try_from(rows).unwrap())
            .map(|i| NlriEntry {
                path_id: if add_path { i + 1 } else { 0 },
                prefix: Prefix::V6(Ipv6Prefix::new(
                    Ipv6Addr::from((0x2001_0db8_u128 << 96) | (u128::from(i) << 80)),
                    match lengths {
                        Lengths::Uniform => 48,
                        Lengths::Mixed => [48, 48, 48, 32, 40, 44, 36, 47][i as usize % 8],
                    },
                )),
            })
            .collect()
    }

    fn evpn_routes(rows: usize) -> Vec<EvpnRoute> {
        (0..u32::try_from(rows).unwrap())
            .map(|i| {
                let [_, b, c, d] = i.to_be_bytes();
                EvpnRoute::MacIp(EvpnMacIp {
                    rd: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
                    esi: EthernetSegmentIdentifier::ZERO,
                    ethernet_tag: EthernetTagId(100),
                    mac: MacAddress([0x02, 0, 0, b, c, d]),
                    ip: Some(IpAddr::V4(Ipv4Addr::new(10, b, c, d))),
                    label1: MplsLabel::new(10_000),
                    label2: None,
                })
            })
            .collect()
    }

    async fn frame_lengths(server: &mut TcpStream, count: usize) -> Vec<usize> {
        let mut frames = Vec::with_capacity(count);
        for _ in 0..count {
            let mut header = [0_u8; 19];
            server.read_exact(&mut header).await.unwrap();
            let length = usize::from(u16::from_be_bytes([header[16], header[17]]));
            let mut body = vec![0_u8; length - header.len()];
            server.read_exact(&mut body).await.unwrap();
            frames.push(length);
        }
        frames
    }

    /// A session with a live writer, the peer's end of its stream, and its
    /// export profile.
    async fn connected(
        family: (Afi, Safi),
        add_path: bool,
        extended: bool,
    ) -> (PeerSession, TcpStream, SessionExportProfile) {
        let mut peer_config = PeerConfig::new(65_001, 65_002, Ipv4Addr::new(10, 0, 0, 1));
        peer_config.families = vec![family];
        let config =
            crate::config::TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(8);
        let (rib_tx, _rib_rx) = tokio::sync::mpsc::channel(8);
        let mut session = PeerSession::new(
            config,
            rustbgpd_telemetry::BgpMetrics::new(),
            command_rx,
            rib_tx,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        let mut negotiated = NegotiatedSession::default();
        negotiated.peer_asn = 65_002;
        negotiated.four_octet_as = true;
        negotiated.negotiated_families = vec![family];
        negotiated.peer_extended_message = extended;
        if add_path {
            negotiated
                .add_path_families
                .insert(family, AddPathMode::Both);
        }
        session.negotiated = Some(Arc::new(negotiated));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        session.test_install_stream(client);
        let profile = SessionExportProfile::capture(&session).with_test_ebgp(true);
        let max_len = profile.max_message_len();
        assert_eq!(max_len, if extended { 65_535 } else { 4_096 });
        assert_eq!(profile.add_path_send(family), add_path);
        (session, server, profile)
    }

    /// Frame lengths in wire order, chunk builds and entries built, for one
    /// group of `rows` entries.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per chunker call shape, mirroring the production call sites"
    )]
    async fn pack(
        wire: Wire,
        rows: usize,
        lengths: Lengths,
        add_path: bool,
        extended: bool,
    ) -> (Vec<usize>, usize, usize) {
        let family = match wire {
            Wire::V4Announce | Wire::V4Withdraw | Wire::SharedV4Announce => {
                (Afi::Ipv4, Safi::Unicast)
            }
            Wire::V6Announce | Wire::V6Withdraw => (Afi::Ipv6, Safi::Unicast),
            Wire::EvpnAnnounce => (Afi::L2Vpn, Safi::Evpn),
        };
        let (mut session, mut server, profile) = connected(family, add_path, extended).await;
        let max_len = profile.max_message_len();

        let attrs = base_attrs();
        let mp_attrs = &attrs[..2];
        let next_hop = IpAddr::V6("2001:db8::1".parse().unwrap());
        BUILT.set((0, 0));
        let sent = match wire {
            Wire::V4Announce => session.send_v4_chunked(
                &v4_entries(rows, lengths, add_path),
                max_len,
                "announce",
                Some(&ipv4_entry_len(add_path)),
                |chunk| profile.build_ipv4_body(chunk, &[], &attrs).unwrap(),
            ),
            Wire::V4Withdraw => session.send_v4_chunked(
                &v4_entries(rows, lengths, add_path),
                max_len,
                "withdraw",
                Some(&ipv4_entry_len(add_path)),
                |chunk| profile.build_ipv4_body(&[], chunk, &[]).unwrap(),
            ),
            Wire::V6Announce => session.send_mp_chunked(
                &v6_entries(rows, lengths, add_path),
                max_len,
                "IPv6 unicast",
                "announcement",
                Some(&entry_len(add_path)),
                |chunk| {
                    profile.build_mp_reach(
                        Afi::Ipv6,
                        Safi::Unicast,
                        next_hop,
                        None,
                        mp_attrs,
                        ReachNlri::Unicast(chunk),
                        Ipv4UnicastMode::Body,
                    )
                },
            ),
            Wire::V6Withdraw => session.send_mp_chunked(
                &v6_entries(rows, lengths, add_path),
                max_len,
                "IPv6 unicast",
                "withdrawal",
                Some(&entry_len(add_path)),
                |chunk| {
                    profile.build_mp_unreach(
                        Afi::Ipv6,
                        Safi::Unicast,
                        UnreachNlri::Unicast(chunk),
                        Ipv4UnicastMode::Body,
                    )
                },
            ),
            Wire::EvpnAnnounce => session.send_evpn_reach_chunked(
                &profile,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                mp_attrs,
                &evpn_routes(rows),
                max_len,
            ),
            Wire::SharedV4Announce => {
                // The update-group encoder publishes bytes instead of
                // enqueueing; every member then sends the same chunks.
                let template = super::super::tests::make_route(100);
                let routes: Vec<Route> = v4_entries(rows, lengths, add_path)
                    .into_iter()
                    .map(|entry| Route {
                        prefix: Prefix::V4(entry.prefix),
                        ..template.clone()
                    })
                    .collect();
                let chunks = super::super::shared_group::encode_shared_unicast_slice(
                    &profile,
                    &mut PreparedAttrCache::default(),
                    &routes,
                    &vec![None; rows],
                    &(0..rows).collect::<Vec<_>>(),
                )
                .expect("one same-attribute source encodes");
                let (builds, built) = BUILT.get();
                return (
                    chunks.iter().map(|chunk| chunk.bytes.len()).collect(),
                    builds,
                    built,
                );
            }
        };
        assert_eq!(
            sent,
            Ok(rows),
            "{wire:?}: the whole group is sent in one call"
        );
        let (builds, built) = BUILT.get();
        let frames = sent_frames(&session, &mut server).await;
        assert_eq!(
            u64::try_from(frames.iter().sum::<usize>()).unwrap(),
            session.writer_bulk_admitted
        );
        (frames, builds, built)
    }

    /// The packing contract, for a full slice and for groups that fit one
    /// message: at most one build that is not sent, a bounded number of
    /// entries built, and every message but a group's last full to within
    /// one entry. The pinned figures move only with a deliberate packing
    /// change.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one table of cases beside the checks every case must pass"
    )]
    async fn packs_groups_by_encoded_bytes() {
        use Lengths::{Mixed, Uniform};
        // Case, largest entry in bytes, then the pinned `(messages,
        // shortest, longest, total bytes, builds, entries built)`.
        let cases = [
            // IPv4 body.
            (
                (Wire::V4Announce, SLICE, Uniform, false, false),
                4,
                (3, 202, 4_094, 8_390, 4, 2_049),
            ),
            (
                (Wire::V4Announce, SLICE, Mixed, false, false),
                4,
                (2, 3_972, 4_096, 8_068, 3, 2_049),
            ),
            (
                (Wire::V4Announce, SLICE, Uniform, true, false),
                8,
                (5, 354, 4_090, 16_714, 6, 2_049),
            ),
            (
                (Wire::V4Announce, SLICE, Uniform, false, true),
                4,
                (1, 8_258, 8_258, 8_258, 1, 2_048),
            ),
            (
                (Wire::V4Withdraw, SLICE, Uniform, false, false),
                4,
                (3, 71, 4_095, 8_261, 4, 2_049),
            ),
            (
                (Wire::V4Withdraw, SLICE, Uniform, true, false),
                8,
                (5, 119, 4_095, 16_499, 6, 2_049),
            ),
            // MP_REACH / MP_UNREACH.
            (
                (Wire::V6Announce, SLICE, Uniform, false, false),
                7,
                (4, 2_330, 4_094, 14_612, 5, 2_049),
            ),
            (
                (Wire::V6Announce, SLICE, Mixed, false, false),
                7,
                (4, 1_310, 4_094, 13_588, 5, 2_049),
            ),
            (
                (Wire::V6Announce, SLICE, Uniform, true, false),
                11,
                (6, 2_467, 4_095, 22_942, 7, 2_049),
            ),
            (
                (Wire::V6Announce, SLICE, Uniform, false, true),
                7,
                (1, 14_405, 14_405, 14_405, 1, 2_048),
            ),
            (
                (Wire::V6Withdraw, SLICE, Uniform, false, false),
                7,
                (4, 2_186, 4_090, 14_456, 5, 2_049),
            ),
            (
                (Wire::V6Withdraw, SLICE, Uniform, false, true),
                7,
                (1, 14_366, 14_366, 14_366, 1, 2_048),
            ),
            // A typed family, sized from measured bytes per route.
            (
                (Wire::EvpnAnnounce, SLICE, Uniform, false, false),
                39,
                (20, 3_606, 4_074, 81_012, 21, 2_049),
            ),
            (
                (Wire::EvpnAnnounce, SLICE, Uniform, false, true),
                39,
                (2, 14_487, 65_499, 79_986, 3, 2_049),
            ),
            // The update-group encoder, always at the standard limit.
            (
                (Wire::SharedV4Announce, SLICE, Uniform, false, false),
                4,
                (3, 143, 4_095, 8_333, 4, 2_049),
            ),
            // Groups that fit one message are built exactly once.
            (
                (Wire::V4Announce, 1_000, Uniform, false, false),
                4,
                (1, 4_066, 4_066, 4_066, 1, 1_000),
            ),
            (
                (Wire::V4Withdraw, 1_018, Uniform, false, false),
                4,
                (1, 4_095, 4_095, 4_095, 1, 1_018),
            ),
            (
                (Wire::V6Announce, 500, Mixed, true, true),
                11,
                (1, 5_319, 5_319, 5_319, 1, 500),
            ),
            (
                (Wire::V6Withdraw, 1, Uniform, false, false),
                7,
                (1, 36, 36, 36, 1, 1),
            ),
            (
                (Wire::EvpnAnnounce, 64, Uniform, false, false),
                39,
                (1, 2_553, 2_553, 2_553, 1, 64),
            ),
            (
                (Wire::SharedV4Announce, 1_000, Uniform, false, false),
                4,
                (1, 4_047, 4_047, 4_047, 1, 1_000),
            ),
            // Only the attributes push this one over, so the whole group is
            // the one build that is not sent.
            (
                (Wire::V4Announce, 1_015, Uniform, false, false),
                4,
                (2, 98, 4_094, 4_192, 3, 2_030),
            ),
        ];
        let mut moved = Vec::new();
        for (case, entry, pinned) in cases {
            let (wire, rows, lengths, add_path, extended) = case;
            let limit = if extended { 65_535 } else { 4_096 };
            let (frames, builds, built) = pack(wire, rows, lengths, add_path, extended).await;
            let messages = frames.len();
            assert!(
                builds <= messages + 1,
                "{case:?}: {builds} builds for {messages} messages"
            );
            // Without sizes a group of up to 64 entries is tried whole; with
            // them, as many entries as fit a message that has no attributes.
            let spare = if wire == Wire::EvpnAnnounce {
                64
            } else {
                (limit - 23) / entry
            };
            assert!(
                built <= rows + spare,
                "{case:?}: {built} entries built to send {rows}"
            );
            let (last, full) = frames.split_last().unwrap();
            assert!(
                *last <= limit && full.iter().all(|frame| limit - frame < entry),
                "{case:?}: a message before the last has room for an entry: {frames:?}"
            );
            let actual = (
                messages,
                *frames.iter().min().unwrap(),
                *frames.iter().max().unwrap(),
                frames.iter().sum::<usize>(),
                builds,
                built,
            );
            if actual != pinned {
                moved.push(format!("{case:?}: {actual:?}"));
            }
        }
        assert!(moved.is_empty(), "packing moved:\n{}", moved.join("\n"));
    }
    async fn sent_frames(session: &PeerSession, server: &mut TcpStream) -> Vec<usize> {
        let messages = usize::try_from(session.config.neighbor_counters.updates_sent()).unwrap();
        timeout(Duration::from_secs(10), frame_lengths(server, messages))
            .await
            .expect("every enqueued UPDATE reaches the peer")
    }

    /// EVPN type-2 routes: 35 bytes MAC-only, 39 with an IPv4 address, 51
    /// with an IPv6 one.
    fn evpn_route(i: u32, ip: Option<IpAddr>) -> EvpnRoute {
        let [_, b, c, d] = i.to_be_bytes();
        EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress([0x02, 0, 0, b, c, d]),
            ip,
            label1: MplsLabel::new(10_000),
            label2: None,
        })
    }

    /// `FlowSpec` rules: 4 bytes for one protocol match, 72 for a prefix
    /// and thirty-two port matches.
    fn flowspec_rule(i: u32, large: bool) -> FlowSpecRule {
        use rustbgpd_wire::{FlowSpecComponent, FlowSpecPrefix, NumericMatch};
        let term = |value: u64, last: bool| NumericMatch {
            end_of_list: last,
            and_bit: false,
            lt: false,
            gt: false,
            eq: true,
            value,
        };
        let components = if large {
            vec![
                FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::from(0x0A00_0000 + i),
                    32,
                ))),
                FlowSpecComponent::Port((0..32).map(|port| term(port, port == 31)).collect()),
            ]
        } else {
            vec![FlowSpecComponent::IpProtocol(vec![term(
                u64::from(i % 200),
                true,
            )])]
        };
        FlowSpecRule { components }
    }

    /// Which entries of a typed group are small ones.
    #[derive(Clone, Copy, Debug)]
    enum Sizes {
        /// 2,048 entries: 500 small, then large ones.
        SmallThenLarge,
        /// 2,048 entries in runs of 100 small and 100 large.
        Alternating,
        /// 500 small entries, 100 large ones, then this many small ones.
        Spike(u32),
    }

    impl Sizes {
        fn small(self, i: u32) -> bool {
            match self {
                Self::SmallThenLarge => i < 500,
                Self::Alternating => (i / 100).is_multiple_of(2),
                Self::Spike(_) => !(500..600).contains(&i),
            }
        }

        fn rows(self) -> u32 {
            match self {
                Self::Spike(tail) => 600 + tail,
                _ => u32::try_from(SLICE).unwrap(),
            }
        }
    }

    /// Frame lengths and builds for one typed group whose entry sizes vary.
    async fn pack_varying(flowspec: bool, sizes: Sizes, extended: bool) -> (Vec<usize>, usize) {
        let rows = sizes.rows();
        let attrs = base_attrs();
        let mp_attrs = &attrs[..2];
        let family = if flowspec {
            (Afi::Ipv4, Safi::FlowSpec)
        } else {
            (Afi::L2Vpn, Safi::Evpn)
        };
        let (mut session, mut server, profile) = connected(family, false, extended).await;
        let max_len = profile.max_message_len();
        BUILT.set((0, 0));
        let sent = if flowspec {
            let rules: Vec<_> = (0..rows)
                .map(|i| flowspec_rule(i, !sizes.small(i)))
                .collect();
            session.send_mp_chunked(&rules, max_len, "FlowSpec", "announcement", None, |chunk| {
                profile.build_mp_reach(
                    Afi::Ipv4,
                    Safi::FlowSpec,
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    None,
                    mp_attrs,
                    ReachNlri::FlowSpec(chunk),
                    Ipv4UnicastMode::Body,
                )
            })
        } else {
            let large = IpAddr::V6("2001:db8::1".parse().unwrap());
            let routes: Vec<_> = (0..rows)
                .map(|i| evpn_route(i, (!sizes.small(i)).then_some(large)))
                .collect();
            session.send_evpn_reach_chunked(
                &profile,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                mp_attrs,
                &routes,
                max_len,
            )
        };
        assert_eq!(sent, Ok(rows as usize));
        let frames = sent_frames(&session, &mut server).await;
        assert!(frames.iter().all(|frame| *frame <= max_len));
        (frames, BUILT.get().0)
    }

    /// Entry sizes that change within a typed group cost extra builds, at
    /// the messages where the entries get larger. The pinned figures are
    /// `(messages, builds)`; the chunkers this replaced took (34, 38),
    /// (3, 3), (34, 38), (3, 3) for EVPN and (37, 155), (3, 4), (29, 130),
    /// (2, 2) for `FlowSpec`.
    #[tokio::test]
    async fn varying_typed_groups_stay_within_the_build_bound() {
        use Sizes::{Alternating, SmallThenLarge};
        let cases = [
            ((false, SmallThenLarge, false), (24, 26)),
            ((false, SmallThenLarge, true), (2, 4)),
            ((false, Alternating, false), (25, 40)),
            ((false, Alternating, true), (2, 4)),
            ((true, SmallThenLarge, false), (34, 36)),
            ((true, SmallThenLarge, true), (2, 4)),
            ((true, Alternating, false), (32, 58)),
            ((true, Alternating, true), (2, 5)),
        ];
        let mut moved = Vec::new();
        for (case, pinned) in cases {
            let (flowspec, sizes, extended) = case;
            let (frames, builds) = pack_varying(flowspec, sizes, extended).await;
            let messages = frames.len();
            assert!(
                builds <= 2 * messages + 4,
                "{case:?}: {builds} builds for {messages} messages"
            );
            if (messages, builds) != pinned {
                moved.push(format!("{case:?}: {:?}", (messages, builds)));
            }
        }
        assert!(moved.is_empty(), "packing moved:\n{}", moved.join("\n"));
    }

    /// A group of one entry is the common case of a diverse table, one
    /// UPDATE per route. It is built once and sent, with no sizing state
    /// created for it; a group of two creates one.
    #[tokio::test]
    async fn a_single_entry_group_is_built_once_without_sizing() {
        for wire in [
            Wire::V4Announce,
            Wire::V4Withdraw,
            Wire::V6Announce,
            Wire::V6Withdraw,
            Wire::EvpnAnnounce,
            Wire::SharedV4Announce,
        ] {
            for add_path in [false, true] {
                if add_path && matches!(wire, Wire::EvpnAnnounce | Wire::SharedV4Announce) {
                    continue;
                }
                for (rows, created) in [(1, 0), (2, 1)] {
                    CREATED.set(0);
                    let (frames, builds, built) =
                        pack(wire, rows, Lengths::Uniform, add_path, false).await;
                    assert_eq!(
                        (frames.len(), builds, built, CREATED.get()),
                        (1, 1, rows, created),
                        "{wire:?}, Add-Path {add_path}, {rows} rows"
                    );
                }
            }
        }
    }

    /// A run of large entries inside a long group of small ones must not
    /// set the size of every later message: once the entries are one size
    /// again the messages are full again. The pinned figures are
    /// `(messages, builds)`. The EVPN tail is shorter so that the group
    /// stays inside the writer's byte budget.
    #[tokio::test]
    async fn messages_fill_again_after_a_run_of_large_entries() {
        let cases = [
            ((true, 2_000, false), (7, 12)),
            ((true, 2_000, true), (1, 2)),
            ((true, 20_000, false), (25, 30)),
            ((true, 20_000, true), (2, 6)),
            ((false, 2_000, false), (24, 26)),
            ((false, 2_000, true), (2, 5)),
            ((false, 10_000, false), (93, 95)),
            ((false, 10_000, true), (6, 9)),
        ];
        let mut moved = Vec::new();
        for (case, pinned) in cases {
            let (flowspec, tail, extended) = case;
            let limit = if extended { 65_535 } else { 4_096 };
            let (frames, builds) = pack_varying(flowspec, Sizes::Spike(tail), extended).await;
            let messages = frames.len();
            // Every frame repeats the attributes, so the bytes sent bound
            // the messages a perfect packing needs from above.
            let full = frames.iter().sum::<usize>().div_ceil(limit);
            assert!(
                messages <= full + full / 4 + 4,
                "{case:?}: {messages} messages where about {full} are full"
            );
            // Only the few messages around the large run are short. From
            // there the entries are one size, and every message but the
            // last is full to within an entry.
            let entry = if flowspec { 4 } else { 35 };
            let (_, sent_full) = frames.split_last().unwrap();
            let short = |frame: &&usize| limit - **frame >= entry;
            assert!(
                sent_full.iter().filter(short).count() <= 6
                    && (messages < 12
                        || !sent_full
                            .iter()
                            .skip(messages * 2 / 3)
                            .any(|frame| short(&frame))),
                "{case:?}: short messages away from the large run: {frames:?}"
            );
            assert!(
                builds <= 2 * messages + 4,
                "{case:?}: {builds} builds for {messages} messages"
            );
            if (messages, builds) != pinned {
                moved.push(format!("{case:?}: {:?}", (messages, builds)));
            }
        }
        assert!(moved.is_empty(), "packing moved:\n{}", moved.join("\n"));
    }

    /// A group whose every build fails ends in the teardown without walking
    /// a long group's chunk sizes down: the single-entry measurement is
    /// itself the unsendable entry. A short group, tried whole, halves.
    #[tokio::test]
    async fn a_group_that_cannot_be_built_tears_down_without_a_walk() {
        for (rows, expected) in [(SLICE, 1), (64, 7), (1, 1)] {
            let (mut session, _server, profile) =
                connected((Afi::Ipv4, Safi::FlowSpec), false, false).await;
            let mut builds = 0;
            let sent = session.send_mp_chunked(
                &vec![(); rows],
                profile.max_message_len(),
                "FlowSpec",
                "announcement",
                None,
                |_| {
                    builds += 1;
                    Err(rustbgpd_wire::EncodeError::ValueOutOfRange {
                        field: "test",
                        value: String::new(),
                    })
                },
            );
            assert_eq!(sent, Err(()));
            assert!(session.writer_bulk_tx.is_none(), "torn down");
            assert_eq!(builds, expected, "{rows} rows");
        }
    }
}
