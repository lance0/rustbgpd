//! Shared staged payloads and per-member delta emission for update groups.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use rustbgpd_policy::{NextHopAction, PolicyAction, PolicyEvaluation};
use rustbgpd_wire::{ExtendedCommunity, LargeCommunity, PathAttribute, Prefix, VpnRouteKey};
use rustc_hash::FxHashMap;

use super::{GroupRibOut, PolicyLabel, RtcMembership};
use crate::route::{Route, VpnRibRoute, VpnRibRouteKey};

/// One entry of a shared group staging pass: the new staged route (or a
/// withdrawal) for a `(prefix, path_id)` key, plus the source peer of
/// the entry it replaced — everything the source-flip matrix needs.
#[derive(Debug, Clone)]
pub(in crate::manager) struct GroupDelta {
    pub(in crate::manager) prefix: Prefix,
    pub(in crate::manager) path_id: u32,
    /// Newly staged post-policy route + its next-hop-override flag, or
    /// `None` for a withdrawal.
    pub(in crate::manager) new: Option<(Route, Option<NextHopAction>)>,
    /// Source peer of the group-table entry this delta replaces, read
    /// BEFORE commit. `None` = the key was not previously staged.
    pub(in crate::manager) old_source: Option<IpAddr>,
    /// Terminal policy of the permitting evaluation (`None` = inline /
    /// no chain). Retained on the staged entry so a later join can
    /// replay the member's export counters without re-running policy.
    pub(in crate::manager) policy_label: Option<PolicyLabel>,
    /// Pre-policy SOURCE attributes of an announce delta (`None` for a
    /// withdrawal, or when the source carries no communities). RFC 7947
    /// control decisions — per-target suppression and prepend — are
    /// made on the source route, exactly like the ungrouped path's
    /// pre-policy gate; only the scrub reads the post-policy `new`.
    pub(in crate::manager) source_attrs: Option<Arc<Vec<PathAttribute>>>,
    /// ADR-0126 Decision 5: the RECOMPUTED (post-pass) exception-lane
    /// entry for this delta's prefix, carried on per-client-best
    /// announce deltas so [`emit_group_deltas_for_member`] stays a
    /// self-contained free fn. The `member == source(w_new)` arm reads
    /// it directly: a member becoming the winner's source receives the
    /// runner-up substitution (or a withdraw when the lane is empty)
    /// instead of the shared announce. Always `None` for plain groups,
    /// for withdraw deltas (no winner ⇒ no runner-up), and for
    /// non-zero-path residue withdraws.
    pub(in crate::manager) lane: Option<RunnerUp>,
}

/// Capture a source route's attributes for RFC 7947 decisions at the
/// member-emit seams. `None` — no communities at all — keeps the
/// common case allocation-free (the capture itself is an `Arc` clone).
pub(in crate::manager) fn capture_source_attrs(source: &Route) -> Option<Arc<Vec<PathAttribute>>> {
    (!source.communities().is_empty() || !source.large_communities().is_empty())
        .then(|| Arc::clone(&source.attributes))
}

/// One staged runner-up of a per-client-best group (ADR-0126 Decision
/// 3): the exception lane's per-prefix payload — the same shape the
/// group table keeps per staged key: the post-policy route shell with
/// its source peer preserved, the next-hop-override residue, the
/// captured pre-policy SOURCE attributes, and the permitting
/// terminal-policy label for join-time counter replay.
#[derive(Debug, Clone)]
pub(in crate::manager) struct RunnerUp {
    pub(in crate::manager) route: Route,
    pub(in crate::manager) nh: Option<NextHopAction>,
    pub(in crate::manager) source_attrs: Option<Arc<Vec<PathAttribute>>>,
    pub(in crate::manager) policy_label: Option<PolicyLabel>,
    /// Source of the winner this entry substitutes for. Every ADR-0126
    /// Decision 5 lane arm is member-scoped "toward `source(w)`", and
    /// [`LaneDelta::old_source`] carries the old RUNNER-UP's source —
    /// without this field no emit, count, or replay seam could know
    /// which member the substitution targets.
    pub(in crate::manager) winner_source: IpAddr,
}

/// One slot of a member's derived advertised view — what
/// [`GroupRibOut::adv_entry`] resolves `adv(m)` to at one staged key:
/// the route on the member's wire plus the residue every read seam
/// fetches alongside it. Borrowed from the group: either the staged
/// table entry with its table residue, or the exception-lane
/// runner-up substituting for it with the lane's own payload.
pub(in crate::manager) struct AdvEntry<'a> {
    pub(in crate::manager) route: &'a Route,
    /// Next-hop-override residue for the slot.
    pub(in crate::manager) nh: Option<&'a NextHopAction>,
    /// Captured pre-policy SOURCE attributes (RFC 7947 rs-control
    /// decisions read these, never the post-policy route).
    pub(in crate::manager) source_attrs: Option<&'a Arc<Vec<PathAttribute>>>,
    /// Terminal policy label of the permitting evaluation (`None` =
    /// inline verdict) — join-time counter replay residue.
    pub(in crate::manager) policy_label: Option<&'a PolicyLabel>,
}

/// One exception-lane transition of a per-client-best staging pass
/// (ADR-0126 Decision 5): the newly staged runner-up (`None` when the
/// lane empties) plus the source of the lane entry it replaced — the
/// old RUNNER-UP's source, never the winner's (that is
/// [`RunnerUp::winner_source`]) — read BEFORE commit; the same
/// `(new, old_source)` shape as [`GroupDelta`]. Carried beside the
/// winner deltas so the lane-only case (runner-up flips or retires
/// while the winner is unchanged) has a first-class encoding, consumed
/// per member by [`emit_lane_deltas_for_member`].
#[derive(Debug, Clone)]
pub(in crate::manager) struct LaneDelta {
    pub(in crate::manager) prefix: Prefix,
    pub(in crate::manager) new: Option<RunnerUp>,
    pub(in crate::manager) old_source: Option<IpAddr>,
    /// The ONE member this transition emits toward, resolved at
    /// staging time (every Decision 5 lane arm is member-scoped
    /// "toward `source(w)`"): the new entry's [`RunnerUp::winner_source`]
    /// for an announce, the REPLACED entry's for a retire — which is
    /// how a retire knows its target after the lane emptied (the
    /// prior entry is read before commit). `None` when the same
    /// pass's winner announce delta supersedes the lane arm — its
    /// `member == source(w_new)` matrix arm already rewrites the
    /// target's slot from [`GroupDelta::lane`], so a lane emission on
    /// top would double-announce or compose announce+withdraw. The
    /// precedence: the winner-delta arms own every member slot they
    /// rewrite; the lane arm owns exactly the slots they skip
    /// (`source(w)` under an unchanged winner source, and the old
    /// `source(w)` on all-candidates-gone).
    pub(in crate::manager) emit_target: Option<IpAddr>,
    /// Captured source attributes of the REPLACED lane entry — the
    /// was-side input for rs-control verdict flips across the
    /// transition, mirroring [`RsTagTransition::prior_source_attrs`].
    pub(in crate::manager) prior_source_attrs: Option<Arc<Vec<PathAttribute>>>,
    /// The post-policy lane route is content-equal across the
    /// transition (`routes_equal`) — the transition was recorded only
    /// because the SOURCE control communities moved. The emit arm then
    /// mirrors [`emit_rs_tag_transitions`]: nothing toward a non-rs
    /// target (its wire form is unchanged — the per-peer path would
    /// equality-suppress), withdraw/re-announce toward an rs-control
    /// target exactly when its suppress/prepend verdict flips.
    pub(in crate::manager) content_unchanged: bool,
}

/// Outcome of one per-client-best group walk over a prefix (ADR-0126
/// Decision 2): the winner residue for the staged [`GroupDelta`] plus
/// the recomputed exception-lane content. The winner announce/withdraw
/// itself rides the caller's output vectors, like every other
/// distribution body.
#[derive(Default)]
pub(in crate::manager) struct PerClientBestPrefixStage {
    /// Terminal policy of the winner's permitting evaluation, captured
    /// at its own permit point: [`GroupEvalAccumulator::take_last`]
    /// returns the walk's LAST evaluation — the runner-up's permit or
    /// a trailing denial — never the winner's.
    pub(in crate::manager) winner_label: Option<PolicyLabel>,
    /// Captured pre-policy SOURCE attributes of the winner candidate.
    /// The first permitted candidate need not be the Loc-RIB best, so
    /// the caller cannot capture these from the Loc-RIB.
    pub(in crate::manager) winner_source_attrs: Option<Arc<Vec<PathAttribute>>>,
    /// The recomputed runner-up (`None` = lane empty), rebuilt from
    /// scratch every pass — no stale second-best by construction
    /// (ADR-0126 Decision 6).
    pub(in crate::manager) runner_up: Option<RunnerUp>,
}

/// Communities and large communities carried by a captured source
/// attribute list (empty slices when nothing was captured).
pub(in crate::manager) fn source_control_input(
    attrs: Option<&Arc<Vec<PathAttribute>>>,
) -> (&[u32], &[LargeCommunity]) {
    let Some(attrs) = attrs else {
        return (&[], &[]);
    };
    let communities = attrs
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::Communities(values) => Some(values.as_slice()),
            _ => None,
        })
        .unwrap_or(&[]);
    let large_communities = attrs
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::LargeCommunities(values) => Some(values.as_slice()),
            _ => None,
        })
        .unwrap_or(&[]);
    (communities, large_communities)
}

/// A tag-only transition staged by a pass: the post-policy route was
/// equality-suppressed against the group table (nothing changed on the
/// shared wire) while the SOURCE control communities changed — a
/// difference policy made invisible post-policy. Non-rs members see
/// nothing (their wire form is the unchanged staged route), but an
/// rs-control member's suppress/prepend verdict may flip, so these
/// ride next to the deltas through the per-member emit seam.
#[derive(Debug, Clone)]
pub(in crate::manager) struct RsTagTransition {
    pub(in crate::manager) prefix: Prefix,
    pub(in crate::manager) path_id: u32,
    /// The staged (post-policy) route, re-emitted toward members whose
    /// verdict flips to announce.
    pub(in crate::manager) route: Route,
    /// Next-hop-override residue for the staged entry.
    pub(in crate::manager) nh: Option<NextHopAction>,
    /// Captured source attributes before this pass.
    pub(in crate::manager) prior_source_attrs: Option<Arc<Vec<PathAttribute>>>,
    /// Captured source attributes after this pass.
    pub(in crate::manager) source_attrs: Option<Arc<Vec<PathAttribute>>>,
}

/// The `Arc`-shared unicast announce payload of one group staging pass:
/// the announce vector and its aligned next-hop-override flags, enqueued
/// per member by `Arc` clone.
pub(in crate::manager) type SharedUnicastPayload = (
    std::sync::Arc<[Route]>,
    std::sync::Arc<[Option<NextHopAction>]>,
);

/// Immutable old-to-new inventory for the strict clean policy-transition
/// path. The route shells and aligned next-hop decisions are materialized once
/// for the whole cohort; transport excludes each target's own source.
pub(in crate::manager) struct CleanPolicyTransitionInventory {
    pub(in crate::manager) announce: std::sync::Arc<[Route]>,
    pub(in crate::manager) next_hop_override: std::sync::Arc<[Option<NextHopAction>]>,
    /// Destination-group permit verdicts, aggregated once for counter replay.
    pub(in crate::manager) permit_totals: HashMap<Option<String>, u64>,
    /// The subset of each aggregate sourced by one peer. Split-horizon
    /// excludes these verdicts from that peer's counter replay.
    pub(in crate::manager) permit_by_source: HashMap<IpAddr, HashMap<Option<String>, u64>>,
}

/// Pre-emission inventory accumulated by the actor-owned clean transition.
/// The builder is private to that transaction and never represents committed
/// peer-visible state.
#[derive(Default)]
pub(in crate::manager) struct CleanPolicyTransitionInventoryBuilder {
    pub(super) announce: Vec<Route>,
    pub(super) next_hop_override: Vec<Option<NextHopAction>>,
    pub(super) permit_totals: HashMap<Option<String>, u64>,
    pub(super) permit_by_source: HashMap<IpAddr, HashMap<Option<String>, u64>>,
}

impl CleanPolicyTransitionInventoryBuilder {
    pub(in crate::manager) fn finish(self) -> CleanPolicyTransitionInventory {
        CleanPolicyTransitionInventory {
            announce: self.announce.into(),
            next_hop_override: self.next_hop_override.into(),
            permit_totals: self.permit_totals,
            permit_by_source: self.permit_by_source,
        }
    }
}

pub(in crate::manager) enum PolicyTransitionGroupStart {
    Maintained,
    Created(Vec<Prefix>),
}

/// Result of one shared staging pass over a group: the deltas (already
/// committed to the group table), the accumulated export-policy
/// verdicts for per-member counter replay, and the pre-built SHARED
/// per-member emission (design §9 / slice 4).
///
/// The shared emission is the source-flip matrix output for any member
/// that is neither the new source nor the displaced old source of any
/// delta — the overwhelming majority in an RR fanout. Those members
/// enqueue `Arc` clones of ONE announce/nh-flag vector (zero `Route`
/// shell copies per member); the exception members (`exceptions`) fall
/// back to the per-member matrix walk.
#[derive(Default)]
pub(in crate::manager) struct GroupStageOutput {
    pub(in crate::manager) deltas: Vec<GroupDelta>,
    pub(in crate::manager) evals: GroupEvalAccumulator,
    /// RFC 9234 denials from this staging pass, replayed per member for
    /// transport's existing metric/event diagnostics.
    pub(in crate::manager) otc_blocked: Vec<Route>,
    /// Announce payload for non-exception members, built once per pass.
    pub(in crate::manager) shared_announce: std::sync::Arc<[Route]>,
    /// Next-hop-override flags aligned with `shared_announce`.
    pub(in crate::manager) shared_nh: std::sync::Arc<[Option<NextHopAction>]>,
    /// Withdraw keys for non-exception members.
    pub(in crate::manager) shared_withdraw: Vec<(Prefix, u32)>,
    /// Tag-only transitions of this pass ([`RsTagTransition`]): keys
    /// whose staged route was equality-suppressed while the source
    /// control communities changed. Deliberately outside the shared
    /// emission — only rs-control members act on them.
    pub(in crate::manager) rs_transitions: Vec<RsTagTransition>,
    /// Exception-lane transitions of this pass ([`LaneDelta`]) —
    /// per-client-best groups only, always empty for plain groups.
    /// Deliberately outside `deltas` and the shared emission: exactly
    /// one member acts on a lane transition (its
    /// [`LaneDelta::emit_target`]), via
    /// [`emit_lane_deltas_for_member`] in the per-member walk.
    pub(in crate::manager) lane_deltas: Vec<LaneDelta>,
    /// Members whose emission differs from the shared one: the new
    /// source of an announce delta (announce → substitution/withdraw),
    /// the old source of a withdraw delta (withdraw → skip/lane
    /// withdraw), or a consumed lane transition's `emit_target`
    /// (member-scoped emission the shared payload does not carry).
    pub(super) exceptions: HashSet<IpAddr>,
}

impl GroupStageOutput {
    /// Keys withdrawn by this pass — the tombstone contribution when a
    /// member is (or goes) dirty.
    pub(in crate::manager) fn withdrawn_keys(&self) -> impl Iterator<Item = (Prefix, u32)> + '_ {
        self.deltas
            .iter()
            .filter(|d| d.new.is_none())
            .map(|d| (d.prefix, d.path_id))
    }

    /// Whether the pre-built shared emission is exactly this member's
    /// source-flip matrix output.
    pub(in crate::manager) fn shared_applies_to(&self, member: IpAddr) -> bool {
        !self.exceptions.contains(&member)
    }

    /// Whether this pass carries a control-form community for `rs_asn`
    /// (LAN-474). A pass with none — the overwhelming majority — lets
    /// `rs_control_communities` members ride the shared emission
    /// untouched; a tagged pass drops them to the per-member matrix
    /// walk where suppression/prepend/scrub diverge per target. Tagged
    /// on EITHER side of policy: source tags drive suppress/prepend,
    /// post-policy tags need scrubbing; a tag-only transition counts on
    /// either side of the pass. Callers memoize per (group, `rs_asn`).
    pub(in crate::manager) fn has_tagged_route(&self, rs_asn: u32) -> bool {
        use crate::manager::distribution::rs_control::rs_control_route_tagged;
        let attrs_tagged = |attrs: Option<&Arc<Vec<PathAttribute>>>| {
            let (communities, large_communities) = source_control_input(attrs);
            rs_control_route_tagged(communities, large_communities, rs_asn)
        };
        self.deltas.iter().any(|delta| {
            delta.new.as_ref().is_some_and(|(route, _)| {
                attrs_tagged(delta.source_attrs.as_ref())
                    || rs_control_route_tagged(
                        route.communities(),
                        route.large_communities(),
                        rs_asn,
                    )
            })
        }) || self.rs_transitions.iter().any(|transition| {
            attrs_tagged(transition.prior_source_attrs.as_ref())
                || attrs_tagged(transition.source_attrs.as_ref())
        }) || self.lane_deltas.iter().any(|delta| {
            // ADR-0126: a tagged lane source must push `source(w)`
            // onto the per-member walk — the substituted announce
            // applies suppress/prepend/scrub from the LANE entry's
            // source attributes, which the shared payload cannot.
            delta.new.as_ref().is_some_and(|entry| {
                attrs_tagged(entry.source_attrs.as_ref())
                    || rs_control_route_tagged(
                        entry.route.communities(),
                        entry.route.large_communities(),
                        rs_asn,
                    )
            })
        })
    }

    /// Member-scoped withdraw keys of this pass that [`Self::withdrawn_keys`]
    /// (the tombstone feed) never records, recorded into the member's
    /// extra (over-)withdraws when its emission is lost to a full
    /// channel:
    ///
    /// - the source-flip arm — the member is the delta's NEW source
    ///   and the displaced entry was another peer's, so the key stays
    ///   IN the group table. Under per-client-best the member's lost
    ///   emission may actually have been a substituted ANNOUNCE
    ///   ([`GroupDelta::lane`]) — or a genuine withdraw when the
    ///   substitution is rs-suppressed toward it, a per-member verdict
    ///   this method cannot see — so the key is recorded
    ///   unconditionally: the resync's `member_retains` guard (routed
    ///   through [`GroupRibOut::adv_entry`]) drops it exactly when the
    ///   lane still substitutes, and the resync substitution announces
    ///   `adv(m)` in its place;
    /// - the ADR-0126 lane-retire arm — a retire toward its
    ///   [`LaneDelta::emit_target`]: the target's wire held the
    ///   substitution while the key stays IN the table, so the retire
    ///   withdraw is invisible to the tombstone feed. A superseded
    ///   retire (`emit_target` = None) needs no record — its target's
    ///   slot is owned by a winner delta this pass, whose own arms
    ///   (above, or the tombstone feed) cover the loss.
    ///
    /// Lost member-scoped ANNOUNCES (a lane flip or a substitution)
    /// leave no residue on purpose: announces are idempotent and the
    /// dirty resync re-derives them from `adv(m)`.
    pub(in crate::manager) fn member_scoped_withdraws(
        &self,
        member: IpAddr,
    ) -> impl Iterator<Item = (Prefix, u32)> + '_ {
        self.deltas
            .iter()
            .filter_map(move |delta| {
                (delta
                    .new
                    .as_ref()
                    .is_some_and(|(route, _)| route.peer == member)
                    && delta.old_source.is_some_and(|source| source != member))
                .then_some((delta.prefix, delta.path_id))
            })
            .chain(self.lane_deltas.iter().filter_map(move |delta| {
                (delta.new.is_none() && delta.emit_target == Some(member))
                    .then_some((delta.prefix, 0))
            }))
    }

    /// Build the shared emission from the committed deltas (one `Route`
    /// shell clone per delta, TOTAL — not per member).
    pub(super) fn build_shared_emit(&mut self) {
        let mut announce: Vec<Route> = Vec::new();
        let mut nh: Vec<Option<NextHopAction>> = Vec::new();
        for delta in &self.deltas {
            if let Some((route, flag)) = &delta.new {
                self.exceptions.insert(route.peer);
                nh.push(flag.clone());
                announce.push(route.clone());
            } else {
                if let Some(source) = delta.old_source {
                    self.exceptions.insert(source);
                }
                self.shared_withdraw.push((delta.prefix, delta.path_id));
            }
        }
        // A consumed lane transition emits toward its target alone —
        // the shared payload carries nothing for it, so the target
        // must take the per-member walk (ADR-0126 Decision 5). A
        // superseded transition (`emit_target` = None) needs no entry:
        // its target is either the winner announce's `route.peer`
        // (inserted above) or exactly served by the shared payload
        // (the flip-away arm announces `w'` to it).
        for delta in &self.lane_deltas {
            if let Some(target) = delta.emit_target {
                self.exceptions.insert(target);
            }
        }
        self.shared_announce = announce.into();
        self.shared_nh = nh.into();
    }
}

/// Shared old→new wire delta of one batched authoritative cohort
/// transition ([`RibManager::batched_transition_inventory`](super::RibManager::batched_transition_inventory)):
/// the
/// equality-suppressed announce/withdraw payload every member shares
/// (split horizon via `announce_source_exclusion`), the member-scoped
/// lane/source-flip corrections, and the pre-aggregated counter rows.
pub(in crate::manager) struct BatchedTransitionInventory {
    /// Destination entries whose wire form differs from the source
    /// entry at the same key — `Arc`-shared across every member
    /// envelope (one `Route` shell clone per changed entry, total).
    pub(in crate::manager) announce: Arc<[Route]>,
    /// Next-hop-override flags aligned with `announce`.
    pub(in crate::manager) next_hop_override: Arc<[Option<NextHopAction>]>,
    /// Keys the destination no longer stages (over-withdraw safe).
    pub(in crate::manager) withdraw: Vec<(Prefix, u32)>,
    /// Member-scoped corrections the shared exclusion cannot express:
    /// the ADR-0126 lane substitution toward each winner's source
    /// (announce) and the displaced/retired own-sourced slot (withdraw).
    pub(in crate::manager) supplements: FxHashMap<IpAddr, BatchedMemberSupplement>,
    pub(super) counters: BatchedTransitionCounters,
}

/// One member's corrections beside the shared batched-transition payload.
#[derive(Default)]
pub(in crate::manager) struct BatchedMemberSupplement {
    pub(in crate::manager) announce: Vec<(Route, Option<NextHopAction>)>,
    pub(in crate::manager) withdraw: Vec<(Prefix, u32)>,
}

/// Pre-aggregated export-counter rows of one batched cohort transition:
/// permit totals per label with per-source breakdown, the lane's
/// per-winner-source substitution labels, and the denial residue rows —
/// the inputs of the ADR-0126 Decision 4 `totals − own + lane`
/// synthesis, folded once per cohort so the per-member replay is
/// O(labels) instead of the O(table) walk
/// [`RibManager::apply_group_join_counters`](super::RibManager::apply_group_join_counters)
/// performs.
#[derive(Default)]
pub(super) struct BatchedTransitionCounters {
    pub(super) permit_totals: FxHashMap<Option<PolicyLabel>, u64>,
    pub(super) permit_by_source: FxHashMap<IpAddr, FxHashMap<Option<PolicyLabel>, u64>>,
    pub(super) lane_by_winner_source: FxHashMap<IpAddr, FxHashMap<Option<PolicyLabel>, u64>>,
    pub(super) deny_totals: FxHashMap<Option<PolicyLabel>, u64>,
    pub(super) deny_by_source: FxHashMap<IpAddr, FxHashMap<Option<PolicyLabel>, u64>>,
}

impl BatchedTransitionCounters {
    pub(super) fn record_permit(&mut self, source: IpAddr, label: Option<PolicyLabel>) {
        *self
            .permit_by_source
            .entry(source)
            .or_default()
            .entry(label.clone())
            .or_default() += 1;
        *self.permit_totals.entry(label).or_default() += 1;
    }

    pub(super) fn record_lane(&mut self, winner_source: IpAddr, label: Option<PolicyLabel>) {
        *self
            .lane_by_winner_source
            .entry(winner_source)
            .or_default()
            .entry(label)
            .or_default() += 1;
    }

    pub(super) fn record_deny(&mut self, source: IpAddr, label: Option<PolicyLabel>) {
        *self
            .deny_by_source
            .entry(source)
            .or_default()
            .entry(label.clone())
            .or_default() += 1;
        *self.deny_totals.entry(label).or_default() += 1;
    }

    /// One member's replay rows: `totals − own-sourced (+ lane
    /// substitutions)` per label, permits and denials alike — the fold
    /// [`RibManager::apply_group_join_counters`](super::RibManager::apply_group_join_counters)
    /// derives per member from
    /// a full table walk.
    pub(super) fn rows_for(&self, peer: IpAddr) -> Vec<(Option<String>, PolicyAction, u64)> {
        let mut rows = Vec::new();
        let own_permits = self.permit_by_source.get(&peer);
        let lane = self.lane_by_winner_source.get(&peer);
        let mut labels: Vec<&Option<PolicyLabel>> = self.permit_totals.keys().collect();
        if let Some(lane) = lane {
            labels.extend(
                lane.keys()
                    .filter(|label| !self.permit_totals.contains_key(*label)),
            );
        }
        for label in labels {
            let total = self.permit_totals.get(label).copied().unwrap_or(0);
            let own = own_permits
                .and_then(|counts| counts.get(label))
                .copied()
                .unwrap_or(0);
            let substituted = lane
                .and_then(|counts| counts.get(label))
                .copied()
                .unwrap_or(0);
            let count = total.saturating_sub(own) + substituted;
            if count > 0 {
                rows.push((
                    label.as_ref().map(ToString::to_string),
                    PolicyAction::Permit,
                    count,
                ));
            }
        }
        let own_denies = self.deny_by_source.get(&peer);
        for (label, total) in &self.deny_totals {
            let own = own_denies
                .and_then(|counts| counts.get(label))
                .copied()
                .unwrap_or(0);
            let count = total.saturating_sub(own);
            if count > 0 {
                rows.push((
                    label.as_ref().map(ToString::to_string),
                    PolicyAction::Deny,
                    count,
                ));
            }
        }
        rows
    }
}

/// Export-policy verdicts of one shared staging pass, aggregated by
/// (terminal policy, action) with a per-source-peer breakdown so each
/// member can be bumped by `totals − own-sourced` — exactly what the
/// per-peer path would have recorded (split horizon skips the eval for
/// the route's own source). Integer adds only; no per-(prefix × peer)
/// prometheus lookups (design §6).
#[derive(Default)]
pub(in crate::manager) struct GroupEvalAccumulator {
    pub(super) totals: Vec<(Option<PolicyLabel>, PolicyAction, u64)>,
    pub(super) per_source: FxHashMap<IpAddr, Vec<(Option<PolicyLabel>, PolicyAction, u64)>>,
    /// Verdict (and source peer) of the most recent evaluation, consumed
    /// per key by the staging loops to label the staged entry / denial
    /// residue (single-best stages at most one eval per key).
    pub(super) last: Option<(Option<PolicyLabel>, PolicyAction, IpAddr)>,
}

pub(super) fn bump_eval_row(
    rows: &mut Vec<(Option<PolicyLabel>, PolicyAction, u64)>,
    policy: Option<&PolicyLabel>,
    action: PolicyAction,
) {
    if let Some((_, _, n)) = rows
        .iter_mut()
        .find(|(p, a, _)| *a == action && p.as_ref() == policy)
    {
        *n += 1;
    } else {
        rows.push((policy.cloned(), action, 1));
    }
}

/// Materialize a policy label only at the peer-counter boundary. Group
/// staging itself retains `PolicyLabel` handles, but telemetry's keyed rows
/// own their strings after the shared pass is complete.
pub(super) fn bump_counter_row(
    rows: &mut Vec<(Option<String>, PolicyAction, u64)>,
    policy: Option<&PolicyLabel>,
    action: PolicyAction,
) {
    if let Some((_, _, n)) = rows
        .iter_mut()
        .find(|(p, a, _)| *a == action && p.as_deref() == policy.map(AsRef::as_ref))
    {
        *n += 1;
    } else {
        rows.push((policy.map(ToString::to_string), action, 1));
    }
}

impl GroupEvalAccumulator {
    /// Record one chain evaluation for the route sourced by `source`.
    pub(in crate::manager) fn record(&mut self, evaluation: &PolicyEvaluation, source: IpAddr) {
        bump_eval_row(
            &mut self.totals,
            evaluation.matched_policy.as_ref(),
            evaluation.action,
        );
        bump_eval_row(
            self.per_source.entry(source).or_default(),
            evaluation.matched_policy.as_ref(),
            evaluation.action,
        );
        self.last = Some((evaluation.matched_policy.clone(), evaluation.action, source));
    }

    /// Take (and clear) the last recorded verdict — the staging loop's
    /// per-key label / denial-residue hook.
    pub(super) fn take_last(&mut self) -> Option<(Option<PolicyLabel>, PolicyAction, IpAddr)> {
        self.last.take()
    }
}

/// Per-member emit for one shared staging pass — the source-flip matrix
/// (design §3). Announce / withdraw / skip is decided per delta entry
/// from `(member == new source, member == old source, lane)` alone:
///
/// | entry             | member == `new.peer`                                                          | member == `old_source`                       | else     |
/// |-------------------|-------------------------------------------------------------------------------|----------------------------------------------|----------|
/// | announce (`Some`) | `old_source` = member → skip (lane arms own the slot); else lane → announce `r`; else old exists → withdraw | announce (member was excluded, now eligible) | announce |
/// | withdraw (`None`) | —                                                                             | skip (lane retire arm owns the slot)         | withdraw |
///
/// The `member == new.peer` column is the ADR-0126 Decision 5 arm: a
/// member BECOMING the winner's source has its slot rewritten here —
/// announce the runner-up substitution ([`GroupDelta::lane`], an
/// implicit replace at `path_id 0`) when the lane holds one, withdraw
/// the displaced other-sourced entry otherwise. A member that ALREADY
/// was the source (`old_source` = member) holds the lane substitution,
/// which transitions only with the lane — its emissions ride
/// [`emit_lane_deltas_for_member`] (same for the retiring source of a
/// withdraw delta, whose lane-retire withdraw rides the same arm).
/// For a plain group `lane` is always `None`, reducing every cell to
/// the historical matrix above it.
///
/// `nh_override_flags` stays aligned with `announce` by pushing in the
/// same arm. A free function so the risk-2 unit matrix can drive it
/// directly.
///
/// `rs_control` is `(rs_asn, member_asn)` for an
/// `rs_control_communities` member (LAN-474): a route whose SOURCE
/// control communities (`GroupDelta::source_attrs` — captured
/// pre-policy, like the ungrouped path's gate) suppress it toward this
/// member emits a withdraw of whatever other-sourced entry the member
/// may hold (over-withdraw is the safe direction), and an announced
/// route is rewritten per target — prepend decided on the source,
/// scrub on the post-policy route. `None` — or an untagged source and
/// route — is byte-identical to the shared emission.
pub(in crate::manager) fn emit_group_deltas_for_member(
    deltas: &[GroupDelta],
    member: IpAddr,
    rs_control: Option<(u32, u32)>,
    announce: &mut Vec<Route>,
    withdraw: &mut Vec<(Prefix, u32)>,
    nh_override_flags: &mut Vec<Option<NextHopAction>>,
) {
    use crate::manager::distribution::rs_control::{
        rs_control_route_rewrite, rs_control_suppressed,
    };
    for delta in deltas {
        match &delta.new {
            Some((route, nh)) => {
                let (source_communities, source_large_communities) =
                    source_control_input(delta.source_attrs.as_ref());
                if route.peer == member {
                    // Split horizon applied at emit: the new best is
                    // the member's own route.
                    if delta.old_source == Some(member) {
                        // The member already was the source: its wire
                        // holds the lane substitution (or nothing),
                        // which moves only with the lane — the
                        // LaneDelta arms own this slot.
                    } else if let Some(entry) = &delta.lane {
                        // ADR-0126 Decision 5: the member becoming
                        // `source(w)` receives the runner-up — an
                        // implicit replace of whatever other-sourced
                        // entry its wire held. rs-control decides on
                        // the LANE entry's source attributes.
                        let (lane_communities, lane_large_communities) =
                            source_control_input(entry.source_attrs.as_ref());
                        if rs_control_suppressed(
                            lane_communities,
                            lane_large_communities,
                            rs_control,
                        ) {
                            if delta.old_source.is_some() {
                                withdraw.push((delta.prefix, delta.path_id));
                            }
                        } else {
                            let mut route = entry.route.clone();
                            rs_control_route_rewrite(
                                &mut route,
                                lane_large_communities,
                                rs_control,
                            );
                            nh_override_flags.push(entry.nh.clone());
                            announce.push(route);
                        }
                    } else if delta.old_source.is_some() {
                        // Empty lane: the member previously held a
                        // different source's advertisement for this
                        // key — withdraw it (per-peer semantics: best
                        // == target ⇒ withdraw existing). Absent old
                        // entry ⇒ the member never had it — skip.
                        withdraw.push((delta.prefix, delta.path_id));
                    }
                } else if rs_control_suppressed(
                    source_communities,
                    source_large_communities,
                    rs_control,
                ) {
                    // RFC 7947 §2.3.2 per-target suppression: same
                    // matrix shape as the split-horizon arm — displace
                    // whatever other-sourced entry the member may hold.
                    if delta.old_source.is_some_and(|source| source != member) {
                        withdraw.push((delta.prefix, delta.path_id));
                    }
                } else {
                    let mut route = route.clone();
                    rs_control_route_rewrite(&mut route, source_large_communities, rs_control);
                    nh_override_flags.push(nh.clone());
                    announce.push(route);
                }
            }
            None => {
                // A member never receives its own-sourced entries, so a
                // withdrawal of one is a no-op for it (and a withdraw
                // delta with no old entry — unreachable by construction
                // — would be a no-op for everyone). A per-client-best
                // old source whose wire held the lane substitution gets
                // its withdraw from the lane-retire arm
                // (`emit_lane_deltas_for_member`) — all-candidates-gone
                // recomputes the lane empty, which always records the
                // retire when an entry existed.
                if delta.old_source.is_some_and(|source| source != member) {
                    withdraw.push((delta.prefix, delta.path_id));
                }
            }
        }
    }
}

/// Per-member emit for a pass's exception-lane transitions (ADR-0126
/// Decision 5, the lane arm): each [`LaneDelta`] is member-scoped —
/// it emits toward its [`LaneDelta::emit_target`] (`source(w)`) alone
/// and toward nobody else. Announce the new runner-up `r'` (an
/// implicit replace at `path_id 0`, with its next-hop flag) or
/// withdraw `(prefix, 0)` on a retire. A transition whose winner
/// announce delta superseded it (`emit_target` = None — the
/// winner-delta arms already rewrote the target's slot) emits
/// nothing here; the exhaustive steady-state matrix proves no
/// double-announce or announce+withdraw composition escapes.
///
/// rs-control divergence applies from the LANE entry's source
/// attributes: a suppressed substitution withdraws whatever the
/// target's wire held (over-withdraw is the safe direction, as in the
/// winner matrix), and a content-equal tag-only transition
/// ([`LaneDelta::content_unchanged`]) mirrors
/// [`emit_rs_tag_transitions`] — nothing toward a non-rs target,
/// withdraw/re-announce toward an rs target exactly on a
/// suppress/prepend verdict flip. A no-op for every member other
/// than the target, and for plain groups (no lane deltas exist).
pub(in crate::manager) fn emit_lane_deltas_for_member(
    lane_deltas: &[LaneDelta],
    member: IpAddr,
    rs_control: Option<(u32, u32)>,
    announce: &mut Vec<Route>,
    withdraw: &mut Vec<(Prefix, u32)>,
    nh_override_flags: &mut Vec<Option<NextHopAction>>,
) {
    use crate::manager::distribution::rs_control::{
        rs_control_prepend_count, rs_control_route_rewrite, rs_control_suppressed,
    };
    for delta in lane_deltas {
        if delta.emit_target != Some(member) {
            continue;
        }
        match &delta.new {
            Some(entry) => {
                let (communities, large_communities) =
                    source_control_input(entry.source_attrs.as_ref());
                let now = rs_control_suppressed(communities, large_communities, rs_control);
                if delta.content_unchanged {
                    // Tag-only transition: the target's wire form is
                    // unchanged unless its rs-control verdict flips.
                    let (prior_communities, prior_large_communities) =
                        source_control_input(delta.prior_source_attrs.as_ref());
                    let was = rs_control_suppressed(
                        prior_communities,
                        prior_large_communities,
                        rs_control,
                    );
                    if now {
                        if !was {
                            withdraw.push((delta.prefix, 0));
                        }
                    } else if was
                        || rs_control.is_some_and(|(rs_asn, member_asn)| {
                            rs_control_prepend_count(prior_large_communities, rs_asn, member_asn)
                                != rs_control_prepend_count(large_communities, rs_asn, member_asn)
                        })
                    {
                        let mut route = entry.route.clone();
                        rs_control_route_rewrite(&mut route, large_communities, rs_control);
                        nh_override_flags.push(entry.nh.clone());
                        announce.push(route);
                    }
                } else if now {
                    // Suppressed substitution: displace whatever the
                    // target's wire held (its old runner-up).
                    if delta.old_source.is_some() {
                        withdraw.push((delta.prefix, 0));
                    }
                } else {
                    let mut route = entry.route.clone();
                    rs_control_route_rewrite(&mut route, large_communities, rs_control);
                    nh_override_flags.push(entry.nh.clone());
                    announce.push(route);
                }
            }
            None => {
                // Retire: an entry existed (a retire transition is
                // recorded only when one did), and the target's wire
                // held it at the path-id-free slot.
                withdraw.push((delta.prefix, 0));
            }
        }
    }
}

/// Per-member emit for a pass's tag-only transitions
/// ([`RsTagTransition`]): the old/new source verdicts decide the
/// member's exact stream delta — withdraw when suppression turns on,
/// re-announce (rewritten) when it turns off or the prepend count
/// changes, nothing otherwise — matching what the per-peer path's
/// restage + Adj-RIB-Out diff would emit. A no-op for members without
/// `rs_control_communities`: their wire form is the unchanged staged
/// route.
pub(in crate::manager) fn emit_rs_tag_transitions(
    transitions: &[RsTagTransition],
    member: IpAddr,
    rs_control: Option<(u32, u32)>,
    announce: &mut Vec<Route>,
    withdraw: &mut Vec<(Prefix, u32)>,
    nh_override_flags: &mut Vec<Option<NextHopAction>>,
) {
    use crate::manager::distribution::rs_control::{
        rs_control_prepend_count, rs_control_route_rewrite, rs_control_suppressed,
    };
    let Some((rs_asn, member_asn)) = rs_control else {
        return;
    };
    for transition in transitions {
        if transition.route.peer == member {
            continue;
        }
        let (old_communities, old_large) =
            source_control_input(transition.prior_source_attrs.as_ref());
        let (new_communities, new_large) = source_control_input(transition.source_attrs.as_ref());
        let was = rs_control_suppressed(old_communities, old_large, rs_control);
        let now = rs_control_suppressed(new_communities, new_large, rs_control);
        if now {
            if !was {
                withdraw.push((transition.prefix, transition.path_id));
            }
        } else if was
            || rs_control_prepend_count(old_large, rs_asn, member_asn)
                != rs_control_prepend_count(new_large, rs_asn, member_asn)
        {
            let mut route = transition.route.clone();
            rs_control_route_rewrite(&mut route, new_large, rs_control);
            nh_override_flags.push(transition.nh.clone());
            announce.push(route);
        }
    }
}

/// A persistent group-verdict VPN denial: (source peer, denying policy
/// label, the denied route's extended communities — the Φ gate input
/// for an RTC member's join-time counter replay).
pub(super) type VpnDenialRecord = (IpAddr, Option<PolicyLabel>, Vec<ExtendedCommunity>);

/// One entry of a shared group VPN staging pass. Unlike the unicast
/// [`GroupDelta`] this carries the full displaced route (`old`), not just
/// its source: the RT-pass matrix needs the displaced entry's extended
/// communities to decide `had` per member (design §2.1). `path_id` is
/// fixed at 0 — Add-Path send disqualifies from grouping.
#[derive(Debug, Clone)]
pub(in crate::manager) struct VpnGroupDelta {
    pub(in crate::manager) key: VpnRouteKey,
    /// Newly staged post-policy route (source-faithful, ADR-0077 §6), or
    /// `None` for a withdrawal.
    pub(in crate::manager) new: Option<VpnRibRoute>,
    /// Prior staged entry for the key, cloned before commit (one clone
    /// per delta, total). `None` = the key was not previously staged.
    pub(in crate::manager) old: Option<VpnRibRoute>,
    /// Terminal policy of the permitting evaluation — join-time counter
    /// replay residue, exactly like [`GroupDelta::policy_label`].
    pub(in crate::manager) policy_label: Option<PolicyLabel>,
}

/// Result of one shared VPN staging pass over a group: deltas (already
/// committed to the group table) plus the accumulated export-policy
/// verdicts for per-member counter replay. No shared-`Arc` payload — the
/// outbound envelope's VPN queue is a `Vec`, so members clone per route
/// either way; the receipt-proven win is collapsing the *staging* (policy
/// eval + suppression per peer), not the emit clones.
#[derive(Default)]
pub(in crate::manager) struct VpnGroupStageOutput {
    pub(in crate::manager) deltas: Vec<VpnGroupDelta>,
    pub(in crate::manager) evals: GroupEvalAccumulator,
}

impl VpnGroupStageOutput {
    /// Member-scoped withdraw keys of this pass that the VPN tombstone
    /// feed (deltas with `new == None`) never records: `had ∧ ¬gets`
    /// entries whose delta still holds a staged route — a source flip
    /// ONTO the member, or a route mutating out of its Φ — so the
    /// member's emission is a withdraw while the key stays IN the group
    /// table. Recorded into the member's extra (over-)withdraws when
    /// its emission is lost to a full channel.
    pub(in crate::manager) fn member_scoped_withdraws<'a>(
        &'a self,
        member: IpAddr,
        filter: Option<&'a RtcMembership>,
    ) -> impl Iterator<Item = VpnRouteKey> + 'a {
        self.deltas.iter().filter_map(move |delta| {
            let had = delta
                .old
                .as_ref()
                .is_some_and(|old| old.peer != member && rt_passes(filter, old));
            let gets = delta
                .new
                .as_ref()
                .is_some_and(|new| new.peer != member && rt_passes(filter, new));
            (delta.new.is_some() && had && !gets).then_some(delta.key)
        })
    }
}

/// Whether a staged VPN route passes a member's RFC 4684 RT filter:
/// no filter (SAFI 132 not negotiated — group-uniform via the key), or
/// any of the route's extended communities falls inside the membership.
/// REUSES [`RtcMembership::matches_any`] — the one implementation of
/// RTC matching semantics (design §2.2: there is no second copy of the
/// 96-bit covering-prefix core to drift).
pub(in crate::manager) fn rt_passes(filter: Option<&RtcMembership>, route: &VpnRibRoute) -> bool {
    filter.is_none_or(|membership| membership.matches_any(route.extended_communities()))
}

/// Per-member VPN emit for one shared staging pass — the design §2.2
/// RT-pass source-flip matrix (`pass_m` = no filter ∨
/// `Φ_m.matches_any`; a non-RTC group passes `None` = the slice-1
/// degenerate `pass ≡ true` case):
///
/// - `had`  = `old` exists ∧ `old.peer ≠ member` ∧ `pass_m(old)`
/// - `gets` = `new` exists ∧ `new.peer ≠ member` ∧ `pass_m(new)`
/// - emit: `gets` → announce `new`; `had ∧ ¬gets` → withdraw `(key, 0)`;
///   else skip.
///
/// Returns the member's net advertised-count delta per VPN family slot
/// `[vpnv4, vpnv6]` (`gets ∧ ¬had` = +1, `had ∧ ¬gets` = −1) — the
/// incremental input for the per-member counters an RT filter makes
/// non-derivable from the group's source counts (design §2.4).
pub(in crate::manager) fn emit_vpn_group_deltas_for_member(
    deltas: &[VpnGroupDelta],
    member: IpAddr,
    filter: Option<&RtcMembership>,
    vpn_announce: &mut Vec<VpnRibRoute>,
    vpn_withdraw: &mut Vec<VpnRibRouteKey>,
) -> [i64; 2] {
    let mut count_delta = [0i64; 2];
    for delta in deltas {
        let had = delta
            .old
            .as_ref()
            .is_some_and(|old| old.peer != member && rt_passes(filter, old));
        let gets = delta
            .new
            .as_ref()
            .is_some_and(|new| new.peer != member && rt_passes(filter, new));
        let slot = GroupRibOut::vpn_count_slot(&delta.key) - 2;
        if gets {
            vpn_announce.push(delta.new.clone().expect("gets implies new exists"));
            if !had {
                count_delta[slot] += 1;
            }
        } else if had {
            vpn_withdraw.push(VpnRibRouteKey {
                nlri_key: delta.key,
                path_id: 0,
            });
            count_delta[slot] -= 1;
        }
    }
    count_delta
}
