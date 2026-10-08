# ADR-0137: Conditional advertisement

**Status:** Accepted
**Date:** 2026-10-07

## Context

Conditional advertisement sends a set of routes to a peer only while a
condition route is present (advertise-if-present, FRR `exist-map`), or only
while it is absent (advertise-if-absent, FRR `non-exist-map`). The usual
deployment is a backup edge: announce a backup aggregate to one upstream only
while the primary upstream's default route is gone, or announce a prefix only
while the route proving its reachability exists. The roadmap listed it under
"Later"; this record proposes it as an opt-in policy feature for IPv4 and IPv6
unicast.

### Reference semantics

The comparison uses the pinned interop version of FRR, 10.7.1
(`frr-10.7.1`, commit `f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1`), and GoBGP
v4.10.0 (commit `da824d99912e02124b53741245ee4186c381adcc`).

**GoBGP v4.10.0 has no conditional advertisement.** A search of the release tree
for `conditional`, `exist-map`, `advertise-map`, `non-exist`, and
`ConditionalAdvertisement` finds only unrelated text, such as "unconditionally"
in capability code. No API, protobuf, or documentation entry exists. Every
[GoBGP policy condition](https://github.com/osrg/gobgp/blob/v4.10.0/internal/pkg/table/policy.go#L160-L177)
evaluates the path being filtered. None tests whether another route exists in
the RIB. The roadmap entry that said GoBGP implements the feature was wrong and
is corrected with this record.

FRR implements it as `neighbor X advertise-map A exist-map|non-exist-map C`
([CLI](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_vty.c#L24264-L24274),
[user documentation](https://github.com/FRRouting/frr/blob/frr-10.7.1/doc/user/bgp.rst#L4437-L4480)).
Its observable semantics are:

| Question | FRR 10.7.1 behavior |
|----------|---------------------|
| Trigger and period | A periodic scan only. The interval is `bgp conditional-advertisement timer (5-240)`, default 60 s ([CLI](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_vty.c#L9031-L9058), [default](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_conditional_adv.h#L31)). The scan runs immediately only when the first advertise-map is configured on an instance ([enable](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_conditional_adv.c#L315-L341)). Otherwise, received UPDATEs, peer-down events, and route-map changes only set flags. A scan skips work unless one of those flags is set ([skip logic](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_conditional_adv.c#L179-L231)), and one received UPDATE anywhere causes every advertise-map peer to be evaluated again. A change can take up to one timer period to take effect. |
| What the condition matches | A full walk of the instance table for the AFI/SAFI. Every path of every destination is evaluated, not only the best path, and the condition becomes true on the first path the condition route-map permits ([table walk](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_conditional_adv.c#L13-L56)). Any route-map match clause works, including community, AS path, and peer, so the condition is not limited to prefixes. |
| Scope | Per neighbor or peer group, per AFI/SAFI. The command is available for unicast, multicast, labeled-unicast, VPNv4, and VPNv6, but not EVPN or FlowSpec. Each VRF instance has its own timer and table, so there is no cross-VRF condition. |
| Order with outbound policy | In the withdraw state, the advertise-map runs before the outbound route-map and suppresses permitted routes ([announce check](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_route.c#L2824-L2853)). In the advertise state, the scanner applies the advertise-map's `set` clauses and **skips the neighbor's outbound route-map**. Prefix lists, filter lists, and distribute lists still apply. Routes that the normal update path sends in the meantime do go through the outbound route-map. FRR's own topotest records a flap regression caused by these two writers disagreeing ([track_peer test](https://github.com/FRRouting/frr/blob/frr-10.7.1/tests/topotests/bgp_conditional_advertisement_track_peer/test_bgp_conditional_advertisement_track_peer.py#L158-L172)). |
| default-originate | The scanner does not withdraw a default route from a peer configured with `default-originate` ([special case](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_conditional_adv.c#L130-L141)). The synthetic default route is never in the table, so a condition cannot match it. |
| Withdrawal on a flip | The scanner changes the subgroup's Adj-RIB-Out directly. It sets selected paths that match the advertise-map in the advertise state and unsets them in the withdraw state. While the state is withdraw, the normal update path also blocks new matching routes immediately. |
| Update groups | The group hash includes the advertise-map name and the current state, but not the condition map or the exist/non-exist mode ([hash](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_updgrp.c#L408-L414), [compare](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_updgrp.c#L665-L672)). A state flip moves the peer to another update group. |
| Add-Path | Advertisement covers every path eligible for Add-Path transmission. Each withdrawal uses that path's transmitted path ID. The condition check ignores selection and Add-Path, because any path can satisfy it. |
| Observability | `show bgp neighbors` reports the condition, both maps, and the advertise/withdraw status, and JSON output also reports the time until the next scan. A state change logs only at debug level. A missing route-map is accepted with a warning, and the peer is skipped until both maps resolve. |

Junos and IOS-XR equivalents were not surveyed for this record.

### Constraints from this codebase

- The unicast export bodies do not share one gate order. Single-best runs
  selection, split horizon, RFC 4456 reflection, family, LLGR, ORF, then the
  RFC 1997 and route-server control gates
  (`crates/rib/src/manager/distribution/unicast.rs`), and its explain path
  dry-runs that body (`crates/rib/src/manager/queries.rs`). The ORR,
  Add-Path, and per-client-best bodies check family and ORF before selection,
  and their explain path (`explain_single_best_prefix`) follows that order.
  Every body evaluates the export chain last, before the Adj-RIB-Out diff.
  RFC 5291 ORF is the nearest existing gate: a per-peer, prefix-level gate
  that applies before the export chain, withdraws silently, and records a
  distinct explain code.
- Policy evaluation fails closed. An evaluation error returns `Deny` with
  `eval_error` set (`crates/policy/src/eval.rs`), so a caller that reads
  only the verdict cannot tell an error from an ordinary rejection.
- Update groups share one staged table among peers with equal `GroupKey`s.
  Per-peer export state that the key does not cover must use the per-peer path.
  ORF does this with the `orf_installed` fallback reason. The per-peer path
  remains the correctness reference for grouping.
- Changing state that alters export results without changing a chain already
  has a pattern: a policy dataset swap marks the affected peers dirty and
  re-evaluates them against their Adj-RIB-Out. The bounded resync timer then
  processes those peers in round-robin slices.
- `.rpol` policies and TOML named policies are pure functions of one route and
  its peer context. Export memoization, the update-group chain key, and
  [`apply(p)`](../reference/rpol-language.md#apply--policy-as-predicate) depend
  on that purity.

## Decision

### 1. Configuration surface

Define conditional advertisements by name under `[policy]` and attach them to
static neighbors by name:

```toml
[policy.conditional_advertisements.backup-via-transit-b]
# Which routes this definition controls: a named policy (TOML or .rpol)
# used as a predicate, with the semantics of `.rpol` `apply(p)`.
advertise_policy = "backup-aggregates"
# Advertise those routes only while the condition is "present" or "absent".
advertise_if = "absent"
# The condition: exact unicast prefixes whose candidates are checked.
condition_prefixes = ["0.0.0.0/0"]
# Optional: a candidate counts only when this predicate permits it.
condition_policy = "default-from-transit-a"
# Seconds a new observed condition must remain stable before it applies.
settle_time = 5

[[neighbors]]
address = "203.0.113.2"
remote_asn = 64502
export_policy_chain = ["transit-out"]
conditional_advertisements = ["backup-via-transit-b"]
```

| Field | Type | Required | Default | Meaning |
|-------|------|----------|---------|---------|
| `advertise_policy` | string | yes | — | Named policy, including the call form of a parameterized `.rpol` policy, that selects the controlled routes. Its permit/deny verdict is the only output; its modifications are not applied, matching `apply(p)`. As with `apply`, a policy that never rejects selects every route, so a predicate policy should use `default_action = "deny"` or a final rejecting term. |
| `advertise_if` | `"present"` \| `"absent"` | yes | — | The condition state in which controlled routes may be advertised. |
| `condition_prefixes` | array of prefixes | yes, nonempty | — | Exact IPv4 or IPv6 unicast prefixes. Prefix ranges are not accepted. One definition may mix address families. |
| `condition_policy` | string | no | none | Named policy used as a predicate over each condition candidate. Peer context in this evaluation is the candidate's **source** peer, so a neighbor-set match can test which peer sent the route. A locally injected candidate has no source peer (see Decision 2). |
| `settle_time` | integer seconds | no | `5` | Range 0–600. See Decision 3. |
| `Neighbor.conditional_advertisements` | array of names | no | `[]` | Definitions attached to this static neighbor. Duplicate entries and unknown names are load errors. |

Load-time validation rejects unknown fields, empty or duplicate condition
prefixes, references to undefined policies, duplicate attachments, and an
out-of-range `settle_time`. FRR accepts a missing route-map with a warning;
here a missing reference is an error, as it is for policy chains.
`PolicyService.DeletePolicy` treats a reference from a definition the same way
as a chain reference.

**No `.rpol` language change.** A built-in such as `exists(prefix)` would make
export policy depend on RIB state. That would break the purity that export
memoization, chain-content update-group keys, and `apply` depend on. Policies
supply predicates; the definition owns the RIB-state dependency.

**Neighbors only, for now.** Static `[[neighbors]]` can attach definitions.
Peer-group inheritance and dynamic neighbors are deferred (see Non-goals). gRPC
neighbor mutations that do not carry the field must preserve it. The
peer-group fix for config-file-only fields is the precedent.

### 2. What counts as present

The condition is **present** when at least one current unicast candidate for
an exact `condition_prefixes` entry satisfies `condition_policy`, or when such
a candidate exists and no `condition_policy` is set. Current candidates are
received routes accepted by import policy and retained in Adj-RIB-In,
including GR/LLGR-stale routes and losing Add-Path candidates, plus locally
injected routes. A candidate does **not** have to be the Loc-RIB best path.
This follows FRR's any-path semantics: "is transit A's default route still
here?" must be true even when transit B's default route is selected.

**Peer context for `condition_policy`.** For a received candidate, the
predicate sees the source peer's address, its configured remote ASN, and its
peer group. A locally injected candidate is stored under the `LOCAL_PEER`
sentinel (`0.0.0.0`), which is not a peer. For such a candidate, all three
peer-context fields are **absent**. The `0.0.0.0` sentinel is never passed as
an address. With absent fields, neither a neighbor-set match nor its negation
(`NeighborSetMatch::matches` / `matches_ne`) is true, so a predicate such as
"not from transit A" cannot silently count an injected route as a match.
Group-staged export evaluation already passes absent peer context the same way.
To select injected candidates explicitly, a predicate matches route type
`local`.

**`condition_policy` evaluation errors do not change state.** A candidate
whose `condition_policy` evaluation returns an `eval_error` is neither a
match nor a miss. If another candidate matches cleanly, the condition is
present. Otherwise, if any candidate errored, the observed state is
`unknown`. Decision 3 defines how the tracker treats `unknown`: it starts no
settle timer, cancels any pending one, and leaves `applied` unchanged,
including `pending` at
startup. Explain reports the held state and the error, and the existing
`bgp_policy_eval_errors_total` counter and per-term error counters record it.
A policy that fails continuously therefore freezes the definition in its last
applied state rather than flipping it.

Condition prefixes may be any unicast prefix, including routes that the
definition itself controls. Within one speaker, a definition cannot feed back
into itself. The condition reads Adj-RIB-In and injected routes, and the gate
writes only Adj-RIB-Out. Loops across speakers, where a controlled route
returns as another speaker's condition, are bounded by `settle_time` and
remain the operator's design responsibility.

### 3. Evaluation model: event-driven, debounced, no scan timer

The RIB actor keeps an index from condition prefix to definitions. When a
selection pass's affected-prefix set includes a condition prefix, the actor
re-evaluates the **observed** state of each definition indexed by that prefix
once the pass has finished applying its batch. The pass already computes that
set. Changes inside one ingested batch therefore coalesce, and a transient
state inside a batch is never observed. Each evaluation visits only the
candidates of a few exact prefixes, and prefixes outside the index add one hash
miss. There is no table walk on route churn.

Each definition holds three values:

- `observed`: `present`, `absent`, or `unknown`, recomputed as above. All
  three are first-class observations.
- `applied`: `pending`, `advertise`, or `suppress`. The gate uses this value.
- `observed_since`: when `observed` last changed to a different observation,
  including a change to or from `unknown`.

When `observed` changes to `present` or `absent`, the actor sets a timer for
`observed_since + settle_time`. When the timer expires, if `observed` has not
changed since then and differs from what `applied` represents, `applied`
changes once. A `settle_time` of 0 applies the change when the pass finishes.

When `observed` changes to `unknown`, the actor cancels any armed timer and
leaves `applied` as it is. When a known observation returns after `unknown`,
it is a new observation: `observed_since` is the time it returned, and the
full `settle_time` interval is armed again. This holds even when the
observation matches the one seen before the error. As a result, `absent →
unknown → absent` always ends with an armed timer, never a cancelled one,
and a condition must remain known and stable for a full `settle_time` before
an error-interrupted interval can change `applied`.

**Justification.** A debounce, unlike a rate limit, suppresses brief
condition losses entirely, such as a session reset that reconnects within the
settle window. In that case the peer receives no gated-route churn, and the
applied state does not change. Each applied transition costs one full Adj-RIB-Out
re-evaluation for each attached peer (Decision 4), so the debounce is also
what bounds work under a flapping condition. A condition that never remains
stable for `settle_time` keeps its last applied state. The debounce has no
penalty accumulation or exponential decay. RFC 2439 damping would add policy
state that this feature does not need. FRR's 60-second poll bounds churn as a
side effect, but makes each reaction wait up to one period. With a 5-second
default, failover through this feature is faster than through FRR's default
timer. `settle_time = 0` provides undamped behavior.

**Startup.** A definition installed at daemon start begins in `pending`, which
suppresses controlled routes regardless of `advertise_if`. It leaves `pending`
through the same debounce, from an empty Loc-RIB. While RFC 4724 selection
deferral is active for a condition prefix's family, the definition stays
`pending` until deferral is released. For `advertise_if = "absent"`, backup
routes are advertised after `settle_time` if the primary condition has not yet
arrived. They are then withdrawn once the primary condition remains present for
`settle_time`. This is the documented consequence of an absent condition.
FRR advertises immediately in the same situation.

### 4. Position in export, and update groups

The gate runs **for each candidate path** in every unicast body:
single-best, ORR, the Add-Path walk, and per-client-best. In each body it is
inserted as the last gate, immediately before that body's export-chain
evaluation, with no other change to the body. The existing gates keep their
current per-body order. A route that an existing gate already stops reports
the same first denial as today, and only a route that would otherwise reach
the export chain can be stopped by conditional advertisement. Explain gets
the same step at the same position in both explain paths: the single-best
dry run and `explain_single_best_prefix`.

For each definition attached to the target peer whose `applied` state is not
`advertise`, the gate evaluates `advertise_policy` on the candidate's source
attributes with the target peer's context. A clean permit suppresses the
candidate. An evaluation error also suppresses it (see below), so an error is
never treated as a miss. Only a clean rejection lets the candidate continue
to the export chain. A route must pass every attached definition. When every definition attached to the peer is advertising, the
gate passes without evaluating a policy, so peers in steady state pay nothing.

**`advertise_policy` evaluation errors fail closed.** While a definition is
not advertising, an evaluation that returns an `eval_error` suppresses the
candidate, as a match would. Explain reports it with its own code,
`conditional_advertisement_eval_error`, which names the failing policy and
term, rather than as an ordinary suppression or rejection. While a definition
is advertising, the predicate is not evaluated, because no predicate result
could change the outcome.

The behavior differs from FRR in three deliberate ways:

- **The gate only filters.** A permitted route still passes through the
  neighbor's export chain, and the advertise policy's modifications are never
  applied. FRR skips the outbound route-map in its advertise state and applies
  the advertise-map's `set` clauses. As a result, one Adj-RIB-Out has two
  writers with different policy, which caused FRR's documented flap regression.
  Operators migrating an FRR configuration that relied on that skip must permit
  the controlled routes in the export chain.
- **Source attributes.** The predicate matches the route as selected, not the
  route after export modifications. This matches the other pre-policy gates
  and keeps the predicate independent of chain order.
- **Suppression is not a policy denial.** Like ORF, it withdraws silently. It
  is not recorded in the `policy_filtered` set or the export-policy counters,
  and it does not affect the RFC 8212 posture.

**Applying a transition.** When `applied` changes, the actor marks every
established peer that has that definition attached as outbound-dirty. The
existing bounded resync tick then re-evaluates those peers against their
Adj-RIB-Out. That re-evaluation sends exact withdrawals for routes now
suppressed and announcements for routes now permitted. Normal distribution
applies the current `applied` state to every route that changes in the
meantime, so no second writer of Adj-RIB-Out exists. A new session's initial
advertisement uses the same gate and needs no special handling.

**Update groups.** A peer with one or more attached definitions uses the
per-peer path, and the new fallback reason is `conditional_advertisement`. This
follows ORF. The reason is an additive value in three places: the
`NeighborState.update_group` string, the config-transaction update-group
impact projection (explicitly outside v1), and the stable
`UpdateGroupComparisonMembership` protobuf enum (a new numeric value; see
Decision 9). The gate's
outcome depends on definition content and global applied state, but not on the
target, when the advertise policy reads no peer context. Peers with identical
attachments could therefore share a group if the interned attachment content
were added to `GroupKey` and a transition marked every group member dirty and
staged the group again, as a dataset swap does. That is deferred until a fleet
of peers with identical attachments makes the per-peer cost visible. The
expected use is a small number of upstream or edge peers, not hundreds of
route-server clients.

### 5. Add-Path, per-client best path, and route reflection

- **Add-Path send:** the gate evaluates each candidate path separately, and a
  suppressed path is withdrawn with its own path ID through the existing
  Adj-RIB-Out diff. With a prefix-only advertise policy, all paths for the
  prefix are suppressed together. This matches FRR. Add-Path peers already use
  the per-peer path.
- **`per_client_best` (RFC 7947 §2.3.2):** a suppressed candidate works like
  an export denial in the first-permitted walk. The walk continues to the next
  ranked candidate, and that candidate is advertised if the advertise policy
  does not control it. Explain records the suppressed candidate with the
  conditional-advertisement code rather than a policy code.
- **Route reflection:** the gate runs after the RFC 4456 reflection rules. It
  never makes a route reflectable that those rules forbid. It also does not
  change `ORIGINATOR_ID` or `CLUSTER_LIST` handling. Reflection does not
  originate routes, so this feature controls existing routes only.
- **No default-originate interaction:** rustbgpd has no default-originate.
  A default route injected through the API is an ordinary candidate. It can be
  a condition and it can be controlled. The FRR special case has no counterpart.

### 6. Reload, transactions, and the commit point

Definitions and attachments belong to the policy section of the
**generation** reload class, like named policies, neighbor sets, and chains.
*Amended during implementation; see
[Amendment: one attachment install](#amendment-one-attachment-install-2026-10-08).*
The RIB holds one install of the attached definitions and the attachments,
keyed by static neighbor address. The commit point is the RIB actor's
acknowledgement of that install, which the generation sends before its
policy snapshot. Compensation restores the install's capture.

Within that batch:

- A definition whose content is unchanged keeps its `observed`, `applied`, and
  settle-timer state. Content means mode, condition prefixes, `settle_time`,
  and the compiled content of both policies. Unchanged content causes no
  transition and no resync, just as a chain with identical content does not.
- A definition with new or changed content, including a change to a
  referenced policy through SIGHUP, `.rpol` reload, or `SetPolicy`, is
  evaluated **immediately** against the current RIB. Its `applied` state is
  set without waiting for `settle_time`, and attached peers are marked dirty.
  The RIB is warm, and the operator requested the change, so a pending window
  would only withdraw routes that are correctly advertised.
- Attaching or detaching a definition marks that peer dirty.
- A definition that no peer references is dropped.

**Compensation restores state; it does not evaluate it again.** The forward
apply captures each replaced or dropped definition's `observed`, `applied`,
`observed_since`, and settle deadline. The restore batch reinstates those
values, so a failed generation cannot change an advertisement decision or
skip the debounce. After the restore, `observed` is recomputed from the
current RIB. If it matches the restored value, the restored deadline stands.
If the RIB changed in the meantime, `observed_since` becomes the restore time
under the ordinary debounce. Peers whose attachments the restore changes are
marked dirty, as in the forward apply.

**Dataset swaps follow the dependency-refresh path.** Dataset content swaps
do not pass through the export-policy batch. They use the dependency-scoped
refresh, which today checks only each peer's import and export chains
(`refresh_dataset_dependents` in `src/peer_manager/policy.rs`). Dependency
discovery is extended to both predicates:

- When a swapped dataset is referenced by an attached definition's
  `advertise_policy`, the peer joins the batched export re-evaluation
  (`ReevaluatePeerExportPolicies`), just as an export-chain reference does.
- When it is referenced by a definition's `condition_policy`, that
  definition's `observed` state is recomputed against the current RIB under
  the ordinary debounce. A dataset feed is external input, like a route
  change, so it does not get the immediate application that an operator
  edit gets.

Native config transactions treat these fields as ordinary TOML. The ADR-0130
external-input fence already covers `.rpol` and dataset inputs.

### 7. Explain integration

`rbgp rib --prefix P advertised PEER --explain` and `ExplainAdvertisedRoute`
receive one gate step named `conditional_advertisement`. It is produced by the
same dry run of the shared export body:

| Verdict | Code | Detail example |
|---------|------|----------------|
| Stop | `conditional_advertisement_suppressed` | `suppressed by conditional advertisement backup-via-transit-b: condition prefix 0.0.0.0/0 present (advertise if absent)` |
| Stop | `conditional_advertisement_suppressed` | `suppressed by conditional advertisement core-reach: condition prefixes 198.51.100.0/24, 2001:db8::/32 absent (advertise if present)` |
| Stop | `conditional_advertisement_suppressed` | `suppressed by conditional advertisement backup-via-transit-b: pending initial evaluation` |
| Stop | `conditional_advertisement_eval_error` | `suppressed by conditional advertisement backup-via-transit-b: advertise_policy backup-aggregates failed in term t3 (evaluation error); failing closed` |
| Pass | `conditional_advertisement` | `conditional advertisement backup-via-transit-b permits: condition prefix 0.0.0.0/0 absent (advertise if absent)` |
| NotApplicable | `conditional_advertisement` | `no conditional advertisement attached` or `route not selected by any attached advertise policy` |

When the observed state differs from the applied state, the detail adds
`observed <state> since <time>, applies after settle_time`. When the observed
state is `unknown` because of a `condition_policy` error, the detail adds
`condition unknown: condition_policy <name> failed in term <term>; holding
<applied state>`. The present-mode
detail names the first matching condition prefix. The absent-mode detail names
every configured prefix, so an operator can see why the condition is false.
`rbgp policy explain --direction export` explains the export chain only and
remains unchanged. The new gate code and reason value are additive explain
vocabulary.

### 8. Metrics and logs

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `bgp_conditional_advertisement_condition` | gauge | `name`, `state` | Observed condition as a state set: one series per state (`present`, `absent`, `unknown`). The current state's series is 1, and the others are 0. |
| `bgp_conditional_advertisement_permitted` | gauge | `name`, `advertise_if` | Applied gate: 1 when controlled routes may be advertised, 0 when suppressed or pending. `advertise_if` carries the configured mode. |
| `bgp_conditional_advertisement_transitions_total` | counter | `name` | Changes to the applied state |

The observed condition uses the Prometheus state-set idiom (one series per
state, with a `state` label) instead of a sentinel value such as `-1`. A
query therefore selects `unknown` explicitly, and it cannot be mistaken for a
numeric comparison. Label cardinality is bounded by configured definition
names times three states. A definition's series are removed when the
definition is dropped.

**Health check.** The applied gate should equal the mode-adjusted
expectation for the observed condition:

- `permitted` should be 1 when the condition is `present` and `advertise_if`
  is `present`;
- `permitted` should be 1 when the condition is `absent` and `advertise_if`
  is `absent`;
- otherwise, `permitted` should be 0.

`unknown` observations are excluded from the comparison, because the gate
deliberately holds its last applied state while the condition is unknown.

```promql
(
  bgp_conditional_advertisement_permitted{advertise_if="present"}
    != on(name) bgp_conditional_advertisement_condition{state="present"}
)
or
(
  bgp_conditional_advertisement_permitted{advertise_if="absent"}
    != on(name) bgp_conditional_advertisement_condition{state="absent"}
)
unless on(name) (bgp_conditional_advertisement_condition{state="unknown"} == 1)
```

A mismatch is expected for a while and does not by itself mean a fault: at
startup the gate is `pending`, which suppresses, and after every change of
condition the gate waits `settle_time` before following. An alert or check
built on this expression must therefore use a `for:` window longer than the
largest configured `settle_time`. A mismatch that lasts longer than that
window, with no new transitions, indicates a condition that is flapping
inside the settle window or a gate that is not following its condition.

Each applied transition logs one
`info`-level event with the definition name, the old and new states, and the
condition prefix that decided it. Logged event fields are a compatibility
surface, so the fields are documented when the event ships. Per-peer suppressed
route counts are not provided; explain answers the per-route question.

### 9. Stability boundary

The feature is opt-in and remains **alpha**, outside the v1 inventory. The new
`PolicyConfig.conditional_advertisements` and
`Neighbor.conditional_advertisements` fields are optional siblings that the
stable digests do not select. The checked-in JSON Schema gains them, but the
v1 inventory hashes do not change. Inventoried unicast route-server and
route-reflector behavior is unchanged for every configuration that omits the
feature. Explain codes, the fallback reason string, and the metrics are
additive.

One stable digest does change. `GetNeighborState` returns
`UpdateGroupComparisonMembership`, so a new enum value
(`UPDATE_GROUP_COMPARISON_MEMBERSHIP_CONDITIONAL_ADVERTISEMENT = 9`) changes the
`NeighborService` message-graph digest in `v1-stable-surface.json`. The
change is classified as additive: no existing number or name changes, and
the comparison JSON pins the membership as a string without a closed value
set. Clients that switch on the enum must already handle an unknown value.
The digest update ships in its own commit with that classification, separate
from the feature code. The review approved this change as additive on
2026-10-07. Reporting the existing `UNKNOWN` membership instead was rejected
because it loses information.

Promotion would require a separate inventory decision after operational use.

### 10. Non-goals

- New address families. The feature covers IPv4 and IPv6 unicast only, not
  labeled unicast, VPN, EVPN, FlowSpec, or BGP-LS.
- Origination. Only routes already present in the RIB are controlled.
- Advertise-map attribute rewriting and skipping the outbound route-map.
- Prefix-range, covering-prefix, or attribute-only conditions. Conditions are
  exact prefixes plus an optional predicate. Range conditions would need trie
  queries on every change and should be added only for a named use.
- A periodic scan timer and RFC 2439-style penalty damping.
- Peer-group inheritance, dynamic-neighbor attachment, a dedicated status RPC
  or CLI subcommand, and update-group keying of attachments. Each is deferred
  until a concrete need appears.

## Test plan

1. **Config:** acceptance and rejection cases for every field. These include
   an unknown policy, empty and duplicate prefixes, a duplicate attachment, an
   out-of-range `settle_time`, and an unknown field. Also cover JSON Schema
   regeneration, reload classification, `DeletePolicy` refusal while a
   definition references the policy, and preservation of attachments across
   gRPC neighbor mutations.
2. **Condition tracker** (RIB actor, controlled time): a non-best candidate
   makes the condition present, and import rejection does not. Also cover a
   source-peer `condition_policy` match, withdrawal of the last candidate,
   peer teardown, and GR-stale retention. A blip shorter than `settle_time`
   causes no transition, a stable change causes exactly one transition,
   continuous flapping keeps the applied state, and `settle_time = 0` applies
   at pass end. Startup stays `pending` until deferral is released. A
   `condition_policy` that rejects a candidate makes it a miss, but one that
   returns an evaluation error makes the observation `unknown`. In that case
   the applied state holds, both during a settle window and from `pending`,
   and a clean match from another candidate still makes the condition
   present. `absent → unknown → absent`, where the outer two observations
   match, arms a fresh full `settle_time` from the return to `absent`. That
   holds whether `applied` differs or not, and the state-set gauge reports
   each of the three observations. A locally injected candidate sees absent
   peer context: a neighbor-set predicate and its negation both miss it, and
   a route-type `local` predicate matches it.
3. **Real export path:** a single-best peer goes present → absent → present
   for `advertise_if = "present"`. Gated routes receive exact withdrawals and
   re-advertisements, and other routes do not change. Run the same sequence
   for `"absent"`. Also cover Add-Path per-path withdrawal, `per_client_best`
   fallthrough to the next candidate, an RR client, and an injected default
   route as both a condition and a controlled route. Verify that a permitted
   route still receives export-chain modifications, that attaching moves the
   peer to the fallback reason and detaching restores grouping, and that
   explain reports each code. An `advertise_policy` evaluation error while
   suppressing withholds the route and reports
   `conditional_advertisement_eval_error`, while an ordinary rejection
   advertises it. For each body, a route that fails an existing earlier gate
   (family, ORF, split horizon, reflection, LLGR, RFC 1997, or route-server
   control) as well as an active conditional suppression must report the
   same first denial as on `main`, in both the live result and both explain
   paths. Prove each sequence test by temporarily removing the gate or the
   transition dirty-mark and confirming that the test fails.
4. **Reload:** reloading with identical content keeps the state and causes no
   resync. A policy edit causes an immediate evaluation. Generation
   compensation restores the previous attachments and their effects on the
   wire. Run compensation during an active settle window and confirm that
   the prior `applied` state and deadline are restored, not evaluated again.
   An unchanged RIB keeps the original deadline, and a RIB change during the
   failed generation restarts the debounce from the restore time.
5. **Dataset refresh:** a dataset swap that affects only an attached
   `advertise_policy` re-evaluates that peer's export, and one that affects
   only a `condition_policy` recomputes the observed state under the debounce.
   A swap that affects neither changes nothing. Confirm each case fails with
   the extended dependency discovery removed.
6. **Interop leg against FRR 10.7.1:** containerlab topology
   `frr-a → rustbgpd → frr-b`. `frr-a` originates the condition prefix, and
   rustbgpd controls a backup prefix toward `frr-b` with
   `advertise_if = "absent"`. Shut down and restore `frr-a`'s announcement,
   and assert from `frr-b`'s `show bgp ipv4 unicast json` (with
   `vtysh.conf` bound) that the backup prefix appears after the settle window
   and is withdrawn after restoration. Also assert the explain output on
   rustbgpd for each state. Deploy fresh for each run.

## Implementation slices

1. **Config and validation.** Add the definition and attachment structs,
   schema, `DeletePolicy` reference checks, gRPC-mutation preservation,
   reload-matrix rows, and config-diff and reload-route classification. The
   generation commits the attachments as part of the candidate. The
   definitions do nothing at runtime yet; they reach the RIB in slice 3,
   alongside the gate that uses them. Roughly 600 lines with tests.
2. **Condition tracker.** Add the prefix index, observed evaluation from the
   affected-prefix set, `unknown` handling for `condition_policy` errors, the
   settle timer, the deferral hold, applied state, `condition_policy`
   dataset-dependency recomputation, the three metrics, and the transition
   log. Applied state has no export effect yet. Roughly 500 lines with tests.
3. **Export gate.** Install the definitions and address-keyed attachments
   through one RIB install with a restorable capture (see the amendment).
   Insert the gate step last before the export chain in each unicast body and
   both explain paths, failing closed on `advertise_policy` errors. Add the
   `conditional_advertisement` fallback reason, with the proto enum value and
   its digest update in a separate commit. Also add transition-to-dirty
   wiring, `advertise_policy` dataset dependency, reload content identity,
   compensation state restore, and the explain codes. Real export-path tests
   cover Decisions 4–7, including first-denial parity. This is the risk slice.
   Roughly 800 lines with tests.
4. **Proof and documentation.** Add the FRR interop leg, configuration and
   explain reference pages, the update-group reason table, the metrics
   reference, the cookbook example, and the changelog fragment.

Deferred until there is demand, each as a separate ticket when accepted:
update-group keying of attachment content, peer-group inheritance, a status
RPC or CLI, and prefix-range conditions.

## Review decisions

The design was accepted as proposed on 2026-10-07. Review settled the open
questions as follows:

1. **`settle_time` defaults to 5 s.** This exceeds the time for a session
   reset and reconnect, while staying an order of magnitude faster than
   FRR's 60-second poll. `settle_time = 0` remains available for undamped
   reaction.
2. **Stale candidates count as present.** GR- and LLGR-stale condition routes
   keep the condition present, following FRR and the fact that forwarding
   still uses them.
3. **Startup is `pending`, which suppresses controlled routes, until the
   condition settles.** This includes the period while RFC 4724 selection
   deferral is active. `advertise_if = "absent"` does not advertise
   immediately at startup, unlike FRR.
4. **Attachment is per static neighbor only.** Peer-group inheritance remains
   deferred.
5. **Conditions are exact prefixes only.**
6. **A missing policy reference is a load error.**
7. **The v1 digest change is approved as additive.** The change is the
   `UPDATE_GROUP_COMPARISON_MEMBERSHIP_CONDITIONAL_ADVERTISEMENT = 9` enum
   value and the resulting `NeighborService` digest update in
   `v1-stable-surface.json`. It ships in its own commit in slice 3
   (Decision 9).

## Amendment: one attachment install (2026-10-08)

Implementation found that attachments cannot travel in
`PeerExportPolicyReplacement` as Decision 6 proposed:

- The generation's export-policy batch names only peers whose chains
  changed, and the RIB skips a member that is not registered for outbound
  updates. Peers that a generation adds or replaces, and peers whose session
  is down, receive their chains through `PeerUp` from the session task. An
  attachment carried in the batch would never reach them.
- Generation compensation re-applies the prior chains through the forward
  policy snapshot, not the rollback-only restore batch, so the tracker
  capture could not ride the restore batch either.

The implemented design keeps the decision's semantics and changes its
plumbing:

- **One owner.** The RIB holds one install: every definition some static
  neighbor attaches, and each such neighbor's attachment names keyed by its
  address. Attachments are static-neighbor only, so the address identifies
  the neighbor. The export gate reads only this install. Definitions and
  attachments commit together, so the gate never sees an attachment whose
  definition is missing; the gate still fails closed if it did.
- **Writers.** The daemon seeds the install when it constructs the RIB,
  before any session can register. A reload generation installs before its
  policy snapshot, so no candidate export chain runs behind the prior gate,
  and so before its hot updates, removals, session replacements, and
  additions, so no session the generation creates registers ahead of its
  gate. A failed snapshot restores the captured install, and the
  generation's unwind restores it before it re-adds peers. Until the
  snapshot commits, attached neighbors run their prior chains behind the
  candidate gate; the gate only filters, and the snapshot's own resync
  settles both. A catalog policy edit (`SetPolicy`, `.rpol` reload) installs
  before its chain snapshot and restores on failure. Any other config
  replacement, such as removing a neighbor, is reconciled against the
  running config after the command, which drops that neighbor's attachment.
  A failed reconcile is retried after an exponential backoff, without
  holding later commands.
- **Commands.** `InstallConditionalAdvertisements` returns the capture;
  `RestoreConditionalAdvertisements` reinstates it without re-evaluating;
  `ReobserveConditionalAdvertisements` carries a `condition_policy` dataset
  swap and also returns a capture. A generation that rolls the swap back
  restores that capture after the dataset rollback, and an unacknowledged
  re-observation leaves the generation ambiguous. The commit point is the
  RIB's acknowledgement of the install.
- **Unchanged.** Content identity, immediate evaluation of new or changed
  definitions, restore of applied state and settle deadlines, dirty marking
  of affected peers, and both dataset dependencies behave as Decision 6
  states. A peer registered before an install that attaches it is regrouped
  and resynced by that install.

## Consequences

- Operators get FRR-style advertise-if-present and advertise-if-absent behavior
  for unicast. Reaction is event-driven and debounced instead of waiting for a
  poll period.
- Steady-state export cost is zero for peers without attachments and for
  attached peers whose definitions are advertising. While a definition
  suppresses, its attached peers evaluate one predicate per exported candidate.
- Each applied transition re-evaluates the entire Adj-RIB-Out of each attached
  peer through the existing bounded resync. `settle_time` is the guard.
- Attached peers do not use update-group sharing. This is acceptable for the
  edge-peer use case and recorded as a deferred optimization.
- Migrating from FRR is not a direct translation where a configuration
  depended on the advertise-map skipping the outbound route-map or rewriting
  attributes.

## References

- [FRR 10.7.1 `bgp_conditional_adv.c`](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_conditional_adv.c)
- [FRR 10.7.1 conditional advertisement documentation](https://github.com/FRRouting/frr/blob/frr-10.7.1/doc/user/bgp.rst#L4437-L4480)
- [GoBGP v4.10.0 policy conditions](https://github.com/osrg/gobgp/blob/v4.10.0/internal/pkg/table/policy.go#L160-L177)
- [ADR-0096](0096-policy-language.md), the `.rpol` policy language
- [ADR-0098](0098-update-groups.md), update groups
- [ADR-0126](0126-shared-group-per-client-best.md), shared-group per-client best path
- [ADR-0130](0130-identity-conditional-external-policy-fence.md), the external-policy transaction fence
- [ADR-0135](0135-flowspec-feasibility.md), cross-RIB revalidation precedent
