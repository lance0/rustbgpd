# ADR-0135: Opt-In FlowSpec Cross-RIB Feasibility Validation

**Status:** Accepted
**Date:** 2026-09-20
**Supersedes:** The deferred feasibility-validation decision in
[ADR-0035](0035-flowspec.md); its other decisions remain in force.

## Context

Received FlowSpec currently undergoes wire validation and import policy,
including applicable destination-prefix RPKI policy. Its best-path selection
does not check feasibility against the unicast RIB. Operators can therefore
retain and advertise a received rule independently of changes to the unicast
routes on which RFC feasibility depends.

The original ADR describes matching the unicast next-hop. The standard defines
an originator identity instead: ORIGINATOR_ID when present, otherwise the source
IP address of the BGP peer. This document corrects that interpretation without
rewriting the dated original decision.

## Decision

Add a global, startup-only setting:

```toml
[flowspec]
validation = "rfc9117"
```

The default is `"off"`; omission preserves current behavior. Changes require a
restart, and both SIGHUP and config transactions preserve the running setting.
The initial mode covers received AFI 1/2, SAFI 133 routes against the same AFI's
SAFI 1 unicast routes. It does not add VPN FlowSpec, a Linux dataplane, per-peer
exemptions, policy extensions, or a destinationless-rule bypass.

Infeasible candidates remain in Adj-RIB-In with a reason, but cannot become a
new selected route or be newly advertised. Relevant unicast changes trigger
revalidation even if the FlowSpec sender does not send another UPDATE.

### Validation rules

Apply [RFC 8955 section 6](https://www.rfc-editor.org/rfc/rfc8955.html#section-6),
as revised by
[RFC 9117 section 4](https://www.rfc-editor.org/rfc/rfc9117.html#section-4),
with the IPv6 destination constraint from
[RFC 8956 section 5](https://www.rfc-editor.org/rfc/rfc8956.html#section-5):

- A destination component is required. IPv6 requires offset zero; another
  offset is wire-valid but infeasible. Missing destination and nonzero offset
  have distinct diagnostics.
- Use the selected longest-covering unicast route for originator and path
  comparison. Originator means ORIGINATOR_ID, otherwise source peer IP.
  NEXT_HOP and peer router ID do not substitute for that identity. Different
  transport addresses, including different address families, remain different
  without matching originator attributes. RFC 9117 section 5 discusses this
  consequence for non-congruent peering topologies.
- Enable RFC 9117's empty-AS_PATH local-domain exception within this mode.
  For received iBGP, a genuinely empty path bypasses originator matching.
  An absent attribute or malformed/unsupported segment does not qualify.
  Confederation paths remain outside the daemon's supported wire model.
- For received eBGP, the first AS_SEQUENCE ASN must match that of the covering
  route. Compare actual path ASNs, not configured transport-peer ASNs. Unknown
  identities never match each other. Existing first-AS admission policy remains
  a separate check.
- Examine every admitted, retained, received unicast candidate strictly more
  specific than the FlowSpec destination, including losing Add-Path candidates.
  A candidate from another neighboring AS makes the rule infeasible. A path's
  first AS_SEQUENCE ASN supplies that identity; an empty local-domain unicast
  path uses the local AS. An unknown identity conservatively fails. Unicast
  routes rejected before retention and locally injected unicast routes are not
  received candidates for this check.

Two conservative product choices make otherwise ambiguous boundaries explicit:

1. Every received FlowSpec requires a covering unicast route, including an
   empty-path iBGP rule. RFC 9117 changes rule (b), while rule (c) still refers
   to the best-match route; it does not expressly resolve every no-cover case.
   This implementation reports `no_covering_unicast` rather than treating the
   local-domain exception as an unconditional pass.
2. Local FlowSpec injection remains explicit trusted origination. It reports
   `local`, not `feasible`, and does not claim received-route RFC validation.
   Enabling receive-side checks does not silently change local injection.

### Reverse dependency work and publication

Index every retained FlowSpec destination, including infeasible rules. A
unicast change affects overlapping ancestors and descendants: a FlowSpec /24
depends on a covering /16 and on received /25 candidates. Drive invalidation
from all affected unicast prefixes, not only changes to the selected route.
This includes candidate replacement and removal, peer teardown, graceful
restart expiry, refresh reconciliation, and policy changes.

Coalesce affected rules and traverse relevant received candidates in bounded
actor slices. Bound the visits inside a rule, not only the number of rules per
slice: a single /0 can cover the entire table. Reuse existing prefix indexes;
do not copy a complete RIB snapshot for each rule.

Dependency discovery is also resumable. Changes beneath a FlowSpec destination
coalesce at that destination; changes covering several destinations use a trie
cursor. A turn discovers at most 16 rules and visits at most 256 received
candidates. These counts do not bound total turn duration: peer inventory and
the existing per-rule selection/distribution add work. Dedicated readiness
checkpoints remain active through those operations, and the existing actor-work
histogram records `flowspec_validation` slices. Validation pauses during a
partially ingested route batch until its coalesced dependency notifications
have been published. Separate IPv4 and IPv6 FIFO queues pause only the family
whose unicast selection is deferred; runnable families alternate without
scanning through held jobs. When both families are held, the actor sleeps on
its ordinary input and timer paths.

The manager owns each validation job's candidate and dependency revisions.
It discards results when either revision is stale. New candidates remain
ineligible until validation completes. A changed FlowSpec payload cannot
inherit the previous payload's verdict.

An unchanged, already selected candidate may keep its last completed verdict
while a relevant unicast change is being revalidated. Diagnostics report that
validation is pending. A pending candidate cannot newly displace the selected
route using an older verdict. Once a current validation completes as
infeasible, ordinary selection and distribution withdraw it or select a
feasible alternative. Deletion of the selected FlowSpec itself still takes
effect immediately.

Retaining the previous selection lasts for only the first uninterrupted
validation attempt. A second relevant dependency change during that attempt
revokes the retained verdict and withdraws the candidate until a current
attempt finishes. Revocation is sticky across subsequent invalidations; a
queued or restarted job cannot restore the old verdict. An already-proven
failure, such as loss of the covering route, takes effect immediately without
waiting for the more-specific scan. Candidate replacement likewise never
inherits the previous payload's verdict. These are implementation choices,
not additional RFC requirements. They prevent continuous changes from keeping
a known-stale selection alive through endless retries, without a timer or an
operator tuning knob.

A fresh attempt may absorb changes already queued when it captures the current
dependency revision. Discovery at an older or equal revision cannot revoke that
fresher attempt or completed result. The guarantee prevents indefinite retention
across interrupted validation attempts; it does not require withdrawal after
any two raw updates received before an attempt starts. Coalesced repeated
changes in one undiscovered scope may conservatively revoke selection earlier.

This is eventual cross-RIB revalidation, not an atomic switch of both tables.
RFC 8955 requires revalidation on unicast change but does not specify a
wall-clock completion deadline. Keeping the previous selected result during
bounded work avoids withdrawing and reannouncing an unchanged valid rule on
every relevant unicast UPDATE. It also leaves an explicit convergence window;
the implementation must provide fair progress, pending diagnostics, and tests
that reject publication from stale revisions. A future deployment requiring
synchronous cross-table withdrawal needs a separate contract and evidence.

### Operator contract

Preserve ordinary FlowSpec listing as the selected-route view. Add an explicit
received-peer view with candidate path ID, selected status, last completed
feasibility and reason, and whether revalidation is pending. This view must
include retained infeasible routes; a selected-only listing cannot explain
them. Default-off routes report validation as disabled.

While dependency discovery or a route batch remains outstanding, received
candidates may conservatively report pending before their exact dependency is
visited. This does not change their last completed verdict or invalidate an
unrelated selection. Local origination has no receive-side pending state.

Diagnostic queries check cancellation before materialization, during traversal
at bounded visit intervals, and before sending. Abandoned reads do not return
partial success and do not cancel mandatory background revalidation. Preserve
existing daemon read deadlines and actor scheduling policy.

## Validation

- Evaluator tests cover originator identities across transport families,
  reflected paths, empty versus absent paths, AS_SET rejection, eBGP first-AS
  comparison, local injection, absent cover, IPv6 offset, and all received
  more-specific candidates.
- Actor tests prove feasible to infeasible to feasible without a new FlowSpec
  UPDATE, including losing Add-Path churn, both prefix-containment directions,
  peer teardown and clean dependency-index retirement.
- Revision tests prevent stale results from selecting or advertising a route;
  bounded-work tests exercise a single broad rule with many candidates and
  canceled diagnostics. Off-mode behavior remains unchanged.
- Configuration tests cover the default, validation of values, diff reporting,
  restart-required classification, and preservation of the running value.
- The existing FlowSpec interop harness exercises a received rule and a
  covering route from one source session. It withdraws and restores only the
  unicast route and checks retained diagnostics and withdrawal/reannouncement
  at the pinned observer without session flaps. The existing default-off
  injection case remains covered. The receipt names the exercised family.

### Integration evidence

On 2026-09-20, the M22 harness passed all 17 checks at source `aa32ba129`
(daemon version `0.71.0`, FRR `10.7.1`). The original default-off local-injection
phase passed, followed by an explicit restart into validation mode. A received
IPv4 rule then moved from feasible to retained `no_covering_unicast` and back
to feasible through unicast-only withdrawal and restoration. The FRR observer
withdrew and restored the rule; session counters stayed unchanged during churn,
and the source did not reinject FlowSpec. The intentional phase-boundary restart
is excluded from that no-flap claim.

IPv6 semantics have evaluator and actor coverage; this live receipt covers IPv4
only. It establishes control-plane behavior in this small topology, not scale,
forwarding, or a wall-clock revalidation guarantee.

## Consequences

Operators can opt into cross-RIB validation without changing existing
deployments by default. Retention permits diagnosis and recovery without asking
the sender to replay a rule. Validation adds destination indexing and bounded
background work when enabled. No dataplane behavior or scale qualification is
implied by implementing these checks.
