# ADR-0112: Opt-in RFC 8212 explicit-policy enforcement for eBGP

**Status:** Accepted — fully shipped. All five implementation-sequence steps
landed: the restart-required knob (step 3), directional provenance and the
reserved deny (steps 1-2), the directional gRPC/CLI/metrics/doctor surface
(step 5), and the live policy-presence transaction contract (step 4). The
integration receipt required below is the M95 interop lab
(`tests/interop/m95-rfc8212-presence-frr-bird.clab.yml`).
**Date:** 2026-07-21

## Context

[RFC 8212](https://www.rfc-editor.org/rfc/rfc8212.html) updates BGP's
default behavior at an external boundary: an eBGP route without an explicit
import policy is ineligible for the decision process, and a route without an
explicit export policy must not enter that peer's Adj-RIB-Out. The requirement
is directional and applies to every enabled address family. It is intended to
limit accidental route leaks caused by permissive defaults or missing
configuration.

rustbgpd currently treats an absent runtime policy chain as permit-all.
`evaluate_chain(None, ...)` is a deliberate, process-wide contract used by
transport import and RIB export. `Config::effective_policy_chains_for_neighbor`
resolves policy in this order:

1. a neighbor named chain, then a neighbor inline policy;
2. a peer-group named chain, then a peer-group inline policy; and
3. the global named chain under `[policy]`.

There is no global inline policy. After that resolution, the same helper may
append implicit RFC 8326 GRACEFUL_SHUTDOWN and RFC 7999 BLACKHOLE receiver rules
to an eBGP import chain. Those tails are safety behavior supplied by the
daemon, not an explicit routing policy supplied by the operator. Testing only
whether the final chain is `Some` would therefore let an eBGP peer satisfy RFC
8212 merely because `honor_graceful_shutdown` or `honor_blackhole` is enabled.

The existing policy-update path can replace a session's import/export chains,
replace RIB export policy, request Route Refresh for a changed import chain,
retain retry intent, and roll back multi-peer changes. This machinery should be
reused rather than adding a family-specific enforcement path. The current
configuration model is neighbor-wide: one resolved import chain and one
resolved export chain govern all of a neighbor's negotiated families.

Dynamic ranges add one important identity edge. `remote_asn = 0` is not AS 0;
it is the configured accept-any sentinel for a dynamic neighbor. The accepted
child reports the ASN learned from OPEN, but the range remains an external
wildcard boundary. Policy enforcement must not briefly classify that child as
iBGP or change its classification after routes can flow.

FRR provides a useful operational comparison. Its official
[`bgp ebgp-requires-policy` documentation](https://docs.frrouting.org/en/latest/bgp.html#require-policy-on-ebgp)
says that a missing inbound filter accepts no routes, a missing outbound filter
announces no routes, the session summary shows `(Policy)` directionally, and a
toggle requires clearing the session. rustbgpd should offer the same
fail-closed property while fitting its existing policy transactions and
rolling-compatible gRPC surface.

## Decision

This ADR proposes an implementation contract. It does not authorize feature
code in this tranche.

### Global opt-in and restart boundary

Add one process-wide `[global] ebgp_requires_policy` boolean. It defaults to
`false`. When false, current permit-all behavior is unchanged.

Changing the knob is restart-required. A SIGHUP reload or configuration diff
may observe and report a different on-disk candidate, but the effective
running configuration retains the startup value until restart. The v1 runtime
configuration plan/apply API rejects a candidate that changes this field as
restart-required; it does not persist or partly adopt the candidate. Extending
runtime transactions to stage restart-required values is a separate contract,
not part of this feature. Receipts must name
`[global].ebgp_requires_policy` explicitly and must not imply that the running
enforcement mode changed. This avoids a fleet-wide import/export transition
hidden inside a hot reload and gives operators a deliberate deployment
boundary.

Default-on behavior and per-neighbor exceptions are deferred. The first version
is an opt-in compatibility step, not a claim that permissive defaults are a good
long-term end state.

### External-session classification

Enforcement applies to static neighbors whose configured `remote_asn` differs
from the local ASN. A dynamic range with a non-zero remote ASN uses the same
comparison. An accept-any dynamic range (`remote_asn = 0`) is always classified
as eBGP for the entire accepted session lifetime, including before and after
OPEN reveals the peer ASN. It never uses the sentinel as a real ASN and never
changes policy class mid-session. Operators who need iBGP configure an explicit
local-AS neighbor or range rather than the wildcard.

iBGP neighbors report the requirement as not applicable and preserve their
current policy behavior. Confederation-aware classification remains deferred
with confederation support; the first implementation must not infer a
confederation boundary that rustbgpd cannot configure today.

### Explicit provenance, before implicit tails

For each direction, policy resolution returns both the effective operator chain
and a directional explicit-provenance verdict. The verdict is computed before
appending any implicit policy and follows the existing precedence rules. It is
true for neighbor named, neighbor inline, peer-group named, peer-group inline,
or global named policy, and false when all sources are absent; there is
deliberately no global-inline case.

The following count as explicit:

- a non-empty neighbor named chain;
- a non-empty neighbor inline policy;
- an inherited non-empty peer-group named chain;
- an inherited non-empty peer-group inline policy; or
- a non-empty global named import/export chain.

An empty field that falls through to the next level does not count. A valid
explicit chain counts even when its configured result is permit-all: RFC 8212
requires deliberate policy, not a particular filtering strategy. The implicit
GSHUT and BLACKHOLE import tails never count, whether appended to an explicit
chain or used to create the first runtime chain.

This verdict must remain attached to the resolved direction through config
diffing, runtime peer state, and operator output. It must not be reconstructed
later by inspecting a compiled `PolicyChain`, because compiled content cannot
reliably distinguish an operator policy from a daemon-owned tail. The exact
inheritance source need not be carried or exposed after resolution; the public
contract is directional explicitness, not a second policy-origin inventory.

### Reserved internal deny

When enforcement is enabled and an eBGP direction lacks explicit provenance,
install a reserved internal deny-all chain for that direction. The chain is
created outside the operator policy catalog, cannot be referenced or shadowed
by a configured name, and is attributed in metrics/explain output as
`rfc8212_missing_import_policy` or `rfc8212_missing_export_policy`, not as an
operator policy hit.

Import deny prevents newly received routes from becoming eligible and export
deny prevents routes from entering that peer's Adj-RIB-Out. The peer remains
Established and continues exchanging protocol keepalives and withdrawals. The
implementation does not change `evaluate_chain(None, ...)`, does not insert a
global default-deny into the policy engine, and does not add a parallel
family-specific RIB or transport gate.

Because policy is neighbor-wide today, one directional verdict covers all of a
peer's configured and negotiated families. A missing import policy denies
unicast and every enabled non-unicast family; a missing export policy does the
same on egress. A later family-specific policy model would require a separate
ADR and API expansion rather than overloading this status.

### Live policy edits while enforcement is active

The global enforcement toggle is restart-required, but ordinary policy edits
remain eligible for the existing live transaction path.

Export transitions between explicit policy and the reserved deny use the
existing actor-fenced export-policy replacement and rollback ordering. Removing
the last explicit export policy must withdraw previously advertised routes
before the transaction reports success. Adding one must resync through exact
export precommit before Adj-RIB-Out advances.

An import transition is live only when an Established peer negotiated Route
Refresh. The transaction installs the candidate import chain, requests refresh
for every negotiated family, and may commit configuration/provenance only after
the session has accepted and queued every request. Basic RFC 2918 Route Refresh
has no completion acknowledgement: commit means the candidate chain is active
and the requests were queued, not that every route has already converged. A
real-session receipt must prove eventual convergence separately. Removing the
last explicit policy eventually re-evaluates and removes routes accepted under
it; adding one requests the routes that the internal deny did not retain.

Before a multi-peer edit mutates any peer, preflight Route Refresh capability
for every affected Established session whose import requirement would change.
One incapable peer rejects the whole edit before mutation. A session reset or
command failure after preflight still follows the rollback rule below.

If session apply, Route Refresh command delivery, RIB work, or a reply deadline
fails before commit, restore the prior import/export chains and provenance
through the existing rollback path and retain retry intent. A partially applied
direction must never be reported as the desired state. Enhanced Route Refresh
BoRR/EoRR-gated convergence is not required by this first tranche.

If an Established peer lacks Route Refresh, reject a live edit that changes its
effective import requirement and return an actionable error requiring an
operator clear/reconnect. Keep the prior running policy and provenance until
then. A down peer may still have routes retained in the RIB by GR or LLGR, even
after the session actor cleared its local route set. Permit an import-presence
edit while down only after the manager confirms that no retained stale state
remains; otherwise reject or defer it until retention expires or is explicitly
purged. A flap after preflight aborts and rolls back the edit before the desired
verdict commits, so any routes retained under the prior policy remain paired
with the prior verdict. The implementation must not infer RIB convergence from
session-local bookkeeping or pretend that export refresh can recover an old
Adj-RIB-In.

### Directional observability

Add two neighbor-state values, one for import and one for export, using a
rolling-compatible enum:

| Value | Meaning |
|-------|---------|
| `UNSPECIFIED = 0` | Field absent/defaulted across a version boundary |
| `UNKNOWN = 1` | Current daemon or client cannot determine the verdict |
| `NOT_REQUIRED = 2` | Enforcement disabled or the session is iBGP |
| `PRESENT = 3` | Enforcement applies and explicit operator provenance exists |
| `MISSING = 4` | Enforcement applies and the reserved deny is active |

New daemons populate a non-zero verdict for configured peers. New clients render
both `UNSPECIFIED` and unrecognized future values as `unknown`, so a new CLI
against an old daemon and an old CLI against a new daemon remain safe. Human and
JSON neighbor detail show import and export separately; they do not collapse a
one-sided configuration into a single “policy present” boolean.

`rbgp doctor` adds a policy-requirement check:

- report enforcement-disabled external peers as informational `NOT_REQUIRED`,
  without warning or failing an otherwise compatible deployment;
- fail each enabled external static peer or dynamic range with a missing import
  or export direction, naming the target and direction; and
- report unknown rather than pass when talking to a daemon that does not expose
  the status.

`/readyz` remains green for a healthy daemon whose reserved deny is working as
configured. Missing operator policy is an actionable configuration failure for
`doctor`, not evidence that the process or its actors cannot serve traffic.
Readiness still fails for actual actor stalls and transition wedges under its
existing contract.

### Implementation sequence

1. Extend config resolution with directional explicit-provenance metadata and
   the internal deny substitution, including dynamic-wildcard classification.
2. Thread the provenance and effective chains through PeerManager, sessions,
   and RIB registration without changing the policy engine's `None` semantics.
3. Add the restart-required knob, pin its effective running value on reload,
   and expose truthful config-diff/apply receipts.
4. Reuse the existing policy transaction for policy-presence transitions,
   adding the Route Refresh qualification and rollback error for live import
   edits.
5. Add directional gRPC, CLI/JSON, metrics/explain attribution, and doctor
   status with rolling-version handling.

Each step must be independently reviewable. No step may temporarily expose
“present” before its policy is installed or “missing” before its deny is
effective.

## Load-bearing validation plan

This ADR-only tranche adds no executable test or gate, so red-proof is N/A.
A future implementation is not complete until each test records the production
break that makes it fail. At minimum:

- **Disabled compatibility:** with the knob false, an unconfigured eBGP peer
  still imports and exports a real route. Removing the startup-value gate must
  make this test red.
- **Directional fail closed:** with enforcement enabled, independently omit
  import and export policy and prove only the missing direction is denied while
  the session remains Established. Replacing the internal deny with `None`
  must make the matching test red.
- **All-family scope:** advertise IPv4 unicast plus one negotiated non-unicast
  family through the same peer and prove a missing direction blocks both.
  Guarding only the unicast call site must make the non-unicast assertion red.
- **Explicit provenance:** cover global named, group named, group inline,
  neighbor named, and neighbor inline sources, then enable GSHUT/BLACKHOLE with
  no operator import policy and prove status remains `MISSING`. Counting the
  appended implicit tail must make this test red.
- **Dynamic wildcard:** accept a `remote_asn = 0` child and prove both directions
  enforce as eBGP for its complete session generation. Classifying from the
  sentinel as an ordinary ASN or changing class after OPEN must make it red.
- **Import transition:** with Route Refresh negotiated, remove and restore an
  explicit import policy, prove every negotiated-family request is queued
  before commit, then prove routes eventually withdraw/relearn. Skipping
  refresh or committing before command acceptance must make it red.
- **Import no-capability and rollback:** without Route Refresh, prove a live
  import-presence edit fails with clear/reconnect guidance and the prior chain
  remains authoritative; inject each apply/refresh failure and prove rollback.
  Accepting the edit or leaving either partial chain installed must make it red.
- **Disconnected GR/LLGR state:** retain stale routes for an already-down peer
  and for a peer that flaps after preflight; prove the edit rejects or defers
  and the prior verdict remains authoritative until stale state is gone.
  Treating session-local route cleanup as RIB convergence must make it red.
- **Export transition:** remove the last explicit export policy and prove a
  previously advertised unicast and non-unicast route are withdrawn before
  commit; restore policy and prove exact-export precommit precedes Adj-RIB-Out.
  Bypassing the fenced replacement must make it red.
- **Restart pinning:** change only `ebgp_requires_policy` on SIGHUP and prove the
  on-disk diff is restart-required while the running verdict and route flow stay
  at the startup value; prove the v1 runtime transaction rejects the same
  candidate without persisting it. Hot-applying or partly adopting the candidate
  must make the matching test red.
- **Rolling observability:** feed the CLI zero and an unknown future enum value
  and require `unknown`, then verify a current daemon reports distinct import
  and export values. Treating zero as `NOT_REQUIRED` must make it red.
- **Doctor versus readiness:** prove disabled enforcement with eBGP is
  informational/`NOT_REQUIRED`, missing enabled directions are fail, and the
  same healthy daemon remains ready. Coupling missing policy to `/readyz`,
  warning on the compatibility default, or silently passing an enabled missing
  direction must make the corresponding assertion red.

An integration receipt must use a real eBGP session and real route exchange;
mock-only policy presence is insufficient. It must disclose the enabled family
set and include at least one unicast and one non-unicast route.

## Rejected alternatives

- **Change `evaluate_chain(None, ...)` to deny globally.** This would silently
  change iBGP, internal policy evaluation, and every caller that deliberately
  uses `None` as permit-all. The enforcement belongs at resolved eBGP peer
  boundaries.
- **Count implicit GSHUT or BLACKHOLE tails as explicit policy.** They do not
  express the operator's import relationship and would create a false green.
- **Drop or refuse the BGP session.** RFC 8212 requires routes to be ineligible,
  not the transport to fail. Keeping the session Established makes the missing
  direction observable and allows policy repair without needless churn.
- **Use readiness as the configuration alarm.** Depooling a healthy RR or route
  server because one peer lacks policy broadens the blast radius. Doctor and
  neighbor status are the correct surfaces.
- **Hot-apply the global toggle.** A fleet-wide, two-direction transition is too
  broad to hide in SIGHUP and would require capability-dependent import
  recovery for every Established eBGP peer.
- **Add family-specific enforcement now.** Current policies are neighbor-wide.
  A second family policy model would be feature expansion rather than the
  smallest RFC 8212 boundary.
- **Enable by default immediately or add per-neighbor escape hatches.** Both are
  deferred until opt-in deployment experience establishes migration and
  interoperability costs. A global exception matrix in the first tranche would
  weaken the safety model and complicate observability.

## Consequences

- Operators can opt into an RFC 8212 fail-closed boundary without changing
  existing deployments by default.
- Import and export mistakes become independently visible in neighbor detail,
  JSON, explain/metrics attribution, and doctor output.
- Sessions remain up while missing directions exchange no routes, avoiding
  transport churn and keeping remediation observable.
- Dynamic accept-any ranges receive deterministic external treatment for the
  full accepted session lifetime.
- Policy resolution carries explicit provenance in addition to compiled
  content, and missing directions consume a small internal deny chain.
- Live import policy-presence edits depend on negotiated Route Refresh; peers
  without it require an operator clear/reconnect.
- The global toggle requires a restart, which makes enablement deliberate but
  prevents instantaneous fleet-wide adoption.
- Default-on enforcement, per-neighbor exceptions, confederation boundaries,
  and family-specific policy remain future decisions.
