# ADR-0125: v1.0 stability contract

**Status:** Accepted (tagging remains evidence-gated; no tag is scheduled)
**Date:** 2026-08-04
**Decision recorded:** 2026-08-08
**Amended:** 2026-08-08 (DR1 revised: the external pilot is advisory
evidence, not a hard tagging gate)

## Decisions recorded

The project owner accepted the contract with all eight decisions below. Each
is expanded in the section named in the last column.

| # | Decision | Recorded outcome | Where |
|---|----------|---------------------|-------|
| DR1 | Is at least one external pilot's incorporated feedback a hard tagging gate? | No (owner revision, same day as the initial yes). An external shadow pilot remains the strongest single piece of evidence and stays actively pursued — two weekly checkpoints, final semantic diff and support bundle, tested rollback, recorded feedback or explicit no-change finding — but it does not block the tag. If no pilot has completed when the remaining bars are green, the tag proceeds and the evidence summary discloses the pilot's absence plainly. | Evidence bar E1 |
| DR2 | How many archived soak receipts at RS/RR flagship shapes gate the tag? | Exactly two receipts, each at least 24 hours. Together they must cover route-server and route-reflector flagship shapes, a real SIGHUP file reload, and a max-prefix trip followed by timed restart. | Evidence bar E2 |
| DR3 | Does the tag require a comparative IRR-scale reload row against BIRD and OpenBGPD, or is the existing IXP matrix sufficient? | Yes, and the gate is satisfied by the published four-root IRR-scale comparison against BIRD 3.3.1 and OpenBGPD 9.1. | Evidence bar E3 |
| DR4 | RFC 8212 secure-by-default: activate per ADR-0119, or record a decision not to flip the default in 1.0? | Activate only the `config_epoch = 2` plus omitted-boolean cell after ADR-0119's representation and production-mutation proofs land. Epoch-less and epoch-1 omission remain permissive forever; explicit booleans retain their value. | Evidence bar E5 |
| DR5 | ADR-0122 open items: D2 (unary vs streaming Plan/Apply) and L1 (`--from-file` pledge) | Unary Plan/Apply is the permanent small-candidate path. The hidden `--from-file` aliases were removed from `config diff`, `config plan`, and `config apply` during v0.65 development. | Evidence bar E4 |
| DR6 | Are streaming Plan/Apply, `ListConfigHistory`, and `RollbackConfigTransaction` re-blessed into the frozen inventory at 1.0? | No. They remain outside the initial frozen inventory and may be added deliberately in a later 1.x minor. | Freeze scope |
| DR7 | Post-1.0 removal floor for inventoried surface | An inventoried surface deprecated in 1.x remains functional throughout 1.x and is removable no earlier than 2.0. | Deprecation policy |
| DR8 | Supported-versions window after 1.0 (SECURITY.md currently says "0.x") | Security fixes support the latest 1.x release. N-1 is a separate migration-compatibility promise, not a security-support promise. | Deprecation policy |

## Context

rustbgpd is public alpha. The README and `docs/v1-stable-contract.md` already
carry a deliberately narrow promise: a machine-pinned route-server /
route-reflector inventory (`docs/v1-stable-surface.json`, enforced by
`scripts/check-v1-stable-surface.py` and linked Cargo tests) is stable, and
everything else may change between minors with a CHANGELOG migration note.
The ROADMAP states that v1.0 is not on a timeline and that its intended
contract is narrower than the complete daemon surface.

Before this decision, the project had no definition of what *tagging v1.0*
would mean:
which surfaces the tag freezes, what evidence must exist before the tag is
honest, and what compatibility posture replaces the alpha
correctness-over-compatibility rule afterward. The project's development rule
is that every claim has a receipt (`docs/RECEIPTS.md`); a 1.0 tag is the
largest claim the project can make and deserves the same treatment.
ADR-0122 (compatibility-debt inventory) supplies the removal schedule and
lifetime policies this contract builds on.

This ADR accepts that contract. Acceptance changes no runtime behavior and
sets no tag date: the inventory freezes at the v1.0 tag only after the evidence
bar below is complete.

## Decision

### What v1.0 freezes

v1.0 promotes the existing machine-pinned inventory — not the whole daemon —
from a narrow v0.x promise to the project's versioned contract. The frozen
surface at the tag is exactly `docs/v1-stable-surface.json` as of the tagging
release, comprising:

- **Config schema for the pinned roles.** The stable
  `route-server-unicast` and `route-reflector-unicast` roles and the four
  scoped RR-only roles (BGP-LS, L3VPN, labeled-unicast, RT-Constrain), at
  field granularity: the inventoried stable fields, types, and the pinned
  effective defaults, under the existing compatibility rules (additive
  optional siblings allowed; removal, rename, type, default, required-set,
  or unknown-field-policy changes are breaking).
- **The blessed RPC sets.** The inventoried GlobalService, ConfigService,
  NeighborService, PolicyService, PeerGroupService, RibService, EventService,
  InjectionService, and ControlService methods, pinned by method name,
  streaming mode, and top-level request/response signature, plus the scoped
  RR-only RibService set. Additive fields and new RPCs remain allowed;
  removed field numbers and names stay reserved.
- **CLI verbs.** The inventoried stable command paths (path and command name
  only, per the existing scope rule), the versioned machine formats
  `rbgp-ribdiff/1` and `rbgp-ribsnap/1`, and the test-pinned JSON floors
  (neighbor detail, update-group comparison, support-bundle manifest v2).
- **Policy programs.** The machine-inventoried `.rpol` compatibility rule and
  pinned decision corpus: grammar additions are allowed, but an existing
  program's parse result, accept/reject result, or modification set is frozen.
- **The upgrade-exercise chain.** The contiguous consecutive-release fixture
  chain must extend to the v1.0 anchor, using the existing milestone-jump
  annotation if the release numbering jumps.

Explicitly **not** frozen at v1.0 (today's `explicitly_outside_v1` and alpha
classifications carry forward):

- Streaming config ingress (`StreamPlanConfigTransaction` /
  `StreamApplyConfigTransaction`), `ListConfigHistory`, and
  `RollbackConfigTransaction`, until deliberately re-blessed (DR6).
- The EVPN/VTEP/IRB alpha surfaces, `linux-dataplane`, BFD, gNMI, FlowSpec
  and EVPN injection, and the experimental Paths-Limit capability.
- Bench, soak, and harness internals; human-readable CLI output; metrics and
  events beyond the existing semantic rules (consumers ignore unknown
  additive fields and series).
- Commit-confirm and config-history on-disk formats. These are not present in
  `docs/v1-stable-surface.json`; their compatibility remains governed by the
  recovery-reader lifetimes in ADR-0122 and explicit migration notes rather
  than an unimplemented machine-pinned promise.
- The daemon remains free to add roles and surfaces in 1.x minors by adding
  inventory entries; blessing is always an explicit, reviewed act, never an
  implication of "shipped".

### The evidence bar for tagging

Each criterion states what it is, its honest current state, and whether it is
an open decision or already satisfied. The gap list below restates these as
a backlog.

**E1 — External pilot feedback incorporated (DR1).** At least one external
shadow deployment, run per the shipped shadow-pilot cookbook for two weekly
checkpoints at the pilot's normal refresh cadence. Archive the final semantic
diff and support bundle, test the rollback, and record the resulting change or
explicit no-change finding. Current state: zero external pilots; the tooling
(semantic diff engine, `rbgp diff`, incumbent adapters, cookbook) is complete
and unused in anger. This is the single largest gap between the receipts
culture and a 1.0 claim: every existing receipt is self-generated.
Revision (2026-08-08): E1 is advisory, not gating — see the DR1 row. The
pilot remains the highest-value outstanding evidence and the adoption
program continues to pursue it; a tag cut without it must disclose that
every receipt behind the contract is self-generated.

**E2 — Soak receipts at flagship RS/RR shapes (DR2).** Exactly two archived
receipts of at least 24 hours each against the precommitted acceptance gates
(`docs/soaks/soak-acceptance-gates.md`). Together the two receipts must cover
route-server and route-reflector flagship shapes, a real SIGHUP file reload,
and a max-prefix trip followed by timed restart. Current state: all archived
24 h soaks are EVPN-shaped; the precommitted gates name eight guarantees with
no soak injection today, of which these two scenarios are scheduled and the
rest deferred. Exactly two final qualifying receipts must be green. Preserve
earlier red attempts and their fixes as evidence, but do not count them toward
the two; the deferred six remain post-1.0 work.

**E3 — Comparative reload evidence at IRR scale (DR3).** The IXP receipt
matrix (700 clients × 400,400 routes vs BIRD 3.3.1 and OpenBGPD 9.1) exists
and publishes losses alongside wins. This gate is satisfied by the four-root,
counterbalanced IRR-scale reload comparison at 320 members × 183,040 routes
and 3,218,965 filter entries against BIRD 3.3.1 and OpenBGPD 9.1. The receipt
publishes rustbgpd's fan-out and memory losses alongside the grouped-control
win; it is indexed in `docs/RECEIPTS.md` and
`docs/perf/irr-reload-comparison-2026-08.md`.

**E4 — Compatibility debt executed (DR5).** The ADR-0122 scheduled removals
land before the tag. The v0.64 deadline was missed for the frozen v1/v2
commit-confirm and legacy-history readers and the Paths-Limit raw-cap field;
those join the existing v0.65 batch. Unary Plan/Apply remains the permanent
small-candidate path. The hidden `--from-file` compatibility aliases on
`config diff`, `config plan`, and `config apply` were removed during v0.65
development. Current state: L1 is complete; the rest of the v0.65 removals
remain to land.

**E5 — RFC 8212 secure default (DR4).** Opt-in enforcement is shipped and
receipted (ADR-0112, M95). ADR-0119's config-epoch representation and
activation are accepted but not implemented. Once every named
production-mutation proof passes, activation changes only epoch-2 omission
from invalid to effective `true`; legacy and explicit epoch-1 omission remain
effective `false`, and explicit booleans retain their value. The proof-gated
implementation must land before the tag.

**E6 — Security and fuzz posture line items.** Current state, largely
satisfied: the exact fail-closed 19-target fuzz inventory runs in PR CI with
the nightly libFuzzer campaign; `cargo audit` runs daily; private
vulnerability reporting is enabled with a stated response timeline. Remaining
for the tag: SECURITY.md's supported-versions table gains a latest 1.x
security-support row (DR8), and release artifacts keep the documented
glibc-floor build discipline.

**E7 — Upgrade chain to the anchor.** Already-working machinery: the tagging
release extends the consecutive-release fixture chain to the v1.0 anchor and
`scripts/check-v1-stable-surface.py` stays green. Satisfied by the existing
release process; listed so the tag cannot skip it.

### Post-1.0 deprecation policy

At the tag, the alpha correctness-over-compatibility posture ends **for the
frozen inventory only**:

- **Frozen surface:** a deprecation is announced in a 1.x minor with a
  CHANGELOG entry and migration note, remains functional for the rest of 1.x,
  and is removed no earlier than 2.0 (DR7). This supersedes, for inventoried
  surface, the current two-minor / 90-day floor. 2.0 is the contract major
  the existing rules already require for breaking inventory changes.
- **Non-inventoried surface:** the ADR-0122 lifetime policies continue
  unchanged — retired-config-key pointers live three minors, rolling-upgrade
  fallbacks support N-1, and unlisted surfaces may still change between
  minors with a migration note. 1.0 does not silently widen the promise.
- **Migration aids and security support:** upgrade compatibility covers the
  current and immediately previous minor release, as today. Security fixes
  support the latest 1.x release. These are deliberately separate promises
  (DR8); N-1 migration compatibility does not imply N-1 security support.
- New compat retentions keep adding rows to the ADR-0122 inventory in the PR
  that introduces them; that inventory remains the single ledger post-1.0.

### Gap list

The actionable backlog seed: criterion → current state → what closes it.

| Criterion | Current state | Closes the gap |
|-----------|---------------|----------------|
| E1 external pilot | Zero pilots; cookbook + tooling shipped, unused externally | Advisory since the 2026-08-08 DR1 revision — pursue per the shadow-pilot cookbook (weekly checkpoints, semantic diff, support bundle, tested rollback, recorded feedback); absence is disclosed at tag time, not blocking |
| E2 RS/RR soaks | Archived soaks are EVPN-shaped; eight precommitted gates uninjected | Archive exactly two receipts of at least 24 h that collectively cover flagship RS/RR, real SIGHUP reload, and max-prefix trip/timed restart |
| E3 comparative IRR row | **Satisfied:** four-root same-harness comparison against BIRD and OpenBGPD publishes wins and losses | Keep the published receipt linked from the evidence index |
| E4 debt schedule | L1 is complete; the v0.64 removals and remaining v0.65 items are still open | Land the rest of the v0.65 removal batch before the tag |
| E5 RFC 8212 | Activation authorized; ADR-0119 representation and proofs unimplemented | Land the representation and every named production-mutation proof; activate only epoch-2 omission |
| E6 security posture | Fuzz/audit/reporting in place | SECURITY.md 1.x supported-versions row; keep artifact build floor |
| E7 upgrade chain | Chain contiguous through the current anchor | Extend to the v1.0 anchor at tag time (existing process) |
| DR6 re-bless list | Streaming ingress, history/rollback RPCs outside v1 | Deliberate re-bless review for each, or defer to a 1.x minor |

## Consequences

- "What would 1.0 take?" has one answer with an explicit decision
  table, instead of an unstated bar. The gap list is directly convertible to
  tracked work.
- The tag stays honest: it cannot happen before the evidence exists, and the
  evidence requirements are receipts of kinds the project already produces —
  except E1, which requires a first external party and is therefore not fully
  under the project's control. That dependency is explicit rather than
  hidden.
- Operators get a stated end to alpha-style breaks for the pinned surface and
  a stated 2.0 removal floor, without the project promising stability for
  EVPN, dataplane, or streaming surfaces it is still shaping.
- The existing machinery (surface checker, upgrade-exercise chain, ADR-0122
  ledger) becomes the enforcement mechanism of the 1.0 contract rather than
  a parallel system; no new tooling is required to adopt this ADR.
- Nothing here schedules the tag. Acceptance fixes the meaning and the bar;
  the timeline remains evidence-driven.

## References

- [`docs/v1-stable-contract.md`](../v1-stable-contract.md) and
  [`docs/v1-stable-surface.json`](../v1-stable-surface.json), the pinned
  inventory and compatibility rules
- [ADR-0122](0122-compatibility-debt-inventory.md), debt inventory, lifetime
  policies, and the recorded D2/L1 outcomes
- [ADR-0112](0112-rfc-8212-ebgp-requires-policy.md) /
  [ADR-0119](0119-rfc-8212-secure-default-config-epoch.md), RFC 8212 posture
- [ADR-0124](0124-bounded-config-history-retention.md), config-history
  formats
- [`docs/RECEIPTS.md`](../RECEIPTS.md) and
  [`docs/soaks/soak-acceptance-gates.md`](../soaks/soak-acceptance-gates.md),
  the evidence culture this bar is drawn from
- `SECURITY.md`, supported versions and reporting posture
