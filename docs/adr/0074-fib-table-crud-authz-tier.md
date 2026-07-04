# ADR-0074: Runtime FIB-table CRUD authorization tier

**Status:** Accepted
**Date:** 2026-06-01

## Context

Runtime `[[fib_tables]]` CRUD shipped post-v0.32.0: `SetFibTable`
(create-or-replace by name), `DeleteFibTable`, and `ListFibTables` on
`RibService`, with `rbgp fib-table {list,set,delete}`. `SetFibTable`
and `DeleteFibTable` change which kernel FIB tables exist and which
configured neighbors / peer-groups feed them; the ADR-0061 reconciler then
programs the kernel — added tables back-fill from current best routes,
removed tables (and `table_id`/`metric` key-moves) withdraw their kernel
rows.

That makes them the second and third `Mutating` methods that cause kernel
dataplane programming, after `EvpnService/ApplyEvpnRuntime` (ADR-0063 v1).
The dataplane-programming RPC guardrail in `docs/RELEASE_CHECKLIST.md` says
that when a second such method appears we should prefer a dedicated
`dataplane_mutating` tier — captured in an ADR — over leaving it in
`mutating` by inattention. This ADR is that explicit decision.

## Tier landscape (ADR-0064)

- **`mutating`** (reachable by the `Automation` role): per-object,
  reversible daemon state changes — `AddNeighbor`/`DeleteNeighbor`,
  dynamic-neighbor CRUD, `Enable`/`DisableNeighbor`, `SoftResetIn`,
  `ClearDuplicateMacQuarantine`, and the deliberate kernel-dataplane
  exception `ApplyEvpnRuntime`.
- **`operator_only`** (reachable only by the `Operator` role):
  process-/network-wide, high-blast, or *injection* of operator-authored
  network state — `SetGlobal`, `Shutdown`, global policy chains / set
  mutation, graceful-shutdown control, MRT dumps, and route injection
  (`AddPath`, `AddFlowSpec`, `AddEvpnRoute`).

## Decision

`SetFibTable` and `DeleteFibTable` stay **`Mutating`**; `ListFibTables` is
**`SensitiveRead`** because table names, ids, and allow-lists disclose routing
topology / intent. A dedicated `dataplane_mutating` tier was considered and
rejected.

Rationale:

1. **They are config-surface mutations, not injection.** They define which
   FIB tables exist and which configured neighbors/peer-groups feed them.
   The routes installed are the daemon's *already-learned best routes*
   back-filled into a table — never operator-authored new network state.
   The injection surface (`AddPath`/`AddFlowSpec`/`AddEvpnRoute`), which
   introduces routes the daemon then originates or advertises, is what
   `operator_only` exists to gate. FIB-table CRUD introduces no new routes.

2. **They are the unicast sibling of dynamic-neighbor CRUD.** Dynamic-neighbor
   CRUD decides which peers may be admitted; FIB-table CRUD decides which
   validated peers / peer-groups may feed configured kernel tables. An
   operator/controller that provisions neighbors (a `mutating` action) and
   the FIB table their routes land in is one persona. The FIB-table path is
   additionally serialized with SIGHUP, staged through the peer-manager live
   config, reconciler-acked, and persistence-acked because it touches kernel
   state. Splitting it to `operator_only` would force that controller to hold
   Operator credentials, which also grant `Shutdown`, `SetGlobal`, global
   policy set mutation, and route injection: exactly the over-grant the
   `ApplyEvpnRuntime` pin warns against.

3. **The destructive leg is bounded and already accepted at `mutating`.**
   `DeleteFibTable` (and a `table_id`/`metric` key-move via `SetFibTable`)
   withdraws a table's kernel rows — not purely additive, unlike
   `ApplyEvpnRuntime`. But `DeleteNeighbor` is already `mutating` and tears
   down a session, withdrawing every route learned from / advertised to that
   peer (potentially a full table). A single named FIB table's rows are a
   comparable or smaller blast radius. The reconciler never removes foreign
   kernel rows, and the action is reversible (re-add back-fills from current
   best routes). The non-additive concern does not push FIB-table CRUD above
   the existing `mutating` bar.

4. **A new tier is disproportionate.** `dataplane_mutating` would sit
   between `mutating` and `operator_only`, but no ADR-0064 role maps there:
   `Automation` stops at `mutating` and `Operator` reaches `operator_only`,
   so a new tier is either Operator-only-reachable (defeating the automation
   use case in point 2) or needs a new role — a model change rippling
   through enforcement, the inventory counts, the threat model, and the test
   matrix — to retier (currently) three methods, and would reopen the
   settled `ApplyEvpnRuntime` decision.

## Consequences

- `SetFibTable`/`DeleteFibTable` are reachable by the `Automation` role
  under `enforcement = "tier"`. Operators who want to withhold FIB-table
  mutation from automation cannot split it from other `mutating` APIs in
  ADR-0064 v1; they must not grant the Automation role a token, or must cap
  the listener `max_tier` below `mutating` and accept that all mutating APIs
  are withheld.
- The decision is pinned by assertions in `crates/api/src/authz.rs`
  (`method_lookup_returns_expected_tiers`) and recorded in the
  `docs/RELEASE_CHECKLIST.md` dataplane-programming guardrail. If FIB-table
  CRUD scope widens past back-filling already-learned routes (e.g. arbitrary
  operator-authored kernel-table injection), revisit this tier via an ADR
  update — not by editing the pin.

## Anchors

- `crates/api/src/authz.rs` — `METHODS` table (`SetFibTable`/`DeleteFibTable`/
  `ListFibTables`) + tier pin in `method_lookup_returns_expected_tiers`.
- `src/fib_table_control.rs` — `mutate()` coordinator-serialized, staged,
  reconciler-acked, and persistence-acked critical section.
- ADR-0061 — configured-table unicast FIB reconciler.
- ADR-0064 — gRPC authorization tiers + roles.
- `docs/RELEASE_CHECKLIST.md` — dataplane-programming RPC guardrail.
