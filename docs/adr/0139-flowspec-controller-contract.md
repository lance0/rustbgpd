# ADR-0139: Scoped FlowSpec Controller Compatibility Contract

**Status:** Accepted
**Date:** 2026-10-10
**Supersedes:** The FlowSpec exclusion in
[ADR-0125](0125-v1-stability-contract.md) only for the controller boundary below.
Its unicast scope, qualification evidence, and v1.0 tagging rules remain in force.

## Context

ADR-0125 excluded FlowSpec from the narrow v1 inventory. Since then, the
controller API gained explicit mutation outcomes, retained local-intent reads,
and committed post-export-policy advertised reads. A separate
[dual-stack qualification](../artifacts/interop/m22-flowspec-controller-20261002/README.md)
exercised their lifecycle against FRR 10.7.1 with 100 local rules, 50 per AFI,
matching destination prefixes, TCP, and destination port 80.

The run covered create, reapply, replace, delete, source precedence, export
policy, peer reconnect, and controller reconciliation after daemon restart.
GR and receive-side feasibility validation were disabled. This is functional
control-plane evidence, not a scale, latency, forwarding, or enforcement
qualification. The [API reference](../reference/api.md#flowspec-injection-contract)
records the historical driver's deadline caveat and subsequent oracle fixes.
The dated receipt's alpha wording remains an accurate record of its original
contract; this ADR records the later promotion decision.

## Decision

Add `flowspec-controller` to the existing stable classification in the
[v1 inventory](../reference/v1-stable-surface.json), with the precise semantics
and shared-message exclusions in the
[controller contract](../reference/v1-stable-contract.md#flowspec-controller-boundary).
The included RPCs and modes are:

- `InjectionService.AddFlowSpec` and `DeleteFlowSpec` for local IPv4/IPv6
  FlowSpec intent, including explicit upsert and delete outcomes.
- `RibService.ListFlowSpecRoutes` for selected routes, retained local intent
  selected by `received_peer_address = "0.0.0.0"`, and committed advertisements
  selected by `advertised_peer_address`.

Remote received-candidate reads, `ReceivedFlowSpecRouteEntry` diagnostics
(`path_id`, `validation`, `reason`, `pending`), `FlowSpecValidationStatus`,
`Config.flowspec`, receive-side feasibility validation, FlowSpec CLI surfaces,
and GR/LLGR guarantees remain outside v1. Local injection is trusted
origination. An `OK` mutation confirms the documented local stage; an advertised
row confirms outbound-channel admission. Neither promises remote acceptance
or dataplane installation, forwarding, or enforcement.

Use the existing 0.x compatibility rules until v1.0. At that tag, the
inventoried controller surface freezes with the rest of the inventory;
deprecated items remain functional throughout 1.x and breaking removal is no
earlier than 2.0. There is no new stability tier or tag date. ADR-0125's dated
unicast receipts are not FlowSpec qualification.

## Consequences

Controllers must retain desired state outside the daemon and re-inject it
after restart. Upgrade and rollback checks require explicit mutation outcomes
and view acknowledgements, including empty views, because older servers may
ignore selectors or report unspecified outcomes. The
[upgrade procedure](../reference/v1-stable-contract.md#controller-upgrade-and-rollback)
defines reconciliation and legacy-server handling.

This decision changes no runtime behavior, config shape, default, or release
anchor. The existing consecutive-release config fixtures remain configuration
upgrade evidence, separate from the controller lifecycle qualification. Future
changes must preserve the inventoried contract or follow its breaking-change
and deprecation rules.
