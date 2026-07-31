# MANRS IXP Programme Action 1 on rustbgpd

**When this is you:** your exchange participates in (or is applying to)
the MANRS IXP Programme and you need to show, control by control, how a
rustbgpd route server implements Action 1 — and how members can verify
each control from the outside.

The normative source is
[MANRS-004.01, "MANRS Actions for IXP Program"](https://manrs.org/specifications/MANRS-004/01/).
Action 1 is mandatory for programme participation:

> **Action 1. Prevent propagation of incorrect routing information.
> (Mandatory)**
> The IXP implements filtering of route announcements at the Route
> Server based on routing information data (IRR and/or RPKI). Based on
> the outcome of the validation process, the invalid announcements are
> filtered in accordance with the IXP published policy.

The specification's guidance names the usual validation inputs: IRR
data (resolving the member's AS-SET), RPKI data (ROA objects or a
validated cache), and checking announcements against bogons/martians —
prefixes per RFC 1918, RFC 5735, RFC 6598, and ASNs in the AS_PATH per
RFC 5398, RFC 6793, RFC 6996, RFC 7300, RFC 7607.

This page maps each element to the config that implements it and the
surface that proves it. Every fragment below is drawn from a complete
configuration that passes `rustbgpd --check --strict` (the
[full example](#complete-example) is at the end).

## Requirement map

| Action 1 element | rustbgpd implementation | Verify with |
|------------------|-------------------------|-------------|
| RPKI-based filtering (validated cache) | [`[rpki]`](../CONFIGURATION.md#rpki) RTR client + a one-statement deny policy; `maxLength` is enforced in the Invalid determination (RFC 6811) | `rbgp policy explain`, looking-glass filtered view |
| IRR-based filtering (AS-SET resolution) | Per-member prefix/origin sets rendered from arouteserver's resolved IRR data ([IXP filter pipeline](ixp-filter-pipeline.md)) | render receipt + looking-glass filtered view |
| Bogon / martian hygiene | Shared hygiene chain: special-purpose prefix rejection, AS_SET reject, ASPA-invalid reject ([`examples/route-server/hygiene.rpol`](../../examples/route-server/hygiene.rpol)); the rendered `rs-hygiene.rpol` adds transit-free and path-length caps | `rbgp rib received <member> --rejected` |
| Filtering per published policy, fail-closed | RFC 8212 posture (`ebgp_requires_policy`), fail-stale rendering, parse-then-swap reload | `rustbgpd --check --strict`, `rbgp policy` surfaces |
| Containment of misbehaving members | Per-family max-prefix ceilings with latched teardown ([ADR-0108](../adr/0108-per-family-max-prefix-limits.md)), outbound mirrors ([ADR-0113](../adr/0113-outbound-prefix-limits.md)) | `rbgp neighbor <ip>` limit state, metrics |
| Member-visible transparency | Reject-retention store + looking-glass filtered view with reject-reason communities | Alice-LG, `rbgp rib received --rejected` |

## RPKI: invalid = reject

Connect to your validated cache (Routinator, rpki-client, StayRTR,
OctoRPKI — anything speaking RTR) and deny Invalid at import. A route
is Invalid when a covering VRP exists but the origin AS does not match
**or the announced prefix exceeds the VRP's `maxLength`** — so
maxLength violations are rejected by the same statement, per RFC 6811:

```toml
[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"

[policy.definitions.reject-rpki-invalid]
[[policy.definitions.reject-rpki-invalid.statements]]
match_rpki_validation = "invalid"
action = "deny"
```

Later VRP updates trigger an inbound Route Refresh for established
members whose import policy depends on validation state, so verdicts
track the cache rather than freezing at ingress time. Details:
[`[rpki]` reference](../CONFIGURATION.md#rpki),
[ADR-0034](../adr/0034-rpki-origin-validation.md). Reject-at-import
against a live RTR cache is exercised in the M83 interop lab
([RECEIPTS.md](../RECEIPTS.md)).

## IRR filtering: the pipeline

Action 1's IRR half expects each member's announcements checked
against its registered AS-SET. rustbgpd's supported path is the
[IXP filter pipeline](ixp-filter-pipeline.md): keep your existing
arouteserver `general.yml` / `clients.yml`, dump the resolved data
model with `arouteserver template-context`, and render per-member
`.rpol` prefix/origin sets plus per-family max-prefix ceilings with
`rs-config-render`. The render is fail-stale, never fail-open: a
broken or implausibly empty IRR answer aborts the whole render and the
last good filters stay live
([ADR-0110](../adr/0110-irr-peeringdb-filtering-pipeline.md)).

Honesty note for your MANRS documentation: the daemon has no native
IRRd/bgpq4 client — IRR ingest rides arouteserver's resolver, caches,
and refresh cadence. That is the same ingest incumbent route servers
use; the rustbgpd-specific part is the render step, maintained in this
repository.

## Bogons, martians, and path hygiene

The checked-in starter hygiene chain
([`examples/route-server/hygiene.rpol`](../../examples/route-server/hygiene.rpol))
rejects announcements carrying AS_SET segments, rejects ASPA-invalid
paths, and applies a dated dual-stack special-purpose (bogon/martian)
prefix snapshot; the rendered pipeline's `rs-hygiene.rpol` adds
transit-free rejection and a path-length cap, with RPKI origin
validation folded in. Wire it into
the import chain ahead of member-specific filters, as the
[route-server cookbook](route-server.md) does.

## The RFC 8212 posture

Action 1 requires that what the route server propagates is a policy
decision, not a default. With `ebgp_requires_policy = true`, an eBGP
direction that resolves no explicit operator policy runs a reserved
internal deny — deleting the filter chain makes members stop receiving
routes loudly instead of inheriting permit-all by omission:

```toml
[global]
asn = 64500
router_id = "192.0.2.1"
ebgp_requires_policy = true
```

Stated plainly: this is opt-in, not the daemon's out-of-the-box
default. Turn it on for a MANRS route server. It is restart-required,
and `--check` names every eBGP neighbor still resolving no explicit
policy — `--strict` turns those warnings into a failing exit. See
[ADR-0112](../adr/0112-rfc-8212-ebgp-requires-policy.md) and the
[`ebgp_requires_policy` reference](../CONFIGURATION.md#ebgp_requires_policy--rfc-8212-explicit-policy-on-ebgp).

## Per-member prefix limits

Contain a member that de-aggregates or leaks past its registered
ceiling. Limits are per family, enforced on accepted routes, and latch
the session off on breach until explicit re-enable (optionally with
one timed restart attempt):

```toml
[[neighbors]]
address = "192.0.2.10"
remote_asn = 64501
route_server_client = true
role = "route_server"
import_policy_chain = ["reject-rpki-invalid", "member-a-irr"]
max_prefixes_ipv4 = 10000
max_prefixes_ipv6 = 2000
max_prefix_restart_seconds = 900
```

The pipeline sources these ceilings from PeeringDB via arouteserver's
resolved context. References:
[ADR-0108](../adr/0108-per-family-max-prefix-limits.md) (per-family
inbound), [ADR-0113](../adr/0113-outbound-prefix-limits.md) (outbound
mirrors), [neighbor options](../CONFIGURATION.md#neighbors).

## What members can verify

Action 1 filtering is only credible if members can see it working:

- **Looking glass** ([`examples/birdwatcher-adapter/`](../../examples/birdwatcher-adapter/README.md)
  + Alice-LG): accepted routes per member, and a **filtered-routes
  view** served from the daemon's reject-retention store, each
  rejection carrying machine-readable reject-reason communities
  Alice-LG renders as human-readable causes. This also satisfies the
  programme's Action 5 (provide monitoring and debugging tools — a
  route-server looking glass for members).
- **`rbgp rib received <member> --rejected`**: enumerates a member's
  rejected announcements with reasons, without needing the prefix
  known in advance.
- **`rbgp policy explain`**: replays a specific prefix through the
  import ladder and names the statement that rejected it — the
  support-ticket workflow is in [explain.md](../explain.md).

## Complete example

A minimal self-contained Action 1 shape — RPKI invalid = reject,
inline stand-ins for rendered IRR sets, hygiene ordering, RFC 8212 on,
per-family limits. In production the member prefix statements and
ceilings come from the pipeline render; the checked-in
[`examples/route-server/`](../../examples/route-server/) starter adds
the `.rpol` hygiene chain, RPKI-valid preference, dual-stack members,
and Add-Path / per-client-best path-hiding mitigation.

```toml
[global]
asn = 64500
router_id = "192.0.2.1"
listen_port = 179
ebgp_requires_policy = true

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/grpc.sock"
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
operator = "operator"

[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"

[policy.definitions.reject-rpki-invalid]
[[policy.definitions.reject-rpki-invalid.statements]]
match_rpki_validation = "invalid"
action = "deny"

# Stand-in for a rendered per-member IRR set: permit only what the
# member's AS-SET resolves to, deny the rest.
[policy.definitions.member-a-irr]
default_action = "deny"
[[policy.definitions.member-a-irr.statements]]
prefix = "203.0.113.0/24"
action = "permit"

# Transparent export is a declared decision (RFC 7947), not an omission.
[policy.definitions.rs-transparent-export]
default_action = "permit"

[policy]
export_chain = ["rs-transparent-export"]

[[neighbors]]
address = "192.0.2.10"
remote_asn = 64501
description = "member-a"
route_server_client = true
role = "route_server"
families = ["ipv4_unicast"]
max_prefixes_ipv4 = 10000
max_prefix_restart_seconds = 900
import_policy_chain = ["reject-rpki-invalid", "member-a-irr"]
```

Validate before anything touches the wire — this exact configuration
exits 0:

```bash
rustbgpd --check --strict manrs-action1.toml
```

## Publishing your policy

MANRS asks for the filtering policy to be published (or at least
member-visible). The pieces to link from your IXP policy page: which
inputs you filter on (IRR via your arouteserver site files, RPKI
invalid = reject including maxLength, the bogon snapshot), the
max-prefix action and restart window, and where members can see their
own filtered routes (your Alice-LG instance). The
[evaluation matrix](../ixp-evaluation.md) is the capability-level
summary; this page is the per-control detail behind it.
