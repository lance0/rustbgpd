# ADR-0064: gRPC per-method authorization

**Status:** Draft
**Date:** 2026-05-18

## Context

rustbgpd's gRPC surface is currently binary: any client that completes
the mTLS handshake on a configured `[[telemetry.grpc_tcp]]` or
`[[telemetry.grpc_uds]]` listener can call any method on any service.
Read and write surfaces share the same listener, the same client cert,
and the same code path through the tonic service routers.

The inventory in `docs/grpc-method-inventory.md` classifies the 66
RPCs across 10 services into four tiers by worst-case effect on a
compromised mTLS cert: `read` (1), `sensitive_read` (38), `mutating`
(16), `operator_only` (11). That distribution makes the binary model
indefensible at v1.0 — a leaked observability cert grants the holder
`Shutdown`, network-wide `SetGracefulShutdown`, route injection,
FlowSpec filter installation, and EVPN MAC hijack origination.

ROADMAP P0 ("gRPC security audit + authorization split") lists this
as a v1.0 blocker. The exit criterion is: "Security review complete;
mutating RPCs can be disabled or isolated from read-only observability
endpoints."

### What we already have

- mTLS handshake at the listener boundary (ADR-0015).
- Per-listener `access_mode = "read_only" | "read_write"` switch
  exists in `[[telemetry.grpc_tcp]]` /
  `[[telemetry.grpc_uds]]`. Each mutating handler in
  `crates/api/src/server.rs` calls `read_only_rejection()` at
  entry and returns `PermissionDenied` when the listener was
  constructed in `ReadOnly` mode. Listener access mode is passed
  into `InjectionService::new`, `PeerGroupService::new`,
  `PolicyService::new`, `GlobalService::new`, and the
  per-listener `ControlService` constructor; methods without an
  explicit `read_only_rejection()` call are reachable from any
  listener.
- A token-bearer `AuthInterceptor` exists at the listener boundary
  for optional bearer-token authentication; it does not yet
  consult per-method tier.

The current `access_mode` is a two-tier substitute for the four-tier
model the inventory needs. It captures "no mutations" reasonably but
puts `ListReceivedRoutes` (RIB content) and `GetHealth` (liveness
ping) in the same bucket, and offers no way to require operator-tier
authorization for `Shutdown` while allowing routine `AddNeighbor`.

### What the design must answer

The eight open questions in the inventory's "Notes for ADR-0064"
section, in summary:

1. Granularity: tier per method, listener tier cap, or both?
2. Role-to-tier mapping mechanism.
3. Authentication identity extraction from mTLS.
4. Streaming RPC handshake-time vs per-event check.
5. Credential ingress (`AddNeighbor`) handling in audit logs.
6. Backwards-compatibility migration mode.
7. Defensive classification of `UNIMPLEMENTED` methods like
   `SetGlobal`.
8. Audit-log requirements per tier.

## Decision

Adopt a **per-method tier annotation enforced by a tonic interceptor,
bounded above by a per-listener tier cap**, with role-to-tier mapping
driven by a cert-identity lookup in `[security.grpc.roles]`. Ship in
six slices so the enforcement default flip is its own reviewable PR.

### 1. Tier model

Use the four tiers from the inventory verbatim:

- `read` — pure observability.
- `sensitive_read` — read-only with topology / RIB / policy disclosure.
- `mutating` — reversible per-object state change.
- `operator_only` — network-wide impact, process lifecycle, or
  large-scale dataplane injection.

Tiers are totally ordered: `read < sensitive_read < mutating <
operator_only`. A role authorized for tier N is implicitly authorized
for all tiers < N.

### 2. Per-method annotation in proto

Embed the tier in the proto so it is the single source of truth and
ships to every consumer:

```proto
import "rustbgpd/v1/authz.proto";

extend google.protobuf.MethodOptions {
  optional rustbgpd.v1.AuthTier auth_tier = 50000;
}

enum AuthTier {
  AUTH_TIER_UNSPECIFIED = 0;
  AUTH_TIER_READ = 1;
  AUTH_TIER_SENSITIVE_READ = 2;
  AUTH_TIER_MUTATING = 3;
  AUTH_TIER_OPERATOR_ONLY = 4;
}

service RibService {
  rpc ListReceivedRoutes(ListRoutesRequest) returns (ListRoutesResponse) {
    option (auth_tier) = AUTH_TIER_SENSITIVE_READ;
  }
  // ...
}
```

`AUTH_TIER_UNSPECIFIED` is treated by the interceptor as
`operator_only` (defense in depth: a method that forgets to declare a
tier fails closed, not open). This is the mechanism that catches the
`SetGlobal` trap from inventory question 7.

### 3. Per-listener tier cap

Extend `[[telemetry.grpc_tcp]]` and `[[telemetry.grpc_uds]]` with a
`max_tier` field (and deprecate the existing binary `access_mode`
field over one release):

```toml
[[telemetry.grpc_tcp]]
address = "0.0.0.0:50051"
max_tier = "operator_only"   # full surface

[[telemetry.grpc_tcp]]
address = "127.0.0.1:50052"
max_tier = "sensitive_read"  # observability listener

[[telemetry.grpc_uds]]
path = "/run/rustbgpd/inject.sock"
max_tier = "operator_only"   # route-injection channel, UDS-scoped
```

The listener's `max_tier` is a hard ceiling: the interceptor rejects
any call whose method tier exceeds `max_tier` regardless of caller
role. This gives operators a defense-in-depth knob — even if a cert
is misclassified or a role assignment is wrong, the listener tier
caps the blast radius. Inventory question 1 is answered: both
granularities, listener as ceiling, per-method as floor.

### 4. Role-to-tier mapping in config

Authentication identity comes from the mTLS peer cert. We extract a
**principal string** in this priority order:

1. The first `URI` SAN whose scheme is `rustbgpd` (e.g.
   `rustbgpd://operator/alice`).
2. The first `email` SAN (e.g. `alice@example.com`).
3. The cert's Subject Common Name.

Roles are configured per-principal in `[security.grpc.roles]`:

```toml
[security.grpc.roles]
"operator-prod.example" = "operator"
"automation.example"    = "automation"
"alice@example.com"     = "operator"
"observer-readonly"     = "observer"
```

The three roles map to tier ceilings:

| Role | Max tier |
|------|----------|
| `observer` | `sensitive_read` |
| `automation` | `mutating` |
| `operator` | `operator_only` |

A cert whose principal is not in the map is rejected at handshake-time
(see slice 4). A custom additional role is not required for v1 — three
roles cover the inventory cleanly; adding a fourth is a non-breaking
config change.

This explicitly **does not** use X.509 custom OIDs, SPIFFE IDs, or
external IAM lookups. Inventory question 2 favors the lowest-friction
mechanism that lets operators rotate roles by editing TOML rather than
re-issuing certs.

### 5. Streaming RPCs

`WatchRoutes` and `WatchEvents` are validated **once at the unary
handshake portion of the streaming open**, not per emitted message.
Tonic's interceptor sees the metadata-and-tier check before the
service handler accepts the stream. A subsequent role change in the
daemon's config does not retroactively close existing streams; the
client must reconnect. Inventory question 4 answered.

### 6. Backwards compatibility

Add `[security.grpc]` with an `enforcement` field:

```toml
[security.grpc]
enforcement = "legacy"  # default in slice 1; flipped to "tier" in slice 4
```

- `legacy` — interceptor logs tier decisions but does not enforce them
  (audit-only). All calls that would have been authorized under the
  old binary `access_mode` continue to work. Calls that would be
  rejected under tier enforcement emit a `WARN` log so operators see
  what would break.
- `tier` — full enforcement per slices 2–4 below.

Slice 1 ships with `legacy` default. Slice 4 flips the default to
`tier` and documents the migration in `CHANGELOG.md` and
`KNOWN_ISSUES.md`. Inventory question 6 answered.

### 7. Audit logging

Every RPC call produces a structured log entry. Minimum level by tier:

| Tier | Log level | Fields |
|------|-----------|--------|
| `read` | sampled (1 in N, configurable) | timestamp, principal, method |
| `sensitive_read` | every call | + peer-identity argument when present |
| `mutating` | every call | + redacted argument summary, result code |
| `operator_only` | every call, at `WARN` | + full argument summary with credential fields masked, caller principal, listener address |

Credential masking is mandatory: `md5_password` (in
`AddNeighborRequest`), `tcp_ao.key` (in `AddNeighborRequest.tcp_ao`),
and any field tagged with a future `[(rustbgpd.v1.credential) = true]`
extension are replaced with `***REDACTED***` before the log line is
emitted. Inventory questions 5 and 8 answered.

### 8. `UNIMPLEMENTED` methods

Annotate every `UNIMPLEMENTED` method as `AUTH_TIER_OPERATOR_ONLY` so
the eventual implementation must explicitly downgrade if warranted.
`SetGlobal` is the current example. Inventory question 7 answered.

## Consequences

**Positive:**

- Per-method tier comes from the proto, so external consumers see the
  classification in generated code and bindings.
- Listener tier cap gives operators a coarse-grained kill-switch
  independent of role-mapping correctness.
- Three-role mapping with TOML-driven principal lookup is cheap to
  audit and rotates without cert re-issuance.
- `UNIMPLEMENTED → operator_only` default prevents the "we'll classify
  it when we implement it" trap.
- Audit log with mandatory credential masking is a v1.0 compliance
  prerequisite, not bolted on after.
- Backwards-compat `enforcement = "legacy"` keeps existing operators
  running through one release while surfacing what would break.

**Negative:**

- Six-slice ladder means full enforcement is not on by default until
  slice 4. Until then, the audit-only mode produces signal but no
  protection.
- Proto annotation requires every consumer to regenerate after
  slice 1. Wire compatibility is preserved (method semantics
  unchanged); only generated code differs.
- The per-listener `max_tier` field deprecates the existing binary
  `access_mode` over one release. Auto-translation at config-load
  keeps existing operator TOML working; the `WARN` on use is the
  forcing function to update the config before the deprecation
  window closes.
- Principal extraction depends on cert SAN conventions; operators
  using bare-CN certs without SANs need to migrate their PKI or
  configure CN-based principal mapping. The fallback to Subject CN
  in §4 covers them, but cleanest practice is URI or email SANs.
- The four-tier model still doesn't separate "credential ingress"
  from other `mutating` calls. `AddNeighbor` carrying
  `md5_password` is the only credential-write surface today; if
  more land later, a future ADR may split a `credential_write`
  tier off. Audit-log masking is the v1.0 mitigation.

## Slicing

Each slice ships as one or more PRs. The slice boundary is the
review/rollback unit.

1. **Foundation.** Add the `AuthTier` enum, the
   `option (auth_tier)` extension, the `[security.grpc]` table with
   `enforcement = "legacy"` default, and the interceptor scaffolding
   that resolves the tier per call and logs (does not enforce). All
   66 methods get their inventory-assigned annotation. `UNIMPLEMENTED`
   defaults to `operator_only`.
2. **Identity + roles.** Implement principal extraction from mTLS
   peer cert (URI-SAN → email-SAN → CN priority). Add
   `[security.grpc.roles]` mapping. Add `observer | automation |
   operator` role-to-tier lookup. Still audit-only.
3. **Listener tier cap.** Add `max_tier` to
   `[[telemetry.grpc_tcp]]` / `[[telemetry.grpc_uds]]`. Translate
   the existing `access_mode = "read_only"` → `max_tier =
   "sensitive_read"` and `access_mode = "read_write"` → `max_tier =
   "operator_only"` automatically at config-load time; deprecate
   `access_mode` (still parsed, emits a `WARN` on use). Listener
   cap enforces in all modes including `legacy`.
4. **Enforcement flip.** Default `enforcement = "tier"`. Update
   `CHANGELOG.md`, `KNOWN_ISSUES.md`, and
   `docs/SECURITY.md` migration notes.
5. **Audit log hardening.** Add the `[(rustbgpd.v1.credential) =
   true]` field extension. Mask credential fields in the audit-log
   formatter. Add per-tier log-level configuration.
6. **External-review prep.** Threat-model doc
   (`docs/adr/0064-threat-model.md`), per-slice security
   sign-off, external auditor packet (inventory + ADR + threat model
   + audit-log sample).

Slices 1–4 are the v1.0 blocker; slice 5 is hardening that should
land in the same release window; slice 6 is the gate the external
review pulls against. Slices 1–3 can ship under `legacy` enforcement
without breaking any existing operator. Slice 4 is the breaking
moment and gets its own release window's worth of operator
communication.

## Open questions deferred to follow-up

- **Per-call MFA for `operator_only`?** Some operators want a second
  factor (e.g. signed timestamp from a hardware token) for `Shutdown`
  and `TriggerMrtDump`. Out of scope for v1; revisit if external
  review flags it.
- **Audit-log durability.** v1.0 ships structured stderr logs; a
  durable audit channel (file rotation, syslog, remote sink) is a
  future operations slice.
- **Dynamic role updates.** Slice 2 reads the role map at startup
  and on SIGHUP. Live role revocation without a SIGHUP (e.g. a
  "kick this principal" RPC) is not v1.
- **Capability-token alternative.** A future model could replace
  per-cert role mapping with short-lived capability tokens minted by
  an external IAM. This ADR's principal-lookup mechanism does not
  preclude that direction — a future ADR could add a token-bearer
  interceptor that resolves to the same tier-check primitive.

## Implementation status

Slice 1 not yet started. This ADR is the design entry; PRs implement
slices in order. Each slice PR updates the **Implementation Status**
section below.

| Slice | Status |
|-------|--------|
| 1. Foundation | Not started |
| 2. Identity + roles | Not started |
| 3. Listener tier cap | Not started |
| 4. Enforcement flip | Not started |
| 5. Audit log hardening | Not started |
| 6. External-review prep | Not started |
