# ADR-0064: gRPC per-method authorization

**Status:** Accepted
**Date:** 2026-05-18

## Context

rustbgpd's gRPC surface is currently protected at the listener level:
clients must satisfy the listener's transport/authentication boundary
(Unix socket permissions, optional bearer token, and/or mTLS), and
`access_mode = "read_only"` rejects mutating handlers. A
`read_write` listener still exposes the full service surface to any
accepted client, and `read_only` does not distinguish liveness from
RIB/policy/topology reads.

The inventory in `docs/grpc-method-inventory.md` classifies the 66
RPCs across 10 services into four tiers by worst-case effect on a
compromised credential: `read` (0), `sensitive_read` (33),
`mutating` (15), `operator_only` (18). That distribution makes
unscoped `read_write` access too broad for v1.0 — a leaked automation
credential grants the holder `Shutdown`, network-wide
`SetGracefulShutdown`, route injection, FlowSpec filter installation,
and EVPN MAC hijack origination.

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
puts `ListReceivedRoutes` (RIB content) and `GetHealth` (peer/route
counts) in the same bucket, and offers no way to require operator-tier
authorization for `Shutdown` while allowing routine `AddNeighbor`.

### What the design must answer

The eight open questions in the inventory's "Notes for ADR-0064"
section, in summary:

1. Granularity: tier per method, listener tier cap, or both?
2. Role-to-tier mapping mechanism.
3. Authentication identity extraction from mTLS.
4. Streaming RPC handshake-time vs per-event check.
5. Credential ingress (`SetPeerGroup` for `md5_password`) handling
   in audit logs.
6. Backwards-compatibility migration mode.
7. Defensive classification of `UNIMPLEMENTED` methods like
   `SetGlobal`.
8. Audit-log requirements per tier.

## Decision

Adopt a **checked per-method tier matrix enforced by a gRPC
authorization layer, bounded above by a per-listener tier cap**, with
role-to-tier mapping driven by an authenticated principal lookup in
`[security.grpc.roles]`. Ship in six slices so the enforcement default
flip is its own reviewable PR.

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

### 2. Checked per-method matrix

The first implementation source of truth is a static Rust matrix in
`crates/api/src/authz.rs`:

```rust
GrpcMethodAuthz {
    path: "/rustbgpd.v1.RibService/ListReceivedRoutes",
    service: "rustbgpd.v1.RibService",
    method: "ListReceivedRoutes",
    tier: AuthTier::SensitiveRead,
}
```

Unit tests parse `proto/rustbgpd.proto` and fail if a new RPC is added
without a tier assignment. This gives the daemon an immediately
testable source of truth without depending on prost/tonic descriptor
reflection. A future proto `MethodOptions` annotation can still be
added for external consumers, but runtime enforcement does not depend
on it.

Unknown method paths are treated as `operator_only` once enforcement
lands (defense in depth: a method that forgets to enter the matrix
fails closed, not open). This is the mechanism that catches the
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

The listener's `max_tier` is a hard ceiling: the authorization layer rejects
any call whose method tier exceeds `max_tier` regardless of caller
role. This gives operators a defense-in-depth knob — even if a cert
is misclassified or a role assignment is wrong, the listener tier
caps the blast radius. Inventory question 1 is answered: both
granularities, listener as ceiling, per-method as floor.

### 4. Role-to-tier mapping in config

Authentication identity comes from the listener's authenticated
principal source:

- mTLS listeners extract a **principal string** from the peer cert in
  this priority order:

1. The first `URI` SAN whose scheme is `rustbgpd` (e.g.
   `rustbgpd://operator/alice`).
2. The first `email` SAN (e.g. `alice@example.com`).
3. The cert's Subject Common Name.

- Bearer-token listeners must configure an explicit token principal
  label before tier enforcement can be enabled, because the token value
  itself is not a stable audit identity.
- UDS listeners must configure an explicit listener principal or rely
  only on `max_tier`; filesystem permissions authenticate the client
  but do not identify a per-client role.

If tier enforcement is enabled on a listener without either mTLS
principal extraction or an explicit non-mTLS principal, startup rejects
the configuration instead of falling back open.

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

`WatchRoutes` and `WatchEvents` are validated **once when the stream
opens**, not per emitted message. A subsequent role change in the
daemon's config does not retroactively close existing streams; the
client must reconnect. Inventory question 4 answered.

### 6. Backwards compatibility

Later runtime-enforcement slices add `[security.grpc]` with an
`enforcement` field:

```toml
[security.grpc]
enforcement = "legacy"  # default in slice 1; flipped to "tier" in slice 4
```

- `legacy` — once the authorization layer exists, it logs tier
  decisions but does not enforce them (audit-only). All calls that
  would have been authorized under the old binary `access_mode`
  continue to work. Calls that would be rejected under tier
  enforcement emit a `WARN` log so operators see what would break.
- `tier` — full enforcement per slices 2–4 below.

The shipped slice 1 matrix has no `[security.grpc]` config and no
runtime authorization/logging behavior change. Slice 2 introduces the
legacy/audit-only runtime mode; slice 4 flips the default to `tier` and
documents the migration in `CHANGELOG.md` and `KNOWN_ISSUES.md`.
Inventory question 6 answered.

### 7. Audit logging

Every RPC call produces a structured log entry. Minimum level by tier:

| Tier | Log level | Fields |
|------|-----------|--------|
| `read` | sampled (1 in N, configurable) | timestamp, principal, method |
| `sensitive_read` | every call | + peer-identity argument when present |
| `mutating` | every call | + redacted argument summary, result code |
| `operator_only` | every call, at `WARN` | + full argument summary with credential fields masked, caller principal, listener address |

Credential masking is mandatory: `PeerGroupDefinition.md5_password`,
`DiffRuntimeConfigRequest.candidate_toml`, and any field tagged with a
future credential marker are omitted or replaced with `***REDACTED***`
before the log line is emitted. TCP-AO key material is TOML/runtime-only
today except when it appears inside `candidate_toml` for config-diff
validation. Peer-group read RPCs redact `md5_password` rather than
echoing stored secret material and expose only `has_md5_password`.
Inventory questions 5 and 8 answered.

### 8. `UNIMPLEMENTED` methods

Assign every `UNIMPLEMENTED` method `operator_only` in the method
matrix so the eventual implementation must explicitly downgrade if
warranted. `SetGlobal` is the current example. Inventory question 7
answered.

## Consequences

**Positive:**

- Per-method tier is checked in code against the proto inventory, so a
  new RPC cannot land silently without an authorization classification.
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
- A Rust matrix is daemon-local; external consumers do not see tier
  metadata in generated bindings until a later proto annotation slice.
- The per-listener `max_tier` field deprecates the existing binary
  `access_mode` over one release. Auto-translation at config-load
  keeps existing operator TOML working; the `WARN` on use is the
  forcing function to update the config before the deprecation
  window closes.
- Principal extraction depends on cert SAN conventions; operators
  using bare-CN certs without SANs need to migrate their PKI or
  configure CN-based principal mapping. The fallback to Subject CN
  in §4 covers them, but cleanest practice is URI or email SANs.
- The four-tier model still does not separate "credential ingress"
  from other writes. `SetPeerGroup` can carry `md5_password` today,
  while `ListPeerGroups` / `GetPeerGroup` redact that field on read
  responses. If more credential-write surfaces land later, a future
  ADR may split a `credential_write` tier off. Audit-log masking and
  read-response redaction are the v1.0 mitigations.

## Slicing

Each slice ships as one or more PRs. The slice boundary is the
review/rollback unit.

1. **Foundation.** Add the `AuthTier` enum and static method matrix in
   `crates/api/src/authz.rs`; tests parse `proto/rustbgpd.proto` and
   require all 66 methods to have an inventory-assigned tier.
   `UNIMPLEMENTED` defaults to `operator_only`. Correct this ADR and
   the inventory to match shipped listener-level `access_mode`
   behavior. No runtime enforcement change.
2. **Audit-only runtime path.** Add a Tower/tonic runtime layer that
   can see the gRPC method path, look up `crates/api/src/authz.rs`,
   and emit structured audit-only tier-decision logs plus bounded
   Prometheus counters. This slice does not deny requests and does
   not alter mTLS, bearer-token, UDS, or listener `access_mode`
   behavior.
3. **Identity + roles.** Implement principal extraction from mTLS
   peer cert (URI-SAN → email-SAN → CN priority), plus explicit
   non-mTLS listener principals for bearer-token / UDS deployments that
   opt into tier enforcement. Add `[security.grpc.roles]` mapping. Add
   `observer | automation | operator` role-to-tier lookup plus
   `[security.grpc].enforcement = "legacy"` audit-only mode.
4. **Listener tier cap.** Add `max_tier` to
   `[[telemetry.grpc_tcp]]` / `[[telemetry.grpc_uds]]`. Translate
   the existing `access_mode = "read_only"` → `max_tier =
   "sensitive_read"` and `access_mode = "read_write"` → `max_tier =
   "operator_only"` automatically at config-load time; deprecate
   `access_mode` (still parsed, emits a `WARN` on use). Listener
   cap enforces in all modes including `legacy`.
5. **Enforcement flip.** Use the runtime layer from slice 2 plus the
   identity/role/listener-cap config from slices 3–4 to deny
   unauthorized RPCs. Default `enforcement = "tier"`. Update
   `CHANGELOG.md`, `KNOWN_ISSUES.md`, and
   `docs/SECURITY.md` migration notes.
6. **Audit log hardening.** Add the `[(rustbgpd.v1.credential) =
   true]` field extension. Mask credential fields in the audit-log
   formatter. Add per-tier log-level configuration.
7. **External-review prep.** Threat-model doc
   (`docs/adr/0064-threat-model.md`), per-slice security
   sign-off, external auditor packet (inventory + ADR + threat model
   + audit-log sample).

Slices 1–5 are the v1.0 blocker; slice 6 is hardening that should
land in the same release window; slice 7 is the gate the external
review pulls against. Slices 1–4 can ship under `legacy` enforcement
without breaking any existing operator. Slice 5 is the breaking
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
  static principal role mapping with short-lived capability tokens minted by
  an external IAM. This ADR's principal-lookup mechanism does not
  preclude that direction — a future ADR could add a token-bearer
  interceptor that resolves to the same tier-check primitive.

## Implementation status

Slice 1 is implemented by the ADR-0064 foundation PR: checked method
matrix plus inventory/ADR correction. Slice 2 is implemented by the
audit-only runtime layer: method-path lookup, structured `grpc_authz`
decision logs, and bounded-cardinality metrics with no authorization
behavior change. Later slices implement real principal extraction,
roles, listener tier caps, runtime enforcement, and result/request
audit-log hardening.

| Slice | Status |
|-------|--------|
| 1. Foundation | Implemented by the checked method-matrix PR |
| 2. Audit-only runtime path | Implemented by the runtime audit-layer PR |
| 3. Identity + roles | Not started |
| 4. Listener tier cap | Not started |
| 5. Enforcement flip | Not started |
| 6. Audit log hardening | Not started |
| 7. External-review prep | Not started |
