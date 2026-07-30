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

The inventory in `docs/grpc-method-inventory.md` classifies every
RPC across the management surface into four tiers by worst-case effect
on a compromised credential. At this ADR's acceptance that was 76 RPCs
(72 native `rustbgpd.v1` RPCs plus 4 `gnmi.gNMI` RPCs) distributed as
`read` (0), `sensitive_read` (40), `mutating` (17), `operator_only`
(19); the surface has grown since (see `docs/grpc-method-inventory.{md,json}`
for the live counts). That distribution makes
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

Extend `[global.telemetry.grpc_tcp]` and `[global.telemetry.grpc_uds]`
with a `max_tier` field while keeping the existing binary
`access_mode` as a compatibility ceiling:

```toml
[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
max_tier = "operator_only"   # full surface

[global.telemetry.grpc_uds]
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
enforcement = "tier"  # default since v0.24.0 (slice 4b default flip)
```

- `legacy` — preserves the pre-tier listener-only authorization
  behavior. Listener `max_tier` caps still deny methods above the
  listener ceiling, but principal roles are not used to authorize or
  deny calls.
- `tier` — opt-in per-principal enforcement. The authenticated
  principal must be present in `[security.grpc.roles]`, and the role's
  ceiling must be at least the requested method tier.

The shipped slice 1 matrix has no `[security.grpc]` config and no
runtime authorization/logging behavior change. Slice 2 introduces the
legacy audit runtime mode; Slice 4 adds listener tier caps while
keeping `legacy` as the default. The opt-in enforcement slice accepts
`tier` and applies deny-by-role decisions; the later default-flip slice
defaults to `tier` and documents the migration in `CHANGELOG.md` and
`KNOWN_ISSUES.md`.
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
`DiffRuntimeConfigRequest.candidate_toml`,
`PlanConfigTransactionRequest.candidate_toml`,
`ApplyConfigTransactionRequest.candidate_toml`, and any field tagged with a
future credential marker are omitted or replaced with redacted metadata before
the log line is emitted. TCP-AO key material is TOML/runtime-only today except
when it appears inside `candidate_toml` for config diff / transaction planning
and apply. Transaction apply comments are also summarized as present/absent
rather than logged verbatim. The first implementation uses an explicit mask table for
the current narrow credential ingress instead of descriptor-driven proto
field-option reflection; a proto credential marker remains a future schema
aid if the field set grows. Peer-group read RPCs redact `md5_password`
rather than echoing stored secret material and expose only `has_md5_password`.
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
  prerequisite, not bolted on after. Result-aware audit records now cover
  forwarded calls with bounded labels such as `handler_ok` and
  `handler_invalid_argument`.
- Backwards-compat `enforcement = "legacy"` keeps existing operators
  running through one release while surfacing what would break.

**Negative:**

- Six-slice ladder means full per-principal enforcement is not on by default
  until the enforcement-flip slice. Until then, listener `max_tier` caps provide
  coarse protection, but role mappings remain audit/planning data.
- A Rust matrix is daemon-local; external consumers do not see tier
  metadata in generated bindings until a later proto annotation slice.
- The per-listener `max_tier` field overlaps with the existing binary
  `access_mode`. Auto-translation at config-load keeps existing operator TOML
  working, and `access_mode = "read_only"` remains a compatibility ceiling that
  cannot be weakened by `max_tier`.
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
   require all methods in it to have an inventory-assigned tier. Export the same
   source-of-truth matrix as `docs/grpc-method-inventory.json` for auditors and
   generated clients, with tests that fail on JSON drift.
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
   `[security.grpc].enforcement = "legacy"` role-audit mode.
4. **Listener tier cap.** Add `max_tier` to
   `[global.telemetry.grpc_tcp]` / `[global.telemetry.grpc_uds]`.
   Translate the existing `access_mode = "read_only"` to a
   `sensitive_read` compatibility ceiling and `access_mode =
   "read_write"` to `operator_only`. If both `access_mode` and
   `max_tier` are configured, the effective cap is the stricter one.
   Listener cap enforcement is active in all modes including
   `legacy`.
5. **Enforcement + default flip.** Use the runtime layer from slice 2 plus the
   identity/role/listener-cap config from slices 3–4 to deny
   unauthorized RPCs. Ship opt-in `enforcement = "tier"` first with
   `legacy` still the default, then flip the default to `tier` in a
   dedicated migration/default-flip slice. Update `CHANGELOG.md`,
   `KNOWN_ISSUES.md`, and `docs/SECURITY.md` migration notes.
6. **Audit log hardening.** First add result-aware audit records and
   explicit masking for the current credential ingress
   (`candidate_toml`, peer-group `md5_password`, and TCP-AO keys embedded in
   candidate TOML; transaction comments summarized as present/absent). Add the
   `[(rustbgpd.v1.credential) = true]` field extension and per-tier log-level
   configuration in follow-up slices if the credential field set expands or
   operators need configurable sampling.
7. **External-review prep.** Threat-model doc, per-slice security
   sign-off, external auditor packet (inventory + ADR + threat model
   + audit-log sample). `docs/adr/0064-threat-model.md` now models the
   enforced tier system and re-derives the residual risks from that
   posture. Per-slice sign-off and assembly of an external auditor packet
   remain follow-up work.

Slices 1–5 are the v1.0 blocker; slice 6 is hardening that should
land in the same release window; slice 7 is the gate the external
review pulls against. Slices 1–4 can ship under `legacy` enforcement
without breaking any existing operator. Slice 5 now has two phases:
opt-in `tier` enforcement first, then the breaking default flip in its
own migration window.

## Open questions deferred to follow-up

- **Per-call MFA for `operator_only`?** Some operators want a second
  factor (e.g. signed timestamp from a hardware token) for `Shutdown`
  and `TriggerMrtDump`. Out of scope for v1; revisit if external
  review flags it.
- **Audit-log durability.** v1.0 ships structured daemon logs collected by
  journald, syslog, or an external log agent. `docs/OPERATIONS.md` now defines
  retention, access-control, and query guidance for `grpc_authz` records. A
  separate in-daemon durable audit channel remains a future design item because
  file/syslog/remote-sink backpressure semantics need an explicit decision.
- **Accepted-client resource budgets.** v1.0 relies on listener `max_tier`,
  tier roles, pagination, bounded histories, stream lag/subscriber metrics, and
  operational network controls. Per-principal or per-listener request/stream
  budgets remain future work if production evidence shows the existing signals
  are insufficient.
- **Dynamic role updates.** Listeners read the role map at startup. SIGHUP
  keeps the live startup authorization pinned and requires a restart for role,
  principal, enforcement, listener, or access changes. Live role revocation
  without rebuilding the listener (for example, a "kick this principal" RPC)
  is not v1.
- **Capability-token alternative.** A future model could replace
  static principal role mapping with short-lived capability tokens minted by
  an external IAM. This ADR's principal-lookup mechanism does not
  preclude that direction — a future ADR could add a token-bearer
  interceptor that resolves to the same tier-check primitive.

## Implementation status

Slice 1 is implemented by the ADR-0064 foundation PR and follow-up JSON export:
checked method matrix, Markdown inventory/ADR correction, and the
machine-readable `docs/grpc-method-inventory.json` artifact. Slice 2 is
implemented by the runtime tier-decision layer: method-path lookup, structured
`grpc_authz` decision logs, and bounded-cardinality metrics. Slice 3a adds staged
`[security.grpc.roles]`, `enforcement = "legacy"`, and explicit non-mTLS
listener principal labels for bearer-token TCP and UDS audit identity.
Slice 4a adds enforced per-listener `max_tier` caps while preserving
`access_mode` as a compatibility ceiling. Slice 3b adds native mTLS certificate
principal extraction (`rustbgpd:` URI SAN, then email SAN, then Subject CN);
slice 5 uses that principal for enforced authorization. Slice 5a adds opt-in
per-principal role enforcement, slice 5b adds migration guidance and config
coverage, and the final phase makes `tier` the default. Slice 6a adds
result-aware audit records and credential-masked request summaries for
`DiffRuntimeConfig`, `SetPeerGroup`, `PlanConfigTransaction`, and
`ApplyConfigTransaction`. Durable in-daemon audit-sink semantics and optional
proto credential markers remain deferred.

| Slice | Status |
|-------|--------|
| 1. Foundation | Implemented by the checked method-matrix PR + machine-readable JSON export |
| 2. Audit/runtime path | Done: decision/audit layer, used by the enforced cap and role checks |
| 3. Identity + roles | Done: roles config + bearer/UDS principals + mTLS principal extraction |
| 4. Listener tier cap | Done: `max_tier` listener cap enforced |
| 5. Enforcement + default flip | Done in v0.24.0: opt-in `tier` role enforcement (slice 5a) + migration prep + default flip from `legacy` to `tier` (slice 5b, closes #164) |
| 6. Audit log hardening | Partial: result-aware records + explicit credential masking table + operations guidance for audit retention and resource guardrails |
| 7. External-review prep | Partial: current enforced-system threat model; external sign-off and auditor packet remain |
