# ADR-0122: Compatibility-debt inventory and removal schedule

**Status:** Accepted
**Date:** 2026-08-03
**Decision recorded:** 2026-08-08

## Context

rustbgpd is public alpha. The stated posture (README "Config stability" /
"API stability", `docs/v1-stable-contract.md`) is correctness over
compatibility: only the machine-pinned v1 RS/RR surface carries a
compatibility promise; everything else may change between minors with a
CHANGELOG migration note, and long-lived shims are not wanted. Despite that,
compatibility code accumulates one PR at a time — dead enum variants kept for
a schema hash, hidden CLI aliases marked "must never be removed",
rolling-upgrade fallbacks for daemons that no longer exist in any supported
deployment.

This ADR is the single inventory of that debt and its removal schedule.
Nothing is removed by this ADR; each scheduled entry lands as its own PR
against the release named here. ADR-0125 records the remaining owner outcomes:
unary Plan/Apply stays as a permanent small-candidate path, and the three
hidden `--from-file` aliases were removed in the v0.65 development cycle.

Not listed, by deliberate judgment: protocol-mandated compatibility (RFC 6793
AS4 compat attributes, RFC 8277 §2.4 compatibility field, RFC 5925 TCP-AO
key deprecation flags), rejection of deprecated third-party proto forms (gNMI
`Path.element` / `Value`), and API semantics that read as compat wording but
are really deliberate design (`page_size = 0` full snapshot, empty
`required_families` inheriting partial-intersection behavior, bare integers
as exact numeric matches). These are not debt.

## Decision

### Lifetime policy for migration aids

Unless an entry says otherwise:

- **Retired-config-key migration pointers** live three minor releases after
  the key's removal, then are deleted (the plain unknown-field error
  remains).
- **CLI/daemon rolling-upgrade fallbacks** support exactly the previous minor
  release; a fallback whose emitting daemon is two or more minors old is
  prunable without a new decision.
- Removal of anything covered by `docs/v1-stable-surface.json` additionally
  runs the blessed-surface procedure (`scripts/check-v1-stable-surface.py`
  re-bless) and gets a CHANGELOG **Removed** entry with migration steps.

### Inventory

Classifications: **remove-now** (next docs/cleanup PR, current release
window), **deprecate → vX** (scheduled removal release), **keep** (retained
with reason), **removed (vX)**, and **simplified (vX)** (completed work retained
as inventory history).

#### Config schema surface

| # | Item | What it preserves | Cost of keeping | Classification | Removal mechanics |
|---|------|-------------------|-----------------|----------------|-------------------|
| C1 | `GrpcEnforcementConfig::Legacy` enum variant (`src/config/schema.rs`). Dead since #1431: validation rejects it outright (`src/config/validation.rs`); the runtime path was removed in v0.63.0 (ADR-0064 status addendum). | v1 config surface still *parses* `enforcement = "legacy"` so the rejection message can carry migration steps; keeps the pinned `GrpcSecurityConfig` schema hash (`docs/v1-stable-surface.json`, `docs/rustbgpd.schema.json`). | Dead variant, bespoke error assembly, structural tests policing that no fixture uses it (`src/reload.rs`, `src/config_transaction_control.rs`). | deprecate → v0.65 | Delete variant; add a `retired_key_error`-style pointer for `enforcement = "legacy"` (three-minor lifetime per policy above); re-bless v1 surface + JSON schema; ADR-0064 addendum note; CHANGELOG Removed. |
| C2 | Retired-key migration pointers in the TOML loader (`retired_key_error`, `src/config/mod.rs`): `[global.telemetry.looking_glass]` and `[[policy.import]]`/`[[policy.export]]`, both removed in v0.51.0. | Actionable migration error instead of a bare serde unknown-field diagnostic. | Two string branches; trivial. | removed (v0.63) | The pointers aged past the three-minor lifetime and were deleted; the documented `retired_key_error` insertion seam remains for C1. The retired keys now receive the ordinary typed-config diagnostic. |
| C3 | `BgpRoleConfig` serde aliases `rs` / `rs-client` (`src/config/schema.rs`). | Common shorthand spellings for RFC 9234 roles in operator configs. | Two attribute lines; zero runtime cost. | keep | Documented spellings, not a migration shim. |

#### CLI surface

| # | Item | What it preserves | Cost of keeping | Classification | Removal mechanics |
|---|------|-------------------|-----------------|----------------|-------------------|
| L1 | Hidden `--from-file` compatibility aliases on `config diff` / `config plan` / `config apply` (`crates/cli/src/main.rs`), kept when LAN-329 made file arguments positional. The conventions comment pledged they "must never be removed" in the same file. | Old scripts invoking the pre-LAN-329 flag spelling. | Three hidden args + `candidate_file()` merge helper; near zero. The real debt was the "never" pledge, which contradicted the alpha posture. | removed (v0.65) | The three hidden args and helper were deleted, first-party callers and checked-in shell completions were migrated, and the CHANGELOG names the positional `CANDIDATE` spelling. The unrelated JSON CRUD `--from-file` flags remain. |
| L2 | Visible aliases `--peer` (for `--neighbor`) and `--asn` (for `--remote-asn`) throughout `crates/cli/src/main.rs`. | Both product-language spellings, by design (LAN-329 conventions block). | Zero; clap renders them in help. | keep | Canonical convention, not a shim. |
| L3 | `rbgp rib diff` older-daemon fallbacks from #1367: single-peer tolerance for daemons that omit `page_version` (`observe_page_version`, `crates/cli/src/commands/diff.rs`) and the MED 0-maps-to-absent fallback for daemons without `med_attr` (including the caveat machinery in the same file). | Version-less legacy path: diffing against a ≤v0.62 daemon that predates the fenced advertised-RIB pages. | A fallback state machine, mixed present/absent fail-closed arms, and a caveat surface — the largest single compat structure in the CLI. | deprecate → v0.65 | Fail closed on any response omitting `page_version` (message: upgrade the daemon); delete the single-peer tolerance + `med_attr` fallback + caveat; CHANGELOG note. Rolling-upgrade policy above (N-1) makes v0.65 the earliest release whose N-1 daemon always emits both fields. |
| L4 | Assorted CLI rolling-upgrade fallbacks for absent additive fields: the `neighbor_source_label` "range unavailable" arm (`crates/cli/src/output.rs`) and max-prefix action absence handling (`crates/cli/src/commands/neighbor.rs`). | `rbgp` from HEAD reading the previous minor's daemon during an upgrade. | Small, individually tested branches. | keep (policy-bounded) | Governed by the N-1 rule: each branch is prunable once its emitting release is two minors old; no per-branch decision needed. |

#### API surface (protobuf / metrics)

| # | Item | What it preserves | Cost of keeping | Classification | Removal mechanics |
|---|------|-------------------|-----------------|----------------|-------------------|
| A1 | `AddNeighborRequest.config` legacy carrier — field 1 outside the oneof-shaped pair (`proto/rustbgpd.proto`), kept by ADR-0118 when `NeighborCreateIntent` became the presence-aware create path. `rbgp` already sends `intent` (`crates/cli/src/commands/neighbor.rs`). | Pre-ADR-0118 gRPC clients that populate the bare `config` field. | Dual-carrier validation ("exactly one carrier") on every create. | deprecate → v0.65 | Reserve field 1; collapse to `intent` only; `AddNeighbor` is in the pinned NeighborService message graph (`docs/v1-stable-surface.json`) → blessed-surface re-bless; CHANGELOG migration (populate `intent`). |
| A2 | `PathsLimitState.effective_send_max` raw cap (`proto/rustbgpd.proto`), superseded by the presence-aware `effective_send_limit`. | New clients reading pre-`effective_send_limit` daemons; old clients reading the raw field. | One conflated field (0 vs UINT32_MAX sentinel encoding) plus the client-side fallback read. | removed (v0.65) | Paths-Limit is Experimental and outside v1 (`docs/v1-stable-contract.md` role matrix). Field number/name 5 are reserved, the CLI fallback and JSON raw key are gone, and field 6 alone carries inactive (absent), unlimited (zero), or finite states. |
| A3 | `RouteEvent.event_id` process-local route cursor (`proto/rustbgpd.proto`, `crates/rib/src/manager/mod.rs`). It is the sole cursor on bare `ListRouteEvents` / `WatchRoutes` and remains nested in non-durable `WatchRouteEvents` / `WatchEvents`, which leave `BgpEvent.event_id` unset on the wire. `rbgp events watch --backfill` uses it to deduplicate the history/live boundary. Only durable `SubscribeFromEvent` makes the envelope id authoritative and mirrors that durable id into the nested route payload as a convenience/back-compat copy (`crates/api/src/event_service/cursor.rs`). | Direct route consumers, non-durable unified consumers, and the CLI's process-local backfill handoff. | Two intentionally distinct cursor domains need clear documentation; durable route envelopes carry the id twice. | keep | This is live API state, not a compatibility shim. Preserve the direct process-local cursor and the durable mirror. Any future unification must first replace the bare route surfaces and the CLI backfill contract. |
| A4 | Legacy `bgp_otc_routes_blocked_total{peer,reason}` counter and `otc_routes_blocked` scalar, named "the compatibility surfaces" alongside `OtcRouteBlockedEvent` (`proto/rustbgpd.proto`). | Existing dashboards/alerts on the counter. | One counter family; metrics are the intended observation surface. | keep | Events complement, not replace, the counter; renaming metrics has its own cost (cf. the `bgp_aspa_records` rename cycle in v0.51.0). |

#### Recorded decisions and slipped removals

| # | Item | Recorded decision | Next step |
|---|------|-------------------|-----------|
| D1 | Legacy v1 config-history rows, the mixed-format reader, and the frozen v1 commit-confirm recovery reader. | **Removed (v0.65).** V2 JSON history remains active; legacy TOML files are ignored and retained. Proto enum value 2 and CLI rendering remain receive-only for N-1. | A locator-free retired journal refuses boot untouched. Recover with rustbgpd v0.64.0, or delete only after proving the old transaction terminal and current config intended. |
| D3 | Frozen v2 commit-confirm recovery reader (`src/confirm_journal/v2.rs`). | **Removed (v0.65).** V3 is the sole write/read authority. | A canonical v2 locator refuses untouched. Coexistence with locator-free retired authority is rejected before candidate or v3 mutation. |
| D2 | Unary `PlanConfigTransaction` / `ApplyConfigTransaction` (`proto/rustbgpd.proto`) alongside streaming Plan/Apply (LAN-794). | **Keep.** Unary Plan/Apply is the permanent, documented small-candidate path. Streaming remains additive and outside the initial v1 frozen inventory; it does not turn unary into a deprecation shim. | Preserve unary byte and behavior compatibility and the CLI's bounded `UNIMPLEMENTED`-only fallback. Any future reversal is a new blessed-surface decision subject to the v1 deprecation floor. |

#### Internal / examples (remove-now follow-up)

| # | Item | What it preserves | Cost of keeping | Classification | Removal mechanics |
|---|------|-------------------|-----------------|----------------|-------------------|
| E1 | Explicit UDS authorization ceremony in nine example configs carrying `[global.telemetry.grpc_uds]` + `principal` + `[security.grpc]` + `[security.grpc.roles]`; Docker Compose instead carries authenticated TCP. | The route-collector's declared `looking-glass = "observer"` mapping is a real least-privilege boundary. The other eight owner-only sockets gained no per-client discrimination from a listener-wide operator principal. | Eight examples taught ~12 lines of unnecessary ceremony as if required; this contradicted the implicit path shipped in #1429. | simplified (v0.63) | Eight ordinary examples now use the implicit owner-only UDS; this changes only their audit label (`operator` / `authn=uds` → `local-operator` / `authn=uds_owner`), not socket access or authority. Route-collector retains the observer UDS and Docker retains authenticated TCP. `config_examples_parse` freezes those two deliberate explicit boundaries. |

## Consequences

- One place answers "why does this still exist and when does it die" for
  every known shim; new compat retentions should add a row here in the same
  PR that introduces them.
- The three-minor / N-1 lifetime policies convert future removals from
  per-item debates into scheduled cleanups.
- The former open calls are closed: unary Plan/Apply remains permanent; L1,
  A2, D1, and D3 were removed for v0.65.
- Scheduled removals (C1, A1) touch the blessed v1 surface; each needs
  the re-bless procedure and a CHANGELOG migration note, which this ADR's
  mechanics columns pre-write.
- Until the scheduled release arrives, everything listed keeps working;
  accepting this ADR changes no runtime behavior.
