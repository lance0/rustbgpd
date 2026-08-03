# ADR-0122: Compatibility-debt inventory and removal schedule

**Status:** Proposed
**Date:** 2026-08-03

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
against the release named here. Entries marked **owner decision** need a call
from the project owner before scheduling.

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
with reason), **owner decision** (genuinely an owner-level call).

#### Config schema surface

| # | Item | What it preserves | Cost of keeping | Classification | Removal mechanics |
|---|------|-------------------|-----------------|----------------|-------------------|
| C1 | `GrpcEnforcementConfig::Legacy` enum variant (`src/config/schema.rs:332`). Dead since #1431: validation rejects it outright (`src/config/validation.rs:2672`); the runtime path was removed in v0.63.0 (ADR-0064 status addendum). | v1 config surface still *parses* `enforcement = "legacy"` so the rejection message can carry migration steps; keeps the pinned `GrpcSecurityConfig` schema hash (`docs/v1-stable-surface.json:70`, `docs/rustbgpd.schema.json:1202`). | Dead variant, bespoke error assembly, structural tests policing that no fixture uses it (`src/reload.rs:2830`, `src/config_transaction_control.rs:3273`). | deprecate → v0.65 | Delete variant; add a `retired_key_error`-style pointer for `enforcement = "legacy"` (three-minor lifetime per policy above); re-bless v1 surface + JSON schema; ADR-0064 addendum note; CHANGELOG Removed. |
| C2 | Retired-key migration pointers in the TOML loader (`retired_key_error`, `src/config/mod.rs`): `[global.telemetry.looking_glass]` and `[[policy.import]]`/`[[policy.export]]`, both removed in v0.51.0. | Actionable migration error instead of a bare serde unknown-field diagnostic. | Two string branches; trivial. | removed (v0.63) | The pointers aged past the three-minor lifetime and were deleted; the documented `retired_key_error` insertion seam remains for C1. The retired keys now receive the ordinary typed-config diagnostic. |
| C3 | `BgpRoleConfig` serde aliases `rs` / `rs-client` (`src/config/schema.rs:1450`). | Common shorthand spellings for RFC 9234 roles in operator configs. | Two attribute lines; zero runtime cost. | keep | Documented spellings, not a migration shim. |

#### CLI surface

| # | Item | What it preserves | Cost of keeping | Classification | Removal mechanics |
|---|------|-------------------|-----------------|----------------|-------------------|
| L1 | Hidden `--from-file` compatibility aliases on `config check` / `config diff` / `config apply` (`crates/cli/src/main.rs:419-457`), kept when LAN-329 made file arguments positional. The conventions comment pledges they "must never be removed" (`crates/cli/src/main.rs:40-42`). | Old scripts invoking the pre-LAN-329 flag spelling. | Three hidden args + `candidate_file()` merge helper; near zero. The real debt is the "never" pledge, which contradicts the alpha posture. | owner decision | If removal is approved: delete the hidden args + helper, regenerate checked-in shell completions, CHANGELOG migration note (positional spelling). Either way, reword the conventions comment from "never" to "until the scheduled removal release". |
| L2 | Visible aliases `--peer` (for `--neighbor`) and `--asn` (for `--remote-asn`) throughout `crates/cli/src/main.rs` (e.g. lines 239, 838). | Both product-language spellings, by design (LAN-329 conventions block). | Zero; clap renders them in help. | keep | Canonical convention, not a shim. |
| L3 | `rbgp rib diff` older-daemon fallbacks from #1367: single-peer tolerance for daemons that omit `page_version` (`observe_page_version`, `crates/cli/src/commands/diff.rs:1012`) and the MED 0-maps-to-absent fallback for daemons without `med_attr` (`crates/cli/src/commands/diff.rs:1072`, caveat machinery at `diff.rs:76`). | Version-less legacy path: diffing against a ≤v0.62 daemon that predates the fenced advertised-RIB pages. | A fallback state machine, mixed present/absent fail-closed arms, and a caveat surface — the largest single compat structure in the CLI. | deprecate → v0.65 | Fail closed on any response omitting `page_version` (message: upgrade the daemon); delete the single-peer tolerance + `med_attr` fallback + caveat; CHANGELOG note. Rolling-upgrade policy above (N-1) makes v0.65 the earliest release whose N-1 daemon always emits both fields. |
| L4 | Assorted CLI rolling-upgrade fallbacks for absent additive fields: `neighbor_source_label` "range unavailable" arm (`crates/cli/src/output.rs:246`), max-prefix action absence handling (`crates/cli/src/commands/neighbor.rs:1666-1701`). | `rbgp` from HEAD reading the previous minor's daemon during an upgrade. | Small, individually tested branches. | keep (policy-bounded) | Governed by the N-1 rule: each branch is prunable once its emitting release is two minors old; no per-branch decision needed. |

#### API surface (protobuf / metrics)

| # | Item | What it preserves | Cost of keeping | Classification | Removal mechanics |
|---|------|-------------------|-----------------|----------------|-------------------|
| A1 | `AddNeighborRequest.config` legacy carrier — field 1 outside the oneof-shaped pair (`proto/rustbgpd.proto:852`), kept by ADR-0118 when `NeighborCreateIntent` became the presence-aware create path. `rbgp` already sends `intent` (`crates/cli/src/commands/neighbor.rs:1136`). | Pre-ADR-0118 gRPC clients that populate the bare `config` field. | Dual-carrier validation ("exactly one carrier") on every create. | deprecate → v0.65 | Reserve field 1; collapse to `intent` only; `AddNeighbor` is in the pinned NeighborService message graph (`docs/v1-stable-surface.json:142`) → blessed-surface re-bless; CHANGELOG migration (populate `intent`). |
| A2 | `PathsLimitState.effective_send_max` raw cap (`proto/rustbgpd.proto:482`), superseded by the presence-aware `effective_send_limit`; "preserved for rolling compatibility". | New clients reading pre-`effective_send_limit` daemons; old clients reading the raw field. | One conflated field (0 vs UINT32_MAX sentinel encoding) plus the client-side fallback read. | deprecate → v0.64 | Paths-Limit is Experimental and outside v1 (`docs/v1-stable-contract.md` role matrix), so no bless needed; reserve the field, drop the CLI fallback read, CHANGELOG note. |
| A3 | `RouteEvent.event_id` back-compat mirror of the envelope event id (`proto/rustbgpd.proto:2815-2825`, `crates/api/src/event_service/cursor.rs:440-443`), kept "for route-only consumers". | Route-only event consumers that never read the `BgpEvent` envelope id. | Duplicate id on every route event; a documented invariant that the two must mirror. | deprecate → v0.65 | RibService/EventService message graphs are pinned (`docs/v1-stable-surface.json:145-146`) → blessed-surface re-bless; reserve the field; CHANGELOG migration (read the envelope id). |
| A4 | Legacy `bgp_otc_routes_blocked_total{peer,reason}` counter and `otc_routes_blocked` scalar, named "the compatibility surfaces" alongside `OtcRouteBlockedEvent` (`proto/rustbgpd.proto:2740-2745`). | Existing dashboards/alerts on the counter. | One counter family; metrics are the intended observation surface. | keep | Events complement, not replace, the counter; renaming metrics has its own cost (cf. the `bgp_aspa_records` rename cycle in v0.51.0). |

#### Decision-owed (owner)

| # | Item | State | What is owed |
|---|------|-------|--------------|
| D1 | Legacy v1 config-history rows, the mixed-format reader (`src/config_history.rs`, `src/config_history/v2.rs`, #1409/#1413), and the v1 commit-confirm boot-revert path. | ADR-0121 §9 keeps legacy rows readable (`LEGACY_TOML_ONLY`, rollback only when no external inputs) and preserves the v1 journal boot revert; LAN-798 (In Progress) is activating commit-confirm v2. No EOL is stated anywhere: legacy *rows* age out via the 20-entry retention, but the legacy reader code and the v1 journal lane live until someone decides. | An EOL release for (a) the legacy row-payload lane in the mixed reader and (b) the locator-absent v1 journal fallback, decided on the LAN-798 thread after v2 activation ships and soaks one release. |
| D2 | Unary `PlanConfigTransaction` / `ApplyConfigTransaction` (`proto/rustbgpd.proto:115,124`) vs the accepted streaming Plan/Apply direction (LAN-794). | LAN-794's accepted contract keeps unary byte- and behavior-compatible and gives the CLI an `UNIMPLEMENTED`-only bounded unary fallback once streaming ships. Whether unary remains the permanent small-candidate path or becomes a deprecated shim is unstated. | After streaming phase 2 lands: decide whether unary Plan/Apply is (a) kept as the documented small-candidate path or (b) scheduled for removal. Both RPCs are in the pinned ConfigService surface, so (b) is a blessed-surface change. |

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
- Two genuinely open calls (D1, D2) and one recorded-pledge conflict (L1)
  are surfaced for the owner instead of being silently perpetuated.
- Scheduled removals (C1, A1, A3) touch the blessed v1 surface; each needs
  the re-bless procedure and a CHANGELOG migration note, which this ADR's
  mechanics columns pre-write.
- Until the scheduled release arrives, everything listed keeps working;
  this ADR changes no behavior.
