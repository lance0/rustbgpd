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
hidden `--from-file` aliases are scheduled for v0.65 removal.

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
| L1 | Hidden `--from-file` compatibility aliases on `config diff` / `config plan` / `config apply` (`crates/cli/src/main.rs`), kept when LAN-329 made file arguments positional. The conventions comment pledges they "must never be removed" in the same file. | Old scripts invoking the pre-LAN-329 flag spelling. | Three hidden args + `candidate_file()` merge helper; near zero. The real debt is the "never" pledge, which contradicts the alpha posture. | deprecate → v0.65 | Delete the three hidden args + helper, regenerate checked-in shell completions, reword the conventions comment, and add a CHANGELOG migration note naming the positional spelling. |
| L2 | Visible aliases `--peer` (for `--neighbor`) and `--asn` (for `--remote-asn`) throughout `crates/cli/src/main.rs`. | Both product-language spellings, by design (LAN-329 conventions block). | Zero; clap renders them in help. | keep | Canonical convention, not a shim. |
| L3 | `rbgp rib diff` older-daemon fallbacks from #1367: single-peer tolerance for daemons that omit `page_version` (`observe_page_version`, `crates/cli/src/commands/diff.rs`) and the MED 0-maps-to-absent fallback for daemons without `med_attr` (including the caveat machinery in the same file). | Version-less legacy path: diffing against a ≤v0.62 daemon that predates the fenced advertised-RIB pages. | A fallback state machine, mixed present/absent fail-closed arms, and a caveat surface — the largest single compat structure in the CLI. | deprecate → v0.65 | Fail closed on any response omitting `page_version` (message: upgrade the daemon); delete the single-peer tolerance + `med_attr` fallback + caveat; CHANGELOG note. Rolling-upgrade policy above (N-1) makes v0.65 the earliest release whose N-1 daemon always emits both fields. |
| L4 | Assorted CLI rolling-upgrade fallbacks for absent additive fields: the `neighbor_source_label` "range unavailable" arm (`crates/cli/src/output.rs`) and max-prefix action absence handling (`crates/cli/src/commands/neighbor.rs`). | `rbgp` from HEAD reading the previous minor's daemon during an upgrade. | Small, individually tested branches. | keep (policy-bounded) | Governed by the N-1 rule: each branch is prunable once its emitting release is two minors old; no per-branch decision needed. |

#### API surface (protobuf / metrics)

| # | Item | What it preserves | Cost of keeping | Classification | Removal mechanics |
|---|------|-------------------|-----------------|----------------|-------------------|
| A1 | `AddNeighborRequest.config` legacy carrier — field 1 outside the oneof-shaped pair (`proto/rustbgpd.proto`), kept by ADR-0118 when `NeighborCreateIntent` became the presence-aware create path. `rbgp` already sends `intent` (`crates/cli/src/commands/neighbor.rs`). | Pre-ADR-0118 gRPC clients that populate the bare `config` field. | Dual-carrier validation ("exactly one carrier") on every create. | deprecate → v0.65 | Reserve field 1; collapse to `intent` only; `AddNeighbor` is in the pinned NeighborService message graph (`docs/v1-stable-surface.json`) → blessed-surface re-bless; CHANGELOG migration (populate `intent`). |
| A2 | `PathsLimitState.effective_send_max` raw cap (`proto/rustbgpd.proto`), superseded by the presence-aware `effective_send_limit`; "preserved for rolling compatibility". | New clients reading pre-`effective_send_limit` daemons; old clients reading the raw field. | One conflated field (0 vs UINT32_MAX sentinel encoding) plus the client-side fallback read. | deprecate → v0.65 (slipped from v0.64) | Paths-Limit is Experimental and outside v1 (`docs/v1-stable-contract.md` role matrix), so no bless needed; reserve the field, drop the CLI fallback read, CHANGELOG note. |
| A3 | `RouteEvent.event_id` back-compat mirror of the envelope event id (`proto/rustbgpd.proto`, `crates/api/src/event_service/cursor.rs`), kept "for route-only consumers". | Route-only event consumers that never read the `BgpEvent` envelope id. | Duplicate id on every route event; a documented invariant that the two must mirror. | deprecate → v0.65 | RibService/EventService message graphs are pinned (`docs/v1-stable-surface.json`) → blessed-surface re-bless; reserve the field; CHANGELOG migration (read the envelope id). |
| A4 | Legacy `bgp_otc_routes_blocked_total{peer,reason}` counter and `otc_routes_blocked` scalar, named "the compatibility surfaces" alongside `OtcRouteBlockedEvent` (`proto/rustbgpd.proto`). | Existing dashboards/alerts on the counter. | One counter family; metrics are the intended observation surface. | keep | Events complement, not replace, the counter; renaming metrics has its own cost (cf. the `bgp_aspa_records` rename cycle in v0.51.0). |

#### Recorded decisions and slipped removals

| # | Item | Recorded decision | Next step |
|---|------|-------------------|-----------|
| D1 | Legacy v1 config-history rows, the mixed-format reader (`src/config_history.rs`, `src/config_history/v2.rs`, #1409/#1413), and the frozen v1 commit-confirm recovery reader (the legacy lane in `src/confirm_journal.rs`, kept by #1433 as bounded legacy recovery). | EOL remains approved, but the v0.64 deadline was missed; removal moves to **v0.65**. v1 stopped being a write format when commit-confirm v2 activated (#1433, after the v0.62.0 tag), so v0.62.0 is the last tagged release that wrote a v1 journal and v0.64 is the last release that can read one. Legacy history *rows* still age out via the 20-entry retention; ADR-0121 §9's bounded semantics (`LEGACY_TOML_ONLY`, rollback only when no external inputs) hold until removal. | The v0.65 removal PR deletes the v1 recovery lane and the legacy row-payload lane in the mixed reader, with their upgrade-recovery tests deleted in the same PR. Boot on an orphaned v1 journal must refuse cleanly with an actionable message (delete the stale journal or recover on ≤v0.64), never silently ignore it. Add a CHANGELOG Removed entry with migration steps. |
| D3 | Frozen v2 commit-confirm recovery reader (`src/confirm_journal/v2.rs`, kept by #1448 for pending-authority upgrade recovery when v3 became the write format). | EOL remains approved, but the v0.64 deadline was missed; removal moves to **v0.65**. v2 was never a tagged release's write format: it activated after the v0.62.0 tag (#1433) and was superseded by v3 (#1448) before any tag, so the reader only serves pending state written by v0.63-development-window daemons and the upgrade into v0.63. | Remove it in the same v0.65 PR as D1: delete the v2 recovery lane and its upgrade-recovery tests together. Boot on an orphaned v2 locator/journal must refuse cleanly with an actionable message, never silently ignore it. |
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
- The former open calls are closed: unary Plan/Apply remains permanent, and
  the hidden `--from-file` aliases leave in v0.65. D1, D3, and A2 carry an
  explicit v0.65 deadline after missing v0.64 rather than silently slipping.
- Scheduled removals (C1, A1, A3) touch the blessed v1 surface; each needs
  the re-bless procedure and a CHANGELOG migration note, which this ADR's
  mechanics columns pre-write.
- Until the scheduled release arrives, everything listed keeps working;
  accepting this ADR changes no runtime behavior.
