# Changelog

All notable changes to rustbgpd will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

> **Release framing.** This is the policy-safety line. RFC 8212
> explicit-policy enforcement and per-peer outbound prefix limits both
> ship complete and opt-in, `rustbgpd --check` learns to say when a
> configuration is merely *valid* rather than *clean*, and every starter
> config we ship was rewritten to pass the strict form of that check.
> Around them sits a correctness pass over the paths that fail: a
> rejected config mutation no longer changes anything an operator can
> observe, a listener that cannot bind exits instead of parking with its
> core function dead, and the initial table dump finally evaluates the
> peer's group-scoped export policy. RFC 6793 AS4 migration, RFC 9072
> extended OPEN, and RFC 9552 BGP-LS attribute framing complete the
> conformance surface, and `rustbgpd-wire` 0.16.0 / `rustbgpd-fsm` 0.3.1
> publish alongside. The first Highlights group lists what needs an
> operator decision before the upgrade.

### Highlights

**Act on these before you upgrade**

- **Breaking: the `peer` metric label is now the bare neighbor address on
  every metric family.** Session-owned series previously used the
  transport endpoint (`192.0.2.1:179`). Existing PromQL, recording rules,
  dashboards, and alert rules that pin the `addr:port` form match nothing
  after the upgrade, and Prometheus reports no error for a selector that
  matches nothing. The affected series and the exact query rewrites are
  listed under *Changed*.
- **The `Adj-RIB-Out prefixes per peer` panel now floors to zero during a
  graceful restart** instead of holding the departed session's plateau
  for the whole restart timer. Any panel, recording rule, or alert
  written against that plateau sees a new shape. `bgp_rib_prefixes`,
  `bgp_gr_active_peers`, and `bgp_gr_stale_routes` remain the series that
  stay nonzero for a peer expected back.
- **Group-scoped export policy now applies to the initial table dump.**
  This is wire-visible: an upgraded daemon's first dump to a peer whose
  export policy matches on peer-group may now be correctly filtered, or
  otherwise transformed by group-matched actions, where it previously was
  not — at every session establishment *and* every re-establishment.
  Peers whose export policy does not match on peer-group are unaffected.
- **`config OK` now means a genuinely clean check.** A configuration with
  anything to flag prints `config VALID, <n> WARNINGS — NOT a clean
  check`, and the new `--check --strict` exits 1 on any warning so a CI
  or deployment gate can refuse it. Every shipped starter config —
  including both `--init-config` profiles, whose output changed
  accordingly — was rewritten to pass that strict check.
- **Default change: import-decision explain is now opt-in.**
  `[policy.explain] enabled` defaults to `false`. A daemon whose config
  never named that section stops recording import decisions on upgrade:
  `rbgp policy explain` answers `cache_disabled` and exits nonzero,
  naming the exact lines to add. **No routing behaviour changes** — the
  cache is diagnostic retention only, and best-path explain, export
  explain, and the retained rejected-route view are untouched. To keep
  the surface, add `[policy.explain] enabled = true`, reload, and let
  sessions re-establish; an explicit `enabled = true` behaves exactly as
  before. The reason is that the cache is held **per session**, so its
  cost multiplies by peer count, and 4096 entries cannot promise
  full-table explainability anyway — full price for a partial answer.
  Sizing guidance, labelled figures, and the conditions that would
  reopen the decision are under *Changed* and in ADR-0073.
- **`rustbgpd-wire` 0.16.0 changes decode acceptance in six places**
  while keeping an additive API. Embedders should read the *Library
  crates* entry under *Changed* before bumping.

**Policy safety**

- RFC 8212 explicit-policy enforcement lands end to end behind opt-in
  `[global] ebgp_requires_policy`: an eBGP direction with no explicit
  operator policy carries no routes instead of everything, per direction,
  with the resulting status on neighbor detail, JSON, Prometheus,
  `rbgp rib advertised --explain`, and `rbgp doctor`.
- Per-peer outbound unicast prefix limits (ADR-0113) bound how far one
  client's export policy can grow its advertised state, without
  withdrawing what is already out and without resetting a session, with
  usage/limit/headroom/blocking on every operator surface.
- `rustbgpd --check` now warns about eBGP neighbors that resolve no
  policy, `rbgp config import` emits configs that fail closed, and the
  shipped starters are all policy-complete.

**Correctness when something fails**

- A rejected config mutation is now externally invisible: persistence is
  reserved before runtime state is touched, so a refused RPC can no
  longer have dropped a session, double-bounced a peer group, or put two
  rounds of Route Refresh on the wire.
- The BGP listener sets `SO_REUSEADDR`, and a bind failure exits 1 rather
  than leaving a live daemon that accepts no BGP; an unexpected gRPC
  server exit also exits non-zero; configured BFD that cannot open its
  sockets refuses to start rather than serving BFD-configured peers
  without it.
- Hot-applicable peer-group edits apply in place instead of bouncing
  every inheriting session — so on a route server, a group-level limit
  raise is flap-free during exactly the incident the limit exists to
  contain.

**Protocol conformance**

- RFC 6793 four-octet-AS migration is lossless end to end across loop
  detection, policy, RIB, export encoding, MRT, and BMP, proven against a
  pinned ExaBGP source and an independent old-speaker sink.
- RFC 9072 extended OPEN optional-parameter lengths, RFC 9552 BGP-LS
  attribute framing with whole-attribute discard, RFC 9774 AS_SET
  prohibition, and RFC 7607 / RFC 6286 OPEN identity validation.
- New admission controls: `min_hold_time` rejects an OPEN proposing too
  short a hold time, `required_families` rejects an OPEN whose negotiated
  intersection is missing a family you depend on.

**Guardrails and observability**

- The max-prefix suite is now alertable before teardown and recoverable
  after it: usage/limit/headroom metrics per scope, per-neighbor
  headroom on neighbor detail, opt-in timed restart, and a live duration
  edit that re-arms the pending attempt instead of silently latching the
  peer down.
- TCP-AO keys can be rotated and retired on a live session across two
  immutable generations, fail-closed, without resetting it.
- Every shipped starter profile and interop lab now runs under tier
  authorization; `security.grpc.enforcement = "legacy"` is reported by
  `--check` rather than only at daemon startup.
- The gRPC method inventory an external reviewer reads is now checked
  against the generated tier export on every test run, so the published
  classification cannot drift from the one the daemon enforces.

**Library crates**

- `rustbgpd-wire` 0.16.0 (additive API, six decode-acceptance changes)
  and `rustbgpd-fsm` 0.3.1 (two additive fields on a `#[non_exhaustive]`
  struct).

### Added

- **Live negotiated-capability visibility.** `NeighborState`,
  `rbgp neighbor <peer>`, and its JSON now expose peer Route Refresh,
  Enhanced Route Refresh, and Extended Messages support plus the directional
  outbound BGP message limit (4096 or 65535 bytes). Optional protobuf and JSON
  scalars distinguish an explicit negotiated `false` from a field absent on an
  older daemon; the existing negotiation status remains authoritative when no
  Established-session snapshot is available.

- **RFC 8212 explicit-policy enforcement — `[global] ebgp_requires_policy`
  (ADR-0112).** Opt-in, default `false`, restart-required, and pinned to
  the startup value across SIGHUP: a reload logs an `ERROR`, keeps the
  running import/export treatment of every eBGP session unchanged, and
  carries the operator's edit forward on disk. `rustbgpd --diff` and the
  v1 runtime configuration transaction name `[global].ebgp_requires_policy`
  explicitly, and the transaction rejects such a candidate rather than
  persisting or partly adopting it.

  With the knob on, an eBGP direction that resolves no explicit operator
  policy runs a reserved internal deny-all chain instead of the
  permit-all default: a missing import policy makes received routes
  ineligible, a missing export policy keeps routes out of that peer's
  Adj-RIB-Out, the session stays Established, and the two directions are
  independent. The verdict is decided before the implicit RFC 8326
  `GRACEFUL_SHUTDOWN` and RFC 7999 `BLACKHOLE` import tails are appended,
  so enabling `honor_graceful_shutdown` or `honor_blackhole` cannot
  satisfy the requirement; a chain whose configured result is permit-all
  does satisfy it. Every negotiated family is covered, because policy is
  neighbor-wide. iBGP is untouched. A `[[dynamic_neighbors]]` range with
  `remote_asn = 0` is accept-any rather than AS 0, so its accepted
  children are classified external for the whole session, including after
  OPEN replaces the sentinel with a learned ASN. With the knob off the
  default resolution is unchanged.

  Live edits that move a direction between explicit policy and the
  reserved deny are only convergent through a Route Refresh, so every
  affected peer is qualified before any peer is modified and one
  unqualified peer rejects the whole edit with nothing mutated: an
  Established peer that never negotiated RFC 2918 Route Refresh is
  rejected with clear/reconnect guidance, a peer that is down while the
  RIB still retains its graceful-restart or long-lived stale routes is
  deferred so those routes stay paired with the verdict they were
  accepted under, and a session that cannot report its state in time is
  rejected rather than guessed at. A peer that qualifies and then flaps
  before its refresh is delivered fails the edit and has its prior chains
  restored. Proven on real sessions by the new M95 interop lab (FRR with
  Route Refresh, BIRD 2 with `enable route refresh off`).

- **Per-direction RFC 8212 policy status on every operator surface.** A
  one-sided configuration is never collapsed into a single "policy
  present" answer:

  - `NeighborState.rfc8212_import_policy` / `.rfc8212_export_policy` carry
    the new `Rfc8212PolicyStatus` enum (`UNSPECIFIED`, `UNKNOWN`,
    `NOT_REQUIRED`, `PRESENT`, `MISSING`) as appended fields 51 and 52. A
    daemon that predates them leaves `UNSPECIFIED`; `rbgp` renders that
    and any unrecognized future value as `unknown` rather than as "no
    requirement", so a new client against an old daemon and an old client
    against a new one are both safe.
  - `rbgp neighbor <addr>` prints an `RFC 8212 Policy` block and `--json`
    gains `rfc8212_import_policy` / `rfc8212_export_policy`.
  - `bgp_rfc8212_missing_import_policy{peer}` and
    `bgp_rfc8212_missing_export_policy{peer}` are 0/1 per direction.
  - `rbgp rib advertised <peer> --explain` attributes a rejection by the
    reserved chain under the `rfc8212_missing_export_policy` gate code
    instead of `policy_denied`, and `rbgp policy explain` labels the
    import side.
  - `rbgp doctor` adds `peer.<addr>.rfc8212_policy`: green for
    `not_required` (the compatibility default) and `present`, red for a
    `missing` direction, yellow against a daemon that does not expose the
    status. `/readyz` is deliberately untouched — a peer without operator
    policy is a configuration state to repair, not a daemon that cannot
    serve traffic.

  The status is read from the chain the peer currently has installed, not
  re-resolved from the running configuration, so it cannot report
  `present` over a live deny. `rfc8212_missing_import_policy` and
  `rfc8212_missing_export_policy` are now reserved policy names: a
  `[policy.definitions]` entry or `.rpol` policy using either is rejected
  at load, which is what makes both the status comparison and the explain
  attribution unambiguous.

- **Per-peer outbound unicast prefix limits (ADR-0113).** New
  `max_prefixes_out_ipv4` / `max_prefixes_out_ipv6` on `[[neighbors]]` and
  peer groups bound how much of the table one client's export policy can
  grow its advertised state to. A neighbor value overrides its group, an
  absent value inherits, and accepted dynamic children inherit their
  configured group's effective values. Excess net-new prefixes are
  withheld while the session stays Established — nothing already
  advertised is withdrawn, no NOTIFICATION is sent, and slots count
  distinct prefixes, so every Add-Path identity for one NLRI shares one.
  Only IPv4- and IPv6-unicast are in scope. Edits are live and
  transactional: adding or lowering a maximum is accepted only when every
  affected live peer is already at or below the candidate, and an
  over-limit family rejects the whole edit with the peer, family, current
  usage, and requested maximum rather than pruning an existing view; a
  valid raise or removal schedules one coalesced, family-scoped resync.
  Commit-confirmed transactions may only tighten, because their automatic
  undo can only loosen. A maximum is a reload-matrix `live` field, so both
  a `[[neighbors]]` edit and a maxima-only `[peer_groups.*]` edit apply in
  place without touching a session.

  `rbgp neighbor <addr>` (human and JSON) and the neighbor API report one
  row per unicast family — usage, optional maximum, optional headroom,
  blocking state, and the stable reason `outbound_prefix_limit_reached` —
  and Prometheus exposes `bgp_outbound_prefix_usage`,
  `bgp_outbound_prefix_limit`, `bgp_outbound_prefix_headroom`,
  `bgp_outbound_prefix_blocking`, and `bgp_outbound_prefix_blocked_total`,
  labelled by peer and family only. An episode logs once when it opens and
  once when recovery proves nothing is still withheld, never per prefix.
  A committed real-session receipt drives four live sessions and reads the
  wire at every phase: 96/96 precommitted checks, caps bound on both the
  shared update-group fanout and the private per-peer path, and no session
  reset by either limit edit including the peer-group one.

- **`rustbgpd --check --strict`.** `--check` reports a valid-but-risky
  configuration as a warning and exits 0, so that adding a warning can
  never break a deployment that meant its configuration — which also
  means a CI job running `--check` passes a config nobody looked at.
  `--strict` is the opt-in for gates that cannot accept that: identical
  output, but any warning exits **1**, the same code `--check` already
  uses for a config it rejects, since a gate reads both as "this config
  did not pass". A clean check still exits 0, and `--strict` without
  `--check` is rejected with exit 2 rather than silently accepted — that
  invocation would otherwise start a daemon. `--strict` is defined over
  the whole `--check` warning set, not one warning, so anything `--check`
  reports in future fails a strict run. `--help` and `rustbgpd(8)` now
  document the exit-status ladder.

- **Applied-config history and `rbgp config rollback N`,** completing the
  Junos-style transactional quartet (check / compare / commit confirmed /
  rollback). Every applied config — transaction applies, gRPC config CRUD,
  successful SIGHUP reloads, and the boot-time config — is recorded in a
  bounded on-disk history under `<runtime_state_dir>/config-history/`
  (last 20 distinct configs, content-hash-deduplicated, timestamped,
  restart-safe). `rbgp config history` lists index / timestamp / SHA-256 /
  one-line summary; `rbgp config rollback N` restores entry N through the
  existing transaction executor — same plan classification, reload-impact
  and update-group annotations, receipts, and optional
  `--confirm-id`/`--confirm-timeout` confirmed-commit window (timeout
  auto-revert and boot revert included). Entry reads verify the content
  digest embedded in the file name and reject non-regular or corrupt
  snapshots. Rolling back past the retained history fails cleanly. New
  `ConfigService.ListConfigHistory` (`sensitive_read`) and
  `ConfigService.RollbackConfigTransaction` (`operator_only`, same tier as
  apply) RPCs; history responses carry metadata only, never config
  documents. A committed receipt exercises the whole area against a real
  daemon with three real sessions attached, including a SIGKILL inside the
  confirmation window and an injected persistence failure.

- **`rbgp config import` — bounded structural importer for BIRD 2, FRR,
  and GoBGP configurations.** Translates the structural subset (local AS,
  router-id, neighbors, peer groups, address families, hold timers,
  max-prefix limits) of a BIRD 2, FRR (vtysh running-config), or GoBGP
  TOML source into a rustbgpd `config.toml` and refuses to guess at
  policy: BIRD filters, FRR route-maps/prefix-lists, and GoBGP
  policy-definitions are listed — with source line numbers — in an import
  report for hand-translation to `.rpol`. Secrets are never imported
  (MD5/auth presence is flagged instead). Distinct exit codes: 0 clean
  full translation, 1 error, 2 translated-with-warnings-or-skips, 3
  nothing translatable; the emitted config for every checked-in fixture is
  gate-tested against `rustbgpd --check`. The route-server migration
  cookbook now opens with the mechanical importer → `--check` → shadow
  trial → `rbgp diff advertised` flow.

- **Minimum accepted hold time and required OPEN families.** Neighbors and
  peer groups accept `min_hold_time`, which rejects a peer OPEN proposing
  a lower hold time — including zero — with OPEN Error 2/6; and
  `required_families`, which rejects an OPEN with RFC 5492 Unsupported
  Capability (2/7) when any required family is absent from the final
  negotiated intersection, the notification Data listing only the missing
  MultiProtocol capabilities in configured order. Both default to unset,
  preserving RFC 4271 hold-time and RFC 4760 partial-intersection
  compatibility. M93 proves the required-families rejection against
  BIRD 2.

- **RFC 9072 extended BGP OPEN Optional Parameters lengths.** OPEN
  messages keep the RFC 4271 encoding through 255 optional-parameter
  octets and use the extended aggregate and per-parameter lengths only
  above that boundary. Receivers accept extended encodings at any length,
  including zero, while OPEN remains bounded to 4096 bytes. Unknown
  capabilities inside the Capabilities parameter remain accepted.

- **Live TCP-AO successor selection and fail-closed key deletion.** After
  an add-only SIGHUP installs the successor everywhere, a later SIGHUP
  sets only local RNext and commits predecessor deprecation after one
  generation-relative peer-traffic observation across affected sessions;
  `awaiting_peer` retries the identical generation on a later SIGHUP, and
  live selection never deletes an MKT or sets Linux Current. A third
  immutable generation can then remove only deprecated MKTs that are
  neither Current nor RNext, preserving the protected owner set, survivor
  order, key definitions, and selected MKT. Listener deletion precedes
  queued-child and protected-session reconciliation; ambiguous partial
  session mutation discards the whole changed cohort; failures retry only
  the identical generation when the listener remained exact, restored its
  exact prior inventory, or already reached desired, and a failed
  prior-inventory restoration requires restart. Key edits/reordering,
  selected or non-deprecated-key deletion, and protected-owner CRUD remain
  restart-required. M43 proves the full live add/select/deprecate/delete
  lifecycle against BIRD while preserving the established session and its
  received route, including recovery from a crash mid-rotation.

- **Max-prefix capacity is alertable before teardown, and visible per
  neighbor.** Prometheus and the shipped Grafana overview expose
  actor-owned usage, finite limits, and headroom for aggregate,
  IPv4-unicast, and IPv6-unicast scopes; the example alert pack warns on
  sustained 80% utilization. Neighbor detail exposes the authoritative
  O(1) aggregate max-prefix-counted NLRI identity count plus unique IPv4-
  and IPv6-unicast prefix counts, with effective finite limits and
  remaining headroom through gRPC, human CLI, and JSON. Unlimited and
  disconnected scopes are absent rather than reporting fake zeroes, and
  stale session snapshots withhold non-authoritative headroom.

- **Opt-in timed restart after a max-prefix teardown.** Neighbors and peer
  groups accept a non-zero `max_prefix_restart_seconds`; the default
  remains an indefinite fail-closed shutdown latch. The peer manager makes
  one generation-fenced restart attempt after the hold-down, invalidates
  stale countdowns on config or dynamic-range replacement, and exposes the
  action, configured duration, and remaining milliseconds through gRPC,
  CLI, and JSON. `rs-config-render` maps ARouteServer's OpenBGPD-style
  `restart_after` minutes to checked seconds and records the emitted timer
  in its render receipt.

- **Negotiated session and Graceful Restart state is visible per
  neighbor.** Neighbor detail reports the current Established session's
  negotiated hold time, remote router ID, four-octet-AS result, mutual
  families, usable peer GR coverage, peer-advertised Restart Time, and
  locally capped effective retention through gRPC, human CLI, and JSON.
  Presence distinguishes older daemons, stale queries, down sessions,
  unsupported GR, locally disabled GR, and active helper state without
  substituting configured defaults.

- **Peer-advertised Graceful Restart retention can be bounded locally.**
  Neighbors and peer groups accept `gr_peer_restart_time_max`
  (default 4095) to cap the RFC 4724 Restart Time used for initial
  disconnected stale-route retention, without changing the Restart Time
  rustbgpd advertises in its own OPEN.

- **BFD remote AdminDown is a distinct state.** `rbgp bfd`, the BFD API,
  and `rbgp doctor` report a peer that has administratively disabled its
  own BFD session separately from a session that is failing, so the
  operator is pointed at the far end's configuration rather than at a
  transport fault.

- **RFC 8326 graceful-shutdown advertise intent is visible per neighbor.**
  `rbgp neighbor <peer>` reports the local desired state as enabled,
  disabled, or unknown when connected to an older daemon; JSON and
  `NeighborState` field 37 preserve the same presence-aware state. This is
  advertisement intent, not evidence of downstream receipt or
  convergence.

- **Per-disposition malformed-UPDATE counters, with an RFC 7606 interop
  proof.** New `bgp_update_malformed_total{peer, disposition}` counter
  (`disposition` ∈ `attribute_discard` / `treat_as_withdraw` /
  `session_reset`) increments once per malformed UPDATE at the point the
  RFC 7606 disposition is decided, on every handling path — including the
  §5.2 no-reachable-NLRI session-reset escalation and decode-level resets.
  The M91 interop lab drives a raw speaker injecting one malformed UPDATE
  per disposition class and asserts session survival, RIB contents, the
  counter, and the §6 DEBUG full-message capture end to end.

- **Exact per-candidate export explain for unicast Add-Path.**
  `ExplainAdvertisedRoute` and `rbgp rib advertised --explain` can select
  a presence-bearing Adj-RIB-In source peer/path ID (including ID 0) for a
  peer with negotiated IPv4/IPv6 unicast Add-Path send. The response keeps
  that inbound identity separate from the independently assigned compact
  outbound rank, explains policy/cap/OTC/exact-wire denials, and diffs the
  exact rank against Adj-RIB-Out. Selector absence preserves the existing
  winner view.

- **`rbgp neighbor A --compare B`** explains live update-group sharing
  with stable, ID-free reasons.

- **Birdwatcher adapter serves the Alice-LG noexport views.**
  `GET /routes/noexport/{id}` completes the adapter's looking-glass
  contract: Loc-RIB best routes not advertised to the peer
  (`RibService.ListBestRoutes` minus `ListAdvertisedRoutes`), each
  explained by a live-ladder dry run (`ExplainAdvertisedRoute`) and tagged
  with a synthesized `64496:65521:<gate id>` noexport-reason large
  community plus human-readable `noexport_reason` /
  `noexport_reason_detail` keys. The view covers every export-ladder
  suppression (split horizon, RFC 4456 reflection, family, RFC 9494 LLGR,
  RFC 5291 ORF, RFC 4684 RT membership, export policy), is prefix-granular,
  and serves an empty view for peers with no live session. All backing
  RPCs are `sensitive_read`-tier — no authorization change for existing
  adapter deployments.

- **Route-safety and slow-peer dashboards with actionable alerts.** The
  shipped Grafana overview adds exact-export rejection and
  malformed-UPDATE disposition rates, raw step-rendered selection-deferral
  state, timeout/ledger-overflow rates, coalesced outbound queues,
  slow-peer state, discrete update-group membership, export-policy
  transition state and duration, actor-poll latency, and accepted-policy
  age, each preserving its metric's native labels. Prometheus rules warn
  on increases in the failure counters, on a peer that remains slow for
  five minutes, and on actor polls above the exact 200 ms histogram
  boundary; structural dashboard and promtool gates protect both. The
  daemon materializes the bounded counter label sets when sessions and
  selection-deferral families are created, so ordinary scrape history can
  establish a zero baseline before producers emit failures.

- **Official ClusterFuzzLite integration for all 17 cargo-fuzz targets.**
  The address-sanitized code-change workflow is manual-dispatch only; the
  existing cargo-fuzz workflow remains the sole nightly campaign. The
  ordinary PR/push CI check and the shared OSS-Fuzz / ClusterFuzzLite
  build path enforce the exact manifest/source inventory, whose mutation
  tests remove every manifest and source target in turn and inject empty,
  failed, and redirected enumeration, an unexpected fuzz crate, and a
  cross-crate target-name collision. A 40m42s commissioning run rejected
  putting this work on the PR critical path. Batch fuzzing, pruning,
  storage, and coverage are not part of this integration.

### Changed

- **Wire-codec temporary allocation churn is lower on the measured attribute
  hot paths.** Path-attribute encoding now reuses one value scratch across an
  invocation, and UPDATE validation uses one stack-resident presence table for
  duplicate and mandatory-attribute checks. Six-pair same-host Criterion
  receipts measure the exact rich encoder and typical validator fixtures
  28.34% and 90.57% faster respectively; separate `System`-wrapped
  `GlobalAlloc` diagnostics reduce the rich fixture from 21 to 8 requests per
  call and the typical valid fixture from 2 to 0. These are fixture-scoped
  request/timing results, not whole-daemon CPU, convergence, RSS, or
  allocation-free encoder claims. See
  [`docs/perf/wire-codec-allocation-2026-07.md`](docs/perf/wire-codec-allocation-2026-07.md).

- **Grouped route-server fanout avoids two peer-multiplied bookkeeping
  costs.** Metrics handles are now cloned once per distribution pass, and
  peers with no new, current, or pending RFC 9234 OTC-blocked state skip the
  empty per-prefix reconciliation scan. Six-pair, pinned real-encoder receipts
  over 64 changed routes show 14.10%..15.04% lower measured fanout time for the
  metrics change and 42.09%..44.61% for the OTC fast path at 64..1,000 peers;
  the metrics one-peer negative control is noise and carries no claim. These
  are bounded actor/probe/commit/enqueue measurements, not whole-daemon
  convergence claims. See
  [`docs/perf/fanout-metrics-handle-2026-07.md`](docs/perf/fanout-metrics-handle-2026-07.md)
  and
  [`docs/perf/otc-pristine-reconcile-2026-07.md`](docs/perf/otc-pristine-reconcile-2026-07.md).

- **Import-decision explain (`[policy.explain] enabled`) now defaults to
  `false`.** Both construction paths moved together: the schema default
  applied when a config file omits `[policy.explain]`, and
  `TransportConfig::new`, which embedders of `rustbgpd-transport` reach
  without loading a config file. An explicit `enabled = true` is
  unchanged in every respect.

  Explain is diagnostic state, never routing correctness — disabling it
  changes what the daemon can *tell* you, not what it *does*. Its cost,
  though, is retained **per session**: `cache_size` is one global number
  applied to every session, and there is no per-peer or per-group
  override, so the bill multiplies by the defining scale dimension of a
  route server. And at the default 4096 entries, retention is
  **partial-table** by construction: a peer announcing more prefixes
  than that keeps the cache saturated, so a query for an arbitrary
  prefix of theirs returns `evicted` rather than a decision. Default-on
  therefore charged in full for a partial answer. Off by default, the
  choice becomes an informed memory-versus-observability trade the
  operator makes.

  **The settled memory receipt, with each figure labelled:**

  | Figure | Kind |
  |---|---|
  | 373.5 MiB steady RSS returned at 1000 sessions × 400 routes | **computed from four measured runs** — same config across the immediate default-on/default-off commits |
  | 154 KiB fixed per session plus 587 B per retained entry | **computed model** — solved from same-binary 1000 × 400 and saturated 100 × 5000 fleet shapes |
  | 2.44 MiB per saturated session | **computed** from the measured 100 × 5000 shape |
  | 2.4 GiB saturation ceiling | **extrapolated**, and only at one fleet shape: roughly **1000 ingress peers each announcing at least 4096 distinct routes**. It was never measured at that fleet size and is not the cost of one full-table member |

  The fifteen-run receipt, controls, raw bounds, and artifacts are in
  `docs/perf/explain-cache-opt-in-2026-07.md`.

  Every shipped starter config and both `--init-config` profiles now
  state the choice explicitly rather than inheriting it: the lab,
  minimal, Docker Compose, DDoS-mitigation, and hosting-provider
  starters set `enabled = true` with the reason on the page; the
  route-server, route-collector, edge, Linux-edge-FIB, and the two EVPN
  starters set `enabled = false` with the reason on the page. All of
  them still pass `rustbgpd --check --strict` with a clean summary.
  Rationale, measured economics, the rejected smaller-default-cache
  alternative, and the conditions that would reopen default-on (a global
  memory budget, per-peer selection, or another bound independent of
  session count) are in ADR-0073.

- **BREAKING (metrics): the `peer` label is now the bare neighbor address
  on every metric family.** Metric labels are a public API, and this one
  had two incompatible formats — sometimes within a single family.
  Session-owned series labelled `peer` with the transport endpoint
  (`192.0.2.1:179`, `[2001:db8::1]:179`) while RIB-, policy-, BFD-, and
  BMP-owned series used the bare configured address (`192.0.2.1`,
  `2001:db8::1`). `bgp_policy_routes_total` carried both: its
  `direction="import"` series came from the session and its
  `direction="export"` series from the RIB. The consequence was silent,
  because Prometheus reports no error for a query that matches nothing:
  `sum by (peer) (bgp_policy_routes_total)` returned two series per peer,
  and any `by (peer)` join across the two groups returned empty — so an
  alert built that way never fired.

  Every emission site now uses the bare address, produced by one helper
  (`rustbgpd_telemetry::peer_label`). The port carried nothing joinable:
  it was the *configured* endpoint, not the observed source port, and
  neighbor identity is already unique by address (configuration validation
  rejects the same IPv6 link-local address on two interfaces), so no peer
  needed it to be told apart. The structured-log `peer` field on session
  events follows the same change, and now matches the rest of the daemon's
  logs.

  **Series that changed format** — all previously `addr:port`, now bare
  address: `bgp_session_state_transitions_total`, `bgp_session_flaps_total`,
  `bgp_session_established_total`, `bgp_fsm_stale_timer_events_total`,
  `bgp_messages_sent_total`, `bgp_messages_received_total`,
  `bgp_notifications_sent_total`, `bgp_notifications_received_total`,
  `bgp_peer_outbound_queue_depth`, `bgp_peer_slow`,
  `bgp_rejected_routes_retained`, `bgp_max_prefix_usage`,
  `bgp_max_prefix_limit`, `bgp_max_prefix_headroom`,
  `bgp_max_prefix_exceeded_total`, `bgp_update_malformed_total`,
  `bgp_otc_routes_blocked_total`, `bgp_role_mismatch_total`,
  `bgp_as_path_loop_detected_total`, `bgp_bgpls_nlri_discarded_total`,
  `bgp_rr_loop_detected_total`, `bgp_inbound_rib_backpressure_total`,
  `bgp_hold_timer_rearmed_pending_input_total`,
  `bgp_send_hold_expirations_total`, `bmp_source_drops_total`, and the
  `direction="import"` half of `bgp_policy_routes_total`. Every other
  `peer`-labelled family already used the bare address and is unchanged.

  **What operator PromQL needs:** drop any port-stripping `label_replace`
  from cross-family joins, and rewrite selectors that pinned an endpoint —
  `bgp_peer_slow{peer="192.0.2.1:179"}` becomes
  `bgp_peer_slow{peer="192.0.2.1"}`, and `peer=~"192\\.0\\.2\\.1:.*"`
  becomes an exact match. Recording rules and dashboards keyed on the old
  values see the old series go stale and new ones appear; counters restart
  from zero, which `rate()` and `increase()` handle as an ordinary reset.
  The shipped dashboard and alert pack are updated: the dashboard's two
  peer selectors (`$peer` endpoint / `$neighbor` address) collapse into one
  `$peer`, which also fixes the RIB, GR, and BFD panels that returned no
  data whenever a specific peer was selected, and `BgpPeerAdjRibInEmpty`
  joins directly instead of rewriting the label. `rbgp doctor`'s slow-peer
  remediation now prints a selector that resolves. No transitional
  dual-emit is provided: emitting both formats would double the per-peer
  series count of 26 families for the whole transition window, and it
  would preserve the exact failure being fixed — `sum by (peer)` would
  still return two series per peer, so a dashboard that looked correct
  during the overlap would break at removal instead of now.

- **`rustbgpd --check` no longer summarizes a flagged config as
  `config OK`, and reports every warning it raises.** `--check` is the
  last gate before a config reaches a production box, and three classes of
  finding were escaping it.

  It previously said nothing about policy, so a config whose eBGP sessions
  were wide open in both directions passed as cleanly as one that was
  fully filtered. It now names each eBGP neighbor that resolves no policy
  and the direction(s) it is missing, framed on stderr, and says which
  consequence applies: unfiltered in that direction with
  `[global] ebgp_requires_policy` off, or carrying no routes in that
  direction with it on.

  `Config::validate` also emitted its non-fatal diagnostics through
  `tracing`, but `Config::load` runs before `init_logging` on every path —
  `--check` returns long before it — so no subscriber was installed and
  those records were written nowhere. The RFC 9107 warning for an
  `orr_vantage` with no neighbor negotiating `linkstate` (a topology feed
  that can never fill, leaving every vantage permanently unresolved) was
  invisible on every path except a SIGHUP reload. Validation diagnostics
  are now returned rather than logged, so they join the counted warning
  set and are logged once at daemon startup where a subscriber exists.

  `security.grpc.enforcement = "legacy"` fired only at daemon startup, so
  a config gate could pass a configuration whose management surface
  enforces no per-method tier authorization: every authenticated client of
  a `read_write` listener may call every method up to the listener's
  `max_tier` cap, including the `operator_only` methods that reconfigure
  the daemon, and `[security.grpc.roles]` entries deny nothing. Tier
  enforcement has been the default since v0.24.0 and becomes mandatory in
  a future release that will reject the config, so the warning now states
  the migration — give every listener a role identity, map each principal
  to a role, then set `enforcement = "tier"` — rather than only reporting
  the setting.

  A check with warnings now summarizes as
  `config VALID, <n> WARNINGS — NOT a clean check: <path>`, so the summary
  line alone cannot read as a clean result. A check with nothing to flag
  still prints `config OK: <path>`. Plain `--check` still exits 0 — a
  permit-all route server is a legitimate configuration and rejecting it
  would break deployments that mean it — and `--check --strict` exits 1.
  The `ebgp_requires_policy` partial-enforcement notice deliberately stays
  a startup-only record: it reports what this release has not finished
  building, not a defect in the operator's config.

- **Every shipped starter config is policy-complete and passes
  `rustbgpd --check --strict`.** The warning above immediately found that
  our own starters were the unpoliced shape it describes: eight of eleven
  failed a strict check, including both `--init-config` profiles,
  `examples/minimal`, the Docker Compose quick-start, and the IXP route
  server. A starter that trips our own safety warning on a first run
  teaches the operator running it that the warning is noise, so each one
  now resolves an explicit import and export chain for every eBGP
  neighbor. Permit-all postures stay permit-all — the `lab` profile,
  `examples/minimal`, the compose quick-start, the route server's
  transparent export (RFC 7947), the collector's import, and the
  mitigation injector's export are all unfiltered by design — but each is
  now written as a named chain whose comment states that it was chosen and
  what it is wrong for, rather than being permit-all by omission, which is
  indistinguishable from having forgotten. The `edge` profile and
  `examples/linux-edge-fib` gain a default-deny export chain to fill in;
  the latter attaches both directions to its `transit` peer group, so a
  new session inherits them. Each of these also sets
  `[global] ebgp_requires_policy = true`, so deleting a shipped chain fails
  closed instead of reverting to permit-all; it is startup-only, which each
  config's comment says where an operator would look. The iBGP-only
  starters (`hosting-provider`, `rr-evpn-fabric`, `evpn-vtep-leaf`) are
  unchanged — RFC 8212 scopes the requirement to eBGP. A workspace test
  enumerates the profiles from the daemon's own profile list and the
  examples from the `examples/` tree, then asserts a clean
  `--check --strict` for each, so a starter added later is covered without
  editing the test. The release checklist now requires that command
  instead of documenting the warnings.

  Independently, every starter profile now ships an explicit tier-authorized
  local control socket — a `[global.telemetry.grpc_uds]` listener with a
  stable `principal`, `enforcement = "tier"`, and a matching
  `[security.grpc.roles]` entry — so a first run is authorized the way the
  documentation describes rather than through legacy enforcement.

- **`rbgp config import` generates configs that fail closed.** The
  importer never translates policy, so every config it emitted came up
  permit-all on every eBGP session it declared. The generated `[global]`
  now sets `ebgp_requires_policy = true`, which makes each eBGP direction
  with no explicit policy carry no routes until one is configured, instead
  of silently passing everything. Because this is a runtime behavior the
  source config did not ask for, the import report states that it was
  added, why, what it does to the sessions below, and that it is
  startup-only; the emitted config carries the same explanation as a
  comment, and deleting the line restores permit-all.

- **`rs-config-render` output passes `rustbgpd --check --strict`.** The
  renderer is the IXP adoption path — an operator runs it in a cron refresh
  loop and gates the result before every swap — and every config it
  produced raised the unpoliced-eBGP warning once per member, because
  members got an import chain and no export chain at all. The first thing
  the new gate told an IXP was that the tool we hand them fails it.
  Rendered configs now carry a declared transparent export chain
  (permit-all, the RFC 7947 posture, stated rather than inherited) and
  `[global] ebgp_requires_policy = true`, the same shape and wording as
  `examples/route-server`, so deleting the chain later stops members
  receiving routes loudly instead of silently reverting to permit-all. The
  documented refresh loop, the renderer's own "gate with" hint, and the M90
  differential gates all run the strict form now, and the workspace test
  over the emitted config asserts both the strict exit code and the
  `config OK` summary line — it previously ran a plain `--check` and passed
  with three warnings, so it had been asserting that output was acceptable
  while the strict gate correctly rejected it.

- **RFC 6793 legacy-AS migration is lossless end to end.** Sessions
  without capability 65 now normalize received type 2/17 paths and
  type 7/18 aggregators before loop detection, policy, and RIB
  processing, then derive the required compatibility attributes in the
  shared classic/MP export encoder. Modern peers never receive stale
  migration shadows; exact-export sizing includes generated AS4 bytes;
  malformed compatibility attributes retain RFC 7606 fault isolation. MRT,
  Loc-RIB BMP, and from-BMP ribsnap serialization preserve the canonical
  aggregator, while the pre-policy BMP tap remains byte-identical. M94
  proves the legacy IPv4 session against a pinned ExaBGP 5.0.9 source and
  an independent old-speaker sink, including reconstructed loop rejection,
  exact path/aggregator wire pairs, withdrawal, and session continuity.

- **RFC 9774: AS_SET and AS_CONFED_SET are prohibited.** A prohibited
  segment type in a received `AS_PATH` or `AS4_PATH` is rejected on decode
  with the RFC 7606 treat-as-withdraw disposition — the UPDATE's routes
  are withdrawn and the session stays Established — and an `AS_PATH`
  containing an AS_SET refuses to encode.

- **RFC 7607 / RFC 6286 OPEN identity validation.** An OPEN claiming AS 0
  is rejected with Bad Peer AS in either representation (`my_as` or the
  four-octet capability), checked before the dynamic-neighbor
  accept-any wildcard; and an OPEN whose BGP Identifier equals the local
  router ID is rejected with Bad BGP Identifier for iBGP only, per
  RFC 6286 §2.2.

- **Unknown FlowSpec component types keep their hard rejection, now with a
  conformance-citing diagnostic.** *No decode-acceptance change: input
  that errored before still errors, and input that parsed before still
  parses* — `rustbgpd-wire` embedders tracking the 0.16.0 acceptance
  changes can ignore this entry, since only the
  `DecodeError::MalformedField` detail string and the documentation
  changed. Component types outside 1–13 remain a malformed NLRI per
  RFC 8955 §4.2, dispositioned per RFC 7606 §7.11. Skip-unknown was
  re-examined and is not implementable for this encoding: only the rule is
  length-prefixed, each component's value grammar is selected by its type
  code, so an unrecognized component cannot be measured or stepped over
  without misparsing the remainder of the rule — and silently dropping one
  would widen the rule's match set past what the sender specified.
  `KNOWN_ISSUES.md` previously described the rejection as a
  forward-compatibility defect to be fixed; it now records it as required
  behavior.

- **RFC-correct RT/RO policy action encoding.** TOML
  `set_community_add` / `set_community_remove` and `.rpol` `add` /
  `remove` actions now share the same typed encoder: numeric ASNs through
  65535 use RFC 4360 type `0x00`, larger ASNs use RFC 5668 type `0x02`,
  and dotted IPv4 administrators preserve their spelling and use RFC 4360
  type `0x01`. The narrow AS4/IPv4 forms reject local administrators above
  65535 with an actionable config error.

- **RFC 8092 Large Community duplicate normalization.** Received
  attributes silently retain only the first occurrence of each value, and
  the encoder applies the same stable deduplication so locally constructed
  API or policy attributes cannot transmit duplicates. Distinct-value
  order, flags, length-encoding rules, and malformed-length behavior
  remain unchanged; the emitted length is recomputed from the retained
  values.

- **RFC 10005 Link Bandwidth receiver subset.** The typed wire accessor
  recognizes exact transitive and non-transitive communities; weighting
  selects the lowest finite nonnegative value without altering raw
  reflection. Zero stays valid; construction stays type `0x40`.

- **The shipped Docker quick-start supports the workflow it documents.**
  `examples/docker-compose` mounted the config read-only, so every
  mutating command failed and the README's "no restarts to add peers,
  change policy, or inject routes" was false out of the box. The config is
  now shipped as a template and copied into the daemon's writable state
  volume on first start, following the pattern the interop labs already
  use; runtime edits survive `docker compose restart` and `down -v`
  reseeds from the template. The standalone `docker run`, containerlab,
  and deployment examples carry the same correction, and
  `docs/CONFIGURATION.md` states the requirement directly: the config
  file's *directory* must be writable by the daemon for runtime mutation,
  because persistence writes `<config>.tmp` alongside it and renames.

- **Library crates: `rustbgpd-wire` 0.16.0 and `rustbgpd-fsm` 0.3.1.** The
  wire API surface is additive, but **decode acceptance changed in six
  places** — embedders should diff exactly this list:

  - **Unsupported OPEN Optional Parameter types now error** with OPEN
    Message Error / Unsupported Optional Parameter (2/4) instead of being
    skipped. Unknown capabilities *inside* the Capabilities parameter
    remain accepted.
  - **BGP-LS attribute 29 enforces its optional non-transitive flags and
    contained TLV framing.** Malformed contained framing discards the
    complete attribute (RFC 9552 whole-attribute discard) while preserving
    the BGP-LS NLRI and the session; valid unknown TLVs remain byte-stable
    for reflection.
  - **AGGREGATOR decodes as a typed `PathAttribute::Aggregator` value**
    instead of falling through to `PathAttribute::Unknown`. Code matching
    on `Unknown` for type code 7 no longer sees it.
  - **OPEN and KEEPALIVE over 4096 bytes are rejected** at header peek,
    before a framing caller buffers the declared body, regardless of a
    negotiated RFC 8654 extended message length.
  - **AS_SET and AS_CONFED_SET are rejected in a received `AS_PATH` or
    `AS4_PATH`** per RFC 9774, with the RFC 7606 treat-as-withdraw
    disposition. Paths that decoded before now withdraw their routes.
  - **`ExtendedCommunity::as_link_bandwidth()` matches exact types only.**
    Communities it previously accepted by a looser match no longer resolve
    as link bandwidth.

  `rustbgpd-fsm` 0.3.1 is purely additive: `PeerConfig` gains
  `min_hold_time: Option<u16>` and `required_families: Vec<(Afi, Safi)>`,
  and `PeerConfig` is `#[non_exhaustive]`, so external construction through
  its builder is unaffected.

- **The gRPC threat-model annex is withdrawn; stop citing it as security
  evidence.** `docs/adr/0064-threat-model.md` described the management
  plane as it stood before v0.24.0 — tier enforcement audit-only and off
  by default, principal mapping unimplemented, and any accepted credential
  reaching the whole read-write surface. Tier enforcement has been the
  default since v0.24.0, so a reviewer working from that document
  prioritised threats the daemon already denies before the handler runs.
  Its risk rankings were all derived from the superseded assumption and
  could not be repaired by editing the prose around them, so the file is
  now a stub that says so and points at the surfaces that are current;
  the rewrite is slice 7 of ADR-0064. `docs/API.md`, `docs/SECURITY.md`,
  and the method inventory no longer present it as an external-review
  packet, and the release checklist now audits the inventory's structural
  fence — the tests that hold `grpc-method-inventory.md` and `.json` to
  the tiers the daemon enforces — in place of a file-non-empty check on
  the annex.

- **Turning off `[policy.explain]` now actually costs nothing per peer.**
  The import-decision cache was built at session construction, so every
  peer paid for it whether or not explain was enabled: at the default
  `cache_size = 4096` that is roughly 150 KiB allocated per session — the
  LRU index sized to capacity up front, plus a 512-entry eviction ring —
  held for the life of a session that, with explain off, never writes a
  single entry. On a 1000-peer route reflector that is about 150 MiB
  allocated for a disabled feature. Most of it is never written, so it is
  address space and allocator bookkeeping rather than measured RSS, but a
  disabled feature should reserve neither. Both allocations are now
  built on the first recorded decision instead, so a disabled session
  holds none of it, and a session that is down releases what it had.
  Enabled sessions are unaffected: the LRU and the eviction ring still
  come up together at their full configured sizes, before any eviction
  can occur. `[policy.explain] enabled` still defaults to on, and its
  behaviour there is unchanged.

- **A peer with no rejected routes no longer allocates its rejected-route
  LRU.** The store previously reserved its 1024-entry index when the
  session was constructed, even if every received route was accepted.
  The existing corrected
  [DHAT capture](docs/perf/explain-cache-opt-in-2026-07.md#dhat-attribution)
  attributes 704,320 allocated bytes to 20 such stores — 35,216 bytes per
  peer. Those are allocated bytes, not an RSS measurement. The backing
  LRU is now created on the first retained rejection and released on
  session reset; listing, replacement, eviction, ordering, counters, and
  the configured capacity are unchanged.

- **Enabling import explain no longer slows down every inbound route.**
  Explain needs a formatted `AS_PATH` string to re-derive which policy
  statement decided a route, and the session used to get it by forcing
  the per-UPDATE string render for *every* inbound route whenever explain
  was on — re-imposing on ingress the cost that per-chain gating removed
  on the export side. The cached decision already stores the typed
  `AS_PATH`, so the string is now rendered from it at explain-query time,
  with the same formatter that produced it. The render is once per
  explain query rather than once per route, the cache stops carrying a
  second copy of the path per entry, and the inbound path builds the
  string only when the import chain's own `AS_PATH` matches need it.
  Explain output is unchanged.

### Fixed

- **RPKI VRP visibility now follows the exported metric family.** The TUI sums
  IPv4 and IPv6 `bgp_rpki_vrp_count` samples, and `rbgp doctor` warns when
  configured caches have a zero, missing, malformed, or unavailable snapshot.

- **A config file the daemon has rewritten now says so.** The first
  runtime mutation — `rbgp neighbor add`, a config transaction, a gNMI
  `Set` — rewrites the config file in canonical form, and always has:
  comments and key order from the previous file are gone and defaulted
  fields are written out explicitly. Nothing on disk said that had
  happened, so an annotated starter config could come back with its
  comments silently dropped, including the `DELIBERATE DEVELOPMENT
  POSTURE: PERMIT ALL, BOTH DIRECTIONS` banner the lab starter carries.
  Every file the daemon writes now opens with a short header stating
  that it is maintained by rustbgpd, that the previous file's comments
  and formatting are not preserved, and that an annotated copy belongs
  in version control. The header carries no version and no timestamp, so
  it does not churn the file or add noise to config-history diffs, and
  rewriting the file repeatedly leaves exactly one of them. Nothing else
  about the write changed — same canonicalization, same crash-safe
  atomic write, same `0600` mode.

- **The daemon now states its eBGP policy posture in the log at
  startup.** `rustbgpd --check` framed this before deployment, but an
  operator whose banner was flattened by a runtime rewrite had nowhere
  left to see it. When any eBGP neighbor resolves no explicit policy,
  startup logs one line naming how many, and whether those directions
  are unfiltered or are carrying no routes under `ebgp_requires_policy`.

- **`rbgp doctor` no longer reports the daemon's own config write as an
  unapplied external edit.** The config-freshness check compared the
  file's mtime against daemon process start, so any deployment following
  the documented runtime-mutation workflow warned permanently —
  `config … was modified after daemon pid 1 started — on-disk changes are
  not applied` — about a change the daemon itself had made and applied.
  Container deployments whose entrypoint seeds a config template after
  the process starts hit the same false warning. A permanent yellow
  trains operators to ignore yellow, which is the whole value of the
  check. The daemon now records the config file's timestamp whenever it
  reads or writes that file, and doctor judges against that record: a
  daemon-authored write and a post-start template seed both read clean,
  a genuine external edit still warns with the same validate-and-SIGHUP
  advice, and a daemon that recorded nothing falls back to the previous
  process-start comparison.

- **Three gRPC errors no longer tell operators to pass a `--config` flag
  that does not exist.** `config history`, config transactions, and
  FIB-table CRUD each answered their unavailable case with "start
  rustbgpd with `--config`"; the daemon takes its config path as a
  positional argument and rejects that flag. Each now states the real
  condition instead.

- **A rejected runtime mutation no longer causes any externally visible
  change.** When config persistence failed — an unwritable config
  directory, a read-only mount, a full filesystem — every persisted
  mutating RPC had already applied its runtime change and then tried to
  undo it by applying the inverse. `rbgp neighbor <addr> delete` returned
  `FAILED_PRECONDITION`, which reads as "nothing happened", while the BGP
  session had in fact been torn down and a *different* session
  re-established in its place: new identity, uptime back to zero,
  cumulative counters back to zero, metric series reaped and restarted,
  and `Flaps` still reading 0 so the event was invisible in the operator's
  own flap accounting. Any `rate()` or `increase()` spanning the window
  was silently wrong. The same apply-then-compensate ordering affected
  `neighbor add`, both dynamic-neighbor RPCs, all twelve policy and
  neighbor-set / policy-chain mutators, and the peer-group and membership
  mutators, where it put a Route Refresh and an Adj-RIB-Out rewrite on the
  wire twice — once forward, once as "rollback" — or bounced every
  inheriting member's session twice, for a request that was rejected.

  Persistence is now a two-phase reservation shared by all of them: the
  candidate config is serialized and durably staged next to the config
  file *before* any runtime state is touched, the runtime change is
  applied only once that succeeded, and the staged write is then published
  with a rename. A staging failure is reported while the sessions, their
  counters, and their metric series are still untouched, and an apply
  failure discards the staged write instead of leaving it on disk.
  `FAILED_PRECONDITION` from a mutating RPC now means what it says: no
  externally visible mutation. Rejections that are simply bad requests keep
  their own status codes rather than being reported as persistence faults.
  The ADR-0076 config-transaction executor and FIB-table CRUD keep
  single-phase persistence — each owns a rollback that restores exact prior
  state and already reports an ambiguous outcome when it cannot.

- **The BGP listener sets `SO_REUSEADDR`, and a bind failure exits 1.**
  The listener socket is built through `socket2`, which does not apply the
  `SO_REUSEADDR` that `std`/`mio` set for the gRPC and metrics listeners.
  The daemon is normally the active closer at shutdown, so on every
  restart with sessions up a connection the previous generation accepted
  still holds the listen port in `FIN_WAIT`/`TIME_WAIT` — and the next
  generation's bind was rejected with `EADDRINUSE`. `SO_REUSEADDR` is set
  before `bind`, ahead of the TCP-AO listener MKT installation, which keeps
  its bind→install→listen ordering. `SO_REUSEPORT` is deliberately not
  used: it permits concurrent binds, which would let two daemon
  generations serve the listen port at once. Because Linux requires the
  option on both endpoints, the first restart of a daemon whose previous
  generation predates this fix can still be rejected; every restart after
  that is clean.

  A bind failure that does happen now exits 1 instead of leaving a live
  daemon that accepts no sessions. The daemon previously marked itself
  not-ready and kept serving gRPC — a state with no recovery path, since
  `listen_port` is mandatory, the listener is never rebound without a
  restart, and the only surface reporting the fault was `/readyz`, which
  exists only when `prometheus_addr` is configured. The process parked
  with its core function dead while its management plane looked healthy.
  Exit 1 matches the code already used for an unexpected gRPC server exit
  and for a bind failure with TCP-AO peers configured, so supervisors with
  `Restart=on-failure` retry; the retry also clears a transient bind
  failure without an operator, and a permanent one repeats the bind error
  in the journal. `rbgp doctor` reports the cause (port in use, missing
  `CAP_NET_BIND_SERVICE`) against the down daemon through its existing
  `bgp.listener` check.

- **The initial table dump now evaluates export policy with the peer's
  peer-group.** The session staged its peer-group policy context *after*
  the `PeerUp` registration, but `PeerUp` builds the initial Adj-RIB-Out
  synchronously — so the first full-table dump to a newly established peer
  was evaluated with no peer-group, and any export rule matching on
  peer-group began applying only from the next update. On a route server
  with group-scoped export filtering this advertised routes the operator's
  policy intends to deny, at every session establishment and every
  re-establishment. The context is now staged before `PeerUp`, alongside
  the RFC 9234 role, RFC 7947 control-community, exact-encoder, and
  RFC 4724 contexts. **This is a wire-visible change to the initial
  dump:** an upgraded daemon's first dump to a group-scoped peer may now
  be correctly filtered, or otherwise transformed by group-matched policy
  actions, where it previously was not. Peers whose export policy does not
  match on peer-group are unaffected.

- **`bgp_rib_adj_out_prefixes` no longer reads stale-nonzero through a
  graceful-restart hold window.** Entering GR tears down the peer's
  outbound registration and its Adj-RIB-Out along with it, but only the
  `PeerDown` teardown zeroed the seven per-family gauge series; the GR
  down path left them advertising the departed session's counts for the
  whole restart timer. The reset moved into the shared outbound-teardown
  helper, so both paths — plus collision failback and
  replacement-`PeerUp`, which empty the same table — now zero it where the
  table is actually removed. RFC 4724 retention is an Adj-RIB-In property:
  `bgp_rib_prefixes`, `bgp_gr_active_peers`, and `bgp_gr_stale_routes`
  remain the series that stay nonzero for a peer expected back, and
  `bgp_rib_outbound_registered_peers` already decremented at GR entry.
  **Operator-visible for dashboards and alerts:** the
  `Adj-RIB-Out prefixes per peer` panel, or any rule that read the old
  nonzero plateau during a restart, now sees zero until the peer returns
  and its table is rebuilt.

- **Hot-applicable peer-group edits no longer tear down every inheriting
  session.** `apply_peer_group_change` reshaped (delete + re-add) the
  group's static members for *any* change, so raising a group-level
  maximum bounced every client that inherits from it — while the identical
  neighbor-level edit hot-applied in place. A peer-group change's changed
  fields are now partitioned by reload-matrix impact class the way
  neighbor changes already were: a change set whose every field is `live`
  is applied to each member in place, with no session reset, and a set
  that mixes in any session-reset, restart-required, or unclassified field
  keeps the ADR-0081 reshape path. The in-place path carries the same
  atomicity contract — every member's next config is resolved and its live
  prior captured before any peer is touched, a mid-cohort failure restores
  the earlier members in reverse order and reports a compound error naming
  any it could not, and the stored group definition advances only after
  the whole cohort succeeded. Dynamic inheritors are part of that cohort
  and pick the new values up without waiting for a reconnect. For a route
  server, where clients inherit from a group, a group-level limit raise is
  now flap-free during exactly the incident the limit exists to contain.

- **Live edits of `max_prefix_restart_seconds` reschedule the pending
  automatic restart instead of cancelling it.** While a max-prefix
  hold-down countdown is armed, changing the duration re-arms the single
  pending attempt to now + the new value (the superseded deadline never
  fires); previously the edit silently converted timed recovery into an
  indefinite latch requiring manual enable. Removing the duration still
  cancels the countdown, adding one to an already-latched peer still does
  not retroactively restart it, and peer-group edits inherited by dynamic
  peers follow the same rules.

- **The daemon exits non-zero when shutdown is caused by unexpected gRPC
  server termination.** The coordinated teardown (NOTIFICATIONs, GR
  marker, checkpoints) still runs, but the process now exits 1 so
  supervisors with `Restart=on-failure` restart the daemon instead of
  treating the component failure as a clean stop. Operator-initiated
  shutdowns (SIGINT/SIGTERM, Shutdown RPC) still exit 0.

- **Configured BFD fails closed when its sockets cannot open.** A BFD
  runtime that could not start — including on a non-Linux host — left the
  daemon serving BFD-configured peers with no liveness detection behind
  them. Startup now aborts with the reason instead.

- **A policy rollback no longer drops retry intent when the forward Route
  Refresh was partially delivered.** Families are requested sequentially,
  so a forward refresh can have IPv4 accepted before IPv6 fails, and a
  reply timeout or dropped reply is ambiguous in both directions —
  Adj-RIB-In may already sit on the candidate policy. The rollback treated
  any incomplete forward as "nothing moved" and restored the prior
  `pending_refresh`, so if its own refresh back also failed the peer was
  left with real unfinished convergence and no armed retry. The forward
  now reports whether delivery began, and the rollback re-arms in that
  case. A forward that failed *before* any refresh was attempted still
  restores the prior state exactly.

- **A whole-peer Route Refresh now asks only for the families the session
  negotiated.** Requesting "everything" iterated the peer's *configured*
  families, so on any session that negotiated fewer than were configured —
  a neighbor offering IPv4 and IPv6 to a peer that accepted only IPv4, say
  — the unnegotiated family's request was rejected and failed the whole
  refresh. Policy edits, RPKI/ASPA cache refreshes, dataset swaps, and
  `SoftResetIn` with no explicit family list are all affected. The
  negotiated set is read from the session; a session that cannot report
  one keeps the previous behavior, which is where the per-family error was
  already the honest answer.

- **A duplicate Graceful Restart capability in an OPEN now honors the last
  instance,** per RFC 4724 §3, rather than the first — which changed every
  negotiated restart flag, timer, and family-forwarding value on a peer
  that sends more than one.

- **Session reset causes survive into diagnostics.** A NOTIFICATION sent
  or received now records a bounded, secret-free cause
  (`sent NOTIFICATION 6/4 (…)`) that `rbgp neighbor` and `rbgp doctor`
  report, including on the Cease/8 send-hold path that previously closed
  without assigning one. An intentional local administrative shutdown or
  reset deliberately does not overwrite an actionable earlier error.

- **RFC 9552 BGP-LS Attribute fault isolation.** Attribute 29 now enforces
  its optional non-transitive flags and contained TLV framing. Malformed
  contained framing discards only the complete attribute while preserving
  the BGP-LS NLRI and the session; valid unknown TLVs remain byte-stable
  for reflection.

- **TCP-AO RNext updates preserve socket policy and fresh counters.**
  Runtime RNext selection now read-modify-writes Linux `TCP_AO_INFO`
  without forcing Current or resetting counters, and composite inspection
  returns the trailing INFO snapshot so errors arriving during key
  enumeration remain visible.

- **Bounded BMP collector shutdown.** Disconnected collectors now stop
  connect and backoff waits promptly after the BMP manager queues its
  final Peer Down messages. Connected collectors still drain that queue,
  send Termination, and flush; all collector clients share one two-second
  shutdown budget instead of consuming two seconds per collector.

- **RFC 1997 export parity for EVPN and FlowSpec.** Source routes carrying
  `NO_EXPORT` or `NO_EXPORT_SUBCONFED` are suppressed toward honor-mode
  eBGP peers across live updates, initial dumps, route refresh, and forced
  resync; iBGP and transparent route-server sessions remain eligible,
  policy-added communities remain deliverable, and prior advertisements
  withdraw by exact family key.

- **EVPN and FlowSpec exports enforce `NO_ADVERTISE` and the generic
  export-policy contract.** EVPN exports enforce stored-route
  `NO_ADVERTISE` before policy and policy-added `NO_ADVERTISE` before the
  Adj-RIB-Out commit; FlowSpec exports enforce source and policy-added
  `NO_ADVERTISE`, apply generic export-policy path-attribute
  modifications, and ignore inapplicable next-hop rewrites. Both withdraw
  only the exact prior advertisement identity and stay silent for
  first-seen suppression, and an import-policy-denied replacement
  withdraws the exact accepted identity.

- **Outbound RFC 9234 OTC diagnostics emit once per transition** into a
  blocked disposition, rather than repeating on unchanged refresh/resync
  retries; permit, withdrawal, or session reset re-arms the edge.

- **`rbgp doctor` no longer fails in the container image.** The image runs
  as a nonroot user with a working directory it cannot write, and doctor
  defaulted its bundle to `./rustbgpd-doctor-<ts>.tar.gz` — so the tool
  the README names for bug reports exited 1 with a bare `Permission
  denied` at the moment someone was trying to file one. Without `--output`
  the bundle now goes to the first writable of: the working directory
  (unchanged where it works), the daemon's `runtime_state_dir`, the temp
  directory. A bundle that still cannot be written names the target path
  and points at `--output`, and a missing or unreadable `--token-file`
  names the path instead of surfacing a bare errno.

- **The `already_advertised` export-explain gate no longer claims the peer
  holds the route.** `identical route already advertised — peer is in
  sync` overstated what BGP can tell a sender: there is no acceptance
  signal, so a peer that treats every UPDATE as withdrawn (RFC 7606) stays
  Established with zero routes while that line reads "in sync". The
  unicast, VPN, and labeled-unicast rungs, the
  `rbgp rib advertised --explain` summary line, and the
  `already_advertised` field documentation now scope the claim to local
  Adj-RIB-Out state and say that remote acceptance is not observable.

- **GShut receiver verification is executable from `rbgp`.** The runbook
  uses the parse-valid received-RIB command, whose JSON now exposes
  optional `local_pref_attr` so operators can distinguish an explicit
  demotion to zero.

- **Route-server cookbooks give the FRR first-AS relaxation in the form
  that works.** Both `docs/cookbook/route-server.md` and
  `docs/cookbook/route-server-migration.md` told operators to disable
  `enforce-first-as` on the member without saying the fix must be
  per-neighbor; the global `no bgp enforce-first-as` alone is insufficient
  in FRR 10.3.1, as `docs/INTEROP.md` already recorded. Both pages now
  give `no neighbor <route-server> enforce-first-as` and describe the
  failure mode, which is silent: the member treats the updates as
  withdrawn (RFC 7606), stays Established, holds zero routes, and neither
  side logs an error.

- **`rbgp config import` no longer splits BIRD constructs that reuse block
  or statement punctuation inside an expression.** Prefix-set range
  suffixes (`[ 0.0.0.0/8{8,32}, ... ]`) were read as block braces, so one
  `define` was reported as one entry per member plus a trailing bare `]`;
  `;`-separated declaration lists (`function f (int a; int b)`, and the
  `filter f` / local-variable form) were read as statement terminators, so
  each header came back in fragments and left the following `{` reported
  with an empty stanza and a stale line number. Both shapes are ordinary
  ARouteServer-generated output, and both now produce exactly one report
  entry at the construct's own line. A `filter`/`function` header that
  arrives through the statement path is also pointed at `.rpol` rather
  than labelled an unknown structural stanza, and report entries folded
  out of a multi-line source no longer carry that source's indentation
  runs. Standalone `include` statements are reported with their source
  lines preserved in every parser context, with explicit flattening
  guidance and exit 2 alongside the translated skeleton.

- **ARouteServer renders fail stale on unsupported session semantics.**
  `rs-config-render` now exits 2 before writing output for effective
  multihop, IPv6-session RFC 8950, and active blackhole
  policy/propagation settings instead of warning and silently omitting
  them.

- **Alice-LG adapter no longer serves a fabricated preferred-route
  count.** `examples/birdwatcher-adapter` emitted a hardcoded
  `"preferred": 0` on `/protocols/bgp`, so a looking glass showed every
  member with zero preferred routes regardless of the Loc-RIB. The gRPC
  surface exposes no per-peer best count and deriving one means paging the
  whole Loc-RIB on every poll, so the field is omitted rather than served
  wrong; the README records the omission. `imported`, `filtered`, and
  `exported` are unchanged.

- **Cold-ingest fanout services readiness between outbound peers.**
  Ordinary route ingest now services the dedicated read-only readiness
  lane at peer boundaries, including mixed update-group and private-policy
  fleets, without admitting general queries or weakening stalled
  policy-transition verdicts.

- Rejected-route retention builds its bounded attribute prototype lazily
  on the first actual rejection in an UPDATE, avoiding reject-only summary
  and timestamp construction on clean permitted UPDATEs while preserving
  one shared prototype per rejected batch.

- **Release tarballs ship `rs-config-render`.** The route-server config
  renderer was built by the release workflow but never staged into
  `rustbgpd-<arch>.tar.gz` — v0.60.0 tarballs contain only `rustbgpd` and
  `rbgp`. The binary is now packed alongside them, and the tarball content
  assertion checks all three binaries for presence and non-emptiness.

- **The documented install paths install `rs-config-render`.** Every
  tarball snippet in the README, the quickstart, and `docs/deployment.md`
  extracted an archive containing three binaries and then installed two of
  them — `docs/deployment.md` contradicted its own contents listing four
  lines earlier — so an operator who followed the documented install and
  then the IXP cookbook hit `rs-config-render: command not found`. Every
  tarball and from-source path names it now, and the cookbook says the
  renderer is in the tarball rather than implying a checkout is required.
  The published container image still omits it deliberately: the refresh
  loop is a host-side cron job that runs `arouteserver` and the renderer
  next to each other and hands the daemon a finished config directory, and
  the deployment guide now says so instead of leaving the gap unexplained.

## [0.60.0] — 2026-07-18

> **Release framing — why this is v0.60.0.** This release marks the
> route-server stabilization line, a deliberate milestone jump from
> v0.51.0. Every finding from an external release review is closed and
> the flagship receipts are re-validated at this tip (reload stall
> p50 0.44–0.92 s, completion 1.50–2.12 s at 700 clients × 400,400
> routes). A differential interop lab drives BIRD 2 (configured by real
> arouteserver 1.23.2) and rustbgpd (configured by `rs-config-render`
> from the same site data) to 65/65 identical accept/reject verdicts,
> and the renderer now ingests real `template-context` output directly.
> RFC 1997 and RFC 7606 semantics are complete, the update-group
> performance arc lands end to end, jemalloc becomes the default
> allocator, and the `rustbgpd-wire` 0.15.0 / `rustbgpd-fsm` 0.3.0
> breaking cut ships in one release.

### Highlights

**Route-server correctness and policy**

- The full IXP pipeline is proven end to end: `rs-config-render`
  consumes real arouteserver 1.23.2 `template-context` output (both the
  single-YAML and sectioned-report forms, fingerprint-pinned) and the
  differential lab passes 65/65 assertions with verdict parity against
  BIRD 2 configured by the incumbent stack from the same
  `general.yml`/`clients.yml`.
- RFC 7947 control communities (do-not-announce, announce-override,
  prepend-toward-target, standard + RFC 8195 large forms) land with
  route-granular enforcement at emit, decided on the source route so
  export policy can neither leak a member-prohibited route nor
  spuriously suppress one.
- RFC 7948 §4.8 next-hop ownership enforcement (`strict_peer`) closes
  the next-hop-hijack case on shared fabrics, fail-closed across every
  decoded next-hop form.
- A member-eligibility leftover that forced entire route-server fleets
  onto serial per-member resyncs is fixed: export-policy reload
  completion 28.6 s → 0.26 s at 200 members × 115k routes.

**Performance and receipts**

- The update-group reload arc: pre-staged destination groups, one
  encode-once wire stream per group, batched cohort commits, and 25 ms
  wall-clock poll budgets throughout. Reload UPDATE stall p50
  494–652 ms and full re-advertisement completion p50 1.54–2.89 s at
  700 clients × 400,400 routes, receipts committed.
- Post-flap re-announce no longer head-of-line blocks behind initial
  table dumps: survivor completion 4.43–4.56 s → 0.32–0.33 s at
  300 peers × 300k prefixes.
- Cross-daemon IXP receipt matrix vs BIRD 3.3.1 and OpenBGPD 9.1 at
  700 peers × 400,400 prefixes, with full config disclosure and raw
  artifacts committed.

**Protocol conformance**

- RFC 7606 revised UPDATE error handling: treat-as-withdraw and
  attribute-discard dispositions, content-based §5.2 reset escalation,
  and complete §6 malformed-UPDATE diagnostics.
- RFC 1997 `NO_EXPORT`/`NO_EXPORT_SUBCONFED` honored at eBGP egress by
  default, and `NO_ADVERTISE` can no longer be bypassed or leaked by
  export policy across any family.
- Experimental Add-Path Paths-Limit (capability 76) with an
  interop receipt against FRR 10.3.1, per family, end to end.

**Observability and operations**

- gNMI dial-out streaming telemetry, a looking-glass filtered-route
  surface with canonical reject reasons (Alice-LG-ready via the
  birdwatcher adapter), policy artifact freshness metrics, slow-peer
  detection with optional update-group isolation, and first-deploy
  `rbgp doctor` environment probes.

**Packaging and crates**

- jemalloc is the default allocator (stock glibc retained reload
  transients, 301→555 MiB across cycles; jemalloc returns them).
- One breaking library cut: `rustbgpd-wire` 0.15.0 and `rustbgpd-fsm`
  0.3.0, including `#[non_exhaustive]` on registry-tracking enums so
  future registry additions land as minors.

### Added

- **`rs-config-render`: IRR/PeeringDB-driven route-server
  configuration from arouteserver data.** New standalone tool
  (`tools/rs-config-render/`) that consumes `arouteserver
  template-context` output — the fully-resolved IRR/PeeringDB/RPKI
  data model behind the incumbent IXP stack — and emits rustbgpd
  configuration: `config.toml` with transparent route-server-client
  sessions (strict next-hop ownership, per-family max-prefix ceilings,
  per-client import chains, per-client-best or Add-Path), a shared
  hygiene `.rpol` (AS_SET reject first, invalid-ASN / transit-free /
  never-via-RS terms, prefix-length windows, bogons, black-list, RPKI
  origin validation with RFC 8097 tagging), per-client IRR
  prefix/origin filters with a default-reject tail, and a refresh
  receipt. Fail-stale, never fail-open: unsupported knobs refuse
  loudly with distinct exit codes, implausibly shrunken per-client
  sets abort the render, and a context-shape fingerprint refuses
  silent upstream drift. The renderer ingests real arouteserver 1.23.2
  output directly, auto-detecting both the single YAML document and
  the sectioned per-key report 1.23.2 actually emits (normalized
  sections, hash-keyed `irrdb_info`, `!!set`-typed
  `as_set_bundle_ids`, deduped bundle union), both shapes
  fingerprint-pinned; a verbatim dump from the digest-pinned image is
  checked in, tests pin render parity between the forms and gate
  emitted output through the real `rustbgpd --check`, generated
  policies carry in-language `test` blocks from the site's own data,
  and an interop script proves the whole pipeline end to end with true
  exit codes. Docs: `docs/cookbook/route-server.md`,
  `tools/rs-config-render/README.md`.

- **arouteserver differential interop lab.** One
  `general.yml`/`clients.yml` pair drives both route servers — BIRD 2
  configured by containerized, digest-pinned arouteserver 1.23.2;
  rustbgpd by `rs-config-render` from the same site's template-context
  dump. Three GoBGP members announce a canned set spanning IRR, bogon,
  prefix-length, black-list, and never-via-RS rejections; 65/65
  assertions pass with identical accept/reject verdicts on both
  daemons, and `rbgp policy explain` names the predicted generated
  policy term for every rejection.

- **Experimental Add-Path Paths-Limit capability, with an interop
  receipt.** Per-family receiver preference via
  `add_path.receive_max`; remote tuples cap only the matching outbound
  Add-Path family, with configured/advertised/received/effective
  values in `rbgp neighbor` and its JSON. Wire format per the expired
  `draft-abraitis-idr-addpath-paths-limit-04` (IANA capability
  code 76), explicitly experimental. A hosted receipt proves it per
  family end to end against three digest-pinned FRR 10.3.1 source ASes
  and a real FRR sink: exact values at every stage, exact Adj-RIB-Out
  and independent sink counts, typed FRR capability state.

- **Route-server control communities (RFC 7947 §2.3.2 / RFC 8195).**
  Clients steer per-target distribution by tagging announcements: do
  not announce to PEER (`0:PEER` / `RS:0:PEER`), announce to no one
  (`0:RS` / `RS:0:0`) with per-target override (`RS:PEER` /
  `RS:1:PEER`), and prepend-toward-target (`RS:101|102|103:PEER`,
  `RS:10x:0`). Standard and RFC 8195 large forms compose;
  extended-community forms are deliberately not implemented. Matched
  control communities are scrubbed toward enabled sessions; everyone
  else keeps byte-level transparency. Knob: `rs_control_communities`,
  default on for `route_server_client` sessions. Enforcement is
  per-target (its own `rs_control` explain rung; Add-Path and
  per-client-best exclude suppressed candidates before ranking) and
  route-granular at emit: enabled sessions stay in shared
  update-groups, untagged routes ride the shared staged emission
  byte-identically, and only control-tagged routes diverge per target
  at the group emit seams — which is what makes the default safe
  (session-level exclusion would cost per-peer Adj-RIB-Out + encode:
  ~1.3 GiB → >100 GiB RSS at 700 full-table clients fleet-wide).

- **Route-server NEXT_HOP ownership enforcement (RFC 7948 §4.8).**
  Opt-in `next_hop_ownership = "strict_peer"` (requires
  `route_server_client = true`): an inbound unicast announcement is
  accepted only when every component of its decoded wire next-hop
  identity — classic IPv4, IPv6 global, RFC 8950 IPv4-over-IPv6,
  scoped link-local — is the advertising session's own address,
  closing the next-hop-hijack case on shared IXP fabrics. Runs before
  import policy on the immutable wire value (policy cannot launder a
  next hop), fails closed (unverified link-local companions and
  unscoped link-locals rejected; RFC 7999 BLACKHOLE is not a bypass),
  and preserves replacement semantics (a rejection replacing an
  accepted route withdraws exactly that `(prefix, path_id)`;
  first-seen rejections stay silent). Rejections log at `warn` with a
  stable `reason` token. RFC 7948 `same-AS` / `explicit-authorized`
  remain deferred.

- **RFC 7606 revised BGP UPDATE error handling** — a malformed path
  attribute no longer resets the session by default. The wire crate
  classifies every attribute error with a disposition
  (`wire::validate::ErrorDisposition`): treat-as-withdraw (ORIGIN,
  AS_PATH, NEXT_HOP, MED, communities, flag conflicts, missing
  mandatory attributes, section overruns) withdraws the UPDATE's
  routes with the session Established; attribute-discard
  (ATOMIC_AGGREGATE, AGGREGATOR, duplicates per §3 (g), eBGP-received
  LOCAL_PREF / ORIGINATOR_ID / CLUSTER_LIST) drops the attribute and
  processes the rest; session reset is retained only where the NLRI
  cannot be trusted (section-length inconsistencies,
  malformed/duplicated MP_REACH/MP_UNREACH, unparseable NLRI, the §5.2
  escalation). New `UpdateMessage::parse_revised` /
  `decode_path_attributes_revised` APIs carry the taxonomy,
  `UpdateError` gains a `disposition` field, the AS_PATH-loop and
  reflection-loop discards share the same engine, and malformations
  log at `warn`. Per-attribute table in `docs/RFC_NOTES.md`.

- **Looking-glass filtered-route surface: rejected inbound routes are
  retained with their reject reason.** Every rejected unicast
  announcement — import-policy deny (incl. RPKI/ASPA), RFC 9234 OTC
  drop, next-hop ownership, AS_PATH / RFC 4456 reflection loop,
  RFC 7606 treat-as-withdraw — is kept in a bounded per-session store
  tagged with a canonical reason token (`policy_reject`,
  `otc_route_leak`, `next_hop_ownership`, `as_path_loop`, `rr_loop`,
  `treat_as_withdraw`) plus detail, next-hop, AS path, communities,
  and RPKI/ASPA states at rejection time. New
  `PolicyService.ListRejectedRoutes` RPC (pre-v1) and `rbgp rib
  received <peer> --rejected` answer the IXP member-support question
  "why isn't my route accepted?" without knowing the prefix in
  advance. Entries self-clean on acceptance, withdrawal, and session
  reset; LRU-bounded per peer via `[policy.reject_retention]`
  (`enabled` default true, `capacity` default 1024 ≈ 0.5 MiB/peer
  worst case; restart-required), occupancy on a peer-reaped
  `bgp_rejected_routes_retained{peer}` gauge. The birdwatcher adapter
  serves the view to Alice-LG: `GET /routes/filtered/{id}`, a real
  per-neighbor `routes.filtered` count (previously a `0` sentinel),
  `reject_reason` / `reject_reason_detail`, and a synthesized
  reject-reason large community `64496:65520:<id>` (one stable id per
  reason token) matchable by Alice-LG's `[rejection]` config;
  retention-disabled and no-live-session serve an empty view. Docs:
  OPERATIONS.md runbook, route-server cookbook, CONFIGURATION.md,
  adapter README.

- **gNMI dial-out streaming telemetry.** New `[gnmi_dialout]` section:
  the daemon opens a persistent gRPC connection OUT to each configured
  collector and pushes the same `SubscribeResponse` stream a dial-in
  STREAM subscription would produce (initial snapshot,
  `sync_response`, SAMPLE ticks or ON_CHANGE events) — the
  central-sink model large fleets use. Wire contract:
  `rustbgpd.gnmi_dialout.v1.GnmiDialout/Publish`
  (`proto/rustbgpd_dialout.proto`), mirroring the de-facto vendor
  dial-out shape. Per-target TLS/mTLS (key files re-read per
  connection attempt — rotation needs no reload), capped exponential
  backoff, a `gnmi_dialout_connected{target}` 0/1 gauge (refreshed on
  both transitions, reaped on removal), dial-in-exact path validation
  at config load, and SIGHUP in-place target-set reconciliation. A
  collector being down never affects BGP operation. Docs:
  `docs/GNMI.md`, `docs/CONFIGURATION.md`, `docs/OPERATIONS.md`,
  `docs/reload-matrix.md`.

- **Policy artifact freshness metrics — alert when the filter-render
  pipeline is stuck.** `bgp_policy_generation_loaded_timestamp_seconds`
  stamps every successful full policy apply (initial load, SIGHUP
  incl. content-unchanged re-accepts, config transactions);
  `bgp_policy_dataset_loaded_timestamp_seconds{dataset}` stamps each
  external dataset's last accepted generation swap. Both deliberately
  freeze across rejected loads — acceptance, not file mtime, is the
  source of truth — so `time() - <gauge>` is a truthful staleness age
  even while a broken render keeps rewriting files. Per-dataset series
  (incl. `bgp_policy_dataset_refresh_errors_total`) are reaped when a
  dataset leaves the config. Alert expressions in `OPERATIONS.md`.

- **Slow-peer detection, optional update-group isolation, and per-peer
  fanout gauges.** An Established peer whose outbound backlog stays at
  or above `slow_peer_threshold_pct` (default 50%) of the writer
  buffer for `slow_peer_duration` seconds (default 30; 0 disables) is
  flagged slow: a `slow_peer` bool on the neighbor surface
  (`rbgp neighbor`, `NeighborState` field 36), warn logs on both
  transitions, a peer-reaped `bgp_peer_slow{peer}` gauge. Detection
  rides existing batch-granularity queue-depth seams plus a 1s
  re-check timer armed only during an episode — zero steady-state
  cost. `slow_peer_isolation = true` (default off) moves a flagged
  peer onto its own update path (ungrouped reason `slow_peer`) so it
  stops holding back the group's shared encode, regrouping
  automatically on recovery; complements RFC 9687 send-hold, modeled
  on IOS-XR Slow Peer handling. Alongside:
  `bgp_peer_outbound_queue_depth{peer}` (the "which clients are
  behind" signal, sampled at batch granularity on enqueue and drain)
  and `bgp_peer_update_group{peer}` (stable group id, `-1` =
  ungrouped), both reaped on teardown.

- **Operator UX: did-you-mean config diagnostics and first-deploy
  `rbgp doctor` probes.** A typo'd TOML key at any level renders the
  enclosing table and closest valid key(s) inside the existing
  source-excerpt diagnostic, reusing the `.rpol` frontend's
  edit-distance ranking; no-close-match keys keep serde's full
  expected-key list, secret-bearing lines stay redacted. Doctor probes
  the classic silent first-30-minutes failures: BGP listener bound
  (TCP connect when the daemon is up, test-bind/release with
  `CAP_NET_BIND_SERVICE` advice when down), per-endpoint TCP
  reachability of every RTR cache, BMP collector, and gNMI dial-out
  collector (2s each, concurrent), `runtime_state_dir` writability and
  free space (yellow < 1 GiB, red < 100 MiB), run-context detection
  (systemd/container, tailoring the `nofile` remediation), and a
  config-freshness warning for post-start edits. Daemon-down runs
  probe targets from the local config file, so doctor works before the
  first start.

- **IXP route-server receipt matrix and cross-daemon tooling.**
  `docs/perf/ixp-matrix-2026-07.md`: rustbgpd vs BIRD 3.3.1 vs
  OpenBGPD 9.1 at 700 peers × 400,400 prefixes through the shared
  reload-stall harness — reload stall + completion over two
  independent runs, flapstorm withdraw/re-announce, convergence, and
  process-tree RSS, with a scale ladder, full config disclosure, and
  raw per-cell artifacts under
  `docs/perf/artifacts/ixp-matrix-2026-07/`; cross-linked from
  `docs/RECEIPTS.md` and `docs/COMPARISON.md`. Tooling
  (`bench/scale/matrix/` + harness extensions): `reload_cmd` (reload
  via `sh -c <cmd>` instead of SIGHUP; the SIGHUP invocation is
  unchanged), `daemon_pid 0` (RSS deferred to an outer sampler),
  `--flapstorm K` (simultaneous stub closes, per-survivor percentiles
  over three rounds), addressing-compatible scenario generators for
  BIRD (`gen-bird-scenario.py`) and OpenBGPD
  (`gen-obgpd-scenario.py`) with reloadable filter/rule generations,
  and `run-matrix.sh` cell sequencing (load-gated start, per-cell RSS
  CSV, resumable status, 100 GiB RSS abort, cool-down).

- **Labeled-unicast export explain.** `rbgp rib advertised <peer>
  --prefix <cidr> --explain --labeled` (gRPC `ExplainAdvertisedRoute`,
  `labeled = true`) dry-runs the live labeled-unicast (SAFI 4,
  RFC 8277) staging body and reports the full export gate ladder —
  family, best-route selection, RFC 9494 LLGR restriction, split
  horizon, RFC 4456 reflection, RFC 1997 gates, export policy,
  advertised-state diff — matching the unicast and VPN explains.
  Labeled suppressions previously produced no reason line.

- **`interpret_rfc1997` per-neighbor / per-peer-group knob.** Controls
  the RFC 1997 `NO_EXPORT` egress enforcement (see Changed). Default
  derived: `true` unless `route_server_client = true` (route servers
  stay transparent; members enforce the community). Explicit values
  override; peers whose effective value differs never share an update
  group.

- **Independent per-family maximum-prefix limits.**
  `max_prefixes_ipv4` / `max_prefixes_ipv6` bound unique IPv4- and
  IPv6-unicast prefixes independently of the aggregate `max_prefixes`
  backstop (both enforced when both set). A per-family violation tears
  down with Cease/1 carrying the RFC 4486 AFI/SAFI/upper-bound data;
  hot-applying a limit below the current count enforces immediately.

- **Marker-backed planned-restart selection deferral.** After a valid
  restart marker is consumed, rustbgpd freezes the eligible GR
  restarting-speaker roster per family and withholds selection and
  outbound propagation until every current-session EoR arrives or the
  bounded timer expires. `NeighborState` field 31
  (`selection_deferral`) and `rbgp neighbor` expose family state;
  `bgp_selection_deferral_active`, `_waiters`, `_releases_total`,
  `_timeouts_total` expose the gate.

- **Exact-export rejection pinned against independent stacks.** A
  hosted receipt drives a legal 4,095-byte GoBGP 4.6 UPDATE through a
  sink-only route-server policy producing a 4,107-byte candidate for a
  BIRD 2.0.12 session capped at 4,096 bytes: the production exact
  encoder rejects once, withdraws the previously advertised BIRD
  route, keeps rejected state out of Adj-RIB-Out with an
  `exact_export_rejected` explanation, preserves session continuity,
  recovers on a small replacement, and converges on source withdrawal.
  Mutation proofs make the independent BIRD stale-route check and
  rejection evidence fail when the production guards are removed.

- **Planned-restart marker durability: clock-step resistance (v3) and
  an optional warm checkpoint.** On Linux 5.6+ with `CONFIG_TIME_NS`,
  startup uses a `CLOCK_BOOTTIME` deadline only when the complete
  clock domain matches exactly (valid boot ID, time-namespace
  device/inode and offsets, sampleable deadline), protecting deferral
  against discontinuous `CLOCK_REALTIME` steps between shutdown and
  startup; legacy markers, mismatches, and sampling failures use the
  wall deadline bounded by the configured maximum. Publication
  degrades atomically to complete v1/v2 markers when necessary,
  logging the visible version, checkpoint binding, and directory-sync
  durability state; runtime expiry stays process-local monotonic.
  Separately, restart-required, default-off
  `warm_cache_checkpoint_on_shutdown` captures eligible established
  static peers' post-import-policy Adj-RIB-In views into an
  owner-private, content-addressed MRT bundle under
  `<runtime_state_dir>/warm-bundle-v1`: deadline-, allocation-, and
  size-bounded, atomically binding exact live identity/config/policy
  inputs to a generation-bound restart marker, with a generationless
  fallback. Startup does not restore, select, install, or advertise
  cached routes; `forwarding_preserved` remains false.

- **TCP-AO: ordered startup keyrings, fail-closed add-only live
  rotation, and dynamic-neighbor prefix protection.** Static neighbors
  and direct dynamic-prefix selectors configure 1–256 MKTs (singleton
  tables serialize unchanged; at most one `preferred`, at least one
  non-deprecated, SendIDs/RecvIDs unique within the keyring); the
  preferred — else first non-deprecated — key is selected for startup
  transmission while every key is installed and reconciled against the
  kernel, partial installs and inventory mismatches failing closed.
  Passive opens: static exact ownership precedes dynamic
  longest-prefix-match, the kernel inventory must equal the union of
  covering protected owners, overlaps need directionally disjoint
  SendID/RecvID sets, TCP-AO/plaintext and TCP-AO/MD5 overlaps remain
  invalid, and listener inventories are capped at 4,096 MKTs per
  address family so inspection cannot truncate a valid configuration.
  SIGHUP appends non-preferred successor MKTs to unchanged owners as
  one immutable, globally preflighted generation — installed
  idempotently, verified against complete kernel inventories, fenced
  across passive accepts, retryable on partial failure — with
  secret-free generation/phase/failure state on the neighbor
  API/CLI/JSON; other key edits and protected-owner CRUD remain
  restart-required. Direct `[[dynamic_neighbors]].tcp_ao` installs
  prefix MKTs before the listener enters `listen(2)` without
  listener-wide `ao_required`; overlapping dynamic/static
  authentication boundaries and inherited MD5 are rejected, and
  protected accepts fail closed unless `TCP_AO_INFO` confirms the
  expected key IDs and clean authentication counters.

- **Unicast route pagination resumes from ordered indices and fails
  closed on mutation.** Unfiltered received, best, and private
  advertised pages clone only the requested page plus lookahead
  instead of sorting a full table; grouped advertised pages resume
  from the shared index (member-local split-horizon and
  exact-rejection filters may inspect additional rows). Opaque
  process-local continuations bind exact scope, filter semantics,
  scope-class generation, and last route key; changed scope/filters
  return `INVALID_ARGUMENT`, any same-class mutation returns `ABORTED`
  (no server-side snapshots or cursor registries). Filtered queries
  keep exact full-scan semantics. The retained comparison enforces the
  10x 400k-grouped traversal target plus p99, seed-ingest, churn, and
  resident-memory gates.

- **Narrow v1 route-server / route-reflector compatibility contract.**
  A machine-checked inventory pins only the proven IPv4/IPv6 unicast
  RS/RR config fields, native gRPC signatures and messages, CLI/JSON
  contracts, and scoped RR-only BGP-LS, VPN, labeled-unicast, and RTC
  surfaces; EVPN, dataplane, experimental, and unlisted surfaces stay
  outside v1. Compatibility and deprecation windows, the canonical
  transaction mutation path, SIGHUP reconcile limits, a release gate,
  and a consecutive v0.50.0 → v0.51.0 upgrade receipt are explicit and
  CI-pinned.

- **Neighbor state reports live transport and distribution truth,
  including authentication health.** Neighbor API/JSON/human output
  identify plaintext, TCP-MD5, and TCP-AO sessions; TCP-AO health is
  refreshed read-only from the connected socket on every query, clears
  rather than serving stale data when inspection fails, and retains
  Linux's cumulative-per-socket degraded semantics, with current/RNext
  KeyIDs and verification counters on connected AO peers. Connect
  setup failures stay in `last_error`, `rbgp doctor` flags AO peers on
  unsupported kernels, and the configuration guide documents
  directional KeyID cross-mapping. The API and CLI report the RIB's
  live effective distribution mode independently of update-group
  diagnostic labels, and Paths-Limit rows use stable numeric AFI/SAFI
  order plus an optional normalized limit — active-unlimited,
  inactive, and finite send caps render without zero-value ambiguity
  while the legacy raw sentinel is preserved for rolling clients.

- **Config plans project update-group impact before apply.** One
  deterministic schema-v1 structure: established-peer
  current/candidate groupability, exact fallback reasons, plan-local
  group IDs, transition and resync rollups, projected shared/private
  totals, and only conservative capacity classes (exact labels for
  published receipt topologies; a structural, explicitly unmeasured
  `fully_shared` label otherwise). Session reshape and future
  negotiation remain explicitly indeterminate — no memory/time
  estimate is implied. The transaction token covers the negotiated
  live-session snapshot as well as config, private fallbacks retain
  policy-content identity, and intervening session changes are
  rejected at the apply-time re-plan rather than silently changing the
  accepted impact (the token does not freeze sessions after that
  re-plan). Policy-lint integration and post-renegotiation projection
  remain future work.

- **Management-plane credentials rotate atomically on SIGHUP.** Bearer
  tokens, mTLS server identity, and client CA material behind
  unchanged configured paths are staged for every gRPC/gNMI listener
  and published as one immutable process-wide generation: new RPCs use
  the new bearer token, new TLS accepts use the new identity/CA,
  existing streams and established TLS connections survive. Invalid or
  partial material preserves the complete last-known-good generation;
  confirmed config transactions fence reload through the runtime lock;
  listener shape, paths, roles, and access policy remain
  restart-required. A bounded success/failure metric and redacted logs
  expose outcomes.

### Changed

- **Docs: operator discoverability and positioning.** New
  `docs/explain.md` catalog of every explain/introspection surface, an
  end-to-end IXP tutorial (`docs/cookbook/ixp-filter-pipeline.md`:
  arouteserver → `rs-config-render` → validated reload → Alice-LG),
  and a pre-built tarball install path ahead of building from source
  in README and QUICKSTART. COMPARISON.md gains a "Why reload behavior
  decided this market" section — the OpenBGPD route-server reload
  history and RIPE NCC funding rationale, the frr-reload.py
  blank-config failure class vs the validate-then-apply transaction
  model, and the inter-daemon config-converter vacuum, each with
  public citations, framed against the published IXP receipt matrix.

- **Docs: measurement and invariant corrections.** `docs/BENCHMARKS.md`
  memory tables refreshed with clean-build measurements — RIB
  structural memory dropped, not grew: the `RouteSlab` migration plus
  attribute interning corrects previously-overstated figures (e.g.
  Full RIB @ 500k 484.0 → 316.6 MiB real), and the `AdjRibIn`
  (1336 B) / `LocRib` (1008 B) stack sizes are confirmed against the
  current structs. `docs/gobgp-parity.md`'s Summary table is
  reconciled against its own detail tables under an explicit counting
  rule (e.g. Path attributes 13/9 → 13/11, Monitoring 5/6 → 5/9,
  Best-path steps 11/11 → 12/12). The update-group shared-encode
  safety docs (module docs + ADR) now state the correct mid-stream
  fallback invariant — per-NLRI attribute identity with the ordinary
  encode, not byte-identical chunks (message boundaries and NLRI order
  differ; skips remain impossible because fallback re-encodes the full
  envelope) — document the encoder's no-await liveness requirement at
  its two tempting yield points, and add four shared-encode regression
  tests (chunk integrity under interning, next-hop-override alignment,
  concurrent consumer streaming, wire-equivalence bounds).

- Dependency refresh: sha2 0.10 → 0.11 (digest 0.11 migration — the
  effective-config hash renders hex pairwise now), clap_mangen
  0.2 → 0.3, zeroize 1.9, uuid 1.24, regex 1.13.1, socket2 0.6.5, and
  cargo-deny-action 2.1.1 in the audit workflow. `cargo audit` clean.

- **BREAKING (library API): registry-tracking wire/fsm enums are now
  `#[non_exhaustive]`** — absorbed into the in-flight `rustbgpd-wire`
  0.15.0 / `rustbgpd-fsm` 0.3.0 breaking cut. 22 wire enums
  (`Capability`, `PathAttribute`, `Afi`, `Safi`, `Message`,
  `MessageType`, `NotificationCode`, `RouteRefreshSubtype`,
  `EvpnRoute`, `EvpnRouteKey`, `RouteDistinguisherParseError`,
  `BgpLsNlriType`, `FlowSpecComponent`, `FlowSpecAction`, `OrfType`,
  `OrfEntries`, `PmsiTunnelType`, `PmsiTunnelIdentifier`, `BgpRole`,
  `AspaValidation`, `DecodeError`, `EncodeError`) and 2 fsm enums
  (`TimerType`, `error::FsmError`) now require a wildcard arm in
  downstream exhaustive matches. This breaks such matches once, in
  this release; every future registry addition (the recurring
  `Capability::PathsLimit` shape from 0.14.x) then lands as a
  non-breaking minor instead of another major. Closed-by-construction
  enums deliberately remain exhaustively matchable: `Origin`,
  `AsPathSegment`, `Prefix`, `AddPathMode`, `OrfAction`, `OrfMatch`,
  `OrfSendReceive`, `WhenToRefresh`, `Ipv4UnicastMode`,
  `ErrorDisposition`, `RpkiValidation`, `EvpnIpPrefixValue`,
  `FlowSpecPrefix`, `VpnAddressFamily`, `VpnPrefix`,
  `LabeledAddressFamily`, and fsm `SessionState`. In-tree daemon
  fallout: every new wildcard arm fails safe (unknown message kind →
  NOTIFICATION via the FSM decode-error path; unsupported
  ROUTE-REFRESH subtype → ignored with a warning; unmodeled EVPN
  withdrawal → export error, never silently dropped; unknown timer
  kind → no slot, no expiry; unknown BGP Role → conservative upstream
  ASPA procedure and omitted from config snapshots; display surfaces
  render `unrecognized`/`unmodeled` labels).

- **`rustbgpd-wire` 0.14.1 → 0.15.0 (breaking, prepared for
  publish).** The exhaustive public `Capability` enum gains the
  experimental `PathsLimit(Vec<PathsLimitFamily>)` variant for the
  expired, archived draft-04 wire format using IANA-assigned
  capability code 76. Downstream exhaustive matches must add an arm.
  `EvpnRouteKey` also gains the additive `Ord` / `PartialOrd`
  implementations for deterministic keyed collections.

- **`rustbgpd-fsm` 0.2.0 → 0.3.0 (breaking, prepared for publish).**
  The FSM's public API now negotiates experimental family-local
  Paths-Limit state and exports `graceful_restart_preserves_family`.
  Its new fields are additive behind `#[non_exhaustive]`, but the
  public surface exposes wire types and now depends on incompatible
  `rustbgpd-wire ^0.15.0`, requiring the 0.x breaking bump. Wire must
  be published before the FSM package can be fully verified or
  published against crates.io.

- **jemalloc is now the default allocator feature.** Shipped artifacts
  (GHCR image, release tarballs) have built with jemalloc since
  v0.50.0+; defaulting the feature makes plain `cargo build --release`
  match the shipped product, so local binaries and receipts agree.
  Motivation: an 8-cycle policy-reload probe (200 peers x 115k
  prefixes) showed stock-glibc RSS ratcheting 301->555 / 295->639 MiB
  across reload cycles without returning memory — allocator arena
  retention of reload transients, live bytes flat — while jemalloc
  oscillated at 270-330 MiB and returned memory via background decay.
  Default builds also expose the `jemalloc_*`
  allocated/active/resident gauges on `/metrics`; a stock-glibc build
  remains available with `--no-default-features` (kept compiling in
  CI).

- **IXP receipt matrix refreshed with post-fix flapstorm numbers**
  (`docs/perf/ixp-matrix-2026-07.md`): all four rustbgpd cells rerun
  at the deferred-PeerUp-dump fix head — S3 re-announce p50
  9.5–9.8 s → 0.46–0.49 s, S1/S2/RSS within run-to-run spread — with a
  post-publication note documenting the plateau the receipt itself
  exposed, the head-of-line mechanism, and the rerun; committed raw
  artifacts swapped to the new runs (BIRD/OpenBGPD cells unchanged).

- **Reload UPDATE-stall receipt re-run at this tip, covering both
  reload shapes.** `docs/perf/reload-stall-2026-07.md` now measures
  the 700-client × 400,400-route scenario in both the historical
  import+export swap and the export-only change operators perform
  routinely, on the outbound size-chunking fix below. The corrected
  harness (unique re-advertised prefixes carrying the new policy
  community, no duplicate over-count) reports UPDATE stall p50
  494–652 ms across both shapes and full new-policy re-advertisement
  completion (p50/max) of 1.54–2.89 s — down from the earlier,
  since-superseded 0.76 s stall / 155 s completion headline. All 700
  clients verifiably received the full re-advertised table under the
  new policy in every run; the daemon-side scenario generator is
  committed at `bench/scale/reloadstall/gen-scenario.py`.

- **Shared export-policy transitions pre-stage their destination group
  and bound every fenced phase by a wall-clock budget.** The cohort
  transaction first prepares the prospective destination update-group
  in budgeted actor slices *without* the transition fence — ordinary
  churn keeps flowing between slices, and the all-groups staging pass
  keeps the prepared table live — so the transition finds it
  `Maintained` and skips the fenced full-table staging walk, halving
  the reload wall during which interleaved churn stalls (700 members x
  400,400 routes, mixed export-only reload under churn: fenced wall
  0.95 s -> 0.45 s, per-observer max inter-UPDATE gap p50 ~1.0 s ->
  ~0.53-0.64 s). Preparation is best-effort with fallback to ordinary
  fenced staging; superseded or abandoned preparations are discarded
  so an orphaned staged table cannot keep consuming per-churn work,
  and partially staged leftovers are rejected by table-length
  validation. The exact-export probe reuses one result per probe shape
  per batch instead of a single-entry UPDATE per route, and the
  strict-cohort ceiling proof reads a store-time maximum instead of
  rescanning per member (quadratic at fleet scale: ~200 ms of fenced
  wall at 700 x 400k) — the fenced probe phase drops ~40% at the
  receipt shape. Every pre-commit phase (member classification,
  destination staging, inventory build, exact-export probe) strides
  under the same 25 ms wall-clock poll budget as the commit flush
  instead of parking after one fixed slice per poll, so the fenced
  window no longer scales with members x table size (previously ~391
  single-slice probe polls at 400k routes — a measured ~1.1 s observer
  gap at 700 members).

- **Import+export reloads now take the batched export cohort instead
  of the per-peer authoritative path.** Cohort eligibility no longer
  requires an unchanged import chain: a changed import chain is
  hot-applied during cohort setup and its inbound Route Refresh
  deferred until the batched RIB commit acknowledges (once per member;
  unchanged-import members get no refresh); on cohort failure the
  rollback restores both chains and re-arms the per-peer retry intent.
  Previously any import-chain change disqualified every peer, so a
  routine import+export reload on a large fleet serialized N
  full-table export restages and Route Refreshes instead of sharing
  one batched transition.

- **Grouped policy-reload re-advertisement encodes each update-group's
  wire UPDATE stream once instead of once per member.** The clean
  export-policy transition hands every member envelope one encode-once
  cell: the first consuming session task encodes the shared inventory
  into per-source-peer, per-family chunks at the standard 4096-byte
  ceiling, and every other member reuses the bytes after proving its
  export profile wire-identical to the encoder's. Split horizon
  composes from whole chunks (a member sends all but its own
  source's), fewer-family members skip chunks, and any anomaly —
  profile mismatch, preparation failure, OTC hit, oversize entry —
  falls back to the unchanged per-session encode. This removes the N×
  duplicate encode that delayed every observer's first post-reload
  UPDATE by the full-table encode time. Publication is progressive:
  chunks publish per slice as produced and members send them as they
  arrive, so an observer's longest wire silence tracks per-slice
  encode latency (single-digit milliseconds); a stream that fails
  mid-way terminates explicitly (drop-guarded against encoder unwind)
  and members fall back to the local encode, whose byte-identical
  re-announcements are idempotent.

- **Grouped export-policy transitions commit in bounded member batches
  under a wall-clock budget.** The former single finalization poll —
  one synchronous actor poll holding the whole per-peer commit/flush
  loop — is now a `Validate` poll (the last that can fall back)
  followed by `CommitMembers` polls that flush validated members under
  a 25 ms wall-clock budget (initially a fixed eight per batch),
  yielding to the dedicated readiness lane between batches, mid-flush
  seam bounded well under the 200 ms readiness deadline. At internet
  scale (1M routes / 500 peers / 300 changed) the old loop blocked the
  actor 1.6–2.4 s and depooled `/readyz`; the stall is
  peer-fleet-driven and volume-flat, so the bound is keyed on members,
  not routes (a fixed-count poll still cost ~0.88 s of staggered first
  emission at 700 members). Commit reply position, terminal retry
  pass, fallback-implies-nothing-emitted contract, and the 30-second
  stalled verdict are unchanged; the poll histogram gains a `commit`
  kind.

- **Dirty-peer resync is bounded per tick, budget-driven, and
  round-robin.** A resync-timer tick used to hand every dirty peer to
  one synchronous `distribute_changes` pass at O(table) each; ticks
  now drain the backlog under the same 25 ms wall-clock budget as
  commit flushes (via an interim 8-peers-per-10 ms bound), selecting
  peers round-robin so a peer whose sends keep failing cannot
  monopolize ticks while drainable peers starve. Partial passes are
  safe because per-peer resync is idempotent — Adj-RIB-Out state and
  the dirty flag commit only after a successful send. Recovery
  throughput under backpressure no longer scales inversely with fleet
  size; each peer is attempted at most once per tick, failed peers
  wait for the ordinary retry interval.

- **RFC 1997 `NO_EXPORT`/`NO_EXPORT_SUBCONFED` are now honored at eBGP
  egress by default.** Routes received with either community are
  suppressed at export staging toward eBGP peers across unicast (incl.
  RFC 8950 next-hop forms), VPNv4/VPNv6, labeled-unicast, RTC, and
  BGP-LS — the same family set as the existing `NO_ADVERTISE`
  enforcement. The check is source-route-only: export policy that adds
  `NO_EXPORT` still delivers the route (the route-server action idiom,
  also used by the RFC 9494 §4.6 LLGR form), and policy that removes
  it cannot bypass the suppression. iBGP targets (incl. RR
  reflection/ORR) are never suppressed; a received `NO_EXPORT` now
  outranks RFC 9494 LLGR eligibility toward eBGP peers; route-server
  clients stay transparent by default via `interpret_rfc1997`. The
  export-explain ladder gains a stable `no_export` rung beside
  `no_advertise`.

- **Durable event-history conversion and encoding moved off the RIB
  actor.** With `[event_history]` enabled, route-event publication
  hands the owned snapshot (producer-captured `timestamp_ns`,
  already-assigned `event_id`) to a bounded FIFO channel; proto
  conversion, prost encoding, and envelope construction run in a
  dedicated conversion stage in front of the event outbox. Payload
  bytes, publish order, cursor contiguity, producer timestamps, drop
  counters, degraded-state semantics, and the legacy ring/broadcast
  surfaces are unchanged; overload sheds before conversion instead of
  after, and the stage drains pre-shutdown snapshots so they still
  commit. Manager-side publish cost with durable history drops by
  roughly an order of magnitude
  (`docs/perf/event-history-producer-2026-07.md`).

- **Policy rollback has one aggregate RIB wait budget.** Authoritative
  self-heal and a subsequent cohort unwind share one lazy absolute
  five-second deadline instead of up to five seconds per peer; every
  reverse-order RIB restore is registered before rollback Route
  Refresh or later lifecycle work, and timeout/cancellation retain the
  same pinned late repairs with conservative pending flags preserving
  retry intent. The bound covers cumulative rollback RIB send/reply
  waiting — not sequential session commands, Route Refresh
  acknowledgements, or late RIB repair.

- **Mixed policy reloads batch their eligible export-only cohort.**
  Snapshot application selects the first equivalent Established
  export-only cohort in configuration order, commits it through one
  shared RIB transition, then preserves the original order for the
  authoritative remainder; duplicate targets disable partitioning
  wholesale, failures roll back newest-first surfacing composed
  errors, and a successful shared transition performs the same global
  dirty-resync opportunity as the authoritative seam. The reload-stall
  harness can independently gate changed-observer completion while
  retaining full-fleet delivery-gap and session checks. Corrected
  700-session / 400,400-route mixed campaign (600 changed,
  100 stable): median completion p50 improves 116.185x and median
  completion maximum 149.261x across four reloads, 700/700 sessions,
  100/100 fresh stable markers, zero parser errors. Not an
  unconditional stall win: median full-fleet gap p50 regresses 2.070x
  to 2022.590 ms and maximum 2.899x to 2906.551 ms, so chunked member
  resync remains required. Raw receipt under
  `docs/perf/artifacts/policy-reload-cohort-partition-2026-07/`.

- **IXP route-server clients share exact-export work across remote
  ASNs.** The immutable session export profile retains the
  wire-relevant eBGP/iBGP classification instead of negotiated
  remote-AS identity; every other wire input still participates in
  full profile equality, and each target still rechecks its own
  message ceiling and generation. Byte-level tests prove distinct eBGP
  ASNs encode identically while eBGP and iBGP remain incompatible,
  including when dynamic peers negotiate away from a configured ASN
  wildcard. Pinned fixture: 4,096-route policy transitions across 700
  distinct-ASN clients collapse from 2,867,200 to 4,096 full exact
  probes (510.332 ms → 7.604 ms); 64-route first-advertise fanout
  improves 47%..65% at 8..256 clients with no homogeneous regression;
  the 64-client homogeneous transition cell has no detected change
  while its distinct-ASN counterpart improves 93.00%.

- **Large uniform export-policy transitions stay observable while they
  converge, without hiding live export-policy counters.** Clean
  grouped-to-grouped unicast cohorts reuse one immutable transition
  inventory and exact-probe plan; staging, inventory, and probe bodies
  process at most 1,024 route identities per poll, while the Loc-RIB
  prefix snapshot and destination-key inventory snapshot remain two
  explicit, measured O(table) actor polls. Live readiness uses
  dedicated type-narrow PeerManager and RIB lanes; general RIB queries
  stay queued with ordinary mutations behind the transaction instead
  of extending its fence (later readiness can overtake queued general
  queries; an already-running O(table) query is non-preemptible), and
  membership plus reserved writer sends still commit as one
  synchronous section. The process-global
  `bgp_rib_policy_transition_in_progress` and terminal-duration
  gauges, an actor-poll histogram split across bounded work / table
  snapshots / finalization, a five-second warning, and a shipped
  one-minute alert make slow transitions visible; readiness stays
  healthy during legitimate bounded progress but fails closed at 30
  seconds of ownership, recovering at a terminal actor seam. An
  enqueued cohort RIB reply remains transaction-owned past the
  ordinary five-second per-peer timeout, preventing a forward/rollback
  race. Pinned 65,536-route/64-peer and 4,096-route/700-peer receipts:
  largest production actor poll 4.927 ms, 700-member atomic
  finalization 2.001 ms, both under the 50 ms budget; paused-clock
  regressions complete in-flight readiness probes with zero 200 ms
  timeouts, even while one session policy command is independently
  stalled. Every grouped membership path — optimized commit,
  authoritative fallback/recompute, rollback — installs the exact
  destination-group policy-chain counter instance for every member, so
  `rbgp policy stats` exposes the same staged evaluations for the
  whole group and keeps advancing as later routes arrive.

- **Authoritative export-policy fallbacks no longer multiply one RIB
  actor stall by peer count.** An ineligible or invalidated clean
  transition returns a typed, fail-closed handoff after releasing
  writer permits and removing every uncommitted destination;
  PeerManager applies one ordinary RIB replacement at a time, keeps
  readiness live while awaiting each five-second reply, and preserves
  newest-first session/RIB rollback without a second session
  hot-apply. A 65,536-route stop-gate receipt records 104.25 ms for
  one peer; a 64-peer reference retains ~4.29 s of total RIB work
  split into individual operations (first warm-up maximum 108.819 ms).

- **Clean update-group exact precommit avoids unused per-peer
  bookkeeping.** Grouped members whose exact probes all succeed no
  longer rebuild candidate keys or walk and allocate the group's prior
  advertised set; that work defers to the rejection/overlay fallback
  that needs it. Per-target wire ceiling and generation checks remain
  mandatory; resync, regroup, VPN/mixed-family, malformed, rejected,
  and non-shared paths keep the full reconciliation path. A pinned
  two-attempt Criterion matrix improves 64/256-peer fanout 32%..36%
  with no one-peer regression; the sealed 16-cell manager flood/churn
  matrix improves 197%..649%. Exact inputs, counterbalancing,
  preflights, confidence gates, and checksummed artifacts are retained
  in the performance receipt.

- **Update-group correctness has a parameterized fixed-scenario
  differential corpus.** The grouped manager path and forced-per-peer
  oracle are compared with explicit exact-stream or normalized
  semantic-effect plus folded-state semantics across bounded channel
  saturation and virtual-time retry, repeated policy regroup while
  dirty, stale session generations, and RT-Constrain membership churn;
  every path must emit non-empty traffic, deliver a terminal sentinel,
  finish its manager task, and clear dirty/force/regroup/residue
  state. A hard-capped 24-seed extension runs weekly and by manual
  dispatch on GitHub-hosted runners; seeds vary fixture identities,
  not schedule order or length, and validated seed-start, seed-count,
  and max-operation controls replay an individual failure without an
  unbounded run.

### Fixed

- **RFC 7606 §5.2 and §6: the reset escalation is content-based and
  the malformed-UPDATE diagnostics are complete.** The "no reachable
  NLRI" escalation gate tested MP_REACH attribute *presence*, not
  content — an UPDATE carrying a structurally valid MP_REACH with zero
  NLRI plus a treat-as-withdraw-class error stayed Established via the
  treat-as-withdraw arm, which had nothing to withdraw. The gate now
  inspects the parsed MP_REACH payload across every family's announced
  vector; the attribute validator keeps its presence-based
  mandatory-attribute semantics, and an MP_REACH that does carry NLRI
  still takes treat-as-withdraw (no over-reset). Per the §5.2
  debugging guidance, malformed UPDATEs are dumped at DEBUG: the
  ENTIRE message as hex — untruncated, since message size is
  protocol-bounded (4096 bytes, or 65535 with Extended Messages;
  initially capped at 512 bytes per section) — with the involved NLRI
  enumerated explicitly (prefixes with Add-Path path IDs, per family,
  announcements and withdrawals), rendered from what the revised parse
  already produced. Still DEBUG-gated and lazily built (clean path and
  log-spam posture unchanged); routing dispositions untouched; the
  rejected-route retention store keeps its separate byte caps.

- **Interop: an FRR zebra startup race pinned out of two hosted
  labs.** On a loaded runner FRR can send its initial IPv6 UPDATE
  before zebra reports a global address on the peering interface; the
  link-local-only MP_REACH next hop is rightly rejected
  (treat-as-withdraw) and FRR never re-advertises, starving the proofs
  for the whole convergence window. Explicit outbound route-maps now
  set the IPv6 global next hop on the FRR sources, removing the
  interface-address timing dependency.

- **Rejected-route retention now enforces its per-entry byte budget.**
  The store was bounded in entry count (LRU, 1024/peer) but each entry
  retained unbounded wire-derived data — a hostile peer with a maximal
  AS_PATH and community lists (worse under RFC 8654 Extended Messages)
  could push entries to multiple KB across hundreds of peers,
  default-on. Entries are now truncated at capture time: AS-path and
  detail strings capped (96 / 64 bytes, `…` marker), community
  vectors capped (16 standard / 8 large) with dropped counts surfaced
  (`communities_dropped` / `large_communities_dropped` in
  `ListRejectedRoutes` and the CLI JSON) so renderers can say "…and N
  more". The documented ≤ 512 B/entry ⇒ ~0.5 MiB/peer bound is now an
  enforced fact, pinned by a size-budget test against the real type
  sizes; one bounded attribute summary is built per UPDATE and shared
  across every rejected identity, replacing the per-identity re-render
  and deep-clone of the full attribute set.

- **Post-flap re-announce latency: initial table dumps no longer
  head-of-line block redistribution.** A peer's outbound registration
  at `PeerUp` ran its full-table initial dump synchronously on the RIB
  actor, so a mass reconnect (e.g. 50 route-server members after a
  flap) serialized N full-table passes ahead of the re-announcements
  queued behind the burst — survivors saw the flapped prefixes only
  after the last dump finished (~9.5 s flat at the 700x400k receipt
  shape, scaling with peers x table). When the actor has queued work,
  the registration (and dump) now defers to the run loop, one per
  iteration strictly after every queued mutation batch drains, so
  imports and their fan-out always preempt reconnecting peers'
  catch-up; a quiet actor or a sub-10k-route table (sub-10-ms dump)
  still registers inline. Session-semantic flags (eBGP / RR-client /
  RFC 9234 role / per-client-best / RFC 1997 interpretation) always
  install immediately at `PeerUp`, so inbound processing never runs
  with absent flags; a session that drops, is superseded, or fails
  over while deferred resolves to its surviving live session,
  including the inbound ROUTE-REFRESH re-solicitation on failover.
  GR/LLGR stale retention, EoR emission, RFC 4724 selection deferral,
  and the RFC 5291 ORF gate are unchanged. Local flapstorm at
  300 peers x 300k prefixes, 30 flapped: survivor re-announce
  completion 4.43-4.56 s -> 0.32-0.33 s (first arrival 4.24-4.40 s ->
  0.17 s), withdraws unchanged at ~0.15 s; the flapstorm harness now
  also reports per-survivor first re-announce arrival
  (`first_reann_s`), separating delivery-start latency from fan-out
  completion.

- **gNMI dial-out: a subscription error no longer strands the session
  on a silent collector.** When the local subscription ended
  mid-session (e.g. ON_CHANGE broadcast lag closing the stream with
  `DataLoss`), the client ended its outbound stream but kept waiting
  on the collector's response stream — and the proto reserves
  `PublishResponse` for future flow control, so a compliant collector
  may never send anything and never close. The session hung forever,
  the promised fresh-snapshot resync never happened, and
  `gnmi_dialout_connected{target}` stayed at 1. Outbound-stream
  completion is now a first-class disconnect signal: the session
  returns to the reconnect loop immediately and resyncs from a fresh
  initial snapshot + `sync_response`.

- **Grouped route-server control decisions are now made on the source
  route, matching the ungrouped path.** The update-groups emission
  path evaluated RFC 7947 control communities on the
  post-export-policy route, so a policy that stripped a control
  community could leak a route the source member prohibited, and
  policy-added control communities could spuriously suppress or
  prepend. Suppression and prepend are now decided from the source
  route's communities captured at staging time; the egress scrub still
  runs post-policy so policy-added control forms are removed without
  acting. Tag-only transitions (policy strips or adds the tag while
  the route is otherwise unchanged) now emit the exact per-member
  withdraw / re-announce delta instead of being equality-suppressed.

- **Route-server fleets take the shared clean export-policy transition
  again — a ~150× reload-completion regression fixed.** The shared
  transition's member-eligibility check blanket-excluded every
  `rs_control_communities` session, a leftover from when the knob was
  opt-in; with it defaulting on for `route_server_client` neighbors,
  an entire IXP fleet fell back to serial per-member full-table
  resyncs on every export-policy reload (200 members × 115k routes:
  ~28.6 s vs 0.22 s with the knob off; ~4.5 min at 700 × 400k). The
  transition's single inventory walk now proves the diff carries no
  RFC 7947 control-form community for the cohort's RS ASNs — checking
  the post-policy routes AND the captured source communities on both
  sides, so a policy that strips or adds a control tag still rejects
  the optimized plan — and untagged inventories (the overwhelming
  case) let rs-control members ride the shared cohort and shared
  encode exactly like ordinary members; tagged inventories keep the
  whole cohort on the authoritative per-peer path, whose emit seams
  apply the per-target suppression/prepend/scrub.

- **Cohort transition edge cases: pre-staging joins and acked-import
  repair windows.** A peer whose (attributes, policy) key equaled a
  mid-walk prestaged destination could join the partially staged group
  through any ordinary membership seam, replay the partial table as
  its initial view, and have the remaining staging slices' deltas
  discarded — routes recorded as advertised but never emitted, with no
  later heal. The join now drops the prestage (the held prepare reply
  resolves as skipped) and rebuilds the group on the ordinary path;
  discards are also exact — the preparation records the group id it
  actually staged, and both an explicit discard and a cohort commit
  that resolved elsewhere remove that recorded group instead of
  re-deriving one that could drift and leak a staged, memberless
  group. Separately, a cohort export hot-apply failure on a member
  whose import delta was already acknowledged now reconciles the
  acked-import window after reasserting the prior import chain: routes
  accepted under the new chain in that window get a Route Refresh when
  Established, or arm `pending_refresh` for the retry pipeline;
  previously a successful inline repair left the window unreconciled.

- **Parse and runtime diagnostics no longer echo credential
  material.** When a TOML error's snippet line — or the line before
  it, for unterminated-quote spans — mentions `md5_password` or TCP-AO
  key material, the diagnostic replaces the source line with a
  redaction placeholder and collapses the caret run (whose width would
  reveal the secret's length), keeping the file/line/column pointer;
  this covers the SIGHUP reload log, daemon stderr, and the
  `DiffRuntimeConfig`/`PlanConfigTransaction` gRPC statuses in one
  place. Typo'd secret keys rejected by unknown-field validation
  (`md5password`, `tcpao`) are caught by a normalized key-prefix check,
  and an error inside a multi-line string walks back to the string's
  opening line so a secret below `md5_password = """` is redacted too;
  ordinary lines, including non-secret unknown fields, keep the full
  snippet. The runtime snapshot token drops its config-rendering
  byte-length component (the rendering includes plaintext secrets)
  while staying a process-local equality token under the same keyed
  digest, and `Neighbor`, `PeerGroupConfig`, and
  `RuntimeConfigSnapshotReply` gain manual `Debug` impls that redact
  `md5_password` and the runtime TOML.

- **Authentication secrets are zeroized, compared in constant time,
  and reloaded under a lock.** TCP-AO MKT secrets and TCP-MD5
  passwords use an immutable redacting wrapper across the internal
  API, peer manager, and transport runtime, so each clone scrubs its
  own allocation when replaced or dropped; the Linux `tcp_md5sig`
  temporary scrubs its key buffer and length after every socket-option
  attempt (TOML parser, config snapshot, protobuf, compiler-created,
  and kernel copies retain separate lifetimes); management-plane
  credential reads (bearer token, TLS private key) and retired
  `BearerAuthSecret` generations are zeroized on drop.
  `TransportAuthSecret` equality is constant-time — the derived
  `PartialEq` had an early-out; the manual impl's timing depends only
  on the longer input's length (current callers only diff config
  against config: a hardened footgun, not an exploitable path).
  `CredentialStore::reload` serializes its sequence increment and
  generation publish behind a reload lock so concurrent reloads cannot
  mint duplicate sequences or publish out of order. The queued-child
  kernel receipt now also exercises a dynamic `127.0.0.0/24` owner and
  proves its successor installs on the accepted child without changing
  Current/RNext or authenticated traffic.

- **RFC 1997 `NO_ADVERTISE` can no longer be bypassed or leaked by
  export policy, and policy-added suppressions are observable.**
  IPv4/IPv6 unicast, VPNv4/VPNv6, labeled-unicast, RTC, and BGP-LS
  SAFI 71/72 check both the stored source route before export policy
  and the modified route after policy across their supported export
  shapes (unicast incl. grouped/private, RFC 7947 per-client-best,
  RFC 9107 ORR; VPN incl. grouped/private; labeled-unicast incl. ORR):
  policy cannot remove the community to make a scoped route
  exportable, and a policy-added community suppresses the route before
  Adj-RIB-Out commit. Scoped replacements withdraw existing state,
  candidate modes compact surviving siblings, ORR suppresses its
  selected winner without falling back; terminal export explain
  reports the suppression (and, for a post-policy stop, the triggering
  modification) for unicast and VPN, and unicast Add-Path best-path
  explain mirrors the compacted advertised ranks. The single-best and
  ORR single-best staging tails previously withheld a
  policy-added-NO_ADVERTISE route with no filtered-routes entry or
  `policy_filtered` event; both tails now record the suppression like
  the policy-deny arm, and policy-added NO_ADVERTISE on a multipath
  (Add-Path) candidate likewise surfaces through the same live
  policy-filtered observability, where previously only export explain
  covered it.

- **Closed outbound channels no longer re-mark peers dirty for resync,
  so shutdown quiesces instead of livelocking.** The outbound send
  path treated a closed per-peer channel (session gone) like a full
  one (peer slow): both re-marked the peer dirty, and the bounded
  dirty-resync tick retried the dead channel forever — at scale each
  tick's export pass outlasted the 10 ms backlog re-arm, so the RIB
  actor never returned to its event loop to observe shutdown, spinning
  at full CPU after SIGTERM until killed externally.
  `mark_outbound_dirty` — the single dirty-insertion seam — now drops
  a peer's dirty state when its channel is closed or deregistered, and
  the resync tick prunes closed-channel peers before selecting its
  slice, so a dead backlog quiesces in one tick and the timer disarms.
  Full session teardown remains with the `PeerDown` path.

- **`/readyz` treats the 200 ms core-readiness deadline as a hard
  bound on the HTTP response.** A runtime stall (such as the
  post-commit outbound flush) could hold the probe past the deadline
  and then complete it, and the queued actor reply was polled before
  the expired probe timer — a late 200 that silently violated the
  readiness contract. The handler now wraps the probe in the deadline
  and rejects a late success, answering `503 not ready: readiness
  probe deadline exceeded`; the fast-503 daemon-gate path is
  unchanged.

- **Shutdown paths can no longer wedge, spin, or lose their
  checkpoint.** GR restart marker publication, its generationless
  fallback, and marker removal at coordinated shutdown run on a
  detached writer thread under a 5-second terminal deadline, so a hung
  filesystem cannot stall daemon exit; warm-bundle entry verification
  treats an entry grown by a same-UID writer mid-read as a typed
  mismatch instead of panicking; and a cleanup pass over a bundle
  directory holding more than 65,536 candidates removes the first
  cap-worth in deterministic name order before reporting the over-cap
  error, so the directory shrinks on every pass instead of failing
  unchanged forever. Peer sessions drain with fixed cross-peer
  concurrency while preserving pending-before-primary ordering and
  each session's timeout/abort/reap guarantees, so a backpressured
  fleet cannot multiply the per-session deadline into a multi-minute
  shutdown. Warm checkpoints retain one committed snapshot: only after
  the `manifest.json` rename and directory fsync establish the commit
  point does publication remove superseded content-addressed snapshots
  and crash-leaked temporaries, continuing past entry-local unlink
  failures and preserving the primary error when rollback also fails;
  startup performs the same bounded descriptor-relative scavenging
  without opening or adopting route snapshots (absent manifests permit
  orphan cleanup, valid byte-stable manifests protect their selection,
  invalid or changed manifests delete nothing), and cleanup failure
  cannot delete the current snapshot or disable later publication.
  Concurrent daemons must use distinct `runtime_state_dir` values.

- **Planned-restart selection deferral: teardown, failback gating,
  release accounting, clock-step bounds, and a bounded identity
  ledger.** Deleting a GR neighbor mid-deferral removes its waiters
  from the frozen roster, so the family releases when the remaining
  waiters satisfy instead of freezing selection until timer expiry.
  Collision failback applies the same OPEN gating as ordinary
  classification: a Restart-State, non-GR, or plain-refresh (no
  RFC 7313) survivor is excluded instead of parked in an unfulfillable
  `awaiting_refresh` that convergence-holds the family; with Enhanced
  Route Refresh negotiated, the exact nonzero, unambiguous survivor
  enters `awaiting_refresh` — the current Loc-RIB stages as soon as
  ordinary waiters finish, but downstream EoR and route-refresh
  responses stay held until a post-failback BoRR/EoRR cycle completes
  (ordinary EoR, stray EoRR, and the local refresh timeout cannot
  release the hold; the marker-bounded selection timer is the
  fallback), and a plain-refresh peer whose deferred route-refresh
  response is delivered at release no longer gets a second
  empty-UPDATE End-of-RIB after the genuine convergence EoR. Release
  accounting: a family gate completing with zero completion markers
  consumed records `all_excluded` instead of `all_eor`; simultaneous
  identity-and-byte ledger exhaustion records
  `identities_and_logical_bytes`. Marker-backed startup clamps the
  persisted marker's remaining lifetime to the maximum effective
  `gr_restart_time`, so a wall-clock correction cannot extend
  restarting-speaker signaling or selection deferral; expired or
  nonpositive-window markers cold-start immediately. The ledger is
  bounded: at most one million affected route identities across all
  gated families plus an independent 64 MiB process-wide ceiling on
  deterministic logical retained-key data (incl. nested FlowSpec terms
  and BGP-LS payload bytes — not RSS or allocator overhead); exceeding
  either sends that family into overflow fallback, where release
  performs a complete Adj-RIB-In + Loc-RIB sweep so pre-EoR
  withdrawals cannot leave stale routes, exposed by a one-shot warning
  and `bgp_selection_deferral_ledger_overflows_total{afi_safi}`.

- **Hot-applied export-affecting knobs re-probe suppressed routes.** A
  SIGHUP reload that hot-applies `local_ipv6_nexthop` or
  `remove_private_as` to a live session issues a forced outbound
  refresh (like the graceful-shutdown toggle and live policy apply),
  so routes the exact-export preflight suppressed under the old knobs
  go back on the wire immediately — and already-advertised AS_PATHs
  re-encode — instead of waiting for unrelated churn or a session
  bounce. Export-inert hot applies issue no refresh.

- **Paths-Limit state survives collision failback and resists foreign
  families.** The RIB's live-session record carries the per-family
  Add-Path Paths-Limit map and restores it when an outbound
  registration fails over to a surviving session, instead of clamping
  every family to the scalar send limit; received limits outside the
  peer's negotiated Add-Path send families are ignored, so they cannot
  activate Add-Path for another family or trigger an initial-table
  replay.

- **Exact-export and outbound transport failures fail closed before
  Adj-RIB-Out commit.** Every route-bearing envelope carries one
  immutable snapshot of the session's exact encoder and negotiated
  message ceiling; the RIB probes the final one-route wire form for
  all supported families after policy and next-hop preparation, so a
  rejected announcement is never recorded as advertised and a route
  that becomes unexportable is withdrawn. Update-group members retain
  the shared staged table with a sparse per-member rejection overlay,
  so 4096-byte and Extended Message peers share policy work without
  sharing an incorrect advertised view; rejections are logged once per
  transition, counted by
  `bgp_exact_export_rejections_total{peer,family,reason}`, retried on
  a later accepted recompute or resync, and retired by an ordinary
  source withdraw without a duplicate wire withdrawal. The transport's
  Cease/8 overflow teardown remains a defense against invariant
  violations, not the primary correctness mechanism: a single EVPN
  announcement or withdrawal that cannot fit the negotiated ceiling
  now invokes that teardown so an Established stream cannot survive
  with logical Adj-RIB-Out ahead of the wire, and the post-commit IPv6
  no-next-hop and Extended-Next-Hop IPv4 preparation arms tear down
  with Cease/Out-of-Resources like the oversize branches instead of
  silently dropping the route (both arms unreachable while producers
  run the preflight). IPv6-unicast and FlowSpec Extended Message
  batches start with a bounded 1,024-entry probe and grow through
  exactly built candidates up to a 4,096-entry ceiling, remembering
  successful and failed bounds without losing, duplicating, or
  reordering NLRI; the transport's defense-only RFC 9234 OTC gate is
  test-pinned as family-neutral for IPv4 and IPv6.

- **Outbound unicast and FlowSpec UPDATEs are split by encoded message
  size.** A same-attribute Adj-RIB-Out group larger than one BGP
  message (≈1000 /24s ≈ 4114 bytes against the 4096-byte limit) was
  built as a single UPDATE; the transport rejected it with
  `MessageTooLong` and abandoned the rest of the batch — but never
  reported the partial delivery back across the RIB/session boundary,
  so the RIB kept believing the whole group was advertised, leaving
  peers silently under-advertised with no dirty-resync recovery
  (sharpest after a changed-policy reload, where every route is
  re-advertised at once). IPv4 body/MP_REACH, IPv4 MP_UNREACH, IPv6
  MP_REACH/MP_UNREACH, and IPv4/IPv6 FlowSpec MP_REACH/MP_UNREACH now
  chunk to the negotiated maximum message size, using bounded, exactly
  encoded probes that can grow beyond 1,024 entries when Extended
  Messages are negotiated. FlowSpec uses fallible structured encoding
  throughout, and its RIB and withdrawal identity now carries AFI
  explicitly, so destination-less IPv4 and IPv6 rules coexist and
  withdraw independently. A lone entry that still cannot fit tears the
  session down so Adj-RIB-Out is rebuilt on reconnect, rather than
  falsely reporting the route advertised.

- **RFC 9234 OTC suppression precedes Adj-RIB-Out commit.** IPv4/IPv6
  unicast routes carrying OTC toward a Provider, Peer, or Route Server
  are rejected while staging grouped and private export views,
  including ORR, Add-Path, and per-client-best: a newly blocked route
  is never recorded as advertised, and a route that becomes blocked
  generates a withdrawal and leaves logical advertised state.
  Session-stamped local roles separate update groups from the initial
  table onward, export explain reports the same OTC gate, and the
  existing counter/event diagnostics remain emitted without relying on
  a transport-only wire drop.

- **Pre-policy and import-policy rejections withdraw prior accepted
  paths.** OTC rejects retire exact accepted unicast
  `(prefix, path_id)` identities; AS_PATH-loop and reflection-loop
  rejects also retire exact VPN, labeled-unicast, RTC, and BGP-LS
  identities. Import-policy-denied replacements do the same across
  every family — unicast `(prefix, path_id)`, VPNv4/VPNv6
  `(RD + prefix, path_id)`, labeled-unicast `(prefix, path_id)`, RTC
  `(NLRI, path_id)`, BGP-LS `(family, NLRI, path_id)` — with the
  removal reaching the RIB immediately. First-seen rejections/denials
  remain filter-only, explicit withdrawals are deduplicated, and
  Add-Path siblings stay intact.

- **Enhanced-refresh omissions no longer poison max-prefix
  accounting.** Inbound RFC 7313 windows mirror exact typed route
  identities across every counted family, retire replayed or withdrawn
  identities only after ordered RIB acceptance, and reconcile omitted
  routes at `EoRR` or the shared timeout; timeout closure is ordered
  ahead of later buffered UPDATEs, remains safe under RIB backpressure
  or shutdown, and runs for quiet peers. GR peers cannot open a family
  refresh window before that family's initial End-of-RIB.

- **TCP-AO passive accepts survive an add-only listener generation
  flip.** Linux does not copy newly added listener MKTs into children
  already completed in the accept queue; rustbgpd now recognizes only
  the exact immediately previous inventory, adds the missing successor
  suffix while it still exclusively owns the child, verifies the exact
  current inventory, and stamps the current generation — partial
  inventories, out-of-fence generations, and failed repairs remain
  fail-closed. The hosted kernel receipt deterministically exercises
  the queued-child race, and a live SIGHUP successor rotation is
  proven against BIRD 3.3.1 without a session flap.

- **The v1 stable-surface gates close their coverage gaps.**
  Contextual defaults: the dynamic-neighbor cap and
  address-/inheritance-dependent family set join the resolver checks,
  with schema omission representations distinguished from runtime
  values and `PeerManager` pinned to the shared cap resolver. Release
  cadence: patch and major releases are supported — upgrade exercises
  remain a contiguous, fail-closed chain of adjacent release lines,
  the latest targeting `vMAJOR.MINOR.0`, with the exact workspace
  patch version pinned separately. Config shape: stable definition
  digests cover the complete required-field set and unknown-field
  policy in addition to selected property schemas, while still
  allowing unselected optional sibling fields and descriptive-prose
  changes. CLI: the inventory covers the complete `rbgp diff` command
  tree and every shipped ribsnap producer — BIRD, FRR, GoBGP, MRT, and
  BMP byte-exact producer tests linked to five pinned goldens, every
  real golden checked against the required type floor, every complete
  artifact still passing the fail-closed parser, and lost
  command-path/golden/producer-test linkage rejected.

- **ORR isolates its SPF graph to the RFC 9552 default topology.**
  BGP-LS Node, Link, and Prefix inputs are classified before
  deduplication or graph insertion: valid non-default MT-ID objects
  and malformed topology/Attribute 29 inputs are excluded fail-closed,
  so they cannot claim nodes, addresses, links, or reachability;
  Flex-Algorithm data remains inert while the base default object and
  classic IGP/Prefix Metric stay usable. `rbgp orr`, the status API,
  aggregate transition logs, export explain, and five fixed-label
  Prometheus series expose the bounded input diagnostics.

- **Peer-supplied `LOCAL_PREF` is ignored on eBGP ingress.** Per
  RFC 4271, external peers can no longer influence import policy,
  explain output, Adj-RIB-In storage, or best-path selection by
  sending `LOCAL_PREF`. iBGP values remain effective, import policy
  may still set a local value, and the byte-exact pre-policy BMP view
  continues to expose the original wire UPDATE.

- **The route-server starter applies documented dual-stack ingress
  hygiene.** Its policy rejects both default routes and a dated
  2025-10-09 snapshot of active IANA special-purpose rows marked
  non-globally reachable, while preserving active globally reachable
  or N/A children of broader rejected parents. Production-loader tests
  pin the complete snapshot, parent exceptions, chain order, and later
  RPKI, ASPA, and prefix-length guards; the interop lab retains an
  explicitly reduced IPv4 projection because its deterministic probes
  use RFC 6598 and TEST-NET-3 space.

- **`rpol` cost passes guard against duplicate-name underflow.** The
  function-cost Kahn pass and the apply-bounds pass seeded their
  `pending`/`dependents` accounting by iterating `file.fns` /
  `file.policies` (which hold every duplicate AST definition) while
  the `edges`/`defs` maps they consume key by name and collapse
  duplicates — completing a shared callee or apply-target could
  decrement a dependent's count past zero, panicking in debug/fuzz
  builds and wrapping silently in release. Names are now seeded at
  most once in both passes; regression tests cover both. Found by the
  nightly `rpol_compile` fuzz target.

- **EVPN load generation validates unsafe workloads and honors exact
  event budgets.** The development-only `evpn-tester` rejects
  zero-sized batches, zero-route or zero-rate churn, 1-2 s hold times,
  out-of-range 24-bit VNIs, MAC/IP counts that would reuse the
  synthetic MAC space, and initial/churn chunks that do not encode
  within a standard 4096-byte message; hold time zero correctly
  disables both periodic keepalives and the receive timer instead of
  constructing a zero-duration Tokio interval. Initial injection and
  withdraw/re-advertise churn wait against cumulative route events
  before sending, avoiding an initial low-rate burst and integer
  batch-rate rounding; configured rates hold when a batch exceeds the
  per-second budget or a chunk is partial, churn does not emit a pair
  scheduled beyond its duration, and session-only `--count 0` and
  unlimited `--rate 0` remain supported.

- **The committed July RIB rebaseline receipt is self-verifying
  again.** The eight CPU derivatives match the current classifier, and
  CI replays both checksum envelopes plus every CPU, DHAT, and
  sanitized CSV derivative. No benchmark was rerun; no measured value
  or performance claim changed.

- The gNMI `subscribe_on_change_streams_session_transitions` test no
  longer flakes on a 2-second delivery timeout: the event-history test
  fixture commits with `SYNCHRONOUS=NORMAL` instead of `FULL` (the
  subscription tests exercise plumbing, not outbox durability; the
  per-commit fsyncs were the latency source), and the bounded wait is
  now a hang guard rather than a latency assertion.

## [0.51.0] — 2026-07-11

### Added

- **Perf-receipt harnesses committed in-repo (`bench/scale/`).** The two
  harnesses backing the published perf receipts are now checked in so the
  receipt harness source is auditable: `bench/scale/rrharness/` (RibManager flood/churn
  CPU+memory profiler, backs `docs/perf/rebaseline-2026-07.md`) and
  `bench/scale/reloadstall/` (route-server-scale policy-reload UPDATE-stall
  driver, backs `docs/perf/reload-stall-2026-07.md`). Both are standalone
  crates kept out of the workspace and built explicitly; see
  `bench/scale/README.md`.

- **Global cross-peer path-attribute interning (LAN-336).** The
  attribute intern table moved from one-per-peer (`AdjRibIn`) to a
  single daemon-wide table owned by the RIB manager — the analog of
  BIRD's refcounted `rta` cache. Identical attribute sets from
  different peers (the common RR/RS reality: reflection preserves
  `NEXT_HOP`, so dual-fed clients advertise byte-identical attribute
  vectors) now share one allocation instead of one copy per peer.
  Measured on the allocator-tracked `memory_profile` harness at
  2 peers × 100k with per-prefix-unique, cross-peer-identical
  attributes (`full_rib_diverse`, new shape): live heap
  310.4 -> 181.1 MiB (-41.7%), intern entries 200k -> 100k. The
  pre-existing `full_rib` / `rr_fanout` / `adj_rib_in` shapes carry one
  attribute set per peer by construction (their entire attribute heap
  is ~1 KiB), so they are byte-neutral — the intern dimension is
  degenerate there, not measured as a win.
  Reclaim is unchanged in kind — `Arc` strong-count sweeps at the same
  batch seams that swept the per-peer tables, plus the peer-teardown
  seam — and is pinned by a cross-peer churn test (steady-state
  replace churn holds the table flat; removing one of two sharing
  peers reclaims nothing; removing the last empties it). New gauge
  `bgp_rib_attr_intern_global_size` (entries), refreshed at every
  insert/remove batch seam.

- **M85/M86 core-RR interop labs against BIRD and OpenBGPD.** Two new
  hosted-CI containerlab jobs pair a rustbgpd route reflector with the
  route-server incumbents: **M85** (two BIRD 2.0.12 clients + a
  rustbgpd client, 33 assertions) covers ipv4+ipv6 reflection over v4
  transport, ORIGINATOR_ID/CLUSTER_LIST in BIRD's own view, no
  reflect-back, and both sides of BIRD's real GR capability shape —
  `graceful restart on` stale-preserves through a kill while the
  default aware mode (capability with restart time 0 and no AFs) is
  correctly not preserved; **M86** (two OpenBGPD 9.1 clients, 27
  assertions) covers the same reflection/attribute surface via
  `bgpctl -j` plus OpenBGPD's helper-only GR truth (R bit, time 0,
  zero AFs on the wire) — a bgpd kill withdraws immediately with zero
  stale. Fixture headers record the cross-implementation quirks found
  while building the labs: BIRD permanently loses its initial v6
  export if the interface address is still in IPv6 DAD at session
  establishment, and OpenBGPD needs a per-AF `local-address` to
  announce v6 NLRI over a v4 session. (LAN-251)
- **gNMI Set graceful-restart subset.** The OpenConfig
  `graceful-restart/config/{enabled, restart-time, stale-routes-time}`
  leaves are now accepted under both static-neighbor and peer-group
  paths, mapped onto the native `graceful_restart` / `gr_restart_time`
  / `gr_stale_routes_time` keys through the same ADR-0076
  candidate-TOML transaction path as the existing Set subsets.
  Fractional decimal64 `stale-routes-time` values are rejected (never
  rounded) and `helper-only` returns `UNIMPLEMENTED`. (LAN-19)
- **Guard test for the `src/lib.rs` module mirror.**
  `tests/lib_module_mirror.rs` parses the `mod` declarations of
  `src/main.rs` and `src/lib.rs` at test time and fails when a new
  `main.rs` module is neither mirrored in `lib.rs` nor added to the
  documented not-mirrored list — making the LAN-198 mirror decision
  explicit at ordinary `cargo test` time instead of surfacing only on
  an `--all-features --lib` build. (LAN-205)
- **Grafana dashboard aligned with the shipped metric set.** New panels
  on `docs/grafana/rustbgpd-overview.json`: graceful restart, per-peer
  attribute-intern size, update-group index internals, policy engine
  errors, and an Operations row (config transactions, event-stream
  subscribers/lag, jemalloc memory). All existing panel series verified
  against a live `/metrics` scrape. (LAN-246)
- **JSON Schema for the TOML config.** Every config struct/enum in the
  deserialization graph now derives `schemars::JsonSchema`, with field
  doc comments carried through as descriptions, serde defaults as
  schema defaults, and `deny_unknown_fields` as
  `additionalProperties: false`. `rustbgpd --dump-config-schema`
  prints the schema to stdout; a generated copy is committed at
  `docs/rustbgpd.schema.json` (freshness-checked by a config test —
  regenerate with `BLESS=1` or by re-running the dump), shipped in the
  release tarballs, and published as a standalone release asset. TOML
  language servers (taplo / Even Better TOML) get as-you-type
  completion, inline validation, and hover docs; see the new "Editor
  integration" section in `docs/CONFIGURATION.md`. (LAN-319)
- **rpol external datasets (`dataset`).** Generation-pinned external
  match data (LAN-305, ADR-0103 Decisions 8.5/9): declare
  `dataset <kind> <name>` in `.rpol`, bind it to an
  operator-maintained snapshot file via `[policy.datasets.<name>]
  path = "..."`, and probe it exactly like a named set
  (`route.origin-as in customers`) — the same indexed structures at
  the same cost. Content refreshes ride SIGHUP: atomic snapshot swap
  with a monotonic generation, per-walk pinning (one route never sees
  two generations), content-equal no-ops, and dependency-scoped peer
  refresh (only chains referencing the swapped dataset re-evaluate;
  chains are never recompiled or replaced). A file that fails to
  load/parse keeps the prior snapshot (WARN +
  `bgp_policy_dataset_refresh_errors_total` + `rbgp policy stats`
  dataset rows); empty data is never substituted. In-language `test`
  blocks supply content with per-test `dataset name { ... }`
  overrides; explain traces annotate probes with the pinned
  generation. File format: one entry per line, `#` comments, set-
  literal syntax; bounds 64 MiB / 1M records / 16 datasets per unit.
  Datasets are the entire external surface — no WASM/host-function
  code tier (ADR-0103 Decision 9). New fuzz target `dataset_parse`.

- **rpol pure user-defined functions (`fn`).** The fourth ADR-0103
  Phase B slice: `fn penalty(len: u32, weight: u32) -> u32 { let base
  = len * weight  min(base, 1000) }` names a pure `u32` computation
  callable from any value position. Bodies are expression-shaped
  (`let` bindings + one result expression) and closed over nothing —
  every input arrives as a parameter, which keeps `requires_*`
  analyses call-site-local (a `peer.asn` argument disqualifies
  update-group sharing; route-only arguments never do). No recursion
  (the call graph is a DAG, cycles named in the diagnostic; depth
  capped at 8 through the same Kahn cost DP as `apply`); calls fully
  inline at compile time into caller-frame binding terms — no runtime
  call frames, zero cost for programs that don't call. Inlined bodies
  count against the existing expansion/eval-cost budgets per call
  site and consume caller-frame slots (a term whose calls exceed the
  256-slot frame is a compile error); explain renders calls
  source-level and errors inside a body name both the function and
  the calling term. (LAN-304)

- **Update-group growth and residue observability.** Three new metrics
  make the registry's append-only growth and the dirty-member
  withdrawal residue visible before they matter:
  `bgp_update_group_interned_chains` and `bgp_update_group_keys` track
  the distinct export-chain contents and fingerprint keys ever created
  (append-only for the process lifetime — the early-warning signal for
  a deployment cycling generated policy contents), and
  `bgp_update_group_residue_entries` tracks group tombstones plus
  per-member pending extra withdraws, emitted at every mutation site
  (growth and clear) and returning to zero when the resync drains a
  dirty member. (LAN-311)

- **Import-side policy hit counters readable via `rbgp policy stats`.**
  `GetPolicyStats` / `rbgp policy stats` now accept
  `--direction import|export|both`: import chains report the same
  per-term hit rows as export chains (already accumulating in each
  session task — pure read surface, no new hot-path work), read from
  the live session tasks with the same peer filtering and JSON shape.
  Import chains additionally report their install generation
  (`policy_generation`, bumps on every chain install including
  content-equal reinstalls), so counters that reset to zero read as a
  chain replacement rather than continuous history; export chains do
  not track an install generation yet. Explain queries and dry runs
  remain non-counting, now pinned by test on the import path. (LAN-248)

- **M80 extended with rpol family / origin-AS parity and migration
  proof.** The ADR-0096 policy-parity interop job now runs its route
  matrix over IPv4 **and** IPv6 unicast on the same MP-BGP sessions and
  proves the new predicate surfaces against FRR route-maps route for
  route: `route.origin-as in <asn-set>` vs an anchored as-path regex,
  and family-branched terms whose same-origin v4/v6 partner twins
  diverge on LP/community purely by `route.family` (import and export —
  the v6 export branch pins a family-scoped MED to the wire). The job
  also asserts live import-side hit counters and the import-chain
  install generation (`rbgp policy stats --direction import`), explain
  traces naming the deciding source term in both directions, and keeps
  the SIGHUP hot-apply receipt (zero flap, Route Refresh scoped to the
  edited peer) on the dual-family topology; 44 scenario assertions, up
  from 29. `docs/rpol-language.md` gains a "Migrating from BIRD and
  FRR" section with the equivalent BIRD filter and FRR route-map for an
  asn-set + family policy. (LAN-297)

- **`.rpol` indexed ASN sets and origin-AS predicates.** New `asn-set`
  declarations (`asn-set customers { 64500, 64501 }`) compile to
  content-interned hash sets probed in O(1) by two new predicates:
  `route.origin-as in <set>` / `peer.asn in <set>`, plus
  `route.origin-as ==`/`!=` comparisons. The route's origin AS (the last
  ASN of the rightmost non-empty `AS_SEQUENCE`) is computed once where the
  typed `AS_PATH` is already parsed and carried on the policy context —
  never re-derived per evaluation. Absent origins (empty or `AS_SET`-only
  paths) match neither equality nor membership, mirroring the other
  absent-attribute predicates. `peer.asn in` reads peer identity and
  therefore excludes its peers from update-group sharing, like the other
  peer-context guards. ASN sets are an `.rpol`-only surface (no TOML
  equivalent), following the strict-next-hop precedent. (LAN-249)

- **Typed `route.family` predicates in `.rpol`** — one policy chain attached
  to several address families can now branch per family
  (`if route.family == ipv4-unicast { ... }`, `==`/`!=` only) over a closed
  enum covering every family rustbgpd evaluates: IPv4/IPv6 unicast,
  IPv4/IPv6 labeled-unicast, VPNv4/VPNv6, IPv4/IPv6 FlowSpec, EVPN, RTC,
  BGP-LS, and BGP-LS VPN. The family is typed knowledge carried by the
  evaluation context at every import/export/explain/policy-test site — never
  inferred from prefix shape — and family predicates are route-context-only,
  so they never disqualify a peer from update-group sharing. Explain traces
  render the source-level expression, and `test` fixtures take an explicit
  `family` field. (LAN-295)
- **Direction-aware computed AS_PATH prepend operands in `.rpol`** —
  `prepend as self|peer|origin <count>` prepends the local speaker's ASN
  (`[global] asn`, stamped onto the chain at attach time), the evaluation
  peer's ASN, or the route's origin AS (the `route.origin-as` value). `peer`
  is import-only: bound as an export chain it would prepend the receiving
  peer's own ASN (rejected by the receiver as an own-AS loop, RFC 4271
  §9.1.2), so the config resolver refuses the attachment with a diagnostic
  naming the policy and term — at load, reload, and transaction time alike.
  `prepend as peer` registers as peer-dependent for update-group
  fingerprinting; `self`/`origin` chains still group. Operands resolve when
  the matched term's action executes; a missing or zero context value fails
  the route closed (ASN 0 never reaches the wire), with the failing operand
  and reason rendered in explain traces. The fixed-AS form and a policy
  parameter named `origin` keep their existing meaning, and test fixtures
  gain a `peer { local-as N }` field backing `self`. (LAN-296)
- **`bgp_rib_attr_intern_size{peer}` gauge** — unique interned attribute sets
  in each peer's Adj-RIB-In table (attribute-memory dedup); sum across peers
  for the daemon-wide total. Three containerlab soak harnesses (GR-restart
  intern-GC, hot-reload, inject-churn), each with a topology and a post-hoc
  analyzer, exercise it and adjacent long-run paths. Recorded O(1) per peer at
  every Adj-RIB-In intern mutation site (GC, injection/withdraw, and announce
  growth) so the series tracks the live intern table under churn.
- **Semantic RIB diff engine** (`rustbgpctl::ribdiff`) — canonical
  route-record model and comparison core for canarying rustbgpd beside an
  incumbent route server. Compares a multiset of semantic paths per
  (peer, family, NLRI) — RFC 7911 path IDs are diagnostic only — and
  classifies divergence as incumbent-only, rustbgpd-only,
  attribute-changed, or multiplicity-changed with before/after attribute
  deltas. Reports carry a versioned JSON schema (`rbgp-ribdiff/1`) and the
  normalization profile (AS_PATH segment order/kind significant, sorted
  community lists, absence-vs-zero MED/LOCAL_PREF, unknown attributes
  compared byte-exact). Bounded ingestion (route count, paths per NLRI,
  attributes, record and total bytes); incomplete, truncated, or
  mixed-generation captures are never reported in sync. Ingestion
  adapters (live gRPC, MRT, BMP) and the CLI surface land separately.
- **`rbgp diff advertised` — live Adj-RIB-Out vs incumbent snapshot**
  (LAN-307). First operator workflow on the semantic RIB diff engine:
  compares what the daemon advertises to each peer (paginated
  `ListAdvertisedRoutes`, processed one peer at a time so both full
  sides are never held in memory) against a versioned `rbgp-ribsnap/1`
  NDJSON snapshot of an incumbent route server's advertised view.
  Exit codes: 0 in sync, 1 divergent, 2 comparison refused — and the
  refusal is fail-closed everywhere: snapshots require a header and a
  counted completion trailer (EOF alone is never completeness), unknown
  fields and trailer-count mismatches are malformed, live pagination
  refuses repeated page tokens and mid-walk `total_count` drift, hard
  route/byte limits are enforced before buffering, deadlines expire the
  comparison, and an unavailable requested peer or family refuses the
  aggregate equal verdict. Human summary with bounded detail rows and a
  complete `--json` report; both emit the ignored-attribute choices and
  the live-source normalization notes (notably: the proto's bare-integer
  MED makes MED-absent and MED 0 indistinguishable over gRPC, so live
  `med=0` is compared as absent). Strictly read-only. Snapshot format,
  producer snippets, and the shadow-trial workflow are documented in
  `docs/ribdiff.md` and the route-server cookbook pages; `rbgp doctor`
  bundles reference the tool without collecting route contents.
- **M84 interop job: multi-cache RTR/ASPA epoch conformance** (LAN-243).
  One containerlab receipt drives the 8210bis per-cache epoch model against
  Routinator (real RTR v2, offline via `--no-rir-tals` + SLURM assertions),
  StayRTR (real RTR v1-only), and the in-repo phased RTR v2 server at once:
  per-cache load at validated End of Data, v2→v1 fallback, cache restart
  with data retention and session rotation (no validation flap), incremental
  epoch advance, ASPA provider-set replacement and empty-provider
  withdrawal, and a same-session serial regression resolved by exactly one
  Reset Query resync with the stale VRP purged. Local-only, like the other
  RTR-cache jobs (M21/M27/M59).
- **NIST-BRIO offline ASPA conformance subset extended to the full demo
  catalog** (NIST-BRIO b7.1.2, commit 23ee402f): upstream exp46 (#4–#6)
  and exp79 (#7–#9), downstream exp8 and exp14 (#2–#4) join the existing
  exp13/exp1/exp57/exp910 vectors, now covering the AS0-only
  ("no providers") ASPA attestation shape on both the upstream and
  downstream procedures, encoded exactly as the BRIO cache scripts send
  it (`addASPA 65060 0`). Also pinned: RFC 1982 serial-number comparison
  at the wrap and half-window boundaries. Shipped RTR/ASPA behavior was
  drift-checked against draft-ietf-sidrops-8210bis-26 and
  draft-ietf-sidrops-aspa-verification-26 (the -26 clarification that
  AS_PATH preprocessing removes *consecutive* duplicates matches the
  shipped compression exactly); stale -25 doc references trued up.
  (LAN-243)
- **Incumbent snapshot adapters + golden-fixture matrix for `rbgp diff`**
  (LAN-308). Four versioned adapters produce `rbgp-ribsnap/1` snapshots
  from an incumbent's own output: `rbgp diff snapshot from-mrt` (in-binary;
  RFC 6396 `TABLE_DUMP_V2` with RFC 8050 Add-Path subtypes, both
  abbreviated and full-form `MP_REACH_NLRI` next hops, extended/large
  communities from raw bytes) plus stdlib-only Python converters under
  `scripts/ribsnap/` for BIRD 2 (`show route export`, verified 2.0.12),
  FRR (`advertised-routes detail json`, verified 10.3.1; the
  community-less summary form is refused), and GoBGP (`adj-out -j`,
  verified 3.37.0; Add-Path duplicates carry no path identifier upstream
  and convert as repeated records). `from-mrt` requires `--view` as a
  producer attestation and refuses `loc-rib` / `adj-rib-in` dumps as
  non-comparable (exit 2) — `TABLE_DUMP_V2` is a collector RIB view by
  default, not an Adj-RIB-Out. All adapters share the fail-closed emission
  contract (counted trailer only after a full parse; absent attributes
  omitted, never defaulted; symbolic-only extended communities skipped
  with a stderr note) and a `source`-field convention naming the adapter
  contract version. Golden-fixture tests in `cargo test -p rustbgpctl`
  pin each converter byte-for-byte against raw captures from real M83 lab
  containers and diff them clean against the same capture's wire-truth
  values, protecting against upstream schema drift; the cookbook gains
  per-incumbent capture commands, prerequisites, limitations, and example
  equal / explained-difference reports.

- **`.rpol` checked u32 value expressions** (LAN-299, the first
  ADR-0103 slice). Arithmetic (`+ - * / %`) and the bounded builtins
  `min`/`max`/`clamp` in value positions — `set med route.med + 50`,
  `set local-pref min(route.local-pref * 2, 400)`, comparisons like
  `route.as-path.len * 10 >= route.med` — over u32 literals,
  parameters, and the u32 fields (`route.local-pref`, `route.med`,
  `route.as-path.len`, `route.origin-as`, `peer.asn`). Every operation
  is checked: overflow, underflow, division/modulo by zero, an
  inverted clamp, or an absent operand (origin AS on an `AS_SET`-only
  path, unknown peer ASN) is an evaluation error that denies the route
  with staged modifications discarded, a per-chain error counter, a
  rate-limited WARN naming the failing policy and term, and the error
  rendered in explain traces in place of a verdict — the uniform
  fail-closed rail later ADR-0103 slices reuse, and the computed
  as-path prepend operands now ride it too. Constant subexpressions
  fold at compile time with the same checked operators (`set med
  25 + 25` compiles to exactly `set med 50`; `4294967295 + 1` is a
  compile error at its span), operator costs land in the typecheck
  cost DP under the ADR's `MAX_EVAL_COST` budget, and grammar
  evolution is source-compatible: kebab-case maximal munch is
  permanent, so `route.med - 1` subtracts while `route.med-1` stays an
  unknown-field error. `peer.asn` operands register peer context for
  update-group fingerprinting; route-field arithmetic never
  disqualifies grouping.

- **`rbgp diff snapshot from-bmp`: RFC 8671 post-policy Adj-RIB-Out BMP
  importer.** A fifth snapshot adapter converts an offline capture of
  an incumbent's raw BMP version 3 byte stream into an `rbgp-ribsnap/1`
  snapshot for `rbgp diff advertised`. Only Route Monitoring messages
  flagged O=1/L=1 contribute routes: the Adj-RIB-In feed (O=0) is
  skipped with a note and a pre-policy Adj-RIB-Out stream (O=1/L=0) is
  refused as non-comparable. Embedded UPDATEs are decoded with
  `rustbgpd-wire` under the Add-Path state negotiated in each Peer Up's
  OPENs (RFC 7911 send/receive directionality per family) and the
  per-message 2-/4-octet AS flag; state is kept per (connection
  generation, peer, family, NLRI, source path ID) so live updates
  interleaved with the initial dump supersede it, and a reconnect, Peer
  Up, or Peer Down invalidates exactly the affected generation. A
  peer/family is complete only after its End-of-RIB — an incomplete
  dump is refused (exit 2, nothing emitted), and RFC 8671 stat types
  15/17 arriving after End-of-RIB are cross-checked against the folded
  counts (never required for completeness). Attributes outside the
  snapshot's typed set (ORIGINATOR_ID, CLUSTER_LIST, OTC, unknowns) are
  preserved byte-exact in a new optional `unknown_attrs` route-record
  field, compared byte-exact by the diff engine and excludable with the
  new `--ignore-attribute unknown`. Hard bounds on input bytes, message
  length, peers, routes, and paths per NLRI refuse over-limit input;
  golden byte fixtures framed by the daemon's own BMP encoder pin the
  matrix end-to-end (capture → canonical records → in-sync, divergent,
  and incomplete verdicts). Capture workflow documented in
  docs/ribdiff.md and the route-server migration cookbook. (LAN-309)
- **`.rpol` immutable `let` bindings with static slot allocation.**
  `let <name> = <value expression>` names a computed u32 in statement
  position — term bodies and `if`/`else` bodies — with lexical block
  scope and deterministic shadowing (innermost wins; a binding may
  shadow an outer binding or a parameter, and resolution stays
  position-typed, so enum members, builtins, and the `prepend as
  origin` operand keep their meanings). Bindings are immutable and
  u32-only; initializers are checked value expressions riding the
  uniform fail-closed eval-error rails (an overflow or absent operand
  in an initializer denies the route and discards staged
  modifications, eagerly — used or not). Locals compile to fixed
  slots in a 128-slot register file (64 per scope, the 65th is a
  compile error with a span; slot assignment is a pure function of
  the source, so unchanged reloads still diff as no-ops) materialized
  lazily on the stack — binding-free policies pay nothing and no
  evaluation heap-allocates. Reads always observe the route as it
  arrived, never staged `set` writes (read-back stays excluded per
  ADR-0103); use-before-definition and unknown names are spanned
  compile errors; `apply` targets may not declare bindings this slice
  (the inlined predicate has no term walk — LAN-304 functions are the
  composition vehicle). Explain traces render `let` statements in
  source form and resolve binding reads on demand; `peer.asn`
  initializers register peer context for update-group
  fingerprinting. (LAN-302, ADR-0103)

- **`.rpol` bounded `for` loops with runtime fuel metering.** The
  third ADR-0103 Phase B slice — and the first to activate the runtime
  budgets. `for <var> in <source> { ... }` iterates exactly three
  finite sources: `route.communities` (standard RFC 1997 communities
  as raw `u32` values — the community-iteration decision that keeps
  the u32-only value model; large/ext kinds stay probe-only),
  `route.as-path` (every ASN in wire order, prepend duplicates and
  `AS_SET` members included), and named `asn-set`s (canonical sorted
  order, deterministic across compiles). The loop variable is an
  immutable per-iteration binding on the LAN-302 slot machinery,
  usable in comparisons and arithmetic, in `in` probes against
  asn-sets and a community-set's standard members, and in the new
  binding-valued `add`/`remove community <var>` actions — the
  route-server scrub-loop idiom (`for c in route.communities { if c in
  scrub { remove community c } }`). `break` exits the innermost loop,
  `continue` skips to the next iteration, and body verdicts terminate
  the policy exactly like an `if` body; iterated collections are the
  arrived route, so staged adds can never self-extend an iteration
  (pinned by test). Budgets per ADR-0103 Decision 3: 4,096 iterations
  per loop (compile-checked for sets; cap-then-**error** at runtime
  for attribute sources — an extended-message route with more
  communities than the cap denies, never truncates), loop nesting ≤ 4
  with multiplicative cost in the typecheck DP (nested route-attribute
  loops exceed the 1M-step budget and are rejected at compile time),
  and per-evaluation instruction fuel initialized at `MAX_EVAL_COST`
  and decremented only at loop iteration steps — loop-free chains pay
  one register write and nothing else, and exhaustion rides the
  uniform-Deny eval-error rails (counter + rate-limited log + explain
  error trace, with `fuel-exhausted` / `loop-limit-exceeded` reasons).
  Explain renders bounded loop summaries (iteration count + the
  deciding iteration, never per-iteration output); `apply` targets may
  not contain loops (no walk to run them in); `RouteContext` gains the
  typed `AS_PATH` so as-path iteration sees the real segments
  everywhere policy evaluates. `while` remains excluded — the
  finite-source grammar is what keeps every bound provable or
  meterable. (LAN-303, ADR-0103)

- **rpol modules and imports.** The fifth ADR-0103 Phase B slice:
  `import "lib/bogons.rpol"` splices another file's definitions —
  sets, functions, policies, `test` blocks — into one flat-namespace
  compilation unit, so shared bogon/customer libraries live in one
  file (qualified names deferred; duplicate names across modules are
  compile errors naming both files). Modules are a resolution
  feature with **no IR change**: imports resolve depth-first in
  declaration order against the importing file's directory plus the
  new `[policy] rpol_roots` (CLI: repeatable `--root`), canonicalized
  with escapes above every root rejected, diamonds loaded once,
  cycles named in the diagnostic, and budgets enforced (nesting ≤ 8,
  1 MiB/file, 8 MiB / 64 files per graph). Each unit compiles
  all-or-nothing, and the reload identity covers the whole resolved
  graph — a leaf-module edit re-syncs every dependent chain while an
  untouched graph stays a content-equal no-op. Diagnostics carry
  per-module spans (errors excerpt the file they're in), and
  `rbgp policy check --list-deps` prints the resolved graph with
  SHA-256 content hashes for packaging/audit. (LAN-300, ADR-0103)

- **Prometheus alert-rule pack.** A ready-to-load rule file at
  `examples/prometheus/rustbgpd-alerts.yml` covers the first-order
  operator questions: daemon down, session not Established (derived
  from the `bgp_session_established_total` / `bgp_session_flaps_total`
  counter pair — the daemon exports no per-peer state gauge), session
  flapping, Established-but-empty Adj-RIB-In, max-prefix breach, empty
  RPKI VRP table, event-outbox degradation, and sustained update-group
  withdrawal residue growth. Every expression references only metrics
  the daemon actually exports (verified against a live two-daemon
  lab), each rule carries severity labels plus templated
  summary/description annotations, and every rule has a firing and a
  non-firing unit test in `rustbgpd-alerts_test.yml`. A path-scoped CI
  workflow runs `promtool check rules` / `promtool test rules` (pinned
  promtool) on any change to the pack. Cross-linked from
  `docs/GRAFANA.md` and the `docs/OPERATIONS.md` metrics catalog.
  (LAN-318)

- **`rbgp neighbor --wide` and a friendly empty state.** The neighbor
  list gains a `--wide` flag that appends the classic vendor summary
  columns operators pattern-match on: `MsgRcvd`/`MsgSent` (total BGP
  messages in each direction, all types including KEEPALIVEs —
  daemon-lifetime counters mirroring `bgp_messages_*_total`, so an
  Established-but-wedged session is visible as counters that stop
  moving), `Flaps`, an `RRC` route-reflector-client marker, and the
  overloaded `State/PfxRcd` column (prefix count when Established,
  state name otherwise) last. The default table is byte-for-byte
  unchanged and `--wide` is display-only (`-j` always carries every
  field; the new `messages_received`/`messages_sent`/
  `route_reflector_client` fields also appear on `NeighborState` and
  in list/detail JSON). With zero peers, `rbgp neighbor` now prints
  `no neighbors configured — add one: rbgp neighbor <addr> add --asn
  <asn>` instead of a bare notice; `-j` still prints `[]`. (LAN-322)
- **rpol evaluation-error observability surface.** The final ADR-0103
  slice (LAN-301) finishes the operator surface over the fail-closed
  evaluation-error rail the runtime slices built: a new
  `bgp_policy_eval_errors_total{direction, kind}` Prometheus counter
  aggregates fail-closed denies by direction and the closed
  `EvalErrorKind` label set (24-series worst case — per-chain detail
  deliberately lives on the stats RPC, not labels); `GetPolicyStats`
  / `rbgp policy stats` chain rows gain `eval_errors` (count since
  chain install) and `last_error` (the most recent error rendered as
  `<kind> in policy <name> term <name>`), shown above the term table
  when nonzero. In-language tests gain an error-pinning expectation:
  `expect p == error` (any evaluation error) and `expect p == error
  KIND` (kind-pinned, e.g. `error divide-by-zero`; unknown kinds are
  compile diagnostics with a suggestion). The ADR-0103 Decision 1
  bytecode re-entry benchmark was re-run against the post-program
  evaluator (bindings, loops, functions, datasets all landed) and the
  gate did not fire — dispatch is still not where evaluation cost
  lives; the receipt addendum is in the ADR. (LAN-301)

- **Man pages and shell completions in release artifacts.** New
  `rbgp man` subcommand renders the full CLI — every nested subcommand
  gets its own SYNOPSIS/DESCRIPTION/OPTIONS section — as a single
  `rbgp.1` roff page on stdout (clap_mangen), and `rustbgpd --man`
  prints a `rustbgpd.8` page covering the daemon's flags, signals, and
  files. Release tarballs now ship both pages plus bash/zsh/fish
  completions under `share/` (`share/man/man1/`, `share/man/man8/`,
  `share/completions/`), generated at package time by the built
  binaries so they cannot drift; the container image installs the bash
  completions at `/usr/share/bash-completion/completions/rbgp`.
  (LAN-326)
- **`rbgp policy fmt` — the canonical `.rpol` formatter.** One
  canonical style, zero options (gofmt philosophy): `rbgp policy fmt
  FILE...` rewrites in place (atomic write-temp-rename), `--check`
  exits 1 with a diff for CI, and `-` formats stdin to stdout for
  editors. Concrete-syntax architecture: the token stream — comments
  included — is re-laid-out and never mutated (semicolons, comments,
  and declaration order are preserved verbatim), so formatting is
  parse-identical by construction; the formatter additionally
  re-lexes its own output and refuses to write on any
  token-or-comment mismatch. Idempotence and compiled-IR identity are
  property-tested over every `.rpol` fixture and fuzz seed in the
  repo, and the repo's own `.rpol` files are reformatted to the
  canonical style. New "Formatting" section in
  `docs/rpol-language.md`. (LAN-323)
- **`rbgp policy check --coverage` — rpol test coverage and static
  lints.** Reports, per term of every policy the in-language tests
  exercise, two distinct facts the walk attribution already knows:
  was the guard ever *evaluated* (never ⇒ earlier terms always
  decide) and did it ever *match* (never ⇒ no fixture hits it) —
  aggregated across parameterized instantiations and attributed to
  the defining module under imports. Policies reached only through
  `apply` are reported as `apply-only` (an inlined predicate carries
  no term-level facts); unreferenced ones are called out with the
  honest caveat that daemon config chains are not visible to a
  standalone check. Static lints ride the same pass: `unused-set` /
  `unused-dataset` / `unused-fn`, `unreachable-term`
  (constant-guard/terminal cases only), and `unreferenced-policy`.
  Coverage never fails the run by itself; `--coverage-min PCT` (CI
  mode) exits 3 below the threshold, with diagnostics (1) and test
  failures (2) taking precedence. `-j` adds a stable-keyed `coverage`
  object. New "Coverage and lints" section in
  `docs/rpol-language.md`. (LAN-323)

- **`rbgp config effective` — dump the running post-defaults config.**
  New `ConfigService.GetEffectiveConfig` RPC (`sensitive_read`) returns
  the daemon's live config as normalized, deterministic TOML with
  per-neighbor defaults materialized: peer-group inheritance and
  computed defaults (`hold_time`, the RFC 9687 `send_hold_time`
  derivation, GR/LLGR timers, address families, `ttl_security`,
  RR/RS-client flags) are resolved to the values the daemon is using.
  `rbgp -j config effective` re-renders the same document as JSON.
  Secret material (`md5_password`, `tcp_ao.key`) is replaced with
  `<redacted>` server-side before the document leaves the daemon, and
  config validation now rejects the placeholder loudly — a dump taken
  from a secret-bearing config cannot silently boot as-is. Secretless
  dumps round-trip: they reload through `rustbgpd --check` and re-dump
  to the identical document. (LAN-325)
- **MRT `TABLE_DUMP_V2` reader.** `rustbgpd-mrt` gains the read half of
  RFC 6396: `SnapshotReader` validates the `PEER_INDEX_TABLE`, then
  streams decoded RIB entries (prefix, peer, originated time, path
  attributes, Add-Path ids per RFC 8050) for every subtype the writer
  emits, including EVPN `RIB_GENERIC` records. Input is treated as
  hostile: all length fields are bounds-checked, malformed data yields
  typed errors instead of panics, unknown record types are skipped and
  counted, and hard caps bound per-record size (16 MiB), total entries
  (2^28), and gzip decompression (4 GiB). Groundwork for MRT warm-boot
  restore. (LAN-337)
- **Doctor bundle v2 (`rbgp doctor`).** The support-bundle command now
  prints red/green triage checks live while it collects — daemon
  reachable/healthy, peers stuck outside Established with
  time-in-state, flap loops, daemon `nofile` rlimits, recent panic
  reports — and produces one `rustbgpd-doctor-<ts>.tar.gz` with a
  stable layout: `manifest.json`, `config/effective.toml` (the
  daemon's secret-redacted `GetEffectiveConfig` dump — the raw config
  file is never copied), `peers/`, `logs/tail-1000.jsonl` (opt-in
  `--log-file`; stdout/journald-only logging is recorded in the
  manifest instead), `crashes/`, and `system/`. The manifest records
  tool + daemon versions, that redaction ran, and which sections were
  collected vs unavailable — a run against a down daemon still
  produces a bundle and says what is missing. Detailed exit codes: 0
  all green / 1 error / 2 red checks found. The daemon side gains
  panic hygiene: a global panic hook writes a bounded, secret-free
  `crash/panic-<ts>.toml` report (message, location, thread, version —
  never env or argv) under `runtime_state_dir`, keeping the 10 most
  recent, and `HealthResponse` now carries `daemon_version`. The
  GitHub bug-report template asks for the bundle. (LAN-324)

- **rpol did-you-mean for unknown set/policy/function/dataset
  references.** Every unknown-symbol diagnostic (prefix-set /
  community-set / asn-set probes, `apply` and test `expect` targets,
  function calls, dataset references and test overrides) now suggests
  the closest same-kind name by edit distance — the same threshold the
  field suggestions use — with a labeled span at the suggested
  symbol's definition site (file:line in the rendering). An exact name
  match of a different kind is named as such (`` `bogons` is an
  asn-set; `route.prefix in` needs a prefix-set ``) instead of a
  spelling suggestion. Right-kind datasets count as candidates for
  typo'd `in` probes. Message/notes enrichment only — error codes and
  exit contracts are unchanged. (LAN-328)

- **rpol coverage-gap fixtures.** In-language tests for the two terms
  `rbgp policy check --coverage` found evaluated-but-never-matched:
  an `aspa invalid` reject fixture in
  `tests/interop/configs/m83-hygiene.rpol` and an `rpki invalid`
  OV_INVALID-tagging fixture in `examples/route-server/hygiene.rpol`;
  both corpora now report full term coverage. (LAN-342)

### Changed
- **`rustbgpd-wire` 0.14.0 → 0.14.1** (non-breaking): adds
  `AsPath::asns()` (a borrowing ASN iterator) and `encode_with_limit()`
  on `NotificationMessage`/`RouteRefreshMessage` plus the free
  `encode_message_with_limit()` for RFC 8654 extended-size encoding.
  Purely additive — no existing item changed or removed, so `^0.14`
  consumers upgrade without edits.
- **Per-peer `bgp_rib_attr_intern_size{peer}` gauge replaced by
  `bgp_rib_attr_intern_global_size`** (LAN-336): the per-peer intern
  tables it measured no longer exist. The GR-restart/hot-reload/
  inject-churn soak harnesses, the Grafana attribute-intern panel, and
  OPERATIONS.md now read the global gauge; the soak slope gates are
  unchanged in meaning (flat under steady-state churn or the gate
  fails).
- **CLI consistency sweep (LAN-329).** One noun, one file-arg style, one
  empty-state shape across `rbgp`; every old spelling keeps working as
  an alias, so existing scripts are unaffected.
  - `--neighbor` is now the canonical peer-selector flag everywhere
    (`gshut`, `diff advertised`, `policy stats|test`, `rib
    fib|bgpls|vpn|labeled|rtc`, `evpn [list]`); `--peer` remains a
    visible alias, and the existing `--neighbor` flags (`policy
    explain`, `policy chain ...`) gained `--peer` as an alias.
    Positional address forms (`rbgp neighbor <ADDRESS>`) are unchanged.
  - `neighbor add` and `dynamic-neighbor add` take `--remote-asn`
    (canonical) with `--asn` as a visible alias, disambiguating the
    remote AS from the local "ASN" shown by `rbgp global`.
  - `config diff|plan|apply` take the candidate TOML as a positional
    `[CANDIDATE]` (matching `policy check|fmt|test FILE`);
    `--from-file` still parses as a hidden compatibility alias.
  - `rbgp events [sessions|policy|evpn]` with no matching events now
    prints `[]` under `--json` (previously nothing, which broke JSON
    consumers) and a one-line "No ... events recorded" empty state in
    human output.
  - `rbgp metrics --json` and `rbgp top --json` now warn on stderr
    that `--json` has no effect (Prometheus text / interactive TUI);
    stdout is unchanged.
  - `rbgp --help` documents the exit-code contracts (general 0/1 plus
    the detailed `diff`, `config diff|plan`, `policy check|test|fmt`
    codes) in one authoritative list, also rendered by `rbgp man`;
    top-level and nested help lists are now terse one-liners with
    details moved to each subcommand's `--help`.
- Removed the deprecated `bgp_aspa_records_total` gauge alias; `bgp_aspa_records` is the only exported name
- **Compact route storage: slab-backed route bodies behind `u32`
  handles.** Adj-RIB-In and Adj-RIB-Out (which also backs the shared
  update-group RIB-Out table — the largest heap component in the
  2026-07 memory re-baseline) no longer keep ~130-byte `Route` values
  inline in hashbrown bucket arrays. Route bodies live densely in a
  per-table slab; the existing prefix-trie index carries
  `(path_id, handle)` pairs, and the separate
  `(prefix, path_id)`-keyed hash maps are gone entirely. Withdrawals
  free slab slots onto a free list, so steady-state churn does not
  grow the tables. The Loc-RIB best-path map deliberately keeps its
  inline route bodies: a slab handle measurably regressed its
  lookup-hot recompute (see the field note in `loc_rib.rs`).
  Allocator-tracked `memory_profile` at the 2-peer × 100k-prefix
  shape: Full-RIB 65.6 MiB → 51.8 MiB (−21.1%), RR-fanout
  110.1 MiB → 82.5 MiB (−25.1%); `rib_ops` insert / pipeline / churn
  benchmarks improved 18–72% from the removed per-route hashing.
  (LAN-335)
- **Docs reorganized by task shape (Diátaxis).** `docs/README.md` now
  indexes every doc under tutorials / how-to guides / reference /
  explanation; archived soak postmortems moved from `docs/soak-*.md`
  to `docs/soaks/` (all cross-references updated); two new operator
  runbooks in the cookbook: peer-flap triage
  (`docs/cookbook/peer-flap-triage.md`) and RR pair day-2 operations
  (`docs/cookbook/rr-pair-day2.md`), plus a shadow-cutover pointer to
  the existing migration guide. (LAN-327)

- **`security.grpc.enforcement = "legacy"` now logs a startup warning.**
  Legacy mode keeps working, but the daemon warns at boot that
  per-method tier authorization is not enforced and that tier
  enforcement becomes mandatory in a future release — migrate to
  `enforcement = "tier"` with `[security.grpc.roles]`. (LAN-194)
- **In-language `test` blocks no longer treat an evaluation error as a
  `reject` verdict.** Per ADR-0103 Decision 4, an `expect ... ==
  accept|reject` whose evaluation ERRORS now FAILS the test with the
  error kind and failing policy/term rendered (previously an error
  silently satisfied `== reject`, so a broken policy could pass as
  "rejects correctly"). Migration: expectations that deliberately pin
  the fail-closed rail switch to the new form — `expect p == error`
  or `expect p == error <kind>`. (LAN-301)

- **Release publication is now fail-closed.** The binary-release and
  container-image workflows refuse to publish unless the pushed tag
  `vX.Y.Z` equals the workspace `[workspace.package]` version and
  `cargo test --workspace` passed for the tagged commit in the same
  run. Release tarballs and the runtime container image now ship
  `LICENSE-MIT` and `LICENSE-APACHE`, with workflow assertions that
  fail the build if either file is missing from an artifact. (LAN-278)

- **Outbound UPDATE writes are coalesced per writer drain.** The
  per-peer session writer now drains up to 64 queued bulk frames
  (UPDATE, ROUTE-REFRESH markers, EoR) or ~256 KiB per drain into one
  contiguous `write + flush` instead of one syscall per message —
  whole frames only, queue order preserved. Priority messages (OPEN,
  KEEPALIVE, NOTIFICATION, Cease) still write individually, so
  teardown ordering and biased preemption semantics are unchanged, as
  are send-hold (RFC 9687) enforcement and the partial-PDU teardown
  discipline. Measured on the writer flood path (loopback, 100-byte
  frames, release build): write syscalls drop 64× (1.0 → 0.016 per
  frame) and sustained writer throughput rises ~10×. (LAN-332)
- **`bgp_aspa_records_total` renamed to `bgp_aspa_records`.** The ASPA
  record count is a gauge and must not carry the counter-only `_total`
  suffix. Both names are exported this release — the old name's HELP
  text marks it DEPRECATED — and `bgp_aspa_records_total` will be
  removed in the next release; repoint dashboards and alerts at
  `bgp_aspa_records`. The shipped Grafana dashboard and the M84
  interop assertions already use the new name. (LAN-318)

### Removed

- **The in-daemon birdwatcher looking glass HTTP server.**
  `[global.telemetry.looking_glass]` is gone; a config that still sets
  it fails to load with a migration error. Run the external
  `examples/birdwatcher-adapter` instead — it serves the identical
  birdwatcher REST endpoints (`/status`, `/protocols/bgp`,
  `/routes/protocol/{id}`, `/routes/peer/{peer}`) from the daemon's
  gRPC API. (LAN-194)

- **The legacy global inline policy fallback.** Top-level
  `[[policy.import]]` / `[[policy.export]]` statements no longer load;
  configs that still set them fail with a migration error. Move the
  statements to named policies (`[policy.definitions.<name>]` or
  `.rpol` files via `[policy] rpol_files`) referenced from `[policy]
  import_chain` / `export_chain` — unlike the fallback, named chains
  hot-apply on SIGHUP and are visible to config transactions.
  Per-neighbor and per-group inline policy (`import_policy` /
  `export_policy`) is unchanged. (LAN-194)

- **The `GlobalService.SetGlobal` RPC.** It was reserved and always
  returned `UNIMPLEMENTED`; runtime global mutation goes through
  config transactions instead. The method, its request/response
  messages, and its authz-matrix entry are removed (97 methods now
  inventoried). (LAN-194)

### Fixed

- **LLGR promotion preserves global attribute interning.** GR-to-LLGR
  promotion now re-interns each locally modified attribute set, so a full table
  sharing one attribute allocation does not expand into one identical allocation
  per retained route for the LLGR stale window.
- **Reload-stall completion is unique and generation-aware.** The committed
  route-server-scale harness now completes only after every expected unique
  base prefix arrives with the requested policy-generation community; duplicate
  or stale-generation announcements cannot shorten the measured window. The
  original July numbers are explicitly invalidated pending a corrected rerun.
- **M66 authorization assertion follows the canonical CLI error.** The EVPN ES
  drain interop proof now recognizes the shipped `permission denied` rendering
  while retaining the nonzero-exit and `operator_only` checks.

- **Unicast routes now carry their graceful-restart stale flags
  through the API.** The unicast RIB conversion was the only family
  that dropped `is_stale`/`is_llgr_stale` when building the gRPC
  `Route` (VPN, labeled, RTC, and BGP-LS entries have always carried
  them), so `rbgp rib received` showed GR-preserved routes as normal
  during a restart window. The proto `Route` message gains
  `stale`/`llgr_stale` fields, the JSON output emits them when set
  (matching the other families), and the human route table marks
  flagged rows with a red `S` (stale, RFC 4724) or `L` (LLGR stale,
  RFC 9494) next to the best marker — the column only appears when a
  flagged route is present, so the everyday table is unchanged.
  (LAN-347)
- **Update-group withdraw residue now drains on the per-peer resync
  path.** A grouped member that went dirty, missed withdrawals (group
  tombstones), and then moved off the grouped path (e.g. its export
  chain became peer-context-dependent) carried those tombstones as
  pending extra withdraws that the per-peer resync never consumed —
  the keys were in neither the Loc-RIB nor the seeded Adj-RIB-Out, so
  the stale routes stayed on the peer's wire until a regroup or
  session bounce, and the residue gauge floored at a nonzero value.
  Relatedly, a resync whose enumeration came up empty in every family
  (a full-withdraw moment after a regroup-while-dirty) dropped the
  carried residue without emitting the withdraws. Pending extra
  withdraws now feed the resync enumerations (so an empty enumeration
  proves there is nothing owed), the per-peer resync appends the
  residue keys as (over-)withdraws — skipping keys announced in the
  same pass or genuinely advertised in Adj-RIB-Out — and the residue
  is dropped only after a successful send. A still-dirty member moving
  to the per-peer path also folds its retained regroup baseline into
  the seeded Adj-RIB-Out (wire values win), matching the union rule
  already used for grouped→grouped moves. (LAN-344)
- **Announces missed while dirty are no longer equality-suppressed
  against the regroup baseline.** A grouped member's regroup baseline
  is a snapshot of the group table — intended state, not wire state:
  the table advances before the send that then fails, so a member that
  went dirty and then regrouped had its missed announces already in
  the baseline, the one-shot resync diff suppressed them as
  "unchanged", and the peer was left permanently missing the routes
  (an under-advertise invisible to the residue gauge). The same
  suppression hit the per-peer destination through the Adj-RIB-Out
  seeded from that baseline on a grouped→ungrouped move. A member that
  is dirty when it regroups now takes the suppression-free dirty
  resync (full-table over-announce — announces are idempotent, the
  same safe direction as the existing plain-dirty arm) with the
  baseline keys riding its extra-(over-)withdraw residue, so the
  baseline's withdraw duty — including the retained-baseline union
  across a second regroup — is preserved exactly and nothing is
  suppressed against unconfirmed state. Clean members' regroup diffs
  are untouched and still suppress redundant announces. (LAN-346)
- **`TestPolicy` no longer panics on a candidate source that probes a
  dataset.** A dry-run source declaring and referencing a `dataset`
  compiles per the language (LAN-305) but has no file bindings inside
  the RPC; the handler previously hit the dataset-free
  `compile_policy` convenience and panicked. It now returns
  `INVALID_ARGUMENT` naming the unbindable datasets, mirroring the
  inline-compilation diagnostic. Found by the LAN-8 `unwrap()`/
  `expect()` audit of the wire, policy, api, cli, fsm, mrt, telemetry,
  bfd, and event-history crates — every other non-test site guards a
  compile-time-certain conversion or a locally provable, documented
  invariant. (LAN-8)
- **`unwrap()`/`expect()` audit of the transport, rpki, bmp, evpn, and
  evpn-linux crates.** Every non-test site was reviewed: none are
  reachable from network input or runtime IO — all remaining `expect()`
  calls guard compile-time-certain conversions or locally provable
  invariants, and the terse invariant messages were expanded to state
  what guarantees them. (LAN-8)
- **Durable config/journal writes are owner-only and symlink-safe.**
  The shared atomic-write primitive behind the config persister and the
  commit-confirm revert journal now creates its temp file with mode
  `0o600` (the journal embeds config snapshots, which may carry secrets
  such as TCP-MD5 passwords; a permissive umask previously left it
  world-readable) and resolves symlinks before writing, so a write
  through a symlinked config lands on the real file instead of
  replacing the symlink with a regular file. The boot-time
  commit-confirm revert likewise resolves the config path up front, so
  a symlinked config survives a revert with its symlink intact and the
  candidate saved aside next to the real file. Plain (non-symlink)
  paths behave exactly as before. (LAN-205)
- **Boot diagnostics distinguish a failed live rollback.** The
  commit-confirm revert journal records when an abort/timeout rollback
  failed at runtime (`rollback_failed`, absent in older journals and
  defaulting to false), and the boot-revert banner then states that the
  pre-restart on-disk state was uncertain instead of only the generic
  never-confirmed message. (LAN-205)
- **SIGHUP config edits limited to hot-applicable neighbor fields no
  longer rebuild the session.** The reload reconciler previously
  delete/re-added the session task for any changed static-neighbor
  field, bouncing an Established session even for a `description` or
  `log_level` edit that `docs/reload-matrix.md` classes as live.
  Changed neighbors are now partitioned by the reload-matrix impact of
  their changed-field set: an edit touching only hot-applied fields
  (`description`, `max_prefixes`, `gr_stale_routes_time`,
  `local_ipv6_nexthop`, `remove_private_as`, `log_level`, import/export
  policies and chains) applies in place — session task, TCP connection,
  and FSM untouched, with policy edits still driving Route Refresh and
  Adj-RIB-Out re-emit. Any session-reset or restart-required field in
  the same edit keeps the neighbor on the rebuild path, which applies
  the whole edit through one session reset. `remote_asn` and
  `peer_group` edits — previously unannotated because the matrix and
  the reconcile mechanics disagreed — are now classed as session
  resets in `rustbgpd --diff` / `rbgp config diff` output, matching
  the shipped behavior (an ASN edit rebuilds the session immediately
  under the new ASN; a peer-group reassignment rebuilds to re-resolve
  inheritance), and the reload matrix's `[[neighbors]]` section now
  documents the real diff key (`address`, `interface`) and the
  immediate-rebuild semantics of session-reset fields. (LAN-341)

- **`rbgp policy explain` no longer reports `not_seen` when the truth
  is a disabled cache or a missing session.** The explain RPC
  previously folded "no live session with this peer" and
  "`[policy.explain] enabled = false`" into the same synthetic
  `NOT_SEEN` as a genuinely unseen prefix. The response now carries
  distinct `CACHE_DISABLED` and `NO_SESSION` outcomes (additive enum
  values; sessions report their own cache flag, so a session built
  before an explain reload answers for itself). The CLI renders
  `cache_disabled` as an error with a config hint and `no_session` as
  "no live session with <peer>", both exiting nonzero — the question
  was not evaluated; `not_seen` keeps its exit-0 evaluated-answer
  semantics, and `--json` carries the distinct outcome values.
  (LAN-320)
- **Config diffs render operator values, impact classes, and a plan
  summary instead of Rust debug output.** `rbgp config diff` /
  `config plan` / `rustbgpd --diff` no longer leak `Some(90) →
  Some(30)` into field change lines: values render bare (`hold_time:
  90 → 30`), absent optionals render `(unset)`, and secret-bearing or
  inline-policy fields stay summarized as `<changed>`. Each changed
  neighbor / peer-group field is annotated with its reload-matrix
  impact class (`[hot-applied]`, `[session reset: OPEN renegotiation]`
  / `TCP re-establish` / `session re-establish`, `[restart required]`),
  and the diff ends with a rollup line (`Plan: 1 to add,
  1 to change · 1 session will reset`). The JSON diff's `changes`
  entries are now structured objects with the stable key set `{field,
  old, new, impact}` (honest `null` for absent values and unknown
  impact) plus a top-level `summary` object with neighbor counts,
  `sessions_will_reset`, and `restart_required`. `rbgp config diff`
  and `config plan` adopt detailed exit codes documented in `--help`:
  0 = no changes, 1 = error, 2 = changes present (a separate contract
  from the `rbgp diff` route diff). (LAN-321)

- **`rbgp` errors are now actionable.** Connect failures name the
  endpoint the CLI actually dialed and the failure class (`cannot
  reach rustbgpd at unix:///var/lib/rustbgpd/grpc.sock (socket does
  not exist)`, connection refused, permission denied, timed out) plus
  a hint pointing at `-s`/`RUSTBGPD_ADDR`, instead of the flat "daemon
  is not running or unreachable". gRPC status codes map to short
  lowercase prefixes (`precondition failed:`, `invalid argument:`,
  `permission denied:`, ...) instead of tonic's sentence-length code
  descriptions. Daemon-side config persistence failures name the file
  being written (`failed to write /var/lib/rustbgpd/config.toml: ...`)
  rather than a bare os error. Lifecycle commands (`config
  apply`/`confirm`/`abort` with a confirmed-commit window, `neighbor
  add`/`disable`, `gshut`) print a one-line `next:` footer on stderr
  with the natural follow-up command; footers are suppressed under
  `--json` so machine output stays pure JSON. (LAN-317)

- **Policy reinstallation is scoped to peers whose resolved chain
  content actually moved.** SIGHUP reloads, rpol overlay swaps, catalog
  edits, and live-impact transactions re-resolve every affected peer's
  chains, but previously reinstalled them even when the resolved
  content was identical (`PolicyChain` content equality — the same
  keying the update-group registry uses). A content-equal reinstall now
  sends nothing: the session keeps its import chain instance (no
  install-generation bump, no term-hit counter reset on peers an
  unrelated edit never touched) and the RIB keeps its export chain
  instance, so a grouped peer's export term-hit counters — accumulated
  through the group's shared staging handle — keep counting instead of
  freezing behind a fresh snapshot instance the stats query reads.
  Peers whose chain content did change get exactly the previous
  behavior: session installs, RIB replacement, regroup, counter reset,
  and Route Refresh. (LAN-311)
- **The gRPC `Route` message now marks MED absence honestly.** A new
  optional `med_attr` field (mirroring `local_pref_attr`) distinguishes
  "no MED attribute" from "MED 0", which the bare 0-defaulted `med`
  field conflates. `rbgp` route tables render an absent MED as `-` and
  route JSON as `null` when the daemon populates the field (older
  daemons keep the bare-field rendering), and `rbgp diff` compares MED
  exactly against such daemons — an explicit MED 0 in a snapshot now
  diffs clean against a live MED 0 — dropping the MED-conflation caveat
  from `live_source_notes`; the caveat and the med=0-as-absent mapping
  remain only for daemons without the field. (LAN-313)

- **Fatal RTR errors now flush the affected cache's data and emit Error
  Reports per draft-ietf-sidrops-8210bis-26, instead of retaining until
  expiry.** Every session-ending event is classified retain-vs-flush:
  ordinary transport loss, Cache Restart (Error Report code 12, §8.5),
  Cache Reset, and the unsupported-version fallback (code 4) keep the
  cache's validated data until the expire interval as before, while
  fatal evidence the cache epoch is invalid — a session-ID mismatch
  (§5.1) or a received fatal Error Report, Cache Shutdown (code 13,
  §8.6) in particular — now removes that cache's VRPs and ASPAs from
  the merged tables immediately (other caches' data is untouched, and
  route validation re-runs exactly as at expiry). The client also
  transmits Error Reports where the draft requires or permits them —
  code 0 on session-ID mismatch, 4/8 on unsupported/unexpected protocol
  versions, 5 on unknown PDU types, 9 on invalid ASPA provider lists
  (§5.12), and 10 on stalled transfers — sent best-effort before the
  session drops, and never in response to a received Error Report
  (§5.11). (LAN-314)
- **A Serial Notify received before RTR version negotiation completes no
  longer fails the session.** Per draft-ietf-sidrops-8210bis-26 §5.2/§7,
  a cache may send a Serial Notify at any time — including between the
  router's first query and the response that opens the session — and the
  router must ignore it regardless of its Protocol Version field. The
  client previously applied the negotiated-version guard to every PDU,
  so a differently-versioned Serial Notify in that window (e.g. from a
  version-0 cache, or a v2 notify during a v1-pinned reconnect) tore the
  session down before negotiation could complete. Serial Notify frames
  are now discarded while negotiation is pending — a correct-version
  notify is equally a no-op, since the query it would trigger is already
  outstanding (§7) — and the version guard applies from the cache's
  first response PDU onward, preserving the post-negotiation
  unexpected-version handling (Error Report code 8) and the held-epoch
  version pinning on reconnect. (LAN-314)
- **Malformed ASPA announcements are rejected instead of poisoning the ASPA
  table.** Per draft-ietf-sidrops-8210bis-26 §5.12 ("ASPA Provider List
  Error"), an ASPA announcement carrying no Provider ASNs — previously
  stored as an empty provider set, turning every route through that
  customer AS ASPA-Invalid — or carrying AS 0 among multiple providers now
  fails the transaction and drops the cache session (retention semantics
  unchanged). The legal single-provider AS 0 "no providers" attestation
  stays accepted. (LAN-243)
- **The RTR client enforces draft-ietf-sidrops-8210bis-26 PDU, timer, and
  ASPA-shape acceptance limits.** A PDU whose Length field exceeds 65,535
  octets (a §5 MUST NOT; previously accepted up to the 256 KiB read
  buffer) is now rejected as corrupt framing with Error Report code 0.
  End of Data timing parameters are bounded to their §6 legal ranges:
  values above the maxima (refresh 86400 s, retry 7200 s, expire
  172800 s) are clamped down with a warning — expire in particular can no
  longer exceed the two-day ceiling the draft sets on data retention —
  while an expire below the 600 s minimum is honored as-is (expiring
  early is safe) and a refresh/retry not below the expire interval is
  lowered under it per the §6 relationship rule; zero-valued fields keep
  meaning "not provided". ASPA PDU shape checks now also reject
  announcements whose provider lists are not strictly increasing
  (§5.12: increasing numeric order, each provider unique) and
  withdrawals carrying any provider list (PDU length other than 12),
  both with Error Report code 9 and the offending PDU embedded.
  Duplicate-announcement (code 7) and withdrawal-of-unknown (code 6)
  detection remains unimplemented — the client does not hold the
  per-cache active record set — and is documented as a deviation in
  docs/RFC_NOTES.md. (LAN-314)
- **A v1-fallback RTR cache restart caused a validation blackout at data
  expiry instead of an immediate re-fallback.** After a v1 session (e.g.
  StayRTR) dropped, the client re-probed protocol v2 on every reconnect;
  a v1-only cache answers that with a version-0 Error Report, which fails
  the session version check before any fallback signal can fire — and
  with data held, the fallback path was unreachable. The client looped on
  version-mismatch retries for the whole expire interval, dropped the
  held VRPs ("cache server down"), flapped validation to `not_found`, and
  only then re-landed v1. The client now reconnects at the version the
  held epoch was validated under, so a downgraded cache restart re-lands
  its v1 session within one retry interval with full retention; v2 is
  deliberately re-probed at the epoch-less points (initial start and
  after data expiry), so a cache that later gains v2 support is still
  discovered. A Serial Query rejected with an Error Report (StayRTR
  answers an unknown session with "Session ID mismatch" error code 0
  rather than a Cache Reset) now also drops the dead epoch — data and
  expiry retained — so the next retry resynchronizes with a full Reset
  Query instead of re-sending the same rejected query. (LAN-312)
- **Update-group members that were outbound-dirty when a unicast source flip
  staged onto them could permanently retain the displaced route on the wire.**
  An already-dirty grouped member never runs the per-member source-flip matrix
  (its pass takes the resync arm), and a flip onto the member keeps the key in
  the group table — invisible to the withdrawal tombstones — while the resync
  announces only `table ∖ own-sourced`, so the member-scoped withdraw of the
  displaced route was silently dropped and the stale route survived until
  session flap. Shared staging now records those member-scoped withdraws into
  the member's extra-withdraw residue for every already-dirty member; the
  record also survives a regroup (the regroup baseline snapshot excludes
  own-sourced keys and could not cover it either), and the resync retention
  guard still drops it if the source flips back before the resync runs.
- **EVPN Type 1/2/4 origination is acknowledgement-aware.** The local Type 2
  MAC/MAC+IP originator and the Ethernet Segment orchestrator's Type 1
  EAD/Type 4 publication treated send-success as done: a dropped RIB reply,
  an ack timeout, or a rejection was only logged, permanently diverging the
  originator's state from the RIB (the Type 5 originator already gated its
  state on acks; Types 1/2/4 now match). Every inject/withdraw is tracked as
  pending under `(route identity, generation)` until the RIB acknowledges it;
  unacknowledged operations retry with bounded exponential backoff (1 s
  doubling to a 30 s cap), newer intent for the same route supersedes older
  pending work, stale acknowledgements are ignored, and withdrawals are never
  forgotten until acked (a `NotFound` rejection counts as done — the route is
  already absent). Nothing is persisted: a restart rebuilds intent from
  kernel/config observation and reconciles idempotently. The MAC+IP path's
  unmatched pending-IP-binding buffer is now bounded (4096 MAC entries, 16
  IPs per MAC). See ADR-0102. (LAN-293)
- **BFD actor bounds its receive work and publishes remote-AdminDown flips
  while already Down.** A packet flood could pin the BFD socket actor in its
  drain loop, starving timer ticks and the shutdown command; each actor turn
  now reads at most a fixed budget of datagrams (garbage counts too), due
  timers fire ahead of pending packets, and shutdown always preempts. The
  BFD→BGP coupling channel no longer grows without bound under a state-change
  burst: it coalesces per peer (latest state wins; a pending real transition
  is never masked by a reconcile ack), bounding it by the session count. And a
  remote `AdminDown` transition while the local session is already Down — the
  reason for being down changing, without a local state transition — is now
  published to the BGP coupling layer instead of being swallowed, so RFC 5882
  §4.1 "peer disabled BFD" handling (and its reverse) applies even from the
  Down state. (LAN-285)
- **Commit-confirm recovery now fails safe through ambiguous transaction
  outcomes.** A confirmed config transaction whose apply failed after the
  point of no proof — the persistence acknowledgement was lost, post-persist
  finalization failed, or a compound rollback failed — used to delete the
  boot-revert journal and reopen the config mutation fence as if nothing had
  committed, losing the only path back to the pre-transaction config. The
  journal is now retained and all further config mutations are rejected until
  a daemon restart boot-reverts (or the operator clears the journal). A failed
  abort or timeout auto-revert likewise no longer clears the fence: the
  transaction stays pending with an `ABORT_FAILED`/`AUTO_REVERT_FAILED`
  status, and the operator resolves it by retrying the abort, confirming the
  candidate, or restarting. Previously a second mutation accepted after such a
  failure could be silently clobbered by the retained journal's boot revert.
- **A rejected `.rpol` reload no longer publishes the candidate registry to
  the runtime snapshot.** When a SIGHUP/apply reload carried `.rpol` changes
  and the peer manager rejected the sync (e.g. a chain failed to re-resolve
  mid-apply), the reload's returned snapshot already carried the candidate
  registry — so sessions created after the failed reload resolved policies
  against the REJECTED registry while existing sessions kept the old one
  (split-brain). The runtime snapshot now adopts the candidate only after the
  peer manager commits it; on rejection every session — existing and new —
  keeps resolving against the last-successfully-applied registry, and the
  operator's `.rpol` files survive on disk as intent for the next successful
  reload. (LAN-284)
- **RTR client models cache state as one epoch and retains data through
  reconnect.** The RTR (RFC 8210/8210bis) client tracked protocol version,
  session ID, and serial loosely, so a version downgrade or session-ID
  change mid-stream could mix records from different cache states, and any
  disconnect or Cache Reset immediately flushed the cache's validated VRPs
  and ASPAs — flapping route validation on every reconnect. Cache state is
  now one per-cache `(version, session ID, serial)` epoch advanced only at
  a validated End of Data; Cache Response / End of Data identity mismatches
  and RFC 1982 serial regressions force a full Reset Query resync instead
  of splicing; validated data is retained through reconnect, version
  fallback, and Cache Reset until a full replacement completes or the
  expire interval passes; every received PDU must carry the negotiated
  version; ASPA updates now follow 8210bis replacement semantics (announce
  replaces the customer's provider set, empty-provider withdraw removes the
  customer ASN — previously sets merged and could never shrink); and each
  RTR transaction is bounded by a wall-clock deadline plus record and byte
  budgets so a broken or malicious cache cannot wedge or OOM the client.
  (LAN-281)
- **EVPN Linux dataplane: foreign-state ownership preflight and revalidation.**
  The reconciler could `replace` over — or delete — a same-key kernel row it
  did not own: an operator/other-agent FDB row, VRF route, L3 neighbor, or
  L3VXLAN FDB row that occupied (or took over) an exact key rustbgpd wanted.
  Every L2/L3 write path now fails closed when a foreign row holds the key
  (level-triggered: the install resumes once the foreign row goes away),
  ownership is relinquished when a live snapshot shows a foreign writer
  replaced an owned row (no "repair" back over it), and deletes during
  withdrawal, `NotReady` drain, and shutdown are revalidated against a live
  snapshot so foreign rows always survive rustbgpd's teardown. Observability:
  warn-once transition logs plus new `evpn_foreign_replaces_blocked_total`,
  `evpn_foreign_deletes_skipped_total`, and
  `evpn_foreign_owned_relinquished_total` counters. (LAN-283)
- **EVPN Linux dataplane: reserved NHID ranges are now an enforced
  single-writer contract.** rustbgpd's kernel nexthop-ID tag ranges
  (`0x3000_0000`/`0x4000_0000` L2, `0x5000_0000`/`0x6000_0000` L3VXLAN) are
  documented as exclusively rustbgpd-owned (`docs/deployment.md`), and the
  startup-adoption and drift-recovery dumps now validate the shape of every
  in-range object (FDB flag, member-vs-group structure matching the tag)
  instead of silently dropping unexpected ones — previously a co-resident
  writer's mis-shaped object in the range was invisible to the allocator, so
  a later allocation could `NLM_F_REPLACE`-clobber it, while an FDB-flagged
  one could be adopted and reaped. Shape conflicts now fail closed per ID:
  the object is left untouched, excluded from adoption and every reap/delete
  path, its ID quarantined so the allocator never hands it out, with a
  warn-once log and a new `evpn_foreign_nhid_range_conflicts_total` counter.
  (LAN-290)

- **LLGR lifecycle is now per-AFI/SAFI and honors the original Long-Lived
  Stale Time through reconnects (RFC 9494).** LLGR stale deadlines are
  tracked per (peer, AFI, SAFI) instead of one peer-wide minimum, so a
  family with a longer negotiated stale time is no longer purged when a
  shorter-lived family's timer fires; each family sweeps on its own
  deadline. A family's deadline is stamped once when it enters the LLGR
  stale phase and survives re-establishment while routes remain
  LLGR-stale: a peer that reconnects during LLGR and goes down again
  re-uses the surviving deadline instead of restarting the timer, and
  LLGR-stale routes are retained (not purged) across consecutive resets
  until that original deadline expires — End-of-RIB for the family retires
  it. Also documented and pinned two deliberate LLGR export behaviors:
  transport's LLGR-stale export form detects staleness by the `LLGR_STALE`
  community (superset of the flag — it also catches upstream-tagged
  routes) with a regression test proving flag/community coupling across
  the Adj-RIB-In mutation paths, and EVPN GR-stale routes intentionally
  continue to be exported during the GR window (RFC 4724) rather than
  triggering VXLAN flood-and-relearn churn. (LAN-282, LAN-191)
- **Outbound saturation teardown: Cease is the final frame, and cleanup runs
  from the run loop.** When a peer stopped draining and the bounded writer
  queue filled (`Cease/8` Out-of-Resources teardown), the writer drained the
  entire queued UPDATE backlog *after* the NOTIFICATION — delaying the close
  for as long as the peer stayed slow, and sending frames a peer must never
  see after a NOTIFICATION — and then exited cleanly, so `TcpConnectionFails`
  was never driven: the FSM stayed Established with no TCP connection and the
  RIB kept the dead peer registered. The writer now discards the backlog
  outright, flushes the Cease best-effort within a short bound (racing any
  wedged in-flight write without ever splicing a frame), hard-closes, and
  exits with a distinct status that the session run loop maps to
  `TcpConnectionFails` → FSM `SessionDown` → RIB `PeerDown`/deregistration,
  exactly like a real TCP failure.
- **Proof-harness assertions fail closed on missing/errored inputs.** The M37
  local-origination harnesses no longer treat a failed/errored FRR query
  (unreachable vtysh, docker exec error) as evidence of route absence, and
  the churn soak records `nan` instead of `0` when the consumer query fails;
  the Gate 8b analyzer's DF-counter monotonicity gate now requires numeric
  samples to be present (all-missing/non-numeric columns fail with a clear
  message instead of passing vacuously); the M33 soak analyzer rejects a
  samples CSV whose expected columns are missing instead of silently gating
  on all-zero deltas.
- **EVPN MAC Mobility sequence numbers saturate at `u32::MAX` instead of
  wrapping.** RFC 7432 leaves sequence wrap undefined; outbidding a received
  `u32::MAX` with a naive `+1` would have overflowed (panic in debug builds,
  wrap to 0 in release — and a wrapped 0 loses every §15 comparison, flapping
  forever). Every sequence increment in the MAC-only and MAC+IP origination
  state machines now saturates at `u32::MAX`: a received `u32::MAX` is
  unbeatable-by-increment, rustbgpd originates at `u32::MAX` too, and the
  RFC 7432 §7.7 lowest-VTEP-IP tiebreak becomes the standing resolution —
  the MAX-vs-MAX tie stays quiet instead of re-emitting the same sequence on
  every remote event. (LAN-287)
- **Reload classification and listener/shutdown truth.** Four daemon-truth
  fixes: (1) `[security.grpc]`, `[event_history]`, and `[managed_netdevs]`
  edits are now classified restart-required — SIGHUP/apply pins the runtime
  snapshot back to the live startup values with an explicit restart-required
  error (the operator's edit survives in the on-disk config), and the first
  two now appear in the `--diff` / transaction-plan restart-required buckets
  alongside `[managed_netdevs]` instead of silently drifting the in-memory
  snapshot. (2) The two peer-manager→RIB reply awaits on the reload/apply
  path (per-peer outbound refresh after a graceful-shutdown toggle,
  export-policy swap) are now bounded by a 5 s deadline that surfaces a clear
  error instead of hanging the reload forever behind a wedged RIB task.
  (3) A BGP listener bind failure at startup now turns `/readyz` red with
  `BGP listener failed to bind` (previously the daemon ran silently
  unreachable for inbound sessions behind a lone warning). (4) Coordinated
  shutdown flips the availability gate first: readiness goes red, persisted
  config mutations are rejected, and new inbound BGP connections are dropped
  before any teardown begins, instead of admitting work into it. (LAN-286)
- **BMP Loc-RIB dumps are fenced per collector connection and serialized
  against the live stream.** On a collector reconnect, the previous
  connection's in-flight table dump kept running and could interleave with
  the new connection's stream — an older dump announcement could follow a
  newer live withdrawal, leaving the collector with a route that no longer
  exists. Each collector connection now carries a generation: reconnect (and
  disconnect) cancels the stale dump task, which additionally re-checks its
  generation before every send. Live Loc-RIB messages for a collector are
  held back while its initial dump streams and flushed after the dump's
  End-of-RIB, so the wire order is always dump rows (point-in-time snapshot)
  → EoR → live deltas from that point. (LAN-289)
- **BMP Loc-RIB dump timestamps are the stored install time, not a
  reconstruction.** Dump entries used to recover the RFC 9069 per-peer
  header timestamp from the monotonic receive instant (`now − elapsed`),
  which skews after an NTP step between install and dump. The Loc-RIB now
  records the wall-clock install time when a best changes, and both the live
  tap and the table dump report that exact stamp — the same route carries an
  identical timestamp in both views. The fabricated Loc-RIB OPEN's
  infallible encoding is now backed by an explicit bounded-size test on the
  declared family set instead of an unproven `expect`. (LAN-193)
- **RIB route listings are bounded, resumable, and never silently
  truncated.** `ListReceivedRoutes`/`ListBestRoutes`/`ListAdvertisedRoutes`
  used to materialize the full table out of the RIB task per call and
  filter/slice it in the API layer with numeric-offset tokens; filtering and
  pagination now run inside the RIB task as bounded resumable queries
  (opaque last-key cursor, per-page allocation capped at 1000 rows, the same
  mutation-robust cursor step as the BMP Loc-RIB dump), and a canceled gRPC
  request whose page query is already enqueued is skipped before any scan.
  `rbgp best` / `rbgp rib received` / `rbgp rib advertised` used to silently
  truncate at 100 rows; they now paginate transparently until the listing
  completes. Canceled on-demand MRT dump requests are likewise skipped
  before the RIB snapshot, encode, and file write. (LAN-288)
- **rpol `apply` composition is bounded before lowering, and the
  non-attributed evaluation path no longer clones policy names.** LAN-184
  bounded parser recursion; `apply` inlining was the remaining unbounded
  surface — a legal apply DAG (no cycles) can still multiply the inlined
  predicate exponentially, so a SIGHUP-supplied file could pin the compiler
  or overflow the lowering stack. The typechecker now rejects compositions
  deeper than 8 `apply` levels or expanding past 100k IR nodes, with one
  root-cause diagnostic per offending policy (dependents don't cascade);
  evaluation stays flat — `apply` is compile-time inlining, never a runtime
  call. Separately, every chain evaluation cloned the terminal policy's
  name for attribution even on the hot per-route path that discards it; the
  non-attributed path now skips that allocation entirely. (LAN-290)
- **Extended Message (RFC 8654) directionality and per-type size limits.**
  The framing layer only accepted inbound messages over 4096 bytes when the
  PEER advertised the Extended Message capability — inverted: RFC 8654 §2
  ties inbound acceptance to OUR advertised capability (always sent), and
  the peer's capability only governs what we may send, which is now the sole
  thing it gates. NOTIFICATION and ROUTE-REFRESH size limits now follow the
  negotiated maximum in both directions (§3: extended messages apply to
  every type except OPEN and KEEPALIVE): an extended NOTIFICATION no longer
  fails to encode toward an extended-message peer, and a ROUTE-REFRESH with
  a large ORF section can no longer exceed 4096 bytes toward a peer that
  never advertised the capability. (LAN-290)
- **Partial managed-netdev creation now converges instead of wedging.** An
  ADR-0091 managed link create that failed between the netlink add and the
  `IFLA_ALT_IFNAME` ownership stamp used to strand an unstamped link the
  daemon would forever classify foreign-present; the failed create now
  deletes its own unstamped link before surfacing the error, so the next
  pass retries from absent. A link that *is* stamped but whose follow-on
  completion steps failed (SVD bridge VLAN/tunnel bindings, VLAN-upper
  admin-up) used to be treated complete-by-existence and/or permanently
  suppressed; the reconciler now re-emits the convergent create for
  exactly-ours stamped-but-incomplete links and classifies post-stamp
  completion failures as retryable. Transiently failed managed-netdev ops
  also wake the actor on their own backoff deadline (previously only
  FDB/BUM/AC-gate/NHG retries did). Finally, managed-netdev and FDB-NHG
  permanent-failure suppressions are pruned once the underlying intent is
  withdrawn — completing LAN-124's pruning, which covered the FDB and L3
  maps but left a withdrawn-then-re-added managed link or NHG member
  update suppressed until restart (and the stale NHG record kept the
  adoption-cleanup gate blocked). (LAN-290)
- **Destination-less FlowSpec rules no longer fabricate `0.0.0.0/0` in the
  export policy context.** A legal FlowSpec rule without a destination-prefix
  component was presented to export policy as an IPv4 default route — for
  IPv6 rules too — so exact-match `0.0.0.0/0` policy terms spuriously matched
  (and could suppress or admit) rules that carry no destination at all. Such
  rules are now `prefix = None` in the policy context, matching the import
  path and the BGP-LS prefixless-context convention; rules that do carry a
  destination prefix still evaluate it unchanged. (LAN-291)
- **Published artifacts now match the benchmarked build.** The GHCR
  runtime image and the release tarballs previously shipped without the
  `jemalloc` feature — and the image additionally used the fast CI
  profile (`lto = false`, `codegen-units = 16`) — while every published
  benchmark is measured on a fat-LTO `--release` build with jemalloc as
  the global allocator. Both artifacts are now built `--release
  --features jemalloc`; the `dev` interop image keeps the CI profile
  for lab build speed. jemalloc builds also export allocator gauges on
  the Prometheus endpoint, refreshed at scrape time:
  `jemalloc_allocated_bytes`, `jemalloc_active_bytes`,
  `jemalloc_resident_bytes`, and `jemalloc_mapped_bytes`. (LAN-331)
- **Interop CI no longer re-downloads its flakiest setup artifacts every
  run.** The containerlab `.deb` is cached via `actions/cache` keyed on the
  pinned version (warm runs skip the download entirely; cold runs keep the
  #208 retry + `dpkg-deb` validation), and the M43 BIRD 3.2.1 TCP-AO image
  build now uses the buildx GHA layer cache, so the bird.nic.cz tarball
  fetch and source compile are skipped on warm runs. (LAN-252)

## [0.50.0] — 2026-07-05

### Added

- **`rbgp doctor` support bundle and familiar CLI aliases.** `rbgp doctor`
  writes a redacted support bundle for issue reports
  (health/global/metrics/environment/manifest, plus the neighbor list and a
  bounded recent slice of session-lifecycle and policy events) — it never
  copies the daemon config file or bearer-token material. New visible aliases match common
  operator muscle memory: `rbgp summary` (neighbor list), `rbgp rib recv
  <peer>` / `rbgp rib sent <peer>`, and `rbgp policy counters`. A slimmed
  README now links deep first-run/limitations content to `docs/QUICKSTART.md`
  and `docs/LIMITATIONS.md`, with new route-server operator and config-knob
  contributor guides.
- **EVPN #268 decomposed-apply fail-stop observability
  (`evpn_runtime_decomposed_fail_stops_total`).** When a decomposed
  `ApplyEvpnRuntime` fails mid-sequence — an earlier primitive step
  committed its generation and a later one pinned the coordinator with
  `mutation_state=Failed` — the daemon now increments a counter next to
  the existing ERROR log. The commit message reports the number of
  steps that actually committed (no-op steps no longer inflate the
  count), and a `Failed` single-shot converge logs that decomposition
  was skipped (only `Unsupported` mixes decompose). (LAN-215)
- **Observability for discarded malformed BGP-LS NLRIs (RFC 9552 fault
  management).** Known BGP-LS NLRIs with out-of-order descriptor TLVs are
  isolated and dropped while the session survives (PR #616); that discard was
  previously silent. The decoder now reports the recoverable-discard count up
  to the session, which increments a per-peer
  `bgp_bgpls_nlri_discarded_total{peer}` counter and emits a `family=bgp_ls`
  debug log line. Fatal BGP-LS framing/length errors stay fatal and are never
  routed through the counter. Closes LAN-135.

- **Durable commit-confirm: a restart inside the confirm window now
  reverts at boot instead of making the unconfirmed config permanent
  (ADR-0076 Decision 6 amendment).** Before a confirmed transaction
  commits, the daemon atomically journals the pre-commit config
  snapshot, confirm handle, and deadline to
  `<runtime_state_dir>/commit-confirm-journal.json`
  (write-tmp+fsync+rename+fsync-dir); confirm, abort, and timeout
  auto-revert consume the journal, and a failed rollback deliberately
  retains it. At startup, an unconfirmed journal triggers a boot-time
  revert BEFORE the on-disk config is adopted — regardless of remaining
  confirm time, per NETCONF (RFC 6241 §8.4) cancel-on-session-loss
  semantics — restoring the pre-transaction config to the config file,
  saving the unconfirmed candidate aside as `<config>.unconfirmed`, and
  logging a loud ERROR + banner notice
  (`config_transaction_lifecycle{operation="boot_revert"}` metric). A
  torn/unreadable journal or an unusable embedded config refuses boot
  naming both files (fail closed). Applies to both the gRPC
  `ApplyConfigTransaction` and gNMI commit-confirmed paths (shared
  controller). Proven by real-binary SIGKILL-mid-window integration
  tests (`tests/commit_confirm_binary.rs`); closes the KNOWN_ISSUES
  "commit-confirmed does not survive a daemon restart" row.

- **RFC 8097 origin-validation-state extended communities as policy
  well-knowns.** `OV_VALID` / `OV_NOT_FOUND` / `OV_INVALID` (RFC 8097:
  non-transitive opaque, type `0x43` sub-type `0x00`, validation state
  in the last octet) are accepted everywhere community names are: TOML
  `match_community` / `set_community_add` / `set_community_remove` and
  `.rpol` `has` / `in` (community sets) / `add ext-community` /
  `remove ext-community`, with matching and removal by exact wire
  value. The route-server example's `hygiene.rpol` now tags routes
  with their RPKI outcome so clients can act on it (the missing
  arouteserver-essentials piece from ADR-0101).
- **Strict next-hop matching in `.rpol`:** `route.next-hop ==
  peer.address` (and `!=`) — the policy-language form of the classic
  IXP next-hop-hygiene check. It is the language's only field-vs-field
  comparison; anything else on the right-hand side is a compile-time
  diagnostic. Reads peer identity, so an export chain using it makes
  the peer ineligible for update-group sharing
  (`policy_peer_context`), exactly like `peer.*` matches; import-chain
  use is grouping-irrelevant. Never matches when either side is
  unknown.
- **Per-client best-path for route-server clients (RFC 7947 §2.3.2
  path-hiding mitigation, the BIRD-`secondary` equivalent).** New
  per-neighbor / per-peer-group knob `per_client_best = true` (requires
  `route_server_client`): when a member's export policy denies the
  Loc-RIB best, the route server advertises the best *permitted*
  candidate instead of hiding the prefix — selected per member at
  distribution time (no shadow per-client Loc-RIBs), staged at
  `path_id 0` so Adj-RIB-Out, BMP RIB-Out, and `ListAdvertisedRoutes`
  keep the single-best shape. Families with negotiated Add-Path send
  keep using Add-Path (the capability outranks the fallback). The
  member sourcing the best gets the runner-up (split horizon inside the
  collector). Churn contract test-pinned against the OpenBGPd
  `rde evaluate all` bug class: unchanged filtered best ⇒ no
  re-announcement, filtered-best flips ⇒ implicit replace (no spurious
  withdraw+announce), no-op policy reload ⇒ zero wire churn.
  Per-client-best peers fall back from update-group sharing with a new
  `per_client_best` ungrouped reason. Exposed end-to-end: TOML +
  inheritance + validation, gRPC (`NeighborConfig`/
  `PeerGroupDefinition`/`NeighborState`), `rbgp neighbor add
  --per-client-best` + show/JSON, config persistence, reload matrix
  (live, effective next session).

- **Route-server profile polish (ADR-0101): truthful explain for
  per-client best-path, distribution-mode display, and the refreshed
  IXP example.** `ExplainAdvertisedRoute` for a `per_client_best`
  member now dry-runs the same filtered-best candidate walk live
  staging performs — ranked candidate ladder with one verdict per
  denied candidate naming the deciding policy term ("candidate 1 of 2
  denied by export policy \"no-tagged:block-tagged\"") and the
  advertised runner-up, instead of the false "denied" the single-best
  dry-run could report. `rbgp neighbor show` names the unicast
  distribution mode (`single-best` / `add-path` / `orr` /
  `per-client-best`, also in JSON). `examples/route-server/` now shows
  both RFC 7947 §2.3.2 mitigations (member-alpha: Add-Path;
  member-beta: `per_client_best`), sets `role = "route_server"` on
  members (RFC 9234 OTC — dynamic/gRPC-added peers confirmed by test),
  and adds `hygiene.rpol` (reject-AS_SET via `route.as-path matches
  "\\{"`, reject-ASPA-invalid) with in-language tests runnable via
  `rbgp policy check`.

- **M83 interop receipt: RFC 7947 route-server profile, multi-stack
  (BIRD 2.0.12 + GoBGP 3.37.0 + FRR 10.3.1 + StayRTR) — the ADR-0101
  proof-ladder closer.** rustbgpd is the route server (AS 65500) for
  three member stacks with `route_server_client` + `role =
  "route_server"` per member and the examples/route-server hygiene/ROV
  import chain (`.rpol` + TOML mixed, RTR-fed). 46 assertions in a new
  `interop` CI job: RFC 7947 §2.2 transparency on all three client
  views AND at byte level (tshark on the RS↔BIRD link — no 65500 in
  any AS_PATH segment, NEXT_HOP = originator, MED + standard/large
  communities verbatim on the wire); RFC 9234 OTC toward members (wire
  attribute 35); per-member export views (`rbgp rib advertised`
  agreeing per member); ROV reject-at-import with `rbgp policy
  explain` naming the deciding term; the RFC 7947 §2.3 path-hiding
  contrast — the member whose export chain denies the Loc-RIB best
  gets NOTHING in single-best mode, gets the runner-up after a live
  `per_client_best` flip (SIGHUP + session bounce) with the explain
  ladder naming "candidate 1 of 2 denied", and the Add-Path member
  holds both candidate paths; runner-up withdraw convergence;
  EoR-after-flood ordering; withdraw propagation; session stability
  through a policy SIGHUP. First-AS relaxation per stack recorded in
  the script header (FRR: per-neighbor `no enforce-first-as`; BIRD:
  `enforce first as off`; GoBGP: no enforcement exists).

- **M82 interop receipt: EVPN VLAN-Aware Bundle (non-zero Ethernet
  Tag) route reflection — including rustbgpd's FIRST vendor-NOS interop
  leg (Nokia SR Linux 25.10).** The ADR-0092 Decision 6 proof ladder,
  both legs. Synthetic leg (new `interop` CI job, GoBGP 3.37.0):
  the RFC 7432 §6.3 bundle shape — one EVI, Ethernet Tags 10/20 with
  per-tag VNIs, the same MAC under both tags — is keyed by the RR with
  the tag as route identity (two distinct Type 2 entries for one
  (RD, MAC), per-tag IMET entries), surfaced via `rbgp evpn`, and
  reflected tag-verbatim (RD/etag/MAC/IP/label field-equal on the
  sink's re-decoded NLRI) with ORIGINATOR_ID + CLUSTER_LIST; a
  single-tag withdraw removes exactly that entry (26/26). Vendor leg
  (local lab, `m82-evpn-bundle-srlinux.clab.yml`): SR Linux in
  VLAN-aware-bundle interoperability mode (`vlan-aware-bundle-eth-tag`
  on two mac-vrfs, shared RT, the same static MAC in both bridge
  domains) originates real vendor non-zero-tag Type 2 + IMET routes;
  same assertion classes, 20/20. SR Linux quirks recorded in the lab
  fixtures: one EVI per mac-vrf enforced (bundle identity = shared RT +
  eth-tag, per-BD RDs) and the session requires an explicit
  `transport local-address` (otherwise SR Linux sources/accepts only on
  the system0 address). Receive/reflect proof only — bundle-mode
  origination and dataplane remain future ADR-0092 tranches.

- **Mixed EVPN runtime edits now hot-apply on SIGHUP via a plan
  decomposer ([#268](https://github.com/lance0/rustbgpd/issues/268)).**
  A candidate combining EVPN changes the ADR-0063 converger dispatch
  rejects as a single shape (e.g. an Ethernet Segment delete + its
  member L2VNI's redefine + a new L2VNI add in one edit) is now split
  into an ordered sequence of already-supported primitive plans —
  deletes → redefines → `ip_vrf` relink → adds — each applied through
  the unchanged converge path and each committing **its own runtime
  generation** (one SIGHUP / `ApplyEvpnRuntime` = N generations,
  visible in runtime snapshots and logs). Every step is validated up
  front, before anything commits; candidates the fixed order cannot
  express (relink away from a deleted IP-VRF, relink onto an added
  IP-VRF, an ES left memberless mid-sequence) and IP-VRF
  L3VNI/device/table identity redefines fail closed naming the
  offending step. A residual mid-sequence convergence failure is
  fail-stop: earlier generations stay committed (no cross-step
  rollback), the model pins, and re-SIGHUP after fixing converges only
  the remainder. `rustbgpd --diff` classifies decomposable mixed edits
  as reload-applied ("decomposed: N steps"). IP-VRF identity redefines
  stay restart-required by design (kernel VRF identity lifecycle); the
  rationale is recorded in the ADR-0063 amendment and
  docs/reload-matrix.md.
- **Routes served over gRPC now carry their receive time.** The
  `Route` message gains `received_at_epoch_seconds` (wall clock,
  recovered at query time from the monotonic RIB receive instant — the
  same recovery the RFC 9069 BMP Loc-RIB dump uses), populated by
  `ListReceivedRoutes` / `ListBestRoutes` / `ListAdvertisedRoutes` and
  the explain RPCs that embed `Route`. The birdwatcher adapter
  (`examples/birdwatcher-adapter`) now serves a real per-route `age`
  from it, closing its last field-level gap vs the deprecated
  in-daemon looking glass; the smoke test drives a live BGP session
  and pins non-empty age equality between the two servers.
- **`send_hold_time` (RFC 9687) is now settable over gRPC.**
  `AddNeighbor`'s `NeighborConfig` and `PeerGroupDefinition` gain an
  optional `send_hold_time` field with config-path validation parity
  (0 = disabled; non-zero must exceed the effective hold time; unset =
  the RFC 9687 §6 derived default), persisted like the config knob.
  `ListNeighbors` reports the effective value, `rbgp neighbor <addr>
  add` gains `--send-hold-time`, and `rbgp neighbor show` /
  `peer-group show` render it.

- **Export-side explain: "why did/didn't route X go to peer Y?" now
  gets a full, truthful gate-ladder answer.** `ExplainAdvertisedRoute`
  (and `rbgp rib advertised <peer> --explain --prefix X`) now reports
  every export gate in the exact order the live export path evaluates
  it — best-route, split horizon, RFC 4456 reflection, sendable
  family, RFC 9494 LLGR export restriction, RFC 5291 ORF (both the
  installed filter and the initial-advertisement gate), export policy
  (labeled `policy:term` for `.rpol` members via the per-term trace
  machinery), and the Adj-RIB-Out diff (`staged_announce` vs
  `already_advertised` = peer in sync) — each rung pass/stop/n-a with
  detail. A new `--rd` flag (request field `rd`) explains VPNv4/VPNv6
  (SAFI 128) identities instead, adding the RFC 4684 RT-Constrain
  membership gate. Truthfulness by construction: the explanation is a
  read-only dry run of the *same* staging body live distribution
  executes (`ExportTarget::Explain`), including update-grouped peers
  (explained against their group table; the response carries
  `update_group_id`), and never counts toward policy metrics or
  per-term hit counters. Response additions are purely additive
  (`gates`, `update_group_id`, `already_advertised`, `rd`); existing
  `reasons` output is unchanged. Completes the explain trilogy next to
  import explain (ADR-0073) and best-path explain.
- **RFC 9687 Send Hold Timer: a peer that stops draining its TCP socket
  can no longer wedge a session forever.** The per-peer writer task
  bounds each `write_all + flush` by the session's `SendHoldTime`;
  expiry tears the session down through the TCP-failure path —
  deliberately **without** a NOTIFICATION (the socket is not draining;
  §4.3 makes it optional) — with a `warn` log, a new
  `bgp_send_hold_expirations_total{peer}` counter, an event-history
  record carrying the RFC 9687 error code 8 ("Send Hold Timer
  Expired"), and a BMP Peer Down reason 2 (local close, no
  NOTIFICATION) with FSM event code 29 (`SendHoldTimer_Expires`).
  Enabled by default at `max(480, 2 × hold_time)` seconds per §6; new
  per-neighbor + peer-group `send_hold_time` knob (0 disables; non-zero
  must exceed the effective `hold_time` per §4.4, enforced at config
  load). Wire decode of NOTIFICATION code 8 gains a named variant.
  Detection is a per-write deadline rather than the RFC's free-running
  restarted-on-send timer — equivalent trigger, documented in
  `docs/RFC_NOTES.md` and `KNOWN_ISSUES.md`.

- **Update groups: shared outbound staging for the RR fanout
  (ADR-0098, #674/#676 + cold paths).** Outbound peers whose staged
  output is provably identical — same export-chain content, eBGP/iBGP +
  RR-client role, sendable unicast families, advertised LLGR families —
  now automatically share ONE staged outbound table: the export tail
  (reflection rules, policy eval, equality diff) runs once per group
  instead of once per peer, per-member updates derive from the shared
  delta by a source-flip matrix, and in-sync members enqueue one
  `Arc`-shared announce payload instead of per-member `Route` clones.
  Joins, initial dumps, RFC 2918 route-refresh responses, and
  advertised-routes/count/BMP-stat-17 queries replay or synthesize from
  the group table (no policy re-evaluation); per-peer unicast
  Adj-RIB-Out storage disappears for grouped members (one table per
  group + O(1) per member). Peers with peer-context policy, Add-Path
  send, ORR, or ORF keep the per-peer path wholesale — no config knob,
  and a differential oracle pins grouped output identical to the
  per-peer path. The SipHash outbound attribute-cache keys flagged in
  the same profile moved to FxHash (bounded-HashDoS tradeoff documented,
  mirroring the #308 route maps). Measured (rrharness, 100k routes ×
  256 uniform RR clients, same host): single-shot convergence 15.1 s →
  0.54 s (~28×), sustained flood 2×; staging+AdjRibOut falls from 82.8%
  to 30.5% of RR CPU and the pipeline is now substantially wire-bound
  (writer+syscall 21.8%). Membership is operator-visible: `rbgp
  neighbor show` Update Group line, `bgp_update_groups`,
  `bgp_update_group_members{group}`, `bgp_update_group_regroups_total`,
  `bgp_update_group_fallback_peers`. Proven at scale by the
  [1000-peer RR scale receipt](docs/perf/scale-receipt-2026-07.md)
  (same host, real transport sessions over loopback): 1000 uniform RR
  clients × 100k routes converge in 1.82 s wire-measured (~32× the
  pre-arc linear extrapolation of ~59 s) at 419 MiB whole-process RSS
  (vs an extrapolated 30–40 GB per-peer Adj-RIB-Out before the arc);
  an M80-style tagging chain on all 1000 clients costs +3%
  convergence / +8% RSS; churn sustains ~55,800 best-path flips/s to
  all 1000 clients with `recompute_best` at 1.6% of CPU (was 40–45%
  pre-#675); a 900-grouped + 100-fallback mixed fleet converges in
  8.4 s, pinning the fallback price at ~22 MiB per ungrouped peer.

- **Update groups v2: VPNv4/VPNv6 join the shared staging, with the
  RFC 4684 RT filter applied per member at emit (ADR-0099,
  #685/#686 + close slice).** The group key gains the VPN-sendable
  and RTC-negotiated dimensions (still one group per peer); grouped
  members' VPN routes stage once per group through the same
  parameterized export tail and fan out via an RT-aware source-flip
  matrix — a PE fleet with distinct RT memberships shares ONE group,
  because the per-member filter Φ is applied at emit and never keyed.
  A member's RT-membership change takes a zero-policy-eval
  membership-delta path: one walk of the group table emits the
  minimal RFC 4684 wire delta, table untouched. Joins, dirty resyncs,
  regroup snapshots, RFC 7313 VPN refresh, and adj-out/BMP queries
  are all Φ-aware; Add-Path send stays a structural disqualifier
  (recorded verdict: per-member path-id correction is unsound without
  per-member state) and per-vantage ORR grouping is cut pending
  demand. Also fixes a v2-slice-1 gap: a member-scoped withdraw
  (source flip onto the member, or a route mutating out of its Φ)
  lost to a full outbound channel now rides the member's
  extra-withdraw residue instead of stranding a stale route until the
  next covering event. Measured (rrharness, 100k VPNv4, same host,
  3-run medians; [scale receipt](docs/perf/scale-receipt-2026-07.md)
  Scenario E): uniform 256-client convergence 18.66 s → 3.75 s and
  RSS 8227 → 492 MiB; heterogeneous ~10%-Φ 256-client 3.21 s → 1.10 s
  / 1481 → 482 MiB; at 1000 clients 12.60 s / 625 MiB uniform and
  3.92 s / 636 MiB heterogeneous (vs ~73 s / ~31 GiB and ~12.5 s /
  ~5.7 GiB extrapolated per-peer); a one-RT membership flip at 100k
  staged routes delivers its 1600-route delta on the wire in ~15 ms
  (widen) / ~12 ms (narrow).

- **M81 interop receipt: the BMP trio + BMPv4, against real collectors.**
  New `interop` CI job (six-node containerlab): rustbgpd as RR reflecting
  unicast v4/v6 + VPNv4 between two GoBGP clients while streaming all
  three Route Monitoring views (`rib_in_pre` / `rib_out_post` /
  `loc_rib`) to four collector slots at once — pmacct pmbmpd
  bleeding-edge and gobmp (independent semantic v3 oracles,
  digest-pinned) plus a raw byte sink with one v3 and one v4 slot under
  tshark pcap capture. 50/50 assertions: the trio agrees on
  Initiation/PeerUp, the RFC 9069 loc-rib instance peer (type 3, table
  name `global`), rib-in-pre vs rib-out-post (RFC 8671 O+L flags) vs
  loc-rib for the same routes, an LP-contested best-path flip,
  withdraws, collector-reconnect table sync (dump + exactly 4
  End-of-RIBs), loc-rib type 8/10 stats gauges, PeerDown reasons,
  loc-rib PeerDown reason 6 + Termination at shutdown; BMPv4 is pinned
  byte-level — version byte on every message, single BGP Message TLV
  (type 7, index 0, length excludes the index), Stats TLV (code 1) wrap
  byte-matching the v3 stats body, Initiation/PeerUp v3-vs-v4
  byte-identical except the version byte, RM PDU sets byte-equal across
  the v3 stream and the v4 TLVs — and Path Marking is pinned on the
  wire (every live loc-rib announce marked `Best`, the contested winner
  carrying reason 0x0003 local-preference, status-only dump entries,
  nothing marked outside loc-rib). The lab's Phase-0 oracle matrix
  documents the ecosystem honestly: no shipped collector decodes
  tlv-20's final code points yet (pmacct bleeding-edge implements the
  pre-tlv-20 numbering and discards tlv-20 RMs despite a comment
  claiming tlv-20; gobmp hard-rejects version 4; released Wireshark
  tracks older TLV drafts), so v4 code points are asserted at raw-byte
  offsets against the drafts' wire figures with tshark scoped to what
  it honestly dissects.

- **BMP Path Marking TLV on Loc-RIB monitoring
  (draft-ietf-grow-bmp-path-marking-tlv-05, pre-IANA).** BMPv4
  (`version = 4`) collectors monitoring `loc_rib` now receive the Path
  Marking TLV on every Route Monitoring announcement (live best-path
  changes and the collector-connect table dump): a 4-octet Path Status
  bitmap marking the route `Best` (§3.1 — every Loc-RIB route is the
  decision winner by definition) plus `Stale` when the GR/LLGR stale
  machinery holds it, and — on live unicast announcements where a
  competing path was compared — the optional 2-octet Reason Code (§3.2)
  naming the decisive best-path step, re-derived at emit against the
  runner-up from the existing explain ladder (the hot-path comparator
  records nothing). Decisive steps without a registered draft code
  (stale/RPKI/ASPA preference, cluster-list length) omit the optional
  reason rather than mislabel it. Status bits a route reflector without
  a forwarding plane cannot attest to (Primary/Backup/Non-installed/
  Best-external/Filtered/Suppressed) are never fabricated; rib-in-pre
  (taps before best-path selection) and rib-out-post (per-peer staged
  output) streams carry no marking; withdrawals carry none (a gone path
  has no status). Automatic on v4 — no new knob; v3 output stays
  byte-identical (pinned by regression tests). **Type-code collision
  caveat:** path-marking-05 self-assigns RM TLV type 5, which
  draft-ietf-grow-bmp-tlv-20 §9 meanwhile assigned to the VRF/Table
  Name TLV — rustbgpd never emits that TLV so its own v4 output is
  unambiguous, but expect a renumber at RFC publication (annotated in
  `crates/bmp/src/tlv.rs`).

- **BMPv4 per-collector framing (draft-ietf-grow-bmp-tlv-20, pre-IANA).**
  New per-collector `version = 3 | 4` config field (default 3). A v4
  collector gets common-header version 4 on every message type (draft
  §3); Route Monitoring encloses the UPDATE PDU in the mandatory BGP
  Message TLV (type 7, index 0, §5.2) and Stats Reports enclose Stats
  Count + stats data in the mandatory Stats TLV (code point 1, §5.4);
  Peer Up/Down, Initiation, and Termination already provision TLV data
  in v3 and change only their version byte (§5.5). Internal BMP events
  stay version-agnostic — framing happens per collector at fan-out, so
  mixed v3/v4 collector fleets each get correctly framed messages and
  v3 output stays byte-identical (pinned by golden-bytes regression
  tests). Indexed-TLV (§4.3) and Group-TLV (§5.2.1, type 4) encode
  infrastructure lands with this slice for the upcoming path-marking
  TLVs. Draft code points are pre-IANA and may renumber at RFC
  publication; they live in one annotated module
  (`crates/bmp/src/tlv.rs`).

- **BMP Loc-RIB route monitoring with collector-connect table sync
  (RFC 9069).** New per-collector `monitor = ["loc_rib"]` view: the
  daemon streams its post-best-path Loc-RIB as Route Monitoring
  messages attributed to the emulated Loc-RIB instance peer (peer type
  3, own flags registry always 0, zero-filled peer address, Peer
  Distinguisher 0, Peer AS = local AS, BGP ID = local router-id,
  timestamp = route install time). Peer Up carries a fabricated OPEN
  (4-octet-ASN capability + one MP capability per streamed family,
  received OPEN a byte-identical repeat) and the VRF/Table Name TLV
  (`"global"`); Peer Down uses reason 6 with the TLV echoed; periodic
  stats add types 8 (Loc-RIB total) and 10 (per-AFI/SAFI). UPDATE PDUs
  are synthesized from the RIB (4-octet-ASN, no Add-Path); v1 synthesis
  covers IPv4/IPv6 unicast and VPNv4/VPNv6 — other Loc-RIB families
  land additively later and are deliberately absent from the fabricated
  OPEN. **Collector (re)connect now performs a table sync** — closing
  the RFC 7854 initial-sync gap: after the cached Peer Up replay, a
  `loc_rib` collector receives a chunked Loc-RIB dump (install-time
  timestamps) closed by one End-of-RIB per family, then the live stream
  continues seamlessly (dump/live overlap is the standard BMP race;
  collectors reconcile by prefix). The dump is produced by the RIB
  manager as a bounded chunked query and paced to the collector's TCP
  drain by a dedicated forwarder task — the RIB task and the BMP
  fan-out loop never block on a slow collector. Adj-RIB-In/Out streams
  remain live-only (see `KNOWN_ISSUES.md`).

- **M80 interop receipt: `.rpol` policy parity against FRR route-maps —
  the ADR-0096 arc closer.** New `interop` CI job (4-node containerlab):
  rustbgpd runs its whole policy surface from an `.rpol` file
  (`[policy] rpol_files`) while an FRR parity node expresses the SAME
  intent as route-maps / prefix-lists / community-lists; both receive
  one route matrix from a source FRR and export to a downstream FRR.
  29/29 assertions: route-for-route import parity (prefix-set ge/le
  boundary, community-set match, community add + remove, LOCAL_PREF
  set, as-path regex reject, a modify-then-continue term, and the same
  parameterized policy instantiated as `customer-in(200)` vs
  `customer-in(300)` for two peers) and export parity (the downstream
  compares MED/communities/deny on the rustbgpd path vs the FRR path,
  prefix by prefix); `rbgp policy check` runs the file's in-language
  tests (exit 0); `rbgp policy test` dry-runs a `customer-in(500)`
  candidate over the live RIB (counts, per-term hits, before/after
  diffs); `rbgp policy stats` shows nonzero live term hits; and an
  `.rpol` edit under traffic (LP flip + SIGHUP, m34 pattern) hot-applies
  with zero session flap, a wire-observed Route Refresh at exactly the
  one peer whose resolved chain changed (the content-identical policies
  on the other peer trigger nothing), and the new LP re-imported. No
  dataplane writes. Implementation record appended to ADR-0096; docs
  finalized (`docs/rpol-language.md` positioning vs BIRD/route-maps,
  comparison tables, README, ROADMAP true-up).

- **The `.rpol` language is now fully explainable through the existing
  surfaces.**
  `ExplainImportPolicy` statement traces cover `.rpol` chain members at
  term granularity: the step names the deciding term and carries one
  rendered line per evaluated term — `term NAME: GUARD => ACTION
  [matched|not matched]` — with guards pretty-printed back to `.rpol`
  surface syntax (sets by their source name; additive proto fields
  `term` / `term_traces`, rendered by `rbgp policy explain`). Guard
  evaluation is shared with the live evaluator and the trace is pinned
  against both `evaluate_with_attribution` and the counting evaluator
  by an rpol agreement matrix. `ExplainAdvertisedRoute` extends its
  policy attribution to `<chain-ref>:<term>` when the deciding export
  member is `.rpol` (TOML members unchanged). New **live per-term hit
  counters** (ADR-0096 Decision 3.3, the IOS-XR `show pcl` idea):
  every live evaluation bumps its matched terms' relaxed-atomic
  counters on the chain instance, surfaced by `rbgp policy stats
  [--peer ADDR] [--json]` via the new `GetPolicyStats` RPC
  (`SensitiveRead`). Counters read as since-chain-install and reset
  when a chain is replaced; explain queries and `policy test` dry runs
  never move them. V1 reads the export direction (the RIB manager owns
  those chains — and its distribution passes now share one compiled
  IR + counter set per installed chain instead of recompiling per
  pass); import-side counters accumulate but their read surface is a
  follow-up. See the explain/stats chapter in `docs/rpol-language.md`.
- **RFC 8671 post-policy Adj-RIB-Out BMP monitoring.** Per-collector
  `monitor = ["rib_in_pre", "rib_out_post"]` selection on
  `[[bmp.collectors]]` (default `["rib_in_pre"]` -- existing behavior
  unchanged). With `rib_out_post`, every outbound UPDATE --
  announcements, withdraws, and End-of-RIB markers across all address
  families -- is mirrored to the collector byte-exact as transmitted,
  with the per-peer header O flag (Adj-RIB-Out) and L flag
  (post-policy) set and the remote peer's identity / advertise-time in
  the header. Periodic Stats Reports now also carry the RFC 8671
  gauges: type 15 (post-policy Adj-RIB-Out total) and type 17 (per
  AFI/SAFI), sourced from per-peer Adj-RIB-Out sizes. The rib-out
  stream is live-only (no table dump on collector connect -- see
  KNOWN_ISSUES). Pre-policy Adj-RIB-Out is deliberately not
  implemented.

- **`.rpol` policies in the running daemon (ADR-0096 slice 3): config
  references, hot reload, and the `rbgp policy test` live-RIB dry
  run.** `[policy] rpol_files = ["policies/core.rpol"]` compiles every
  referenced file at config load (paths relative to the config file,
  rewritten absolute; ariadne-rendered compile diagnostics are load
  errors); the policies join the same namespace as
  `[policy.definitions]` (collisions are load errors naming both
  sources) and mix freely with TOML policies in chains, with
  parameterized policies referenced by call-form —
  `import_policy_chain = ["customer-in(200)", "bogon-filter"]` —
  arity- and type-checked at load and monomorphized into pre-compiled
  chain members. Chain identity for the ADR-0076 planner is compiled
  content: an edited `.rpol` file classifies as a `policy_chain`
  live-impact for exactly the referencing peers, and SIGHUP hot-applies
  it through a new `SyncRpolPolicies` peer-manager step (same atomic
  resolved-policy fan-out + Route Refresh as `[policy.definitions]`
  edits); reloading unchanged content is a no-op. Config transactions
  cannot stage `.rpol` file content (out-of-band files) — such
  candidates are rejected as unsupported, and gNMI Set remains
  TOML-surface-only. The differentiator verb: `rbgp policy test
  <file.rpol> --policy name(args) --direction import|export [--peer]
  [--family] [--limit] [--show-changes] [--json]` sends the candidate
  source to the daemon (new `PolicyService.TestPolicy` RPC,
  `SensitiveRead`), compiles it server-side, and evaluates it
  read-only over a live Adj-RIB-In / Loc-RIB snapshot — accepted/
  rejected/modified counts, per-term hit counters, and before/after
  attribute diff samples, with zero route/session/counter impact
  (V1 scope: IPv4/IPv6 unicast). Docs: `docs/rpol-language.md`
  ("Using policies in the daemon"), `docs/CONFIGURATION.md`.

- **The `.rpol` policy language frontend (ADR-0096 slice 2): lexer,
  parser, typechecker, in-language tests, and `rbgp policy check`.**
  `.rpol` source — `prefix-set`/`community-set` definitions (ge/le per
  member; standard/large/RT/RO literals), `policy` blocks with named
  terms and `u32` parameters, `if`/`else` guards over the full
  route/peer context (prefix, the three community kinds, AS-path
  len/contains/matches, local-pref/MED with the RFC 4271 implicit
  defaults, next-hop, RPKI/ASPA state, route-type, EVPN route type,
  peer address/ASN/group), `apply(policy)` composition (compile-time
  DAG check, no recursion), and `accept`/`reject`/`set`/`add`/
  `remove`/`prepend` actions — compiles into the existing public typed
  IR with match data interned through the shared `SetStore`.
  Parameterized policies are templates monomorphized at each use site;
  term fallthrough (modify-and-continue) lowers through a new surgical
  `TermAction::Continue` IR variant (the TOML frontend never emits
  it). Diagnostics are ariadne-rendered with labeled spans,
  multi-error recovery, and did-you-mean suggestions. In-language
  `test` blocks (route/peer fixtures + verdict/attribute expectations)
  run through the real IR evaluator; the new local-only
  `rbgp policy check <file.rpol>` verb (exit codes 0 clean /
  1 diagnostics / 2 test failures, `--json`) runs them with zero
  daemon involvement. Language reference: `docs/rpol-language.md`.
  Daemon integration (config wiring, `rbgp policy test`) ships in the
  slice-3 entry above.
  New policy-crate-only dependencies: `logos` (MIT OR Apache-2.0),
  `ariadne` (MIT).

- **Typed, compiled policy IR (ADR-0096 slice 1): indexed match sets
  behind the existing engine, zero behavior change.** TOML policy
  chains now lazily compile into a public, analyzable IR
  (`rustbgpd_policy::ir` — typed guard expressions, named terms,
  `CompiledPolicy`/`CompiledChain`) evaluated by a tree-walk engine
  behind the unchanged `evaluate_chain_with_attribution` choke point;
  all 14 import/export seams are untouched and existing configs behave
  identically. Match *data* compiles out of the expression tree into
  `Arc`-shared, content-deduplicated indexed structures
  (`rustbgpd_policy::sets`): prefix sets with ge/le ranges resolved in
  one hash probe per distinct member length, community/RT/RO/large
  criteria sets, and interned AS-path regexes — the OpenBGPd lesson
  that set-heavy policy cost lives in the index layer. In-repo
  measurement of the ADR's headline (`policy_eval.rs` `set_heavy`
  group): a 1,000-prefix list costs ~3.8 µs as a statement chain but
  ~14 ns as one IR set-match — ~270×. Realistic single/short-chain and
  short-circuit shapes improved 20-50% (the IR walks only configured
  predicates instead of checking ~18 optional fields per statement);
  the one measured step backwards is the walk-every-statement long
  chain (~5.2 → ~7.2 ns/statement, `policy_chain_eval/32` +27%), the
  tree-walk's And-children indirection — the ADR's deferred
  linearized-bytecode pass is the recovery path if that shape ever
  dominates a profile. The `requires_as_path_string` /
  `requires_rpki_validation` / `requires_aspa_validation` hot-path
  gates are reimplemented as IR analyses with identical results.
  Decision compatibility is pinned by a golden corpus
  (`engine/tests/ir_parity.rs`, ~4,500 chain×route cases asserting the
  legacy walker and the IR path return byte-identical `PolicyResult`
  *and* `PolicyEvaluation`); the legacy walker stays in-tree as the
  oracle until a later slice deletes it. The `.rpol` language frontend
  (lexer/parser/typechecker, `rbgp policy test`) arrives in later
  ADR-0096 slices — this slice is the IR substrate that makes them
  surface work.

- **IPv4/IPv6 labeled-unicast (RFC 8277, SAFI 4) route reflection — the
  ADR-0077 quartet is complete.** The last family of the ADR-0077 scope
  (BGP-LS, VPNv4/v6, RT-Constrain, labeled-unicast) ships as one complete
  vertical: MP_REACH/MP_UNREACH dispatch accepts (IPv4/IPv6,
  LabeledUnicast) with the RFC 8277 announce-mode codec and the §2.4
  withdraw-compatibility field (label values ignored on receipt; peers
  that echo the announced label stack instead are tolerated — see the
  label-stack-withdraw fix below); inbound ingest mirrors the VPN path (honest per-prefix policy
  context, loop-detection withdraw handling, `known_labeled` max-prefix
  accounting); reflection preserves the MPLS label stack and next-hop
  verbatim (ADR-0077 §4/§6 — next-hop-self is inert for SAFI 4, and a
  same-peer relabel re-advertises); and the family joins every existing
  lifecycle from day one: Add-Path (RFC 7911) receive + ranked top-N
  send, RFC 7313 BoRR/EoRR refresh-stale, RFC 4724 GR helper retention
  (not-in-capability withdraw, consecutive-restart deletion, EoR sweep),
  RFC 9494 two-phase LLGR with the §4.4/§4.6 export gate, RFC 9107 ORR
  per-vantage bests, initial dump + EoR, and dirty resync. Config takes
  `ipv4_labeled_unicast` / `ipv6_labeled_unicast` (OpenConfig names);
  gRPC `ListLabeledRoutes` at SensitiveRead and `rbgp rib labeled`
  (prefix / labels / next-hop / peer / path-id, `--json`) expose the
  Loc-RIB. RR-only: no label allocation, rewrite, or MPLS FIB install.
  M79 (GoBGP 4.6.0, hosted CI) is the real-peer receipt: reflection with
  labels/next-hop verbatim + ORIGINATOR_ID/CLUSTER_LIST (incl. a
  multi-label stack and a v6 next-hop over the v4 session), relabel
  implicit replace, multi-label withdraw with zero session flap, the
  RFC 4724 GR window + End-of-RIB sweep, and no dataplane install —
  40/40. The lab also caught the label-stack-withdraw session reset
  pre-CI (fixed below) and two GoBGP quirks recorded in
  `docs/upstream-findings.md`.

- **RFC 9494 LLGR-stale export gate (closes the last legacy GR/LLGR
  gap).** LLGR-stale routes are no longer advertised to eBGP peers that
  didn't advertise the Long-Lived Graceful Restart capability for the
  route's family (§4.4: stale routes "SHOULD NOT be advertised to any
  neighbor from which the Long-Lived Graceful Restart Capability has not
  been received") — every family's Adj-RIB-Out staging (unicast
  single-best/multipath/ORR, FlowSpec, EVPN, BGP-LS, VPNv4/v6 including
  each Add-Path candidate individually, RT-Constrain, plus the initial
  dump and route-refresh replay) suppresses them with the standard
  withdraw-if-present shape. Non-LLGR **iBGP** peers take the §4.6
  intra-AS exception instead: the route is advertised with NO_EXPORT
  attached and LOCAL_PREF set to zero — applied in transport's per-peer
  attribute rewrite — and the LLGR_STALE community rides through
  unchanged ("MUST NOT be removed when the route is further
  advertised"). This replaces the previous non-compliant behavior of
  stripping LLGR_STALE toward non-LLGR peers while still advertising
  the route. Receiver LLGR capabilities are plumbed from session
  negotiation into the RIB via `PeerUp`. LLGR-capable peers and all
  fresh-route advertisement are unchanged.

- **Add-Path (RFC 7911) for VPNv4/VPNv6 (SAFI 128).** The family-blind
  `add_path` knobs now cover the VPN families: negotiation advertises
  Add-Path for configured `l3vpn_ipv4_unicast` / `l3vpn_ipv6_unicast`
  alongside unicast, the wire codec encodes/decodes the 4-octet Path
  Identifier prepended to each SAFI-128 NLRI (announce mode and the RFC
  8277 §2.4 withdraw-compatibility mode alike), received path IDs are
  distinct Adj-RIB-In entries withdrawn independently per path, and an
  Add-Path-send peer receives up to `add_path_send_max` candidates per
  RD+prefix with outbound path IDs `1..=N` ranked by the VPN best-path
  chain — with the vantage-cost comparator for an RFC 9107 ORR client
  (Add-Path between RRs is what RFC 9107 requires for multi-cluster ORR,
  and VPN RR redundancy generally). Best-path selection and single-best
  reflection collapse per RD+prefix identity, so non-Add-Path peers are
  unchanged. BGP-LS and RT-Constrain keep their Add-Path rejections (no
  demand; RTC membership Add-Path semantics are undefined-ish).
  `ListVpnRoutes`/`rbgp rib vpn` surface the winning received path ID.

- **GR/LLGR stale preservation for the RR families (VPNv4/v6, BGP-LS,
  RT-Constrain).** A restarting peer's SAFI-128/71/72/132 routes are now
  preserved as stale through the graceful-restart window (RFC 4724 helper
  retention, keyed to the peer's advertised GR families; families absent
  from the capability are withdrawn) instead of conservatively withdrawn,
  with the full RFC 9494 two-phase LLGR lifecycle (NO_LLGR honored,
  LLGR_STALE community injected and preserved through re-export,
  per-family promote-vs-purge on the LLGR capability split, least-preferred
  demotion via the existing three-tier stale ranks). Operationally this
  makes the RR role restart-real: a reflector no longer dumps its VPN
  table to every client when one PE restarts; an RR client's VPN filter
  membership survives its own restart so VPN routes flow immediately at
  re-establish (no strict-empty blackout); and an ORR topology source's
  restart no longer unresolves vantages mid-window. The new families
  implement the RFC-strict consecutive-restart deletion and EoR sweep of
  non-readvertised stale routes; the pre-existing unicast/FlowSpec/EVPN
  paths were brought in line afterwards (see Fixed below), and the
  LLGR-stale export restriction is closed by the RFC 9494 export gate
  above. M77 is the live peer-restart interop receipt.

- **Optimal Route Reflection (RFC 9107, ADR-0095) — per-client best paths
  via BGP-LS-sourced SPF.** A route reflector normally reflects *its own*
  best path to every client; ORR computes each client's best from the
  client's own topological position. Configure `orr_vantage = "<ip>"`
  (an IP identifying a node in the BGP-LS topology) on an iBGP
  route-reflector client or peer-group; the RR builds a topology graph
  from all received BGP-LS routes (nodes interned by canonical descriptor
  bytes; link costs from the IGP Metric TLV parsed lazily out of the
  never-typed BGP-LS Attribute), runs one Dijkstra per distinct vantage,
  and ranks that client's candidate set with the interior-cost tiebreak
  at RFC 4271's step-(e) slot — unknown cost is least preferred, and an
  unresolved vantage falls back silently to the standard best. Topology
  changes re-stage exactly the affected clients with minimal deltas.
  Observability: `rbgp topology nodes|links`, `rbgp orr`, and
  `ListTopologyNodes`/`ListTopologyLinks`/`ListOrrStatus` (SensitiveRead),
  plus SPF/topology telemetry. Zero cost and zero behavior change when no
  vantage is configured (pinned by an output-equality guardrail test).
  Deferred (ADR-0095): backup vantages, inter-RR Add-Path (multi-cluster),
  TE/multi-topology metrics. M76 proves live divergence: two
  GoBGP clients of one RR receive different best paths for the same
  prefix, flip on a topology metric change, and collapse to the identical
  standard best when the topology is withdrawn. **No other open-source
  BGP daemon ships ORR.**

- **VPN-ORR: per-vantage best selection for VPNv4/VPNv6 reflection.**
  ORR now composes with the SAFI-128 route reflector (the ADR-0095
  deferral, un-deferred): an ORR client's VPN routes are ranked with its
  vantage's interior cost to each candidate's next-hop, exactly like
  unicast — same candidate filtering (split horizon + RFC 4456
  suppression before ranking), same interior-cost slot in the tiebreak
  chain, same unknown-cost-least-preferred and unresolved-vantage
  fallback semantics, live across receive, initial dump, dirty resync,
  route-refresh replay, and topology-driven restage. The RFC 4684
  RT-Constrain gate applies to the vantage winner's Route Targets (the
  route actually advertised), not the Loc-RIB best's. Non-ORR peers are
  byte-identical to before. (M76 pins the unicast ORR wire behavior;
  VPN-ORR is the same engine — a VPN-ORR interop receipt can join a
  future M-job if demanded.)

- **RT-Constrain (RFC 4684, AFI 1 / SAFI 132) — constrained VPN route
  distribution.** The scalability companion to the VPNv4/v6 route reflector:
  peers advertise Route Target membership NLRI (a 0–96-bit prefix over
  origin-AS + the 8-byte RT extended community; zero-length = default
  wildcard), and the RR filters SAFI-128 reflection per-peer accordingly —
  strict semantics (a peer that negotiated SAFI 132 with no advertised
  interest receives no VPN routes; membership changes emit the RFC-minimal
  announce/withdraw delta with no session resets). RTC routes are themselves
  stored, best-path-selected, and reflected between clients, and rustbgpd
  self-originates the default RTC NLRI (it has no VRFs, so its own interest
  is always "everything" — required so RFC 4684-compliant PEs send it their
  VPN routes). Configure with the `rtc` family; inspect with
  `RibService.ListRtcRoutes` (SensitiveRead) or `rbgp rib rtc`. Includes the
  RFC 7313 Enhanced Route Refresh stale lifecycle whose end-of-refresh sweep
  re-derives membership and restages VPN. Matching is RFC-faithful 96-bit
  prefix matching (documented divergence from GoBGP's exact-match shortcut in
  ADR-0077). Deferred: RFC 4684 §3.2(ii) non-client attribute-swap, the §6
  60-second EoR delay, eBGP RTC subtleties, RTC×ORF interaction, Add-Path.
  M75 proves filtering, widen/narrow-without-reset, RTC reflection, and the
  unfiltered non-RTC-peer path against GoBGP.

- **VPNv4/VPNv6 L3VPN route-reflection (RFC 4364 / RFC 4659, SAFI 128).**
  rustbgpd now negotiates, receives, stores, reflects, and withdraws
  VPN-IPv4/VPN-IPv6 routes as a route reflector / controller feed
  (ADR-0077): configure with the `l3vpn_ipv4_unicast` /
  `l3vpn_ipv6_unicast` families, inspect with `RibService.ListVpnRoutes`
  (SensitiveRead) or `rbgp rib vpn`. Route identity is Route
  Distinguisher + prefix; the MPLS label stack is route data — a
  same-peer relabel re-advertises — and RD, label stack, next-hop, and
  Route Target extended communities are preserved verbatim through
  reflection (no VRF import, no MPLS FIB install, next-hop rewriting is
  inert for SAFI 128). Wire codec implements the RFC 4364 §4.3.2 /
  RFC 4659 §3.2.1.1 RD-prefixed next-hop forms (12/24/48 bytes) and the
  RFC 8277 §2.4 withdraw-mode compatibility field (0x800000 on transmit,
  ignored on receive). Includes the RFC 4456 reflection pipeline
  (ORIGINATOR_ID / CLUSTER_LIST, initial table dump, EoR, plain
  route-refresh replay, dirty Adj-RIB-Out resync), the RFC 7313 Enhanced
  Route Refresh stale lifecycle (BoRR/EoRR sweep, family-isolated), and
  conservative GR-entry withdraw (SAFI-128 routes are not preserved as
  stale). Add-Path, labeled-unicast (SAFI 4), and RT-Constrain remain
  deferred. M74 proves reflection, field preservation, withdrawal, and
  no-dataplane-install against a GoBGP source and sink.

### Changed

- **Published crates bumped: `rustbgpd-wire` 0.13.0 → 0.14.0 (breaking),
  `rustbgpd-fsm` 0.1.0 → 0.2.0 (breaking).** Wire gained typed VPNv4/VPNv6,
  RT-Constrain, labeled-unicast, and BGP-LS NLRI/topology types plus
  origin-validation community constants; `MpReachNlri` / `MpUnreachNlri`
  gained `pub` fields, so external struct-literal construction needs
  updating. fsm's `default_send_hold_time` gained a `hold_time` parameter
  and `PeerConfig` gained a `send_hold_time` field.
- **`.rpol` `route.evpn-route-type` now accepts only 1-5 (LAN-192).**
  rustbgpd emits EVPN NLRIs of route types 1-5 (RFC 7432 §7), so a
  comparison against `0` or `6`-`255` could never match a real route.
  The typechecker previously accepted `0`-`255` and silently compiled a
  dead policy; out-of-range literals are now a compile-time diagnostic.
- **The default container image is now a lean production runtime.**
  `docker build .` (and the GHCR release image) ships only the daemon
  and the `rbgp` CLI, runs as a nonroot `rustbgpd` user, and carries no
  dev/test/bench helpers. The previous all-in image (adds
  `evpn-tester` / `evpn-monitor`, `iproute2`, the interop start
  script; runs as root) is now the `dev` build target:
  `docker build --target dev -t rustbgpd:dev .` — CI interop/soak
  workflows are pinned to it.
- **systemd packaging split into an unprivileged base unit + opt-in
  dataplane drop-in.** `examples/systemd/rustbgpd.service` now runs as
  a dedicated `rustbgpd` user with `CAP_NET_BIND_SERVICE` only
  (`CAP_NET_RAW` dropped from the bounding set — nothing in the daemon
  needs it; kernel programming was never possible under the old unit
  either, which lacked `CAP_NET_ADMIN`). Kernel-dataplane deployments
  ([[fib_tables]], blackhole install, EVPN VTEP/IRB) opt in via the
  new `examples/systemd/rustbgpd-dataplane.conf` drop-in, which adds
  `CAP_NET_ADMIN`. See docs/deployment.md "systemd".

### Deprecated

- **The in-daemon birdwatcher looking glass
  (`[global.telemetry.looking_glass]`) is deprecated and will be
  removed in a future release.** Partial compatibility with an external
  REST contract does not belong in daemon core; the daemon's durable
  API is gRPC + `rbgp`. The same birdwatcher-compatible REST surface
  (identical endpoints and response shapes, consumed by Alice-LG and
  similar frontends) is now served by a maintained external adapter,
  `examples/birdwatcher-adapter`, which sources everything from the
  daemon's gRPC API — point it at a gRPC TCP listener and keep the same
  frontend config. The daemon logs a deprecation warning at startup
  while the section is present; behavior is otherwise unchanged. An
  end-to-end smoke test pins adapter-vs-in-daemon response equality.
- **Global inline policy (`[[policy.import]]` / `[[policy.export]]`)
  is deprecated and will be removed in a future release.** It is the
  legacy pre-chain fallback: restart-required on change (no SIGHUP
  hot-apply) and invisible to config transactions and the impact
  planner. The daemon now logs a loud deprecation warning at startup,
  in the startup banner, and on every reload while it is present.
  Migrate to named policy chains (`[policy.definitions]` +
  `import_chain` / `export_chain`) or `.rpol` files
  (`policy.rpol_files`); see docs/CONFIGURATION.md "Inline policy
  (deprecated)". Per-neighbor inline policy is unaffected.

### Removed

- **BREAKING — the `RUSTBGPD_EVPN_ADOPTION_ACCEPT_LEGACY` escape hatch is
  gone; setting it now aborts boot.** The ADR-0082 stamp-or-legacy
  migration window closed at v0.38.0, so the strict rule — L3 neighbor
  adoption requires the `NDA_PROTOCOL = RTPROT_BGP` ownership stamp;
  stamp-less rows are foreign (preserved untouched, never adopted or
  reaped) — is now the only mode. The daemon refuses to start if the
  variable is set to **any** value (including `0`), naming the variable
  and the upgrade path, so automation still exporting it fails loudly
  instead of silently changing crash-restart adoption behavior. Operators
  upgrading from v0.37.0 or earlier with EVPN L3 kernel rows still live
  must run a v0.38.0–v0.45.0 release once (its converge re-stamps every
  owned row) before this version — see `docs/evpn-vtep-troubleshooting.md`,
  "Crash-restart adoption across upgrades (ADR-0082)".

### Fixed

- **Restored the consolidated "supported standards at a glance" table.** The
  README slim replaced the old protocol-coverage row with a pointer to
  `docs/RFC_NOTES.md`/`INTEROP.md`/`RECEIPTS.md`, but none of those carried a
  single at-a-glance list of the supported RFCs/SAFIs. `docs/RFC_NOTES.md` now
  opens with that table and the README "Protocol coverage" row links to it.
- **EVPN decomposed-apply response disambiguates committed vs planned
  steps.** When no-op steps are skipped mid-sequence the `ApplyEvpnRuntime`
  message now appends `(N of M planned steps committed)` so an API consumer
  does not read the committed count as the planned count. The boot-revert
  save-aside's hard-link filesystem requirement is now documented in
  `docs/OPERATIONS.md`.
- **BMP VPNv6 Adj-RIB-Out mirror preserves the link-local next-hop
  (LAN-217 follow-up).** `synthesize_vpn_announce` now copies the route's
  link-local half into the synthesized `MP_REACH`, mirroring the unicast
  path — previously a VPNv6 RouteMonitoring PDU reconstructed a 24-byte
  single next-hop and dropped the RFC 4659 link-local half (the live BGP
  UPDATE to peers was unaffected). Tested via
  `borrowed_encode_vpnv6_link_local_matches_clone_based_oracle`.
- **ORR vantage validation also rejects wildcard/loopback addresses
  (LAN-216 follow-up).** A `0.0.0.0` / `::` / loopback `orr_vantage` names
  no real topology node and silently ran inert ORR; it now fails closed at
  config load.
- **Hold-time default fully deduplicated (LAN-211 follow-up).**
  `config::schema::DEFAULT_HOLD_TIME` now sources
  `rustbgpd_fsm::DEFAULT_HOLD_TIME`, so the daemon default lives in exactly
  one place.
- **VPN export-explain no longer records staged modifications for a denied
  route (LAN-212 follow-up).** The VPN distribution arm now sets
  `trace.modifications` only after a Permit, matching the unicast arm.
- **VPNv6 reflection no longer drops the link-local next-hop (LAN-217).**
  `VpnRibRoute` stored only a single global next-hop, so a VPNv6 route
  received with an RFC 4659 §3.2.1.1 two-address next-hop (48-byte: RD +
  global, RD + link-local) was reflected with a 24-byte single-address
  next-hop — the link-local half was silently discarded. Mirroring the
  labeled-IPv6 fix (LAN-190), the route data model now carries
  `link_local_next_hop` alongside the global next-hop; the receive path
  populates it and the reflected `MP_REACH_NLRI` re-emits the 48-byte
  form verbatim, so VPNv6 link-local forwarding survives reflection. A
  change confined to the link-local half now correctly re-advertises.
  (The wire codec already round-tripped the 48-byte two-address VPN
  next-hop; the gap was purely the RIB/transport plumbing.)
- **CLI/API consistency cleanup (LAN-211).** The default hold time (90s)
  is now a single `rustbgpd_fsm::DEFAULT_HOLD_TIME` constant reused by the
  gRPC neighbor service's send-hold-time validation instead of a duplicated
  literal, added a `per_client_best` proto round-trip test for peer groups,
  and documented the deliberate export-gate-verdict label duplication across
  the client/server type boundary.
- **Export-explain no longer reports staged modifications for a denied
  route (LAN-212).** `distribute_single_best_prefix` recorded the export
  policy's `modifications` into the explain trace before the deny gate,
  so a policy-denied prefix could surface modifications it would never
  apply; the assignment now happens only after a Permit, matching the
  per-client-best explain arm. Regression-tested via
  `denied_route_explain_has_no_modifications`. Also clarifies two
  precision limitations in comments/docs: the grouped-member explain
  dry-run still counts a member's own-sourced (split-horizon-excluded)
  prefixes in its `already_advertised` gate, and
  `Route.received_at_epoch_seconds` is recovered from two independent
  clock reads and so is a display timestamp, not a precise ordering key.
- **ORR vantage config validation now rejects a degenerate vantage IP
  (LAN-216).** An `orr_vantage` (RFC 9107) equal to the neighbor's own
  peering address or the reflector's `router_id` degenerates to the
  reflector's own viewpoint (plain non-ORR reflection) and is a
  copy-paste misconfiguration. Config load/validate now fails closed on
  either case with a diagnostic naming the field and offending address,
  alongside the existing iBGP / `route_reflector_client` checks, rather
  than silently accepting it.
- **`rpol_files` policy entries are canonicalized before they are read
  (LAN-218).** Each `[policy] rpol_files` path is now `canonicalize()`d
  immediately before `read_to_string`, so the file that is opened is the
  file that was resolved — closing a symlink TOCTOU window between path
  resolution and open. A path that cannot be canonicalized (missing or
  unreadable) surfaces the same `failed to read` config error as before.
  Robustness hardening; path resolution stays deliberately unconfined to
  the config directory. Regression-tested via
  `rpol_symlinked_file_canonicalizes_and_loads`.
- **Boot-revert save-aside is now an atomic no-clobber move (LAN-224).**
  `save_candidate_aside` in the commit-confirm revert journal previously did a
  check-then-act `try_exists` + `rename` on the `<config>.unconfirmed` backup.
  Because `rename(2)` overwrites its destination unconditionally, an
  `.unconfirmed` created between the check and the rename — by an external writer
  to the state dir, or a second daemon booting against the same config dir —
  could be clobbered, violating the "never overwrite an existing `.unconfirmed`
  with different bytes" invariant. It now uses a `hard_link` + `remove_file`
  move whose no-clobber guard is atomic: an existing backup yields the same
  `Ok(false)` (did-not-move) result and its bytes are left untouched.
- **Update-groups: a second policy-driven regroup while a member's prior
  regroup resync is still un-drained no longer leaks stale routes.** A
  grouped member keeps no per-family Adj-RIB-Out record of its unicast/VPN
  wire state, so its `pending_regroup_baseline` is the *only* record of
  what is on its wire. When a regroup resync send failed (outbound channel
  full) the member stayed dirty with that baseline retained; a second
  regroup before it drained *overwrote* the baseline with a fresh
  group-view snapshot of a table the member was never advertised. Keys on
  the wire but absent from both the new snapshot and the new group's table
  then fell out of the withdraw candidate set and were never withdrawn,
  stranding stale routes on the peer. The second regroup now *unions* the
  new snapshot onto the retained baseline (existing/wire values win on
  conflict) for both unicast and VPN, so every wire key stays a withdraw
  candidate; `member_retains` still suppresses withdrawing keys present in
  the new group's table. Regression-tested against the per-peer oracle
  (`oracle_second_regroup_while_dirty_unions_baseline_no_leak`).
- **Labeled IPv6 reflection no longer drops the link-local next-hop
  (LAN-190).** `LabeledRibRoute` stored only a single global next-hop, so
  a labeled-unicast (SAFI 4) IPv6 route received with an RFC 8950 §4 /
  RFC 2545 §3 two-address next-hop (32-byte: global + link-local) was
  reflected with a 16-byte single-address next-hop — the link-local half
  was silently discarded. The route data model now carries
  `link_local_next_hop` alongside the global next-hop; the receive path
  populates it and the reflected `MP_REACH_NLRI` re-emits the 32-byte
  form verbatim, so labeled IPv6 link-local forwarding survives
  reflection. A change confined to the link-local half now correctly
  re-advertises. (The VPNv6 reflection path shares the same
  single-next-hop limitation on `VpnRibRoute`; that mirror is deferred as
  a follow-up — the wire codec already round-trips the RFC 4659 48-byte
  two-address VPN next-hop.)
- **`.rpol` `route.next-hop != …` no longer matches a route with no
  next-hop (LAN-209).** `!=` (both `route.next-hop != <ip>` and
  `route.next-hop != peer.address`) lowered to `Not(NextHopEq…)`, which
  matched whenever the attribute was absent — the opposite of the
  documented rule that next-hop predicates never match a route without a
  next-hop. `!=` now lowers to dedicated `NextHopNe` / `NextHopNePeer`
  guards that, like `==`, require the attribute present, so an absent
  next-hop matches neither. `!= peer.address` still reads peer identity
  (disqualifies update-group sharing).
- **`.rpol` `route.prefix != …`, `route.route-type != …`, and
  `route.evpn-route-type != …` no longer match a route missing that
  attribute — closes the absent-`!=` class LAN-209 opened for
  next-hop.** The same `!= → Not(<X>Eq)` lowering that flipped next-hop
  affected every field whose `==` is false-on-absent: `route.prefix`
  matched every prefixless route (BGP-LS / RTC NLRIs), `route.route-type`
  matched when the source class was absent, and — the highest-impact
  case — `route.evpn-route-type != N` matched **every non-EVPN route**
  (they all carry no EVPN route type), silently rejecting normal unicast
  traffic. Each now lowers to a dedicated `PrefixNe` / `RouteTypeNe` /
  `EvpnRouteTypeNe` guard that, like `==`, requires the attribute
  present, so an absent attribute matches neither operator. A class-guard
  test asserts every absent-able comparable field matches neither `==`
  nor `!=` when its attribute is absent, so a future field cannot
  reintroduce the flip. (Fields with RFC 4271 implicit defaults —
  `local-pref` / `med` — and the total-enum `rpki` / `aspa` states were
  audited and are correctly unaffected.)
- **Policy hit-counter attribution no longer risks a panic on a stale
  counter set (LAN-192).** `evaluate_with_attribution_counting` indexed
  the per-policy and per-term counter arrays directly; a counter set
  shorter than the chain (a hot-reload leftover) would panic on the
  production evaluation path. It now degrades to skipped increments via
  bounds-checked access. (The counters live on the owning chain and are
  replaced with it, so a short set is a construction impossibility today
  — this is defense-in-depth.)
- **`apply_community_mods` can no longer panic (LAN-175).** The private
  helper paired a match predicate with a separate value extractor joined
  by `.expect("… agree")`; a caller mismatch would have panicked the
  daemon on the export path. Predicate and extractor are merged into one
  `Fn(&PathAttribute) -> Option<Vec<_>>` closure that matches and
  extracts together, so disagreement — and the `expect` — are gone.

- **Grouped peers no longer lose export-policy counters on a dirty
  resync (LAN-210).** After a full-outbound-channel dirty (or forced)
  resync, `distribute_changes` replayed a grouped member's table to the
  wire but never re-recorded its per-member export-policy counters:
  `apply_group_policy_counters` was `!resync`-gated and the join-style
  replay only ran from the route-refresh / peer-lifecycle paths, while
  ungrouped peers re-record every prefix through the per-prefix staging
  path on every resync. Grouped and ungrouped peers therefore drifted
  on `bgp_policy_routes_total`. The resync branch now replays
  `apply_group_join_counters` (full-table permit/deny counts), matching
  the ungrouped path exactly.

- **ORR next-hop resolution is now deterministic on equal-metric ties
  (LAN-189).** `OrrTopology::resolve_node` broke equal prefix-metric LPM
  ties by advertiser `Vec` order, which derives from hasher-dependent
  Adj-RIB-In iteration, so an ambiguous vantage could resolve to a
  different node across restarts. Ties now break on the lowest canonical
  BGP-LS node key. Additionally, an empty BGP-LS batch (a withdraw of a
  key not held, or an empty announce) no longer triggers a wasted ORR
  topology rebuild + per-vantage SPF recompute, and the covering-default
  (`0.0.0.0/0` / `::/0`) Prefix-NLRI LPM semantics are now documented and
  regression-pinned (a default route yields a finite `distance + metric`
  cost; least-preferred `None` means no covering Prefix NLRI at all).

- **`per_client_best` never reached live sessions.** The knob
  (RFC 7947 §2.3.2 per-client best-path, #696) parsed, validated,
  survived SIGHUP diffs, and displayed in the docs/reload matrix — but
  `PeerManager::build_transport_config` never copied it into the
  transport session config, so every configured peer silently
  registered single-best and `rbgp neighbor` reported `Distribution
  Mode: single-best` regardless of config. Caught live by the M83 lab
  (the RIB- and CLI-layer tests from #696/#698 sit above the dropped
  seam); fixed with a one-line copy plus a
  `build_transport_config_preserves_per_client_best` unit pin.

- **`ApplyEvpnRuntime` with `validate_only` now rejects what a real apply
  would reject (LAN-214 #9).** The dry-run path returned
  `EvpnRuntimeApplyValidated` immediately after the (pure, rejection-free)
  `plan_candidate`, so an operator could "validate" a candidate that a
  real apply then fails closed (e.g. an IP-VRF L3VNI identity redefine, or
  an undecomposable mixed candidate). Validate-only now runs the same
  shape acceptance the commit path uses — `validate_supported_plan_shape`
  plus, for unsupported-but-mixed candidates, the #268 decomposition —
  without committing or touching any actor, returning the planned step
  descriptions on success and the real shape rejection on failure.
- **The EVPN runtime shape gate and converge dispatch are now proven to
  classify plan shapes identically (LAN-214 #8).**
  `validate_supported_plan_shape` mirrors `EvpnRuntimeActorConverger::converge`'s
  if/else routing by hand, previously guarded only by a "keep in sync"
  comment. Regression tests now drive a representative set of shapes
  through both routers and assert identical classification — byte-identical
  rejection messages for unsupported shapes (every `converge_*` runs its
  `validate_single_*` before any actor, so the comparison is side-effect
  free) and gate-acceptance of every shape the dispatch commits.

- **BMP peer-state lifecycle no longer emits spurious or mis-ordered
  events across a TCP flap (LAN-200).** Two gaps closed. (1) A pending
  BMP divergence repair (the synthetic RFC 7854 PeerDown/PeerUp forced
  after a RouteMonitoring drop) is now abandoned when the TCP session
  tears down: `close_tcp` / `handle_tcp_disconnect` clear the divergence
  latch and disarm the `bmp_repair_timer`, so the run loop's repair arm
  can no longer fire a synthetic PeerDown/PeerUp for a dead session that
  a reconnect would then stack a real PeerUp on top of. (2) A live
  Loc-RIB PeerUp (RFC 9069) dropped on a full collector channel at
  connect now suppresses that collector's subsequent live Loc-RIB Route
  Monitoring until a later reconnect lands the PeerUp — a collector can
  no longer see Loc-RIB RM with no preceding Loc-RIB PeerUp. The
  connect-time Loc-RIB dump path was already safe (it skips the dump on
  a dropped PeerUp).

- **Config persistence now fsyncs before rename (LAN-206).**
  `ConfigPersister::persist()` wrote the temp config with `fs::write` +
  `fs::rename` and never called `sync_all()` on the temp file or fsynced
  the parent directory, so a crash in the settle window could leave a
  torn/zero-length config that fails to parse on the next boot — on
  *every* gRPC config mutation. It now routes through the same
  write-tmp+fsync+rename+fsync-dir primitive the commit-confirm journal
  uses (`confirm_journal::write_atomic`).

- **Boot revert can no longer leave the config file missing, and its
  refusal messages are state-aware (LAN-207, LAN-220).**
  `boot_revert_check` renames the on-disk candidate to
  `<config>.unconfirmed` before writing the restored pre-transaction
  config; if that write failed, the config file was gone and boot
  refused with nothing left to load. The candidate is now put back on a
  restore-write failure. The refusal message now detects whether the
  config file exists: when it is missing it no longer tells the operator
  to `rm <journal>` and boot the on-disk config (there is none) — it
  points them at the pre-transaction config embedded in the journal and
  the `<config>.unconfirmed` candidate to restore instead. The revert is
  idempotent across a crash mid-revert (config missing + live journal
  resumes cleanly).

- **A journal-removal failure at boot now FAILS STARTUP instead of
  booting anyway, and never clobbers the saved-aside candidate
  (LAN-219; supersedes the earlier LAN-208 boot-anyway behavior).**
  After the revert is written, if the journal cannot be removed
  `boot_revert_check` returns `Err` and the daemon refuses to start: a
  daemon that cannot prove the revert intent was consumed would
  otherwise silently re-revert every config the operator applies on each
  restart. The reverted config is still written to disk and the
  unconfirmed candidate is preserved at `<config>.unconfirmed`; the
  refusal message states exactly this and tells the operator to preserve
  the candidate, then fix the journal's permissions or `rm` it and
  restart. The `.unconfirmed` recovery copy is written once and is never
  overwritten with different bytes on a subsequent boot, so a restart
  loop can no longer destroy the real saved candidate.

- **Oversized and non-regular-file commit-confirm journals are rejected
  before read (LAN-204, LAN-221).** A corrupt journal with a huge
  `rollback_toml` could OOM during boot deserialization; boot refuses
  (fail closed) any journal larger than 10 MB. The size guard trusted
  `metadata().len()`, which a FIFO/socket/device reports as 0 (bypassing
  it) before a read blocks or runs unbounded — boot now also refuses any
  journal path that is not a regular file, and reads the journal through
  a hard byte cap as defense-in-depth.

- **The library target now builds under `--all-features` (LAN-198).**
  The lib exposes `pub mod config` only under `bench-internals`, and
  `config`'s reload-diff logic (`classify_evpn_runtime_change`) reaches
  into the EVPN runtime subsystem — modules previously declared only in
  `main.rs`. With `bench-internals` off (the default) the lib compiled
  empty, so the gap was invisible; `cargo check -p rustbgpd
  --all-features --lib` failed with `E0433: cannot find
  evpn_plan_decomposer in crate` while the binary stayed green. The lib
  now declares the transitive EVPN module closure (plan decomposer,
  converger, ES-drain, originator, segment, dataplane, IMET, L3
  originator, SVI) under the same feature gate, and CI gained a
  `cargo check -p rustbgpd --all-features --lib` step so the
  bench-internals lib surface can no longer regress unnoticed.
- **Per-peer `log_level` is now genuinely live on SIGHUP — and no longer
  aborts boot.** Two bugs closed. (1) The generated filter directive used
  the unbracketed span form `peer{peer_addr=X}=level`, which the
  `EnvFilter` parser rejects (`error parsing level filter`); `init_logging`
  surfaced that as an error and the daemon `exit(1)`-ed, so any config that
  set a per-peer `log_level` failed to boot. The directive is now the
  correct bracketed `[peer{peer_addr=X}]=level`, guarded by a test that
  parses every emitted directive. (2) The reload matrix and deployment docs
  already classed `[[neighbors]] log_level` (and the peer-group
  equivalent) as live, but the tracing subscriber was installed once at
  startup with no reload handle, so an edited per-peer level never took
  effect without a restart. The subscriber's `EnvFilter`
  now sits behind a `tracing_subscriber::reload` handle (stored in a
  process-global `OnceLock` in the telemetry crate, matching the
  subscriber's own global scope); after a validated config reload the
  SIGHUP path recomputes `per_peer_log_directives` and swaps in a freshly
  rebuilt filter (`RUST_LOG` base level plus every current per-peer
  directive — the base always survives). Reapplying identical directives
  is a no-op and a malformed directive leaves the live filter untouched.
  The global base level stays restart-required (read once from
  `RUST_LOG`). Formatting/output are unchanged. Also adds a class-guard
  unit test (`build_transport_config_reflects_every_transport_field`) that
  fails at compile time when a new `PeerManagerNeighborConfig` transport
  field is added without a copy into `TransportConfig`, and at run time
  when an existing copy is dropped — the same seam that silently lost
  `per_client_best` (#702); plus a reload-matrix test that pins the
  live/restart-required class column so a docs-vs-reality drift fails CI.

- **BMP monitoring can no longer diverge silently from the wire under
  saturation.** Two per-peer holes closed in the PeerSession→BmpManager
  path: (1) BMP `PeerUp`/`PeerDown` were emitted with the same lossy
  `try_send` as Route Monitoring, so under a full BMP event channel the
  one signal that tells collectors to discard a peer's state could be
  dropped — collectors would trust a stale Adj-RIB-In/Adj-RIB-Out view
  forever. Lifecycle events now await channel space (bounded: the
  manager loop always drains and never blocks; a dead manager returns
  an immediate counted error). (2) When an outbound UPDATE reached the
  wire but its rib-out Route Monitoring mirror hit a full channel, the
  event was dropped with only a counter — and the rib-in/rib-out
  streams being live-only (no dump), the collector's view stayed
  incomplete until the next real session flap. The session now latches
  the divergence and forces a synthetic `PeerDown`/`PeerUp` pair (an
  RFC 7854 peer-state reset, reason 2/FSM code 0) ahead of the next
  emission — retried on a 1s timer so a session that goes quiet after
  the drop is still repaired — making the gap collector-detectable
  instead of silent. The outbound-writer saturation path itself was
  verified correct and is now regression-pinned: the UPDATE that fails
  to enqueue is never mirrored (RFC 8671 mirrors what was sent), and
  the teardown's `PeerDown` — now truthfully reason 1 carrying the
  `Cease/8` NOTIFICATION we send, rather than the "remote closed"
  default — is ordered after the last mirrored event on the same
  channel. `bmp_source_drops_total` still counts every drop; no
  unbounded queueing anywhere. Per-collector fan-out drops
  (`bmp_collector_drops_total`) remain the documented lossy layer,
  healed by the collector's own reconnect (RFC 7854 state discard +
  PeerUp replay).
- **The BMP Loc-RIB collector-connect dump no longer materializes the
  whole table on the RIB task.** The RFC 9069 dump handler synthesized
  every Loc-RIB UPDATE PDU into one vector before chunking — an
  O(table) allocation burst (hundreds of MB transient at full-DFZ
  scale) during which no other RIB command ran. The dump is now
  resumable: the BMP dump forwarder requests one 256-message chunk at
  a time and hands back a key-based cursor ("smallest keys strictly
  greater than the last emitted"), so per-request allocation is
  bounded by the chunk size, live route processing and queries
  interleave between chunks, and the cursor stays valid across
  mid-dump insertions and withdrawals (surviving routes dump exactly
  once; a route added behind the cursor reaches the collector on the
  live stream — the accepted dump/live overlap race, ADR-0097).
  Peer-up replay → dump → per-family End-of-RIB → live ordering is
  unchanged and remains test-pinned.

- **An enhanced route refresh no longer purges GR/LLGR-stale routes
  awaiting End-of-RIB (LAN-187).** RFC 7313's end-of-refresh sweep
  removes routes not re-advertised inside the BoRR..EoRR window — but a
  refresh window opened while a peer was re-established under graceful
  restart (End-of-RIB still pending) also snapshotted the GR-stale and
  LLGR-stale routes RFC 4724 §4.1 / RFC 9494 §4.2 deliberately retain,
  so an EoRR (or refresh timeout) from the still-converging restarter
  deleted exactly the paths GR preserves. GR/LLGR-stale routes are now
  excluded from the refresh snapshot: a re-advertisement inside the
  window still refreshes them, and End-of-RIB or the GR/LLGR timers
  remain their only removal points. Manager tests pin the joint
  GR+refresh and LLGR+refresh lifecycles across all seven route
  families' snapshot arms.
- **A deeply-nested `.rpol` expression can no longer crash the daemon
  (LAN-184).** The rpol parser is recursive descent, and typecheck,
  lowering, and AST teardown all recurse over expression depth — so a
  policy file with thousands of nested parens, `!` chains, or chained
  `&&`/`||` (which fold into a left-leaning tree) overflowed the stack
  and aborted the process. `.rpol` files arrive via the SIGHUP overlay
  and the `TestPolicy` RPC at runtime, so this was a
  daemon-crash-by-config. The parser — the only producer of user-shaped
  expression trees — now enforces a 128-level nesting cap and reports a
  spanned diagnostic (`expression nesting exceeds 128 levels`) like any
  other rpol error, which bounds every recursive pass downstream
  (typecheck, lowering, eval, drop). The TOML frontend has no
  equivalent exposure: its match blocks compile to flat `And`/`Or`
  child vectors with no user-controlled nesting. The crash case is
  pinned in the `rpol_compile` fuzz seed corpus.

- **Label-stack withdraws no longer reset labeled-unicast and VPN
  sessions (caught live by the M79 lab; resolves LAN-188).** RFC 8277
  §2.4 says a withdraw
  carries a single ignored 3-octet compatibility field in the label
  position, but GoBGP (and any stack without a dedicated withdraw
  encoder) echoes the announced BOS-terminated label stack instead. Our
  SAFI 4 and SAFI 128 withdraw decoders assumed exactly one field, so a
  withdraw of a multi-label route mis-computed the prefix length (or
  mis-read the RD) → NOTIFICATION 3/10 → session reset, flushing the
  peer's whole table with reconnect-flap potential. The decoders (plain
  and Add-Path, both families) now dispatch like GoBGP's own parser: an
  exact 0x800000/0x000000 value is one compatibility field, anything
  else is S-bit-walked like announce mode; labels are ignored either
  way. Encode side unchanged (we still emit the compliant 0x800000) —
  a LAN-188 audit re-verified that every SAFI 4/128 withdraw emitter
  (session floods, update-group emits, Add-Path variants, BMP Loc-RIB
  synthesis) routes through the normalizing withdraw encoders.

- **Unicast, FlowSpec, and EVPN GR/LLGR semantics brought in line with
  RFC 4724/9494.** The legacy families now match the strict semantics the
  RR families (VPN/BGP-LS/RTC) shipped with: a route still stale from a
  previous restart is deleted — not re-marked in place — when the peer
  enters graceful restart again (RFC 4724 §4.1: no retention across
  consecutive restarts), and End-of-RIB removes routes still marked
  stale or LLGR-stale for that family instead of only clearing flags
  (RFC 4724 §4.1 / RFC 9494 §4.2), withdrawing them downstream. The EoR
  sweep is family-scoped (IPv4 and IPv6 unicast/FlowSpec are independent)
  and also covers the re-establish-during-LLGR path for every family,
  including the typed ones. The then-remaining legacy gap — no LLGR-stale
  export restriction toward non-LLGR peers — is closed by the RFC 9494
  export gate under Added above.

- **Audit-tail hardening for BGP-LS, durable cursors, and GR/LLGR intern GC.**
  BGP-LS known-NLRI descriptor TLV ordering errors now discard only the
  affected NLRI instead of resetting the session; durable event-history replay
  cursor-gap math uses saturating arithmetic for `from_event_id = u64::MAX`;
  BGP-LS policy contexts no longer fabricate a `0.0.0.0/0` prefix; and GR/LLGR
  stale sweeps run the intern-table GC after Loc-RIB recompute so selected-route
  clones cannot leave one-cycle attribute-set orphans.

## [0.45.0] — 2026-06-30

### Added

- **ADR-0077 BGP-LS receive/API tranche.** `families` now accepts
  `linkstate` / `linkstate_vpn` (AFI 16388, SAFI 71/72), the wire parser
  decodes RFC 9552 BGP-LS and BGP-LS VPN `MP_REACH_NLRI` /
  `MP_UNREACH_NLRI`, and the transport/RIB store learned BGP-LS routes as
  opaque topology objects with RFC 4271-style best-path selection. The new
  `RibService.ListBgpLsRoutes` (`sensitive_read`) and `rbgp rib bgpls` CLI
  expose family, NLRI type, next-hop, peer, raw descriptor/payload bytes, and
  raw BGP-LS Attribute bytes for controller-facing export. rustbgpd still does
  not originate local BGP-LS objects, compute paths from BGP-LS data, or
  negotiate BGP-LS Add-Path / GR / LLGR stale preservation until those typed
  lifecycle slices land.
- **ADR-0077 BGP-LS reflection/export tranche.** BGP-LS and BGP-LS VPN routes
  now participate in the existing route-reflector distribution pipeline:
  inbound changes recompute Loc-RIB, eligible negotiated peers receive outbound
  `MP_REACH_NLRI` / `MP_UNREACH_NLRI`, initial table dumps include BGP-LS
  routes, route-refresh requests replay the requested BGP-LS family, and dirty
  Adj-RIB-Out resyncs cover BGP-LS alongside unicast / FlowSpec / EVPN. The
  transport encoder preserves opaque RFC 9552 NLRI bytes and applies the same
  RFC 4456 `ORIGINATOR_ID` / `CLUSTER_LIST` reflection attributes used by the
  existing families.
- **M73 GoBGP interop proof for BGP-LS reflection.** The hosted interop suite
  now includes a GoBGP 4.6.0 source -> rustbgpd route reflector -> GoBGP 4.6.0
  sink receipt for ADR-0077. GoBGP injects an RFC 9552 BGP-LS Node NLRI,
  rustbgpd exposes it through `rbgp rib bgpls`, the sink receives the reflected
  route with the BGP-LS Attribute payload intact, and source withdrawal removes
  the object from both rustbgpd and the sink.
- **ADR-0063 EVPN runtime convergence — additive ES member expansion.**
  `EvpnService.ApplyEvpnRuntime`, SIGHUP, and static `rustbgpd --diff` now treat an
  additive candidate that adds L2VNIs and expands an existing Ethernet
  Segment's `member_vnis` with exactly those newly added VNIs as a live
  hot-apply shape. The converger reuses the additive build-up rollback ladder:
  newly added VNIs originate IMET, candidate L2/IP-VRF/ES snapshots are
  republished to the dataplane, Type 2 originator, SVI, segment, and Type 5
  actors, and any failed publish restores committed snapshots and withdraws
  speculative IMET. ES field changes, member removals, existing-member
  additions, arbitrary relinks, and IP-VRF identity edits still fail closed.

### Changed

- **`rustbgpd-wire` 0.12.0 → 0.13.0 (breaking).** The decoupled wire crate
  gains BGP-LS (RFC 9552) codec support, which adds `Afi::BgpLs` and
  `Safi::BgpLs` (71) / `Safi::BgpLsVpn` (72) variants to the `Afi`/`Safi`
  enums — exhaustive downstream matches must add arms. Structured
  `MP_REACH_NLRI` / `MP_UNREACH_NLRI` attribute encoding is now fallible
  (returns `EncodeError` for oversized FlowSpec rule vectors instead of
  panicking), and `UpdateMessage::try_build` is added as the fallible
  counterpart to `UpdateMessage::build`.

### Fixed

- **Control-plane lifecycle hardening from the repo-wide audit.** RIB
  GR/LLGR stale-clear, injected-route, and unicast / EVPN withdraw paths now
  garbage-collect interned attribute sets only after the Loc-RIB recompute drops
  selected-route clones, closing the remaining one-cycle orphan cases around the
  M67 intern-GC fix. Failed OpenSent/OpenConfirm teardown now clears negotiated
  session metadata before the FSM returns to Idle, connect-retry accounting
  saturates instead of wrapping back to fast retries, and cursor-gap
  `missed_count` calculation no longer overflows for
  `from_event_id = u64::MAX`.
- **Policy hot-path allocation cleanup from the repo-wide audit.** Policy
  chains now compare structurally instead of formatting resolved chains through
  `Debug` on reload / hot-apply classification paths, and standalone deny
  statements return the documented empty-modification result without cloning
  discarded route modifications.
- **Policy community-list hot-path cleanup from the repo-wide audit.** Community
  match criteria now scan only their matching community family, and standard /
  large community add/remove paths use adaptive exact-list conflict checks while
  preserving existing policy ordering and later-wins semantics.
- **FlowSpec MP-BGP encode hardening from the repo-wide audit.** Structured
  `MP_REACH_NLRI` / `MP_UNREACH_NLRI` FlowSpec encoding now returns
  `EncodeError::ValueOutOfRange` for oversized public rule vectors instead of
  panicking inside the attribute encoder. The error is propagated through the
  MRT RIB exporter and a new fallible `UpdateMessage::try_build`.
- **EVPN originator churn bounds from the repo-wide audit.** Duplicate-MAC
  move-window sidecar keys are pruned when inactive windows age out, Type 2
  route-event bursts coalesce into a single full RIB repoll, and MAC-only remote
  view construction indexes sticky metadata once per poll instead of scanning
  every projected route for every winner.
- **EVPN Linux permanent-failure suppression is cleared when desired state is
  withdrawn.** A permanent kernel failure still suppresses the exact same
  L2/L3 dataplane op while the row remains desired, but withdrawing the failed
  MAC or Type 5 prefix now prunes the stale suppression record so a later
  same-shape re-add is attempted without requiring a daemon restart.
- **BGP-LS routes no longer survive stale lifecycle transitions as live data.**
  The receive/API tranche intentionally does not implement BGP-LS GR/LLGR
  stale preservation yet, but the RIB lifecycle paths now enforce that boundary:
  a peer entering Graceful Restart withdraws and recomputes its BGP-LS routes,
  and Enhanced Route Refresh tracks BGP-LS stale snapshots so omitted objects
  are swept at EoRR/timeout instead of remaining visible through
  `ListBgpLsRoutes`.
- **Invalid ORF `When-to-refresh` values no longer install hidden deferred
  filters.** RFC 5291 defines only `IMMEDIATE` and `DEFER`; a negotiated
  Address-Prefix ORF update carrying any other value now resets the installed
  ORF list for that family/type and forces a safe outbound resync instead of
  treating the unknown value as defer-like state.
- **RIB unicast recompute avoids per-prefix candidate vector allocation.**
  Best-path recompute now streams each affected prefix's candidate routes
  directly from peer Adj-RIB-In tables into `LocRib::recompute`, preserving
  selection behavior while avoiding a transient `Vec` on every affected prefix.
- **Address-Prefix ORF updates now honor the RIB completion result.** The
  transport session now waits for the RIB's bounded `PeerOrfUpdate` reply before
  treating an ORF-carrying ROUTE-REFRESH as handled. Stale-session,
  unregistered-peer, dropped-reply, and timed-out ORF updates now fall back to
  the plain Route Refresh path instead of silently suppressing re-advertisement.
- **PeerManager lifecycle commands are bounded on stalled sessions.** Start,
  stop, collision-dump, shutdown, and operator Route Refresh command paths now
  use bounded session-command sends / joins when driven by the single
  PeerManager actor. A peer whose session task stops draining its bounded
  command channel now returns a targeted timeout or logs best-effort cleanup
  failure instead of wedging unrelated peer RPC/reconcile work. Shutdown shares
  a single deadline budget across the command send and task join, and a failed
  dynamic-accept start aborts the orphaned session task.
- **Transport/FSM low-risk tail cleanup from the repo-wide audit.** Inbound
  UPDATE decode now reuses the negotiated Add-Path receive-family set instead
  of rebuilding it per UPDATE, OTC route-blocked paths skip event-only prefix
  rendering when no event-history sink consumes the structured event, and
  dynamic-peer dead-letter overflow now evicts the oldest pending entry
  deterministically instead of depending on `HashMap` iteration order.

## [0.44.0] — 2026-06-29

### Fixed

- **EVPN attribute intern table leaked under MAC mobility.** The EVPN
  Adj-RIB-In attribute intern table was never garbage-collected on EVPN
  mutation paths, so under sustained MAC mobility (RFC 7432 §7.7, where each
  move re-advertises with a fresh attribute set) it grew unbounded — linear
  RSS growth on every node, including a pure route reflector. The intern table
  is now reclaimed on all EVPN mutation paths (announce/withdraw chunks, route
  injection, and injected-route withdrawal) and after the graceful-restart
  family prune. An M67 link-drain churn soak confirms the per-node RSS slope
  drops from ~279 MB/h to ~0.2 MB/h.
- **EVPN re-advertised routes could lose a peer-originated `LLGR_STALE`
  community.** `insert_evpn` / `withdraw_evpn` did not clear the
  locally-injected-`LLGR_STALE` bookkeeping tag the way unicast and FlowSpec
  already do, so if a key promoted to LLGR-stale was re-advertised (or
  withdrawn and re-learned) during a long-lived graceful restart, the
  end-of-RIB sweep could strip an `LLGR_STALE` community the peer had set
  itself. The tag is now cleared on EVPN re-advertise and withdraw.
- **Unicast attribute intern table could grow under re-advertisement churn.**
  The unicast announce and local inject/withdraw paths did not garbage-collect
  the attribute intern table after a route was replaced in place (same prefix,
  changed attributes, no intervening withdraw) — the same class of unbounded
  growth fixed for EVPN above. The intern table is now reclaimed on those
  paths; the announce path collects only when a replacement actually occurred,
  keeping the initial-load flood off the collection cost.
- **M67 soak session sampler no longer fails on isolated CLI/query misses.**
  The link-drain churn analyzer now distinguishes transient VTEP-side
  `rbgp neighbor` sampling misses from a sustained non-Established window,
  records the miss count and max consecutive run in `report.json`, and keeps
  real multi-sample session loss as a failing gate.

## [0.43.0] — 2026-06-27

### Added

- **ASPA external-vector test coverage.** `rustbgpd-rpki` now imports a compact
  offline subset of the NIST-BRIO ASPA demo corpus (b7.1.2) as verifier unit
  tests, covering upstream Valid/Invalid/Unknown, downstream
  Valid/Invalid/Unknown, and the documented forged-origin / forged-segment
  limitations that remain ASPA-Valid.

### Removed

- **`rustbgpctl` CLI binary.** `rbgp` is now the only shipped CLI binary from
  the `rustbgpctl` Cargo package. The old long-form binary and `include!`
  alias/shim are removed; Docker images, release tarballs, generated
  completions, first-party scripts, and supported docs now use `rbgp`.

## [0.42.0] — 2026-06-23

### Added

- **HTTP liveness and readiness probes.** When
  `[global.telemetry] prometheus_addr` is configured, the telemetry listener
  now serves `/livez` for process liveness and `/readyz` for core actor
  readiness alongside `/metrics`. Readiness checks PeerManager and RIB
  responsiveness under the same 200 ms deadline now used by `GetHealth`,
  without requiring any peers or routes to exist.
- **ADR-0091 managed EVPN bridge config/status substrate.** `[managed_netdevs]`
  now accepts opt-in bridge desired state (`owner_token`,
  `[[managed_netdevs.bridges]] name`, `vlan_filtering`), derives the durable
  `rustbgpd:bridge:<owner>:<name>` Linux altname ownership stamp, starts the
  EVPN dataplane actor for managed-only configs, and exposes read-only
  desired/observed/orphan/foreign/unsafe rows through
  `EvpnService.ListManagedNetdevs` and `rbgp evpn managed-netdevs`.
- **ADR-0091 managed EVPN bridge lifecycle.** The Linux dataplane actor now
  creates configured managed bridges, stamps them with
  `IFLA_ALT_IFNAME`, treats exact stamped bridges as crash-restart adoption,
  safely reaps exact same-owner orphans when the config keeps the owner token,
  and preserves foreign, wrong-owner, multi-stamped, or protected-attribute
  drifted links. The `managed_bridge` netns proof covers create, idempotent
  restart adoption, reap, and same-name unstamped foreign preservation on a
  real kernel. `evpn_managed_netdev_state{class,name,desired,state}` exposes
  bounded Prometheus state for alerting; detailed reason text stays in
  `ListManagedNetdevs` / `rbgp`.
- **ADR-0091 fixed-VNI VXLAN lifecycle.** `[managed_netdevs]` now accepts
  fixed-VNI `[[managed_netdevs.vxlans]]` rows with protected `name`, `vni`,
  `local`, `dstport`, `bridge`, and `learning = false` attributes, derives
  `rustbgpd:vxlan:<owner>:<name>` ownership stamps, parses named VXLAN links
  from the Linux link snapshot, creates missing fixed-VNI VXLANs on the
  desired bridge, stamps them, treats exact stamped VXLANs as crash-restart
  adoption, safely reaps exact same-owner VXLAN orphans, and preserves
  foreign, wrong-owner, multi-stamped, SVD/collect-metadata, `vnifilter`, or
  protected-attribute-drifted VXLAN links. The `managed_vxlan` netns proof
  covers create, idempotent restart adoption, reap, and same-name unstamped
  foreign preservation on a real kernel; the `managed_ready` proof creates a
  managed bridge plus managed fixed-VNI VXLAN and verifies the real EVPN
  instance probe transitions from NotReady to Ready only after both links are
  owned-safe.
- **ADR-0091 managed VRF/L3VXLAN schema and status substrate.**
  `[managed_netdevs]` now accepts `[[managed_netdevs.vrfs]]` and
  `[[managed_netdevs.l3vxlans]]` rows, derives
  `rustbgpd:vrf:<owner>:<name>` and `rustbgpd:l3vxlan:<owner>:<name>`
  ownership stamps, validates protected VRF/L3VXLAN identity attributes,
  parses observed VRF/L3VXLAN link state from Linux link dumps, and exposes
  desired/observed/orphan/foreign/unsafe status through
  `EvpnService.ListManagedNetdevs` and `rbgp evpn managed-netdevs`. This is
  the substrate for the lifecycle slice below.
- **ADR-0091 managed VRF/L3VXLAN lifecycle.** The Linux dataplane actor now
  creates configured managed VRFs and L3VXLANs, stamps them with their derived
  ownership altnames, treats exact stamped links as crash-restart adoption, and
  reaps exact same-owner orphans in safe dependency order (`L3VXLAN` before
  `VRF`). Managed L3VXLAN rows must reference a configured managed VRF, and
  managed rows that match `[[evpn_ip_vrfs]]` device names must agree on table
  id, L3VNI, local VTEP IP, and Router MAC. The `managed_ip_vrf_ready` netns
  proof creates a managed VRF plus managed L3VXLAN on a real kernel, verifies
  protected attributes and idempotent adoption, proves the IP-VRF readiness
  probe transitions from NotReady to Ready, and confirms VRF deletion refuses
  while the L3VXLAN remains enslaved.
- **ADR-0091 managed VLAN upper lifecycle.** `[managed_netdevs]` now accepts
  `[[managed_netdevs.vlan_uppers]]` rows bound to a configured
  `[[evpn_instances]] bridge` / `bridge_vlan` pair, derives
  `rustbgpd:vlan-upper:<owner>:<name>` ownership stamps, creates VLAN upper
  devices on the configured bridge, stamps them, treats exact stamped VLAN
  uppers as crash-restart adoption, and reaps exact same-owner VLAN upper
  orphans before their parent bridge. `ListManagedNetdevs`, `rbgp evpn
  managed-netdevs`, and the managed-netdev Prometheus gauge now report the
  `vlan-upper` class and observed VLAN id; the `managed_vlan_upper` netns proof
  covers create, idempotent restart adoption, reap, and same-name unstamped
  foreign preservation on a real kernel.
- **ADR-0091 managed SVD / collect-metadata VXLAN lifecycle.**
  `[managed_netdevs]` now accepts `[[managed_netdevs.svd_vxlans]]` rows and
  derives their bridge VLAN / VNI bindings from configured
  `[[evpn_instances]] bridge` / `bridge_vlan` rows on the same bridge. The
  Linux dataplane actor creates `external` / `vnifilter` / `nolearning` VXLAN
  devices, enables bridge `vlan_tunnel`, programs bridge VLAN tunnel mappings,
  stamps links with `rustbgpd:svd-vxlan:<owner>:<name>`, treats exact stamped
  links as crash-restart adoption, and safely reaps exact same-owner SVD VXLAN
  orphans while preserving foreign, wrong-owner, multi-stamped, fixed-VNI, or
  protected-attribute-drifted links. The `managed_svd_vxlan` netns proof covers
  create, idempotent restart adoption, bridge VLAN/tunnel inventory, reap, and
  same-name unstamped foreign preservation on a real kernel.

### Changed

- **`#![deny(unsafe_code)]` enforced across all crates.** Added to the CLI and
  event-history crates (both already unsafe-free), so the project-wide policy
  holds everywhere; the sole documented exception remains `crates/transport`'s
  `socket_opts` socket-option FFI (`TCP_MD5SIG`, `IP_MINTTL`, TCP-AO).
- **Managed VXLAN config validation rejects a duplicate `vni`.** Two
  `[[managed_netdevs.vxlans]]` rows that share the same `vni` (even under
  distinct names) now fail config validation with an `InvalidManagedNetdev`
  error, mirroring the existing duplicate-name and `[[fib_tables]]`
  duplicate-`table_id` checks.
- **Managed VXLAN orphan reap preserves mode-drifted stamped links.** A
  de-configured rustbgpd-stamped VXLAN orphan that has drifted into a
  collect-metadata / external or vnifilter mode — modes the fixed-VNI lifecycle
  never creates — is now preserved as owned-unsafe rather than reaped. A plain
  same-owner stamped orphan is still reaped; VNI / local / dstport / learning /
  bridge drift on a de-configured plain VXLAN remains reapable.
- **Managed VRF/L3VXLAN config validation hardening.** A `[[managed_netdevs.vrfs]]`
  `table_id` is now rejected when it names a Linux reserved table (`252`–`255`:
  compat/default/main/local) or collides with a `[[fib_tables]]` `table_id`, and
  a `[[managed_netdevs.l3vxlans]]` `vni` (L3VNI) is rejected when it equals any
  `[[managed_netdevs.vxlans]]` `vni` (L2VNI). These make lifecycle configs fail
  closed at load time before the dataplane actor can create conflicting links.

### Fixed

- **Cross-class mis-stamped managed netdevs surface as owned-unsafe.** The
  unconfigured/orphan managed-netdev status scan previously filtered each kernel
  link to ownership stamps of the class matching its kind, so a rustbgpd-stamped
  link carrying only a stamp of the wrong class for its kind (e.g. a bridge-kind
  link with only a `rustbgpd:vxlan:...` altname, or a VXLAN-kind link with only a
  `rustbgpd:bridge:...` altname) was dropped from status entirely. It is now
  reported as `owned-unsafe`, satisfying ADR-0091 Decision 6 that fail-closed
  states are observable, never silent. The class-exact reap gate is unchanged; the
  owned-unsafe reason text is reworded to name all owned-unsafe causes (wrong
  class, multiple stamps, or stamp/name mismatch).

## [0.41.0] — 2026-06-18

### Added

- **ADR-0090 all-active ESI overlay-index Type 5 receive contract.** The
  remaining RFC 9136 §4.3 receive-side work now has a dedicated ADR instead of
  growing ADR-0087 further: all-active RT-5 receive must project a deterministic
  remote-VTEP target set, install the prefix as route-level ECMP over the
  L3VXLAN device, program per-VTEP L3 neighbors, and use an L3VXLAN FDB
  nexthop-group for the shared Router MAC.
- **EVPN all-active ESI Type 5 projection model substrate.** The IP-VRF
  projection layer now distinguishes single-active, all-active, and conflicting
  EAD redundancy signals for RFC 9136 §4.3 ESI overlay-index Type 5 receive,
  and can model deterministic all-active remote-VTEP target sets while keeping
  conflicting mixed-mode signals fail-closed.
- **EVPN L3VXLAN FDB-NHG ownership substrate.** The Linux EVPN dataplane now has
  distinct L3 nexthop-ID ranges, L3 Router-MAC FDB-NHG owned-state/refcount
  types, and a separate L3 owned-nexthop dump surface so all-active ESI Type 5
  receive cleanup/adoption cannot be conflated with the existing L2 aliasing
  FDB-NHG domain.
- **EVPN all-active ESI Type 5 L3 diff boundary.** The daemon-facing remote
  IP-prefix model now carries an explicit single-target vs. all-active
  target-set shape, and the `evpn-linux` L3 diff validates all-active target
  sets before the writer. Single-member all-active target sets and incompatible
  target sets sharing one Router MAC fail closed instead of degrading to a
  scalar route or letting scalar state survive beside a multipath claim.
- **EVPN all-active ESI Type 5 L3 writer.** Valid RFC 9136 §4.3 all-active ESI
  overlay-index Type 5 target sets with at least two remote VTEPs now install as
  a VRF-table ECMP route over the L3VXLAN device, per-VTEP L3 neighbors, and an
  L3VXLAN Router-MAC FDB row pointing at an L3-tagged FDB nexthop group. The
  reconcile actor owns L3 member/group IDs separately from ADR-0059 L2 aliasing
  NHIDs, suppresses exact-repeat permanent L3 writer failures until the op shape
  changes, and cleans up the route, neighbors, FDB row, and nexthop objects on
  withdraw or all-active-to-single collapse.
- **LAN-77 all-active Type 5 L3 restart adoption.** Crash-leftover all-active
  L3VXLAN FDB-NHG rows now re-adopt the existing L3 NHID group/member tree at
  startup, reclaim the ECMP VRF route and every remote-VTEP neighbor, preserve
  the prior NHG ID on desired re-claim, and reap unreferenced L3 NHIDs through
  the L3 allocator namespace instead of leaking them or deleting the FDB row as
  a scalar single-dst entry. The `l3_all_active_writer` netns selector now also
  aborts and restarts the actor in the same namespace to prove the adoption path
  against the real kernel.
- **LAN-76 all-active Type 5 L3 writer netns proof.** The privileged Docker
  netns harness now has an `l3_all_active_writer` selector that drives a real
  `ReconcileActor<LinuxDataplane>` through the production writer path and
  asserts the kernel ECMP route, per-VTEP neighbors, L3-tagged FDB-NHG members,
  Router-MAC `nhid` FDB row, clean withdrawal, and restart adoption.
- **M72 GoBGP interop proof for all-active ESI overlay-index Type 5 receive.**
  The hosted kernel-dataplane workflow now extends M71's real-peer route-source
  shape to two GoBGP PEs advertising all-active EAD-per-ES / EAD-per-EVI state.
  rustbgpd first holds the Type 5 unresolved, then imports it as a VRF-table
  ECMP route over `l3vxlan100` with per-VTEP L3 neighbors and a Router-MAC
  `nhid` FDB row, then cleans the route, FDB-NHG, nexthops, and neighbors on
  target-set collapse and Type 5 withdraw. This closes the ADR-0090 real-peer
  proof gate for all-active receive.
- **LAN-70 L3VNI all-active Type 5 kernel-mechanism proof.** The
  privileged netns harness now has an `l3_multipath` selector that proves the
  Linux shape needed before implementing all-active RFC 9136 §4.3 ESI
  overlay-index Type 5 receive: a VRF-table route accepts multiple `onlink`
  nexthops through one L3VXLAN device, duplicate single-dst FDB rows for one
  Router MAC collapse to one destination, and an FDB nexthop-group row with
  `nhid` works on the L3VXLAN device and cleans up with its member/group
  objects.
- **LAN-78 EVPN VLAN-aware MAC+IP attribution.** AF_INET / AF_INET6
  neighbor events on VLAN upper devices such as `brvlan.10` now resolve through
  the configured `bridge_vlan` binding before emitting local Type 2 MAC+IP
  observations. The privileged netns harness adds a `macip_vlan_attribution`
  selector proving the same MAC+IP on VLAN 10 and VLAN 20 maps to VNI100 and
  VNI200 with no cross-VNI bleed. ARP/ND neighbor events reported on the raw
  `vlan_filtering=1` bridge ifindex still fail closed because Linux does not
  report bridge VLAN identity there.

### Changed

- **Clippy suppression reason ratchet expanded to `rustbgpd-api`.**
  `scripts/check-clippy-reasons.py` now covers `crates/api/src`, and the API
  crate's generated-proto, tonic `Status`, DTO-shape, and route-converter
  suppressions carry explicit `reason =` text.

## [0.40.0] — 2026-06-17

### Added

- **ADR-0089 EVPN VNI-per-broadcast-domain VLAN-aware bridge support.**
  The VLAN-aware bridge follow-up now has a precise v1 scope: Linux
  `vlan_filtering=1` support targets the existing one-VNI-per-broadcast
  domain EVPN model, keeps Type 2 / Type 3 / EAD-per-EVI Ethernet Tag ID
  at `0`, adds a local `bridge_vlan` binding for kernel attribution, and
  defers true RFC VLAN-aware bundle / non-zero-Ethernet-Tag service
  models plus SVD / managed-netdev support to separate gates. The ADR is
  the design gate for the implementation slices below.
- **EVPN bridge-VLAN schema/status plumbing.** `[[evpn_instances]]` now
  accepts optional `bridge_vlan` values from `1..=4094` when `bridge` is
  set, and `EvpnService.ListEvpnInstances` / `rbgp evpn instances` expose
  the local binding. The binding selects the local Linux VLAN scope for
  ADR-0089's VNI-per-broadcast-domain mode; EVPN Type 2 / Type 3 /
  EAD-per-EVI routes still use Ethernet Tag ID `0`.
- **EVPN VLAN-aware bridge readiness and FDB attribution.** L2VNIs with
  `bridge_vlan` can now become `Ready` on traditional Linux
  `vlan_filtering=1` bridges when exactly one VXLAN member matches the
  instance VNI and the configured VLAN is present on both the bridge and
  that VXLAN member. Single-dst and FDB-NHG remote-MAC writes include
  `NDA_VLAN`, snapshots / owned-state / adoption-reap bookkeeping are
  VLAN-scoped, and legacy instances without `bridge_vlan` still reject
  VLAN-aware bridges fail-closed.
- **EVPN VLAN-aware local-MAC attribution.** Kernel-learned AF_BRIDGE
  local-MAC events now resolve `(bridge port or VXLAN port, NDA_VLAN)` through
  the configured `bridge_vlan` bindings before emitting local Type 2
  observations. Missing, unknown, or duplicate VLAN attribution fails closed,
  while legacy non-VLAN-aware single-VXLAN bridges keep the existing ifindex
  path. A gated netns test covers the same MAC on VLAN 10 and VLAN 20 sharing
  one bridge with no cross-VNI bleed; MAC+IP ARP/ND observations on
  VLAN-aware bridges now fail closed and remain a separate follow-up pending
  kernel evidence.
- **M70 FRR interop proof for ADR-0089 VLAN-aware bridge FDB attribution.**
  The hosted kernel-dataplane suite now includes a rustbgpd ↔ FRR topology
  where rustbgpd owns one `vlan_filtering=1` bridge with VLAN10/VNI100 and
  VLAN20/VNI200 `bridge_vlan` bindings, while FRR uses traditional
  one-bridge/one-VXLAN-per-VNI topology. FRR originates the same MAC in both
  VNIs; rustbgpd programs `NDA_VLAN`-scoped rows on `vxlan100 vlan 10` and
  `vxlan200 vlan 20`, then a VNI100 withdraw removes only the VLAN10 row and
  leaves VLAN20 intact. The proof keeps Ethernet Tag ID `0` and deliberately
  uses the traditional fixed-VNI VXLAN shape; managed netdev creation and RFC
  VLAN-Aware Bundle service remain separate gates.
- **EVPN SVD / collect-metadata Ready and FDB programming.** L2VNIs with
  `bridge_vlan` can now become `Ready` on a shared `external` /
  collect-metadata VXLAN device when `vnifilter`, `nolearning`, bridge VLAN
  membership, and an unambiguous `bridge vlan ... tunnel_info id <VNI>`
  mapping all line up. Single-dst and FDB-NHG remote-MAC writes target the
  shared ifindex with `NDA_SRC_VNI`; FDB snapshots parse explicit-VNI rows,
  infer the configured VLAN when the tested kernel omits `NDA_VLAN`, and use
  owned state to avoid churn when the tested SVD echo omits `NDA_DST`. The
  privileged `svd_fdb_vni` netns selector now proves Ready + add + same-MAC
  two-VNI isolation + scoped delete on a real kernel. True RFC VLAN-aware
  bundle / non-zero-Ethernet-Tag service and managed netdev creation remain
  separate gates.
- **ADR-0088 EVPN VLAN-aware bridge / managed netdev boundary.** The EVPN
  roadmap now records the safety boundary for the remaining Linux VTEP
  operability gap: VLAN-aware programming requires an explicit
  EVPN-to-Linux binding, managed bridge / VXLAN / VLAN upper / VRF creation
  stays opt-in and class-scoped, and read-only Linux topology substrate can land before
  programming behavior changes. This is a decision document only; it adds no
  runtime feature.
- **EVPN L2 readiness API/CLI surface.** `EvpnService.ListEvpnInstances`
  and `rbgp evpn instances` now join each configured L2VNI with the
  Linux dataplane reconciler's latest `Ready` / `NotReady` / `Unbound`
  verdict. Bound instances without a report yet show `Unknown`; unbound
  instances are visible even before a dataplane report. `NotReady`
  rows carry the existing probe reason, including missing or ambiguous
  VLAN-aware bridge attribution.
- **EVPN read-only VLAN-aware topology substrate.** The Linux EVPN link
  inventory now requests `AF_BRIDGE` compressed bridge-VLAN data and
  snapshots bridge / port VLAN membership plus VLAN tunnel mappings for
  diagnostics and ADR-0089 readiness. Managed netdev creation remains
  deferred.
- **BGP-LS wire codec substrate.** The wire crate now exposes an
  unreachable RFC 9552 BGP-LS NLRI/TLV codec that preserves unknown NLRI
  types and TLVs opaquely and round-trips BGP-LS VPN route
  distinguishers. This does **not** enable BGP-LS negotiation,
  `MP_REACH_NLRI` / `MP_UNREACH_NLRI` dispatch, RIB storage, policy,
  API/CLI output, or MPLS dataplane behavior; those remain behind the
  ADR-0077 full-family checklist.
- **VPNv4/VPNv6 wire codec substrate.** `rustbgpd-wire` now has pure
  helpers for RFC 8277 MPLS label-stack entries and RFC 4364 / RFC 4659
  RD-prefixed VPN NLRI keys. The substrate preserves VPN route identity
  as Route Distinguisher + family-specific prefix without using the
  unicast `Prefix` enum, and keeps labels as route data rather than key
  identity. This does not enable VPNv4/VPNv6 negotiation, UPDATE
  dispatch, RIB storage, policy, API/CLI exposure, interop, label
  allocation, next-hop-self label rewrite, or MPLS dataplane behavior.
- **`rustbgpd-wire` 0.11.0 → 0.12.0 (additive).** The BGP-LS and
  VPNv4/VPNv6 codec substrates add public modules, round-trip helpers,
  proptest coverage, and fuzz targets without enabling those families in
  the daemon.
- **M67 link-driven Ethernet Segment drain churn soak harness.** New
  `tests/soak/m67-link-drain-soak.clab.yml`,
  `tests/soak/run-m67-link-drain-churn-soak.sh`, and
  `tests/soak/analyze-m67-link-drain-soak.py` repeat the ADR-0085
  production failure trigger for hours: pe1's bound AC loses carrier,
  the link drain withdraws its segment routes, pe2 promotes, traffic
  fails over, pe1 recovery is held, and pe1 re-wins DF. The analyzer
  gates sessions, restart counters, drain/DF transitions, bounded
  blackout/release timing, and RSS slope/peak. This adds the repeatable
  soak machine; it does not claim a new 24 h receipt until one is run
  and archived.
- **EVPN Ethernet Segment diagnose surface.** `EvpnService.ListEthernetSegments`
  and `rbgp evpn es list [ESI]` now join configured ES membership with
  live multi-homing runtime state: composed operator/link drain reasons,
  per-member DF role and BUM forwarding action, ADR-0085 same-ESI
  local-bias eligibility, single-active AC-gate state/interface, and
  matching owned FDB-NHG group / MAC-ref counts. The RPC is read-only
  (`sensitive_read`) and complements the existing `SetEthernetSegmentDrain`
  mutator.
- **M69 FRR interop proof for RFC 9785 preference-DF election.** The
  hosted kernel-dataplane suite now includes a rustbgpd ↔ FRR
  Ethernet Segment where rustbgpd advertises Highest-Preference with
  `df_preference = 100` and FRR advertises `evpn mh es-df-pref 200`.
  Default modulo carving for VNI 200 would elect rustbgpd, so the test
  proves the cross-vendor DF Election extended community drives the
  outcome: rustbgpd decodes FRR's Type 4 DF Election extcomm as
  Highest-Preference/preference 200, settles NonDF, and FRR reports
  itself DF with local preference 200 and remote preference 100.
- **ADR-0063 EVPN runtime convergence — mixed L2VNI composer.**
  `EvpnService.ApplyEvpnRuntime`, SIGHUP, and static `rustbgpd --diff`
  now treat L2VNI-only candidates that compose add/delete/redefine
  change classes, or redefine multiple standalone L2VNIs together, as
  coordinator-supported hot-apply shapes. The daemon composes the
  existing legs: added VNIs originate IMET, deleted VNIs withdraw IMET,
  redefined VNIs withdraw the old Type 3 key and originate the new one,
  IP-VRF link metadata is republished when the changed references belong
  only to added/deleted VNIs, and the dataplane/Type 2/SVI/segment
  consumers receive a single candidate instance snapshot before the
  runtime generation advances. The slice deliberately excludes
  ES-member deletes, arbitrary `ip_vrf` relinks on surviving/redefined
  VNIs, and IP-VRF/ES row changes; those broader mixed edits still fail
  closed.
- **M68 FRR consume-side interop proof for native GW-IP overlay-index
  Type 5 origination (ADR-0087).** The hosted kernel-dataplane suite now
  includes a rustbgpd → FRR topology where rustbgpd originates a
  Gateway-IP Type 5 from a static VRF route, FRR receives it with
  `enable-resolve-overlay-index`, holds it unresolved until the
  companion Type 2 MAC/IP route appears, then imports the prefix into
  the tenant VRF via the Gateway Address. The protected-recursion
  checks are target-scoped through FRR/kernel route JSON, and the
  unit suite now pins GW-IP fallback plus via appears/disappears
  re-origination without a withdraw pulse. The test also withdraws
  the static route and asserts FRR drops the imported VRF route.
- **RFC 9136 §4.3 ESI overlay-index Type 5 origination.**
  `[[evpn_ip_vrfs]] overlay_index_mode = "esi"` now originates local
  Type 5 routes with a configured non-zero ESI, zero Gateway Address,
  L3VNI in the label slot, and a Router's MAC extended community naming
  the configured virtual/transit MAC. The default remains
  `"interface_less"` and the shipped `"gateway_ip"` mode is unchanged.
  Config load fails closed unless the selected ESI exists in
  `[[ethernet_segments]]`, the IP-VRF has at least one linked L2VNI,
  ambiguous multi-L2VNI links specify `overlay_index_l2vni`, and that
  L2VNI is a member of the selected ESI. The companion receive-side
  substrate preserves Type 5 ESI and Ethernet Tag metadata and exposes
  a scoped EAD-per-EVI resolver index.
- **RFC 9136 §4.3 single-active ESI overlay-index Type 5 receive v1.**
  Remote non-zero-ESI Type 5 routes can now resolve through matching
  EAD-per-EVI protected-recursion state when the matched IP-VRF has a
  linked L2VNI and that EAD candidate is exactly one single-active
  remote VTEP. The Type 5 Router MAC remains the inner destination MAC,
  the resolved EAD next hop becomes the FIB next hop, and existing
  interface-less / GW-IP overlay-index behavior is unchanged. All-active
  and ambiguous ESI candidates stay fail-closed with bounded drop reasons
  until L3 multipath/NHG support and an all-active real-peer proof exist.
- **M71 GoBGP interop proof for ESI overlay-index Type 5 single-active
  receive.** The hosted kernel-dataplane suite now drives the RFC 9136
  §4.3 receive path against a real GoBGP route source: rustbgpd is the
  receive-side DUT with a full L3 datapath (vrf1 / L3VNI 100 + linked
  L2VNI 10), and GoBGP injects an ESI overlay-index Type 5 plus the
  Type 1 EAD-per-ES / EAD-per-EVI rows that resolve it. The four phases
  assert (1) the Type 5 alone is held unresolved
  (`evpn_ip_vrf_remote_prefix_drops{reason="unresolved_esi_overlay_index"}`),
  (2) adding the single-active EAD-per-ES + EAD-per-EVI imports the prefix
  into vrf1 with a kernel route via the PE VTEP, (3) advertising the
  same EAD-per-ES without the Single-Active flag withdraws the import and fails closed
  as a one-candidate all-active target set
  (`...{reason="unsupported_all_active_target_set"}`), and
  (4) withdrawing the Type 5 leaves vrf1 clean. GoBGP rather than FRR
  because the proof needs byte-exact, independent control over the
  EAD-per-ES Single-Active vs All-Active ESI Label flag, which FRR's
  all-active-only multi-homing cannot originate. All-active ESI overlay
  receive remains deferred (fail-closed by design).

### Changed

- **Typed transport peer-session command errors.** The transport command
  boundary now returns structured errors for route-refresh, live policy, and
  graceful-shutdown ACK failures while preserving the existing operator-facing
  error text at peer-manager/API boundaries.
- **Clippy escape-hatch reasons are now ratcheted across core protocol crates.**
  CI runs `scripts/check-clippy-reasons.py`, which requires every
  `#[allow(clippy::...)]` / `#[expect(clippy::...)]` in `crates/rib/src`,
  `crates/fsm/src`, `crates/policy/src`, `crates/rpki/src`, and
  `crates/evpn/src` to carry an explicit `reason = "..."`. Existing
  suppressions in those paths are backfilled; the script is intentionally
  path-scoped so future PRs can expand coverage one crate or file group at a
  time without churning the whole workspace.
- **CLI event JSON streaming now avoids an intermediate owned tree.**
  `rbgp watch events --json` / `rustbgpctl watch events --json` now serialize
  BGP event envelopes and EVPN route payloads through borrowed `Serialize`
  wrappers instead of cloning proto fields into a second `serde_json::Value`
  object before printing. The serialized output — including key ordering — is
  byte-for-byte identical to the previous `serde_json::Value` rendering for
  every event variant, asserted against a frozen pre-change reference builder
  by `direct_bgp_event_json_matches_legacy_value`.
- **Shared EVPN multi-homing interop helpers.** The M66 and M67
  rustbgpd-on-both-sides scripts now use common `test-lib.sh`
  helpers for rustbgpctl wrappers, EVPN route polling, Prometheus
  gauge reads, FDB/NHG parsing, ping probing, and AC-gate/drain-gauge
  checks. Scenario-specific phase assertions stay in the M scripts, so
  the receipt wording and failure points remain transparent.
- **Documented the EVPN standards-tail boundary.** The README, roadmap,
  comparison matrix, EVPN enablement guide, and ADR-0087 now distinguish the
  near-term VXLAN/Linux alpha gaps (notably overlay-index protected-recursion
  interop beyond the shipped GW-IP proof; ESI origination and single-active
  receive now ship, the single-active receive path now has the M71 GoBGP
  interop proof, and all-active ESI receive was split to the ADR-0090/M72
  follow-up that closes in v0.41.0) from demand-shaped service-provider EVPN
  breadth such as route types 6-11, PBB-EVPN, multicast EVPN/MVPN, VPWS/E-Tree,
  and MPLS/SRv6 service encapsulation.
  The docs also correct stale wording that tied EVPN Add-Path to RFC 9252:
  RFC 9252 is SRv6 BGP overlay services; future EVPN Add-Path work would use
  the general RFC 7911 Add-Path capability for AFI 25 / SAFI 70.
- **Pinned the EVPN Type-5 ESI protected-recursion prerequisites.**
  ADR-0087 and the roadmap now call out why all-active non-zero-ESI RT-5s
  still drop fail-closed after ESI origination and single-active receive
  shipped. The receive-side substrate carries Type-5 ESI and Ethernet Tag
  metadata and exposes a L2VNI-scoped EAD-per-EVI resolver index; the
  single-active receive path now has the M71 real-peer interop proof. In
  v0.40.0 the remaining work was L3 multipath/NHG receive policy for the
  all-active case; ADR-0090/M72 close that receipt gate in v0.41.0.
- **Tightened the ADR-0077 route-family substrate boundary.** Future
  BGP-LS, VPNv4/v6, RTC, and labeled-unicast work now has an explicit
  review rule: substrate-only PRs must remain unreachable from peers and
  operators, while anything negotiable/configurable must ship as a
  complete typed family slice with codec, RIB, policy, API, refresh/GR,
  metrics/caps, docs, and interop. This is documentation-only; rustbgpd
  still does not negotiate those families.

### Performance

- **CLI route JSON avoids cloning routes into an owned output tree.**
  `rbgp rib --json` / `rustbgpctl rib --json` and best-path explain JSON
  now serialize borrowed route fields directly instead of first cloning each
  route into `JsonRoute`. The emitted JSON bytes are preserved by equivalence
  tests against the previous owned builder.
- **Import-policy explain cache retains a compact policy context.**
  When `[policy.explain]` is enabled, cached import decisions now store the
  pre-policy fields needed for statement-level re-derivation instead of the
  full raw path-attribute vector. Explain output is unchanged, but live cache
  entries no longer retain attributes irrelevant to policy matching.

### Fixed

- **RTR encode length conversions are now checked, with typed errors.** The RTR
  encoder now returns `RtrEncodeError` for variable-length ASPA and
  Error Report PDUs whose computed length would overflow RTR's `u32`
  length fields, and the RTR client propagates that as a typed
  `RtrError`. Valid PDU bytes are unchanged.
- **Raw EVPN nexthop netlink encoders no longer panic on length overflow.**
  The ADR-0059 raw `RTM_NEWNEXTHOP` / `RTM_DELNEXTHOP` byte builders now
  return `NexthopEncodeError` for oversized netlink attributes or message
  lengths, propagate through `NexthopError`, and classify as permanent
  dataplane `InvalidArgument` failures instead of transient socket errors.
  Valid byte fixtures are unchanged.
- **EVPN hot-apply documentation drift.** `KNOWN_ISSUES.md`,
  `docs/CONFIGURATION.md`, and `docs/OPERATIONS.md` now describe the
  current ADR-0063 boundary: SIGHUP and `EvpnService.ApplyEvpnRuntime`
  share the coordinator for supported EVPN table shapes, while
  restart-only IP-VRF identity changes and ES/IP-VRF row mixed edits stay
  outside the hot-apply set.
- **No-op peer-group updates no longer bounce sessions.** Targeted
  peer-group mutations whose resulting config is structurally identical
  to the running snapshot now return success without publishing a policy
  event or rebuilding affected sessions. Real peer-group/session reshapes
  still take the captured-prior rebuild path and remain rollback-capable.
- **Fail-closed MP-BGP family dispatch for future route-family substrate.**
  `MP_REACH_NLRI` / `MP_UNREACH_NLRI` decoding now runs through one
  explicit supported-family classifier before any NLRI parser is called.
  Only the currently complete verticals are accepted — IPv4/IPv6 unicast,
  IPv4/IPv6 FlowSpec, and L2VPN EVPN. Recognized but unsupported
  combinations such as IPv4/IPv6 multicast, non-L2VPN EVPN, or L2VPN
  FlowSpec now reject at the family gate instead of falling through to
  unicast `Prefix` decoding. No BGP-LS, VPN, RTC, or labeled-unicast
  support is enabled by this guard.
- **Completed the RIB session-identity gate for policy-context updates.**
  `SetPeerPolicyContext` is now stamped with the transport `session_id`
  and discarded when it comes from a superseded session, matching the
  existing stale-message contract for routes, EoR, route-refresh, and
  ORF updates. The
  `bgp_rib_stale_session_message_ignored_total{peer,kind}` counter now
  includes the bounded `policy_context` kind. Matching-session and
  unregistered legacy behavior are unchanged.
- **Hardened EVPN single-active multi-homing edge cases.** The
  single-active AC gate now refuses to overwrite STP-owned bridge-port
  states (`listening`, `learning`, `blocking`) on a bound access
  circuit: it warns and leaves the port untouched until the kernel
  reports a rustbgpd-owned `disabled` / `forwarding` state. The
  ADR-0083 backup-swap path also has a regression test for a failed
  group membership `REPLACE`: the old active group remains intact, the
  MAC row keeps pointing at it, the pre-created backup nexthop stays
  available for retry, and the failure is reported instead of counted
  as a completed swap.
- **Shape-aware EVPN runtime `--diff` classification.** Static config
  diffs now put ADR-0063/ADR-0085 coordinator-supported EVPN shapes
  (single L2VNI/IP-VRF/ES edits, additive build-up, tenant teardown,
  `ip_vrf` relink, and ES binding-only edits) in the reload-applied
  bucket instead of blanket restart-required. Unsupported mixed edits
  and restart-only IP-VRF identity changes remain restart-required,
  matching SIGHUP's runtime behavior more closely while still leaving
  actor availability/convergence failures as runtime outcomes.

## [0.39.0] — 2026-06-13

### Added

- **Native GW-IP overlay-index Type 5 origination (RFC 9136 §4.1/§4.2,
  ADR-0087).** A new per-IP-VRF `overlay_index_mode` knob on
  `[[evpn_ip_vrfs]]` opts into originating EVPN Type 5 routes with a
  non-zero Gateway Address. In `"gateway_ip"` mode a local kernel
  route whose via lands on a connected subnet of the VRF is
  originated with that via in the Type 5 Gateway Address and **no**
  Router's MAC extended community (RFC 9136 §3.2 makes it
  ignored-if-present for the GW-IP overlay index); receivers resolve
  the gateway recursively through its Type 2 MAC/IP route — the
  receive-side recursion rustbgpd already shipped. Routes without an
  eligible via (off-subnet, cross-family, or no via) fall back to the
  interface-less shape, and the default (`"interface_less"`) is
  byte-for-byte the pre-ADR-0087 behavior — no change unless opted in.
  The kernel-route observation layer now carries the via, the L3
  originator selects the gateway per-pass against the VRF's connected
  subnets and re-originates in place on a via change (one UPDATE, no
  withdraw/announce pulse — the route key excludes the gateway), and
  the L3VNI stays in the label slot in both modes (deviating from the
  §3.1 SHOULD-zero to match our own receive side and FRR). Config load
  rejects `"gateway_ip"` on an IP-VRF with no `ip_vrf`-linked L2VNI
  (the receive side needs the link to scope the recursive lookup). A
  self-consistency test feeds a natively-originated GW-IP route back
  through the daemon's own projection with a matching Type 2 present
  and asserts it resolves end-to-end. ESI overlay-index origination
  (RFC 9136 §4.3) and the FRR consume-side interop M-job are explicit
  follow-ups.
- **`cargo deny` dependency gate.** `deny.toml` enforces a
  permissive-license allowlist, registry-source pinning, wildcard
  bans (with a path-dependency exemption for the deliberately
  unversioned decoupled `rustbgpd-wire`), and RustSec advisories; CI
  runs `cargo deny check advisories bans licenses sources` as a
  second job in the security-audit workflow beside `cargo audit`, on
  the same manifest/lockfile path scope plus the gate configs.
- **Peer-group field edits now reach live dynamic sessions on the
  config-transaction path (ADR-0086, closes the ADR-0081 decision-4
  deferral).** A peer-group edit affecting a `[[dynamic_neighbors]]`
  range (e.g. `hold_time`) previously classified as unsupported
  "effective neighbor inheritance impact" and was rejected by
  `ApplyConfigTransaction` / gNMI Set, while the live sessions kept
  their old config until a natural reconnect. The session reshape
  executor now commits it: static members are reconfigured in place
  with captured priors exactly as before, and — only after the
  transaction persists — the live dynamic sessions accepted by each
  affected range are gracefully reset (Cease NOTIFICATION with an
  RFC 8203 shutdown communication, `"peer-group configuration
  change"`). The remote's reconnect is re-accepted under the committed
  config (snapshot staging advances the accept matcher before
  persist), and `dynamic_neighbor_limit` slot accounting stays owned
  by the normal session-idle reaping — the reset never delete/re-adds
  an ephemeral peer. A failed transaction never flaps a dynamic peer
  (pinned by test); a session that cannot be signaled keeps its
  running config until reconnect and is reported in the apply
  response, never silently swallowed. Dynamic-range peer-group
  *reassignments* remain outside the reshape family (a
  `[[dynamic_neighbors]]` record edit; sessions accepted under the
  old group cannot be live-reassigned). SIGHUP / targeted peer-group
  RPCs now hot-apply policy-only peer-group edits to live dynamic
  sessions through the resolved-policy fanout; session-shaping edits
  keep the reconnect/reset semantics described above (see ADR-0086).
- **Canonical ingress reason-label contract
  (`crates/telemetry/src/reason_labels.rs`).** The reason strings
  that ingress route-rejection mechanisms report are now a single
  typed vocabulary shared by every surface — Prometheus label values,
  log-line `reason` tokens, and the structured `OTC_ROUTE_BLOCKED`
  event payload — instead of free-form `&str` literals repeated per
  call site. `OtcBlockReason` (RFC 9234: `ingress_from_customer_rsclient`,
  `ingress_peer_mismatch`, `malformed_length`,
  `egress_to_upstream_via_otc`) is enforced at compile time through
  the `bgp_otc_routes_blocked_total` recorder and the transport event
  payload; `RrLoopReason` (`originator_id`, `cluster_list`) pins the
  RFC 4456 §8 log token. Tests pin the exact strings — renaming one
  now fails a test and must be called out as a breaking observability
  change. **No metric names, label sets, or metric label values
  changed.** One log-only token changed: the debug-level
  "Route reflector loop detected" line's `reason` field is now
  snake_case per the contract — `ORIGINATOR_ID` → `originator_id`,
  `CLUSTER_LIST` → `cluster_list`. `docs/OPERATIONS.md` gains an
  "Ingress rejection / route-leak detection" metric table listing the
  canonical reason values per metric, plus the previously
  undocumented `bgp_fib_routes_rejected_total{reason="link_local_next_hop_scope_missing"}`
  row; `docs/deployment.md` now uses the real metric names
  (`bgp_as_path_loop_detected_total`, `bgp_rr_loop_detected_total`,
  `bgp_max_prefix_exceeded_total` — the `_total` suffix was missing —
  and the nonexistent `bgp_routes_received_total` /
  `bgp_routes_installed_total` references were replaced with
  `bgp_rib_prefixes` / `bgp_rib_loc_prefixes`).
- **Coordinator-level invariant tests for the EVPN cross-actor seams
  (the ROADMAP seam audit).** The Ethernet Segment lifecycle spans
  the segment actor (Type 1/4, DF election, bias/AC-gate snapshots),
  the local Type 2 originator, the drain coordinator, and the
  link-drain coordinator; the invariants each assumes about the
  others are now pinned where they are observable: one drain through
  `apply_ethernet_segment_drain` withdraws across BOTH real actors
  and the undrain replays exactly the preserved live kernel state (a
  MAC aged out while drained must not return, one learned while
  drained must); the reverse actor-publish order converges to the
  same withdrawn state (the documented either-order-converges
  contract); drain mutations serialize behind the EVPN runtime apply
  lock; a failed originator publish rolls the segment fanout and the
  shared drain state back together; a GC'd, re-added ESI starts
  undrained inside the segment actor; bias eligibility can never
  coexist with a Blocked AC gate (exhaustive mode × drain × binding ×
  DF-role matrix); a DF flip republishes the bias and AC-gate
  snapshots together; a bound ES whose AC is down at boot converges
  to drained + bias-ineligible + gate-blocked through the real
  segment actor; and an unrelated runtime L2VNI add preserves an
  operator drain on every actor model. The audit also annotated
  ADR-0084 with a found split-state window on a failed ES-delete
  apply (tracked on the ROADMAP, not fixed here).

- **RIB distribution-health observability for the wedged
  post-Established advertisement path (ROADMAP, observed in an M66 CI
  run).** Root-cause analysis identified a silent failure mode:
  `PeerUp`/`PeerDown` carry no session identity, so when two sessions
  for one peer overlap during the RFC 4271 §6.8 collision window, a
  stale collision-loser `PeerDown` processed after the winner's
  `PeerUp` deregisters the live session's outbound sender — every
  later advertisement is silently skipped (never dirty-marked, no
  resync, no log) while the session stays Established on writer-owned
  keepalives. A manager-level characterization test now pins the
  mechanism. New metrics make the next occurrence self-diagnosing:
  `bgp_rib_outbound_registered_peers` (gauge; fewer registered peers
  than Established sessions = a wedged advertisement path),
  `bgp_rib_outbound_registration_replaced_total{peer}` (a `PeerUp`
  replaced a still-registered sender — the collision-overlap
  precondition), `bgp_rib_dirty_resync_total{outcome}` (resync-timer
  fires by `cleared`/`still_dirty`), and
  `bgp_rib_ingest_channel_depth` (sampled RIB manager ingest queue
  depth). The RIB manager also WARNs when a `PeerUp` replaces a live
  registration and INFO-logs every outbound deregistration. The
  session-identity fix itself shipped separately — see "Silent
  advertisement wedge after a BGP session collision" under Fixed.
- **Statement-level attribution in `rustbgpctl policy explain` — the
  decision trace now names WHICH statement inside the matched import
  chain decided, not just which policy.** Each `permit` / `deny`
  match gains a `statements` trace: one step per policy the chain
  evaluated, carrying the policy index + name, the index of the
  matching statement (or a default-action fallthrough marker when
  nothing matched), the action it contributed, the conditions the
  statement matched (stable leading labels: `prefix`, `community`,
  `as_path`, `neighbor_set`, `rpki`, `local_pref`, … or `any` for an
  unconditional statement), and the attribute edits it contributes
  rendered as `before -> after` against the route's pre-policy
  values (`local_pref 100 -> 200`). A deny ends the trace at the
  denying policy — later policies were never consulted and get no
  step. The trace is re-derived at query time from the cached compact
  pre-policy context (ADR-0073 decision cache) against the
  session's import chain, so the inbound UPDATE hot path records
  nothing new; the explain-only chain walk is pinned to the live
  evaluator by an agreement matrix in the policy crate, and the
  evaluation-time next-hop is now stored alongside the cached
  attributes so the reconstruction is exact (MP-unicast next-hops
  live in MP_REACH framing, which the stored attributes drop).
  Statement traces attach only to current-generation `permit` /
  `deny` outcomes: `stale` entries were decided by a chain that no
  longer exists, `withdrawn` tombstones have shed their attributes,
  and `evicted` / `not_seen` carry no decision. Surfaces:
  `ExplainImportPolicy` gains `repeated ImportExplainStatementStep
  statements` per match (no new RPC, authz unchanged), the CLI text
  renderer prints a `statements:` section, and `--json` gains a
  run-stable `statements` array per match.
- **Single-active non-DF full AC blocking: the whole-port
  attachment-circuit gate.** RFC 7432 single-active redundancy
  requires the non-DF PE to block **all** traffic on the segment AC —
  known unicast included — but Gate 8b's DF enforcement only set the
  per-port BUM flood flags (correct for all-active, insufficient for
  single-active: the non-DF bridge still forwarded known unicast, so
  a dual-homed CE could see duplicate delivery or have its return
  path pulled to the non-forwarding PE). The dataplane now also
  drives the bound AC bridge port's whole-port state
  (`IFLA_BRPORT_STATE`): blocked (`state disabled`) while this PE is
  non-DF for **every** member VNI of the ES or the ES is drained
  (maintenance semantic — the ADR-0085 recovery hold-off keeps the
  port blocked until the segment re-converges), forwarding when DF.
  Scope and caveats, stated plainly: the gate applies only to
  **single-active segments with an ADR-0085 `interface` binding**
  (the binding provides the port handle; unbound segments stay
  BUM-flood-only — one more reason to bind), it is gated behind the
  same `apply_bum_enforcement` knob as the flood flags, and it is
  **per port, not per VLAN** — when RFC 8584 service carving splits
  the DF roles across an ES's member VNIs the port stays forwarding
  with BUM-only enforcement and the condition is surfaced via a
  structured warning plus the new
  `evpn_es_ac_gate{esi, state="blocked"|"forwarding"|"mixed-roles"}`
  gauge (single-VNI ESes, the common case, always get full
  enforcement). The reconciler diffs desired against the *observed*
  kernel port state every pass because the kernel re-enables a
  disabled port when carrier returns — that drift self-heals on the
  next reconcile wake. Removing the ES/binding (or daemon shutdown)
  restores the port to forwarding; a disabled port is never left
  orphaned. Do not run kernel STP on a bound AC — both would fight
  over the same per-port state. Proven in CI by new M67 asserts
  (non-DF blocked at steady state, promoted DF re-opened before the
  flood-path relearn, demoted PE re-blocked after the revert) and a
  privileged netns round-trip that also pins the flood-flag
  non-clobber (the gate message carries only the state attribute).

- **M67 interop proof for the ADR-0085 link-driven Ethernet Segment
  drain: a real AC failure drives the failover end-to-end, no RPC in
  the path.** New `kernel-dataplane` CI job — the M66 sibling with
  the production trigger, closing the four-slice ADR-0085 arc. Same
  five-node topology (two full-dataplane rustbgpd single-active
  segment PEs behind a rustbgpd VTEP/RR, a host pinging the
  dual-homed CE at a 100 ms grain), but the PEs bind their CE-facing
  attachment circuit (`interface = "eth2"`,
  `recovery_delay_secs = 5`) and the stimulus is
  `ip link set eth2 down` inside the active PE — the binding watches
  that PE's own ifindex carrier, and the veth peer (the CE leg)
  drops with it: cable-pull semantics. Hard asserts on the
  mechanism: the carrier monitor armed and every
  `evpn_es_drained{esi, reason}` gauge 0 at steady state; on AC loss
  the `link` reason goes 1 with the operator reason untouched, the
  RFC 7432 §8.2 mass-withdraw shape (all four route classes) leaves
  the VTEP while the peer PE's routes survive, the backup promotes
  to DF and the VTEP hands the CE MAC to exactly the backup; on
  carrier return the recovery hold-off demonstrably holds (gauge
  still 1 on every sub-second sample through up+3 s against the 5 s
  window) before releasing; a down-up-down-up flap inside the
  hold-off stays drained past the first up's would-be deadline
  (proving the per-up-edge re-arm) and recovers only after the last
  up + hold-off; and the drain reasons compose — an operator drain
  survives a full link down/up cycle and only the operator undrain
  restores origination. Failover blackout measured informationally
  (100–300 ms locally; unlike M66's RPC drain the AC is really
  dead, so this is the genuine end-to-end failover) under a
  generous < 30 s bound. Re-runnable against a live topology: a
  prior cycle's shared-ESI co-advertisement (legitimate RFC 7432
  aliasing once the CE has spoken on both legs) downgrades the two
  fresh-bring-up-only steady-state pins to informational.
- **Same-ESI local bias in the remote-MAC projection (ADR-0085
  slice 3 — decision 5).** A multi-homed PE no longer lets a peer
  PE's Type 2 usurp its own healthy attachment circuit: a remote
  MAC/MAC-IP route whose ESI is locally attached (via the
  `[[ethernet_segments]].interface` binding), healthy, not drained,
  and **entitled to forward** is suppressed from remote-FDB intent —
  the local AC is the correct egress, and per RFC 7432 §15.1 same-ES
  reachability is not mobility (the usurpation M66 surfaced is fixed
  at its root). Entitlement is DF-aware: all-active members always
  qualify; in single-active mode only the DF does — a healthy
  single-active **backup keeps the remote row toward the active PE**
  (its AC is non-forwarding; biasing there would blackhole). MAC-IP
  neighbor rows follow the MAC's bias: the host's L3 adjacency also
  resolves on the local AC. The bias lifts the moment the segment
  drains (operator or link reason, including the recovery hold-off)
  or loses entitlement — remote rows then program and the peer PE
  takes over, which is the M66 takeover behavior by design instead of
  by usurpation. Unbound segments (no `interface`) keep today's
  behavior — AC health is unknowable without the binding. Published
  by the segment actor as a per-`(ESI, VNI)` eligibility snapshot
  next to the BUM-enforcement flow; the dataplane supervisor
  re-projects on every snapshot change, so the desired state stays a
  pure function of the EVPN RIB and the published snapshots.
- **Best-path explain now names the tiebreaker that won — with the
  compared values.** `rustbgpctl rib --prefix X --explain` (RibService
  `ExplainBestPath`) already annotated each losing path with the
  decisive RFC 4271 §9.1.2 step; the trace now also carries, per loser,
  the compared values behind that step (`vs_best_detail`, e.g.
  `local_pref 100 < 200` or `as_path_len 3 > 1`), a winner-level
  `best_reason` + `best_reason_detail` naming the step that eliminated
  the runner-up — the deepest-surviving competitor — (`only_path` for a
  single-path prefix), and a per-candidate `multipath` classification
  (`eligible` / `relax_only` / `none`) showing which losers would still
  survive the ADR-0066 equal-cost multipath cut. Asking about a prefix
  with no paths in any Adj-RIB-In now returns a clean `NOT_FOUND`
  instead of an empty trace. The attribution is re-derived on demand
  from the current Adj-RIB-In paths through the explain-only comparison
  ladder; the hot-path comparator is untouched (agreement pinned by a
  per-step matrix and a property test). Text and `--json` CLI renders
  both carry the new fields.
- **Link-driven Ethernet Segment drain (ADR-0085 slice 2 — decisions
  1–3).** `[[ethernet_segments]]` gains an optional
  `interface = "<linkname>"` binding: the ES's drain state now follows
  the bound attachment circuit's carrier. Carrier loss (cable pull or
  admin down — the `IFF_LOWER_UP` bit) drains the segment immediately,
  producing the RFC 7432 §8.2 mass-withdraw shape with no operator
  action; a bound link absent from the kernel counts as down
  (fail-closed). Recovery is held off by the new per-ES
  `recovery_delay_secs` (default 30, range 0–3600; rejected without
  `interface`): the hold re-arms on every up edge, so a flapping
  circuit stays drained until it holds carrier for the full window.
  Down is always immediate; startup applies the first probe directly
  (an ES whose AC is down at boot starts drained, up at boot
  originates immediately). Drain state is now **reason-keyed** and
  reasons compose: the ADR-0084 RPC owns the `operator` reason, the
  binding owns `link`, and the ES stays drained while either holds —
  an operator undrain never overrides a dead link, and link recovery
  never overrides a maintenance drain. The `SetEthernetSegmentDrain`
  response and `rustbgpctl evpn es drain`/`undrain` now report the
  composed state plus the reason set, and the new
  `evpn_es_drained{esi, reason}` gauge answers "why is this ES
  drained" in Prometheus. SIGHUP / `ApplyEvpnRuntime` may add, change,
  or remove bindings at runtime: a binding change re-evaluates against
  the new link immediately, and removing the binding clears any `link`
  drain. Consumes the slice-1 carrier monitor (spawned lazily when the
  first binding appears, dropped when the last one goes).
- **EVPN link carrier monitor (ADR-0085 slice 1).** New standalone
  monitor in `rustbgpd-evpn-linux`
  (`linux::link_carrier::spawn_link_carrier_monitor`): subscribes to
  `RTNLGRP_LINK` on a dedicated rtnetlink connection and projects
  per-link **carrier** state — the `IFF_LOWER_UP` bit in the link
  flags, deliberately not `IFLA_OPERSTATE` (ADR-0085 decision 1) —
  for a watched set of link names into a `tokio::sync::watch`
  channel. Resolution is by name on every event (ifindex reuse is
  real; names are the operator contract); a watched name with no
  kernel link is published as down, fail-closed. Startup applies the
  first-probe walk directly before any event processing, a 10 s
  re-walk backstop heals missed netlink messages, the watch only
  publishes on actual change, and the watched-name set is replaceable
  at runtime with immediate re-evaluation (the SIGHUP path slice 2
  needs). Proven against a real kernel by a netns veth carrier-flap
  test (`link_carrier` selector in the netns Docker harness). First
  of four ADR-0085 slices: pure infrastructure — nothing consumes the
  monitor yet, no daemon wiring, no config keys, no behavior change.
- **M66 interop proof for the ADR-0084 Ethernet Segment drain: a
  service handover with rustbgpd on BOTH sides.** New
  `kernel-dataplane` CI job — the proof M65 couldn't be (M65 needed
  GoBGP PEs because rustbgpd had no origination-side withdrawal
  stimulus; the runtime drain is that stimulus). Two full-dataplane
  rustbgpd PEs share a single-active ES (RFC 9785 highest-preference
  DF) behind a rustbgpd VTEP/route-reflector, with a host pinging the
  dual-homed CE at a 100 ms grain. Hard asserts on the mechanism:
  steady state (Type 4 + EAD-per-ES + EAD-per-EVI from both PEs,
  CE-MAC Type 2 from the DF only, the ADR-0083 one-member NHG with
  the backup NH pre-created), the ADR-0064 operator_only ceiling via
  rustbgpctl (observer principal → PermissionDenied, unknown ESI →
  NotFound), the drain (all four route classes withdrawn while the
  peer PE's survive, idempotent repeat reports `changed=false`, df
  gauge → 0, the peer promotes to DF), the service handover (the
  surviving PE learns the CE MAC through the flood path, originates
  its own Type 2, and the VTEP's CE-MAC FDB row re-resolves toward
  it), SIGHUP-while-drained non-resurrection (a live L2VNI-add reload
  demonstrably applies while the drained ES stays withdrawn —
  ADR-0084 decision 3), and the undrain (Type 4 + both EAD classes
  return immediately, the drained PE re-wins DF revertively, and
  after one CE maintenance-exit ARP broadcast the CE-MAC Type 2 and
  end-to-end service are asserted back — the broadcast routes around
  two pre-existing daemon gaps the proof surfaces and documents in
  the topology header: no same-ESI local bias in the PE remote-MAC
  projection, and no local-delete observation for the in-place FDB
  port move that usurpation performs). The blackout window is
  informational with
  a generous < 30 s bound: the BUM-flood-only enforcement limit (a
  drained/non-DF AC does not block known unicast) keeps the observed
  gap near zero while the control-plane handover completes behind it.
- **Runtime Ethernet Segment drain for access-circuit maintenance
  (ADR-0084).** `rustbgpctl evpn es drain <esi>` (and `undrain`)
  withdraws one configured ES's Type 4 + EAD-per-ES + EAD-per-EVI
  routes (exiting DF election) and the member VNIs' locally-originated
  Type 2 MAC/MAC+IP routes, and suppresses new local-MAC origination
  while drained — remote PEs' ADR-0083 single-active backup swap then
  repairs traffic around this PE before you touch the circuit.
  Undraining re-originates the ES routes, re-runs DF election, and
  replays the cached local MAC/IP state (the kernel keeps the cache
  fresh during the drain). Backed by the new operator-only
  `EvpnService.SetEthernetSegmentDrain` gRPC method; unknown ESIs
  return `NOT_FOUND`, repeats are idempotent no-ops, and drain state
  survives SIGHUP/runtime applies that keep the ES configured.
  **Caveat:** drain state is in-memory — a daemon restart clears it
  and replays configured state.
- **M65 interop proof for the ADR-0083 single-active backup path:
  failover blackout measured on a live kernel (slice 4 — closes the
  ADR).** New `kernel-dataplane` CI job: rustbgpd is the remote VTEP
  (receive side); two GoBGP-driven PEs share a single-active ES, and a
  host behind the DUT pings the dual-homed CE at a 100 ms grain across
  an AC failure injected as the RFC 7432 §8.2 mass-withdraw wire shape
  (active PE's CE leg down + its EAD-per-ES withdrawn, MAC routes
  retained). Hard asserts on the mechanism: the slice-2 pre-install
  (one-member FDB nexthop group + the backup PE's nexthop pre-created
  but not a member), the slice-3 swap (the SAME group retargeted to the
  pre-created standby id in one membership replace — nothing allocated,
  the MAC row's `nhid` held continuously, the withdrawn PE's nexthop
  GC'd, swap counter == 1, backup-active gauge == 1), the last-PE
  ordered teardown (rows flushed, group gone, teardown counter == 1,
  pings hard-dead — no flood entries exist in the topology, so the swap
  is provably the only restoration path), and foreign FDB rows + an
  untagged fdb nexthop untouched throughout. The blackout window is
  informational, with one generous < 30 s hard bound: **~4.5 s on local
  hardware (both validation runs), AC-failure case** — dominated by the
  dataplane supervisor's 5 s RIB-poll cadence, not the swap itself
  (one `NLM_F_REPLACE`); the event-driven intent recompute shipped
  below under *Changed* shaves the repair to ~0.3 s and tightens the
  bound to 3 s.
  The PEs are GoBGP because no in-tree origin can emit the stimulus:
  rustbgpd originates the Single-Active flag fine but has no
  AC/interface binding for an ES (config-removal SIGHUP drains and
  synchronously re-keys the VNI's Type 2 routes, destroying the swap
  window), and FRR's EVPN multihoming is all-active only.

- **EVPN single-active failover becomes a local repair: the backup-PE
  swap on EAD-per-ES withdrawal (ADR-0083 slice 3).** When the active
  PE of a single-active Ethernet Segment withdraws its EAD-per-ES (CE
  link down, segment de-configured) and at least one eligible PE
  survives, the RFC 7432 §8.2 mass-withdraw no longer flushes the
  segment's remote MACs into a flood-and-relearn wave. Instead, each
  affected `(ESI, Ethernet Tag)` nexthop group is atomically retargeted
  at the slice-2 pre-created backup PE with **one** `RTM_NEWNEXTHOP`
  `NLM_F_REPLACE` per group — every MAC row behind the group follows in
  that single kernel operation; the rows themselves are untouched, and
  the swap allocates nothing (the backup's nexthop object already
  exists). The standby then re-pins to the next-lowest surviving PE
  (pre-creating its nexthop if needed) before the withdrawn PE's
  nexthop is garbage-collected, and a withdrawal that empties the
  eligible set keeps today's ordered teardown (MAC rows removed before
  the group — never through empty — with the standby reaped alongside).
  Desired membership stays a pure function of the EVPN RIB (ADR-0083
  decision 5): the post-swap window is just what that function yields
  while the dead PE's MAC routes outlive its EAD-per-ES, so a daemon
  restart inside the window re-derives the swapped state from the
  reloaded RIB, and the new active PE's eventual re-advertisements
  converge to the identical dataplane state whether or not the swap
  fired. **Bounded honestly:** the repair at each remote VTEP is one
  netlink message per affected group once the withdrawal *arrives*;
  end-to-end blackout is still floored by withdrawal propagation, by
  the segment's own DF re-election unblocking the backup's access
  circuit (expect drops at the backup egress until then — the new
  `evpn_single_active_backup_active` gauge makes that window legible),
  and, for PE *node* failure, by BGP session death (hold timer / BFD to
  the RR); cutting detection latency needs liveness toward the VTEP
  itself, which is a future ADR. New observability:
  `evpn_single_active_backup_swaps_total`,
  `evpn_single_active_teardowns_total`, the
  `evpn_single_active_backup_active` gauge, and an info-level log at
  the swap site naming VNI/ESI/Ethernet Tag/old PE/new PE.

- **EVPN single-active backup-path dataplane pre-install (ADR-0083 slice
  2).** Single-active remote MACs with at least one other eligible PE on
  the segment now route through the FDB nexthop-group machinery instead
  of plain single-dst rows: the projection gives each such MAC a
  per-`(ESI, Ethernet Tag)` group key with a **one-member** desired
  membership (the active PE), and the reconcile actor programs the
  per-VTEP fdb nexthop for the active PE, **pre-creates the backup PE's
  per-VTEP fdb nexthop** (so the future failover swap allocates nothing
  — slice 3), installs the one-member group, and points the MAC rows at
  it via `NDA_NH_ID`. The backup NH is deliberately *not* a group member
  (the kernel hashes over all members; single-active means exactly one
  egress forwards) — a new *standby* reference class in the dataplane's
  group refcounting pins it while the `(ESI, Ethernet Tag)` intent
  lives — the ADR-0059 drift sweep tracks and heals it like any owned
  NH, but it is exempt from the orphan reap — and reaps it when the
  intent disappears. Single-active MACs whose ES
  has **no** other eligible PE keep today's single-dst rows (ADR-0083
  decision 1's no-backup fallback); all-active aliasing and the
  RFC 7432 §8.2 mass-withdraw flush are unchanged this slice (the
  EAD-withdrawal swap reinterpretation is slice 3). NHG-backed rows stay
  under the ADR-0059 drift sweep's jurisdiction — the ADR-0079
  single-dst adoption sweep neither adopts nor reaps them.

- **EVPN single-active eligible-PE set / backup-PE derivation (ADR-0083
  slice 1).** New pure-logic layer in `crates/evpn/src/aliasing.rs`
  (`SingleActiveEligibleIndex`, `SingleActiveBackupView`): for a
  single-active `(ESI, Ethernet Tag)`, derives the RFC 7432 §8.4
  eligible-PE set — every VTEP advertising *both* an EAD-per-ES with the
  Single-Active flag set and an EAD-per-EVI for the key — and the backup
  PE (numerically lowest VTEP IP excluding the primary, per ADR-0083
  decision 2). Desired state is a pure function of the EVPN RIB snapshot
  (ADR-0083 decision 5), so crash-restart, the drift sweep, and the
  EAD-withdrawal event path converge on the same answer. First of four
  ADR-0083 slices: derivation only, no dataplane or projection
  behavior change in this slice (the slice-2 entry above adds the
  consumer).

### Changed

- **The general-FIB and BLACKHOLE reconcilers now wake on kernel route
  drift instead of waiting out the 30 s periodic pass.** Each actor's
  NETLINK_ROUTE connection subscribes to `RTNLGRP_IPV4_ROUTE` /
  `RTNLGRP_IPV6_ROUTE` (`src/kernel_route_notify.rs`, the evpn-linux
  notify-task pattern), and a pure per-actor classifier decides what
  is drift of owned state: a deleted row carrying the actor's
  ownership signature (`proto bgp` at a configured
  `[[fib_tables]]` table/metric identity, or the ADR-0079
  `proto bgp` + blackhole marker in `main`), or a foreign-protocol
  replace landing on an exact owned route identity. Qualifying events
  coalesce into one reconcile through the existing 200 ms debounce
  shared with the RIB-event path, so externally deleted or clobbered
  routes are repaired in ~0.2 s instead of up to 30 s; install echoes
  and unrelated host churn never wake the actors, and the 30 s pass
  remains as the level-triggered backstop (it alone catches a replace
  that spoofs `proto bgp`). Subscription failure degrades to exactly
  the previous periodic-only behavior.
- **EVPN L3 neighbor adoption now requires the NDA_PROTOCOL `RTPROT_BGP`
  ownership stamp by default (ADR-0082 strict flip).** The stamp-or-legacy
  migration window v0.38.0 opened is closed: the crash-restart adoption
  sweep (ADR-0079) no longer adopts a stamp-less `extern_learn` + permanent
  L3 neighbor row — the shape a pre-stamp rustbgpd left behind — and
  classifies it as foreign instead (preserved untouched, never reaped).
  Foreign stamps (e.g. zebra's `proto zebra`) remain refused, FDB
  classifiers stay in prefer mode (mainline AF_BRIDGE does not store the
  attribute), and install-side stamping is unchanged from v0.38.0.
  **Upgrade gate:** operators upgrading from v0.37.0 or earlier must run
  v0.38.0 (which stamps every row it installs or re-claims) at least once
  before this version, or set `RUSTBGPD_EVPN_ADOPTION_ACCEPT_LEGACY=1` for
  the first boot — it restores the stamp-or-legacy acceptance rule for that
  run, and the re-claims stamp the rows so the variable can then be
  dropped. The M61 kill-and-restart job now proves the strict default: a
  planted stamp-less legacy-shaped neighbor survives the sweep untouched
  (the pre-flip rule would have adopted and reaped it), alongside the
  existing `protocol zebra` foreign-row survival assert.

- **EVPN dataplane intent recompute is event-driven; single-active
  failover repair drops from ~4.5 s to ~0.3 s.** The dataplane
  supervisor now subscribes to the RIB's EVPN route-event broadcast
  (the same stream the local-MAC originator and the segment
  orchestrator consume) and re-projects 200 ms after the last event of
  a burst, instead of waiting for its 5 s RIB-poll tick. Any EVPN
  best-path change (Type 1/2/3/4/5 add/withdraw/best-change) triggers
  the debounced recompute; the unchanged-intent early return keeps
  spurious triggers free, and the 5 s poll is retained as the backstop
  (lost subscription, sustained sub-debounce churn). M65 re-measured
  the ADR-0083 single-active AC-failure blackout at **300 ms on local
  hardware (both post-change runs, from 4500-4600 ms before)** —
  including the driver's ~100-200 ms failure-injection serialization
  gap — and its hard blackout bound tightens from 30 s to 3 s so a
  regression back to poll-driven recompute fails CI.

- **Operator-visible row shape for single-active remote MACs (ADR-0083
  slice 2).** `bridge fdb show` now reports `nhid <id>` (pointing at the
  one-member group) instead of `dst <vtep>` for single-active MACs with
  an eligible backup; `ip nexthop show` gains one group + up to two
  per-VTEP fdb nexthops (active + pre-created backup) per single-active
  `(ESI, Ethernet Tag)`. On upgrade, the first reconcile pass converts
  each existing single-dst row with an explicit per-row delete→add (the
  kernel rejects in-place `NDA_DST`→`NDA_NH_ID` conversion with
  `-EOPNOTSUPP`), so the transient forwarding gap is bounded per MAC,
  never per segment; the reverse conversion (segment degrades to one
  PE / config removes it) runs the same per-row discipline through the
  group-teardown path. The per-VNI `apply_aliasing_ecmp = false`
  off-switch governs the single-active indirection too (falls back to
  single-dst at the active PE, no backup pre-create).

- **Kernel-side EVPN dataplane drift now repairs within the reconcile
  actor's 50 ms coalesce window instead of the 60 s periodic dump
  (poll-cadence tail sweep).** The notify task's existing netlink feeds
  gain two drift classes on the same kernel-event wake channel the
  IP-VRF route observation already uses: an `AF_BRIDGE` `RTM_DELNEIGH`
  on a managed VXLAN port (a programmed remote-MAC row swept by
  `bridge fdb del`/flush — unicast, BUM flood, and NHG-backed rows
  alike) and, via a new `RTNLGRP_LINK` subscription on the notify
  socket, link drift on the EVPN surface: bridge-port flag/state writes
  (the BUM-filter and AC-gate enforcement targets, including the
  single-active non-DF port block), VXLAN/managed-bridge topology
  bring-up and teardown, and AC-port enslavement. Classifiers keep
  container-runtime veth churn and VNI-less-bridge noise out of the
  wake path; external in-place FDB *replaces* (no delete emitted) and
  ports of not-yet-VNI-resolved bridges still ride the periodic dump,
  which is retained unchanged as the backstop. The remaining
  fixed-cadence loops were swept and stay deliberately: BMP statistics
  (RFC 7854 interval reporting), BFD protocol timers, MRT dump
  rotation, the originator/segment/dataplane/FIB/blackhole poll ticks
  (all already event-driven; the ticks are their backstops), and the
  FIB/blackhole 30 s kernel-drift bound (no kernel event feed behind
  `UnicastFib` yet — noted on the roadmap).

### Fixed

- **GW-IP overlay-index Type 5 origination now rejects ordinary IPv4
  subnet network and directed-broadcast vias.** In
  `overlay_index_mode = "gateway_ip"`, a route via such as
  `10.1.1.0` or `10.1.1.255` inside `10.1.1.0/24` now falls back to
  the interface-less Type 5 shape instead of advertising an
  unresolvable Gateway Address. `/31` point-to-point endpoints and
  `/32` host routes remain eligible gateways.
- **Config rollback no longer leaves candidate-born dynamic peers
  alive, and peer-group policy-only edits now reach live dynamic
  peers on every mutation path.** The peer manager now treats a
  transaction snapshot as provisional until the config writer acks
  persistence: unknown inbound sessions are not accepted from
  candidate-only `[[dynamic_neighbors]]` ranges during that staged
  window. Once persistence succeeds, dynamic accepts proceed normally
  (including commit-confirmed pending configs); if the transaction is
  later aborted or auto-reverted, restoring the previous snapshot
  reaps any dynamic peers whose accepted range no longer exists.
  Separately, targeted `SetPeerGroup` and TOML+SIGHUP peer-group
  edits that change only resolved import/export policy now use the
  same dynamic-aware policy fanout as catalog policy mutations, so
  established dynamic route-server clients no longer keep stale
  chains until reconnect.
- Documentation and feature-build freshness for the post-v0.38.0 EVPN/config
  surface: the RIB fanout bench-internals build now matches the current
  session registration signature, the ADR index lists ADR-0087 and marks
  ADR-0081 accepted, overview docs no longer describe native GW-IP
  overlay-index Type 5 origination as future work after it shipped, and
  `redundancy_mode = "single-active"` now points at the shipped receive-side
  backup-path pre-install behavior.
- **Kernel route-event degradation is now alertable.** The general-FIB
  and BLACKHOLE route-notify path still drops wake events on a full
  bounded channel and falls back to the periodic reconcile on
  subscription failure, but those degraded modes now increment
  `bgp_kernel_route_notify_dropped_total{actor,reason="channel_full"}`
  and
  `bgp_kernel_route_notify_subscription_failures_total{actor,group}`.
  The repair semantics are unchanged; operators no longer need to
  scrape logs to detect route-event pressure or multicast-subscription
  loss.
- **Route-event ID exhaustion no longer panics the RIB manager.** The
  process-local route-event id now saturates at `u64::MAX` with a
  one-time warning instead of taking down the manager in the
  practically unreachable case where one daemon lifetime emits the
  full 64-bit event space.
- **Session-identity gating now covers every session-scoped RIB
  message, not just teardowns — a superseded session's queued data
  messages can no longer mutate the replacement session's state.**
  The collision-window fix below stamped
  `PeerUp`/`PeerDown`/`PeerGracefulRestart`, but a dumped session's
  messages already queued in the ingest channel were still attributed
  by bare peer IP when processed after the winner's `PeerUp`: stale
  `RoutesReceived` landed in the replacement session's Adj-RIB-In (an
  announce/withdraw race could leave entries the new session never
  sent), a stale `EndOfRib` could prematurely complete the winner's
  GR stale sweep for a family, a stale RFC 7313 `BoRR`/`EoRR` could
  open or close an enhanced-refresh window over the wrong session's
  table and sweep refresh-stale routes early, a stale
  `RouteRefreshRequest` triggered a spurious re-advertisement, and a
  stale `PeerOrfUpdate` installed the dumped session's ORF entries as
  the replacement session's outbound filter (ORF state is
  per-session, RFC 5291). All six variants now carry the transport
  session id, stamped at every transport emit site (`0` stays the
  documented legacy degraded mode), and the RIB manager discards any
  whose id doesn't match the peer's active registration: INFO log
  with both ids + the new
  `bgp_rib_stale_session_message_ignored_total{peer,kind}` counter
  (`kind` ∈ `routes`/`eor`/`refresh`/`orf`, documented in
  docs/OPERATIONS.md); a discarded ORF push also reports the
  rejection on its reply channel. A message for a peer with no
  registration keeps the pre-stamping accept-all behavior, mirroring
  the teardown rule — per-producer FIFO puts a session's data
  messages strictly between its own `PeerUp` and its down event, so
  only legacy unregistered emitters can hit that arm. During the
  collision overlap only the registered session's routes are accepted
  into the address-keyed Adj-RIB-In; if the registration later fails
  over, the existing failover ROUTE-REFRESH re-learns the survivor's
  routes from the peer, so nothing is permanently lost. GR/LLGR
  semantics are unchanged for matching ids. `SetPeerPolicyContext`
  stays unstamped (idempotent, config-derived); `PeerDeleted` is
  config-scoped by design.
- **Ethernet Segment drain-GC split state on a failed runtime apply
  (ADR-0084 annotation resolved, from the cross-actor seam audit).**
  A runtime apply / SIGHUP that deleted a drained ES GC'd the
  coordinator's drain entry BEFORE publishing the candidate snapshots
  to the EVPN actors; if a publish then failed mid-converge, the
  rollback (deliberately, per ADR-0084) did not restore the entry —
  but the segment actor's drained-set mirror had never been updated
  either, so the ES stayed withdrawn actor-side while the coordinator
  (gauge, RPC drain reasons) reported it undrained, and a bare
  operator undrain was an idempotent no-op that fanned nothing out
  (manual remedy: re-drain, then undrain). Both converge paths
  (`publish_ethernet_segment_runtime_snapshot`,
  `converge_tenant_teardown`) now GC and push the GC'd set only after
  the last fallible actor publish has succeeded: a failed converge
  leaves the drain entry intact on both sides — coordinator and actor
  agree (still drained) and a subsequent undrain is a real transition
  that fans out — while ADR-0084's no-restore-on-rollback stance is
  preserved by construction (nothing is GC'd that a rollback would
  need to restore). In practice the window required an actor publish
  failure mid-apply (i.e. daemon teardown), so blast radius was near
  nil; pinned by converger-level invariant tests on both paths.
- **Silent advertisement wedge after a BGP session collision: a stale
  collision-loser `PeerDown` is now discarded by session identity.**
  When two sessions for one peer address overlapped during the
  RFC 4271 §6.8 collision window and the loser's `PeerDown` was
  processed after the winner's `PeerUp`, the RIB manager deregistered
  the surviving session's outbound sender — every later advertisement
  to that peer was silently lost while the session stayed Established
  on writer-owned keepalives (observed once in an M66 CI run; the
  observability for it shipped earlier under Added).
  `PeerUp`/`PeerDown`/`PeerGracefulRestart` now carry the transport
  session id; the RIB manager records the registered session's id at
  `PeerUp` and discards a teardown whose id doesn't match — the whole
  teardown, so a stale `PeerDown` can no longer clear the surviving
  session's Adj-RIB-In, abort its GR/LLGR retention, or deregister its
  outbound sender (INFO log + new
  `bgp_rib_stale_peer_down_ignored_total{peer}` counter). A
  replacement `PeerUp` (same address, new session) is treated as a
  session reset: the prior session's Adj-RIB-In/Out is cleared before
  re-registering so dumped-session state can't linger — except routes
  under GR/LLGR stale retention, which remain deadline-bounded as on
  any GR reconnect. GR flap semantics are unchanged when the id
  matches. The SYMMETRIC interleaving is covered too: when the
  collision loser's `PeerUp` is processed AFTER the winner's (event
  order across session tasks is arbitrary; which session survives is
  decided by BGP-ID comparison, not order), the loser's `PeerUp`
  becomes the active registration and its own `PeerDown` *matches* —
  the id gate alone would tear down a peer that still has an
  Established session. The RIB manager now keeps every live session
  for an address (bounded map, collision window = 2) and, when the
  active session goes down with another live session present, FAILS
  OVER the registration to the survivor instead of tearing the peer
  down: re-registers its channel, re-runs the initial table dump, and
  requests an inbound ROUTE-REFRESH (RFC 2918) through it so the
  Adj-RIB-In cleared by the replacement reset is re-learned from the
  peer (inbound `RoutesReceived` carries no session identity, so
  local recovery is impossible by construction; the session task
  picks the refresh families from its negotiated set, since the
  manager sees only the sendable subset and a family negotiated for
  receive but not sendable must still be refreshed; without the
  negotiated Route Refresh capability the request is skipped with a
  warning and inbound state recovers only on the peer's natural
  re-advertisement). A GR-down of the active session with a live
  survivor also fails over rather than entering stale retention —
  retention bridges a session that is gone, and here one is present.
  New `bgp_rib_outbound_registration_failover_total{peer}` counter.
- **The EVPN local-MAC observation layer now detects in-place FDB
  port moves, so the originator's cache tracks the kernel instead of
  claiming MACs the kernel no longer holds locally.** When a remote
  Type 2 is programmed over a kernel-learned local AC row — likely
  during a single-active ES drain, where the peer PE takes over the
  CE MAC — the kernel performs an in-place port move: one
  `RTM_NEWNEIGH` on the VXLAN port and **no** `RTM_DELNEIGH` for the
  replaced local row, so no local-delete observation ever reached the
  originator. The M66 drain-handover proof caught the consequence: the
  drained PE's cache kept claiming the CE MAC and the undrain replayed
  a stale Type 2 for a MAC the kernel had already handed to the peer,
  violating ADR-0084 decision 1's "undrain replays the latest kernel
  state". The `AF_BRIDGE` classifier now surfaces `RTM_NEWNEIGH` on an
  EVPN-owned VXLAN port as an `ObservedOnVxlanPort` observation (the
  bridge FDB holds one row per MAC, so a row there means the MAC is on
  no local AC port); the originator treats it as local-gone for MACs
  it currently claims — withdrawing the Type 2 (live) or dropping the
  cached claim (drained) — and ignores it for MACs it never claimed,
  so remote-programming echoes and foreign rows stay inert (ADR-0054).
  The mobility-sequence ratchet survives, so when the CE speaks again
  and the kernel moves the MAC back to the AC port, the
  re-advertisement bumps the RFC 7432 §15 sequence above the peer's.

- **An inbound connection no longer replaces a possibly-Established
  session when the collision state query times out.** The inbound
  handler bounds its query of the existing session's FSM state, but a
  timeout was mapped to Idle and took the replace-the-session path —
  yet the documented cause of a missed deadline (a session task wedged
  on TCP write back-pressure) is exactly a case where the existing
  session may be Established, which RFC 4271 §6.8 says must win the
  collision. A transient stall plus one inbound SYN could therefore
  reset a healthy session. The state query now distinguishes a timeout
  from an exited session task: on timeout the inbound connection is
  dropped (logged; the remote retries, and a genuinely dead session is
  torn down by hold-timer expiry so the retry lands in the normal
  accept path), while a dead session task still accepts the inbound
  immediately as before.

- **GR restarters no longer receive End-of-RIB for ORF-gated families
  before the gated flood.** The RFC 5291 §6 initial-advertisement gate
  withholds a family's table until the peer's first ROUTE-REFRESH, but
  the initial End-of-RIB was still sent immediately — an RFC 4724
  restarter took it as "initial update complete", ran route selection,
  and swept the stale routes it had retained, blackholing exactly the
  prefixes the gated flood was about to re-announce. For a peer that
  re-establishes as a graceful-restart restarter (including via the
  LLGR stale phase), the gated family's End-of-RIB is now withheld and
  follows the first ROUTE-REFRESH that lifts the gate, ordered behind
  the gated flood it triggers (it is sent as a genuine End-of-RIB even
  when enhanced route refresh would normally substitute its EoRR
  demarcation). Non-GR ORF peers keep the immediate honest-empty-table
  End-of-RIB — a client that never sends ROUTE-REFRESH must still see
  End-of-RIB — and GR restarters without ORF are unchanged.

- **Re-establishment during LLGR now honors the negotiated stale-routes
  time.** The per-peer LLGR config (which carries the stale-routes time
  captured at GR entry) was consumed at GR→LLGR promotion, so a peer
  coming back during the LLGR stale phase always had its End-of-RIB
  deadline re-armed with the 360 s default instead of the configured
  value. The config now survives the LLGR phase and is dropped at each
  terminal point instead (End-of-RIB completion, LLGR expiry, the
  no-LLGR purge, peer down) — which also lets a second GR-deadline
  expiry after an LLGR re-establishment promote back to LLGR rather
  than silently purging.

- **Expired GR/LLGR retention now releases the departed peer's RIB and
  identity state.** A GR flap deliberately keeps the peer's Adj-RIB-In
  and identity maps (ASN, BGP identifier, peer-group — the MRT
  `TABLE_DUMP_V2` peer index reads them) for the returning session, but
  if the peer never re-established, the retention-expiry sweeps removed
  only the routes: the empty Adj-RIB-In shell and the identity entries
  leaked forever. Both sweeps now run the full peer-down teardown for a
  peer that has not re-registered; a peer that re-established but whose
  End-of-RIB is merely late keeps its session state untouched.

- **Peer-group reshape rollback is now best-effort across every prior
  member (ADR-0081).** When a mid-fanout reconfigure failure triggers
  rollback of the already-reshaped members, a failed restore no longer
  short-circuits the reverse sweep: every captured prior is still
  attempted, so one stuck member cannot strand the others in the
  reshaped state. The compound `Internal` error now names exactly which
  members could not be restored (with each underlying error) — members
  it does not name were rolled back to their prior config — instead of
  reporting only the first failure and leaving the fate of the
  remaining priors unstated.

- **EAD-per-EVI routes now originate with Ethernet Tag 0 (RFC 7432
  §6.1 / RFC 8365 §5.1.3), carrying the VNI in the label field.**
  rustbgpd's Type 1 EAD-per-EVI origination put the VNI in the
  Ethernet Tag ID while its Type 2 MAC/IP routes carry tag 0 — a spec
  deviation for VLAN-based service (both RFCs pin the tag to 0; the
  VNI belongs in the route's 3-octet label field) found while building
  M65. Because the receive-side aliasing and ADR-0083 single-active
  eligibility joins are keyed on `(ESI, Ethernet Tag)`, a
  rustbgpd-originated EAD-per-EVI could never join a remote rustbgpd's
  alias/eligible set for its tag-0 MACs, structurally breaking
  rustbgpd↔rustbgpd multi-homing aliasing and backup paths; FRR peers
  additionally misclassified the non-zero-tag route as an EAD-per-ES
  contribution (FRR discriminates the two variants by `tag != 0`).
  Origination now emits tag 0 with the member VNI in the label
  (matching FRR's `BGP_EVPN_AD_EVI_ETH_TAG`), and per-VNI route
  distinctness rides on the per-VNI RD, which config validation
  already requires to be unique. Receive-side behavior is unchanged
  (M65 already proves the tag-0 + VNI-label shape end to end).
  **Upgrade note:** the Ethernet Tag is part of the EAD-per-EVI NLRI
  key, so upgrading a multi-homed PE re-keys its EAD-per-EVI routes —
  one withdraw/advertise per `(ES, member VNI)` as sessions
  re-establish (under graceful restart the stale VNI-tagged route is
  purged at End-of-RIB). EAD routes are not forwarding state; remote
  receive-side joins recompute from the new advertisements, and peers
  that ignored the old route (FRR per-EVI handling, remote rustbgpd
  joins) only gain function.

- **Adoption-retained nexthop IDs are re-evaluated on every drift
  cycle (ADR-0059/0079/0083).** A crash-leftover tagged nexthop
  retained at startup adoption because a kernel FDB row referenced it
  kept that protection forever, even after the row was retargeted at a
  fresh group — e.g. a restart inside the ADR-0083 failover window,
  where the first reconcile points the surviving rows at a new group
  and the prior lifetime's group + member nexthops become permanently
  unreferenced kernel cruft. The drift sweep's in-line adoption cleanup
  now re-runs whenever any adopted-unreferenced IDs remain (the
  retention set is recomputed from the fresh snapshot each cycle), so
  dereferenced leftovers are reaped on the normal drift cadence while
  anything still referenced stays protected.

## [0.38.0] — 2026-06-11

### Added

- **True IPv6-only peering via `disable_ipv4_unicast` (M64).** New opt-in
  neighbor / peer-group flag (default `false`, existing configs behave
  identically) that closes the KNOWN_ISSUES "implicit IPv4 prevents
  IPv6-only peers" limitation: with the flag set, the session never treats
  IPv4 unicast as implicitly available. IPv4 unicast is excluded from the
  MultiProtocol capability rustbgpd advertises (and from every
  family-derived capability — GR, LLGR, Add-Path, ORF, extended next-hop)
  regardless of the resolved `families`, and the RFC 4760 §8 implicit-IPv4
  fallback is suppressed during OPEN negotiation. A session whose family
  intersection ends up empty (e.g. the peer advertises only IPv4 unicast,
  or sends no MultiProtocol capability at all) is rejected with
  NOTIFICATION OPEN error / Unsupported Capability (2/7) — FRR parity with
  its "Configured AFI/SAFIs do not overlap with received MP capabilities"
  behavior. Config validation rejects the contradictory shape where the
  flag is set but the effective `families` resolve to `ipv4_unicast` only.
  Capability-negotiation scope only: RFC 8950 extended next-hop encoding
  and ADR-0069 unnumbered peering are untouched. Proven by the new M64
  interop job: rustbgpd ↔ FRR over IPv6 GUA with `no neighbor ... activate`
  in IPv4 + activate in IPv6, asserting Established with no IPv4-unicast MP
  capability received by FRR, IPv6 routes exchanged both directions, and a
  §8 regression guard — a second flag-less neighbor against an FRR peer
  sending no capabilities at all (`dont-capability-negotiate`) still
  implicitly negotiates IPv4 and exchanges IPv4 routes.

- **M63 interop proof for ADR-0078 hold-timer survival under a stalled
  RIB.** New `interop` CI job closing the follow-up the ADR-0078
  implementation carried (the contract was unit-tested but had no receipt
  against a real peer): with the RIB manager artificially stalled 12 s per
  `RoutesReceived` batch and the transport→RIB channel shrunk to 2 slots, an
  FRR peer floods 4000 /32s in 8 wave-separated UPDATE batches, the channel
  saturates, and the session task parks for longer than the 9 s negotiated
  hold time — repeatedly — while both ends stay Established (the
  writer-task-owned KEEPALIVE cadence feeds FRR's hold timer while the
  session task is parked; our own hold timer stays fresh because each
  parked delivery completes with the UPDATE's normal hold reset, so the
  pending-input re-arm counter is expected 0 here and stays pinned by the
  transport unit tests). Asserts `bgp_inbound_rib_backpressure_total` > 0,
  exactly 4000 routes in the RIB after the drain (the never-drop receipt),
  and zero session flaps from both vantage points. Ships two test-only
  fault-injection envs, parsed once at startup and inert unless set:
  `RUSTBGPD_TEST_RIB_INGEST_STALL_MS` (per-batch RIB ingest sleep) and
  `RUSTBGPD_TEST_RIB_CHANNEL_CAPACITY` (channel-capacity override — filling
  the production 4096-slot channel against a real peer would need thousands
  of in-flight UPDATE batches). Never set either in production.

- **NDA_PROTOCOL ownership stamping on EVPN kernel state (ADR-0082).** Every
  EVPN FDB/neighbor install — L2 single-dst FDB, ADR-0059 NHG FDB rows, L3
  neighbors, and L3VXLAN router-MAC FDB — now carries
  `NDA_PROTOCOL = RTPROT_BGP` (186), the same kernel identity our routes
  already use, so `ip neigh show` reports `proto bgp` on managed L3 neighbor
  rows. The ADR-0079 adoption sweeps use it as a second, value-bearing
  ownership discriminator: L3 neighbor adoption requires the stamp **or**
  accepts a stamp-less row as the pre-stamp legacy shape (one-release
  migration window — a future release may require the stamp, gated on having
  run this release once), while any other stamped value (e.g. zebra's 11)
  disqualifies the row as provably another controller's. FDB classifiers
  apply the same check in *prefer* mode only, because mainline AF_BRIDGE
  silently drops the attribute (stamping it is a forward-compatible no-op,
  FRR parity): a foreign stamp disqualifies if a future kernel ever returns
  one, absence keeps today's flag-based rule — zero behavior change on
  current kernels. If a strict-validation kernel rejects a stamped L3
  neighbor install with `EINVAL`, the install is retried once unstamped and
  stamping is latched off for the rest of the run (warned once). The M61
  kill-and-restart job now also proves the stamp end-to-end: the re-claimed
  neighbor row shows `proto bgp`, and a planted `extern_learn` + permanent +
  `protocol zebra` neighbor — adoptable under the old flags-only rule —
  survives the sweep untouched.

- **M61 kill-and-restart interop proof for the ADR-0079 EVPN L3 sweep.**
  New `kernel-dataplane` CI job closing the residual-risk gap the v0.37.0
  notes carried (the L3 slice — the largest new surface — had only in-memory
  and netns-unit coverage): rustbgpd imports two FRR-originated Type 5
  prefixes into a real kernel VRF table over the M48 symmetric-IRB topology,
  is SIGKILLed (the netns and its VRF-route / L3-neighbor / L3VXLAN-FDB rows
  survive), one prefix is withdrawn while the daemon is down, and the restart
  proves the still-desired route plus the shared resolution rows stay marked
  continuously while the unclaimed route is reaped after the deferral — with
  a foreign `proto static` route and a non-`extern_learn` neighbor untouched
  and all six `evpn_l3_*_adopted_total` / `_reaped_total` counters asserted.

- **M62 kill-and-restart interop proof for the ADR-0079 blackhole sweep.**
  New `kernel-dataplane` CI job closing the last open ADR-0079 proof item
  (the blackhole slice — the worst failure mode — had only in-memory
  coverage): rustbgpd installs two FRR-tagged RFC 7999 host routes as kernel
  `RTN_BLACKHOLE` + `RTPROT_BGP` discards over the M41 topology, is
  SIGKILLed (the netns and its discard rows survive), one prefix is
  withdrawn while the daemon is down, and the restart proves the
  still-desired discard stays present continuously while the unclaimed row
  surfaces as `adopted_pending_reap` and is reaped only after the deferral —
  with a foreign `proto static` blackhole row untouched and the
  `bgp_blackhole_discard_adopted_total` / `_reaped_total` counters asserted.
  The blackhole deferral gains the same test/operational escape hatch the
  EVPN sweeps have: `RUSTBGPD_BLACKHOLE_ADOPTION_REAP_DEFERRAL_SECS`
  overrides the 500 s default at actor startup (unset or invalid values keep
  the default).

### Fixed

- **Deleted peers no longer leave stale per-peer Prometheus series behind.**
  Every `peer`-labeled metric family (27 of them — session/FSM, message and
  NOTIFICATION counters, Adj-RIB-In/Out gauges, policy/loop-detection/OTC
  counters, graceful-restart and Enhanced Route Refresh gauges, BFD, BMP
  source drops) now has its label sets removed when the peer is *deleted* —
  static neighbor delete (CLI/gRPC/SIGHUP reload) and dynamic-peer
  auto-removal alike. Previously a deleted peer's gauges froze at their last
  value (e.g. a `bgp_session_established_total` series for a neighbor that
  no longer exists) and misled dashboards forever after peer churn. Reaping
  happens on deletion only: a session flap or admin disable keeps the peer's
  history, and a reconfigure (delete-then-re-add reshape) routes around the
  reap because the peer continues to exist. Process-global and
  non-peer-labeled families (Loc-RIB, EVPN, FIB, BMP collector, event
  outbox, …) are untouched. Prometheus marks the removed series stale at the
  next scrape; if the same peer is later re-added, its counters restart from
  zero, which `rate()` / `increase()` handle as an ordinary counter reset —
  no negative-rate artifacts.

- **Targeted peer-group RPCs now reshape members atomically (ADR-0081).**
  `SetPeerGroup`, `SetPeerGroupPreserveMd5`, `SetNeighborPeerGroup`, and
  `ClearNeighborPeerGroup` reshaped each affected static member with
  delete-then-re-add in a loop and no rollback, so a mid-fanout failure left
  earlier members running the new config, the failing member possibly
  deleted entirely, and the runtime config snapshot disagreeing with the
  live sessions. The member fan-out now resolves every affected member's
  next config up front and commits the whole set through the same
  captured-prior reshape primitive the config-transaction path uses: a
  resolution or preflight failure rejects with zero sessions touched, and a
  mid-fanout failure restores the already-reshaped members to their captured
  priors (preserving live admin-disabled / graceful-shutdown intent) without
  advancing the config snapshot. A member whose resolved next config changes
  TCP-AO now yields `FAILED_PRECONDITION` (restart required) *before* any
  session bounces, instead of after some members were already flapped — a
  deliberate, observable behavior change. Dynamic peers at an affected
  address are never bounced by these RPCs; their sessions keep the running
  config until they reconnect.

- **Hold-expiry re-arm now requires a complete pending frame (ADR-0078).**
  The hold-timer expiry handler treated ANY buffered or readable bytes as
  peer liveness, so a peer whose application hung mid-frame while its kernel
  kept ACKing (half a BGP header, then silence) re-armed the hold timer
  forever — a zombie session that never expired. The pending-input check now
  counts complete BGP frames (a full 19-byte header whose declared length
  is fully buffered; a header the codec will reject as malformed also
  counts, since resuming processing makes immediate progress on it),
  matching RFC 4271's "hold timer resets on receipt of a
  complete message" and FRR's parsed-packet rule; a permanently incomplete
  frame lets the session expire. Frame completeness is the only check —
  marker/length validation stays with the codec, so a malformed header still
  resolves through the normal NOTIFICATION path.

## [0.37.0] — 2026-06-11

### Added

- **Blackhole crash-restart reconciliation (ADR-0079).** The RFC 7999 discard
  reconciler now adopts marker-matching kernel rows (`proto bgp` + blackhole
  type, main table) on its first pass after a restart instead of rejecting
  them as `foreign_route_exists`. A still-desired prefix re-claims its row
  silently (status `adopted`); adopted rows that no BGP route re-claims stay
  visible as `adopted_pending_reap` and are reaped after a 500 s deferral
  (FRR zebra `-K` parity), so a crashed daemon can no longer leave a discard
  route blackholing traffic forever — and the deferral makes reaping while
  BGP is still reconverging unlikely (the deadline is a time proxy for
  convergence, not a convergence signal). New counters:
  `bgp_blackhole_discard_adopted_total`,
  `bgp_blackhole_discard_reaped_total`. The reconciler also now performs one
  kernel route dump per pass instead of one full-table dump per candidate per
  pass; a failed dump degrades the pass to stale-route removals (status
  `dump_failed`) instead of churning owned state.

- **EVPN L3 crash-restart reconciliation (ADR-0079).** The symmetric-IRB
  install pipeline tracked its kernel state (per-VRF routes, L3 neighbors,
  L3VXLAN FDB rows) in memory only, so after an unclean restart a Type 5
  withdrawn while the daemon was down kept steering tenant traffic into a
  dead VXLAN tunnel forever. The reconcile actor now adopts marker-matching
  rows on its first pass with `[[evpn_ip_vrfs]]` configured — `proto bgp` +
  onlink routes in configured VRF tables, permanent `extern_learn` neighbors
  and `extern_learn` FDB rows on managed L3VXLAN devices. A still-desired
  prefix re-claims its rows implicitly (every L3 add applies with netlink
  replace semantics, so the re-install is the claim); adopted rows that no
  Type 5 re-claims are reaped after a 500 s deferral plus a clean L3 apply pass,
  routes before their resolution rows, with a fresh marker dump re-check so
  a vanished or foreign-replaced row is dropped without a remove. New
  counters: `evpn_l3_route_adopted_total` / `_reaped_total`,
  `evpn_l3_neighbor_adopted_total` / `_reaped_total`,
  `evpn_l3vxlan_fdb_adopted_total` / `_reaped_total`.

- **M60 kill-and-restart interop proof for the ADR-0079 EVPN FDB sweep.**
  New `kernel-dataplane` CI job: rustbgpd programs two FRR-advertised Type 2
  MACs into a real kernel bridge FDB, is SIGKILLed (the netns and its rows
  survive), one MAC is withdrawn while the daemon is down, and the restart
  proves the still-desired row stays present continuously while the unclaimed
  row is reaped after the deferral — with foreign-static rows untouched and
  the adoption/reap counters asserted. Ships with a test/operational escape
  hatch: `RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS` overrides both ADR-0079
  adoption-reap deferrals (production default stays 500 s, FRR `-K` parity).

- **Enhanced Route Refresh observability.** Prometheus now exposes
  `bgp_route_refresh_in_progress{peer,afi_safi}` and
  `bgp_route_refresh_stale_entries{peer,afi_safi}` so operators can see active
  inbound RFC 7313 refresh windows and how many routes are still awaiting
  replacement before EoRR or timeout. The sprint also corrected two roadmap
  hypotheses: unknown FlowSpec component types are RFC 8955 malformed NLRI (not
  a pass-through compatibility surface), and inbound BoRR/EoRR delivery already
  backpressures with `send().await` rather than dropping on channel-full.

- **SIGHUP EVPN runtime convergence.** File-driven reload now submits
  `[[evpn_instances]]`, `[[evpn_ip_vrfs]]`, and `[[ethernet_segments]]`
  candidates through the ADR-0063 EVPN runtime coordinator for the same
  supported live shapes as `EvpnService.ApplyEvpnRuntime` (single
  L2VNI/IP-VRF/ES add/delete/redefine, additive build-up, atomic tenant
  teardown, and `ip_vrf` relink). The runtime snapshot advances only after the
  daemon actor converger accepts the candidate; generic mixed add/delete/redefine
  edits, L3VNI/device/table IP-VRF identity changes, missing EVPN actors, actor
  convergence failure, and `apply_bum_enforcement` remain fail-closed and are
  pinned back to the committed model.

- **ADR-0063 EVPN runtime convergence — additive build-up.**
  `EvpnService.ApplyEvpnRuntime` and SIGHUP reload can now commit pure add-only
  multi-row or multi-domain EVPN candidates, such as adding a linked L2VNI, its
  IP-VRF, and its Ethernet Segment in one request. The daemon converger validates
  that no delete/redefine or existing-L2VNI relink is mixed in, originates Type 3
  IMET for each added L2VNI, republishes candidate snapshots to dataplane, Type 2,
  SVI, segment, and Type 5 actors, and rolls all touched actors plus speculative
  IMET back to the committed model on failure. Generic add+delete/redefine
  composers remain fail-closed and tracked as future #268 work.

- **gNMI Set transaction bridge and static-neighbor config subset.** The gNMI
  service now supports the first durable OpenConfig config mutations:
  operator-tier `Set` can create/update/delete static, numbered BGP neighbors
  for `neighbor-address`, `peer-as`, `description`, and `peer-group`. Supported
  edits are translated from OpenConfig paths into full candidate TOML and
  committed through ADR-0076 `PlanConfigTransaction` /
  `ApplyConfigTransaction`, including persistence acknowledgement and rollback;
  the standard gNMI commit-confirmed extension can start, confirm, and cancel
  the same confirmed transaction lifecycle, and can reset a pending transaction's
  rollback timer with `CommitSetRollbackDuration`; unsupported paths still
  return `UNIMPLEMENTED`. Set payloads are redacted in gRPC audit summaries, and
  delete / replace / update requests are prefix-expanded and normalized in gNMI
  application order. The M54 `gnmic` interop smoke now proves
  static-neighbor Set add/delete, peer-group and dynamic-neighbor-prefix Set
  persistence, commit-confirmed confirm/cancel, read-tier `Set` denial
  (`PermissionDenied`), and unsupported-path rejection (`Unimplemented`) over
  mTLS.

- **gNMI Set peer-group object subset.** The OpenConfig Set bridge can now
  create/update/delete BGP peer-group list entries through ADR-0076 catalog
  transactions. The supported peer-group leaves are deliberately narrow and map
  to existing native TOML fields: `config/peer-group-name`,
  `config/auth-password`, `config/remove-private-as`, and
  `timers/config/hold-time`. Peer-group leaves without a native inherited model
  such as `config/peer-as`, `config/local-as`, `config/peer-type`,
  `config/send-community-type`, and `config/description` continue to return
  `UNIMPLEMENTED`.

- **gNMI Set dynamic-neighbor-prefix subset.** The OpenConfig Set bridge can
  now create/update/delete dynamic BGP neighbor prefix ranges under
  `bgp/global/dynamic-neighbor-prefixes`. The supported leaves are
  `config/prefix` and `config/peer-group`; OpenConfig-created ranges use
  native `remote_asn = 0` (accept the peer ASN from OPEN) and no description.
  Native validation still enforces defined peer-group references, duplicate
  effective-prefix rejection, prefix bounds, and the existing dynamic-neighbor
  BFD restriction. M54 now proves the supported path through the real `gnmic`
  client and asserts an undefined peer-group reference is rejected.

- **ADR-0077 MPLS/VPN/BGP-LS address-family boundary.** Added a
  research-backed control-plane scope for future labeled-unicast, VPNv4/v6,
  Route Target Constraints, and BGP-LS work. The ADR keeps `Prefix` scoped to
  IPv4/IPv6 unicast, requires future families to land as typed route-key/RIB/API
  slices, identifies BGP-LS export and route-reflector-only VPN/MPLS families as
  the on-identity entry points, and makes MPLS dataplane programming an explicit
  non-goal.

- **Config transaction effective-impact kinds.** The redacted transaction diff
  now labels each `effective_neighbor_impact` entry as `policy_chain` or
  `session_reshape`, making the planner's live-policy versus session-reconfigure
  decision explicit for future peer-group reshape executors and operator JSON
  tooling.

- **High-N RIB structural memory harness.** The RIB memory profile now has an
  ignored high-N JSONL mode that measures Adj-RIB-In, Full-RIB, and
  RR/route-server fanout shapes at 100k/500k/900k prefixes, plus
  `bench/compare-rib-memory.sh` for base/head CSV and Markdown summaries under
  the shared bench/soak host mutex.

- **Criterion nightly confident-regression tripwire.**
  `bench/compare-criterion.sh` now emits a per-row verdict and supports
  `--fail-on-regression`, failing only when enough attempts completed,
  `min..max` stays entirely above zero, stddev stays below the configured
  ceiling, and mean delta crosses the configured threshold. The nightly
  release-baseline workflow enables that mode so noisy straddle-zero/high-stddev
  rows remain advisory while confirmed regressions go red.

- **Operational proof receipts page.** Added `docs/OPERATIONAL_PROOF.md` as
  the consolidated operator-facing index for CI interop, hosted kernel
  dataplane, benchmark, high-N memory, and archived 24 h soak receipts.

- **Peer reshape snapshot foundation.** The peer manager now has an atomic
  internal command that reconfigures a set of concrete static peers, returns
  their prior configs as a rollback token, and restores already-changed peers on
  the first per-peer failure. This is the rollback substrate for peer-group /
  session-reshape config transactions.

- **Static peer-group/session reshape config transactions.**
  `ApplyConfigTransaction` can now commit peer-group field edits and
  static-neighbor peer-group reassignments that reshape existing static
  sessions. The executor stages the candidate snapshot, reconfigures affected
  peers with captured prior configs, persists with an acknowledgement, and
  restores live peers plus the snapshot on failure. Dynamic-range session
  reshapes remain rejected until accepted dynamic sessions can be targeted with
  equivalent rollback semantics.

- **Reload matrix transaction overlay.**
  The operator reload matrix now distinguishes SIGHUP reload classes from
  ADR-0076 transaction committability, including the newly committable static
  peer-group/session reshape impact and the still-rejected dynamic-range or
  mixed policy/session effective-impact shapes.

- **Config transaction lifecycle metric.**
  `bgp_config_transaction_lifecycle_total{operation, outcome}` now counts
  confirmed-transaction confirm, abort, and auto-revert lifecycle transitions
  with bounded labels. `operation` is `confirm`, `abort`, or `auto_revert`;
  `outcome` is `success` or `failure`, so operators can alert on failed abort /
  timer rollback without scraping logs or exposing `confirm_id` / candidate
  content as metric labels.

- **Dynamic-neighbor accepted-range attribution.** Established peers created
  from `[[dynamic_neighbors]]` now retain the canonical longest-prefix-match
  range that accepted them internally. This does not change peer matching,
  `PeerInfo`, or the public API; it gives the config-transaction planner and
  executor a stable target key for dynamic-range live-policy commits.

- **Dynamic-range live-policy config transactions.** `ApplyConfigTransaction`
  can now commit policy definitions, neighbor sets, peer groups, and global
  named policy-chain edits that move live dynamic peers' resolved import/export
  chains through their accepting `[[dynamic_neighbors]]` range. The executor
  expands the affected ranges to currently managed dynamic peers, reuses the
  same Route Refresh, captured-prior, persistence-ack, and rollback path as
  static live-policy transactions. Dynamic-range session reshapes remain
  rejected until a dedicated reconfigure executor exists.

### Fixed

- **Catalog policy mutations apply to peers atomically.** The fan-out shared
  by all 12 policy / neighbor-set / policy-chain catalog mutators (`SetPolicy`,
  `DeletePolicy`, neighbor sets, global and per-neighbor chain edits) updated
  affected peers' resolved import/export chains in a loop: a mid-loop failure
  (for example one Established peer rejecting the required Route Refresh) left
  already-updated peers running the new chains while later peers kept the old
  ones — split-brain policy across sessions. The fan-out now resolves every
  affected peer's chains first, then commits the whole set through the
  ADR-0076 resolved-policy-snapshot primitive: on a mid-fanout failure the
  already-updated peers are restored to their captured prior chains, the
  mutation is rejected cleanly, and the runtime config does not advance.

- **`[[fib_tables]]` edits no longer quarantine-freeze unrelated owned
  routes (ADR-0079).** The crash-restart owned-state file was gated on an
  ordered whole-list signature comparison, so any `[[fib_tables]]` edit
  across an unclean restart — even reordering stanzas — quarantined the
  entire file and froze every table's prior routes in the kernel as
  `foreign_route_exists`. The comparison is now per table and set-wise,
  keyed by `(table_id, metric)`: reordering is a no-op, adding a table is
  additive, and editing or removing one table drops only that table's
  routes from ownership. On a partial mismatch the loader preserves a
  `.stale` evidence copy and keeps the original file live, so a second
  crash before the next persist can't strand the surviving tables' routes.

- **Crash-leftover EVPN FDB rows are adopted and reaped (ADR-0079).** The
  dataplane's ownership record dies with the process and the kernel never
  ages `extern_learn` rows, so after an unclean restart a still-desired MAC
  was never re-owned and a MAC withdrawn while the daemon was down kept
  steering traffic into a dead VXLAN tunnel forever. Single-destination
  marker rows are now adopted from the first kernel snapshot: a desired MAC
  re-claims its row implicitly (the re-program is the claim), and rows no
  EVPN route re-claims are reaped after a 500 s deferral plus a clean apply
  pass — together those make reaping mid-reconvergence unlikely, not
  impossible (the deadline is a time proxy, and an ADR-0078 backpressure
  stall consumes the same budget). NHG-tagged rows keep their
  existing ADR-0059 sweep; operator-static and kernel-learned entries stay
  untouched. New counters: `evpn_fdb_single_dst_adopted_total`,
  `evpn_fdb_single_dst_reaped_total`.

- **Inbound routes are never dropped on a busy RIB (ADR-0078).**
  `RoutesReceived` delivery used a lossy `try_send`: a full RIB channel
  silently discarded the batch — a dropped announce was a permanently missing
  route and a dropped withdraw a permanently stale one (the lost-withdraw
  "BGP zombie" failure mode), invisible to every counter while the transport
  bookkeeping claimed acceptance. Delivery now blocks when the channel is
  full: the session task parks, stops reading its TCP socket, and kernel
  receive-window backpressure paces the sender — the consensus contract
  across FRR/BIRD/OpenBGPD. Liveness is decoupled so the park is safe: the
  KEEPALIVE cadence is owned by the per-connection writer task (a parked
  session keeps feeding the peer's hold timer), and a hold-timer expiry with
  unprocessed peer input pending re-arms instead of tearing the session down.
  New counters: `bgp_inbound_rib_backpressure_total{peer}`,
  `bgp_hold_timer_rearmed_pending_input_total{peer}`.

- **Policy and peer-group runtime CRUD can no longer drift from the persisted
  config.** All 16 catalog mutators (`PolicyService` definitions,
  neighbor-sets, global and per-neighbor chains; `PeerGroupService`
  definitions and membership) previously applied their runtime change and
  queued persistence fire-and-forget outside the runtime-config coordinator
  lock: a failed disk write was log-only (the RPC returned OK and the next
  SIGHUP silently reverted the edit — e.g. a permit→deny policy flip), a
  SIGHUP racing the unacknowledged write could rebuild from stale TOML, and
  the unlocked transaction-gate check was check-then-act. They now follow the
  same contract as neighbor/FIB CRUD and config transactions: the apply runs
  on a detached task (a disconnected client can't split apply from persist),
  holds the coordinator lock with the gate checked inside it, awaits the
  on-disk persistence acknowledgement before releasing the lock, and rolls
  the runtime back to the captured prior state when persistence fails — so a
  failed RPC means "nothing changed". Peer-group rollback restores the stored
  definition with its md5 secret intact.

- **Commit-confirmed rollback no longer reports success when the rollback was
  rejected.** Abort and auto-revert re-apply the captured pre-commit snapshot
  through the transaction executor; a re-apply whose plan came back `Rejected`
  returns cleanly at the RPC level but commits nothing — the unconfirmed
  candidate is still running. That outcome was recorded as
  `Aborted`/`AutoReverted` success. It now surfaces as
  `AbortFailed`/`AutoRevertFailed` with a failure lifecycle metric, matching
  what actually happened (a `Noop` rollback — runtime already at the snapshot —
  still counts as success).

- **EVPN runtime applies are cancellation-shielded (ADR-0080).** The
  `ApplyEvpnRuntime` converge + coordinator commit ran inline in the gRPC
  request future, so a client disconnect or RPC deadline mid-apply dropped the
  converge at an internal await point: half-applied actor state with no
  rollback, no Degraded record, and a stale committed baseline that made the
  next SIGHUP of an unchanged file diff as "no change" and skip repair. The
  critical section now runs on a detached task the caller merely awaits (the
  FIB-CRUD pattern), for both the RPC and the SIGHUP reload path — losing the
  caller loses only the response, never the mutation's atomicity; treat a lost
  response as at-least-once and read `GetEvpnRuntime` for the outcome.
  Coordinated shutdown now also takes the apply lock (bounded at 10 s) before
  the EVPN teardown, so an in-flight converge finishes before the withdraw-all
  sweep and a late apply cannot re-originate routes after it.

- **Graceful-restart flaps no longer leak per-session ORF state.** The GR
  teardown path kept the dead session's installed ORF filter set and RFC 5291
  §6 initial-advertisement gate. A peer re-establishing without ORF inherited
  the stale gate — its family flooded nothing indefinitely (a session that
  never negotiated ORF has no reason to send the ROUTE-REFRESH that lifts a
  gate) — or kept being constrained by the dead session's prefix filter. The
  shared per-session outbound teardown is now one helper used by both the
  `PeerDown` and GR paths, so the two cleanup lists can no longer drift.

- **Runtime-added neighbors now carry the RR cluster id.** The
  resolved-neighbor transport path (used by snapshot-sync gRPC peer adds)
  never set `cluster_id`, so an iBGP route-reflector client added at runtime
  reflected routes without CLUSTER_LIST prepend and skipped inbound
  cluster-loop detection (RFC 4456) until the daemon restarted. A two-path
  transport-construction parity test now pins full struct equality between
  the resolved-neighbor and reconcile paths so the next added field cannot
  silently diverge.

- **`DeleteNeighbor` refuses dynamic-range peers.** Deleting a dynamic peer
  through the static-neighbor surface permanently leaked one
  `dynamic_neighbor_limit` slot per call (the idle-time decrement never ran),
  eventually wedging the dynamic-accept plane at the limit with zero live
  peers, and a persistence-failure rollback resurrected the ephemeral peer as
  a persisted static neighbor. Dynamic peers are removed automatically when
  their session ends; the delete now returns `INVALID_ARGUMENT` pointing at
  dynamic-neighbor range deletion instead.

- **BFD Down now also clears a pending collision candidate.** A genuine BFD
  Down stopped only the primary BGP session; a live inbound collision
  candidate spawned before the hold survived and was promoted on the
  primary's `BackToIdle`, re-establishing BGP over the BFD-down path moments
  after the teardown. The Down handler now shuts the candidate down and
  `BackToIdle` promotion checks the BFD withhold before promoting.

- **EVPN IMET controller self-heals on withdraw `not_found`.** A Type 3 IMET
  withdraw the RIB answered with `NotFound` (e.g. after a dropped reply on a
  prior withdraw) was treated as `Rejected` and the controller kept tracking
  the key — making that VNI permanently un-deletable and un-redefinable at
  runtime (re-origination short-circuited on already-originated; every later
  delete/redefine converge rejected) until a daemon restart. The controller
  now converges to RIB reality: a `not_found` withdraw untracks the key and
  reports it withdrawn.

- **Loc-RIB now detects same-peer payload churn (unicast + FlowSpec).** A peer
  re-advertising the same prefix with a new next-hop or changed attributes
  (communities, equal-length AS_PATH content), or the same FlowSpec rule with a
  changed action (rate-limit/redirect extended communities), previously
  compared equal in the Loc-RIB change detector and was silently dropped:
  single-best downstream peers, newly-established sessions, and FIB install
  candidates kept the stale payload while Add-Path peers saw the update. The
  unicast and FlowSpec recompute paths now use the same payload-aware
  comparison the EVPN table already had.

- **SIGHUP now delivers `[[dynamic_neighbors]]` edits.** The reload path
  detected dynamic-neighbor range changes but never carried the new range set
  into the runtime snapshot it returns, so the peer manager's accept-matcher
  rebuild re-parsed the old ranges: TOML range edits applied via SIGHUP
  silently never took effect (and every subsequent SIGHUP re-detected and
  re-dropped the same diff). Runtime gRPC dynamic-neighbor CRUD was
  unaffected.

- **Catalog policy mutations now reach live dynamic peers.** `SetPolicy`,
  neighbor-set, and global policy-chain edits (gRPC and SIGHUP alike)
  previously skipped established dynamic-range sessions — they have no
  `[[neighbors]]` record, so the per-peer fan-out never resolved their chains
  and the sessions kept stale import/export policy until they flapped. The
  fan-out now resolves dynamic peers through their accepted peer group (the
  honor-knob pattern) and hot-applies with the usual Route Refresh on import
  change. Orphaned dynamic peers with unresolvable chains are skipped with a
  warning instead of failing the mutation.

- **Typed policy/catalog command errors.** Policy definitions, neighbor sets,
  peer groups, global named policy chains, and per-neighbor policy/peer-group
  catalog mutations now return typed peer-manager errors for not-found,
  still-referenced, and invalid-input failures. The gRPC policy and peer-group
  services map those variants directly to stable status codes instead of
  parsing operator-facing error strings.

- **Typed static-peer lifecycle command errors.** Static peer add/delete,
  reconfigure, peer reshape, enable/disable, and soft-reset replies now carry a
  typed lifecycle error instead of `String`, so gRPC and config-transaction
  callers map duplicate, missing-peer, invalid-input, restart-required, and
  internal failures to stable status classes without substring matching.

- **Runtime `expect` tail cleanup.** The RIB prefix-trie wrapper no longer
  relies on `expect(...)` when converting canonical `Prefix` values to `ipnet`
  trie keys. BFD runtime setup and timer processing now handle impossible
  socket-length conversion and post-peek timer-pop failures as warnings or
  no-op fallbacks instead of panicking. Normal behavior is unchanged.

- **Peer-group reload-matrix docs drift.** The reload matrix and its structural
  test now match the schema: `[peer_groups.<name>]` includes policy and ORF
  inheritance fields, while `tcp_ao` remains static-neighbor-only and is not
  inherited from peer groups. Security and roadmap wording now distinguish
  shipped internal accepted-socket TCP-AO inspection/logging from the
  still-deferred public API/CLI/metrics surface.

## [0.36.0] — 2026-06-05

### Added

- **Short CLI binary (`rbgp`).** Release artifacts and container images now ship
  `rbgp` as the preferred operator CLI spelling alongside the compatible
  `rustbgpctl` long-form binary. Help and shell completion generation render the
  invoked binary name, and pre-generated bash/fish/zsh completions are included
  for `rbgp`.

- **CLI command-surface README refresh.** The `rustbgpctl` crate README now
  groups commands by workflow — config transactions, peers/BFD, RIB/policy,
  EVPN, events, dataplane, and daemon control — instead of a single long
  command list.

- **Commit-confirmed config transactions.** `ApplyConfigTransaction` now accepts
  a `confirm_id` plus optional `confirm_timeout_seconds` to apply a candidate
  immediately while starting a confirm timer. `ConfirmConfigTransaction` makes
  the change permanent, `AbortConfigTransaction` rolls it back immediately, and
  timer expiry automatically re-applies the pre-commit runtime snapshot through
  the same transaction executor. `GetConfigTransactionStatus` exposes the
  redacted pending/last lifecycle state, including failed abort/auto-revert
  rollback attempts. While a confirmed transaction is applying or pending,
  persisted runtime config mutators are rejected with `FAILED_PRECONDITION` so
  timeout rollback cannot overwrite a later ad hoc config change.

- **`rbgp` commit-confirmed workflow.** `rbgp config apply` now accepts
  `--confirm-id` and `--confirm-timeout`; `rbgp config confirm`,
  `rbgp config abort`, and `rbgp config status` expose the
  corresponding confirmed transaction control and status RPCs with text and JSON
  output.

- **Live-impact policy config transactions.** `ApplyConfigTransaction` can now
  commit policy definitions, neighbor sets, peer groups, and global named
  policy-chain edits that move existing static neighbors' resolved import/export
  policy chains.
  The executor stages the candidate snapshot, re-applies resolved chains to
  affected live sessions, captures prior chains for rollback, persists with an
  acknowledgement, and restores live chains plus the snapshot on failure.
  Re-evaluating an affected Established peer's received routes uses Route Refresh
  (RFC 2918), so the transaction requires every impacted Established peer to have
  negotiated the Route Refresh capability; otherwise it is rejected and rolled
  back cleanly. Dynamic-range policy impact, peer-group/session reshapes, mixed
  families, and other unsupported sections remain rejected without mutation.

### Fixed

- **`rbgp` confirmed config workflow input checks.** The CLI now rejects
  invalid confirmed-commit handles and over-limit `--confirm-timeout` values
  before reading the candidate file or sending an RPC, matching the daemon-side
  guardrails for safe deploys.

- **CLI JSON serialization failures are errors, not panics.** Non-config
  `rbgp` JSON renderers now route `serde_json` serialization failures
  through `CliError::Json` instead of `expect(...)`, including route/event JSON,
  mutation result JSON, and streaming watch output. Operator-visible JSON shapes
  are unchanged.

- **Typed config-transaction stage errors.** The internal
  `StageConfigSnapshot` path now returns a typed peer-manager error so
  `ApplyConfigTransaction` maps candidate-validation failures and rollback
  snapshot serialization failures without parsing error-string prefixes.

## [0.35.0] — 2026-06-04

### Added

- **Config transaction model foundation (ADR-0076).** `ConfigService` now has a
  validate-only `PlanConfigTransaction` RPC that parses a full candidate TOML,
  compares it against the daemon's live runtime config snapshot, returns an
  optimistic `runtime_snapshot_token`, and classifies sections into v1
  `supported_sections`, `unsupported_sections`, and
  `restart_required_sections`. The token is a per-process **keyed** hash of the
  canonical config: it still covers secrets (so a `md5_password`/`tcp_ao.key`
  rotation invalidates a stale plan) but cannot be used as an offline
  secret-guessing oracle by a `sensitive_read` caller. Tokens are process-local
  and do not survive a daemon restart — re-plan after a restart.
  `ApplyConfigTransaction` is the operator-tier commit entry point; v1 commits
  one pure runtime family at a time: full-set `[[fib_tables]]`, full-set
  `[[dynamic_neighbors]]`, or static `[[neighbors]]` add/delete/modify changes
  under the shared runtime-config coordinator, with persistence ack and rollback
  on apply/persist failure. Static-neighbor modifies use the same delete/re-add
  session-reconfigure semantics as SIGHUP while preserving disabled and
  graceful-shutdown intent. It also commits catalog-only policy definitions,
  policy neighbor sets, peer groups, and global named-chain assignments when the
  diff does not alter the effective runtime policy of any static neighbor or
  dynamic range. Mixed families, live-impacting policy/peer-group inheritance
  edits, and other unsupported sections are rejected without mutation. Candidate
  TOML remains audit-redacted, and `rustbgpctl config plan` /
  `rustbgpctl config apply` expose the operator workflow with text and JSON
  output. gNMI `Set` remains unimplemented/read-only pending an OpenConfig
  mapping onto this transaction model.

- **Full-scope ASPA path verification.** ASPA validation now uses the
  configured BGP Role to select the draft-ietf-sidrops-aspa-verification-25
  procedure: routes received from providers use downstream/customer-cone
  verification, while customer, peer, route-server, and route-server-client
  sessions use upstream verification. Stored routes retain the compact session
  context needed to replay the same ASPA direction on RTR cache updates, so
  cache revalidation no longer falls back to context-free upstream verification.

- **Outbound Route Filtering (ORF, RFC 5291 + RFC 5292) — receive side.**
  rustbgpd can now advertise willingness to receive Address-Prefix ORF entries
  (capability code 3, ORF-Type 64) and apply a peer-pushed prefix filter to the
  routes it advertises *to that peer* — an additional outbound filter on top of
  export policy, for route-server clients that want to constrain what they
  receive. Enable per neighbor or peer-group with `prefix_orf_receive = true`.
  Filtering follows prefix-list semantics (sequence-ordered, first match wins,
  implicit deny, `ge`/`le` length windows). Initial advertisement for an
  ORF-negotiated family is gated until the peer's first ROUTE-REFRESH (RFC 5291
  §6). The legacy Cisco ORF-Type 128 is decoded for interoperability but never
  advertised or applied. No new gRPC surface; configured via TOML only. See
  ADR-0075. (`rustbgpd-wire` gains an `orf` module and an optional ORF section on
  `RouteRefreshMessage` — a breaking change for that crate.)

- **Validation-cache import-refresh metric.**
  `bgp_validation_import_refreshes_total{dependency, outcome}` now counts
  inbound Route Refresh work triggered by VRP / ASPA cache updates for peers
  whose import policy matches validation state. `dependency` is `rpki` or
  `aspa`; `outcome` is `eligible`, `refreshed`, `skipped_not_established`, or
  `failed`.

### Changed

- **`rustbgpd-wire` 0.10.0 → 0.11.0 (breaking).** The receive-side ORF work adds
  a new `orf` module (RFC 5291/5292 types) and an optional ORF section to
  `RouteRefreshMessage`: the struct gains `orf: Option<OrfPayload>` and loses
  `Copy` (now `Clone` only). Consumers that construct or match `RouteRefreshMessage`
  literally, or rely on its `Copy` semantics, must update.

### Fixed

- **SIGHUP reload baseline after config transactions.** SIGHUP now reads the
  peer manager's live runtime config snapshot after acquiring the shared
  runtime-config coordinator lock, so a reload queued behind a committed
  transaction diffs against the transaction-updated runtime state instead of
  main.rs' stale process-local copy.

- **Config transaction rollback hardening.** Snapshot rollback during
  `ApplyConfigTransaction` now reports failure instead of silently discarding it,
  and static-neighbor rollback preserves both the original apply/persistence
  error and any rollback error in the returned `INTERNAL` status. Transaction
  plan stale-token errors are now structurally typed before gRPC status mapping
  instead of classified by string-prefix matching. The shared FIB-table commit
  path used by FIB-table CRUD and config transactions now reports peer-manager
  snapshot rollback failures consistently too.

- **Disabled static-peer reconfigure hardening.** Static-neighbor modify,
  SIGHUP changed-peer reconcile, and peer-group hot-apply now rebuild a disabled
  peer as disabled instead of re-adding it enabled and stopping it afterward.
  That prevents a transient session start and preserves disabled state across
  the SIGHUP reconcile path.

- **ASPA draft v25 first-AS precondition.** Role-aware ASPA validation now
  checks that the most recently added AS in the `AS_PATH` matches the negotiated
  neighbor ASN, with the transparent route-server-client exception from the
  draft. Routes that previously validated despite a stripped or rewritten
  leftmost AS now evaluate `invalid` when BGP Roles provide the validation
  context, which can affect the existing ASPA best-path preference and
  `match_aspa_validation` import/export policy.

- **Validation-cache updates now converge import policy matches.** When a fresh
  VRP or ASPA table arrives, rustbgpd still revalidates admitted RIB routes
  directly, and now also triggers inbound Route Refresh for established peers
  whose resolved import policy uses `match_rpki_validation` or
  `match_aspa_validation`. Routes that were previously denied because they
  evaluated against `not_found` / `unknown` can be reconsidered after the cache
  loads or changes; peers without validation-state import predicates are not
  refreshed.

- **BFD discriminator allocation no longer panics on theoretical exhaustion.**
  The local discriminator allocator now returns a typed exhaustion error, and
  the daemon logs and refuses to start that BFD session instead of panicking if
  the 32-bit non-zero discriminator space is ever exhausted.

### Performance

- **Config transaction static-neighbor apply now resolves only touched peers.**
  Static-neighbor add/modify transactions no longer rebuild the full candidate
  neighbor set before selecting the changed peers; the executor resolves just
  the added/modified `[[neighbors]]` entries through the same inheritance path.

## [0.34.0] — 2026-06-02

### Performance

- **Constant-time RPKI origin validation (bucketed VRP index).** `VrpTable`
  replaced its O(n) per-route linear scan with a family-split,
  prefix-length-bucketed index (33 IPv4 / 129 IPv6 buckets, each sorted by
  network); `validate` walks the route's ancestor prefix lengths with one binary
  search per length. At an 800k-VRP table a validation drops from ~460 µs to
  ~50 ns (>4 orders of magnitude) and is now roughly constant-time across table
  sizes (1k → 800k). Validation runs on every inbound NLRI and every RTR
  cache-update revalidation, so this also shortens cache-update reconvergence at
  scale. A new `validate` Criterion bench covers 1k/100k/800k VRPs across the
  five RFC 6811 outcomes.

- **Manager-level distribution fanout benchmark.** Added a feature-gated
  `rustbgpd-rib` Criterion bench that drives the real
  `RibManager::distribute_changes` path — per-peer export-policy evaluation,
  Adj-RIB-Out staging, and bounded-channel send — instead of only the bare RIB
  structs. The baseline is now documented in `BENCHMARKS.md`: first-advertise
  route-server fanout scales linearly at ~178 ns per (peer × prefix), and an
  eight-statement scalar-guard export chain adds ~18%.

- **Cap/configure tokio runtime worker threads.** The runtime previously
  spawned one worker per CPU core (`Runtime::new()`), so on a high-core host it
  over-provisioned the async runtime — dozens of workers for an I/O-bound
  daemon that never needs that parallelism. The worker count now defaults to
  `min(CPU parallelism, 8)` and is configurable via `[global] worker_threads`
  or the `RUSTBGPD_WORKER_THREADS` environment variable (env > config >
  default; restart-required, as the runtime is built once at startup). This
  reduces virtual-address reservation and scheduler footprint and gives
  operators a knob for constrained containers; same-host bgperf2 showed **no
  RSS change and no performance regression** at 8 workers. No change on hosts
  with ≤ 8 cores.

- **Compact trie-backed RIB prefix indexes.** The two prefix-keyed secondary
  indexes — `AdjRibIn::prefix_index` and `AdjRibOut::prefix_path_ids`, each
  mapping `Prefix → SmallVec<[path_id]>` — now use a family-split
  `prefix_trie::PrefixMap` instead of `hashbrown::HashMap`. This removes the
  per-prefix hash-bucket overhead that dominated RIB index memory: the
  allocator-tracked `memory_profile` drops the Adj-RIB-In-only footprint
  ~12% / ~19% at 100k / 500k prefixes and the full 2-peer + Loc-RIB profile
  ~9% / ~14%, while `adj_rib_in_insert` gets ~8% faster (compact trie nodes,
  no rehash) with best-path comparison and lookup unchanged. The Loc-RIB
  best-path map was evaluated for the same migration but kept on `HashMap`: the
  trie regressed the lookup-hot best-path recompute ~2.6×, not worth the extra
  memory on a read-dominated structure.

- **Precompiled FIB projection table policy.** The ADR-0061 FIB projection
  path now parses each table's `allowed_neighbors` once per projection pass and
  uses precomputed peer / peer-group membership sets for candidate filtering,
  instead of reparsing and rescanning table policy during every route and ECMP
  next-hop check. A new `fib_projection` Criterion bench covers configured
  tables x candidates x ECMP width behind the `bench-internals` feature.
- **One-pass API route listing.** `ListBestRoutes`, `ListReceivedRoutes`, and
  `ListAdvertisedRoutes` now fuse family filtering, route filters, pagination,
  and response construction into one pass over the RIB snapshot. High-volume
  list calls no longer allocate intermediate filtered `Vec<Route>` buffers, and
  large-community filters compare canonical typed values instead of allocating a
  per-route `Vec<String>`. Pagination, `total_count`, and invalid/non-canonical
  large-community filter behavior are unchanged.
- **Allocation-free max-prefix accounting.** Transport sessions now maintain a
  unicast prefix refcount beside the Add-Path `(prefix, path_id)` set, so
  max-prefix enforcement and `QueryState` no longer rebuild a temporary
  `HashSet<Prefix>` after every UPDATE just to count unique prefixes. Add-Path
  multiplicity remains correct — multiple path IDs for the same prefix still
  count as one prefix — and `FlowSpec` / EVPN accounting is unchanged.
- **Short-circuit policy predicate evaluation.** `PolicyStatement::matches` now
  evaluates match predicates cheapest-first with early returns instead of
  computing every predicate eagerly, so a cheap match failure (prefix, route
  type, RPKI / ASPA state, LOCAL_PREF / MED / AS_PATH-length bounds, next hop)
  avoids the expensive AS_PATH regex and community-list scan entirely. Matching
  is unchanged — still a logical AND of all configured predicates — only the
  cost ordering. The new `policy_predicate_eval` bench shows a regex-bearing
  statement dropping from ~80 ns to ~27 ns and a 64-community statement from
  ~51 ns to ~27 ns per route-statement when a cheaper predicate fails first;
  statements that genuinely reach those predicates are unaffected.
- **Lazy `AS_PATH` string on the export path.** The export-policy evaluator no
  longer renders the `AS_PATH` to a string for every advertised route unless an
  export policy actually matches on an `AS_PATH` regex. The rendered string's
  only consumer is that regex check, but it was built per (route × peer) in the
  distribution path — pure waste for the common RR / route-server case with no
  `AS_PATH`-regex policy. A no-`AS_PATH` export chain now skips the allocation
  entirely — the `export_policy_eval` bench's eager-vs-lazy arms differ by
  ~45 ns/route (the removed `AS_PATH`-string allocation), multiplied by peer
  fanout in real deployments. The import path is unchanged — there the string
  also feeds event / OTC attribution.

### Fixed

- **RFC 6811: a route exceeding a covering ROA's maxLength is now `Invalid`,
  not `NotFound`.** `VrpTable::validate` previously folded the maxLength check
  into the coverage test, so a route more specific than an otherwise-covering
  ROA (e.g. a `/25` under `10.0.0.0/16-24`) was misclassified `NotFound`.
  Per RFC 6811 §2 coverage is network containment only — maxLength gates the
  `Valid` decision — so such a route is `Invalid` (covered, no covering VRP
  authorizes it). **Behavior change:** these routes now carry `Invalid`, so the
  existing default best-path RPKI preference deprioritizes them (Valid > NotFound
  > Invalid) and operator `match rpki-validation = invalid` policies match them.
  No new automatic action is introduced; routes with no determinable origin ASN
  are unaffected (still `NotFound`).
- Docker Compose quick-start ports now bind to host loopback
  (`127.0.0.1`) instead of all host interfaces. The lab keeps legacy gRPC
  authorization for zero-setup `rustbgpctl` access, but the published gRPC and
  Prometheus ports now match the documented localhost-only access pattern.
- SIGHUP now rebuilds the live `[[dynamic_neighbors]]` accept matcher from the
  reloaded TOML, so adding, removing, or editing dynamic-neighbor ranges in the
  config file takes effect without a daemon restart. Runtime
  `AddDynamicNeighbor` / `DeleteDynamicNeighbor` now share the same
  runtime-config coordinator lock with SIGHUP and wait for config-persistence
  acknowledgement before returning; if persistence rejects an accepted mutation,
  the runtime matcher is rolled back instead of drifting ahead of disk.
- Runtime static-neighbor CRUD (`AddNeighbor` / `DeleteNeighbor`) now uses the
  same runtime-config coordinator lock and config-persistence acknowledgement as
  dynamic-neighbor CRUD. If the TOML write is rejected after the peer manager
  accepts the mutation, the API rolls the runtime change back and reports
  failure instead of letting a later SIGHUP reload stale disk.
- Dynamic peers created from `remote_asn = 0` accept-any ranges now surface the
  learned ASN from OPEN negotiation in peer snapshots, API state, BMP peer
  state, and RIB peer-up metadata instead of leaking the sentinel `0`.

## [0.33.0] — 2026-06-01

### Added

- **Runtime dynamic-neighbor CRUD.** `AddDynamicNeighbor` /
  `DeleteDynamicNeighbor` (NeighborService, tier `mutating`) are now live
  mutations instead of `UNIMPLEMENTED` — add or remove `[[dynamic_neighbors]]`
  prefix ranges without a restart, with `rustbgpctl dynamic-neighbor
  {list,add,delete}`. Changes reserve config-persistence capacity before
  mutating runtime state and queue an atomic TOML write when the daemon was
  started with `--config`, same as `AddNeighbor`. Delete stops future accepts
  only — already-established dynamic peers drain on Idle.
  Adding a range validates identically to config load (peer-group must exist
  and not enable BFD, valid prefix, no duplicate effective prefix); config-load
  validation now also rejects exact-duplicate effective prefixes.
- **Runtime `[[fib_tables]]` CRUD.** `SetFibTable` (create-or-replace by name,
  tier `mutating`), `DeleteFibTable` (tier `mutating`), and `ListFibTables`
  (tier `sensitive_read`) on `RibService`, with `rustbgpctl fib-table
  {list,set,delete}`. `set` carries the full table definition (not a patch);
  changing `table_id`/`metric` for an existing name is a table-key move (old
  kernel rows withdraw, the new table back-fills). Edits hot-apply through the
  ADR-0061 FIB reconciler and persist to the TOML config (atomic write) when
  started with `--config`. The candidate is validated against the live config
  before dispatch, persisted only after the reconciler acknowledges the exact
  accepted set, and serialized with SIGHUP FIB reloads through one coordinator
  lock — so runtime and on-disk config cannot drift. Requires the reconciler to
  be running (at least one `[[fib_tables]]` entry at startup) — otherwise the
  mutating RPCs return `FAILED_PRECONDITION` (enabling FIB from an empty config
  is still restart-required).

### Changed

- **`[[fib_tables]]` is now SIGHUP hot-reloadable.** When the ADR-0061 FIB
  reconciler is running (i.e. at least one `[[fib_tables]]` entry was present at
  startup), edits — adding/removing a table or changing `allowed_neighbors`,
  `allowed_peer_groups`, `max_routes`, ECMP caps, or `families` — are applied to
  the live reconciler on SIGHUP without a restart: added tables back-fill from
  current best routes, removed tables have their kernel rows withdrawn, and
  unaffected rows don't flap. The in-memory snapshot advances only after the
  reconciler acknowledges the new set (no best-effort drift). Starting the FIB
  subsystem from an empty config still requires a restart (the reconciler isn't
  spawned otherwise); deleting all tables leaves the actor idle and re-adding
  hot-applies. Previously any `[[fib_tables]]` edit was restart-required.
- **`--diff --json` `[[fib_tables]]` keys moved.** Following the hot-reload
  reclassification, the previously-released `restart_required.fib_tables_changed`
  key is replaced by `reload_applied.fib_tables_changed` (the hot-apply cases:
  N→M edits and deleting all tables) plus a new
  `restart_required.fib_tables_requires_restart` (the 0→N startup-from-empty
  case, which still needs a restart). The same split applies to the
  `DiffRuntimeConfig` gRPC `diff_json`. Consumers keying on the old path should
  switch to the new keys.

### Performance

- **Faster cold-start BGP reconnect after refused TCP dials.** A peer that
  starts before its passive neighbor has bound its listener no longer waits for
  the full 5s ConnectRetry base after the first refused TCP dial. TCP connection
  failures now retry twice at a 1s floor before returning to the configured
  exponential curve; OPEN validation failures / NOTIFICATION fallback still use
  the slower Idle reconnect guard so misconfigured peers do not hot-loop.
- **Dataplane reconcile allocation-churn reductions.**
  - `fib`: the unicast FIB reconciler no longer clones the full `FibOwnedState`
    each pass to detect changes — it tracks owned-state mutations explicitly and
    persists the owned-state file only when the content actually changed
    (`record_fib_success` reports per-op whether it mutated the map, so a
    kernel-drift repair that re-applies a route already owned no longer triggers
    a redundant persist). (#330)
  - `evpn`: the EVPN supervisor caches the projected remote-MAC and IP-prefix
    intent tables behind `Arc`s, sharing one allocation between cached state and
    the published `DataplaneIntent` and reusing it on BUM-only republishes
    instead of deep-cloning the tables. (#331)

### Fixed

- All bundled example configs now validate under the default tier gRPC
  authorization model. Production-style examples use local UDS listeners with
  explicit principals and `[security.grpc.roles]`; the Docker Compose
  quick-start opts into legacy enforcement intentionally for zero-setup lab
  access over its published TCP port. The `config_examples_parse` regression
  test now uses strict production-default parsing so missing gRPC auth config
  cannot be masked by the test helper's legacy compatibility shim.
- FIB-table runtime CRUD now rolls the reconciler and peer-manager snapshot back
  if the config bridge / persister rejects the accepted `[[fib_tables]]` set
  after runtime apply. The RPC reports failure without leaving runtime ahead of
  the persisted config.
- FIB-table runtime CRUD now waits for the config bridge and persister to
  acknowledge the accepted `[[fib_tables]]` set before releasing its SIGHUP/CRUD
  coordinator lock. This prevents an immediate SIGHUP from refreshing runtime
  snapshots from stale TOML after a successful `SetFibTable` / `DeleteFibTable`.
- SIGHUP `[[fib_tables]]` hot-reload now refreshes the peer manager's
  `fib_tables` snapshot before same-reload peer-group deletion checks, so
  removing a FIB table's `allowed_peer_groups` reference and deleting that peer
  group in one reload no longer trips a stale "still referenced" rejection.
- Dynamic-neighbor add/delete now queue their persistence event from a durable
  spawned task after the peer manager acknowledges the runtime mutation, so a
  canceled RPC cannot split the live `[[dynamic_neighbors]]` change from the
  TOML update.
- `AddDynamicNeighbor` now maps a missing referenced peer group to gRPC
  `NOT_FOUND` (matching the public API taxonomy for missing named resources)
  instead of `INVALID_ARGUMENT`; malformed prefixes and BFD-enabled peer groups
  remain `INVALID_ARGUMENT`.
- Dynamic neighbor ranges now resolve overlaps by longest-prefix-match: a more
  specific range (e.g. `10.0.5.0/24`) wins over a wider one (`10.0.0.0/16`)
  regardless of TOML declaration order, matching FRR/GoBGP. Previously the first
  matching range in config order won, so the selected peer-group depended on
  ordering when ranges overlapped.

## [0.32.0] — 2026-05-29

### Changed

- **Event-history durable outbox is now opt-in (default `false`).** ADR-0072's
  outbox shipped default-on in v0.31.0; v0.32.0 bgperf2 benchmarking showed the
  always-on cost was material — ~62 MB RSS and roughly double the peak CPU at
  2p/100k — a tax every operator paid before asking for replay semantics. The
  safer default for a routing daemon is fast-and-lean, so operators who want
  restart-safe event replay must now set `[event_history].enabled = true` and
  restart. With it off, `SubscribeFromEvent` and gNMI `Subscribe ON_CHANGE`
  return `FAILED_PRECONDITION` pointing at the knob; the live `WatchEvents` /
  `WatchRoutes` / `List*Events` surfaces are unaffected. The ADR-0072
  implementation is unchanged — only the default posture.
- **Inbound UPDATE attribute hot-path optimizations.** `process_update` now does
  a single-pass attribute-context extraction (`PolicyAttrSummary`) instead of
  ~8 separate scans of the attribute vector, and shares the canonical attribute
  `Arc` across same-UPDATE NLRI when policy makes no modifications
  (`RouteAttrBundle`) instead of deep-cloning per accepted route.
  Behaviour-identical; cuts per-UPDATE allocation churn and dropped 2p/100k
  full-daemon RSS ~21% (lower jemalloc allocator high-water mark).
- Inlined the per-peer Adj-RIB-In secondary prefix index
  (`HashMap<Prefix, HashSet<u32>>` → `HashMap<Prefix, SmallVec<[u32; 1]>>`),
  eliminating one heap-allocated `HashSet` per prefix for the common
  no-Add-Path case — ~21–22% lower Adj-RIB-In resident memory at scale
  (−110 MB at 900k prefixes × 2 peers in the `memory_profile` test).
  Mirrors the existing `AdjRibOut::prefix_path_ids` layout; no behaviour
  change.
- **MSRV 1.92 → 1.95** for the workspace. Driven by the embedded SQLite
  build: `rusqlite` 0.32 → 0.40 pulls `libsqlite3-sys` 0.38, whose build
  script uses the `cfg_select!` macro stabilized in Rust 1.95. Updated in
  lockstep: `Cargo.toml` `rust-version`, the CI `msrv` toolchain
  (`dtolnay/rust-toolchain@1.95`), and the `rust:1.95-bookworm` builder
  images (`Dockerfile` + the EVPN-Linux test image). The event-history
  outbox now binds `event_id` as `i64` (rusqlite 0.40 dropped the `u64`
  `ToSql` impl) via the existing `clamp_event_id` helper; no schema or
  behaviour change.

## [0.31.0] — 2026-05-28

### Added

- `rustbgpd --init-config <profile> --stdout` prints a curated, commented
  starter config to stdout and exits — a zero-setup bootstrap that works
  before any config file or daemon exists. Profiles: `lab` (minimal
  single-box local setup, gRPC over a local UDS) and `edge` (eBGP edge
  skeleton with a named import-policy chain). Each built-in profile is
  validated through the real config loader before it is emitted (and a
  unit test round-trips every profile), so the output is always loadable.
  Daemon flag rather than a subcommand to avoid retrofitting the
  hand-rolled arg parser; `--stdout` is required (file output is a future
  addition).

- `PolicyService.ExplainImportPolicy` (ADR-0073): answer "why didn't
  this prefix come in?" — or "what did the chain do to it when it
  did?" — from a new bounded per-session import-decision cache. Every
  import evaluation (permit **and** deny) is recorded at the transport
  eval site keyed by `(AFI, SAFI, prefix, path_id)`, so denied routes
  that never reached the RIB stay explainable. Outcomes:
  `PERMIT` / `DENY` / `WITHDRAWN` (tombstone) / `EVICTED` / `STALE`
  (policy reloaded since the decision) / `NOT_SEEN`. The query is
  side-effect-free (no RIB touch, no counter movement). Scope is
  IPv4 / IPv6 unicast; the cache resets on peer session reset and is
  not durable across restart (it is diagnostic state, not event
  history). Per-peer capacity is `[policy.explain] cache_size`
  (default 4096, a fabric / partial-table size — raise it for
  full-table peers). `[policy.explain] enabled` (default `true`)
  gates the write path: when `false`, the inbound UPDATE path skips
  the decision-snapshot clone entirely (one boolean check, nothing
  stored) for perf-sensitive full-table peers. `WITHDRAWN` entries
  are kept as lightweight tombstones (attributes/modifications
  dropped). `SensitiveRead` authz tier.
- `bench/compare-criterion.sh` gains `--attempts N`: run the A/B
  comparison N times with alternating base-first / head-first ordering
  to dampen base/head cache-warming bias. Each ref's run uses its own
  saved Criterion baseline (`attempt-N-base` / `attempt-N-head`); deltas
  are computed head-vs-base from the saved baseline medians so the sign
  convention is independent of which ref ran first. With `attempts ≥ 2`
  the summary table reports across-attempt stddev, min..max, and a
  conservatively propagated last-run 95% CI alongside the mean delta.
  The `Criterion Bench Compare` workflow defaults to `attempts=3`.
  Single-attempt behaviour is the same simpler table as before.
- `bench/compare-criterion.sh` and all five soak entrypoints under
  `tests/soak/` now acquire a shared exclusive `flock` on
  `$HOME/.local/state/rustbgpd-host.lock` before doing real work. A
  bench dispatch on a host with an active soak (or vice versa) fails
  fast with a clear error rather than producing useless numbers. The
  soak side shares logic through a new `tests/soak/host-lock.sh`
  helper. Local dev boxes without that XDG state directory skip the
  locking. Running soak under `sudo` moves the lock path to
  `/root/.local/state/...` and bypasses the guard; the soak README's
  "Host mutex" section documents the `RUSTBGPD_HOST_LOCK` override for
  the rare case where sudo is unavoidable.
- Added `bench/compare-criterion.sh` and a short `bench/` runbook for
  pinned local Criterion comparisons. The tool creates detached
  worktrees for two refs, runs the same bench target on a selected CPU
  core, and writes a paste-ready Markdown summary plus raw Criterion
  artifacts under `target/bench-compare/`.
- Added a manual `Criterion Bench Compare` workflow that reuses the
  local compare script on a future `[self-hosted, rustbgpd-bench]`
  runner. It is deliberately not wired into normal pull-request CI
  until the runner exists and its noise floor is calibrated.
- Added a `bulk_initial_load` Criterion group to the RIB benchmark
  suite for cold single-peer table convergence into Adj-RIB-In,
  Loc-RIB, and Adj-RIB-Out.
- Added `policy_eval` (policy-chain walk + early-deny short-circuit) and
  `explain_snapshot` (ADR-0073 import-decision-snapshot clone cost)
  Criterion benches under `crates/policy/benches/`, so the policy-eval
  hot path and the explain-cache write-path clone are individually
  measurable.

### Fixed

- Reduced `AdjRibIn::insert` small-N clone overhead by boxing the rare
  RFC 8950 unnumbered `Route.next_hop_scope` payload. Pinned repeat
  measurements on the v0.30.0 benchmark host confirmed the 10k insert
  regression versus v0.24.0 was real (+11.9% median on `main`) and the
  layout change brings the 10k median back within 1.2% of the v0.24.0
  baseline without moving the 500k case.

### Docs

- Added a per-release gRPC authorization release-readiness gate to
  `docs/RELEASE_CHECKLIST.md` (verify every RPC has an authz tier, the
  matrix matches `proto/rustbgpd.proto`, and the inventory export is
  current) plus a dataplane-programming guardrail.
- Codified the per-row benchmark grading rule in `docs/BENCHMARKS.md`
  (`min..max` straddling zero = noise; stddev at/above the ~10% same-SHA
  noise floor = inconclusive; ~3% regression floor) as reviewer guidance,
  with a "how to read bench output" reading guide.

## [0.30.0] — 2026-05-27

### Changed

- **`rustbgpd-wire` 0.9.4 → 0.10.0** (breaking). RFC 9234 BGP Roles
  + OTC work landed three additive `pub` API changes that are
  breaking on existing enums without `#[non_exhaustive]`:
  - New `pub enum BgpRole` (provider / customer / peer / route-server
    / route-server-client) re-exported from `lib`.
  - New `Capability::Role(BgpRole)` variant on the OPEN capability
    enum (RFC 9234 §4 capability code 9).
  - New `PathAttribute::OnlyToCustomer(u32)` variant on the path-
    attribute enum (RFC 9234 §6, attribute type 35).
  Consumers exhaustively matching on `Capability` or `PathAttribute`
  will need to add the new arms. Internal OTC Partial-bit
  preservation fixes are non-breaking and roll up in the same
  version.
- **ASPA verification: tighter scope + proven §5.4 algorithm
  equivalence (ADR-0049 amended).** ADR-0049 retargeted to
  `draft-ietf-sidrops-aspa-verification-25` (April 19, 2026).
  - §6.2 family gate: `ValidationSnapshot::validate_aspa` now takes
    `(Afi, Safi)` and returns `Unknown` for any family outside IPv4
    / IPv6 unicast. Previously the ASPA verdict was computed once
    per UPDATE from the shared AS_PATH and propagated to every NLRI
    in the UPDATE — including FlowSpec, EVPN, and other non-unicast
    families that the draft explicitly excludes from ASPA.
    `match_aspa_validation` import policy against non-unicast
    families now sees `Unknown` instead of unsafely inheriting the
    upstream walk's verdict. IPv4 / IPv6 unicast routes are
    unchanged.
  - Proven equivalence: production `verify_upstream` (pairwise walk)
    matches draft v25 §5.4's bounds-checker form across a
    synthesized 69k-case corpus (distinct-ASN paths of length 2..=5
    × every per-pair attestation state combination). A
    `#[cfg(test)]` reference implementation of the bounds-checker
    stays in tree as a regression oracle.
  - Inline note flags the missing draft v25 §5.4 step 2 first-AS
    check (no `enforce-first-as`-equivalent today); tracked as a
    follow-up, not addressed in this PR.

### Added

- **ADR-0070 deferral resolved: gNMI `Subscribe ON_CHANGE` v1.**
  `STREAM` + `ON_CHANGE` is accepted for
  `…/neighbor[neighbor-address=*]/state/session-state` (the explicit
  `*` wildcard and the no-key shorthand both lower to the same
  all-neighbors target). The handler sources live FSM transitions
  from `EventHistoryManager::subscribe_live()`, decodes each
  `CommittedEvent`'s prost-encoded `BgpEvent` payload, and emits a
  per-leaf OpenConfig Update with the short-form state name. Initial
  sync delivers one Update per configured peer (including non-
  Established peers) followed by `sync_response`. Other leaves under
  `ON_CHANGE` return `Unimplemented`; the `ONCE` and `POLL` outer
  modes continue to reject `ON_CHANGE`. `FailedPrecondition` when
  `[event_history]` is disabled or EHM is in pass-through.
  Reconnect = fresh initial snapshot (no replay); broadcast `Lagged`
  closes with `DataLoss` so the collector reconnects and resyncs.
  Authz: gNMI Subscribe stays at the `SensitiveRead` tier — the
  external contract is unchanged even though the implementation is
  EHM-backed.
- **ADR-0072 follow-up: `OtcRouteBlocked` structured event payload.**
  Closes the deferred ADR-0071 (RFC 9234 BGP Roles + OTC) item.
  Every OTC ingress / egress block decision now publishes a
  durable `OtcRouteBlockedEvent` payload on `SubscribeFromEvent`
  alongside the existing `bgp_otc_routes_blocked_total{peer, reason}`
  counter and the per-`NeighborState` `otc_routes_blocked` scalar.
  The payload carries `peer`, `direction` (`ingress` / `egress`),
  `reason` (the same bounded label vocabulary as the counter), all
  blocked `prefixes` from one rejected UPDATE (or one prefix per
  blocked route for egress), `local_role` / `remote_role`, optional
  `otc_value` (omitted on `malformed_length` where the attribute
  couldn't be decoded), and a lossless string AS_PATH that preserves
  `AS_SET` / confederation segments via `{…}` notation. Rides on
  `EVENT_CATEGORY_POLICY` with the next-free
  `BGP_EVENT_TYPE_OTC_ROUTE_BLOCKED` enum value. A new
  `TransportEventSink` trait (mirroring `RibEventSink` from PR5)
  keeps the producer-side hot path free of any proto / event-history
  dependency cycle; the binary plugs in an EHM-backed implementation
  when `[event_history].enabled = true` and a no-op sink otherwise,
  so the legacy counter + scalar surfaces are byte-identical
  pre-PR.
- **ADR-0072 follow-up: dataplane events flow through EHM.** The
  `spawn_dataplane_poller` summary producer
  (FIB / blackhole installed / rejected / failed rollups) and the
  `spawn_fib_dataplane_event_bridge` per-route producer now enqueue
  into `EventHistoryManager` alongside the existing `WatchEvents`
  broadcast. Both event flavors live under
  `EVENT_CATEGORY_DATAPLANE`, discriminated by `BgpEventType`. The
  poller is **startup-spawned** when `[event_history].enabled` so
  `SubscribeFromEvent` collectors see dataplane summaries from
  the first tick — independent of whether any `WatchEvents`
  subscriber ever attaches. When EHM is disabled, the existing
  lazy-spawn-and-exit behavior is byte-identical to pre-PR.
  Closes the v1 producer-set deferral from ADR-0072.
- **ADR-0072 — durable event history (local outbox).** New design
  contract for a SQLite WAL-backed daemon-local event outbox that
  survives restart with a monotonic `event_id` cursor. External
  collectors (Kafka, NATS, Vector, journald, custom) bridge to their
  own bus via the existing gRPC stream; rustbgpd does not try to be
  an event bus itself. Unblocks the deferred `OtcRouteBlocked`
  structured event payload from ADR-0071 and the `Subscribe
  ON_CHANGE` deferral from ADR-0070.
- **Event-history foundation crate (`rustbgpd-event-history`).** New
  `EventHistoryManager` actor + storage thread, explicit
  `metadata.last_event_id` allocator with primary DB plus
  `events.db.stale` quarantine recovery; `events.last_id` is
  diagnostic-only in v1. Adds `event_peers` join table for any-role peer queries,
  count + byte retention with explicit `ORDER BY event_id ASC`
  eviction. Behind `[event_history]` config — default-on, ~256 MB
  soft retention target on disk. Producer wiring shipped in PR5
  (RIB route + EVPN + PeerManager + BFD) and the follow-up sprint
  (dataplane #291). Pinned by the byte-equality invariant
  test: producer bytes == persisted bytes == broadcast bytes.
- **`[event_history]` config block** with `enabled` (default-on),
  `required` (fail-start vs pass-through), `max_events`,
  `max_bytes`, `synchronous`, `overflow`, batching tuning. All
  fields are restart-required.
- **`bgp_event_outbox_*` Prometheus metrics:** `_committed_total`,
  `_dropped_total{reason}`, `_queue_depth`, `_db_size_bytes`,
  `_retention_evicted_total{reason}`, `_latest_event_id`,
  `_open_failures_total`, `_degraded`. The degraded flag flips on
  the first drop or open failure and does not auto-clear in v1.
- **ADR-0072 PR5 — `EventHistoryManager` runtime wiring + cursor
  handler.** Closes the durable event outbox end-to-end. New
  `EventHistoryHandle` (Clone) is the read/write projection
  threaded into `EventService`, `RibManager`, `PeerManager`, and
  the BFD bridge; the parent `EventHistoryManager` keeps lifecycle
  (consuming `shutdown(self)`) on the daemon binary. Producers
  flow into EHM alongside their existing rings + broadcasts via a
  new `crates/rib/src/event_sink.rs` `RibEventSink` trait (route
  + EVPN), in-place `try_send` calls at every
  `src/peer_manager/events.rs` publish site (session-lifecycle +
  notification + policy — **first time notification events are
  durably persisted**, closing ADR-0071's notification-history
  gap), and an EHM `try_send` inside the existing BFD →
  `BgpEvent` bridge. `SubscribeFromEvent` returns a real stream
  (replay-then-live via the PR3 actor-ordered handoff); when the
  requested cursor is older than the live retention floor the
  handler emits a leading `StreamLagEvent` (global-stream gap
  count, not filtered) and then resumes from the earliest
  retained event; new `bgp_event_outbox_cursor_gap_total` counter
  tracks how often that fires. `Status::failed_precondition` on
  disabled / pass-through / `required = false` start-failure
  paths; the legacy `WatchEvents` / `WatchRoutes` /
  `List*Events` surfaces are byte-identical to pre-PR. CLI
  `rustbgpctl events watch --from-event-id <u64>` (mutually
  exclusive with `--backfill`); the watch formatters now print
  the envelope-level `event_id` for every category, not only
  routes. New `examples/event-bridge/` reference workspace
  binary streams `BgpEvent` as JSON-lines to stdout via a shared
  `rustbgpd_api::json_format::bgp_event_to_json_line` helper —
  operators replace the stdout writer with Kafka / NATS / Vector
  / journald and persist `last_seen_event_id` after their
  downstream sink confirms durable receipt. In this PR5 slice,
  dataplane events stayed live-only; the follow-up dataplane wiring
  listed above superseded that initial caveat.

- **Operator Confidence Polish Sprint 1.**
  - **Reload matrix** (`docs/reload-matrix.md`). Per-field classification —
    `live` / `restart-required` / `rejected` / `unsupported` / `validation-only`
    — for the full config surface, including `[[neighbors]]` (28 fields),
    `[[peer_groups]]` (19 fields), `[global]` + telemetry / gRPC sub-sections,
    `[policy]` (named definitions / chains hot-apply; inline `[policy.import]`
    / `[policy.export]` are warn + no-op), and the pinned EVPN / FIB / BFD /
    TCP-AO sections. Cross-linked from `CONFIGURATION.md`. Backed by two
    structural tests in `src/config/tests.rs` that catch field-drift on
    future PRs.
  - **`bgp_policy_routes_total{peer, policy, direction, action}` Prometheus
    counter** plus the four scalar per-peer aggregates on `NeighborState`:
    `import_policy_routes_permitted` / `_denied` (per session — reset on
    session-down) and `export_policy_routes_permitted` / `_denied` (per RIB
    peer-attach — same reset semantics). Attribution is to the terminal-
    decision policy in the chain — the policy that issued the Deny, or the
    last policy when all permit. `policy="inline"` for anonymous statements
    and permit-all peers without an explicit chain (no `inline-<n>` —
    positions aren't stable across reloads). New `rustbgpd_policy::
    NamedPolicy { name, policy }` and `PolicyChain::evaluate_with_attribution`
    are the underlying seam; existing `PolicyResult` matchers don't churn.
    `RibUpdate::QueryNeighborPolicyStats` exposes the export-side aggregates
    via the same control channel as `QueryNeighbor`. Wired through every
    `evaluate_chain` call site on both ingress (`crates/transport/src/session/
    inbound.rs`) and egress (`crates/rib/src/manager/{distribution,
    peer_lifecycle, route_refresh}.rs`) — initial peer sync, route refresh,
    SIGHUP-driven outbound recompute, FlowSpec, and EVPN all increment.
    `ExplainAdvertisedRoute` remains diagnostic-only and does not count.
  - **`ExplainAdvertisedRoute` deny / permit reasons** now name the matched
    policy in the `ExplainReason.message` string (`"export policy
    \"filter-customers\" denied this route"` rather than the generic
    `"policy_denied"`).
  - **`rustbgpctl neighbor show` Policy Stats block** rendering the four
    scalar aggregates, with JSON output (`--format json`) carrying the same
    fields elided when zero.
  - **`docs/deployment.md`** — end-to-end install + lifecycle runbook:
    pre-built binary / source / container install, hardened systemd unit
    install, Docker + Docker Compose with state volumes, containerlab
    "hello world" (M0-frr), recommended first-production-ish topology that
    walks the build → validate → reload → observe loop, `--check` / `--diff`
    workflow, Observability (Prometheus / BMP / gNMI / CLI) including the new
    policy counter + scalar aggregates, GR-aware upgrade story with state-
    persistence inventory, sample-profile cross-reference table, and
    troubleshooting pointers. Cross-linked from README + OPERATIONS /
    CONFIGURATION / SECURITY / INTEROP.
- **ADR-0071 BGP Roles + Only-to-Customer behavior.** Static eBGP neighbors can
  set `role = "provider" | "rs" | "rs-client" | "customer" | "peer"` plus
  optional `strict_role = true`. rustbgpd advertises the RFC 9234 Role
  capability, rejects incompatible or contradictory Role OPENs with
  NOTIFICATION 2/11, and applies OTC route-leak procedures for IPv4/IPv6
  unicast: set OTC on Provider / Peer / Route-Server egress when absent,
  preserve existing OTC, suppress invalid OTC propagation to upstream / peer /
  route-server sessions, and treat malformed OTC length as withdraw for unicast
  announcements while preserving withdrawals in the same UPDATE. FlowSpec and
  EVPN are intentionally untouched in v1. Prometheus exposes
  `bgp_otc_routes_blocked_total{peer,reason}` for blocked unicast routes, and
  `NeighborService` / `rustbgpctl neighbor` surface configured and negotiated
  roles plus per-peer OTC block counts. M55 validates compatible Role pairs,
  Role mismatch / strict-mode rejection, OTC egress set, deliberate ingress
  leak rejection, and malformed-OTC treat-as-withdraw against FRR 10.3.1 plus a
  raw-BGP fixture.
- **ADR-0070 read-only gNMI / OpenConfig telemetry adapter.** A native gNMI
  target (`gnmi.gNMI`, gNMI v0.10.0) served over the mTLS TCP and UDS gRPC
  listeners, backed by the existing typed snapshots — not a config datastore.
  `Capabilities` advertises the OpenConfig BGP modules and `JSON` / `JSON_IETF`
  encodings; `Get` and `Subscribe` (`ONCE` / `POLL` / `STREAM SAMPLE`) return a
  strict OpenConfig BGP state subset under
  `network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/`
  — global `as` / `router-id` and per-neighbor `neighbor-address` / `enabled` /
  `peer-as` / `local-as` / `session-state` / `established-transitions` / message
  counters — rendered as RFC 7951 JSON. `Set` returns a stable `Unimplemented`.
  gNMI read RPCs are classified `SensitiveRead` under the ADR-0064 tier model and
  are only served on an mTLS-configured TCP listener (or local UDS). Per-AFI-SAFI
  counters, negotiated capabilities, `ON_CHANGE`, and `Set` are deferred
  (see ADR-0070). M54 adds a hosted `gnmic` smoke for `Capabilities`, `Get`, and
  `Subscribe STREAM/SAMPLE` over native mTLS.

## [0.29.0] — 2026-05-25

### Added

- **ADR-0066 per-class ECMP caps.** New per-table `[[fib_tables]].maximum_paths_ebgp`
  and `maximum_paths_ibgp` (FRR's `maximum-paths` / `maximum-paths ibgp`) cap eBGP
  and iBGP equal-cost groups independently. They override the table's overall
  `maximum_paths` for their class and fall back to it (then `1`) when unset, so
  existing configs are unchanged. The equal-cost group is homogeneous, so the
  best route's class selects the cap at projection; the RIB gathers siblings at
  the widest of the three caps. Validated `>= 1`, capped at 256.
- **ADR-0066 multipath-relax.** New global `[global].multipath_relax` (default
  `false`) relaxes unicast ECMP grouping from an exact `AS_PATH` match to
  `AS_PATH`-*length* equality, so equal-length paths through different ASes
  co-install as multipath (FRR's `bgp bestpath as-path multipath-relax`). It is
  a best-path-wide knob (the FIB install-candidate query groups once at the
  widest `maximum_paths`), threaded into `multipath_equal`; eBGP/iBGP class
  homogeneity and all other best-path tie conditions are unchanged. Inert unless
  a `[[fib_tables]]` sets `maximum_paths`, `maximum_paths_ebgp`, or
  `maximum_paths_ibgp` above `1`.
- **Link Bandwidth Extended Community parsing** (`rustbgpd-wire`,
  draft-ietf-idr-link-bandwidth). `ExtendedCommunity::as_link_bandwidth()` /
  `link_bandwidth()` decode and construct the non-transitive
  two-octet-AS-specific community (type 0x40 subtype 0x04) carrying the
  advertising AS and an IEEE-754 bytes/second bandwidth, and
  `Route::link_bandwidth()` surfaces it from a route's extended communities for
  weighted unequal-cost multipath.
- **ADR-0068 weighted (unequal-cost) multipath.** New global
  `[global].link_bandwidth_weighted` (default `false`) weights unicast ECMP
  next-hops by their Link Bandwidth Extended Community
  (draft-ietf-idr-link-bandwidth, FRR's `bgp bestpath bandwidth`). When the whole
  equal-cost group advertises a bandwidth, weights are normalized in proportion
  (largest → kernel weight 256) and programmed as per-next-hop `rtnh_hops` in the
  `RTA_MULTIPATH` route; if any path lacks the community, or the knob is off, the
  group stays equal-cost — byte-for-byte ADR-0066. A lone next-hop is always
  weight 1 (it carries all traffic and the kernel emits it weightless). Weights
  round-trip through the kernel and the v3 owned-state envelope, so a bandwidth
  change reprograms and an unchanged set never flaps. Inert unless a
  `[[fib_tables]]` sets `maximum_paths`, `maximum_paths_ebgp`, or
  `maximum_paths_ibgp` above `1`.
- **ADR-0069 BGP unnumbered spike artifacts.** Added a privileged netns proof
  for scoped IPv6 link-local TCP, IPv6 Hop-Limit/GTSM socket options, and IPv4
  route install via `fe80::/10` gateway + `dev`, plus an FRR↔FRR containerlab
  observation topology for BGP unnumbered / RFC 8950 behavior. The FRR 10.3.1
  observation establishes over link-local-only fabric links, exchanges IPv4
  routes with visible `fe80::/10` next-hops, captures 32-byte MP_REACH next-hop
  encoding, reports Extended Next Hop, and does not expose Link-Local Next Hop
  capability 77.
- **ADR-0069 scoped static neighbor identity.** Static IPv6 link-local
  neighbors now require `[[neighbors]].interface`, are keyed by
  `(address, interface)`, and can be addressed through gRPC / `rustbgpctl` as
  `fe80::...%ifname`. Active opens use scoped `SocketAddrV6`; passive accepts
  match the accepted scope id back to the configured interface; IPv6 GTSM uses
  Hop-Limit / Min-Hop. The same link-local address bound to more than one
  interface is rejected in this release (on load and SIGHUP) because the RIB
  still keys peers by bare address; scoped multi-interface peering is deferred.
  RFC 8950 route exchange and Linux FIB `dev` propagation ship in the companion
  ADR-0069 entries below.
- **ADR-0069 RFC 8950 unnumbered route exchange core.** Scoped IPv6 link-local
  peers now fail closed for `ipv4_unicast` unless RFC 8950 Extended Next Hop is
  negotiated: rustbgpd no longer falls back to IPv4 body NLRI on unnumbered
  links, ignores inbound IPv4 body NLRI from scoped link-local peers, accepts
  link-local primary IPv4 `MP_REACH_NLRI` only for scoped
  ENHE-negotiated sessions, emits the FRR-proven 32-byte link-local/link-local
  next-hop form, and carries next-hop scope metadata through RIB install
  candidates for Linux FIB projection.
- **ADR-0069 Linux FIB scoped link-local installs.** General unicast FIB
  projection now accepts IPv4 routes via IPv6 link-local next-hops only when the
  RIB install candidate carries a non-zero egress ifindex. Linux netlink emits
  scoped link-local routes as `RTA_VIA` plus `RTA_OIF` for single-path routes, or
  per-hop `rtnh_ifindex` inside `RTA_MULTIPATH` for ECMP / weighted multipath.
  Kernel dumps and owned-state v5 preserve the ifindex, so scoped rows remain
  diff-stable across reconciles and crash restart; missing link-local scope is
  rejected explicitly as `link_local_next_hop_scope_missing`.
- **M53 BGP unnumbered FRR interop.** Added the production ADR-0069
  rustbgpd↔FRR smoke: two IPv6 link-local-only FRR interface peers advertise the
  same IPv4 prefix, rustbgpd installs kernel ECMP through link-local gateways on
  two different interfaces, withdraw/re-advertise collapses and restores the
  scoped forwarding set, and injected rustbgpd IPv4 routes reach FRR with a
  link-local next-hop.

### Changed

- **`rustbgpd-wire` 0.9.3 → 0.9.4** (additive, non-breaking). Adds Link Bandwidth
  Extended Community decode/construct (`ExtendedCommunity::as_link_bandwidth` /
  `link_bandwidth`, draft-ietf-idr-link-bandwidth) and optional link-local-primary
  IPv4 `MP_REACH_NLRI` next-hop acceptance for unnumbered peers via the new
  `UpdateValidationOptions` + `validate_update_attributes_with_options`. No
  breaking API changes — existing items are unchanged.

## [0.28.0] — 2026-05-24

### Added

- **ADR-0066 unicast multipath / ECMP FIB install.** A new per-table knob
  `[[fib_tables]].maximum_paths` (default `1`, validated `>= 1`, capped at 256)
  selects up to N equal-cost BGP paths per prefix and installs them as a kernel
  `RTA_MULTIPATH` route. Groups are homogeneous (eBGP **or** iBGP, never mixed)
  and require exact `AS_PATH` equality; locally-originated routes never group. A
  single next-hop still emits a plain `RTA_GATEWAY`, so the default is
  byte-for-byte today's behavior. The RIB gained
  `QueryFibInstallCandidates` / `multipath_equal` (the equal-cost
  install-candidate view ADR-0061 deferred); crash-restart owned-state migrates
  v1 → v2 (loads and upgrades the legacy scalar next-hop); `ListFibRoutes` and
  `rustbgpctl` surface the full canonical `next_hops` set (scalar `next_hop`
  retained for back-compat — the best/representative next-hop, a member of
  `next_hops`). Validated by projection / canonicalization /
  owned-state unit tests, kernel encode→parse round-trips, a privileged netns
  install/failover test, and interop smoke **M50**
  (`tests/interop/m50-fib-ecmp-frr.clab.yml`) against two equal-cost FRR peers.
  Supersedes ADR-0061's ECMP deferral.
- **ADR-0067 single-hop asynchronous BFD — config + actor (observability,
  no BGP coupling yet).** New `[[bfd_profiles]]` blocks
  (`min_tx_interval` / `min_rx_interval` ms, floor 100; `multiplier`, min 2;
  defaults 300/300/3) plus opt-in `[neighbors.bfd]` / `[peer_groups.<name>.bfd]`
  (`profile`, `enabled` (default true — set false to override an inherited
  peer-group block off), `strict`), validated for profile-reference + bounds. An in-process
  BFD actor (`src/bfd_runtime.rs`) runs single-hop async sessions (RFC 5880 /
  5881) over real UDP/3784 sockets — TTL/Hop-Limit 255 on send, discard on
  receive if ≠ 255 — driving the pure `rustbgpd-bfd` sans-IO session FSM, and
  publishes per-session Up/Down via a status channel and Prometheus
  (`bfd_session_up`, `bfd_session_flaps_total`). This slice runs the sessions
  for observability **only**; BFD does not yet affect the BGP session (RFC 5882
  coupling lands in a later slice). IPv4 + IPv6 global, static neighbors only.
  Transmit source port is in the RFC 5881 §4 49152..=65535 range. BFD edits are
  restart-required (the actor resolves its sessions once at startup): `--diff`
  surfaces `bfd_changed` and SIGHUP pins `[[bfd_profiles]]` + neighbor/peer-group
  `bfd` back to the live snapshot. Config **rejects** effective BFD on IPv6
  link-local neighbors (deferred to v1.1). Validated by config parse/validation
  tests, `from_config` resolution tests, a reload-pinning test, and a privileged
  netns test (session reaches Up over real sockets, TTL≠255 is discarded,
  transmit source port is in range, detection drives Down when the peer goes
  silent). See ADR-0067 for the staged plan and deferral list (multihop,
  echo/demand, auth, dynamic-peer BFD, IPv6 link-local → v1.1).
- **ADR-0067 BFD operator inspection surface.** New `BfdService.GetBfdSessions`
  gRPC RPC (`BfdSession` { peer, state, diagnostic, strict }, optional
  peer-address filter) reading the actor's status snapshot, and
  `rustbgpctl bfd [list | show <peer>]` (JSON + table). Read-only, ADR-0064
  tier `sensitive_read`. This slice also lands the **event proto contract**
  (`EVENT_CATEGORY_BFD`, `BGP_EVENT_TYPE_BFD_SESSION_{UP,DOWN,STATE_CHANGED}`,
  `BfdSessionEvent`, the `BgpEvent.bfd` oneof) so it is stable, but BFD events
  **do not yet stream** over `EventService.WatchEvents` — actor event emission
  lands in a follow-up (the next entry).
- **ADR-0067 BFD event emission.** The BFD actor now publishes session
  state-change events into the unified `EventService.WatchEvents` stream as
  `BfdSessionEvent` payloads (`EVENT_CATEGORY_BFD`,
  `BGP_EVENT_TYPE_BFD_SESSION_{UP,DOWN,STATE_CHANGED}`). Opt-in like the
  dataplane / EVPN categories (not in the default route+session set);
  filterable by category, event type, and peer address. The actor stays
  decoupled from the gRPC proto — it broadcasts an internal event that a daemon
  bridge converts (mirrors the FIB dataplane bridge).
- **ADR-0067 BFD/BGP coupling — non-strict (RFC 5882).** A BFD session going
  **down** now tears the BGP session down before the hold timer expires, and
  recovery lets it re-establish — sub-second failover for BFD-enabled neighbors.
  `PeerManager` owns the desired BFD session set (published to the actor over a
  `watch`, updated on neighbor enable/disable/delete) and consumes session
  state changes over a lossless channel; the BFD actor remains a pure
  session-runner with no BGP knowledge. A deliberate disable/delete drains the
  session to `AdminDown` and is not treated as a failure. Per RFC 5882 §4.1, a
  *remote* `AdminDown` (the peer administratively disabling BFD) permits the BGP
  adjacency in **both** strict and non-strict mode (an established session stays
  up; a withheld strict session is released) — BFD is disabled, not failing. (Our
  local session state stays `Down`; the remote-AdminDown cause is tracked
  separately and consumed by the coupling.) Genuine failures (a detection
  timeout or a remote-signaled `Down`) still tear BGP down / keep strict
  withheld. The coupling is **level-triggered**: the actor re-confirms each
  session's current state to `PeerManager` on reconcile (an "ack"), so a strict
  re-enable always withholds and is released only when BFD is confirmed to permit
  BGP — it never trusts a stale cached state (no leak) and never waits for an
  edge that won't come (no deadlock).
- **ADR-0067 BFD/BGP coupling — strict (RFC 5882).** `[neighbors.bfd] strict =
  true` now withholds BGP establishment until BFD is Up: `add_peer` spawns the
  session Idle and withholds `start()` (the create/start split), and the first
  BFD Up releases it through the same up→start path non-strict recovery uses.
  A strict peer whose BFD never comes Up never establishes BGP.
- **ADR-0067 single-hop BFD — FRR interop + landed.** New interop test **M51**
  (`tests/interop/m51-bfd-frr.clab.yml`) peers rustbgpd with a real FRR `bfdd`
  (fast profile, 300 ms × 3 ≈ 900 ms detection, 90 s BGP hold) and proves the
  full path against a third-party implementation: BGP Established **and** BFD Up
  asserted from both sides (`GetBfdSessions` + FRR `show bfd peers`), a killed
  `bfdd` drops BFD and tears the BGP session down far faster than the hold timer
  (the RFC 5882 coupling, not a hold-timer expiry), and recovery re-establishes
  both. Wired into the `kernel-dataplane` CI workflow. With this, single-hop
  asynchronous BFD ships in v1 (IPv4 + IPv6 global, static neighbors, strict +
  non-strict coupling) and `COMPARISON.md` moves BFD `No → Yes`. **Deferred to
  follow-ups:** multihop (RFC 5883), echo / demand mode, authentication,
  C-bit / GR-aware nuance, static-route BFD tracking, dynamic-neighbor BFD,
  hardware / offload, and IPv6 link-local / unnumbered → v1.1.
- **ADR-0063 EVPN runtime convergence — `ip_vrf` relink.**
  `EvpnService.ApplyEvpnRuntime` now commits an L2VNI re-homed to a different
  IP-VRF (or its `ip_vrf` link added/removed) at runtime. A relink edits no
  IP-VRF/L2VNI/Ethernet-Segment row — the link lives only in the IP-VRF table's
  reference metadata — so the plan now carries an `ip_vrf_references_changed`
  signal (also surfaced in `ApplyEvpnRuntimeResponse.plan`) and converges
  dataplane-only (the dataplane is the sole consumer of the link, for RFC 9135
  overlay-index recursion; the RD is unchanged, so no Type 3 re-origination).
- **EVPN DF election — RFC 9785 Don't-Preempt origination.**
  `[[ethernet_segments]].df_dont_preempt` (default `false`) makes a
  preference-DF PE advertise the RFC 9785 Don't-Preempt bit on its Type 4 ES
  route's DF Election extended community (the wire signal for non-revertive DF).
  Config rejects it for non-preference algorithms (default-modulo / HRW). This
  is origination + parse only: the DP bit is intentionally not an election
  input (a stateless election cannot implement "don't preempt the incumbent");
  stateful non-revertive election remains deferred. New interop smoke **M49**
  (`tests/interop/m49-evpn-preference-df.clab.yml`) proves preference-DF drives
  the cross-PE election (a 2-PE rustbgpd ES where the preference winner differs
  from the modulo winner).
- **ADR-0063 EVPN runtime convergence — atomic tenant teardown.**
  `EvpnService.ApplyEvpnRuntime` now commits a delete-only tenant teardown: a
  plan that drops an Ethernet-Segment-member L2VNI together with its Ethernet
  Segment (deleted or member-shrink redefined) and/or a linked IP-VRF in one
  pass. This closes the runtime tenant lifecycle — an operator can now both
  build up and tear down a tenant without a restart. The converger validates
  internal consistency (no surviving L2VNI may dangle on a deleted IP-VRF; no
  candidate Ethernet Segment may still list a deleted member VNI; ES redefines
  accepted only as a member-shrink), withdraws each deleted L2VNI's Type 3 IMET,
  and republishes the candidate snapshots to every level-triggered actor
  (dataplane instances + IP-VRF metadata, SVI, Type 2 originator, segment, Type 5
  originator) with a rollback ladder that re-originates IMET on failure. The
  segment actor now emits Type 1/4 withdraws for a member VNI whose instance was
  removed in the same pass. Two new interop smokes drive the teardown over gRPC
  against FRR: **M47** (`tests/interop/m47-evpn-tenant-teardown.clab.yml`,
  control-plane ES-member L2VNI + Ethernet Segment) and **M48**
  (`tests/interop/m48-evpn-tenant-teardown-datapath.clab.yml`, a linked
  L2VNI + IP-VRF teardown over the kernel L3 datapath, asserting the Type 5
  withdraw and imported kernel-route drain). `ip_vrf` relink also commits live
  (see above); only non-teardown mixed edits (an add combined with a
  delete/redefine) and L3VNI/device/table IP-VRF identity changes remain
  non-live under [#210](https://github.com/lance0/rustbgpd/issues/210).
- **ADR-0063 EVPN runtime convergence — ES-member L2VNI redefine.**
  `EvpnService.ApplyEvpnRuntime` can now commit exactly one redefined
  `[[evpn_instances]]` entry even when that VNI is an Ethernet Segment member,
  as long as the candidate has no L2VNI add/delete, IP-VRF, or Ethernet
  Segment changes and the `ip_vrf` link metadata is unchanged. The segment
  actor now treats watched member-instance content changes as a Type 1/4
  rebuild trigger, withdrawing old-RD Type 4 / EAD-per-ES / EAD-per-EVI routes
  and originating the candidate route identity while keeping the ESI label
  stable. (Standalone `ip_vrf` relink commits live on its own path — see
  above; only non-teardown mixed edits and L3VNI/device/table IP-VRF identity
  changes remain non-live under
  [#210](https://github.com/lance0/rustbgpd/issues/210).)
- **EVPN DF election — RFC 9785 Highest-/Lowest-Preference.**
  `[[ethernet_segments]].df_algorithm` now accepts `"highest-preference"`
  and `"lowest-preference"` with `df_preference` in the RFC 9785
  `0..=65535` range. Type 4 Ethernet Segment routes advertise the selected
  preference algorithm and configured preference, remote Type 4 routes decode
  the Don't-Preempt bit (status/telemetry only), and unanimous preference-DF
  candidate sets elect the highest or lowest preference, tie-broken by the
  lowest PE IP. Mixed algorithms still fall back to default service carving.
  The DP bit is not an election input; local/stateful non-revertive election
  remains deferred.
- **EVPN multi-homing — single-active mode signaling.**
  `[[ethernet_segments]].redundancy_mode` now accepts `"all-active"` (the
  default) or `"single-active"`. Single-active segments set the RFC 7432 ESI
  Label extended-community Single-Active flag on Type 1 EAD-per-ES routes, and
  the receive path suppresses all-active aliasing ECMP when remote EAD-per-ES
  reachability advertises that flag. Mass-withdraw reachability filtering still
  applies; proactive single-active backup-path installation remains a follow-up.

- **EVPN DF election — RFC 8584 Highest Random Weight.**
  `[[ethernet_segments]].df_algorithm = "highest-random-weight"` now runs the
  HRW DF algorithm using the RFC 8584 §3.2 `Wrand(V, ESI, PE-IP)` weight
  function (a 31-bit CRC-32 digest of the Ethernet Tag + ESI fed through the
  specified LCG, `mod 2^31`), with the numerically lowest PE IP as the
  equal-weight tie-break, and advertises the DF Election Extended Community on
  Type 4 ES routes. Mixed or absent DF Election advertisements still fall back
  to default service carving. Validated by the
  M46 two-PE rustbgpd HRW interop smoke (over a VNI where the HRW winner differs
  from the modulo winner) plus a known-answer unit test pinning the weight to
  the RFC value; cross-vendor HRW is not testable against FRR, which implements
  RFC 9785 preference-DF rather than HRW. IPv6 originator addresses use the
  low-order 31 bits as the HRW `Si` input (self-consistent; IPv4 is the
  cross-vendor-exact case).
- **ADR-0063 EVPN runtime convergence — single IP-VRF redefine.**
  `EvpnService.ApplyEvpnRuntime` can now commit exactly one redefined
  `[[evpn_ip_vrfs]]` entry when the candidate has no L2VNI or Ethernet Segment
  changes, no IP-VRF add/delete, and the IP-VRF keeps the same name, L3VNI,
  `vrf_device`, `l3vxlan_device`, and `table_id`. The live slice supports
  route/policy/egress-field changes (`rd`, `route_targets`, `local_vtep_ip`,
  and `router_mac`) by republishing the candidate IP-VRF table to the dataplane
  supervisor and Type 5 originator. The Type 5 originator now drains local
  prefixes for removed or redefined IP-VRFs before reconciling the candidate
  table, so local Type 5 routes are withdrawn under the old RD and replayed
  under the new route attributes. Linked IP-VRF delete / tenant teardown,
  ES-aware L2VNI delete, and `ip_vrf` relink now commit live; only
  L3VNI/device/table IP-VRF identity redefinition and non-teardown mixed edits
  remain non-live under [#210](https://github.com/lance0/rustbgpd/issues/210).

- **ADR-0063 EVPN runtime convergence — single L2VNI redefine.**
  `EvpnService.ApplyEvpnRuntime` can now commit exactly one redefined
  `[[evpn_instances]]` entry (same VNI, changed `rd` / `route_targets` /
  `local_vtep_ip` / `bridge` / `advertise_svi_mac` / `sticky_macs` /
  `duplicate_mac_detection` / `apply_aliasing_ecmp`) when the candidate has no
  L2VNI add/delete, IP-VRF, or Ethernet Segment changes. The daemon
  re-originates the per-VNI Type 3 IMET (withdraw committed, originate
  candidate) and republishes the candidate instance table to the
  level-triggered Type 2 originator, SVI task, dataplane supervisor, and
  segment actor, which drain and re-derive the content-changed VNI; rollback
  unwinds on partial failure. This makes `apply_aliasing_ecmp` runtime-drivable
  via the dataplane `FdbNhg → SingleDst` transition (SIGHUP stays
  restart-required). Multi-element edits now commit live as atomic tenant
  teardown (and `ip_vrf` relink on its own path); only non-teardown mixed edits
  and L3VNI/device/table IP-VRF identity changes remain non-live under
  [#210](https://github.com/lance0/rustbgpd/issues/210).

### Changed

- **`rustbgpd-wire` 0.9.2 → 0.9.3** (additive, non-breaking). Adds the DF
  Election Extended Community (type 0x06, subtype 0x06):
  `ExtendedCommunity::as_df_election()` / `::df_election(...)` and the typed
  `attribute::DfElectionExtendedCommunity`, covering the RFC 8584 §2.2
  algorithm/capabilities fields and the RFC 9785 §3 preference / Don't-Preempt
  fields. No existing public item changed.

## [0.27.0] — 2026-05-22

### Added

- **ADR-0063 EVPN runtime convergence — runtime-added member VNIs for Ethernet Segments.**
  The EVPN segment actor now consumes runtime `[[evpn_instances]]`
  snapshots in addition to desired `[[ethernet_segments]]` snapshots. When a
  segment actor was already running at startup, single L2VNI add/delete
  convergence republishes the candidate instance table to it, so a later
  single Ethernet Segment add or redefine can bind a member VNI that was added
  live by `EvpnService.ApplyEvpnRuntime`. ES applies still fail closed for
  unknown member VNIs, mixed same-request L2VNI+ES edits, RR-only/no-segment
  actor deployments, and live segment actor spawn from a zero-ES startup model.

- **EVPN Type 5 overlay-index gateway injection.** `AddEvpnRoute` and
  `rustbgpctl evpn add-ip-prefix` can now inject a Type 5 IP Prefix route with
  an optional non-zero Gateway Address for controller-supplied overlay-index
  testing. Empty `gateway` preserves the existing interface-less gateway-zero
  shape; non-zero ESI and native local overlay-index origination remain out of
  scope.

- **ADR-0063 EVPN runtime convergence — single Ethernet Segment redefine.**
  `EvpnService.ApplyEvpnRuntime` can now commit exactly one redefined
  `[[ethernet_segments]]` entry when the candidate has no L2VNI, IP-VRF, or
  ES add/delete changes. The daemon republishes the Type 2 originator's
  candidate VNI-to-ESI map so member VNIs added to or removed from the segment
  restamp local MAC routes, then publishes the full candidate ES snapshot to
  the segment actor so Type 4, EAD-per-ES, EAD-per-EVI, and BUM enforcement
  state drain and rebuild under the segment owner. Mixed and multi-element
  edits, same-request L2VNI+ES changes, and RR-only/no-actor redefine remain
  fail-closed under #210.

- **ADR-0063 EVPN runtime convergence — single Ethernet Segment delete.**
  `EvpnService.ApplyEvpnRuntime` can now commit exactly one deleted
  `[[ethernet_segments]]` entry when the candidate has no L2VNI, IP-VRF, or
  ES redefine/add changes. The daemon republishes the Type 2 originator's
  candidate VNI-to-ESI map so former member VNIs restamp local MAC routes back
  to single-homed ESI zero, then publishes the full candidate ES snapshot to
  the segment actor so Type 4, EAD-per-ES, EAD-per-EVI, and BUM enforcement
  state drain under the segment owner. Mixed and multi-element edits,
  same-request L2VNI+ES changes, and RR-only/no-actor delete remain
  fail-closed under #210.

- **EVPN Type 5 projection-drop metrics.** Prometheus now exports
  `evpn_ip_vrf_remote_prefix_drops{vrf,reason}` as a current gauge for
  receive-side remote Type 5 routes that were kept fail-closed by the
  projection layer. The fixed reason labels cover overlay-index recursive
  failures (`overlay_index_no_linked_l2vni`,
  `unresolved_overlay_index_gateway`,
  `ambiguous_overlay_index_gateway`), RT misses, missing Router MACs,
  self-originated routes, and L3VNI mismatches; the special
  `vrf="_unscoped"` label covers drops that occur before a route can be tied
  to a configured IP-VRF.

- **EVPN Type 5 projection-drop status.** `EvpnService.ListIpVrfs`,
  `EvpnService.GetIpVrf`, and `rustbgpctl evpn vrfs [NAME]` now expose scoped
  `remote_prefix_drop_counts` for current receive-side remote Type 5 routes
  that were kept out of dataplane intent. The status surface reuses the bounded
  Prometheus reason labels and intentionally omits per-route prefixes,
  gateways, next-hops, MACs, RDs, and RTs.

- **ADR-0063 EVPN runtime convergence — single standalone IP-VRF delete.**
  `EvpnService.ApplyEvpnRuntime` can now commit exactly one deleted
  `[[evpn_ip_vrfs]]` entry when no committed L2VNI references that IP-VRF.
  The daemon republishes the candidate IP-VRF table to the dataplane
  supervisor and Type 5 originator so remote Type 5 FIB intent and locally
  originated Type 5 routes drain before the runtime generation advances.
  Linked IP-VRF delete, redefine, mixed and multi-element edits,
  and RR-only/no-actor delete remain fail-closed under #210.

- **ADR-0063 EVPN runtime convergence — single L2VNI delete in IP-VRF deployments.**
  `EvpnService.ApplyEvpnRuntime` can now commit exactly one deleted
  `[[evpn_instances]]` entry when the VNI is not an Ethernet Segment member,
  including IP-VRF deployments where the candidate keeps the IP-VRF row and
  only drops the deleted L2VNI's derived tenant link metadata. The daemon
  republishes candidate IP-VRF metadata plus the candidate L2VNI table to the
  dataplane supervisor and Type 2/SVI originators, withdraws the removed VNI's
  IMET route, and advances the runtime generation only after convergence
  accepts the candidate. Linked IP-VRF delete / tenant teardown, ES-aware
  L2VNI delete, redefine, mixed and multi-element edits, RR-only/no-actor
  delete, and same-request L2VNI+ES edits remain fail-closed under #210.
  SIGHUP EVPN edits remain restart-required.

- **EVPN overlay-index Type 5 receive-side recursion.** Remote Type 5 routes
  with a non-zero Gateway Address now resolve through a Type 2 MAC/IP route
  from the same RIB snapshot when the Type 2 route's L2VNI is linked to the
  matched IP-VRF through `[[evpn_instances]].ip_vrf`. The dataplane programs
  the resolved Type 2 VTEP and MAC for the remote prefix. Contenders are
  tie-broken the same way as the Type 2 path — the highest MAC mobility
  sequence wins, and a single MAC reachable through several VTEPs
  (multi-homing) resolves to a deterministic next_hop. Missing IP-VRF/L2VNI
  linkage, unresolved gateways, gateways resolving to multiple distinct MACs,
  self-originated rows, quarantined MACs, mass-withdraw-filtered Type 2 rows,
  RT misses, and L3VNI mismatches remain observable fail-closed drops.

## [0.26.0] — 2026-05-21

### Added

- **ADR-0063 EVPN runtime convergence — live commit for single-add edits.**
  `EvpnService.ApplyEvpnRuntime` now drives a daemon actor converger instead of
  failing closed on every non-noop edit. A **single L2VNI add** (one new
  `[[evpn_instances]]` entry) originates IMET and republishes the effective
  L2VNI table to the dataplane supervisor, the Type 2 MAC/MAC+IP originator, and
  the SVI-MAC task; a **single IP-VRF add** (one new `[[evpn_ip_vrfs]]` entry)
  republishes the effective IP-VRF table to the dataplane supervisor and the
  Type 5 originator; and a **single Ethernet Segment add** (one new
  `[[ethernet_segments]]` entry) republishes the full desired-ES snapshot to the
  segment actor — which drains/rebuilds Type 4 / EAD-per-ES / EAD-per-EVI and
  BUM-enforcement state — and re-stamps the member VNIs' local MAC routes with
  the segment ESI (duplicate-MAC quarantine and pending IP bindings are
  preserved across the change). Each supported add commits the next runtime
  generation.
  Convergence is ordered with rollback: a partial actor failure restores the
  prior effective tables, withdraws the speculative IMET, and marks the runtime
  degraded. Other non-noop shapes — delete, redefine, mixed L2VNI + IP-VRF in
  one request, more than one add, an add on an RR-only / no-actor daemon, or an
  Ethernet Segment referencing a member VNI added at runtime (the segment actor
  reads a startup-pinned instance table) — still return `FAILED_PRECONDITION`
  without advancing the generation or degrading the committed model. The
  originator and SVI actors drain removed/redefined VNIs (including stale
  duplicate-MAC move-window state) before accepting a new model. Remaining
  shapes tracked in [#210](https://github.com/lance0/rustbgpd/issues/210).
  SIGHUP that edits EVPN is still restart-required.

- **FIB status-row sampling metadata.** `ListFibRoutes` `FibRouteStatus` rows now
  carry sampling fields (`sampling_sampled_rows`, `sampling_suppressed_rows`,
  `sampling_total_rows`, `sampling_max_routes`, `sampling_sample_limit`,
  `sampling_complete`) for high-cardinality sets such as `route_limit_exceeded`,
  so operators can see how many over-cap rows were suppressed behind the sampled
  status rows. Counts are scoped to the table/metric/reason set, not the
  pagination page. `rustbgpctl rib fib` surfaces the metadata in both human and
  `--page-size` JSON output (deduplicated per sampled set).

## [0.25.0] — 2026-05-21

### Added

- **ADR-0063 EVPN runtime mutation foundation.** Added the safe-mutation
  contract for the startup-pinned EVPN model (`[[evpn_instances]]`,
  `[[evpn_ip_vrfs]]`, `[[ethernet_segments]]`). A generationed runtime model
  is initialized from the startup-resolved L2/L3/ES tables and exposed
  read-only through `EvpnService.GetEvpnRuntime` and `rustbgpctl evpn runtime`.
  Pure candidate-planning primitives classify add/delete/redefine/unchanged
  rows without publishing a generation. A coordinator core adds a convergence
  commit gate with idle/commit/failed state that retains failed-convergence
  plan and error detail without publishing candidate tables. The public
  `EvpnService.ApplyEvpnRuntime` mutation contract validates a full candidate
  TOML through the daemon config layer, supports validate-only planning and
  no-op apply, redacts credentials from audit summaries, and fails closed for
  non-noop mutations (no generation advance) until actor convergence exists.
  SIGHUP restart-required behavior is unchanged. Tracked in #210.

- **ADR-0063 EVPN runtime convergence command surfaces.** The daemon now owns
  an `EvpnImetController` for Type 3 IMET lifecycle state with per-VNI
  originate/withdraw methods and explicit outcomes (including reply-dropped
  tracking so a possibly-applied inject is still withdrawn at shutdown). The
  EVPN dataplane supervisor consumes watch-backed effective L2VNI and IP-VRF
  tables instead of startup-pinned `Arc`s and republishes `DataplaneIntent`
  immediately when those tables change, while preserving stable-poll
  generation suppression and the cached BUM-enforcement publish path. The
  Type 5 originator gains a handle-owned effective IP-VRF model watch and
  reconciles origination on IP-VRF model changes in addition to
  route/readiness changes. These are the command targets the coordinator will
  drive; live commits remain gated behind actor convergence (#210).

- **EVPN Type 5 (IP Prefix) route injection.** Added pure / interface-less
  EVPN Type 5 support to `AddEvpnRoute` / `DeleteEvpnRoute` (ESI 0, gateway 0,
  L3VNI label, Router MAC extended community) with `rustbgpctl evpn
  add-ip-prefix` / `delete-ip-prefix`. Validated against FRR 10.3.1 by the new
  M45 control-plane interop smoke. Per RFC 9136.

- **EVPN duplicate-MAC quarantine manual clear.** Added
  `EvpnService.ClearDuplicateMacQuarantine` (classified as an ADR-0064
  mutating method) and a bounded EVPN originator control command that clears
  one active duplicate-MAC quarantine, resets metrics/watch state, and replays
  still-live local MAC / MAC+IP state. Exposed as `rustbgpctl evpn
  clear-duplicate-mac`.

- **EVPN auto-derived Route Targets.** `auto_derive_route_target = true` is now
  accepted for both `[[evpn_instances]]` and `[[evpn_ip_vrfs]]`. L2VNI MAC-VRFs
  derive the RFC 8365 §5.1.2.1 VXLAN form; L3VNI IP-VRFs derive the plain
  `AS:VNI` form (the cross-vendor form FRR's tenant-VRF auto-RT uses). Explicit
  RTs are preserved, and explicit/derived duplicates are deduplicated through
  the existing runtime tables. Cross-vendor import validated by the new M39b
  FRR interop smoke. Requires a 2-octet AS.

- **EVPN route event history.** `EventService` now carries typed EVPN route
  events under `EVENT_CATEGORY_EVPN` with bounded in-RIB history exposed via
  `ListEvpnEvents` (peer / RD / route-type filters) and a live `WatchEvents`
  category. Added `rustbgpctl events evpn` plus live-watch rendering.

- **FIB dataplane route outcome events.** Added typed `DataplaneRouteEvent`
  payloads and event types for ADR-0061 FIB install, withdraw, and
  apply-failure outcomes, published live from `fib_runtime`, bridged into
  `EventService`, and filterable by dataplane type / peer / family / prefix.
  Surfaced in `rustbgpctl events watch`.

- **Policy-filtered route events.** Added unicast `policy_filtered` route
  events carrying explicit source-peer, target-peer, and reason fields, with
  export-policy denial state tracked so dirty/forced resyncs do not emit
  duplicate events. Wired through history queries, `EventService` filters, and
  CLI JSON/text output.

- **`ListFibRoutes` pagination.** Added optional `page_size` / `page_token`
  request fields and `next_page_token` / `total_count` response fields, with
  legacy unpaged behavior preserved when `page_size = 0`. Exposed via
  `rustbgpctl rib fib --page-size/--page-token`.

- **TCP-AO socket info inspection (ADR-0062).** Added Linux `TCP_AO_INFO`
  inspection and a transport `TcpAoInfoSnapshot`; the daemon logs TCP-AO
  current / rnext key IDs and counters after a protected active-open connect
  and a protected passive accept, and carries accepted-socket TCP-AO info on
  `AcceptedConnection` for a later API/CLI exposure tranche.

### Changed

- **Startup failures now emit fatal diagnostics instead of panicking.**
  Production startup `expect()` paths in `src/main.rs` are replaced with
  explicit fatal diagnostics and clean `process::exit(1)`. Pre-logging Tokio
  runtime construction reports through `eprintln!`; post-logging invariant
  failures report through `tracing::error!`.

### Fixed

- **EVPN duplicate-MAC remote route processing is suppressed during an active
  quarantine.** While a duplicate-MAC quarantine is active, the EVPN originator
  no longer runs remote MAC / MAC+IP route-processing callbacks for the
  quarantined MAC, while keeping remote contender caches fresh and continuing
  to enforce local Type 2 suppression once per quarantined MAC (RFC 7432
  §15.1).

## [0.24.0] — 2026-05-19

### Changed

- **BREAKING — `[security.grpc].enforcement` now defaults to `"tier"`.** The
  ADR-0064 slice 4b default flip lands the v1.0 security gate: gRPC requests
  are now authorized by per-principal role ceilings out of the box, in
  addition to the listener `max_tier` cap that already shipped in v0.23.0.
  Existing deployments that have not staged a `[security.grpc.roles]` block
  will fail validation at startup with a message pointing at the migration
  checklist in `docs/CONFIGURATION.md` AND the legacy escape hatch
  (`security.grpc.enforcement = "legacy"`). The migration checklist has
  shipped since v0.24-prep so operators have had the upgrade path documented
  with concrete `--check` validation steps. The opt-out remains supported
  indefinitely — `enforcement = "legacy"` continues to honor explicit
  configuration. Closes #164. Slice 4a opt-in enforcement, slice 4b
  migration prep, and the operations runbook for `grpc_authz` audit
  collection all shipped earlier in this release cycle and are
  prerequisites for the flip.

- **`rustbgpd:dev` container build ~7.6× faster on per-commit source changes.**
  Added `[profile.ci]` (release-shaped without fat-LTO / single-codegen-unit)
  for the interop / dev / CI container image; release-tagged binaries still
  use `--release`. The Dockerfile is rewritten with `cargo-chef` so the
  ~300-dep cook layer invalidates only on `Cargo.lock` changes, with BuildKit
  cache mounts (`/usr/local/cargo/registry`, `/usr/local/cargo/git`,
  `/build/target`) so cargo state survives across builds. `mold` is now the
  linker. The `kernel-dataplane.yml` workflow's `Build rustbgpd:dev` step
  moves from plain `docker build` to `docker/build-push-action@v7` with
  `type=gha` cache backend matching the existing `interop.yml` pattern.
  Measured wall-clock on the dev box: warm-cache no-source-change baseline
  2m 15s → 0.7s (cache hit); source-only-change rebuild
  2m 15s → 17.8s; first cold build 1m 03s.

- **CI interop test lifecycle now bounded-retries transient failures.**
  Added `.github/actions/run-interop-test` composite action that wraps
  `destroy → deploy → run → destroy-on-exit` for every M-series interop
  job (M1, M10, M13, M14, M15, M17, M22, M24, M25, M29, M30, M34, M35,
  M35b, M35c, M41, plus self-hosted M36 / M37 / M37+IP / M38 / M39 /
  M40 / M42 / M43) with a 2-attempt retry on transient failure. A
  successful retry annotates a workflow `::warning::` so the CI flake
  stays visible in the UI rather than silently hiding. M38's
  "PE2 promotes to DF after PE1 shutdown" gate widened from 60s to
  120s to absorb BGP hold-timer jitter under host contention. The
  `build-image`, MSRV, clippy, doc, and security-audit jobs are
  intentionally **not** retried — those failures are real regressions.

### Added

- **M44 — gRPC tier-authorization interop smoke.** New hosted-CI interop test
  (`tests/interop/m44-grpc-tier-authz.clab.yml`) proves the ADR-0064
  `enforcement = "tier"` default enforces over the wire, not just in config
  validation. `tests/interop/scripts/gen-m44-certs.sh` builds an mTLS PKI with
  four client certs whose `rustbgpd://` URI SANs map to `observer` /
  `automation` / `operator` roles plus one unmapped principal; the driver
  asserts per-tier allow/deny via `grpcurl` (observer can read but not mutate,
  automation can mutate but not run operator-only RPCs, operator can, unmapped
  is denied everything) and confirms `bgp_grpc_authz_decisions_total` records
  the `role_tier_denied` / `principal_unmapped` labels. Runs in
  `.github/workflows/interop.yml` — no kernel features required.

- **ADR-0064 machine-readable method-tier inventory.**
  `docs/grpc-method-inventory.json` now exports the checked 66-RPC gRPC
  authorization matrix for auditors and generated clients. The API `authz`
  tests verify the JSON artifact against `crates/api/src/authz.rs`, while the
  existing proto coverage test still fails if a new RPC lacks a tier assignment.

- **ADR-0064 mTLS principal cache.** Native gRPC mTLS listeners now carry an
  API-internal tonic connection-info cache for the principal derived from the
  validated client certificate. Repeated RPCs on the same HTTP/2 TLS
  connection reuse the cached result instead of reparsing the DER chain on
  every request, while preserving `mtls-unresolved` fallback and
  fail-closed role-enforcement behavior.

- **ADR-0064 opt-in gRPC role enforcement.** `security.grpc.enforcement =
  "tier"` is now accepted when every enabled listener has an authenticated
  principal source and `[security.grpc.roles]` maps principals to `observer`,
  `automation`, or `operator`. Tier mode enforces role ceilings before handlers
  run: unmapped principals get `PERMISSION_DENIED` with
  `principal_unmapped`, and below-tier roles get `role_tier_denied`. Legacy
  remains the default until the dedicated migration/default-flip slice.

- **ADR-0064 tier-enforcement migration guidance.** Configuration, API,
  security, roadmap, and ADR docs now spell out the safe staging path for the
  future default flip: declare `[security.grpc.roles]`, add explicit principals
  for UDS and bearer-token listeners, validate with `rustbgpd --check`, opt
  into `enforcement = "tier"`, then monitor `grpc_authz` denial labels. Config
  tests now include a positive bearer-token tier-mode example with a mapped
  principal and listener `max_tier`.

- **ADR-0064 mTLS audit principal extraction.** Native gRPC mTLS listeners now
  derive the `grpc_authz` audit principal from the validated client
  certificate (`rustbgpd:` URI SAN, then email SAN, then Subject CN) instead of
  always reporting `mtls-unresolved`. This is audit-only: listener `max_tier`
  caps still enforce the current boundary, while per-principal deny-by-tier
  enforcement and the default flip remain deferred.

- **ADR-0064 gRPC audit-log hardening.** Forwarded gRPC calls now emit
  result-aware `grpc_authz` audit outcomes such as `handler_ok` and
  `handler_invalid_argument` instead of only pre-handler `audit_forward`.
  Credential-bearing request summaries are masked before logging:
  `DiffRuntimeConfigRequest.candidate_toml` is summarized as redacted metadata
  (covering embedded `md5_password` and `tcp_ao.key` values), and
  `SetPeerGroup` records only MD5 state (`set_redacted`, `preserve`, or
  `clear`) without secret material. In-daemon durable audit sinks and proto
  credential-field annotations remain follow-up ADR-0064 slices.

- **ADR-0064 gRPC operations guardrails.** `docs/OPERATIONS.md` now documents
  the v1 audit posture for `grpc_authz` records: collect structured daemon logs
  with journald/syslog/log agents, apply external retention and access controls,
  query high-tier and denied calls, and alert on
  `bgp_grpc_authz_decisions_total`, stream lag, and subscriber gauges. The same
  runbook inventories expensive unary and streaming RPC classes and explains
  why in-daemon audit sinks and per-principal request budgets remain deferred
  design work rather than v1 defaults.

## [0.23.0] — 2026-05-19

### Added

- **ADR-0064 gRPC authorization foundation.** Added a checked
  `crates/api/src/authz.rs` method-tier matrix that classifies all 66 gRPC RPCs
  as `read`, `sensitive_read`, `mutating`, or `operator_only`, with tests that
  parse `proto/rustbgpd.proto` and fail when a new RPC lacks a tier assignment.
  `docs/grpc-method-inventory.md` and ADR-0064 now match the current
  listener-level `access_mode` behavior and document the future finer-grained
  authorization slices. No runtime authorization behavior changes in this
  foundation slice.

- **ADR-0064 gRPC authorization audit runtime.** gRPC listeners now run an
  audit-only Tower layer that observes each method path, looks up the checked
  ADR-0064 tier matrix, emits structured `grpc_authz` log records, and records
  `bgp_grpc_authz_decisions_total{tier,result,authn,access_mode}` without
  changing authorization behavior. Existing mTLS, bearer-token, Unix-socket,
  and `access_mode` checks remain unchanged. Full mTLS principal extraction,
  listener `max_tier`, and deny-by-tier enforcement remain follow-up ADR-0064
  slices.

- **ADR-0064 external-audit packet.** Added
  `docs/adr/0064-threat-model.md`, a repository-grounded gRPC management-plane
  threat model covering assets, trust boundaries, attacker capabilities, abuse
  paths, residual risks, external review evidence, and concrete follow-up issues
  for the remaining authorization/enforcement slices.

- **ADR-0064 gRPC roles config and audit principals.** Added staged
  `[security.grpc]` configuration with `enforcement = "legacy"` and
  `[security.grpc.roles]` principal-to-role mappings (`observer`,
  `automation`, `operator`). Bearer-token TCP and UDS listeners can now set
  explicit `principal` labels so audit-only `grpc_authz` records use stable
  operator-controlled identities. `enforcement = "tier"` remains reserved and
  is rejected until the deny-by-tier enforcement slice lands; existing mTLS,
  bearer-token, UDS, and listener `access_mode` behavior is unchanged.

- **ADR-0064 gRPC listener tier caps.** Added `max_tier` to TCP and UDS gRPC
  listeners and enforce it in the existing method-path Tower layer. Existing
  configs preserve their old behavior when `max_tier` is omitted:
  `access_mode = "read_only"` maps to a `sensitive_read` ceiling, and
  `read_write` maps to `operator_only`. When both fields are present, the
  effective cap is the stricter one, so `access_mode` cannot be weakened by
  `max_tier`. Role-based deny-by-tier enforcement and the default flip remain
  deferred.

- **Filtered general FIB status queries.** `RibService.ListFibRoutes` now
  accepts optional `table_name`, `state`, `reason`, exact prefix, and
  peer-address filters, and `rustbgpctl rib fib` exposes the same filters via
  `--table`, `--state`, `--reason`, `--prefix`, and `--peer`. Filters compose
  with AND semantics and the prefix filter is an exact prefix+length match.

- **ADR-0062 static-neighbor TCP-AO runtime support.** `[[neighbors]]` now
  accepts `tcp_ao = { key, send_id, recv_id, algorithm, preferred,
  deprecated }` and installs RFC 5925 TCP-AO keys on Linux startup active-open
  sockets before `connect()` and on the passive BGP listener before `listen()`.
  The schema is mutually exclusive with `md5_password`, redacts secrets in
  config diffs, validates key length and Linux TCP-AO algorithm names, aborts
  startup on listener key-install failure, and fails active-open connect attempts
  without falling back to unauthenticated TCP. Dynamic-neighbor TCP-AO, runtime
  key rotation, multi-key rollover, and accepted-socket inspection remain
  follow-up work.

- **M43 BIRD 3.2.1 TCP-AO interop smoke.** New
  `tests/interop/m43-tcp-ao-bird.clab.yml` topology and
  `tests/interop/scripts/test-m43-tcp-ao-bird.sh` driver validate
  ADR-0062 static-neighbor TCP-AO against a real BIRD 3.2.1 peer on Linux:
  matching keys establish and import `203.0.113.43/32`, then a mismatched BIRD
  key withdraws the route and fails closed instead of re-establishing. The
  protected self-hosted `kernel-dataplane` workflow now includes M43 and runs
  it on runner kernels that advertise `CONFIG_TCP_AO=y` after building the
  BIRD 3.2.1 image; runners without TCP-AO support skip the job with a warning
  because hosted runners do not guarantee the feature.

### Changed

- **EVPN production-default flip — `apply_bum_enforcement` now defaults to
  `true`.** The `[global].apply_bum_enforcement` field previously defaulted to
  `false` (observe-only). With both gating soaks PASS — Gate 8b 24h MAC-churn
  (2026-05-16, postmortem `docs/soaks/soak-gate8b-mac-churn-24h.md`) and M37
  local-origination 24h MAC-churn (2026-05-19, postmortem
  `docs/soaks/soak-m37-local-origination-churn-24h.md`) — the default flips to `true`,
  so new and upgraded deployments program the kernel BUM-suppression triplet
  (`IFLA_BRPORT_*_FLOOD`) on CE-facing bridge ports out of the box. Operators
  who need the prior observe-only posture must opt out explicitly with
  `apply_bum_enforcement = false`; the deserializer continues to honor explicit
  values unchanged. Restart-required (matches the prior behavior of the field).
  `apply_aliasing_ecmp` already defaulted to `true` (since ADR-0059 slice 3.5,
  PR #91); no schema change there, but the same soak evidence now backs both
  production defaults. See ROADMAP P1 "EVPN production-default decision point"
  (now complete).

- **TCP-AO edits are restart-required on SIGHUP.** Static-neighbor
  `tcp_ao` additions, removals, or key changes are pinned to the live startup
  snapshot during reload and reported through `--diff` / config-diff JSON as
  restart-required because Linux TCP-AO MKTs must be installed when sockets are
  created. Runtime deletion of a protected TCP-AO peer is rejected for the same
  reason until listener MKT deletion / key rotation support lands.

### Fixed

- **Peer-group read RPC secret redaction.** `PeerGroupService.ListPeerGroups`
  and `GetPeerGroup` no longer echo stored `md5_password` values; the
  write-side `SetPeerGroup` path still accepts MD5 material, but read responses
  redact the field and expose only `has_md5_password` so read-only listeners do
  not expose credentials. `SetPeerGroup` preserves an existing MD5 password
  when a read/modify/write client omits `has_md5_password` or sends
  `has_md5_password=true` without a new `md5_password` value; clients must send
  `has_md5_password=false` with no `md5_password` to clear it explicitly.

- **FDB nexthop raw-netlink parser hardening.**
  `NexthopSocket` response and `RTM_GETNEXTHOP` dump parsing now returns
  typed `NexthopError::Truncated` errors for malformed netlink datagrams
  instead of relying on guarded runtime slice conversions.

## [0.22.0] — 2026-05-17

### Added

- **EVPN duplicate-MAC M/N detector and opt-in local-origin quarantine.**
  Each `[[evpn_instances]]` entry now accepts
  `duplicate_mac_detection = { action, window_seconds, threshold,
  recovery_seconds }` with RFC 7432 §15.1 defaults (5 moves in 180 s).
  Default `action = "detect"` preserves existing behavior while adding
  threshold observability. Opt-in `action = "suppress_local"` withdraws
  and suppresses locally-originated Type 2 MAC-only and MAC+IP routes for
  the offending `(VNI, MAC)` until timed recovery. New metrics:
  `evpn_duplicate_mac_threshold_exceeded_total{vni,mac,action}` and
  `evpn_duplicate_mac_quarantine_active{vni,mac}`.

- **Live runtime config diff API/CLI.** New read-only
  `ConfigService.DiffRuntimeConfig` validates candidate TOML and
  compares it against the peer manager's live runtime config snapshot,
  returning only redacted diff text plus the existing
  `rustbgpd --diff --json` schema. `rustbgpctl config diff --from-file
  <PATH>` exposes the same surface for operators who need to preview a
  SIGHUP or restart-required edit against what the daemon is actually
  running, without exporting secret-bearing config snapshots.

- **Linux edge FIB operator example.** New
  `examples/linux-edge-fib/` config demonstrates a concrete ADR-0061
  `[[fib_tables]]` deployment with peer-group allow-list and route-count
  guardrail, plus a config test that parses every in-tree example TOML so
  future schema changes cannot silently break operator-facing examples.

- **Bounded route-event history.** `RibService.ListRouteEvents`
  returns recent unicast best-path events from the RIB manager's
  in-memory 4096-event ring, filtered by peer, IPv4/IPv6 unicast
  family, and exact prefix. `rustbgpctl events --prefix <PREFIX>`
  exposes the same drilldown for operators who need after-the-fact
  route add / withdraw / best-change context without leaving a live
  `WatchRoutes` stream running.

- **Unified live event stream foundation.** New
  `EventService.WatchEvents` streams typed `BgpEvent` envelopes, starting
  with the existing unicast best-path route events. `rustbgpctl events
  watch` exposes the same live stream with peer, family, exact-prefix, and
  route-event-type filters while leaving `WatchRoutes` and
  `ListRouteEvents` unchanged.

- **Route-event cursors and CLI backfill.** Unicast route events now carry a
  monotonic process-local `event_id` through `WatchRoutes`,
  `ListRouteEvents`, and `WatchEvents` route payloads. `rustbgpctl events
  watch --backfill N` opens the live stream first, prints recent matching
  route history through the same `BgpEvent` output shape used by the live
  tail, then suppresses already-printed live route events by cursor.

- **EventService session lifecycle events.** `EventService.WatchEvents`
  now also carries structured session events from the peer manager:
  `session_state_changed`, `session_established`, `session_lost`,
  `peer_enabled`, and `peer_disabled`. `rustbgpctl events watch
  --category session` tails those events with peer and type filters.
  Ordinary FSM state-change lifecycle delivery uses a bounded transport
  channel that is separate from the lossless TCP collision-coordination path,
  so session-event observability cannot grow the collision queue under churn.
  EVPN event categories remain deferred until their sources expose one
  complete structured event path.

- **EventService BGP NOTIFICATION events.** `EventService.WatchEvents`
  now surfaces metadata-only sent/received BGP NOTIFICATION events under
  the existing session category. Events include peer, direction, code,
  subcode, RFC code/subcode description, session role, and RFC 8203
  shutdown communication text when present. `rustbgpctl events watch
  --category session --type notification_sent` tails the same
  stream without exposing raw NOTIFICATION packet data.

- **EventService missed-event signaling.** `WatchEvents` now emits
  `stream_lagged` warning events when a slow subscriber falls behind the
  bounded route or session event broadcast. The event includes the source
  category and missed count so operators can distinguish a complete live
  tail from a lossy one.

- **EventService policy mutation events.** `EventService.WatchEvents`
  now supports the opt-in `EVENT_CATEGORY_POLICY` /
  `BGP_EVENT_TYPE_POLICY_CHANGED` stream. The peer manager emits one
  `PolicyEvent` after each successful runtime policy, neighbor-set,
  peer-group, or chain mutation, and `rustbgpctl events watch --category
  policy --type policy_changed` renders the same live audit trail. This is a
  runtime-apply signal, not per-route policy evaluation logging.

- **Bounded policy-event history.** `EventService.ListPolicyEvents`
  returns recent runtime policy / neighbor-set / peer-group / chain mutation
  events from the peer manager's in-memory 4096-event ring, filtered by
  peer-scoped target and limit. `rustbgpctl events policy` exposes the same
  after-the-fact audit trail while `WatchEvents` remains a live stream.

- **Bounded session-event history.** `EventService.ListSessionEvents`
  returns recent peer lifecycle events from the peer manager's in-memory
  4096-event ring, filtered by peer, session event type, and limit.
  `rustbgpctl events sessions` exposes the same after-the-fact session
  flap context while `WatchEvents` remains a live-only stream.

- **EventService dataplane status-row summary events.** `WatchEvents` now
  accepts `EVENT_CATEGORY_DATAPLANE` and emits
  `BGP_EVENT_TYPE_DATAPLANE_STATUS_CHANGED` when the surfaced FIB or
  BLACKHOLE discard status-row counts change. `rustbgpctl events watch
  --category dataplane --type dataplane_status_changed` tails the same
  summary stream. The FIB rejected count follows `ListFibRoutes` status rows,
  including sampled `route_limit_exceeded` rows, so it is not a global
  suppressed-route total. This is intentionally not a per-route, per-MAC, or
  EVPN reconcile-report stream; richer dataplane/EVPN event categories remain
  deferred.

- **Event stream loss observability.** New Prometheus metrics expose slow
  live-event consumers and route-history retention:
  `bgp_event_stream_lagged_total{service,source}` counts events missed by
  lagging `WatchEvents` / `WatchRoutes` subscribers,
  `bgp_event_stream_subscribers{service,source}` tracks active stream
  subscribers, and `bgp_route_event_history_depth` /
  `bgp_route_event_history_capacity` expose the bounded unicast route-event
  ring.

- **Self-hosted kernel dataplane CI gate.** New
  `.github/workflows/kernel-dataplane.yml` runs the privileged Linux
  dataplane checks that hosted runners cannot reliably exercise:
  M36 real-VTEP FDB programming, M37 local-MAC origination, M37+IP
  MAC/IP origination, M38 DF election + Type 1/4 origination, M39
  symmetric Interface-less IRB, M40 EVPN aliasing ECMP via FDB nexthop
  groups, M42 configured-table unicast FIB runtime, and the Docker
  `fdb_nhg` / `fib_runtime` netns selectors. Jobs target the protected
  `kernel-dataplane` GitHub Environment so PR code waits for maintainer
  approval before it reaches the self-hosted runner.

- **M37 local-origination MAC-churn soak harness.** New
  `tests/soak/run-m37-local-origination-churn-soak.sh` drives a
  bounded rotating bridge-FDB MAC pool against the M37 rustbgpd
  originator / FRR consumer topology, producing `samples.csv`,
  `churn.log`, daemon logs, and `run.json` under
  `tests/soak/runs/m37-local-origination-<UTC>/`. The harness prepares
  the 24 h validation tracked in #134; it does not claim the soak has
  passed until a postmortem is filled in.

- **ADR-0061 FIB guardrails.** `[[fib_tables]]` now supports
  `allowed_peer_groups`, `allowed_neighbors`, and `max_routes`.
  Peer / peer-group allow-lists are enforced before kernel apply, and
  `max_routes` freezes existing owned rows while suppressing table
  growth when the eligible route count exceeds the cap. Rejections
  surface through `ListFibRoutes`, `rustbgpctl rib fib`, and
  `bgp_fib_routes_rejected_total` as `peer_not_allowed` or
  `route_limit_exceeded`.

- **ADR-0061 FIB crash-restart owned-state.** The general unicast FIB
  runtime now persists its owned route map to
  `<runtime_state_dir>/fib-owned.json` after successful apply/drain
  operations. On startup it reloads the file only when the recorded
  `[[fib_tables]]` declaration still matches, then still requires the
  live kernel row to be `RTPROT_BGP` with the exact persisted next-hop
  before replacing or removing it. Rows that fail those checks remain
  foreign, so recovery no longer depends on protocol-only adoption.

- **ADR-0061 FIB drift hardening.** Live reconciles now distinguish rows
  rustbgpd previously owned but another writer changed. These rows surface as
  `owned_route_drifted`, increment
  `bgp_fib_routes_rejected_total{reason="owned_route_drifted"}`, release
  daemon ownership, and are preserved on later withdraws.

- **ADR-0062 TCP-AO foundation.** The transport crate now has an internal
  Linux TCP-AO socket primitive and capability probe around
  `TCP_AO_ADD_KEY` / `TCP_AO_INFO`, with UAPI layout and encoding tests.
  `GlobalService.GetGlobal` and `rustbgpctl global` now surface the host
  TCP-AO capability probe status so operators can verify kernel readiness
  before TCP-AO config/session wiring lands. TCP-AO neighbor configuration
  remains deferred.
  Runtime operator configuration and BGP session wiring remain deferred until
  the inbound listener and outbound connect paths can install keys before TCP
  OPEN.

### Changed

- `rustbgpd-wire` bumped 0.9.1 → 0.9.2 (non-breaking, additive). Adds
  `FlowSpecRule::validate_encoded_len`, `FlowSpecRule::encoded_len`,
  and the `MAX_FLOWSPEC_NLRI_RULE_LEN` constant (4095 bytes) so callers
  can reject rules that would overflow RFC 8955's 12-bit rule-length
  field before they reach outbound encode.

- EVPN Type 4 ES routes now honor ES-Import RT at the local
  DF-election projection boundary. The segment orchestrator ignores
  remote Type 4 candidates whose ES-Import RT is missing or does not
  match the configured ESI, while `QueryEvpnRoutes`, `ListEvpnRoutes`,
  and route-reflector reflection keep exposing the complete EVPN
  Loc-RIB.

- EVPN planning and operator docs now reflect the post-v0.21 state:
  Gate 7c sub-second mobility is no longer listed as a known issue,
  Gate 8b MAC-churn is recorded as passed, M36/M37/M37+IP/M38 now run
  in protected self-hosted CI, and remaining EVPN work is tracked
  through concrete GitHub issues for optional ES-Import RT filtering,
  duplicate-MAC quarantine, runtime `[[evpn_instances]]` mutation
  semantics, and the M37 local-origination churn soak.

- FIB and BLACKHOLE route-event wakeups now use a resettable debounce
  deadline instead of a fixed-grid interval, so the first route event after
  an idle period waits for the full coalescing window and bursts produce one
  follow-up RIB query after the last event.

- `rustbgpd --diff` now itemizes hot-applied `[global]` flags in both
  human and JSON output. `honor_graceful_shutdown` and
  control-plane-only `honor_blackhole` edits already made the diff
  actionable; they now appear under `Reload-applied changes` /
  `reload_applied` instead of producing an actionable diff with no
  concrete changed line.

- Locally injected and withdrawn FlowSpec rules whose encoded NLRI
  payload would exceed the 4095-byte RFC 8955 rule-length limit now
  fail request validation with `InvalidArgument` instead of reaching
  outbound encode and silently wrapping the 12-bit length field.

- Runtime observability docs now include an operator-facing surface map
  distinguishing live streams, bounded route-event history, status
  snapshots, and Prometheus metrics. CLI JSON rendering for route events,
  unified BGP events, BLACKHOLE discard status, general FIB status, EVPN
  FDB nexthop groups, and IP-VRF status now has focused contract coverage.

- `RibService` prefix-length validation now rejects out-of-range values
  (`> 32` for IPv4, `> 128` for IPv6) on `ExplainAdvertisedRoute`,
  `ExplainBestPath`, and `ListRouteEvents` instead of silently clamping to
  the family maximum. Clients sending malformed `prefix_length` values now
  receive `InvalidArgument`.

- gRPC request validation and read-only listener handling are stricter:
  reserved mutating RPC placeholders now return `PermissionDenied` on
  read-only listeners, unicast RIB list/watch RPCs reject FlowSpec/EVPN
  address-family filters, `ListFlowSpecRoutes` rejects non-FlowSpec
  families, and `ListRoutesRequest` prefix filters reject missing or
  out-of-range prefix lengths instead of silently broadening or clamping.

- `clap_complete` bumped 4.6.3 → 4.6.5 (`rustbgpctl completions` builder).

### Fixed

- EVPN MAC+IP origination now withdraws correctly when Linux emits an
  `RTM_DELNEIGH` IP-neighbour notification without `NDA_LLADDR`.
  The Linux notify loop remembers the MAC from the matching `IpAdded`
  edge and uses it to synthesize the precise `IpRemoved { MAC, IP }`
  observation required to withdraw the Type 2 MAC+IP route.

- TCP transport collision handling now resolves simultaneous inbound
  collision candidates correctly (#105). Adds regression coverage for
  local-wins / equal router-id collisions, primary-idle promotion, stale
  notifications, and pending-candidate disable drain.

- General FIB shutdown and withdraw paths now use key-only deletes so
  cleanup is not pinned to stale next-hop values.

- EVPN SVI MAC originator no longer double-decrements
  `originated_local_mac_counts` on shutdown drain — the
  `drain_to_withdraws` path now relies on `withdraw_svi_mac` for the
  decrement, matching the bridge-MAC-change fix that landed earlier in
  the cycle.

## [0.21.0] — 2026-05-14

### Added

- **RFC 7999 BLACKHOLE control-plane receiver support.** The wire crate now
  exposes `COMMUNITY_BLACKHOLE` (`0xFFFF_029A`, rendered as `65535:666`) plus
  RFC 1997 well-known community constants for `NO_EXPORT`, `NO_ADVERTISE`, and
  `NO_EXPORT_SUBCONFED`. The policy parser accepts `"BLACKHOLE"` everywhere
  `match_community`, `set_community_add`, and `set_community_remove` parse
  community values. New opt-in `[global] honor_blackhole = true` appends an
  EBGP import chain-tail rule (`match BLACKHOLE → permit, add BLACKHOLE +
  NO_ADVERTISE`) and hot-applies on SIGHUP through the peer manager.

- **RFC 7999 opt-in BLACKHOLE FIB discard.** New startup-only
  `[global] install_blackhole_discard = true` starts a Linux
  `RTN_BLACKHOLE` route reconciler when paired with
  `[global] honor_blackhole = true`. The reconciler installs only
  accepted EBGP best routes that still carry `BLACKHOLE`, defaults to
  host routes only (`/32` and `/128`), preserves existing kernel routes
  by refusing overwrite, removes owned rows on withdraw and shutdown,
  and exposes status through `RibService.ListBlackholeDiscards`,
  `rustbgpctl rib blackholes`, and Prometheus install / withdraw /
  reject / kernel-failure counters. `allow_blackhole_broad_prefixes =
  true` is a separate opt-in for non-host discards.

- **RFC 7999 operator follow-through.** ADR-0060 records the
  BLACKHOLE receiver and FIB-discard decisions;
  `examples/ddos-mitigation/config.toml` now shows
  `[global] honor_blackhole = true` plus an explicit host-route-only
  import guard; M41 is a CI-gated FRR interop for BLACKHOLE receiver
  scoping plus opt-in kernel discard install / withdraw; and
  `rustbgpctl` renders `65535:666` as `BLACKHOLE` in route community
  output.

- **ADR-0061 general unicast FIB runtime actor.** Configured
  `[[fib_tables]]` now start a default-off Linux route reconciler that
  projects unicast Loc-RIB best routes into explicit non-reserved FIB
  tables, preserves foreign kernel rows, drains daemon-owned rows on
  shutdown, and exposes status through `RibService.ListFibRoutes`,
  `rustbgpctl rib fib`, and Prometheus install / withdraw / reject /
  kernel-failure counters. Empty `fib_tables` keeps the daemon
  control-plane-only.

- **ADR-0061 general FIB netns validation.** The existing privileged
  Docker netns harness now has a `fib_runtime` selector that exercises
  the default-off unicast FIB runtime against a real Linux network
  namespace. The smoke proves configured table / metric / gateway /
  `proto bgp` route programming, empty-config no-op behavior, foreign
  route preservation, withdraw cleanup, shutdown drain, and
  missing-delete idempotency.

- **ADR-0061 M42 FRR interop smoke.** New local containerlab topology
  `tests/interop/m42-fib-runtime-frr.clab.yml` validates the full
  FRR → rustbgpd RIB → opt-in general Linux FIB path. FRR advertises
  unicast routes over EBGP; rustbgpd installs the selected route into
  configured table `1000` with metric `200`, gateway `10.0.0.2`, and
  `proto bgp`; a pre-existing `proto static` row at the configured
  target key is preserved and reported as `foreign_route_exists`; FRR
  withdrawal removes the owned route; and graceful daemon shutdown
  drains an owned route while preserving the foreign row.

- **ADR-0059 FDB-NHG drift-recovery Prometheus counters.** New
  counters expose the periodic nexthop drift-recovery path without
  scraping logs: `evpn_fdb_nhg_drift_members_repaired_total`,
  `evpn_fdb_nhg_drift_groups_replaced_total`,
  `evpn_fdb_nhg_orphans_cleaned_total`, and
  `evpn_fdb_nhg_drift_disabled_total`. The Linux reconcile actor
  reports per-`DataplaneReport` deltas for member repairs, group
  re-adds / replaces, orphan cleanup, and permanent drift-disable
  latches; the daemon consumes those deltas into process-level
  Prometheus counters.

- **EVPN FDB nexthop-group operator visibility.** New
  `EvpnService.ListEvpnNexthops` gRPC RPC and
  `rustbgpctl evpn nexthops` CLI command expose the reconciler's
  owned ADR-0059 FDB-NHG state: per-VNI groups, ESI / Ethernet Tag,
  kernel group ID, per-VTEP member nexthop IDs, MAC refs, orphan
  nexthop count, pending-delete count, and drift-recovery latch state.
  The surface is read-only and backed by `DataplaneReport.fdb_nexthops`
  so operators can compare rustbgpd's view against `ip nexthop show`
  / `bridge fdb show` without scraping logs.

### Changed

- **rustbgpd-wire 0.9.0 → 0.9.1.** The wire crate exposes new RFC 1997 /
  RFC 7999 well-known community constants (`COMMUNITY_NO_EXPORT`,
  `COMMUNITY_NO_ADVERTISE`, `COMMUNITY_NO_EXPORT_SUBCONFED`,
  `COMMUNITY_BLACKHOLE`). Non-breaking — additive `pub const`s only, no
  signature or struct changes.

- **ADR-0061 FIB ownership is conservative.** Pre-existing kernel
  routes in configured `[[fib_tables]]` are treated as foreign unless
  rustbgpd has matching owned state in memory or in
  `<runtime_state_dir>/fib-owned.json`. `RTPROT_BGP` is still the
  protocol marker rustbgpd writes, but it is not ownership proof by
  itself because FRR/BIRD can use the same marker in the same table and
  metric. This avoids replacing or draining other daemons' BGP routes
  after an ungraceful restart while allowing exact-match recovery of rows
  this daemon previously installed.

- **ADR-0061 FIB runtime hardening and documentation sweep.** The
  runtime now uses the RIB manager's priority query channel for
  `QueryBestRoutes`, publishes failed status rows when a RIB query
  fails instead of serving stale installed rows, and aborts in-flight
  reconcile/apply work promptly on shutdown so the bounded drain gets
  priority. `ListFibRoutes`, `[[fib_tables]]`, M42, and the privileged
  netns harness docs now match the shipped behavior.

- **EVPN Gate 9 documentation accuracy.** Refreshed the
  `EvpnInstanceConfig.ip_vrf` schema comment and GoBGP parity row so
  they describe the shipped Type 5 origination / import and L3 FIB
  programming path instead of the earlier schema-only foundation.

- **ADR-0063 EVPN runtime instance mutation semantics.** New ADR defines
  the safe future contract for runtime `[[evpn_instances]]` mutation:
  a single command-driven EVPN coordinator, validation-first generation
  updates, and explicit drain/replay across IMET, Type 2, Type 5,
  DF/ES, and Linux owned state. The current `EvpnService` remains
  read-only and SIGHUP keeps `[[evpn_instances]]`,
  `[[evpn_ip_vrfs]]`, and `[[ethernet_segments]]` restart-required
  until that coordinator exists.

### Removed

- **`NexthopError::Ipv6Unsupported`.** The v0.20.0 compatibility
  shim is gone now that ADR-0059 slice 3.5 supports homogeneous IPv6
  alias members. `NexthopSocket::add_fdb_member` accepts IPv4 and
  IPv6 gateways; socket-layer error mapping no longer carries the
  obsolete IPv6-only branch.

## [0.20.0] — 2026-05-13

ADR-0059 slice 3.5 hardening shipped end-to-end in three follow-up
PRs after the v0.19.0 baseline: per-instance `apply_aliasing_ecmp`
off-switch (PR #91), periodic `RTM_GETNEXTHOP` drift recovery
(PR #92), and homogeneous IPv6 alias members (PR #93). Documentation
across `ROADMAP.md`, `docs/adr/0059-evpn-aliasing-fdb-nexthop-groups.md`,
and the operator-facing handbooks (`docs/OPERATIONS.md`,
`docs/DESIGN.md`, `docs/evpn-enablement.md`, `docs/evpn-alpha-soak.md`,
`docs/milestones.md`) was refreshed to reflect the shipped state.

Production-default multi-homing enforcement remains gated on a
clean Gate 8b 24h MAC-churn soak with `apply_bum_enforcement = true`
+ `apply_aliasing_ecmp = on`. The wire crate stays at 0.9.0 — no
source-level changes under `crates/wire/src/` since v0.18.0.

### Added

- **ADR-0059 slice 3.5 PR 1 — per-instance `apply_aliasing_ecmp`
  off-switch.** New `[[evpn_instances]].apply_aliasing_ecmp` bool
  on the TOML schema (default `true`). When flipped to `false` for
  a given L2VNI, multi-homed Type 2 entries on that VNI route
  through the single-dst FDB path (primary VTEP only) instead of
  programming FDB nexthop groups; other L2VNIs in the same daemon
  are unaffected. Restart-required posture matches the rest of
  `[[evpn_instances]]` — config reload pins the instance table
  back to the startup snapshot, so operators must restart the
  daemon to apply a flip. The diff layer would converge cleanly
  via the standard `FdbNhg → SingleDst` transition (`RemoveFdbNhg`
  + `AddRemoteFdb` for any previously-installed entry) if and when
  a runtime instance-mutation surface lands. `EvpnInstance::new` still
  defaults the field on; the `with_apply_aliasing_ecmp` builder
  applies the operator's choice at config-parse time, and
  `compute_diff` now takes a `&EvpnInstanceTable` parameter so the
  diff layer can consult the per-VNI bit (unknown VNIs default to
  enabled — the `InstanceProbes` readiness gate remains the real
  install/no-install boundary). Known cold-start gap: restart with
  `apply_aliasing_ecmp = false` + stale tagged FDB rows from a
  prior run leaves the orphaned rows in place until slice 3.5
  PR 2's periodic drift cycle cleans them up (≤ 60 s); documented
  in `docs/evpn-vtep-troubleshooting.md`.
- **ADR-0059 slice 3.5 PR 2 — periodic `RTM_GETNEXTHOP` drift
  recovery.** The reconcile actor now runs a steady-state safety
  net every `periodic_dump` interval (60 s production default)
  after the one-shot startup adoption completes. The drift cycle
  re-dumps tagged kernel NHIDs and heals four shapes of drift
  between rustbgpd's `GroupOwnedMap` + `OwnedSet` and the
  kernel:
  - **Missing per-VTEP members** — re-add at the same kernel ID
    via `add_nexthop_member` (no allocator churn).
  - **Missing or member-set-drifted groups** — re-add via
    `add_nexthop_group` (`NLM_F_CREATE | NLM_F_REPLACE`).
  - **Stale tagged FDB rows from a prior daemon** — emits
    `remove_fdb_nhg_row` for any kernel FDB row whose `nh_id`
    is in our tag space but neither tracked in `GroupOwnedMap`
    nor recorded in `OwnedSet`. **Closes the slice 3.5 PR 1
    cold-start gap** where flipping `apply_aliasing_ecmp =
    false` and restarting left orphan tagged rows behind.
  - **Untracked tagged NHIDs in kernel** — folded into
    `adopted_unreferenced` so the next reconcile pass routes
    them through `cleanup_unreferenced_adoptions` with the
    retention-set logic.

  All failures are non-fatal: logged + deferred. Allocator
  integrity is preserved end-to-end (allocator slots are never
  released before the kernel confirms the delete). The drift
  cycle is gated on `adoption_done = true` to avoid colliding
  with startup adoption; it shares the existing 60 s
  `periodic_dump` cadence so there is no new timer or config
  knob.
- **ADR-0059 slice 3.5 PR 3 — IPv6 FDB-NHG alias members.** The
  `rustbgpd-evpn-linux` netlink encoder now accepts homogeneous
  IPv6 alias VTEPs alongside IPv4. Multi-homed Type 2 entries
  whose primary VTEP and every alias share the IPv6 family land
  on the FDB nexthop group path (kernel programs the same
  aliasing-ECMP shape as v4), instead of falling back to single-
  dst at the primary. Mixed-family entries still degrade to
  single-dst, but projection (`crates/evpn/src/projection.rs`)
  normally drops mismatched aliases before the diff sees them.

  Wiring: `encode_add_fdb_member` now picks `nh_family = AF_INET`
  / `AF_INET6` from the gateway form; `NexthopSocket::add_fdb_member`
  no longer rejects `IpAddr::V6` at the boundary; the diff layer's
  `all_v4` predicate becomes `all_same_family` to cover the
  homogeneous-v6 case. The wire parser at
  `socket.rs#parse_dump_message` already handles 16-byte
  `NHA_GATEWAY` payloads — no changes needed.

### Deprecated

- **`NexthopError::Ipv6Unsupported` variant.** The slice-2-era
  error path is no longer produced (IPv6 is now supported); the
  variant is kept for one release as a source-compatibility shim
  and is slated for removal in v0.21.0.

## [0.19.0] — 2026-05-13

ADR-0059 EVPN aliasing dataplane ECMP via FDB nexthop groups ships
end-to-end here: multi-homed Type 2 routes program FDB nexthop
groups (`NDA_NH_ID` / `NHA_FDB`) on the receiving VTEP with proper
refcounting, atomic REPLACE on member-set drift, partial-install
rollback, snapshot-aware startup adoption, per-key-space retry
schedules, and a steady-state delete-retry queue. The M40 manual
containerlab smoke validates the end-to-end path against FRR
EVPN-MH 10.3.1 (16/16 PASS first-shot).

Also rolls up the post-v0.18.0 documentation audit (`docs:
post-slice-4 documentation audit + refresh`, PR #90) that touched
27 doc surfaces — flipped Gate 9 slice 6 and ADR-0059 from
"still ahead" to "shipped" across READMEs, ADR status headers,
crate docstrings, and operator runbooks; added missing
`[[evpn_instances]]` / `[[ethernet_segments]]` CONFIGURATION
sections; added `ListIpVrfs` / `GetIpVrf` to API.md; added M40 to
INTEROP.md; added FDB-NHG + IP-VRF `NotReady` troubleshooting.

The wire crate stays at 0.9.0 — no source-level changes under
`crates/wire/src/` since v0.18.0.

### Added

- **ADR-0059 slice 4 — M40 manual containerlab smoke against FRR
  EVPN-MH.** First end-to-end validation that rustbgpd consumes
  real FRR Type 1 EAD-per-EVI + Type 2 routes from a shared
  Ethernet Segment and programs an FDB nexthop group via
  `NDA_NH_ID` on the receiving VTEP. Gating evidence for flipping
  aliasing-ECMP from "shipped, kernel-primitive smoke green" to
  "production-default". Topology:
  `tests/interop/m40-evpn-aliasing-ecmp-frr.clab.yml` — rustbgpd
  VTEP observer ↔ 2× FRR VTEPs sharing ES1; FRR's bond-as-ES
  shape via `tests/interop/scripts/start-frr-vtep-mh.sh` (reused
  from M32). Driver
  `tests/interop/scripts/test-m40-evpn-aliasing-ecmp-frr.sh`
  injects a test MAC on pe-a's ES bond and asserts on
  `bridge fdb show` + `ip nexthop show`: the FDB row has a
  decimal `nhid N`, `ip nexthop show` lists an `id N group X/Y …
  fdb` line whose members resolve to pe-a's and pe-c's VTEP IPs,
  and a clean teardown removes all three layers in ADR-0059 §5
  invariant-2 order. Phase 2 of the driver exercises the
  drain-to-single-dst transition the projection invariant
  produces when an alias withdraws (`empty alias_vtep_ips ⇔
  alias_group_key.is_none()` — N=2 → N=1 collapses to single-dst,
  not "group with one member"). **First-shot green on the laptop
  privileged runner** (Linux 6.17 + containerlab + FRR 10.3.1):
  16/16 assertions PASS in ~17 s, with the NHIDs landing under
  the expected `NHG_TAG | n` / `VTEP_NH_TAG | n` tag scheme.
  Manual / local only; containerlab requires privileges the
  GitHub runner doesn't carry. M39-style privileged-runner CI
  gate is the next ROADMAP follow-up.

- **ADR-0059 slice 3b — FDB nexthop group reconcile actor + diff
  Pass 1b + startup adoption.** Multi-homed Type 2 routes now
  program FDB nexthop groups in the kernel (RFC 7432 §14 aliasing
  ECMP). On the encap path, traffic to a multi-homed MAC fans out
  across every observed alias VTEP. This is the first slice with
  operational behavior change in the ADR-0059 chain; slice 4
  (M40 interop against FRR) closes out the validation story.

  Wiring landed in this PR:

  - **`compute_diff` Pass 1b** emits `InstallFdbNhg` /
    `UpdateFdbNhgMembers` / `RemoveFdbNhg` based on
    `RemoteMacEntry::alias_group_key`. IPv6 alias members fall
    back to single-dst FDB (primary VTEP only) with a `warn!` per
    `(VNI, MAC)` — slice 2's `NexthopSocket` rejects v6 gateways,
    so this is graceful degradation until the v6 fixture follow-up
    lands. Six transition tests cover the owned↔desired matrix
    (SingleDst↔FdbNhg, group-key drift, N→1 drain, NotReady
    drain, IPv6 fallback).
  - **`NexthopOps` impls** on `LinuxDataplane` (delegates to slice
    2's `NexthopSocket` + slice 3a's `linux::fdb_nhg` with the
    CVE-2025-39851 inline guard) and `InMemoryDataplane` (records
    `add_nexthop_member` / `add_nexthop_group` / `del_nexthop` /
    `install_fdb_nhg_row` / `remove_fdb_nhg_row` / `dump_owned_nexthops`
    calls for unit-testing the coordinator without netlink).
  - **Reconcile actor coordinator** intercepts the three FDB-NHG
    op variants before `Dataplane::apply`, calls `NexthopOps`
    methods in ADR-0059 §5 invariant 1+2 order (install: members
    → group → FDB row; teardown: FDB row → group → members per
    refcount), and updates `GroupOwnedMap` + `NhIdAllocator`.
  - **`NexthopSocket::dump_owned`** — `RTM_GETNEXTHOP` multipart
    parser tolerating `NHA_GROUP_TYPE` / `NHA_OP_FLAGS` per
    research §1, filtering by rustbgpd tag bits + `NHA_FDB`. 7
    unit tests on the parser.
  - **Startup adoption + deferred stale cleanup**: first
    `reconcile_once` pass dumps tagged nexthops, reserves their
    IDs in the allocator (prevents fresh `NLM_F_REPLACE`
    collisions with a prior daemon's state), and tracks them in
    `adopted_unreferenced`. After the first apply phase, anything
    still unreferenced by `GroupOwnedMap` is true-stale and gets
    deleted + released. Gated to one shot via `adoption_done`.
  - **Docker-runnable netns integration test**
    (`crates/evpn-linux/tests/netns_fdb_nhg.rs`) covering install +
    `ip nexthop show` + `bridge fdb show nhid` verification +
    `dump_owned_nexthops` round-trip + idempotent del + CVE-guard
    negative path. Harness extended with `fdb_nhg` /
    `fdb_nhg_roundtrip` / `fdb_nhg_cve` selectors.

  **Operational note**: `apply_aliasing_ecmp` defaults to on; if
  this needs an off-switch, slice 3.5 can add the knob.
  Periodic `RTM_GETNEXTHOP` drift recovery (research §8 confirms
  RTNLGRP_NEIGH doesn't fire on forced NHG deletion) is also
  deferred to slice 3.5 per the ADR.

- **ADR-0059 slice 3a — FDB nexthop group state types and apply
  primitive.** Foundation infrastructure for the aliasing-ECMP
  dataplane; **zero operational behavior change** in this PR — slice
  3b wires the new surface into `compute_diff` + the reconcile actor's
  apply coordinator + startup NHID adoption + an end-to-end netns
  test. The pieces that ship here:

  - **`crates/evpn-linux/src/nh_id_alloc.rs`** —
    `NhIdAllocator` over a `[1, 0x4000]` bitmap with tag bits
    `0x3000_0000` (per-VTEP FDB nexthop) / `0x4000_0000` (FDB
    nexthop group), deliberately offset from FRR's
    `0x1000`/`0x2000` reservations so concurrent FRR + rustbgpd
    installs never collide on `NLM_F_REPLACE` (ADR-0059 §5
    invariant 6). `reserve()` API for slice 3b's startup
    adoption pass.
  - **`crates/evpn-linux/src/group_state.rs`** — `GroupOwnedMap`
    with per-group `(VNI, ESI, EthernetTag)` refcount across
    referring `(VNI, MAC)` rows, plus a per-VTEP-NH refcount
    across referring groups. `RefDelta` return value tells the
    apply coordinator when a group should be torn down on
    `RemoveFdbNhg`. ADR-0059 §7's `share_l2_nhg` knob defaults
    off, so the Linux-owned key includes VNI even though the
    portable `RemoteMacEntry::alias_group_key` from slice 1
    stays VNI-less.
  - **`crates/evpn-linux/src/linux/fdb_nhg.rs`** —
    `apply_install_fdb_nhg_row` / `apply_remove_fdb_nhg_row`
    that build bridge FDB rows with `NDA_NH_ID` (= 13, via
    `NeighbourAttribute::Other(DefaultNla)` since
    `netlink-packet-route 0.30` has no typed variant). Inline
    **CVE-2025-39851 guard** rejects any install whose target
    L2VXLAN does not have `learning_disabled == Some(true)`
    (mainline fix `6ead38147ebb`; the readiness probe is the
    upstream guard, this is belt-and-suspenders).
  - **`KernelFdbEntry::nh_id: Option<u32>`** + `linux/fdb.rs`
    parse path extracts `NDA_NH_ID` from the kernel dump.
    `merge_fdb_rows` preserves `nh_id` across the self/master
    row split so the merged entry surfaces both halves.
  - **`OwnedEntry` enum refactor** — replaced the field-soup
    pre-3a `{ last_applied_dst, last_applied_seq }` shape — which
    would have grown a third `last_applied_group_key: Option<...>`
    flag in a naïve forward-compat extension — with an explicit
    enum `OwnedEntryKind { SingleDst { dst, mobility_seq }, FdbNhg { group_key } }`.
    Invalid states like "dst set AND group_key set" are
    structurally impossible. Existing call sites use the new
    `OwnedEntry::single_dst()` constructor; FDB-NHG-aware sites
    land in slice 3b.
  - **`DataplaneOp::InstallFdbNhg` / `UpdateFdbNhgMembers` /
    `RemoveFdbNhg`** variants declared. Slice 3b will emit them
    from `compute_diff` Pass 1b and route them through the
    coordinator. In slice 3a they are explicitly **not yet
    emitted** — `compute_diff` still produces only single-dst
    ops — and `Dataplane::apply` returns
    `InvalidArgument("must use coordinator")` if one slips
    through.
  - **`NexthopOps` trait** declared on `dataplane.rs` with the
    six low-level methods the slice 3b coordinator will call
    (`add_nexthop_member`, `add_nexthop_group`, `del_nexthop`,
    `install_fdb_nhg_row`, `remove_fdb_nhg_row`,
    `dump_owned_nexthops`). `KernelNexthop` +
    `KernelNexthopKind` types for the startup-adoption dump.
    No impls yet — slice 3b lands `LinuxDataplane` +
    `InMemoryDataplane` impls.

  Test coverage: 213 lib tests passing (13 `NhIdAllocator` + 9
  `GroupOwnedMap` + 4 `fdb_nhg` CVE-guard tests + 1 merge-`nh_id`
  test + 186 pre-existing). No netns test in slice 3a; the
  end-to-end Docker-runnable test lands with slice 3b's
  coordinator.

- **ADR-0059 slice 2 — `nexthop_raw` raw-netlink module.** New
  internal `crates/evpn-linux/src/linux/nexthop_raw/` emitting
  `RTM_NEWNEXTHOP` / `RTM_DELNEXTHOP` messages with `NHA_FDB` for
  FDB nexthop groups (RFC 7432 §14 aliasing dataplane).
  `NexthopSocket::{connect, add_fdb_member, add_fdb_group, del}`
  async API over a dedicated `netlink-sys::TokioSocket` (separate
  from the primary `rtnetlink::Handle`); `&mut self` methods
  serialize request/ACK pairing at the borrow checker.
  `NexthopGroupMember::{new, with_weight}` enforces non-zero IDs
  before encoding; `add_fdb_group` validates against empty
  groups, duplicate member IDs, and ID 0. Clean-room from
  `include/uapi/linux/nexthop.h`; tested against real iproute2
  byte-fixture captures (strace decode of `ip nexthop add` /
  `ip nexthop del` in an unprivileged userns, iproute2 6.1.0 /
  kernel 6.17). IPv4 gateways only in this slice — `IpAddr::V6`
  rejected with explicit `NexthopError::Ipv6Unsupported` until a
  captured v6 fixture and matching netns test land as a
  follow-up. No diff/apply caller yet — slice 3 wires the
  reconcile actor.
- **ADR-0059 slice 1 — `RemoteMacEntry::alias_group_key` portable
  intent extension.** New `Option<(EthernetSegmentIdentifier,
  EthernetTagId)>` field on `RemoteMacEntry`, populated by the
  projection layer when the originating Type 2 carries a non-zero
  ESI and at least one EAD-per-EVI alias has been observed for
  that segment. Identifies the Ethernet Segment instance the MAC
  sits behind so subsequent ADR-0059 slices can key one FDB
  nexthop group per `(ESI, EthernetTag)` instead of re-deriving
  it at apply time. Empty `alias_vtep_ips` ⇔ `alias_group_key.is_none()`.
  Pure-logic / portable-intent change; dataplane behaviour
  unchanged.
- **`aliasing::group_members(entry: &RemoteMacEntry) -> Vec<IpAddr>`**
  helper returning the canonical FDB nexthop group membership for
  an entry — the union of `remote_vtep_ip` and `alias_vtep_ips`,
  sorted by `IpAddr` natural order and deduplicated. Backed by
  `BTreeSet` so two entries with the same member set always
  produce the same canonical group, which is what the dataplane
  will key "membership unchanged" on to avoid spurious
  `NLM_F_REPLACE` traffic. Defensive dedup covers operator-static
  or hand-rolled constructions where the primary VTEP could
  appear in `alias_vtep_ips`.
- **`evpn_ip_vrf_originated_routes{vrf}` Prometheus gauge.**
  Slice 6b's originated-route count is now exposed as a
  Prometheus gauge alongside the existing
  `evpn_ip_vrf_installed_routes` / `evpn_ip_vrf_observed_routes`
  series. Previously gRPC-only via
  `IpVrfState.originated_routes_count`. The L3 originator
  pre-populates every configured VRF at 0 on startup (so
  dashboards see the series before the first origination)
  and re-emits after every successful inject / withdraw /
  drain — same pattern as the installed-routes gauge,
  matching the gRPC field exactly. Caught during the Gate 9
  slice 6 soak setup: the soak's CSV had to use
  `observed_routes` as a proxy because no Prometheus
  series existed for `originated_routes`.

- **Gate 9 slice 6 24h Type 5 churn soak harness in-tree**
  (PR #80). `tests/soak/gate9-slice6-soak.clab.yml` + driver
  (`tests/soak/run-gate9-slice6-soak.sh`) + analyzer
  (`tests/soak/analyze-gate9-slice6-soak.py`) — the sibling
  to the existing Gate 8b BUM-state soak. Two-PE containerlab
  topology (rustbgpd PE1 ↔ FRR 10.3.1 PE2) running the
  symmetric Interface-less IRB datapath under continuous
  tenant-prefix churn (default 30 s `ip addr add` / `del`
  cycle on the PE1 tenant dummy for 24 h). Samples CSV every
  60 s: ts, elapsed, both-PE RSS, installed-routes, observed-
  routes, BGP-established, tenant-present, churn-cycles.
  Gates: PE1/PE2 RSS slope < 1 MB/h, peak RSS < 400 MB,
  `bgp_established == 1` post-warmup, `pe1_installed_routes ==
  1` post-warmup, `tenant_present` ↔ `pe1_observed_routes`
  correlation, monotone `churn_cycles`. Result for this
  release: 24h00m clean run between v0.18.0 and v0.19.0
  (`gate9-slice6-20260511T214936Z`) — peak PE1 RSS 14.3438 MB,
  steady-state slope 0.025 MB/h, 0 BGP flaps, 0 route
  oscillations. Post-mortem at
  [`docs/soaks/soak-gate9-slice6-24h-symmetric-irb.md`](docs/soaks/soak-gate9-slice6-24h-symmetric-irb.md)
  with raw artifacts pinned at
  [`docs/artifacts/soak/gate9-slice6-20260511T214936Z/`](docs/artifacts/soak/gate9-slice6-20260511T214936Z/).
  Validates the symmetric Interface-less IRB datapath that
  shipped in v0.18.0.

- **[ADR-0059](docs/adr/0059-evpn-aliasing-fdb-nexthop-groups.md)
  EVPN aliasing dataplane via FDB nexthop groups.** Design
  document for the four-slice receive-path aliasing-ECMP
  implementation (PR #83). Locks the kernel surface: FDB
  nexthop groups via `NDA_NH_ID` + `NHA_FDB`, raw-netlink
  construction because `rtnetlink 0.21` exposes no nexthop
  API. Group keyed by `(VNI, ESI, EthernetTag)` so multiple
  MACs share one group. PR #85 (`docs: ADR-0059 — correct
  rust-netlink PR #225 status and upstreaming plan`) followed
  with a status correction on the upstream rust-netlink
  nexthop-API track (PR #225 is open against rust-netlink,
  not merged; rustbgpd ships the raw-netlink primitive in
  `nexthop_raw` until that lands).

### Changed

- **EVPN projection now enforces same-address-family-per-`(ESI,
  EthernetTag)` invariant on aliasing resolution.** Mixed-family
  EAD-per-EVI observations (e.g., an IPv6 alias under an IPv4
  primary's Ethernet Segment) are treated as operator
  misconfiguration: the mismatched alias VTEP is dropped from
  `alias_vtep_ips` and a `warn!` is logged with the (VNI, MAC,
  ESI, EthernetTag, primary, dropped) tuple so the bad config
  surfaces in the daemon log. Backs ADR-0059's cross-family
  out-of-scope clause with code from day one — the dataplane
  never sees a mixed-family FDB-NHG member list.

- **Post-slice-4 documentation audit + refresh** (PR #90). 27
  documentation surfaces brought back in sync with the
  current shipped state after the v0.18.0 Gate 9 slice 6
  release + the ADR-0059 slice chain. Highlights:
  - **README** "Not yet supported" row drops aliasing
    dataplane ECMP (shipped); ADR count 58 → 59; soak
    automation note reflects both Gate 8b BUM-state and
    Gate 9 slice 6 24h harnesses landing.
  - **ROADMAP** flips slice 3b + slice 4 from "in flight" to
    shipped under the EVPN Phase 3 entry; adds M40 to the
    Interop Test Coverage section.
  - **KNOWN_ISSUES** moves the EVPN Type 2 MAC+IP origination
    (resolved in v0.16.0) and the EVPN sticky / static MAC
    anti-spoof config (resolved in v0.17.0 / ADR-0056)
    entries into the **Resolved** section.
  - **ARCHITECTURE** + **CONTRIBUTING** crate inventories
    grow `nexthop_raw` / `fdb_nhg` / `group_state` /
    `nh_id_alloc` and the `RTNLGRP_IPV4/IPV6_ROUTE` route
    observer.
  - **CONFIGURATION** gained the missing `## [[evpn_instances]]`
    and `## [[ethernet_segments]]` sections — both were
    referenced throughout but never defined. The Gate 9
    `[[evpn_ip_vrfs]]` section also lost its "Type 5
    origination + FIB programming not yet shipped" line.
  - **API.md** gained `ListIpVrfs` + `GetIpVrf` RPC docs
    (proto added them in v0.18.0; doc still listed only
    `ListEvpnInstances`).
  - **INTEROP.md** gained the M40 row alongside M39.
  - **evpn-vtep-troubleshooting.md** gained sections for FDB-NHG
    / aliasing-ECMP triage and IP-VRF `NotReady` triage — both
    shipped surfaces with no prior runbook coverage.
  - **DESIGN / OPERATIONS / USE_CASES / COMPARISON /
    gobgp-parity / milestones / RFC_NOTES / evpn-alpha-soak
    / evpn-enablement** — Gate 9 slice 6 framing flipped
    from "foundation landed" to "shipped end-to-end";
    aliasing-ECMP framing flipped from "kernel-side follow-up"
    to "shipped, M40-validated"; stale `Last updated:` /
    version stamps refreshed.
  - **ADR-0057 / 0058 / 0059** status headers updated to
    reflect shipped state.
  - **Crate-level docstrings** (transport, evpn, evpn-linux,
    wire/README) refreshed: `transport` "only crate that
    touches async I/O" narrowed to "BGP peer TCP session I/O"
    (other crates run their own async tasks); `evpn` and
    `evpn-linux` module lists + "Out of scope" blocks
    updated.
  - **docs/SECURITY.md** `CAP_NET_ADMIN` requirement section
    extended to cover the slice 6 route-multicast + ADR-0059
    nexthop programming.

### Fixed

- **ADR-0059 FDB-NHG startup adoption could delete still-live
  adopted NHIDs after install suppression.** Found in deep
  review during PR #88. After a permanent `InstallFdbNhg`
  failure, the suppression branch `continue`s out of
  `apply_plan` without joining `failed`, so the next pass's
  `failed.is_empty()` gate would let
  `cleanup_unreferenced_adoptions` delete adopted NHIDs that
  still had kernel FDB rows pointing at them. Two-layer fix:
  (1) cleanup blocks entirely when any FDB-NHG op is permanently
  suppressed (`nhg_permanent_failures` non-empty or
  `permanent_failures` contains an FDB-NHG variant);
  (2) `cleanup_unreferenced_adoptions` now takes
  `&KernelSnapshot` and builds a retention set from
  `snapshot.iter_fdb()` of every adopted NHID a kernel FDB row
  references, recursively including the members of retained
  groups. Regression-tested at the actor level via
  `fdb_nhg_adoption_retains_live_kernel_fdb_refs` and
  `fdb_nhg_perm_suppressed_install_blocks_adoption_cleanup`.

## [0.18.0] — 2026-05-11

Gate 9 symmetric Interface-less IRB ends here. v0.17.0 closed
the L2 EVPN story; v0.18.0 lights up the L3 datapath end-to-end.
The release bundles slice 6 (PR A origination + PR B import +
M39 manual smoke against FRR) and the sub-second route-event
subscription follow-up. After this release rustbgpd can stand
up symmetric IRB between two PEs, originate and import Type 5
prefixes through a transactional kernel-ownership model with
value-aware drift detection, and propagate operator
`ip addr del` to peers within ~2 s. M39 manual containerlab
smoke is 15/15 PASS against Linux 6.17 + FRR 10.3.1.

The wire crate stays at 0.9.0 — no source-level changes under
`crates/wire/src/` since v0.17.0.

### Added

- **EVPN Gate 9 slice 6 follow-up — `RTNLGRP_IPV4_ROUTE` /
  `RTNLGRP_IPV6_ROUTE` subscription for sub-second IP-VRF
  observation refresh.** The slice 6a kernel route observer
  previously refreshed only via the reconcile actor's 1-min
  periodic dump, which bounded local-originator withdraw
  latency at ~60 s. `LinuxDataplane::connect` now subscribes
  the rtnetlink socket to the IPv4 + IPv6 route multicast
  groups; `notify::classify_route` filters by table (drops the
  reserved main/local/default/unspec set), protocol (drops
  RTPROT_BGP — including our own installs — plus the
  active-routing-daemon set), and kind (RTN_UNICAST only) so
  the kernel-event channel stays quiet during system route
  churn. Surviving events fire `KernelEvent::KernelStateChanged`,
  the reconcile actor wakes inside its existing 50 ms coalesce
  window, and `dump_ip_vrf_routes` runs against the fresh
  state. Local-originator withdraw (operator `ip addr del` on
  a tenant dummy) now propagates to peers within ~1 s instead
  of up to 60 s; the M39 smoke's `wait_frr_loses_type5`
  timeout is tightened from 90 s to 15 s to catch a regression
  in the route-event wire fast. Six new classifier unit tests
  in `crates/evpn-linux/src/linux/notify.rs` plus a new
  privileged netns regression
  `linux_dataplane_route_event_wakes_within_2s` in
  `tests/netns_l3_install.rs` that validates the full
  subscribe → kernel-event channel round trip end-to-end
  against a real netns under `EVPN_LINUX_NETNS=1`.

- **EVPN Gate 9 slice 6 — symmetric Interface-less IRB
  end-to-end (PR A #77 + PR B #78).** Closes the Gate 9
  control + dataplane loop for RFC 9136 §4.4.2 symmetric
  Interface-less IRB. The previous slices unlocked the
  readiness gate; slice 6 lights up the actual datapath in
  both directions.

  **Slice 6 PR A (#77) — local Type 5 origination.** Per
  IP-VRF kernel-route dump on every reconcile pass through
  `Dataplane::dump_ip_vrf_routes` (RTM_GETROUTE over
  rtnetlink, filtered to the VRF's `table_id`). A
  conservative classifier keeps connected (`RTPROT_KERNEL`)
  and manual (`RTPROT_BOOT`, `RTPROT_STATIC`) routes and
  drops other routing daemons' routes (`RTPROT_BGP`,
  `RTPROT_ZEBRA`, `RTPROT_OSPF`, …), non-forwardable types
  (`RTN_LOCAL`, `RTN_BROADCAST`, `RTN_MULTICAST`,
  `RTN_UNREACHABLE`, `RTN_PROHIBIT`, `RTN_BLACKHOLE`,
  `RTN_THROW`), link-local / multicast prefixes, and any
  route whose output device is the IP-VRF's own L3 VXLAN
  (these are the import path's installs — looping them back
  as originations would be wrong). The daemon mirrors the
  observation set onto a `tokio::sync::watch` channel that
  the new L3 originator task subscribes to alongside the
  slice-5 readiness watch. The originator's level-triggered
  diff loop injects Type 5 routes when the IP-VRF is `Ready`
  and withdraws them on readiness loss; transient netlink
  failures preserve the last-good observation snapshot so a
  hiccup doesn't cascade into a mass withdraw. New
  `IpVrfState.originated_routes_count` field surfaced via
  gRPC + CLI; new Prometheus series for observed gauge,
  filtered counter, and origination-suppressed counter.

  **Slice 6 PR B (#78) — remote Type 5 import + L3 FIB
  programming.** The daemon subscribes to the EVPN best-path
  broadcast, runs `project_ip_prefix_routes()` on each
  refreshed RIB view (RT-keyed import, Router MAC
  enforcement, self-origination filtering), and drives the
  kernel through a transactional L3 ownership model
  (`crates/evpn-linux/src/l3_diff.rs`):
  - `L3OwnedState` tracks per `(IpVrfId, prefix)` install
    state plus shared kernel resolution rows —
    `kernel_neighbors: BTreeMap<(idx, ip), MacAddress>` and
    `kernel_fdb: BTreeMap<(idx, MacAddress), IpAddr>`. The
    diff catches both refcount changes *and* value drift, so
    a Router MAC or next-hop transition under the same
    prefix emits an atomic `.replace()` op on the kernel-side
    row rather than silently misforwarding traffic at the
    old VTEP.
  - Three netlink primitives per remote prefix: kernel IP
    route in `IpVrf.table_id` (RTPROT_BGP + RTNH_F_ONLINK,
    via `RouteAttribute::Table` for table_id ≥ 256 with
    RT_TABLE_COMPAT = 252), L3 neighbor `(dev, dst → lladdr)`
    (NUD_PERMANENT + NTF_EXT_LEARNED), L3VXLAN FDB
    `(dev, lladdr → dst)` (NTF_SELF +
    NUD_NOARP|NUD_PERMANENT + extern_learn). Family mismatch
    rejected at build time.
  - Four-phase apply ordering — route-remove → resolution-add
    (neighbor → FDB) → route-add → resolution-remove — keeps
    the kernel forwarding-safe across transitions. Routes
    referencing soon-to-be-added resolution land after the
    resolution; routes referencing soon-to-be-removed
    resolution land before the resolution goes away.
  - Router MAC conflict detection: two prefixes mapping
    `(L3VXLAN ifindex, router_mac)` to different next-hops
    drops *all* conflicting prefixes with
    `L3Drop::RouterMacConflict` rather than silently
    misforwarding to one VTEP.
  - Foreign-state preservation enforced by diffing only
    against `L3OwnedState`, never the kernel dump.
  - Shutdown drain (`reconcile::drain`) computes
    `compute_l3_diff` against empty intent so L3 ownership
    state unwinds before the actor exits.

  Validated by 11 unit tests in `l3_diff.rs` covering cold
  start, refcount, shape change, value drift (fdb_dst +
  neighbor_lladdr), Router MAC conflict, partial-success
  cleanup, failed-remove retry, NotReady drain, and
  idempotent `record_l3_success`. Two privileged netns
  integration tests at
  `crates/evpn-linux/tests/netns_l3_install.rs` (gated on
  `EVPN_LINUX_NETNS=1`) re-exec the process inside an `ip
  netns` and assert kernel `ip route show table`, `ip neigh
  show dev`, and `bridge fdb show dev` produce the expected
  rows; one test pre-loads a `proto static` foreign route
  and verifies it survives our install/withdraw cycle.

  Operator surface: `IpVrfState.installed_routes_count` in
  the gRPC `ListIpVrfs` / `GetIpVrf` responses and the
  `rustbgpctl evpn vrfs` output;
  `DataplaneReport.ip_vrf_installed_routes` for in-process
  consumers.

  **M39 manual containerlab smoke** at
  `tests/interop/m39-evpn-type5-symmetric-irb.clab.yml`
  validates the slice end-to-end against FRR 10.3.1: two
  PEs (rustbgpd 10.0.0.1 + FRR 10.0.0.2) in direct iBGP,
  both running vrf1 / L3VNI 100 with the L3VXLAN device
  enslaved directly to the VRF (no bridge — ADR-0058 §3
  Interface-less shape). Asserts BGP Established within
  30 s; Type 5 origination both directions; PE1 kernel
  route for 192.0.2.2/32 via 10.0.0.2 dev l3vxlan100 in
  table 100; PE1 neighbor row `10.0.0.2 lladdr <PE2
  router_mac> PERMANENT extern_learn`; PE1 FDB row `<PE2
  router_mac> dev l3vxlan100 dst 10.0.0.2 self
  extern_learn`; `IpVrfState.installed_routes_count == 1`;
  bidirectional `ip vrf exec vrf1 ping` over the L3VNI
  VXLAN tunnel; `ip addr del` on PE1's tenant dummy → FRR
  drops the Type 5 within 30 s. Manual only — same
  hosted-runner gap as M30b (Azure kernel lacks `vrf`
  module).

- **EVPN Gate 9 `DataplaneReport.ip_vrf_status` rows +
  `rustbgpctl evpn vrfs [NAME]` (slice 5).** Final operator-visibility
  slice in the Gate 9 readiness chain — closes the loop from
  configured `[[evpn_ip_vrfs]]` to a human-readable view of each
  IP-VRF's live readiness. New `IpVrfDataplaneStatus` row type on
  `DataplaneReport` (one row per configured IP-VRF, joining the
  resolved `IpVrfTable` with the actor's per-pass
  `probe_ip_vrfs` verdict). New gRPC `EvpnService.ListIpVrfs` /
  `EvpnService.GetIpVrf` RPCs return the full Gate 9 config
  surface (RD, RTs, VTEP IP, Router MAC, vrf/L3VXLAN device names,
  table id) plus the live readiness state — `READY` with kernel
  ifindexes, `NOT_READY` with one human-readable line per failing
  ADR-0058 §3 predicate, or `UNKNOWN` on cold start before the
  first probe pass. New `rustbgpctl evpn vrfs` lists every
  configured VRF; `rustbgpctl evpn vrfs <NAME>` fetches one VRF
  with indented not-ready reasons; both modes also accept
  `--format json`. A daemon-side broadcast subscriber maintains
  the latest snapshot for the gRPC layer so steady-state reads
  don't synchronize with the actor. The spawn gate now triggers
  on `[[evpn_instances]]` OR `[[evpn_ip_vrfs]]` so an L3-only
  deployment also gets the readiness probe path. Type 5
  origination + L3 FIB programming remain ahead (slice 6).

- **EVPN Gate 9 IpVrfTable plumbed through DataplaneIntent +
  reconcile call.** Closes the daemon-side end-to-end wiring slice:
  the daemon's `src/evpn_dataplane.rs` supervisor now publishes the
  resolved `IpVrfTable` on every `DataplaneIntent` it broadcasts,
  the reconcile actor reads it on each pass, calls
  `Dataplane::probe_ip_vrfs(&intent.ip_vrfs)`, diffs the returned
  `Vec<IpVrfStatus>` against the previous pass's snapshot, and
  emits `tracing::info!` / `warn!` log lines for readiness
  transitions (Ready ↔ NotReady, plus the failing-predicate set
  on every NotReady so operators can grep). The intent's IP-VRF
  generation advances only on semantic change so empty
  `[[evpn_ip_vrfs]]` deployments keep paying zero dataplane cost,
  and RR-only deployments still short-circuit the spawn entirely.
  No kernel mutation yet — readiness state is observable only.
  `DataplaneReport.ip_vrf_status` + `rustbgpctl evpn vrfs` land in
  the next slice; Type 5 origination + L3 FIB programming follow
  on top.

- **EVPN Gate 9 `Dataplane::probe_ip_vrfs` trait surface + Linux
  impl.** New default-implemented method on the `Dataplane` trait
  (`async fn probe_ip_vrfs(&mut self, table: &IpVrfTable) ->
  Vec<IpVrfStatus>`) returns an empty vec by default so non-Linux
  fakes and the `InMemoryDataplane` opt in only when the test
  drives readiness explicitly. `LinuxDataplane`'s impl gathers an
  `IpVrfKernelSnapshot` from the rtnetlink VRF / L3VXLAN dumps
  shipped earlier and pipes it into the pure
  `rustbgpd_evpn::ip_vrf::readiness::evaluate` helper for every
  configured `[[evpn_ip_vrfs]]` entry, returning one
  `IpVrfStatus` per entry. `InMemoryDataplane` gains a matching
  hook so unit tests can pin readiness transitions deterministically.

- **EVPN Gate 9 Linux IP-VRF + L3 VXLAN netlink dumps.** New
  `crates/evpn-linux/src/linux/ip_vrf.rs` adds two rtnetlink-backed
  dump helpers — `dump_vrf_devices` (resolves `IFLA_LINKINFO`
  kind = `"vrf"`, `IFLA_VRF_TABLE`, oper-state) and
  `dump_l3_vxlan_devices` (resolves VXLAN attributes with
  `IFLA_VXLAN_ID`, `IFLA_VXLAN_LOCAL`, master ifindex, link-layer
  address, oper-state) — and bundles them into an
  `IpVrfKernelSnapshot`. The classifier filters non-VRF / non-VXLAN
  links structurally so unrelated bridges, bonds, and physical
  netdevs never reach readiness evaluation. Errors propagate as
  the existing `KernelError` variants for consistency with the
  FDB and link-dump paths.

- **EVPN Gate 9 IP-VRF readiness probe (pure-logic).** New
  `rustbgpd_evpn::ip_vrf::readiness` module: takes a portable
  [`IpVrfKernelSnapshot`] (built by the `crates/evpn-linux`
  reconciler from rtnetlink in a follow-on slice — kernel-free in
  this layer) and an [`IpVrf`] config, returns an [`IpVrfStatus`]
  verdict against the seven readiness predicates from ADR-0058 §3:
  `vrf_device` exists + UP + `IFLA_VRF_TABLE` matches; `l3vxlan_device`
  exists + UP + `IFLA_VXLAN_ID` matches + `IFLA_VXLAN_LOCAL` matches +
  enslaved to the right master + `address` (MAC) matches the
  configured Router MAC. Every failing predicate is reported in the
  `NotReady { reasons }` vec so a future `--json` view can render
  the full list rather than the first one tripped. The probe also
  suppresses the `L3VxlanNotInVrf` complaint when the VRF
  observation itself is missing — that situation is already named
  via `VrfDeviceMissing` and synthesizing a duplicate reason with
  no useful info would just clutter operator output. 14 unit tests
  pin every variant + the suppress-duplicate behavior.

- **EVPN Gate 9 Type 5 domain helpers (pure-logic).** Two new
  modules in `rustbgpd_evpn::ip_vrf`:
  - `origination` — `originate_ip_prefix_route(&IpVrf,
    &LocalIpRoute) -> Result<OriginatedIpPrefixRoute, …>` builds the
    full RT-5 NLRI + non-MP path-attribute list for an outbound
    advertisement. Enforces ADR-0058 §2 on every emit: `label =
    L3VNI`, `gateway = 0.0.0.0/::` (Interface-less model), `ESI = 0`,
    `EthernetTag = 0`, `Origin = IGP`, empty `AS_PATH`, RT extcomms
    from `IpVrf::route_targets`, BGP Encapsulation = VXLAN, Router
    MAC extcomm = `IpVrf::router_mac`. Rejects mixed-family
    prefix/vtep_ip pairs structurally.
  - `projection` — `project_ip_prefix_routes(&IpVrfTable, …) ->
    RemoteIpPrefixTable` consumes inbound best-path Type 5 records,
    matches each route's RT extcomms against every IP-VRF's
    `route_targets`, fans the route out into every matching tenant
    (RFC 9136 §4.4.2 allows the same prefix to land in multiple
    IP-VRFs when both legitimately claim the same RT), drops routes
    that lack the RFC 9135 Router MAC extcomm, and filters
    self-originated routes whose `NEXT_HOP` matches any local
    IP-VRF's `local_vtep_ip`. Every drop is reported via
    `RemoteIpPrefixTable::drops()` with a typed reason so the
    eventual CLI can render `"prefix dropped: missing Router MAC"`
    instead of silently losing data.

  Also adds `RouteTarget::to_extended_community` /
  `from_extended_community` on the public surface — both were
  previously open-coded in one place (`src/evpn_originator.rs`); the
  Type 5 origination needs the same encoder so it's moved into the
  domain crate alongside `RouteTarget` itself.

  Pure: no I/O, no tokio, no kernel state. The daemon-side
  supervisor lands in a follow-on slice (Step 3: Linux readiness
  probe; Step 5: end-to-end wiring + M39 smoke). 20 new unit tests
  (7 origination + 11 projection + 2 route-target round-trip)
  cover happy path, family-mismatch rejection, RT match / no
  match / multi-VRF fan-out, Router MAC enforcement, self-origin
  filter, and IPv6 parity.

- **EVPN Gate 9 foundation: ADR-0058 + `[[evpn_ip_vrfs]]` config
  schema.** New top-level TOML array declares IP-VRF / L3VNI
  tenants this VTEP serves under the RFC 9136 §4.4.2 symmetric
  Interface-less IRB model (matches FRR's default). Each entry
  binds a name, L3VNI, RD, Route Targets, local VTEP IP,
  operator-supplied Router MAC, and observe-only Linux
  `vrf_device` / `l3vxlan_device` / `table_id`. `[[evpn_instances]]`
  gains an optional `ip_vrf` field that binds an L2VNI to a
  declared IP-VRF by name.

  Validation at config load: per-entry shape (name regex, VNI
  range, RD parse, RT parse, Router MAC must be unicast non-zero,
  device names non-empty, table id > 0), name + L3VNI uniqueness
  across `[[evpn_ip_vrfs]]`, L3VNI must not collide with any
  L2VNI in `[[evpn_instances]]` (the wire VNI space is shared),
  and every `[[evpn_instances]].ip_vrf` reference must resolve to
  a declared IP-VRF. Backed by `rustbgpd_evpn::ip_vrf::{IpVrf,
  IpVrfId, IpVrfTable}` — pure-logic domain object, kernel-free,
  with 10 unit tests + 7 config integration tests.

  No behavioral wiring yet — this commit only declares the
  schema and surfaces config errors at startup. Subsequent
  slices add Linux device readiness probe (Step 3), Type 5
  origination / projection helpers (Step 4), CLI visibility
  (Step 5), and end-to-end wiring + M39 interop smoke (Step 6).
  See ADR-0058 for the architecture pinned around this object,
  including the deliberate decision to not auto-derive the
  Router MAC from kernel state (§4) and the observe-only Linux
  device lifecycle contract (§3).

### Changed

- **Policy `match_local_pref_ge/le` and `match_med_ge/le` now use
  RFC 4271 implicit defaults when the attribute is absent.**
  Previously a route arriving without `LOCAL_PREF` (typically
  eBGP-received routes, where `LOCAL_PREF` doesn't go on the
  wire) silently failed any `match local-preference >= N`
  comparison, regardless of the threshold. Same for `MED`. The
  engine now substitutes RFC 4271 §5.1.4–§5.1.5 defaults — 100
  for `LOCAL_PREF`, 0 for `MED` — so a single policy reads
  identically against routes regardless of whether the attribute
  is on the wire. Matches FRR / BIRD / GoBGP behavior. Operators
  who relied on the old "absent → no match" semantics will see
  policies that previously silently passed eBGP routes now match
  them against any LP threshold ≤ 100; if that's a behavioral
  change you need to roll back, the workaround is an explicit
  `match_route_type = "external"` guard or a separate import
  policy chain for that peer group.

### Added

- **`rustbgpctl` policy / peer-group / neighbor-set commands.**
  Three new subcommand trees that wrap the existing PolicyService
  and PeerGroupService gRPCs. `rustbgpctl policy {list|get|set|
  delete}` covers named `[[policy_definitions]]`; `rustbgpctl
  policy chain {show|set-import|set-export|clear-import|
  clear-export} [--neighbor ADDR]` covers the global / per-neighbor
  import/export chains. `rustbgpctl neighbor-set {list|get|set|
  delete}` covers `[[neighbor_sets]]`. `rustbgpctl peer-group
  {list|get|set|delete|attach|detach}` covers `[[peer_groups]]`
  and binds neighbors to / from a group. `set` accepts a JSON file
  via `--from-file PATH` whose shape mirrors the proto messages —
  `serde(deny_unknown_fields)` rejects typos at parse time. Empty
  `chain set-{import,export}` is rejected at the CLI layer with a
  pointer at the matching `clear-*` command. Operators no longer
  need TOML + SIGHUP for these surfaces. 24 new mock-server tests
  pin the entire dispatch path; 5 new clap parse tests pin the
  CLI surface.

- **`bgp_fsm_stale_timer_events_total{peer, state, timer}`
  Prometheus counter.** Emitted whenever the FSM receives a
  timer-expired event in a state where the corresponding timer
  should not be running per RFC 4271 §8.1's per-state event tables
  (e.g. `KeepaliveTimerExpires` in Connect, `ConnectRetryTimerExpires`
  in Established). Operators can graph it against zero; non-zero
  identifies the specific (state, timer) pair, which points at the
  daemon-side timer-management bug rather than a peer or wire issue.

- **Add-Path send-view in ExplainBestPath.** `rustbgpctl rib
  --prefix X --explain --explain-peer P` now scopes the explain
  to peer P's actual send view: candidates are filtered by the
  peer's resolved export policy + sendable families and the top
  `add_path_send_max` are tagged with their advertised rank. The
  CLI prints an extra `Adv-PathID` column showing rank or
  `(filtered)` for each candidate. Empty `--explain-peer`
  preserves the v0.7.0 global-view shape exactly. Proto fields
  added to `ExplainBestPathRequest` (`peer_address`),
  `BestPathCandidate` (`advertised_path_id`), and
  `ExplainBestPathResponse` (`peer_address`,
  `add_path_send_max`) — all additive, so old clients keep
  working. `add_path_send_max` in the response reflects the
  *effective* cap (zero when the prefix's AFI/SAFI isn't
  sendable to the peer or isn't in the peer's
  `add_path_send_families`), not the bare config knob.

### Fixed

- **FSM stale timer events no longer tear sessions down.** Timer
  events that arrive in a state where the corresponding timer
  should not be running per RFC 4271 §8.1 (e.g. a stale
  `ConnectRetryTimerExpires` after Established) used to fall
  through the catch-all and trigger an FSM Error NOTIFICATION,
  converting a daemon-side timer-management bug (a tick that
  wasn't cancelled when the FSM left the originating state) into
  a real-world reachability outage. None of FRR/BIRD/GoBGP behave
  this way; their FSMs treat stale ticks as benign. The FSM now
  has explicit match arms for all 11 stale-timer (state, timer)
  pairs across the six states; each emits a new
  `Action::StaleTimerIgnored { state, timer }` for telemetry but
  the session stays put. 11 new FSM tests pin every arm,
  including a regression test that pins
  `Established + ConnectRetry → no SessionDown`. Closes the
  ROADMAP P1 item under Operational / Observability Hardening.

- **EVPN mass-withdraw receive-side filter (RFC 7432 §8.4).**
  The dataplane supervisor now drops any Type 2 MAC route from the
  projection if its non-zero ESI doesn't have a matching
  EAD-per-ES advertisement from the same *(origin VTEP next-hop,
  ESI)*. When a PE withdraws its Type 1 EAD-per-ES route, every
  Type 2 route attributed to that origin VTEP + segment vanishes
  from the next supervisor pass (≤5s) — the canonical RFC §8.4
  fast-flip primitive, observable end-to-end without per-MAC
  `MP_UNREACH_NLRI`.
  Stateless: each `build_remote_mac_table` call snapshots the
  current EAD-per-ES set from the RIB and applies it as a
  reachability gate, so there's no event-tracking state machine
  in the supervisor. Single-homed routes (ESI=0) bypass the gate.
  +1 unit test pinning the three relevant cases (no-EAD-per-ES
  drops; matching EAD-per-ES allows; the same ESI from a different
  origin VTEP doesn't satisfy the gate).

- **EVPN aliasing receive-side wiring (RFC 7432 §14).** The
  projection layer now resolves aliasing alternatives for Type 2
  MAC routes whose ESI is non-zero, populating each
  `RemoteMacEntry::alias_vtep_ips` with the additional VTEPs that
  advertise EAD-per-EVI routes for the same `(ESI, EthernetTag)`.
  - `RemoteMacEntry` gains an `alias_vtep_ips: Vec<IpAddr>` field
    (default empty). The dataplane consumes it as the input for
    future ECMP forwarding work; today's `LinuxDataplane` ignores
    the field, so this slice is observable in
    `DataplaneIntent::remote_macs` but not yet in the kernel.
  - `ProjectedEvpnRoute` gains `esi` + `ethernet_tag` fields
    sourced from the Type 2 NLRI. The supervisor in
    `src/evpn_dataplane.rs` plumbs these through from the RIB.
  - New `ProjectedEvpnEadPerEvi` input type and
    `project_evpn_routes_with_aliases` function: builds an
    `AliasIndex` from the EAD-per-EVI feed once, then resolves
    alternatives for every Type 2 in one pass. The
    `project_evpn_routes` legacy wrapper still exists for callers
    without an EAD-per-EVI feed and yields empty alias lists.
  - Self-originated EAD-per-EVI routes are filtered at the
    daemon-side projection by checking next-hop against the
    union of local VTEP IPs from `EvpnInstanceTable`.
  - +5 unit tests covering: empty aliases for ESI=0 routes,
    populated aliases for non-zero ESI, primary deduplication,
    `(ESI, EthernetTag)`-keyed lookups, and the legacy wrapper's
    empty-aliases contract.

- **EVPN Gate 8b — four remaining feature slices.** Pure-logic
  modules + plumbing that complete the architectural surface for
  multi-homing. Each slice composes onto the Gate 8b enforcement
  base shipped earlier; together they retire all five remaining
  Gate 8b "concrete slices" tracked in `docs/evpn-alpha-soak.md`
  except the 24h soak validation.
  - **Per-ESI label allocator** (`crates/evpn/src/label_allocator.rs`).
    `EsiLabelAllocator` with stable `(ESI -> label)` assignments,
    a free list for released labels, and a synth-first strategy
    so operators upgrading from Gate 8b prep observe no label
    change unless they hit a real collision. Replaces the
    deterministic `synthesize_esi_label` in `src/evpn_segment.rs`
    that was vulnerable to bytes-[4..7] collisions across ESIs
    chosen by independent operators. The synth itself stays
    exposed (`synthesize_from_esi`) for tests / offline tooling.
    +10 unit tests; orchestrator now caches the allocated label
    on `SegmentState.esi_label` and threads it through
    `build_es_route` so the EAD-per-ES NLRI's MPLS label field
    and the ESI Label extcomm always agree.
  - **DF-role-aware (ESI-aware) MAC origination.** When a local
    MAC is learned on a VNI that participates in a configured
    `[[ethernet_segments]]` block, the originated Type 2 NLRI now
    carries the segment's ESI rather than the all-zero
    single-homed sentinel. Plumbed via a new
    `Arc<BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>>` lookup
    threaded through the originator (`src/evpn_originator.rs`)
    and built once at startup from `config.resolve_ethernet_segments()`.
    SVI MAC origination remains ESI=0 (it's the L3 next-hop, not
    a CE-side MAC — matches FRR / Cumulus). +1 unit test in
    `evpn_originator::tests`.
  - **Aliasing resolver** (`crates/evpn/src/aliasing.rs`).
    Pure-logic `AliasIndex` keyed on `(ESI, EthernetTagId)`,
    built from EAD-per-EVI advertisements, exposing a
    `vtep_ips_for(esi, eth_tag)` lookup for the projection /
    dataplane wiring slices that follow. Includes
    `alias_resolved_next_hops` convenience for the upcoming
    `RemoteMacEntry::alias_vtep_ips` field. Filters single-homed
    (ESI=0) advertisements and dedupes `(ESI, EthTag, VTEP)`
    triples. +9 unit tests. The actual ECMP-to-multiple-VTEPs
    forwarding is a follow-up (`LinuxDataplane` programs one
    `dst` per MAC today; multi-VTEP needs `nexthop` group or
    L3-route-based ECMP).
  - **Per-`(origin VTEP, ESI)` EAD-per-ES event tracker for receiver-side
    mass-withdraw** (`crates/evpn/src/mass_withdraw.rs`). RFC 7432
    §8.4 names the EAD-per-ES *withdrawal* as the standard
    fast-convergence signal — when an origin VTEP withdraws its
    Type 1 EAD-per-ES route for an ESI, every receiver sweeps
    every MAC route attributed to that `(origin VTEP, ESI)`
    pairing in one operation. Pure-logic `AsPathTracker` exposes:
    - `record_withdrawal` — canonical RFC 7432 §8.4 trigger.
      Returns `Some(MassWithdrawTrigger)` when there was prior
      state for `(origin VTEP, ESI)` to sweep; `None` for unseen
      pairs (no phantom RIB sweep).
    - `drop_origin_vtep` — direct-peer teardown or origin-VTEP
      disappearance. Returns one trigger per ESI the origin VTEP
      was tracking.
    - `record_advertisement` (optional) — vendor-interop
      heuristic adopted by FRR / Cumulus / Junos: if the origin
      VTEP's EAD-per-ES `AS_PATH` changes between two
      advertisements without an explicit Withdraw between them,
      treat it as mass-withdraw. Not in the RFC, documented as a
      heuristic.
    `AsPathFingerprint::from_as_path` hashes segment type +
    segment length + ASN bytes per `AsPathSegment`, so re-
    segmentation by an upstream peer (e.g. `[1,2]` becoming
    `[1] [2]`, or `AsSequence` becoming `AsSet`) produces
    distinct fingerprints. FNV-1a backs the hash; a
    `from_asns` flat helper stays for tests / single-segment
    callers but is documented as fidelity-lossy. +13 unit tests.
    The RIB-side sweep that consumes triggers is the next slice.

- **EVPN Gate 8b multi-homing enforcement — end-to-end wired,
  opt-in by config.** Closes the loop from DF election to kernel
  split-horizon enforcement, gated by a default-`false` config
  flag so existing observe-only deployments are unchanged.
  - **Kernel primitive proven**: privileged netns spike at
    `crates/evpn-linux/tests/scripts/netns-bum-filter-spike.sh`
    validates that the per-port `bridge link set ... flood off
    mcast_flood off bcast_flood off` triplet on the CE-facing
    bridge port is the right kernel hammer for split-horizon.
    Five load-bearing invariants hold: DF allows, Non-DF blocks
    broadcast / multicast / unknown-unicast, **known-unicast
    forwarding survives Non-DF**, the toggle is symmetric, and
    `extern_learn` FDB add/del succeed regardless of mode.
  - **Pure-logic mapping** in `crates/evpn-linux/src/bum_filter.rs`
    turns `BumEnforcementStatus` rows into a flat
    `Vec<BumPortFlagPlan>` (ifindex + per-port flag triplet) with
    most-restrictive-wins on ifindex collisions and
    auto-restoration of disappeared previously-suppressed ports
    to `allow_all`. `diff_flag_plans` makes the apply path
    idempotent at the netlink boundary.
  - **New `DataplaneOp` variant `SetBumPortFlags { ifindex, flags }`**
    routes through the same trait the FDB ops use.
    `InMemoryDataplane` records each call by ifindex for
    assertion (`InMemoryHandle::bum_port_flags()`); the BUM op
    path uses its own retry / permanent-failure schedule keyed by
    ifindex (separate from the FDB `(VNI, MAC)` schedule), so no
    sentinel-VNI collision risk exists.
  - **Linux netlink apply** in
    `crates/evpn-linux/src/linux/bum_filter.rs` issues a single
    `RTM_NEWLINK` (sent through `rtnetlink::LinkHandle::set_port`)
    carrying `IFLA_LINKINFO` with `IFLA_INFO_PORT_KIND = "bridge"`
    and `IFLA_INFO_PORT_DATA` holding the
    `IFLA_BRPORT_UNICAST_FLOOD` / `IFLA_BRPORT_MCAST_FLOOD` /
    `IFLA_BRPORT_BCAST_FLOOD` triplet. Errors map to
    `KernelTooOld` (`EOPNOTSUPP`), `PermissionDenied`
    (`EPERM` / `EACCES`), `LinkNotFound` (`ENODEV`),
    `InvalidArgument` (caller-side guard), or `Other`
    (catch-all the actor's backoff retries).
  - **Reconciler-side emission**: the actor computes a fresh
    `BumPortFlagPlan` each pass, diffs against the last-applied
    plan, and emits `DataplaneOp::SetBumPortFlags` ops for changed
    entries through the same `apply_plan` loop the FDB ops use.
    Per-port `last_bum_plan` updates only for ifindexes whose op
    succeeded — failed ports keep their prior recorded state so
    the next reconcile pass re-emits the op (the apply-side
    retry/backoff governs the cadence).
  - **Operator-facing config** `apply_bum_enforcement: bool` on
    `Config` (default `false`). Plumbed into the supervisor's
    `ReconcileActorConfig`. With the flag off, the resolved
    enforcement plan is still surfaced via
    `DataplaneReport.bum_enforcement` for operator visibility,
    but no kernel mutation occurs.
  - **Gated integration tests**: shell-driven netns spike
    (`bum_filter_spike_validates_kernel_primitive`) and Rust
    netlink round-trip (`linux_dataplane_set_bum_port_flags_
    round_trip`) both run under `EVPN_LINUX_NETNS=1` +
    `CAP_NET_ADMIN` + Linux >= 4.18. Hosted PR-CI skips them
    cleanly. Two actor-level integration tests pin the emit /
    no-emit toggle behavior. +17 unit + integration tests.
  - **Docker harness** at `crates/evpn-linux/tests/docker/`
    (`Dockerfile` + `run-netns-tests.sh` + `README.md`) runs the
    privileged tests inside a container so contributors don't
    need iproute2 / iputils-ping / sudo on the host. One-command
    invocation: `bash crates/evpn-linux/tests/docker/run-netns-tests.sh`.
    Validated single-pass against host kernel 6.17 (Ubuntu 24.04,
    Docker 29.2.1): spike + round-trip both green, confirming the
    `RTM_NEWLINK + IFLA_LINKINFO + IFLA_INFO_PORT_DATA +
    IFLA_BRPORT_*_FLOOD` netlink-attribute encoding actually lands
    the desired flag triplet on the kernel-side bridge port.
- **EVPN Gate 8b enforcement intent foundation — observable BUM
  plan, no kernel mutation yet.** The daemon now feeds DF-election
  role state into the EVPN Linux dataplane supervisor as a portable
  `BumEnforcementTable` keyed by `(ESI, VNI)`. The reconciler
  resolves each row against current link inventory and emits
  `DataplaneReport.bum_enforcement` rows with bridge name, VXLAN
  ifindex, CE-facing port ifindexes, DF role, and desired action
  (`allow` for DF, `suppress` for Non-DF). This tees up Gate 8b's
  actual split-horizon kernel primitive while staying observable-only
  and preserving all existing remote-FDB behavior.
- **EVPN Gate 8b prep — ES-Import RT + ESI Label extcomms on
  Type 1/4 origination.** Closes the two control-plane gaps ADR-0057
  flagged from Gate 8:
  - **Type 4 ES route** now carries the auto-derived ES-Import RT
    extcomm (RFC 7432 §7.6) — high-order 6 octets of the ESI Value
    (bytes [1..7] of the 10-byte ESI). Peers that filter Type 4
    imports on this RT can correlate the segment without
    preconfiguration.
  - **Type 1 EAD-per-ES route** now carries the ESI Label extcomm
    (RFC 7432 §7.5) with the synthesized label and
    `single_active = false` (all-active default). Peers can now
    wire the label into their split-horizon filter tables; the
    dataplane-side drops on non-DF receivers remain Gate 8b proper.
  - **Type 1 EAD-per-EVI** stays unchanged — per RFC 7432 §14 it
    carries no ESI Label (the per-EVI label lives in the route's
    own MPLS label field). Aliasing extcomms remain Gate 8b
    territory.
  - The wire codec already supported both extcomms
    (`ExtendedCommunity::es_import_rt` / `::esi_label`); the change
    is purely on the origination side. No wire bump.
  - `M38` driver now scrapes `ListEvpnRoutes` via gRPC on each PE
    and asserts the new extcomms appear on both Type 4 and
    Type 1 EAD-per-ES routes. M38 PE configs gain the gRPC TCP
    listener on `:50051` to support the assertion.
  - ADR-0057 updated: ES-Import RT + ESI Label origination moved
    from "deferred to Gate 8b" to "closed in Gate 8b prep
    follow-up."
- **EVPN multi-homing foundation — observable DF election (Gate 8,
  ADR-0057).** First half of EVPN multi-homing: control-plane
  election + Type 1/4 origination + Prometheus visibility. Gate 8b
  follow-ups in this release window add opt-in split-horizon/BUM
  enforcement, ESI Label / ES-Import RT origination, aliasing
  projection, and receive-side mass-withdraw filtering; remaining
  gaps are called out in `docs/evpn-alpha-soak.md`.
  - **Domain types** — new `crates/evpn/src/segment.rs` ships
    `EthernetSegment` (ESI, member VNIs, DF preference, algorithm,
    originator IP), `DfAlgorithm` (`DefaultModulo`,
    `HighestRandomWeight`, `HighestPreference`, `LowestPreference`),
    and `DfRole`.
  - **Pure DF election state machine** in
    `crates/evpn/src/df_election.rs`. `DfElection::run` takes the
    candidate set + the local PE's originator IP and returns
    `BTreeMap<EvpnInstanceId, DfRole>`. Implements RFC 7432 §8.5
    service carving (sort candidates by originator IP ascending;
    candidate at slot `vni mod n` is DF) and RFC 8584 §3 algorithm
    negotiation (algorithm disagreement falls back to default service
    carving; `DefaultModulo` is the universal floor).
  - **Three Type 1/4 origination state machines** in
    `crates/evpn/src/origination_es.rs`. `LocalEsOriginator`
    (Type 4 ES), `LocalEadPerEsOriginator` (Type 1 EAD-per-ES with
    MAX_ET marker), `LocalEadPerEviOriginator` (Type 1 EAD-per-EVI,
    role-aware via `on_vni_role_changed`). Same deterministic
    `(state, event) → action` pattern as the Gate 7b+1
    `LocalMacOriginator` — pure, callable from a unit test.
  - **Daemon orchestrator** in `src/evpn_segment.rs`. One tokio
    task per `[[ethernet_segments]]` block, subscribed to the
    EVPN best-path broadcast (Gate 7c). On every Type 4 event for
    a tracked ESI, re-gathers candidates from the RIB, re-runs
    election, fires per-VNI `on_vni_role_changed` for any flipped
    slot, and updates Prometheus. Shutdown drains all per-ESI
    Type 1/4 routes before peer sessions tear down.
  - **Config schema** — `[[ethernet_segments]]` TOML block with
    `esi`, `member_vnis`, `df_preference`, `df_algorithm`,
    `originator_ip`. ESI parser rejects the Type 0 single-homed
    sentinel, requires a non-empty member-VNI list, validates that
    every member VNI maps to a configured EVPN instance, and accepts
    only `df_algorithm = "default-modulo"` plus the default
    `df_preference = 32768` until non-default algorithms are implemented.
  - **Observable surface** — `evpn_df_role{esi,vni,role}` gauge
    (PromQL `evpn_df_role{role="df"} == 1` finds active DFs) and
    `evpn_df_role_changes_total{esi,vni}` counter for spotting
    flap loops.
  - **M38 interop smoke** — new
    `tests/interop/m38-evpn-df-election.clab.yml` 2-PE rustbgpd
    topology with shared ESI for VNI 100. Asserts PE1 (lower IP)
    elected DF, PE2 elected NonDF, PE2 promotes after PE1
    shutdown, transition counter advances.
  - **Operator note**: `[[ethernet_segments]]` is now useful for
    controlled multi-homing trials, but `apply_bum_enforcement`
    remains default-`false` until the 24 h churn soak closes. Gate 8
    remains correct for observing election behavior without enabling
    kernel enforcement.

## [0.17.0] — 2026-05-09

EVPN VTEP polish on top of v0.16.0. Five operator-facing slices:
Gate 7c sub-second mobility convergence (RIB push notifications
replacing the 5 s poll), `sticky_macs` operator config (ADR-0056)
for RFC 7432 §15.4 sticky-bit origination, `advertise_svi_mac`
consumption (originates the bridge's own MAC on instance-Ready),
Gate 7b+2 MAC-with-IP origination via ARP/ND suppression under
the FRR replace model, and a coordinated bump of the netlink
ecosystem (`rtnetlink 0.21`, `netlink-packet-route 0.30`,
`netlink-packet-core 0.8`). The wire crate stays at 0.9.0
(unchanged source).

### Added

- **MAC-with-IP Type 2 origination via ARP/ND suppression
  (Gate 7b+2 — alpha supported, three slices).** The
  `advertise_svi_mac` flag and `sticky_macs` config (already
  shipped) handled the MAC-only path; this closes the long-deferred
  MAC+IP path. RFC 7432 §7.2 permits a Type 2 NLRI to carry an IP
  alongside the MAC; RFC 9135 §7.2.3 frames MAC-only as
  *supplementary*, and FRR's actual operator-facing behavior is
  the **replace model** — at any time at most one of `{MAC-only,
  MAC+IP}` is advertising for a given MAC. The daemon mirrors that:
  an `IpAdded` event withdraws the MAC-only route and emits a
  MAC+IP route in its place; the last `IpRemoved` for a MAC
  downgrades back to MAC-only.

  **Operator prerequisite**: the bridge must have
  `bridge link set dev vxlan<vni> neigh_suppress on` per VXLAN
  port — that's what makes the kernel snoop ARP/ND traffic into
  the bridge's neighbour table and emit
  `AF_INET` / `AF_INET6` `RTM_NEWNEIGH` messages on the bridge
  ifindex. Without it, no `IpAdded` events reach the daemon and
  only MAC-only Type 2s get advertised. See
  `docs/evpn-vtep-troubleshooting.md` for verification steps.

  Implementation:
  - **Wire layer** (slice 1): the existing `RTNLGRP_NEIGH`
    classifier now splits the message stream by family. `AF_BRIDGE`
    drives MAC-only as before; `AF_INET` / `AF_INET6` on bridge
    ifindexes drives the new `LocalMacObservation::{IpAdded,
    IpRemoved}` variants. Validity gate drops `NUD_INCOMPLETE` /
    `NUD_DELAY` / `NUD_PROBE` / `NUD_FAILED` (including combined
    bitmasks like `NUD_STALE | NUD_PROBE`) so kernel re-probe
    thrash never reaches origination. Address-shape filter rejects
    unspecified, multicast, broadcast, IPv4 link-local (APIPA),
    IPv6 link-local (`fe80::/10`), and loopback bindings on both
    add and remove edges. Path:
    `crates/evpn-linux/src/linux/notify.rs`,
    `crates/evpn/src/mac.rs`.
  - **State machine** (slice 2): `LocalMacIpOriginator` parallels
    `LocalMacOriginator` but keyed on `(MAC, IP)` with independent
    RFC 7432 §15.1 mobility ratchets per RFC 9135 §7.2.3
    coexistence. New `on_local_mac_aged(mac)` cascade hook
    withdraws every `(MAC, *)` IP route at once. Diverges from
    MAC-only on sticky-bit changes — re-emits at the same
    sequence rather than bumping, since for MAC+IP the sticky bit
    is closer to an ARP/ND-suppression hint than a mobility
    signal. Path: `crates/evpn/src/origination_macip.rs`.
  - **Daemon correlation** (slice 3): `OriginatorState` bundles
    the per-VNI MAC + MAC+IP originators, a `local_macs` cache
    (with retained ifindex for downgrade replay), pending IP
    bindings (handles cold-start ordering between `AF_BRIDGE` and
    `AF_INET[6]` feeds), and a live `(MAC, IP)` cache. RIB
    projection extended to build both `RemoteMacViewMap` and
    `RemoteMacIpViewMap` from one `QueryEvpnRoutes` snapshot;
    `repoll_rib` diffs both. Shutdown drains MAC+IP first, then
    MAC-only. Path: `src/evpn_originator.rs`.

  Tested end-to-end against FRR via the new M37+IP containerlab
  smoke (`tests/interop/m37-evpn-mac-ip-origination.clab.yml`,
  operator-run / privileged); 28 unit tests in
  `src/evpn_originator.rs#tests` cover the replace flow, the
  cold-start ordering edge, the downgrade path, sticky pass-
  through, and the MAC-aged cascade.
  (The earlier `[Unreleased]` entries that announced the slice 1
  wire-layer and slice 2 state-machine in isolation are now
  superseded by this aggregate; their text described the work as
  "daemon no-ops, slice 2/3 will wire" which no longer reflects
  the shipped behavior.)

### Fixed

- **Gate 7c: events used as wakeup, not as projection deltas.** The
  original handler computed `RemoteMacView` directly from one event's
  `best` field and applied it as a delta to the
  `(VNI, MAC)`-keyed `remote_view` cache. That doesn't match the
  RIB ↔ projection model: `EvpnRouteEvent` is keyed by full
  `EvpnRouteKey` (with RD), but `crates/evpn::project_evpn_routes`
  picks the per-`(VNI, MAC)` winner across **all** RDs by mobility
  sequence + next-hop (RFC 7432 §15.1, §7.9.5). Two failure modes
  the original code silently hit:
  - Lower-seq Added under a different RD overwriting a higher-seq
    winner with the worse candidate.
  - A non-winning Withdrawn clearing the cache while a winning RD
    still existed in the RIB.
  Fix: the event is now used purely as a wakeup signal — any Type 2
  event triggers a full `repoll_rib`, which re-runs the projection
  from scratch via `build_remote_view` → `project_evpn_routes`.
  Sub-second wakeup is preserved; the projection is now correct
  under multi-RD contention. Two regression tests pin the failure
  modes; an additional test verifies non-Type-2 events do not
  trigger a repoll.
- **EVPN Withdrawn events now reliably clear the originator's
  `remote_view`.** The earlier per-event delta path tried to recover
  VNI for `Withdrawn` events by scanning local `EvpnInstance.rd`
  against the route key's RD; that's wrong because RFC 7432 §7.9.5
  lets each PE pick its own RD, so a remote-imported Type 2 carries
  the **remote**'s RD, which won't match any local instance.
  `EvpnRouteEvent` now carries `previous_best: Option<EvpnRibRoute>`
  alongside `best`, populated from the prior Loc-RIB state captured
  before `recompute_evpn`. (Under the wakeup-only model above, the
  originator no longer reads `previous_best` directly — the field
  remains on the event for other consumers, e.g. BMP-style
  observers, who want the prior next-hop without a back-channel
  query.)
- **SVI-MAC origination honors `sticky_macs`.** Per ADR-0056, an
  operator listing the bridge MAC in `[[evpn_instances]].sticky_macs`
  expected the originated SVI Type 2 to carry the RFC 7432 §15.4
  sticky bit. The previous wiring hardcoded `false`. Fix: SVI
  origination now consults `inst.sticky_macs.contains(&mac)` on
  Inject.

### Changed

- Documentation pass for the three follow-on slices in
  `[Unreleased]`: README maturity row + Rust 1.92 MSRV references
  (badge, install prereqs, runtime row), `docs/DESIGN.md` Phase 2
  description, `docs/evpn-enablement.md` follow-up table,
  `docs/RFC_NOTES.md` deferred list, `docs/milestones.md` Phase 2
  status, `docs/evpn-alpha-soak.md` checklist, and the
  `examples/evpn-vtep-leaf/config.toml` field comments — all
  updated so they no longer describe these features as deferred.

### Added

- **EVPN SVI-MAC origination (RFC 9135 §6.1).** The
  `advertise_svi_mac = true` flag on `[[evpn_instances]]` was
  previously parsed but inert; it now drives Type 2 origination of
  the bridge's own MAC address. The Linux dataplane captures bridge
  link-layer addresses during link inventory, surfaces them on
  `InstanceDataplaneStatus.bridge_mac` (rather than reaching back
  into the dataplane's `LinkCache`, which would break ADR-0054 §1),
  and the daemon's new SVI task subscribes to the
  `DataplaneReport` broadcast to originate / withdraw on
  `Ready` ↔ `NotReady` transitions and on bridge MAC changes.
  `OriginatedLocalMacCounts` participates so
  `originated_local_macs_count` accounts for SVI MACs alongside
  kernel-learned ones. Path: `crates/evpn/src/dataplane.rs`,
  `crates/evpn-linux/src/{linux/links,linux/probe,reconcile}.rs`,
  `crates/evpn-linux/src/snapshot.rs`, `src/evpn_dataplane.rs`,
  `src/evpn_svi.rs`, `src/main.rs`.
- **`DataplaneReport` mpsc → broadcast refactor.** The reconcile
  actor still emits reports through its bounded mpsc, but the
  daemon-side glue now forwards each report to a
  `broadcast::Sender<DataplaneReport>` so multiple subscribers
  (existing log-only consumer; new SVI task; future BMP exporter
  / dashboards) can react in parallel without contending. Backstop
  for late subscribers: the actor re-emits a fresh
  `instance_status` row on every reconcile pass, so a fresh
  subscriber converges on the next pass without missed state.
- **EVPN sticky-MAC operator config (ADR-0056 — RFC 7432 §15.4).**
  New `sticky_macs` field on `[[evpn_instances]]` entries — a list
  of MAC addresses (`aa:bb:cc:dd:ee:ff` form) that, when learned by
  the local kernel, are originated as Type 2 routes with the MAC
  Mobility extended community's sticky bit set. **Not** a static FDB:
  rustbgpd does not synthesize routes for these MACs, it only marks
  them on origination. Empty by default. Restart-required (changes
  surface as `evpn_instances_changed` in `rustbgpd --diff`). Path:
  `src/config/schema.rs`, `src/config/mod.rs`,
  `crates/evpn/src/instance.rs`, `src/evpn_originator.rs`,
  `examples/evpn-vtep-leaf/config.toml`, ADR-0056.
- **EVPN best-path push notifications (Gate 7c — sub-second mobility
  convergence).** New `EvpnRouteEvent` broadcast in `crates/rib`,
  keyed by `EvpnRouteKey` and carrying the full `Option<EvpnRibRoute>`
  best path so subscribers can build `RemoteMacView`s without a
  follow-up `QueryEvpnRoutes` round-trip. The daemon's local-MAC
  originator subscribes at startup and reacts to each best-path
  change synchronously; the existing 5 s `QueryEvpnRoutes` poll is
  retained as a backstop for `Lagged` subscribers and for cold-start
  cache population (the broadcast is edge-triggered and does not
  replay history). Path: `crates/rib/src/event.rs`,
  `crates/rib/src/manager/distribution.rs`,
  `crates/rib/src/manager/mod.rs`, `crates/rib/src/update.rs`,
  `src/evpn_originator.rs`.

## [0.16.0] — 2026-05-07

Operational polish on the v0.15.0 EVPN VTEP loop. No new feature
gates; the bidirectional VTEP path stays as it shipped. Highlights:
end-to-end Prometheus observability for the local-MAC origination
flow, gRPC + CLI diagnostic surfaces (`originated_local_macs_count`,
`evpn diagnose`), an operator runbook, a synthetic-churn soak
driver, and an MSRV bump that puts the toolchain on a 6-month-behind-
stable track (Tokio's policy) — gated in PR-CI so it doesn't drift.

### Changed

- **MSRV 1.88 → 1.92** for the workspace. The 1.88 floor was set in
  June 2025 when let-chains stabilized — picked for a feature, not an
  operator-facing constraint. 1.92 (Dec 2025) matches Tokio's
  published rolling-6-month MSRV policy, modern enough to stop
  tripping on rustc inference improvements that worked on stable but
  not on the pinned Docker builder. Single workspace MSRV
  intentionally; RFC 3537 / Cargo issue #14414 document the resolver
  edge cases of mixed-MSRV workspaces. The wire crate stays at
  0.9.0 (no source change since publish), but its published metadata
  on crates.io continues to advertise the 1.88 floor it was published
  with — a future wire bump will republish at 1.92.
- **Dockerfile builder** `rust:1.88-bookworm` → `rust:1.92-bookworm`
  to match the workspace MSRV.

### Added

- **EVPN local-origination Prometheus counters**
  (`crates/telemetry/src/metrics.rs`):
  - `evpn_local_originations_total{action="inject"|"withdraw"}` —
    successful RIB-accepted Type 2 actions.
  - `evpn_local_origination_errors_total{action="inject"|"withdraw"}`
    — failed RIB handoff / rejection / reply-drop paths.
  - `evpn_local_observations_dropped_total{reason="channel_full"|"channel_closed"}`
    — `RTNLGRP_NEIGH` notify-loop drops, distinguishing pre-
    originator kernel-event loss from RIB-side origination failures.
  - `evpn_duplicate_mac_moves_total{vni,mac}` +
    `evpn_duplicate_mac_first_move_timestamp_seconds{vni,mac}` —
    detection-only counters for repeated `(VNI, MAC)` contention,
    feeding the future RFC 7432 §15.1 M=180s/N=5 quarantine work.
    The action remains deferred (ADR-0055 §9), but operators can
    now see contention happening.
- **`originated_local_macs_count` per EvpnInstance** in
  `EvpnService.ListEvpnInstances` (gRPC) and `rustbgpctl evpn
  instances` (human + JSON). Fast "is the loop alive?" view without
  scraping logs.
- **`rustbgpctl evpn diagnose`** — CLI subcommand surfacing the
  bidirectional-VTEP signals an operator wants when triaging
  ("MAC learned in kernel but Type 2 not on wire" / "originator
  spawned but quiescent" / etc.) — instance status, originated-MAC
  count, drop counters, and the relevant log-grep hints in one
  output.
- **Operator runbook** at `docs/evpn-vtep-troubleshooting.md`
  cross-referencing the new metrics and the structured log lines
  the daemon emits at the diagnostic seams (`notify::classify_neigh`
  cache miss, originator emit, IMET inject, shutdown drain).
- **M37 churn soak driver** at
  `tests/interop/scripts/test-m37-evpn-local-origination-churn.sh`.
  Synthetic `bridge fdb add` / `bridge fdb del` at ~10 Hz against a
  configurable MAC set. `--smoke` runs a one-round, five-MAC pre-
  release sanity check; the no-flag form is meant for the 24h soak
  documented in `docs/evpn-alpha-soak.md`.
- **MSRV gate job** in `.github/workflows/ci.yml`. New `msrv` job
  pinned to `dtolnay/rust-toolchain@1.92` runs `cargo check
  --workspace --all-targets` so MSRV breakage fails at PR time
  rather than at Interop time. Hard-coded version so a deliberate
  bump shows up in the workflow diff alongside `Cargo.toml` and
  `Dockerfile`.

### Fixed

- **Telemetry metric label-types compile failure on MSRV.** A
  `with_label_values(&[&vni, mac])` call where `vni: String` and
  `mac: &str` mixed `&String` and `&str` in the array literal.
  rustc 1.95 silently coerced via `Deref`; rustc 1.88 (Docker
  builder MSRV at the time) didn't, so every Interop image build
  failed with `expected &[&String], found &[&str; 2]` while PR-CI
  on stable rustc passed clean. Fixed by making both elements
  unambiguously `&str` via `vni.as_str()`. Underlying gap (no MSRV
  gate at PR time) closed by the new `msrv` CI job above.
- **Clippy 1.95 `duration_suboptimal_units` lint** sweep across
  pre-existing code. `Duration::from_secs(60 / 120 / 300 / 86_400 /
  86_400 * 365)` calls converted to `from_mins` / `from_hours`
  equivalents at 8 sites in `crates/rib`, `crates/transport`,
  `crates/rpki`, `crates/evpn-linux`, `bench/evpn-load`,
  `src/main.rs`, `src/evpn_originator.rs`. `from_days` is still
  feature-gated under `duration_constructors`; the year-long
  placeholders use `from_hours(24 * 365)`.

## [0.15.0] — 2026-05-07

### Changed

- **Breaking — `rustbgpd-wire` 0.8.5 → 0.9.0.** New
  `PathAttribute::PmsiTunnel(PmsiTunnel)` variant added to the
  non-`#[non_exhaustive]` `PathAttribute` enum. Downstream consumers
  doing exhaustive matches on `PathAttribute` will need a new arm
  (typically `PathAttribute::PmsiTunnel(_) => …` to forward or skip
  the attribute). Also exports new types: `PmsiTunnel`,
  `PmsiTunnelType`, `PmsiTunnelIdentifier`. Migration is a one-line
  match-arm addition; the rest of the wire surface is unchanged.

### Added

- **EVPN VTEP local-MAC origination — Gate 7b+1 (ADR-0055).**
  Closes the upward EVPN flow that Gate 7b's foundation left as a
  stub. rustbgpd-as-VTEP is now bidirectional: kernel-learned local
  MACs flow up through `RTNLGRP_NEIGH` and become BGP EVPN Type 2
  originations per RFC 7432 §15.1; one Type 3 IMET (RFC 7432 §7.3)
  is emitted per L2VNI carrying the PMSI Tunnel attribute
  (RFC 6514 §5) for ingress-replication BUM. Landed across
  `crates/evpn`, `crates/wire`, `crates/evpn-linux`, and `src/`:
  - **`LocalMacOriginator` state machine** in
    `crates/evpn/src/origination.rs`. Pure deterministic per-VNI
    sequencer encoding RFC 7432 §15.1 explicitly: first-Learned-no-
    contender ⇒ seq=0 / no extcomm; first-Learned-vs-contender at R
    ⇒ R+1 with extcomm; remote announces M ≥ N ⇒ bump to
    `max(M, N) + 1`. Aged-then-re-Learn preserves the seq ratchet so
    a stale peer can never win contention against us. 17 in-module
    tests including a monotonicity invariant across mixed-handler
    sequences.
  - **PMSI Tunnel path attribute** (RFC 6514 §5, type 22) in new
    `crates/wire/src/pmsi.rs`. Typed `PmsiTunnelType` (preserves
    unknown values for forward-compat), `PmsiTunnelIdentifier` (IPv4 /
    IPv6 / Raw), `for_evpn_ingress_replication(vni, ip)` constructor
    encoding the label field as the raw 24-bit VNI per RFC 8365
    §5.1.3 (no MPLS-style high-20-bits shift). 16 codec tests + an
    integration round-trip through the full `PathAttribute` dispatch.
  - **`EvpnOriginator` daemon actor** in `src/evpn_originator.rs`.
    `tokio::select!` over local-MAC channel, RIB poll (5s default),
    and shutdown drain. Per-instance `LocalMacOriginator`s share an
    `Arc<EvpnInstanceTable>` and the daemon's `rib_tx`. Self-NH
    routes are filtered before reaching the state machine via the
    existing `project_evpn_routes` so we never see our own re-Inject
    as a contender. Shutdown emits Withdraws for every still-
    advertising MAC under a 5s bound.
  - **Type 3 IMET origination** in `src/evpn_imet.rs`. One Type 3
    per `EvpnInstance` originated at startup, withdrawn at
    coordinated-shutdown. Lifecycle is decoupled from kernel
    Ready/NotReady — IMET advertises BGP-level VNI membership, not
    data-plane programmability. Carries Origin/AsPath/NextHop, all
    configured RTs, and a PMSI Tunnel attribute (Ingress Replication,
    label = raw 24-bit VNI per RFC 8365 §5.1.3, tunnel id = local
    VTEP IP).
  - **Upward `LocalMacObservation` channel surface** in
    `crates/evpn-linux/src/dataplane.rs`. New
    `Dataplane::take_local_mac_rx` trait method with a default
    `None` impl. `InMemoryDataplane` exposes a parallel inject hook
    for tests. Channel is intentionally separate from the existing
    `KernelEvent::LocalMacObservation` reconcile-actor flow to keep
    actor lifetimes decoupled (ADR-0054 §1's "narrow upward
    interface" rule).
  - **`RTNLGRP_NEIGH` subscription** in
    `crates/evpn-linux/src/linux/notify.rs`. `LinuxDataplane::connect`
    now calls `add_membership(RTNLGRP_NEIGH)` on the rtnetlink
    socket and spawns a worker task that classifies unsolicited
    `RTM_NEWNEIGH` / `RTM_DELNEIGH` messages with `family = AF_BRIDGE`
    via a pure `classify_neigh` function. Drops `NTF_EXT_LEARNED`
    echoes (we programmed those), drops VXLAN-port ifindexes (those
    are remote MAC echoes), and resolves `header.ifindex` → VNI via a
    new `LinkCache::bridge_port_to_vni` map. 8 unit tests cover the
    happy path + every drop branch.
  - **Daemon main wiring**: spawns the originator alongside the
    reconciler under the same `[[evpn_instances]]` gate; coordinated
    shutdown drains the originator first (so its final Withdraws
    land before the reconciler stops accepting work), then withdraws
    the IMET keys, then drains the reconciler.

  RR-only deployments (empty `[[evpn_instances]]`) still spawn no
  background tasks. macOS dev builds still build cleanly — the
  Linux-only `RTNLGRP_NEIGH` subscription is gated by
  `cfg(target_os = "linux")` via the existing dataplane spawn path.

  M37 containerlab interop smoke validates rustbgpd as a Type 2 +
  Type 3 originator against an FRR consumer
  (`tests/interop/m37-evpn-local-origination.clab.yml`).

  ADR-0055 documents the boundary, sequence rules, and explicit
  deferrals (MAC-with-IP origination, sticky-MAC config schema,
  duplicate-MAC quarantine heuristic, sub-second mobility convergence).

## [0.14.0] — 2026-05-06

### Added

- **EVPN VTEP Linux dataplane reconciler — Gate 7b foundation
  (ADR-0054).** The daemon now consumes selected EVPN Type 2
  best-paths from the RIB and reconciles them through a level-
  triggered actor against a portable [`Dataplane`] trait. Landed
  across the new `crates/evpn-linux` workspace member, the existing
  `crates/evpn` domain crate, and `src/`:
  - **Domain types** in `crates/evpn`: `DataplaneIntent`,
    `DataplaneReport`, `RemoteMacTable` + builder with typed
    duplicate-key error, `RemoteMacEntry`, `LocalMacObservation`,
    `InstanceState` (Ready / NotReady / Unbound), `DataplaneOpKind`.
    The intent surface lives in `crates/evpn` rather than
    `crates/evpn-linux` so macOS dev builds keep compiling and a
    future RR-only feature flag can drop the netlink crate cleanly.
  - **Pure diff loop** in `crates/evpn-linux::diff::compute_diff`.
    Foreign-entry preservation is structural: the delete pass
    iterates `OwnedSet` (rustbgpd-programmed keys), never the kernel
    snapshot, so kernel-learned local MACs and operator-static FDB
    entries cannot be deleted by the algorithm. Mobility update is
    triggered by destination-VTEP change; sequence number is
    recorded on apply for stale-race detection. 11 explicit case
    tests + key-grounding cross-check.
  - **Reconcile actor** generic over `Dataplane`, with `tokio::select!`
    over: new intent (`watch::Receiver`), kernel events (mpsc),
    60 s periodic full dump (configurable), per-op exponential
    backoff retry (100 ms → 5 s with ±25% deterministic jitter),
    and a `CancellationToken` driving a 5 s bounded shutdown drain
    that withdraws only owned remote FDB entries.
  - **`InMemoryDataplane` fake** with a cloneable handle for test
    state inspection and failure injection. The actor's full
    lifecycle is end-to-end testable without netlink: 7 integration
    tests cover initial reconcile, fast intent supersession,
    failed-apply retry, foreign-entry-preservation through shutdown
    drain, periodic-dump cadence, kernel-event-triggered reconcile,
    and NotReady-instance status emission.
  - **M36 real-VTEP smoke** (`tests/interop/m36-evpn-vtep-smoke.clab.yml`)
    proves the full path against a real Linux kernel via
    containerlab: rustbgpd brings up bridge+VXLAN in its container
    netns, peers with FRR over iBGP L2VPN/EVPN, FRR originates a
    Type 2 for a static MAC, rustbgpd programs the kernel FDB with
    both the NTF_MASTER bridge row and the NTF_SELF+dst VXLAN-encap
    row (matching iproute2's wire shape, verified via strace), the
    test asserts `bridge fdb show` reports the MAC with
    `extern_learn` AND the correct remote-VTEP `dst`, then
    withdraws and asserts cleanup. A foreign-static FDB entry
    pre-loaded into rustbgpd's bridge survives both program and
    withdraw cycles. 8/8 PASS locally against Linux 6.17 + FRR
    10.3.1 (rustbgpd-as-VTEP, FRR-as-originator, iBGP/AS65000).
  - **`LinuxDataplane` real rtnetlink integration** at
    `crates/evpn-linux::linux::LinuxDataplane` (rtnetlink 0.14 +
    netlink-packet-route 0.19). Three submodules: `links.rs` walks
    `LinkHandle::get` and stitches VXLAN ports onto their master
    bridges (counting attaches per bridge so 2+ VXLAN ports report
    `NotReady`, not the alternating-clear bug an early prototype
    had); `fdb.rs` programs entries through the
    `bridge fdb add MAC dev vxlanX master dst REMOTE` shape on the
    wire — a single `RTM_NEWNEIGH` targeting the **VXLAN port
    ifindex** (not the bridge) with combined
    `NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED` flags and
    `ndm_state = NUD_NOARP | NUD_PERMANENT`, matching iproute2's
    wire shape (verified via strace) so the kernel materializes both
    the bridge-FDB row and the VXLAN-self encap row from one
    message. The FDB dump path merges the resulting `NTF_SELF`
    (carrying `dst`) and `NTF_MASTER` (no `dst`) rows the kernel
    returns for the same `(VNI, MAC)` so `dst` doesn't collapse to
    `None`, and resolves VNI from the VXLAN port ifindex via the
    link cache's `vxlan_ifindex_to_vni` map. `probe.rs` enforces
    the ADR §4 five-point readiness check (bridge exists, exactly
    one VXLAN port, VNI matches, `local_vtep_ip` matches,
    `IFLA_VXLAN_LEARNING` reports `nolearning` — fail-closed if the
    attribute is missing — and the bridge is not VLAN-aware). The
    netlink error classifier reads `ErrorMessage::raw_code()` and
    maps `EPERM` / `EACCES` → `DataplaneError::PermissionDenied`
    (permanent), `EOPNOTSUPP` → `KernelTooOld` (permanent),
    `EINVAL` → `InvalidArgument` (permanent); other errno values
    stay transient. Permission and kernel-version failures stop
    retrying instead of looping forever, and the operator-facing
    message correctly distinguishes "missing CAP_NET_ADMIN" from
    "kernel too old".
  - **Privileged netns integration test** at
    `crates/evpn-linux/tests/netns_dataplane.rs`, gated on
    `EVPN_LINUX_NETNS=1` (not in CI yet — privileged runner job is
    a deferred follow-up). Creates a bridge + VXLAN port inside a
    Linux namespace, runs the real `probe()` to populate the link
    cache, programs a remote-MAC entry through `apply()`, asserts
    per-row that both the `NTF_MASTER` bridge row and the
    `NTF_SELF + dst` VXLAN-encap row carry `extern_learn`,
    withdraws it, and verifies a pre-loaded foreign static FDB
    entry survives the drain (validates ADR-0054 §5/§7 foreign-
    entry preservation end-to-end). The M36 containerlab smoke
    carries the same per-row assertion against a real Linux
    kernel.
  - **Per-op retry/backoff is enforced**, not just recorded.
    `apply_plan` skips ops whose `(VNI, MAC)` key is in the retry
    schedule and not yet due. Permanent failures
    (`PermissionDenied` / `KernelTooOld` / `InvalidArgument`) are
    suppressed by **per-op-fingerprint**: the failed
    [`DataplaneOp`] is recorded under its `(VNI, MAC)` key, and the
    actor only suppresses subsequent passes whose op shape equals
    the recorded one. A mobility move (different remote VTEP) or an
    add↔remove transition for the same key clears the stale
    suppression inline. Cross-key isolation is structural —
    unrelated `RemoteMacTable` churn never touches another key's
    suppression, and generation churn alone (e.g., a daemon-side
    re-projection that produced an identical table) doesn't clear
    anything. The supervisor compares the projected table to the
    previous publish and only bumps the intent generation on
    semantic change as a separate optimization to avoid pointless
    `watch::send` calls. The actor's outer `tokio::select!` re-fires
    on the retry timer, so deferred ops run as soon as their backoff
    elapses instead of waiting for the next 60 s periodic dump.
    Three suppression tests lock the contract:
    `reconcile_actor.rs::permanent_failure_suppression_is_per_op_fingerprint`,
    `reconcile_actor.rs::permanent_failure_does_not_leak_across_keys`,
    and `evpn_dataplane.rs::supervisor_does_not_bump_generation_on_stable_table`.
  - **Errno-based netlink classification.**
    `errno_to_dataplane_error` reads the kernel's `errno` from
    `ErrorMessage::raw_code()` and maps it to a typed
    [`DataplaneError`] variant: `EPERM` / `EACCES` →
    `PermissionDenied` (new variant; permanent), `EOPNOTSUPP` →
    `KernelTooOld` (permanent), `EINVAL` → `InvalidArgument`
    (permanent), anything else → `Other` (transient). Operator-
    facing messages now correctly distinguish "missing
    `CAP_NET_ADMIN`" from "kernel too old", and the classifier no
    longer string-matches the rtnetlink `Debug` rendering.
  - **Self-originated Type 2 routes are filtered from projection.**
    `project_evpn_routes` now drops routes whose `next_hop` matches
    the local instance `local_vtep_ip` — programming such a route as
    a remote FDB entry would point traffic at ourselves. Two new
    projection tests cover the single-instance and multi-instance
    cases.
  - **EVPN dataplane shutdown drain wired into coordinated shutdown.**
    The daemon's coordinated shutdown block now calls
    `EvpnDataplaneHandle::shutdown().await` after PeerManager drains
    and before BMP — the handle was previously held but never used,
    leaving the actor's drain path dead. The 5 s drain runs the
    actor's bounded delete pass on owned remote FDB entries
    (foreign entries survive), and a 10 s outer timeout prevents a
    stuck task from wedging daemon exit.
  - **Daemon supervisor** at `src/evpn_dataplane.rs`: polling loop
    queries the RIB's existing `QueryEvpnRoutes` channel every 5 s
    (configurable), projects best-path Type 2 routes into a
    `RemoteMacTable` via `rustbgpd_evpn::project_evpn_routes`,
    publishes a `DataplaneIntent` with a monotonic generation
    counter. Empty `[[evpn_instances]]` short-circuits the spawn so
    route-reflector deployments incur zero dataplane cost (no
    netlink socket, no background task — the architectural
    invariant from ADR-0054 §1).

### Tests

- 87 net new tests across the EVPN dataplane stack: domain-type
  unit tests in `crates/evpn`, `compute_diff` cases plus a key-
  grounding cross-check, actor + backoff + in-memory fake tests,
  the LinuxDataplane connect-doesnt-panic smoke + probe.rs
  rejection legs (including missing-`IFLA_VXLAN_LEARNING` and
  multi-VXLAN-port cases), errno-classification tests in
  `linux/fdb.rs`, projection tests (incl. self-VTEP filter),
  supervisor / daemon-wiring tests (incl. the generation-
  stability check), per-op-fingerprint suppression tests, and the
  binary-spawn RR-only invariant test. Workspace count climbs
  from 1406 (v0.13.4 baseline) to 1493.

### Packaging

- New workspace member `crates/evpn-linux` (`publish = false`).
  cfg-gated `target_os = "linux"` deps: rtnetlink 0.14, netlink-
  packet-route 0.19, netlink-packet-core 0.7, netlink-packet-utils
  0.5, netlink-sys 0.8 (with `tokio_socket`), futures 0.3. Pinned
  to the 0.14/0.19 pair because the newer 0.21+/0.30+ releases
  changed the message-shape ABI and pull async-std incompatibly
  with the workspace's tokio/tonic stack. Daemon picks up
  `tokio-util` 0.7 directly for `CancellationToken` (the
  evpn-linux crate already uses it).

## [0.13.4] — 2026-05-04

### Fixed

- **RFC 8326 `[global] honor_graceful_shutdown` now hot-applies on
  SIGHUP.** Reload flips advance the live config snapshot and fan out
  policy recomputation to EBGP peers; established peers reuse the
  existing route-refresh retry path when their effective import policy
  changes. The hot-apply is best-effort: `set_honor_graceful_shutdown`
  precomputes every EBGP peer's effective chain against the new
  snapshot, advances `current_config` unconditionally, then iterates
  applying and accumulates per-peer failures into an aggregated `Err`.
  Failed peers retry on their next `update_runtime_policies` via the
  existing `pending_refresh` / `pending_export_apply` bail-and-carry
  plumbing — no peer-manager-vs-snapshot drift on partial apply.
- **RFC 8326 runtime GShut toggles now replay onto dynamic peers.**
  The per-peer dead-letter side table on `PeerManager` (introduced in
  v0.13.2 to carry `pending_refresh` / `pending_export_apply` across
  `BackToIdle` auto-removal) now also snapshots
  `advertise_graceful_shutdown` and restores it when the same address
  re-establishes.
- **Reload no longer rolls back on partial honor-knob hot-apply.**
  `reload_config` previously `halt_partial`'d on the
  `set_honor_graceful_shutdown` `Err`, rolling the daemon's
  `working_config` back to the pre-flip value while the peer manager
  had already advanced its snapshot — drift one layer up. Reload now
  logs the partial failure as `warn!` and advances
  `working_config.global.honor_graceful_shutdown` to match the peer
  manager's snapshot so both views stay aligned.

### Tests

- **M35b + M35c interop coverage.** New FRR 10.3.1 containerlab tests
  prove `attach_graceful_shutdown_if_enabled` fires on FlowSpec and
  L2VPN/EVPN outbound MP_REACH advertisements, complementing M35's
  IPv4 unicast coverage. The tests capture BGP UPDATE bytes inside
  the FRR container so the assertion is on the actual `0xffff0000`
  community on the wire. The capture parser maintains per-flow TCP
  reassembly buffers keyed by `(src, sport, dst, dport)` so BGP
  messages whose marker / length / community attribute span a TCP
  segment boundary still parse correctly under CI segmentation.
  `CAPTURE_DURATION_SECS=8` plus a new `wait_for_capture` helper that
  polls for the parser's JSON output before asserting eliminates the
  earlier 4 s-capture / 5 s-sleep window mismatch.
- **Peer-manager failure-mode hardening.** Added unit coverage for
  channel-full policy updates, back-to-back hot-apply updates, and
  peer deletion while retry intent is pending.

### Packaging

- Workspace crates bumped to `0.13.4`. `rustbgpd-wire` remains
  `0.8.5`; this release does not touch `crates/wire/src/` or require
  a wire-crate publish.

## [0.13.3] — 2026-05-04

### Added

- **RFC 8326 BGP Graceful Shutdown — well-known `GRACEFUL_SHUTDOWN`
  community (`65535:0` / `0xFFFF_0000`) end-to-end.** Lets operators
  drain traffic ahead of planned EBGP-session maintenance without
  writing the policy by hand. Architecture: ADR-0053.
  - **Wire crate**: new `pub const COMMUNITY_GRACEFUL_SHUTDOWN: u32`
    next to the LLGR constants. rustbgpd-wire 0.8.4 → 0.8.5
    (non-breaking pub addition). Value-pin test asserts all three
    well-known constants match their spec values.
  - **Policy engine**: `parse_community_match` accepts
    `"GRACEFUL_SHUTDOWN"` as a community alias. Because
    `parse_community_values` (the policy *set* side —
    `set_community_add` / `set_community_remove`) routes through the
    same parser, the alias works in both match and set positions.
  - **Inbound honor (opt-in)**: new `[global] honor_graceful_shutdown
    = true` knob appends an implicit chain-tail import rule on every
    EBGP peer (`match GRACEFUL_SHUTDOWN → permit, set local_pref =
    0`). Running at the chain *tail* (not head) guarantees the
    demotion wins last-writer-accumulation against any operator
    policy that also sets `local_pref` — placing the rule at the head
    would silently let an operator's `set_local_pref = 200` overwrite
    the demotion. iBGP exempt because LOCAL_PREF is preserved within
    an AS. Off by default.
  - **Outbound advertise (operator-runtime, not policy)**: new
    `NeighborService.SetGracefulShutdown { address, enabled }` gRPC +
    `rustbgpctl gshut [--peer X] [--clear]` CLI. Empty `address`
    broadcasts to all currently-managed peers. The toggle is stored
    on `ManagedPeer` (the authoritative desired-state record),
    mirrored to the live `PeerSession`, and replayed onto fresh
    sessions on collision-replace / inbound-accept so a session flap
    mid-maintenance doesn't silently drop the toggle. Flipping the
    toggle issues `RibUpdate::RefreshPeerOutbound` so routes already
    in `AdjRibOut` re-emit immediately with (or without) the
    community on the wire.
  - **gRPC error mapping**: typed `SetGshutError::PeerNotFound` /
    `Internal` so the handler distinguishes operator-typo
    (`NOT_FOUND`) from session/RIB dispatch failures (`INTERNAL`).
    Authoritative state on `ManagedPeer` advances even when the
    immediate dispatch fails — the toggle takes effect on the next
    session spawn regardless.
  - **`Route.local_pref_attr` proto field**: new optional `uint32`
    that distinguishes "explicit `LOCAL_PREF` attribute set" from
    "no attribute on the wire". Required for downstream consumers
    (and the M35 interop test) to verify the implicit demotion
    actually fired on a tagged route — proto3 omits zero-valued
    `local_pref` whether policy set it or no attribute was on the
    wire, so the explicit-vs-default signal would otherwise be lost.
  - **M35 interop test against FRR 10.3.1**
    (`tests/interop/m35-graceful-shutdown-frr.clab.yml` +
    `test-m35-graceful-shutdown-frr.sh`). Receiver leg: FRR tags
    `192.168.1.0/24` outbound; assertion checks rustbgpd's RIB
    carries the community AND has `local_pref_attr = 0` on the
    tagged prefix while the untagged prefix has no attribute.
    Initiator leg: rustbgpd injects `172.16.0.0/24` and toggles
    GShut via gRPC; FRR's `show ip bgp ... json` shows the path
    with `community.list ⊇ ["gracefulShutdown"]`. Clear leg:
    toggle off + delete + re-add forces a fresh advertise; FRR no
    longer sees the community.

### Known limitations (tracked in `KNOWN_ISSUES.md` + ROADMAP)

- RFC 8326 EBGP gating uses a simple `remote_asn != global.asn`
  comparison. Will need an explicit `is_external_neighbor()` helper
  when confederation support lands.
- The runtime initiator toggle does not persist across daemon
  restart by design — it's a maintenance-window action, not config.
- Dynamic peers that auto-remove and re-establish at the same
  address come up with the toggle off. Operators re-issue
  `rustbgpctl gshut` after a re-establish if the maintenance
  window is still active.

## [0.13.2] — 2026-05-03

### Fixed

- **Dynamic peers no longer silently drop unfired hot-apply intent on
  auto-removal.** When a `[[dynamic_neighbors]]`-spawned peer went idle
  and the peer manager auto-removed it, any `pending_refresh` /
  `pending_export_apply` flag the `ManagedPeer` was carrying (unfired
  Route Refresh or session-side export-policy apply, normally retried
  on the next `update_runtime_policies`) evaporated with the dropped
  struct. A re-establishing peer at the same address restarted both
  flags at `false`, leaving the prior `SetPolicy` edit unfired against
  routes already accepted under the old policy. New per-IP dead-letter
  side table on `PeerManager` (bounded at `dynamic_neighbor_limit`)
  snapshots the flags at remove and restores them when the peer
  re-incarnates. Regression test:
  `dead_lettered_pending_survives_dynamic_peer_auto_removal_and_re_establish`.

- **gRPC-config-event bridge no longer holds a stale snapshot across
  SIGHUP.** The bridge that converts gRPC `ConfigEvent`s into
  `ReplaceConfig` mutations for the on-disk persister owns its own
  pre-persist snapshot. SIGHUP-driven reloads previously sent the
  reloaded snapshot directly to the persister, bypassing the bridge —
  the bridge's snapshot stayed at the pre-reload state, and the next
  gRPC mutation overwrote the persisted file with `stale_pre_reload +
  one_mutation`. Lifted the bridge into a named `run_config_bridge`
  task that selects on both an event channel and a new
  `bridge_replace_tx` snapshot-replacement channel (biased toward
  replacement so a backlog of events can't delay reload visibility).
  `apply_reload_outcome` now routes through the bridge; the post-
  SIGHUP gRPC mutation applies to the reloaded snapshot, not the
  stale one. Regression test:
  `config_bridge_replacement_makes_subsequent_events_apply_to_new_snapshot`.

- **Post-reload sync ordering.** The SIGHUP arm previously sent the
  config-persister snapshot before the peer-manager internal snapshot;
  if the persister succeeded but the peer-manager send failed (manager
  task dropped — fatal anyway), the persister had advanced while the
  authoritative runtime view had not, leaving observable but silent
  split-brain across the next gRPC mutation. Lifted the two sends into
  `apply_reload_outcome`: peer manager first (`mpsc::UnboundedSender`,
  can only fail on receiver-drop and never blocks), config bridge
  second. Failure surfaces as a named stage (`peer_mgr_snapshot` /
  `config_bridge`) so the operator log is actionable. Both downstream
  consumers replace their snapshot wholesale, so the next SIGHUP
  retries cleanly.

### Changed

- **`reload_config` now runs on a dedicated tokio task.** Previously
  the SIGHUP arm `.await`'d the reload inline inside the main
  `tokio::select!`, blocking SIGINT/SIGTERM observation for the
  duration (up to ~7 round-trip commands × 500 ms
  `PEER_POLICY_UPDATE_TIMEOUT` plus reconcile round-trip). Operators
  hitting Ctrl-C mid-reload now see the daemon respond. A SIGHUP that
  arrives while a reload is still running is logged
  (`"SIGHUP received while previous reload still in flight; ignoring"`)
  and dropped — concurrent reloads would race on `peer_mgr_tx` command
  ordering and double-fire the post-reload sync. Coordinated shutdown
  aborts any in-flight reload before tearing down the peer manager.

- **`.cargo/audit.toml` ignore-list hygiene.** Dropped the stale
  RUSTSEC-2024-0437 entry (cleared by the v0.13.1 prometheus 0.14
  bump). RUSTSEC-2026-0097 (rand soundness via ratatui-termwiz) stays
  ignored — verified upstream that ratatui-termwiz 0.1.0 is the latest
  release and the phf ecosystem hasn't bumped rand yet; the soundness
  case requires a custom rand logger that this workspace does not
  install.

## [0.13.1] — 2026-05-01

### Changed

- **Bump `prometheus` 0.13 → 0.14** to clear RUSTSEC-2024-0437
  (uncontrolled-recursion crash in `protobuf` 2.x reachable via
  `prometheus`'s transitive dependency). Prometheus 0.14 moves to
  `protobuf` 3.x, splitting its proto-generated types between
  field access for containers (`MetricFamily.metric`,
  `Metric.label`, `Metric.counter`, `Metric.gauge`) and method
  access for leaf accessors (`LabelPair.name()`, `LabelPair.value()`,
  `Counter.value()`, `Gauge.value()`). Migrated four test/internal
  files: `crates/bmp/src/client.rs`, `crates/bmp/src/manager.rs`,
  `crates/rib/src/manager/tests.rs`,
  `crates/transport/tests/session_lifecycle.rs`. No
  operator-visible behavior change; closes the open `cargo audit`
  finding tracked in ROADMAP.

### Fixed

- **M34 SIGHUP-policy interop test stops asserting on FRR's
  `bgpTimerUpEstablishedEpoch`.** The FRR field is rounded to whole
  seconds and the rounding direction can shift by ±1s under heavy
  parallel-runner load (observed multiple times during dependabot
  churn on 2026-05-01, including the epoch going *backwards* by 1s
  — physically impossible for a real session flap). M34 now reads
  rustbgpd's own `NeighborState.flapCount` and `uptimeSeconds` via
  gRPC: `flapCount` must not increase AND `uptimeSeconds` must
  monotonically advance across the SIGHUP. The cross-check pins
  "session continuity" — flapCount alone would let a hypothetical
  tear-down + fresh-handle re-establish slip through (every fresh
  `PeerSession` starts at `flap_count = 0`); `uptimeSeconds` resets
  to ~0 on a new handle, so the monotonicity guard catches that
  case. Mirrors the `flapCount` pattern M33 has been using.

### Added

- **EVPN `MP_REACH` IPv6 next-hop roundtrip test**
  (`mp_reach_evpn_ipv6_next_hop_roundtrip` in `crates/wire/src/attribute.rs`).
  Closes the validate-side audit gap RFC 7432 §7.5 left
  untested: the egress PE address may be IPv4 or IPv6, and the
  IPv4 path was the only one with a roundtrip test on the EVPN
  branch of `encode_mp_reach_nlri`. The new test pins the 16-byte
  single-address IPv6 form end-to-end (encode → wire → decode →
  identity).
- **EVPN `MP_REACH` 32-byte next-hop rejection test**
  (`mp_reach_evpn_rejects_32byte_next_hop`). Hand-crafts an
  attribute with `AFI=25 / SAFI=70 / NH-Len=32` and asserts the
  decoder rejects with `MalformedField`. EVPN does NOT use the
  global+link-local 32-byte form (that's RFC 2545 unicast
  territory); the L2VPN decoder branch in
  `crates/wire/src/attribute.rs` already enforces this, but the
  invariant had no direct regression test. Pins it now so a
  future broadening of the L2VPN decoder is caught.

## [0.13.0] — 2026-05-01

### Added

- **EVPN VTEP foundation — declarative local EVI/VNI domain model.**
  Phase 2 of the EVPN track (ADR-0052) lands as two slices; this is
  the first. New `[[evpn_instances]]` config block declares per-VNI
  local state: VNI (24-bit, RFC 8365 §5), Route Distinguisher
  (RFC 4364 §4.2), bidirectional Route Targets (RFC 4360 / RFC 5668),
  VXLAN tunnel source IP, optional Linux bridge name, and an
  `advertise_svi_mac` flag (RFC 9135 §6.1; recognized today, wired
  to origination in the next slice). New `crates/evpn` exposes
  the runtime [`EvpnInstance`] / [`EvpnInstanceId`] / [`EvpnInstanceTable`]
  types — kernel-free, route-origination-free, parses / validates /
  enforces VNI and RD uniqueness. Read-only gRPC surface
  (`EvpnService.ListEvpnInstances`) and `rustbgpctl evpn instances`
  expose the resolved table. Empty by default — RR-only
  deployments (the `rr-evpn-fabric` example) are unchanged.
  See `examples/evpn-vtep-leaf/config.toml` for the leaf shape.

- **`RouteDistinguisher::from_str` in `rustbgpd-wire`.** Parses the
  RFC 4364 §4.2 textual encodings (`asn:val`, `ipv4:val`, 4-octet AS
  form). Disambiguation matches the FRR / Cisco / Junos convention
  used elsewhere in the codebase. Independently useful for any
  caller that round-trips RD strings without pulling in the EVPN
  domain crate.

### Changed

- **gRPC stack: tonic 0.13 → 0.14, prost 0.13 → 0.14, socket2 0.5 → 0.6.**
  tonic 0.14 split prost-coupled codegen out into a new
  `tonic-prost-build` crate; `crates/api/build.rs` and
  `crates/cli/build.rs` migrated to use it (same `compile_protos` /
  `configure()` surface, only the crate name changed). socket2 0.6
  renamed `set_ttl` → `set_ttl_v4`, with a parallel `set_ttl_v6`;
  GTSM (RFC 5082) on the BGP transport socket is IPv4-only here, so
  the IPv4-specific setter is the correct call. tonic 0.14's `Status`
  type is smaller, allowing 17 stale
  `#[expect(clippy::result_large_err)]` annotations to drop from
  `crates/api/src/injection_service.rs`. New `tonic-prost` runtime
  crate added alongside; replaced PRs #20 + #27 (which needed code
  migrations the bot couldn't write) with a direct migration commit.

- **toml 0.8 → 1.1 (TOML 1.1 spec compliance) + toml_edit 0.22 → 0.25.**
  toml_edit 0.25 deprecated `ImDocument` in favor of `Document` (the
  immutable-document type alias was renamed); `src/config/diagnostic.rs`
  follows the rename. `Document::parse` semantics unchanged — pure
  rename, no operator-visible behavior change.

- **Patch / minor rollup:** tokio 1.49 → 1.50, criterion 0.5 → 0.8,
  proptest 1.10 → 1.11, tracing-subscriber 0.3.22 → 0.3.23,
  clap_complete 4.5 → 4.6, libc 0.2.182 → 0.2.186. No
  operator-visible changes; criterion bench code uses only stable
  APIs across 0.5–0.8.

- **GitHub Actions workflow rollup:** actions/checkout 4 → 6,
  actions/download-artifact 4 → 8, actions/upload-artifact 4 → 7,
  docker/metadata-action 5 → 6, docker/setup-buildx-action 3 → 4.
  All workflow YAML keys in use survive the bumps; runners are on
  Node 24 by default. No workflow edits needed.

## [0.12.2] — 2026-04-30

### Fixed

- **IPv6 `MP_REACH` link-local next-hop now validated as `fe80::/10`.**
  The audit follow-up to v0.12.1's FlowSpec `NEXT_HOP` fix found a
  sibling gap: when an `MP_REACH_NLRI` carried a 32-byte next-hop
  (the global + link-local form, RFC 4760 §3 / RFC 2545 §3), the
  validator only inspected the global address and silently accepted
  any value at `link_local_next_hop`. A peer sending a malformed
  `MP_REACH` whose second 16 bytes were not in `fe80::/10` would
  land in the receive path where downstream consumers may treat it
  as if it were link-local. Now rejected with subcode 8 (Invalid
  `NEXT_HOP`). Symmetric defense-in-depth `debug_assert` added in
  the encoder (`crates/wire/src/attribute.rs`) catches future
  regressions where a non-LL value would be emitted on the wire.

### Changed

- **`rustbgpd-wire` 0.8.2 → 0.8.3 (patch).** Carries the IPv6 LL
  next-hop validation fix above. No public API changes — single
  match-arm guard, function signature change limited to a private
  helper. Downstream consumers picking up 0.8.3 close the
  symmetric gap to the v0.12.1 FlowSpec patch.

### Tests

- `mp_reach_ipv6_invalid_link_local_segment_rejected` — pins the
  bug fix; non-LL second segment → subcode 8.
- `mp_reach_ipv6_global_plus_link_local_accepted` — pins that
  valid 32-byte form still passes (no over-rejection).
- `mp_reach_flowspec_rejects_nonzero_nh_len` — pins decoder-side
  rejection of malformed FlowSpec `NH-Len`, complementing the
  validate-time skip from v0.12.1.

### Documentation

- **Project-wide doc accuracy pass** after the v0.10.0 → v0.12.1
  feature surge (SIGHUP reconcile, automatic Route Refresh,
  FlowSpec `NEXT_HOP` fix, 12-job interop CI gate, native gRPC
  mTLS, link-local `NEXT_HOP` end-to-end). Highlights:
  - `crates/wire/README.md` — `OpenMessage` and decode examples
    rewritten to compile against the actual API (struct field
    name, `Capability` variant shapes, `decode_message` /
    `encode_message` entry points).
  - `docs/SECURITY.md` — native gRPC mTLS is no longer described
    as deferred; section now leads with the in-daemon TLS path
    and treats the proxy front-end as a multi-host fallback.
  - `docs/CONFIGURATION.md` — `tls_cert_file` / `tls_key_file` /
    `tls_client_ca_file` documented; eight broken `docs/adr/...`
    cross-references corrected; SIGHUP-reload section rewritten
    to cover the four-bucket reconcile pipeline.
  - `docs/OPERATIONS.md` — SIGHUP-reload section rewritten;
    automatic Route Refresh on import-policy hot-apply called
    out so operators don't reach for `softreset` after every
    chain swap.
  - `docs/INTEROP.md` — CI carve-out section added (12 jobs in
    four tiers: foundation, address-family, operational+security,
    EVPN+SIGHUP); M22 results table rewritten for the JSON +
    flap-detection shape; M34 (SIGHUP soft-reset) section added.
  - `docs/API.md` — TLS / mTLS section added; missing
    `*DynamicNeighbor`, `ListEvpnRoutes`, EVPN injection RPCs
    folded into the service tables; `ADDRESS_FAMILY_L2VPN_EVPN`
    added to the AF filter list.
  - `README.md` — workspace test count (1245 → 1312), interop
    count (27 → 31, of which 12 CI-gated), and RPC tables
    refreshed.
  - `ARCHITECTURE.md` — file-path drift swept (`session.rs` →
    `session/`, `best_path_cmp` location), SIGHUP "Lifecycle
    Flow" rewritten end-to-end.

## [0.12.1] — 2026-04-30

### Fixed

- **FlowSpec MP_REACH next-hop validation no longer tears the
  session.** Per RFC 8955 §6.1 the `NEXT_HOP` value for FlowSpec
  (SAFI 133) advertisements is "irrelevant" and recommended to be
  0. Wire decoder fills `MpReachNlri.next_hop` with `0.0.0.0`
  when the on-wire NH-Len is 0 (the FlowSpec convention). The
  pre-fix validate path then rejected `0.0.0.0` with subcode 8
  (Invalid `NEXT_HOP`), causing rustbgpd to send `NOTIFICATION`
  3/8 and tear the session against any RFC-compliant FlowSpec
  peer (FRR, GoBGP). Result: a flap-and-recover cycle on every
  FlowSpec UPDATE exchange. M22's prior version masked this with
  long FRR-display-path waits — the test would "pass" once FRR
  re-established and re-received the rules. Surfaced by switching
  M22 to JSON convergence signals + a per-step
  `connectionsDropped` flap-detection assertion. Validate now
  skips `check_mp_reach_next_hop` for `Safi::FlowSpec`. M22
  runtime dropped from ~120 s on the slow-path branch to ~22 s
  deterministic.

### Changed

- **`rustbgpd-wire` 0.8.1 → 0.8.2 (patch).** Carries the FlowSpec
  `NEXT_HOP` validation fix above. No public API changes — single
  match-arm guard inside `validate_update_attributes` plus a unit
  test pinning the regression. Downstream consumers picking up
  0.8.2 fix the session-tear behaviour against any RFC-compliant
  FlowSpec peer.

### CI

- **M22 FlowSpec test rewired to direct convergence signals.**
  Prior version polled `show bgp ipv4 flowspec` text output for
  every FRR-side check, which lags the underlying RIB by tens of
  seconds and hid the session-flap bug above. Now uses
  `show bgp ipv4 flowspec json` parsed with `jq` for state
  queries, asserts session stability via `connectionsDropped`
  delta after every test step, and tightens timeouts from the
  60–120 s slow-path windows to 30 s. M22 also now requires `jq`
  on the runner; CI wiring already installs it for M30/M34.

## [0.12.0] — 2026-04-30

### Added

- **SIGHUP reconciliation for policy, peer-groups, neighbor-sets,
  and global chains.** `reload_config` now applies named-policy /
  neighbor-set / peer-group / global-chain edits at reload time,
  not just `[[neighbors]]` deltas. Operators editing TOML and
  running `kill -HUP` get the same effect as a sequence of gRPC
  policy/peer-group mutations: definitions land first (so peer
  groups and chains can reference them), then neighbors reconcile,
  then obsolete definitions delete in reverse-dependency order so
  `still referenced` rejections don't fire transiently. Each step
  is a single-shot command to the peer manager that goes through
  `apply_policy_change` / `apply_peer_group_change` — runtime
  effect (hot-applied policy chain, delete + re-add for peer-group
  members) matches the existing gRPC API path. Reload halts at the
  first step failure and returns a partial-state snapshot, so the
  daemon's in-memory config tracks what the peer manager actually
  applied instead of lying that the prior config is still in effect
  — the operator fixes the failing TOML and reloads again to
  converge against the half-applied state.
  *Exception:* the neighbor reconcile step is the one place where
  partial failure leaves live state genuinely ambiguous (the peer
  manager sequences delete-then-readd for changed peers and any
  subset can succeed before the failure point); reload returns
  `None` in that specific case rather than guessing a snapshot, and
  logs an explicit "inspect via `rustbgpctl neighbor list`"
  pointer. Earlier reload steps (policy / peer-group / chain
  edits) still land at the manager and remain in effect.

- **Automatic Route Refresh on import-policy hot-apply.** When a
  policy / peer-group / chain mutation changes a peer's *effective*
  import policy without recreating the session,
  `PeerManager::update_runtime_policies` now issues
  `soft_reset_in` for that peer (gated on the session being
  Established) so routes already accepted in the AdjRibIn under
  the old policy get re-evaluated. Driven from inside the peer
  manager rather than from the SIGHUP-only reload path so dynamic
  peers — which live only in the manager's runtime table, not in
  `[[neighbors]]` — get the same correctness guarantee as static
  peers, and so the same code path covers gRPC `SetPolicy` /
  `SetPeerGroup` / chain mutations and TOML+SIGHUP. Failure
  bubbles via the `apply_policy_change` result so SIGHUP reloads
  halt via `halt_partial` rather than silently logging-and-
  forgetting. Validated end-to-end against FRR 10.3.1 by the new
  M34 interop test (`tests/interop/m34-policy-soft-reset-frr.clab.yml`,
  CI-gated alongside M29 / M30): a SIGHUP that adds a deny rule
  for one of three advertised prefixes drops just that prefix
  from the RIB while the session stays Established and the other
  two prefixes remain.
  *Limitation:* inline `policy.import` / `policy.export` (the
  legacy non-named global-fallback statements) still require a
  full restart — they're evaluated at session start, and the
  command surface for swapping them at runtime doesn't exist yet.
  Operators are warned at reload time; `--diff` surfaces them under
  "Restart-required" with a one-line migration hint. Closes the top
  two open ROADMAP "Next Up — Pre-v1.0 Polish" bullets.

- **Auto-retry for failed import-policy refreshes.** Added a
  `pending_refresh: bool` flag to `ManagedPeer`, set when
  `soft_reset_in` returns Err for an Established peer and re-armed
  when an inherited flag finds the peer still not Established.
  Drained at the start of every `update_runtime_policies` call: if
  the peer is now Established the refresh is retried, otherwise the
  flag is held for the next call. Closes the silent-stale-routes
  class where a transient refresh send failure (peer task mid-
  restart, mpsc backpressure) left routes in `AdjRibIn` accepted
  under the prior policy until an operator manually reissued
  `SetPolicy` / `rustbgpctl neighbor soft-reset-in`.

- **Bookkeeping is deferred until the session acknowledges a
  policy update.** `update_runtime_policies` now hot-applies the
  import / export policy to the session task FIRST and only
  advances `managed.import_policy` / `managed.export_policy` after
  the session replies. If the session-side update fails (task
  back-pressured past the deadline, exited mid-shutdown, mpsc full),
  the daemon's bookkeeping stays at the prior value so the next
  call's `import_changed` / `export_changed` comparisons still see a
  delta and retry. When the failure happens under apply-changing
  intent — for *any* session state, not just Established — the call
  bails before the RIB update and the Route Refresh: firing those
  steps against a session that still holds the prior policy would
  re-evaluate `AdjRibIn` against the *old* import policy and / or
  drift the RIB's view of the export policy away from what the
  session is announcing, and silently returning Ok for non-
  Established peers would let the caller advance `current_config`
  with no retry signal — leaving the peer to establish later under
  the stale policy if the session task subsequently dropped the
  queued command. Route Refresh stays gated by `soft_reset_in`'s
  own Established check; the gates serve different purposes.

- **Symmetric retry for export-side hot-apply failures.** Added a
  `pending_export_apply: bool` flag to `ManagedPeer` that mirrors
  `pending_refresh` for the export side. Set when
  `update_export_policy_timeout` fails for an export-changing edit;
  drained at the start of every `update_runtime_policies` call and
  combined with `export_changed` to retry. Closes the symmetric
  silent-stale-policy class on the export side: a transient session-
  side export-policy update failure could otherwise leave the peer
  announcing under the prior policy while the daemon's config
  snapshot had advanced, with no automatic retry — permit→deny
  export edits would silently keep leaking routes until the next
  unrelated mutation or restart.

- **Cross-side retry intent preserved across bails.** When
  `update_runtime_policies` bails because one side's hot-apply
  failed, both `pending_refresh` and `pending_export_apply` are
  set whenever the corresponding intent (`needs_refresh` /
  `needs_export_apply`) was present — not just the side that
  triggered the bail. This closes a partial-success failure mode
  where import apply succeeded (advancing
  `managed.import_policy`) but export apply failed: the export
  bail would set only `pending_export_apply`, and on retry
  `import_changed` would be false (bookkeeping already advanced)
  with no `pending_refresh` to drive `needs_refresh`. Route
  Refresh would silently never fire, leaving `AdjRibIn` routes
  accepted under the prior import policy stuck against a session
  that now had the new policy. Setting both flags at the bail
  makes the retry pipeline pick up *every* unfired downstream
  step regardless of which side bailed.

- **RIB-update failure preserves refresh intent.** Same silent-
  skip class at a different downstream step: when session-side
  hot-apply succeeds (bookkeeping advances) but the
  `RibUpdate::ReplacePeerExportPolicy` step fails — RIB channel
  closed, reply dropped, RIB returned Err — the `?` short-circuit
  used to bubble Err without re-arming `pending_refresh`. On
  retry, `import_changed` would compute false (bookkeeping
  already advanced) and `soft_reset_in` would silently never
  fire. Replaced the `?` chain with an explicit match that
  re-arms `pending_refresh` (when `needs_refresh` was true)
  before returning Err. Note that "Established gate" applies
  only to *firing* Route Refresh (via `soft_reset_in`'s own
  check); the failure-bail and pending-flag carry semantics are
  state-independent.

- **Stale `query_state_timeout` preserves refresh intent.** When
  the session task is back-pressured past the query deadline,
  `query_state_timeout` returns `None` and `is_established`
  reads false — indistinguishable from a genuinely Idle peer.
  With a fresh `import_changed = true` (no inherited
  `had_pending_refresh`), the prior `else if` branch wouldn't
  re-arm `pending_refresh`; the call would return Ok with
  bookkeeping advanced, and the next call would compute
  `import_changed = false` and silently skip Route Refresh.
  Generalized the re-arm to fire whenever
  `needs_refresh && !is_established`, regardless of whether the
  intent was inherited or freshly generated. The wasted-refresh
  cost on a genuinely Idle peer (next call sends a no-op Route
  Refresh against an empty `AdjRibIn`) is small and acceptable
  next to silent stale-routes.

- **SIGHUP `resolved_neighbors` failure routes through
  `halt_partial`.** The neighbor-resolve failure path previously
  logged with `error!` and returned `Some(working_config)`
  directly, bypassing the structured `halt_partial` failure
  reporting (`bucket` / `target` / `error`) used by every other
  reload step. Routed through `halt_partial` with
  `bucket = "neighbors.resolve"` so operators get consistent
  structured diagnostics across all reload-step halts.

- **Effective neighbor diff via peer-group resolution.**
  `rustbgpd --diff` (and `--diff --json`) now surfaces a per-
  neighbor "effective impact" view: every neighbor whose resolved
  config (after peer-group inheritance and policy-chain resolution)
  would move at reload is listed with the upstream change(s)
  responsible. Implementation diffs `Config::resolve_neighbor` for
  the old vs new config, so transitive references are caught: a
  policy definition edit picked up via the global `import_chain`
  (chain list itself unchanged) or via a peer-group's chain
  (peer-group record unchanged) still flags every affected member.

### Changed

- **`rustbgpd --diff` "Informational (not reconciled)" bucket
  removed.** Per-named definitions, chains, peer-groups, and
  neighbor-sets all reload now, so the dimmed "informational"
  block is gone. Inline `policy.import` / `policy.export` move to
  the existing "Restart-required" section with an explicit
  migration hint to named definitions + chains.

- **`--diff --json` schema mirrors the human bucketing.** The JSON
  output now includes peer-groups, peer-group field details, named
  policy / neighbor-set / global-chain deltas, and the per-neighbor
  effective-impact view under `reload_applied`; inline
  `policy.import` / `policy.export` flags appear under
  `restart_required`; the `informational` block is empty (kept on
  the schema as a stable bucket so consumers don't break when it's
  populated again in a future release). Automation classifying
  hot-applied edits by which bucket they land in stays correct.

- **`TransportConfig` now derives `Debug`.** Used by the new
  effective-impact diff to compare resolved neighbor configs
  via `format!("{:?}", ...)` without requiring a `PartialEq` impl
  (which would mean touching every nested type — out of scope).
  Cosmetic side benefit: tracing spans that include
  `TransportConfig` now render readably.

- **`rustbgpd-wire` 0.8.0 → 0.8.1 (patch).** Documentation-only
  refresh of `crates/wire/README.md` so the crates.io and docs.rs
  rendering matches the actual published surface: adds RFC 1997,
  2545, 2918, 4486, 6793, 7313, 7432, 7674, 8365, 9012, 9135, 9136
  to the Supported RFCs table; lists `EvpnRoute` / `EvpnRouteKey`
  under Key types; updates the header sentence to mention EVPN.
  No source changes.

### CI

- **Interop suite expanded from 3 to 12 parallel jobs.** Every PR
  now exercises foundation behaviour (M1 basic UPDATE/RIB, M13
  policy engine, M15 gRPC SoftResetIn), address-family + topology
  shapes (M10 IPv6 dual-stack, M14 Route Reflector, M17 Add-Path),
  operational + security (M22 FlowSpec, M24 BMP, M25 TCP MD5 +
  GTSM), and EVPN + SIGHUP (M29 cap negotiation, M30 Type 2
  reflection, M34 SIGHUP soft-reset) against a real FRR 10.3.1
  peer. Per-job wall-clock is ~5 min, all in parallel. Catches
  wire-protocol, policy, and reload regressions at PR time
  instead of post-merge.

- **Standardized rustbgpd startup across all interop scripts.**
  Eliminates the brittle 3 s fixed-sleep pattern that had drifted
  into 16 of the 22 interop scripts. The `start_rustbgpd` helper
  in `tests/interop/scripts/test-lib.sh` is now the single source
  of truth: 10 s `/proc` poll loop + 30 s gRPC-ready wait +
  diagnostic capture on failure. Three scripts that need a custom
  config path (M21 RPKI, M24 BMP, M27 ASPA) use a parametric
  variant that takes the launch command as an argument. Net diff
  in the standardization commit: +52 / −246 lines (mostly
  deletion of duplicated boilerplate).

- **Wire crate README freshness gate.** `.github/workflows/ci.yml`
  now fails if `crates/wire/Cargo.toml` version was bumped without
  any touch to `crates/wire/README.md` in the same diff. Catches
  the failure mode where a wire bump publishes with a stale RFC
  table or stale Key types list. The gate is escapable with a
  whitespace-only README edit — its purpose is a forcing function
  for a deliberate review, not a content lint.

## [0.11.0] — 2026-04-29

### Added

- **Native gRPC mTLS for TCP listeners.** Operators who don't want an
  Envoy/nginx sidecar can now terminate TLS in-process via tonic +
  rustls/ring. Three new TOML keys under
  `[global.telemetry.grpc_tcp]`: `tls_cert_file` (server identity),
  `tls_key_file` (server private key), `tls_client_ca_file` (CA used
  to verify client certs). All three are required together — partial
  config is rejected at `Config::load` with `InvalidGrpcConfig`.
  Server identity + client-cert verification land together; there is
  no "TLS-without-mTLS" half-mode. UDS listeners are unchanged
  (file-system permissions remain their auth surface).
  Pre-flight reads each PEM file at config load / `--check` time
  and rejects missing, unreadable, empty, non-PEM, or wrong-kind
  files (e.g., a private-key blob at the cert path) before the
  daemon starts — closes the gap where a successful `--check` could
  be followed by a startup failure during cert rotation.
  *Restart-required:* gRPC listener config — including TLS material
  — does **not** take effect on SIGHUP. The reload path emits an
  explicit `error!` log when `[global.telemetry.grpc_tcp]` or
  `[global.telemetry.grpc_uds]` changes so cert rotation against a
  running daemon fails loudly instead of silently keeping stale
  material. Captured in KNOWN_ISSUES; listener rebind on reload is
  post-v1 scope. Closes the original "No native gRPC TLS" limitation
  and the audit-prep ROADMAP item.

- **Chaos stress-test sweep** (`tests/chaos/`). Three short-running
  harnesses that bounce specific subsystems hard and assert
  post-storm health, complementing the M33 long-running soak:
  - `chaos-flap-storm.sh` — `EnableNeighbor`/`DisableNeighbor` storm
    against M33; verifies daemon stays responsive and memory growth
    < 10 MB across N cycles.
  - `chaos-grpc-churn.sh` — concurrent `AddNeighbor`/`DeleteNeighbor`/
    `SoftResetIn` calls via `xargs -P` against 10.99.0.0/16 churn
    IPs; verifies no deadlock (≥90 % response rate) and no
    `GetHealth` probe failures.
  - `chaos-gr-cycles.sh` — repeated GR cycles against an FRR peer
    (M16 LLGR topology); verifies the RR's stale-sweep / clear-on-
    reconnect lifecycle stays correct across N back-to-back cycles.
  Each writes `tests/chaos/runs/<UTC-timestamp>/{driver.log, samples,
  report.json}` with a clean / needs-attention verdict. Closes ROADMAP
  P3.5 "Peer flap storms", "gRPC churn", "Repeated GR recovery".

- **`match_evpn_route_type` policy clause.** New numeric match field
  on `PolicyStatement` filters EVPN routes by RFC 7432 §7 / RFC 9136
  route type: 1 (EAD per-ES/per-EVI), 2 (MAC/IP), 3 (IMET),
  4 (Ethernet Segment), 5 (IP Prefix). `u8` leaves headroom for
  RFC 9251 6/7/8 without bumping the proto/config schema.
  `RouteContext.evpn_route_type` is `None` for non-EVPN traffic, so
  a set match value never fires on unicast / FlowSpec — operators
  can write EVPN-only deny statements without an extra
  community/RT clause. Wired through TOML config, gRPC
  `PolicyStatement` (proto field 24), and both EVPN policy
  evaluation sites in transport (inbound) and the RIB manager
  (`stage_evpn_routes` outbound). Closes the corresponding ROADMAP
  Pre-v1.0 Polish bullet.

- **EVPN routes in MRT `TABLE_DUMP_V2` snapshots.** Loc-RIB / Adj-RIB-In
  EVPN routes (AFI 25 / SAFI 70) are now emitted as `RIB_GENERIC`
  records (RFC 6396 §4.3.5, subtype 6) alongside the existing IPv4 /
  IPv6 unicast records. Each EVPN route in any peer's Adj-RIB-In
  becomes a single-entry record carrying the encoded EVPN route TLV
  in the record header (via `encode_evpn_nlri`) plus a synthesized
  `MP_REACH_NLRI(AFI=25, SAFI=70, next_hop, evpn_announced=[])` in
  the attribute set. Operators running rustbgpd as an EVPN RR can
  now archive forensic snapshots that actually contain the EVPN
  routes — previously the snapshot path silently skipped them. Type
  2 (MAC/IP) and Type 5 (IP Prefix) round-trip tests cover the wire
  format. See ADR-0044 for the encoding choice.

- **BMP regression test for EVPN `RouteMonitoring`.** The BMP emit
  site at `crates/transport/src/session/io.rs` has no AFI/SAFI
  filter — every inbound UPDATE flows to the collector with raw
  wire bytes, regardless of family. EVPN UPDATEs already reach BMP
  collectors today; the inner `MP_REACH_NLRI` (AFI 25 / SAFI 70)
  tells the collector how to parse. A new transport-side regression
  test (`inbound_evpn_update_emits_bmp_route_monitoring`) pins this
  contract: a future refactor that quietly added a unicast-only
  family gate at the emit site would now fail at build time.

### Changed

- **`rustbgpd-wire` 0.7.0 → 0.8.0 (breaking).** The `MpReachNlri`
  struct gains a new `pub link_local_next_hop: Option<Ipv6Addr>`
  field so received 32-byte IPv6 next-hops (RFC 4760 §3 / RFC 2545)
  round-trip through the wire codec, the RIB, and MRT
  `TABLE_DUMP_V2` snapshots without dropping the link-local
  address. The field is decoded when NH-Len == 32, emitted as the
  32-byte form by `encode_mp_reach_nlri`, plumbed through `Route`
  and `EvpnRibRoute`, and serialized as a 33-byte reduced-form
  `MP_REACH_NLRI` value (NH-Len=32 + 16-byte global + 16-byte
  link-local) by the MRT exporter. Any external caller that was
  constructing `MpReachNlri { ... }` via struct literal will need
  to add `link_local_next_hop: None` (or the actual value). Closes
  the long-standing "IPv6 link-local next-hop discarded"
  KNOWN_ISSUES limitation.

- **`EvpnRibRoute` no longer caches `EvpnRouteKey`.** The struct
  previously stored both the full `EvpnRoute` payload and a cached
  identity key derived from it; the cache had no type-level invariant
  (every construction site had a `let key = route.key();` line that
  the compiler did not enforce), and the HashMap that already keys by
  `EvpnRouteKey` was redundantly carrying the same key inside its
  values. Identity is now derived on demand via `EvpnRibRoute::key()`
  — a one-line wrapper around `EvpnRoute::key()`, which is O(1) and
  allocation-free since `EvpnRouteKey` is `Copy`. Adding RFC 9251
  Route Types 6/7/8 (S-PMSI, IGMP/MLD JOIN/LEAVE) will now only need
  new arms in `EvpnRoute::key()` rather than parallel synchronization
  at every construction site. Internal refactor — no proto-side or
  config-side effects, no behavior change. Closes ROADMAP §198.

### Testing

- **12 h soak extends ADR-0051 writer-split validation.**
  `tests/soak/runs/20260429T004656Z/` ran 12 h sustained 1 k-rps
  EVPN churn against the post-v0.10.0 image with `verdict: clean`:
  slope **+0.0094 MB/h** (essentially zero — the 4 h run's
  -0.10 MB/h drift was within this noise band), 0 drops, 0 flaps,
  0 gRPC health failures, no daemon restart, p99 RSS 85.10 MB,
  4.10 M messages sent / 2.05 M received across 708 samples
  (698 steady-state). Extends the v0.10.0 validation 3× past the
  original +46-min wedge and ~5× past the 4 h reference run.

## [0.10.0] — 2026-04-28

### Added

- **`bool stale = 13` on `NeighborState`.** The gRPC neighbor view
  surfaces a flag indicating that a peer's last `query_state` round-trip
  exceeded its bounded deadline (default 100 ms). `stale = true` means
  the row is fresh-but-uncertain rather than absent: it lets dashboards
  distinguish "peer was Established the last time we got a fast
  answer, but the session task isn't currently responsive" from "peer
  Established right now." `rustbgpctl` (text + JSON) and the TUI
  established-counter / state-column both honor the field — stale rows
  are excluded from the established count and rendered with a distinct
  color in the TUI. Behind-the-scenes, every `query_state` and policy
  hot-apply round-trip in the daemon is now bounded by a deadline; the
  full set of changes that close the +46-min `GetHealth` wedge are
  described under the writer-split entry below.

- **M29 + M30 EVPN interop tests gated in GitHub Actions.**
  `.github/workflows/interop.yml` runs both the L2VPN/EVPN
  capability-negotiation gate (M29) and the Type 2 MAC reflection +
  kernel VXLAN gate (M30) against FRR 10.3.1 on every push and PR.
  Total wall time ~5 min per push (parallel jobs). M30 became viable
  after `tests/interop/scripts/test-lib.sh`'s `start_rustbgpd` helper
  swapped its 3 s fixed sleep for a 10 s poll with diagnostic dump on
  failure (`docker top`, container `/proc/[0-9]*/comm`, 2 s foreground
  rustbgpd capture) — the original sleep was tight under heavy CI
  load. M30b stays manual: ubuntu-latest's Azure-tuned kernel
  (`6.17.0-1010-azure`) ships without the `vrf` module, so the L3VNI
  binding fails on hosted runners. Captured in INTEROP.md and
  ROADMAP "CI wiring for M29-M33".

- **M30b interop: EVPN Type 5 / IP Prefix origination against FRR
  10.3.1.** Single-VTEP containerlab topology
  (`tests/interop/m30b-evpn-type5-frr.clab.yml`) plus the new
  `start-frr-vtep-l3.sh` kernel-setup helper that builds VRF + L3VNI +
  bridge + SVI + VXLAN + tenant loopback so FRR will originate Type 5
  NLRIs (RFC 9136) for a tenant prefix. Test asserts session
  Established, FRR Type 5 origination for `192.0.2.1/32` with
  RD/RT `65000:100`, rustbgpd's `ListEvpnRoutes` surfacing the route
  with correct RD, prefix, next-hop, VNI label, RT ext-community
  (encoded u64 = 842122827661412), VXLAN `tunnel_type=8`, and
  withdrawal propagation. Closes a recurring external-review item
  ("Type 5 wire codec lands but no harness against a real
  implementation"). Manual-only — see the M29/M30 CI entry above for
  why ubuntu-latest can't host the VRF setup. RR-reflection of Type 5
  (2-VTEP variant) tracked as M30c.

- **BMP drop / replay Prometheus counters.** Four new `bmp_*_total`
  metrics surface what previously was only `tracing::warn!` output:
  `bmp_source_drops_total{peer, reason}` for the PeerSession→BmpManager
  mpsc fill, `bmp_collector_drops_total{collector, phase, reason}` for
  the per-collector mpsc fill (with `phase` distinguishing fan-out
  from `PeerUp`-cache replay), `bmp_replay_attempts_total
  {collector}` as the denominator for a "replay drop rate" alert,
  and `bmp_control_event_drops_total{collector, kind, reason}` for
  BMP control events (`collector_connected`, `collector_disconnected`)
  that fail to reach the manager — that path is what makes the
  difference between "the manager is wedged but Prometheus tells you
  so" and "the manager is wedged and your replay metrics are silently
  flat."
  `reason` is parsed from `mpsc::error::TrySendError` (`channel_full` /
  `channel_closed`); the `collector` label uses the SocketAddr string
  for stability across config reloads. Replay aborts attribute every
  remaining cached `PeerUp` message as dropped (not just the first
  failed `try_send`), so a saturated reconnect on a fabric with
  thousands of peers reports the real loss. The collector-side
  `CollectorConnected` event now uses an awaited send with a 1 s
  timeout instead of `try_send` so a wedged manager can't silently
  skip the whole `PeerUp` replay while the collector still looks
  healthy. Operators can now alert on BMP loss without a log scraper.
  Closes the [BMP drop/replay counters](KNOWN_ISSUES.md) gap.

### Fixed

- **Per-peer outbound writer task; eliminates `GetHealth` wedge under
  sustained EVPN churn.** The peer session task no longer owns the TCP
  write half — a new dedicated writer task (one per peer) holds the
  `OwnedWriteHalf` and a bounded bulk channel + an unbounded priority
  channel. The session task encodes BGP messages and enqueues bytes;
  the writer's biased `select!` ensures NOTIFICATION/KEEPALIVE/OPEN
  preempt UPDATE backlog. When the bulk channel fills (peer's TCP
  receive buffer hasn't drained `OUTBOUND_BUFFER = 4096` messages),
  the session emits a `Cease`/`Out of Resources` (RFC 4486 §4 subcode
  8) and tears the session down, replacing today's silent
  `bgp_outbound_route_drops_total` accumulation with an observable
  flap. Together with the bounded `query_state_timeout` containment in
  `0735dd9`, this closes the deterministic +46-min wedge surfaced by
  the M33 1h soak. See [ADR-0051](docs/adr/0051-per-peer-outbound-writer-task.md).
  Validated end-to-end on the M33 soak harness:
  `tests/soak/runs/20260428T150509Z/` ran 4 h sustained 1 k-rps EVPN
  churn with `verdict: clean` — 0 drops, 0 flaps, 0 gRPC health
  failures, no daemon restart, memory slope -0.10 MB/h (drifted
  *down*, well inside the 0.5 MB/h clean-tier threshold), p99 RSS
  83.76 MB, 1.36 M messages sent. The 1 h post-fix run on
  `20260427T230448Z/` is the original validation; the 4 h run extends
  it ~5× past the original +46-min wedge with the same headline
  numbers. Internal architectural change — no proto-side or
  config-side effects beyond the new `bool stale = 13` field on
  `NeighborState` added in `0735dd9`.

- **`evpn-load` testers drain inbound traffic.** The synthetic-peer
  testers under `bench/evpn-load` previously held only the `tx` side
  of their `PeerHandle` — they injected routes but never read inbound
  reflections. `PeerHandle.rx` is backed by a 65 536-deep mpsc that
  the reader task back-pressures on `send().await`; under sustained
  churn the channel filled in ~43.7 minutes, parking the reader on
  send, filling the kernel TCP receive buffer, and triggering ADR-0051's
  saturation handler on the rustbgpd side. Fix is a discard task
  spawned next to the tester's send loop, plus a rustdoc warning on
  `PeerHandle.rx` so future load-test authors don't recreate the same
  trap. Production rustbgpd was never affected — real BGP peers
  always drain their inbound. See `tests/soak/runs/20260427T172938Z/`
  for the saturation reproducer and `20260427T230448Z/` for the clean
  post-fix run.

### Testing

- **M33 long-running soak harness** at `tests/soak/run-m33-soak.sh`
  extends the M33 EVPN scale topology to arbitrary durations (default
  24 h, `SOAK_HOURS` / `SOAK_SEC` overrides for shorter runs). Samples
  cgroup RSS + Prometheus counters every minute into `samples.csv`;
  runs a stdlib-only Python analyzer (`tests/soak/analyze-soak.py`)
  that gates on memory slope, peak RSS, session flap delta, drop
  delta, gRPC health continuity, and process-restart detection
  (counter monotonicity). The fix-validation infrastructure behind
  ADR-0051 — the harness surfaced the original +46-min wedge and
  produced the 1 h + 4 h clean-verdict runs cited above.

- **Bisection flags on `evpn-monitor`.** `--no-live-set` and
  `--no-parse` let an investigator turn off the live-set tracker and
  the per-message parse to isolate what's contributing to a
  saturation event. Periodic stats logging every 5 s, plus a
  `LifetimeStats` block in the final JSON report (renames the inner
  helper to `apply_evpn_instrumented` so per-call NLRI counts and
  parse-failure flags are visible to the bisection flags). Used to
  rule out daemon-side parse pressure during the +49-min wedge
  investigation that ultimately turned out to be the load-test bug
  fixed above.

## [0.9.0] — 2026-04-26

### Added

- **EVPN Route Reflector (Phase 1, RFC 7432).** L2VPN/EVPN address family
  (AFI 25 / SAFI 70) with wire codec for all 5 RFC 7432 route types
  (EAD per-ES, EAD per-EVI, MAC/IP, IMET, Ethernet Segment, IP Prefix),
  MAC mobility best-path with sticky-flag preservation per §15.1, RFC 4456
  reflection, and 6 typed extended-community accessors (BGP Encapsulation
  per RFC 8365/9012, MAC Mobility, ESI Label, ES-Import RT, Router MAC
  per RFC 9135, Default Gateway). `l2vpn_evpn` family string in TOML
  config, `ListEvpnRoutes` gRPC RPC on `RibService`, `rustbgpctl evpn`
  CLI subcommand with `--route-type` / `--peer` / `--rd` filters,
  `ADDRESS_FAMILY_L2VPN_EVPN` proto enum. Example config
  `examples/rr-evpn-fabric/config.toml` demonstrates a 3-VTEP fabric RR.
  FRR interop sanity test M29 validates capability negotiation against
  FRR 10.3.1. See [ADR-0050](docs/adr/0050-evpn-route-reflector.md).
  Phase 1 is RR role only — VTEP mode with local EVI/VRF/VNI state
  (kernel FDB MAC learning + local origination), controller injection
  beyond Type 2 / Type 3 (Type 5 IP-Prefix, Type 1 / Type 4
  multi-homing origination), DF election (RFC 7432 §8 / RFC 8584),
  symmetric IRB semantics (RFC 9135), PBB-EVPN (RFC 7623), and EVPN-
  MVPN integration (RFC 9251) are future-phase work. Gate 6 ships
  controller-driven Type 2 / Type 3 injection via
  `AddEvpnRoute` / `DeleteEvpnRoute`.
- **EVPN Type 2 MAC reflection interop (Gate 1, M30).** Three-node
  containerlab topology (rustbgpd RR + 2× FRR VTEPs running kernel
  VXLAN + bridge) validating Type 2 MAC/IP Advertisement reflection
  end-to-end. MAC injected on VTEP-A via `bridge fdb add` propagates
  through rustbgpd and appears on VTEP-B's `show evpn mac vni 100`
  within 30 seconds. Assertions cover: session Established on both
  VTEPs with L2VPN/EVPN negotiated, Type 3 IMET reflection (baseline),
  Type 2 MAC learning end-to-end, RFC 4456 `ORIGINATOR_ID` + `CLUSTER_LIST`
  on the reflected UPDATE, next-hop preservation (VTEP loopback, not RR),
  VXLAN encap community (`tunnel_type=8`) surfaced through the
  `ListEvpnRoutes` gRPC, and withdrawal propagation via
  `bridge fdb del`. New `start-frr-vtep.sh` shim sets up `br100` +
  `vxlan100` with `nolearning` so EVPN controls the FDB.
- **EVPN GR / LLGR stale handling (Gate 2, RFC 4724 + RFC 9494).**
  Reflected EVPN routes now participate in the stale-route pipeline:
  `mark_stale_evpn` on `PeerGracefulRestart`, promotion to LLGR-stale
  with `LLGR_STALE` community injection via `Arc::make_mut`, and sweep
  on GR / LLGR timer expiry. End-of-RIB and Enhanced Route Refresh
  (BoRR / EoRR per RFC 7313) clear stale state per-family, preserving
  peer-originated `LLGR_STALE` communities and stripping only locally-
  injected ones. `NO_LLGR` community per RFC 9494 §4.7 is honored —
  routes carrying it are dropped on GR timer rather than promoted.
  Without this, a VTEP restart would have dropped reflected EVPN routes
  from every other peer mid-flap — the biggest correctness gap on the
  production-ready RR checklist. 13 new unit + integration tests.
- **EVPN MAC mobility + sticky-MAC preservation interop (Gate 3, M31).**
  Four-node topology (rustbgpd RR + 3× FRR VTEPs) extending the M30
  harness. Exercises RFC 7432 §15.1 MAC Mobility semantics against
  real FRR 10.3.1: (a) MAC M1 injected on VTEP-A reflects to VTEP-B
  via the RR; (b) M1 moved to VTEP-C (`bridge fdb add` on C + `del`
  on A), VTEP-B's best path flips to VTEP-C and the MAC Mobility
  sequence number on the reflected Type 2 increments strictly; (c)
  sticky MAC M2 on VTEP-A (`bridge fdb add … sticky`) is not
  displaced by a non-sticky advertisement from VTEP-C — VTEP-B's
  best path stays on VTEP-A per §7.7. VTEP-B is a pure observer
  with no local MACs, so its Loc-RIB state is driven entirely by
  what rustbgpd reflects.
- **EVPN multi-homing Type 1 EAD + Type 4 ES reflection interop
  (Gate 4, M32).** Four-node topology where VTEP-A and VTEP-C share
  an Ethernet Segment via identical `evpn mh es-id` + `evpn mh
  es-sys-mac` on an LACP bond ES interface (single dummy slave —
  the minimal shape FRR EVPN-MH recognizes as a local ES). rustbgpd
  reflects both Type 4 ES and Type 1 EAD-per-EVI routes unchanged;
  VTEP-B (observer) receives both peers' copies with correct RFC 4456
  `ORIGINATOR_ID` + `CLUSTER_LIST`. rustbgpd's `ListEvpnRoutes` gRPC
  surfaces both Type 4 + both Type 1 routes (one of each per sharing
  peer). The RR does not execute DF election itself — VTEPs run the
  election independently over the reflected inputs. The
  `start-frr-vtep-mh.sh` shim extends M30's VXLAN setup with the
  bond ES access interface and a vtysh-based EVPN-MH config apply
  loop that handles FRR's startup-delay timer and per-interface
  config race.
- **EVPN RR scale validation (Gate 5, M33).** In-tree iBGP load
  generator (`bench/evpn-load` crate — tester + monitor binaries
  built directly on `rustbgpd-wire`, no third-party daemon in the
  measurement path). Three-peer topology: 2 testers originate 25k
  Type 2 MAC/IP routes each (50k total) at 5,000/sec; 60 s of
  1,000/sec churn (withdraw + re-advertise) layered on top; monitor
  asserts initial convergence (< 60 s ceiling), post-churn count
  within ±tester batch (40 routes) of 50,000, observed withdrawal
  events ≥ ½·`CHURN_RATE`·`CHURN_DURATION` (proves churn fired and
  withdrawals propagated), tester peers stay Established without
  flaps, and rustbgpd's gRPC stays healthy throughout. Binaries ride
  the `rustbgpd:dev` image so a single `docker build` + `containerlab
  deploy` reproduces the harness.
- **Controller-driven EVPN injection (Gate 6).** Two new RPCs on
  `InjectionService`: `AddEvpnRoute` and `DeleteEvpnRoute`. Phase 1
  supports Type 2 MAC/IP and Type 3 IMET origination; the
  controller supplies RD, ethernet-tag, MAC, host IP, VNI, next-hop,
  and optional route targets, and the RR synthesizes an
  `EvpnRibRoute` with `RouteOrigin::Local` that flows through the
  same reflection pipeline that serves iBGP-learned routes. New
  `rustbgpctl evpn add-mac-ip / add-imet / delete-mac-ip / delete-imet`
  subcommands. Includes 10 new unit tests covering RD parsing
  (types 0/1/2), MAC parsing, VNI validation, unsupported route
  types, read-only access-mode rejection, and end-to-end RIB
  channel round-trip.
- **Four correctness fixes in the EVPN RR pipeline** (commit
  7d09108, surfaced during code review):
  (1) source-peer split-horizon for EVPN — the RR no longer reflects
      a route back to its originator;
  (2) `LocRib::recompute_evpn` detects same-peer attribute / payload
      churn (MAC Mobility sequence, sticky flip, label/VNI, Router
      MAC, ESI Label) — previously only peer + stale flags triggered
      redistribution;
  (3) `evpn_tiebreak_simple` gets stale, ORIGIN, `CLUSTER_LIST`
      length, and `ORIGINATOR_ID` comparators — matches the
      `flowspec_tiebreak` chain and stops GR-stale routes from beating
      fresh alternatives on LocalPref/AS_PATH;
  (4) RFC 4456 loop-detection inbound path now propagates EVPN
      withdrawals alongside unicast + FlowSpec — no more silent drops
      on reflected-loop UPDATEs.
  Seven new regression tests land with the fixes.

---

## [0.8.0] — 2026-03-23

### Added

- **Dynamic prefix-based neighbors.** Accept inbound sessions from any peer
  matching a configured IP prefix range (`[[dynamic_neighbors]]`), with peer
  group inheritance, `remote_asn = 0` (accept any ASN from OPEN), automatic
  peer slot management, and config validation. `ListDynamicNeighbors` gRPC RPC
  and `is_dynamic` flag in peer state.
- **RPKI/ASPA import policy validation.** Import policy can now apply
  origin-validation and ASPA upstream-path-verification results to filter or
  tag incoming routes. Transport sessions receive the current VRP + ASPA
  tables via `tokio::sync::watch` channel.
- **FlowSpec interop test (M22).** Injection, distribution to FRR, withdrawal.
- **GoBGP interop test (M23).** Bidirectional route exchange against GoBGP 4.3.0.
- **BMP collector interop test (M24).** Python receiver validates message types.
- **TCP MD5 + GTSM interop test (M25).** Two FRR peers with transport security.
- **Cease subcode interop test (M26).** Max-prefix Cease/1 handling with FRR.
- **ASPA/RTR v2 cache interop test (M27).** Validates RTR v2 session setup
  and ASPA data delivery against a Python RTR v2 mock server.
- **Dynamic neighbor interop test (M28).** FRR auto-accepted via
  `[[dynamic_neighbors]]` prefix range, auto-removed on disconnect.
- **Shared test library.** `test-lib.sh` with pre-flight checks, timestamps,
  common helpers — deduplicated across all interop scripts.
- **Duplicate BMP collector detection.** Config validation rejects duplicate
  collector addresses.
- **Policy helper deduplication.** Extracted shared `policy_helpers.rs` from
  `policy_service.rs` and `peer_group_service.rs`.

### Fixed

- **Peer slot leak on dynamic neighbor start failure.** Dynamic peers are only
  inserted and counted after `handle.start()` succeeds, preventing slot leaks
  on failed inbound starts.
- **Config validation hardening.** `remote_asn = 0` rejected for static
  neighbors; impossible prefix lengths rejected for dynamic ranges.
- **BMP duplicate detection canonicalized through `SocketAddr`.** Previously
  used string comparison, which could miss equivalent addresses.
- **M11 GR test flake.** Replaced `sleep 10` with EoR polling loop.
- **M22 FlowSpec test race.** Fixed race condition in withdrawal rule 2 check.
- **M21 RPKI interop switched from GoRTR to StayRTR.**

---

## [0.7.0] — 2026-03-14

### Added

- **Best-path explain.** New `RibService.ExplainBestPath` RPC and
  `rustbgpctl rib --prefix X --explain` show all candidates for a prefix with
  the decisive comparison reason (`BestPathReason` enum) for each non-winner.
  Winner is excluded from the candidate list and returned in a dedicated `best`
  field. `--explain` is rejected with a clear error when used with rib
  subcommands other than the default best-routes view.
- **Birdwatcher-compatible looking glass API.** Optional axum HTTP server
  exposing `/status`, `/protocols/bgp`, `/routes/protocol/{id}`, and
  `/routes/peer/{peer}`. Response shapes match birdwatcher field names for
  looking glass frontend consumption (Alice-LG, etc.). Configured via
  `[global.telemetry.looking_glass]`. Not yet integration-tested against
  Alice-LG.
- **Optional Prometheus metrics listener.** `prometheus_addr` is now optional.
  If absent, no metrics HTTP server is started; metrics are still collected for
  gRPC health and internal counters.
- **RTR/RPKI cache interop test (M21).** Containerlab scenario with StayRTR
  serving static VRPs. 12 assertions covering RTR session establishment, VRP
  delivery, and origin validation (Valid/Invalid/NotFound) visible via gRPC.

### Fixed

- **RTR v2→v1 version fallback against real caches.** GoRTR and StayRTR
  disconnect on unsupported protocol versions instead of sending RFC 8210
  error code 4. The RTR client now also falls back to v1 when the connection
  is closed without completing a handshake, and preserves the v1 downgrade
  across reconnection attempts. The underlying server-side race was later
  fixed upstream in [bgp/stayrtr#167](https://github.com/bgp/stayrtr/pull/167)
  (merged 2026-04-13); the client-side workaround stays in place to support
  older StayRTR / GoRTR builds.

---

## [0.6.0] — 2026-03-14

### Added

- **ASPA upstream path verification.** Validates AS_PATH
  customer-provider relationships to detect route leaks. RTR v2 support with
  automatic v1 fallback, ASPA PDU type 11 codec, `AspaTable` with multi-record
  merge, upstream verification algorithm per
  draft-ietf-sidrops-aspa-verification. Best-path step 0.7 (Valid > Unknown >
  Invalid) between RPKI and LOCAL_PREF. `match_aspa_validation` in import and
  export policy. `aspa_state` exposed in gRPC Route responses. Import
  validation is best-effort against the current snapshot — see validation
  snapshot delivery. Downstream verification deferred. (ADR-0049)

### rustbgpd-wire 0.6.0

- Added `AspaValidation` enum (`Valid`, `Invalid`, `Unknown`) with `Display`,
  `FromStr`, `Default`, `Hash`, and `Eq` implementations.

---

## [0.5.1] — 2026-03-13

### Added

- **Config reload dry-run (`rustbgpd --diff`).** Preview what a SIGHUP reload
  would change before sending it. Output grouped into three sections:
  reload-applied (neighbor add/remove/modify), restart-required
  (global/rpki/bmp/mrt), and informational (peer-group/policy changes not yet
  reconciled by current SIGHUP path). Supports `--json` for scripting with
  `has_actionable_changes`, `has_informational_changes`, and `has_any_changes`
  flags. Exit code 1 = actionable changes found, 0 = no actionable changes.
- **Multi-implementation feature comparison.** New `docs/COMPARISON.md` compares
  rustbgpd against FRR, BIRD, GoBGP, and OpenBGPd across address families, core
  protocol, policy, security, observability, API, and operations.

### Changed

- **Wire crate version decoupled from workspace.** `rustbgpd-wire` now has its
  own explicit version in `crates/wire/Cargo.toml` instead of inheriting from the
  workspace. All internal crates are marked `publish = false`. Wire crate is only
  published when `crates/wire/` actually changes.
- **Roadmap aligned with market research.** Added "Next Up" section with ASPA
  verification, birdwatcher-compatible looking glass API, and best-path explain.
  Built-in looking glass replaced by API-first approach. Deprioritized EVPN/VPN,
  YANG/NETCONF.

---

## [0.5.0] — 2026-03-12

### Fixed

- **Reliable GR / route-refresh control delivery.** Inbound `EndOfRib`,
  `RouteRefreshRequest`, `BeginRouteRefresh`, `EndRouteRefresh`, and
  transport lifecycle updates (`PeerUp`, `SetPeerPolicyContext`, `PeerDown`,
  `PeerGracefulRestart`) now use reliable `send(...).await` delivery to the
  RIB instead of lossy `try_send`, eliminating dropped control messages when
  the RIB channel is full.
- **GR timer vs buffered `EoR` race.** Before firing GR, LLGR, or refresh
  timer sweeps, the RIB manager now drains already-buffered main-channel
  updates so a buffered `EndOfRib` is processed before stale routes are swept.
- **Injection API zero-value `local_pref` / `MED`.** `AddPathRequest`
  `local_pref` and `med` are now presence-based optional fields, so valid
  zero values can be injected instead of being silently treated as unset.
- **Peer-group / policy API validation parity.** Peer-group family strings and
  `remove_private_as` values now reuse the dynamic-neighbor validation helpers,
  and `PolicyService` / `PeerGroupService` reject invalid policy action strings
  at the API boundary.
- **AS_PATH segment encode overflow.** `AS_SEQUENCE` and `AS_SET` segments
  longer than 255 ASNs are now split into multiple wire segments during
  encode instead of silently truncating the length via `u8` wraparound.
- **Adj-RIB-In teardown cleanup.** `PeerDown` now removes empty per-peer
  `AdjRibIn` entries entirely, and unicast withdraw chunks trigger intern-table
  garbage collection to prevent orphaned attribute intern entries from growing
  without bound under churn.
- **Route explain global export policy fallback.** `ExplainAdvertisedRoute`
  now uses the per-peer → global export policy fallback (via
  `export_policy_for()`), matching the actual distribution path. Previously
  it only checked per-peer export policy, returning incorrect results for
  peers using the global default.
- **Drain pending route batches on PeerDown/GR.** `handle_peer_down()` and
  `handle_peer_graceful_restart()` now drain any in-progress chunked route
  batches for the departing peer. Previously, pending chunks could be
  processed after the peer's RIB was cleared, re-inserting ghost routes.
- **FSM double-increment of connect_retry_counter on DecodeError.** The
  `DecodeError` handler in Connect, Active, OpenSent, OpenConfirm, and
  Established states incremented the counter before calling
  `enter_idle_with_notification()` / `enter_idle_silent()`, which also
  increments — resulting in double-counting. Removed the redundant
  increment from all five handlers.
- **FlowSpec routes not stale-marked or swept during GR/LLGR.** Graceful
  restart and LLGR now correctly mark, sweep, promote, and clear stale
  flags on FlowSpec routes alongside unicast routes. Added
  `promote_to_llgr_stale_flowspec()`, `sweep_llgr_stale_flowspec()`,
  `clear_llgr_stale_flowspec()`, and `sweep_stale_flowspec_family()` to
  `AdjRibIn`. End-of-RIB handling now clears FlowSpec stale/LLGR-stale
  flags for the completed family, recomputes/distributes affected
  FlowSpec routes, and removes locally injected `LLGR_STALE`
  communities when the route returns to fresh state.
- **IPv6 export next-hop rewrite locked down.** Export policy
  `set_next_hop = "<ipv6>"` is now covered by transport and explain
  regression tests, confirming the MP_REACH export path and
  `ExplainAdvertisedRoute` report the same effective IPv6 next hop.
- **LLGR_STALE stripped for non-LLGR peers.** Outbound transport now removes
  the `LLGR_STALE` community when the destination peer did not negotiate
  LLGR for that family, matching RFC 9494 §4.6. LLGR-capable peers still
  receive the community unchanged.

### Added

- **Rustc-style config error diagnostics.** Config validation errors now show
  the offending TOML source line with column markers and underlined spans, like
  `rustc` error messages. Uses `toml_edit::ImDocument` for span-preserving
  key/value lookup on semantic errors, and `toml::de::Error::span()` for parse
  errors. Falls back to plain text when no span is available.
- **Minimal export route explain.** New `RibService.ExplainAdvertisedRoute`
  and `rustbgpctl rib advertised <peer> --prefix <CIDR> --explain` explain
  whether the current best route for one prefix would be advertised to one peer,
  including decisive reasons and any export modifications. This v1 scope is
  export-only. Import explain and named policy/statement attribution are not
  yet implemented.
- **Per-peer log level filtering.** New `log_level` field on `[[neighbors]]`
  and `[peer_groups.<name>]` overrides the global `RUST_LOG` level for
  individual peers. Each peer session runs inside a tracing span with
  `peer_addr`, `remote_asn`, and `peer_group` fields, enabling targeted
  filtering via config (`log_level = "debug"`) or environment
  (`RUST_LOG=info,peer{peer_addr=10.0.0.1}=debug`).
- **gRPC priority query channel.** Read-only gRPC queries (neighbor list, RIB
  queries, control RPCs) now use a dedicated channel with bounded fair
  scheduling (8 queries per route chunk). This prevents management API stalls
  during bulk route loading — previously queries could block for 60+ seconds
  behind thousands of queued route updates.
- **Chunked RIB processing.** Large `RoutesReceived` batches are now split
  into 1024-prefix chunks with per-chunk recompute/distribute. Between chunks,
  bounded query servicing and timer checks proceed. Main channel ordering is
  preserved: control messages (EoR, PeerDown) cannot overtake unfinished route
  work. At 200k prefixes, convergence improved from 103s to 74s (28%).
- **AdjRibIn pre-sizing.** New `AdjRibIn::with_capacity()` constructor uses
  first-batch size hints to pre-allocate routes, prefix index, and intern
  table, reducing HashMap rehash stalls during bulk insert.
- **Outbound UPDATE construction optimization.** The export hot path now uses
  `try_reserve`-based enqueue/commit to avoid clone-before-send overhead,
  pointer fast-paths in route equality, hash-indexed attribute grouping, and
  per-call prepared-attribute caching in `send_route_update()`. This reduces
  per-route allocation and repeated attribute rewrites during large outbound
  batches without changing wire behavior.
- **AdjRibOut secondary prefix index.** `AdjRibOut` now maintains a
  `HashMap<Prefix, SmallVec<[u32; 1]>>` secondary index for O(1) per-prefix
  path ID lookup. Previously, `path_ids_for_prefix()` and `iter_prefix()`
  scanned the entire route HashMap — O(N) per call, called per-prefix during
  outbound distribution. At 200k routes this caused a 560x cost blowup
  (1.4 µs/prefix early → 780 µs/prefix late). With the index, 200k-prefix
  convergence dropped from 71s to 12s (5.9x improvement).

### Changed

- **ConnectRetryTimer default reduced to 5 seconds.** The BGP connect retry
  interval now defaults to 5s (down from 30s), reducing session establishment
  delay when the first outbound connection attempt fails. The exponential
  backoff progression is now 5→10→20→40→80→160→300s.

---

## [0.4.3] — 2026-03-06

### Added

- **Policy CRUD via gRPC.** New `PolicyService` adds named policy definition
  CRUD plus global/per-neighbor chain assignment at runtime. Successful
  mutations hot-apply to the running daemon, persist back to TOML, and reuse
  the existing named-policy / chain model from ADR-0036. Import-chain changes
  affect future inbound UPDATE processing; operators use `SoftResetIn` when
  they want existing Adj-RIB-In state re-evaluated. Export-chain changes
  trigger immediate outbound recomputation.
- **Peer groups via gRPC.** New `PeerGroupService` adds full-replace peer-group
  CRUD plus neighbor membership assignment. Effective peer config is resolved
  through the existing config/peer-manager boundary and persisted back to TOML.
- **Peer-aware policy matching.** Policy statements now support
  `match_neighbor_set`, `match_route_type`, `match_local_pref_ge/le`, and
  `match_med_ge/le`. Neighbor sets are managed under `PolicyService`, persist to
  TOML, and evaluate against the current policy peer context on both import and
  export.
- **Exact next-hop policy matching.** Policy statements now support
  `match_next_hop` for unicast routes on both import and export. The field is
  available in TOML config and the gRPC `PolicyService`, persists through config
  snapshots, and evaluates as exact IPv4/IPv6 equality.
- **`--version` and `--check` flags.** Both `rustbgpd --version` and
  `rustbgpctl --version` now print the version. `rustbgpd --check config.toml`
  validates config and exits without starting the daemon.
- **Shell completions.** `rustbgpctl completions {bash,zsh,fish}` generates
  shell completions. Pre-generated files shipped in `examples/completions/`.
- **Startup banner.** The daemon now prints a human-friendly topology summary
  on startup: ASN, router-id, peer counts by type, peer groups, named policies,
  listener endpoints, and optional subsystems (RPKI, BMP, MRT).
- **FlowSpec route-server transparency.** `route_server_client = true` now skips
  automatic eBGP AS_PATH prepend on FlowSpec export too, matching transparent
  unicast behavior. FlowSpec still has no `NEXT_HOP` field on the wire.
- **Colored CLI output.** `rustbgpctl` now uses colored session states
  (green=Established, yellow=OpenSent/Connect/OpenConfirm, red=Idle/Active),
  colored best-path markers, colored health/event output, human-readable
  uptimes ("2d 4h 12m"), and dynamically aligned table columns. Colors
  auto-disable when piped. Use `--no-color` or `NO_COLOR=1` to force plain
  output.
- **Live TUI dashboard.** `rustbgpctl top` launches a terminal UI (ratatui)
  showing sessions, prefix counts, message rates, RPKI VRP counts, and
  streaming route events — all updating live. Peer table with sort (cycle
  with `s`/`S`), detail view (`Enter`), toggleable events panel (`e`), and
  help overlay (`h`). Configurable poll interval (`-i`). Think `htop` for
  BGP.
- **Docker Compose quick-start.** New `examples/docker-compose/` spins up
  rustbgpd peered with FRR (4 IPv4 + 3 IPv6 sample prefixes) in a single
  `docker compose up -d`. gRPC exposed on localhost:50051 for immediate
  `rustbgpctl` use from the host.
- **Per-listener gRPC access mode.** Each configured gRPC listener (TCP or UDS)
  can independently set `access_mode = "read_write"` (default) or `"read_only"`.
  Read-only listeners allow query and watch RPCs but reject all mutating RPCs
  (neighbor add/delete, route injection, policy changes, peer-group changes,
  shutdown, MRT trigger) with `PERMISSION_DENIED`. Intended for monitoring or
  dashboard listeners that should not expose control-plane writes.
- **CLI gRPC integration tests.** `rustbgpctl` commands now have mock-server
  integration tests over both TCP (with bearer token auth) and Unix domain
  sockets, covering health, global, neighbor add, and soft-reset RPC paths.
- **BMP transport-path tests.** Session-to-BMP emission points (PeerUp,
  PeerDown, RouteMonitoring) are now covered by transport crate tests.
- **M17-M20 interop tests.** Four new containerlab test suites validated
  against FRR 10.3.1: Add-Path multi-path send (15 assertions), Extended
  Next-Hop dual-stack (9), Transparent Route Server with NH preservation and
  AS_PATH transparency (13), Private AS Removal in remove/all/replace modes
  (22). Total: 59 new interop assertions.

### Fixed

- **CLI `NO_COLOR` handling.** `rustbgpctl` now treats `NO_COLOR` as a
  presence-based runtime override instead of asking clap to parse it as a
  boolean, so environments with `NO_COLOR=1` no longer break argument parsing.
- **CLI uptime display.** Zero-second uptimes now render as `00:00:00`
  instead of `never`.
- **Use-case command examples.** `docs/USE_CASES.md` now uses the actual
  `rustbgpctl` command surface and a gRPC example for peer-group assignment.

---

## [0.4.2] — 2026-03-06

First public alpha release. No protocol changes from v0.4.1 — this release
focuses on operator experience, documentation accuracy, and release hygiene.

### Added

- **Operations guide** (`docs/OPERATIONS.md`). Covers configuration reload
  (SIGHUP), upgrade procedure, state persistence, failure modes for gRPC /
  RPKI / BMP / MRT, key metrics and log messages, session debugging, and
  common operational tasks.

- **Example configs.** Minimal single-peer config (`examples/minimal/`) and
  IXP route-server config with RPKI, Add-Path, and policy chains
  (`examples/route-server/`).

- **systemd unit** (`examples/systemd/rustbgpd.service`). Hardened with
  `ProtectSystem=strict`, `NoNewPrivileges`, `CAP_NET_BIND_SERVICE`, and
  `ExecReload` for SIGHUP.

- **Release checklist** (`docs/RELEASE_CHECKLIST.md`). Pre-release smoke
  matrix covering CLI, UDS, token auth, interop, and Docker.

- **Container image CI** (`.github/workflows/container.yml`). Publishes to
  GHCR with semver tags on version tag push.

- **Issue and PR templates.** Bug report, feature request, and pull request
  templates.

- **CI rustdoc gate.** `cargo doc --workspace --no-deps` with `-D warnings`.

- **Project status statement** in README. Explicit alpha expectations for
  config/API stability, supported OS, and target use case.

### Fixed

- **CLI examples in docs.** All `rustbgpctl` examples now match actual CLI
  syntax (`neighbor <addr> add --asn`, `neighbor <addr> softreset`,
  `rib received <addr>`, etc.).

- **Build command.** README, CONTRIBUTING.md, Dockerfile, and release
  checklist now use `cargo build --workspace --release` to build both
  `rustbgpd` and `rustbgpctl`.

- **systemd config persistence.** Unit file now includes `/etc/rustbgpd` in
  `ReadWritePaths` so gRPC `AddNeighbor`/`DeleteNeighbor` can persist to the
  config file under `ProtectSystem=strict`.

- **Non-root quickstart.** Minimal example uses `runtime_state_dir =
  "/tmp/rustbgpd"` so the quickstart works without root. README documents
  `RUSTBGPD_ADDR` env var for matching UDS path.

- **RTR reconnect docs.** Operations guide now correctly says "fixed
  retry_interval" instead of "exponential backoff" for RTR client reconnect.

- **Dockerfile.** Now includes `rustbgpctl` in the image and uses a
  production-friendly default CMD. Interop clab topologies updated with
  explicit `cmd: sleep infinity` override.

---

## [0.4.1] — 2026-03-06

### Added

- **Secure-by-default gRPC listeners.** The daemon now defaults to a local Unix
  domain socket at `/var/lib/rustbgpd/grpc.sock` instead of loopback TCP. TCP
  gRPC listeners are now explicit config via `[global.telemetry.grpc_tcp]`,
  local UDS can be configured via `[global.telemetry.grpc_uds]`, and both may
  run concurrently. Optional per-listener bearer-token authentication is
  available via `token_file`. `rustbgpctl` now supports `unix:///...` endpoints
  and `--token-file` / `RUSTBGPD_TOKEN_FILE`. Security docs and the Envoy mTLS
  example were updated to reflect the new operator posture.

- **Interop tests M13–M16.** Four new containerlab test suites: policy engine
  with chain accumulation (M13, 15 assertions), route reflector with
  ORIGINATOR_ID/CLUSTER_LIST validation (M14, 14 assertions), route refresh via
  SoftResetIn (M15, 10 assertions), and LLGR GR→stale transition (M16, 8
  assertions). All 10 interop suites now pass (130 total assertions).

### Fixed

- **Route reflector config wiring.** `route_reflector_client` was not copied
  from the neighbor config to `TransportConfig`, so route reflection was
  non-functional when configured via TOML (gRPC dynamic peers were unaffected).

- **M10 IPv6 interop test.** FRR static IPv6 routes via `fd00::2` were
  unreachable in the container, preventing IPv6 prefix advertisement. Changed
  to `Null0` blackhole routes.

---

## [0.4.0] — 2026-03-06

### Added

- **Enhanced Route Refresh (RFC 7313).** Capability code 70 is now
  advertised alongside RFC 2918 Route Refresh. ROUTE-REFRESH message type 5
  now models subtype `0/1/2` (Normal/BoRR/EoRR). `SoftResetIn` gains
  family-scoped replacement semantics for ERR-capable peers: inbound `BoRR`
  marks current routes refresh-stale, refreshed announcements/withdrawals
  clear replaced entries, and inbound `EoRR` sweeps unreplaced state.
  Active ERR windows now also have a fixed 5-minute timeout, which performs
  the same unreplaced-state sweep if `EoRR` never arrives.
  Outbound route-refresh responses emit `BoRR -> routes -> EoRR` for ERR
  peers while preserving existing `routes -> EndOfRib` behavior for
  RFC 2918-only peers. (ADR-0038)

- **Extended Next Hop (RFC 8950).** Capability code 5 is now advertised
  automatically for dual-stack unicast peers. IPv4 unicast NLRI can be
  received and advertised via `MP_REACH_NLRI` / `MP_UNREACH_NLRI` with an
  IPv6 next hop. Existing peers that do not negotiate RFC 8950 keep the
  legacy body-NLRI + `NEXT_HOP` encoding. Add-Path for IPv4 unicast remains
  compatible in both legacy and RFC 8950 MP-encoding modes. (ADR-0037)

- **Policy chaining + named policies (ADR-0036).** Named policy definitions
  in TOML with configurable `default_action` (permit or deny). Policy chains
  reference named policies by name in ordered sequences. GoBGP-style chain
  semantics: permit accumulates modifications and continues, deny stops
  immediately, implicit permit after all policies. Backward compatible —
  existing inline `import_policy`/`export_policy` entries still work.
  `RouteModifications::merge_from()` accumulates across chain steps (scalars:
  later wins; lists accumulate, with later conflicting add/remove operations
  winning). New TOML syntax: `[policy.definitions.*]`,
  `import_chain`/`export_chain` on global and per-neighbor.

- **Admin shutdown communication (RFC 8203).** DisableNeighbor gRPC reason
  field is now propagated through to the Cease/2 (Administrative Shutdown)
  NOTIFICATION data as a 1-byte length + UTF-8 string (max 128 bytes).
  Inbound Cease/2 and Cease/4 NOTIFICATIONs with shutdown communication
  are decoded and logged. Wire helpers: `encode_shutdown_communication()`
  and `decode_shutdown_communication()` in the notification module.
- **Notification GR (RFC 8538).** GR capability now advertises the N-bit
  (notification support). NOTIFICATION-triggered teardown now preserves routes
  only when both sides negotiated N-bit support. Cease/Hard Reset (subcode 9)
  sent or received bypasses Graceful Restart, forcing immediate route purge
  instead of stale preservation. Completes the GR story alongside ADR-0024 (helper),
  ADR-0040 (restarting speaker), and ADR-0042 (LLGR). (ADR-0046)
- **AS_PATH length matching in policy.** New `match_as_path_length_ge` and
  `match_as_path_length_le` fields on policy statements for inclusive
  range-based AS_PATH length filtering. Fields can be used independently or
  together (AND logic), and work standalone or combined with existing match
  criteria (prefix, community, regex, RPKI). `AS_SET` counts as 1 per
  RFC 4271.
- **Private AS removal.** New per-neighbor `remove_private_as` config strips
  private ASNs (64512–65534, 4200000000–4294967294) from AS_PATH before
  eBGP advertisement. Three modes: `"remove"` (entire path must be private),
  `"all"` (unconditional), `"replace"` (substitute local ASN). Applied before
  local ASN prepend in both unicast and FlowSpec outbound paths. eBGP only;
  route-server clients skip. (ADR-0045)
- **Transparent route server mode.** Static neighbor config now supports
  `route_server_client = true` for eBGP peers. Outbound unicast
  advertisements to route-server clients preserve the original next hop and
  skip the automatic local-AS prepend normally applied on eBGP export.
  Explicit export-policy next-hop overrides still win. RFC 8950 IPv4 over
  IPv6 next-hop and IPv6 unicast both honor the same transparent behavior.
  FlowSpec transparency remains deferred. (ADR-0039)
- **Graceful Restart restarting speaker (minimal mode).** Static peers now
  advertise GR `restart_state = true` after a coordinated daemon restart
  when a persisted marker file is present in `global.runtime_state_dir`.
  This is an honest helper-to-speaker bridge only: `forwarding_preserved`
  remains false for all families, and dynamic gRPC-added peers do not
  participate in the restart window. (ADR-0040)
- **FlowSpec fuzz target.** New `decode_flowspec` fuzz target exercises
  FlowSpec NLRI decoding directly with both IPv4 and IPv6 AFIs, complementing
  the existing `decode_message` and `decode_update` targets.
- **BMP exporter (RFC 7854).** New `crates/bmp/` crate implementing the BGP
  Monitoring Protocol. Unidirectional streaming of BGP state to external
  collectors (OpenBMP, pmacct). Encodes Initiation, Peer Up, Peer Down, Route
  Monitoring, Stats Report, and Termination messages. Per-collector async TCP
  client with reconnect/backoff. Fan-out manager distributes encoded BMP
  messages to all configured collectors. Raw BGP PDU capture in transport layer
  (`ReadBuffer::try_decode()` returns `(Message, Bytes)`) enables byte-perfect
  Route Monitoring and Peer Up messages. TOML config: `[bmp]` section with
  `[[bmp.collectors]]`. Near-zero overhead when BMP is not configured (raw
  frame capture uses `Bytes` refcount clones, not data copies). (ADR-0041)
- **Periodic BMP Stats Report.** `PeerManager` now emits periodic per-peer BMP
  Statistics Report messages every 60 seconds (RFC 7854 type 7: routes in
  Adj-RIB-In), using current `prefix_count` from transport session state.
- **CLI tool (`rustbgpctl`).** New `crates/cli/` crate providing a command-line
  interface wrapping the gRPC API. Client-only proto codegen — no dependency on
  internal crates. Commands: `global`, `neighbor` (list/show/add/delete/enable/
  disable/softreset), `rib` (best/received/advertised/add/delete), `watch`
  (streaming), `flowspec` (list/add/delete), `health`, `metrics`, `shutdown`.
  Global `--json` flag for structured output on all commands. Global `--addr`
  flag with `RUSTBGPD_ADDR` env var support.
- **Long-Lived Graceful Restart (RFC 9494).** Two-phase GR timer: when
  the GR restart timer expires, routes for LLGR-negotiated families are
  promoted to LLGR-stale (with `LLGR_STALE` community, well-known
  0xFFFF0006) instead of being purged. Routes carrying `NO_LLGR`
  (0xFFFF0007) are purged at the GR-to-LLGR transition. Effective stale
  time is `min(local llgr_stale_time, peer per-family minimum)`.
  Three-tier best-path ranking: fresh > GR-stale > LLGR-stale at step 0
  (before LOCAL_PREF). New capability code 71 with per-family 24-bit
  stale time. Config: `llgr_stale_time` per neighbor (0 = disabled,
  default). EoR during LLGR clears `is_llgr_stale` and removes locally-
  injected `LLGR_STALE` communities. PeerUp during LLGR moves families
  back to GR phase.
- **Config persistence + SIGHUP reload.** Neighbor add/delete mutations
  via gRPC are now persisted back to the TOML config file via atomic
  write (temp file + rename). `ConfigPersister` task accepts mutations
  through a bounded channel. Sending `SIGHUP` to the daemon triggers a
  config reload: `diff_neighbors()` computes the delta, `ReconcilePeers`
  applies per-peer add/delete operations. Global config changes are logged
  as warnings but require restart. Structured per-peer failure reporting
  on reconciliation.
- **MRT dump export (RFC 6396).** New `crates/mrt/` crate implementing
  `TABLE_DUMP_V2` (type 13) periodic and on-demand RIB snapshots.
  `MrtManager` runs a configurable interval timer and accepts on-demand
  triggers via the new `TriggerMrtDump` gRPC RPC on `ControlService`.
  Snapshots query Adj-RIB-In routes from `RibManager` via
  `QueryMrtSnapshot` (no Loc-RIB overlay to avoid duplication). Peer
  metadata (`peer_asn`, `peer_bgp_id`) is tracked in `RibManager` and
  retained during GR/LLGR transitions. Codec synthesizes next-hop
  attributes stripped by the MP-BGP architecture: `NEXT_HOP` for IPv4,
  `MP_REACH_NLRI` for IPv6, and `MP_REACH_NLRI` with `Afi::Ipv4` for
  RFC 8950 IPv4-with-IPv6-NH routes. Add-Path subtypes 8/9 per RFC 8050.
  `EncodeError` enum for explicit length-overflow handling (no truncation).
  Atomic file writes with optional gzip compression (flate2).
  Collision-resistant filenames (seconds + nanoseconds). TOML config:
  `[mrt]` section with `output_dir`, `dump_interval`, `compress`, and
  `file_prefix`. CLI: `mrt-dump` subcommand. (ADR-0044)

### Changed

- **Policy `RouteContext` struct.** Policy evaluate functions now take a
  borrowed `RouteContext<'a>` instead of 7+ individual parameters,
  eliminating `#[expect(clippy::too_many_arguments)]` from all production
  policy code. Public API: `rustbgpd_policy::RouteContext`.
- **`RibManager::handle_update()` extraction.** The 615-line match
  dispatch is now a thin dispatcher delegating to focused handler methods
  in `distribution.rs`, `peer_lifecycle.rs`, `route_refresh.rs`, and
  `graceful_restart.rs`. Structural refactor only.
- **Config and peer-session module splits.** `src/config.rs` is now
  organized as `src/config/` submodules (`mod.rs`, `schema.rs`,
  `parse.rs`, `validation.rs`, `tests.rs`). The transport peer runtime
  is likewise split from `crates/transport/src/session.rs` into
  `crates/transport/src/session/` submodules (`mod.rs`, `fsm.rs`,
  `io.rs`, `inbound.rs`, `outbound.rs`, `commands.rs`, `tests.rs`).
  This is a structural refactor only; behavior and public interfaces are
  unchanged.
- **RibManager submodule split.** The 8,318-line `manager.rs` has been
  split into 7 files under `crates/rib/src/manager/`: `mod.rs` (893
  lines, struct + event loop), `distribution.rs` (729 lines),
  `peer_lifecycle.rs` (193 lines), `route_refresh.rs` (333 lines),
  `graceful_restart.rs` (170 lines), `helpers.rs` (100 lines), and
  `tests.rs` (5,969 lines). Zero behavior change — pure refactor for
  reviewability.

### Fixed

- **Neighbor gRPC `remove_private_as` parity.** `AddNeighbor` now validates
  and applies `remove_private_as` (`"", remove, all, replace`) instead of
  silently forcing disabled mode for dynamic peers. `ListNeighbors` and
  `GetNeighborState` now return the active `remove_private_as` mode from
  runtime peer state.
- **Neighbor gRPC mutations are now fail-fast when persistence is unavailable.**
  `AddNeighbor` and `DeleteNeighbor` reserve config-persistence queue capacity
  before mutating runtime state. If the persistence channel is busy/closed, the
  RPC fails with `INTERNAL` instead of applying an unpersisted runtime change.
- **SIGHUP reload no longer silently accepts partial reconcile failures.**
  `ReconcilePeers` now returns structured per-peer failures; reload logs each
  failed operation and keeps the previous in-memory config snapshot when
  reconciliation is incomplete.
- **LLGR_STALE community provenance preserved.** Adj-RIB-In now tracks which
  `LLGR_STALE` communities were injected locally during LLGR promotion and
  only removes those on stale clear/EoR. Peer-originated `LLGR_STALE`
  communities are preserved.
- **Neighbor duplicate detection uses canonical IP identity.** Config
  validation now detects duplicates by parsed `IpAddr` (e.g., `::1` and
  `0:0:0:0:0:0:0:1` are treated as the same neighbor address).
- **BMP Termination on coordinated shutdown.** Main runtime now sends an
  explicit BMP shutdown control event, then drains BMP manager/client tasks
  with bounded waits so connected collectors receive BMP Termination (type 5,
  reason 0) before daemon exit.
- **BMP client write timeout.** Per-collector TCP writes now use a 5-second
  timeout to avoid indefinite stalls on slow or wedged collectors.
- **CLI gRPC connect timeout.** `rustbgpctl` now sets a 5-second
  `Endpoint::connect_timeout(...)` to avoid hanging indefinitely when the
  daemon endpoint is unreachable.
- **CLI FlowSpec DSCP validation.** `mark-dscp=` is now bounds-checked in the
  CLI (0..=63) and fails fast on invalid values before RPC submission.
- **CLI prefix IP validation.** Prefix parsing now validates address syntax
  (`IpAddr`) instead of only slash-length bounds.
- **`sendable_families` excluded IPv6 for route-server clients.** eBGP peers
  without a local IPv6 next-hop had IPv6 unicast filtered from
  `sendable_families`, silently preventing IPv6 route advertisement to
  `route_server_client` peers that preserve the original next-hop. Fixed by
  including route-server clients in the filter condition.
- **BMP collector reconnect replay.** `BmpManager` now caches live Peer Up
  state and replays it only to the collector that just reconnected, instead of
  requiring fresh session transitions to rebuild collector state.
- **Policy engine test modularization.** Extracted the `RouteModifications::merge_from`
  and `PolicyChain` test cluster into `crates/policy/src/engine/tests/chain.rs`
  to reduce monolithic test sprawl in `engine.rs`.
- **Export policy IPv6 next-hop discarded on MP path.** When export policy set
  `NextHopAction::Specific(IpAddr::V6(addr))`, the IPv6 MP_REACH send path
  detected the policy but used `route.next_hop` instead of extracting the
  policy address. Fixed by matching `Specific(addr)` directly.
- **IPv6 policy next-hop on classic IPv4 body-NLRI now warns.** Setting an IPv6
  next-hop via export policy for a non-RFC-8950 peer is unencodable in the
  classic `NEXT_HOP` attribute. This now logs a warning and falls through to
  default next-hop selection instead of silently discarding the policy address.

- **Cease subcode constants.** `ADMINISTRATIVE_RESET` (4) added,
  `OUT_OF_RESOURCES` corrected from 4 to 8 per RFC 4486. Description
  table updated for subcode 4 ("Administrative Reset") and 8.

- **FlowSpec (RFC 8955/8956).** IPv4 and IPv6 unicast FlowSpec (SAFI 133)
  with all 13 component types: destination/source prefix, IP protocol,
  port, destination/source port, ICMP type/code, TCP flags, packet length,
  DSCP, fragment, flow label. Numeric and bitmask operator encoding per
  RFC 8955. `FlowSpecRule`/`FlowSpecRoute` parallel types preserve
  `Prefix`'s `Copy` trait. FlowSpec actions (rate-limit, redirect, DSCP
  mark) encoded as extended communities. Separate FlowSpec collections in
  AdjRibIn/LocRib/AdjRibOut. Transport decode/encode via MP_REACH/MP_UNREACH
  with NH length 0. gRPC `AddFlowSpec`/`DeleteFlowSpec`/`ListFlowSpecRoutes`
  RPCs. Same policy/iBGP/RR infrastructure. Config families
  `"ipv4_flowspec"` and `"ipv6_flowspec"`. (ADR-0035)
- **RPKI Origin Validation (RFC 6811).** New `rustbgpd-rpki`
  crate with persistent RTR client (RFC 8210), per-cache-server async
  client, `SerialNotify`-triggered refreshes, enforced expiry timers,
  and multi-cache VRP aggregation. Routes stamped with `RpkiValidation`
  (Valid/Invalid/NotFound). Best-path step 0.5 prefers Valid > NotFound >
  Invalid. Policy `match_rpki_validation` enables rejection of invalid
  routes. Config `[rpki]` section with `[[rpki.cache_servers]]` for
  connecting to validators (Routinator, rpki-client, FORT). Prometheus
  metrics for VRP counts. gRPC `validation_state` on Route messages.
  (ADR-0034)
- **Extended Communities (RFC 4360).** `ExtendedCommunity(u64)` newtype
  with helpers for type/sub-type extraction, route target, and route origin
  decoding. Full wire codec (type 16, Optional|Transitive), stored on
  routes, exposed via gRPC `Route` and `AddPath`. (ADR-0025)
- **Extended Community Policy Matching.** Import/export policy can now match
  on route target (`RT:`) and route origin (`RO:`) values via
  `match_community` in prefix list entries. Encoding-agnostic matching
  (2-octet AS, IPv4-specific, and 4-octet AS compare equal). Prefix is now
  optional — entries can match community-only, prefix-only, or both (AND).
  Multiple communities in one entry use OR logic. (ADR-0026)
- **M12 interop test** — Extended communities validated against FRR 10.3.1.
  FRR route-map sets RT:65002:100, rustbgpd decodes/stores/exposes via gRPC.
  Injection round-trip verified. 14/14 tests pass.
- **Route Refresh (RFC 2918).** ROUTE-REFRESH message codec (type 5),
  capability code 2 advertised unconditionally. Inbound: peer requests
  trigger Loc-RIB re-advertisement for the requested family. Outbound:
  `SoftResetIn` gRPC RPC sends ROUTE-REFRESH to peers for soft inbound
  reset after policy changes. (ADR-0027)
- **AS_PATH loop detection (RFC 4271 §9.1.2).** Routes containing the
  local ASN in any AS_PATH segment (AS_SEQUENCE or AS_SET) are discarded
  before RIB entry. Applies to all peers (eBGP and iBGP). Withdrawals
  in the same UPDATE are still processed. New metric:
  `bgp_as_path_loop_detected_total` (labeled by peer, counts rejected
  prefixes).
- **iBGP split-horizon (RFC 4271 §9.1.1).** Non-route-reflector speakers
  no longer re-advertise iBGP-learned routes to other iBGP peers. Applies
  to `distribute_changes()`, `send_initial_table()`, and route refresh
  responses. Uses `RouteOrigin` enum (Ebgp/Ibgp/Local) instead of a
  boolean — locally originated routes pass through to all peers.
- **Standard Communities Policy Matching (RFC 1997).** Import/export
  policy can now match on standard community values via `match_community`
  in prefix list entries. Three formats: `ASN:VALUE` (e.g., `65001:100`),
  well-known names (`NO_EXPORT`, `NO_ADVERTISE`, `NO_EXPORT_SUBCONFED`),
  and existing extended community syntax (`RT:65001:100`). Standard and
  extended community criteria use OR semantics within a single entry.
  (ADR-0028)
- **Route Reflector (RFC 4456).** Designated speakers can reflect
  iBGP-learned routes based on client/non-client roles, eliminating
  the full-mesh requirement. Config: `cluster_id` (global),
  `route_reflector_client` (per-neighbor). Reflection rules: client
  routes go to all iBGP peers, non-client routes go to clients only.
  ORIGINATOR_ID (type 9) and CLUSTER_LIST (type 10) attributes with
  full wire codec, inbound loop detection, outbound manipulation
  (set on reflection, stripped on eBGP). Best-path tiebreakers:
  shortest CLUSTER_LIST, lowest ORIGINATOR_ID (RFC 4456 §9). New
  metric: `bgp_rr_loop_detected_total`. (ADR-0029)
- **Policy actions — route modification on import/export.** Policy
  engine redesigned from accept/reject to full match+modify+filter.
  `set_local_pref`, `set_med`, `set_next_hop` (self or IP),
  `set_community_add`/`set_community_remove` (standard, extended,
  large), `set_as_path_prepend` (ASN + count). Import modifications
  stored on Route; export modifications clone Loc-RIB route. Policy
  types renamed from prefix-list terminology to engine terminology.
  (ADR-0030)
- **AS_PATH regex matching.** `match_as_path` field in policy
  statements supports Cisco/Quagga-style patterns (`^65100_`,
  `_65200$`, `_65100_`). `_` expands to boundary anchor. ANDed with
  existing prefix and community conditions. `AsPath::to_aspath_string()`
  for regex-matchable format. (ADR-0030)
- **Large Communities (RFC 8092).** 12-byte community values for
  4-byte ASN operators. Wire codec (type 32, Optional|Transitive),
  `Route::large_communities()` accessor, gRPC API fields on Route and
  AddPath, policy matching (`LC:global:local1:local2` format in
  `match_community`), and set/delete in policy actions. (ADR-0031)
- **Extended Messages (RFC 8654).** Raises the 4096-byte BGP message
  limit to 65535 bytes. Capability code 6 advertised unconditionally.
  Negotiated per-session; dynamic buffer sizing on establishment.
  `max_message_len` parameter threaded through header decode, message
  decode, and UPDATE encode. (ADR-0032)
- **Add-Path (RFC 7911) — receive + multi-path send.** Accept and
  advertise multiple paths per prefix. Capability code 69 with
  `AddPathMode` (Receive/Send/Both) negotiation. `NlriEntry` and
  `Ipv4NlriEntry` structs for path-id-aware NLRI. RIB re-keyed with
  composite `(Prefix, path_id)` keys in Adj-RIB-In and Adj-RIB-Out.
  Multi-path send (route server mode): `distribute_multipath_prefix()`
  collects all candidates, applies per-candidate export policy, assigns
  rank-based path IDs. TOML config: `[neighbors.add_path] receive = true`,
  `send = true`, `send_max = N`. gRPC API: `path_id` on Route,
  RouteEvent, AddPathRequest, DeletePathRequest. (ADR-0033)

### Fixed

- **IPv4 `set_next_hop` now reaches the wire.** `apply_modifications()` updates
  `PathAttribute::NextHop` directly for `Specific(V4)` addresses. Export path
  carries full `NextHopAction` (not a boolean) so `prepare_outbound_attributes()`
  can skip eBGP rewrite when policy explicitly sets an address. IPv6 policy
  next-hop override also wired through.
- **RT/RO extended community ASN validation.** `build_rt_ec()`/`build_ro_ec()`
  now reject ASN > 65535 at config load time (2-octet AS-Specific sub-type only
  carries u16). Previously silently truncated to u16.
- **RT/RO impossible match specs rejected.** `parse_community_match()` rejects
  RT/RO match patterns with local fields exceeding the encoding capacity (e.g.
  `RT:192.0.2.1:70000` where IPv4-specific only allows u16 local).
- **AS_PATH regex `_` now matches AS_SET braces.** Expanded from `(?:^| |$)` to
  `(?:^| |$|[{}])` so patterns like `_65003_` match inside `{65003 65004}`.
- **Zero-length LARGE_COMMUNITIES rejected.** Wire decoder now rejects
  zero-length attribute value (must carry at least one 12-byte community).
- **Extended community add/remove uses logical RT/RO equivalence.**
  `set_community_remove` and `set_community_add` now compare RT/RO semantically,
  not by raw bytes. Removes work across encodings (2-octet AS, 4-octet AS,
  IPv4-specific) and adds avoid creating logical duplicates.
- **AS_PATH prepend overflow guard.** `set_as_path_prepend` no longer creates
  AS_SEQUENCE segments longer than 255 ASNs (wire segment length is u8). When
  merging would exceed the limit, a separate leading AS_SEQUENCE is created.
- **Proto `large_communities` format documented.** Added format comments
  (`"global_admin:local_data1:local_data2"`) to `Route` and `AddPathRequest`
  message fields.
- **Dead code removed.** Deleted `prefix_list.rs` (969 lines of duplicated code
  superseded by `engine.rs`). Removed 36 duplicate tests.

### Known Limitations

- **Large community duplicates preserved.** Duplicate large communities in
  received UPDATEs are stored and re-advertised unchanged. Strict RFC 8092
  normalization (dedup on receipt) is deferred as a hardening item.

- **Proto: single source of truth.** Eliminated duplicate proto file;
  `crates/api/build.rs` now compiles from `proto/rustbgpd.proto` directly.
  `SoftResetIn` RPC is now in the public proto.
- **ROUTE-REFRESH: unknown AFI/SAFI no longer tears down session.**
  `RouteRefreshMessage` stores raw wire values; unknown families are logged
  and ignored instead of triggering a decode error.
- **ROUTE-REFRESH: outbound queue no longer leaks across reconnects.**
  Outbound channel is recreated on `SessionDown` so stale updates from a
  dying session cannot be sent on the next one.
- **ROUTE-REFRESH: negotiated family/capability checks on both paths.**
  Inbound and outbound ROUTE-REFRESH now verify the requested family is
  negotiated and the peer advertised the capability.
- **SoftResetIn: accurate gRPC error codes.** Peer-not-found returns
  `NOT_FOUND`; send failures return `INTERNAL` (was all `NOT_FOUND`).
- **SoftResetIn: docs corrected.** Empty families means "all configured"
  (not "all negotiated"); transport filters to negotiated.
- **Route refresh: backpressure observable.** RIB channel full and EoR
  enqueue failures are now logged at `warn` level.
- **EoR retry under backpressure.** Failed EoR markers are tracked in
  `pending_eor` and retried on the next dirty-peer resync, so the protocol
  completion signal is no longer permanently lost.
- **SoftResetIn returns actual send outcome.** `SendRouteRefresh` is now a
  request/reply command; the gRPC response reflects whether the message was
  sent, not just enqueued.
- **AS_PATH loop fast-path: negotiated-family filter on withdrawals.** The
  loop-detection branch now applies the same `negotiated_families` check to
  `MP_UNREACH_NLRI` as the normal UPDATE path, preventing withdrawals for
  unnegotiated address families from reaching the RIB.
- **Best-path step 5 comment corrected.** The comment now accurately states
  that only `RouteOrigin::Ebgp` is preferred over iBGP; `Local` routes do
  not receive explicit preference at this step (they win via LOCAL_PREF or
  shorter AS_PATH instead).

---

## [0.3.0] — 2026-03-01

Graceful Restart (RFC 4724) — receiving speaker. Wire codec hardening.
448 tests.

### Added

- **Graceful Restart — receiving speaker (RFC 4724).** When a peer restarts
  with GR capability, routes are preserved as stale during the restart window
  instead of immediately withdrawn. End-of-RIB markers clear stale flags;
  timer expiry sweeps remaining stale routes. Enabled by default.
  - Wire: capability code 64 encode/decode with per-family forwarding flags
  - Config: `graceful_restart` (default `true`), `gr_restart_time` (default
    `120`), `gr_stale_routes_time` (default `360`)
  - FSM: peer GR capability negotiation
  - RIB: stale route demotion in best-path (step 0, before LOCAL_PREF),
    timer-based stale sweep, End-of-RIB detection and sending
  - Transport: GR-aware session teardown (PeerGracefulRestart vs PeerDown)
  - Metrics: `bgp_gr_active_peers`, `bgp_gr_stale_routes`,
    `bgp_gr_timer_expired_total`
- `rustbgpd-wire`: `Capability::encode()` now returns `Result<(), EncodeError>`
  — validates capability value lengths and `restart_time` range before encoding
- Config: `gr_restart_time=0` rejected when `graceful_restart` is enabled;
  `gr_stale_routes_time` capped at 3600 seconds; duplicate address families
  in config are deduplicated

### Fixed

- **Graceful Restart state machine corrections (RFC 4724 review).**
  - GR trigger now checks `peer_gr_capable` instead of the R-bit from the
    dying session; R-bit is only meaningful in the *new* OPEN after restart
  - All families from the peer's GR capability are retained as stale, not
    just those with `forwarding_preserved=true`
  - Routes for negotiated families NOT in the peer's GR capability are
    withdrawn immediately on GR start
  - `PeerUp` during GR no longer clears stale flags — routes stay stale
    until End-of-RIB per family, matching RFC 4724 §4.2
  - Initial GR timer uses `restart_time` (session window); timer resets to
    `stale_routes_time` on `PeerUp` (EoR window)
  - `graceful_restart=false` config now gates GR in transport
  - `bgp_gr_stale_routes` metric updated during partial EoR recovery
  - Dead outbound channels cleaned up on GR start
- `rustbgpd-wire`: capability decode now bounded to the enclosing
  optional-parameter slice — a malformed capability length can no longer
  consume into the next parameter or beyond the OPEN body
- `rustbgpd-wire`: `restart_time > 4095` in `Capability::encode()` now
  returns an error instead of silently masking with `& 0x0FFF`

- `rustbgpd-rib`: Adj-RIB-Out no longer diverges from wire state for eBGP
  peers without a valid IPv6 next-hop. `sendable_families` passed at `PeerUp`
  time filters unsendable address families before Adj-RIB-Out insertion,
  keeping `ListAdvertisedRoutes`, withdraw bookkeeping, and dirty-peer resync
  in sync with what the transport actually sends.
- `rustbgpd-wire`: `MP_REACH_NLRI` flags corrected from optional-transitive
  (0xC0) to optional-non-transitive (0x80) per RFC 4760 §3. Affects encoding,
  decoding validation (`expected_flags`), and `flags()` accessor.
  `MP_UNREACH_NLRI` was already correct.
- `rustbgpd-wire`: `validate_update_attributes()` now requires `NEXT_HOP` for
  body NLRI even when `MP_REACH_NLRI` is present. Mixed UPDATEs (body NLRI +
  MP_REACH) no longer incorrectly waive NEXT_HOP.
- `rustbgpd-wire`: `Ipv4Prefix::new()` clamps prefix length to 32;
  `Ipv6Prefix::new()` clamps to 128. Wire decoders already rejected invalid
  lengths but constructors silently created invalid prefixes.
- `rustbgpd-wire`: IPv6 next-hops in `MP_REACH_NLRI` validated — link-local
  (`fe80::/10`), loopback, multicast, and unspecified addresses rejected with
  NOTIFICATION (3,8).
- `rustbgpd-transport`: IPv6 routes built from `MP_REACH_NLRI` no longer
  inherit `PathAttribute::NextHop(ipv4)` from the same UPDATE.
- `rustbgpd-transport`: IPv6 eBGP next-hop resolution: uses
  `local_ipv6_nexthop` config > local socket address > suppress (no longer
  falls back to `::`).
- `rustbgpd-transport`: IPv6 outbound batching now groups by `(attributes,
  next_hop)` instead of just attributes. Routes with different next-hops get
  separate UPDATEs.
- `rustbgpd-transport`: Negotiated address families enforced at inbound and
  outbound edges. Routes for non-negotiated families are ignored inbound and
  filtered outbound.
- `rustbgpd-transport`: Send-time IPv6 next-hop filter now rejects loopback,
  link-local, and multicast (was only rejecting `::`), consistent with
  receive-side validation.
- `rustbgpd-fsm`: Implicit IPv4 unicast fallback per RFC 4760 §8 — when
  neither side advertises MP-BGP for IPv4, IPv4 unicast is still negotiated.
- `rustbgpd-api`: `ListReceivedRoutes`, `ListBestRoutes`, `ListAdvertisedRoutes`,
  and `WatchRoutes` now filter results by the requested `afi_safi` family
  (previously validated the enum but returned all routes regardless).
- `rustbgpd-api`: `AddNeighbor` gRPC now accepts `families` field for address
  family configuration (previously hardcoded to IPv4 unicast).
- `rustbgpd-api`: `ListNeighbors` and `GetNeighborState` now return configured
  address families (was hardcoded to empty).
- `rustbgpd-api`: `local_ipv6_nexthop` config now properly wired through
  `PeerManagerNeighborConfig` for statically configured peers (was dead config).
- `rustbgpd-rib`: Metrics label changed from `"ipv4_unicast"` to `"all"` since
  RIB now tracks both IPv4 and IPv6 routes.
- Config: `local_ipv6_nexthop` validation now rejects loopback, link-local,
  multicast, and unspecified addresses (was only checking parse-ability).

### Added

- Config: `local_ipv6_nexthop` field on `[[neighbors]]` — explicit IPv6
  next-hop address for eBGP sessions over IPv4 transport.
- `rustbgpd-wire`: Public `is_valid_ipv6_nexthop()` helper for reuse across
  config validation, send-time filtering, and receive-side validation.

## [0.2.0] — 2026-02-28

MP-BGP (IPv6 unicast) support. rustbgpd is now a dual-stack BGP speaker —
IPv6 prefixes are exchanged via `MP_REACH_NLRI` / `MP_UNREACH_NLRI` (RFC 4760)
alongside existing IPv4 unicast. This is a cross-cutting change touching all 7
crates. 388 tests pass.

### Added

- `rustbgpd-wire`: `Ipv6Prefix` type with NLRI encode/decode (prefix-length
  encoding, max 128, host-bit masking). `Prefix` enum wrapping `Ipv4Prefix` and
  `Ipv6Prefix` for AFI-agnostic route representation. Helper methods
  `addr_string()` and `prefix_len()` on `Prefix`.
- `rustbgpd-wire`: `MpReachNlri` and `MpUnreachNlri` path attribute variants
  (types 14 and 15). Full decode/encode per RFC 4760 §3: AFI/SAFI, variable-
  length next-hop (16 or 32 bytes for IPv6, take global address), NLRI.
  `Afi` and `Safi` enums with `Unknown(u16)` / `Unknown(u8)` variants.
- `rustbgpd-wire`: `MP_REACH_NLRI` (14) and `MP_UNREACH_NLRI` (15) constants.
  Flag validation: type 14 = Optional (0x80), type 15 = Optional (0x80)
  per RFC 4760 §3/§4 (both are optional non-transitive).
- `rustbgpd-fsm`: `intersect_families()` computes the intersection of locally
  configured address families and peer-advertised MP-BGP capabilities.
  `NegotiatedSession` gains `negotiated_families: Vec<(Afi, Safi)>`.
- `rustbgpd-transport`: `process_update()` extracts `MpReachNlri` and
  `MpUnreachNlri` from parsed attributes, builds routes with `Prefix::V6` and
  `IpAddr::V6` next-hops, combines with body NLRI for unified RIB insertion.
- `rustbgpd-transport`: `send_route_update()` splits outbound routes by AFI —
  IPv4 routes use body NLRI (existing path), IPv6 routes use `MpReachNlri` /
  `MpUnreachNlri` attributes. eBGP IPv6 next-hop rewritten to local socket
  address.
- `rustbgpd-api`: `InjectionService` accepts IPv6 prefixes and next-hops in
  `AddPath` and `DeletePath`. Prefix length validated against AFI-specific
  maximum (32 for IPv4, 128 for IPv6).
- `rustbgpd-api`: `RibService` accepts IPv6 unicast in `afi_safi` filter
  (previously rejected non-IPv4). `WatchRoutes` events carry correct AFI based
  on prefix type.
- Config: `families` field on `[[neighbors]]` — list of address families to
  negotiate (e.g., `["ipv4_unicast", "ipv6_unicast"]`). Defaults to
  `["ipv4_unicast"]` for IPv4 neighbors, `["ipv4_unicast", "ipv6_unicast"]`
  for IPv6 neighbors.
- Config: IPv6 neighbor addresses now accepted (previously rejected at
  validation).
- Config: IPv6 prefixes supported in policy prefix lists (e.g.,
  `prefix = "2001:db8::/32"`). Prefix length validation uses AFI-specific
  maximum (32 for IPv4, 128 for IPv6).
- Interop: `m10-frr-ipv6.clab.yml` containerlab topology — rustbgpd + FRR
  dual-stack (IPv4 session with MP-BGP IPv6 unicast). FRR advertises 2 IPv4
  and 2 IPv6 prefixes.
- Interop: `test-m10-frr-ipv6.sh` automated test script with 6 tests: session
  with IPv6 capability, IPv4 backward compat, IPv6 prefix receipt, IPv6 best
  routes, IPv6 withdrawal, IPv6 route injection via gRPC.
- ADR-0023: Prefix enum and AFI-agnostic RIB for MP-BGP.

### Changed

- `rustbgpd-wire`: `UpdateMessage::build()` now encodes path attributes when
  attributes are non-empty, even if body NLRI is empty. Required for IPv6-only
  UPDATEs that carry NLRI inside `MpReachNlri` attributes.
- `rustbgpd-wire`: `validate_update_attributes()` relaxes the NEXT_HOP
  requirement when `MP_REACH_NLRI` is present (RFC 4760 §3 — next-hop is
  carried inside the MP attribute for non-IPv4 families).
- `rustbgpd-rib`: `Route.prefix` changed from `Ipv4Prefix` to `Prefix` enum.
  `Route.next_hop` changed from `Ipv4Addr` to `IpAddr`. All RIB data
  structures (`AdjRibIn`, `LocRib`, `AdjRibOut`) generalized from
  `HashMap<Ipv4Prefix, _>` to `HashMap<Prefix, _>`.
- `rustbgpd-rib`: `RibUpdate` and `OutboundRouteUpdate` use `Prefix` for
  withdrawn routes (was `Ipv4Prefix`). `RouteEvent.prefix` is now `Prefix`.
- `rustbgpd-policy`: `PrefixListEntry` generalized to match both IPv4 and IPv6
  prefixes. `le` defaults to 32 for IPv4, 128 for IPv6.
- `rustbgpd-transport`: `known_prefixes` changed from `HashSet<Ipv4Prefix>` to
  `HashSet<Prefix>`. `prepare_outbound_attributes()` strips `MpReachNlri` and
  `MpUnreachNlri` from cloned attributes (rebuilt per-route for outbound).
- Workspace version bumped to 0.2.0.

## [0.1.0] — 2026-02-28

First tagged release. Covers milestones M0–M9: a fully functional,
IPv4-unicast BGP daemon with gRPC API, RFC 4271 compliance, TCP collision
detection, and interop validation against FRR 10.3.1 and BIRD 2.0.12.
367 tests pass.

### Fixed

- `rustbgpd-transport`: `SessionNotification::OpenReceived` now reads
  `self.fsm.negotiated()` (available at `OpenConfirm`) instead of
  `self.negotiated` (set later at `SessionEstablished`). Previously the
  notification never fired, bypassing TCP collision detection entirely.
  1 integration test.
- `rustbgpd-transport`: `QueryState` now reads `remote_router_id` (and
  `negotiated_hold_time`, `four_octet_as`) from `self.fsm.negotiated()`
  with fallback to `self.negotiated`. Previously `handle_inbound()` in
  OpenConfirm could not resolve collisions because `remote_router_id` was
  `None`. 1 integration test.
- `rustbgpd-transport`: Session notification channel changed from bounded
  `mpsc::channel(64)` with `try_send()` to `mpsc::unbounded_channel()` with
  `send()`. Collision notifications are no longer silently dropped under
  channel pressure. Unbounded is safe here because rate is bounded by FSM
  state transitions (infrequent). Avoids deadlock risk that `send().await`
  on a bounded channel would introduce (PeerManager queries peer state via
  the same task).
- `PeerManager`: `disable_peer()` now clears `pending_inbound`. `BackToIdle`
  handler guards against accepting pending inbound for disabled peers.
  Previously disabling a peer could be undone by a queued inbound connection.
  1 test.
- `src/metrics_server.rs`: Semaphore permit acquired before `accept()` for
  exact connection cap (was off-by-one: 65 instead of 64).
- `docs/SECURITY.md`: Corrected metrics endpoint description (no default
  address; common port is 9179, not 9090).
- `README.md`: Docker section now warns that `grpc_addr = "0.0.0.0:50051"`
  exposes unauthenticated RPCs. Links to `docs/SECURITY.md`.
- `crates/fsm/src/session.rs`: Doc comment on `negotiated()` corrected from
  "available after Established" to "available after `OpenConfirm`".
- `ROADMAP.md`: Corrected M8 test count from 347 to 357.

## M9 — "Production Hardening"

### Added

- `rustbgpd-wire`: Cease subcode 7 (`CONNECTION_COLLISION_RESOLUTION`) for
  TCP collision detection per RFC 4271 §6.8. Human-readable description in
  `notification::description()`.
- `rustbgpd-transport`: `SessionNotification` enum (`OpenReceived`,
  `BackToIdle`) sent from peer sessions to PeerManager for collision detection
  coordination. `CollisionDump` command variant on `PeerCommand` — sends
  Cease/7 NOTIFICATION, cleans up RIB if Established, closes TCP.
  `remote_router_id: Option<Ipv4Addr>` added to `PeerSessionState`. Session
  notification channel threaded through `PeerHandle::spawn()` and
  `PeerHandle::spawn_inbound()`. (ADR-0021)
- `PeerManager`: TCP collision detection. `pending_inbound` per peer stores
  inbound TCP streams awaiting resolution. `session_notify_rx` in `select!`
  loop handles `OpenReceived` (resolve collision) and `BackToIdle` (accept
  pending). `resolve_collision()` compares BGP Identifiers — higher wins.
  `replace_with_inbound()` helper extracted for clean session replacement.
  4 new tests. (ADR-0021)
- `docs/SECURITY.md`: new document covering gRPC security posture,
  authentication gaps, privileged RPCs, and deployment recommendations.
- `docs/adr/0021-tcp-collision-detection.md`: ADR for collision detection
  architecture.
- `docs/adr/0022-grpc-server-supervision.md`: ADR for gRPC server
  supervision.

### Changed

- `src/main.rs`: gRPC server `JoinHandle` now supervised — unexpected exit
  triggers coordinated shutdown (API-first daemon without API should not
  keep running). Added to shutdown `select!` alongside ctrl-c and Shutdown
  RPC. (ADR-0022)
- `src/main.rs`: Non-loopback gRPC bind address triggers a warning at
  startup, informing operators that all RPCs are unauthenticated.
- `src/metrics_server.rs`: Read timeout (5s) prevents slow-client
  exhaustion. Request-line size limit (8192 bytes) returns 400 for oversized
  requests. Concurrent connection cap (64 via `tokio::sync::Semaphore`)
  provides backpressure. `gather()` errors return 500 Internal Server Error
  instead of panicking. 3 new tests.
- CHANGELOG updated with versioning through M9.
- ROADMAP updated: completed summary reflects M0–M8 work, M9 marked
  complete, v1 scope section added, TCP collision detection moved from
  post-v1 into M9.

## M8 — "API & Observability"

### Fixed

- `rustbgpd-rib`: WatchRoutes event model now carries `previous_peer` and
  `timestamp` on all `RouteEvent` variants. Subscribers filtered to a specific
  peer now see "route moved away" events (BestChanged/Withdrawn) where the old
  peer matches. `recompute_best()` captures previous best peer before Loc-RIB
  mutation. 4 tests.
- `rustbgpd-rib`: Prometheus gauges (`bgp_rib_prefixes`, `bgp_rib_adj_out_prefixes`,
  `bgp_rib_loc_prefixes`) wired at all RIB mutation points — RoutesReceived,
  PeerDown, distribute_changes, send_initial_table, InjectRoute, WithdrawInjected,
  recompute_best. Zero-valued gauges initialized on PeerUp for stable dashboard
  series. 3 tests.
- `rustbgpd-api`: `active_peers` in GetHealth now counts only Established peers
  (was counting all configured peers). `total_routes` now queries Loc-RIB count
  (was summing per-peer prefix counts). 1 test.
- `rustbgpd-api`: `prefixes_sent` in ListNeighbors and GetNeighborState now
  queries Adj-RIB-Out count per peer (was hardcoded to 0). Returns
  `Status::internal` on RIB manager failure instead of silently returning 0.
  1 test.
- Config: IPv6 neighbor addresses rejected at config validation and gRPC
  `AddNeighbor` boundary. Wire crate is IPv4-only and GTSM uses IPv4-only
  socket options. 2 tests.

### Changed

- Proto: `AddPathResponse.uuid` removed (was a fake 6-byte value derived from
  prefix bytes that `DeletePath` ignored). Both `AddPathResponse` field 1 and
  `DeletePathRequest` field 3 are now reserved for wire compatibility.
- Proto: `SetGlobal` RPC, `SetGlobalRequest`, and `SetGlobalResponse` annotated
  as reserved for future use (documentation-only; RPC still returns UNIMPLEMENTED).
- Proto: `RouteEvent` gains `previous_peer_address` (field 7) and timestamp
  comment clarified as Unix epoch seconds.
- `rustbgpd-rib`: `QueryLocRibCount` and `QueryAdvertisedCount` variants added
  to `RibUpdate` for accurate health and neighbor counters. 2 tests.
- `rustbgpd-api`: `ControlService` and `NeighborService` now accept `rib_tx`
  for querying RIB state.

## M7 — "Wire & RIB Correctness"

### Fixed

- `rustbgpd-rib`: Adj-RIB-Out divergence on channel-full. `distribute_changes()`
  and `send_initial_table()` now stage deltas before `try_send()`. Mutations
  commit only on success. On failure the peer is marked dirty and a persistent
  resync timer (1 second, pinned across loop iterations) fires independently of
  both incoming mutations and non-mutating query traffic, diffing the entire
  Loc-RIB against AdjRibOut to recover missed updates and withdrawals. AdjRibOut
  is preserved (not cleared) so knowledge of the peer's on-wire state is
  retained. 4 tests.
- `rustbgpd-wire`: Both malformed NLRI cases — prefix length > 32 and truncated
  NLRI buffer — now produce `InvalidNetworkField` with UPDATE subcode 10
  (Invalid Network Field). Previously prefix_len > 32 used subcode 1 and
  truncation mapped to Message Header / Bad Message Length (1/2). Error data
  includes the offending length byte and available address bytes. 2 tests.
- `rustbgpd-wire`: PARTIAL bit on re-advertised unknown attributes narrowed
  to optional transitive only (both OPTIONAL and TRANSITIVE flags set).
  Previously set PARTIAL whenever TRANSITIVE was set, incorrectly marking
  well-known transitive attributes like ATOMIC_AGGREGATE. 1 test.
- Config: policy prefix lengths eagerly validated in `Config::validate()` at
  load time. Rejects prefix length > 32, ge > 32, ge < prefix length, le > 32,
  and ge > le. Previously deferred to first policy access, which could cause
  panics in `PrefixListEntry::matches()`. Both global and per-neighbor policies
  are now checked. 4 tests.

### Added

- `rustbgpd-rib`: eBGP-over-iBGP preference in best-path selection. `Route`
  gains `origin_type: RouteOrigin` field (Ebgp/Ibgp/Local). Best-path step 5
  (between MED and peer address tiebreaker) prefers eBGP routes over iBGP per
  RFC 4271 §9.1.2. 3 tests.

## M6 — "Compliance"

### Added

- `rustbgpd-wire`: RFC-compliant attribute flag validation at decode time. Known
  attribute types are checked for correct Optional/Transitive flags, producing
  `UpdateAttributeError` with subcode 4 (Attribute Flags Error) and full attribute
  data per RFC 4271 §6.3. Replaces dead `check_wellknown_flags` in validator.
- `rustbgpd-wire`: Specific UPDATE error subcodes replace generic subcode 1
  (Malformed Attribute List) — length errors produce subcode 5, invalid ORIGIN
  produces subcode 6, malformed AS_PATH produces subcode 11. All include the
  offending attribute as NOTIFICATION data.
- `rustbgpd-wire`: `UpdateAttributeError` variant on `DecodeError` carrying subcode,
  attribute data, and detail string. `to_notification()` maps it to the correct
  `(UpdateMessage, subcode, data)` tuple.
- `rustbgpd-wire`: Shared `attr_error_data()` helper builds RFC 4271 §6.3 error data
  (flags + type + length + value), correctly setting the Extended Length flag for
  values > 255 bytes. Replaces buggy `encode_attr_for_error` in validator.
- `rustbgpd-wire`: Partial bit (0x20) is now OR'd into flags when encoding unknown
  transitive attributes for re-advertisement, per RFC 4271 §5. 10 new tests.
- `rustbgpd-api`: `GlobalService` gRPC implementation — `GetGlobal` returns daemon
  ASN, router-id, and listen port; `SetGlobal` returns UNIMPLEMENTED (runtime mutation
  deferred to post-v1). 2 tests. (ADR-0020)
- `rustbgpd-api`: `ControlService` gRPC implementation — `GetHealth` returns uptime,
  active peer count, and total route count; `GetMetrics` returns Prometheus text
  exposition; `Shutdown` initiates coordinated daemon shutdown via gRPC. 2 tests.
  (ADR-0020)
- Coordinated shutdown: ctrl-c and `Shutdown` RPC both trigger ordered teardown —
  PeerManager drains all peers (sending NOTIFICATIONs), then gRPC server exits
  gracefully via `serve_with_shutdown`. Previously the runtime dropped mid-shutdown.

### Fixed

- `rustbgpd-transport`: eBGP NEXT_HOP rewrite now uses the TCP session's local
  address instead of `local_router_id`. Router-id is often a loopback that is
  not reachable from the peer; the local socket address is correct.
- `rustbgpd-api`: `AddPath` with empty `as_path` no longer produces a zero-length
  AS_SEQUENCE segment that fails our own UPDATE validator. Empty input now creates
  an AS_PATH with no segments (correct for locally-originated routes).
- `rustbgpd-api`: `afi_safi` field in `ListReceivedRoutes`, `ListBestRoutes`,
  `ListAdvertisedRoutes`, and `WatchRoutes` is now validated. Requesting an
  unsupported address family (e.g., IPv6) returns `INVALID_ARGUMENT` instead of
  silently returning IPv4 data.
- `rustbgpd-wire`: 2-octet ASN encoding no longer silently truncates 4-byte ASNs.
  ASNs > 65535 are now mapped to `AS_TRANS` (23456) per RFC 6793.
- Config: invalid policy entries (unknown action, malformed prefix) now return
  `ConfigError::InvalidPolicyEntry` instead of being silently filtered. 2 tests.
- `KNOWN_ISSUES.md`: removed stale entries about missing inbound listener and
  outbound UPDATE generation (resolved in M5 and M3 respectively).
- Metrics server: inbound accept forwarding failure now logged instead of silently
  dropped.

### Changed

- `rustbgpd-api`: Deduplicated pagination logic in `RibService` — extracted
  `parse_page_params()` and `build_response()` helpers used by all 3 list RPCs.
- Workspace version bumped to 0.1.0. Repository URL fixed. Added `rust-version`,
  `keywords`, `categories` metadata for crates.io publishing. Proto file copied
  into api crate for standalone packaging.

### Added (M5 — "Polish")

- `rustbgpd-transport`: Inbound TCP listener. `BgpListener` accepts connections on
  `listen_port` and forwards to PeerManager via `AcceptInbound` command. `PeerSession::new_inbound()`
  starts with an already-connected stream. `PeerHandle::spawn_inbound()` spawns inbound sessions.
  (ADR-0019)
- `rustbgpd-transport`: Session counters — `updates_received`, `updates_sent`,
  `notifications_received`, `notifications_sent`, `flap_count`, `uptime_secs`, `last_error`
  tracked per session and exposed via `PeerSessionState` and gRPC `NeighborState`.
- `rustbgpd-transport`: Accurate prefix tracking via `HashSet<Ipv4Prefix>` instead of
  add/subtract heuristic. Duplicate announcements no longer inflate count; withdrawals
  of unknown prefixes no longer underflow.
- `rustbgpd-transport`: NLRI batching — outbound UPDATEs with identical path attributes
  are grouped into a single wire UPDATE message.
- `rustbgpd-api`: Input validation for `AddNeighbor` (reject `remote_asn=0`,
  `hold_time` of 1 or 2) and `AddPath` (reject `next_hop` of `0.0.0.0` or multicast).
  4 unit tests.
- `rustbgpd-api`: `NeighborState` proto fields fully populated — uptime, update/notification
  counters, flap count, last error, hold_time, max_prefixes. Previously hardcoded to 0.
- `rustbgpd-rib`: `RibManager` accepts `BgpMetrics` and records `outbound_route_drops`
  counter when `try_send()` fails.
- `rustbgpd-telemetry`: `outbound_route_drops` IntCounterVec metric (labeled by peer).
- Config: `#[serde(deny_unknown_fields)]` on all config structs — typos now cause
  startup errors instead of silent acceptance. 2 tests.
- Metrics server: per-connection task spawn, HTTP path routing (404 for non-`/metrics`),
  5-second write timeout. 2 tests.

### Added (M4 — "Route Server Mode")

- `rustbgpd-wire`: Typed COMMUNITIES attribute (RFC 1997). `PathAttribute::Communities(Vec<u32>)`
  variant replaces opaque `Unknown` for type code 8. Decode, encode, and `Route::communities()`
  accessor. 6 tests.
- `rustbgpd-rib`: `RouteEvent` type with `Added`, `Withdrawn`, `BestChanged` variants.
  `tokio::sync::broadcast` channel (capacity 4096) emits events after best-path recomputation.
  `SubscribeRouteEvents` variant in `RibUpdate`. (ADR-0018)
- `rustbgpd-rib`: Per-peer export policy support. `RibManager` stores per-peer policies via
  `PeerUp`, resolves with `export_policy_for()` (per-peer overrides global). Cleaned up on
  `PeerDown`. 2 new tests.
- `rustbgpd-api`: `NeighborService` gRPC implementation with all 6 RPCs: `AddNeighbor`,
  `DeleteNeighbor`, `ListNeighbors`, `GetNeighborState`, `EnableNeighbor`, `DisableNeighbor`.
- `rustbgpd-api`: `WatchRoutes` gRPC streaming endpoint. Subscribes to RIB broadcast channel,
  wraps in `BroadcastStream`, filters by peer address, maps `RouteEvent` to proto `RouteEvent`.
  Lagged subscribers are logged and skipped.
- `rustbgpd-api`: `peer_types` module with shared `PeerManagerCommand`, `PeerManagerNeighborConfig`,
  and `PeerInfo` types used by both binary and API crate.
- `rustbgpd-api`: Communities field populated in `route_to_proto()` and accepted in
  `AddPath` injection requests.
- `rustbgpd-transport`: `PeerCommand::QueryState` variant returns `PeerSessionState`
  (FSM state, prefix count, negotiated hold time, four-octet-AS flag).
- `PeerManager` (`src/peer_manager.rs`): Channel-based single-task ownership for dynamic
  peer lifecycle management. Commands: AddPeer, DeletePeer, ListPeers, GetPeerState,
  EnablePeer, DisablePeer, Shutdown. (ADR-0017)
- Config: per-neighbor `import_policy` and `export_policy` sections in `[[neighbors]]`.
  Neighbor-specific policy overrides global; absence falls back to global.
- Config: starting with zero `[[neighbors]]` is now valid (peers added dynamically).
- Dependencies: `tokio-stream` (with `sync` feature) for `BroadcastStream` wrapper.
- Interop: 10-peer containerlab topology `m4-frr.clab.yml` (rustbgpd + 10× FRR).
  8 static peers + 2 dynamic. Automated test script `test-m4-frr.sh` with 7 test
  scenarios (17 pass/fail checks): static sessions, ListNeighbors, received routes,
  per-peer export policy, dynamic AddNeighbor/DeleteNeighbor, Enable/Disable.

### Changed

- MSRV bumped from Rust 1.85 to 1.88. Required for `let` chains and
  `usize::is_multiple_of()` stabilization.
- Dockerfile updated from `rust:1.85-bookworm` to `rust:1.88-bookworm`.

### Added (M3 — "Speak")

- `rustbgpd-policy`: `PrefixList` with ge/le range matching, first-match-wins
  evaluation, and `check_prefix_list()` convenience function. 9 tests.
- `rustbgpd-wire`: `UpdateMessage::build()` high-level constructor for creating
  outbound UPDATEs from structured data (announced prefixes, withdrawn prefixes,
  path attributes). 4 tests.
- `rustbgpd-rib`: `AdjRibOut` per-peer outbound route table. `OutboundRouteUpdate`
  type for announce/withdraw batches. (ADR-0015)
- `rustbgpd-rib`: `RibManager` gains outbound distribution: `distribute_changes()`
  computes deltas per peer with split-horizon and export policy filtering.
  `send_initial_table()` sends full Loc-RIB dump on peer establishment.
- `rustbgpd-rib`: Route injection via `InjectRoute` / `WithdrawInjected` messages.
  Injected routes stored under sentinel peer `0.0.0.0` in standard Adj-RIB-In,
  participating in normal best-path selection and distribution.
- `rustbgpd-rib`: `QueryAdvertisedRoutes` variant for querying Adj-RIB-Out per peer.
  8 new M3 tests (38 total).
- `rustbgpd-transport`: Per-peer outbound channel (mpsc, capacity 4096) receives
  `OutboundRouteUpdate` from RIB manager. `send_route_update()` converts to wire
  UPDATEs. `prepare_outbound_attributes()` handles eBGP (ASN prepend, NEXT_HOP
  rewrite, LOCAL_PREF strip) and iBGP (default LOCAL_PREF 100). 5 unit tests.
- `rustbgpd-transport`: Import policy filtering — inbound UPDATEs filtered by
  global prefix-list before RIB insertion.
- `rustbgpd-transport`: Max-prefix enforcement — tracks accepted prefix count,
  sends Cease/1 (Maximum Number of Prefixes Reached) NOTIFICATION when exceeded.
- `rustbgpd-transport`: TCP MD5 authentication (RFC 2385) via `setsockopt(TCP_MD5SIG)`.
  Linux only. Configurable per-neighbor via `md5_password` config field. (ADR-0016)
- `rustbgpd-transport`: GTSM / TTL security (RFC 5082) via `setsockopt(IP_MINTTL)`.
  Linux only. Configurable per-neighbor via `ttl_security` config field.
- `rustbgpd-transport`: TCP connection refactored to use `socket2::Socket` for
  pre-connect socket option application.
- `rustbgpd-api`: `InjectionService` with `AddPath` (returns UUID derived from
  prefix) and `DeletePath` gRPC endpoints.
- `rustbgpd-api`: `ListAdvertisedRoutes` implemented (previously UNIMPLEMENTED stub).
  Queries Adj-RIB-Out for a specific peer.
- `rustbgpd-telemetry`: New metrics — `rib_adj_out_prefixes` (gauge),
  `rib_loc_prefixes` (gauge), `max_prefix_exceeded` (counter).
- Config: `max_prefixes`, `md5_password`, `ttl_security` fields on `[[neighbors]]`.
  Global `[policy]` section with `import` and `export` prefix-list entries.
- Interop: 3-node containerlab topology `m3-frr.clab.yml` (rustbgpd + 2× FRR).
  Automated test script `test-m3-frr.sh` with 5 test scenarios: route
  redistribution, split horizon, route injection, withdrawal propagation, DeletePath.

### Added (M2 — "Decide")

- `rustbgpd-rib`: `Route` now carries `peer: IpAddr` for tiebreaking and gRPC
  reporting. Accessor helpers `origin()`, `as_path()`, `local_pref()`, `med()`
  extract attributes with RFC-appropriate defaults.
- `rustbgpd-rib`: Best-path comparison function `best_path_cmp()` implementing
  RFC 4271 §9.1.2 decision process: LOCAL_PREF → AS_PATH length → ORIGIN → MED
  → peer address. Deterministic MED (always-compare). Standalone function, not
  `Ord` on `Route`. (ADR-0014)
- `rustbgpd-rib`: Property tests for best-path comparison (antisymmetry,
  transitivity, totality) via proptest.
- `rustbgpd-rib`: `LocRib` struct — stores one best route per prefix, with
  incremental `recompute()` that returns whether the best path changed.
- `rustbgpd-rib`: `RibManager` now owns a `LocRib` and recomputes best paths
  on every announce, withdraw, and peer-down event. Only affected prefixes are
  recomputed. `QueryBestRoutes` variant added to `RibUpdate`.
- `rustbgpd-api`: `ListBestRoutes` gRPC endpoint with offset pagination,
  returning routes with `best: true`. `route_to_proto()` now uses `route.peer`
  for the `peer_address` field.
- Interop validation: FRR 10.3.1 — M1 automated test script (15/15 pass),
  `ListBestRoutes` returns correct best routes with pagination. Reuses M1
  containerlab topology (`m1-frr.clab.yml`).

### Fixed

- Interop test script: peer restart test (test 4) now relies on watchfrr to
  auto-restart bgpd instead of manually running `/usr/lib/frr/bgpd -d` which
  failed to load FRR's integrated config. Wait timeout increased to 90s to
  accommodate the 30s reconnect timer.

- `rustbgpd-wire`: Unknown NOTIFICATION error codes are now preserved as
  `NotificationCode::Unknown(u8)` instead of being silently mapped to `Cease`.
  This fixes incorrect logging and metrics for NOTIFICATIONs with future or
  non-standard error codes. (ADR-0011)
- `rustbgpd-transport`: Use `code.as_u8()` instead of `code as u8` cast for
  NOTIFICATION metric labels — more explicit and correct with the new enum
  representation.
- `rustbgpd-transport`: Fix hot reconnect loop when peer persistently rejects
  OPENs (e.g., ASN mismatch). Auto-reconnect now uses a deferred timer
  (connect-retry interval, default 30s) instead of firing `ManualStart`
  immediately. Discovered during malformed OPEN interop testing against FRR.

### Added (M1 — "Hear")

- `rustbgpd-wire`: `Ipv4Prefix` type with NLRI encode/decode per RFC 4271 §4.3
  prefix-length encoding. Host bit masking, 0-32 range validation, Display impl.
- `rustbgpd-wire`: Path attribute decode/encode (`decode_path_attributes`,
  `encode_path_attributes`) supporting ORIGIN, AS_PATH (2-byte and 4-byte),
  NEXT_HOP, MED, LOCAL_PREF, and unknown attribute preservation. Extended Length
  flag support.
- `rustbgpd-wire`: UPDATE attribute validation (`validate_update_attributes`)
  separate from structural decode. Checks: duplicate types (3,1), unrecognized
  well-known (3,2), missing mandatory attributes (3,3), flag mismatch (3,4),
  invalid NEXT_HOP (3,8), malformed AS_PATH (3,11). (ADR-0012)
- `rustbgpd-wire`: `ParsedUpdate` struct and `UpdateMessage::parse()` for
  combined NLRI + attribute decoding.
- `rustbgpd-wire`: Fuzz target for UPDATE decoder (`decode_update`), added to
  nightly fuzz CI.
- `rustbgpd-rib`: Adj-RIB-In implementation with `Route`, `AdjRibIn`, and
  `RibManager`. Single tokio task owns all state via bounded mpsc channel (4096).
  Queries via embedded oneshot. No `Arc<RwLock>`. (ADR-0013)
- `rustbgpd-fsm`: `UpdateValidationError` event — triggers NOTIFICATION and
  session teardown on RFC-violating UPDATEs. `UpdateReceived` is now payloadless
  (transport handles UPDATE content).
- `rustbgpd-transport`: UPDATE processing pipeline in `process_update()`:
  structural decode → semantic validation → RIB insertion → FSM event. Sends
  `PeerDown` to RIB on session teardown.
- `rustbgpd-api`: gRPC server via tonic with proto codegen. `ListReceivedRoutes`
  RPC with offset pagination (default page_size=100). Other RibService RPCs
  return UNIMPLEMENTED.
- Config: `grpc_addr` field in `[global.telemetry]` (default `127.0.0.1:50051`)
  with SocketAddr validation.
- Daemon: gRPC server spawned alongside metrics server and RIB manager.
- CI: `protobuf-compiler` installed in GitHub Actions workflow.
- Dockerfile: `protobuf-compiler` added to builder stage for tonic-build.
- Containerlab topology `m1-frr.clab.yml`: FRR advertising 3 prefixes
  (192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16) for UPDATE/RIB interop testing.
- Interop test script `test-m1-frr.sh`: validates routes received, path
  attributes, withdrawal propagation, and RIB clearing on peer restart.

### Added (M0 — "Establish")

- Workspace with 7 crates: wire, fsm, transport, rib, policy, api, telemetry
- gRPC proto skeleton (`rustbgpd.v1` package, all 5 services)
- Containerlab interop topologies for FRR 10.x and BIRD 2.x
- Design document, RFC notes, interop matrix template
- Roadmap with market context and milestone plan (M0–M4)
- `rustbgpd-wire`: OPEN, KEEPALIVE, NOTIFICATION, UPDATE encode/decode
- `rustbgpd-wire`: Capability parsing (4-byte ASN, MP-BGP, unknown pass-through)
- `rustbgpd-wire`: Strict 4096-byte message size enforcement
- `rustbgpd-wire`: `DecodeError::to_notification()` mapping for protocol errors
- `rustbgpd-wire`: Property tests (`encode(decode(x)) == x` roundtrip)
- `rustbgpd-fsm`: RFC 4271 §8 state machine (all 6 states, full transition table)
- `rustbgpd-fsm`: Timer management as input events / output actions
- `rustbgpd-fsm`: OPEN validation and capability negotiation
- `rustbgpd-fsm`: Exponential backoff on connect retry (30s–300s)
- `rustbgpd-fsm`: Property tests (no panics on arbitrary event sequences)
- `rustbgpd-telemetry`: Prometheus metrics (state transitions, flaps, notifications, messages)
- `rustbgpd-telemetry`: RIB metric stubs (registered at zero for M1)
- `rustbgpd-telemetry`: Structured JSON logging via tracing-subscriber with env-filter
- `rustbgpd-transport`: Single-task-per-peer Tokio TCP session runtime
- `rustbgpd-transport`: Length-delimited framing with `peek_message_length`
- `rustbgpd-transport`: Timer management with `poll_timer` future for `select!` compatibility
- `rustbgpd-transport`: `PeerHandle` / `PeerCommand` API for spawning and controlling sessions
- `rustbgpd-transport`: Full OPEN/KEEPALIVE handshake, reconnection, and teardown
- `rustbgpd-transport`: Telemetry integration (state transitions, messages, notifications)
- Daemon entrypoint: TOML config loading, peer spawning, graceful SIGTERM shutdown
- Prometheus `/metrics` HTTP endpoint served via `tokio::net::TcpListener`
- Config module (`src/config.rs`) with validation (router ID, neighbor addresses, hold time)
- CI workflow (`.github/workflows/ci.yml`): fmt, clippy, test on push/PR
- Nightly fuzz CI (`.github/workflows/fuzz.yml`): 5-minute wire decoder fuzzing
- `rustbgpd-wire`: Negative property tests — 5 corruption strategies (bit flip,
  truncation, insertion, overwrite, trailing garbage) verify decoder never panics
- `rustbgpd-wire`: Fuzz harness for `decode_message` via cargo-fuzz / libfuzzer
- Malformed OPEN interop test config (`rustbgpd-frr-badopen.toml`)
