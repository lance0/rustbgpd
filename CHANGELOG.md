# Changelog

All notable changes to rustbgpd will be documented in this file.

For releases before 0.68.0, see the [older release history](docs/project/changelog/older-releases.md).

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Opt-in received FlowSpec feasibility validation against the unicast RIB,
  including automatic revalidation after unicast changes. Set
  `[flowspec] validation = "rfc9117"` at startup; the default remains `"off"`.
  Infeasible candidates remain available through the received-peer FlowSpec
  view with their reason and pending state. Local injection remains trusted
  origination, and validation does not add a FlowSpec dataplane. The RIB
  actor-work histogram adds the `flowspec_validation` work-unit label.
- `rbgp rpki aspa CUSTOMER_ASN` and `rbgp rpki verify-path --role ROLE
  --neighbor-asn ASN "AS_PATH"` expose bounded merged-provider lookup and
  literal eBGP-unicast path verification through two `sensitive_read` RPCs.
  Results distinguish unavailable ASPA data, missing attestations, and
  authoritative empty data; verification reuses the ingress verifier and
  reports the first proven invalid customer/provider pair when available.

### Fixed

- Advertised-route explain JSON now includes each ORR candidate's inbound
  `path_id`, distinguishing Add-Path candidates that share a peer and next hop.
  The opt-in `rbgp-json` envelope advances to version 1.1 for this additive field;
  the separate `rbgp-rib` streaming format remains at 1.0. Exhaustive projection
  fixtures now guard the remaining curated RPC JSON views against field loss.
- Controller-injected unicast replacements and withdrawals now share the
  existing deferred attribute collection bound: 4,096 displaced routes or
  a one-second actor deadline for large intern tables. Route visibility,
  per-prefix distribution and successful RPC acknowledgement semantics are
  unchanged; small tables retain immediate collection.
- Publish the first accepted empty VRP and ASPA tables to validation consumers,
  allowing RPKI operator queries to report authoritative empty data correctly.
  Identical replays remain suppressed, and pre-accept disconnects do not
  fabricate available data.
- Keep live RIB readiness responsive during selection-deferral release and
  collision-failback staging, including all released route families. Readiness
  reports the current unicast Loc-RIB count while general reads and mutations
  remain queued; family convergence and table-before-EoR ordering are preserved.

## [0.71.0] — 2026-09-20

### Added

- Per-member BFD attachments now apply on SIGHUP: add or remove a neighbor,
  enable or disable BFD, or inherit it from a peer group without restarting
  the daemon. Non-strict attachment changes preserve BGP sessions; strict
  coupling continues to withhold BGP until BFD permits it. The first BFD
  session can be enabled after startup. Profile definitions remain
  restart-required, and BFD changes remain unsupported in config transactions.
  Apply attachment edits separately from TCP-AO rotation or edits to existing
  listener MD5/GTSM settings; mixed candidates are rejected before any effect.
  Peer-group RPC edits preserve file-defined BFD settings and reject effective
  BFD membership changes with instructions to use SIGHUP.
- `rbgp -j --json-version 1` emits a versioned `rbgp-json` document for
  supported inspection and management commands, preserving the existing result
  under `data`. Ordinary `-j` output and existing streaming formats are unchanged.

### Changed

- This release publishes documentation-only patch releases of two
  independently versioned crates: `rustbgpd-wire` 0.21.1 → 0.21.2, whose
  RFC 9003 shutdown-communication encoder now documents the deliberate
  128-byte sender cap alongside the 255-byte receive limit, and
  `rustbgpd-fsm` 0.8.1 → 0.8.2, whose `PeerConfig` timer fields now document
  that the FSM does not validate local timer settings and that the embedding
  application must enforce the RFC 4271 and RFC 9687 ranges. No public item
  was added, removed, or changed in either crate, and no encode, decode, or
  state-machine behavior changed, so each stays on its current compatibility
  line. `rustbgpd-fsm` 0.8.2 requires wire 0.21.2 or later on the 0.21 line.
  `rustbgpd-rpki` 0.3.1 is unchanged this cycle and is not republished.

### Fixed

- Service live RIB readiness during initial table export, including negotiated
  Add-Path limit replay. Bounded checkpoints and an executor handoff allow
  health replies to complete while the synchronous export still owns the RIB;
  ordinary reads and mutations remain queued, and health deadlines are unchanged.

- Skip closed session receivers in VPN, labeled-unicast, RTC, EVPN, BGP-LS,
  and FlowSpec distribution as well as unicast. Outbound prefix-limit recovery
  also discards closed receivers, including entries parked behind selection or
  ORF gates, so they cannot keep retrying before session teardown. Live peers
  retain their withdrawals, backpressure retries, and prefix-limit state.

- All-hot peer-group changes on SIGHUP now update already accepted dynamic
  sessions' inherited runtime knobs, including inbound prefix limits and GR
  retention caps. These updates retain the session identity and participate in
  generation compensation. Mixed session-shaping group edits still defer those
  dynamic settings until reconnect.
- Skip outbound update preparation for closed session receivers awaiting RIB
  teardown, avoiding repeated shutdown warnings and failed-send accounting.
  Healthy peers still receive withdrawals, and full live channels retain their
  backpressure warnings and resync retries.

- Unrelated SIGHUP changes and policy-only transactions no longer fail merely
  because an accepted IPv6 link-local peer's interface is temporarily missing.
  Hot updates retain its accepted scope, and configuration impact and checkpoint
  metadata projections no longer need a fresh socket scope. New and replacement
  sessions still require a resolvable interface before any reload effects.
- Unicast UPDATE replacement and withdrawal no longer sweep a large global
  attribute-intern table on every message. Collection runs after at most 4,096
  displaced routes (plus the triggering chunk) or a one-second actor deadline;
  a final source withdrawal still collects immediately. Small tables and
  explicit teardown paths retain immediate collection. The existing
  `bgp_rib_actor_work_duration_seconds` histogram adds `work_unit="attribute_gc"`
  for deadline-triggered sweeps outside ingest chunks.

### Upgrade notes

- A BFD attachment that SIGHUP previously ignored now takes effect. Review
  pending neighbor and peer-group BFD edits before reloading, because a
  reload that was previously a no-op for BFD now establishes or tears down
  BFD sessions. New profile definitions still require a restart before
  members can use them, and BFD changes remain unsupported in config
  transactions.
- In `--diff --json`, `restart_required.bfd_changed` now describes profile
  definitions only; an attachment change appears in the neighbor and
  peer-group diff instead. A consumer that gates a restart on that field sees
  a BFD attachment edit as an ordinary reload from this release on.
- An all-hot peer-group change applied by SIGHUP now updates the inherited
  runtime knobs of already accepted dynamic sessions, including inbound
  prefix limits and graceful-restart retention caps. A lowered inbound prefix
  limit therefore applies to a live dynamic session at reload rather than at
  its next reconnect. Mixed session-shaping group edits still defer those
  dynamic settings until reconnect.
- Unicast attribute-intern collection is now deferred until at most 4,096
  displaced routes, plus the triggering chunk, or a one-second actor
  deadline, so the interned attribute table can read larger immediately after
  a large replacement than it did before. A final source withdrawal, explicit
  teardown, and small tables still collect immediately.
  `bgp_rib_actor_work_duration_seconds` gains the `work_unit="attribute_gc"`
  label series for deadline-triggered sweeps outside ingest chunks; a
  dashboard that enumerates `work_unit` values sees one more.
- Upgrading directly from 0.70.0 also picks up the `bgp_event_outbox_storage_failed`
  gauge added in 0.70.2. It reads `1` once the event-history storage thread has
  stopped while the daemon runs, which is when the outbox refuses producer
  events and durable cursor subscriptions and `bgp_event_outbox_degraded` is
  also `1`. It distinguishes that runtime failure from shutdown-time drops and
  does not auto-clear; restart the daemon to recover.

## [0.70.2] — 2026-09-18

### Added

- `rs-config-render` in IXP Manager mode now renders members with multiple
  router connections on the peering LAN, emitting one `[[neighbors]]` block
  per VLAN interface keyed by `vlan_interface_id`. The renderer permits
  repeated customer IDs and ASNs across distinct interfaces and addresses,
  and requires `peering_ips` to be exactly the member's own interface
  addresses. A member whose interfaces disagree on IRR filtering or
  more-specifics is refused. Sessions operate under
  `next_hop_ownership = "strict_peer"`; routes announcing a sibling router's
  address as next hop are rejected with the `next_hop_ownership` reason,
  which the Birdwatcher adapter reports as IXP Manager reject reason 8
  ("NEXT HOP NOT PEER IP").
- `rs-config-render` in IXP Manager mode now renders members with IRRDB
  filtering disabled (`irr_filter: false` / `irrdbfilter` off): policies
  enforce hygiene and first-AS checks, plus RPKI-invalid rejection when the
  router has RPKI enabled, while omitting IRR prefix and origin dataset
  terms. On a router with RPKI off, such a member is filtered only by
  hygiene and the first-AS check. Render receipts record
  IRRDB-disabled members in `irrdb_disabled_clients` and `warnings`, and the
  render command prints each warning on stderr.
- The IXP Manager export skin emits a customer's UI-filter rows once per
  router even when the member has several interfaces on the VLAN.
- `just gate-ci` runs `just gate` plus the other `ci.yml` checks that need no
  privileges: `just test-feature-gated`, the new `just gate-ci-steps`, which
  runs the named script steps of the core and scale/receipt jobs straight
  from the workflow, and the new `just gate-msrv`, which checks the workspace
  on the `rust-version` toolchain. `CONTRIBUTING.md` lists the checks that
  remain CI-only.
- `just gate-release` runs locally the checks that otherwise first fail on a
  release commit in hosted CI: the metric release-note contract, the
  published-crate README freshness check, and the changelog heading of every
  crate whose manifest is ahead of the published record. On a release commit
  it also requires dated crate changelog headings, released crate README
  wording, and the root changelog section the release workflow extracts;
  `--heavy` adds `cargo audit`, the release build, and the publish dry-run.
  The `semver-checks` workflow now also runs on every `v*` tag push, and the
  CI and Interop workflows accept a manual dispatch.

### Changed

- The RTR client now caps a configured `expire_interval` above the RFC 8210 §6
  maximum of 172800 s (two days) at that maximum, with a warning. Such a value
  only mattered when the cache omitted its own expire. A non-zero value below
  the §6 minimum of 600 s is kept unchanged, because expiring early is safe.
  For `rustbgpd-rpki` library callers, `RtrClient::new` also raises a zero
  `expire_interval` to 600 s and bounds a `Some` `max_expire_interval` the
  same way; daemon configuration validation already rejects a zero
  `expire_interval` and a `max_expire_interval` above two days.
- This release publishes patch releases of the independently versioned
  crates: `rustbgpd-wire` 0.21.1 (a `FlowSpecAction::TrafficAction`
  documentation correction), `rustbgpd-fsm` 0.8.1 (ORF receive families
  limited to the negotiated MultiProtocol families), and `rustbgpd-rpki`
  0.3.1 (RTR client refresh, retry, and expire interval bounds). No public
  item was added, removed, or changed, so each stays on its current
  compatibility line; FSM 0.8.1 and RPKI 0.3.1 require wire 0.21.1 or later
  on the 0.21 line.

### Fixed

- SRv6 service eligibility now treats the compressed End.DT2M flavors,
  End.DT2M with NEXT-CSID (behavior 68) and End.DT2M with REPLACE-CSID
  (behavior 124), as argument-capable, as RFC 9819 section 3 specifies.
  Previously only End.DT2M (24) was accepted with a nonzero Argument Length,
  so EVPN BUM routes over uSID/CSID SRv6 that carried an ESI-filtering
  argument were reported as `srv6_sid_invalid`, excluded from selection, and
  withdrawn from peers. As for End.DT2M, a behavior 68 or 124 SID advertised
  without a SID Structure is now ineligible (RFC 9819 section 2); such routes
  were previously selected.
- The Linux EVPN dataplane now retries a failed delete of an L3 (all-active
  Type 5) FDB nexthop or nexthop group on later reconcile passes, as it
  already did for L2 FDB nexthop groups. Previously the orphaned kernel object
  stayed until the periodic drift sweep removed it. Retry bookkeeping is also
  cleared whenever the kernel confirms a delete. Previously, if the drift
  sweep removed a nexthop whose failed delete was queued for retry, the queued
  retry could later delete a new L2 FDB nexthop that had reused the same ID.
  `pending_delete_count` in `ListEvpnNexthops` still counts only L2 FDB
  nexthop IDs.
- A peer that advertises the Outbound Route Filtering Send role for an
  address family outside the session's negotiated MultiProtocol families no
  longer counts as ORF-negotiated for that family. A peer whose only ORF Send
  entries were for such families was kept out of update-group sharing for the
  whole session, and `rbgp rib --prefix P advertised PEER --explain` reported
  an `orf_pending` stop for such a family, which no ROUTE-REFRESH could lift,
  instead of the family not being negotiated. Route advertisement was
  unaffected.
- SIGHUP now applies a route-server member join or leave with its datasets
  when the member carries `md5_password` or `ttl_security` (GTSM). The change
  applies as one compensated runtime generation, not as a rejected compound
  candidate, so `rs-config-render activate` settles these candidates for MD5
  members and GTSM fleets without a restart, and unchanged members keep their
  sessions. The daemon installs the joining member's listener MD5 key or GTSM
  selector before it adds the session, and withdraws a leaving member's entry
  only after the session is removed. If the generation fails later, the prior
  member set, dataset bindings, and listener MD5 keys and GTSM selectors are
  restored. A static neighbor added or removed with its own authentication
  but without dataset changes also takes the generation route now, instead
  of the sequential route. Changing the password or GTSM setting of a
  neighbor that stays configured is still sequential on its own and rejects
  when combined with dataset changes. The runtime refusal for adding an
  authenticated neighbor through a config transaction now says that SIGHUP
  applies the join, datasets included, as one generation.
- `rs-config-render activate` and `ixp-manager-lifecycle run` now roll back
  when the daemon rejects the reload without runtime effect, instead of
  returning exit 5 for manual recovery. Examples are a generation combined with
  an honor-knob edit, or a dataset change combined with an in-place MD5 or GTSM
  edit. The helper reads `rbgp metrics` before the activation command, then
  re-points `current` at the previous generation. It exits 7 (`rolled_back`,
  release callback delivered) only when a second read shows the same daemon
  process recorded exactly one SIGHUP outcome, `rejected_no_effect`, no
  runtime-config settlement is in progress, and the daemon still runs the
  previous generation. A settle timeout without that outcome, a dropped or
  additional reload, a daemon restart, a partial apply, or an unreachable
  daemon still returns exit 5.
- `rs-config-render` no longer rejects an RPKI-valid route that lacks an IRR
  route object when the incumbent accepts it. In IXP Manager mode with RPKI
  on, the client's `reject-irrdb-prefix-filtered` term now rejects only a
  route outside the member's prefix set that is not RPKI-valid, after the
  origin-AS check, as IXP Manager v7.4's BIRD templates do. In arouteserver
  mode, `irrdb.use_rpki_roas_as_route_objects` was ignored; it now renders an
  accept term for an RPKI-valid route whose origin is in the client's AS-SET,
  tags it with `prefix_validated_via_rpki_roas` when configured with
  `tag_as_set`, and scrubs that tag on entry. RPKI-invalid routes are still
  rejected by shared hygiene. Before the RTR cache's first End of Data, every
  route reads `not-found`, so these routes are rejected until the cache syncs
  wherever IRR prefix enforcement is on. In an arouteserver context with
  `irrdb.enforce_prefix_in_as_set` off there is no prefix term to fail, so an
  authorized origin is accepted regardless of RPKI state, and the generated
  in-language self-check for that case expects `accept`.
- `rbgp config plan`, `config apply`, and `config rollback` now exit 3 when the
  daemon rejects the transaction. A rejected plan previously exited 2, the
  same code as a committable plan, and a rejected apply or rollback exited 0,
  the same code as a commit. The full receipt, including `--json` output, is
  still printed before the non-zero exit. A receipt with an unrecognized
  status now exits 1 instead of passing as a commit or as changes present.
- VPNv4/VPNv6 and labeled-unicast best-path selection now breaks a tie
  between routes from the same peer on the lower Add-Path path identifier, as
  IPv4/IPv6 unicast selection already did. Two Add-Path routes from one peer
  with identical attributes previously tied through every step, so the
  selected route, the Add-Path send ranking, and the Optimal Route Reflection
  per-vantage choice followed arrival order: withdrawing and re-advertising
  the selected path could move selection to the other one. FlowSpec selection
  gains the same final step; FlowSpec does not negotiate Add-Path, so its
  selection does not change.
- Durable event history now stops cleanly when its storage thread exits or
  panics while the daemon runs. Previously the outbox kept accepting events
  and dropped every batch, while new `SubscribeFromEvent` streams were
  admitted and never received an event. The outbox now closes producer
  admission, ends open `SubscribeFromEvent` and gNMI `Subscribe ON_CHANGE`
  streams with `DATA_LOSS`, and refuses new `SubscribeFromEvent` requests with
  `UNAVAILABLE`. It logs `event-history storage stopped` and sets the new
  `bgp_event_outbox_storage_failed` gauge and `bgp_event_outbox_degraded` to
  `1`. The example Prometheus rules add a critical
  `BgpEventOutboxStorageFailed` alert. A restart is required to recover. A
  SQLite commit failure is still a per-batch loss and does not stop the
  outbox.
- Event history no longer quarantines its database after a single failed
  open. It retries once after 200 ms and quarantines only if the retry also
  fails, so a brief lock or I/O error no longer discards the stored history.
  A quarantine no longer overwrites an earlier one: an existing
  `events.db.stale` set moves to `events.db.stale.1` (or the next unused
  number) first. The configuration reference now documents how to restore a
  quarantined store by hand.
- Best-path selection now gives a locally originated route a fixed place at
  the BGP Identifier step (RFC 4271 §9.1.2.2 step (f)): it ranks ahead of
  every session-learned route, and two locally originated routes tie there.
  The step previously had no value for such a route and passed the pair on
  to the CLUSTER_LIST and peer-address steps, which made the comparison
  intransitive for a locally originated route that carried a CLUSTER_LIST
  or a peer address other than `0.0.0.0`. With such a route among iBGP
  candidates tied down to this step, the selected best path depended on the
  order the candidates were examined in, and sorting a larger candidate set
  could panic. The daemon builds every locally originated route with the
  `0.0.0.0` local peer and no CLUSTER_LIST, and that shape already won the
  later steps against every session-learned route, so the selected route
  does not change for them. The unicast, ORR, VPN, labeled-unicast,
  FlowSpec, BGP-LS, RT-Constrain, and EVPN chains share the change.
- `rbgp config import` now prefixes its stderr errors with `Error:`, like
  every other `rbgp` command, instead of `error:`. Scripts that match the
  lowercase prefix on import failures need updating. Exit codes are
  unchanged.
- The event-history outbox now releases its `event_id` allocator explicitly
  when a batch insert fails after ids were assigned, so the rolled-back batch
  is counted as a per-batch loss and the next batch commits. Previously, in
  debug builds, the allocator's leak check panicked the storage thread on that
  rollback, which closed the outbox until restart. Release builds were
  unaffected.
- The `[[fib_tables]]` reconciler now wakes for install-candidate changes
  that keep the winning best path. An equal-cost member added, withdrawn,
  lost to a session drop, or re-advertised with a new next hop under
  `maximum_paths > 1` reaches the kernel on the event path (about 200 ms
  debounce) instead of waiting for the 30 s periodic pass. The RIB
  publishes a payload-free candidate-change signal, bumped once per unicast
  distribution batch, beside the existing route events; the reconciler
  treats both as the same wake and the periodic pass remains the backstop.
  Route events themselves are unchanged: they still report best-path
  changes only. The interop ECMP lanes wait 30 s for a kernel row again.
- The event-history outbox no longer quarantines an `events.db` whose
  `schema_version` is newer than the daemon supports. The open now fails with
  a message naming both versions and the two remedies (upgrade the daemon, or
  move the store aside by hand); with `[event_history].required = true` the
  daemon exits 1, otherwise it continues in live-only mode. Previously the
  recovery ladder treated the newer store like corruption, moved it to
  `events.db.stale`, and started an empty one. No released daemon has bumped
  the schema version yet, so this only affects a future downgrade.
- A peer that has been sent a ROUTE-REFRESH response no longer keeps its
  update group out of the clean export-policy transition. Previously an
  export-policy reload for a group containing such a peer took the slower
  fallback path until the peer's next outbound resync. Advertised routes were
  unaffected.

### Upgrade notes

- A daemon downgraded onto an `events.db` written by a newer daemon now stops
  (`required = true`) or runs live-only (`required = false`) with the store
  untouched, instead of moving the store aside and starting an empty one.
  Upgrade the daemon again, or move `events.db` and its `-wal` / `-shm` files
  aside before starting the older daemon.

- `rs-config-render` render receipts gain two keys, `irrdb_disabled_clients`
  and `warnings`. Activation, `status`, and `recover rollback` accept both
  the previous six-key shape and the new one, so generations rendered before
  this release remain valid current generations and rollback targets. Zero
  `counts.prefixes` or `counts.origins` are accepted only when every client
  is listed in `irrdb_disabled_clients`.
- `rbgp config diff` and `rustbgpd --diff` report
  `SIGHUP reload route: generation` for a member join or leave that carries
  `md5_password` or `ttl_security`, where they previously reported
  `rejected` (with datasets) or `sequential` (without). Such a reload now
  needs no restart. A generation that applies but cannot withdraw a departed
  member's listener entry returns a known-partial receipt with bucket
  `listener_auth.withdraw`. The entries it leaves cover only addresses that
  are no longer configured.
- A candidate that the daemon rejects without runtime effect now makes
  `rs-config-render activate` and `ixp-manager-lifecycle run` exit 7 instead
  of 5, with `current` back on the previous generation, the activation receipt
  `rolled_back`, and no host fence. Wrappers that branch on the exit code need
  no change: 7 already means the candidate was not applied and a retry is safe.
  The exit-7 stderr text is now `candidate not applied; prior generation
  restored` (`...; lock released` for the lifecycle). The helper also makes one
  `rbgp metrics` call per activation, which needs the same gRPC read access as
  `rbgp health`. If `current` was restored but the rejection could not be
  re-proven, exit 5 now leaves `current` on the previous generation.
- `rs-config-render` output changes for IXP Manager sites with RPKI enabled:
  each `policy/client-<id>.rpol` prefix term gains `&& route.rpki != valid`
  and three in-language tests, so candidate hashes change once and members'
  RPKI-valid routes without IRR route objects are accepted after activation.
  As in IXP Manager, no option restores the stricter prefix-set-only term.
- arouteserver contexts with `irrdb.use_rpki_roas_as_route_objects.enabled`
  now render the ROA accept term, emit `[rpki]`, and require `--rtr-cache`
  even with origin validation disabled; the flag also requires
  `irrdb.enforce_origin_in_as_set`. Enabled
  `irrdb.use_arin_bulk_whois_data` or `irrdb.use_registrobr_bulk_whois_data`
  now refuses the render (exit 2) instead of being ignored. An unknown key in
  the general `irrdb` section or under its `use_*` options fails the render
  with exit 1.
- Scripts that gate on `rbgp config plan`, `config apply`, or
  `config rollback` now see exit 3 for a rejected transaction. `plan` keeps 0
  for noop and 2 for committable. `apply` and `rollback` keep 0 for a commit
  and also exit 0 for a noop; the receipt's `status` field tells them apart.
  A wrapper that applies after `plan` exits 2 no longer reaches an apply the
  daemon would refuse. A wrapper that treats every `plan` exit other than 1
  as "changes present" must handle 3 as a rejection.
- After an event-history storage failure, event producers see a closed
  outbox. The accepted events that could not be written count as
  `bgp_event_outbox_dropped_total{reason="db_error"}`, and events refused after
  the failure count as `reason="closed"`, the label that previously meant only
  shutdown. Use `bgp_event_outbox_storage_failed` to tell the two cases apart.
  New gNMI `Subscribe ON_CHANGE` streams end with `DATA_LOSS` until the daemon
  restarts.
- Earlier event-history quarantines are now kept as `events.db.stale.<n>`
  files, which are full copies of the store and are never deleted
  automatically. Remove them when they are no longer needed. A failed
  event-history open now delays startup by 200 ms before quarantine.
- When a locally originated best route ties a session-learned route down to
  the BGP Identifier step, explain output now reports `lower_bgp_identifier`
  with detail `bgp_identifier local < <identifier>` (EVPN:
  `effective BGP identifier local versus <identifier>`) instead of
  `shorter_cluster_list` or `lower_peer_address`. When that session-learned
  route is the runner-up, BMP path marking for a unicast best route carries
  the "router ID" reason code instead of the peer-address code or no reason
  code. The selected route is unchanged.

## [0.70.1] — 2026-09-15

### Security

- **`rustls` 0.23.43 → 0.23.45 clears RUSTSEC-2026-0285** (TLS 1.3 handshake
  messages accepted across encryption level boundaries). The crate is
  transitive via `tokio-rustls`/`tonic` and `ureq`, which makes the TLS gRPC
  listener and rustls-based clients the exposed surfaces. Lockfile-only: no
  configuration change is needed.

### Added

- `rs-config-render`'s IXP Manager router document accepts an optional
  `listen_port`, which defaults to 179 and refuses `0`.

### Changed

- `[global].dynamic_neighbor_limit` is now reload-applied instead of
  restart-required. Changing the limit in the configuration and reloading
  updates the dynamic peer admission ceiling immediately without dropping
  existing sessions or requiring a daemon restart. If the limit is lowered
  below the current connected dynamic peer count, active sessions are
  retained and new connections are refused until natural session departures
  bring the count below the new ceiling. Capacity and headroom metrics
  (`bgp_dynamic_neighbor_slots_limit`, `bgp_dynamic_neighbor_slots_headroom`)
  update on reload.

- **Operator-visible:** `rbgp config diff` and `rustbgpd --diff` now print
  `datasets: contents not compared (N declared); a reload re-reads them`
  whenever the candidate declares `[policy.datasets]`, and no longer print
  `No changes.` for such a candidate, because previews compare configuration
  and bindings but never dataset file contents. The JSON output adds
  `declared_datasets_count` under both `summary` and `reload_applied`. Exit
  codes are unchanged: an IRR-only refresh that changes dataset files while
  the TOML stays identical still exits 0, so reload on every rendered refresh
  rather than gating the reload on the diff's exit code.

### Fixed

- `rbgp config diff`, `plan`, and `apply` now resolve relative `rpol_files`,
  `rpol_roots`, and `[policy.datasets.*].path` references against the candidate
  file's parent directory before sending the candidate TOML to the daemon. The
  daemon evaluates gRPC configuration candidates without an inherited working
  directory, so relative policy and dataset paths previously failed with
  missing-file errors when comparing or planning candidates outside the daemon's
  working directory.

- A daemon started with a relative config path (for example
  `cd /etc/rustbgpd && rustbgpd config.toml`) now records absolute
  `rpol_files`, `rpol_roots`, and `[policy.datasets.*].path` values, as an
  absolute launch already did. `rbgp config diff` no longer reports false
  policy path changes against such a daemon, and `rbgp config plan` and
  `apply` no longer reject every candidate that declares `rpol_files` or
  datasets. `rbgp config effective` and configs persisted by such a daemon
  now show absolute paths. `rustbgpd --diff` resolves both files the same
  way, so the same file spelled relatively and absolutely compares equal.

- SIGHUP now applies `[policy.datasets]` binding changes through the same
  compensated runtime generation as dataset contents instead of rejecting
  them. Adding, removing, or re-mapping a dataset, together with the matching
  `[[neighbors]]` change, applies without a daemon restart, so a route-server
  member join or leave with its own datasets no longer flaps every other
  member. A late failure restores the prior binding set, dataset contents,
  policy chains, and sessions and rejects cleanly; a newly declared dataset
  that fails to load rejects the candidate before any effect. Binding changes
  combined with TCP-AO rotation, listener MD5/GTSM changes,
  `[[dynamic_neighbors]]`, EVPN runtime tables, `[[fib_tables]]`, or the honor
  knobs still reject before any effect.
- `rs-config-render activate` now rewrites `[policy.datasets.*].path` into the
  activation `current/` tree for its `rbgp config diff` comparison, the same
  way it already rewrites `rpol_files` and `rpol_roots`. The daemon resolves a
  gRPC candidate without a base directory, so a candidate with relative
  dataset paths previously failed the settle check with a missing-file error
  and `activate` exited 5 against a healthy daemon. Every rendered IXP
  candidate declares per-client datasets, so member joins and leaves through
  `activate` now settle and exit 0.
- `SetGlobalImportChain`, `SetGlobalExportChain`, `ClearGlobalImportChain`, and
  `ClearGlobalExportChain` no longer fail with `policy_state_non_established`
  while a configured neighbor is positively Idle, Connect, or Active. That
  session holds the new chain and installs it, with its RIB outbound
  registration, at `PeerUp`. Ambiguous observations (the session is gone or
  its state query times out) still fail closed with `INTERNAL` and full
  compensation. Routes retained under an active GR/LLGR window stay evaluated
  under the prior chain until re-sync.

### Upgrade notes

- Route-server member joins and leaves that add, remove, or re-map
  `[policy.datasets]` bindings now apply through SIGHUP without a restart and
  without flapping other members, and `rs-config-render activate` settles such
  candidates and exits 0. A join or leave of a member that carries
  `md5_password` or `ttl_security` (GTSM), which covers every join and leave
  in a fleet whose members use GTSM, also changes the listener's MD5/GTSM keys
  and is still rejected before any effect. For those fleets
  `rs-config-render activate` does not settle, and a restart is still required
  to apply the change. Binding changes combined with the listed
  authentication, dynamic-neighbor, EVPN, FIB, or honor-knob changes still
  reject before any effect.
- `rbgp config diff` and `rustbgpd --diff` print a
  `datasets: contents not compared` notice, and no longer print `No changes.`,
  for a candidate that declares `[policy.datasets]`. JSON output adds
  `declared_datasets_count` under `summary` and `reload_applied`. Exit codes
  are unchanged, so an IRR-only refresh still exits 0: when datasets are
  declared, do not gate the reload on the diff's exit code.
- `[global].dynamic_neighbor_limit` is now reload-applied. Lowering it below
  current occupancy keeps existing dynamic sessions and refuses new
  connections until the count falls under the new limit.
- `rbgp config diff`, `plan`, and `apply` send relative `rpol_files`,
  `rpol_roots`, and dataset paths as absolute paths resolved from the
  candidate file's directory. The daemon opens those paths itself, so run
  these commands on the daemon's host with candidate files the daemon can
  read. A daemon started with a relative config path now records absolute
  policy and dataset paths, so `rbgp config effective` and configs it
  persists show absolute paths, matching an absolute launch.
- Global import and export chain set and clear calls no longer require every
  configured session to be Established: a positively down session adopts the
  new chain when it comes up. An ambiguous session state still fails with
  `INTERNAL`.

## [0.70.0] — 2026-09-13

### Added

- Added a verified release installer that resolves one release tag, matches a
  per-architecture checksum manifest, and supports explicit tags,
  download-only, and tarball-prefix modes without starting a service.

- The RIB logs one `post-commit first general query timing` record per
  committed export-policy transition that an operator read follows within
  ten seconds: the terminal commit poll's duration, the general queries and
  primary updates queued at commit, the wall-clock wait from the end of that
  poll to the first general or summary query dispatched, elapsed wall time in
  completed route-chunk, primary-update, and dirty-resync work units, and the
  unattributed remainder (including other actor work, idle time, and
  scheduling delays). A synchronous owner still running when a summary
  dispatches from the frozen view or during retirement remains unattributed.
  This describes the RIB side before query execution,
  not end-to-end operator latency. The historical event name is retained;
  `query_lane` identifies the dispatch lane and `queued_summary_queries` adds
  its queue depth at commit.

- Added `bgp_rib_actor_work_duration_seconds{work_unit}` and
  `bgp_rib_readiness_query_wait_seconds{seam}`. The first times route-chunk
  construction and processing, coalesced outbound distribution, and subsequent
  exact-export rejection retirement separately. The second measures admitted
  readiness queries until actor service, including service after caller timeout,
  through both ordinary drains and synchronous replacement checkpoints. These
  support correlation rather than identifying every probe timeout: distribution
  services readiness internally, and query waits exclude admission wait, prior
  peer-manager work, and reply delivery. Both use the shared RIB actor latency
  buckets, including an exact 200 ms boundary. Actor scheduling is unchanged.

- Added `bgp_peer_manager_operator_query_wait_seconds{seam}`, timing each
  operator-lane read (neighbor snapshots, policy stats, dataset status) from
  send until peer-manager service begins, including bounded-channel admission
  wait. Service after the caller's deadline still contributes a sample; sends
  canceled before admission and reads never drained do not. The wait excludes
  work before the send, service execution, and reply delivery. The closed
  `seam` set is `unfenced`, `prestage` (policy preflight, cohort selection,
  destination prestage and session setup), `forward_transition`,
  `commit_batches`, and `rollback`. It reports the current command's policy
  marker, or the latest completed marked command overlapping the wait;
  intervening ordinary commands preserve it. A marker includes trailing
  command work. Reads report their entire wait under one label, not the
  time caused by each phase. Fenced phases
  produce samples only after reads are drained, so per-seam counts depend on
  arrival timing and are not phase load. Buckets retain the shared RIB actor
  latency edges and add an exact 2 s edge: 100 ms, 500 ms and 2 s are caller
  budget boundaries, and `count - bucket{le="2"}` counts waits over 2 s.

- Authenticated `ControlService.CheckLiveness` and `rbgp health --liveness`
  answer without topology disclosure using the `read` authorization tier.
  The new RPC is outside the narrow v1 contract. Ordinary `rbgp health`
  retains its actor-readiness checks and detailed output.

- Experimental `rbgp neighbor PEER replay-out` schedules one peer's IPv4/IPv6
  unicast replay for eligible outbound-only BMP collectors. It requires a
  unicast-only negotiated session and a unique address among managed peers. The new
  `ReplayOutbound` RPC acknowledges scheduling; terminal BMP EoRs follow local
  writer completion. See the [bounded replay contract](docs/reference/api.md#replay-one-peers-unicast-routes-with-terminal-eors).

- Added `bgp_update_malformed_causes_total{peer,type_code,reason,disposition}`
  with bounded reported cause labels, including typed RFC 9774 prohibited
  AS sets, and the final applied disposition. The existing malformed-UPDATE
  counter keeps one increment per message; mixed attribute-discard and ASPA
  first-AS failures now increment only the final treat-as-withdraw row.

- SIGHUP reloads of static neighbors, peer groups, inline policy, changed
  `.rpol` content, and dataset contents with unchanged bindings now settle as one owned
  runtime generation. The daemon
  resolves the complete candidate once and derives one session action per
  peer, so a peer-group reshape and an explicit edit of one of its members
  rebuild that session exactly once and a replacement receives its final
  policies directly. The prior config, compiled `.rpol` registry, resolved
  chains, dataset snapshots and loader errors, and captured session configs
  are retained through the whole
  operation: a later step failure restores them from memory and reports a
  clean rejection with the candidate file left in place, instead of adopting
  a partial result. Lost acknowledgement or a failed restore still fences the
  daemon. `rustbgpd --diff` and the runtime config-diff API report the
  `SIGHUP reload route` the candidate would take (`sighup_reload` in JSON).

- `rbgp doctor --pre-upgrade CONFIG` adds read-only pre-upgrade checks to the
  existing doctor run, against the config file the upgraded daemon will boot:
  `upgrade.transaction` (the same evidence as `rbgp config status`),
  `upgrade.settlement` (the runtime-config settlement watchdog gauge), and
  `upgrade.posture` (the candidate's resolved RFC 8212 epoch/posture against
  the live effective posture, with the documented omitted-versus-explicit
  rules). A pending, applying, rollback-failed, or ambiguous confirmed
  transaction, an active settlement owner, a posture mismatch, and any
  unavailable, denied, or unimplemented evidence are red with the operator
  action to take; the mode never confirms, aborts, rewrites, or stops
  anything. Plain `doctor` keeps its check set, RPC set, JSON shape, and exit
  contract; the mode adds a `pre_upgrade` object with the observation instant
  to `--json` output and a `pre_upgrade` section to the bundle manifest.

- `just fuzz-list` and `just fuzz <crate> <target>` run the cargo-fuzz
  inventory from the crate that owns each `fuzz/Cargo.toml`, which is the only
  directory cargo-fuzz can resolve a target from. Both recipes read the target
  list from the existing inventory check and select the reviewed nightly from
  `fuzz/rust-nightly.txt`. `just hooks` installs the commit and push hooks.

- Accepted normalized configs larger than 10 MiB now record bounded,
  metadata-only config-history rows with hashes, byte count, and a redacted
  summary. They share the twenty-row chronology with rollback-capable v2
  entries, and API/CLI listings explicitly mark them rollback-ineligible.
  History listing rejects an over-cap directory before decoding any final.

- Policy stats audit records retain per-stage elapsed time, remaining budget at
  entry, and gRPC outcome for peer validation, export, import, and datasets.
  Debug tracing exposes the same stage timings for reload diagnostics.

- VPN and EVPN Prefix-SID API, CLI JSON, and text views include an optional
  `reconstructed_sid` alongside the raw advertised SID when a single route
  supplies an unambiguous Function transposition. Missing labels, ambiguous
  structures, invalid ranges, and Argument-dependent composition leave it
  absent; raw attributes and route selection are unchanged.

### Changed

- Prepare the independently versioned `rustbgpd-wire` 0.21.0 crate with
  additive UPDATE error-context APIs and diagnostic refinements, alongside
  `rustbgpd-fsm` 0.8.0 and `rustbgpd-rpki` 0.3.0 for the matching public
  wire-type boundary. Registry examples remain on the last verified
  published versions until those releases are published. RPKI 0.3.0 also makes
  `RtrPdu`, `RtrDecodeError`, `RtrEncodeError`, and `RtrError` non-exhaustive:
  downstream exhaustive matches need a fallback. Existing constructors and
  fields are unchanged; `ProviderAuth` and `VrpUpdate` remain exhaustive.

- Import policy statistics read the selected session's installed live counters
  without waiting for its command queue. The shared two-second deadline,
  cancellation and all-or-error responses remain. Success establishes counter
  availability rather than session progress; numeric fields are sampled during
  collection, with generation and labels tied to one installed chain.

- The route-server flagship soak analyzer now fails its `/readyz` gate on
  three consecutive breached samples rather than on a single one. This follows
  Kubernetes's default failure count; the soak's 30-second interval and 250 ms
  response limit remain separate choices from Kubernetes's 10-second and
  one-second defaults. It tolerates isolated breaches while rejecting missing
  observations. The verdict reports the total breach count, the longest consecutive
  run, and the first 20 offending samples, separating a non-200 status
  (including a failed request) from a late 200. See the
  [readiness acceptance policy](docs/soaks/soak-acceptance-gates.md#readiness-acceptance-and-kubernetes-probes).

- The container healthcheck now uses `rbgp health --liveness`: it checks gRPC
  responsiveness rather than core-actor readiness. Override it with
  `--health-cmd='rbgp health'` to retain the previous probe. Successful `read`
  authorization audits now log at DEBUG; counters and other audit levels
  are unchanged. Deployment guidance includes bounded container log retention.

- gRPC credential rotation on SIGHUP now runs after the runtime generation is
  acknowledged, so a candidate rejected at preflight or restored after a
  failure has no credential effect. Rotation failure remains non-fatal with
  the last-known-good generation active.

- Local checks that compile now serialize on one lock in the target directory,
  so `just gate` and a concurrent commit or push wait for each other instead of
  building the same workspace twice at once. Separate worktrees with separate
  target directories are unaffected.

- The container image now pins its account to uid/gid 999 and declares a
  numeric `USER`, so a base-image rebuild cannot shift the uid that
  deployment docs tell operators to chown host bind mounts to, and
  Kubernetes `runAsNonRoot` verifies the image without the pod spec
  repeating `runAsUser`. The container workflow asserts the built image's
  uid and gid.

- The image healthcheck now uses `rbgp health`'s exit status instead of
  matching pretty-printed JSON text. The previous probe required a space
  after the colon in `"healthy": true`, so a change of JSON writer would
  have reported every healthy daemon unhealthy. The container workflow
  now exercises the declared healthcheck in both the reachable and
  unreachable directions.

- Published-crate documentation now refreshes with one command after registry
  verification. Preparation and CI use an offline version record; release
  updates no longer require editing contract tests.

### Fixed

- `GetPolicyStats` now returns `DEADLINE_EXCEEDED` when a backend reply is
  observed at or after its shared two-second deadline, including a ready final
  dataset reply. Stage audit status reflects the same deadline decision.

- Canceling outbound replay now releases the session while BMP admission,
  enrollment, or RIB admission is blocked. Once the BMP queue accepts the
  replay-begin event, ordinary mirrored EoRs remain suppressed even if enrollment
  is abandoned, preventing a partial capture from appearing complete; BGP EoR
  transmission is unchanged.

- Shared update-group consumers yield at their bounded chunk checkpoints even
  when the encoder has already completed, allowing other tasks to enqueue
  session-state and import-counter reads during the drain. Encoder election,
  command ordering, and writer failure handling are unchanged.

- The route-server flagship soak drains its management probes before releasing
  the engine's final session shutdown. The analyzer checks this ordering against
  the daemon log, preventing natural teardown from being counted as a stable
  prefix failure while preserving every recorded probe result.

- **Operator-visible:** Forward API policy transactions and policy-only
  publication-failure compensation now admit session
  snapshots, import-policy statistics, and dataset status at the same
  peer-manager waits as SIGHUP applies. `TestPolicy` uses that operator lane
  for its live peer context while retaining the route-page version fence.
  Reads report live observations without a shared generation across their
  sources; session ACK/bookkeeping fences, other transaction stages, and RIB
  work can still exhaust caller deadlines.

- Export-policy counters and the RIB portion of neighbor status can be read
  during synchronous export replacement, rollback, and dataset reevaluation.
  A separate bounded summary lane serves values captured before the operation.
  The daemon hands the executor to sibling tasks during this synchronous scope,
  allowing the RPCs woken by those replies to run; general route queries and
  mutations retain their fences. Reads return current
  RIB values after completion. Existing RPC deadlines remain unchanged, and
  peer-manager/session observations in the same response remain independent.
  Projection capture must finish before this service begins; capture and
  retirement timings are available in diagnostic builds.

- RIB backlog draining before timers, export-policy destination preparation,
  and deferred initial registrations now serves bounded reads and yields
  between route chunks and primary messages. Earlier route payloads still
  complete before later End-of-RIB messages or timer release; an aggregate
  of short ingest work can no longer bypass the ordinary actor fairness seam.

- **Operator-visible:** The peer manager now serves session snapshots,
  import-policy statistics, and dataset status while a rejected reload awaits
  enqueue or completion of its batched RIB restore. These reads report live
  state, including sessions whose restoration failed; they do not promise a
  common policy generation. Mutations and the rollback's two-minute batch
  budget are unchanged.

- Outbound refresh, GSHUT refresh, and live export-knob refresh share one
  five-second budget for RIB queue admission and acknowledgement. Refresh
  and replay scheduling serve readiness and operator reads while waiting;
  hot-knob refresh keeps reads fenced until manager metadata catches up with
  the session. An already-admitted read retains its own deadline if scheduling
  expires or its caller disconnects. Later mutations remain queued until that
  read and the scheduling step settle.

- Forward policy transactions admit bounded operator reads during read-only
  qualification and state probes, authoritative per-peer RIB waits, and between
  acknowledged session policy steps, including SIGHUP honor-knob fan-outs.
  Dataset settlement carries explicit forward or compensation admission through
  RIB capacity and reply waits; legacy dataset
  refresh also bounds RIB capacity using the existing five-second allowance.
  Individual session acknowledgements keep their fences; clean generation
  compensation admits live reads, while earlier restoration failures retain the
  fence against inconsistent metadata. Existing operator RPC deadlines and
  mutation ownership are unchanged.

- **Operator-visible:** `rbgp policy stats` and `rbgp neighbor` no longer fail
  with `DEADLINE_EXCEEDED` when they arrive while a SIGHUP reload's batched
  export-policy transition is in progress. Both actors previously parked
  operator reads behind the whole RIB transition, so a read arriving more than
  about 0.8 s before the commit exhausted its two-second budget at 1000 peers.
  The peer manager now keeps serving session snapshots and import-statistics
  collections while it awaits the batched RIB reply, on the same terms as
  during destination prestaging, and the RIB answers general queries from the
  pre-commit state between its pre-commit transition polls. Reads that arrive
  during the short commit batches still wait for the commit, which remains the
  single switch point; a paged route listing started before the commit cannot
  be continued across it. Budgets, the reload's atomic commit, and rollback
  fencing are unchanged.

- **Operator-visible:** a configuration reload could be rejected with no runtime
  effect when one peer's session-state query was slow during heavy RIB load.
  The slow peer was excluded from the batched export-policy cohort and fell to
  the serial authoritative walk, where each per-peer RIB command was allowed
  only five seconds — while that command performs a full Loc-RIB distribution
  pass of its own and can legitimately take longer under load. The walk and the
  RFC 8212 presence proofs that precede it now share one absolute two-minute
  deadline for RIB channel admission and replies across the walk, matching the
  batched cohort's allowance for equivalent work. Session-only preflight and
  hot-apply work before the first RIB command do not start the deadline.
  Single-peer inline policy edits retain a five-second allowance, now covering
  channel admission as well as the reply. Because the budget is now a total
  rather than a fresh allowance per peer, a whole-fleet fallback that previously
  accumulated unbounded time across peers is bounded and fails sooner. Rollback retains
  its separate budget and existing exact-state restoration or fail-closed
  handling. The graceful-shutdown and blackhole knob fan-outs and the dataset
  dependent proofs carried the same per-peer exposure and are bounded the same
  way.

- The scale matrix now finishes and records each active management probe before
  shutting down the daemon, preventing orphaned CLI requests and missing final
  CSV rows. Cleanup waits for owned processes and retains the daemon exit status;
  a native daemon that exceeds its shutdown deadline is killed and the cell fails.
  After final evidence capture, BGP stubs stop churn, send Cease, and drain
  incoming output before exiting; task failures or a fleet timeout fail the cell.

- IPv4-unicast reflection with an unchanged IPv6 next hop now suppresses
  export to peers without Extended Next Hop support, instead of emitting
  classic IPv4 NLRI without NEXT_HOP. Ordinary eBGP and export-policy rewrites
  that supply an IPv4 next hop remain eligible.

- NOTIFICATION diagnostics now describe the maintained registered code/subcode
  table, including Connection Rejected and Other Configuration Change. Unknown
  pairs retain numeric values as `unassigned(code/subcode)` or
  `reserved(code/subcode)`, including inside Hard Reset notifications.

- FlowSpec byte/packet traffic-rate helpers now interpret and construct
  negative rates as zero, following RFC 8955 sections 7.1 and 7.2. They also
  canonicalize NaN and negative zero to positive zero as a local choice,
  preserving positive rates including positive infinity. This affects typed
  action interpretation and construction, including byte-rate API views and
  injection; raw extended-community storage and reflection remain unchanged.

- `rbgp --json flowspec` now includes raw `extended_communities` as numeric
  values, preserving their order and duplicates alongside the curated actions.

- `rbgp --json flowspec` now includes ordered `component_details` records with
  the API component type, prefix, value, and offset. The existing formatted
  `components` array is unchanged.

- gNMI neighbor snapshots now use the operator-read lane on TLS and Unix
  listeners and for dial-out subscriptions. `Get` and subscription snapshots
  can complete during policy waits that admit operator reads, retaining live
  session values, the two-second peer-manager deadline, and terminal stream
  errors when a snapshot is unavailable.

- `rbgp doctor` attributes local process limits and config freshness to the
  connected Unix-socket peer, with process-start verification and reconnect
  updates. Co-resident daemons no longer contribute unrelated low-limit
  failures. TCP and unavailable local identities do not trigger process scans
  or borrow another daemon's config; an unreachable local socket retains the
  packaged-file first-deploy fallback.

- M83 waits for the latest BIRD session's captured OPEN, exact initial route
  inventory, and End-of-RIB before stopping packet capture. Incomplete capture
  snapshots remain pending within a bounded wait, and timeout retains diagnostics;
  the final closed-file and wire-attribute checks remain mandatory.

- AS_PATH prepend policy validation now rejects AS 0 in TOML and literal
  `.rpol` actions, and rejects `.rpol` parameters resolving to AS 0 when a
  chain is attached. Invalid policies previously reached evaluation before
  the existing wire encoder rejected the resulting AS_PATH.

- SIGHUP generations no longer reinstall unchanged RPOL chains solely because
  an unreferenced literal set changed in the same source file. The runtime keeps
  installed counters while adopting the candidate policy catalog; pending
  retries and dataset-dependent refreshes still run. Policies with local set
  bindings, loops, or collapsed set aliases, and mixed TOML/RPOL chains retain
  their existing structural comparison. Exact-equal chains also retry pending
  import refresh or export application instead of skipping that work.

- The IXP matrix retains timestamped health-probe errors alongside its latency
  CSV, so failed operator checks identify the daemon error in the receipt.

- Export policy changes now update the accepting session’s collision-recovery
  record. Promoting a surviving session preserves its accepted policy, including
  explicit permit-all and rollback. Superseded session records release their
  compiled policy ownership; registry and other runtime owners remain separate.

- The route-server and route-reflector flagship soak analyzers now require
  valid daemon-log evidence and fail on every daemon `ERROR`, including
  metrics listener failures that successful client probes can miss. Verdicts
  also report `WARN` counts by message.

- `rbgp policy stats` now allows backend waits up to one shared 2-second
  deadline, increased from 500 ms. This lets reads wait through longer
  `.rpol` reload transitions that temporarily queue RIB queries. Reloads or
  congested backends that exceed the budget still return `DEADLINE_EXCEEDED`
  with no partial rows.

- Periodic BMP statistics no longer park peer-manager reads or shutdown
  indefinitely on a full RIB mailbox. Loc-RIB sampling bounds queue admission and reply together;
  session, peer-RIB, and Loc-RIB sample waits run concurrently instead of
  accumulating three separate waits. Unavailable values are still omitted.

- The paired route-server cookbook now starts the RFC 8671 post-policy BMP
  capture before RS2's member sessions establish: the `rib_out_post` stream
  sends no dump to a collector that connects later, and
  `rbgp diff snapshot from-bmp` refuses a capture missing a peer's End-of-RIB.
  Neither `rbgp neighbor <peer> refresh-out` nor a member's ROUTE-REFRESH
  completes a late capture. The comparison step now passes
  `--ignore-attribute unknown` for the OTC attribute a route server attaches
  on the wire.

- Dataset content refreshes now recompute shared export-policy results before
  refreshing advertisements. Grouped peers previously replayed cached results,
  leaving newly denied routes advertised and newly permitted routes absent.
  Each affected group is recomputed once, including per-client-best groups;
  unrelated groups and installed policy counters are preserved.

- Config transactions now durably stage their candidate next to the config
  file before touching any session, catalog, or policy state. An ordinary
  disk failure — an unwritable or read-only config directory, a full
  filesystem, or a candidate the daemon cannot derive from its accepted
  config — is reported as `FAILED_PRECONDITION` while every live session
  keeps its identity, uptime, and counters. Previously every transaction
  family applied its runtime change first and compensated after the write
  failed, so a peer-group or neighbor edit could rebuild sessions the
  failure then rebuilt again. A rename that fails after the stage is still
  compensated exactly as before; an ambiguous publication or a lost
  acknowledgement still fences and exits 70.

- Removing the global export chain through SIGHUP now remains effective when
  a peer reconnects. The daemon previously restored its startup fallback
  chain when the peer's current effective chain was empty. Export policy
  statistics now report installed peer chains without a separate `global`
  fallback row; this row was not an aggregate of peer counters.

- The update-group registry now releases unused compiled policy contents
  after regrouping or discarded preparation. Across repeated distinct
  reloads, the registry retains only live group and transition payloads;
  historical ID slots remain so retired IDs cannot alias another policy.

- Export-policy rollback into an occupied compatible update group now shares
  the movers' policy delta and encoding without rebuilding the group or
  replaying its unchanged members. Dataset-dependent policies and other
  nonqualifying transitions retain the existing per-peer fallback; dirty
  members keep their ordinary resync and withdrawal recovery.

- `rbgp doctor` now shares one parsed effective-config document across checks
  and probes explicit BGP listener addresses instead of substituting loopback.
  Local failed binds remain red; default wildcard probes tolerate one unavailable
  address family, and remote listener probes identify their CLI vantage.

- Policy-statistics reads can proceed while a normal neighbor inventory or
  detail read waits for session state. Additional neighbor reads remain bounded,
  and peer mutations wait for the active snapshot to finish or be canceled.
  Request deadlines and policy-transaction fences are unchanged.

- Neighbor and policy-statistics reads can complete during a forward SIGHUP
  generation's export-destination prestaging, before installed policies or
  datasets change. Later policy application, rollback, and standalone mutations
  remain fenced; existing read deadlines and complete-result requirements remain.

- Session-state and import policy-statistics reads can proceed while grouped
  unicast updates are encoded or streamed. Reads preserve command order across
  queued policy changes and other mutations; the shared statistics deadline and
  complete-result requirements are unchanged.

- Service RIB readiness probes throughout synchronous export-policy
  replacement and rollback, including construction, per-peer work, and
  cleanup. Ordinary queries remain fenced, and readiness replies retain the
  exact Loc-RIB count and the existing transition-age limit.

- Native SIGHUP measurement and flagship soak runners now require terminal
  daemon success as well as receiver delivery before recording a reload as
  complete. Rejection or rollback fails that cycle before A/B alternation can
  turn it into a misleading later re-advertisement stall.

- Canceled session diagnostics no longer hold later neighbor and import-counter
  reads behind an unfinished shared update stream. Cancellation releases reads
  already deferred by the session; queued mutations keep their FIFO position
  even when their acknowledgement receiver has closed.

- Neighbor and import-counter reads can complete while a live explicit outbound
  replay waits for BMP admission, collector enrollment, or RIB admission. Replay
  retains its original five-second deadline and channel queue positions; deferred
  mutations and live diagnostics keep later commands behind them.

### Upgrade notes

- Embedders using the prepared wire 0.21, FSM 0.8, or RPKI 0.3 source
  versions must upgrade dependencies that exchange public wire types together.
  The wire additions preserve existing parse and validation signatures, but
  the new 0.x dependency line gives those types a different crate identity.

- The container healthcheck now checks gRPC liveness with `rbgp health
  --liveness`. Deployments that require core-actor readiness should override
  it with `--health-cmd='rbgp health'`. Ordinary `rbgp health` retains its
  readiness checks.

- Consumers of `GetPolicyStats` or `rbgp policy stats` should use the installed
  peer rows. The daemon no longer reports a `global` export fallback row.

- A config transaction whose candidate cannot be staged on disk now fails
  before any session is reset. Expect no session churn from such a failure;
  the successful path, its response, and its history rows are unchanged.
  File-driven SIGHUP reload is unaffected: an operator-managed or read-only
  config file acquires no API write requirement.
- A green `rbgp doctor --pre-upgrade` result is an observation at one instant,
  not a maintenance fence: a config transaction can start after it. The
  race-free package upgrade procedure remains preflight, coordinated stop,
  verify the service is inactive, repeat the candidate `rustbgpd --check
  --strict` and any offline authority checks, then install and start; the
  runbook now names the diagnostic as its preflight step and keeps the
  post-stop checks explicit.

- A SIGHUP candidate that changes static neighbors, peer groups, inline
  policy, `.rpol` content, or dataset contents **together with**
  `[[dynamic_neighbors]]`, EVPN runtime tables, `[[fib_tables]]`, or
  `honor_graceful_shutdown` / `honor_blackhole` is rejected before any effect.
  Dataset content generations require unchanged names, kinds, file mappings,
  and handles; binding changes require a restart. Dataset changes combined
  with listener MD5/GTSM authentication or TCP-AO rotation also reject.
  Without dataset changes, authentication-bearing candidates retain the
  sequential path, which offers no restoration of earlier steps.
- Dataset content generations reject malformed input before publication and
  require local dependent-refresh settlement. Established import dependents
  need Route Refresh; offline peers remain eligible when their state is known
  and no GR/LLGR routes are retained. A failed generation restores dataset
  contents at a new monotonically increasing generation, then refreshes every
  potentially affected peer. Lost acknowledgements or unknown state fence the
  daemon. This does not promise remote replay completion or atomic visibility
  across datasets or BGP sessions.
- Generation-class reload failures no longer produce a known-partial
  runtime receipt; the sequential path keeps its known-partial semantics.

- After config-history v3 publication, stop the daemon and preserve/move the
  complete history directory aside before starting an older writer that
  ignores v3. Metadata rows cannot restore oversized configs; keep deployment
  sources independently. Commit-confirm v3 recovery remains a separate lifecycle.

- `bgp_update_group_interned_chains` now counts currently retained registry
  payloads, rather than all contents seen since startup. The
  `bgp_update_group_keys` gauge still counts historical key slots. Group IDs
  remain stable while their policy contents are live and across no-op
  reloads; reinstalling a fully retired policy creates a new ID.

## [0.69.0] — 2026-09-07

### Added

- Config diff impact reasons now name directly changed `.rpol` policy terms
  for static neighbors and dynamic ranges. Text and JSON preserve the existing
  reasons and reload classifications; ambiguous structural changes retain
  broader attribution.

- Native gRPC TLS expiry visibility through
  `bgp_grpc_tls_certificate_not_after_seconds{kind}` for the active server leaf,
  supplied server bundle minimum, and supplied client CA bundle minimum.
  Successful client handshakes log observed leaf expiry. The restart-required
  `tls_expiry_warning_seconds` setting defaults to `0` (warnings off); a
  positive window adds startup, reload, client-handshake, and config-check
  warnings. Plain `--check` retains exit 0 for warnings and `--strict`
  returns 1. Bundle dates are metadata, not effective handshake cutoffs, and
  expiry visibility does not introduce date-based startup rejection.

- VPN and EVPN route views now expose optional Prefix-SID raw bytes and flags,
  advertised SRv6 SID values, numeric endpoint behavior, and SID Structure
  fields. EVPN explain and current/previous event snapshots retain the same
  view. CLI text summarizes advertised values; JSON retains complete raw
  attribute hex and reports malformed stored data without partial decoding.
  This adds inspection only, with no SID reconstruction or forwarding.
- Prepared wire `0.20.0`, FSM `0.7.0`, and RPKI `0.2.0` compatibility lines
  for the new public Prefix-SID inspection API and shared wire types. Registry
  dependency examples continue to name the currently published versions.

- Python gRPC client example under `examples/python-client/`: an export-gate
  explain script and a controller script that checks health, watches the live
  event stream, and injects then withdraws a route. Both call only v1-stable
  methods, attach the bearer token as channel-composed call credentials rather
  than per-call metadata, and set an explicit deadline on every RPC. The README
  covers stub generation and warns that an owner-only Unix socket authorizes
  its clients at operator tier, so a local run proves nothing about the
  authorization the deployed identity will meet.

- Explicit `rbgp --json-lines` output for accepted unicast best, received,
  and advertised routes. The versioned stream emits routes page by page and
  ends with matching-row counts and completeness; ordinary JSON arrays and
  limited envelopes retain their existing output and failure behavior.

- Website ingest manifest in `docs/site-manifest.json`, checked in the public
  docs workflow so moving a consumed page without updating its source mapping
  fails CI. Site destinations remain independent of repository page paths.

- Read-only Model Context Protocol server (`rustbgpd-mcp`) exposing the
  explain surfaces to an MCP host over stdio: export-gate ladder, import
  decision, best-path selection, retained rejections, neighbors, and health.
  It runs on the operator's workstation as a gRPC client, adds no process to
  the daemon host, and ships in no release artifact — build it with
  `cargo build -p rustbgpd-mcp`. Read-only rests on two controls: no write
  tool exists in the binary (fenced by a contract test against the gRPC
  method inventory) and a listener capped at `max_tier = "sensitive_read"`.
  Remote HTTPS connections verify the server and present a client certificate;
  every tool bounds the complete gRPC response at 30 seconds. See the
  [how-to](docs/how-to/mcp-server.md) and
  [ADR-0131](docs/adr/0131-read-only-mcp-server.md).

- `rbgp_explain_evpn_route` on the MCP server: exact EVPN route explain
  (RFC 7432 Types 1-5) carrying the selection story and the export gate ladder
  from `ExplainEvpnRoute`. The response states in words that an empty retained
  source is neither an import-rejection explanation nor proof the peer never
  sent the key, and that a deferred selection means the installed best may
  differ from fresh selection.

- Per-neighbor EVPN received and advertised route views through additive
  `ListReceivedEvpnRoutes` / `ListAdvertisedEvpnRoutes` RPCs and
  `rbgp evpn received|advertised PEER`. Type/RD filters and bounded pages
  expose accepted post-policy input and committed output while preserving
  each route's source peer. Continuation tokens reject table changes.

- Exact EVPN route explain through `ExplainEvpnRoute` and
  `rbgp evpn explain`: typed selectors cover Types 1–5, including both
  Type 1 forms and distinct MAC-only / MAC+IP keys. The response separates
  retained accepted input, installed best, fresh selection, current export
  eligibility, and committed outbound state. Import rejection history and
  remote receipt or installation are not inferred.

- Reproducible EVPN reflector fanout runner with separate initial-load and
  churn phases, exact withdrawal checks, and a dated receiver-count baseline.
  The load generator accepts `--churn-delay-sec` (default zero).

- EVPN discard visibility by wire route type through the additive
  `bgp_evpn_nlri_discarded_by_type_total{peer,route_type}` counter and one
  warning per type per TCP connection. The existing peer aggregate counter
  and RFC 7606 discard behavior are unchanged; repeated discards continue
  counting without repeated warnings.

- `just lab quickstart up|verify|break|explain|down`: a guided local BGP
  exercise using the Docker Compose demo. Verify a route, remove its import
  policy, explain the RFC 8212 rejection, and restore the policy.
  See the [operator lab guide](docs/tutorials/operator-labs.md).

- **Operator-visible:** EVPN interop receipts for an IPv6 VXLAN underlay,
  the first in the suite to run tunnel endpoints, BGP transport, and EVPN
  next hops entirely on IPv6. M109
  (`tests/interop/m109-evpn-ipv6-underlay-vtep.clab.yml`) covers the L2 path
  against FRR 10.7.1 — Type 3 IMET and Type 2 MAC-only plus MAC+IP in both
  directions with the originator's IPv6 VTEP address as a 16-octet next hop,
  and remote-MAC kernel FDB rows carrying an IPv6 `dst` — and runs in hosted
  `kernel-dataplane` CI. M110
  (`tests/interop/m110-evpn-ipv6-underlay-irb.clab.yml`) covers symmetric
  Interface-less IRB over the same underlay and is a manual leg. Both
  topologies assert that the underlay carries no IPv4 address, so no
  fallback path can satisfy an assertion. `docs/reference/limitations.md` now records
  that Interface-less IRB has no `RTA_VIA`: under an IPv6 VTEP only IPv6
  tenant prefixes are carried.

- **Operator-visible:** a received Address-Prefix ORF entry whose maximum
  length is below its own prefix length (for example `10.0.0.0/8 le 4`) can
  never match a route. The daemon installs it exactly as before and now logs
  one `warn` line per ORF update naming the peer, the family, and each
  impossible window (`<prefix> min <n> max <n>`). The entry is not rejected:
  RFC 5291 §5.2 clears the whole list on a malformed entry, which would fail
  open to permit-all.
- `rbgp policy explain --direction <import|export>`. The default `import`
  is the existing per-session import-decision cache lookup and still
  requires `[policy.explain] enabled = true`; `export` runs the read-only
  export dry run behind `rbgp rib --prefix <cidr> advertised <peer>
  --explain` (unicast, unlabeled, best source) and needs no configuration.
  `--path-id` with `--direction export` is rejected before the daemon is
  dialed, pointing at the `rib advertised --explain --source-peer` /
  `--source-path-id` flags for Add-Path source selection. Shell completions
  regenerated.
- Tiered `just` recipes for the local developer loop: `check-fast`,
  `check-contracts`, `check-devtools`, `check-clippy`, `docs`, `test-crates`,
  `test-bins`, and `test-integration` split `just gate` into runnable
  pieces, and `test-feature-gated`, `test-ignored`, and `netns` expose the
  feature-gated, ignored, and privileged network-namespace test surfaces that
  hosted CI runs. `just gate` runs the same commands in the same order as
  before.

- **Operator-visible:** RFC 5883 multihop BFD. Setting
  `bfd = { profile = "...", multihop = true }` on a static global neighbor
  uses UDP/4784 with the same profiles, inspection, metrics, events, and RFC
  5882 coupling as single-hop BFD. Both modes transmit with TTL/Hop-Limit 255;
  multihop has no receive minimum-TTL knob. When configured,
  `[global].listen_addresses` supplies the per-family multihop transmit source.
  M108 validates Up, forwarding-loss Down and BGP teardown, and recovery
  against FRR over routed /32 loopbacks.

- `tcp_mss` on `[[neighbors]]` and `[peer_groups.<name>]` clamps the TCP
  maximum segment size (`TCP_MAXSEG`, 88..=32767 bytes) for sessions behind
  tunnels or reduced-MTU paths. **Operator-visible:** the clamp is installed
  on the active-open socket before connect. Each bound passive listener socket
  takes the smallest effective value across resolved static neighbors of the
  same address family before listen, so an IPv4 tunnel constraint does not
  down-clamp IPv6 sessions. Every accepted child inherits its family's clamp.
  Dynamic-range peer groups cannot set `tcp_mss`. Omitting the field leaves it
  unset; values outside the kernel range are rejected at load. The field is
  restart-required.

- **Operator-visible:** `rs-config-render` now renders arouteserver IRR white
  lists instead of refusing them: `white_list_pref` and `white_list_asn` join
  the client's prefix and origin datasets, and each `white_list_route` entry
  becomes an ordered accept term ahead of IRR enforcement, bound to the
  entry's origin ASN when given and tagged with the site's
  `route_validated_via_white_list` community (standard and large forms; the
  hygiene policy scrubs the tag on entry). The render receipt counts each
  client's white-listed routes. A configured `ext` form or a malformed tag
  value is now refused, as are arouteserver's four IRR result communities,
  which the daemon cannot preserve; all five were previously ignored.

- **Operator-visible:** `rs-config-render` now renders an effective
  `rfc8950: true` IPv6 session for a uniform IPv6 fleet: the session carries
  both unicast families, so the daemon negotiates the RFC 8950 extended next
  hop, and `next_hop_ownership = "strict_peer"` binds IPv4 routes to that
  session's IPv6 address. A fleet that also has IPv4-session members, or an
  active `blackhole_filtering.policy_ipv4`, is still refused (ADR-0128 keeps
  next-hop translation demand-gated).

- `NeighborService.ResetNeighbor` (outside v1, `mutating` tier) and
  `rbgp neighbor <addr> reset [--reason <text>]` bounce one enabled session:
  Cease / Administrative Reset with the optional RFC 9003 shutdown
  communication and TCP close without changing the peer's enable/disable
  state. Static active-open peers retry on their normal schedule; an accepted
  dynamic peer is removed when it reaches Idle and must dial in again. Unknown
  peers return `NOT_FOUND`; disabled peers return `FAILED_PRECONDITION`.
- **Operator-visible:** the daemon now speaks the systemd notify protocol
  without a new dependency: `READY=1` once every configured gRPC listener is
  bound, the configured peer roster is installed, and BGP ingress is active;
  a gRPC bind failure enters the existing shortened startup teardown instead.
  `STOPPING=1` marks coordinated shutdown, and `WATCHDOG=1` is sent at half
  `WATCHDOG_USEC` while the PeerManager and RIB actors answer the same bounded
  core-actor probe `/readyz` uses. PID 1
  independently applies the five-minute watchdog deadline. The
  shipped `rustbgpd.service` and `rustbgpd@.service` units switch to
  `Type=notify`, `NotifyAccess=main`, `WatchdogSec=5min`, and
  `TimeoutStartSec=10min`;
  `Restart=on-failure` already covers a watchdog kill. Without `NOTIFY_SOCKET`
  nothing changes.
- `examples/peer-loop`: a minimal BGP speaker whose rustbgpd dependencies are
  `rustbgpd-wire` and `rustbgpd-fsm`. It dials one peer, drives the FSM to
  Established, performs the required socket, timer, and session actions,
  sends KEEPALIVEs on the negotiated timer, and prints each successfully
  parsed UPDATE. Its loopback tests exercise the library-embedding shape in
  `docs/reference/embedding.md`.
- `[[rpki.cache_servers]]` accepts `md5_password` (RFC 2385) or a
  neighbor-shaped `tcp_ao` keyring (RFC 5925); the key is installed on the
  RTR socket before connect. **Operator-visible:** key material the kernel
  refuses is a startup error, a cache holding a different key never completes
  the handshake and is logged as `RTR connection failed` after a 10 s bound,
  and there is no plaintext fallback. Both fields are redacted by
  `rbgp config effective`, rejected when the `<redacted>` placeholder is
  loaded back, and restart-required like the rest of `[rpki]`. RTR over TLS
  or SSH remains unimplemented. `rustbgpd-rpki` gains
  `RtrClient::with_dialer` for embedders that open the connection themselves.

- `rs-config-render --help` now lists its rendering, activation, status,
  pruning, recovery, and IXP Manager lifecycle command paths.

- `rbgp --pager auto|always|never` now provides terminal-aware paging for
  complete human best, received, and advertised unicast RIB listings.

- `rbgp rib lookup <IP|CIDR>` now performs one atomic IPv4/IPv6
  longest-prefix match against the global Loc-RIB and renders the existing
  best-path explanation in human or JSON form. Invalid targets, no covering
  route, and daemons without the outside-v1 RPC remain distinct failures; the
  CLI never falls back to a route-table scan.

- Accepted received, best, and advertised RIB queries now share typed RPKI and
  ASPA verdict filters plus exact numeric `AS_SEQUENCE`/`AS_SET` membership via
  `--as-path-contains`. All predicates compose with count and bounded listing,
  bind continuation-token identity, and reject unknown verdicts or ASN 0.

- Add a self-contained IPv4 two-member `--init-config route-server` starter
  with fail-closed import policy and explicit transparent export.

- `rbgp top` now opens an on-demand route explorer from peer detail: `v`
  cycles the global unicast Best table and the selected peer's Received,
  Advertised, and Rejected tables, `f` toggles IPv4/IPv6 unicast, `/` applies
  an exact prefix filter with a longer-prefixes toggle, `Space`/`PgDn` move
  within a server page while `n`/`p` follow server page tokens, and `e`
  explains any typed prefix for the peer. Every scope change cancels the
  in-flight request and restarts at page 1; a stale page token restarts once
  and is named in the status line.

- **Operator-visible:** `max_prefixes_received_ipv4` / `max_prefixes_received_ipv6`
  (neighbor and peer-group, hot-applied) bound the unique unicast prefixes a
  peer announces **before** import policy: accepted and rejected prefixes count
  once each, Add-Path identities share one slot, and withdrawals and
  enhanced-route-refresh sweeps release slots exactly. Violations use the same
  latched Cease/1 teardown, RFC 4486 data, Notification GR encapsulation, and
  timed-restart contract as the accepted-route bounds, and the
  `bgp_max_prefix_usage`/`_limit`/`_headroom` gauges gain the
  `ipv4_unicast_received` and `ipv6_unicast_received` scopes while the bound is
  configured. Enabling the bound on an Established session requests a route
  refresh so existing rejections are recounted (ADR-0108 amendment).

- **Operator-visible:** `max_prefix_action = "block" | "warning"` and
  `max_prefix_warning_percent` (neighbor and peer-group, hot-applied) add the
  non-teardown max-prefix modes. `block` withholds net-new prefixes beyond a
  full per-family bound while the session stays Established (already accepted
  prefixes keep taking attribute changes and Add-Path identities), opens a
  blocking episode visible as `bgp_max_prefix_blocking{peer,scope}` and an
  `inbound_prefix_limits[]` row with reason `inbound_prefix_limit_reached` in
  `rbgp neighbor <addr>`, counts each blocking episode once in
  `bgp_max_prefix_blocked_total{peer,scope}` when the first prefix is withheld,
  and requests one route refresh when usage falls back under the bound or
  blocking is disabled. Peers without route-refresh support require
  reannouncement or a session reset to recover withheld routes. Admission
  reserves net-new prefixes across a whole UPDATE, so one batch cannot
  overshoot either bound. `warning`, or a
  `max_prefix_warning_percent` threshold under any action, emits one warn log
  line, one `max_prefix_warning` session event, and one
  `bgp_max_prefix_warning_total{peer,scope}` increment per crossing. Neither
  mode latches the peer; `block` requires the aggregate `max_prefixes` to be
  unset and both exclude `max_prefix_restart_seconds`. The neighbor API and
  CLI gain `inbound_prefix_limits[]` (one row per finite bound) and report
  `max_prefix_action` as `block`/`warning` when configured.

- **Operator-visible:** export one
  `bgp_peer_info{peer,interface,remote_asn,description,peer_group}` identity
  gauge per configured and dynamic peer so dashboards and alerts can name a
  member instead of its bare address. The row is published on install,
  replaced in place on a description, peer-group, or learned-ASN change, and
  reaped with the other per-peer series on delete; `description` and
  `peer_group` are scrubbed of control characters and bounded to 128
  characters. The shipped overview dashboard adds a **Peer identity** row
  with a `group_left(remote_asn, description)` join, and
  `BgpSessionNotEstablished` now carries `remote_asn`, `description`, and
  `peer_group` labels with a fallback that still fires for peers without an
  identity row. No existing metric family or label changes.

- **Operator-visible:** `birdwatcher-adapter` serves
  `GET /routes/table/{table}/filtered`, the table-wide retained-reject dump
  Alice-LG's single-table source reads for its prefix-lookup routes store.
  Rows render exactly as the peer filtered view; the retention envelope sums
  the table's live sessions (capacity, evictions, `may_be_incomplete`) and
  an inventory-stability retry rechecks the neighbor inventory and returns
  HTTP 502 after three changed snapshots. The endpoint adds no truncation
  beyond each peer's bounded retention store. The pinned IXP compatibility
  gate now runs Alice-LG 6.2.0 with `enable_prefix_lookup = true` and proves an
  AS-path-loop and an import-policy rejection through Alice's filtered view
  and global prefix lookup.

- `just lab ixp up|verify|break|explain|down`: a local route-server exercise
  with two FRR members and a pinned RPKI cache. Introduce an invalid origin
  and a prefix-length rejection, explain the import and export decisions,
  then restore and verify transparent route delivery to the other member.

- `just lab rr up|verify|break|explain|down`: diagnose an unintended
  duplicate origin, inspect the route reflector's identifier tie-break and
  split-horizon export decision, and restore the intended source.

- `just lab monitoring up|verify|break|explain|down`: stop a BMP collector
  while BGP remains live, inspect delivery diagnostics, and verify a decoded
  Loc-RIB route snapshot after the collector reconnects.

- Add optional EVPN `duplicate_ip_detection` diagnostics per L2VNI, disabled
  by default. Conflicting local/local and local/remote IPv4 or IPv6 ownership
  uses an M/N window, with `evpn_duplicate_ip_moves_total{vni}` and
  `evpn_duplicate_ip_threshold_exceeded_total{vni}` counters and an
  IP-specific warning. Replayed bindings, sticky MACs, same-segment peer-sync
  routes, and duplicate-MAC-quarantined contenders are excluded. This slice
  does not quarantine IPs, probe neighbors, or change routing actions.

- `rbgp policy check --coverage-matched-min PCT` independently gates the
  percentage of source terms matched by in-language tests. Coverage reports
  include matched totals; existing evaluated-term percentages and
  valid `--coverage-min` semantics remain unchanged. Matched coverage does not
  guarantee branch coverage or detect every widened guard.

- Opt-in `.rpol` policy fallbacks with `default-action accept|reject`,
  declared before terms. Omission keeps accept-and-continue behavior;
  a rejecting fallback stops the chain and discards staged changes.
  Defaults also apply to parameterized policies and `apply` predicates.

### Changed

- Refreshed the transitive HTTP/gRPC stack: `hyper` 1.8.1 → 1.11.1 and `h2`
  0.4.16 → 0.4.19. This lockfile-only update applies upstream HTTP/2 trailer
  handling and frame-budget hardening to the tonic gRPC and gNMI listeners.

- Refreshed internal TLS dependencies to tokio-rustls 0.26.5, rustls 0.23.43,
  rustls-webpki 0.103.15, and rustls-pki-types 1.15.1. tokio-rustls can return
  more data from a stream read; provider selection and TLS configuration remain
  unchanged.

- `rbgp rib add` uses `--next-hop` as the canonical flag, retaining
  `--nexthop` as a visible compatibility alias. The default RIB pager now
  wraps long lines (`less -FRX` in auto mode, `less -RX` in always mode);
  explicit `RBGP_PAGER` and `PAGER` arguments remain unchanged.

- Root `rbgp` help and the man-page command index group commands by task,
  preserving command paths, aliases, and subcommand help.

- The three example programs (`event-bridge`, `peer-loop`, `birdwatcher-adapter`)
  now build under the same lint policy as the workspace crates
  (`deny(unsafe_code)`, `deny(clippy::all)`, `warn(clippy::pedantic)`).

- `rustbgpd-wire` 0.19.0 → prepared 0.20.0 compatibility line. Its additive
  `mrt` API adds `decode_table_dump_v2_mp_reach_next_hop`, the RFC 6396 §4.3.4
  `TABLE_DUMP_V2` RIB-entry `MP_REACH_NLRI` next-hop decoder, now shared by
  the daemon's warm-checkpoint reader and `rbgp diff snapshot from-mrt`.
  `rustbgpd-fsm` is prepared at 0.7.0 and `rustbgpd-rpki` at 0.2.0; their
  public signatures expose wire types, so the wire requirement follows the
  prepared workspace pin to `^0.20.0`.

- **Operator-visible:** the EVPN MAC and ESI text forms are parsed by one
  grammar shared by the configuration loader and the gRPC services: exactly
  six (MAC) or ten (ESI) colon-separated groups of exactly two hex digits,
  either case. `AddEvpnRoute`, `DeleteEvpnRoute`, and
  `ClearDuplicateMacQuarantine` previously accepted one-digit and
  three-digit MAC groups (`2:0:0:0:0:1`, `00f:00:00:00:00:01`) that
  configuration load refused, and both entry points accepted a signed
  two-character group (`+2:+0:+0:+0:+0:+1`). All three forms are now
  rejected everywhere. gRPC refusals read `invalid MAC "<input>": <reason>`;
  the configuration reason for a wrong MAC group count now reads
  `expected 6 colon-separated hex octets`. `ListEthernetSegments` and
  `SetEthernetSegmentDrain` already parsed `esi` with the configuration
  grammar but likewise accepted a signed group
  (`+0:11:22:33:44:55:66:77:88:99`); they now refuse it with
  `INVALID_ARGUMENT`. Canonical zero-padded MAC and ESI input is
  unaffected.

- EVPN: a local bridge-port move of a MAC advertised as MAC+IP now
  re-advertises every (MAC, IP) Type 2 route for that MAC with the MAC
  Mobility sequence incremented (RFC 9721 §5.1/§6.2); such moves were
  previously not signalled. Duplicate-MAC accounting now counts one move per
  MAC event instead of one per IP.

- Prometheus metric help strings and runtime `warn` messages no longer carry
  internal tracker identifiers; the behavioral explanation is kept and metric
  names are unchanged. The public-text checker now also covers exported
  runtime strings (metric help text and `tracing` message literals) in crate
  sources, leaving comments, lint reasons, and test assertions untouched.

- The reload log line for a changed `[global]`, `[rpki]`, `[bmp]`, or `[mrt]`
  section (`... changed — requires full restart to take effect`) is now
  emitted at `ERROR`, the level the reload matrix documents for
  restart-required edits and the level the other restart-required reload
  sites already use; it was `WARN`. The message text is unchanged, so
  filters keyed on it still match.
- Policy prefix entries now reject `ge`/`le` bounds whose derived length range
  can never match: `le` below the prefix length, `ge` above `le`, or either
  bound below the prefix length or above the address-family maximum. TOML
  `[policy.definitions]` statements, `.rpol` prefix sets, `test` dataset
  overrides, and dataset snapshot files share one validator and one wording.
- `md5_password` on a neighbor or peer group is now validated at load to the
  kernel `TCP_MD5SIG` key bound, 1..=80 bytes, with the same wording the
  `[[rpki.cache_servers]]` check already uses.

- **Operator-visible:** best-path selection now applies RFC 4271 §9.1.2.2
  step (f), preferring the route received from the speaker with the lowest
  BGP Identifier. A route's ORIGINATOR_ID substitutes for the identifier when
  present (RFC 4456 §9); otherwise the advertising peer's BGP Identifier from
  its OPEN is used. Previously the step ran only when both routes carried
  ORIGINATOR_ID, and it ran after the CLUSTER_LIST comparison. The order below
  eBGP-over-iBGP (and the RFC 9107 ORR interior cost where it applies) is now
  lowest effective BGP Identifier, shorter CLUSTER_LIST, lowest peer address.
  Pairs that include a locally originated route skip the identifier step. The
  unicast, VPN, labeled-unicast, FlowSpec, BGP-LS, and RT-Constrain chains all
  follow this order, as does the EVPN chain (next entry). Explain output and
  BMP path marking report the new `lower_bgp_identifier` reason when at least
  one side was compared by its peer's identifier and keep `lower_originator_id`
  when both carried ORIGINATOR_ID; both map to the path-marking "router ID"
  reason code.

- **Operator-visible:** EVPN best-path selection now runs the same order
  below eBGP-over-iBGP as every other family: lowest effective BGP Identifier
  (ORIGINATOR_ID when present, else the advertising peer's BGP Identifier),
  shorter CLUSTER_LIST, lowest peer address. Previously the EVPN chain
  compared CLUSTER_LIST length before the identifier, and it compared a
  locally originated VTEP route by its `0.0.0.0` injection sentinel. A pair
  that includes a locally originated route now skips the identifier step, as
  the other chains already do; such a pair is decided by CLUSTER_LIST length,
  then the peer-address step, which the sentinel still wins, so its outcome is
  unchanged.

- Reject AS 0 in received and locally encoded AS paths and aggregators per RFC
  7607. Malformed ordinary paths are treated as withdraw, while affected AS4
  compatibility and aggregator attributes are discarded without entering
  canonical route state.

- Replace `bgp_session_lifecycle_source_dropped_total{reason}` with
  `bgp_session_event_source_dropped_total{kind,reason}` so dropped state changes
  and notifications are counted separately before peer-manager publication.

- **Operator-visible:** config transactions no longer reject a full-snapshot
  candidate merely because `[policy] rpol_files` / `[policy.datasets]` are
  declared. The planner now captures every declared external file at plan and
  apply time and admits the transaction when its byte identity matches the
  accepted snapshot's recorded identity (ADR-0130) — restoring plan, apply,
  commit-confirm, and rollback for `.rpol`/dataset deployments whose external
  sources are unchanged on disk. Any drift (an edited dataset or `.rpol`
  module, including comment-only rewrites), a missing/unreadable file, or a
  rollback across an external-content change still rejects without mutation,
  and gNMI Set full-snapshot candidates remain rejected whenever external
  inputs are present.

- Intentionally narrow `[global.telemetry].log_format` to JSON only. Other
  strings were previously ignored but now fail configuration parsing; migrate
  them to `log_format = "json"`.

- `rbgp doctor` now describes config freshness as an mtime comparison with the
  daemon's last config-file marker rather than claiming effective runtime
  agreement. The Prometheus alert pack reports authoritative partial
  SIGHUP reloads and failed retained reload tasks over a reset-safe ten-minute
  window.

- The rrtransport receipt verifier now tolerates at most 4 MiB of Linux
  `/proc` `VmHWM` accounting drift between checkpoints while retaining raw
  observations. `VmHWM` below `VmRSS`, larger regressions, and the 2 GiB RSS
  ceiling remain fail-closed.

- The hosted M43 TCP-AO rotation and crash-recovery proof now uses
  checksum-built BIRD 3.3.2. Before either mode starts BIRD, it verifies the
  exact container image, sleeping command, runtime version, and all four bound
  configurations; the existing proof semantics and archive-unavailable
  tolerance remain unchanged.

- `rbgp events watch --from-event-id` now resumes after clean stream EOF or
  gRPC `UNAVAILABLE`, preserving every filter and reconnecting from the highest
  fully written and flushed top-level event ID with 1-to-30-second exponential
  backoff. Lag frames do not advance the cursor; all other RPC and output
  failures remain terminal, and cursorless event watches remain one-shot.

- Release containers are now built and runtime-verified on native Linux amd64
  and arm64 runners before a single exact two-platform GHCR manifest is
  published. A fail-closed dry-run dispatch exercises both native builds
  without registry authentication or publication.

- **Operator-visible:** `rs-config-render` accepts ARouteServer's
  `max_prefix.count_rejected_routes: true` (its default) instead of refusing it:
  an effective `true` renders the pre-policy `max_prefixes_received_ipv4`/`_ipv6`
  bounds and `false` renders the accepted-route `max_prefixes_ipv4`/`_ipv6`
  bounds. The render receipt reports each client's limits under the emitted key
  and `null` under the other. `max_prefix.action: block` and `warning` are
  accepted as well and render `max_prefix_action = "block"` / `"warning"`
  (reported in the receipt as `max_prefix_action`); `restart_after` is ignored
  for them, as ARouteServer does.
- **Operator-visible:** a session that keeps falling to Idle because of a
  NOTIFICATION (sent or received, including an OPEN exchange that ends in
  one) now doubles its reconnect wait per consecutive failure, from
  `connect_retry_secs` up to 300 s, instead of retrying at a fixed
  interval. The streak clears after five minutes Established, on
  `rbgp neighbor <addr> enable`, or on an administrative reset. Resetting an
  enabled static peer that is already Idle also starts its connection
  immediately. TCP connection failures, the max-prefix latch, disable, and
  graceful shutdown are unchanged. `NeighborState.reconnect_in_seconds`, the
  `rbgp neighbor <addr>` detail row `Reconnect In`, and its JSON key
  `reconnect_in_seconds` report the remaining wait. Older daemons leave the
  API field absent; JSON omits the value when absent or zero.
- Add `[global] max_as_path_length` (default `750`, `0` disables), a ceiling
  on the number of AS numbers accepted in a received `AS_PATH`. A longer path
  carrying reachable NLRI is handled as RFC 7606 treat-as-withdraw and counted
  under `bgp_update_malformed_total{disposition="treat_as_withdraw"}`; without
  reachable NLRI, RFC 7606 section 5.2 requires a session reset.
- The rustdoc gate (`just gate`, the pre-push hook, and CI) now documents the
  `rustbgpd` and `rbgp` binaries in addition to the workspace libraries. The
  root lib target shares its name with the daemon binary, so the previous
  `--lib`-only run documented an empty stub and cargo skipped every daemon
  module; one intra-doc link that pointed at a test-only item is now plain
  text.
- The library run of the rustdoc gate now passes `--document-private-items`,
  so doc comments on private items in the workspace library crates are checked
  the way the binary runs already checked theirs. Twenty-eight doc comments
  that the previous run never saw are corrected: twenty-one unresolved
  intra-doc links (paths re-pointed, one of them at a renamed constant, or
  plain text where the target is private to another module or lives in another
  crate), six unclosed HTML tags in the route-distinguisher parser docs, and one
  redundant explicit link target.

### Fixed

- EVPN best, received, and advertised JSON route rows now retain standard and
  extended communities returned by the daemon. Standard communities use the
  existing display strings and extended communities retain raw unsigned
  64-bit values, matching exact-explain JSON.

- IXP Manager lifecycle requests now abort slow control-response bodies when
  the global request budget expires. Uncertain update-lock acquisition stays
  in manual recovery instead of continuing the lifecycle.

- VPNv4 sessions now advertise RFC 8950 IPv6 next-hop receive support,
  including VPN-only configurations. Reflection preserves the IPv6 next hop
  and exports it only to recipients advertising the matching capability.
  An ineligible replacement withdraws the old advertisement; IPv4 next-hop
  VPNv4 routes and VPN withdrawals retain their existing behavior.

- SRv6 service routes with no semantically valid applicable SID now remain
  retained but cannot win selection, Add-Path, ORR, or ECMP. Invalid-only
  input withdraws existing advertisements; a corrected replacement recovers
  normally. Unicast and EVPN explain identify `srv6_sid_invalid`, including
  successful unicast API/CLI explanations with candidates and no best route.

- gRPC Unix sockets now reject unsafe parent directories and ancestor paths,
  bind without a permission window, and preserve existing live or uncertain
  sockets. Descriptor-relative operations and cooperative startup locking
  protect endpoint creation and cleanup. UDS authorization diagnostics now
  recommend owner-only access, and token-protected UDS listeners report
  `authn = "bearer_token"` without changing their principal or role.

- Prefix-SID SRv6 L3/L2 Service TLVs now validate nested framing under
  RFC 9252 §7. Recognized service malformation returns the additive
  `DecodeError::MalformedSrv6ServiceTlv` and uses treat-as-withdraw in revised
  decoding; generic Prefix-SID length errors keep attribute-discard. Valid
  opaque values and unknown/reserved fields remain unchanged. These framing
  checks are separate from RIB service eligibility and do not originate or
  forward SRv6 services.

- EVPN local MAC/IP activation now advertises above the effective sequence of
  a different imported remote MAC holding the same IPv4 or IPv6 address
  (RFC 9721 §6.1). The retained floor applies to the local MAC and its IP
  children without treating the different MAC as a duplicate-MAC move.
  Repeated observations, remote updates, and suppression recovery do not
  repeatedly raise this floor.

- Locally learned EVPN MACs now adopt a higher sequence from a peer on the
  same nonzero Ethernet Segment, including all locally learned IPv4/IPv6
  bindings. Adoption uses the exact sequence without a mobility increment,
  preserves local sticky state, and does not count as duplicate-MAC or
  duplicate-IP movement. Only matching import RTs, VNI, tag zero, and a
  nonlocal next hop qualify; peer routes alone do not create local ownership.

- Gate 8b MAC-churn receipts aggregate all duplicate-MAC series and retain
  raw scrapes, process epochs, and actual daemon logs. An opt-in proof mode
  requires ten active minutes after readiness, sustained churn, recovery,
  and owned-resource cleanup without treating missing scrapes as zero.

- `rbgp policy check --coverage-min` rejects nonfinite and out-of-range
  percentages instead of allowing `NaN` or negative values to bypass the
  evaluated-coverage gate. Valid thresholds retain their existing behavior.

- Reject explicitly incompatible EVPN encapsulations before local VXLAN
  forwarding, mobility, and gateway or alias/backup resolution. Absent
  encapsulation uses the configured VXLAN fallback; advertised sets containing
  VXLAN remain eligible. Global retention and reflection are unchanged.

- Preserve fresh routes and live peer state when GR or LLGR retention expires
  while a re-established peer's initial outbound registration is deferred.
  Stale routes still expire, and the pending registration completes normally.

- `rbgp rib` best-path and advertised explanations reject missing prefixes and
  conflicting or unsupported `--family` selectors before connecting. A conflicting
  family no longer produces a successful explanation for the prefix's family.
  Matching IPv4/IPv6 aliases and omitted-family inference remain supported.

- `rustbgpd-wire` shutdown communication errors now implement `Display` and
  `std::error::Error` for downstream error propagation, with bounded static
  descriptions. Decoding and structured log categories are unchanged.

- Withdraw every IPv4/IPv6 FlowSpec path immediately when a restarting
  peer's Graceful Restart capability omits that family. Recompute the best
  rule and downstream advertisements, selecting an alternate source when
  available, while keeping GR-covered families stale. Keep the FlowSpec
  Adj-RIB-In gauge current through GR/LLGR expiry, End-of-RIB cleanup, and
  peer teardown.

- **Operator-visible:** an IPv6 FlowSpec rule whose destination component
  carries a non-zero offset no longer presents the unshifted address as its
  destination prefix. RFC 8956 §3.1 matches the address shifted right by the
  offset, so the rule names no routable prefix: import and export policy
  prefix terms no longer match it, and RPKI origin validation of the
  destination no longer runs against a prefix the rule does not name, the
  same treatment as a rule with no destination component. The wire form is
  still accepted unchanged.

- **Operator-visible:** an IP that rebinds to a new MAC in the kernel
  neighbour table now withdraws the old MAC+IP Type 2 route before the new
  one is advertised. The kernel replaces the neighbour row's link-layer
  address in place with one `RTM_NEWNEIGH` and sends no delete for the old
  binding; the Linux observation layer now delivers that change as
  `IpRemoved` for the displaced MAC followed by `IpAdded` for the new one.
  Previously the old MAC's cached binding was silently overwritten and its
  MAC+IP route stayed advertised until that MAC aged out of the bridge FDB.

- **Operator-visible:** the daemon's warm-checkpoint reader and `rbgp diff
  snapshot from-mrt` now share one decoder for the `MP_REACH_NLRI` inside a
  `TABLE_DUMP_V2` RIB entry. It accepts both the RFC 6396 §4.3.4 reduced form
  (next-hop length, next hop) and the full RFC 4760 form some collectors
  write (AFI, SAFI, next-hop length, next hop, optional reserved octet), told
  apart by the leading octet (a next-hop length is never 0), and rejects a
  next-hop length other than 4, 16, or 32, a truncated next hop, an AFI that
  disagrees with the next-hop length, and octets trailing the next hop.
  Previously the two readers disagreed: warm-checkpoint loading accepted
  only the reduced form with an exact length match, while `from-mrt` also
  accepted the full form and ignored trailing octets, so one collector dump
  converted in one place and was rejected in the other. The decoder,
  `decode_table_dump_v2_mp_reach_next_hop`, lives in `rustbgpd-wire`, which
  both readers already depend on.

- `rbgp top` now restores the terminal (leaves the alternate screen, shows
  the cursor, disables raw mode) when the process is terminated by SIGTERM,
  SIGINT, or SIGHUP; the signal quits the dashboard the same way Ctrl-C does
  and the process exits with status 0.

- **Operator-visible:** `rustbgpd --diff` now exits 2 when the current
  config (the second path) cannot be loaded, as documented and as the
  candidate side already did; it previously exited 1, the code that means
  the diff carries actionable changes. The diagnostic text is unchanged.
  Daemon boot and `--check` still exit 1 on a config that cannot be loaded.
- `birdwatcher-adapter` route views now emit `bgp.ext_communities` (an empty
  array when the route carries none), so Alice-LG shows route targets and
  other extended communities instead of nothing. Each entry is birdwatcher's
  `[kind, key, value]` string triple as parsed from BIRD 2.0.12 text: `rt` /
  `ro` for the transitive two-octet-AS, IPv4-address, and four-octet-AS
  families, `unknown 0x<type>` for other subtypes of those families, and
  `generic` with the two 32-bit halves in hex for every other type. The
  pinned IXP compatibility live fixture carries the empty array; filtered
  routes are unchanged.
- `birdwatcher-adapter` `/routes/noexport/{id}` now diffs each Loc-RIB page
  against the peer's advertised prefix set as it arrives and applies
  `--max-routes` to the retained candidates per page, so a request retains
  only the advertised keys plus at most `--max-routes` candidate rows instead
  of the entire Loc-RIB with its attributes. Rendered output is unchanged; an
  oversized view fails with the same 403 on the page that crosses the cap.

- An UPDATE that changes only the link-local companion of an IPv6 next hop
  (RFC 2545 two-address form) is now re-advertised to downstream peers instead
  of being suppressed as an unchanged Adj-RIB-Out entry.
- `bgp_route_refresh_in_progress` and `bgp_route_refresh_stale_entries` are
  now reset when a peer session ends while an enhanced route refresh is in
  progress, including graceful-restart entry and session fail-over.
  Previously the gauges kept their last values until the peer was removed
  from configuration.
- Extended community accessors in `rustbgpd-wire` now match the type byte
  exactly instead of masking it with `0x3F`, so values in the IANA
  experimental-use range (type bit `0x80`) are no longer decoded as EVPN,
  opaque encapsulation, default-gateway, route-target, or route-origin
  communities.
- Add-Path and extended-next-hop negotiation in `rustbgpd-fsm` are now
  limited to the negotiated address families. A peer advertising Add-Path or
  Extended Next Hop Encoding for a family outside the MultiProtocol
  intersection no longer leaves that family in the session's Add-Path or
  extended-next-hop set; the Add-Path case previously suppressed RFC 9972 BMP
  Adj-RIB-In counts for sessions that never negotiated the family.
- `rs-config-render` renders the transit-free filter only when
  `transit_free.action` is `reject`; a null or absent action with
  `transit_free.asns` populated no longer emits reject terms arouteserver
  would not generate.
- Mutation RPCs (`AddPath`, `DeletePath`, `AddFlowSpec`, `DeleteFlowSpec`,
  `AddEvpnRoute`, `DeleteEvpnRoute`, `TriggerMrtDump`, and the peer-manager
  mutations routed through the shared request path) now return `UNAVAILABLE`
  instead of `INTERNAL` when the actor command channel is closed, matching
  the documented status-code contract. A reply dropped after the actor
  accepted the command still returns `INTERNAL`.

- **Operator-visible:** `rs-config-render` now states `rs_control_communities`
  on every rendered member session instead of inheriting the daemon default:
  off when the site configures no control community, on only when the site
  configures exactly the daemon's fixed RFC 7947 §2.3.2 / RFC 8195 matrix.
  Any differing value, a matrix key left unset while another is configured,
  or a configured `add_noexport_to_*` / `add_noadvertise_to_*` community is
  refused (exit 2) naming the key. Previously every rendered session
  interpreted and scrubbed the daemon's matrix regardless of what the site
  had declared to arouteserver.

- Policy and peer-group mutations now report unavailable when configuration
  persistence admission is closed or temporarily full.

- Redirected daemon diffs no longer contain terminal color escapes, and the
  interactive CLI restores normal terminal mode if alternate-screen entry fails.

- Invalid TUI intervals and empty policy-chain replacements now fail locally
  before the CLI attempts to connect to the daemon.

- The CLI now preserves actionable daemon reasons on mid-RPC gRPC
  `UNAVAILABLE` responses instead of replacing them with a generic diagnostic.

- Session enqueue attempts without an active writer now report `WriterClosed`
  instead of falsely reporting success.

- Durable event replay now reports a closed storage mailbox or dropped reply
  as one terminal gRPC `UNAVAILABLE` status with resume guidance instead of a
  clean end-of-stream. Allocator pass-through remains `FAILED_PRECONDITION`,
  and post-admission producer loss remains `DATA_LOSS`.

- `bgp_policy_routes_total` now retires stale policy/action label identities
  after successful settled policy replacement while preserving exact values
  for every identity the installed peer chains can still emit.

- RTR v2 now rejects IPv4 and IPv6 Prefix PDUs with nonzero host bits as
  corrupt data, sends Error Report code 0 with the offending frame, and avoids
  publishing the incomplete transaction while flushing that cache's previously
  learned data as required for a fatal error. RTR v1 continues accepting nonzero
  host bits; invalid prefix-length and max-length PDUs on either version now
  share the same fatal code-0 flush disposition.

- `rbgp rib received` and `rbgp rib advertised` now expose their prefix,
  longer-prefix, origin-ASN, standard-community, and large-community filters
  after the route view where operators naturally look for them. A single-page
  `--limit 1..1000` query reports explicit completeness and remains usable
  against a churning full table; unbounded walks still fail closed rather than
  emit a torn snapshot.

- RPKI fail-stop receipts now retain the task class behind a panic even when a
  dependent forwarder returns first. The daemon still performs coordinated
  shutdown and exits 1; ordinary RTR reconnect and expiry remain non-fatal.

- Event-history shutdown now reports accepted-but-unreceived terminal loss
  exactly once by category. A closeable acceptance ledger excludes
  pre-admission attempts and actor-received work while remaining the sole
  queue-depth source across shutdown and manager restarts.

- Coordinated shutdown now bounds the gRPC listener drain and removes the
  bound gRPC Unix socket on every exit path. An active streaming RPC no
  longer holds a listener open indefinitely: the listeners share a
  one-second grace deadline, after which the remaining tasks are aborted and
  the count is logged. A guard unlinks the socket path on the cancelled path
  as well as the completing one, and retains the path when it is no longer a
  socket or when its device and inode no longer match the socket the daemon
  bound, so a replacement is never removed. The daemon joins the gRPC task
  before closing the durable event outbox, so active streams cannot outlive
  their dependencies, and a panic in that task during shutdown is reported
  as a component failure and exits 1.
- The `writer: write/flush failed` warning now carries the `peer` and `error`
  fields alongside `error_kind`, matching the other session transport
  warnings; the message text is unchanged.

- `rbgp` now rejects an unknown `--family` value before dialing the daemon,
  so a typo reports `unknown address family: ...` instead of a connection
  error when the daemon is unreachable. The message and exit code are
  unchanged.
- `rbgp top` now bounds each refresh by the refresh interval. A daemon that
  accepts the connection but never answers is reported as unavailable (or
  stale, for data already on screen) by the next tick instead of freezing
  the refresh loop.
- Human-readable `rbgp` output for connected commands now goes through the
  same fallible stdout writer as JSON output, so a reader that closes the
  pipe early (for example `rbgp rib | head -1`) ends the command quietly
  with exit code 1 instead of a `failed printing to stdout` panic. Output
  bytes are unchanged.
- **Operator-visible:** the EVPN local originators no longer treat a Type 2
  received from a PE on the same Ethernet Segment as a MAC mobility
  contender (RFC 7432 §15, RFC 9721 §6.4). The received ESI was discarded
  when the remote contender views were built, so on an all-active multihomed
  pair each PE raised its MAC Mobility sequence against the other's
  advertisement of the same locally learned MAC or MAC/IP and counted the
  echo toward `evpn_duplicate_mac_moves_total`; enough echoes inside the
  duplicate-MAC window could quarantine a legitimately multihomed MAC from
  peer traffic alone. A route whose ESI equals the VNI's own non-zero ESI is
  now dropped from the contender views alongside self-originated routes, so
  it neither raises the local sequence nor counts as a move. Routes with a
  different or zero ESI are contenders as before, and the receive-side
  tiebreak is unchanged.

- Correct MRT Add-Path entry ordering to Peer Index, Originated Time, then
  Path Identifier, and use subtype 10 for IPv6 unicast. Snapshot encoders,
  the reader, and the CLI MRT adapter now follow RFC 8050; subtype 9 is
  treated as unsupported IPv4 multicast. The CLI adapter also rejects
  trailing bytes after a RIB record's declared entries without emitting
  a partial snapshot. Legacy non-Add-Path encoding is unchanged.

- EVPN Linux route withdrawal treats an already-absent kernel route as
  successfully removed, including single-path and ECMP IP-VRF routes. This
  clears owned state instead of retrying the deletion indefinitely.

- Unicast CLI JSON now includes AGGREGATOR and ATOMIC_AGGREGATE when present,
  including best-route and candidate rows in best-path explanations. Routes
  without either attribute retain their existing JSON shape.

- `rbgp neighbor` rejects malformed addresses before connecting, including
  accidental `neighbor list` invocations. Valid scoped IPv6 peer addresses
  remain supported. Help and man pages now distinguish parser/usage exit `2`
  from argument-validation and execution exit `1`, preserving detailed
  per-command exit codes.

- `rbgp top` honors `--no-color` and the presence of `NO_COLOR` with a
  monochrome theme that preserves bold emphasis and selection markers.

- Local EVPN Type 2 consumption now requires a matching instance VNI and
  Route Target, Ethernet Tag 0, and a nonlocal next hop before forwarding,
  mobility, duplicate accounting, or Type 5 gateway-IP recursion. Global RIB
  retention and reflection are unchanged.

- Scope EVPN EAD-per-EVI alias and single-active backup selection to the
  local VNI as well as ESI and Ethernet Tag. Local EAD consumption now
  requires a matching Route Target and zero Ethernet Tag, including Type 5
  ESI overlay resolution. The backup-window gauge counts each VNI separately.

- Bound configured policy chains to 1,000,000 structural IR nodes across
  `.rpol` and TOML members, including legacy inline policies and implicit
  GSHUT/BLACKHOLE tails. Reject oversized candidates before installation;
  `compile_rpol` enforces the same cap when composing zero-parameter policies.

- `rustbgpd --check` and `--check --strict` validate TLS credential content
  through the same staging path as startup, rejecting invalid certificates,
  keys, client CA bundles, and mismatched cert/key pairs before reporting
  success. Neither mode binds listeners.

- Rejected native gRPC TLS handshakes now increment
  `bgp_grpc_tls_handshake_failures_total{reason}`, including handshake timeouts.
  Fixed reason labels distinguish missing, expired, not-yet-valid, untrusted,
  and other invalid client certificates from other TLS or transport failures.
  Request authorization counters continue to count RPC decisions only.

### Documentation

- Publish a descriptive raw bridge event-skew receipt across six pinned Jammy
  Linux 5.15 and Noble Linux 6.8 profile tuples. All 24,000 measured pairs
  completed FDB-first. One run per tuple provides no variance, bound, kernel
  regression, acceptance, or production-behavior claim.

- Publish the current v0.68.0 benchmark evidence bundle: exact-release
  cross-stack import/convergence, exact-source high-N route-server and RIB
  memory results, exact-release FIB and Enhanced Route Refresh refreshes, and
  source-equivalent IXP, route-server-1000, RR1000, and twelve-root IRR reload
  receipts with compact checksummed artifacts and explicit claim boundaries.

- Refresh the comparison matrix and GoBGP parity page against current
  upstream releases: GoBGP re-pinned to v4.9.0 (TCP-AO keychains, JSON
  logging by default), OpenBGPD credited for OpenMetrics output and its OCI
  image, BIRD's exporter-based Prometheus path, a defined looking-glass row,
  a dated latest-release row, and an "Other Rust implementations" section
  covering zebra-rs, Holo, and RustyBGP.

- Refresh standards pins: the ASPA conformance page, a dated ADR-0123
  amendment, rustdoc, and the M59 interop note follow
  draft-ietf-sidrops-aspa-verification-28 (new §5.1 prerequisite AS_PATH
  checks, §5.2–§5.7 renumbering; no verifier change); TCP-AO documentation
  states the mainline Linux 6.7 or downstream-backport requirement;
  RFC_NOTES records the non-automatic validation-state encoding boundary
  from draft-ietf-sidrops-avoid-rpki-state-in-bgp and RFC 9736; the
  rs-config-render README corrects the RTT-community refusal rationale.

- Root, neighbor, and RIB CLI help include practical inspection examples.
  The man page includes subcommand help footers, including examples and
  detailed exit codes. Contributor guidance defines verbs by operation
  semantics without renaming existing commands.

### Upgrade notes

- **VPNv4 IPv6 next hops:** VPNv4 peers advertise the additional receive
  capability on the next OPEN exchange, with no new configuration setting.
  A recipient without RFC 8950 tuple 1/128/2 no longer receives VPNv4 IPv6
  next-hop announcements; exact-export rejection also removes an older
  advertisement when an IPv4 next hop is replaced by an IPv6 next hop.

- **gRPC Unix socket paths:** the immediate parent must be effective-UID-owned,
  readable/searchable and writable by the daemon, and not group/world-writable.
  Paths must be absolute, have no symlink or `..` components, and use trusted
  root/effective-UID ancestors. Sticky ancestors such as `/tmp` are allowed
  only above a protected child directory; move `/tmp/name.sock` to a private
  directory. Linux `/proc/self/fd` must be available. Both the configured and
  descriptor-relative socket paths must fit the Unix socket pathname limit.
  Existing live listeners now cause startup failure instead of losing their
  socket. Token-protected UDS audit labels change from `uds`/`uds_owner` to
  `bearer_token`; permissions-only labels and supported group-sharing roles
  remain unchanged. See the [UDS path requirements](docs/reference/security.md#unix-socket-path-integrity).

- **SRv6 Prefix-SID structural validation:** malformed recognized L3/L2
  Service TLVs now withdraw the UPDATE's reachable routes while preserving
  the session when NLRI can be recovered. Unusable NLRI retains session reset;
  malformed snapshot entries fail admission. Generic Prefix-SID errors retain
  attribute-discard, and valid opaque reflection is unchanged. Embedders using
  prepared wire `0.20.0` can receive `DecodeError::MalformedSrv6ServiceTlv`.

- **EVPN IP ownership sequence:** a newly learned local MAC/IP binding can
  now carry a higher MAC Mobility sequence when another eligible remote MAC
  advertises its IP. Existing higher local and same-segment peer sequences
  are preserved. Local activations wait for the first successful RIB snapshot
  and after a failed refresh; without the event subscription, they wait for
  the next successful scheduled poll. Prolonged query failure can fill the
  bounded deferred queue and backpressure further observations. This remains
  part of the EVPN alpha boundary and does not implement stale-entry probing
  or full duplicate-address resolution.

- **Same-segment EVPN sequence adoption:** locally owned MAC and MAC/IP
  advertisements can now advance to an eligible ES peer's higher sequence.
  Existing higher local sequences never decrease. Withdrawn, quarantined, or
  drained routes stay suppressed until normal local replay permits origination.
  A host learned only from the ES peer is still not originated locally.

- **Coverage thresholds require finite percentages from 0 through 100:**
  invalid `--coverage-min` values now exit 2 before loading the policy file.
  Previously, `NaN` and negative values could pass, while values above 100
  and positive infinity forced a coverage failure (exit 3). Valid percentages,
  including fractional and scientific notation, retain their existing results
  and diagnostic/test-failure precedence.

- **EVPN VXLAN import:** Type 2, Type 5, and EAD-per-EVI advertisements with
  explicit encapsulation sets lacking VXLAN no longer contribute local state.
  Check remote Encapsulation communities before upgrading; absent communities
  continue to use the configured VXLAN profile. See
  [encapsulation compatibility](docs/how-to/evpn-vtep-setup.md#vxlan-encapsulation-compatibility).

- **EVPN RPCs apply the configuration MAC and ESI grammar:** `AddEvpnRoute`,
  `DeleteEvpnRoute`, and `ClearDuplicateMacQuarantine` now parse `mac` and
  `router_mac` with the parser the configuration loader uses: exactly six
  colon-separated groups of exactly two hex digits. Requests carrying a
  one-digit group (`2:0:0:0:0:1`), a three-digit group
  (`00f:00:00:00:00:01`), or a signed group (`+2:+0:+0:+0:+0:+1`) are now
  refused with `INVALID_ARGUMENT`. `ListEthernetSegments` and
  `SetEthernetSegmentDrain` now refuse a signed ESI group
  (`+0:11:22:33:44:55:66:77:88:99`) the same way, and configuration load
  refuses the signed form for MAC and ESI fields, where it previously
  parsed. Clients that send canonical zero-padded MAC and ESI input are
  unaffected.
- **`TABLE_DUMP_V2` RIB-entry `MP_REACH_NLRI` decoding is shared:**
  warm-checkpoint loading now reads dumps whose RIB entries carry the full
  RFC 4760 `MP_REACH_NLRI` form, which it previously rejected as malformed.
  `rbgp diff snapshot from-mrt` now refuses (exit 2, nothing emitted) a RIB
  entry with octets trailing the next hop, which it previously ignored; such
  bytes were never part of a valid entry, so re-export the dump from its
  collector.
- **EVPN local port moves now re-advertise MAC+IP routes:** when a MAC that
  is advertised as MAC+IP moves between local bridge ports, peers receive one
  additional Type 2 per IP bound to that MAC, each carrying the incremented
  MAC Mobility sequence. Because such a move now counts as one duplicate-MAC
  move (rather than none), a multi-IP MAC that flaps between local ports
  reaches the `duplicate_mac_detection` threshold where it previously did
  not; a MAC learned with several pending IPs under remote contention now
  counts one move where it previously counted one per IP, so that shape trips
  suppression later than before.
- **Dead prefix-length ranges are now load errors:** a TOML policy prefix
  entry or an `.rpol` prefix-set member whose `le` is below the prefix length
  (`10.0.0.0/24 le 16`) or whose `ge` exceeds `le` (`10.0.0.0/24 ge 28 le 26`)
  is rejected at load. Such entries previously loaded and matched nothing.
  `.rpol` dataset snapshot files use the same grammar, so a snapshot holding
  such a line is a startup error at initial load and, on SIGHUP reload, keeps
  the prior generation with the existing refresh-failure WARN and counter.
  Remove or correct the entry; the effective policy does not change.
- **Neighbor and peer-group `md5_password` length is checked at load:** an
  empty password or one longer than 80 bytes is now a config error
  (`md5_password must be 1..=80 bytes`) instead of loading and then failing
  when the session or listener socket installs the key. Such a value never
  produced a working session; shorten or remove it.
- **Best-path selection can change after upgrade** between otherwise-equal
  paths from different peers: the lowest advertising BGP Identifier (or
  ORIGINATOR_ID) now decides before CLUSTER_LIST length and peer address,
  where previously peer address decided unless both routes carried
  ORIGINATOR_ID. Expect a one-time best-path change, and the corresponding
  withdraw/announce toward peers, for prefixes that tied down to the peer
  address. `rbgp rib --prefix <cidr> --explain` and BMP path marking report
  the new `lower_bgp_identifier` reason; `lower_originator_id` is retained
  for the both-ORIGINATOR_ID case.
- **EVPN best-path selection can change after upgrade** between
  otherwise-equal routes for the same EVPN key received from different
  peers: the lowest effective BGP Identifier (ORIGINATOR_ID, else the
  advertising peer's BGP Identifier) now decides before CLUSTER_LIST length,
  and a locally originated VTEP route no longer wins the identifier step by
  its `0.0.0.0` sentinel. Expect a one-time best-path change, and the
  corresponding withdraw/announce toward VTEP peers, for keys whose paths
  tied down to CLUSTER_LIST length across different identifiers. Pairs that
  include a locally originated route keep their prior outcome.
- Received `AS_PATH` attributes with more than 750 AS numbers and reachable
  NLRI are now treated as withdraw by default; without reachable NLRI, the
  session resets. Deployments that must relay arbitrarily long paths set
  `[global] max_as_path_length = 0` to keep the previous behavior.
- **Shipped systemd units are `Type=notify`:** `rustbgpd.service` and
  `rustbgpd@.service` now declare `Type=notify`, `NotifyAccess=main`,
  `WatchdogSec=5min`, and `TimeoutStartSec=10min`. A `.deb` or `.rpm`
  upgrade replaces both units under `/lib/systemd/system`, discarding local
  edits to those files, so keep customizations in an
  `/etc/systemd/system/rustbgpd.service.d/` drop-in. Deploy the unit and the
  binary together: a new binary under an old `Type=simple` unit behaves
  exactly as before, because systemd sets no `NOTIFY_SOCKET` and every
  notification is a no-op, but an old binary under the new unit never sends
  `READY=1`, so `systemctl start` blocks until `TimeoutStartSec` and the
  service is then killed and retried on a ten-minute loop. Opting out on a
  native unit requires all three of `Type=simple`, `NotifyAccess=none`, and
  `WatchdogSec=0`; the container unit already stays `Type=simple`.
- **Reconnect wait escalates after repeated NOTIFICATION teardowns:** a
  session that keeps falling to Idle because of a NOTIFICATION — sent,
  received, or an OPEN exchange that ends in one — now doubles its reconnect
  wait per consecutive failure instead of retrying at a fixed interval. At
  the `connect_retry_secs` default of 5 s the wait runs 5, 10, 20, 40, 80,
  160, and then 300 s, which is the cap. Monitoring and automation that
  assumed a worst case near `connect_retry_secs` must widen that
  expectation. The curve has no configuration knob:
  `rbgp neighbor <addr> enable` or an administrative reset clears the streak
  and retries immediately, and five minutes Established clears it on its
  own. TCP connection failures, the max-prefix latch, disable, and graceful
  shutdown keep their existing timing.
- **Config transactions accept unchanged external policy inputs:** a
  full-snapshot candidate that declares `[policy] rpol_files` or
  `[policy.datasets]` is no longer rejected on declaration alone. The
  planner records each declared external file's byte identity and admits the
  transaction when it matches the accepted snapshot, so plan, apply,
  commit-confirm, and rollback work again for `.rpol` and dataset
  deployments whose sources are unchanged on disk. Automation that treated
  the blanket rejection as the expected outcome now sees these transactions
  commit. Nothing that previously succeeded now fails: drift in a declared
  file, including a comment-only rewrite, a missing or unreadable file, and
  a rollback across an external content change all still reject without
  mutation, and gNMI Set full-snapshot candidates remain rejected whenever
  external inputs are present.
- **`rbgp neighbor` reports inbound prefix limits for existing bounds:** any
  peer already configured with `max_prefixes`, `max_prefixes_ipv4`, or
  `max_prefixes_ipv6` now carries an `inbound_prefix_limits[]` row per
  finite bound in the neighbor API, the `rbgp neighbor <addr>` detail
  output, and its JSON, and publishes `bgp_max_prefix_blocking{peer,scope}`
  at 0 for each of those bounds. No configuration change is required to see
  either. Consumers that parse the detail output or pin its JSON keys should
  accept the new section; the `block` and `warning` modes themselves stay
  off until `max_prefix_action` is set.
- **Shipped alert rules join peer identity:** the packaged
  `BgpSessionNotEstablished` rule now joins `bgp_peer_info`, so an alert for
  a peer that has an identity row carries `remote_asn`, `description`, and
  `peer_group` labels. Alertmanager matchers and silences keyed on the
  previous labels still match, but an explicit `group_by` list, grouping and
  deduplication behavior, or a notification template built on the old label
  set should be reviewed before adopting the refreshed rules. Keeping the
  previous rules changes nothing, and the rule's fallback arm still fires
  for peers without an identity row, including against an older daemon.
- **Route-server renders state `rs_control_communities`:**
  `rs-config-render` now writes `rs_control_communities` on every rendered
  member session. A site that configures none of the nine arouteserver
  control-community keys renders `false`, where the previously omitted key
  left the daemon default in force, so re-rendering an otherwise unchanged
  site turns off RFC 7947 section 2.3.2 and RFC 8195 control-community
  interpretation and scrubbing on those sessions. Re-render and diff before
  activating, then either accept the transparent behavior or declare the
  full nine-key matrix exactly as the daemon expands it. A partial or
  differing matrix, and any `add_noexport_to_*` or `add_noadvertise_to_*`
  community, now exit 2 naming the key; both rendered before. The IXP
  Manager render path is unchanged.
- **Route-server renders refuse more IRR community inputs:**
  `rs-config-render` now exits 2 on an `ext` form or a malformed value under
  `communities.route_validated_via_white_list`, and on any of arouteserver's
  four IRR result communities `origin_present_in_as_set`,
  `origin_not_present_in_as_set`, `prefix_present_in_as_set`, and
  `prefix_not_present_in_as_set`. All five were previously ignored and the
  site rendered. A site that declares the white-list tag community also
  gains a hygiene term scrubbing that tag on entry, whether or not it
  configures any white-list entry. Re-render before activating and remove
  the refused keys.
- **Route-server renders accept arouteserver max-prefix inputs:**
  `rs-config-render` previously exited 2 on arouteserver's default
  `max_prefix.count_rejected_routes: true` and on
  `max_prefix.action: block` or `warning`; those sites now render. The
  emitted bound is not equivalent: an effective `true` renders the
  pre-policy `max_prefixes_received_ipv4`/`_ipv6`, which count accepted and
  rejected prefixes before import policy, while `false` keeps the
  accepted-route `max_prefixes_ipv4`/`_ipv6`. Confirm the intended bound
  before activating. Every render receipt also gains the
  `max_prefixes_received_ipv4`, `max_prefixes_received_ipv6`,
  `max_prefix_action`, and `white_list_routes` client keys, so receipt diffs
  and schema consumers see new fields on unchanged sites.
- **EVPN all-active pairs stop ratcheting each other:** on multihomed
  deployments `evpn_duplicate_mac_moves_total` and the MAC Mobility
  sequences advertised for multihomed MACs drop, because a same-segment
  peer's advertisement no longer counts as a move or raises the local
  sequence. Re-baseline alerts keyed on that counter for multihomed VNIs;
  single-homed VNIs are unaffected.

- **MRT Add-Path snapshots and warm checkpoints:** regenerate historical
  Add-Path dumps, whose peer, time, and path-ID fields could be misread by
  external tools. Warm manifests now use format version 2 and reject all
  version-1 bundles before decoding, without automatic conversion. The next
  coordinated shutdown can replace an old checkpoint; the daemon still does
  not restore routes from these artifacts at boot.

- Lightweight native CLI reads now bound the complete RPC response to
  30 seconds per call or page, so stalled TCP or Unix-socket endpoints
  cannot hang scripts indefinitely. Doctor preserves successful evidence
  and marks timed-out sections incomplete, with a separate allowance for
  large effective-config exports. A failed health collection no longer
  leaves the system section marked collected.

- **EVPN local VTEP upgrades:** Type 2 routes with missing or mismatched RTs,
  or nonzero Ethernet Tags, no longer contribute local forwarding or mobility
  state. Check remote advertisements and configured `route_targets` before
  upgrading; see [local Type 2 import](docs/how-to/evpn-vtep-setup.md#local-type-2-import).

- **EVPN EAD import scope:** alias or backup paths previously admitted from
  another VNI, a nonmatching or missing Route Target, or a nonzero Ethernet
  Tag are removed from local forwarding intent. Check remote EAD labels and
  Route Targets if a path disappears after upgrading. Global EVPN RIB
  retention, reflection, and export are unchanged. The
  `evpn_single_active_backup_active` gauge may increase when multiple VNIs
  share an ESI and tag because each forwarding group is now counted.

- **Policy chain size:** chains exceeding 1,000,000 structural IR nodes now
  fail startup/reload validation or return `INVALID_ARGUMENT` on policy API
  mutations. Reduce repeated members or expanded policy structure before
  upgrading. Policy/term/action overhead and nested guards/value expressions
  count; shared set contents and unused definitions do not. Per-policy cost,
  runtime loop fuel, and trusted infallible Rust compilation APIs are unchanged.
  A reload's new definitions combined with its old chain references must also
  fit: shorten chains in a separate reload before loading larger definitions
  when that intermediate combination would exceed the cap.
  See [policy bounds](docs/reference/rpol-language.md#loops--for).

- **Policy language:** `default-action` is optional; existing `.rpol` files
  retain their behavior. Upgrade readers before adding the new declaration,
  since older releases reject its syntax. `default-action accept` continues
  the policy chain; `reject` affects only fallthrough and does not diagnose
  widened guards. Keep negative route assertions when adopting it.

## [0.68.0] — 2026-08-30

> **Release framing — broader control surfaces, faster route-server release.**
> v0.68 closes the externally reported gRPC address-family gap: neighbor and
> peer-group mutations now accept every family the configuration file supports.
> In the [fully reusable homogeneous-wire-profile receipt](docs/perf/artifacts/selection-deferral-release-v0680-2026-08/README.md),
> releasing 400,400 routes across 700 peers drops from a 53.613 s median to
> 0.811 s (about 66x);
> mixed profiles form separate cohorts or keep the exact per-member fallback.
> IPv6 link-local BFD, RPKI cache and validation APIs, structured NOTIFICATION
> telemetry, broader pinned interoperability, `rustbgpd-wire` 0.19.0,
> `rustbgpd-fsm` 0.6.0, and the first `rustbgpd-rpki` 0.1.0 publish alongside.

### Added

- M100 adds a hosted, proof-only 20-cell receiver differential for an exact
  `0xa0` Partial-flag corpus across released rustbgpd 0.67.0, BIRD 2.19.2,
  OpenBGPD 9.2, and FRR 10.3.1. MED, ORIGINATOR_ID, CLUSTER_LIST, MP_REACH,
  and MP_UNREACH outcomes are frozen as accept, same-session withdrawal,
  treat-as-withdraw, or reset with exact UPDATE bytes, route/survivor state,
  observer reconstruction, and ordered `3/4` notification/close/reconnect
  evidence. This adds no production, configuration, or default-behavior change.

- Hosted M85, M93, and M95 interop proofs now run against a shared,
  checksum-built BIRD 2.19.2 image. Each driver verifies the configured image
  and exact runtime before testing; the existing reflection/GR, required-family,
  and RFC 8212 contracts remain exact at 33/0, 8/0, and 31/0.

- M104 adds a hosted current-daemon sibling of the immutable M90
  ARouteServer filtering differential. It reuses the exact M90 site and
  11-route corpus while requiring a 23/23 context-ingestion proof and 74/0
  live verdict/session proof against ARouteServer 1.23.2, staged BIRD 2.19.2,
  GoBGP 4.8.0, and the exact checked-out rustbgpd image.

- Hosted M83 and M101 interop jobs now consume independently cached,
  checksum- and source-version-verified BIRD 2.19.2 and 3.3.2 archives from
  required same-run producers before building their images with dedicated
  Buildx cache scopes. Their Dockerfiles recheck staged bytes before extraction
  and retain a bounded three-attempt download only for cold local builds; the
  existing M43 BIRD 3.3.1 unavailable-upstream tolerance is unchanged.

- M103 adds a sibling hosted GoBGP 4.8.0 route-server differential without
  changing the historical M92 GoBGP 4.7 receipt. Exact normal 56/0 and
  missing-EoR 17/0 runs retain the baseline/mutant/restore contract while
  requiring raw 4.7/4.8 oracle equality after recursive deletion of only
  `age`; route records and trailer remain byte-identical under a separately
  versioned M103 golden.

- `rbgp doctor` warns on a narrowly evidenced first-session GTSM stall when
  effective TTL-security configuration and the authoritative administrative
  metric agree; established, stale, held, disabled, previously established,
  ambiguous, and unattributed peers remain silent.

- Single-hop asynchronous BFD now supports static IPv6 link-local neighbors.
  rustbgpd resolves the neighbor's required `interface` to a startup-pinned
  scope, transmits through the shared IPv6 socket with that scope, and accepts
  control packets only when kernel packet-info reports the same receive
  interface. Missing or unresolvable scopes fail startup before BFD sockets are
  prepared; global IPv4/IPv6 behavior and public BFD peer identity are
  unchanged.

- Decoded inbound and attempted outbound BGP NOTIFICATIONs now emit exactly one
  structured INFO record with peer, direction, outer code/subcode, and a human
  description. Hard Reset records retain outer Cease/9 and identify the valid
  inner error; optional shutdown communication is escaped to ASCII and bounded
  to 512 bytes, while malformed communication remains omitted and warned.

- `RpkiService.ListCaches` and `rbgp rpki caches` expose a bounded,
  deterministic inventory of configured RTR caches, connection state, and
  latest atomically accepted epoch. Accepted-empty tables remain distinguishable
  from initial, expired, and flushed state; responses cap at 256 rows with exact
  omission metadata, and the sensitive-read RPC remains outside narrow v1.

- `EvpnService.ListDuplicateMacQuarantines` and `rbgp evpn
  duplicate-mac-quarantines` expose the current duplicate-MAC local-origin
  quarantine set as one deterministic, key-only snapshot. Responses are capped
  at 4096 rows with exact omission metadata; the sensitive-read method remains
  outside the narrow v1 contract.

- `RpkiService.ValidateRouteOrigin` and `rbgp rpki validate <PREFIX>
  <ORIGIN_ASN>` provide a read-only, bounded explanation of one route-origin
  validation against the latest authoritative VRP snapshot. The complete-table
  verdict is independent of the 256-row diagnostic cap; effective covering
  VRPs are deterministic, report exact omission, retain AS0 rows without ever
  marking them authorizing, and the whole service remains outside the narrow
  v1 contract.

- M102 adds a hosted dual-stack route-server receipt with a digest-pinned
  OpenBGPD 9.2 member and FRR 10.3.1 control. Its exact 32/0 contract covers
  enforced role/family/four-octet-AS negotiation, bidirectional transparent
  routes with standard and Large Communities, independently reassembled raw
  OPEN and IPv4 UPDATE evidence, explicit import/export policy, all four
  directional-family withdrawals, and session continuity. Malformed Partial
  and AS_SET behavior remain outside this receipt.

- `bgp_dataplane_reconcile_planning_failures_total{actor,reason}` exposes
  bounded pre-kernel planning aborts for the general FIB and BLACKHOLE discard
  reconcilers. Each abort emits one structured warning while preserving the
  last successful status snapshot, ownership, unresolved/adoption bookkeeping,
  and kernel state; general-FIB shutdown cancellation is not counted.

- M101 adds a hosted three-node IPv4-unicast route-server receipt against
  checksum-built BIRD 3.3.2 and digest-pinned FRR 10.3.1. A BIRD-originated
  optional-transitive-partial type-40 attribute is pinned as the exact raw
  tuple `e0 28 01 00`; rustbgpd discards only that attribute, preserves the
  route and unrelated communities through post-policy Adj-RIB-In to FRR, and
  advances only the `attribute_discard` malformed-UPDATE disposition. The
  exact 27/0 receipt also covers import and member-scoped export policy
  controls, explain/advertised views, deterministic withdrawal, and stable
  sessions.

- The M86 OpenBGPD route-reflector receipt now pins the reviewed 9.1
  multi-platform image index. Hosted CI verifies its exact linux/amd64
  manifest and image-config digests, and the driver requires both sleeping
  clients to match the local pinned image and exact `OpenBGPD 9.1` runtime
  before either daemon starts. Its reflection, graceful-restart, timing, and
  exact 27/0 receipt remain unchanged.

- The M83 route-server multi-stack receipt now runs its incumbent members as
  checksum-pinned BIRD 2.19.2 and GoBGP 4.8.0 images plus manifest-pinned FRR
  10.7.0, with exact runtime version preflights before capture. Its AS_SET-only
  policy fixture and assertions 1–50 remain unchanged; a fresh local run
  completed the full 57/0 receipt.

- Process-global `bgp_sighup_reload_outcomes_total{outcome}` and
  `bgp_rib_policy_transition_total{outcome}` counters expose bounded terminal
  results without peer, path, configuration, or error-text labels. The
  overview dashboard groups SIGHUP results with config lifecycle activity and
  pins policy-transition outcomes beside the existing transition state and
  actor-duration panels.

- Active-primary session telemetry now exports the exact one-hot
  `bgp_peer_session_state{peer,interface,state}` FSM vector and
  `bgp_session_down_total{peer,interface,reason}`. The down counter records
  each Established epoch once under bounded local/remote notification,
  no-notification, transport-error, or defensive unknown reasons; collision
  candidates remain silent until promotion.

- The M99 FRR receipt now proves RFC 9072 extended OPEN framing at raw-byte
  level. One pinned FRR 10.3.1 process forces a small extended OPEN on one
  link while a second link stays classic; rustbgpd emits its exact 342-byte,
  307-capability-octet maximum production OPEN on the first and its exact
  49-byte classic OPEN on the second. Host tshark exports raw TCP payload,
  while an independent stream oracle permits identical retransmissions,
  rejects gaps or conflicts, consumes every type-2 parameter exactly, requires
  one OPEN per direction and no NOTIFICATION, and proves a non-empty common
  capability inventory on both Established sessions.

- The M16 FRR receipt now gates dual-stack LLGR in hosted interop CI. Exact
  two-route IPv4 and one-route IPv6 inventories cross fresh, GR-stale,
  LLGR-stale, and fresh states around one controlled restart; structured views
  pin both-family MP/GR/LLGR timer negotiation and EoR, while cumulative flap
  and GR-expiry counters each advance exactly once.

- The Enhanced Route Refresh 100k real-session receipt now applies always-on
  adjacent-operation ceilings to its actor-duration histogram: 25 ms for each
  accepted BoRR begin and 250 ms for EoRR or timeout completion. Every phase
  revalidates the exact accepted predecessor and baseline-relative actor counts;
  timed transitions advance exactly one operation while all other counts and
  sums remain unchanged, preventing cumulative averages from masking one slow
  operation.

- A runnable `rustbgpd-container.service` example now supervises the production
  image with Docker host networking, a fail-closed image selection, a
  root-owned state bind, and a read-only config bind. The root container drops
  all capabilities except `NET_BIND_SERVICE`; Docker gets the full 32-minute
  stop grace inside a 33-minute systemd margin, and reload maps to SIGHUP. The
  deployment guide now distinguishes Docker bridge low-port behavior from host
  networking and explains the uid 999 capability and state-owner traps.

- `bgp_session_lifecycle_source_dropped_total{reason}` exposes session state
  changes dropped before process-local, live, and durable event history. Its
  preinitialized `channel_full` and `channel_closed` series feed the shipped
  warning alert, which directs operators to resnapshot current neighbor state.

- Periodic BMP peer statistics now include RFC 9972 type 22 for exact counts of
  current pre-policy IPv4/IPv6-unicast Adj-RIB-In routes rejected by inbound
  policy. Rows are emitted only for negotiated families while rejected-route
  retention remains authoritative; disabled retention or any capacity eviction
  omits them rather than reporting a false lower bound. Path-aware retained
  identities keep the counts exact when Add-Path receive is negotiated.

- The M77 GoBGP 4.8.0 receipt now peer-proves VPNv6 graceful restart and
  long-lived graceful restart over the existing IPv4 sessions. Deterministic
  blue/red VPNv6 routes are retained stale without client churn, reconciled
  exactly at End-of-RIB after a selective re-injection, promoted with the
  LLGR_STALE community, and withdrawn exactly at LLGR expiry; the RR keeps its
  MPLS and IPv6 dataplanes untouched.

- The retained VPN RIB query campaign now gates all three full-run completion
  paths on its unchanged classifier while preserving advisory direct verifier
  use. Gated runs write the classification before returning a follow-up status
  and always recheck source, toolchain, affinity, and binary provenance first.

- `bench/compare-rib-memory.sh --fail-on-regression` turns the existing
  advisory RIB structural-memory comparison into a fixed fail-closed gate. A
  +5% or +32 MiB increase, or a missing base/head row, exits 1 only after the
  CSV, summary, and metadata record the result; the default invocation remains
  advisory.

- Periodic BMP peer statistics now include RFC 9972 types 35, 36, and 37 for
  exact post-policy Adj-RIB-In RPKI Invalid, Valid, and NotFound path counts per
  negotiated IPv4/IPv6-unicast family. The RIB maintains the gauges across
  insert, replacement, withdrawal, clear, and VRP-driven revalidation, so
  Add-Path identities remain exact. The rows are omitted until an authoritative
  VRP table is installed; negotiated families with an authoritative zero remain
  present.

- Nightly wire campaigns now seed all 12 targets, apply one reviewed BGP byte
  dictionary to the 11 binary targets, and carry a validated corpus forward on
  the `main` lineage. Restore happens in runner-temporary staging and accepts
  only the exact target layout, per-target input bounds, a matching SHA-256
  manifest, at most 20,000 files, and at most 16 MiB; a miss or cache-service
  outage falls back explicitly to tracked seeds, while invalid matched content
  stops before the campaign. Successful bounded runs seal a fresh bundle for
  the next nightly run, and hosted builders ship the same dictionary beside
  each applicable target.

- Route-server clients can configure `discard_path_attributes = [TYPE, ...]`
  on a neighbor or inherited peer group. Surviving decoded attributes are
  removed after RFC 7606 handling and route-safety checks but before import
  policy, explain caching, and RIB admission; pre-policy BMP retains the exact
  wire UPDATE. Effective-list changes purge-reset every static or accepted
  dynamic session generation, bypassing GR retention (RFC 8538 Hard Reset when
  Notification GR is negotiated), and
  `bgp_path_attribute_discarded_total{peer,type_code}` counts removed
  occurrences once per UPDATE.

- Periodic BMP peer statistics now include RFC 9972 post-policy Adj-RIB-In
  gauges: global type 20 and negotiated IPv4/IPv6-unicast family types 21 and
  23. These gauges are omitted when effective unicast Add-Path receive is active,
  because the current prefix counters intentionally deduplicate paths.

- The RIB memory harness now models the opposing costs of interned attribute
  container layouts at live-table-calibrated diversity and route-reflector
  fanout. Its pinned full campaign rejects an `Arc<[PathAttribute]>` migration
  that would add 17.7 MiB at 900k full RIB and 31.4 MiB at fanout, while the
  DHAT receipt sanitizer accepts both historical and provenance-rich bgperf2
  row schemas without admitting unbounded host identity.

- Prepare `rustbgpd-wire 0.19.0` and `rustbgpd-fsm 0.6.0` as the next paired
  standalone-library boundary. Wire adds observation and framing surfaces plus
  revised RFC 7606 handling without removing public items; FSM moves its
  exposed wire-type identity and adds the non-exhaustive
  `Event::AdministrativeReset` variant.

- Prepare `rustbgpd-rpki 0.1.0` for its first registry publish, with its current
  root and module API documented as the complete
  `0.1.x` compatibility boundary. The package includes a compiled origin
  validation example, an explicit Tokio/plain-TCP RTR boundary, and a
  registry-aware CI bootstrap that begins semver checking automatically once
  the first normal crates.io release is visible. Because no prior RPKI crate
  release exists, the initial line starts directly on `rustbgpd-wire 0.19.0`.

- `NeighborService.GetNeighborState` update-group comparisons now report
  `per_client_best` when two shared-staging group keys differ on the RFC 7947
  per-client-best axis; CLI human and JSON output use the same stable label.

- `bench/scale/compare-rrharness.sh --max-regression PCT` turns an unpinned
  rrharness comparison into a gated run: every rung — 1000-client rungs
  included — fails when head regresses by more than PCT percent
  (`parse_rrharness.py compare --max-regression`), and the receipt reports
  `regression-gate-passed` / `max-regression` instead of the advisory or
  pinned statuses it did not run under. (LAN-1316)

### Removed

- Remove the unused EVPN `mass_withdraw` tracker API; receive-side
  mass-withdraw remains the stateless, route-event-driven projection owned by
  the daemon dataplane supervisor.

- BMPv4 Path Marking TLV emission is temporarily removed because its draft
  type 5 assignment conflicts with the current Route Monitoring TLV registry.
  BMPv3 output is unaffected.

### Fixed

- Recognized optional non-transitive attributes now reject an invalid Partial
  flag. MED uses treat-as-withdraw; ORIGINATOR_ID and CLUSTER_LIST use
  attribute-discard on eBGP and treat-as-withdraw on iBGP. MP_REACH and
  MP_UNREACH retain their exact UPDATE `3/4` session-reset behavior. The policy
  is uniform rather than configurable and uses the existing malformed-UPDATE
  log and disposition metric.

- Outbound TCP connect failures now surface once per failed-connect episode
  instead of remaining below the default log level: a cold peer's first socket
  failure is INFO, the first failure after an Established epoch and the first
  internal connect-task failure are WARN, and subsequent retries remain DEBUG.
  Every retry still refreshes `last_error`, and a successful TCP connection
  re-arms visibility without changing the FSM or ConnectRetry cadence.

- The unpublished RIB crate no longer exposes unrestricted mutable Adj-RIB-In
  iteration. Its sole internal all-route mutation callback now maintains exact
  RPKI validation counts, preserving RFC 9972 BMP path-count rows and safe
  withdrawal after ASPA or future validation-state updates.

- `rbgp doctor` now requires every configured RPKI cache to have retained
  accepted complete End-of-Data readiness before reporting a healthy nonzero
  merged VRP table, while distinguishing not-ready caches from missing metric
  rows and keeping CLI-vantage connectivity probes separate.

- SIGHUP settlement fail-stop diagnostics now name the static reload step
  that fenced and whether an earlier effect was accepted. Non-SIGHUP owners
  report an explicit non-applicable step, while
  targets, configuration contents, and raw error text remain excluded.

- The July bgperf2 receipt and its documentation mirrors now preserve the raw
  historical rows without cross-daemon rankings. A fixed target order,
  sampler threads that continued polling across later cells, incomplete
  competitor build provenance, and an instrumented FRR build make the former
  margins and ratios unsupported; rustbgpd's fresh no-cache and release-only
  repeatability receipts remain valid.

- BMP per-collector queue loss now resets only the affected connection
  generation. A full or closed live fan-out queue closes that collector's TCP
  session without BMP Termination; the existing one-second retry reconnects,
  replays cached Peer Up state, and runs a fresh EoR-closed Loc-RIB dump when
  configured. Healthy collectors still receive the triggering event, and
  `bmp_collector_drops_total{phase="fan_out",reason}` records the reset trigger
  exactly once.

- Linux BLACKHOLE and general unicast FIB reconciliation now walks bounded,
  ordered Loc-RIB pages instead of retaining a second full route snapshot.
  Each pass has a 30-second planning ceiling and two-second query slices;
  daemon-owned keys missing from the provisional walk receive an exact current
  prefix check before removal. Route or peer-group churn freezes guarded new
  programming while safe exact cleanup continues, and incomplete planning
  leaves kernel, ownership, status, and replacement terminality unchanged.

- EVPN UPDATE decoding now reports unrecognized or unsupported typed NLRIs
  without dropping supported routes in the same MP attribute. One bounded
  debug record preserves each route type and count, while
  `bgp_evpn_nlri_discarded_total{peer}` exposes the aggregate without adding a
  route-type metric label; malformed framing remains a decode error.

- `/readyz` now checks peer-manager responsiveness with a constant-time actor
  ping instead of building a full peer inventory and querying every session.
  The mutation gate, RIB check, and shared 200 ms deadline are unchanged;
  `GetHealth` continues to return the detailed peer snapshot.

- Full-table blackhole and FIB RIB queries now share one two-second deadline
  across channel admission and reply, and cooperatively abandon Loc-RIB and
  ECMP materialization at bounded strides. An incomplete snapshot is dropped
  instead of reaching kernel reconciliation.

- Neighbor, peer-group, and policy gRPC mutations now mark a failed runtime
  change whose effects were fully compensated, distinguishing it from a
  rejection that made no change while preserving the original status code and
  error details. The response trailer and message warn that retrying can repeat
  transient runtime changes even though the staged persistent candidate was
  discarded.

- Tunnel Encapsulation and ATTR_SET attributes now receive bounded structural
  validation before opaque re-advertisement. Tunnel TLV/sub-TLV boundaries and
  ATTR_SET's Origin AS/embedded-attribute stream must be complete; embedded MP
  reachability attributes are rejected. The change adds no semantic decoding,
  and malformed input remains treat-as-withdraw.

- Plain eBGP export now removes non-transitive Extended Communities after
  export policy by default, while iBGP and transparent route-server-client
  sessions preserve them. A peer-group-inheritable
  `send_non_transitive_extended_communities` opt-in permits deliberate export
  across an AS boundary; normal and Partial attribute forms remain distinct.

- BMPv4 Route Monitoring now follows draft-ietf-grow-bmp-tlv-21's registry:
  Group=1, VRF/Table Name=2, Stateless Parsing=3, BGP Message=4, Sequence
  Number=5, Extended Flags=6, and Timestamp=7. BMPv3 remains byte-identical.

- Validation-cache and generated-dataset refreshes now distinguish a departed
  or non-Established session from a timed-out state query. Ambiguous queries
  fail the refresh and retain the pending import or export work for a later
  policy replay; RFC 8212 preflight and clean-convergence cohort selection use
  the same closed three-way outcome model. Periodic BMP statistics use that
  distinction too: a timed-out snapshot is counted and logged as
  `state_query_timeout`, not silently treated as a departed peer.

- The nightly and hosted wire fuzz campaigns now exercise complete BGP
  messages through the 65,535-byte RFC 8654 limit and UPDATE bodies through
  the corresponding 65,516-byte framing boundary instead of stopping at the
  legacy 4,096-byte ceiling. ROUTE-REFRESH bodies use that same extended
  framing boundary, while pre-negotiation OPEN bodies retain their exact
  4,077-byte legacy boundary.

- Neighbor and peer-group gRPC mutations now accept every address family
  supported by the configuration file, and read responses emit the same
  canonical vocabulary. BGP-LS remains `linkstate` / `linkstate_vpn` on
  configuration and operator surfaces while existing `bgpls` metric labels
  remain unchanged.

- Policy mutation preflight failures now preserve `NOT_FOUND`, `INVALID_ARGUMENT`, and
  `FAILED_PRECONDITION` while retaining the closed `policy_preflight_rejected` diagnostic.

- Canonical and Partial community and Only-to-Customer attributes now receive
  the same value-based treatment in consumers and interoperability fixtures.

- Settlement-owned live policy changes no longer treat one missed 100 ms
  session-state reply as session loss. A timed-out query retries at most once
  inside one shared two-second clean-state window; a confirmed non-Established
  state, a departed session task, or retry exhaustion compensates the change
  instead of committing uncertain state.

- Policy compensation now registers one exact rollback-only RIB batch before
  issuing Route Refresh. The batch rejects duplicate peers before mutation,
  restores in reverse application order, retains its late reply owner after a
  local timeout or caller cancellation, and clears retry debt only from ordered
  positive receipts. Settlement surfaces expose closed, secret-free policy
  failure codes while unprovable repair remains `KnownDivergence`.

- Collision registration failback now retains one survivor-session-scoped
  inbound ROUTE-REFRESH request when its outbound channel is full and retries
  it through the existing bounded RIB resync cadence. Repeated requests
  coalesce, a newer registration or peer teardown reaps stale intent, and a
  closed matching channel is counted as terminal loss instead of spinning.

### Changed

- Eligible homogeneous route-server update groups now share unicast staging,
  encoding, and exact-probe work, including safe own-source exclusion and
  group-uniform OTC handling. In the [fully reusable homogeneous-wire-profile
  700-peer / 400,400-route receipt](docs/perf/artifacts/selection-deferral-release-v0680-2026-08/README.md),
  median release time fell from 53.613 s to 0.811 s (about 66x). Mixed wire
  profiles form separate compatible cohorts; other ineligible cases retain
  the exact per-member fallback for source flips, lanes, withdrawals, export
  rejection, and prefix-limit filtering.

- The IXP comparator refresh now records OpenBGPD 9.2 at 700 clients and
  400,400 routes. Policy delivery improves from the 9.1 refresh's 244–251 s
  to 201–206 s, and 50-member re-announcement fan-out improves from
  21.1–21.6 s to 17.4–17.8 s. Repeated reconnects also expose 9.2's deliberate
  IdleHold pacing: after the fixed 10 s flap hold, rounds two and three wait
  about 20 s and 50 s before OPEN. The harness now retries only transport
  failures before peer OPEN inside its existing 120 s establishment window;
  BGP NOTIFICATION and decode failures remain immediate errors.

- The current cross-stack bgperf2 snapshot now measures rustbgpd v0.67.0,
  BIRD 2.19.2, FRR 10.7.0, and GoBGP 4.8.0 across five fleet shapes and four
  counterbalanced repetitions. Fresh pinned images and cell-scoped samplers
  replace the July campaign's fixed-order and build-provenance limitations;
  all 80 raw rows and the single disclosed incomplete cell are retained.

- `bmp_source_drops_total{peer,reason}` now also counts omitted periodic
  reports as `state_query_timeout`; the existing warning expression, severity,
  and timing are unchanged.
- Debug rendering of address families now uses the canonical public labels;
  unsupported or unconfigured known pairs use the `afi_N_safi_N` fallback.
- `bgp_outbound_route_drops_total` now counts only terminal outbound work loss;
  temporary collision-failback ROUTE-REFRESH saturation is retained and
  retried instead.

- Dependency resolution moves the dev-only MRT oracle from `bgpkit-parser`
  0.19.0 to 0.21.0, the wire crate's test-only direct `syn` requirement from
  major line 2 to 3, and locked `uuid` from 1.24.1 to 1.26.0. Other consumers
  retain their required `syn` lines; the parser and wire-test changes do not
  enter the shipped daemon dependency graph.

### Upgrade notes

- **BMPv4 collector migration:** Route Monitoring TLV type assignments changed
  from Group `4` to `1`, VRF/Table Name `5` to `2`, Stateless Parsing `6` to
  `3`, BGP Message `7` to `4`, Sequence Number `1` to `5`, Extended Flags `2`
  to `6`, and Timestamp `3` to `7`. Upgrade BMPv4 collectors before rustbgpd,
  or temporarily configure the collector with `version = 3`; BMPv3 framing is
  byte-identical. Path Marking is not emitted until its draft receives a
  non-conflicting type, so consumers that require it must remain on the prior
  release or tolerate its absence.
- **BMP source-drop accounting:** `bmp_source_drops_total` adds the bounded
  `state_query_timeout` reason. It means one periodic report was omitted and
  will be retried on the next tick; `channel_full` and `channel_closed` mean a
  source-channel event or report was lost. The shipped warning rule's
  expression, severity, and timing are unchanged, and an increment alone does
  not prove Route Monitoring divergence or a reset; use
  `bmp_stream_diverged` as the authoritative divergence signal.
- **Plain eBGP export default:** non-transitive Extended Communities are now
  filtered after export policy on plain eBGP sessions. iBGP and transparent
  route-server-client sessions are unaffected. Set the peer-group-inheritable
  `send_non_transitive_extended_communities = true` only when deliberate
  propagation across the AS boundary is required.
- **Policy mutation errors:** preflight failures that were formerly collapsed
  to gRPC `INTERNAL` now retain `NOT_FOUND`, `INVALID_ARGUMENT`, or
  `FAILED_PRECONDITION` as applicable. Clients should branch on the status code
  while continuing to use the stable `policy_preflight_rejected` diagnostic.
- **Compensated mutation errors:** a failed runtime mutation whose effects were
  fully repaired now prefixes its message with `runtime effects were fully
  compensated; retry may repeat transient runtime changes:` and adds the
  `rustbgpd-runtime-config-outcome: fully-compensated` response trailer. The
  original gRPC status code remains authoritative; retry may repeat transient
  runtime work even though the staged persistent candidate was discarded.
- **Address-family diagnostics:** old Debug-form family spellings in read-side
  diagnostics are replaced by canonical labels such as `ipv4_unicast`, with a
  `afi_N_safi_N` fallback for unsupported or unconfigured known pairs. This is
  display-only: no persisted configuration or stored value is rewritten during
  upgrade.
- **Opaque attribute validation:** malformed Tunnel Encapsulation (type 23) or
  ATTR_SET (type 128) attributes that were previously re-advertised opaquely
  now make affected NLRI treat-as-withdraw. Monitor
  `bgp_update_malformed_total{disposition="treat_as_withdraw"}` and correct the
  sending peer before retrying the route.
- **BLACKHOLE reconciliation:** bounded full-table planning can report
  `route_churn_deferred` while route churn prevents a stable
  snapshot. No install token is consumed and no new guarded route is installed;
  safe exact cleanup of stale daemon-owned entries may continue. Allow a later
  reconcile to retry after churn settles.
- **Outbound-drop alerting:** collision-failback ROUTE-REFRESH saturation is now
  retried and excluded from `bgp_outbound_route_drops_total`, so the unchanged
  critical alert may fire less often. An increment still means terminal
  outbound work loss; inspect the writer and peer, then refresh outbound if an
  advertised view was missed. The former inbound soft-reset advice no longer
  applies to this counter.
