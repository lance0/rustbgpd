# Changelog

All notable changes to rustbgpd will be documented in this file.

For releases before 0.68.0, see the [older release history](docs/project/changelog/older-releases.md).

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

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

### Changed

- `rbgp rib add` uses `--next-hop` as the canonical flag, retaining
  `--nexthop` as a visible compatibility alias. The default RIB pager now
  wraps long lines (`less -FRX` in auto mode, `less -RX` in always mode);
  explicit `RBGP_PAGER` and `PAGER` arguments remain unchanged.

- Root `rbgp` help and the man-page command index group commands by task,
  preserving command paths, aliases, and subcommand help.

- The three example programs (`event-bridge`, `peer-loop`, `birdwatcher-adapter`)
  now build under the same lint policy as the workspace crates
  (`deny(unsafe_code)`, `deny(clippy::all)`, `warn(clippy::pedantic)`).

- `rustbgpd-wire` 0.19.0 → 0.19.1 (additive): a new `mrt` module adds
  `decode_table_dump_v2_mp_reach_next_hop`, the RFC 6396 §4.3.4 `TABLE_DUMP_V2`
  RIB-entry `MP_REACH_NLRI` next-hop decoder now shared by the daemon's
  warm-checkpoint reader and `rbgp diff snapshot from-mrt`. `rustbgpd-fsm`
  stays at 0.6.0 and `rustbgpd-rpki` at 0.1.0; their wire requirement follows
  the workspace pin to `^0.19.1`, which the patch satisfies.

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

- Locally learned EVPN MACs now adopt a higher sequence from a peer on the
  same nonzero Ethernet Segment, including all locally learned IPv4/IPv6
  bindings. Adoption uses the exact sequence without a mobility increment,
  preserves local sticky state, and does not count as duplicate-MAC or
  duplicate-IP movement. Only matching import RTs, VNI, tag zero, and a
  nonlocal next hop qualify; peer routes alone do not create local ownership.

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
