# Known Issues

Tracked issues and limitations. Updated as bugs are discovered and
resolved.

---

## Resolved

- **Add-Path export explain covers exact candidates (resolved).** For
  negotiated IPv4/IPv6 unicast Add-Path send, `ExplainAdvertisedRoute` and
  `rbgp rib advertised --explain` accept a presence-bearing Adj-RIB-In source
  peer/path ID (including ID 0), then report its independent compact outbound
  rank and rank-specific Adj-RIB-Out state. Legacy winner, VPN, labeled, ORR,
  and `ExplainBestPath` behavior is unchanged when the selector is absent.

- **Large community duplicates normalized (resolved).** Per RFC 8092,
  received duplicate values are silently removed and locally constructed
  duplicates are removed again at encode. Both boundaries retain first-seen
  order with expected linear work; flags, distinct-value order, and malformed
  length handling are unchanged.

- **Implicit IPv4 prevents IPv6-only peers (resolved).** Per RFC 4760
  §8, IPv4 unicast was implicitly added whenever it was not explicitly
  negotiated via the MultiProtocol capability, so a peer could not be
  made genuinely IPv6-only. The `disable_ipv4_unicast` neighbor /
  peer-group option now suppresses that fallback and excludes IPv4
  unicast from the advertised MultiProtocol capability; a session whose
  family intersection ends up empty is rejected with OPEN error /
  Unsupported Capability (2/7), matching FRR. Configs that set the flag
  while the effective `families` resolve to IPv4 unicast only are
  rejected at load. Proven against FRR in the M64 interop job.

- **IPv6 link-local next-hop preserved (resolved).** `MP_REACH_NLRI`
  with a 32-byte next-hop (global + link-local per RFC 4760 §3 / RFC
  2545) is decoded, stored on `Route` / `EvpnRibRoute`, re-emitted by
  the BGP UPDATE encoder, and round-trips through MRT
  `TABLE_DUMP_V2` exports as a 33-byte reduced-form attribute value
  (NH-Len=32 + 16-byte global + 16-byte link-local).

- **Native gRPC mTLS (resolved).** TCP listeners terminate TLS
  in-process via tonic + rustls/ring. Configure via three TOML keys
  on `[global.telemetry.grpc_tcp]`: `tls_cert_file` (server identity),
  `tls_key_file` (server private key), `tls_client_ca_file` (CA used
  to verify client certificates). All three are required together —
  partial config is rejected at config load. The validation path
  also reads each PEM file at config load / `--check` time and
  rejects missing, unreadable, empty, non-PEM, or wrong-kind files
  (e.g., a key path swapped with a cert path) before the daemon
  starts — a successful `--check` proves the listed TLS material
  is at least structurally usable. UDS listeners stay
  file-system-permission-authenticated, unchanged.

- **BMP drop / replay Prometheus counters (resolved).** Four new
  `bmp_*` counters surface what was previously only `tracing::warn!`
  output: `bmp_source_drops_total{peer, reason}` covers the
  PeerSession→BmpManager mpsc fill, `bmp_collector_drops_total
  {collector, phase, reason}` covers the per-collector mpsc fill
  (with `phase` distinguishing fan-out from PeerUp-cache replay),
  `bmp_replay_attempts_total{collector}` is the denominator for a
  "replay drop rate" alert, and `bmp_control_event_drops_total
  {collector, kind, reason}` surfaces BMP control events that fail
  to reach the manager (closing the silent skipped-replay window).
  Operators can now alert on BMP loss without a log scraper.

- **CLI gRPC integration tests added (fixed).** `rbgp` now has
  mock-server integration tests covering health, global, neighbor add,
  and soft-reset command-to-RPC paths over both TCP+token and UDS.

- **Hot reconnect loop on persistent OPEN rejection (fixed).** When a peer
  consistently rejected OPENs (e.g., ASN mismatch), auto-reconnect fired
  `ManualStart` immediately as a synchronous follow-up, causing 29K+ cycles
  in 10 seconds. Fixed by introducing a deferred reconnect timer that waits
  `connect_retry_secs` (default 5s) before reconnecting. TCP-level connection
  refusals use the separate fast-retry / exponential-backoff path; persistent
  OPEN rejection deliberately uses the fixed Idle reconnect guard. Discovered
  during malformed OPEN interop testing against FRR.

- **Unknown NOTIFICATION codes mapped to Cease (fixed).** The wire decoder
  silently converted unrecognized NOTIFICATION error codes to `Cease`,
  losing the original byte. Fixed by adding `Unknown(u8)` variant to
  `NotificationCode`. See ADR-0011.

- **EVPN Type 2 MAC+IP origination (resolved).** Gate 7b+2 (v0.16.0)
  added the parallel `AF_INET` / `AF_INET6` `RTNLGRP_NEIGH`
  subscription that correlates ARP/ND-suppression bindings with
  bridge FDB learns. The `LocalMacIpOriginator` task originates
  MAC+IP Type 2 under the FRR-style replace model — `IpAdded`
  upgrades a MAC-only Type 2 to MAC+IP, the last `IpRemoved`
  downgrades back. Predicated on `bridge link set ... neigh_suppress
  on` per the kernel snooping path. ADR-0055 §7 + ADR-0056.

- **EVPN sticky / static MAC anti-spoof config (resolved).** v0.17.0
  added the operator-facing `[[evpn_instances]].sticky_macs` schema
  (a list of MAC addresses to originate with the RFC 7432 §15.4
  sticky bit set). The originator consults the list on every
  observed local MAC and propagates the sticky flag through
  `OriginationAction::Inject` into the Extended Community on the
  wire. SVI MAC origination follows the same list when
  `advertise_svi_mac = true`. ADR-0056.

- **Single task per peer (resolved).** The peer session task no longer
  owns the TCP write half. A dedicated writer task per peer (ADR-0051,
  commits `9675ecb` → `bcd2e0d` → `56c7527`) holds the `OwnedWriteHalf`
  with a bounded bulk channel + unbounded priority channel; the
  session task encodes BGP messages and enqueues bytes. TCP write
  back-pressure can no longer park the session's `select!`. Bulk-
  channel saturation triggers a `Cease/8` (Out of Resources) and a
  clean BGP session restart instead of silent drops. Validated by the
  M33 1h soak: 0 drops, 0 flaps, memory flat at 83 MB, slope 0.50 MB/h
  under sustained 1k rps EVPN churn.

- **Commit-confirmed config transactions now survive a daemon restart
  (resolved).** The confirm timer and the pre-commit rollback snapshot used to
  be held in memory only, so a restart inside the confirm window left the
  already-committed candidate live (confirmed-by-restart) and the auto-revert
  never fired. The daemon now journals the pre-commit config snapshot to
  `<runtime_state_dir>/commit-confirm-journal.json` (atomic write) before the
  candidate commits; a restart that finds an unconfirmed journal reverts to
  the journaled config at boot — regardless of remaining confirm time, since
  the confirming session died with the old process (NETCONF RFC 6241 §8.4
  cancel-on-session-loss semantics) — saving the unconfirmed candidate aside
  as `<config>.unconfirmed`. A torn or unusable journal refuses boot naming
  both files. Proven by SIGKILL-mid-window real-binary tests
  (`tests/commit_confirm_binary.rs`). See ADR-0076 Decision 6 amendment.

- **Implicit LOCAL_PREF/MED policy defaults (resolved).** Policy matches now
  apply the BGP implicit defaults when these attributes are absent: 100 for
  `LOCAL_PREF` and 0 for `MED`. Routes that rely on those defaults therefore
  match `match_local_pref_ge/le` and `match_med_ge/le` consistently with routes
  carrying the equivalent explicit attribute values.

- **Typed catalog deletion preconditions (resolved).** Policy and peer-group
  deletion paths now return the typed `CatalogMutationError::StillReferenced`
  variant when an object remains in use. The gRPC API maps that variant to
  `FAILED_PRECONDITION` without coupling behavior to error-message text.

- **Peer-supplied eBGP LOCAL_PREF handling (resolved).** A `LOCAL_PREF`
  received from an eBGP peer is ignored before policy evaluation, explain-cache
  capture, Adj-RIB-In storage, and best-path selection. iBGP `LOCAL_PREF` and
  values set by import policy remain effective, while byte-exact pre-policy BMP
  monitoring retains the original wire UPDATE, including the peer-supplied
  attribute.

## Measurement tooling defects

These profiling-instrument defects do not affect daemon behavior. All three
were found during the explain-cache memory campaign
(`docs/perf/explain-cache-opt-in-2026-07.md`) and are resolved; the retained
derivatives were reclassified from unchanged normalized stacks and per-stack
byte counts.

- **DHAT import-decision owner matching (resolved).** The classifier now
  requires an actual `ImportDecisionCache` owner rather than any generic type
  mentioning its module. The unrelated `RejectedRouteStore` no longer enters
  the cache bucket, and the disabled-cache capture reports exactly zero there.
  The explain-cache receipt retains its per-row semantic table because
  policy-context clones allocated in the inbound path have no cache owner in
  their allocation stack.

- **Current demangled RIB owner matching (resolved).** Owner markers accept the
  optimized `<Type>::method` spelling emitted by current Rust toolchains, so
  group, Loc-RIB, Adj-RIB-In, prefix-trie, daemon-core, and per-peer Adj-RIB-Out
  allocations no longer collapse into `RIB other`.

- **Stripped DHAT capture diagnostic (resolved).** A live allocation with an
  empty frame stack now fails with an actionable message requiring a symbolized
  `release-prof` build and explicitly rejecting the stripped release profile.

## Limitations (by design, not bugs)

- **Required-family enforcement is local.** `required_families` lets rustbgpd
  require selected AFI/SAFIs from a peer's OPEN, but BGP has no symmetric
  standard capability that makes the remote implementation enforce rustbgpd's
  advertised set. Configure the equivalent policy independently on both ends;
  BIRD 3.3.1 exposes this as per-channel `mandatory on`. The rustbgpd rejection
  interop fixture deliberately leaves BIRD `mandatory` off so rustbgpd remains
  the rejecting speaker under test.

- **RFC 9687 send hold timer is a per-write deadline, not the RFC's
  free-running timer.** The RFC models a `SendHoldTimer` restarted on
  every sent message; rustbgpd instead bounds each individual
  `write_all + flush` in the writer task by the configured
  `send_hold_time`. The trigger condition is equivalent — a peer that
  stops draining its socket stalls the pending write, which then times
  out — and the per-write shape cannot false-fire on an idle session
  (so protection stays active even with `hold_time = 0`, where the RFC
  would stop its timer). Two practical consequences: detection starts
  only once the kernel send buffer stops accepting bytes (shared by
  every implementation of this mechanism — FRR's SendQ-progress check
  measures the same way), and a `send_hold_time` config change applies
  to sessions established after the change, not to the currently
  running writer. No NOTIFICATION is sent on expiry (optional per
  §4.3; the socket is by definition not draining). Details in
  `docs/RFC_NOTES.md` (RFC 9687 section).

- **BMP Adj-RIB-In/Adj-RIB-Out streams are live-only — no table dump on
  collector (re)connect.** A collector that connects mid-life receives
  the cached Peer Up replay but no synthesized Route Monitoring dump of
  those views: the RFC 8671 post-policy Adj-RIB-Out stream
  (`monitor = ["rib_out_post"]`) starts at the next outbound UPDATE,
  exactly as the pre-policy Adj-RIB-In stream has always started at the
  next inbound UPDATE. The RFC 9069 Loc-RIB view
  (`monitor = ["loc_rib"]`) does NOT share this gap — it performs a
  full table dump (closed by per-family End-of-RIB) on every collector
  (re)connect, and for a route reflector the post-policy Loc-RIB is the
  view most dump consumers actually want. Rib-out dump synthesis was
  evaluated and deliberately deferred: `AdjRibOut` stores post-policy
  routes *before* transport stamping, so a synthesized dump would miss
  the session-side attribute rewrites (`ORIGINATOR_ID`/`CLUSTER_LIST`
  on reflection, GShut community, LLGR §4.6 form) and not be
  byte-faithful to what was advertised; pre-policy Adj-RIB-In is
  unreconstructable post-import. Collectors needing those exact views
  should connect before sessions establish (or trigger a route
  refresh). Because these streams are live-only, a Route Monitoring
  event lost to BMP-channel saturation can never be replayed — so the
  daemon guarantees such a loss is collector-detectable, never silent:
  per-peer `PeerUp`/`PeerDown` delivery from sessions to the BMP
  manager is reliable, and a Route Monitoring event dropped on a full
  session→manager channel (counted in `bmp_source_drops_total`) forces
  a synthetic `PeerDown`/`PeerUp` peer-state reset on the stream so
  collectors discard the now-incomplete view and rebuild from live
  traffic. The per-collector fan-out queue remains lossy by design
  (`bmp_collector_drops_total`); a collector that saturates its own
  channel diverges until its next reconnect, which per RFC 7854
  discards all state and replays PeerUp — alert on that counter.

- **RFC 8326 receiver gating doesn't yet know about confederations.**
  When `[global] honor_graceful_shutdown = true`, the implicit chain-
  tail demotion rule fires only on EBGP peers. The current EBGP gate
  is a simple `neighbor.remote_asn != self.global.asn` comparison.
  This is correct for traditional EBGP/iBGP topologies (which is all
  rustbgpd supports today) but will be wrong once confederation
  support lands: confederation-EBGP peers have a different sub-AS
  but are still inside the same routing domain for `LOCAL_PREF`
  preservation purposes. When confederations land, the gate should
  key off an explicit `is_external_neighbor()` helper that knows
  about the sub-AS topology. Tracked under "RFC 8326 confederation
  gating" in `ROADMAP.md`. No-op for the current release because
  rustbgpd doesn't support confederations yet.

- **RFC 8326 initiator toggle does not persist across daemon restart.**
  `rbgp gshut --peer X` flips a runtime bool on `ManagedPeer`
  + the corresponding session, and triggers a RIB refresh so the
  community appears on the wire. The toggle survives session flaps
  and collision-replaces during the daemon's lifetime, but is lost
  on daemon restart by design (RFC 8326 is a maintenance-window
  action, not steady-state config). Operators running planned
  maintenance that includes a daemon restart should re-issue the
  `gshut` command after the daemon comes back. If you want
  permanent GShut behavior, write it into export policy as
  `set_community_add = ["GRACEFUL_SHUTDOWN"]` instead.

- **RFC 7999 BLACKHOLE FIB discard has first-slice guardrails only.**
  `[global] honor_blackhole = true` plus
  `[global] install_blackhole_discard = true` now installs Linux kernel
  blackhole routes for accepted EBGP best routes carrying `BLACKHOLE`,
  but the authorization model is intentionally narrow: EBGP + import
  policy acceptance + host-prefix-only by default. Per-peer allow-lists,
  active blackhole limits, rate limits, and startup stale-route adoption
  remain follow-ups. M41 covers FRR-originated install/remove behavior
  in CI. See ADR-0060.

- **ADR-0061 general FIB crash recovery is exact-match only.**
  `[[fib_tables]]` route installs use `RTPROT_BGP`, but that marker is not
  rustbgpd-specific; FRR and BIRD can install indistinguishable rows in the
  same table and metric. rustbgpd now persists daemon-owned rows to
  `<runtime_state_dir>/fib-owned.json` and reloads that file after crash,
  `SIGKILL`, or OOM. Recovery is deliberately conservative: the
  `[[fib_tables]]` declaration must be unchanged and the live kernel row must
  still be `RTPROT_BGP` with the exact next-hop rustbgpd recorded. Rows absent
  from the file and rows with changed config are preserved and reported as
  `foreign_route_exists` rather than adopted by protocol alone. Rows with
  persisted owned-state that drifted are reported once as `owned_route_drifted`.
  If the route remains desired on a later pass, the same live row is then
  reported as ordinary foreign state after ownership is released.

- **No DelayOpen timer.** RFC 4271 §8 optional. Not planned for v1.
- **gRPC listener shape is restart-required; credential bytes rotate on
  SIGHUP.** The listener *shape* — `address`, `access_mode`, the auth mode,
  and the configured `token_file` / `tls_cert_file` / `tls_key_file` /
  `tls_client_ca_file` **paths** — is fixed for the process. Adding, removing,
  or repointing any of those on `[global.telemetry.grpc_tcp]` does **not** take
  effect on SIGHUP; the live listener keeps its prior shape until the daemon is
  restarted, and reload emits an explicit `error!` log so the drift is visible.
  The credential *material* behind those unchanged paths does rotate: SIGHUP
  re-reads the bytes, validates the complete token / server identity / client CA
  for every listener, and atomically publishes one process-wide generation.
  Existing TLS connections and admitted streams continue; new TLS accepts and
  new bearer-authenticated RPCs use the new generation; a malformed or partial
  rotation retains the last-known-good generation. UDS listener config
  (`grpc_uds`) shape has the same restart-required semantics.

- **SIGHUP reconcile is not transactional.** Reload now applies
  named-policy / neighbor-set / peer-group / global-chain edits in
  addition to `[[neighbors]]` deltas. On any step failure, reload
  halts and returns the partial-state snapshot — the daemon's
  in-memory config matches what the peer manager actually applied,
  rather than the previous behaviour of lying that the prior config
  is still in effect. The operator converges by editing the failing
  TOML and reloading again; the next diff runs against the half-
  applied state, so only the remaining steps fire. True rollback
  (replaying reverse commands to undo successful steps) is still
  out of scope — peer-group changes flap sessions, and unwinding
  flap them again.
- **MRT snapshot attribute synthesis still allocates per entry.** The
  dominant allocation cost — millions of exact-capacity output-buffer
  reallocations on full-table dumps — was removed by bounded geometric
  output growth (growth misses fell from millions to ~40 on both
  measured fleet shapes; see
  [docs/perf/mrt-snapshot-allocation-2026-07.md](docs/perf/mrt-snapshot-allocation-2026-07.md)).
  The `TABLE_DUMP_V2` encoder still groups routes by prefix and
  synthesizes per-entry attributes, which remains a residual allocation
  cost for very large snapshots. Track as a performance optimization,
  not a correctness issue.
- **Injected routes support multiple paths via path_id.** `InjectionService`
  supports multiple injected routes per prefix using explicit `path_id`.
  Path ID 0 is the default path.
- **EVPN runtime mutation is alpha-complete with one by-design
  exception.** SIGHUP and the gRPC `EvpnService.ApplyEvpnRuntime` path
  both use the ADR-0063 coordinator for supported live shapes:
  L2VNI / IP-VRF / Ethernet-Segment add/delete/redefine, additive
  build-up, additive ES `member_vnis` expansion (adding L2VNIs that join
  an existing Ethernet Segment's member set in the same request, ADR-0063),
  atomic tenant teardown, `ip_vrf` relink, standalone and
  IP-VRF-linked L2VNI swaps, and decomposable mixed edits ordered as
  deletes -> redefines -> `ip_vrf` relinks -> adds. Unsupported dependency
  cycles fail closed without advancing the committed generation; a later
  primitive convergence failure fail-stops after any earlier generations that
  already committed and increments `evpn_runtime_decomposed_fail_stops_total`.
  L3VNI/device/table IP-VRF identity changes remain outside the hot-apply
  boundary by design (restart-required — kernel VRF lifecycle).
- **Family scope is still limited.** MP-BGP supports AFI/SAFI negotiation,
  but rustbgpd currently implements IPv4/IPv6 unicast (AFI 1/2, SAFI 1),
  IPv4/IPv6 FlowSpec (AFI 1/2, SAFI 133), L2VPN/EVPN (AFI 25, SAFI
  70) RR-mode forwarding (ADR-0050, RFC 7432), BGP-LS / BGP-LS VPN
  (AFI 16388, SAFI 71/72) receive + reflection + API export (ADR-0077,
  RFC 9552; local topology production remains deferred), and VPNv4/VPNv6
  (AFI 1/2, SAFI 128) route-reflection (RFC 4364 / RFC 4659 —
  RR/controller-feed only: RD, MPLS label stack, next-hop, and Route
  Targets are preserved verbatim; no VRF import, no MPLS FIB install;
  Add-Path per RFC 7911 is supported for SAFI 128), and
  RT-Constrain (AFI 1, SAFI 132) per RFC 4684 (strict per-peer VPN
  reflection filtering with self-originated default membership; §3.2(ii)
  non-client attribute-swap, the §6 60-second EoR delay, eBGP RTC
  subtleties, and Add-Path remain deferred — see the ADR-0077
  amendment). IPv4/IPv6 labeled-unicast (AFI 1/2, SAFI 4) per RFC 8277 is
  implemented RR-only — the label stack and next-hop are preserved
  verbatim, no label allocation, rewrite, or MPLS FIB install; Add-Path
  per RFC 7911 is supported — completing the ADR-0077 quartet
  (BGP-LS, VPNv4/v6, RT-Constrain, labeled-unicast); M79 is the GoBGP
  real-peer receipt (reflection incl. multi-label stacks and a v6
  next-hop over a v4 session, relabel implicit replace, label-stack
  withdraw with zero session flap, GR window + EoR sweep). GR/LLGR stale
  preservation now covers all of these RR
  families (RFC 4724 helper retention + RFC 9494 two-phase LLGR, M77
  receipt), and the pre-existing unicast/FlowSpec/EVPN paths implement
  the same RFC-strict consecutive-restart deletion, End-of-RIB sweep
  of non-readvertised stale routes (RFC 4724 §4.1 / RFC 9494 §4.2), and
  the RFC 9494 §4.4 export restriction (LLGR-stale routes are withheld
  from eBGP peers that didn't advertise the LLGR capability; non-LLGR
  iBGP peers receive them per the §4.6 intra-AS exception with NO_EXPORT
  and LOCAL_PREF 0, LLGR_STALE community intact). Other families such
  as VPN FlowSpec (AFI 1/2, SAFI 134) are not implemented.
- **Graceful Restart: no forwarding-state preservation.** RFC 4724 is
  implemented as helper (receiving speaker) plus minimal restarting speaker
  (`R=1` after coordinated restart via marker file, ADR-0040). However,
  `forwarding_preserved` is always false because rustbgpd does not persist
  route/FIB ownership across restart or verify that forwarding state survived.
  ADR-0061 FIB programming is opt-in and scoped; crash-left rows are preserved
  as foreign rather than adopted.
- **Route Refresh is unconditional.** The ROUTE-REFRESH capability
  (code 2) is always advertised. Inbound route refresh requests check
  peer capability, but there is no config option to disable the feature.
- **TCP-AO not supported for RTR connections.** RPKI cache (RTR) server
  connections use plain TCP; TCP-AO (RFC 5925) is not available for the
  RTR transport. Use network-level access controls or SSH tunnels for RTR
  transport security. (TCP-AO *is* supported for BGP static-neighbor and
  dynamic-prefix keys on Linux, including live successor installation,
  selection, and deprecated-key deletion on SIGHUP — see SECURITY.md and
  ADR-0062.)
- **Non-negotiated Add-Path NLRI is not detected.** If a peer violates
  negotiation and sends Add-Path-encoded NLRI for a family where Add-Path
  was not negotiated, the wire format is ambiguous — the 4-byte path ID
  can be misparsed as normal NLRI prefix encoding. Compliant peers will
  never do this. Fixing it would require a deeper parser redesign.
- **Unknown FlowSpec component types are rejected — and must be.**
  A component type outside 1–13 makes the whole NLRI a decode error.
  This is RFC 8955 §4.2 conformance, not a gap: "an NLRI that contains
  an unknown component type[] is considered malformed". Skip-unknown is
  not implementable for this encoding — only the *rule* is
  length-prefixed, and each component's value grammar is selected by its
  type code (types 1–2 are `<length, prefix>`, with an extra offset
  octet under RFC 8956; types 3–13 are numeric- or bitmask-operator
  lists whose width comes from the operator octet). A decoder cannot
  measure a component it does not recognize, so it cannot resynchronize
  on the next one, and dropping a component would widen the rule's match
  set beyond what the sender asked for. Consequently a future type 14+
  requires a rustbgpd upgrade to interoperate — as it does for every
  RFC 8955 implementation. Disposition follows RFC 7606 §7.11
  (session reset for malformed `MP_REACH_NLRI`), since the remaining
  NLRI cannot be located.
- **FlowSpec NLRI rule-length cap is enforced at encode time.** Rules
  exceeding the on-wire 12-bit limit (`MAX_FLOWSPEC_NLRI_RULE_LEN = 4095`)
  return `EncodeError::ValueOutOfRange` from
  `try_encode_flowspec_nlri`; callers building rules locally are expected
  to invoke `FlowSpecRule::validate_encoded_len` first. The prior
  silent-truncation behavior is fixed in `rustbgpd-wire` 0.9.2; this
  note is retained as documentation of the resulting hard cap.
- **MRT `originated_time` silently clamps to `u32::MAX`.** The MRT
  `TABLE_DUMP_V2` encoder clamps `originated_time` to `u32::MAX`
  instead of returning an error when the timestamp exceeds the 32-bit
  range. Correct per RFC 6396 wire format (field is 4 bytes) but will
  lose precision after 2106.
- **FlowSpec `encode_numeric_ops()` overwrites `end_of_list` flag.**
  The encoder computes `end_of_list` from position (last element gets
  `true`), silently discarding the original flag on round-trip. This is
  safe for all normal use but means a decode→encode cycle is not
  perfectly lossless for malformed inputs with incorrect flags.
- **FlowSpec AFI defaults to IPv4 when no destination prefix component.**
  A FlowSpec rule with no destination prefix component (e.g., "drop all
  UDP") received on an IPv6 FlowSpec session is stored with
  `afi: Afi::Ipv4` implicitly via the MpReachNlri AFI. This is correct
  per wire semantics (the AFI comes from the MP_REACH attribute, not the
  rule itself) but worth noting — the AFI is always set correctly from
  the MP_REACH/MP_UNREACH framing.
