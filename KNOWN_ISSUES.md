# Known Issues

Tracked issues and limitations. Updated as bugs are discovered and
resolved.

---

## Resolved

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

## Limitations (by design, not bugs)

- **Commit-confirmed config transactions do not survive a daemon restart.**
  The confirm timer and the captured pre-commit rollback snapshot are held in
  memory only. A restart inside the confirm window leaves the already-committed
  candidate live (effectively confirmed-by-restart) and the auto-revert never
  fires. Commit-confirmed therefore guards against a bad-but-*running* config
  (push a change, lose management reachability, and the timer rolls it back) —
  not against a daemon crash. Validate with `rustbgpd --check` or
  `PlanConfigTransaction` before applying a change that could itself prevent
  recovery. See ADR-0076 Decision 6.

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
- **LOCAL_PREF accepted on eBGP sessions.** RFC 4271 §5.1.5 says
  LOCAL_PREF should only appear in iBGP UPDATEs. The validator does
  not reject LOCAL_PREF from eBGP peers because session type (iBGP vs
  eBGP) is not yet fully distinguished. Will be enforced post-v1.
- **gRPC listener config (including mTLS) is restart-required.**
  Adding, removing, or rotating `[global.telemetry.grpc_tcp]` fields
  — including `tls_cert_file`, `tls_key_file`, `tls_client_ca_file`,
  `address`, `token_file`, and `access_mode` — does **not** take
  effect on SIGHUP. The live gRPC listener keeps serving the prior
  security mode and material until the daemon is restarted. Reload
  emits an explicit `error!` log when these fields change, so the
  drift is visible. Listener rebind on reload is post-v1 scope; the
  workaround for cert rotation today is `systemctl restart rustbgpd`
  or equivalent. UDS listener config (`grpc_uds`) has the same
  restart-required semantics.

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
- **Inline `policy.import` / `policy.export` reload requires restart.**
  Named-definition / chain edits hot-reload now (as of v0.12.0), but
  the legacy inline global-fallback statements at `[policy.import]` /
  `[policy.export]` are evaluated at session start and have no
  runtime swap surface yet. `rustbgpd --diff` flags them under
  "Restart-required" with a migration hint to named definitions plus
  `import_chain` / `export_chain`. Adding a runtime swap is tractable
  follow-up work — would need a new `ConfigEvent` variant and a
  `PeerManagerCommand` that re-runs `effective_policy_chains_for_neighbor`
  for every peer.
- **MRT snapshot encoding is allocation-heavy at large scale.** The
  `TABLE_DUMP_V2` encoder groups routes by prefix and synthesizes
  per-entry attributes, which is correct but can create extra allocation
  pressure for very large snapshots. Track as a performance optimization,
  not a correctness issue.
- **Injected routes support multiple paths via path_id.** `InjectionService`
  supports multiple injected routes per prefix using explicit `path_id`.
  Path ID 0 is the default path.
- **EVPN runtime mutation is alpha-complete with two by-design
  exceptions.** SIGHUP and the gRPC `EvpnService.ApplyEvpnRuntime` path
  both use the ADR-0063 coordinator for supported live shapes:
  L2VNI / IP-VRF / Ethernet-Segment add/delete/redefine, additive
  build-up, additive ES `member_vnis` expansion (adding L2VNIs that join
  an existing Ethernet Segment's member set in the same request, ADR-0063),
  atomic tenant teardown, `ip_vrf` relink, standalone and
  IP-VRF-linked L2VNI swaps, and L2VNI-only add/delete/redefine
  compositions. Unsupported candidates fail closed without advancing the
  committed generation. Two shape classes remain outside the hot-apply
  boundary by design: L3VNI/device/table IP-VRF identity changes
  (restart-required — kernel VRF lifecycle) and ES/IP-VRF row mixed edits
  outside the L2VNI-only composer. Tracked in
  <https://github.com/lance0/rustbgpd/issues/268>.
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
- **Large community duplicates preserved.** Duplicate large communities
  in received UPDATEs are stored and re-advertised unchanged. Strict
  RFC 8092 normalization (dedup on receipt and before encode) is deferred
  as a hardening item.
- **RT/RO extended communities are 2-octet AS-Specific only.** The
  `set_community_add`/`set_community_remove` policy actions encode RT/RO
  as 2-octet AS-Specific sub-type (type 0x00). ASNs > 65535 are rejected
  at config load time. 4-octet AS-Specific (type 0x02) and IPv4-Specific
  (type 0x01) encodings are matched correctly but cannot be generated by
  policy actions.
- **Route Refresh is unconditional.** The ROUTE-REFRESH capability
  (code 2) is always advertised. Inbound route refresh requests check
  peer capability, but there is no config option to disable the feature.
- **TCP-AO not supported for RTR connections.** RPKI cache server
  connections use plain TCP. TCP-AO (RFC 5925) is not supported for
  either BGP or RTR sessions. Use network-level access controls or
  SSH tunnels for RTR transport security.
- **Non-negotiated Add-Path NLRI is not detected.** If a peer violates
  negotiation and sends Add-Path-encoded NLRI for a family where Add-Path
  was not negotiated, the wire format is ambiguous — the 4-byte path ID
  can be misparsed as normal NLRI prefix encoding. Compliant peers will
  never do this. Fixing it would require a deeper parser redesign.
- **Unknown FlowSpec component types are rejected.** Component types >13
  (or any future RFC extension) cause a hard decode error rather than
  being preserved or skipped. This breaks forward compatibility if a
  future RFC defines type 14+. Should switch to skip-unknown behavior.
- **FlowSpec NLRI rule-length cap is enforced at encode time.** Rules
  exceeding the on-wire 12-bit limit (`MAX_FLOWSPEC_NLRI_RULE_LEN = 4095`)
  return `EncodeError::ValueOutOfRange` from
  `try_encode_flowspec_nlri`; callers building rules locally are expected
  to invoke `FlowSpecRule::validate_encoded_len` first. The prior
  silent-truncation behavior is fixed in `rustbgpd-wire` 0.9.2; this
  note is retained as documentation of the resulting hard cap.
- **Add-Path explain only covers best path.** `ExplainAdvertisedRoute`
  operates on the single Loc-RIB best path. For Add-Path peers, non-best
  candidates that are actually advertised are invisible to explain.
- **Policy match on absent LOCAL_PREF/MED returns false.**
  `match_local_pref_ge/le` and `match_med_ge/le` return false when the
  attribute is absent rather than using BGP implicit defaults (100 for
  LOCAL_PREF, 0 for MED). This means policies matching on these values
  won't fire for routes that rely on the implicit default.
- **String-based error matching in API deletion handlers.** Policy and
  peer-group deletion operations match `PeerManager` error messages with
  `error.contains("still referenced")` to distinguish precondition
  failures from not-found errors. Fragile coupling that could break if
  error messages are changed.
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
