# Known Issues

Tracked issues and limitations. Updated as bugs are discovered and
resolved.

---

## Resolved

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

- **CLI gRPC integration tests added (fixed).** `rustbgpctl` now has
  mock-server integration tests covering health, global, neighbor add,
  and soft-reset command-to-RPC paths over both TCP+token and UDS.

- **Hot reconnect loop on persistent OPEN rejection (fixed).** When a peer
  consistently rejected OPENs (e.g., ASN mismatch), auto-reconnect fired
  `ManualStart` immediately as a synchronous follow-up, causing 29K+ cycles
  in 10 seconds. Fixed by introducing a deferred reconnect timer that waits
  `connect_retry_secs` (default 30s) before reconnecting. Discovered during
  malformed OPEN interop testing against FRR.

- **Unknown NOTIFICATION codes mapped to Cease (fixed).** The wire decoder
  silently converted unrecognized NOTIFICATION error codes to `Cease`,
  losing the original byte. Fixed by adding `Unknown(u8)` variant to
  `NotificationCode`. See ADR-0011.

- **Single task per peer (resolved).** The peer session task no longer
  owns the TCP write half. A dedicated writer task per peer (ADR-0051,
  commits `9675ecb` → `bcd2e0d` → `56c7527`) holds the `OwnedWriteHalf`
  with a bounded bulk channel + unbounded priority channel; the
  session task encodes BGP messages and enqueues bytes. TCP write
  back-pressure can no longer park the session's `select!`. Bulk-
  channel saturation triggers a `Cease/8` (Out of Resources) and a
  clean BGP session restart instead of silent drops. Validated by the
  M33 1h soak in `tests/soak/runs/20260427T230448Z/`: 0 drops, 0
  flaps, memory flat at 83 MB, slope 0.50 MB/h under sustained 1k rps
  EVPN churn.

## Limitations (by design, not bugs)

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
  Named-definition / chain edits hot-reload now (post-v0.11.0), but
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
- **Family scope is still limited.** MP-BGP supports AFI/SAFI negotiation,
  but rustbgpd currently implements IPv4/IPv6 unicast (AFI 1/2, SAFI 1),
  IPv4/IPv6 FlowSpec (AFI 1/2, SAFI 133), and L2VPN/EVPN (AFI 25, SAFI
  70) RR-mode forwarding (ADR-0050, RFC 7432). Other families such as
  VPNv4/VPNv6 (AFI 1/2, SAFI 128) and VPN FlowSpec (AFI 1/2, SAFI 134)
  are not implemented.
- **Implicit IPv4 prevents IPv6-only peers.** Per RFC 4760 §8, IPv4
  unicast is implicitly added when not explicitly negotiated via
  MultiProtocol capability. A `disable_ipv4_unicast` config option
  would be needed for true IPv6-only operation — future work.
- **Graceful Restart: no forwarding-state preservation.** RFC 4724 is
  implemented as helper (receiving speaker) plus minimal restarting speaker
  (`R=1` after coordinated restart via marker file, ADR-0040). However,
  `forwarding_preserved` is always false because rustbgpd does not own or
  verify the FIB. Full forwarding-state preservation is deferred until FIB
  integration exists.
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
- **FlowSpec NLRI length encoding limited to 4095 bytes.** The FlowSpec
  length prefix uses a 12-bit mask. Rules exceeding 4095 bytes get a
  silently truncated length on the wire. Extremely unlikely in practice
  (a single FlowSpec rule would need hundreds of match components).
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
- **Import `match_rpki_validation` / `match_aspa_validation` is best-effort.**
  Transport sessions evaluate import policy against the current validation
  snapshot (delivered via `tokio::sync::watch`). Routes arriving before the
  first VRP/ASPA table loads see `not_found`/`unknown`. Later cache updates
  revalidate routes in the RIB and recompute best-path, but do not
  retroactively re-run import policy or trigger route refresh. For
  convergent filtering, prefer best-path demotion (steps 0.5/0.7) and
  export policy. Use import validation matches as an early discard
  optimization, not as a sole defense.
