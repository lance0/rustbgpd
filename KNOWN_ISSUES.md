# Known Issues

Tracked issues and limitations. Updated as bugs are discovered and
resolved.

---

## Resolved

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

## Limitations (by design, not bugs)

- **No DelayOpen timer.** RFC 4271 §8 optional. Not planned for v1.
- **No collision detection.** RFC 4271 §6.8. Transport supports only
  outbound connections. Collision detection requires inbound listener
  support (planned for M3).
- **No inbound TCP listener.** Transport initiates outbound connections
  only. Passive-mode peers require a listener (planned for M3).
- **Single task per peer.** Adequate for current OPEN/KEEPALIVE/UPDATE
  traffic. May need split reader/writer tasks for high UPDATE throughput.
- **No best-path selection.** Adj-RIB-In stores all received routes.
  Loc-RIB best-path comparison is M2 scope.
- **No outbound UPDATE generation.** Routes are received and stored but
  not re-advertised. Adj-RIB-Out is M3 scope.
- **gRPC: only ListReceivedRoutes implemented.** Other RibService RPCs
  and all other services return UNIMPLEMENTED. Full API is incremental
  across M2-M4.
- **No gRPC TLS.** Server listens in plaintext. TLS and mTLS are
  post-v1 scope. Default bind is localhost only.
