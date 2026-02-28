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
- **No collision detection.** RFC 4271 §6.8. If both sides initiate
  simultaneously, the inbound connection is dropped. Collision detection
  (compare router IDs, close the higher) is deferred to post-v1.
- **Single task per peer.** Adequate for current OPEN/KEEPALIVE/UPDATE
  traffic. May need split reader/writer tasks for high UPDATE throughput.
- **LOCAL_PREF accepted on eBGP sessions.** RFC 4271 §5.1.5 says
  LOCAL_PREF should only appear in iBGP UPDATEs. The validator does
  not reject LOCAL_PREF from eBGP peers because session type (iBGP vs
  eBGP) is not yet fully distinguished. Will be enforced post-v1.
- **No gRPC TLS.** Server listens in plaintext. TLS and mTLS are
  post-v1 scope. Default bind is localhost only.
- **InjectionService uuid is prefix-derived.** `AddPathResponse.uuid` is
  deterministically derived from the prefix; `DeletePath` ignores uuid and
  withdraws by prefix only. Multiple distinct injected paths per prefix
  are not supported.
- **DisableNeighbor reason not propagated.** The `reason` field in
  `DisableNeighborRequest` is accepted but not included in the Cease
  NOTIFICATION sent to the peer.
