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
- **IPv6 link-local next-hop discarded.** When `MP_REACH_NLRI` carries a
  32-byte next-hop (global + link-local), only the first 16 bytes (global
  address) are used. Link-local next-hops are not tracked or advertised.
- **Only IPv4 and IPv6 unicast.** MP-BGP supports AFI/SAFI negotiation
  but only IPv4 unicast (AFI 1, SAFI 1) and IPv6 unicast (AFI 2, SAFI 1)
  are implemented. Other families (VPNv4, FlowSpec, etc.) are rejected.
