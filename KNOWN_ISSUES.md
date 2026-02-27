# Known Issues

Tracked issues and limitations. Updated as bugs are discovered and
resolved.

---

*No known issues yet.*

## Limitations (by design, not bugs)

- **No DelayOpen timer.** RFC 4271 §8 optional. Not planned for v1.
- **No collision detection.** RFC 4271 §6.8. Transport supports only
  outbound connections in M0. Collision detection requires inbound
  listener support (post-M0).
- **UPDATE processing deferred.** Wire-level decode exists but RIB
  population is M1 scope. The FSM accepts `UpdateReceived` events in
  Established (resets hold timer) but does not process route content.
- **No inbound TCP listener.** Transport initiates outbound connections
  only. Passive-mode peers require a listener (post-M0).
- **Single task per peer.** Adequate for M0 OPEN/KEEPALIVE traffic.
  May need split reader/writer tasks for UPDATE throughput in M1.
