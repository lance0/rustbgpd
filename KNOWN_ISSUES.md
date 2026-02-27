# Known Issues

Tracked issues and limitations. Updated as bugs are discovered and
resolved.

---

*No known issues yet.*

## Limitations (by design, not bugs)

- **No DelayOpen timer.** RFC 4271 §8 optional. Not planned for v1.
- **No collision detection.** RFC 4271 §6.8 deferred to transport crate.
- **UPDATE processing deferred.** Wire-level decode exists but RIB
  population is M1 scope. The FSM accepts `UpdateReceived` events in
  Established (resets hold timer) but does not process route content.
