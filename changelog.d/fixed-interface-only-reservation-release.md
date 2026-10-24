### Fixed
- An interface-only neighbor that loses its Router Advertisement binding while
  its link stays up now releases its last address once nothing retains it.
  While Graceful Restart or LLGR stale routes from the old session remain, the
  neighbor keeps redialing that address and it stays reserved, as before; when
  the stale timer retires them, or at once when the session ended without
  retention, the peer is removed with reason `binding_expired` and another
  link may admit the address
  ([ADR-0142](../docs/adr/0142-interface-only-unnumbered-neighbors.md)).
  **Operator-visible:** a silent peer on a link that stays up no longer keeps
  a parallel link to the same device refused after its retained routes are
  gone.
