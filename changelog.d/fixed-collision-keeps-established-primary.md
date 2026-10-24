### Fixed

- A connection collision no longer closes a session that reached Established
  while the collision was being resolved. When the peer's higher BGP
  Identifier picked the inbound connection, the outbound session could
  receive the peer's KEEPALIVE before the Cease/7 (Connection Collision
  Resolution) reached it, and was then torn down as the loser. RFC 4271
  §6.8 says an Established connection wins, so that session is now kept and
  the inbound connection is closed instead. The check and the Cease are one
  step in the session's own task.
  **Operator-visible:** after a link flap where both sides dial at once, the
  neighbor establishes once rather than two or three times, and every
  `bgp_session_established_total` increment is matched by a
  `bgp_session_flaps_total` increment when that session ends.
