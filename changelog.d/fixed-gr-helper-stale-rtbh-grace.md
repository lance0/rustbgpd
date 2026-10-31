### Fixed

- Withdraw an RTBH or host route that a GR-capable peer kept stale across a
  clean session end while replay grace holds our End-of-RIB toward it, even
  after the selection hold released or when the session ended outside any
  hold. Previously the peer kept a route deleted while the session was down
  until the grace window ended, at most `gr_eor_grace_time` seconds after
  start. A deleted route whose prefix still has another route still stays
  until our End-of-RIB.
