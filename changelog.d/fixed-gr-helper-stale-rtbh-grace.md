### Fixed

- Withdraw an RTBH or host route that a GR-capable peer kept stale across a
  clean session end while replay grace holds our End-of-RIB toward it, even
  after the selection hold released or when the session ended outside any
  hold. Previously the peer could keep a route deleted while the session was
  down until End-of-RIB reached it or its own stale-route timer expired. A
  deleted route whose prefix still has another candidate follows the
  [GR-helper RTBH limitation](../docs/reference/known-issues.md#open-issues).
  The grace window's end is not a withdrawal deadline: an ORF hold, a queued
  refresh, or outbound backpressure can extend the wait for End-of-RIB.
