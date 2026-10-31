### Fixed

- Withdraw an RTBH or host route deleted during a graceful-restart selection
  hold from a GR-capable peer whose session ended cleanly, once its new
  session has resent its table. Previously the peer kept the deleted route as
  stale until End-of-RIB reached it or its own stale-route timer expired. A
  deleted route whose prefix still has another candidate can remain until a
  replacement reaches the same key, End-of-RIB reaches the peer, or its
  stale-route timer expires. Selection release is not a withdrawal deadline;
  see the [GR-helper RTBH limitation](../docs/reference/known-issues.md#open-issues).
