### Fixed

- Withdraw an RTBH or host route deleted during a graceful-restart selection
  hold from a GR-capable peer whose session ended cleanly before the hold
  armed, once its new session is caught up. Previously the peer kept the
  deleted route as stale until End-of-RIB reached it or its own stale-route
  timer expired, when its new session had not sent its table and End-of-RIB
  before the hold armed. A deleted route whose prefix still has another
  candidate follows the [GR-helper RTBH limitation](../docs/reference/known-issues.md#open-issues);
  selection release is not a withdrawal deadline.
