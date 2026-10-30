### Fixed

- Withdraw an RTBH or host route deleted during a graceful-restart selection
  hold from a GR-capable peer whose session ended cleanly, once its new
  session has resent its table. Previously the peer kept the deleted route as
  stale until the hold released and End-of-RIB was sent.
