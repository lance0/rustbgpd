### Fixed

- Withdraw an RTBH or host route deleted during a graceful-restart selection
  hold from a GR-capable peer whose session ended cleanly before the hold
  armed, once its new session is caught up. Previously the peer kept the
  deleted route as stale until the hold released, when its new session had
  not sent its table and End-of-RIB before the hold armed. A deleted route
  whose prefix still has another route still stays at the peer until
  release.
