### Fixed

- Release session-notification outstanding accounting when receiver teardown
  races with an already-admitted send. Queued notifications now own their
  accounting reservation, so channel cleanup cannot leave a stale positive
  `bgp_session_notification_outstanding` value. Lossless delivery and the
  daemon-lifetime high-water metric are unchanged.
