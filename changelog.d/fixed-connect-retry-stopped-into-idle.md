### Fixed

- A TCP failure in OpenConfirm or Established no longer leaves the
  ConnectRetry timer running into Idle (RFC 4271 §8.2.2 sets it to zero).
  Its later expiry counted in `bgp_fsm_stale_timer_events_total`, whose
  help text treats a non-zero value as a daemon bug. Reconnects are
  unaffected; they use the session's own reconnect timer.
