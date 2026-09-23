### Fixed

- An `[rpki] cache_servers[].retry_interval` above the RFC 8210 §6 maximum of
  7200 seconds is now applied as 7200 seconds. Retry paces reconnects before
  any End of Data can lower it, so a larger value parked the first reconnect
  at a far-future deadline and the daemon never retried a cache that was down
  at startup. Values from 1 to 7200 seconds are unchanged.
  **Operator-visible:** the daemon logs a warning, `RTR configured timer
  outside the §6 range, bounded`, with the configured and applied values.
