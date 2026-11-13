### Upgrade notes

- Monitoring that relied on the daemon exiting 1 when its RPKI VRP manager or
  a validation-table forwarder panicked no longer sees that event for a
  panic the daemon recovers from. Alert on `bgp_rpki_task_restarts_total`
  (the shipped `RpkiTaskRestarted` rule) and on
  `bgp_rpki_cache_resync_pending` staying `1` (`RpkiCacheResyncPending`).
  While a cache is resync pending, validation uses that cache's last applied
  data until its expire; no restart is needed. `rbgp doctor` reports the
  panic report of a recovered panic as a recent crash.
