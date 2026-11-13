### Upgrade notes

- Monitoring that relied on the daemon exiting 1 when its metrics/readiness
  server failed (a `Restart=on-failure` count, or a log match on
  `initiating shutdown due to metrics/readiness server failure`) no longer
  sees that event. Alert on a failed scrape while the listener is down and on
  an increase of `bgp_management_server_crashes_total` afterwards; the
  shipped `BgpManagementServerCrashed` rule covers the second. This
  supersedes the earlier behavior of fail-stopping rather than running
  without the health surface: the listener is now recovered in place, and a
  daemon whose restarts keep failing stays up with the listener down and an
  ERROR line per attempt.
