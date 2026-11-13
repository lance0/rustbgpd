### Fixed

- A panic in the RPKI VRP manager or in a validation-table forwarder no
  longer shuts the daemon down. The manager loses only the message it was
  handling: each cache's VRPs and ASPAs and the validation tables in use stay
  exactly as they were, so validation states, import policy that matches on
  them, and advertisements do not change, and nothing is revalidated to
  NotFound. A cache whose update was lost is asked for a full table (a Reset
  Query after `retry_interval`); until it arrives the cache's last applied
  data stays in use, and it is dropped at its original expire if the table
  never comes. A forwarder forwards the latest table again after a short
  backoff. BGP sessions and the other caches are not touched. Previously
  either panic aborted every RPKI task and the daemon exited 1. See
  [operations](../docs/reference/operations.md#rpki-subsystem-task-exits-unexpectedly).
  **Operator-visible:** new `bgp_rpki_task_restarts_total{task}` (`vrp_manager`,
  `vrp_forwarder`, `aspa_forwarder`, each `0` from startup) and
  `bgp_rpki_cache_resync_pending{cache}` (`1` while a cache owes a full
  table), with the shipped `RpkiTaskRestarted` and `RpkiCacheResyncPending`
  alert rules. Each recovered panic logs at ERROR and leaves a panic report.
- A full table that replaces a cache's previous one (after a Cache Reset, a
  reconnect without a usable serial, or a resynchronization), and the loss of
  a cache's data at flush or expire, now revalidate only the routes covered
  by the VRPs or ASPA customers that actually changed. Previously each made
  the RIB and every session re-evaluate all routes. A cache's first table
  still re-evaluates everything.
