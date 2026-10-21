### Changed

- A neighbor's `updates_received` / `updates_sent`, `otc_routes_blocked` and
  `import_policy_routes_permitted` / `import_policy_routes_denied` (API
  `NeighborState`, `rbgp neighbor`, and the gNMI
  `state/messages/{sent,received}/UPDATE` leaves) no longer reset when the session re-establishes. Like `flap_count`,
  `notifications_*` and `messages_*`, they now count for the daemon's lifetime
  per neighbor: a reconfigure keeps them, and only a daemon restart or
  deleting the neighbor clears them. Previously the import-policy totals reset
  on every session-down, and all five restarted at 0 whenever the session
  re-established on a new session actor (an inbound reconnect, for example),
  so their scope depended on which side reconnected. Use `uptime_seconds` and
  `flap_count` to tell sessions apart.
