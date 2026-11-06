### Fixed

- Setting graceful shutdown on all peers (`rbgp gshut --all`) now also sets
  the intent held for a dynamic neighbor between sessions and for an unbound
  interface-only neighbor, as the all-peers clear already did. Before, such a
  neighbor reconnected during the maintenance window without
  GRACEFUL_SHUTDOWN, and its routes were preferred again. A dynamic neighbor
  with no dead-letter entry still starts its next session without the intent.
