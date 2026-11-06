### Fixed

- Setting graceful shutdown on all peers (`rbgp gshut --all`) now also sets
  the intent held for a dynamic neighbor between sessions and for an
  interface-only neighbor with no bound endpoint, including one that has
  never bound. The all-peers clear reaches the same neighbors. Before, such a
  neighbor connected during the maintenance window without
  GRACEFUL_SHUTDOWN, and its routes were preferred again. A dynamic neighbor
  with no dead-letter entry still starts its next session without the intent.
