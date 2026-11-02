### Fixed

- Clearing graceful shutdown on all peers (`rbgp gshut --all --clear`) now
  also clears the intent held for a dynamic neighbor between sessions and for
  an unbound interface-only neighbor. Before, such a neighbor came back still
  advertising GRACEFUL_SHUTDOWN, with no peer left to clear it by name.
