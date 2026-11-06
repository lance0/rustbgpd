### Fixed

- A session closed by a locally sent Cease/Out of Resources (an outbound
  writer saturation, an exact-export invariant failure or a RIB admission
  stall) now escalates the reconnect backoff as every other sent
  NOTIFICATION does. Before, it reconnected after the base
  `connect_retry_secs` wait without advancing the streak, so a peer whose
  sessions kept ending this way re-sent its table at the shortest interval.
  An administrative reset whose close drain raises the Cease/8 still clears
  the streak, as an administrative reset does.
