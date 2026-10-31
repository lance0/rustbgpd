### Fixed

- Use one 200 ms deadline for the core probes in `GetHealth` (and so
  `rbgp doctor`'s `daemon.healthy` check) and `/readyz` while sessions deliver
  a reload's new exports. Previously `GetHealth` queried each session through
  the peer manager, delaying readiness pings behind that work, and the RIB
  probe waited for the peer-manager probe before starting. The two core
  probes now run concurrently under the shared deadline. `active_peers`
  counts the sessions' published Established state without querying each
  session, so an Established session busy writing exports remains counted
  even when its `ListNeighbors` observation is unavailable.
