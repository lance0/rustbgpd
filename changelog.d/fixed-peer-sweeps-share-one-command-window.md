### Fixed

- Sweeps over many peers no longer hold the peer manager for one command
  deadline per peer whose session has stopped reading commands, as a session
  waiting on a full RIB mailbox does, and they keep answering readiness
  probes while they wait. Dynamic-peer resets after a peer-group change and
  the all-peers graceful-shutdown toggle send their command to every peer at
  once and take one 500 ms window however many sessions are stuck; a reset
  that purges routes sends two commands per peer and takes up to two
  windows (1 s). On a
  SIGHUP reload that takes the sequential route (one that also changes
  TCP-AO keys or listener MD5/GTSM settings), the route purges for changed
  neighbors whose discard list changes are likewise all sent at once. The
  rollback reap of dynamic peers, RPKI/ASPA revalidation, and that reload's
  neighbor removals and replacements run each peer's chain of commands 64
  peers at a time, so stuck sessions cost one chain's deadlines per 64 of
  them. A SIGHUP reload on the default generation route still replaces
  neighbors one at a time.
- The VRP and ASPA forwarders no longer hold the next cache delta's RIB
  update until the previous delta's revalidation pass ends. Each keeps one
  pass in flight and merges the deltas that arrive meanwhile into the next
  one.
