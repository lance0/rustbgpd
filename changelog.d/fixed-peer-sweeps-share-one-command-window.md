### Fixed

- Sweeps over many peers no longer stall the peer manager for one command
  deadline per peer whose session has stopped reading commands, as a session
  waiting on a full RIB mailbox does. Dynamic-peer resets after a peer-group
  change, the rollback reap of dynamic peers, SIGHUP removal and replacement
  of neighbors, the all-peers graceful-shutdown toggle and RPKI/ASPA
  revalidation now command every peer at once, up to 64 at a time, and keep
  answering readiness probes while they wait. The all-peers graceful-shutdown
  toggle refreshes every acknowledging peer with one RIB distribution pass,
  and the VRP and ASPA forwarders no longer hold the next cache delta until
  the previous delta's revalidation pass ends.
