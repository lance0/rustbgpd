### Fixed

- Sweeps over many peers no longer stall the peer manager for one command
  deadline per peer whose session has stopped reading commands, as a session
  waiting on a full RIB mailbox does. Dynamic-peer resets after a peer-group
  change, the rollback reap of dynamic peers, SIGHUP removal and replacement
  of neighbors, the all-peers graceful-shutdown toggle and RPKI/ASPA
  revalidation now send a single command to every peer at once, and run a
  chain of commands, such as a delete, for up to 64 peers at a time, and keep
  answering readiness probes while they wait. The VRP and ASPA forwarders no
  longer hold the next cache delta until the previous delta's revalidation
  pass ends. The all-peers graceful-shutdown toggle's outbound refresh now
  waits up to two minutes for the RIB and reports one failure if it times
  out, instead of failing every peer after five seconds.
