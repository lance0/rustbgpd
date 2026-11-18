### Fixed

- One peer's burst no longer delays every other peer's updates for the length
  of the burst. Each session now stops reading its socket while 2,048 routes it
  already sent are unfinished in the RIB and resumes at 1,024, so the RIB's
  input queue holds at most about two distribution passes per source and TCP
  paces the sender. Previously a session queued its whole burst ahead of other peers:
  in the transport harness, 150,000 routes sent at once toward 150 private
  receivers made an unrelated peer's update wait about 15 s. The wait still
  grows with the number of peers bursting at once. See
  [ADR-0078](../docs/adr/0078-inbound-rib-backpressure.md).
  **Operator-visible:** a route a restarting peer re-advertises just before a
  stale-route or refresh deadline, behind a larger burst the RIB has not
  finished, can be swept at the deadline and announced again when it is read;
  see [graceful restart timers](../docs/reference/configuration.md). While a
  session's input waits behind its own unfinished routes, each hold-timer
  expiry processes one pending message from the peer, and a peer with none
  pending gets Hold Timer Expired; the session is not closed for the wait
  itself.
