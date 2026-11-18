### Fixed

- One peer's burst no longer delays every other peer's updates for the length
  of the burst. Each session now stops reading its socket while 1,536 routes it
  already sent are unfinished in the RIB and resumes at 1,024, so the RIB's
  input queue holds a bounded number of route entries per source and TCP
  paces the sender. The limit counts route entries, not messages: about two
  UPDATEs of roughly 1,000 routes, or up to 1,536 one-route UPDATEs. Previously a session queued its whole burst ahead of other peers:
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
  pending gets Hold Timer Expired. After eight consecutive such expiries
  without the RIB finishing those routes, the session is closed with
  `Cease/Out of Resources` within about two more hold times. A hold expiry
  that finds the peer has closed the connection, while input waited for the
  RIB, ends the session as a TCP failure, after processing the messages the
  peer sent before closing; a NOTIFICATION among them ends the session as a
  received NOTIFICATION.
