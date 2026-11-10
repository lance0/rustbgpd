### Fixed

- A session whose connection is discarded after a failed TCP-AO key mutation
  now goes down at once. When a SIGHUP key rotation failed part-way on a
  session, or its acknowledgement timed out, the affected sessions closed
  their sockets but stayed Established: the peer's routes stayed installed
  and advertised, and its reconnect was dropped against the Established
  session, until the hold timer expired (indefinitely with a hold time of 0).
  The close is now handled as a transport failure: the routes are withdrawn,
  or retained under Graceful Restart where it was negotiated, and the session
  reconnects.
  **Operator-visible:** such a session records the last error `TCP-AO key
  mutation failed; connection discarded` and counts in
  `bgp_session_down_total` with reason `local_no_notification`.
